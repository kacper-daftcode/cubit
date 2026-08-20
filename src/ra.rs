//! Register-allocation pass (M4/BARRACUDA b1): plan -> validate -> apply.
//!
//! M4.1 scope: mode "identity" only. The plan maps every structurally-used
//! physical register 1:1 (`virt == phys`). `apply` is the real rewriter of
//! the IR (registers are per-operand struct fields, so a remap is a field
//! rewrite, not text surgery); in identity mode it must report ZERO
//! changed numerals -- that is the machine-checked proof the pass observed
//! every register occurrence the liveness engine knows.
//!
//! Fail-closed doctrine (as M2/M3), RA-level: unknown register-role
//! families stop the run; an incomplete plan (register without a mapping)
//! is an error, never a passthrough; identity drift (changed != 0) is an
//! internal error. SPAN SHAPE observations (odd WIDE/.64 pair bases,
//! non-4-aligned .128/.256 dest quads, R-domain crossing at 255) are
//! REPORTED as `span_notes`, not errors: the M4.1 corpus census on the
//! silicon-certified R0b REFUTED the naive legality readings (see
//! results/fe/M4/M4_1 report): LDG.E.*.128 dest quads appear at R4k+2
//! bases, UIMAD.WIDE appears with odd UR dest (UR13 -- legal), and
//! desc[URx] is a separate 8-bit descriptor namespace (UR64..UR252 in
//! certified code) exempt from architectural-UR rules. The only
//! silicon-positive alignment constraint today is the MMA-tuple rule
//! (BUG-037), enforced in the ENCODER -- RA does not double-gate it.
//! `span_notes` is the tripwire channel for M4.2's allocator policy:
//! silicon-unknown shapes get flagged and gate-snapshotted, never
//! silently accepted into NEW allocations without evidence.
//!
//! Non-identity modes (pin-override M4.2, full allocation M4.3) plug in at
//! [`plan_for_mode`]; their text emission goes through the printer, NOT
//! the byte-verbatim path identity uses.

use crate::ir::{Instruction, Operand};
use crate::reg_liveness::{self, RegDom, RegXfer};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;

/// Allocation mode. M4.1 gates `identity` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaMode {
    Identity,
}

pub fn parse_mode(s: &str) -> Result<RaMode> {
    match s {
        "identity" => Ok(RaMode::Identity),
        other => bail!(
            "ra: unknown mode '{other}' (M4.1 implements 'identity'; \
             pin-override arrives with M4.2)"
        ),
    }
}

/// Whole-kernel register plan: virtual -> physical per domain.
/// Identity mode: virtual numbers ARE the physical ones (text is already
/// register-assigned; BARRACUDA kernels are static-shape, the RA contract
/// starts from a fully-numbered seed).
#[derive(Debug, Clone, Default)]
pub struct RegPlan {
    pub r: BTreeMap<u8, u8>,
    pub ur: BTreeMap<u8, u8>,
}

/// Per-kernel pass report (JSON-serializable for the CLI --report stream).
#[derive(Debug, Clone, Serialize)]
pub struct KernelRaReport {
    pub name: String,
    pub n_ins: usize,
    /// Sorted union of structurally-used registers (span-expanded), per
    /// domain. Plan keys equal these sets in identity mode.
    pub r_used: Vec<u8>,
    pub ur_used: Vec<u8>,
    /// Highest register touched per domain (None when untouched).
    pub r_max: Option<u8>,
    pub ur_max: Option<u8>,
    /// Operand-occurrence numerals the rewriter changed. Invariant 0 for
    /// identity mode; surfaced so a future accidental mutation fails loud.
    pub changed: usize,
    /// unknown role families (module-level fail-closed: run() rejects when
    /// non-empty; recorded here for the report).
    pub unknown_ops: Vec<String>,
    /// Advisory span-shape observations (see module docs): unusual but
    /// silicon-certified-legal shapes, tripwire for M4.2 policy. First N
    /// entries; `span_notes_total` carries the full count.
    pub span_notes: Vec<String>,
    pub span_notes_total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RaRunReport {
    pub mode: String,
    pub kernels: Vec<KernelRaReport>,
}

/// Domain-exclusive ends: R255 (RZ) / UR64. Mirrors reg_liveness::put.
fn dom_max(dom: RegDom) -> u32 {
    match dom {
        RegDom::R => 255,
        RegDom::UR => 64,
    }
}

fn dom_name(dom: RegDom) -> &'static str {
    match dom {
        RegDom::R => "R",
        RegDom::UR => "UR",
    }
}

/// Collect advisory span-shape notes for one kernel (never errors).
/// Classes flagged: width-2/4/8 spans whose bases break the EVEN/QUAD
/// regularities (corpus says: happen and are legal), R/UR spans crossing
/// the domain end, and any width outside 1/2/4/8 (unprecedented class).
/// desc_namespace spans (desc[URx]) are exempt: separate 8-bit namespace.
pub fn span_notes(insns: &[Instruction], xfers: &[RegXfer]) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    for (ins, x) in insns.iter().zip(xfers.iter()) {
        for sp in &x.spans {
            if sp.desc_ns {
                continue;
            }
            let top = sp.base as u32 + sp.width as u32;
            if top > dom_max(sp.dom) {
                notes.push(format!(
                    "0x{:x} {}: {}{} width {} crosses domain end {}",
                    ins.addr,
                    ins.opcode_full,
                    dom_name(sp.dom),
                    sp.base,
                    sp.width,
                    dom_max(sp.dom)
                ));
            }
            let unusual = match sp.width {
                0 | 1 => false,
                2 => sp.base % 2 != 0,
                4 => sp.base % 4 != 0,
                8 => sp.base % 4 != 0,
                _ => true,
            };
            if unusual {
                notes.push(format!(
                    "0x{:x} {}: {}{} width {} unusual base ({})",
                    ins.addr,
                    ins.opcode_full,
                    dom_name(sp.dom),
                    sp.base,
                    sp.width,
                    if sp.is_def { "def" } else { "use" }
                ));
            }
        }
    }
    notes.sort();
    notes.dedup();
    notes
}

/// Build the plan for `mode`. Identity covers every register appearing in
/// the span-expanded transfer sets of the kernel.
pub fn plan_for_mode(mode: RaMode, xfers: &[RegXfer]) -> RegPlan {
    match mode {
        RaMode::Identity => {
            let mut p = RegPlan::default();
            for x in xfers {
                for &r in x.rdefs.iter().chain(x.ruses.iter()) {
                    p.r.insert(r, r);
                }
                for &u in x.udefs.iter().chain(x.uuses.iter()) {
                    p.ur.insert(u, u);
                }
            }
            p
        }
    }
}

/// Coverage check: every span-expanded register a kernel touches must map.
/// Identity mode satisfies this by construction; the check exists so the
/// M4.2+ plan sources (pins, allocators) can never silently pass through.
pub fn validate_coverage(plan: &RegPlan, xfers: &[RegXfer]) -> Result<()> {
    for (i, x) in xfers.iter().enumerate() {
        for &r in x.rdefs.iter().chain(x.ruses.iter()) {
            if !plan.r.contains_key(&r) {
                bail!("ra: plan misses R{r} (insn index {i})");
            }
        }
        for &u in x.udefs.iter().chain(x.uuses.iter()) {
            if !plan.ur.contains_key(&u) {
                bail!("ra: plan misses UR{u} (insn index {i})");
            }
        }
    }
    Ok(())
}

/// Remap every register numeral in the operands of `insns` per `plan`.
/// Returns the number of occurrences whose value CHANGED. Unmapped
/// non-sink numerals are an error (coverage should have caught them).
pub fn apply_plan(insns: &mut [Instruction], plan: &RegPlan) -> Result<usize> {
    let mut changed = 0usize;
    for ins in insns.iter_mut() {
        for o in ins.operands.iter_mut() {
            changed += remap_operand(o, plan).with_context(|| {
                format!("ra: remap failed at 0x{:x} {}", ins.addr, ins.opcode_full)
            })?;
        }
    }
    Ok(changed)
}

fn remap1(slot: &mut u8, map: &BTreeMap<u8, u8>, dom: &str) -> Result<usize> {
    match map.get(slot) {
        Some(&to) => {
            let ch = usize::from(to != *slot);
            *slot = to;
            Ok(ch)
        }
        None => bail!("plan misses {dom}{slot} in remap"),
    }
}

fn remap_operand(o: &mut Operand, plan: &RegPlan) -> Result<usize> {
    match o {
        Operand::Reg { num, .. } => {
            if *num == 255 {
                Ok(0) // RZ sink: architectural constant, never allocated
            } else {
                remap1(num, &plan.r, "R")
            }
        }
        Operand::UReg { num, is_zero, .. } => {
            if *is_zero {
                Ok(0) // URZ literal
            } else {
                remap1(num, &plan.ur, "UR")
            }
        }
        Operand::Addr {
            base_reg, ur_reg, ..
        } => {
            let mut ch = 0;
            if let Some(b) = base_reg {
                if *b != 255 {
                    ch += remap1(b, &plan.r, "R")?;
                }
            }
            if let Some(u) = ur_reg {
                ch += remap1(u, &plan.ur, "UR")?;
            }
            Ok(ch)
        }
        Operand::ConstMem {
            base_reg, ur_reg, ..
        } => {
            let mut ch = 0;
            if let Some(b) = base_reg {
                if *b != 255 {
                    ch += remap1(b, &plan.r, "R")?;
                }
            }
            if let Some(u) = ur_reg {
                ch += remap1(u, &plan.ur, "UR")?;
            }
            Ok(ch)
        }
        Operand::Desc {
            ur_idx, base_reg, ..
        } => {
            // desc[URx] is a descriptor-table namespace, not an
            // architectural UR (M4.1 corpus finding: certified code uses
            // indices >= 64 with rsd-overlay bits). Remap only indices the
            // plan explicitly covers (identity covers the <64 ones that
            // liveness tracks); everything else passes through opaque.
            let mut ch = match plan.ur.get(ur_idx) {
                Some(&to) => {
                    let c = usize::from(to != *ur_idx);
                    *ur_idx = to;
                    c
                }
                None => 0,
            };
            if let Some(b) = base_reg {
                if *b != 255 {
                    ch += remap1(b, &plan.r, "R")?;
                }
            }
            Ok(ch)
        }
        _ => Ok(0),
    }
}

/// Cap of span notes carried per kernel in the report (the aggregate count
/// is always exact). 32 keeps reports readable on the certified corpus.
const SPAN_NOTES_REPORT_CAP: usize = 32;

/// Run the RA pass over a whole .sass source. Strict parse, liveness
/// (shared CFG/dataflow with M2/M3), machine-checked mode semantics:
///   plan(mode) -> validate coverage -> span notes (advisory) -> apply.
/// Fail-closed on: unparsable lines, unknown role families, plan gaps,
/// and (identity) any nonzero change count.
/// Returns the rewritten kernels plus the report.
pub fn run_file(text: &str, mode: RaMode) -> Result<(crate::sass_file::SassFile, RaRunReport)> {
    let file = crate::sass_file::parse_sass_file_str_strict(text)
        .context("ra: strict parse failed")?;
    let mut out = file.clone();
    let mut reports = Vec::new();
    for (src_k, k) in file.kernels.iter().zip(out.kernels.iter_mut()) {
        let xfers: Vec<RegXfer> = src_k.instructions.iter().map(reg_liveness::reg_xfer).collect();
        let unknown: Vec<String> = src_k
            .instructions
            .iter()
            .zip(xfers.iter())
            .filter(|(_, x)| !x.known)
            .map(|(ins, _)| format!("{} @0x{:x}", ins.opcode_full, ins.addr))
            .collect();
        if !unknown.is_empty() {
            bail!(
                "ra: kernel {} has {} unknown register-role op(s): {}",
                src_k.name,
                unknown.len(),
                unknown[..unknown.len().min(8)].join(", ")
            );
        }
        let plan = plan_for_mode(mode, &xfers);
        validate_coverage(&plan, &xfers)?;
        let notes_all = span_notes(&src_k.instructions, &xfers);
        let span_notes_total = notes_all.len();
        let span_notes: Vec<String> =
            notes_all.into_iter().take(SPAN_NOTES_REPORT_CAP).collect();
        let changed = apply_plan(&mut k.instructions, &plan)?;
        if mode == RaMode::Identity && changed != 0 {
            bail!(
                "ra: identity mode changed {} numeral(s) in {} -- internal error",
                changed,
                src_k.name
            );
        }
        let r_used: Vec<u8> = plan.r.keys().copied().collect();
        let ur_used: Vec<u8> = plan.ur.keys().copied().collect();
        reports.push(KernelRaReport {
            name: src_k.name.clone(),
            n_ins: src_k.instructions.len(),
            r_max: r_used.last().copied(),
            ur_max: ur_used.last().copied(),
            r_used,
            ur_used,
            changed,
            unknown_ops: unknown,
            span_notes,
            span_notes_total,
        });
    }
    Ok((
        out,
        RaRunReport {
            mode: "identity".to_string(),
            kernels: reports,
        },
    ))
}
