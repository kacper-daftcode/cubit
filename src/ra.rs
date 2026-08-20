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
use crate::reg_liveness::{self, InsRegLive, RegDom, RegXfer};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Allocation mode. M4.1 gates `identity`; M4.2 adds `pin` (windowed
/// pin-override splice).
#[derive(Debug, Clone)]
pub enum RaMode {
    Identity,
    Pin(PinPlan),
}

/// CLI/pyo3 mode spelling. `pin` carries its plan separately, so this only
/// validates the name; builders live in main.rs / python.rs.
pub fn parse_mode_kind(s: &str) -> Result<&'static str> {
    match s {
        "identity" => Ok("identity"),
        "pin" => Ok("pin"),
        other => bail!(
            "ra: unknown mode '{other}' (implemented: 'identity', 'pin' -- \
             pin-override needs a plan, M4.2)"
        ),
    }
}

/// Legacy single-arg mode parse (identity only; kept for M4.1 callers).
pub fn parse_mode(s: &str) -> Result<RaMode> {
    match parse_mode_kind(s)? {
        "identity" => Ok(RaMode::Identity),
        _ => bail!("ra: mode 'pin' requires a plan (use ra_apply / --plan)"),
    }
}

/// Pin-override plan for ONE kernel (M4.2). The rename applies ONLY to
/// instructions whose index falls inside a declared window; everything
/// outside the windows keeps its numerals (splice semantics).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PinKernelPlan {
    /// `[start, end)` instruction indices, 0-based, end-exclusive
    /// (G8b-window convention). Sorted, non-overlapping (validated).
    #[serde(default)]
    pub windows: Vec<(u32, u32)>,
    /// Partial override map: unlisted registers map to themselves.
    #[serde(default)]
    pub r: BTreeMap<u8, u8>,
    #[serde(default)]
    pub ur: BTreeMap<u8, u8>,
}

/// Whole-file pin plan, keyed by kernel name.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PinPlan {
    #[serde(default)]
    pub kernels: BTreeMap<String, PinKernelPlan>,
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

/// Build the plan for `mode` on kernel `kname`. Identity covers every
/// register appearing in the span-expanded transfer sets; Pin is the
/// identity plan with the kernel's overrides merged on top (unlisted
/// registers keep their numerals; windows do not shape the plan, they
/// gate where it is APPLIED).
pub fn plan_for_mode(mode: &RaMode, kname: &str, xfers: &[RegXfer]) -> Result<RegPlan> {
    let mut p = RegPlan::default();
    for x in xfers {
        for &r in x.rdefs.iter().chain(x.ruses.iter()) {
            p.r.insert(r, r);
        }
        for &u in x.udefs.iter().chain(x.uuses.iter()) {
            p.ur.insert(u, u);
        }
    }
    if let RaMode::Pin(pin) = mode {
        // Subset semantics: kernels the plan does not name pass through
        // untouched (windows gate where renames apply; unnamed kernels are
        // simply outside every window).
        if let Some(kp) = pin.kernels.get(kname) {
            for (&s, &d) in &kp.r {
                p.r.insert(s, d);
            }
            for (&s, &d) in &kp.ur {
                p.ur.insert(s, d);
            }
        }
    }
    Ok(p)
}

/// One numeral rewrite produced by the windowed rewriter.
#[derive(Debug, Clone)]
pub struct OperandChange {
    pub insn_idx: usize,
    pub operand_idx: usize,
    pub dom: RegDom,
    pub from: u8,
    pub to: u8,
}

/// Validate a pin plan against the kernel's liveness and return the set of
/// instruction indices the rename applies to. Fail-closed (M4.2 contract):
///   * windows: at least one, sorted, non-overlapping, inside the kernel;
///   * pins: R src/dst != RZ(255); UR src/dst < 64 (desc[URx>=64] is a
///     separate namespace -- M3.5/M4.1; pinning it is M4.3 territory);
///     src must occur in the kernel (typo trap); no-op pins rejected;
///   * BOUNDARY: src AND dst of every pin must be dead at each window edge
///     (live_in[start] and live_out[end-1]) -- renaming a value that
///     crosses the window edge would desync it from its partner occurrences
///     outside the window;
///   * SPAN-INTEGRITY: width>1 spans (WIDE/.64 pairs, .128/.256 quads)
///     must be untouched (pin moving/tearing a multi-register span is
///     M4.3 full-allocation territory);
///   * INJECTIVITY: per instruction in the window, the map restricted to
///     the occupancy set (live_in + defs + uses, span-expanded) must be
///     injective -- the kernel soundness check against live-value clobber.
pub fn validate_pin(
    kname: &str,
    n_ins: usize,
    xfers: &[RegXfer],
    live: &[InsRegLive],
    kp: &PinKernelPlan,
) -> Result<BTreeSet<usize>> {
    if kp.windows.is_empty() {
        bail!("ra: pin plan for {kname:?}: no windows (M4.2 needs >=1 splice window)");
    }
    let mut prev_end = None;
    for &(s, e) in &kp.windows {
        if s >= e {
            bail!("ra: pin plan for {kname:?}: bad window [{s},{e})");
        }
        if e as usize > n_ins {
            bail!("ra: pin plan for {kname:?}: window [{s},{e}) past kernel end {n_ins}");
        }
        if let Some(pe) = prev_end {
            if s < pe {
                bail!("ra: pin plan for {kname:?}: overlapping/unsorted windows (at [{s},{e}))");
            }
        }
        prev_end = Some(e);
    }
    // pin sanity + occurrence
    let mut r_occ: BTreeSet<u8> = BTreeSet::new();
    let mut u_occ: BTreeSet<u8> = BTreeSet::new();
    for x in xfers {
        r_occ.extend(x.rdefs.iter().chain(x.ruses.iter()).copied());
        u_occ.extend(x.udefs.iter().chain(x.uuses.iter()).copied());
    }
    for (&s, &d) in &kp.r {
        if s == 255 || d == 255 {
            bail!("ra: pin {kname:?} R{s}->R{d}: RZ is not allocatable");
        }
        if s == d {
            bail!("ra: pin {kname:?} R{s}->R{d}: no-op pin");
        }
        if !r_occ.contains(&s) {
            bail!("ra: pin {kname:?} R{s}->R{d}: source R{s} never occurs in kernel");
        }
    }
    for (&s, &d) in &kp.ur {
        if s >= 64 || d >= 64 {
            bail!(
                "ra: pin {kname:?} UR{s}->UR{d}: UR>=64 is the desc-namespace \
                 (separate 8-bit space, M4.1 census) -- desc-index pinning is \
                 out of M4.2 scope"
            );
        }
        if s == d {
            bail!("ra: pin {kname:?} UR{s}->UR{d}: no-op pin");
        }
        if !u_occ.contains(&s) {
            bail!("ra: pin {kname:?} UR{s}->UR{d}: source UR{s} never occurs in kernel");
        }
    }
    // window instruction set + boundary checks
    let mut in_window: BTreeSet<usize> = BTreeSet::new();
    let mr = |v: u8| kp.r.get(&v).copied().unwrap_or(v);
    let mu = |v: u8| kp.ur.get(&v).copied().unwrap_or(v);
    for &(s, e) in &kp.windows {
        in_window.extend(s as usize..e as usize);
        let entry = &live[s as usize];
        let exit = &live[e as usize - 1];
        for (&src, &dst) in &kp.r {
            for v in [src, dst] {
                if entry.rlive_in.contains(&v) {
                    bail!(
                        "ra: pin {kname:?} R{src}->R{dst}: R{v} is live-in at \
                         window [{s},{e}) start (0x{:x}) -- splice rename would \
                         desync from the definition outside the window",
                        entry.addr
                    );
                }
                if exit.rlive_out.contains(&v) {
                    bail!(
                        "ra: pin {kname:?} R{src}->R{dst}: R{v} is live-out at \
                         window [{s},{e}) end (0x{:x}) -- splice rename would \
                         desync from the use outside the window",
                        exit.addr
                    );
                }
            }
        }
        if !kp.ur.is_empty() {
            // UR live-out: InsRegLive carries succ + ulive_in; out = union(succ).
            let mut uout: BTreeSet<u8> = BTreeSet::new();
            for &t in &exit.succ {
                uout.extend(live[t].ulive_in.iter().copied());
            }
            for (&src, &dst) in &kp.ur {
                for v in [src, dst] {
                    if entry.ulive_in.contains(&v) || uout.contains(&v) {
                        bail!(
                            "ra: pin {kname:?} UR{src}->UR{dst}: UR{v} crosses \
                             window [{s},{e}) edge (0x{:x})",
                            entry.addr
                        );
                    }
                }
            }
        }
    }
    // span-integrity + per-instruction injectivity over the occupancy set
    for &i in &in_window {
        let x = &xfers[i];
        for sp in &x.spans {
            if sp.desc_ns || sp.width <= 1 {
                continue;
            }
            let (map, dname) = match sp.dom {
                RegDom::R => (&kp.r, "R"),
                RegDom::UR => (&kp.ur, "UR"),
            };
            for v in sp.base..sp.base + sp.width as u8 {
                if map.get(&v).copied().unwrap_or(v) != v {
                    bail!(
                        "ra: pin {kname:?} {dname}{v} moves inside width-{} span \
                         {}{} (+def={}) at 0x{:x} -- tearing multi-register \
                         spans is M4.3 territory",
                        sp.width, dname, sp.base, sp.is_def, live[i].addr
                    );
                }
            }
        }
        for dom in [RegDom::R, RegDom::UR] {
            let occ: BTreeSet<u8> = match dom {
                RegDom::R => live[i]
                    .rlive_in
                    .iter()
                    .chain(x.rdefs.iter())
                    .chain(x.ruses.iter())
                    .copied()
                    .collect(),
                RegDom::UR => live[i]
                    .ulive_in
                    .iter()
                    .chain(x.udefs.iter())
                    .chain(x.uuses.iter())
                    .copied()
                    .collect(),
            };
            let m: &dyn Fn(u8) -> u8 = match dom {
                RegDom::R => &mr,
                RegDom::UR => &mu,
            };
            // target -> distinct sources; a target with >1 source, or a
            // moved value landing on a stationary occupant, is a collision.
            let mut by_target: BTreeMap<u8, u8> = BTreeMap::new();
            for &v in &occ {
                let t = m(v);
                if let Some(&prev) = by_target.get(&t) {
                    if prev != v {
                        bail!(
                            "ra: pin {kname:?}: collision at insn {i} (0x{:x}): \
                             {} {} and {} both land on {}{}",
                            live[i].addr,
                            match dom { RegDom::R => "R", RegDom::UR => "UR" },
                            prev,
                            v,
                            match dom { RegDom::R => "R", RegDom::UR => "UR" },
                            t
                        );
                    }
                } else {
                    by_target.insert(t, v);
                }
            }
        }
    }
    Ok(in_window)
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

/// Windowed sibling of [`apply_plan`] (M4.2 pin mode): only instructions
/// whose index is in `in_window` are rewritten; every numeral change is
/// recorded as an [`OperandChange`] (the splice emitter consumes these).
pub fn apply_plan_windowed(
    insns: &mut [Instruction],
    plan: &RegPlan,
    in_window: &BTreeSet<usize>,
) -> Result<(usize, Vec<OperandChange>)> {
    let mut changed = 0usize;
    let mut edits: Vec<OperandChange> = Vec::new();
    for (i, ins) in insns.iter_mut().enumerate() {
        if !in_window.contains(&i) {
            continue;
        }
        for (oi, o) in ins.operands.iter_mut().enumerate() {
            let recs = remap_operand_rec(o, plan).with_context(|| {
                format!("ra: remap failed at 0x{:x} {}", ins.addr, ins.opcode_full)
            })?;
            changed += recs.len();
            edits.extend(recs.into_iter().map(|(dom, from, to)| OperandChange {
                insn_idx: i,
                operand_idx: oi,
                dom,
                from,
                to,
            }));
        }
    }
    Ok((changed, edits))
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

/// Recording remap1: returns the (from, to) pair when the numeral changed.
fn remap1_rec(
    slot: &mut u8,
    map: &BTreeMap<u8, u8>,
    dom: &str,
) -> Result<Option<(u8, u8)>> {
    match map.get(slot) {
        Some(&to) => {
            let from = *slot;
            *slot = to;
            Ok((to != from).then_some((from, to)))
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

/// Recording sibling of [`remap_operand`]: returns the list of
/// (dom, from, to) numeral changes performed on this operand (upto one per
/// domain; Desc may yield both a UR-index and an R-base change).
fn remap_operand_rec(
    o: &mut Operand,
    plan: &RegPlan,
) -> Result<Vec<(RegDom, u8, u8)>> {
    let mut out: Vec<(RegDom, u8, u8)> = Vec::new();
    match o {
        Operand::Reg { num, .. } => {
            if *num != 255 {
                if let Some((f, t)) = remap1_rec(num, &plan.r, "R")? {
                    out.push((RegDom::R, f, t));
                }
            }
        }
        Operand::UReg { num, is_zero, .. } => {
            if !*is_zero {
                if let Some((f, t)) = remap1_rec(num, &plan.ur, "UR")? {
                    out.push((RegDom::UR, f, t));
                }
            }
        }
        Operand::Addr { base_reg, ur_reg, .. } | Operand::ConstMem { base_reg, ur_reg, .. } => {
            if let Some(b) = base_reg {
                if *b != 255 {
                    if let Some((f, t)) = remap1_rec(b, &plan.r, "R")? {
                        out.push((RegDom::R, f, t));
                    }
                }
            }
            if let Some(u) = ur_reg {
                if let Some((f, t)) = remap1_rec(u, &plan.ur, "UR")? {
                    out.push((RegDom::UR, f, t));
                }
            }
        }
        Operand::Desc { ur_idx, base_reg, .. } => {
            // Same desc-namespace discipline as remap_operand: only indices
            // the plan explicitly covers are remapped.
            if let Some(&to) = plan.ur.get(ur_idx) {
                if to != *ur_idx {
                    let f = *ur_idx;
                    *ur_idx = to;
                    out.push((RegDom::UR, f, to));
                }
            }
            if let Some(b) = base_reg {
                if *b != 255 {
                    if let Some((f, t)) = remap1_rec(b, &plan.r, "R")? {
                        out.push((RegDom::R, f, t));
                    }
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

/// Cap of span notes carried per kernel in the report (the aggregate count
/// is always exact). 32 keeps reports readable on the certified corpus.
const SPAN_NOTES_REPORT_CAP: usize = 32;

/// Full result of one RA pass over a .sass source.
#[derive(Debug)]
pub struct RaRun {
    /// Rewritten IR (identity mode: numerals untouched).
    pub file: crate::sass_file::SassFile,
    /// Emitted output text. Identity mode: the input VERBATIM (byte-
    /// conservative). Pin mode: splice emission (lines outside windows are
    /// verbatim; window lines carry the pin renames) proven by full
    /// re-parse equality against the rewritten IR.
    pub out_text: String,
    pub report: RaRunReport,
}

/// Run the RA pass over a whole .sass source. Strict parse, liveness
/// (shared CFG/dataflow with M2/M3), machine-checked mode semantics:
///   plan(mode) -> validate coverage -> span notes (advisory) -> apply.
/// Fail-closed on: unparsable lines, unknown role families, plan gaps,
/// (identity) any nonzero change count, and (pin) the validate_pin
/// contract -- window sanity, boundary-dead pins, span integrity,
/// per-instruction injectivity -- plus the splice-emission proof.
pub fn run_file(text: &str, mode: RaMode) -> Result<RaRun> {
    let file = crate::sass_file::parse_sass_file_str_strict(text)
        .context("ra: strict parse failed")?;
    let is_identity = matches!(mode, RaMode::Identity);
    let mode_name = parse_mode_kind(match mode {
        RaMode::Identity => "identity",
        RaMode::Pin(_) => "pin",
    })?
    .to_string();
    if let RaMode::Pin(pin) = &mode {
        // kernel-name typo trap: every planned kernel must exist.
        for kname in pin.kernels.keys() {
            if !file.kernels.iter().any(|k| &k.name == kname) {
                bail!(
                    "ra: pin plan names unknown kernel {kname:?} (file has: {:?})",
                    file.kernels.iter().map(|k| &k.name).collect::<Vec<_>>()
                );
            }
        }
    }
    let mut out = file.clone();
    let mut reports = Vec::new();
    let mut all_edits: BTreeMap<(usize, usize), Vec<OperandChange>> = BTreeMap::new();
    for (kidx, (src_k, k)) in file.kernels.iter().zip(out.kernels.iter_mut()).enumerate() {
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
        let plan = plan_for_mode(&mode, &src_k.name, &xfers)?;
        validate_coverage(&plan, &xfers)?;
        let notes_all = span_notes(&src_k.instructions, &xfers);
        let span_notes_total = notes_all.len();
        let span_notes: Vec<String> =
            notes_all.into_iter().take(SPAN_NOTES_REPORT_CAP).collect();
        let (changed, edits) = match &mode {
            RaMode::Identity => {
                let changed = apply_plan(&mut k.instructions, &plan)?;
                (changed, Vec::new())
            }
            RaMode::Pin(pin) => match pin.kernels.get(&src_k.name) {
                Some(kp) => {
                    let live = reg_liveness::liveness(&src_k.instructions);
                    let in_window = validate_pin(
                        &src_k.name,
                        src_k.instructions.len(),
                        &xfers,
                        &live,
                        kp,
                    )?;
                    apply_plan_windowed(&mut k.instructions, &plan, &in_window)?
                }
                None => {
                    // kernel not named by the plan: verify identity passes
                    // cleanly (changed must be zero by construction).
                    let changed = apply_plan(&mut k.instructions, &plan)?;
                    if changed != 0 {
                        bail!(
                            "ra: pin plan left unplanned kernel {} changed ({}) \
                             -- internal error",
                            src_k.name,
                            changed
                        );
                    }
                    (0, Vec::new())
                }
            },
        };
        if is_identity && changed != 0 {
            bail!(
                "ra: identity mode changed {} numeral(s) in {} -- internal error",
                changed,
                src_k.name
            );
        }
        for e in edits {
            all_edits.entry((kidx, e.insn_idx)).or_default().push(e);
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
    let out_text = if is_identity {
        text.to_string()
    } else {
        emit_spliced(text, &all_edits).context("ra: splice emission failed")?
    };
    let run = RaRun {
        file: out,
        out_text,
        report: RaRunReport {
            mode: mode_name,
            kernels: reports,
        },
    };
    if !is_identity {
        verify_splice_proof(&run)?;
    }
    Ok(run)
}

/// Re-parse the emitted splice text and require structural equality with
/// the rewritten IR (opcode, modifiers, guard, operands, control code, rsd,
/// hand_sched per instruction; same kernels, same counts). This is the
/// fail-closed proof that the line-level emitter changed EXACTLY the
/// planned numerals -- any renderer slip aborts the run instead of writing
/// a drifting file.
fn verify_splice_proof(run: &RaRun) -> Result<()> {
    let re = crate::sass_file::parse_sass_file_str_strict(&run.out_text)
        .context("ra: splice output failed strict re-parse")?;
    if re.kernels.len() != run.file.kernels.len() {
        bail!("ra: splice proof: kernel count drifted");
    }
    for (a, b) in run.file.kernels.iter().zip(re.kernels.iter()) {
        if a.name != b.name || a.instructions.len() != b.instructions.len() {
            bail!("ra: splice proof: kernel {} shape drifted", a.name);
        }
        for (i, (x, y)) in a.instructions.iter().zip(b.instructions.iter()).enumerate() {
            if x.opcode_full != y.opcode_full
                || x.modifiers != y.modifiers
                || x.guard != y.guard
                || x.operands != y.operands
                || x.ctrl != y.ctrl
                || x.rsd != y.rsd
                || x.hand_sched != y.hand_sched
            {
                bail!(
                    "ra: splice proof: instruction {} ({}) of kernel {} drifted \
                     past the planned renames",
                    i, x.opcode_full, a.name
                );
            }
        }
    }
    Ok(())
}


// ---------------------------------------------------------------------------
// Splice emitter (M4.2 pin mode)
// ---------------------------------------------------------------------------
//
// Emission contract: lines outside splice windows are BYTE-VERBATIM from the
// input. Inside a window, only the planned register numerals change, applied
// in place inside their operand token (all whitespace/labels/control
// prefixes/!rsd annotations preserved). The result is proven by
// verify_splice_proof (full re-parse equality vs the rewritten IR), so the
// emitter never trusts its own string handling.
//
// One instruction per line is required (labels on the same line are fine);
// anything else aborts the run (fail-closed).

/// Emit the pin-mode output text from the original source and the recorded
/// numeral changes, keyed by (kernel index, instruction index).
pub fn emit_spliced(
    original: &str,
    edits: &BTreeMap<(usize, usize), Vec<OperandChange>>,
) -> Result<String> {
    use regex::Regex;
    use std::sync::LazyLock;
    static RE_LABEL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.$]*\s*:\s*").unwrap());

    let mut consumed: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut out_lines: Vec<String> = Vec::new();
    let mut in_kernel = false;
    let mut kidx: isize = -1;
    let mut kernel_insn_counts: Vec<usize> = Vec::new();

    let mut lines = original.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t.starts_with(".entry") || t.starts_with(".func") {
            in_kernel = true;
            kidx += 1;
            out_lines.push(line.to_string());
            kernel_insn_counts.push(0usize);
            continue;
        }
        if t.starts_with(".endentry") || t.starts_with(".endfunc") {
            in_kernel = false;
            out_lines.push(line.to_string());
            continue;
        }
        if !in_kernel || t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            out_lines.push(line.to_string());
            continue;
        }
        if t.starts_with('.') {
            // in-kernel directives (.reg/.param/.shared/...) are not
            // instructions -- the strict parser excludes them too.
            out_lines.push(line.to_string());
            continue;
        }
        let cur_k = kidx as usize;

        // Strip leading labels from a COPY to decide instruction-ness; the
        // emitted line keeps them verbatim (they sit before asm_off).
        let mut rest = t;
        let mut label_len = 0usize;
        loop {
            match RE_LABEL.captures(rest) {
                Some(c) => {
                    let m = c.get(0).unwrap().as_str();
                    label_len += m.len();
                    rest = &rest[m.len()..];
                }
                None => break,
            }
        }
        if rest.is_empty() {
            out_lines.push(line.to_string()); // lone label line
            continue;
        }
        // Candidate instruction line: census it (strict parse already
        // accepted it, so classification matches the parser's).
        if !line.is_ascii() {
            bail!("ra: splice emitter: non-ASCII line in kernel body (unsupported)");
        }
        let count = &mut kernel_insn_counts[cur_k];
        let i_idx = *count;
        *count += 1;
        let Some(changes) = edits.get(&(cur_k, i_idx)) else {
            out_lines.push(line.to_string());
            continue;
        };
        consumed.insert((cur_k, i_idx));
        out_lines.push(rewrite_instruction_line(line, label_len, changes, cur_k, i_idx)?);
    }
    let missing: Vec<&(usize, usize)> =
        edits.keys().filter(|k| !consumed.contains(*k)).collect();
    if !missing.is_empty() {
        bail!(
            "ra: splice emitter: {} edit(s) targeted non-existent lines (first: {:?})",
            missing.len(),
            missing[0]
        );
    }
    let mut out = out_lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Rewrite the operand numerals of one instruction line in place.
/// `label_len` = byte length of the stripped leading label chain.
fn rewrite_instruction_line(
    line: &str,
    label_len: usize,
    changes: &[OperandChange],
    kidx: usize,
    iidx: usize,
) -> Result<String> {
    // Locate the asm text region within the line: after the leading
    // whitespace + labels + optional "[B..:R..:W..:Y:S..]" prefix, and
    // before " !rsd[" / " ;" terminators.
    let lead_ws = line.len() - line.trim_start().len();
    let mut asm_start = lead_ws + label_len;
    let bytes = line.as_bytes();
    if bytes[asm_start] == b'[' {
        let close = line[asm_start..]
            .find(']')
            .with_context(|| format!("ra: splice: unterminated ctrl prefix on kernel {kidx} insn {iidx}"))?;
        asm_start += close + 1;
        while asm_start < line.len() && bytes[asm_start] == b' ' {
            asm_start += 1;
        }
    }
    let mut asm_end = line.len();
    for marker in [" !rsd[", " ;", ";"] {
        if let Some(pos) = line[asm_start..].find(marker) {
            asm_end = asm_end.min(asm_start + pos);
        }
    }
    let region = &line[asm_start..asm_end];
    if region.contains(';') {
        bail!(
            "ra: splice emitter: multiple instructions on one line (kernel {kidx} \
             insn {iidx}) -- unsupported in splice mode"
        );
    }

    // Split into guard?/opcode + operand tokens, tracking token spans so
    // reassembly can be byte-conservative.
    let mut pos = 0usize;
    let rbytes = region.as_bytes();
    if rbytes.first() == Some(&b'@') {
        while pos < region.len() && !rbytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        while pos < region.len() && rbytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
    }
    // opcode token
    while pos < region.len() && !rbytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    while pos < region.len() && rbytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    // operand tokens with spans (comma split at bracket depth 0)
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut depth = 0i32;
    let mut tok_start: Option<usize> = None;
    let mut i = pos;
    while i <= region.len() {
        let at_end = i == region.len();
        let ch = if at_end { None } else { Some(rbytes[i]) };
        match ch {
            Some(b'[') | Some(b'(') => depth += 1,
            Some(b']') | Some(b')') => depth -= 1,
            Some(b',') if depth == 0 => {
                if let Some(s) = tok_start.take() {
                    spans.push((s, trim_end(region, s, i)));
                }
            }
            None => {
                if let Some(s) = tok_start.take() {
                    spans.push((s, trim_end(region, s, i)));
                }
                break;
            }
            Some(c) if !c.is_ascii_whitespace() && tok_start.is_none() => {
                tok_start = Some(i);
            }
            _ => {}
        }
        i += 1;
    }

    // Apply the planned changes token-locally, exactly one hit each.
    // Changes are grouped per operand token (a Desc token can carry both a
    // UR-index and an R-base rename); replaced tokens are spliced back in
    // DESCENDING span order so earlier offsets stay valid.
    let mut by_op: BTreeMap<usize, Vec<&OperandChange>> = BTreeMap::new();
    for ch in changes {
        by_op.entry(ch.operand_idx).or_default().push(ch);
    }
    let mut replaced_tokens: BTreeMap<usize, String> = BTreeMap::new();
    for (oi, chs) in &by_op {
        let Some(&(ts, te)) = spans.get(*oi) else {
            bail!(
                "ra: splice: change targets operand {oi} but line has {} token(s) \
                 (kernel {kidx} insn {iidx})",
                spans.len()
            );
        };
        let mut token = region[ts..te].to_string();
        for ch in chs {
            let needle = match ch.dom {
                RegDom::R => format!("R{}", ch.from),
                RegDom::UR => format!("UR{}", ch.from),
            };
            let replacement = match ch.dom {
                RegDom::R => format!("R{}", ch.to),
                RegDom::UR => format!("UR{}", ch.to),
            };
            token = replace_reg_numeral(&token, &needle, &replacement).with_context(|| {
                format!(
                    "ra: splice: kernel {kidx} insn {iidx} operand {oi}: expected \
                     exactly one {needle} in token {token:?}"
                )
            })?;
        }
        replaced_tokens.insert(*oi, token);
    }
    let mut new_region = region.to_string();
    for (oi, token) in replaced_tokens.iter().rev() {
        let (ts, te) = spans[*oi];
        new_region.replace_range(ts..te, token);
    }
    Ok(format!(
        "{}{}{}",
        &line[..asm_start],
        new_region,
        &line[asm_end..]
    ))
}

fn trim_end(s: &str, start: usize, end: usize) -> usize {
    let b = s.as_bytes();
    let mut e = end;
    while e > start && b[e - 1].is_ascii_whitespace() {
        e -= 1;
    }
    e
}

/// Replace exactly one standalone occurrence of register literal `needle`
/// (`R<num>` / `UR<num>`) inside an operand token. The numeral must be
/// delimited by a non-register-numeral character so `R2` never matches the
/// head of `R20`. Zero or multiple hits are an error (fail-closed).
fn replace_reg_numeral(token: &str, needle: &str, replacement: &str) -> Result<String> {
    let b = token.as_bytes();
    let n = needle.len();
    let mut hits: Vec<usize> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = token[from..].find(needle) {
        let at = from + rel;
        let end = at + n;
        let after_ok = end >= token.len() || !b[end].is_ascii_digit();
        // the char BEFORE is fine whatever it is ('-', '|', '[', ' '):
        // needle itself starts with the domain letter which can't extend
        // an identifier we care about in operand position (UR vs R distinct).
        if after_ok {
            hits.push(at);
        }
        from = at + 1;
    }
    if hits.len() != 1 {
        bail!("found {} occurrence(s), need exactly 1", hits.len());
    }
    let at = hits[0];
    Ok(format!("{}{}{}", &token[..at], replacement, &token[at + n..]))
}
