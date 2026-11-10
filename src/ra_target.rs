//! Target policy of the full register allocation (`cubit ra --mode full --target sm120`).
//!
//! The allocator of `ra_full` renames by a liveness model that was grounded on one certified
//! sm_103a corpus. Run on the production sm_120 attention kernel (2026-11-10) the same model
//! produced a kernel that assembles and cannot run, and three of its assumptions do not hold for
//! sm_120 code in general. A target policy states what the allocator must know about the silicon
//! it allocates for; without one (`--target` absent) nothing here is used and the pass is
//! byte for byte what it was.
//!
//! `sm120` -- what it adds, each with its evidence:
//!
//! * **The grid.** Every operand that names more than one 32-bit register starts on a multiple
//!   of its width: 64-bit pairs on even registers, 128-bit quads (and wider) on multiples of
//!   four. Silicon (RTX PRO 6000 Blackwell, 2026-11-10; `tools/ra/gen_align_probes.py`,
//!   `align_probes_sm120_20261110.json`): 38 one-warp probe kernels, one shaped instruction
//!   each -- every one of the 23 with an off-grid base ends the launch with
//!   CUDA_ERROR_ILLEGAL_INSTRUCTION (715), every one of the 15 controls is exact. Measured
//!   shapes: the addend pair and the destination pair of `IMAD.WIDE`; the destination of
//!   `LDC.64`, `LDG.E.64`, `LDS.64`, `CS2R`, `LDSM.2` (odd) and of `LDG.E.128`, `LDS.128`,
//!   `LDSM.4` (4k+1, 4k+2, 4k+3); the data of `STS.64` / `STS.128`; the address pair of `LDG`
//!   and `STG`; an odd uniform pair under `LDCU.64` + `desc[UR]`. MMA tuples: BUG-037.
//!   Vendor practice agrees everywhere: in the sm_120 census (166 nvcc / ptxas cubins,
//!   1 811 600 instructions) no multi-register operand of any kind is off the grid
//!   (`tools/ra/align_census.py`). The assembler takes the off-grid words (KNOWN_ISSUES A28);
//!   without the grid the allocator placed the attention kernel's address pairs on odd
//!   registers and its `LDG.E.128` quads on 4k+3: 55 words the strict round trip refuses.
//! * **Hardware footprints the role table does not carry.** `desc[URa][Rb.64]` reads the 64-bit
//!   address `Rb:Rb+1` and the 64-bit descriptor `URa:URa+1` (the table's `desc_base` width of 1
//!   is a finding of the sm_103a corpus); `CS2R Rd, <SR>` without `.32` writes the pair
//!   `Rd:Rd+1` (measured by the probes' control: `CS2R R8, SRZ` zeroes R8 and R9; the role
//!   table writes a pair only for `SR_*LO` names); `LDSM.<..>.2` writes two registers
//!   (measured likewise; the role table: `.4` four, anything else one).
//!   A register the model does not see written can be handed to a live value.
//! * **Guarded writes do not kill.** `@P0 LDG.E.128 R88, ...` leaves `R88..R91` untouched when
//!   `P0` is false, so the value they held before stays live across the instruction. The shared
//!   backward dataflow treats every write as a kill: a register is "dead" between its default
//!   and its guarded overwrite and may be given to something else in between. Here liveness
//!   facts carry the guard they hang on: a write under guard `g` ends only what is needed under
//!   that same `g`, and a write of the predicate itself makes those facts unconditional.
//! * **The plan is audited against the footprints**: every span lands on consecutive registers
//!   on its grid, whoever made the plan (`--mode apply` included).
//! * **`.reg` follows the allocation**: the output declares `R0` to the highest register the
//!   plan uses, so the register count of the cubin (`KernelResources::reg_count`: that plus the
//!   two shadow registers of KNOWN_ISSUES A1, in granules of 8) is the allocation's own. A
//!   source may therefore name its registers freely (`.reg R0-R253`, one numeral per value).

use crate::ir::{Instruction, Operand};
use crate::pred_liveness::{self, InsLive as PredInsLive, PredXfer, XferMode};
use crate::reg_liveness::{self, InsRegLive, RegDom, RegSpan, RegXfer};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet};

/// The group orders a targeted allocation tries; the placement with the lowest watermark is
/// kept, the first of equals. On a register grid the first-live order of the target-neutral
/// pass leaves holes (the attention kernel: 128 registers against 126 by hand).
pub const GROUP_ORDERS: [crate::ra_full::GroupOrder; 3] = [
    crate::ra_full::GroupOrder::FirstLive,
    crate::ra_full::GroupOrder::WideFirst,
    crate::ra_full::GroupOrder::GridFirst,
];

/// The silicon a full allocation is made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaTarget {
    Sm120,
}

impl RaTarget {
    pub fn parse(s: &str) -> Result<RaTarget> {
        match s {
            "sm120" | "sm_120" => Ok(RaTarget::Sm120),
            other => bail!("ra: unknown target '{other}' (implemented: 'sm120')"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RaTarget::Sm120 => "sm120",
        }
    }
}

fn dom_end(dom: RegDom) -> u32 {
    match dom {
        RegDom::R => 255,
        RegDom::UR => 64,
    }
}

fn add_span(x: &mut RegXfer, dom: RegDom, base: u8, width: usize, is_def: bool) {
    x.spans.push(RegSpan { base, width, dom, is_def, align: 1, desc_ns: false });
    let set = match (dom, is_def) {
        (RegDom::R, true) => &mut x.rdefs,
        (RegDom::R, false) => &mut x.ruses,
        (RegDom::UR, true) => &mut x.udefs,
        (RegDom::UR, false) => &mut x.uuses,
    };
    for k in 0..width as u32 {
        let r = base as u32 + k;
        if r < dom_end(dom) {
            set.insert(r as u8);
        }
    }
}

/// The transfer sets and spans of one instruction as the target's hardware reads and writes
/// registers: `reg_liveness::reg_xfer` plus the footprints and the grid of the module docs.
pub fn target_xfer(target: RaTarget, ins: &Instruction) -> RegXfer {
    let mut x = reg_liveness::reg_xfer(ins);
    if !x.known {
        return x;
    }
    match target {
        RaTarget::Sm120 => {
            for op in &ins.operands {
                if let Operand::Desc { ur_idx, base_reg, base_reg_suffix, .. } = op {
                    let wide = base_reg_suffix.as_deref().is_some_and(|s| s.trim_start_matches('.') == "64");
                    if let Some(b) = base_reg {
                        if *b != 255 && wide {
                            add_span(&mut x, RegDom::R, *b, 2, false);
                        }
                    }
                    if (*ur_idx as u32) + 1 < dom_end(RegDom::UR) {
                        add_span(&mut x, RegDom::UR, *ur_idx, 2, false);
                    }
                }
            }
            let dest = match ins.operands.first() {
                Some(Operand::Reg { num, .. }) if *num != 255 => Some(*num),
                _ => None,
            };
            if let Some(d) = dest {
                let has = |m: &str| ins.modifiers.iter().any(|x| x == m);
                if (ins.opcode == "CS2R" && !has(".32")) || (ins.opcode == "LDSM" && has(".2")) {
                    add_span(&mut x, RegDom::R, d, 2, true);
                }
            }
            for sp in x.spans.iter_mut() {
                if sp.desc_ns {
                    continue;
                }
                let grid = match sp.width {
                    0 | 1 => 1,
                    2 | 3 => 2,
                    _ => 4,
                };
                sp.align = sp.align.max(grid);
            }
        }
    }
    x
}

/// A guard: (uniform, predicate, negated). `None` = unguarded.
type Cond = Option<(bool, u8, bool)>;

fn guard_of(ins: &Instruction) -> Cond {
    match &ins.guard {
        Some(g) if g.pred < 7 => Some((g.uniform, g.pred, g.negated)),
        _ => None,
    }
}

/// Backward liveness with guard-conditional facts (module docs). `defs` / `uses` are the sets
/// of one register domain; `always` are uses that happen whatever the guard says (the guard's
/// own predicate, in the predicate domain); `pdefs` the predicates each instruction writes, as
/// (uniform, number). Returns (live_in, live_out): a register is live when any fact names it.
fn conditional_liveness(
    succ: &[Vec<usize>],
    guards: &[Cond],
    defs: &[BTreeSet<u8>],
    uses: &[BTreeSet<u8>],
    always: &[BTreeSet<u8>],
    pdefs: &[BTreeSet<(bool, u8)>],
) -> (Vec<BTreeSet<u8>>, Vec<BTreeSet<u8>>) {
    let n = succ.len();
    let mut fin: Vec<BTreeSet<(u8, Cond)>> = vec![BTreeSet::new(); n];
    let mut fout: Vec<BTreeSet<(u8, Cond)>> = vec![BTreeSet::new(); n];
    let mut changed = true;
    while changed {
        changed = false;
        for i in (0..n).rev() {
            let mut o: BTreeSet<(u8, Cond)> = BTreeSet::new();
            for &s in &succ[i] {
                o.extend(fin[s].iter().copied());
            }
            let g = guards[i];
            // an instruction that rewrites its own guard predicate: the facts behind it hang
            // on the NEW value, so its guarded write ends none of them
            let g_holds_after = match g {
                Some((u, p, _)) => !pdefs[i].contains(&(u, p)),
                None => true,
            };
            let mut cur: BTreeSet<(u8, Cond)> = BTreeSet::new();
            for &(r, c) in &o {
                if defs[i].contains(&r) && (g.is_none() || (g_holds_after && c == g)) {
                    continue; // written here on every path that needs it
                }
                let c = match c {
                    Some((u, p, _)) if pdefs[i].contains(&(u, p)) => None,
                    other => other,
                };
                cur.insert((r, c));
            }
            for &r in &uses[i] {
                cur.insert((r, g));
            }
            for &r in &always[i] {
                cur.insert((r, None));
            }
            if o != fout[i] || cur != fin[i] {
                fout[i] = o;
                fin[i] = cur;
                changed = true;
            }
        }
    }
    let flat = |v: Vec<BTreeSet<(u8, Cond)>>| -> Vec<BTreeSet<u8>> {
        v.into_iter().map(|s| s.into_iter().map(|(r, _)| r).collect()).collect()
    };
    (flat(fin), flat(fout))
}

/// Register and predicate liveness of one kernel under the target policy: the rows the
/// allocator, its conflict graph and its audits read.
pub fn target_liveness(
    insns: &[Instruction],
    xfers: &[RegXfer],
    pxfers: &[PredXfer],
) -> (Vec<InsRegLive>, Vec<PredInsLive>) {
    let n = insns.len();
    let succ: Vec<Vec<usize>> = (0..n).map(|i| pred_liveness::cfg_successors(insns, i)).collect();
    let guards: Vec<Cond> = insns.iter().map(guard_of).collect();
    let pdefs: Vec<BTreeSet<(bool, u8)>> = pxfers
        .iter()
        .map(|x| x.defs.iter().map(|&p| (false, p)).chain(x.udefs.iter().map(|&p| (true, p))).collect())
        .collect();
    let none: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); n];
    let col = |f: &dyn Fn(&RegXfer) -> &BTreeSet<u8>| -> Vec<BTreeSet<u8>> { xfers.iter().map(|x| f(x).clone()).collect() };
    let (rin, rout) = conditional_liveness(&succ, &guards, &col(&|x| &x.rdefs), &col(&|x| &x.ruses), &none, &pdefs);
    let (uin, _) = conditional_liveness(&succ, &guards, &col(&|x| &x.udefs), &col(&|x| &x.uuses), &none, &pdefs);
    let live: Vec<InsRegLive> = insns
        .iter()
        .enumerate()
        .map(|(i, ins)| InsRegLive {
            addr: ins.addr,
            opcode_full: ins.opcode_full.clone(),
            raw_text: ins.raw_text.clone(),
            succ: succ[i].clone(),
            rdefs: xfers[i].rdefs.clone(),
            ruses: xfers[i].ruses.clone(),
            udefs: xfers[i].udefs.clone(),
            uuses: xfers[i].uuses.clone(),
            rlive_in: rin[i].clone(),
            rlive_out: rout[i].clone(),
            ulive_in: uin[i].clone(),
            known: xfers[i].known,
        })
        .collect();
    // Predicates: the guard's own predicate is read whatever it holds; the others under it.
    let guard_use: Vec<BTreeSet<u8>> = insns
        .iter()
        .map(|ins| match &ins.guard {
            Some(g) if g.pred < 7 && !g.uniform => [g.pred].into_iter().collect(),
            _ => BTreeSet::new(),
        })
        .collect();
    let p_defs: Vec<BTreeSet<u8>> = pxfers.iter().map(|x| x.defs.clone()).collect();
    let p_uses: Vec<BTreeSet<u8>> = pxfers.iter().map(|x| x.uses.clone()).collect();
    let (pin, pout) = conditional_liveness(&succ, &guards, &p_defs, &p_uses, &guard_use, &pdefs);
    // The uniform predicates keep the shared engine's rows (`ra_full::build_pred_cosets`
    // recomputes them with it and cross-checks).
    let base = pred_liveness::liveness(insns, XferMode::Strict);
    let plive: Vec<PredInsLive> = base
        .into_iter()
        .enumerate()
        .map(|(i, mut row)| {
            row.live_in = pin[i].clone();
            row.live_out = pout[i].clone();
            row
        })
        .collect();
    (live, plive)
}

/// Every span of every instruction must land on consecutive registers on its grid (and inside
/// the domain). Checked on whatever plan is about to be applied; an unmapped register stands
/// for itself.
pub fn audit_spans(
    kname: &str,
    insns: &[Instruction],
    xfers: &[RegXfer],
    rmap: &BTreeMap<u8, u8>,
    urmap: &BTreeMap<u8, u8>,
) -> Result<()> {
    for (i, (ins, x)) in insns.iter().zip(xfers.iter()).enumerate() {
        for sp in &x.spans {
            if sp.desc_ns {
                continue;
            }
            let (map, dname) = match sp.dom {
                RegDom::R => (rmap, "R"),
                RegDom::UR => (urmap, "UR"),
            };
            let at = |r: u32| -> u32 { map.get(&(r as u8)).copied().unwrap_or(r as u8) as u32 };
            let home = at(sp.base as u32);
            let end = dom_end(sp.dom);
            for k in 0..sp.width as u32 {
                let r = sp.base as u32 + k;
                if r >= end {
                    bail!(
                        "ra: kernel {kname:?} ins {i} `{}`: {dname}{}..+{} leaves the register file",
                        ins.raw_text.trim(), sp.base, sp.width - 1
                    );
                }
                if at(r) != home + k || home + k >= end {
                    bail!(
                        "ra: kernel {kname:?} ins {i} `{}`: the plan tears the {}-register operand at \
                         {dname}{} ({dname}{} -> {dname}{}, expected {dname}{})",
                        ins.raw_text.trim(), sp.width, sp.base, r, at(r), home + k
                    );
                }
            }
            if sp.align > 1 && home % sp.align as u32 != 0 {
                bail!(
                    "ra: kernel {kname:?} ins {i} `{}`: the {}-register operand at {dname}{} is placed on \
                     {dname}{home}, off its grid of {}",
                    ins.raw_text.trim(), sp.width, sp.base, sp.align
                );
            }
        }
    }
    Ok(())
}
