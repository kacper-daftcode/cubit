//! Predicate liveness pass over parsed SASS (M2/BARRACUDA).
//!
//! Tracks two independent predicate domains per instruction:
//!   * P  domain (P0..P6; PT=7 is the constant-true sink and never tracked)
//!   * UP domain (UP0..UP6, uniform warp-invariant; UPT=7 likewise dropped)
//!
//! Two transfer modes:
//!   * Compat: bit-parity with the certified reference `predcheck.py` (s6 /
//!     publish/draft/tools-mit). P domain only; PLOP3.LUT reads only the
//!     first two predicate inputs (reference limitation, kept for the gate).
//!   * Strict: compat + documented deltas. Currently the only delta is
//!     PLOP3.LUT reading all THREE predicate inputs (Pa,Pb,Pc) -- a superset
//!     of compat, i.e. strictly more conservative for liveness.
//!
//! Fail-closed: any instruction carrying Pred/UPred OPERANDS outside the
//! known families is reported with known=false (sets empty) and surfaced in
//! the per-kernel unknown list -- no silent pass-through.

use crate::ir::{Instruction, Operand};
use std::collections::{BTreeMap, BTreeSet};

/// Transfer semantics mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferMode {
    /// Bit-parity with predcheck.py (P domain only).
    Compat,
    /// Compat + documented deltas (superset; also tracks the UP domain).
    Strict,
}

/// Predicate read/write sets for one instruction (one domain kept in
/// defs/uses; the UP domain lives in udefs/uuses). Indices are register
/// numbers (0..6); PT/UPT never appear.
#[derive(Debug, Clone, Default)]
pub struct PredXfer {
    pub defs: BTreeSet<u8>,
    pub uses: BTreeSet<u8>,
    pub udefs: BTreeSet<u8>,
    pub uuses: BTreeSet<u8>,
    /// False when the instruction carries predicate operands the family
    /// rules do not know how to classify (fail-closed signal).
    pub known: bool,
}

/// Collect operand indexes of predicate operands (P or UP) in order.
fn pred_positions(insn: &Instruction, uniform: bool) -> Vec<usize> {
    insn.operands
        .iter()
        .enumerate()
        .filter(|(_, o)| match (o, uniform) {
            (Operand::Pred { .. }, false) => true,
            (Operand::UPred { .. }, true) => true,
            _ => false,
        })
        .map(|(i, _)| i)
        .collect()
}

/// Predicate number at operand index (num<7 kept; PT/UPT=7 dropped).
fn pred_num_at(insn: &Instruction, idx: usize, uniform: bool) -> Option<u8> {
    let n = match (&insn.operands[idx], uniform) {
        (Operand::Pred { num, .. }, false) => *num,
        (Operand::UPred { num, .. }, true) => *num,
        _ => return None,
    };
    if n < 7 {
        Some(n)
    } else {
        None
    }
}

/// Transfer sets for one instruction.
pub fn pred_xfer(insn: &Instruction, mode: XferMode) -> PredXfer {
    let mut x = PredXfer {
        known: true,
        ..Default::default()
    };
    // Guard reads its predicate. P guards: both modes. UP guards: Strict
    // only -- Compat mirrors predcheck.py, which is blind to the UP domain.
    if let Some(g) = &insn.guard {
        if g.pred < 7 {
            if g.uniform {
                if mode == XferMode::Strict {
                    x.uuses.insert(g.pred);
                }
            } else {
                x.uses.insert(g.pred);
            }
        }
    }
    let has_p = pred_positions(insn, false);
    let has_up = pred_positions(insn, true);
    if has_p.is_empty() && has_up.is_empty() {
        return x; // guard-only or no predicates at all
    }

    let op = insn.opcode.as_str();
    let is_x = insn.modifiers.iter().any(|m| m == ".X");
    let wide = insn.modifiers.iter().any(|m| m == ".WIDE");
    let convdiv = insn
        .modifiers
        .iter()
        .any(|m| m == ".CONV" || m == ".DIV");

    // Helper view over P positions.
    let p = &has_p;
    let def_at = |x: &mut PredXfer, idx: usize| {
        if let Some(n) = pred_num_at(insn, idx, false) {
            x.defs.insert(n);
        }
    };
    let use_at = |x: &mut PredXfer, idx: usize| {
        if let Some(n) = pred_num_at(insn, idx, false) {
            x.uses.insert(n);
        }
    };

    let handled = match op {
        "IADD3" => {
            for (ord, &idx) in p.iter().enumerate() {
                if ord < 2 {
                    def_at(&mut x, idx);
                } else if is_x {
                    use_at(&mut x, idx);
                }
            }
            true
        }
        "IMAD" => {
            if wide {
                // IMAD.WIDE.*: predicate at operand slot 1 is carry-out.
                if matches!(insn.operands.get(1), Some(Operand::Pred { .. })) {
                    def_at(&mut x, 1);
                }
                if is_x {
                    // .X carry-in: predicate in the final operand slot.
                    if let Some(&last) = p.last() {
                        if last == insn.operands.len() - 1 {
                            use_at(&mut x, last);
                        }
                    }
                }
            } else if is_x && insn.modifiers.len() == 1 {
                // IMAD.X: last predicate is the carry-in (read).
                if let Some(&last) = p.last() {
                    use_at(&mut x, last);
                }
            }
            wide || (is_x && insn.modifiers.len() == 1)
        }
        "ISETP" => {
            for (ord, &idx) in p.iter().enumerate() {
                if ord < 2 {
                    def_at(&mut x, idx);
                } else if ord == 2 {
                    use_at(&mut x, idx);
                }
            }
            true
        }
        "LOP3" => {
            if !p.is_empty() && p[0] == 0 {
                def_at(&mut x, 0);
                for &idx in &p[1..] {
                    use_at(&mut x, idx);
                }
            } else if let Some(&last) = p.last() {
                use_at(&mut x, last);
            }
            true
        }
        "PLOP3" => {
            for (ord, &idx) in p.iter().enumerate() {
                if ord < 2 {
                    def_at(&mut x, idx);
                } else {
                    let limit = if mode == XferMode::Strict { 5 } else { 4 };
                    if ord < limit {
                        use_at(&mut x, idx);
                    }
                }
            }
            true
        }
        "VOTE" => {
            // VOTE.ANY/ALL/EQ Pd, Ps(, ...): first predicate operand is the
            // warp-aggregate DEF, remaining predicate operands are
            // vote-source USEs (negation does not change the read; PT drops
            // out via pred_num_at). BUG-072 / sm120 REQ-063 (i139/i140):
            // hopb divstep loop-exit `VOTE.ALL P1, !P0` previously stood
            // outside every family -> known=false -> sched fail-closed.
            if p.first() == Some(&0) {
                def_at(&mut x, 0);
            }
            for &idx in p.iter().skip(if p.first() == Some(&0) { 1 } else { 0 }) {
                use_at(&mut x, idx);
            }
            true
        }
        "VOTEU" => {
            for &idx in p {
                def_at(&mut x, idx);
            }
            true
        }
        "SHFL" => {
            if matches!(insn.operands.first(), Some(Operand::Pred { .. })) {
                def_at(&mut x, 0);
            }
            true
        }
        "IMNMX" => {
            for (ord, &idx) in p.iter().enumerate() {
                if ord < 2 {
                    def_at(&mut x, idx);
                } else {
                    use_at(&mut x, idx);
                }
            }
            true
        }
        "ATOMG" | "REDG" => {
            if matches!(insn.operands.first(), Some(Operand::Pred { .. })) {
                def_at(&mut x, 0);
            }
            true
        }
        "BRA" if convdiv => {
            if let Some(&first) = p.first() {
                def_at(&mut x, first);
            }
            true
        }
        // Strict-only uniform twins (UP domain). Compat ignores UP entirely,
        // mirroring predcheck.py.
        "UIADD3" => {
            for (ord, &idx) in has_up.iter().enumerate() {
                if mode != XferMode::Strict { break; }
                if let Some(n) = pred_num_at(insn, idx, true) {
                    if ord < 2 {
                        x.udefs.insert(n);
                    } else if is_x {
                        x.uuses.insert(n);
                    }
                }
            }
            true
        }
        "UISETP" => {
            for (ord, &idx) in has_up.iter().enumerate() {
                if mode != XferMode::Strict { break; }
                if let Some(n) = pred_num_at(insn, idx, true) {
                    if ord < 2 {
                        x.udefs.insert(n);
                    } else if ord == 2 {
                        x.uuses.insert(n);
                    }
                }
            }
            true
        }
        "ULOP3" => {
            if mode == XferMode::Strict {
            if !has_up.is_empty() && has_up[0] == 0 {
                if let Some(n) = pred_num_at(insn, 0, true) {
                    x.udefs.insert(n);
                }
                for &idx in &has_up[1..] {
                    if let Some(n) = pred_num_at(insn, idx, true) {
                        x.uuses.insert(n);
                    }
                }
            } else if let Some(&last) = has_up.last() {
                if let Some(n) = pred_num_at(insn, last, true) {
                    x.uuses.insert(n);
                }
            }
            }
            true
        }
        _ => false,
    };

    if handled && op == "VOTEU" && mode == XferMode::Strict {
        // VOTEU writes its UP destination too (e.g. VOTEU.ANY UP0, P0).
        for &idx in &has_up {
            if let Some(n) = pred_num_at(insn, idx, true) {
                x.udefs.insert(n);
            }
        }
    }
    if !handled {
        // Unknown-family signaling applies only when the instruction carries
        // predicates of a domain this mode is responsible for: Compat tracks
        // P operands, Strict tracks P and UP alike.
        let relevant = match mode {
            XferMode::Compat => !has_p.is_empty(),
            XferMode::Strict => !has_p.is_empty() || !has_up.is_empty(),
        };
        x.known = !relevant;
        x.defs.clear();
        x.uses.clear();
        x.udefs.clear();
        x.uuses.clear();
        // Guard-only knowledge is retained: keep the guard use we recorded.
        if x.known {
            return x;
        }
        if let Some(g) = &insn.guard {
            if g.pred < 7 {
                if g.uniform {
                    x.uuses.insert(g.pred);
                } else {
                    x.uses.insert(g.pred);
                }
            }
        }
    }
    x
}

/// Successor indexes for instruction `i` within a kernel of `n` instructions.
/// Mirrors predcheck.py liveness() edge semantics exactly.
pub fn cfg_successors(insns: &[Instruction], i: usize) -> Vec<usize> {
    let n = insns.len();
    let insn = &insns[i];
    let nxt: Vec<usize> = if i + 1 < n { vec![i + 1] } else { vec![] };
    let addr2idx: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(j, x)| (x.addr, j))
        .collect();
    let target_idx = |v: u32| addr2idx.get(&v).copied();

    let branch_target = insn.operands.iter().rev().find_map(|o| match o {
        Operand::BranchTarget(a) => Some(*a),
        _ => None,
    });

    match insn.opcode.as_str() {
        "EXIT" => vec![],
        "BRA" => {
            let convdiv = insn
                .modifiers
                .iter()
                .any(|m| m == ".CONV" || m == ".DIV");
            if convdiv {
                let mut e: Vec<usize> = Vec::new();
                if let Some(t) = branch_target.and_then(target_idx) {
                    e.push(t);
                }
                e.extend(nxt);
                e
            } else {
                let mut e: Vec<usize> = Vec::new();
                if let Some(t) = branch_target.and_then(target_idx) {
                    e.push(t);
                }
                // Guarded plain BRA also falls through.
                if insn.guard.is_some() {
                    e.extend(nxt);
                }
                e
            }
        }
        "BRXU" => {
            if insn.modifiers.iter().any(|m| m == ".U") {
                nxt // opaque-dispatch annotation form: fallthrough only
            } else if let Some(t) = branch_target.and_then(target_idx) {
                vec![t]
            } else {
                // Absolute hex target form: last operand Imm32, address/16.
                match insn.operands.last() {
                    Some(Operand::Imm32(v)) if *v >= 0 => {
                        let a = *v as u32;
                        match target_idx(a) {
                            Some(t) => vec![t],
                            None => vec![],
                        }
                    }
                    _ => vec![],
                }
            }
        }
        "BSSY" | "CALL" | "JMP" => {
            // Not present in the certified corpus; conservative both-edges.
            let mut e: Vec<usize> = Vec::new();
            if let Some(t) = branch_target.and_then(target_idx) {
                e.push(t);
            }
            e.extend(nxt);
            e
        }
        "RET" => vec![], // terminal (not in corpus; documented choice)
        _ => nxt,
    }
}

/// Per-instruction liveness record.
#[derive(Debug, Clone)]
pub struct InsLive {
    pub addr: u32,
    pub opcode_full: String,
    pub raw_text: String,
    pub defs: BTreeSet<u8>,
    pub uses: BTreeSet<u8>,
    pub udefs: BTreeSet<u8>,
    pub uuses: BTreeSet<u8>,
    pub live_in: BTreeSet<u8>,
    pub live_out: BTreeSet<u8>,
    pub ulive_in: BTreeSet<u8>,
    pub known: bool,
}

/// Shared backward dataflow over a CFG: IN = use ∪ (OUT − def),
/// OUT = union of successors' IN. Iterates in reverse order to a fixpoint.
/// Used by both the predicate and register liveness passes.
pub fn backward_liveness(
    succ: &[Vec<usize>],
    defs: &[BTreeSet<u8>],
    uses: &[BTreeSet<u8>],
) -> (Vec<BTreeSet<u8>>, Vec<BTreeSet<u8>>) {
    let n = succ.len();
    let mut live_in: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); n];
    let mut live_out: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); n];
    let mut changed = true;
    while changed {
        changed = false;
        for i in (0..n).rev() {
            let mut o: BTreeSet<u8> = BTreeSet::new();
            for &s2 in &succ[i] {
                for v in &live_in[s2] {
                    o.insert(*v);
                }
            }
            let mut ni = o.clone();
            for v in &defs[i] {
                ni.remove(v);
            }
            for v in &uses[i] {
                ni.insert(*v);
            }
            if o != live_out[i] || ni != live_in[i] {
                live_out[i] = o;
                live_in[i] = ni;
                changed = true;
            }
        }
    }
    (live_in, live_out)
}

/// Run predicate liveness over one kernel's instruction list.
pub fn liveness(insns: &[Instruction], mode: XferMode) -> Vec<InsLive> {
    let n = insns.len();
    let xfer: Vec<PredXfer> = insns.iter().map(|i| pred_xfer(i, mode)).collect();
    let succ: Vec<Vec<usize>> = (0..n).map(|i| cfg_successors(insns, i)).collect();

    let (live_in, live_out) = backward_liveness(
        &succ,
        &xfer.iter().map(|x| x.defs.clone()).collect::<Vec<_>>(),
        &xfer.iter().map(|x| x.uses.clone()).collect::<Vec<_>>(),
    );
    let (ulive_in, _) = backward_liveness(
        &succ,
        &xfer.iter().map(|x| x.udefs.clone()).collect::<Vec<_>>(),
        &xfer.iter().map(|x| x.uuses.clone()).collect::<Vec<_>>(),
    );

    insns
        .iter()
        .enumerate()
        .map(|(i, ins)| InsLive {
            addr: ins.addr,
            opcode_full: ins.opcode_full.clone(),
            raw_text: ins.raw_text.clone(),
            defs: xfer[i].defs.clone(),
            uses: xfer[i].uses.clone(),
            udefs: xfer[i].udefs.clone(),
            uuses: xfer[i].uuses.clone(),
            live_in: live_in[i].clone(),
            live_out: live_out[i].clone(),
            ulive_in: ulive_in[i].clone(),
            known: xfer[i].known,
        })
        .collect()
}

/// Liveness for a whole parsed .sass source: one entry per kernel.
pub struct KernelLiveness {
    pub name: String,
    pub ins: Vec<InsLive>,
    /// Opcode_full of every instruction with unknown predicate xfer.
    pub unknown_ops: Vec<String>,
}

pub fn liveness_file(text: &str, mode: XferMode) -> anyhow::Result<Vec<KernelLiveness>> {
    // Strict parse: the liveness index space must provably match the source
    // (fail-closed; a silently skipped line would corrupt every CFG index).
    let file = crate::sass_file::parse_sass_file_str_strict(text)?;
    let mut out = Vec::new();
    for k in &file.kernels {
        let ins = liveness(&k.instructions, mode);
        let mut unk: Vec<String> = Vec::new();
        for r in &ins {
            if !r.known {
                unk.push(format!("{} @0x{:x}", r.opcode_full, r.addr));
            }
        }
        out.push(KernelLiveness {
            name: k.name.clone(),
            ins,
            unknown_ops: unk,
        });
    }
    Ok(out)
}
