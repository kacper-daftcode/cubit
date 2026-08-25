//! Register liveness pass over parsed SASS (M3/BARRACUDA, RA foundation b1).
//!
//! Domains: R (0..254; RZ=255 constant-zero sink never tracked) and UR
//! (0..63; literal URZ = is_zero sink never tracked), solved over the same
//! CFG as pred_liveness (cfg_successors) with the shared backward fixpoint
//! (pred_liveness::backward_liveness).
//!
//! Semantics status (honest): operand ROLES are structurally grounded on the
//! certified R0b corpus (73 distinct opcode_full -> bases below). Anything
//! outside the table carrying Reg/UReg operands is fail-closed:
//! known=false, surfaced per kernel (unknown_ops).
//!
//! Width discipline: defs expand to their physical span from opcode
//! modifiers (.WIDE/.64 -> 2, .128 -> 4, .256 -> 8); the WIDE multiply's
//! 64-bit addend reads (c, c+1). Def sets are intended as complete clobber
//! sets for RA; uncertain widths went to the superset-of-writes direction
//! and are pinned by tests.

use crate::ir::{Instruction, Operand};
use crate::pred_liveness::{backward_liveness, cfg_successors};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Operand direction/width table (M3.5): tables/operand_roles.json.
// Roles are DATA: scoreboard RAW/WAR edge census on the silicon-certified R0b
// schedule + SASS class semantics, provenance per base op. Address widths:
// desc[UR][Rx.64] base is a single 32-bit offset register (Q1 resolved
// 2026-08-20: 7 of 24 R0b desc bases never have x+1 anywhere in the kernel,
// odd bases are legal, producers are 32-bit ops) - not a register pair.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct RolesMeta {
    address_suffix_widths: AddrWidths,
}

#[derive(serde::Deserialize)]
struct AddrWidths {
    desc_base: usize,
    plain_base_dot64: usize,
    x_scale_suffix: usize,
}

#[derive(serde::Deserialize)]
struct RolesTable {
    #[serde(rename = "_meta")]
    _meta: RolesMeta,
    base_ops: HashMap<String, RoleOp>,
}

#[derive(serde::Deserialize)]
struct RoleOp {
    #[serde(rename = "class")]
    cls: String,
}

fn roles_table() -> &'static RolesTable {
    static T: OnceLock<RolesTable> = OnceLock::new();
    T.get_or_init(|| {
        serde_json::from_str(include_str!("../tables/operand_roles.json"))
            .expect("operand_roles.json must parse")
    })
}

fn addr_widths() -> &'static AddrWidths {
    &roles_table()._meta.address_suffix_widths
}

/// Register domain of a span record (M4.1/RA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegDom {
    R,
    UR,
}

/// Structural register span (base + width + direction), recorded alongside
/// the transfer sets during the SAME role-driven classification pass
/// (M4.1/RA). The liveness sets stay the semantic output; spans carry the
/// (base, width) pairing the RA validator needs for alignment checks
/// (even WIDE/.64 pairs, .128 quads, .256 two-quads) without re-deriving
/// roles. Recorded BEFORE domain clipping so domain-crossing spans stay
/// visible to the validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegSpan {
    pub base: u8,
    pub width: usize,
    pub dom: RegDom,
    pub is_def: bool,
    /// Required alignment of the span BASE (1 = none). Grounded rule data:
    /// 4 for MMA-tuple positions (IMMA C/D/A/B quads -- the ENCODER rejects
    /// misaligned tuples per BUG-037; the one silicon-proven alignment
    /// rule, see the M4.1 corrigendum for the debunked LDG/.128 variants).
    /// RA-full must honor it when picking group homes.
    pub align: u8,
    /// True when this "UR" number is actually a descriptor-table index
    /// (desc[URx]): an 8-bit namespace distinct from architectural URs
    /// (certified kernels routinely use desc[UR64..UR252]; the liveness
    /// sets still clip at 64). RA validation must not apply UR-domain
    /// rules to these.
    pub desc_ns: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RegXfer {
    pub rdefs: BTreeSet<u8>,
    pub ruses: BTreeSet<u8>,
    pub udefs: BTreeSet<u8>,
    pub uuses: BTreeSet<u8>,
    pub known: bool,
    /// Span records parallel to the sets above (unsorted, un-deduped).
    pub spans: Vec<RegSpan>,
}

/// Destination span in 32-bit registers from opcode modifiers.
fn dest_width(insn: &Instruction) -> usize {
    for m in &insn.modifiers {
        match m.as_str() {
            ".256" => return 8,
            ".128" => return 4,
            ".64" | ".WIDE" => return 2,
            _ => {}
        }
    }
    1
}

/// Address-base span from suffix (".64"/".X8" ...).
fn suffix_width(suffix: &Option<String>) -> usize {
    // Plain (non-desc) bracket forms. ".64" is a register-PAIR span
    // (table: plain_base_dot64; unobserved in the R0b corpus - every global
    // access there is desc-form). X-suffixed forms ([R5.X16] in STS/LDS)
    // are address SCALING on a single register (grounded: STS.128 [R5.X16]
    // smem bank math; table: x_scale_suffix).
    match suffix.as_deref() {
        Some(".64") | Some("64") => addr_widths().plain_base_dot64,
        _ => addr_widths().x_scale_suffix,
    }
}

fn put(
    set: &mut BTreeSet<u8>,
    spans: &mut Vec<RegSpan>,
    num: u8,
    w: usize,
    dom: RegDom,
    dom_max_excl: u32,
    is_def: bool,
) {
    put_ns(set, spans, num, w, dom, dom_max_excl, is_def, false);
}

/// Aligned sibling (MMA tuples, BUG-037): same set membership, span record
/// carries the alignment requirement for the allocator.
#[allow(clippy::too_many_arguments)]
fn put_aligned(
    set: &mut BTreeSet<u8>,
    spans: &mut Vec<RegSpan>,
    num: u8,
    w: usize,
    dom: RegDom,
    dom_max_excl: u32,
    is_def: bool,
    align: u8,
) {
    put_ns(set, spans, num, w, dom, dom_max_excl, is_def, false);
    if let Some(sp) = spans.last_mut() {
        sp.align = align;
    }
}

#[allow(clippy::too_many_arguments)]
fn put_ns(
    set: &mut BTreeSet<u8>,
    spans: &mut Vec<RegSpan>,
    num: u8,
    w: usize,
    dom: RegDom,
    dom_max_excl: u32,
    is_def: bool,
    desc_ns: bool,
) {
    spans.push(RegSpan {
        base: num,
        width: w,
        dom,
        is_def,
        align: 1,
        desc_ns,
    });
    for k in 0..w as u32 {
        let r = num as u32 + k;
        if r < dom_max_excl {
            set.insert(r as u8);
        }
    }
}

/// Record every register occurrence INSIDE one operand as a use
/// (top-level Reg/UReg, Addr/Desc/ConstMem bases and descriptor URs).
fn use_operand(o: &Operand, x: &mut RegXfer, width: usize) {
    match o {
        Operand::Reg { num, .. } => {
            if *num != 255 {
                put(&mut x.ruses, &mut x.spans, *num, width, RegDom::R, 255, false);
            }
        }
        Operand::UReg { num, is_zero, .. } => {
            if !is_zero {
                put(&mut x.uuses, &mut x.spans, *num, width, RegDom::UR, 64, false);
            }
        }
        Operand::Addr {
            base_reg,
            base_reg_suffix,
            ur_reg,
            ..
        } => {
            if let Some(b) = base_reg {
                if *b != 255 {
                    put(&mut x.ruses, &mut x.spans, *b, suffix_width(base_reg_suffix), RegDom::R, 255, false);
                }
            }
            if let Some(u) = ur_reg {
                put(&mut x.uuses, &mut x.spans, *u, 1, RegDom::UR, 64, false);
            }
        }
        Operand::Desc {
            ur_idx,
            base_reg,
            ..
        } => {
            put_ns(
                &mut x.uuses,
                &mut x.spans,
                *ur_idx,
                1,
                RegDom::UR,
                64,
                false,
                true, // desc[URx] is the descriptor-table namespace, not an architectural UR
            );
            if let Some(b) = base_reg {
                if *b != 255 {
                    // Q1: desc-form base is a single 32-bit offset register;
                    // the printed .64 is the effective-address width, not a
                    // register pair (table: address_suffix_widths.desc_base).
                    put(&mut x.ruses, &mut x.spans, *b, addr_widths().desc_base, RegDom::R, 255, false);
                }
            }
        }
        Operand::ConstMem {
            base_reg, ur_reg, ..
        } => {
            if let Some(b) = base_reg {
                if *b != 255 {
                    put(&mut x.ruses, &mut x.spans, *b, 1, RegDom::R, 255, false);
                }
            }
            if let Some(u) = ur_reg {
                put(&mut x.uuses, &mut x.spans, *u, 1, RegDom::UR, 64, false);
            }
        }
        _ => {}
    }
}

/// Def the destination operand (position 0) with modifier-derived width.
fn def_operand0(insn: &Instruction, x: &mut RegXfer, w: usize) {
    match insn.operands.first() {
        Some(Operand::Reg { num, .. }) if *num != 255 => {
            put(&mut x.rdefs, &mut x.spans, *num, w, RegDom::R, 255, true)
        }
        Some(Operand::UReg { num, is_zero, .. }) if !is_zero => {
            put(&mut x.udefs, &mut x.spans, *num, w, RegDom::UR, 64, true)
        }
        _ => {}
    }
}

/// Does this instruction carry any Reg/UReg operand (anywhere)?
fn has_reg_operands(insn: &Instruction) -> bool {
    insn.operands.iter().any(|o| {
        matches!(
            o,
            Operand::Reg { .. } | Operand::UReg { .. } | Operand::Addr { .. } | Operand::Desc { .. }
        ) || matches!(o, Operand::ConstMem { base_reg: Some(_), .. } | Operand::ConstMem { ur_reg: Some(_), .. })
    })
}

/// Count leading consecutive top-level Reg operands (dest quads of .256
/// memory forms). .256 loads/stores print TWO 128-bit base registers
/// (LDG.E.*.256 Rhi, Rlo, desc[..] / STG.E.*.256 desc[..], Ra, Rb): M3.5
/// census edge-votes DEF on pos1; each leading reg spans half the width.
fn leading_reg_operands(insn: &Instruction) -> usize {
    insn.operands
        .iter()
        .take_while(|o| matches!(o, Operand::Reg { .. }))
        .count()
}

/// Role class of a base opcode from tables/operand_roles.json (M3.5 data
/// table). None when the family is not in the table. Exposed for passes
/// that need the measured direction-class without the full transfer sets
/// (POSTFIX-103 v2 stallfix uniform/boundary rules).
pub fn role_class(base_op: &str) -> Option<&'static str> {
    roles_table().base_ops.get(base_op).map(|e| e.cls.as_str())
}

/// Register transfer sets for one instruction. Roles come from
/// tables/operand_roles.json (M3.5 data table); unknown base opcodes
/// carrying registers stay fail-closed.
pub fn reg_xfer(insn: &Instruction) -> RegXfer {
    let mut x = RegXfer {
        known: true,
        ..Default::default()
    };
    let w = dest_width(insn);
    let op = insn.opcode.as_str();
    let wide = insn.modifiers.iter().any(|m| m == ".WIDE");

    let Some(entry) = roles_table().base_ops.get(op) else {
        if has_reg_operands(insn) {
            // Unrecognized register-carrying family: fail closed.
            x.known = false;
        }
        // Predicate/imm-only instruction outside the table: nothing to track.
        return x;
    };

    // b9p13 (phase-3 #11): PLOP3 has two domains. The predicate-domain rows
    // (P_P_P_P_P_II_II, class "none") track nothing here; the b9p13 encode
    // row PLOP3_P_P_R_R_R_II_II (R.SIGN sign-inputs, add.sat.s32 family)
    // carries R operands. The roles table is keyed per base op (no per-sig
    // dispatch), so the SIGN shape gets a dedicated branch: every top-level
    // R operand is a USE (the .SIGN source registers; the sum dest appears
    // as its own IADD3 def). Pred dest stays pred-domain (M2 pred-liveness).
    // Evidence note: tables/operand_roles.json base_ops.PLOP3.
    if op == "PLOP3" {
        for o in &insn.operands {
            use_operand(o, &mut x, 1);
        }
        return x;
    }
    match entry.cls.as_str() {
        // Plain ALU / moves (R and UR twins): dest-first, rest read.
        "alu" => {
            def_operand0(insn, &mut x, w);
            for o in &insn.operands[1.min(insn.operands.len())..] {
                use_operand(o, &mut x, 1);
            }
            if wide {
                // 64-bit addend c reads the (c, c+1) pair. Over all grounded
                // WIDE forms the addend is the last NON-PREDICATE operand:
                // [dest,a,b,c], [dest,Pout,a,b,c(,Pin)]. If c is RZ or an
                // immediate, there is no pair read.
                let c = insn
                    .operands
                    .iter()
                    .skip(1)
                    .rev()
                    .find(|o| !matches!(o, Operand::Pred { .. } | Operand::UPred { .. }));
                match c {
                    Some(Operand::Reg { num, .. }) if *num != 255 => {
                        put(&mut x.ruses, &mut x.spans, *num, 2, RegDom::R, 255, false);
                    }
                    Some(Operand::UReg { num, is_zero, .. }) if !is_zero => {
                        put(&mut x.uuses, &mut x.spans, *num, 2, RegDom::UR, 64, false);
                    }
                    _ => {}
                }
            }
        }
        // Loads: dest width from modifier; address operands read.
        // .256 two-reg shape: two half-width dest quads (see
        // leading_reg_operands; census-verified, fixes the M3 hand rule).
        "load" => {
            let nlead = leading_reg_operands(insn);
            if w == 8 && nlead == 2 {
                def_operand0(insn, &mut x, 4);
                if let Some(Operand::Reg { num, .. }) = insn.operands.get(1) {
                    if *num != 255 {
                        put(&mut x.rdefs, &mut x.spans, *num, 4, RegDom::R, 255, true);
                    }
                }
                for o in &insn.operands[2.min(insn.operands.len())..] {
                    use_operand(o, &mut x, 1);
                }
            } else {
                def_operand0(insn, &mut x, w);
                for o in &insn.operands[1.min(insn.operands.len())..] {
                    use_operand(o, &mut x, 1);
                }
            }
        }
        // Stores / reductions (no return): no register def; every operand
        // read. Top-level data registers expand by the access width, split
        // per printed data register for the .256 two-reg shape.
        "store" => {
            let ndata = insn
                .operands
                .iter()
                .filter(|o| matches!(o, Operand::Reg { .. }))
                .count();
            let dw = if w == 8 && ndata == 2 { 4 } else { w };
            for o in &insn.operands {
                match o {
                    Operand::Reg { .. } => use_operand(o, &mut x, dw),
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        // Global atomics WITH return (sig P_R_dARI_R): the first top-level
        // register after the predicate output is the old-value destination
        // pair (consumers in R0b read both halves), everything else reads.
        "atomg" => {
            let mut first_reg_seen = false;
            for o in &insn.operands {
                match o {
                    Operand::Reg { num, .. } if !first_reg_seen && *num != 255 => {
                        put(&mut x.rdefs, &mut x.spans, *num, 2, RegDom::R, 255, true);
                        first_reg_seen = true;
                    }
                    Operand::Reg { .. } => use_operand(o, &mut x, w),
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        // Compares: no register def, all register operands read.
        "cmp" => {
            for o in &insn.operands {
                use_operand(o, &mut x, 1);
            }
        }
        // Shuffle (sig P_R_R_..): destination is the first REGISTER operand
        // (token 0 may be the predicate output), remaining registers read.
        "shfl" => {
            let mut first_reg_seen = false;
            for o in &insn.operands {
                match o {
                    Operand::Reg { num, .. } if !first_reg_seen && *num != 255 => {
                        put(&mut x.rdefs, &mut x.spans, *num, 1, RegDom::R, 255, true);
                        first_reg_seen = true;
                    }
                    _ => {
                        if first_reg_seen {
                            use_operand(o, &mut x, 1);
                        } else if matches!(o, Operand::Addr { .. } | Operand::Desc { .. }) {
                            use_operand(o, &mut x, 1);
                        }
                    }
                }
            }
        }
        // Branches / dispatch: no defs; UR operands read.
        "branch" => {
            for o in &insn.operands {
                use_operand(o, &mut x, 1);
            }
        }
        // MMA tuple forms (IMMA.16832-era): C-accumulator and D-dest are
        // 4-register tuples (encoder-validated quad alignment, BUG-037);
        // A/B source tuples are quads on the grounded sond form. v0 keeps
        // ONE width for every position (conservative; a narrower B-pair
        // variant must land as data with evidence first).
        // 64-bit FP ALU (DADD/DMUL/DFMA, BUG-118): the
        // destination is a register PAIR and every register source reads a
        // pair (vendor anchors: ptxas 13.3 sm_103a pd64/p17_f64 nvcc
        // cubins, "DADD R8, R4, R8" / "DFMA R4, R2, 1.5, R4", 2026-08-24).
        "f64alu" => {
            def_operand0(insn, &mut x, 2);
            for o in &insn.operands[1.min(insn.operands.len())..] {
                if let Operand::Reg { num, .. } = *o {
                    if num != 255 {
                        put(&mut x.ruses, &mut x.spans, num, 2, RegDom::R, 255, false);
                    }
                }
            }
        }
        // Float/int converts around f64 (BUG-118): the f64
        // half of the conversion spans the register pair. Type-slot
        // semantics differ per base op (vendor anchors: p17_f64 nvcc
        // sm_103a, "F2F.F64.F32 R8, R13" / corpus "F2I.F64.TRUNC R10, R6"):
        //   F2F.<dst>.<src>: dst type first, src second
        //   F2I.<F64>.TRUNC: single float suffix names the SOURCE (dst i32)
        //   I2F.<F64|..>*: dst is the float side (pair iff .F64 first), the
        //     integer source is always one 32-bit register
        "fcvt" => {
            let (wd, ws) = match insn.opcode.as_str() {
                "F2I" => (1, if insn.modifiers.iter().any(|m| m == ".F64") { 2 } else { 1 }),
                "I2F" => (if insn.modifiers.first().is_some_and(|m| m == ".F64") { 2 } else { 1 }, 1),
                // F2F and any other: both sides by modifier position,
                // conservative both-pairs when the shape is unclear.
                _ => (
                    if insn.modifiers.first().is_some_and(|m| m == ".F64") { 2 } else { 1 },
                    if insn.modifiers.get(1).is_some_and(|m| m == ".F64") { 2 } else { 1 },
                ),
            };
            def_operand0(insn, &mut x, wd);
            for o in &insn.operands[1.min(insn.operands.len())..] {
                if let Operand::Reg { num, .. } = *o {
                    if num != 255 {
                        put(&mut x.ruses, &mut x.spans, num, ws, RegDom::R, 255, false);
                    }
                }
            }
        }
        // Atomics with register return (ATOM/ATOMS, BUG-118):
        // the FIRST register operand is the destination (access width from
        // the .64 modifier: ATOM.E.CAS.STRONG.GPU = 32-bit, ATOMS.*.64 =
        // pair); every later register is a use (compare/value operands read
        // at the same width -- conservative is correct here).
        "atom" => {
            let mut first_reg_seen = false;
            for o in &insn.operands {
                match o {
                    Operand::Reg { num, .. } if !first_reg_seen && *num != 255 => {
                        put(&mut x.rdefs, &mut x.spans, *num, w, RegDom::R, 255, true);
                        first_reg_seen = true;
                    }
                    Operand::Reg { .. } => use_operand(o, &mut x, w),
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        // Uniform-result warp ops (ELECT/REDUX/CREDUX, BUG-118 gate
        // landing): the first non-zero UREG operand is the destination
        // (UR79 vendor scratch), remaining tracked operands are uses
        // (anchors: "ELECT P0, UR79, PT" / "REDUX.SUM UR79, R6", b9 p08/p10).
        "urdef_first" => {
            let mut ureg_dst_seen = false;
            for o in &insn.operands {
                match o {
                    Operand::UReg { num, is_zero, .. }
                        if !ureg_dst_seen && !is_zero =>
                    {
                        put(&mut x.udefs, &mut x.spans, *num, 1, RegDom::UR, 64, true);
                        ureg_dst_seen = true;
                    }
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        // ldmatrix (BUG-118): destination width is a quad only
        // SYNCS-family (BUG-118): the FIRST tracked register
        // operand is the destination state register (SYNCS.ARRIVE.TRANS64
        // [REDACTED-PAIR-lo|RZ], SYNCS.EXCH.64 URZ sink, ...); every later
        // operand is a use (addr brackets, UR state inputs).
        "syncs" => {
            let mut dst_seen = false;
            for o in &insn.operands {
                match o {
                    Operand::Reg { num, .. } if !dst_seen && *num != 255 => {
                        put(&mut x.rdefs, &mut x.spans, *num, 1, RegDom::R, 255, true);
                        dst_seen = true;
                    }
                    Operand::UReg { num, is_zero, .. } if !dst_seen && !is_zero => {
                        put(&mut x.udefs, &mut x.spans, *num, 1, RegDom::UR, 64, true);
                        dst_seen = true;
                    }
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        // on the .4 row (LDSM.16.M88.4 R20, [R16]); x1 is a single
        // register. Address bracket is a plain 32-bit shared offset.
        "ldsm" => {
            let w4 = insn.modifiers.iter().any(|m| m == ".4");
            def_operand0(insn, &mut x, if w4 { 4 } else { 1 });
            for o in &insn.operands[1.min(insn.operands.len())..] {
                use_operand(o, &mut x, 1);
            }
        }
        // stmatrix (mirror of ldsm): no register def; the data source is a
        // quad on .4, single register otherwise; address is a use.
        "stsm" => {
            let w4 = insn.modifiers.iter().any(|m| m == ".4");
            for o in &insn.operands {
                match o {
                    Operand::Reg { .. } => use_operand(o, &mut x, if w4 { 4 } else { 1 }),
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        "mma" => {
            // MMA tuple quads. Alignment per operand position follows the
            // silicon-measured BUG-037 legality table (encoder errata,
            // for IMMA/QMMA.16832(.F32) and HMMA.16816.F32 the
            // rule per position is D%4 A%4 B%2 C%4 (HMMA.1688.F32 has a
            // single-register B of any alignment; unidentified families keep
            // the encoder's previous acceptance -- mirrored loosely here as
            // the same D/A/B/C vector, which is the measured common shape of
            // the sond corpus IMMA.16832.S8.S8).
            const MMA_ALIGN: [u8; 4] = [4, 4, 2, 4];
            for (idx, o) in insn.operands.iter().enumerate() {
                let is_dest = idx == 0;
                let align = MMA_ALIGN.get(idx).copied().unwrap_or(4);
                match o {
                    Operand::Reg { num, .. } if *num != 255 => {
                        let set = if is_dest { &mut x.rdefs } else { &mut x.ruses };
                        // BUG-118: HMMA.16816's B fragment is a
                        // 64-bit PAIR (%2 align already implied this); the
                        // lowerer emits only the pair and the b10 matrix's
                        // mma-f16 A/B PASSes prove the pair shape on silicon.
                        // Other families keep the conservative quad.
                        let bw = if insn.opcode == "HMMA"
                            && insn.modifiers.iter().any(|m| m == ".16816")
                            && idx == 2
                        {
                            2
                        } else {
                            4
                        };
                        put_aligned(set, &mut x.spans, *num, bw, RegDom::R, 255, is_dest, align);
                    }
                    Operand::UReg { num, is_zero, .. } if !is_zero => {
                        let set = if is_dest { &mut x.udefs } else { &mut x.uuses };
                        put_aligned(set, &mut x.spans, *num, 4, RegDom::UR, 64, is_dest, align);
                    }
                    _ => use_operand(o, &mut x, 1),
                }
            }
        }
        // System-register reads / uniform moves: dest-only.
        "dest_only" => {
            def_operand0(insn, &mut x, 1);
        }
        // CS2R from a 64-bit system register (BUG-118): the
        // hardware writes the whole even PAIR even though only the low
        // register prints (vendor anchor: ptxas 13.3 sm_103a gt.ptx probe
        // 2026-08-24 -- "CS2R R4, SR_GLOBALTIMERLO; STG.E.64 [..], R4").
        // 32-bit SRs keep the single-register def.
        "cs2r" => {
            let pair = insn.operands.iter().any(|o| matches!(
                o, Operand::SysReg(name) if name.ends_with("LO")
            ));
            def_operand0(insn, &mut x, if pair { 2 } else { 1 });
        }
        // Predicate-only or operand-free: known, empty reg xfer.
        "none" => {}
        other => {
            // Corrupt table entry: fail closed rather than guess.
            if has_reg_operands(insn) {
                x.known = false;
            }
            debug_assert!(false, "unknown operand-role class {other}");
        }
    }
    apply_desc_addr_pair_align(insn, &mut x.spans);
    x
}

/// BUG-076/078 silicon alignment: desc-form 64-bit address operands
/// (desc[URm][Rn.64]) of stores/atomics require an EVEN pair base on
/// sm_103a (encoder guards fail-closed scoped-103; see encoder.rs).
/// Split of concern: span WIDTH stays 1 here (Q1 corpus semantics: the
/// producer dataflow covers the low half only) while the ALIGN mark on
/// the base span tells full-RA to place the base on an even boundary and
/// reserve base+1 atomically (ra_full build_groups union) -- even bases
/// are legal on every arch, so this stops full-RA from *planning* a
/// rename the assembler would reject (surfaced 2026-08-22 by G15a2 after
/// the pin advanced past the guards: m9a_im_ix planned desc[UR0][R7.64]).
/// Exemptions mirror the guard exactly: ELL2/EFL2 mod classes render
/// [Rn.U32+URm] (no register pair). LDG desc pairs stay unconstrained on
/// purpose: odd-base ENL2-load is 066-kand flaky, asm does not reject.
fn apply_desc_addr_pair_align(insn: &Instruction, spans: &mut [RegSpan]) {
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    // Guards mirrored 1:1 (encoder.rs): BUG-076 covers STG with ELL2/EFL2
    // exempt; BUG-078 covers ATOMG/REDG with .EL exempt (single-offset desc
    // mode [Rn.U32+URm], no register pair in the word at all). ATOM/ATOMS/
    // RED and all LDG carry no encoder guard -> no allocator constraint
    // either (066-kand flaky-park documented in the guards).
    let covered = match insn.opcode.as_str() {
        "STG" => !mods.split(',').any(|m| m == "ELL2" || m == "EFL2"),
        "ATOMG" | "REDG" => !mods.split(',').any(|m| m == "EL"),
        _ => false,
    };
    if !covered {
        return;
    }
    for op in &insn.operands {
        if let Operand::Desc {
            base_reg: Some(r),
            base_reg_suffix: Some(sfx),
            ..
        } = op
        {
            if sfx == "64" {
                for sp in spans.iter_mut() {
                    if sp.dom == RegDom::R && sp.base == *r && !sp.desc_ns {
                        sp.align = sp.align.max(2);
                    }
                }
            }
        }
    }
}

/// Per-instruction register liveness record.
#[derive(Debug, Clone)]
pub struct InsRegLive {
    pub addr: u32,
    pub opcode_full: String,
    pub raw_text: String,
    pub succ: Vec<usize>,
    pub rdefs: BTreeSet<u8>,
    pub ruses: BTreeSet<u8>,
    pub udefs: BTreeSet<u8>,
    pub uuses: BTreeSet<u8>,
    pub rlive_in: BTreeSet<u8>,
    pub rlive_out: BTreeSet<u8>,
    pub ulive_in: BTreeSet<u8>,
    pub known: bool,
}

pub fn liveness(insns: &[Instruction]) -> Vec<InsRegLive> {
    let n = insns.len();
    let xfer: Vec<RegXfer> = insns.iter().map(reg_xfer).collect();
    let succ: Vec<Vec<usize>> = (0..n).map(|i| cfg_successors(insns, i)).collect();
    let (rin, rout) = backward_liveness(
        &succ,
        &xfer.iter().map(|x| x.rdefs.clone()).collect::<Vec<_>>(),
        &xfer.iter().map(|x| x.ruses.clone()).collect::<Vec<_>>(),
    );
    let (uin, _uout) = backward_liveness(
        &succ,
        &xfer.iter().map(|x| x.udefs.clone()).collect::<Vec<_>>(),
        &xfer.iter().map(|x| x.uuses.clone()).collect::<Vec<_>>(),
    );
    insns
        .iter()
        .enumerate()
        .map(|(i, ins)| InsRegLive {
            addr: ins.addr,
            opcode_full: ins.opcode_full.clone(),
            raw_text: ins.raw_text.clone(),
            succ: succ[i].clone(),
            rdefs: xfer[i].rdefs.clone(),
            ruses: xfer[i].ruses.clone(),
            udefs: xfer[i].udefs.clone(),
            uuses: xfer[i].uuses.clone(),
            rlive_in: rin[i].clone(),
            rlive_out: rout[i].clone(),
            ulive_in: uin[i].clone(),
            known: xfer[i].known,
        })
        .collect()
}

pub struct KernelRegLiveness {
    pub name: String,
    pub ins: Vec<InsRegLive>,
    pub unknown_ops: Vec<String>,
}

pub fn liveness_file(text: &str) -> anyhow::Result<Vec<KernelRegLiveness>> {
    let file = crate::sass_file::parse_sass_file_str_strict(text)?;
    let mut out = Vec::new();
    for k in &file.kernels {
        let ins = liveness(&k.instructions);
        let unk: Vec<String> = ins
            .iter()
            .filter(|r| !r.known)
            .map(|r| format!("{} @0x{:x}", r.opcode_full, r.addr))
            .collect();
        out.push(KernelRegLiveness {
            name: k.name.clone(),
            ins,
            unknown_ops: unk,
        });
    }
    Ok(out)
}
