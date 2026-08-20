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

#[derive(Debug, Clone, Default)]
pub struct RegXfer {
    pub rdefs: BTreeSet<u8>,
    pub ruses: BTreeSet<u8>,
    pub udefs: BTreeSet<u8>,
    pub uuses: BTreeSet<u8>,
    pub known: bool,
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

fn put(set: &mut BTreeSet<u8>, num: u8, w: usize, dom_max_excl: u32) {
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
                put(&mut x.ruses, *num, width, 255);
            }
        }
        Operand::UReg { num, is_zero, .. } => {
            if !is_zero {
                put(&mut x.uuses, *num, width, 64);
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
                    put(&mut x.ruses, *b, suffix_width(base_reg_suffix), 255);
                }
            }
            if let Some(u) = ur_reg {
                put(&mut x.uuses, *u, 1, 64);
            }
        }
        Operand::Desc {
            ur_idx,
            base_reg,
            ..
        } => {
            put(&mut x.uuses, *ur_idx, 1, 64);
            if let Some(b) = base_reg {
                if *b != 255 {
                    // Q1: desc-form base is a single 32-bit offset register;
                    // the printed .64 is the effective-address width, not a
                    // register pair (table: address_suffix_widths.desc_base).
                    put(&mut x.ruses, *b, addr_widths().desc_base, 255);
                }
            }
        }
        Operand::ConstMem {
            base_reg, ur_reg, ..
        } => {
            if let Some(b) = base_reg {
                if *b != 255 {
                    put(&mut x.ruses, *b, 1, 255);
                }
            }
            if let Some(u) = ur_reg {
                put(&mut x.uuses, *u, 1, 64);
            }
        }
        _ => {}
    }
}

/// Def the destination operand (position 0) with modifier-derived width.
fn def_operand0(insn: &Instruction, x: &mut RegXfer, w: usize) {
    match insn.operands.first() {
        Some(Operand::Reg { num, .. }) if *num != 255 => put(&mut x.rdefs, *num, w, 255),
        Some(Operand::UReg { num, is_zero, .. }) if !is_zero => {
            put(&mut x.udefs, *num, w, 64)
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
                        put(&mut x.ruses, *num, 2, 255);
                    }
                    Some(Operand::UReg { num, is_zero, .. }) if !is_zero => {
                        put(&mut x.uuses, *num, 2, 64);
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
                        put(&mut x.rdefs, *num, 4, 255);
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
                        put(&mut x.rdefs, *num, 2, 255);
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
                        put(&mut x.rdefs, *num, 1, 255);
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
        // System-register reads / uniform moves: dest-only.
        "dest_only" => {
            def_operand0(insn, &mut x, 1);
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
    x
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
