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
use std::collections::BTreeSet;

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
    // The parser stores address-base suffixes without the leading dot
    // (e.g. "64" for [R210.64]). Only ".64" is a register-PAIR span;
    // X-suffixed forms ([R5.X16] in STS/LDS) are address SCALING on a
    // single register (grounded: STS.128 [R5.X16] smem bank math).
    match suffix.as_deref() {
        Some(".64") | Some("64") => 2,
        _ => 1,
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
            base_reg_suffix,
            ..
        } => {
            put(&mut x.uuses, *ur_idx, 1, 64);
            if let Some(b) = base_reg {
                if *b != 255 {
                    put(&mut x.ruses, *b, suffix_width(base_reg_suffix), 255);
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

/// Register transfer sets for one instruction.
pub fn reg_xfer(insn: &Instruction) -> RegXfer {
    let mut x = RegXfer {
        known: true,
        ..Default::default()
    };
    let w = dest_width(insn);
    let op = insn.opcode.as_str();
    let wide = insn.modifiers.iter().any(|m| m == ".WIDE");

    let handled = match op {
        // Plain ALU / moves (R and UR twins): dest-first, rest read.
        "IADD3" | "IMAD" | "LOP3" | "SHF" | "IABS" | "LEA" | "I2FP" | "MOV" | "IMNMX"
        | "UIMAD" | "UIADD3" | "UMOV" | "ULOP3" => {
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
            true
        }
        // Loads: dest width from modifier; address operands read.
        "LDG" | "LDCU" | "LDS" => {
            def_operand0(insn, &mut x, w);
            for o in &insn.operands[1.min(insn.operands.len())..] {
                use_operand(o, &mut x, 1);
            }
            true
        }
        // Stores / reductions (no return): no register def; every operand
        // read. Top-level data registers expand by the access width.
        "STG" | "STS" | "REDG" => {
            for o in &insn.operands {
                match o {
                    Operand::Reg { .. } => use_operand(o, &mut x, w),
                    _ => use_operand(o, &mut x, 1),
                }
            }
            true
        }
        // Global atomics WITH return (sig P_R_dARI_R): the first top-level
        // register after the predicate output is the old-value destination
        // pair (consumers in R0b read both halves), everything else reads.
        "ATOMG" => {
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
            true
        }
        // Compares: no register def, all register operands read.
        "ISETP" | "UISETP" => {
            for o in &insn.operands {
                use_operand(o, &mut x, 1);
            }
            true
        }
        // Shuffle (sig P_R_R_..): destination is the first REGISTER operand
        // (token 0 may be the predicate output), remaining registers read.
        "SHFL" => {
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
            true
        }
        // Branches / dispatch: no defs; UR operands read (BRXU.U UR30,
        // BRA.DIV ... URZ excluded as zero-sink).
        "BRA" | "BRXU" | "BRX" | "JMP" | "RET" | "CALL" | "BSSY" | "BSYNC" => {
            for o in &insn.operands {
                use_operand(o, &mut x, 1);
            }
            true
        }
        // System-register reads / uniform moves: dest-only.
        "S2R" | "S2UR" | "CS2R" | "R2UR" => {
            def_operand0(insn, &mut x, 1);
            true
        }
        // Predicate-only or operand-free: known, empty reg xfer.
        "VOTEU" | "PLOP3" | "NOP" | "EXIT" | "BAR" | "DEPBAR" | "KILL" => true,
        _ => false,
    };

    if !handled {
        if has_reg_operands(insn) {
            // Unrecognized register-carrying family: fail closed.
            x.known = false;
            x.rdefs.clear();
            x.ruses.clear();
            x.udefs.clear();
            x.uuses.clear();
        }
        // Predicate/imm-only instruction outside the table: nothing to track.
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
