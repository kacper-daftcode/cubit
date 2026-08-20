//! Per-modifier-group field-based encoder.
//!
//! Encoding pipeline:
//! 1. Look up (InsKey, mod_group) → {and_base, fields}
//! 2. enc = and_base
//! 3. For each field: enc |= extract(operand, extraction) << shift
//! 4. Apply branch encoding (BRA/BSSY/BRX/RET)
//! 5. Inject scheduling bits [127:105]

use crate::ir::{Instruction, Operand};
use crate::scheduling;
use crate::table::{IsaTable, Field, Extraction};
use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// System register IDs
// ---------------------------------------------------------------------------
fn sysreg_id(name: &str) -> u64 {
    match name {
        "SR_LANEID" => 0x00,
        "SR_TID.X" | "SR_TID_X" => 0x21,
        "SR_TID.Y" | "SR_TID_Y" => 0x22,
        "SR_TID.Z" | "SR_TID_Z" => 0x23,
        "SR_CTAID.X" | "SR_CTAID_X" => 0x25,
        "SR_CTAID.Y" | "SR_CTAID_Y" => 0x26,
        "SR_CTAID.Z" | "SR_CTAID_Z" => 0x27,
        "SR_SWINHI" | "SR_0x002f" => 0x2f,
        "SR_LTMASK" => 0x39,
        "SR_LEMASK" => 0x3a,
        "SR_GTMASK" => 0x3b,
        "SR_GEMASK" => 0x3c,
        "SR_VIRTUALSMID" => 0x43,
        "SR_CLOCKLO" => 0x50,
        "SR_CLOCKHI" => 0x51,
        "SR_GLOBALTIMERLO" => 0x52,
        "SR_CgaCtaId" => 0x88,
        "SR_CgaSize" => 0x8a,
        "SRZ" => 0xff,
        // Unknown/arch-specific SR printed by the decoder as SR_0x<hex> —
        // keep the raw code bit-exact instead of dropping it to 0.
        _ => match name.strip_prefix("SR_0x") {
            Some(h) => u64::from_str_radix(h, 16).unwrap_or(0),
            None => 0,
        },
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Build the "full key" variant: opcode_full (with dots) + operand type suffixes.
/// E.g. "HMMA.16816.F32 R16, R8, R12, RZ" → "HMMA.16816.F32_R_R_R_R"
fn full_key(insn: &Instruction) -> String {
    // Strip ?N opaque modifier parts from the opcode (e.g. "ISETP.EQ.AND.?6.?0" → "ISETP.EQ.AND")
    let clean_opcode: String = insn.opcode_full.split('.')
        .filter(|p| !p.is_empty() && !p.starts_with('?'))
        .collect::<Vec<_>>()
        .join(".");
    let mut key = clean_opcode;
    for op in &insn.operands {
        key.push('_');
        key.push_str(crate::parser::operand_type_label_pub(op));
    }
    key
}

/// Operand kinds acceptable for a value-carrying extraction. Mirrors exactly what
/// the `op_*` helpers below handle; any other combination would silently fall into
/// the helper's `_ => 0` default and encode garbage (hardware-confirmed: an imm-form
/// ISETP picking a register-form table entry encodes the immediate as R0).
fn extraction_accepts(ext: &Extraction, op: &Operand) -> bool {
    use Extraction::*;
    match ext {
        // Flags / guard / opaque mods are non-discriminating: they read optional
        // attributes (neg/abs/reuse/...) and legitimately default to 0.
        Guard | GuardLo3 | GuardNeg | Neg | NegShl1 | Reuse | Inv | Abs | NegAbs
        | ByteSel | HalfSel | OpaqueModifier | OpModFlag(_) | MnemMod(..)
        | UrExpl | UrExplInv | YieldInv | AddrScale | None => true,

        Reg | RegShr(_) => matches!(op,
            Operand::Reg { .. } | Operand::Addr { .. } | Operand::Desc { .. }),
        RegFf => matches!(op, Operand::Reg { .. } | Operand::UReg { .. }),
        UReg | URegShr(_) => matches!(op,
            Operand::UReg { .. } | Operand::Addr { .. } | Operand::Desc { .. }),
        URegFf => matches!(op, Operand::UReg { .. }),
        Pred => matches!(op, Operand::Pred { .. } | Operand::UPred { .. }),
        Barrier => matches!(op, Operand::Barrier(_)),

        // RZ/URZ are accepted by imm extractions: the helper returns 0, which is
        // exactly the register's architectural value (several harvested entries
        // are imm-form encodings that production kernels feed RZ through).
        Imm | ImmShr(_) => matches!(op,
            Operand::Imm32(_) | Operand::Imm64(_) | Operand::BranchTarget(_)
            | Operand::FloatImm(_) | Operand::Desc { .. } | Operand::Addr { .. }
            | Operand::Label(_)
            | Operand::Reg { num: 255, .. } | Operand::UReg { is_zero: true, .. }),
        ImmDec | ImmDecU32 => matches!(op, Operand::Imm32(_) | Operand::Label(_)
            | Operand::Reg { num: 255, .. } | Operand::UReg { is_zero: true, .. }),

        F32 | F64hi => matches!(op, Operand::FloatImm(_) | Operand::Imm32(_)),
        LblPat(_) => matches!(op, Operand::Label(_) | Operand::Desc { .. }),
        F16 | F16d | BF16 => matches!(op, Operand::FloatImm(_)),

        SysReg | SysRegLo7 | SysRegLo4 | SysRegHi4 | SysRegHi1 =>
            matches!(op, Operand::SysReg(_)),

        SubR(_) | SubRShr(..) | SubUR(_) | SubURShr(..) | SubURm1(_)
        | SubImm(_) | SubImmS24(_) | SubImmShr(..) => matches!(op,
            Operand::Addr { .. } | Operand::Desc { .. } | Operand::ConstMem { .. }),
        Cm16Off | Cm17Off => matches!(op, Operand::ConstMem { .. }),
    }
}

/// True when `ext` can encode a register NUMBER for the operand (not just RZ-ness).
fn ext_encodes_reg(ext: &Extraction) -> bool {
    matches!(ext, Extraction::Reg | Extraction::RegShr(_)
        | Extraction::SubR(_) | Extraction::SubRShr(..))
}

fn ext_encodes_ureg(ext: &Extraction) -> bool {
    matches!(ext, Extraction::UReg | Extraction::URegShr(_) | Extraction::URegFf
        | Extraction::SubUR(_) | Extraction::SubURShr(..)
        | Extraction::SubURm1(_))
}

fn ext_encodes_imm(ext: &Extraction) -> bool {
    matches!(ext, Extraction::Imm | Extraction::ImmShr(_) | Extraction::ImmDec
        | Extraction::ImmDecU32 | Extraction::F32 | Extraction::F64hi
        | Extraction::SubImm(_) | Extraction::SubImmS24(_) | Extraction::SubImmShr(..)
        | Extraction::Cm16Off | Extraction::Cm17Off
        | Extraction::F16 | Extraction::F16d | Extraction::BF16)
}

/// Validate that a table entry's field extractions are compatible with the
/// instruction's actual operands. Two checks:
///
/// 1. TYPE: every field whose token references an existing operand must use an
///    extraction that can read that operand kind (see `extraction_accepts`).
/// 2. COMPLETENESS: every operand carrying a non-default payload (a non-RZ
///    register, non-PT predicate, non-zero immediate, ...) must have at least one
///    field able to encode that payload. Catches fully-baked bad harvests (e.g. a
///    count=2 FSETP entry with register numbers baked into and_base) that would
///    otherwise silently encode the harvest-time operands instead of the real ones.
///
/// Fields referencing tokens beyond the operand list are ignored — that is the
/// documented `{fk}_?` wildcard-suffix behavior (extra trailing operand defaults).
fn entry_matches_operands(insn: &Instruction, entry: &crate::table::ModGroupEntry) -> std::result::Result<(), String> {
    // Branch-family operands (targets, RET register, BRA.U upred) are encoded by
    // apply_branch_encoding, not by table fields.
    if BRANCH_OPS.iter().any(|&o| insn.opcode == o) { return Ok(()); }
    // Raw-address LDG/STG bypass the field system entirely (full lo64 rebuild).
    if (insn.opcode == "LDG" || insn.opcode == "STG")
        && insn.operands.iter().any(|op| matches!(op, Operand::Addr { .. }))
        && !insn.operands.iter().any(|op| matches!(op, Operand::Desc { .. })) {
        return Ok(());
    }

    // 1. Type check
    for field in &entry.fields {
        if let Some(op) = get_op(insn, field.token_idx) {
            if !extraction_accepts(&field.extraction, op) {
                return Err(format!(
                    "field (shift={} ext={:?}) expects a different operand kind than \
                     operand {} ({})",
                    field.shift, field.extraction, field.token_idx,
                    crate::parser::operand_type_label_pub(op)));
            }
        }
    }

    // 2. Completeness check
    let is_mem_load = matches!(insn.opcode.as_str(),
        "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "ATOM" | "ATOMS" | "ATOMG" |
        "RED" | "REDG" | "LDSM" | "LDGSTS" | "LD" | "LDGX");
    for (oi, op) in insn.operands.iter().enumerate() {
        let tok = (oi + 1) as i32;
        let fields_for_tok = || entry.fields.iter().filter(move |f| f.token_idx == tok);
        let missing = |what: &str| Err(format!(
            "operand {tok} ({what}) has no field able to encode it"));
        match op {
            Operand::Reg { num, .. } if *num != 255 => {
                // Memory-load destination (operand 1) is placed at bits[23:16] by the
                // encoder fixup even when the entry lacks the field.
                if is_mem_load && oi == 0 { continue; }
                if !fields_for_tok().any(|f| ext_encodes_reg(&f.extraction)) {
                    return missing(&format!("R{num}"));
                }
            }
            Operand::UReg { num, is_zero: false, .. } => {
                if !fields_for_tok().any(|f| ext_encodes_ureg(&f.extraction)) {
                    return missing(&format!("UR{num}"));
                }
            }
            Operand::Pred { num, .. } | Operand::UPred { num, .. } if *num != 7 => {
                if !fields_for_tok().any(|f| matches!(f.extraction, Extraction::Pred)) {
                    return missing(&format!("P{num}"));
                }
            }
            Operand::Imm32(v) if *v != 0 => {
                if !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)) {
                    return missing(&format!("imm 0x{v:x}"));
                }
            }
            Operand::Imm64(v) if *v != 0 => {
                if !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)) {
                    return missing(&format!("imm 0x{v:x}"));
                }
            }
            Operand::FloatImm(bits) if *bits != 0 => {
                if !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)
                    || matches!(f.extraction, Extraction::F16 | Extraction::F16d)) {
                    return missing("float imm");
                }
            }
            Operand::SysReg(name) if sysreg_id(name) != 0 => {
                if !fields_for_tok().any(|f| matches!(f.extraction,
                    Extraction::SysReg | Extraction::SysRegLo7 | Extraction::SysRegLo4
                    | Extraction::SysRegHi4 | Extraction::SysRegHi1)) {
                    return missing(name);
                }
            }
            Operand::Barrier(b) if *b != 0 => {
                if !fields_for_tok().any(|f| matches!(f.extraction, Extraction::Barrier)) {
                    return missing(&format!("B{b}"));
                }
            }
            Operand::Addr { ur_reg, offset, .. } => {
                // base_reg is placed at bits[31:24] by the encoder fixup when the
                // entry lacks the field, so it is always encodable.
                if ur_reg.is_some_and(|u| u != 63)
                    && !fields_for_tok().any(|f| ext_encodes_ureg(&f.extraction)) {
                    return missing("addr UR");
                }
                if *offset != 0 && !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)) {
                    return missing(&format!("addr offset 0x{offset:x}"));
                }
            }
            Operand::Desc { base_reg, offset, .. } => {
                // ur_idx defaults via op_ureg/op_sub_ureg; base_reg via the Addr-style
                // fixup does NOT apply to Desc, so require fields for the varying parts.
                if base_reg.is_some_and(|r| r != 255)
                    && !fields_for_tok().any(|f| ext_encodes_reg(&f.extraction)) {
                    return missing("desc base reg");
                }
                if *offset != 0 && !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)) {
                    return missing(&format!("desc offset 0x{offset:x}"));
                }
            }
            Operand::ConstMem { bank, offset, base_reg, ur_reg, .. } => {
                let has_cm = |f: &&Field| matches!(f.extraction,
                    Extraction::Cm16Off | Extraction::Cm17Off);
                if *bank != 0 && !fields_for_tok().any(|f| has_cm(&f)
                    || matches!(f.extraction, Extraction::SubImm(0))) {
                    return missing(&format!("c[0x{bank:x}] bank"));
                }
                if *offset != 0 && !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)) {
                    return missing(&format!("c[][0x{offset:x}] offset"));
                }
                if base_reg.is_some_and(|r| r != 255)
                    && !fields_for_tok().any(|f| ext_encodes_reg(&f.extraction)) {
                    return missing("constmem base reg");
                }
                if ur_reg.is_some_and(|u| u != 63)
                    && !fields_for_tok().any(|f| ext_encodes_ureg(&f.extraction)) {
                    return missing("constmem UR");
                }
            }
            _ => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Errata guards — sm120lab silicon findings (results/cubit-bugs BUG-001..011,
// 2026-08-18). Each rule converts a previously SILENT mis-encode into a hard
// assembler error (fail-closed) or, where the encoding exists, a table fix.
// ---------------------------------------------------------------------------

/// BUG-004 (+guards): predicate literals >= 7 are not real predicates. Index 7
/// is the always-true PT/UPT; text `P7` used to alias to it SILENTLY
/// (3-bit field), making every @P7 / ->P7 fire on all lanes. `P8+` is worse:
/// the parser produced a truncated/garbage index. Scan raw_text (the IR alone
/// cannot tell `PT` from literal `P7`) and refuse with a clear message.
fn check_pred_literal_errata(insn: &Instruction) -> Result<()> {
    use std::sync::LazyLock;
    static RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        // Candidate: optional guard-marker/'!', optional U, 'P', digits.
        // (Delimiter checks are done in code — the regex crate has no
        // lookahead.) Labels like `P8_loop` and opcodes like `R2P` are
        // rejected by the boundary tests below.
        regex::Regex::new(r"!?(?:UP|P)[0-9]+").unwrap()
    });
    let bytes = insn.raw_text.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for m in RE.find_iter(&insn.raw_text) {
        // Left boundary: start / whitespace / ',' / '@' / '!'. Right boundary:
        // whitespace / ',' / ';' / ']' / ')' / '+' / end.
        let left_ok = m.start() == 0
            || matches!(bytes[m.start() - 1], b' ' | b'\t' | b',' | b'@' | b'!');
        let right_ok = m.end() == insn.raw_text.len()
            || !is_ident(bytes[m.end()]);
        if !left_ok || !right_ok {
            continue;
        }
        let digits_start = insn.raw_text[m.start()..].find(|c: char| c.is_ascii_digit())
            .map(|i| i + m.start()).unwrap_or(m.end());
        let n: u32 = insn.raw_text[digits_start..m.end()].parse().unwrap_or(0);
        if n >= 7 {
            let tok = insn.raw_text[m.start()..m.end()].trim_start_matches('!');
            anyhow::bail!(
                "invalid predicate literal `{tok}` in {:?}: predicate space is P0..P6                  plus PT (always-true). Predicate index 7 *is* PT — writing `{tok}` used                  to alias to PT silently, firing on ALL lanes (BUG-004). Use PT (or a real                  predicate P0..P6).",
                insn.raw_text.trim()
            );
        }
    }
    // IR-level belt: operand/guard predicate indices >= 8 can also arrive via
    // programmatic IR construction (no raw_text token to catch them).
    for op in &insn.operands {
        let n = match op {
            Operand::Pred { num, .. } | Operand::UPred { num, .. } => Some(*num),
            _ => None,
        };
        if let Some(n) = n {
            if n > 7 {
                anyhow::bail!(
                    "predicate index {n} out of range (P0..P6 + PT=7) in {:?}",
                    insn.raw_text.trim()
                );
            }
        }
    }
    Ok(())
}

/// BUG-002: `IMAD.HI[.U32]` on sm_120. The table once carried harvested
/// "HI" encodings, but silicon runs those words as IMAD.WIDE.U32: Rd gets the
/// LOW half and Rd+1 is CLOBBERED by the high half (iter60 hi_t.sass). The
/// poisoned entries were removed from tables/sm120.json; this guard keeps any
/// `.HI` IMAD text fail-closed unless the chosen table entry actually carries
/// the HI modifier (i.e. a future, hardware-true HI encoding would pass).
fn check_imad_hi_erratum(insn: &Instruction, table: &IsaTable, sel_key: &str, sel_mg: &str) -> Result<()> {
    let is_imad = insn.opcode == "IMAD";
    let has_hi = insn.modifiers.iter().any(|m| m == ".HI");
    if !is_imad || !has_hi {
        return Ok(());
    }
    let key_covers_hi = sel_key.starts_with("IMAD.HI") || sel_key.contains(".HI_") || sel_key.contains(".HI.");
    let mg_covers_hi = sel_mg.split(',').any(|m| m == "HI");
    if table.target_sm() != 120 && (key_covers_hi || mg_covers_hi) {
        return Ok(()); // entry explicitly encodes the HI modifier (non-120 arch)
    }
    // On sm_120 no harvested entry is trustworthy: silicon proved the "HI"
    // encodings execute as IMAD.WIDE.U32 regardless of which entry matched.
    anyhow::bail!(
        "IMAD.HI is NOT encodable on this target: sm_120 silicon executes the          harvested `IMAD.HI` encodings as IMAD.WIDE.U32 — Rd receives the LOW half          and Rd+1 is silently CLOBBERED (BUG-002, silicon-verified). Use          `IMAD.WIDE[.U32] Rd, Ra, Rb, RZ` (or the 5-operand pout form) and read the          high half from Rd+1."
    )
}

/// BUG-008 shape detector: 4+-operand `IMAD.WIDE[.U32][.X]` WITHOUT a
/// destination predicate whose c accumulator is not RZ. Silicon reads the c
/// operand of a wide IMAD as the 64-BIT PAIR (Rc, Rc+1) — so the encoded word
/// implicitly consumes a register the text never names (Rc+1), and the hi half
/// of the result silently includes its content. The 5-operand pout form
/// (`IMAD.WIDE.U32 Rd, Pn, Ra, Rb, Rc`, PT legal) makes the pair-c semantics
/// canonical; `c = RZ` zero-extends safely. ptxas emits the bare 4-op form too,
/// so this stays a WARNING (the word itself is encodable/possibly-intended).
fn imad_wide_implicit_cpair(insn: &Instruction, table: &IsaTable) -> bool {
    if insn.opcode != "IMAD" || !insn.modifiers.iter().any(|m| m == ".WIDE") {
        return false;
    }
    if table.target_sm() != 120 {
        return false;
    }
    if matches!(insn.operands.get(1), Some(Operand::Pred { .. } | Operand::UPred { .. })) {
        return false;
    }
    let n = insn.operands.len();
    if n < 4 {
        return false;
    }
    let has_x = insn.modifiers.iter().any(|m| m == ".X");
    let c_idx = if has_x && matches!(insn.operands.last(), Some(Operand::Pred { .. } | Operand::UPred { .. })) {
        n - 2
    } else {
        n - 1
    };
    if c_idx < 3 {
        return false;
    }
    match &insn.operands[c_idx] {
        Operand::Reg { num, .. } => *num != 255,
        _ => true,
    }
}

/// BUG-006: a NEGATED predicate operand whose slot has no negation encoding in
/// the selected form must never silently degrade to the non-negated predicate
/// (silicon then reads the un-negated value — iter64 measured exactly that on
/// IMAD.WIDE.U32.X carry-in). Re-encode with the negation flipped; a
/// bit-identical word proves the neg bit has no representation here.
fn check_pred_neg_encoded(insn: &Instruction, table: &IsaTable, out: u128) -> Result<()> {
    // Scoped to `.X` carry-chain forms: their tail carry-in predicate is a
    // REAL architectural operand (silicon reads cin — iter64 measured the
    // dropped-neg failure). Elsewhere a trailing `!PT` is a vestigial
    // print-convention (LOP3.LUT's operand 6 is always !PT in production
    // cubins and is not silicon-read), so dropping neg there is pre-existing,
    // harmless behavior that must not become a hard error.
    if !insn.modifiers.iter().any(|m| m == ".X") {
        return Ok(());
    }
    for (i, op) in insn.operands.iter().enumerate() {
        let negated = matches!(op,
            Operand::Pred { neg: true, .. } | Operand::UPred { neg: true, .. });
        if !negated {
            continue;
        }
        let mut flipped = insn.clone();
        match &mut flipped.operands[i] {
            Operand::Pred { neg, .. } | Operand::UPred { neg, .. } => *neg = false,
            _ => unreachable!(),
        }
        if let Ok(other) = encode_instruction_inner(&flipped, table, false) {
            if other == out {
                anyhow::bail!(
                    "operand {} of {:?} is a negated predicate but this form has no                      negation bit for that slot: the `!` would be silently DROPPED                      (BUG-006; silicon reads the UN-negated predicate). Negate the                      producer instead (e.g. ISETP into a dedicated always-false                      predicate), or pick a form whose carry/predicate slot supports                      negation.",
                    i + 1,
                    insn.raw_text.trim()
                );
            }
        }
    }
    Ok(())
}

/// Soft errata (warn, don't refuse): conditions that encode fine but are
/// silicon traps on specific targets. Human-facing drivers print these
/// BUG-034 (HW quirk, sm_120 silicon, results/s4/i94_b34): the dest-UP
/// selector (3 bits @[83:81]) is encodable and nvdisasm-renderable for every
/// value 0..7, but on the UIADD3 cout slot values 0 and 1 are DEAD WRITES
/// (the carry result silently never lands in UP0/UP1), and on the UFSETP dest
/// slot value 0 is a DEAD WRITE. VOTEU writes UP0..UP3 fine — the quirk is
/// specific to the UIADD3/UFSETP dest slots. The encoding itself is legal and
/// corpus-nvcc emits it, so this is a WARN, not a hard error.
fn bug034_dead_write_dest_up(insn: &Instruction, table: &IsaTable) -> Option<String> {
    if table.target_sm() != 120 {
        return None;
    }
    let (idx, dead_max) = match insn.opcode.as_str() {
        "UIADD3" => (1usize, 1u8),   // cout slot: UP0 and UP1 dead
        "UFSETP" => (0usize, 0u8),   // dest slot: UP0 dead
        _ => return None,
    };
    if let Some(Operand::UPred { num, .. }) = insn.operands.get(idx) {
        if *num <= dead_max {
            return Some(format!(
                "{:?} writes its result to UP{num}, a DEAD WRITE on sm_120 silicon                  (BUG-034: encodable and rendered, but the hardware silently drops                  the write on the {op} dest slot). Move the result to UP2..UP6, or                  sink it to UPT.",
                insn.raw_text.trim(), num = num, op = insn.opcode));
        }
    }
    None
}

/// (deduplicated). Hard errata live in the encode path itself.
pub fn errata_warnings(insn: &Instruction, table: &IsaTable) -> Vec<String> {
    let mut out = Vec::new();
    // BUG-005: plain `WARPSYNC R<n>` (register membermask) on sm_120. cubit and
    // nvdisasm both accept the word, but iter60 measured ILLEGAL_INSTRUCTION on
    // silicon depending on the surrounding schedule (context-sensitive). The
    // immediate-mask form is the safe spelling.
    if table.target_sm() == 120
        && insn.opcode == "WARPSYNC"
        && insn.modifiers.is_empty()
        && insn.operands.len() == 1
        && matches!(insn.operands[0], Operand::Reg { num, .. } if num != 255)
    {
        out.push(format!(
            "WARPSYNC with a register membermask ({:?}) is context-sensitive on sm_120              silicon (BUG-005: accepted by cubit+nvdisasm, ILLEGAL depending on              surrounding schedule). Safer: the corpus-blessed barrier-wide form `WARPSYNC.ALL ;`, or drop WARPSYNC entirely when intra-warp ordering suffices (sm_120 honors STS->LDS without a sync; iter60)",
            insn.raw_text.trim()));
    }
    // BUG-008: 4-op IMAD.WIDE with c != RZ — the word encodes fine and ptxas
    // emits it, but the c operand of a wide IMAD is read by silicon as the
    // 64-bit pair (Rc, Rc+1): the assembly consumes a register the text never
    // names. (iter71 probes first flagged this form as "silicon runs IMAD-32";
    // their own data — Rd+1 == R(c+1) — equally proves correct wide execution
    // with a 64-bit c. Either way the form is treacherous; spell it out or use
    // the canonical 5-operand pout form.)
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_none()
        && imad_wide_implicit_cpair(insn, table)
    {
        out.push(format!(
            "{:?} is a 4-operand IMAD.WIDE with c != RZ (BUG-008): silicon reads c \
             as the 64-bit pair (Rc, Rc+1), so the result's hi half silently \
             includes R{}, a register the text never names. Canonical:              `IMAD.WIDE[.U32] Rd, Pn(PT), Ra, Rb, Rc` (5-op pout) or c=RZ.",
            insn.raw_text.trim(),
            match &insn.operands[insn.operands.len()-1] {
                Operand::Reg { num, .. } => (num + 1).to_string(),
                _ => "?".to_string(),
            }));
    }
    // BUG-034: dead-write dest-UP selector (see helper; corpus-legal, so WARN).
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_none() {
        if let Some(w) = bug034_dead_write_dest_up(insn, table) {
            out.push(w);
        }
    }
    out
}

/// Encode a parsed instruction using the per-modifier-group table.
pub fn encode_instruction(insn: &Instruction, table: &IsaTable) -> Result<u128> {
    encode_instruction_inner(insn, table, true)
}

fn encode_instruction_inner(insn: &Instruction, table: &IsaTable, run_errata_checks: bool) -> Result<u128> {
    // Fail-closed operand errata (parser-level admission can't error here: the
    // .sass file reader silently drops lines whose parse fails — so the encoder
    // is the last place that can refuse a bad instruction noisily).
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_none() {
        check_pred_literal_errata(insn)?;
    }
    let mod_group = crate::table::extract_mod_group(&insn.raw_text);

    // Lookup chain: compound-opcode key with exact mod_group first, then base key,
    // then compound key with empty mods, then wildcard suffix. An entry whose field
    // extractions don't match the actual operand kinds is REJECTED and the chain
    // continues — a wrong-signature entry (e.g. register-form fields under an
    // immediate-form key from a bad harvest) must never silently encode garbage.
    let fk = full_key(insn);
    let mut candidates: Vec<(String, String)> = vec![
        (fk.clone(), mod_group.clone()),
        (insn.key.clone(), mod_group.clone()),
        (fk.clone(), String::new()),
        // base key bez modow: harvest trzyma niektore formy modifiy pod bazowym
        // kluczem z grupe "" (np. IMAD.U32 z UR-sorcem = MOV-idiom; ktest sass
        // 2026-08-05: (IMAD_R_R_R_UR, "U32") REJ. rodzajowo, (fk,"") brak).
        (insn.key.clone(), String::new()),
        (format!("{fk}_?"), String::new()),
    ];
    // cuobjdump prints SM120 LDGSTS.128 as `LDGSTS.E.128`, while the harvested
    // table records the same encoding under the more explicit cache-policy group.
    if insn.opcode == "LDGSTS" && mod_group == "128,E" {
        candidates.push((insn.key.clone(), "128,BYPASS,E,LTC128B".to_string()));
    }
    // BUG-028: trailing immediates with DEFAULT (zero) payload are invisible to
    // nvdisasm renders and carry no table field, so the harvested sig space
    // only knows the short form (QMMA.SP.16864.***_R_R_R_R_R_II). For text
    // that spells the zero tail out (`..., 0x0, 0x0`), try collapsed-sig
    // candidates after the exact forms. entry_matches_operands still
    // fail-closes on a nonzero trailing immediate.
    let n_drop = insn.operands.iter().rev()
        .take_while(|o| matches!(o, Operand::Imm32(0) | Operand::Imm64(0)))
        .count();
    if n_drop > 0 && n_drop < insn.operands.len() {
        let clean_opcode: String = insn.opcode_full.split('.')
            .filter(|part| !part.is_empty() && !part.starts_with('?'))
            .collect::<Vec<_>>().join(".");
        // Try every collapse level (drop 1, 2, ...): text like `..., 0x0, 0x0`
        // must first try the harvested single-imm sig before shorter forms.
        for d in 1..=n_drop {
            let sig: String = insn.operands[..insn.operands.len() - d].iter()
                .map(|op| format!("_{}", crate::parser::operand_type_label_pub(op)))
                .collect();
            let fk_c = format!("{clean_opcode}{sig}");
            let k_c = format!("{}{}", insn.opcode, sig);
            candidates.push((fk_c.clone(), mod_group.clone()));
            candidates.push((k_c.clone(), mod_group.clone()));
            candidates.push((fk_c, String::new()));
            candidates.push((k_c, String::new()));
        }
    }
    candidates.dedup();

    let mut attempts: Vec<String> = Vec::new();
    let mut entry = Option::<&crate::table::ModGroupEntry>::None;
    let mut sel_key = String::new();
    let mut sel_mg = String::new();
    for (k, mg) in &candidates {
        match table.get(k, mg) {
            Some(e) => match entry_matches_operands(insn, e) {
                Ok(()) => {
                    entry = Some(e);
                    sel_key = k.clone();
                    sel_mg = mg.clone();
                    break;
                }
                Err(why) => attempts.push(format!("({k}, \"{mg}\") REJECTED: {why}")),
            },
            None => attempts.push(format!("({k}, \"{mg}\") not in table")),
        }
    }
    let entry = entry.with_context(|| {
        let mut msg = format!(
            "no operand-compatible table entry; attempted keys: [{}]",
            attempts.join("; "));
        // BUG-001: PRMT's silent swap trap — authors coming from PTX write
        // `prmt.b32 d, a, b, c` (selector LAST), but the SASS/nvdisasm operand
        // order is (d, a, sel, b) — selector THIRD. All-register text is
        // accepted either way and encodes the operands in hardware order, so a
        // PTX-order line silently swaps the selector and b. Say so at the one
        // place the mismatch becomes visible (a failing form lookup).
        if insn.opcode == "PRMT" {
            msg.push_str(
                ". PRMT note: SASS operand order is (d, a, sel, b) — the selector is                  operand 3 (PTX prmt.b32 is d, a, b, c). PTX-order text swaps sel and b                  SILENTLY for the all-register form; write hardware order (see README                  errata, BUG-001)");
        }
        if insn.opcode == "IMAD" && insn.modifiers.iter().any(|m| m == ".HI") {
            msg.push_str(
                ". IMAD.HI note (BUG-002): on sm_120 the harvested `IMAD.HI` encodings \
                 are executed by silicon as IMAD.WIDE.U32 (Rd = LOW half, Rd+1 \
                 CLOBBERED); the bogus entries were removed, so the text now fails \
                 fail-closed. Use `IMAD.WIDE[.U32] Rd, Ra, Rb, RZ` and read Rd+1, \
                 or the 5-operand pout form");
        }
        msg
    })?;
    // BUG-002 guard: IMAD.HI text must never ride an entry that does not
    // encode the HI modifier (silicon: such words are IMAD.WIDE.U32 and
    // clobber Rd+1).
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_none() {
        check_imad_hi_erratum(insn, table, &sel_key, &sel_mg)?;
    }
    if std::env::var("CUBIT_DEBUG_LOOKUP").is_ok() {
        eprintln!("[lookup] fk={} key={} mod_group={:?} -> fields={:?}",
            fk, insn.key, mod_group,
            entry.fields.iter().map(|f|(format!("{:?}",f.extraction),f.shift,f.bits,f.token_idx)).collect::<Vec<_>>());
    }

    let mut code = entry.and_base;

    // Apply field extractions
    for field in &entry.fields {
        let value = extract_value(insn, field)?;
        let mask128 = (field.mask as u128) << field.shift;
        code = (code & !mask128) | ((value as u128 & field.mask as u128) << field.shift);
    }

    // (carry pred / drain fixes applied below after guard)

    // SM120 abs/neg modifier bits on register operands.
    // These are separate from the operand key (key always uses "R").
    //   abs on Rb (operand index 2 for ALU): lo bit 62
    //   neg on Rb: lo bit 63
    //   abs on Ra (operand index 1 for ALU): hi bit 9  (bit 73 overall)
    //   neg on Ra: hi bit 8  (bit 72 overall)
    {
        let is_alu = !matches!(insn.opcode.as_str(),
            "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "STG" | "STL" | "STS" |
            "ATOM" | "RED" | "BRA" | "BSSY" | "BSYNC" | "EXIT" | "RET" |
            "BAR" | "S2R" | "S2UR" | "LDSM" | "LDGSTS" | "QMMA");
        if is_alu {
            // Find Ra (typically operand index 1) and Rb (operand index 2)
            // For most ALU: op0=Rd, op1=Ra, op2=Rb
            let skip_preds = insn.operands.iter()
                .take_while(|o| matches!(o, Operand::Pred { .. } | Operand::UPred { .. }))
                .count();
            // For standard ALU: [Rd, Ra, Rb, ...] — Rd is a Reg, so ra/rb follow it.
            // For predicate-dest instructions (DSETP, FSETP, ISETP): [P, P, Ra, Rb, ...]
            // — the first non-pred is Ra, not Rd.
            let has_reg_dest = matches!(insn.operands.first(), Some(Operand::Reg { .. }));
            let ra_idx = if has_reg_dest { skip_preds + 1 } else { skip_preds };
            let rb_idx = if has_reg_dest { skip_preds + 2 } else { skip_preds + 1 };
            let ra_tok = (ra_idx + 1) as i32;
            let rb_tok = (rb_idx + 1) as i32;

            // Skip generic neg/abs if the table entry already has a field-level
            // neg/abs for the same operand token. Field-level handling uses the
            // correct bit position for each instruction variant; the generic
            // code assumes fixed positions (72/73 for Ra, 62/63 for Rb) which
            // are wrong for variants where operand indices shift (e.g. _P_ prefix).
            let has_field_neg = |tok: i32| -> bool {
                entry.fields.iter().any(|f|
                    f.token_idx == tok && matches!(f.extraction,
                        Extraction::Neg | Extraction::NegShl1))
            };
            let has_field_abs = |tok: i32| -> bool {
                entry.fields.iter().any(|f|
                    f.token_idx == tok && matches!(f.extraction, Extraction::Abs))
            };

            // abs/neg on UR source operands counts too (e.g. FFMA R8, R3, |UR16|, RZ
            // needs abs-Rb bit62 set; the earlier Reg-only match dropped it silently).
            let is_abs = |o: Option<&Operand>| -> bool {
                matches!(o, Some(Operand::Reg { abs: true, .. })
                         | Some(Operand::UReg { abs: true, .. }))
            };
            let is_neg = |o: Option<&Operand>| -> bool {
                matches!(o, Some(Operand::Reg { neg: true, .. })
                         | Some(Operand::UReg { neg: true, .. }))
            };

            if !has_field_abs(rb_tok) && is_abs(insn.operands.get(rb_idx)) {
                code |= 1u128 << 62;  // abs Rb
            }
            if !has_field_neg(rb_tok) && is_neg(insn.operands.get(rb_idx)) {
                code |= 1u128 << 63;  // neg Rb
            }
            if !has_field_abs(ra_tok) && is_abs(insn.operands.get(ra_idx)) {
                code |= 1u128 << 73;  // abs Ra (hi bit 9)
            }
            if !has_field_neg(ra_tok) && is_neg(insn.operands.get(ra_idx)) {
                code |= 1u128 << 72;  // neg Ra (hi bit 8)
            }
            // Third source (Rc slot, e.g. Ops[3] in DSETP/FFMA): abs at 74, neg at 75,
            // mirroring the Ra slot pair. Guards via has_field_* as above.
            let rc_idx = rb_idx + 1;
            let rc_tok = rb_tok + 1;
            if !has_field_abs(rc_tok) && is_abs(insn.operands.get(rc_idx)) {
                code |= 1u128 << 74;
            }
            if !has_field_neg(rc_tok) && is_neg(insn.operands.get(rc_idx)) {
                code |= 1u128 << 75;
            }
        }
    }

    // SM120: bits[15:12] of lo64 are ALWAYS the guard predicate.
    // Many mod_groups were learned from unconditional instructions only, so they
    // never learned the guard field and their and_base has guard=0 (from AND
    // across examples with different predicates). Force PT (7) as default.
    let has_full_guard_at_12 = entry.fields.iter().any(|f| {
        f.shift <= 12 && (f.shift + f.bits) >= 16
            && matches!(f.extraction, Extraction::Guard)
    }) || (
        entry.fields.iter().any(|f| {
            f.shift <= 14 && (f.shift + f.bits) >= 15
                && matches!(f.extraction, Extraction::Guard | Extraction::GuardLo3)
        }) &&
        entry.fields.iter().any(|f| {
            f.shift == 15 && f.bits == 1
                && matches!(f.extraction, Extraction::GuardNeg | Extraction::Inv | Extraction::Neg)
        })
    );
    if !has_full_guard_at_12 {
        let guard = guard_val(insn) as u128;
        code = (code & !(0xFu128 << 12)) | (guard << 12);
    }
    // Fixup: place operand registers at standard SM120 positions when the ISA
    // table's mod_group is missing the field (learned from limited examples).
    //
    // SM120 memory instruction layout (lo64):
    //   [15:0]  = opcode
    //   [23:16] = Rd (destination register for loads, or source for some ops)
    //   [31:24] = Ra (address base register from Addr/Desc operand)
    //   [39:32] = Rs (source register for stores, or secondary reg)
    {
        let is_mem_load = matches!(insn.opcode.as_str(),
            "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "ATOM" | "ATOMS" | "ATOMG" |
            "RED" | "REDG" | "LDSM" | "LDGSTS" | "LD" | "LDGX");

        // Rd at shift=16: for memory loads, operand 1 = destination register
        if is_mem_load {
            let has_rd_field = entry.fields.iter().any(|f| {
                f.shift == 16 && f.bits >= 8
                    && matches!(f.extraction, Extraction::Reg)
            });
            if !has_rd_field {
                if let Some(Operand::Reg { num, .. }) = insn.operands.first() {
                    let mask = 0xFFu128 << 16;
                    code = (code & !mask) | ((*num as u128) << 16);
                }
            }
        }

        // Ra at shift=24: address base register from Addr operand
        let has_addr_reg_field = entry.fields.iter().any(|f| {
            f.shift == 24 && f.bits >= 8
                && matches!(f.extraction, Extraction::Reg | Extraction::SubR(_))
        });
        if !has_addr_reg_field {
            for (oi, op) in insn.operands.iter().enumerate() {
                if let Operand::Addr { base_reg: Some(r), .. } = op {
                    let tok = (oi + 1) as i32;
                    let addr_field_covered = entry.fields.iter().any(|f| {
                        f.token_idx == tok
                            && matches!(f.extraction, Extraction::Reg | Extraction::SubR(_))
                    });
                    if !addr_field_covered {
                        let mask = 0xFFu128 << 24;
                        code = (code & !mask) | ((*r as u128) << 24);
                    }
                    break;
                }
            }
        }
    }

    // Branch encoding (address-dependent, separate from field system)
    code = apply_branch_encoding(insn, code, &mod_group, table.ef_flags == 0x0600_6702);

    // Reuse bits [124:122] (Ra/Rb/Rc register cache reuse flags)
    code = apply_reuse_encoding(insn, code, entry);

    // Raw-address LDG/STG full rebuild: the ISA table's _ARI mod_groups for
    // .64/.128 variants have scattered 1-bit register fields and wrong opcodes
    // (the and_base is AND'd across too few examples). Instead of patching
    // individual fields, rebuild lo64 + hi_lower32 entirely using the known
    // SM120 memory instruction layout.
    //
    // SM120 raw-address layout (lo64):
    //   [11:0]  = base opcode (LDG=0x981, STG=0x986)
    //   [15:12] = guard predicate (PT=7)
    //   [23:16] = Rd (load destination) or 0 (store)
    //   [31:24] = Ra (address base register)
    //   [39:32] = Rs (store source register) or 0 (load)
    //   [63:40] = 24-bit signed offset
    //
    // hi_lower32 templates (from dARI entries, nvcc 12.8 SM120):
    //   LDG.E       → 0x0c1e1900    LDG.E.64  → 0x0c1e1b00    LDG.E.128 → 0x0c1e1d00
    //   STG.E       → 0x0c101900    STG.E.64  → 0x0c101b00    STG.E.128 → 0x0c101d00
    // sm_103a tables derived from the B300 corpus carry correct and_base+fields
    // for these variants; the legacy SM120 rebuild would clobber them.
    let sm103a_derived = table.ef_flags == 0x0600_6702;
    {
        let uses_raw_addr = insn.operands.iter().any(|op| matches!(op, Operand::Addr { .. }));
        let uses_desc = insn.operands.iter().any(|op| matches!(op, Operand::Desc { .. }));

        // BUG-038: when the selected table entry actually OWNS the address
        // (a ureg field bound to the Addr token — the plain [Rn.U32+URm] form),
        // this hardcoded rebuild must not run: it has no UR slot at all and
        // overwrites the entry's mode/width dword with a desc-era template.
        let addr_tok = insn.operands.iter()
            .position(|op| matches!(op, Operand::Addr { .. }))
            .map(|i| i as i32 + 1);
        let entry_covers_addr_ur = addr_tok.is_some_and(|tok| {
            entry.fields.iter().any(|f| f.token_idx == tok
                && ext_encodes_ureg(&f.extraction))
        });

        if !sm103a_derived && uses_raw_addr && !uses_desc && !entry_covers_addr_ur
            && (insn.opcode == "LDG" || insn.opcode == "STG") {
            let is_64 = insn.opcode_full.contains(".64");
            let is_128 = insn.opcode_full.contains(".128");
            let guard = guard_val(insn) as u128;

            let addr_offset = insn.operands.iter().find_map(|op| match op {
                Operand::Addr { offset, .. } => Some(*offset),
                _ => None,
            }).unwrap_or(0);
            let ra = insn.operands.iter().find_map(|op| match op {
                Operand::Addr { base_reg: Some(r), .. } => Some(*r as u128),
                _ => None,
            }).unwrap_or(255);

            let hi_upper32 = (code >> 96) & 0xFFFFFFFF;

            if insn.opcode == "LDG" {
                let hi_lo32: u128 = if is_128 { 0x0c1e1d00 } else if is_64 { 0x0c1e1b00 } else { 0x0c1e1900 };
                let rd = insn.operands.first().and_then(|op| match op {
                    Operand::Reg { num, .. } => Some(*num as u128),
                    _ => None,
                }).unwrap_or(0);
                code = (hi_upper32 << 96)
                    | (hi_lo32 << 64)
                    | (((addr_offset as u128) & 0xFFFFFF) << 40)
                    | (ra << 24)
                    | (rd << 16)
                    | (guard << 12)
                    | 0x981u128;
            } else {
                let hi_lo32: u128 = if is_128 { 0x0c101d00 } else if is_64 { 0x0c101b00 } else { 0x0c101900 };
                let rs = insn.operands.iter().find_map(|op| match op {
                    Operand::Reg { num, .. } => Some(*num as u128),
                    _ => None,
                }).unwrap_or(0);
                code = (hi_upper32 << 96)
                    | (hi_lo32 << 64)
                    | (((addr_offset as u128) & 0xFFFFFF) << 40)
                    | (rs << 32)
                    | (ra << 24)
                    | (guard << 12)
                    | 0x986u128;
            }
        }
    }

    // LDGSTS.E.128 descriptor form used by SM120 FlashAttention:
    //   LDGSTS.E.128 [Ra], desc[URd][Rb.64]
    //
    // The harvested table has the right opcode family but incomplete descriptor
    // fields, so rebuild the operand portion from the observed SM120 layout:
    //   lo[15:12] = guard, lo[23:16] = shared Ra, lo[31:24] = global Rb
    //   hi[31:0]  = 0x0b9a180e for E.128 descriptor copies.
    {
        let uses_addr = insn.operands.iter().any(|op| matches!(op, Operand::Addr { .. }));
        let desc = insn.operands.iter().find_map(|op| match op {
            Operand::Desc { ur_idx, base_reg, .. } => Some((*ur_idx, *base_reg)),
            _ => None,
        });
        if !sm103a_derived && insn.opcode == "LDGSTS" && insn.opcode_full.contains(".128") && uses_addr {
            if let Some((_ur_idx, Some(desc_r))) = desc {
                let shared_r = insn.operands.iter().find_map(|op| match op {
                    Operand::Addr { base_reg: Some(r), .. } => Some(*r as u128),
                    _ => None,
                }).unwrap_or(255);
                let guard = guard_val(insn) as u128;
                let hi_upper32 = (code >> 96) & 0xFFFFFFFF;
                code = (hi_upper32 << 96)
                    | (0x0b9a180e_u128 << 64)
                    | ((desc_r as u128) << 24)
                    | (shared_r << 16)
                    | (guard << 12)
                    | 0x0fae_u128;
            }
        }
    }

    // BUG-028: removed blanket `code &= !(1u128 << 80)` for QMMA.SP. The hack
    // zeroed the Structured-Sparsity gate bit for ALL 144 SP table entries on
    // the claim "RTX 5090 rejects bit80=1 (ILLEGAL 715)" — contradicted by the
    // corpus: nvcc-produced SM120 words carry bit80=1 (all SP and_base rows),
    // nvdisasm renders them as valid SP, and the s4 0x14-form probes ran EXACT
    // on the 5090 (605/605). With the clear active, QMMA.SP.16864 emitted
    // byte10=0, which nvdisasm reads as QMMA.INVALID2 and silicon rejects.
    // Table authority restored: each SP entry's own and_base decides bit80.

    // BSSY/BSYNC convergence barrier bits (bit73 for RECONVERGENT, bit72 for
    // RELIABLE) are encoded in the ISA table and_base per mod_group.
    // No hardcoded fixup needed.

    // SM120 scheduling goes ONLY in upper32[25:9]. hi_lower32 contains
    // instruction-specific fields (register values, modifier bits, SR codes)
    // and must NOT be modified by scheduling. The previous code here injected
    // scheduling at hi_lower32 positions, corrupting baked register values
    // (e.g. SHF's RZ at bits[71:64]) — removed per tungsten reference.

    // SM120 upper32: the entire upper32 is the scheduling word.
    //
    // Layout (from tungsten `buildSchedUpper32`):
    //   bits [31:26] = reuse flags (from apply_reuse_encoding)
    //   bits [25:9]  = 17-bit scheduling: wait[6]|rbar[3]|wbar[3]|yield[1]|stall[4]
    //   bits [8:0]   = always 0
    //
    // The epoch value from the ISA table provides the default scheduling
    // (typically 0x000fc200 = stall=1, wbar=7, rbar=7, yield=0).
    // We replace the scheduling field [25:9] with the scheduling pass result.
    // All standard instructions use 0x000fc200 as upper32 base
    // (stall=1, wbar=7, rbar=7, yield=0). The scheduling pass overrides
    // via insn.ctrl. ISA table epoch values are not used — they encode
    // non-standard defaults that conflict with the scheduling pass.
    // Fully static instructions (EXIT, NOP, BRA) have their own base
    // values from the epoch table.
    let epoch_upper32_static = table.epoch_upper32(&insn.key)
        .or_else(|| {
            let fk = full_key(insn);
            table.epoch_upper32(&fk)
        })
        .unwrap_or(0x000fc200);
    let epoch_upper32_default: u32 = 0x000fc200;

    let hi64 = (code >> 64) as u64;
    let current_upper32 = (hi64 >> 32) as u32;

    let ctrl_class = table.ctrl_class(&insn.key)
        .or_else(|| {
            let fk = full_key(insn);
            table.ctrl_class(&fk)
        });

    use crate::ctrl_class::CtrlClass;
    let is_fully_static = matches!(
        ctrl_class,
        Some(CtrlClass::ExitStatic) |
        Some(CtrlClass::CtrlFlow) | Some(CtrlClass::Barrier)
    );
    let is_nop = matches!(ctrl_class, Some(CtrlClass::Nop));

    // Reuse bits at upper32[28:26] come from apply_reuse_encoding.
    let reuse_bits = current_upper32 & 0x1C00_0000;

    let final_upper32 = if is_nop {
        // NOP: use table upper32 but allow scheduling override if provided
        let non_sched = (epoch_upper32_static & !scheduling::SCHED_UPPER32_MASK) | reuse_bits;
        non_sched | scheduling::encode_sched_upper32(&insn.ctrl)
    } else if is_fully_static {
        if insn.hand_sched {
            // BUG-010: fully_static classes (DEPBAR/MEMBAR/BAR/ctrl-flow/EXIT)
            // used to take the epoch upper32 VERBATIM, discarding the parsed
            // [B..:R..:W..:Y..S..] control word — frozen round-trips of e.g.
            // `DEPBAR.LE SB0, 0x9` lost b104..111 (0x000fe800 orig came back
            // 0x000fe200, and MEMBAR.GPU.SC's 0x000fcc00/0x...01 ctrl word
            // degraded likewise). The disassembler prints the control prefix
            // for these lines precisely so the assembler can reproduce the
            // word; merge it like the NOP path does. Text WITHOUT a control
            // prefix (fresh asm) keeps the table epoch default unchanged.
            let non_sched = (epoch_upper32_static & !scheduling::SCHED_UPPER32_MASK) | reuse_bits;
            non_sched | scheduling::encode_sched_upper32(&insn.ctrl)
        } else {
            epoch_upper32_static | reuse_bits
        }
    } else {
        // Replace scheduling field [25:9] with the scheduling pass result.
        let non_sched = (epoch_upper32_default & !scheduling::SCHED_UPPER32_MASK) | reuse_bits;
        non_sched | scheduling::encode_sched_upper32(&insn.ctrl)
    };

    let lo64 = code as u64;
    let lo32_hi = hi64 as u32;
    if std::env::var("CUBIT_ENCDBG").is_ok() {
        let sched_encoded = scheduling::encode_sched_upper32(&insn.ctrl);
        eprintln!("[encoder] {} static={is_fully_static} sched=0x{sched_encoded:08x} final=0x{final_upper32:08x} ctrl.wait=0x{:02x} ctrl.wbar={}",
                  insn.opcode, insn.ctrl.wait_mask, insn.ctrl.write_bar);
    }
    let new_hi64 = ((final_upper32 as u64) << 32) | (lo32_hi as u64);
    let mut out = ((new_hi64 as u128) << 64) | (lo64 as u128);
    // !rsd[...] bit-residue overlay: author's explicit bit assignments, applied
    // LAST — after fields, branch/reuse paths, scheduling and epoch merge (the
    // final u128 is fully composed at this point). This is the escape hatch that
    // makes strict round-trips exact even where the ISA table has no field for
    // a hardware detail (disassemble emits !rsd only where text fidelity would
    // otherwise be lost).
    if let Some(rsd) = &insn.rsd {
        for &(bit, val) in rsd {
            if val != 0 { out |= 1u128 << bit; } else { out &= !(1u128 << bit); }
        }
    }
    // BUG-006 guard (fail-closed): a negated predicate operand whose slot
    // lacks a negation encoding must not silently degrade to the non-negated
    // predicate. Runs after the full pipeline; skipped for __raw__ (no
    // operands) and for the internal flipped-variant re-encodes.
    if run_errata_checks && std::env::var_os("CUBIT_DISABLE_ERRATA").is_none() {
        check_pred_neg_encoded(insn, table, out)?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Field value extraction
// ---------------------------------------------------------------------------

fn extract_value(insn: &Instruction, field: &Field) -> Result<u64> {
    let mk = field.mask;

    match &field.extraction {
        // Guard extractions (token 0)
        Extraction::Guard => Ok(guard_val(insn) & mk),
        Extraction::GuardLo3 => Ok((guard_val(insn) & 7) & mk),
        Extraction::GuardNeg => Ok(if insn.guard.as_ref().is_some_and(|g| g.negated) { 1 } else { 0 }),

        // Register
        Extraction::Reg => Ok(op_reg(insn, field.token_idx) & mk),
        Extraction::UReg => {
            // UMOV dest slot: corpus rule "URZ reads as 0xFF in source slots"
            // does not extend to the uniform move destination — FA4 hardware
            // encoding stores URZ as its architectural number 63 there.
            if insn.opcode.starts_with("UMOV") && field.token_idx == 1 {
                if let Some(Operand::UReg { is_zero: true, .. }) = get_op(insn, 1) {
                    return Ok(63 & mk);
                }
            }
            Ok(op_ureg(insn, field.token_idx) & mk)
        }
        Extraction::RegFf => Ok(op_reg_ff(insn, field.token_idx) & mk),
        Extraction::URegFf => Ok(op_ureg_ff(insn, field.token_idx) & mk),
        Extraction::Pred => Ok(op_pred(insn, field.token_idx) & mk),
        Extraction::Barrier => Ok(op_barrier(insn, field.token_idx) & mk),

        // Immediate
        Extraction::Imm => Ok(op_imm(insn, field.token_idx) & mk),
        Extraction::ImmShr(n) => Ok((op_imm(insn, field.token_idx) >> n) & mk),
        Extraction::ImmDec => Ok(op_imm_dec(insn, field.token_idx) & mk),
        Extraction::ImmDecU32 => Ok((op_imm_dec(insn, field.token_idx) & 0xFFFFFFFF) & mk),

        // Float
        Extraction::F32 => Ok(op_f32(insn, field.token_idx) & mk),
        Extraction::F16 => Ok(op_f16_via_f32(insn, field.token_idx) & mk),
        Extraction::F16d => Ok(op_f16_via_f64(insn, field.token_idx) & mk),
        Extraction::F64hi => Ok(op_f64hi(insn, field.token_idx) & mk),

        // Flags
        Extraction::Neg => {
            let v = op_neg(insn, field.token_idx);
            if v == 0 { Ok(op_inv(insn, field.token_idx) & mk) } else { Ok(v & mk) }
        }
        Extraction::NegShl1 => Ok((op_neg(insn, field.token_idx) << 1) & mk),
        Extraction::Reuse => Ok(op_reuse(insn, field.token_idx) & mk),
        Extraction::Inv => Ok(op_inv(insn, field.token_idx) & mk),
        Extraction::Abs => Ok(op_abs(insn, field.token_idx) & mk),
        Extraction::NegAbs => {
            let a = op_abs(insn, field.token_idx);
            let n = op_neg(insn, field.token_idx);
            Ok((if a != 0 { 2 } else if n != 0 { 1 } else { 0 }) & mk)
        }
        Extraction::ByteSel => Ok(op_byte_sel(insn, field.token_idx) & mk),
        Extraction::LblPat(pat) => {
            // Double-bracket operands (Operand::Desc) carry the UR id structurally;
            // raw scraping only understands the single-bracket desc[URn] form.
            if let Some(Operand::Desc { ur_idx, .. }) = get_op(insn, field.token_idx) {
                if matches!(pat.as_str(),
                    "desc_ur" | "gdesc_ur" | "idesc_ur" | "tmem_ur" | "tdesc_ur") {
                    return Ok((*ur_idx as u64) & mk);
                }
            }
            Ok(op_lbl_scrape(insn, field.token_idx, pat) & mk)
        },
        Extraction::AddrScale => Ok(op_addr_scale(insn, field.token_idx) & mk),
        Extraction::UrExpl => Ok(op_urz_flag(insn, field.token_idx) & mk),
        Extraction::UrExplInv => Ok((1 - op_urz_flag(insn, field.token_idx)) & mk),
        Extraction::HalfSel => Ok(op_hsel(insn, field.token_idx) & mk),
        Extraction::OpModFlag(name) => Ok(op_mod_flag_value(insn, field.token_idx, name) & mk),
        Extraction::MnemMod(i, name) => Ok(op_mnemod(insn, *i, name) & mk),
        Extraction::BF16 => Ok(op_bf16(insn, field.token_idx) & mk),

        // System register
        Extraction::SysReg => Ok(op_sysreg(insn, field.token_idx) & mk),
        Extraction::SysRegLo7 => Ok((op_sysreg(insn, field.token_idx) & 0x7F) & mk),
        Extraction::SysRegLo4 => Ok((op_sysreg(insn, field.token_idx) & 0xF) & mk),
        Extraction::SysRegHi4 => Ok(((op_sysreg(insn, field.token_idx) >> 4) & 0xF) & mk),
        Extraction::SysRegHi1 => Ok(((op_sysreg(insn, field.token_idx) >> 7) & 1) & mk),

        // Register bit-shifted (for double-precision, S64, etc.)
        Extraction::RegShr(n) => Ok((op_reg(insn, field.token_idx) >> n) & mk),
        Extraction::URegShr(n) => Ok((op_ureg(insn, field.token_idx) >> n) & mk),

        // Address sub-parts
        Extraction::SubR(i) => Ok(op_sub_reg(insn, field.token_idx, *i) & mk),
        Extraction::SubUR(i) => Ok(op_sub_ureg(insn, field.token_idx, *i) & mk),
        Extraction::SubURm1(i) => Ok(op_sub_ureg(insn, field.token_idx, *i)
            .wrapping_sub(1) & mk),
        Extraction::SubImm(i) => Ok(op_sub_imm(insn, field.token_idx, *i) & mk),
        Extraction::SubImmS24(i) => Ok((op_sub_imm(insn, field.token_idx, *i) & 0xFFFFFF) & mk),
        // Address sub-parts, bit-shifted (for .64 addresses storing reg/2)
        Extraction::SubRShr(i, n) => Ok((op_sub_reg(insn, field.token_idx, *i) >> n) & mk),
        Extraction::SubURShr(i, n) => Ok((op_sub_ureg(insn, field.token_idx, *i) >> n) & mk),
        Extraction::SubImmShr(i, n) => Ok((op_sub_imm(insn, field.token_idx, *i) >> n) & mk),

        // Constant memory
        Extraction::Cm16Off => Ok(op_cm_off(insn, field.token_idx, 16) & mk),
        Extraction::Cm17Off => Ok(op_cm_off(insn, field.token_idx, 17) & mk),

        // Opaque modifier: extract the ?NN value from the opcode text.
        // The printer formats these as ".?6" (for value 6), and the parser
        // preserves them in opcode_full. Extract the value from there.
        Extraction::OpaqueModifier => {
            let val = extract_opaque_mod(&insn.raw_text, field.shift, field.bits);
            Ok(val & mk)
        }

        Extraction::None => Ok(0),
        Extraction::YieldInv => Ok(if insn.ctrl.yield_flag { 0 } else { 1 } & mk),
    }
}

// ---------------------------------------------------------------------------
// Operand value helpers
// ---------------------------------------------------------------------------

fn guard_val(insn: &Instruction) -> u64 {
    // SM120 guard encoding at bits[12:15]:
    // - PT (unconditional): 0x7 (0111)
    // - @Pn (non-negated): pred (0000..0110) — bit 15 = 0
    // - @!Pn (negated): pred | 8 (1000..1110) — bit 15 = 1 = negation flag
    // Hardware-verified on RTX 5090: bit 15 is the negation flag, NOT "guard active".
    match &insn.guard {
        Some(g) => (g.pred as u64) | (if g.negated { 8 } else { 0 }),
        None => 7, // PT
    }
}

fn get_op(insn: &Instruction, tok: i32) -> Option<&Operand> {
    if tok <= 0 { None } else { insn.operands.get((tok - 1) as usize) }
}

fn op_reg(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Reg { num, .. }) => *num as u64,
        Some(Operand::Desc { base_reg, .. }) => base_reg.map_or(255, |r| r as u64),
        Some(Operand::Addr { base_reg, .. }) => base_reg.map_or(255, |r| r as u64),
        _ => 0,
    }
}

fn op_ureg(insn: &Instruction, tok: i32) -> u64 {
    // URZ encodes as 0xFF in 8-bit slots on sm_103a; UR63 is a real register
    // and keeps its number (63).
    match get_op(insn, tok) {
        Some(Operand::UReg { is_zero: true, .. }) => 255, // URZ=0xff
        Some(Operand::UReg { num, .. }) => *num as u64,
        Some(Operand::Desc { ur_idx, .. }) => *ur_idx as u64,
        Some(Operand::Addr { ur_reg, .. }) => ur_reg.map_or(255, |r| r as u64),
        _ => 0,
    }
}

fn op_reg_ff(insn: &Instruction, tok: i32) -> u64 {
    // reg_ff: 255 for RZ/URZ, 0 for everything else
    // (NOT the register number — that's what `reg` and `ureg` are for)
    match get_op(insn, tok) {
        Some(Operand::Reg { num: 255, .. }) => 255,   // RZ
        Some(Operand::UReg { is_zero: true, .. }) => 255,   // URZ
        _ => 0,
    }
}

fn op_ureg_ff(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::UReg { is_zero: true, .. }) => 255,  // URZ → 255
        Some(Operand::UReg { num, .. }) => *num as u64,
        _ => 0,
    }
}

fn op_pred(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Pred { num, .. }) | Some(Operand::UPred { num, .. }) => *num as u64,
        _ => 7, // PT
    }
}

/// Address scale selector from the base-register suffix of an Addr operand
/// ([R9.X8] / [R9.X16]): none/"U32" = 0, X4 = 1, X8 = 2, X16 = 3.
/// i108 golden attribution (BUG-038): LDS.64 `[R.X8]` carries bits[79:78]=2,
/// LDS.128 `[R.X16]` = 3 at the same window.
fn op_addr_scale(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Addr { base_reg_suffix: Some(sfx), .. }) => match sfx.as_str() {
            "X4" => 1,
            "X8" => 2,
            "X16" => 3,
            _ => 0,
        },
        _ => 0,
    }
}

fn op_barrier(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Barrier(b)) => *b as u64,
        _ => 0,
    }
}

fn op_imm(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Imm32(v)) => *v as u64,
        Some(Operand::Imm64(v)) => *v,
        Some(Operand::BranchTarget(t)) => *t as u64,
        Some(Operand::FloatImm(v)) => {
            let f = f64::from_bits(*v);
            (f as f32).to_bits() as u64
        }
        // Desc[UR][R+off]: 'imm' extraction gives the byte offset
        Some(Operand::Desc { offset, .. }) => *offset as u64,
        // Addr[R+off] or Addr[UR+off]: 'imm' gives the offset
        Some(Operand::Addr { offset, .. }) => *offset as u64,
        _ => 0,
    }
}

fn op_imm_dec(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Imm32(v)) => *v as u64,
        _ => 0,
    }
}

fn op_f32(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => (f64::from_bits(*v) as f32).to_bits() as u64,
        Some(Operand::Imm32(v)) => {
            // Hex immediate in F32 context: treat as raw IEEE754 bits
            // *v is already the IEEE754 bit pattern
            (*v & 0xFFFFFFFF) as u64
        }
        _ => 0,
    }
}

fn op_f64hi(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => {
            let bits = f64::from_bits(*v).to_bits();
            bits >> 32
        }
        Some(Operand::Imm32(v)) => {
            let bits = (*v as f64).to_bits();
            bits >> 32
        }
        _ => 0,
    }
}

fn f32_to_f16(bits: u32) -> u16 {
    let sign = (bits >> 16) & 0x8000;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let frac = bits & 0x7FFFFF;
    if exp == 0xFF { return (sign | 0x7C00 | if frac != 0 { 0x200 } else { 0 }) as u16; }
    if exp == 0 { return sign as u16; }
    let ne = exp - 127 + 15;
    if ne >= 31 { return (sign | 0x7C00) as u16; }
    if ne <= 0 {
        if ne >= -10 {
            let f = (frac | 0x800000) >> (1 - ne + 13);
            return (sign | f) as u16;
        }
        return sign as u16;
    }
    (sign | ((ne as u32) << 10) | (frac >> 13)) as u16
}

fn f64_to_f16_direct(bits: u64) -> u16 {
    let sign = ((bits >> 48) & 0x8000) as u32;
    let exp = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & 0xFFFFFFFFFFFFF;
    if exp == 0x7FF { return (sign | 0x7C00 | if frac != 0 { 0x200 } else { 0 }) as u16; }
    if exp == 0 { return sign as u16; }
    let ne = exp - 1023 + 15;
    if ne >= 31 { return (sign | 0x7C00) as u16; }
    if ne <= 0 {
        if ne >= -10 {
            let f = (frac | (1u64 << 52)) >> (1 - ne + 42);
            return (sign | f as u32) as u16;
        }
        return sign as u16;
    }
    (sign | ((ne as u32) << 10) | ((frac >> 42) as u32 & 0x3FF)) as u16
}

fn op_f16_via_f32(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => {
            let f32bits = (f64::from_bits(*v) as f32).to_bits();
            f32_to_f16(f32bits) as u64
        }
        _ => 0,
    }
}

fn op_f16_via_f64(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => f64_to_f16_direct(*v) as u64,
        _ => 0,
    }
}

fn op_neg(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Reg { neg: true, .. }) => 1,
        Some(Operand::UReg { neg: true, .. }) => 1,
        _ => 0,
    }
}

/// Scrape a number from a Label operand's raw text. tcgen05 address forms
/// (tmem[UR4+0x10], gdesc[UR24], idesc[UR23], desc[UR6]) stay labels in the
/// parsed operand list; pat selects the value: "<kind>_ur" reads the UR
/// number, "<kind>_off" the optional offset after '+'. "tdesc_*" patterns
/// accept any descriptor kind (mixed-kind operand positions); "dsel2"
/// returns the kind tag (desc=0, gdesc=1, tmem=2, idesc=3) matching the
/// hardware selector field derived from the B300 corpus (UTCQMMA operand 1).
fn op_lbl_scrape(insn: &Instruction, tok: i32, pat: &str) -> u64 {
    let s = match get_op(insn, tok) {
        Some(Operand::Label(s)) => s.as_str(),
        _ => return 0,
    };
    fn parse_body(s: &str) -> Option<(u64, u64, u64)> {
        for (pfx, tag) in [("tmem[UR", 2u64), ("gdesc[UR", 1),
                           ("idesc[UR", 3), ("desc[UR", 0)] {
            if let Some(b) = s.strip_prefix(pfx)
                  .and_then(|r| r.strip_suffix(']')) {
                let (num_s, off_s) = match b.split_once('+') {
                    Some((a, b)) => (a, Some(b)),
                    None => (b, None),
                };
                let n = num_s.parse::<u64>().unwrap_or(0);
                let off = match off_s {
                    Some(o) => o.strip_prefix("0x")
                        .and_then(|h| u64::from_str_radix(h, 16).ok())
                        .or_else(|| o.parse::<u64>().ok())
                        .unwrap_or(0),
                    None => 0,
                };
                return Some((n, off, tag));
            }
        }
        None
    }
    match pat {
        "tdesc_ur" => return parse_body(s).map(|x| x.0).unwrap_or(0),
        "tdesc_off" => return parse_body(s).map(|x| x.1).unwrap_or(0),
        "dsel2" => return parse_body(s).map(|x| x.2).unwrap_or(0),
        _ => {}
    }
    let (prefix, want_off) = match pat {
        "tmem_ur" => ("tmem[UR", false),
        "tmem_off" => ("tmem[UR", true),
        "gdesc_ur" => ("gdesc[UR", false),
        "gdesc_off" => ("gdesc[UR", true),
        "idesc_ur" => ("idesc[UR", false),
        "desc_ur" => ("desc[UR", false),
        _ => return 0,
    };
    let body = match s.strip_prefix(prefix).and_then(|r| r.strip_suffix(']')) {
        Some(b) => b,
        None => return 0,
    };
    let (num_s, off_s) = match body.split_once('+') {
        Some((a, b)) => (a, Some(b)),
        None => (body, None),
    };
    // UTMALDG/UTMASTG single-bracket desc[URZ]: the 8-bit window at [47:40]
    // carries 0xFF for the zero uniform register (verified on the 4D bucket).
    let n = if num_s == "Z" { 255 } else { num_s.parse::<u64>().unwrap_or(0) };
    if !want_off {
        return n;
    }
    match off_s {
        Some(o) => o.strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .or_else(|| o.parse::<u64>().ok())
            .unwrap_or(0),
        None => 0,
    }
}

/// 1 when operand `tok`'s raw text carries an explicit "+URZ" qualifier (an
/// addressing-mode toggle distinct from an omitted UR on sm_103a; STS.64
/// corpus records flip bits 9/11/91 and put 0xFF in the UR slot).
fn op_urz_flag(insn: &Instruction, tok: i32) -> u64 {
    if tok <= 0 { return 0; }
    let text = insn.raw_text.trim().trim_end_matches(';').trim();
    let text = regex::Regex::new(r"^@!?\w+\s+").unwrap().replace(text, "");
    let parts: Vec<&str> = text.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 { return 0; }
    let mut depth = 0;
    let mut cur = String::new();
    let mut tokens = Vec::new();
    for ch in parts[1].chars() {
        match ch {
            '[' | '(' => { depth += 1; cur.push(ch); }
            ']' | ')' => { depth -= 1; cur.push(ch); }
            ',' if depth == 0 => { tokens.push(cur.trim().to_string()); cur.clear(); }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() { tokens.push(cur.trim().to_string()); }
    match tokens.get((tok - 1) as usize) {
        Some(t) if t.contains("URZ") => 1,
        _ => 0,
    }
}

fn op_reuse(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Reg { reuse: true, .. }) => 1,
        Some(Operand::UReg { reuse: true, .. }) => 1,
        _ => 0,
    }
}

/// bf16 (round-to-nearest-even via f32) of the float immediate at `tok`
fn op_bf16(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => {
            let b = (f64::from_bits(*v) as f32).to_bits() as u64;
            let r = (b >> 16) & 1;
            (b.wrapping_add(0x7FFF).wrapping_add(r)) >> 16
        }
        _ => 0,
    }
}

/// 1 when the instruction mnemonic's `idx`-th suffix (1-based, counted after
/// the base op name) equals `name` (F2F.F32.F64 vs F2F.F64.F32 direction).
fn op_mnemod(insn: &Instruction, idx: u8, name: &str) -> u64 {
    let text = insn.raw_text.trim().trim_end_matches(';').trim();
    let text = regex::Regex::new(r"^@!?\w+\s+").unwrap().replace(text, "");
    let head = text.split_whitespace().next().unwrap_or("");
    let mods: Vec<&str> = head.split('.').skip(1).collect();
    match mods.get((idx as usize).saturating_sub(1)) {
        Some(m) if m.to_uppercase() == name.to_uppercase() => 1,
        _ => 0,
    }
}

fn op_inv(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Reg { inv: true, .. }) => 1,
        Some(Operand::UReg { inv: true, .. }) => 1,
        Some(Operand::Pred { neg: true, .. }) | Some(Operand::UPred { neg: true, .. }) => 1,
        _ => 0,
    }
}

fn op_abs(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::Reg { abs: true, .. }) => 1,
        Some(Operand::UReg { abs: true, .. }) => 1,
        _ => 0,
    }
}

fn op_byte_sel(insn: &Instruction, tok: i32) -> u64 {
    // .B0/.B1/.B2/.B3 suffix on register operand
    // Extract from raw_text since it's not in the Operand enum
    if tok <= 0 { return 0; }
    // Parse the tok-th operand from raw text
    let text = insn.raw_text.trim().trim_end_matches(';').trim();
    let text = regex::Regex::new(r"^@!?\w+\s+").unwrap().replace(text, "");
    let parts: Vec<&str> = text.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 { return 0; }
    let ops_str = parts[1];
    let mut depth = 0;
    let mut current = String::new();
    let mut tokens = Vec::new();
    for ch in ops_str.chars() {
        match ch {
            '[' | '(' => { depth += 1; current.push(ch); }
            ']' | ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => { tokens.push(current.trim().to_string()); current.clear(); }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() { tokens.push(current.trim().to_string()); }
    if let Some(op_text) = tokens.get((tok - 1) as usize) {
        // Look for .B0, .B1, .B2, .B3
        if let Some(caps) = regex::Regex::new(r"\.B(\d)").unwrap().captures(op_text) {
            return caps[1].parse::<u64>().unwrap_or(0);
        }
    }
    0
}

fn op_hsel(insn: &Instruction, tok: i32) -> u64 {
    // .H0_H0/.H0_H1/.H1_H1 pair-select suffix: none=0, H0_H1=1, H0_H0=2, H1_H1=3
    if tok <= 0 { return 0; }
    let text = insn.raw_text.trim().trim_end_matches(';').trim();
    let text = regex::Regex::new(r"^@!?\w+\s+").unwrap().replace(text, "");
    let parts: Vec<&str> = text.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 { return 0; }
    let ops_str = parts[1];
    let mut depth = 0;
    let mut current = String::new();
    let mut tokens = Vec::new();
    for ch in ops_str.chars() {
        match ch {
            '[' | '(' => { depth += 1; current.push(ch); }
            ']' | ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => { tokens.push(current.trim().to_string()); current.clear(); }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() { tokens.push(current.trim().to_string()); }
    if let Some(op_text) = tokens.get((tok - 1) as usize) {
        if op_text.contains(".H0_H1") { return 1; }
        if op_text.contains(".H0_H0") { return 2; }
        if op_text.contains(".H1_H1") { return 3; }
    }
    0
}

/// 1 if the raw text of operand `tok` carries the modifier `.name`
/// (e.g. opmod:HI_LO for `R106.F32x2.HI_LO`). Used by sm_103a tables where
/// operand suffixes control real encoding bits (FFMA2/HADD2 families).
fn op_mod_flag_value(insn: &Instruction, tok: i32, name: &str) -> u64 {
    if tok <= 0 { return 0; }
    let text = insn.raw_text.trim().trim_end_matches(';').trim();
    let text = regex::Regex::new(r"^@!?\w+\s+").unwrap().replace(text, "");
    let parts: Vec<&str> = text.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 { return 0; }
    let ops_str = parts[1];
    let mut depth = 0;
    let mut current = String::new();
    let mut tokens = Vec::new();
    for ch in ops_str.chars() {
        match ch {
            '[' | '(' => { depth += 1; current.push(ch); }
            ']' | ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => { tokens.push(current.trim().to_string()); current.clear(); }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() { tokens.push(current.trim().to_string()); }
    if let Some(op_text) = tokens.get((tok - 1) as usize) {
        let needle = format!(".{name}");
        // match at a segment boundary: ".HI_LO" must end a dotted suffix
        let mut rest = op_text.as_str();
        while let Some(i) = rest.find(&needle) {
            let after = &rest[i + needle.len()..];
            if after.is_empty() || after.starts_with('.') || after == " " {
                return 1;
            }
            rest = &rest[i + 1..];
        }
    }
    0
}

fn op_sysreg(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::SysReg(name)) => sysreg_id(name),
        _ => 0,
    }
}

/// Sub-part extraction follows Python's sequential bracket parsing order:
/// Desc[UR][R+off]:      sub_ur0=ur_idx, sub_r1=base_reg, sub_imm2=offset
/// Addr[R+off]:          sub_r0=base_reg, sub_imm1=offset
/// Addr[R+UR+off]:       sub_r0=base_reg, sub_ur1=ur_reg, sub_imm2=offset
/// ConstMem c[B][R+off]: sub_imm0=bank, sub_r1=base_reg, sub_imm2=offset
/// ConstMem c[B][UR+off]:sub_imm0=bank, sub_ur1=ur_reg, sub_imm2=offset
fn op_sub_reg(insn: &Instruction, tok: i32, idx: u8) -> u64 {
    match get_op(insn, tok) {
        // Addr[R+off]: R is sub_r0
        Some(Operand::Addr { base_reg, .. }) if idx == 0 => base_reg.map_or(255, |r| r as u64),
        // Desc[UR][R+off]: R is sub_r1 (UR took slot 0)
        Some(Operand::Desc { base_reg, .. }) if idx == 1 => base_reg.map_or(255, |r| r as u64),
        // ConstMem c[B][R+off]: R is sub_r1 (bank took slot 0)
        Some(Operand::ConstMem { base_reg, .. }) if idx == 1 => base_reg.map_or(255, |r| r as u64),
        _ => 0,
    }
}

fn op_sub_ureg(insn: &Instruction, tok: i32, idx: u8) -> u64 {
    match get_op(insn, tok) {
        // Desc[UR][R+off]: UR is sub_ur0
        Some(Operand::Desc { ur_idx, .. }) if idx == 0 => *ur_idx as u64,
        // Addr[R+UR+off]: UR is sub_ur1 (R took slot 0)
        Some(Operand::Addr { base_reg: Some(_), ur_reg, .. }) if idx == 1 => ur_reg.map_or(255, |r| r as u64),
        // Addr[UR+off] (no base_reg): UR is sub_ur0
        Some(Operand::Addr { base_reg: None, ur_reg, .. }) if idx == 0 => ur_reg.map_or(255, |r| r as u64),
        // ConstMem c[B][UR+off]: UR is sub_ur1 (bank took slot 0)
        Some(Operand::ConstMem { ur_reg, .. }) if idx == 1 => ur_reg.map_or(255, |r| r as u64),
        _ => 0,
    }
}

fn op_sub_imm(insn: &Instruction, tok: i32, idx: u8) -> u64 {
    match get_op(insn, tok) {
        // Addr[R+off]: offset is sub_imm1 (R at 0, off at 1)
        // Addr[UR+off]: offset is sub_imm1 (UR at 0, off at 1)
        // Addr[off]: offset is sub_imm0
        Some(Operand::Addr { base_reg: None, ur_reg: None, offset, .. }) if idx == 0 => *offset as u64,
        Some(Operand::Addr { offset, .. }) if idx >= 1 => *offset as u64,
        // Desc[UR][R+off]: offset is sub_imm2 (UR=0, R=1, off=2)
        Some(Operand::Desc { offset, .. }) if idx >= 2 => *offset as u64,
        // ConstMem c[B][...]: bank is sub_imm0
        // c[B][R+off]: R takes slot 1, offset is sub_imm2
        // c[B][off]:   no R, offset is sub_imm1
        Some(Operand::ConstMem { bank, .. }) if idx == 0 => *bank as u64,
        Some(Operand::ConstMem { base_reg: Some(_), offset, .. }) if idx >= 2 => *offset as u64,
        Some(Operand::ConstMem { ur_reg: Some(_), offset, .. }) if idx >= 2 => *offset as u64,
        Some(Operand::ConstMem { base_reg: None, ur_reg: None, offset, .. }) if idx >= 1 => *offset as u64,
        _ => 0,
    }
}

fn op_cm_off(insn: &Instruction, tok: i32, bank_shift: u8) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::ConstMem { bank, offset, .. }) => {
            let b = (*bank as u64) << bank_shift;
            let o = (*offset as u64) & ((1u64 << bank_shift) - 1);
            b | o
        }
        _ => 0,
    }
}

/// Extract opaque modifier value from SASS text.
/// The printer emits ".?6.?0.?1" for three opaque_mod fields (in field order).
/// Since fields are processed in table order, we use a thread-local counter
/// to map the Nth opaque_mod field to the Nth ?-value in the text.
fn extract_opaque_mod(sass: &str, _shift: u32, _bits: u32) -> u64 {
    use std::cell::RefCell;
    thread_local! {
        static STATE: RefCell<(String, usize)> = const { RefCell::new((String::new(), 0)) };
    }

    let opcode_part = sass.split_whitespace().next().unwrap_or("");
    let opcode_part = if opcode_part.starts_with('@') {
        sass.split_whitespace().nth(1).unwrap_or(opcode_part)
    } else {
        opcode_part
    };

    let mut values: Vec<u64> = Vec::new();
    for part in opcode_part.split('.') {
        if let Some(token) = part.strip_prefix('?') {
            if let Ok(v) = u64::from_str_radix(token, 16) {
                values.push(v);
            } else if let Some(v) = parse_opaque_name(token) {
                values.push(v);
            }
        }
    }

    STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        if state.0 != sass {
            state.0 = sass.to_string();
            state.1 = 0;
        }
        let idx = state.1;
        state.1 += 1;
        values.get(idx).copied().unwrap_or(0)
    })
}

/// Map semantic opaque modifier names back to numeric values.
/// Handles all names emitted by printer's resolve_opaque_mod.
fn parse_opaque_name(name: &str) -> Option<u64> {
    match name {
        // REDUX function codes (shift=78, bits=3)
        // and combine modes (shift=91, bits=2)
        "AND" => Some(0), "OR"  => Some(1), "XOR" => Some(2),
        "SUM" => Some(3), "MIN" => Some(4), "MAX" => Some(5),
        // Comparison codes (shift=76, bits=3)
        "LT"  => Some(1), "EQ"  => Some(2), "LE"  => Some(3),
        "GT"  => Some(4), "NE"  => Some(5), "GE"  => Some(6),
        // Signed flag (shift=73, bits=1)
        "U32" => Some(0), "S32" => Some(1),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Branch encoding
// ---------------------------------------------------------------------------

const BSSY_OPS: &[&str] = &["BSSY", "BSYNC", "BREAK"];
const BRANCH_OPS: &[&str] = &["BRA", "BRA.U", "BRX", "BRXU", "CALL", "JMP", "RET", "RET.NODEC", "BSSY", "BSYNC", "BREAK"];

fn apply_branch_encoding(insn: &Instruction, mut code: u128, mod_group: &str, sm103a: bool) -> u128 {
    if !BRANCH_OPS.iter().any(|&o| insn.opcode == o)
        && !(sm103a && insn.opcode == "WARPSYNC") { return code; }

    let op = insn.opcode.as_str();

    // sm_103a PC-relative 16-bit branch immediate, verified on the B300 corpus
    // (98,821 CALL + 10,346 RET samples): imm = (target - addr - 16) >> 4,
    // imm[5:0] at word bits [23:18], imm[15:6] at [43:34], sign extension into
    // [63:44]. Applies to CALL.REL.NOINC, RET.REL.NODEC and WARPSYNC.COLLECTIVE
    // (the R_II form whose immediate operand is a code address), superseding
    // the SM120 dword-split layout (which lands the offset at [23:16]+[63:32]).
    // sm_103a: BRA.DIV also uses the REL16 layout (imm16@([23:18]|[43:34]),
    // mod_bits=2 at [33:32]) — fitted on 14,924 corpus-gap samples (GF2 exact).
    let rel_mod = mod_group.split(',').any(|m| m == "REL" || m == "COLLECTIVE")
        || (op == "BRA" && mod_group.split(',').any(|m| m == "DIV"));
    if sm103a && rel_mod
        && (op == "CALL" || op.starts_with("RET") || op == "BRA"
            || (op == "WARPSYNC" && insn.operands.iter().any(|o| matches!(o, Operand::Reg{..}))))
    {
        if let Some(target) = find_branch_target(insn) {
            let rel = target - insn.addr as i64 - 16;
            let rq = rel >> 4;                 // arithmetic shift keeps the sign
            let imm16 = (rq as i64) & 0xFFFF;
            code = (code & !(0x3F_u128 << 18)) | (((imm16 & 0x3F) as u128) << 18);
            code = (code & !(0x3FF_u128 << 34)) | ((((imm16 >> 6) & 0x3FF) as u128) << 34);
            if imm16 & 0x8000 != 0 {
                code |= 0xFFFF_Fu128 << 44;    // sign extension into [63:44]
            }
            // rel >= 0: bits [63:44] carry only and_base constants — untouched.
        }
        if op == "WARPSYNC" || op == "BRA" {
            return code;
        }
        // fall through for CALL/RET: RET register placement below still applies
    } else if op == "WARPSYNC" {
        return code;    // no legacy WARPSYNC handling
    }

    // BRX/BRXU: offset from register, second operand
    if op == "BRX" || op == "BRXU" {
        if sm103a && op == "BRX" {
            // sm_103a layout, verified on the 77-record B300 corpus: the
            // immediate operand (signed byte offset as printed; with a label
            // operand, pc-relative target-addr-16) is encoded as the 17-bit
            // instruction-scale value rq = offset >> 4 (arithmetic shift):
            // rq[5:0] at word bits [23:18], rq[16:6] at [44:34], sign
            // extension into [63:45].
            let v = match insn.operands.get(1) {
                Some(Operand::Imm32(x)) => Some(*x as i64),
                Some(Operand::Imm64(x)) => Some(*x as i64),
                // corpus disassembly annotates the numeric offset with a
                // (*"BRANCH_TARGETS ..."*) comment, which the parser keeps as
                // a Label; scrape the leading numeric literal.
                Some(Operand::Label(s)) => {
                    let head = s.trim_start().split_whitespace().next().unwrap_or("");
                    let sv = head.strip_prefix("-0x")
                        .and_then(|h| u64::from_str_radix(h, 16).ok().map(|v| -(v as i64)))
                        .or_else(|| head.strip_prefix("0x")
                            .and_then(|h| u64::from_str_radix(h, 16).ok().map(|v| v as i64)))
                        .or_else(|| head.parse::<i64>().ok());
                    sv.or_else(|| find_branch_target(insn)
                        .map(|t| t as i64 - insn.addr as i64 - 16))
                }
                _ => find_branch_target(insn).map(|t| t as i64 - insn.addr as i64 - 16),
            };
            if let Some(v) = v {
                let rq = v >> 4;
                let imm17 = (rq as u64) & 0x1FFFF;
                code &= !((0x3F_u128 << 18) | (0x7FF_u128 << 34));
                code |= ((imm17 & 0x3F) as u128) << 18;
                code |= (((imm17 >> 6) & 0x7FF) as u128) << 34;
                code &= !(0x7FFFF_u128 << 45);
                if imm17 & 0x10000 != 0 {
                    code |= 0x7FFFF_u128 << 45;
                }
            }
            return code;
        }
        // BRXU.U URn, imm (dispatch-table form, two operands): the imm token
        // is a raw byte offset — legacy semantics, legacy layout.
        if let Some(Operand::Imm32(offset)) = insn.operands.get(1) {
            let rq = if *offset >= 0 { *offset >> 2 } else { -((-*offset) >> 2) };
            code = (code & !(0xFF_u128 << 16)) | (((rq & 0xFF) as u128) << 16);
            let t32 = (((rq >> 8) << 2) as u64) & 0xFFFFFFFF;
            code = (code & !(0xFFFFFFFF_u128 << 32)) | ((t32 as u128) << 32);
            if *offset < 0 { code |= 0x3FFFF_u128 << 64; }
            return code;
        }
        // BUG-027 (sm_120): single-token absolute-target form (`BRXU 0xT` /
        // label). The disassembler renders this form in the nvdisasm absolute
        // convention (`pc + 0x10 + rel`, rel = rq*4, rq at [23:16] with the
        // rest at [63:32]>>2<<8) — the same dword-split layout as BRA. The
        // legacy path only fired on a second immediate operand, so the
        // single-token form fell back to the harvest-artifact BRXU_II table
        // field imm@[39:19], whose absolute-target value aliased into the
        // dword-split region and silently dropped offset bits (observed:
        // rendered target off by -0x200 for (pc,T)=(0x9cc0,0xc840)/
        // (0x9b60,0xc6e0); silicon HANG on a shifted-layout kernel). Encode
        // the absolute target like BRA does, shadowing the bogus table-field
        // write over the branch-owned region.
        if insn.operands.len() == 1 {
            if let Some(target) = find_branch_target(insn) {
                let rel = target - insn.addr as i64 - 16;
                let rq = if rel >= 0 { rel >> 2 } else { -((-rel) >> 2) };
                code = (code & !(0xFF_u128 << 16)) | (((rq & 0xFF) as u128) << 16);
                let t32 = (((rq >> 8) << 2) as u64) & 0xFFFFFFFF;
                code = (code & !(0xFFFFFFFF_u128 << 32)) | ((t32 as u128) << 32);
                if rel < 0 { code |= 0x3FFFF_u128 << 64; }
            }
        }
        return code;
    }

    // BSSY/BSYNC/BREAK: byte offset at [63:32]
    if BSSY_OPS.contains(&op) {
        if let Some(target) = find_branch_target(insn) {
            let rel = target - insn.addr as i64 - 16;
            code = (code & !(0xFFFFFFFF_u128 << 32)) | (((rel as u64 & 0xFFFFFFFF) as u128) << 32);
        }
        return code;
    }

    // BRA/CALL/JMP/RET: dword-split encoding (SM120 layout; on sm_103a the
    // REL forms were already handled above and must not be double-written)
    let sm103a_rel_done = sm103a && rel_mod && (op == "CALL" || op.starts_with("RET") || op == "BRA");
    if let Some(target) = find_branch_target(insn).filter(|_| !sm103a_rel_done) {
        let is_abs = mod_group.split(',').any(|m| m == "ABS");
        if !is_abs {
            let rel = target - insn.addr as i64 - 16;
            let rq = if rel >= 0 { rel >> 2 } else { -((-rel) >> 2) };

            // [23:16] = low byte of rq
            code = (code & !(0xFF_u128 << 16)) | (((rq & 0xFF) as u128) << 16);

            // [63:32] = ((rq >> 8) << 2) | modifier_bits
            let mods: std::collections::HashSet<&str> = mod_group.split(',').collect();
            let mod_bits: u64 = if mods.contains("U") { 1 }
                else if mods.contains("DIV") { 2 }
                else if mods.contains("CONV") { 3 }
                else { 0 };
            let t32 = ((((rq >> 8) << 2) as u64) | mod_bits) & 0xFFFFFFFF;
            code = (code & !(0xFFFFFFFF_u128 << 32)) | ((t32 as u128) << 32);

            // Sign extension at [81:64]
            if rel < 0 { code |= 0x3FFFF_u128 << 64; }
        }
    }

    // RET: encode register at bits[31:24] for RET with register operand
    if op == "RET" || op.starts_with("RET.") {
        for operand in &insn.operands {
            if let Operand::Reg { num, .. } = operand {
                code = (code & !(0xFF_u128 << 24)) | ((*num as u128) << 24);
                break;
            }
        }
    }

    // BRA.U: encode uniform predicate at bits[26:24] and negation at bit 27
    if op == "BRA" || op == "BRA.U" {
        // Look for a UPred operand among the instruction operands
        for operand in &insn.operands {
            if let Operand::UPred { num, neg, .. } = operand {
                // Clear bits[27:24] first
                code &= !(0xF_u128 << 24);
                // Set uniform pred number at bits[26:24]
                code |= ((*num as u128) & 0x7) << 24;
                // Set negation at bit 27
                if *neg { code |= 1u128 << 27; }
                break;
            }
        }
    }

    code
}

// ---------------------------------------------------------------------------
// Format-aware reuse encoding
// ---------------------------------------------------------------------------

/// Reuse bits 122/123/124 correspond to register slots Ra/Rb/Rc.
/// Derive which operand maps to each slot from the field table,
/// then set the reuse bit based on that operand's .reuse flag.
fn apply_reuse_encoding(insn: &Instruction, mut code: u128, entry: &crate::table::ModGroupEntry) -> u128 {
    // Reuse bit → register slot shift
    const REUSE_SLOTS: [(u32, u32); 3] = [(122, 24), (123, 32), (124, 64)];

    let explicit_reuse_toks: Vec<i32> = entry.fields.iter()
        .filter(|f| matches!(f.extraction, Extraction::Reuse))
        .map(|f| f.token_idx)
        .collect();
    // sm_103a tables carry explicit Reuse fields at these bits; when present
    // the field-level value is authoritative and the legacy slot fixup must
    // not touch that bit (its slot_shift->tok mapping misfires on variants
    // like IMAD_UR where shift 32 holds a UR operand, wiping bit 123).
    let explicit_reuse_bits: Vec<u32> = entry.fields.iter()
        .filter(|f| matches!(f.extraction, Extraction::Reuse))
        .map(|f| f.shift)
        .collect();

    for &(reuse_bit, slot_shift) in &REUSE_SLOTS {
        if explicit_reuse_bits.contains(&reuse_bit) { continue; }
        let slot_tok = entry.fields.iter()
            .find(|f| f.shift == slot_shift && f.bits == 8
                && matches!(f.extraction, Extraction::Reg | Extraction::UReg
                    | Extraction::URegFf | Extraction::RegFf))
            .map(|f| f.token_idx);

        if let Some(tok) = slot_tok {
            if explicit_reuse_toks.contains(&tok) { continue; }
            let has_reuse = matches!(get_op(insn, tok), Some(Operand::Reg { reuse: true, .. }) | Some(Operand::UReg { reuse: true, .. }));
            if has_reuse {
                code |= 1u128 << reuse_bit;
            } else {
                code &= !(1u128 << reuse_bit);
            }
        }
    }

    // PLOP3.LUT fixup: bits[64:66] = (lut1 XOR lut2) & 7 when non-trivial preds.
    // Hardware uses this as a fast-evaluation hint for the predicate LUT.
    // sm_103a learns bits 64..66 as the real low-3 slice of LUT imm0; when a
    // table field covers that region, trust the table and skip the fixup.
    let taught_64_66 = entry.fields.iter()
        .any(|f| f.shift < 67 && f.shift + f.bits > 64);
    if (insn.opcode.starts_with("PLOP3") || insn.opcode.starts_with("LOP3"))
        && !taught_64_66 {
        // Find LUT values (the two integer immediate operands, typically last two)
        let imms: Vec<u64> = insn.operands.iter().filter_map(|o| match o {
            Operand::Imm32(v) => Some(*v as u64),
            _ => None,
        }).collect();
        // Check if INPUT predicates (Pa, Pb, Pc = operands 2,3,4) are non-PT.
        // Operands: Pd(0), Ps(1), Pa(2), Pb(3), Pc(4), lut1(5), lut2(6)
        let has_real_input_pred = insn.operands.iter().skip(2).any(|o| match o {
            Operand::Pred { num, .. } => *num != 7, // P0-P6 are "real" (PT=7)
            _ => false,
        });
        if imms.len() >= 2 && has_real_input_pred {
            let xor_lo3 = ((imms[0] ^ imms[1]) & 7) as u128;
            code = (code & !(7u128 << 64)) | (xor_lo3 << 64);
        }
    }

    // FADD neg-on-RZ fixup: when Rb is -RZ, encode as abs (bit63) not neg (bit62).
    // nvcc optimization: -0 = |0| = 0, so nvcc uses abs encoding for -RZ.
    // Only apply if -RZ is the operand whose neg/abs bits live at 62/63
    // (i.e., the token_idx of the neg field at shift 62). This avoids
    // clobbering bits that belong to a different operand (e.g. |UR16|).
    if insn.opcode.starts_with("FADD") {
        let neg62_tok = entry.fields.iter()
            .find(|f| f.shift == 62 && f.bits == 1
                && matches!(f.extraction, Extraction::Neg | Extraction::Abs))
            .map(|f| f.token_idx);
        let rb_tok = neg62_tok.unwrap_or(3);  // standard: tok3 = Rb
        if let Some(Operand::Reg { num: 255, neg: true, .. }) = get_op(insn, rb_tok) {
            // Check if bit62 is set (neg encoding) — swap to bit63 (abs encoding)
            if (code >> 62) & 1 == 1 && (code >> 63) & 1 == 0 {
                code &= !(1u128 << 62); // clear neg bit
                code |= 1u128 << 63;    // set abs bit
            }
        }
    }

    code
}

fn find_branch_target(insn: &Instruction) -> Option<i64> {
    insn.operands.iter().find_map(|o| match o {
        Operand::BranchTarget(t) => Some(*t as i64),
        Operand::Imm32(v) => Some(*v),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Batch encoding
// ---------------------------------------------------------------------------

pub fn encode_all(insns: &[Instruction], table: &IsaTable) -> Result<Vec<u128>> {
    insns.iter().map(|i| encode_instruction(i, table)
        .with_context(|| format!("at 0x{:x}: {}", i.addr, i.raw_text))).collect()
}
