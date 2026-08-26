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
/// Name -> raw encoded value. Grounded in an nvdisasm-13.3 sm_120 name sweep
/// (BUG-r043, F2-iter7): all 256 codes probed through the encoder's SR_0x<hex>
/// escape hatch and read back with nvdisasm; every name below matches the
/// nvdisasm render word-for-word. SR_NTID (0x28) additionally silicon-verified
/// (sm120 i120: returns blockDim). sm_120 has NO codes for SR_NTID.Y/.Z,
/// SR_NCTAID.*, SR_WARPID, SR_SMID or SR_GRIDID — literature values (0x29/0x2a,
/// 0x2c..0x2e, 0x40/0x42/0x44) name OTHER registers in the nvdisasm sm_120
/// table, so mapping them there would re-create the BUG it fixes. Unknown
/// names are fail-closed (None) instead of silently encoding as SR_LANEID(0).
fn sysreg_id(name: &str) -> Option<u64> {
    let id = match name {
        "SR_LANEID" => 0x00,
        "SR_ORDERING_TICKET" => 0x0f,
        "SR_TID" => 0x20,
        "SR_TID.X" | "SR_TID_X" => 0x21,
        "SR_TID.Y" | "SR_TID_Y" => 0x22,
        "SR_TID.Z" | "SR_TID_Z" => 0x23,
        "SR_CTAID.X" | "SR_CTAID_X" => 0x25,
        "SR_CTAID.Y" | "SR_CTAID_Y" => 0x26,
        "SR_CTAID.Z" | "SR_CTAID_Z" => 0x27,
        "SR_NTID" | "SR_NTID.X" | "SR_NTID_X" => 0x28,
        "SR_SWINHI" => 0x2f,
        "SR_SWINLO" => 0x30,
        "SR_SWINSZ" => 0x31,
        "SR_SMEMSZ" => 0x32,
        "SR_SMEMBANKS" => 0x33,
        "SR_LWINLO" => 0x34,
        "SR_LWINSZ" => 0x35,
        "SR_LMEMLOSZ" => 0x36,
        "SR_LMEMHIOFF" => 0x37,
        "SR_EQMASK" => 0x38,
        "SR_LTMASK" => 0x39,
        "SR_LEMASK" => 0x3a,
        "SR_GTMASK" => 0x3b,
        "SR_GEMASK" => 0x3c,
        "SR_GLOBALERRORSTATUS" => 0x40,
        "SR_CGAERRORSTATUS" => 0x41,
        "SR_WARPERRORSTATUS" => 0x42,
        "SR_VIRTUALSMID" => 0x43,
        "SR_VIRTUALENGINEID" => 0x44,
        "SR_CLOCKLO" => 0x50,
        "SR_CLOCKHI" => 0x51,
        "SR_GLOBALTIMERLO" => 0x52,
        "SR_GLOBALTIMERHI" => 0x53,
        "SR_VARIABLE_RATE" => 0x84,
        "SR_CgaCtaId" => 0x88,
        "SR_GpcLocalCgaId" => 0x89,
        "SR_CgaSize" => 0x8a,
        "SR_CTARegPoolSz" => 0x8b,
        "SR_TMemSz" => 0x8d,
        "SRZ" => 0xff,
        // Numeric escape hatch: SR_0x<hex> keeps any raw code (also unknown to
        // nvdisasm) encodable bit-exactly.
        _ => {
            let h = name.strip_prefix("SR_0x")?;
            u64::from_str_radix(h, 16).ok()?
        },
    };
    Some(id)
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

        // Float immediates / value-cast float: read the value itself.
        NegF32 | F32Cast => matches!(op, Operand::FloatImm(_) | Operand::Imm32(_)),

        Reg | RegShr(_) => matches!(op,
            Operand::Reg { .. } | Operand::Addr { .. } | Operand::Desc { .. }),
        RegFf => matches!(op, Operand::Reg { .. } | Operand::UReg { .. }),
        UReg | URegShr(_) => matches!(op,
            Operand::UReg { .. } | Operand::Addr { .. } | Operand::Desc { .. }),
        URegFf => matches!(op, Operand::UReg { .. }),
        Pred => matches!(op, Operand::Pred { .. } | Operand::UPred { .. }),
        PredInv4 => matches!(op, Operand::Pred { .. } | Operand::UPred { .. }),
        UPredGate => matches!(op, Operand::UPred { .. } | Operand::Pred { .. }),
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
        | SubImm(_) | SubImmS24(_) | SubImmShr(..) | SubImmShrU(..) => matches!(op,
            Operand::Addr { .. } | Operand::Desc { .. } | Operand::ConstMem { .. }),
        Cm16Off | Cm17Off => matches!(op, Operand::ConstMem { .. }),
    }
}

/// BUG-071: detect harvest-artifact rows that would emit baked junk for a
/// default-payload operand. `key` is the table key that matched (the sibling
/// set); `entry` the concrete mod-group entry. Returns Some(reason) when an
/// operand is default (immediate 0 or URZ) on a token the entry has NO field
/// for, while a same-key sibling owns an imm/ureg-class field for that token
/// and this entry's and_base carries non-zero bits inside the sibling window
/// (that window is genuinely the operand's payload slot).
fn zero_payload_junk(
    insn: &Instruction,
    key: &str,
    entry: &crate::table::ModGroupEntry,
    table: &IsaTable,
) -> Option<String> {
    // Branch targets (and other fixup-owned payloads) are encoded by
    // apply_branch_encoding; and_base bits there are placeholders by design.
    if BRANCH_OPS.iter().any(|&o| insn.opcode == o) {
        return None;
    }
    let ike = table.entries.get(key)?;
    // Sibling-proven imm/ureg payload windows per token.
    let mut win: std::collections::HashMap<i32, u128> = std::collections::HashMap::new();
    for sib in ike.mod_groups.values() {
        for f in &sib.fields {
            if f.token_idx <= 0 { continue; }
            if ext_encodes_imm(&f.extraction) || ext_encodes_ureg(&f.extraction) {
                let m: u128 = if f.bits >= 128 { u128::MAX }
                    else { ((1u128 << f.bits) - 1) << f.shift };
                *win.entry(f.token_idx).or_default() |= m;
            }
        }
    }
    if win.is_empty() {
        return None;
    }
    for (oi, op) in insn.operands.iter().enumerate() {
        let tok = (oi + 1) as i32;
        let Some(w) = win.get(&tok) else { continue };
        // Only default payloads are at risk (non-zero immediates are rejected by
        // completeness when no field exists for their token).
        let is_default = matches!(op,
            Operand::Imm32(0) | Operand::Imm64(0) | Operand::UReg { is_zero: true, .. });
        if !is_default {
            continue;
        }
        if entry.fields.iter().any(|f| f.token_idx == tok) {
            continue; // entry covers the token
        }
        let junk = entry.and_base & !(0xFFFFFFFF_u128 << 96) & w;
        if junk != 0 {
            return Some(format!(
                "BUG-071-class: operand {tok} (default payload) has no field in \
                 this entry, and and_base carries junk bits 0x{junk:x} in the \
                 sibling-proven payload window; row would emit baked constants \
                 (harvest artefact — needs a table repair, not assembly)"));
        }
    }
    None
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
        | Extraction::SubImmShrU(..)
        | Extraction::Cm16Off | Extraction::Cm17Off
        | Extraction::F16 | Extraction::F16d | Extraction::BF16
        // KAND-058: value-cast f32 payload carrier for float/int-immediates.
        | Extraction::F32Cast)
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
    // Branch-family targets (and the RET register / BRA.U upred) are encoded by
    // apply_branch_encoding, not by table fields. Until BUG-023 this skipped
    // ALL checks for branch ops, which let wrong-shape harvest artifacts (a
    // stale `BRA.DIV_P_UR_II` key carrying UR_II-shaped fields) shadow the
    // correct entry in the fk-first lookup chain and silently drop predicate /
    // uniform-register operands (encode "BRA.DIV P0, URZ, 0x.." wrote the
    // artifact's and_base: pred=7, ureg=0). Branch ops therefore skip only what
    // the fixup owns (imm/label targets, RET's register, BRA.U's upred); the
    // register-class completeness below still applies. The per-field type
    // check stays skipped for branches: legacy fixup-shadowed entries carry
    // intentionally loose field/token pairings (BRXU_L, BRXU_II) that only the
    // fixup makes coherent.
    let is_branch = BRANCH_OPS.iter().any(|&o| insn.opcode == o);
    // Raw-address LDG/STG bypass the field system entirely (full lo64 rebuild).
    if (insn.opcode == "LDG" || insn.opcode == "STG")
        && insn.operands.iter().any(|op| matches!(op, Operand::Addr { .. }))
        && !insn.operands.iter().any(|op| matches!(op, Operand::Desc { .. })) {
        // BUG-099/095: uniform-indexed GLOBAL addresses ([Rn.U32+URm..] vs
        // [Rn.64+URm..]) differ in a REAL encoding mode (bits [92:90]); rows
        // for both textual forms sit under the same key+mg, so the bracket
        // suffix is the only discriminator. A row pinning `addr_width` must
        // match the textual suffix — pre-fix the ".64" text silently encoded
        // the ".U32" mode word. Runs BEFORE the raw-address Ok bypass: LOUD
        // rejection here steers the lookup chain to the sibling row.
        if let Some(Operand::Addr { ur_reg: Some(_), base_reg_suffix: Some(sfx), .. }) =
            insn.operands.iter().find(|op| matches!(op, Operand::Addr { .. }))
        {
            if let Some(w) = entry.addr_width.as_deref() {
                if matches!(sfx.as_str(), "U32" | "64") && sfx.as_str() != w {
                    return Err(format!(
                        "addr width .{sfx} (row pins .{w}; pick the sibling row)"));
                }
            }
        }
        return Ok(());
    }

    // 1. Type check (non-branch ops only, see above)
    if !is_branch {
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
            // BUG-023: operands owned by apply_branch_encoding are exempt from
            // field-carry requirements (their bits come from the fixup).
            Operand::Imm32(_) | Operand::Imm64(_) | Operand::Label(_)
                if is_branch => continue,
            Operand::Reg { .. } if is_branch && insn.opcode.starts_with("RET") => continue,
            Operand::UPred { .. } if is_branch
                && (insn.opcode == "BRA" || insn.opcode == "BRA.U") => continue,
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
                if !fields_for_tok().any(|f| matches!(f.extraction,
                    Extraction::Pred | Extraction::UPredGate | Extraction::PredInv4)) {
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
            Operand::SysReg(name) => {
                // BUG-r043 fail-closed: an unknown SR name must NOT degrade to
                // SR_LANEID (0). Numeric escape hatch remains SR_0x<hex>.
                let id = sysreg_id(name).ok_or_else(|| format!(
                    "unknown sysreg {name:?} for this arch (encode the raw code                      as SR_0x<hex> if intentional)"))?;
                if id != 0
                    && !fields_for_tok().any(|f| matches!(f.extraction,
                        Extraction::SysReg | Extraction::SysRegLo7 | Extraction::SysRegLo4
                        | Extraction::SysRegHi4 | Extraction::SysRegHi1))
                {
                    return missing(name);
                }
            }
            Operand::Barrier(b) if *b != 0 => {
                if !fields_for_tok().any(|f| matches!(f.extraction, Extraction::Barrier)) {
                    return missing(&format!("B{b}"));
                }
            }
            Operand::Addr { ur_reg, offset, base_reg_suffix, .. } => {
                // base_reg is placed at bits[31:24] by the encoder fixup when the
                // entry lacks the field, so it is always encodable.
                // BUG-099/095: same width-pin rule as the raw-address fast path
                // above, for LDG/STG forms WITH desc or non-global Addr users.
                if let (Some(sfx), Some(w)) = (base_reg_suffix.as_deref(), entry.addr_width.as_deref()) {
                    if ur_reg.is_some() && matches!(sfx, "U32" | "64") && sfx != w {
                        return missing(&format!(
                            "addr width .{sfx} (row pins .{w}; pick the sibling row)"));
                    }
                }
                if ur_reg.is_some_and(|u| u != 63)
                    && !fields_for_tok().any(|f| ext_encodes_ureg(&f.extraction)) {
                    return missing("addr UR");
                }
                if *offset != 0 && !fields_for_tok().any(|f| ext_encodes_imm(&f.extraction)) {
                    return missing(&format!("addr offset 0x{offset:x}"));
                }
                // BUG-017: a scaled-index suffix (.X4/.X8/.X16) is real silicon
                // state (addr_scale field [79:78]); an entry without the field
                // would DROP it silently — refuse instead of miss-encoding.
                if let Some(sfx) = base_reg_suffix.as_deref() {
                    if matches!(sfx, "X4" | "X8" | "X16")
                        && !fields_for_tok().any(|f| matches!(f.extraction,
                            Extraction::AddrScale)) {
                        return missing(&format!("addr scale suffix .{sfx}"));
                    }
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
// Errata guards — silicon findings (BUG-001..011).
// Each rule converts a previously SILENT mis-encode into a hard
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

/// BUG-002 scoped per-arch (BUG-049 register: cubit encoder hard-rejected
/// `IMAD.HI[.U32]` on EVERY target, but the broken-HI erratum is
/// silicon-verified on sm_120 ONLY — sm_121a silicon (SPARK q3, GB10) runs
/// nvcc's IMAD.HI.U32 encodings with correct hi32 and Rd+1 untouched, and
/// the sm_103a corpus carries ptxas-emitted IMAD.HI forms hardware honors.
/// On non-120 targets the table is authoritative exactly like for every
/// other opcode: a matching entry encodes the text, a missing entry fails
/// honestly at lookup (no operand-compatible entry). Additionally, the table
/// loader now maps SM121A (_meta.architecture) to real e_flags, so a genuine
/// sm_121a table no longer pretends to be sm_120 here.
fn check_imad_hi_erratum(insn: &Instruction, table: &IsaTable) -> Result<()> {
    let is_imad = insn.opcode == "IMAD";
    let has_hi = insn.modifiers.iter().any(|m| m == ".HI");
    if !is_imad || !has_hi {
        return Ok(());
    }
    // On sm_120 no harvested entry is trustworthy: silicon proved the "HI"
    // encodings execute as IMAD.WIDE.U32 regardless of which entry matched.
    // The poisoned entries were removed from tables/sm120.json, and every
    // `.HI` IMAD text stays fail-closed there. Other targets: silicon-truth
    // is that of their own table (verified on sm_121a per BUG-049).
    if table.target_sm() != 120 {
        return Ok(());
    }
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

/// BUG-132: reject when the lookup chain's selected row cannot express every
/// requested mnemonic modifier. The claim set is computed from the PRINTER's
/// render of the produced word (not the raw InsKey, whose mods may contain
/// '_' themselves, e.g. `BAR.SYNC.DEFER_BLOCKING_II`): the printed text is
/// exactly what a human would re-feed, and corpus roundtrips pin the printer
/// to claim every bit the row encodes. Every requested mod must be claimed
/// (superset rule — see the call-site comment). A miss means the author's
/// modifiers were silently dropped into a different variant: fail loudly.
fn verify_mod_group_retained(
    insn: &Instruction,
    table: &IsaTable,
    out: u128,
    requested_mg: &str,
    selected_mg: &str,
) -> Result<()> {
    let idx = table.decode_index();
    let decoded = idx.decode(out, insn.addr, table).with_context(|| {
        format!(
            "encoded word does not decode back under this table              (requested mod-group {requested_mg:?} fell back to row              {selected_mg:?}; insn: {})",
            insn.raw_text.trim()
        )
    })?;
    let back_text = crate::printer::to_sass(&decoded);
    let claimed_mg = crate::table::extract_mod_group(&back_text);
    let claimed: std::collections::BTreeSet<&str> = claimed_mg.split(',')
        .filter(|m| !m.is_empty())
        .collect();
    let mut missing: Vec<&str> = requested_mg.split(',')
        .filter(|m| !m.is_empty() && !claimed.contains(*m))
        .collect();
    missing.sort_unstable();
    missing.dedup();
    // Tolerated mod-drop idioms: load-bearing authoring forms whose produced
    // word is pinned byte-exact elsewhere while the DECODER cannot claim the
    // mods (render-claim gap / mod-baked wildcard row era). Scoped to
    // (opcode, missing-mod-set) — anything outside fails closed below.
    //   F2FP ...PACK_AB_MERGE_C via the `{fk}_?` wildcard row (sm120; qpack
    //     production kernel, tests/encoding::test_wildcard_suffix_chain_):
    //     render splits the token into PACK_AB + MERGE_C (plus RZ tail).
    //   REDUX.ADD.U32 (sm103a, tests/bug080 t5): table models the reduction
    //     op as SUM/"" (bits [79:78]=00), decode claims nothing; vendor
    //     2049-cubin corpus shows only .OR. Follow-up: REDUX default-op
    //     census on silicon.
    // NOTE: `LDC.128` R-domain forms were REMOVED from this list (BUG-135):
    //   the pre-132 encoder silently dropped the width and the pinned word
    //   (bug088 t5, W_LDC128_R53) is in fact a PLAIN 32-bit LDC word —
    //   nvdisasm renders it as plain `LDC`, the R-domain width enum
    //   [74:73] has codes 2/3 rendered INVALID6/INVALID7 by nvdisasm
    //   (graft probes ldc_graft.cubin, sm_103a + sm_120a alike), ptxas
    //   decomposes 128-bit constant loads into 2x LDC.64, and the 2049-cubin
    //   vendor corpus contains ZERO R-domain `LDC.128` renders (only the
    //   uniform-domain LDCU.128 exists, width bit74). The BUG-088 silicon
    //   campaign's "LDC.128 unconstrained" conclusion is vacuous: those
    //   probes executed width-dropped 32-bit LDC words. Authoring guidance:
    //   use 2x LDC.64 — there is no R-domain 128-bit constant load.
    const MOD_DROP_TOLERATED: &[(&str, &[&str])] = &[
        ("F2FP", &["PACK_AB_MERGE_C"]),
        ("REDUX", &["ADD", "U32"]),
    ];
    for &(op, mods) in MOD_DROP_TOLERATED {
        if insn.opcode == op && missing.iter().all(|m| mods.contains(m)) {
            return Ok(());
        }
    }
    anyhow::ensure!(
        missing.is_empty(),
        "silent modifier drop (BUG-132): {} requested mod-group {:?} but the          selected row {:?} does not encode it — the produced word decodes          back as {:?} (mod-group {:?}; missing: [{}]). No table row expresses          this modifier combination; continuing would emit a DIFFERENT variant          silently. Write a supported combination (see the table's {} groups)          or extend the table.",
        insn.raw_text.trim(), requested_mg, selected_mg,
        back_text.trim(), claimed_mg, missing.join(","), insn.opcode_full,
    );
    Ok(())
}

/// BUG-006: a NEGATED predicate operand whose slot has no negation encoding in
/// the selected form must never silently degrade to the non-negated predicate
/// (silicon then reads the un-negated value — measured exactly that on
/// IMAD.WIDE.U32.X carry-in). Re-encode with the negation flipped; a
/// bit-identical word proves the neg bit has no representation here.
fn check_pred_neg_encoded(insn: &Instruction, table: &IsaTable, out: u128) -> Result<()> {
    // Scoped to `.X` carry-chain forms: their tail carry-in predicate is a
    // REAL architectural operand (silicon reads cin — measured the
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


/// BUG-037: warp-level MMA register-operand alignment. Multi-register MMA
/// operands must be aligned to their register-tuple width; silicon runs
/// misaligned forms as ILLEGAL_INSTRUCTION while the encoder used to accept
/// them silently (sm120 measured tables; BUG-037 repro:
/// `IMMA.16832.S8.S8 R8, R42, R44, R8` with A=R42 -> silicon ILLEGAL).
///
/// Fail-closed ONLY on silicon-measured (opcode, shape, accum) combos —
/// arithmetic width guesses were falsified by silicon (HMMA.1688.F32 A is
/// quad-aligned despite a nominally narrower A), so unmeasured space
/// (SP/SF forms, F16 accumulators, IMMA.16816, QMMA.16816, HMMA.1684,
/// UR-space UTC*/DMMA) keeps its previous accept-behavior:
///   IMMA.16832.* (acc S32):   D%4 A%4 B%2 C%4
///   QMMA.16832.F32.*:         D%4 A%4 B%2 C%4   (E4M3 measured)
///   HMMA.16816.F32:           D%4 A%4 B%2 C%4
///   HMMA.1688.F32:            D%4 A%4 Bany C%4  (B is single-reg)
fn check_mma_reg_alignment(insn: &Instruction) -> Result<()> {
    let has_mod = |m: &str| insn.modifiers.iter().any(|x| x == m);
    // Dense warp-level forms only: .SP. (sparse, extra metadata operands) and
    // .SF. (scale-factor) layouts are not silicon-mapped for alignment.
    if has_mod(".SP") || has_mod(".SF") {
        return Ok(());
    }
    // (require-D4, require-A4, require-B2, require-C4)
    let (d4, a4, b2, c4) = match insn.opcode.as_str() {
        "IMMA" if has_mod(".16832") => (true, true, true, true),
        "QMMA" if has_mod(".16832") && has_mod(".F32") => (true, true, true, true),
        "HMMA" if (has_mod(".16816") || has_mod(".1688")) && has_mod(".F32")
            && !has_mod(".BF16") && !has_mod(".TF32") =>
        {
            // 1688 measured with a SINGLE-reg B (odd B legal); 16816 B is a pair.
            (true, true, has_mod(".16816"), true)
        }
        _ => return Ok(()),
    };
    // First four top-level R operands are D, A, B, C (leading/interspersed
    // predicates and UP gates are not Reg operands, so position in the
    // reg-only stream is stable; forms with fewer regs are unmapped here).
    let regs: Vec<u32> = insn
        .operands
        .iter()
        .filter_map(|o| match o {
            Operand::Reg { num, .. } => Some(*num as u32),
            _ => None,
        })
        .collect();
    if regs.len() < 4 {
        return Ok(());
    }
    let (d, a, b, c) = (regs[0], regs[1], regs[2], regs[3]);
    for (name, val, rule) in [
        ("D", d, d4.then_some(4u32)),
        ("A", a, a4.then_some(4)),
        ("B", b, b2.then_some(2)),
        ("C", c, c4.then_some(4)),
    ] {
        if let Some(align) = rule {
            if val % align != 0 {
                anyhow::bail!(
                    "{:?} is ILLEGAL on silicon (BUG-037): the {name} operand of {} \
                     spans {align} registers and @{val} is not {align}-aligned \
                     (R{}..R{}). Multi-register MMA operands must start at \
                     reg%{align}==0 (sm120 measured).",
                    insn.raw_text.trim(),
                    insn.opcode_full,
                    val,
                    val + align - 1,
                );
            }
        }
    }
    Ok(())
}

/// BUG-030: UPLOP3.LUT's two trailing immediates are NOT 8-bit LUTs — in the
/// silicon-blessed encoding (i93 corpus, 2635 words, nvdisasm-strict render)
/// tok5 lives in a 2-bit field @75 rendered as `value<<6` ({0,0x40,0x80,0xc0})
/// and tok6 in a 2-bit field @18 rendered as `value<<2` ({0,0x4,0x8,0xc}).
/// The encoder used to accept arbitrary values and write a word OUTSIDE the
/// decodable space (nvdisasm: "undefined value 0x1e for TABLES_opex_1"). The
/// scaled imm fields truncate silently, so out-of-lattice values are refused
/// here instead of being dropped.
fn check_uplop3_lut_lattice(insn: &Instruction) -> Result<()> {
    if insn.opcode != "UPLOP3" || insn.operands.len() < 7 {
        return Ok(());
    }
    for (oi, shift) in [(5usize, 6u32), (6usize, 2u32)] {
        let v = match &insn.operands[oi] {
            Operand::Imm32(v) => *v,
            Operand::Imm64(v) => *v as i64,
            _ => continue,
        };
        let bad = v < 0 || (v & ((1 << shift) - 1)) != 0 || (v >> shift) > 3;
        if bad {
            anyhow::bail!(
                "{:?}: operand {} of UPLOP3.LUT is a 2-BIT lattice immediate, \\
                 rendered as value<<{shift} — only {{0x0, {:#x}, {:#x}, {:#x}}} \\
                 are representable in this form (BUG-030; the previous encoder \\
                 silently emitted an undecodable word).",
                insn.raw_text.trim(),
                oi + 1,
                1u64 << shift,
                2u64 << shift,
                3u64 << shift,
            );
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
    // nvdisasm both accept the word, but sm_120 silicon measured ILLEGAL_INSTRUCTION on
    // silicon depending on the surrounding schedule (context-sensitive). The
    // immediate-mask form is the safe spelling.
    if table.target_sm() == 120
        && insn.opcode == "WARPSYNC"
        && insn.modifiers.is_empty()
        && insn.operands.len() == 1
        && matches!(insn.operands[0], Operand::Reg { num, .. } if num != 255)
    {
        out.push(format!(
            "WARPSYNC with a register membermask ({:?}) is context-sensitive on sm_120              silicon (BUG-005: accepted by cubit+nvdisasm, ILLEGAL depending on              surrounding schedule). Safer: the corpus-blessed barrier-wide form `WARPSYNC.ALL ;`, or drop WARPSYNC entirely when intra-warp ordering suffices (sm_120 honors STS->LDS without a sync)",
            insn.raw_text.trim()));
    }
    // BUG-008: 4-op IMAD.WIDE with c != RZ — the word encodes fine and ptxas
    // emits it, but the c operand of a wide IMAD is read by silicon as the
    // 64-bit pair (Rc, Rc+1): the assembly consumes a register the text never
    // names. (silicon probes first flagged this form as "runs IMAD-32";
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


/// BUG-059 (silicon, B300/sm_103a): the consumer IMNMX opcode class
/// (and_base 0x*817-family; era words such as
/// `IMNMX.S64 P0, P0, |R218|, R218, 0x3ffff, PT, P0` from the sm120-era
/// rt98 lineage) is ENCODABLE/DECODABLE per table but ILLEGAL on sm_103a
/// silicon -- capsule KernelA+0x4640 traps CUDA_ERROR_ILLEGAL_INSTRUCTION
/// even with every predicate slot forced PT (m48 probes P1-P3), and probe P5
/// shows the sibling VIMNMX-with-predicate-output form is likewise illegal.
/// ptxas never emits consumer IMNMX for sm_103a (u32 min/max -> VIMNMX.U32,
/// s64 -> UISETP+USEL emulation), so there is no 1:1 legal substitute the
/// tool could auto-apply. The table row stays DECODE-ONLY (RE of legacy
/// sm120 cubins keeps working); the encoder fails closed here, scoped to the
/// target with silicon evidence (sm_103a). UIMNMX/UVIMNMX (uniform path) are
/// NOT covered -- no silicon probe either way.
/// BUG-060 (silicon, B300/sm_103a): LDG.E.NA.EFL2.256.STRONG.GPU[.HINT] in the
/// descriptor addressing form (desc[URm][Rn.64], vendor: [Rn.U32+URm]) requires
/// an ODD address base register Rn on sm_103a. krun probes 7/7, 100% correlation
/// with Rn LSB (bit24 of the word): even Rn -> CUDA_ERROR_ILLEGAL_INSTRUCTION,
/// odd Rn -> executes (faults only on the dereference). Same era bytes ran fine
/// on sm120, so this is a per-field silicon legality delta, subtler than BUG-059.
/// The table rows stay decode-capable (RE of legacy cubins works); the encoder
/// fails closed on the even-Rn form, scoped to sm_103a (the only target with
/// silicon evidence). Sibling classes (ELL2/ENL2/LTC128B) are NOT covered --
/// no parity probes for them yet (krun-audit queue from BUG-060).
fn check_efl2_addr_parity_sm103(insn: &Instruction, table: &IsaTable) -> Result<()> {
    if insn.opcode != "LDG" {
        return Ok(());
    }
    if table.target_sm() != 103 {
        return Ok(());
    }
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    let efl2_256 = mods.split(',').any(|m| m == "EFL2")
        && mods.split(',').any(|m| m == "256");
    if !efl2_256 {
        return Ok(());
    }
    for op in &insn.operands {
        if let Operand::Desc { base_reg: Some(r), .. } = op {
            if r % 2 == 0 {
                anyhow::bail!(
                    "LDG.E.NA.EFL2.256 desc-form address base R{} is EVEN -- SILICON-ILLEGAL on sm_103a                     (BUG-060; B300 krun probes 7/7: the [Rn.U32+URm] form requires an ODD Rn on sm_103a,                     even Rn traps CUDA_ERROR_ILLEGAL_INSTRUCTION; R{} likely encodes a 64-bit pair where                     only the odd upper half carries a low partner). Renumber the address register (RA pin)                     instead of assembling the era word; decode stays full-fidelity for RE."
                , r, r);
            }
        }
    }
    Ok(())
}

/// BUG-076 (silicon, B300/sm_103a): STG desc-form with a 64-bit address
/// pair (desc[URm][Rn.64], the vendor render for these rows) requires an
/// EVEN pair base Rn on sm_103a -- OPPOSITE polarity to BUG-060
/// (LDG.E.NA.EFL2.256 needs an ODD base). krun/krunp probe series on B300
/// (measured on B300): odd Rn
/// -> CUDA_ERROR_ILLEGAL_INSTRUCTION (rejected before the memory stage),
/// even Rn -> executes (the paramless probe env faults ILLEGAL_ADDRESS only
/// on the dereference). Matrix over width/mod classes:
///   deterministic trap (II):   STG.E (9/9), STG.E.64 (9/9),
///                              STG.E.128 (~16/17), STG.E.STRONG.GPU (9/9),
///                              STG.E.ENL2.256 (12/17)
///   flaky trap (II in some device-state epochs, II/IA mixes observed):
///                              STG.E.EF (4/6), STG.E.EL.ENL2.256.STRONG.GPU
///                              (3/4) -- same fail-closed policy as the
///                              (flaky = poison; must-not-emit)
///   never trapped (0 II in 20+ runs across epochs): the ELL2/EFL2 L2-policy
///                              classes (EL.ELL2.256, NA.ELL2.256,
///                              NA.EFL2.256, all STRONG.GPU). These render
///                              [Rn.U32+URm] vendor-side = a different desc
///                              addressing mode (encoded word bit84=0), and
///                              their transactions are default-desc-rejected
///                              at the memory stage on sm_103a anyway (B12).
/// First seen by the B12 A/B O3 wrapper (work/o3/y_ur4_r59.sass R59.64
/// ILLEGAL vs y_e58.sass R58.64 EXACT). The guard fails closed on every
/// desc-pair STG with an odd base EXCEPT the ELL2/EFL2 classes (nvdisasm's
/// own render split matches the exemption: desc[UR][Rn.64] vs [Rn.U32+URm]).
/// LDG (non-EFL2) desc pairs are NOT covered (ENL2-load odd = 066-kand
/// flaky, parked), REDG/ATOMG desc pairs likewise (era corpus carries odd
/// bases, untested). Decode untouched: era odd-base words (3 x EL.ELL2 in
/// rt98_ref.s103, exempt class) still disassemble; expected encoder-census
/// delta = 0.
fn check_stg_desc_pair_parity_sm103(insn: &Instruction, table: &IsaTable) -> Result<()> {
    if insn.opcode != "STG" {
        return Ok(());
    }
    if table.target_sm() != 103 {
        return Ok(());
    }
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    // Evidenced exempt classes (silicon 2026-08-22: execute with any base
    // parity; desc addressing mode bit 84 = 0 in the encoded word).
    const EXEMPT: [&str; 2] = ["ELL2", "EFL2"];
    if mods.split(',').any(|m| EXEMPT.contains(&m)) {
        return Ok(());
    }
    for op in &insn.operands {
        if let Operand::Desc { base_reg: Some(r), base_reg_suffix: Some(sfx), .. } = op {
            if sfx == "64" && r % 2 == 1 {
                anyhow::bail!(
                    "STG desc-form address pair R{}.64 has an ODD base -- SILICON-ILLEGAL on sm_103a                     (BUG-076; measured on B300: odd base -> CUDA_ERROR_ILLEGAL_INSTRUCTION                     before the memory stage -- deterministic for E/64/128/STRONG/ENL2 desc-pair classes,                     flaky-epochal for EF/EL.ENL2 (fail-closed: flaky counts as poison); even base                     executes. Opposite polarity to BUG-060 LDG-EFL2 (odd required there); only the                     ELL2/EFL2 L2-policy classes stay exempt (different desc addressing mode, vendor                     render [Rn.U32+URm], never trapped in silicon runs; their transactions are                     default-desc-rejected at the memory stage on sm_103a anyway). Renumber the address                     pair to an even base (RA pin) instead of assembling the odd-base word; decode                     stays full-fidelity for RE."
                , r);
            }
        }
    }
    Ok(())
}

/// BUG-077 (silicon, B300/sm_103a): LDG desc-form with a 64-bit address
/// pair (desc[URm][Rn.64]) requires an EVEN pair base Rn for every class
/// whose addressing mode is the true register pair (encoded word bit84=1).
/// krunp probe matrix 2026-08-22 (idle windows; records in
/// measured on B300): odd base -> CUDA_ERROR_ILLEGAL_INSTRUCTION
/// (pre-memory stage), even base -> executes.
///   odd trap (deterministic or flaky-by-epoch; flaky counts as poison
///   policy): LDG.E 4/8 II, LDG.E.64 7/8, LDG.E.128 7/8, LDG.E.STRONG.GPU
///   5/6, LDG.E.EF 5/6, LDG.E.U16 5/6, LDG.E.256.ENL2 8/8 this window
///   (066-kand already showed ~50/80 flaky II for ENL2-load odd).
///   odd executes (exempt): LTC128B class (0/7 II; era corpus carries 69
///   such words), ELL2 256 (066: 20/20 both parities), EFL2 256
///   (BUG-060: odd base REQUIRED there -- the even side already fails
///   closed under check_efl2_addr_parity_sm103).
/// Untested sub-classes (CONSTANT/SM/SYS/S8/U8/EL.ENL2-load) are guarded
/// by the default rule: every tested non-exempt class traps; the exemptions
/// are exactly the classes with silicon counter-evidence. LDGSTS combos
/// carry LTC128B and ride the same exemption. Era corpus (rt98_ref.s103):
/// odd desc-LDG = 69 LTC128B + 3 ELL2, zero trap-class words -> expected
/// encoder-census delta = 0. Decode untouched.
fn check_ldg_desc_pair_parity_sm103(insn: &Instruction, table: &IsaTable) -> Result<()> {
    if insn.opcode != "LDG" {
        return Ok(());
    }
    if table.target_sm() != 103 {
        return Ok(());
    }
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    // Evidenced exemptions (silicon): LTC128B/ELL2 execute odd bases;
    // EFL2 REQUIRES odd (BUG-060 reverse-polarity guard covers the even side).
    const EXEMPT: [&str; 3] = ["LTC128B", "ELL2", "EFL2"];
    if mods.split(',').any(|m| EXEMPT.contains(&m)) {
        return Ok(());
    }
    for op in &insn.operands {
        if let Operand::Desc { base_reg: Some(r), base_reg_suffix: Some(sfx), .. } = op {
            if sfx == "64" && r % 2 == 1 {
                anyhow::bail!(
                    "LDG desc-form address pair R{}.64 has an ODD base -- SILICON-ILLEGAL on sm_103a                     (BUG-077; measured on B300: odd base ->                     CUDA_ERROR_ILLEGAL_INSTRUCTION before the memory stage for the true-pair desc                     classes E/64/128/STRONG/EF/U16/ENL2-256; even base executes. Only LTC128B / ELL2                     classes tolerate odd, and EFL2.256 REQUIRES odd under BUG-060 -- the polarity is                     class-specific, not universal; renumber the address pair to an even base (RA pin)                     instead of assembling the odd-base word; decode stays full-fidelity for RE."
                , r);
            }
        }
    }
    Ok(())
}

/// BUG-078 (silicon, B300/sm_103a): ATOMG/REDG desc-form with a 64-bit
/// address pair (desc[URm][Rn.64], non-EL classes -- encoded word uses the
/// true register-pair addressing mode, vendor render `desc[URm][Rn.64]`)
/// requires an EVEN pair base Rn. krunp probe matrix 2026-08-22 (idle
/// windows, measured on B300):
///   odd trap (decisive experiment, valid VA in the pair):
///     ATOMG.E.ADD.STRONG.GPU desc[UR4][R5.64] -> CUDA_ERROR_ILLEGAL_
///     INSTRUCTION 10/10 across epochs; even base R2.64 -> OK 10/10,
///     memory updated (32-lane add-sum exact).
///   FAULT-PRIORITY (differs from STG/LDG!): on the atom path an invalid
///   address faults as ILLEGAL_ADDRESS *before* the pair-parity check, so
///   garbage-address odd probes read IA and CANNOT see the trap -- the
///   valid-address A/B is mandatory for atoms.
///   .EL classes (ATOMG/REDG *.EL.STRONG.GPU) are EXEMPT: they encode in the
///   single-32-bit-offset desc mode (vendor render `[Rn.U32+URm]`, same mode
///   family as the BUG-076/077 ELL2/EFL2 exemptions) -- no register pair
///   exists in the word, so the parity rule does not apply. (Their
///   transactions are default-desc-rejected at the memory stage on sm_103a
///   regardless -- B12 silicon facts -- a separate descriptor-campaign
///   question, b12-full-2.)
/// Untested non-EL atom sub-classes ride the default fail-closed rule; RZ
/// base stays inside the guard like in BUG-076/077 (no era usage, no
/// silicon counter-evidence; era RZ atoms are all .EL hence exempt).
/// Era corpus (rt98_ref.s103): odd desc-atoms = 44 words, ALL .EL ->
/// encoder census delta = 0. Decode untouched.
fn check_atom_desc_pair_parity_sm103(insn: &Instruction, table: &IsaTable) -> Result<()> {
    if insn.opcode != "ATOMG" && insn.opcode != "REDG" {
        return Ok(());
    }
    if table.target_sm() != 103 {
        return Ok(());
    }
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    // Evidenced exemptions (silicon/census): .EL classes encode in the
    // single-offset desc mode ([Rn.U32+URm]); no pair -> no parity rule.
    if mods.split(',').any(|m| m == "EL") {
        return Ok(());
    }
    for op in &insn.operands {
        if let Operand::Desc { base_reg: Some(r), base_reg_suffix: Some(sfx), .. } = op {
            if sfx == "64" && r % 2 == 1 {
                anyhow::bail!(
                    "ATOMG/REDG desc-form address pair R{}.64 has an ODD base -- SILICON-ILLEGAL on sm_103a                     (BUG-078; B300 krunp A/B 2026-08-22 with a VALID VA in the pair: odd base ->                     CUDA_ERROR_ILLEGAL_INSTRUCTION 10/10 across epochs, even base -> executes, memory                     updated exactly. NOTE the atom-path fault priority masks the trap behind                     ILLEGAL_ADDRESS when the address itself is invalid, so a garbage-address probe                     cannot discriminate -- unlike STG/LDG (BUG-076/077) where odd traps pre-memory.                     Only the .EL classes are exempt: they encode the single-32-bit-offset desc mode                     ([Rn.U32+URm]) which has no register pair at all. Renumber the address pair to                     an even base (RA pin) instead of assembling the odd-base word; decode stays                     full-fidelity for RE."
                , r);
            }
        }
    }
    Ok(())
}

/// BUG-080 (silicon, B300/sm_103a): a guard-PREDICATED non-EL memory atomic
/// (`@Pn` / `@!Pn` / `@UPn` on ATOM/ATOMS/ATOMG/RED/REDG) is SILENTLY BROKEN
/// on sm_103a -- the operation returns garbage to memory with NO trap, at
/// every producer stall and even with an always-true guard.
///
/// Silicon (B300, census-hi F-SS4, 2026-08-22; raws
/// results/stallsuf/fss4/raw/{x_atomt_d1h,x_atomte,p_atomv}.txt):
///   `@P2 ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44` with
///   P2 forced always-true -> destination cells hold NONDET garbage on a
///   12-variant sweep x 4 replications (x_atomt_d1h), incl. the 1x32
///   geometry (not an occupancy artifact). The UNGUARDED instance of the
///   same word performs the service correctly (p_atomv count-analytic
///   PASS). The .EL variant traps loudly (ILLEGAL_ADDRESS on the default
///   descriptor) instead -- loud, hence not this guard's business.
/// Mechanism unknown (the guarded-atom issue path itself reads broken --
/// even a *true* guard corrupts), so the encoder fails closed on ANY
/// non-trivial guard (`@!PT` rejected too: never-executing forms encode a
/// distinct pred field that was never probed; fail-closed doctrine).
/// Exemptions:
///   * explicit `@PT` -- encodes bit-identical to the unguarded word
///     (verified byte-wise), so it is the unguarded form spelled out;
///   * .EL mod classes -- era production form; under real descriptors
///     (=O1 descriptor-port road) legality is an open silicon question
///     (078-open-Q / b12-full-2), and on the default descriptor they die
///     loudly;
///   * REDUX -- register-space reduction (UR dest, no memory operand),
///     not a memory atomic; no silicon evidence.
///
/// ATOM/ATOMS guarded were not probed; they ride the family guard by
/// prevention (same atomic issue path as ATOMG, like BUG-078 covered
/// REDG from ATOMG probes). Era corpus (rt98_ref.s103): all 22 guarded
/// atom sites are .EL (F-SS4 guard census) -> encoder census delta = 0.
///
/// Complements POSTFIX-103 v1, which already treats every guard-D1 atomic
/// consumer as a violation; this guard closes the ENCODER side so the word
/// cannot be minted at all. Scoped to sm_103a (no sm120 silicon).
fn check_guarded_atomic_sm103(insn: &Instruction, table: &IsaTable) -> Result<()> {
    const MEM_ATOMIC: &[&str] = &["ATOM", "ATOMS", "ATOMG", "RED", "REDG"];
    if !MEM_ATOMIC.contains(&insn.opcode.as_str()) {
        return Ok(());
    }
    if table.target_sm() != 103 {
        return Ok(());
    }
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    if mods.split(',').any(|m| m == "EL") {
        return Ok(());
    }
    match &insn.guard {
        Some(g) if !(g.pred == 7 && !g.negated && !g.uniform) => anyhow::bail!(
            "guard-predicated non-EL {} is SILENTLY BROKEN on sm_103a (BUG-080; B300             census-hi 2026-08-22: guarded ATOMG.E.ADD.STRONG.GPU with an ALWAYS-TRUE guard             wrote NONDET garbage to memory at every stall 04..15 and at 1x32 occupancy, no             trap; the unguarded word works). Do not assemble guarded atomics for sm_103a --             restructure (guard a BRA around the atomic) or use the .EL form with a real             descriptor (O1-road). Decode stays full-fidelity for RE."
            , insn.opcode),
        _ => Ok(()),
    }
}

fn check_imnmx_sm103_erratum(insn: &Instruction, table: &IsaTable) -> Result<()> {
    if insn.opcode != "IMNMX" {
        return Ok(());
    }
    if table.target_sm() != 103 {
        return Ok(());
    }
    anyhow::bail!(
        "IMNMX (consumer min/max with predicate outputs) is SILICON-ILLEGAL on sm_103a          (BUG-059; B300 m48 probes P1-P3: CUDA_ERROR_ILLEGAL_INSTRUCTION for the exact          era bytes, guard-forced-PT variants included; P5: pred-output VIMNMX also illegal;          ptxas emits VIMNMX.U32 for 32-bit and UISETP+USEL for 64-bit instead). The table          row is decode-only for reverse engineering; port the text (VIMNMX.U32 + explicit          ISETP predicate materialization) instead of assembling era IMNMX words."
    )
}


/// BUG-088 (silicon, B300/sm_103a; from the b12-full-2
/// preflight, extended into a full probe matrix 2026-08-22): wide
/// const/shared-memory accesses enforce DESTINATION/DATA register alignment
/// laws that the encoder previously accepted silently -- the assembled word
/// then traps CUDA_ERROR_ILLEGAL_INSTRUCTION at execution (same fail-closed
/// doctrine as the BUG-060/076/077/078 family).
///
/// Probe matrix (measured on B300;
/// krunp on B300, 2-3 replications, deterministic across epochs):
///   LDC.64 dest R (cAI imm and cARI register-offset forms): ODD Rn ->
///     II (R53/R201), even OK, RZ(255) exempt. Plain 32-bit LDC unconstrained.
///   LDCU.64 dest UR: ODD URn -> II (UR5/UR61 -- REAL UR63 traps too),
///     even OK, URZ exempt.
///   LDS.64 dest / STS.64 data R: ODD -> II (R5/R201), even OK, RZ exempt.
///   LDS.128 dest / STS.128 data R: legal iff RZ, Rn%8==0, or
///     (Rn<44 && Rn%4==0). Rn%4!=0 -> II everywhere (R13/41/45/46/49/126);
///     odd-quad (Rn/4)%2==1 with Rn>=44 -> II (R44/52/60/68/100/132/196/204).
///   LDC.128 R-form: the 088 campaign's "NO constraint observed" conclusion is
///     VACUOUS (BUG-135): those probes ran width-dropped plain-LDC words (the
///     era encoder silently dropped .128 pre-BUG-132). nvdisasm renders
///     R-domain width codes 2/3 as LDC.INVALID6/INVALID7 on sm_103a and
///     sm_120a alike -- no R-domain LDC.128 encoding exists. Authoring
///     `LDC.128 R...` now fails closed in verify_mod_group_retained (BUG-132;
///     no table row expresses the combination), so this guard never sees it.
///     Write 2x LDC.64 instead. Left deliberately UNGUARDED here only as a
///     documented non-statement; the hard reject lives in the 132 check.
///
/// Era corpus (rt98_ref.s103) carries exactly ONE word that now fails
/// closed: `STS.128 [R5.X16+0x10], R204` in KernelA (R204 = quad 51, odd,
/// >=11). The verbatim era shape traps II on silicon when executed; nothing
/// > observed it because the site is on a dead path at runtime. Encoder census
/// > delta = 1 documented slot (errs 21 -> 22), decode untouched.
/// > Scoped to target_sm()==103 (no sm120 silicon evidence);
/// > CUBIT_DISABLE_ERRATA unlocks for analysis, like the rest of the battery.
fn check_wide_mem_reg_align_sm103(insn: &Instruction, table: &IsaTable) -> Result<()> {
    if table.target_sm() != 103 {
        return Ok(());
    }
    match insn.opcode.as_str() {
        "LDC" | "LDCU" | "LDS" | "STS" => {}
        _ => return Ok(()),
    }
    let mods = crate::table::extract_mod_group(&insn.raw_text);
    let w64 = mods.split(',').any(|m| m == "64");
    let w128 = mods.split(',').any(|m| m == "128");
    if !w64 && !w128 {
        return Ok(());
    }
    // The constrained register is the R-domain destination (LDC/LDS) or the
    // data source (STS); for LDCU the uniform destination. Address registers
    // live inside Addr/ConstMem/Desc operands, so the first Reg/UReg operand
    // IS the data register.
    if insn.opcode == "LDCU" {
        if !w64 {
            return Ok(());
        }
        if let Some((num, is_zero)) = insn.operands.iter().find_map(|o| match o {
            Operand::UReg { num, is_zero, .. } => Some((*num, *is_zero)),
            _ => None,
        }) {
            if !is_zero && num % 2 == 1 {
                anyhow::bail!(
                    "LDCU.64 uniform destination UR{} is ODD -- SILICON-ILLEGAL on sm_103a                     (BUG-088; B300 krunp matrix 2026-08-22: odd URn -> CUDA_ERROR_ILLEGAL_INSTRUCTION                     deterministically (UR5/UR61; note REAL UR63 traps -- only the URZ zero-constant                     encoding is exempt); even URn executes. Renumber to an even UR (RA pin) instead                     of assembling the odd-dest word; the real-constant URZ stays legal; decode                     stays full-fidelity for RE."
                    , num
                );
            }
        }
        return Ok(());
    }
    let Some(num) = insn.operands.iter().find_map(|o| match o {
        Operand::Reg { num, .. } => Some(*num),
        _ => None,
    }) else {
        return Ok(());
    };
    if num == 255 {
        return Ok(()); // RZ zero-constant encoding: silicon-exempt (probed).
    }
    if w64 && num % 2 == 1 {
        anyhow::bail!(
            "{}.64 data/destination register R{} is ODD -- SILICON-ILLEGAL on sm_103a             (BUG-088; B300 krunp matrix 2026-08-22: odd Rn -> CUDA_ERROR_ILLEGAL_INSTRUCTION             deterministically for LDC.64 dest (cAI and cARI forms alike) and LDS.64 dest /             STS.64 data; even Rn executes, RZ is exempt). Renumber to an even register (RA             pin) instead of assembling the odd-register word; decode stays full-fidelity for RE."
            , insn.opcode, num
        );
    }
    if w128 && insn.opcode != "LDC" {
        let legal128 = num % 8 == 0 || (num < 44 && num % 4 == 0);
        if !legal128 {
            anyhow::bail!(
                "{}.128 data/destination register R{} violates the sm_103a alignment law                 -- SILICON-ILLEGAL (BUG-088; B300 krunp matrix 2026-08-22: legal iff RZ,                 Rn%8==0, or Rn<44 with Rn%4==0; Rn%4!=0 traps EVERYWHERE tested                 (R13/41/45/46/49/126), odd-quad (Rn/4)>=11 traps (R44/52/60/68/100/132/196/204)).                 Renumber (RA pin) instead of assembling the word. NOTE: the era corpus carries                 exactly one such word (`STS.128 [R5.X16+0x10], R204`, quad 51) on a runtime-                 dead path; LDC.128 R-form is NOT under this guard -- it is outright                 REJECTED upstream (BUG-135: no such encoding exists; the 088-era 'no constraint' claim came from width-dropped probes). Decode stays full-fidelity for RE."
                , insn.opcode, num
            );
        }
    }
    Ok(())
}

/// Encode a parsed instruction using the per-modifier-group table.
pub fn encode_instruction(insn: &Instruction, table: &IsaTable) -> Result<u128> {
    // BUG-091 (fail-closed): an unresolved label operand on a branch op must
    // never be encoded. The parser resolves defined labels to BranchTarget;
    // whatever reaches here as Operand::Label has no definition in scope and
    // used to degrade into the immediate path, silently emitting a bogus
    // target. Refuse with full context instead (render-level IR stays
    // lenient -- the check fires only at byte production).
    // b9 phase-3 #7: WARPSYNC.COLLECTIVE carries a label operand like any
    // branch; without this the unresolved label silently encoded a 0 target.
    static BRANCH_OPS: &[&str] = &["BRA", "BSSY", "CALL", "JMP", "RET", "BRX", "BRXU", "WARPSYNC"];
    if BRANCH_OPS.contains(&insn.opcode.as_str()) {
        if let Some(bad) = insn.operands.iter().find_map(|op| match op {
            crate::ir::Operand::Label(name) => Some(name.clone()),
            _ => None,
        }) {
            anyhow::bail!(
                "unresolved branch label {:?} on {} at addr 0x{:x} -- label has no                  definition in this input (BUG-091; nvdisasm `.L_x_N` definitions and                  the backtick-paren form are supported since the fix)",
                bad, insn.opcode_full, insn.addr);
        }
    }
    encode_instruction_inner(insn, table, true)
}

fn encode_instruction_inner(insn: &Instruction, table: &IsaTable, run_errata_checks: bool) -> Result<u128> {
    // Fail-closed operand errata (parser-level admission can't error here: the
    // .sass file reader silently drops lines whose parse fails — so the encoder
    // is the last place that can refuse a bad instruction noisily).
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_none() {
        check_pred_literal_errata(insn)?;
        check_mma_reg_alignment(insn)?;
        check_uplop3_lut_lattice(insn)?;
        check_imnmx_sm103_erratum(insn, table)?;
        check_efl2_addr_parity_sm103(insn, table)?;
        check_stg_desc_pair_parity_sm103(insn, table)?;
        check_ldg_desc_pair_parity_sm103(insn, table)?;
        check_atom_desc_pair_parity_sm103(insn, table)?;
        check_guarded_atomic_sm103(insn, table)?;
        check_wide_mem_reg_align_sm103(insn, table)?;
    }
    let mod_group = crate::table::extract_mod_group(&insn.raw_text);

    // BUG-012: IMAD.MOV is an ALIAS of plain IMAD — nvdisasm prints it when both
    // multiplier operands are RZ. Accept the alias only in that exact shape
    // (fail-closed otherwise) and encode via the plain rows.
    // BUG-083: the strip must apply ONLY to the bare `MOV` alias. `MOV,U32` is a
    // real row (bit73=0, the U32/signed discriminator); stripping `MOV` from it
    // left mg="U32" which does not exist for these keys, and the "" fallback
    // silently encoded the SIGNED plain row (bit73=1) — 16,866 corpus words
    // re-encoded with bit73 flipped before this fix.
    let mov_alias = insn.opcode == "IMAD"
        && mod_group.split(',').any(|m| m == "MOV");
    // `MOV,U32` keeps its own mod_group (own table row); alias-shape still enforced.
    let mov_u32 = mov_alias
        && mod_group.split(',').any(|m| m == "U32");
    if mov_alias {
        let is_rz = |o: &Operand| matches!(o,
            Operand::Reg { num: 255, neg: false, abs: false, inv: false, .. });
        let ok = insn.operands.len() >= 3
            && is_rz(&insn.operands[1]) && is_rz(&insn.operands[2]);
        if !ok {
            anyhow::bail!(
                "IMAD.MOV alias requires multiplier operands RZ, RZ (got: {})",
                insn.raw_text
            );
        }
    }
    let mod_group = if mov_alias && !mov_u32 {
        mod_group.split(',').filter(|m| *m != "MOV").collect::<Vec<_>>().join(",")
    } else {
        mod_group
    };

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
        // base key without mods: the harvest keeps some modified forms under the base
        // key with the "" group (e.g. IMAD.U32 with a UR source = the MOV idiom; ktest sass
        // 2026-08-05: (IMAD_R_R_R_UR, "U32") REJ by kind, (fk,"") absent).
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
    // BUG-132: remember which mod-group the winning candidate carries so the
    // post-encode check can tell an exact-cover match from a "" fallback.
    let mut selected_mg = String::new();
    for (k, mg) in &candidates {
        match table.get(k, mg) {
            Some(e) => match entry_matches_operands(insn, e) {
                Ok(()) => {
                    // BUG-071 guard: default-payload operand (imm 0 / URZ) on a
                    // token the entry has no field for must not ride an entry
                    // whose and_base carries junk in a sibling-proven imm/ureg
                    // window for that token (harvest artefact: FADD 0x0 -> 1.0,
                    // FMUL.FTZ 0x0 -> 0.5, FADD URZ -> UR15). Reject so the
                    // chain either finds a well-formed sibling or fails loudly.
                    if let Some(why) = zero_payload_junk(insn, k, e, table) {
                        attempts.push(format!("({k}, \"{mg}\") REJECTED: {why}"));
                        continue;
                    }
                    entry = Some(e);
                    selected_mg = mg.clone();
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
            if table.target_sm() == 120 {
                msg.push_str(
                    ". IMAD.HI note (BUG-002): on sm_120 the harvested `IMAD.HI` encodings \
                     are executed by silicon as IMAD.WIDE.U32 (Rd = LOW half, Rd+1 \
                     CLOBBERED); the bogus entries were removed, so the text now fails \
                     fail-closed. Use `IMAD.WIDE[.U32] Rd, Ra, Rb, RZ` and read Rd+1, \
                     or the 5-operand pout form");
            } else {
                msg.push_str(
                    ". IMAD.HI note (BUG-049): the BUG-002 hard reject is scoped to \
                     sm_120 silicon; on this target the table simply has no \
                     operand-compatible entry for this IMAD.HI form (harvest gap), \
                     so the text fails honestly here");
            }
        }
        if matches!(insn.opcode.as_str(), "ULOP3" | "UPLOP3") {
            msg.push_str(
                ". UP-write note (BUG-030): the silicon-blessed UP-writing form is \
                 `ULOP3.LUT UPd, URd, URa, imm_b, URc, lut8, !UPx` (7 operands; the \
                 short UP-write shape was a harvest phantom and was removed). \
                 UPLOP3.LUT takes UPd, UPT, UPT, UPT, UPc_src and two tiny lattice \
                 immediates (value<<6 / value<<2), e.g. \
                 `UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8`");
        }
        msg
    })?;
    // BUG-002 guard: IMAD.HI text must never ride an entry that does not
    // encode the HI modifier (silicon: such words are IMAD.WIDE.U32 and
    // clobber Rd+1).
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_none() {
        check_imad_hi_erratum(insn, table)?;
    }
    if std::env::var("CUBIT_DEBUG_LOOKUP").is_ok() {
        eprintln!("[lookup] fk={} key={} mod_group={:?} -> fields={:?}",
            fk, insn.key, mod_group,
            entry.fields.iter().map(|f|(format!("{:?}",f.extraction),f.shift,f.bits,f.token_idx)).collect::<Vec<_>>());
    }

    let mut code = entry.and_base;

    // Apply field extractions
    for field in &entry.fields {
        // b9 phase-3 #7: WARPSYNC.COLLECTIVE's `(label)` payload is owned by
        // apply_branch_encoding's REL16 fixup (same doctrine as BUG-023 for
        // branch ops): the legacy harvest rows carry a bogus imm field over
        // that window which would read the RESOLVED BranchTarget address and
        // smear it across [49:18]. Skip the table field; the fixup writes the
        // real payload afterwards.
        if insn.opcode == "WARPSYNC"
            && matches!(get_op(insn, field.token_idx),
                Some(Operand::BranchTarget(_)) | Some(Operand::Label(_)))
        {
            continue;
        }
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
    code = apply_branch_encoding(insn, code, &mod_group,
        crate::table::is_sm103a_encoding_family(table.ef_flags));

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
    let sm103a_derived = crate::table::is_sm103a_encoding_family(table.ef_flags);
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
        // BUG-084: post-re-canonicalization the sm120 table carries complete
        // sm103a-derived address geometry (base-register SubR + SubImm on the
        // Addr token) for the raw-address LDG/STG family -- identical to the
        // sm103a tables the legacy rebuild below already steps aside for
        // ("would clobber them"). When the selected entry fully owns the
        // address operand, its and_base+fields encode the vendor-exact word
        // (2049-cubin census, 676,912 roundtrip anchors). Keep the legacy
        // template only for entries with incomplete address coverage.
        let entry_covers_addr_base_imm = addr_tok.is_some_and(|tok| {
            entry.fields.iter().any(|f| f.token_idx == tok
                && matches!(f.extraction,
                    Extraction::SubR(..) | Extraction::SubRShr(..)))
            && entry.fields.iter().any(|f| f.token_idx == tok
                && ext_encodes_imm(&f.extraction))
        });

        if !sm103a_derived && uses_raw_addr && !uses_desc
            && !entry_covers_addr_ur && !entry_covers_addr_base_imm
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
        //
        // BUG-103/BUG-105: the tcgen05 c1 UTC*MMA descriptor-form family carries
        // a vendor-CONSTANT ctrl word per (class, guard-presence) — independent of
        // whatever the scheduling pass computed (mk300: 750/750 words split 1:1).
        // An author-owned `[B..:R..:W..:Y..S..]` prefix (hand_sched) always wins.
        let cc = if !insn.hand_sched {
            crate::ctrl_class::utc_mma_vendor_ctrl(insn).unwrap_or(insn.ctrl)
        } else {
            insn.ctrl
        };
        let non_sched = (epoch_upper32_default & !scheduling::SCHED_UPPER32_MASK) | reuse_bits;
        non_sched | scheduling::encode_sched_upper32(&cc)
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
    // BUG-132 (fail-closed): silent modifier drop. The lookup chain falls
    // back to a row whose mod-group is narrower than the requested one when
    // the exact combination row is missing (e.g. FADD_R_R_R carries "RZ" /
    // "SAT" / "FTZ,RZ" but no "RZ,SAT"); the dropped modifiers then silently
    // encode a DIFFERENT variant (pre-fix `FADD.RZ.SAT` encoded bits
    // [80:78]=000 = plain RN — wrong-code). Verified by decode-back: the
    // produced word, decoded through this same table, must claim EVERY
    // requested modifier (claim set = mnemonic mods embedded in the matched
    // InsKey UNION the row's mod-group — both harvest eras: tb_i82* bake
    // mods into the key, modern tables into group names). Decode-back is
    // the only sound equivalence oracle here: documented load-bearing ""
    // fallbacks (IMAD.U32 _UR idiom, BRXU.U / LOP3.LUT.PAND /
    // IADD3.X.RCNEG / BAR.SYNC.DEFER_BLOCKING on tb_i82p3, LDGSTS.128
    // policy-group expansion on sm120) ride rows whose and_base already
    // carries the mod bits, so their words decode back WITH the modifiers
    // and pass. Superset rule (requested <subset-eq> claimed): a chosen row
    // may legitimately claim MORE than requested (the only harvest row for
    // the shape, e.g. LDGSTS "128,E" -> "128,BYPASS,E,LTC128B"), but never
    // silently LESS. Runs after the full pipeline so the `!rsd` overlay is
    // visible to the decoder.
    if run_errata_checks
        && std::env::var_os("CUBIT_DISABLE_ERRATA").is_none()
        && selected_mg != mod_group
    {
        verify_mod_group_retained(insn, table, out, &mod_group, &selected_mg)?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Field value extraction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// BUG-139 (F2 follow-up of BUG-130): generic encode-lint "value must fit
// field". Every field application used to truncate the operand payload with
// `value & field.mask`, so an operand that did not fit its encoding window
// was silently re-issued as a DIFFERENT value (BUG-130 barrier-alias class;
// BUG-136 mod-4 predicate wrap; BUG-027-class immediate aliasing).
//
// Two tiers, because the harvest model complicates "fits the mask":
//  * TIER-1 (hard, fail-closed): small-domain total payloads — guards,
//    predicates, barriers, reuse + 0/1/2-domain flags. No split windows, no
//    sentinel carriers — any loss is a bug. This closes the BUG-130
//    barrier-alias and BUG-136 predicate-wrap surfaces at the encoder.
//  * TIER-2 (soft audit): value-carrying families (reg/imm/addr/cmem) where
//    truncation can be legitimate: one operand decomposed into sibling
//    fields with disjoint coverage (PLOP3.LUT lattice imm = imm[0:3)
//    @64 + imm_shr3[3:8) @72; LDG.256-desc trailer = imm[0:6) + imm_shr7),
//    payloads and_base-carried or owned by the branch fixup (BRA/WARPSYNC
//    label rows), sentinel mappings (RZ base 0xFF -> 0x7F in a 7-bit
//    window, vendor-confirmed in t123 goldens). Legacy masked payload is
//    always returned; with CUBIT_FIT_LINT=warn the misfit is logged for
//    census. Promotion of tier-2 to hard requires the aggregate
//    per-operand coverage model (see results/cubitfix/139.md).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum FitLint {
    Unsigned,
    Signed,
}

fn fit_lint_warn_enabled() -> bool {
    use std::sync::OnceLock;
    static WARN: OnceLock<bool> = OnceLock::new();
    *WARN.get_or_init(|| std::env::var("CUBIT_FIT_LINT").is_ok_and(|v| v == "warn"))
}

fn fit_lint_msg(insn: &Instruction, field: &Field, raw: u64, kind: FitLint) -> String {
    let what = match kind {
        FitLint::Unsigned => "value",
        FitLint::Signed => "immediate",
    };
    format!(
        "encode-lint: `{}` key `{}` operand {} ({:?}): {} {:#x} does not fit \
         field (shift={} bits={} mask={:#x}); legacy behaviour silently \
         encoded {:#x}",
        insn.opcode_full,
        insn.key,
        field.token_idx,
        field.extraction,
        what,
        raw,
        field.shift,
        field.bits,
        field.mask,
        raw & field.mask
    )
}

/// TIER-1 (hard): the field must carry the value losslessly.
fn fit(insn: &Instruction, field: &Field, v: u64) -> Result<u64> {
    if v & !field.mask == 0 {
        Ok(v)
    } else {
        Err(anyhow::anyhow!(fit_lint_msg(insn, field, v, FitLint::Unsigned)))
    }
}

/// TIER-1 (hard) with a value-domain guard for extractions that compute
/// `K - v` style transforms — bail when the transform itself is undefined
/// (e.g. 7 - n with n > 7 wrapped on u64, 1 - f with f > 1 folded by the
/// field mask into a valid-looking payload).
fn fit_bail(insn: &Instruction, field: &Field, v: u64) -> anyhow::Error {
    anyhow::anyhow!(fit_lint_msg(insn, field, v, FitLint::Unsigned))
}

/// TIER-2 (soft audit, CUBIT_FIT_LINT=warn): legacy masked payload always;
/// `signed` adds the two's-complement round-trip leg so negative immediates
/// are canonical, not violations.
fn fit_soft(insn: &Instruction, field: &Field, v: i64, signed: bool) -> Result<u64> {
    let enc = (v as u64) & field.mask;
    let lossless = (v as u64) & !field.mask == 0
        || (signed && crate::printer::sign_extend_pub(enc, field.bits) == v);
    if !lossless && fit_lint_warn_enabled() {
        let kind = if signed { FitLint::Signed } else { FitLint::Unsigned };
        eprintln!("[fit-lint] {}", fit_lint_msg(insn, field, v as u64, kind));
    }
    Ok(enc)
}

/// TIER-2 const-mem combined field (bank << shift | offset & window): the
/// offset is sliced into a two's-complement window of `bank_shift` bits —
/// audit the slice round-trip, then hand the combined legacy payload to the
/// soft audit (never bails; CUBIT_FIT_LINT=warn logs).
fn fit_cm_off_soft(insn: &Instruction, field: &Field, bank_shift: u8) -> Result<u64> {
    let win = (1u64 << bank_shift) - 1;
    if let Some(Operand::ConstMem { offset, .. }) = get_op(insn, field.token_idx) {
        if crate::printer::sign_extend_pub((*offset as u64) & win, bank_shift as u32) != *offset
            && fit_lint_warn_enabled()
        {
            eprintln!("[fit-lint] {}", fit_lint_msg(insn, field, *offset as u64, FitLint::Signed));
        }
    }
    fit_soft(insn, field, op_cm_off(insn, field.token_idx, bank_shift) as i64, false)
}

fn extract_value(insn: &Instruction, field: &Field) -> Result<u64> {
    let mk = field.mask;

    match &field.extraction {
        // Guard extractions (token 0)
        Extraction::Guard => fit(insn, field, guard_val(insn)),
        Extraction::GuardLo3 => fit(insn, field, guard_val(insn) & 7),
        Extraction::GuardNeg => fit(insn, field,
            if insn.guard.as_ref().is_some_and(|g| g.negated) { 1 } else { 0 }),

        // Register
        Extraction::Reg => fit_soft(insn, field, op_reg(insn, field.token_idx) as i64, false),
        Extraction::UReg => {
            // UMOV dest slot: corpus rule "URZ reads as 0xFF in source slots"
            // does not extend to the uniform move destination — FA4 hardware
            // encoding stores URZ as its architectural number 63 there.
            if insn.opcode.starts_with("UMOV") && field.token_idx == 1 {
                if let Some(Operand::UReg { is_zero: true, .. }) = get_op(insn, 1) {
                    return fit_soft(insn, field, 63, false);
                }
            }
            fit_soft(insn, field, op_ureg(insn, field.token_idx) as i64, false)
        }
        Extraction::RegFf => fit_soft(insn, field, op_reg_ff(insn, field.token_idx) as i64, false),
        Extraction::URegFf => fit_soft(insn, field, op_ureg_ff(insn, field.token_idx) as i64, false),
        Extraction::Pred => fit(insn, field, op_pred(insn, field.token_idx)),
        // sm_121a trailing guard-pred inverted 4-bit map (q2 iter38 port):
        // PT/none -> 0, Pn -> 7-n, !PT -> 8, !Pn -> 15-n. The _ => 0 default
        // matches "no pred operand": window stays 0, which decode reads as
        // "no guard pred" (the inv4 zero rule).
        Extraction::PredInv4 => {
            let v = match get_op(insn, field.token_idx) {
                Some(Operand::Pred { num, neg, .. }) | Some(Operand::UPred { num, neg, .. }) => {
                    if *neg {
                        if *num == 7 { 8 } else { 15 - *num as u64 }
                    } else if *num == 7 {
                        0
                    } else {
                        7 - *num as u64
                    }
                }
                _ => 0,
            };
            fit(insn, field, v)
        }
        // BUG-032: nvdisasm gate naming is inverted (sel = 7 - n, UPT = sel 0);
        // physical value (sel) is identical, only the name mapping flips.
        Extraction::UPredGate => {
            let n = op_pred(insn, field.token_idx);
            // 7 - n on u64 with n > 7 used to panic (debug) or wrap into a
            // huge payload that the field mask folded back (release).
            let sel: u64 = if n == 7 {
                0
            } else if let Some(s) = 7u64.checked_sub(n) {
                s
            } else {
                return Err(fit_bail(insn, field, n));
            };
            fit(insn, field, sel)
        }
        Extraction::Barrier => fit(insn, field, op_barrier(insn, field.token_idx)),

        // Immediate
        Extraction::Imm => fit_soft(insn, field, op_imm(insn, field.token_idx) as i64, true),
        Extraction::ImmShr(n) => {
            let raw = op_imm(insn, field.token_idx) as i64;
            let gran = 1i64 << n;
            // The shift consumes the low bits: a non-granule immediate
            // silently loses them (BUG-070 class) — tier-2 audit only
            // (harvest rows may legitimately window the operand).
            if raw % gran != 0 && fit_lint_warn_enabled() {
                eprintln!("[fit-lint] {}", fit_lint_msg(insn, field, raw as u64, FitLint::Signed));
            }
            fit_soft(insn, field, raw >> n, true)
        }
        Extraction::ImmDec => fit_soft(insn, field, op_imm_dec(insn, field.token_idx) as i64, true),
        Extraction::ImmDecU32 => fit_soft(insn, field, (op_imm_dec(insn, field.token_idx) & 0xFFFFFFFF) as i64, false),

        // Float
        Extraction::F32 => fit_soft(insn, field, op_f32(insn, field.token_idx) as i64, false),
        Extraction::F16 => fit_soft(insn, field, op_f16_via_f32(insn, field.token_idx) as i64, false),
        Extraction::F16d => fit_soft(insn, field, op_f16_via_f64(insn, field.token_idx) as i64, false),
        Extraction::F64hi => fit_soft(insn, field, op_f64hi(insn, field.token_idx) as i64, false),

        // Flags
        Extraction::Neg => {
            let v = op_neg(insn, field.token_idx);
            if v == 0 { fit(insn, field, op_inv(insn, field.token_idx)) } else { fit(insn, field, v) }
        }
        Extraction::NegF32 => fit(insn, field, op_neg_f32(insn, field.token_idx)),
        Extraction::F32Cast => fit_soft(insn, field, op_f32_cast(insn, field.token_idx) as i64, false),
        Extraction::NegShl1 => fit(insn, field, op_neg(insn, field.token_idx) << 1),
        Extraction::Reuse => fit(insn, field, op_reuse(insn, field.token_idx)),
        Extraction::Inv => fit(insn, field, op_inv(insn, field.token_idx)),
        Extraction::Abs => fit(insn, field, op_abs(insn, field.token_idx)),
        Extraction::NegAbs => {
            let a = op_abs(insn, field.token_idx);
            let n = op_neg(insn, field.token_idx);
            fit(insn, field, if a != 0 { 2 } else if n != 0 { 1 } else { 0 })
        }
        Extraction::ByteSel => fit(insn, field, op_byte_sel(insn, field.token_idx)),
        Extraction::LblPat(pat) => {
            // Double-bracket operands (Operand::Desc) carry the UR id structurally;
            // raw scraping only understands the single-bracket desc[URn] form.
            if let Some(Operand::Desc { ur_idx, .. }) = get_op(insn, field.token_idx) {
                if matches!(pat.as_str(),
                    "desc_ur" | "gdesc_ur" | "idesc_ur" | "tmem_ur" | "tdesc_ur") {
                    return fit_soft(insn, field, *ur_idx as i64, false);
                }
            }
            fit_soft(insn, field, op_lbl_scrape(insn, field.token_idx, pat) as i64, false)
        },
        Extraction::AddrScale => fit(insn, field, op_addr_scale(insn, field.token_idx)),
        Extraction::UrExpl => fit(insn, field, op_urz_flag(insn, field.token_idx)),
        // 1 - flag on u64 underflows to all-ones for flag > 1, which the mask
        // then folds back into a valid-looking payload: audit before folding.
        Extraction::UrExplInv => {
            let f = op_urz_flag(insn, field.token_idx);
            let Some(inv) = 1u64.checked_sub(f) else {
                return Err(fit_bail(insn, field, f));
            };
            fit(insn, field, inv)
        }
        Extraction::HalfSel => fit(insn, field, op_hsel(insn, field.token_idx)),
        Extraction::OpModFlag(name) => fit(insn, field, op_mod_flag_value(insn, field.token_idx, name)),
        Extraction::MnemMod(i, name) => fit(insn, field, op_mnemod(insn, *i, name)),
        Extraction::BF16 => fit_soft(insn, field, op_bf16(insn, field.token_idx) as i64, false),

        // System register
        Extraction::SysReg => fit_soft(insn, field, op_sysreg(insn, field.token_idx) as i64, false),
        // Split-field slices: the Lo/Hi decomposition is the documented
        // semantics; the lint checks each slice against its own field mask
        // (a mis-sized table row now fails closed instead of aliasing).
        Extraction::SysRegLo7 => fit_soft(insn, field, (op_sysreg(insn, field.token_idx) & 0x7F) as i64, false),
        Extraction::SysRegLo4 => fit_soft(insn, field, (op_sysreg(insn, field.token_idx) & 0xF) as i64, false),
        Extraction::SysRegHi4 => fit_soft(insn, field, ((op_sysreg(insn, field.token_idx) >> 4) & 0xF) as i64, false),
        Extraction::SysRegHi1 => fit_soft(insn, field, ((op_sysreg(insn, field.token_idx) >> 7) & 1) as i64, false),

        // Register bit-shifted (for double-precision, S64, etc.)
        Extraction::RegShr(n) => fit_soft(insn, field, (op_reg(insn, field.token_idx) >> n) as i64, false),
        Extraction::URegShr(n) => fit_soft(insn, field, (op_ureg(insn, field.token_idx) >> n) as i64, false),

        // Address sub-parts
        Extraction::SubR(i) => fit_soft(insn, field, op_sub_reg(insn, field.token_idx, *i) as i64, false),
        Extraction::SubUR(i) => fit_soft(insn, field, op_sub_ureg(insn, field.token_idx, *i) as i64, false),
        Extraction::SubURm1(i) => {
            let v = op_sub_ureg(insn, field.token_idx, *i);
            // wrapping_sub(1) on 0 silently aliases to all-ones ("sibling UR
            // = first - 1" is undefined for slot 0): audit before folding.
            let Some(m1) = v.checked_sub(1) else {
                return Err(fit_bail(insn, field, v));
            };
            fit(insn, field, m1)
        }
        Extraction::SubImm(i) => fit_soft(insn, field, op_sub_imm(insn, field.token_idx, *i) as i64, true),
        Extraction::SubImmS24(i) => {
            let raw = op_sub_imm(insn, field.token_idx, *i);
            // Legacy 24-bit slice: bits above the window were silently
            // dropped; require the signed 24-bit window to round-trip first.
            if crate::printer::sign_extend_pub(raw & 0xFFFFFF, 24) != raw as i64
                && fit_lint_warn_enabled()
            {
                eprintln!("[fit-lint] {}", fit_lint_msg(insn, field, raw, FitLint::Signed));
            }
            fit_soft(insn, field, (raw & 0xFFFFFF) as i64, false)
        }
        // Address sub-parts, bit-shifted (for .64 addresses storing reg/2)
        Extraction::SubRShr(i, n) => fit_soft(insn, field, (op_sub_reg(insn, field.token_idx, *i) >> n) as i64, false),
        Extraction::SubURShr(i, n) => fit_soft(insn, field, (op_sub_ureg(insn, field.token_idx, *i) >> n) as i64, false),
        Extraction::SubImmShr(i, n) => {
            let imm = op_sub_imm(insn, field.token_idx, *i) as i64;
            let gran = 1i64 << n;
            // Fail closed instead of silently wrapping (BUG-070 class): the
            // window is signed-offset, so the value must round-trip through
            // sign-extend(bits) << n and be a granule multiple.
            let shrunk = imm >> n;
            if imm % gran != 0 || (shrunk << n) != imm
                || crate::printer::sign_extend_pub(shrunk as u64, field.bits) != shrunk {
                return Err(anyhow::anyhow!(
                    "operand {} offset {imm:#x} not encodable in scaled \
                     (>>{n}) signed {}-bit desc window",
                    field.token_idx, field.bits));
            }
            Ok((shrunk as u64) & mk)
        }
        Extraction::SubImmShrU(i, n) => {
            // BUG-070: unsigned scaled offset window (STG.256 desc). Any of
            // negative / sub-granule / out-of-window was silently truncated
            // by `& mk` (+0x20 -> -0x20, +0x40.. -> 0); fail closed (loud
            // `cubit asm` failure per BUG-043).
            let imm = op_sub_imm(insn, field.token_idx, *i) as i64;
            let gran = 1i64 << n;
            if imm < 0 || imm % gran != 0 || (imm >> n) as u64 > mk {
                return Err(anyhow::anyhow!(
                    "operand {} offset {imm:#x} not encodable in scaled \
                     (>>{n}) unsigned {}-bit desc window (0 <= imm <= {:#x}, \
                     multiple of {gran:#x})",
                    field.token_idx, field.bits, (mk as i64) << n));
            }
            Ok(((imm >> n) as u64) & mk)
        }

        // Constant memory
        Extraction::Cm16Off => fit_cm_off_soft(insn, field, 16),
        Extraction::Cm17Off => fit_cm_off_soft(insn, field, 17),

        // Opaque modifier: extract the ?NN value from the opcode text.
        // The printer formats these as ".?6" (for value 6), and the parser
        // preserves them in opcode_full. Extract the value from there.
        Extraction::OpaqueModifier => {
            let val = extract_opaque_mod(&insn.raw_text, field.shift, field.bits);
            fit_soft(insn, field, val as i64, false)
        }

        Extraction::None => Ok(0),
        Extraction::YieldInv => fit(insn, field,
            if insn.ctrl.yield_flag { 0 } else { 1 }),
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

/// KAND-058 (SPARK sm_121a, UFADD.UR imm): hardware mirrors the immediate's
/// sign in a separate bit (UFADD imm bit2). Reachable only via this new
/// extraction, so existing rows (Reg/UReg-only `neg`) are unaffected.
fn op_neg_f32(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => f64::from_bits(*v).is_sign_negative() as u64,
        Some(Operand::Imm32(v)) => (*v < 0) as u64,
        _ => 0,
    }
}

/// KAND-058: nvdisasm prints integral f32 patterns as decimal-looking ints
/// (e.g. `UFADD UR7, UR6, -12583039` means f32(-12583039.0) = 0xcb40007f).
/// This extraction emits the f32 bit pattern of the token VALUE; FloatImm
/// keeps F32 behavior. Existing rows keep `f32` (raw IEEE bits for Imm32).
fn op_f32_cast(insn: &Instruction, tok: i32) -> u64 {
    match get_op(insn, tok) {
        Some(Operand::FloatImm(v)) => (f64::from_bits(*v) as f32).to_bits() as u64,
        Some(Operand::Imm32(v)) => (*v as f32).to_bits() as u64,
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
                // URZ alias: URZ encodes as 0xFF in the 8-bit descriptor slots
                // (same rule as the kind-fixed scrape paths below).
                let n = if num_s == "Z" { 255 }
                    else { num_s.parse::<u64>().unwrap_or(0) };
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
        // Unreachable for unknown names: the validation pass above rejects
        // them before field extraction runs.
        Some(Operand::SysReg(name)) => sysreg_id(name).unwrap_or(0),
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
    // b9 phase-3 #7: WARPSYNC.COLLECTIVE.ALL `(L)` (no register membermask)
    // is the same REL16 shape as the R-form -- vendor anchors cl1 prove
    // imm=(target-addr-16)>>4 for both; the gate is "has a resolved target",
    // not "has a Reg operand".
    if sm103a && rel_mod
        && (op == "CALL" || op.starts_with("RET") || op == "BRA"
            || (op == "WARPSYNC" && (insn.operands.iter().any(|o| matches!(o, Operand::Reg{..}))
                || find_branch_target(insn).is_some())))
    {
        if let Some(target) = find_branch_target(insn) {
            let rel = target - insn.addr as i64 - 16;
            // BUG-115: rq is a signed 21-bit immediate, not 16+blanket-ones.
            // Corpus proof (11,714/11,714 RET words + anchor CALL/BRA):
            // rq=(target-addr-16)>>4 with rq[5:0]@[23:18], rq[15:6]@[43:34],
            // rq[20:16]@[48:44], true sign-extension into [63:49]. The old
            // "imm16 & 0x8000 -> set [63:44]=1s" folded rq's bit15 into the
            // whole window, losing rq[16] (bit44) for far negative targets
            // (e.g. RET-to-0x0 from addr >1MB: rq=-0x10c71 -> vendor ext
            // 0xFFFFE) and wrapping rq-negative/imm16-positive cases.
            let rq21 = (rel >> 4) & 0x1F_FFFF; // arithmetic shift keeps the sign
            code = (code & !(0x3F_u128 << 18)) | ((rq21 as u128 & 0x3F) << 18);
            code = (code & !(0x3FF_u128 << 34)) | ((((rq21 as u128) >> 6) & 0x3FF) << 34);
            let hi20: u128 = (((rq21 as u128) >> 16) & 0x1F)
                | if rq21 & 0x10_0000 != 0 { 0xF_FFE0 } else { 0 };
            code = (code & !(0x000F_FFFF_u128 << 44)) | (hi20 << 44);
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
                Some(Operand::Imm32(x)) => Some(*x),
                Some(Operand::Imm64(x)) => Some(*x as i64),
                // corpus disassembly annotates the numeric offset with a
                // (*"BRANCH_TARGETS ..."*) comment, which the parser keeps as
                // a Label; scrape the leading numeric literal.
                Some(Operand::Label(s)) => {
                    let head = s.split_whitespace().next().unwrap_or("");
                    let sv = head.strip_prefix("-0x")
                        .and_then(|h| u64::from_str_radix(h, 16).ok().map(|v| -(v as i64)))
                        .or_else(|| head.strip_prefix("0x")
                            .and_then(|h| u64::from_str_radix(h, 16).ok().map(|v| v as i64)))
                        .or_else(|| head.parse::<i64>().ok());
                    sv.or_else(|| find_branch_target(insn)
                        .map(|t| t - insn.addr as i64 - 16))
                }
                _ => find_branch_target(insn).map(|t| t - insn.addr as i64 - 16),
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
