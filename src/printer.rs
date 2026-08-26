//! SASS instruction printer: DecodedInst → text.
//!
//! Reconstructs the SASS assembly text from a decoded instruction, producing
//! output equivalent to `cuobjdump -sass` (without the scheduling annotations).

use crate::decoder::{DecodedField, DecodedInst};
use std::collections::BTreeMap;

// ── public entry point ────────────────────────────────────────────────────────

/// Uniform-guard family law (BUG-171, census evidence hexdb 32.2M + sm120
/// nv-harvest: vendor prints @UPn/@!UPn/@!UPT guards ONLY for these families —
/// all `U*` uniform-datapath ops, LDCU (uniform constant load), SYNCS_UR
/// (uniform-domain SYNCS, e.g. EXCH), S2UR). Guard bits [15:12] carry just
/// (pred,neg); uniformness follows the family, both print paths agree.
fn guard_is_uniform_family(key: &str) -> bool {
    key.starts_with('U') || key.starts_with("LDCU")
        || key.starts_with("SYNCS_UR") || key.starts_with("S2UR")
}

/// Format a decoded instruction as SASS text (without trailing ` ;`).
pub fn to_sass(insn: &DecodedInst) -> String {
    let by_token = group_by_token(&insn.fields);
    let raw = insn.raw_code;

    // Format guard: prefer decoded fields; fall back to raw bits [15:12] when the
    // table entry has no guard field (e.g. some uniform/special-purpose instructions
    // whose variable_mask was learned from PT-only training records).
    let tok0_fields = by_token.get(&0).map(Vec::as_slice).unwrap_or(&[]);
    let has_guard_field = tok0_fields.iter().any(|f| {
        let e = norm_ext(&f.extraction);
        e == "guard" || e == "guard_neg"
    });
    // Uniform-datapath instructions print their guard as @UPn/@!UPn (nvdisasm);
    // the guard bits [15:12] encode only (pred, neg) — uniformness follows the family.
    // BUG-171: single source of truth for both the field and the raw-fallback
    // path (the fallback copy below lacked "LDCU" → @Pn printed for LDCU rows
    // without a guard field, e.g. sm120 LDCU_UR_cAI * 565 battery anchors).
    let is_uni = guard_is_uniform_family(&insn.key);
    let guard = if has_guard_field {
        format_guard_uni(tok0_fields, is_uni)
    } else {
        // Extract 4-bit guard from raw bits [15:12] directly.
        let raw_guard = (raw >> 12) & 0xF;
        let pred = raw_guard & 0x7;
        let neg  = (raw_guard >> 3) & 1;
        if pred == 7 && neg == 0 {
            String::new() // PT = no guard (unconditional)
        } else if pred == 7 && neg != 0 {
            // @!UPT (uniform) or @!PT (regular) — QMMA drain pattern
            if is_uni { "@!UPT".to_string() } else { "@!PT".to_string() }
        } else {
            let neg_s = if neg != 0 { "!" } else { "" };
            if is_uni { format!("@{neg_s}UP{pred}") } else { format!("@{neg_s}P{pred}") }
        }
    };
    let opcode = format_opcode(&insn.opcode, &insn.mod_group, &insn.key);

    // Collect opaque modifier fields (tok=0) — these encode comparison modes,
    // reduction functions, etc. as raw values that become part of the opcode text.
    // Resolve to human-readable names when possible (e.g. ?6 → ?GE for comparison).
    let opaque_suffix = {
        let mut parts = Vec::new();
        for f in tok0_fields {
            if norm_ext(&f.extraction) == "opaque_mod" {
                parts.push(resolve_opaque_mod(f.shift, f.bits, f.value));
            }
        }
        if parts.is_empty() { String::new() } else { format!(".{}", parts.join(".")) }
    };
    let opcode = if opaque_suffix.is_empty() { opcode } else { format!("{opcode}{opaque_suffix}") };

    let (_, op_types) = parse_ins_key(&insn.key);

    // Special handling for branch instructions: decode target from raw bits
    if is_branch_op(&insn.opcode) {
        let target = decode_branch_target(insn);
        let guard_prefix = if guard.is_empty() { String::new() } else { format!("{guard} ") };
        // BRA/CALL/JMP: format as "opcode target"
        // BSSY/BSYNC/BREAK: format as "opcode [barrier,] target"
        if is_bssy_op(&insn.opcode) {
            // BSSY has a barrier operand (B0..B7) and a target
            // The barrier is typically from the first R/B operand field
            let barrier_str = if let Some(fields) = by_token.get(&1) {
                format_barrier(fields)
            } else {
                "B0".to_string()
            };
            return format!("{guard_prefix}{opcode} {barrier_str}, 0x{target:x}");
        }
        // BRA.U: uniform predicate at bits[26:24], negation at bit 27.
        // DecodedInst.opcode is the base "BRA" (the .U suffix lives in the
        // mod group), so key off the InsKey which carries the UP operand sig.
        if insn.opcode == "BRA.U" || insn.key.starts_with("BRA_UP_") {
            let lo64 = insn.raw_code as u64;
            let upred = (lo64 >> 24) & 0x7;
            let upred_neg = (lo64 >> 27) & 1;
            let upred_str = if upred == 7 && upred_neg == 0 {
                "UPT".to_string()
            } else if upred == 7 && upred_neg == 1 {
                "!UPT".to_string()
            } else if upred_neg != 0 {
                format!("!UP{upred}")
            } else {
                format!("UP{upred}")
            };
            return format!("{guard_prefix}{opcode} {upred_str}, 0x{target:x}");
        }
        // BRX: register at bits[31:24] plus signed byte offset; sm_103a layout
        // imm17 = rq[5:0]@[23:18] | rq[16:6]@[50:34], sext [63:45], off=rq<<4
        // (inverse of the encoder's verified BRX path; corpus prints
        // "BRX R2 -0x890" with an optional BRANCH_TARGETS comment).
        if insn.opcode == "BRX" {
            let lo64 = insn.raw_code as u64;
            let reg = (lo64 >> 24) & 0xFF;
            let rq = ((lo64 >> 18) & 0x3F) | (((lo64 >> 34) & 0x7FF) << 6);
            let rq = if rq & 0x10000 != 0 { rq | !0x1FFFFu64 } else { rq } as i64;
            let off = rq << 4;
            let off_s = if off < 0 { format!("-0x{:x}", -off) } else { format!("0x{off:x}") };
            return format!("{guard_prefix}{opcode} R{reg}, {off_s}");
        }
        // RET/RET.NODEC: register at bits[31:24], then branch target
        if insn.opcode.starts_with("RET") {
            let lo64 = insn.raw_code as u64;
            let reg = (lo64 >> 24) & 0xFF;
            if reg != 0 && reg != 255 {
                return format!("{guard_prefix}{opcode} R{reg}, 0x{target:x}");
            }
        }
        // BRA-with-predicate-AND-uniform-register operands (InsKey
        // BRA_P_UR_II — the sm_120 DIV/CONV diverge/converge form): nvdisasm
        // prints "@Pg BRA.DIV [!]Pn, URn, target". The generic BRA_P_ arm
        // below prints only two tokens, silently dropping the UR operand
        // (BUG-022) — re-assembling that render lands on the BRA_P_II entry
        // and fails encode-verify (-> __raw__). UR field: 8 bits at [31:24];
        // 0xff is the URZ sink by the same convention as format_ureg_raw.
        if insn.key.starts_with("BRA_P_UR_") {
            let p = ((insn.raw_code >> 87) & 0x7) as u8;
            let n = ((insn.raw_code >> 90) & 1) as u8;
            let pred = if p == 7 && n == 0 { "PT".to_string() }
                       else { format!("{}P{}", if n == 1 { "!" } else { "" }, p) };
            let ur = ((insn.raw_code >> 24) & 0xFF) as u64;
            let ur_s = if ur == 0xFF { "URZ".to_string() } else { format!("UR{ur}") };
            return format!("{guard_prefix}{opcode} {pred}, {ur_s}, 0x{target:x}");
        }
        // BRA-with-predicate-operand (InsKey BRA_P_II): nvdisasm prints
        // "@Pg BRA [!]Pn, target" — Pn = bits[89:87], neg = bit90.
        if insn.key.starts_with("BRA_P_") {
            let p = ((insn.raw_code >> 87) & 0x7) as u8;
            let n = ((insn.raw_code >> 90) & 1) as u8;
            let pred = if p == 7 && n == 0 { "PT".to_string() }
                       else { format!("{}P{}", if n == 1 { "!" } else { "" }, p) };
            return format!("{guard_prefix}{opcode} {pred}, 0x{target:x}");
        }
        // BRA.DIV URn, target (InsKey BRA_UR_II, mg "DIV"): the exception-weight
        // uniform register operand lives at bits[31:24]; without this the text
        // silently drops it and the round-trip loses the operand.
        if insn.key.starts_with("BRA_UR_") {
            let lo64 = insn.raw_code as u64;
            let ur = (lo64 >> 24) & 0xFF;
            return format!("{guard_prefix}{opcode} UR{ur}, 0x{target:x}");
        }
        // CALL.ABS register-indirect (InsKey CALL_R, mg "ABS,NOINC"): nvdisasm
        // prints "CALL.ABS.NOINC Rn" -- the operand is the register at
        // bits[31:24], NOT a computed branch target (hexdb census 2026-08-25,
        // iter72: 2154/2154 vendor ABS anchors are "R2"; zero immediate-ABS
        // witnesses). The generic arm used to print decode_branch_target(raw)
        // = addr+0x10 (rel==0 under this row) -> fabricated address text that
        // no table row could re-encode (2,884 corpus lines; BUG-153).
        if insn.opcode == "CALL" && insn.mod_group.contains("ABS") {
            let lo64 = insn.raw_code as u64;
            let reg = (lo64 >> 24) & 0xFF;
            let reg_s = if reg == 255 { "RZ".to_string() } else { format!("R{reg}") };
            return format!("{guard_prefix}{opcode} {reg_s}");
        }
        return format!("{guard_prefix}{opcode} 0x{target:x}");
    }

    let is_s2r = matches!(insn.opcode.as_str(), "S2R" | "S2UR" | "CS2R");

    // Instruction-level descriptor-family marker: true when ANY token carries
    // a tcgen05 descriptor field (used to route the field-less UTC idesc tok5).
    let inst_is_utc_desc = insn.fields.iter().any(|f| {
        let e = norm_ext(&f.extraction);
        matches!(e.as_str(),
            "tdesc_ur" | "gdesc_ur" | "tmem_ur" | "idesc_ur"
            | "gdesc_off" | "tmem_off" | "idesc_off" | "tdesc_off")
    });

    let mut operands: Vec<String> = Vec::new();
    for (i, op_type) in op_types.iter().enumerate() {
        let tok = (i + 1) as i32;
        let fields = by_token.get(&tok).map(Vec::as_slice).unwrap_or(&[]);
        let has_desc_family = fields.iter().any(|f| {
            let e = norm_ext(&f.extraction);
            matches!(e.as_str(),
                "tdesc_ur" | "gdesc_ur" | "tmem_ur" | "idesc_ur" | "dsel2"
                | "gdesc_off" | "tmem_off" | "idesc_off" | "tdesc_off"
                | "desc_ur" | "desc_off")
        });
        // S2R/S2UR: second operand is always a system register
        // (may be stored as '?', 'II', or 'L' in InsKey depending on decoder match)
        let s = if is_s2r && (i >= 1 || op_type == "?") {
            format_sysreg(fields, raw)
        } else if op_type == "dARI" {
            // Descriptor-with-base form: must print the full desc[UR][R.64+off]
            // pair (a lone desc[URn] loses base_reg/offset on the round-trip).
            format_desc_addr(fields, raw)
        } else if op_type == "II" && insn.opcode == "WARPSYNC"
            && insn.mod_group.split(',').any(|m| m.trim() == "COLLECTIVE")
        {
            // WARPSYNC.COLLECTIVE[.ALL] [Rn,] <partner target>: the encoded field
            // is the number of 16-byte slots ahead; nvdisasm prints the RESOLVED
            // address target = addr + 16 + (field << 4) as a label. Corpus proof
            // (BUG-116): 230,944 labelled WARPSYNC words over 2,145 cubins, per-
            // sample target == addr+16+(v<<4), v = [23:18]|[43:34]<<6 (rq16).
            // Printing the raw field (e.g. "0x5", the WARPSYNC_II/ALL form used
            // to) breaks our own text->encode roundtrip (encoder treats operands
            // as absolute targets), so resolve both collective forms here.
            let v = (((raw >> 18) & 0x3F) as u64) | ((((raw >> 34) & 0x3FF) as u64) << 6);
            format!("0x{:x}", insn.addr as u64 + 16 + (v << 4))
        } else if has_desc_family || (inst_is_utc_desc && tok == 5) {
            // tcgen05 descriptor operand: InsKey sig may read II but the text
            // form is kind[URN(+0xoff)] — gdesc[]/tmem[]/idesc[] (UTCHMMA,
            // UTCQMMA, LDTM, STTM, …). UTC tok5 (idesc) may have NO field:
            // hardware then derives UR_idesc == UR_tmem2 + 1 (run27 rule).
            // The empty-fields tok5 still must route here (else the generic
            // operand path prints "0x0" — F3).
            format_utc_desc(tok, by_token.get(&tok).map(Vec::as_slice).unwrap_or(&[]),
                            by_token.get(&4).map(Vec::as_slice).unwrap_or(&[]))
        } else {
            format_operand(op_type, fields, &insn.mod_group, &insn.key, tok, raw)
        };
        // pred_inv4 zero window = no guard pred: nvdisasm OMITS the token,
        // so an empty format result for a P slot is dropped here (not ", ").
        let inv4_omitted = s.is_empty()
            && op_type == "P"
            && fields.iter().any(|f| norm_ext(&f.extraction) == "pred_inv4");
        if !inv4_omitted {
            operands.push(s);
        }
    }

    // Print any extra trailing pred fields (tok > InsKey length).
    // Only for carry-extended (.X) instructions where the carry-in pred is meaningful.
    let is_carry_x = insn.mod_group.split(',').any(|m| m.trim() == "X");
    let max_tok = op_types.len() as i32;
    let mut extra_toks: Vec<i32> = if is_carry_x {
        by_token.keys()
            .filter(|&&k| k > max_tok && k > 0)
            .copied()
            .collect()
    } else {
        Vec::new()
    };
    extra_toks.sort_unstable();
    for extra_tok in extra_toks {
        let extra_fields = by_token.get(&extra_tok).map(Vec::as_slice).unwrap_or(&[]);
        let has_pred = extra_fields.iter().any(|f| {
            let e = norm_ext(&f.extraction);
            e == "pred" || e == "upred" || e == "pred_inv4"
        });
        if !has_pred { continue; }
        let pred_val = extra_fields.iter()
            .find(|f| { let e = norm_ext(&f.extraction); e == "pred" || e == "upred" })
            .map(|f| f.value)
            .unwrap_or(7);
        // sm_121a inverted 4-bit pred map (pred_inv4): v==0 -> PT, v==8 -> !PT,
        // v in 1..=7 -> P(7-v), v in 9..=15 -> !P(15-v). Translate into the
        // mainstream (number, inv) pair used below.
        let inv4 = extra_fields.iter().any(|f| norm_ext(&f.extraction) == "pred_inv4");
        let inv4_field_val = if inv4 {
            extra_fields.iter()
                .find(|f| norm_ext(&f.extraction) == "pred_inv4")
                .map(|f| f.value)
                .unwrap_or(0)
        } else { 0 };
        let uniform = extra_fields.iter().any(|f| norm_ext(&f.extraction) == "upred");
        // Detect !PT. BUG-089: the negation is PER-SLOT: consult an explicit
        // neg/inv field attached to THIS extra token first (e.g. IADD3.X tail
        // preds: tok7 neg@90, tok8 inv@80). Only when the row declares none,
        // fall back to the legacy heuristic (pred==7 && bit80 of raw), which
        // is correct solely for the combining-pred slot.
        let explicit_neg = extra_fields.iter().find(|f| {
            let e = norm_ext(&f.extraction);
            e == "neg" || e == "inv"
        });
        let (pred_val, inv) = if inv4 {
            // inv4 carries negation inside the 4-bit window; no side fields.
            let (n, ng) = match inv4_field_val {
                0 => (7u64, false),
                8 => (7u64, true),
                v @ 1..=7 => (7 - v, false),
                v => (15 - v, true), // 9..=15
            };
            (n, ng)
        } else {
            let inv = match explicit_neg {
                Some(f) => f.value != 0,
                // legacy heuristic is correct solely for the combining-pred (PT) slot
                None => pred_val == 7 && ((raw >> 80) & 1) != 0,
            };
            (pred_val, inv)
        };
        let s = if pred_val == 7 {
            let pt = if uniform { "UPT" } else { "PT" };
            if inv { format!("!{pt}") } else { pt.to_string() }
        } else {
            let prefix = if uniform { "UP" } else { "P" };
            // explicit neg/inv on THIS token also negates non-PT preds (`!P0`):
            // vendor renders tail-pred negation for both carry slots of .X ops
            // (BUG-089 sweep v3/v12: nvdisasm `!P0`, byte-exact encode path).
            if inv { format!("!{prefix}{pred_val}") } else { format!("{prefix}{pred_val}") }
        };
        operands.push(s);
    }

    let guard_prefix = if guard.is_empty() {
        String::new()
    } else {
        format!("{guard} ")
    };

    // Post-process: add .reuse from raw bits 122/123/124 if not already present.
    // Reuse bit mapping: bit122→Ra(shift=24), bit123→Rb(shift=32), bit124→Rc(shift=64).
    // Map from register slot shift to operand index (1-based token).
    {
        let reuse_slots: [(u32, u32); 3] = [(122, 24), (123, 32), (124, 64)];
        for &(reuse_bit, slot_shift) in &reuse_slots {
            if (raw >> reuse_bit) & 1 != 0 {
                // Find which token (1-based) has a reg field at this shift
                let tok_opt = insn.fields.iter()
                    .find(|f| f.shift == slot_shift && f.bits == 8 && {
                        let e = norm_ext(&f.extraction);
                        e == "reg" || e == "ureg" || e == "ureg_ff" || e == "reg_ff"
                    })
                    .map(|f| f.token_idx);
                if let Some(tok) = tok_opt {
                    let idx = (tok - 1) as usize;
                    if idx < operands.len() && !operands[idx].contains(".reuse") {
                        // Append .reuse, handling the case where the operand might have trailing flags
                        operands[idx] = format!("{}.reuse", operands[idx]);
                    }
                }
            }
        }
    }

    // BUG-012: IMAD.MOV idiom alias — with both multiplier operands RZ the
    // instruction is a pure move; nvdisasm prints `.MOV`. Render it so the text
    // matches nvdisasm (encoder accepts the alias, rejecting non-RZ misuse).
    // BUG-083: nvdisasm applies the MOV alias only when the moved operand is in
    // the R domain (or an immediate); `IMAD Rx, RZ, RZ, URn` / `-URn` stays
    // plain (0 MOV-aliased UR samples in the 2049-cubin census, 896 plain UR
    // samples that must not be aliased).
    let opcode = if insn.opcode == "IMAD"
        && insn.mod_group.split(',').all(|m| m.trim().is_empty())
        && operands.len() >= 3
        && operands[1] == "RZ"
        && operands[2] == "RZ"
        && !operands[3].starts_with("UR")
        && !operands[3].starts_with("-UR")
    {
        format!("{opcode}.MOV")
    } else {
        opcode
    };

    // BUG-045: ULOP3 UP-dest == UPT is the hardware encoding of the
    // dest-less form — every i93 no-dest golden word has dest-sel 7 (UPT)
    // baked. nvdisasm omits the operand; drop the leading "UPT" so render
    // matches nvdisasm and the text re-encodes through the UR_* rows
    // byte-identically (their and_base fixes sel=7). Data: 7 gold words,
    // class "cosmetic" in the gold census.
    if insn.opcode == "ULOP3"
        && op_types.first().map(|t| t == "UP").unwrap_or(false)
        && operands.first().map(|s| s == "UPT").unwrap_or(false)
    {
        operands.remove(0);
    }

    // BUG-104 (ur-up URZ elision): the *_UR_UP enable-UR slot encodes URZ as
    // 0xFF; nvdisasm then prints the SHORT form without the UR token entirely
    // (harvest-2049 bi8_hop class, 164 words, cuobjdump-verified). Re-encode
    // is byte-identical: the elided text routes to the 6II row whose and_base
    // carries the same 0xFF in that slot. Elide the URZ token so render ==
    // vendor spelling.
    if insn.opcode.starts_with("UTC")
        && (insn.key.ends_with("_UR_UP") || insn.key.contains("_UR_UP_II"))
    {
        let last_is_upred = operands.last().map(|s| {
            let t = s.trim_start_matches('!');
            t == "UPT" || (t.starts_with("UP") && t[2..].chars().all(|c| c.is_ascii_digit()) && t.len() > 2)
        }).unwrap_or(false);
        if last_is_upred && operands.len() >= 2 {
            let urz_tok = insn.fields.iter().find(|f| {
                norm_ext(&f.extraction) == "ureg" && f.value == 255
            }).map(|f| f.token_idx);
            if let Some(tok) = urz_tok {
                let idx = (tok - 1) as usize;
                if idx + 1 == operands.len() - 1 {
                    operands.remove(idx);
                }
            }
        }
    }

    if operands.is_empty() {
        format!("{guard_prefix}{opcode}")
    } else {
        format!("{guard_prefix}{opcode} {}", operands.join(", "))
    }
}

/// Check if tok is the last token in the instruction's operand list.
fn is_last_token(tok: i32, ins_key: &str) -> bool {
    let (_, op_types) = parse_ins_key(ins_key);
    tok == op_types.len() as i32
}

fn is_branch_op(opcode: &str) -> bool {
    // BRA, CALL, JMP, RET, BSSY need branch target decoding
    // BSYNC/BREAK do NOT have target addresses (just barrier operands)
    matches!(opcode, "BRA" | "BRA.U" | "BRX" | "BRXU" | "CALL" | "JMP" | "RET" | "RET.NODEC" | "BSSY")
}

fn is_bssy_op(opcode: &str) -> bool {
    matches!(opcode, "BSSY")
}

/// Decode branch target address from raw instruction bits.
/// BRA/CALL/JMP/RET: split-word encoding with dword offset.
/// BSSY/BSYNC/BREAK: byte offset at [63:32].
fn decode_branch_target(insn: &DecodedInst) -> u32 {
    let raw = insn.raw_code;
    let lo64 = raw as u64;
    let hi64 = (raw >> 64) as u64;
    // Strip scheduling bits from hi64 (bits [57:41] of hi64 = bits [121:105] of full)
    let hi64_clean = hi64 & !((0x1FFFF_u64) << 41);

    if is_bssy_op(&insn.opcode) {
        // BSSY: rel = sign_extend_32bit(bits[63:32] of instruction)
        let rel = ((lo64 >> 32) & 0xFFFFFFFF) as i64;
        // Sign-extend from 32 bits
        let rel = if rel & (1 << 31) != 0 { rel | (!0x7FFFFFFFi64) } else { rel };
        return (insn.addr as i64 + 16 + rel) as u32;
    }

    // BRA/CALL/JMP: dword-split encoding
    // lo_byte = bits[23:16] (8 bits)
    // hi_part = bits[63:32] >> 2 (30 bits, sign extended)
    let lo_byte = (lo64 >> 16) & 0xFF;
    let hi_raw  = (lo64 >> 32) & 0xFFFFFFFF;
    let hi_part = hi_raw >> 2;  // 30 bits of shifted dword offset

    // Sign-extend hi_part from 30 bits using sign extension bits [81:64] (= hi64[17:0])
    let sign_bits = hi64_clean & 0x3FFFF;
    let hi_signed: i64 = if sign_bits != 0 || (hi_part >> 29) & 1 != 0 {
        // Negative: sign-extend hi_part from 30 bits
        (hi_part as i64) | (!(0x3FFFFFFFi64))
    } else {
        hi_part as i64
    };

    let rq = lo_byte as i64 | (hi_signed << 8);
    let rel = rq * 4;
    (insn.addr as i64 + 16 + rel) as u32
}

// ── helpers ───────────────────────────────────────────────────────────────────

type TokenMap<'a> = BTreeMap<i32, Vec<&'a DecodedField>>;

fn group_by_token(fields: &[DecodedField]) -> TokenMap<'_> {
    let mut m: TokenMap = BTreeMap::new();
    for f in fields {
        m.entry(f.token_idx).or_default().push(f);
    }
    m
}

/// Resolve an opaque_mod field to a human-readable `?NAME` string.
/// Uses shift/bits to identify the field's semantic role:
///   shift=78, bits=3 → REDUX function: AND/OR/XOR/SUM/MIN/MAX
///   shift=76, bits=3 → ISETP/UISETP comparison: LT/EQ/LE/GT/NE/GE
///   shift=73, bits=1 → signed flag: U32 (0) / S32 (1)
///   shift=91, bits=2 → combine mode: AND/OR/XOR
fn resolve_opaque_mod(shift: u32, bits: u32, value: u64) -> String {
    let name = match (shift, bits) {
        (78, 3) => match value {
            0 => "AND", 1 => "OR",  2 => "XOR",
            3 => "SUM", 4 => "MIN", 5 => "MAX",
            _ => return format!("?{:x}", value),
        },
        (76, 3) => match value {
            1 => "LT", 2 => "EQ", 3 => "LE",
            4 => "GT", 5 => "NE", 6 => "GE",
            _ => return format!("?{:x}", value),
        },
        (73, 1) => match value {
            0 => "U32", 1 => "S32",
            _ => return format!("?{:x}", value),
        },
        (91, 2) => match value {
            0 => "AND", 1 => "OR", 2 => "XOR",
            _ => return format!("?{:x}", value),
        },
        _ => return format!("?{:x}", value),
    };
    format!("?{name}")
}

/// Normalise extraction type name to lowercase snake_case.
fn norm_ext(s: &str) -> String {
    // Explicit known mappings (PascalCase from decoder → snake_case for matching)
    match s {
        "SysReg"     => return "sysreg".to_string(),
        "SysRegLo7"  => return "sysreg_lo7".to_string(),
        "SysRegLo4"  => return "sysreg_lo4".to_string(),
        "SysRegHi4"  => return "sysreg_hi4".to_string(),
        "SysRegHi1"  => return "sysreg_hi1".to_string(),
        "None"       => return "none".to_string(),
        "Cm16Off"    => return "cm16off".to_string(),
        "Cm17Off"    => return "cm17off".to_string(),
        _ => {}
    }
    // Parameterised forms: SubImm(1) → sub_imm1, SubR(0) → sub_r0
    if let Some(rest) = s.strip_prefix("SubImm") {
        let n = rest.trim_matches(|c: char| c == '(' || c == ')');
        return format!("sub_imm{n}");
    }
    if let Some(rest) = s.strip_prefix("SubImmS24") {
        let n = rest.trim_matches(|c: char| c == '(' || c == ')');
        return format!("sub_imm_s24_{n}");
    }
    if let Some(rest) = s.strip_prefix("SubR(") {
        let n = rest.trim_end_matches(')');
        return format!("sub_r{n}");
    }
    if let Some(rest) = s.strip_prefix("SubUR(") {
        let n = rest.trim_end_matches(')');
        return format!("sub_ur{n}");
    }
    if let Some(rest) = s.strip_prefix("RegShr(") {
        let n = rest.trim_end_matches(')');
        return format!("reg_shr{n}");
    }
    if let Some(rest) = s.strip_prefix("URegShr(") {
        let n = rest.trim_end_matches(')');
        return format!("ureg_shr{n}");
    }
    // Already snake_case: guard, reg, imm, ureg, pred, neg, abs, inv, reuse, f32, f16, etc.
    s.to_lowercase()
}

/// Known operand-type segments in InsKey (longer first to avoid prefix conflicts).
const OP_TYPES: &[&str] = &[
    "ARURR", "ARURI", "ARUR", "AURI", "AURR", "AUR",
    "cAI", "dARI", "ARI",
    "UP", "UR", "SR", "FI", "II", "IM", "LO",
    "R", "P", "L", "B", "?",
];

fn parse_ins_key(key: &str) -> (String, Vec<String>) {
    let parts: Vec<&str> = key.split('_').collect();
    let mut opcode_parts: Vec<&str> = Vec::new();
    let mut op_parts: Vec<String> = Vec::new();
    let mut in_ops = false;

    for part in &parts {
        if !in_ops && OP_TYPES.contains(part) {
            // "_B" right after a (UN)PACK opcode is a lane suffix
            // (F2FP...PACK_B / UNPACK_B), not a Barrier operand — keep it in the opcode.
            let pack_b = *part == "B"
                && opcode_parts.last().is_some_and(|p| p.ends_with("PACK"));
            if !pack_b {
                in_ops = true;
            }
        }
        if in_ops {
            op_parts.push(part.to_string());
        } else {
            opcode_parts.push(part);
        }
    }
    (opcode_parts.join("_"), op_parts)
}

/// Priority ordering for CUDA instruction modifiers.
/// Lower number = appears earlier in the mnemonic (e.g. IMAD.WIDE.U32.AND).
fn mod_priority(m: &str) -> u8 {
    match m {
        // Comparison operators (ISETP, FSETP etc.)
        "GE" | "GT" | "LT" | "LE" | "NE" | "EQ" |
        "GEU"| "GTU"| "LTU"| "LEU"| "NEU"| "EQU"|
        "NAN"| "NUM"| "GEF"| "NEF" => 1,
        // Wrap/mode qualifiers (SHF.R.W = wrap comes AFTER direction): priority 4
        "W" => 4,
        // CALL.REL.NOINC / RET.REL.NODEC — nvdisasm prints the addr form (REL/ABS)
        // before the control qualifier (NOINC/NODEC).
        "REL" | "ABS" => 2,
        "NOINC" | "NODEC" => 8,
        // Direction qualifiers (SHF.R = right, SHF.L = left, WIDE, etc.)
        // Note: HI (half result) comes AFTER data-size modifiers (e.g. SHF.R.S32.HI, USHF.L.U64.HI)
        // Note: X (carry-in/out) comes AFTER data-size/type modifiers (e.g. IADD.64.X, IMAD.WIDE.U32.X)
        "R" | "L" | "WIDE"| "SHL"| "SX32"| "LO"| "FTZ"| "SAT" => 3,
        // Memory access mode
        "E"| "LTC128B"| "BYPASS"| "STRONG"| "GPU"|"SYS"|"CTA"|
        "GL"| "IL"| "MMU"=> 3,
        // Synchronisation
        "SYNC" => 4,
        // Data types
        "U32"| "S32"| "U64"| "S64"| "U16"| "S16"|
        "F32"| "F64"| "F16"| "BF16"|
        "E4M3"| "E5M2"| "NTZ"| "NTB"| "TRUNC"|
        "F32X2"| "F16X2"| "BF16X2" => 5,
        // Data size
        "256"| "128"| "64"| "32"| "16"| "8" => 6,
        // HI modifier (high half): comes after data size (SHF.R.S32.HI, USHF.L.U64.HI)
        "HI" => 7,
        // Boolean operators
        "AND"| "OR"| "XOR" => 7,
        // EX (second-output-predicate present) prints LAST in nvdisasm syntax:
        // "ISETP.GE.U32.AND.EX", never "ISETP.GE.EX.U32.AND".
        "EX" => 9,
        // Barrier/convergence qualifiers
        "DEFER_BLOCKING"| "RECONVERGENT"| "RELIABLE"| "NODEP" => 8,
        // X (carry-in) comes after data types/sizes
        "X" => 8,
        // LUT and similar always last
        "LUT"| "MT88"| "4" => 9,
        _ => 5, // unknown → treat like data type
    }
}

fn format_opcode(base: &str, mod_group: &str, key: &str) -> String {
    if mod_group.is_empty() {
        return base.to_string();
    }
    let base_mods: std::collections::HashSet<&str> = base.split('.').skip(1).collect();
    let mut mods: Vec<&str> = mod_group.split(',')
        .filter(|m| !base_mods.contains(m))
        .collect();
    if mods.is_empty() {
        return base.to_string();
    }
    mods.sort_by_key(|m| mod_priority_for_key(base, key, m));
    let suffix: String = mods.iter().map(|m| format!(".{m}")).collect();
    format!("{base}{suffix}")
}

/// Key-aware modifier priority wrapper. BUG-125: the fresh nvcc-13.3 f32-imm
/// form of F2I (key F2I_R_FI) prints vendor order FTZ < dst-type < rounding <
/// NTZ (`F2I.FTZ.U32.CEIL.NTZ R0, 16`, nvdisasm-13.3 oracle sweep x96), while
/// the legacy register-form F2I_R_R rows keep their alphabetical/priority
/// prints (gold-locked pre-125 renders — do NOT unify silently).
fn mod_priority_for_key(base: &str, key: &str, m: &str) -> u8 {
    if key == "F2I_R_FI" {
        match m {
            "U8" | "S8" | "U16" | "S16" | "U32" | "S32" | "U64" | "S64" => return 4,
            "FLOOR" | "CEIL" | "RN" | "TRUNC" => return 5,
            "NTZ" => return 6,
            _ => {}
        }
    }
    mod_priority_for(base, m)
}

/// Opcode-aware modifier priority (overrides generic mod_priority for specific cases).
fn mod_priority_for(base: &str, m: &str) -> u8 {
    // HSETP2.BF16_V2.NEU.AND — the vector-width modifier precedes the comparison
    // in nvdisasm output for the half-precision setp family.
    if m == "BF16_V2" && matches!(base, "HSETP" | "HSETP2") { return 0; }
    // op18: UTCATOMSWS — nvdisasm order: 2CTA < op (FIND_AND_SET/AND) < ALIGN
    // (UTCATOMSWS.2CTA.FIND_AND_SET.ALIGN, UTCATOMSWS.FIND_AND_SET.ALIGN).
    if base == "UTCATOMSWS" {
        match m {
            "2CTA" => return 1,
            "FIND_AND_SET" | "AND" | "OR" | "XOR" | "EXCH" => return 4,
            "ALIGN" => return 5,
            _ => {}
        }
    }
    // IMAD.HI means "high-half product" and appears BEFORE the data type: IMAD.HI.U32
    if m == "HI" && matches!(base, "IMAD" | "IMAD_U32" | "IMAD_S32") { return 4; }
    // SH (shift-count hint) in FLO comes AFTER the data type: FLO.U32.SH
    if m == "SH" { return 6; }
    // LEA.HI.X.SX32 — SX32 is a suffix that comes AFTER HI and X
    if m == "SX32" && base == "LEA" { return 9; }
    // ULEA.HI.X.SX32 — same
    if m == "SX32" && base == "ULEA" { return 9; }
    // UTMA* (TMEM/tensor descriptor ops): nvdisasm order is
    // L2 hint < dimensionality < MULTICAST < 2CTA < op
    // (UTMAPF.L2.3D, UTMALDG.3D.MULTICAST.2CTA, UTMAREDG.3D.ADD).
    if matches!(base, "UTMALDG" | "UTMASTG" | "UTMAPF" | "UTMAREDG" | "UTMACCTL") {
        match m {
            "L2" => return 1,
            "2D" | "3D" | "4D" | "5D" => return 2,
            "MULTICAST" => return 3,
            "2CTA" => return 4,
            _ => {}
        }
    }
    // ATOMG/REDG/ATOMS: E first, then operation, then SIZE (BUG-094: vendor
    // prints ATOMG.E.CAS.64.STRONG.SYS, not ATOMG.E.CAS.STRONG.64.SYS), then
    // consistency (STRONG), then scope (GPU/SYS)
    if matches!(base, "ATOMG" | "REDG" | "ATOMS" | "ATOM") {
        match m {
            "ADD" | "MIN" | "MAX" | "CAS" | "INC" | "DEC" | "EXCH"
            // mk35: booleans as a subop too (REDG.E.AND.STRONG.GPU; AND/AND? not LOP3)
            | "AND" | "OR" | "XOR"
            // BUG-094b: CAST/SPIN are also an operation name (ATOM.E.CAST.SPIN.64:
            // the size PRINTS after them, before STRONG)
            | "CAST" | "SPIN" => return 4,
            // BUG-179: nvdisasm prints the POPC return-count qualifier BEFORE
            // the operation (ATOMS.POPC.INC.32, never .INC.POPC); it is the
            // only POPC-bearing row in either table (iter83 whole-table scan).
            "POPC" => return 3,
            "64" | "128" => return 5,
            "STRONG" | "WEAK" | "ACQUIRE" | "RELEASE" => return 6,
            "GPU" | "SYS" | "CTA" | "GL" | "IL" | "MMU" => return 7,
            _ => {}
        }
    }
    // BUG-098: LDSM (matrix load from shared) - nvdisasm prints tile width
    // BEFORE layout and matrix count LAST: LDSM.16.M88.4 / LDSM.16.M88.2
    // (was LDSM.M88.16.4 / LDSM.2.M88.16 via generic buckets). Vendor anchors:
    // 32 slots in the 2049-cubin census.
    if base == "LDSM" || base == "STSM" {
        // b9p11: STSM shares the LDSM vendor order (BUG-098 anchors; STSM
        // anchor corpus_p12_stmatrix O0 0x190 = STSM.16.M88.4 [R0], R4).
        match m {
            "16" => return 4,
            "M88" | "MT88" | "M816" => return 5,
            "2" | "4" => return 6,
            _ => {}
        }
    }
    // b9p11: UBLKCP.S.G — vendor prints dst space (.S) BEFORE src space (.G)
    // (anchor corpus_b_bulk_cp O0 0x410); generic buckets sorted G first.
    if base == "UBLKCP" {
        match m {
            "S" => return 4,
            "G" => return 5,
            _ => {}
        }
    }
    // b4fill: IMAD.WIDE.U32.X.B90 — the B90 tag prints after X (IMAD.WIDE.U32.X.B90)
    if m == "B90" && base.starts_with("IMAD") { return 9; }
    // b4fill: LDG cache-policy family — nvdisasm order is
    // E < L1-hint(EL/EF/NA/EU/EN) < L2-hint(ELL2/ENL2/EFL2) < size(256) < consistency < scope
    // (LDG.E.EL.ELL2.256.STRONG.GPU).
    // render-parity (b11, era rt98 anchor): trailing .HINT prints AFTER scope:
    // LDG.E.NA.EFL2.256.STRONG.GPU.HINT (was mis-ordered EFL2.HINT.256...).
    if base == "LDG" || base == "STG" {
        match m {
            "EL" | "NA" | "EN" | "EF" | "EU" => return 3,
            "ELL2" | "ENL2" | "EFL2" | "RML2" => return 4,
            "CONSTANT" => return 6,
            "STRONG" | "WEAK" | "ACQUIRE" | "RELEASE" => return 7,
            "GPU" | "SYS" | "SM" | "CTA" => return 8,
            "HINT" => return 9,
            _ => {}
        }
    }
    // BUG-097: generic-memory LD/ST share the global family order — nvdisasm
    // prints size BEFORE consistency/scope (LD.E.128.STRONG.SYS, ST.E.64.STRONG.GPU),
    // while the generic priority bucketed STRONG/GPU/SYS together with E (all 3) and
    // sizes after (6): a stable sort then kept the table's alphabetical mg order
    // (LD.E.GPU.STRONG, LD.E.STRONG.SYS.128). Without an explicit arm the 2,478-word
    // corpus class diverges from cuobjdump text on the sm103a canon table.
    if base == "LD" || base == "ST" {
        match m {
            "STRONG" | "WEAK" | "ACQUIRE" | "RELEASE" => return 7,
            "GPU" | "SYS" | "SM" | "CTA" => return 8,
            _ => {}
        }
    }
    // render-parity (b11, era rt98 anchor: LOP3.LUT.PAND): in the LOP3 family the
    // PAND boolean qualifier prints AFTER LUT, not before (generic LUT=9 would
    // still lose to PAND's default 5 — pin explicitly per family).
    if matches!(base, "LOP3" | "ULOP3" | "PLOP3" | "UPLOP3") && m == "PAND" {
        return 10;
    }
    mod_priority(m)
}

// ── guard ─────────────────────────────────────────────────────────────────────

fn format_guard_uni(fields: &[&DecodedField], uni: bool) -> String {
    let mut guard_val: Option<u64> = None;
    let mut extra_neg = false;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "guard"     => guard_val = Some(f.value),
            "guard_neg" => extra_neg = f.value != 0,
            _ => {}
        }
    }

    let v = guard_val.unwrap_or(7);
    let pred = v & 0x7;
    let neg = ((v >> 3) & 1) != 0 || extra_neg;

    if pred == 7 && !neg {
        return String::new(); // PT (unconditional, no negation)
    }
    let neg_s = if neg { "!" } else { "" };
    // pred==7 + neg → @!PT or @!UPT (uniform)
    let pt_name = if pred == 7 {
        if uni { "UPT".to_string() } else { "PT".to_string() }
    } else if uni {
        format!("UP{pred}")
    } else {
        format!("P{pred}")
    };
    format!("@{neg_s}{pt_name}")
}

// ── operand dispatch ──────────────────────────────────────────────────────────

fn format_operand(
    op_type: &str,
    fields: &[&DecodedField],
    mod_group: &str,
    ins_key: &str,
    tok: i32,
    raw: u128,
) -> String {
    match op_type {
        // R/UR type: when the field has imm extraction instead of reg/ureg
        // (e.g. IMAD.SHL Rb=imm, USHF shift=imm), format as immediate.
        "R" | "UR" if fields.iter().any(|f| {
            let e = norm_ext(&f.extraction);
            e.starts_with("imm") && !e.contains("shr")
        }) => format_imm(fields, mod_group, ins_key),
        // R with a byte_sel field (R2P/I2F "R0.B1" form): append .B<n> when set.
        "R"     => {
            let s = format_reg(fields, mod_group, tok, raw, ins_key);
            let bsel = fields.iter()
                .find(|f| matches!(norm_ext(&f.extraction).as_str(),
                    "byte_sel" | "bytesel") && f.value != 0)
                .map(|f| f.value);
            match bsel {
                Some(b) => format!("{s}.B{b}"),
                None => s,
            }
        },
        // R2P destination: always the predicate-register file token "PR"
        // (parsed as imm-0 in the corpus; printing the numeral round-trips
        // but loses the architectural form nvdisasm emits).
        "II" if ins_key.starts_with("R2P") && tok == 1 => "PR".to_string(),
        // DEPBAR first operand is a scoreboard id; nvdisasm prints SB<n>.
        "II" if ins_key.starts_with("DEPBAR") && tok == 1 => {
            let n = fields.iter()
                .find(|f| norm_ext(&f.extraction) == "imm")
                .map(|f| f.value)
                .unwrap_or(0);
            format!("SB{n}")
        },
        // For LOP3/LOP2/ULOP3 last P/UP operand: decode inv from bit 90 (not bit 87).
        // The trailing pred for these instructions uses bits[90:87]: bit90=inv, bits[89:87]=pred.
        // Only applies to LOP3/LOP2/ULOP3 (NOT PLOP3 which has different pred layout).
        "P" | "UP" if (ins_key.starts_with("LOP3") || ins_key.starts_with("LOP2")
                 || ins_key.starts_with("ULOP3"))
             && is_last_token(tok, ins_key)
            => format_lop3_pred_with_fields(fields, raw, op_type == "UP"),
        // LEA/ULEA trailing pred: when table maps both output+trailing pred to same
        // token_idx, the trailing P slot has no fields. Extract from bits[89:87]+bit[90].
        "P" if fields.is_empty() && is_last_token(tok, ins_key)
             && matches!(ins_key.split('_').next().unwrap_or(""), "LEA" | "ULEA")
            => {
            let pred = ((raw >> 87) & 0x7) as u64;
            let inv = ((raw >> 90) & 1) != 0;
            let inv_s = if inv { "!" } else { "" };
            if pred == 7 {
                format!("{inv_s}PT")
            } else {
                format!("{inv_s}P{pred}")
            }
        },
        "P"     => format_pred_with_raw(fields, false, 0),
        "UP"    => format_pred_with_raw(fields, true, 0),
        // UR slot: if no ureg field present, use raw fallback (for USHF II-typed UR slots)
        "UR"    => format_ureg_raw(fields, raw),
        "II" | "IM" | "LO"
                => format_imm_or_reg(fields, mod_group, ins_key, tok, raw),
        "FI"    => format_float_imm(fields),
        "L" | "SR"
                => format_lit_or_sysreg(fields, mod_group, raw),
        // BUG-179 (superset of parked-BUG-157): SYNCS- and ATOMS-family ARI
        // rows carry the uniform-register window baked as URZ in and_base
        // (0xff @ [64:72)) and have no UR field. These two families PRINT the
        // sink explicitly in vendor output (`SYNCS.ARRIVE.TRANS64.A1T0 RZ,
        // [R5+URZ+0x130], RZ`; `ATOMS.POPC.INC.32 RZ, [R0+URZ+0x3c]`), while
        // the other baked-sink families (LDGSTS_ARI_ARI{,_P}, STAS_ARI_R)
        // elide it (iter83 census: 2,183 LDGSTS + 5 STAS machine anchors,
        // zero vendor `+URZ`; nvdisasm arb179 D/E). Self-guarded on the raw
        // window so relaxed/broad fallback matches stay legacy-shaped.
        "ARI" if (ins_key.starts_with("SYNCS") || ins_key.starts_with("ATOMS"))
            && !fields.iter().any(|f| matches!(
                norm_ext(&f.extraction).as_str(), "sub_ur0" | "sub_ur1" | "ureg"))
            && ((raw >> 64) & 0xFF) == 0xFF
            => format_syncs_ari(fields, raw, ins_key),
        // BUG-038/017: LDS/STS with a scaled-index address ([R9.X8+..]/
        // [R9.X16+..]) — the addr_scale field carries the suffix. Scale=0
        // prints exactly like format_addr (historical shape preserved for
        // every existing entry).
        "ARI" if (ins_key.starts_with("LDS") || ins_key.starts_with("STS"))
            && fields.iter().any(|f| norm_ext(&f.extraction) == "addr_scale")
            => format_lds_scaled_addr(fields, rz_signed_elide(ins_key)),
        "ARI" | "AI"
                => format_addr(fields, raw, rz_signed_elide(ins_key)),
        // STS/LDS/LDSM use [R+UR+off] format, not desc[UR][R.64+off].
        // starts_with covers size-suffixed variants: STS.64, LDS.128, etc.
        "ARURI" if {
            let op = ins_key.split('_').next().unwrap_or("");
            op.starts_with("STS") || op.starts_with("LDS") || op.starts_with("LDSM")
        } => format_sts_lds_addr(fields, raw),
        // BUG-038: plain uniform-indexed LDG.E/STG.E forms (class bytes 0x81/0x86)
        // render as [Rn.U32+URm(+0xoff)], not desc[UR][R.64] (that's the dARI world).
        // BUG-097: same plain-u32-ur shape on generic-memory LD_R_ARURI/ST_ARURI_R
        // (nvdisasm: `LD.E R0, [RZ.U32+UR4]`); the desc-form print mislabels the UR
        // index as a descriptor selector and silently changes the instruction's
        // meaning for RE text.
        "ARURI" if ins_key.starts_with("LDG.E") || ins_key.starts_with("STG.E")
            || ins_key.starts_with("REDG.E") || ins_key.starts_with("ATOMG.E")
            || ins_key.starts_with("LD_") || ins_key.starts_with("ST_")
            => format_plain_u32_ur(fields, raw),
        // BUG-099/095: canon-era key names LDG_R_ARURI / STG_ARURI_R whose
        // repaired mod groups carry the same plain (reg/ureg/imm) field shape
        // as the sm120-native rows above must print the same bracket form
        // (pre-fix they printed desc[UR][R.64] = fabricated semantics for
        // raw-UR words, e.g. corpus `LDG.E R10, [R12.64+UR12+0x80]`). Junk
        // desc-form sibling mod groups keep sub_* fields and stay on
        // format_aruri below, so legit desc claims are untouched.
        "ARURI" if (ins_key.starts_with("LDG_R_ARURI")
                    || ins_key.starts_with("STG_ARURI_R"))
            && fields.iter().any(|f| norm_ext(&f.extraction) == "ureg")
            && fields.iter().any(|f| norm_ext(&f.extraction) == "reg")
            => format_plain_u32_ur(fields, raw),
        // BUG-154: SYNCS.PHASECHK.TRANS64[.TRYWAIT] ARURI rows are plain
        // uniform-datapath bracket addresses in vendor text --
        // [Rn+URm(+0xoff)] with the UR part printed explicitly (0xff = URZ,
        // vendor never prints bare [Rn] here). The generic desc[UR][R.64]
        // print below fabricates descriptor semantics (149/150-class).
        "ARURI" if ins_key.starts_with("SYNCS") => format_syncs_addr(fields),
        // BUG-143: shared-memory atomics print the UR-tied address as a plain
        // bracket [R+UR+off] (nvdisasm: `ATOMS.MAX.S32 RZ, [UR6+0x210c], R2`),
        // never desc[UR][R.64] (that's the global-memory descriptor world).
        // URZ sink is 0xFF in this family (130 vendor anchors).
        "ARURI" if ins_key.starts_with("ATOMS") => format_shared_atom_addr(fields, raw),
        "ARURI" => format_aruri(fields, raw),
        // No-immediate / UR-only address variants (ARUR/AUR/AURI/AURR/ARURR).
        // These are the same bracket address forms as ARURI (the address entry
        // may still carry an `imm` offset field). STS/LDS/LDSM print [R+UR+off];
        // everything else mirrors ARURI's desc[UR][R.64+off] form.
        "AURI" => format_auri_uronly(fields, raw),
        "ARUR" | "AUR" | "AURR" | "ARURR" if {
            let op = ins_key.split('_').next().unwrap_or("");
            op.starts_with("STS") || op.starts_with("LDS") || op.starts_with("LDSM")
        } => format_sts_lds_addr(fields, raw),
        "ARUR" | "AUR" | "AURR" | "ARURR" => format_aruri(fields, raw),
        "dARI"  => format_desc_addr(fields, raw),
        "cAI" | "cARI" => format_const_addr(fields, ins_key),
        "B"     => format_barrier(fields),
        // Unknown token type "?" — treat as UR register (raw fallback)
        "?"     => format_ureg_raw(fields, raw),
        _       => format!("?{op_type}"),
    }
}

// ── R — register ──────────────────────────────────────────────────────────────

/// Check if instruction is a half-float HFMA/HADD etc. where Rb=0 means RZ.
fn is_hfma_ins(ins_key: &str) -> bool {
    let op = ins_key.split('_').next().unwrap_or("");
    matches!(op, "HFMA2" | "HFMA" | "HADD2" | "HMUL2" | "HSET2" | "HSETP2"
        | "HFMA2_F32" | "HMNMX2")
}

/// Floating-point instructions where neg modifier on src registers is meaningful.
fn is_fp_ins(ins_key: &str) -> bool {
    let op = ins_key.split('_').next().unwrap_or("");
    matches!(op, "HFMA2" | "HFMA" | "HADD2" | "HMUL2" | "HSET2" | "HSETP2"
        | "HFMA2_F32" | "HMNMX2"
        | "FFMA" | "FADD" | "FMUL" | "FSET" | "FSETP" | "FMNMX"
        | "DFMA" | "DADD" | "DMUL" | "DSET" | "DSETP"
        | "MUFU")
}

/// Standard register bit positions by token index (most instructions).
/// For P-prefix InsKeys (first operand is a predicate), register tokens start at tok=2
/// but map to the SAME physical bit positions as tok=1,2,3,4 in non-prefix instructions.
fn reg_bits_for_tok(tok: i32, ins_key: &str) -> (u32, u32) {
    // Detect P-prefix: if first operand type is P or UP, registers shift
    let (_, op_types) = parse_ins_key(ins_key);
    let p_prefix = op_types.first().map(|t| t == "P" || t == "UP").unwrap_or(false);
    // Adjust tok: for P-prefix, tok=2 → position 1 (Rd), tok=3 → position 2 (Ra), etc.
    let reg_pos = if p_prefix { tok - 1 } else { tok };
    match reg_pos {
        1 => (16, 8), // Rd
        2 => (24, 8), // Ra
        3 => (32, 8), // Rb
        4 => (64, 8), // Rc
        _ => (16, 8),
    }
}

/// Neg bit positions for Ra/Rb/Rc (used when field is baked into and_base).
fn neg_bit_for_tok(tok: i32, _ins_key: &str) -> Option<u32> {
    match tok {
        2 => Some(72),
        3 => Some(73),
        4 => Some(74),
        _ => None,
    }
}

/// For LOP3/ULOP3 etc.: decode the trailing predicate operand from raw bits[90:87].
/// Encoding: bit90 = inv, bits[89:87] = predicate register number.
/// `uniform` = true for ULOP3 (UP/UPT), false for LOP3/LOP2 (P/PT).
fn format_lop3_pred_with_fields(fields: &[&DecodedField], raw: u128, uniform: bool) -> String {
    let (pt_name, pred_prefix) = if uniform { ("UPT", "UP") } else { ("PT", "P") };

    // If the table has explicit pred/inv fields for this token, use them.
    let mut pred: Option<u64> = None;
    let mut inv_from_field = false;
    for f in fields {
        let e = norm_ext(&f.extraction);
        if e == "pred" || e == "upred" {
            pred = Some(f.value);
        } else if e == "inv" {
            inv_from_field = f.value != 0;
        }
    }

    // Trailing pred is encoded at bits[90:87]: bit90 = inv, bits[89:87] = pred_num.
    let raw4 = ((raw >> 87) & 0xF) as u64;
    let (pn, inv) = if let Some(p) = pred {
        (p, inv_from_field || (raw4 >> 3) & 1 != 0)
    } else {
        (raw4 & 0x7, (raw4 >> 3) & 1 != 0)
    };

    if pn == 7 {
        if inv { format!("!{pt_name}") } else { pt_name.to_string() }
    } else {
        let inv_s = if inv { "!" } else { "" };
        format!("{inv_s}{pred_prefix}{pn}")
    }
}

fn format_reg(fields: &[&DecodedField], _mod_group: &str, tok: i32, raw: u128, ins_key: &str) -> String {
    let mut reg: Option<u64> = None;
    let mut neg = false;
    let mut abs = false;
    let mut inv = false;
    let mut reuse = false;
    let mut opmods: Vec<String> = Vec::new();

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "reg"       => reg = Some(f.value),
            "reg_shr1"  => reg = Some(f.value << 1),
            "reg_shr2"  => reg = Some(f.value << 2),
            "reg_shr3"  => reg = Some(f.value << 3),
            "neg"       => neg = f.value != 0,
            "neg_shl1"  => neg = (f.value >> 1) & 1 != 0,
            "neg_abs"   => { neg = f.value & 1 != 0; abs = (f.value >> 1) & 1 != 0; }
            "abs"       => abs = f.value != 0,
            "inv"       => inv = f.value != 0,
            "reuse"     => reuse = f.value != 0,
            _ => {}
        }
        // Operand-level modifier flags (.F32x2.HI_LO etc.) live as opmod:NAME
        // fields; when set non-zero they must be printed, else the encoder
        // drops the bits (FMUL2 Rn, Rn.F32x2.HI_LO, R0.reuse.F32).
        // NOTE: take the RAW extraction string (norm_ext lowercases
        // "opmod:F32x2" → "opmod:f32x2"); the parser is case-sensitive here.
        // Half-selectors (.H0_H0/.H0_H1/.H1_H1) come from the field-level
        // "hsel" extraction (encoder op_hsel maps the same strings back).
        if norm_ext(&f.extraction) == "hsel" && f.value != 0 {
            let h = match f.value { 3 => "H1_H1", 2 => "H0_H0", 1 => "H0_H1", _ => "" };
            if !h.is_empty() { opmods.push(h.to_string()); }
        }
        if let Some(name) = f.extraction.strip_prefix("opmod:") {
            if f.value != 0 {
                opmods.push(name.to_string());
            }
        }
    }

    // HSETP/HSETP2 with no hsel field: nvdisasm prints the default half-selector
    // ".H0_H0" on every R operand (corpus: 100% of HSETP2 records).
    if ins_key.starts_with("HSETP")
        && !fields.iter().any(|f| norm_ext(&f.extraction) == "hsel")
    {
        opmods.push("H0_H0".to_string());
    }

    // Fallback: when the register is baked into and_base (no variable field),
    // extract it from the raw instruction at the standard bit position.
    if reg.is_none() {
        let (shift, bits) = reg_bits_for_tok(tok, ins_key);
        let mask = (1u128 << bits) - 1;
        let v = ((raw >> shift) & mask) as u64;
        // For HFMA2/HFMA family with FI (float immediate) Rb operand:
        // The Rb register slot bits[39:32] is repurposed for the float immediate.
        // The Rb operand is always displayed as RZ in this format.
        let v = if tok == 3 && is_hfma_ins(ins_key) && (ins_key.contains("FI") || v == 0) {
            255 // RZ
        } else { v };
        reg = Some(v);
        if !neg && is_fp_ins(ins_key) {
            // Also for RZ: nvdisasm prints "-RZ" when the sign bit is set, and the
            // encoder must see it to reproduce the bit (HADD2.F32 Rn, -RZ, …).
            if let Some(neg_shift) = neg_bit_for_tok(tok, ins_key) {
                neg = ((raw >> neg_shift) & 1) != 0;
            }
        }
    }

    // Recover abs from raw instruction bits (FP instructions; RZ excluded)
    let rn = reg.unwrap_or(255);
    if !abs && rn != 255 && is_fp_ins(ins_key) {
        // The abs flag position depends on which register SLOT this operand occupies,
        // determined by the field's actual shift (NOT the token index):
        //   Ra @[31:24] -> abs at bit 73;  Rb @[39:32] -> abs at bit 62.
        // Using the shift is correct for predicate-prefixed keys (e.g. FSETP_P_P_R_FI_P,
        // where tok3 is Ra@24, not Rb@32) and avoids misreading bit 62 when [63:32] holds
        // an f32/II immediate (Rb slot is the immediate, so there is no reg field at 32).
        let reg_shift = fields.iter()
            .find(|f| { let e = norm_ext(&f.extraction); e == "reg" || e.starts_with("reg_shr") })
            .map(|f| f.shift);
        let abs_shift: Option<u32> = match reg_shift {
            Some(24) => Some(73),   // Ra abs at hi bit 9 (overall bit 73)
            Some(32) => Some(62),   // Rb abs at lo bit 62
            Some(64) => Some(74),   // Rc abs at bit 74 (FSETP/DSETP third source)
            _ => None,
        };
        if let Some(s) = abs_shift {
            abs = ((raw >> s) & 1) != 0;
        }
    }
    let base = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };

    let s = if inv              { format!("~{base}") }
            else if neg && abs  { format!("-|{base}|") }
            else if abs         { format!("|{base}|") }
            else if neg         { format!("-{base}") }
            else                { base };

    // Canonical operand-mod order in SASS text: data-type modifiers first
    // (F32x2/BF16x2/…), lane/selector mods last (HI_LO, LO_HI, H0, H1).
    let rank = |m: &str| -> u8 {
        if m.ends_with("X2") || m.ends_with("x2") { 0 }
        else if matches!(m, "F32" | "F16" | "BF16" | "TF32" | "F64"
                          | "E4M3" | "E5M2" | "E3M2" | "E2M3" | "E2M1"
                          | "S32" | "U32" | "S64" | "U64" | "S16" | "U16"
                          | "S8" | "U8" | "FP8" | "BF16x2") { 1 }
        else { 2 }
    };
    opmods.sort_by_key(|m| rank(m));
    let mods = if opmods.is_empty() { String::new() }
               else { format!(".{}", opmods.join(".")) };
    if reuse { format!("{s}.reuse{mods}") } else { format!("{s}{mods}") }
}

/// Format an "II" operand — can be immediate OR register (when IMAD.SHL uses
/// an immediate in an R-typed slot).
fn format_imm_or_reg(
    fields: &[&DecodedField],
    mod_group: &str,
    ins_key: &str,
    tok: i32,
    raw: u128,
) -> String {
    // If any imm-like extraction is present → format as immediate
    let has_imm = fields.iter().any(|f| {
        let e = norm_ext(&f.extraction);
        e.starts_with("imm") || e == "f32" || e == "f16" || e == "f16_d" || e == "f64hi"
            || e == "f32cast"
    });

    // If no fields: check if raw bits at UR position look like a UR/URZ register.
    // This handles USHF/SHF II-typed UR slots where URZ is baked into and_base.
    if fields.is_empty() && raw != 0 {
        // BUG-159: MUFU II rows (MUFU.RSQ) carry the immediate as a constant
        // baked into and_base — no field exists. The decoder only matches
        // words whose [32:64) equal that constant, so print the constant
        // itself as the f32 literal, sign folded in the value bits
        // (corpus: the sole value is 0xFFC00000 = "-QNAN", 1,235 vendor
        // anchors, archs sm_100/sm_103). Without this arm the generic
        // fallback printed "0x0", losing nvdisasm parity and breaking the
        // round-trip ("0x0" fail-closes at encode, BUG-071 guard).
        let op = ins_key.split('_').next().unwrap_or("");
        if op == "MUFU" {
            let bits = ((raw >> 32) & 0xFFFF_FFFF) as u32;
            let f = f32::from_bits(bits);
            return format_float(f.abs(), f.is_sign_negative())
                .trim_end()
                .to_string();
        }
        let raw_ur = ((raw >> 64) & 0xFF) as u64;
        // UR registers are 0-62 for real UR regs, 63 = URZ. Value > 63 = not a UR reg.
        // Only use UR fallback for USHF/SHF-family instructions.
        let is_ushf = {
            let op = ins_key.split('_').next().unwrap_or("");
            matches!(op, "USHF" | "SHF")
        };
        if is_ushf && raw_ur <= 63 {
            let base = if raw_ur == 63 { "URZ".to_string() } else { format!("UR{raw_ur}") };
            return base;
        }
    }

    if has_imm || fields.is_empty() {
        // LEA/ULEA scale_imm: when no imm field exists, extract bits[79:75] (5-bit scale).
        let op = ins_key.split('_').next().unwrap_or("");
        if fields.is_empty() && matches!(op, "LEA" | "ULEA") && mod_group.contains("HI") {
            let scale = ((raw >> 75) & 0x1F) as u64;
            return format!("0x{scale:x}");
        }
        // LOP3/ULOP3/PLOP3/UPLOP3 LUT: when no imm field for LUT token, extract bits[79:72].
        if fields.is_empty() && mod_group.contains("LUT") {
            let is_lop = matches!(op, "LOP3" | "ULOP3" | "PLOP3" | "UPLOP3" | "LOP2");
            if is_lop {
                let lut = ((raw >> 72) & 0xFF) as u64;
                return format!("0x{lut:x}");
            }
        }
        return format_imm(fields, mod_group, ins_key);
    }
    // Might also be an R slot formatted as II (IMAD.SHL case)
    format_reg(fields, mod_group, tok, raw, ins_key)
}

// ── P — predicate ─────────────────────────────────────────────────────────────

fn format_pred_with_raw(fields: &[&DecodedField], uniform: bool, raw: u128) -> String {
    format_pred_raw(fields, uniform, raw)
}

fn format_pred_raw(fields: &[&DecodedField], uniform: bool, raw: u128) -> String {
    let prefix  = if uniform { "UP" } else { "P" };
    let pt_name = if uniform { "UPT" } else { "PT" };

    // sm_121a pred_inv4: inverted 4-bit window carries the predicate AND its
    // negation; v==0 means "no guard pred" and nvdisasm omits the token, so
    // the caller drops it — signal via an empty string.
    for f in fields {
        if norm_ext(&f.extraction) == "pred_inv4" {
            let v = f.value;
            if v == 0 { return String::new(); }
            let (n, neg) = match v {
                8 => (7u64, true),
                v @ 1..=7 => (7 - v, false),
                v => (15 - v, true), // 9..=15
            };
            let inv_s = if neg { "!" } else { "" };
            if n == 7 { return format!("{inv_s}{pt_name}"); }
            return format!("{inv_s}{prefix}{n}");
        }
    }

    let mut pred: Option<u64> = None;
    let mut inv = false;
    let mut gate = false;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "pred" | "upred" => pred = Some(f.value),
            // BUG-032: MMA gate slot carries nvdisasm-INVERTED names
            // (sel = 7 - n, UPT = sel 0); straight everywhere else.
            "upred_gate"    => { pred = Some(f.value); gate = true; }
            "inv" | "neg"    => inv = f.value != 0,
            _ => {}
        }
    }

    if gate {
        let sel = pred.unwrap_or(0);
        let inv_s = if inv { "!" } else { "" };
        if sel == 0 {
            return if inv { format!("!{pt_name}") } else { pt_name.to_string() };
        }
        return format!("{inv_s}{prefix}{}", 7 - sel);
    }

    // Raw fallback: extract pred from bits [83:81] and inv from bit [87].
    // Only used when the caller explicitly passes a non-zero raw (targeted use).
    if pred.is_none() && raw != 0 {
        pred = Some(((raw >> 81) & 0x7) as u64);
        inv  = ((raw >> 87) & 1) != 0;
    }

    let pn = pred.unwrap_or(7);
    if pn == 7 {
        return if inv { format!("!{pt_name}") } else { pt_name.to_string() };
    }
    let inv_s = if inv { "!" } else { "" };
    format!("{inv_s}{prefix}{pn}")
}

// ── UR — uniform register ─────────────────────────────────────────────────────

fn format_ureg_raw(fields: &[&DecodedField], raw: u128) -> String {
    let mut ureg: Option<u64> = None;
    let mut neg = false;
    let mut abs_u = false;
    let mut inv = false;
    let mut reuse = false;
    let mut hsel: u64 = 0;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            // 8-bit ureg fields: 255 = URZ (sink), 63 = UR63 (a real architectural
            // register — e.g. "ULEA UR63, ...", "LDS.128 R8, [UR63]").
            // 6-bit ureg fields: 63 = URZ. Keep the source width to tell them apart.
            "ureg"     => { ureg = Some(f.value | (if f.bits >= 8 { 0x100 } else { 0 })); }
            "ureg_ff"  => { ureg = Some(f.value | 0x100); }
            "ureg_shr3" => ureg = Some(f.value << 3),
            "neg"      => neg = f.value != 0,
            "abs"      => abs_u = f.value != 0,
            "inv"      => inv = f.value != 0,
            "reuse"    => reuse = f.value != 0,
            "hsel"     => hsel = f.value,
            _ => {}
        }
    }

    // Raw fallback: when UR slot has no ureg field (baked into and_base or II-typed UR slot),
    // extract UR register from raw bits at Rc position [71:64].
    if ureg.is_none() && raw != 0 {
        let raw_ur = ((raw >> 64) & 0xFF) as u64;
        // UR registers: 0-62 are real UR regs, 63 = URZ
        if raw_ur <= 63 {
            ureg = Some(raw_ur);
        }
    }

    // ureg stores (value | 0x100) when it came from an 8-bit field: 255 = URZ
    // there; 63 is then the real UR63 register. 6-bit/none: 63 = URZ.
    let un = ureg.unwrap_or(63);
    let base = if un & 0x100 != 0 {
        let v = un & 0xFF;
        if v == 255 { "URZ".to_string() } else { format!("UR{v}") }
    } else if un == 63 {
        "URZ".to_string()
    } else {
        format!("UR{un}")
    };
    // nvdisasm prints |URn| / -|URn| on uniform ALU sources (e.g. "FFMA R8, R3, |UR16|, RZ").
    let s = if inv { format!("~{base}") }
            else if neg && abs_u { format!("-|{base}|") }
            else if abs_u { format!("|{base}|") }
            else if neg { format!("-{base}") }
            else { base };
    // HMUL2.BF16_V2 prints lane selection on the uniform source too ("UR8.H1_H1").
    let hs = match hsel { 3 => ".H1_H1", 2 => ".H0_H0", 1 => ".H0_H1", _ => "" };
    let s2 = format!("{s}{hs}");
    if reuse { format!("{s2}.reuse") } else { s2 }
}

// ── II / IM / LO — immediate ──────────────────────────────────────────────────

fn format_imm(fields: &[&DecodedField], _mod_group: &str, ins_key: &str) -> String {
    let mut imm: i64 = 0;
    let mut has_imm = false;
    let mut is_f32 = false;
    let mut f32_bits: u32 = 0;
    let mut is_f64 = false;
    let mut f64_hi: u32 = 0;
    let mut neg = false;

    let mut imm_bits: u32 = 0; // total bits for sign extension
    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "imm" => {
                // Sign-extend for "medium" immediates (12-62 bits).
                // Small fields (<12 bits: shift amounts, LUT values) stay unsigned.
                // Large 64-bit fields stay as raw unsigned.
                // OR-accumulate (not overwrite): split-window immediates pair a
                // plain "imm" slice with an "imm_shrN" sibling on one token
                // (PLOP3.LUT tok6 = [66:64] | [76:72]<<3 -> "0x80").
                let val = if f.bits >= 12 && f.bits < 64 {
                    sign_extend(f.value, f.bits)
                } else {
                    f.value as i64
                };
                imm |= val;
                imm_bits = imm_bits.max(f.bits);
                has_imm = true;
            }
            s if s.starts_with("imm_shr") => {
                let shift: u32 = s["imm_shr".len()..].parse().unwrap_or(0);
                imm |= (f.value as i64) << shift;
                imm_bits = imm_bits.max(f.bits + shift);
                has_imm = true;
            }
            "f32" | "f32cast" => { is_f32 = true; f32_bits = f.value as u32; }
            "f64hi"        => { is_f64 = true; f64_hi   = f.value as u32; }
            "f16" | "f16_d" => {
                is_f32 = true;
                f32_bits = half_to_f32_bits(f.value as u16);
            }
            "neg"          => neg = f.value != 0,
            _ => {}
        }
    }

    if is_f64 {
        let bits64 = (f64_hi as u64) << 32;
        return format_double(f64::from_bits(bits64), neg);
    }
    if is_f32 {
        return format_float(f32::from_bits(f32_bits), neg);
    }
    if has_imm {
        // Integer immediates: always hex.
        // Negative integer immediates:
        // MOV always shows values as unsigned (bit-copy semantics, 32-bit mask).
        // For other instructions: show as signed hex if abs <= 0xFFFFFF, else unsigned.
        if imm < 0 {
            let abs_val = (-imm) as u64;
            // Whole-mnemonic sign families measured on the sm_103a corpus (op16):
            // unsigned always: VIADD-family (prefix order matters:
            // VIADDMNMX before VIADD), LOP3/ULOP3, SEL/USEL, LEA/ULEA, MOV/UMOV,
            // SHF/USHF. Signed always (incl abs > 0xFFFFFF): *SETP, IADD3/UIADD3,
            // IMAD/UIMAD, VIMNMX.
            let is_unsigned_op = ins_key.starts_with("VIADDMNMX")
                || ins_key.starts_with("MOV") || ins_key.starts_with("UMOV")
                || ins_key.starts_with("SHF") || ins_key.starts_with("USHF")
                || ins_key.starts_with("VIADD") || ins_key.starts_with("SEL")
                || ins_key.starts_with("USEL") || ins_key.starts_with("LEA")
                || ins_key.starts_with("ULEA") || ins_key.starts_with("LOP3")
                || ins_key.starts_with("ULOP3");
            let is_setp = ins_key.starts_with("ISETP") || ins_key.starts_with("UISETP")
                || ins_key.starts_with("IADD3") || ins_key.starts_with("UIADD3")
                || ins_key.starts_with("IMAD") || ins_key.starts_with("UIMAD")
                || ins_key.starts_with("VIMNMX");
            if is_setp {
                return format!("-0x{abs_val:x}");
            } else if is_unsigned_op {
                // MOV/UMOV: show as unsigned hex, using full immediate field width
                let mask = if imm_bits >= 64 { u64::MAX } else { (1u64 << imm_bits) - 1 };
                return format!("0x{:x}", imm as u64 & mask);
            } else if abs_val <= 0xFFFFFF {
                return format!("-0x{abs_val:x}");
            } else {
                // Large negative → show as unsigned, masked to field size
                let bits = imm_bits.min(32);
                let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                return format!("0x{:x}", imm as u64 & mask);
            }
        }
        return format!("0x{imm:x}");
    }
    // Fallback when no immediate field found (value baked into and_base).
    // For half-float instruction families the zero immediate is printed as decimal.
    if is_hfma_ins(ins_key) { "0".to_string() } else { "0x0".to_string() }
}

// ── FI — float immediate (half-float in HFMA2 etc.) ──────────────────────────

fn format_float_imm(fields: &[&DecodedField]) -> String {
    let mut bits: Option<u32> = None;
    let mut f64_hi: Option<u32> = None;
    let mut neg = false;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "f16" | "f16_d" => bits = Some(half_to_f32_bits(f.value as u16)),
            // BF16 immediate: top-half of an f32 (HFMA2.BF16_V2 0x3f80 -> "1").
            "bf16"          => bits = Some((f.value as u32) << 16),
            "f32" | "f32cast" => bits = Some(f.value as u32),
            // FP64 immediate carried as its high dword (DFMA/DADD/etc.);
            // low 32 bits are zero in this encoding.
            "f64hi"         => f64_hi = Some(f.value as u32),
            "imm"           => {
                if f.bits >= 32 {
                    bits = Some(f.value as u32);
                } else {
                    bits = Some(half_to_f32_bits(f.value as u16));
                }
            }
            "neg"           => neg = f.value != 0,
            _ => {}
        }
    }

    if let Some(h) = f64_hi {
        return format_double(f64::from_bits((h as u64) << 32), neg);
    }
    match bits {
        Some(b) => format_float(f32::from_bits(b), neg),
        None    => "0".to_string(),
    }
}

// ── L / SR — literal or system register ──────────────────────────────────────

fn format_lit_or_sysreg(fields: &[&DecodedField], mod_group: &str, raw: u128) -> String {
    let has_sysreg = fields.iter().any(|f| norm_ext(&f.extraction).starts_with("sysreg"));
    if has_sysreg {
        return format_sysreg(fields, raw);
    }
    // If the only non-neg/abs/reuse field is "reg", format as register instead of
    // immediate — the "L" operand type sometimes maps to a register-encoded slot.
    let reg_field = fields.iter().find(|f| {
        let e = norm_ext(&f.extraction);
        e == "reg" || e == "ureg"
    });
    let has_imm_field = fields.iter().any(|f| {
        let e = norm_ext(&f.extraction);
        e == "imm" || e.starts_with("imm_shr") || e == "f32" || e == "f16" || e == "f64hi"
            || e == "f32cast"
    });
    if !has_imm_field {
        if let Some(rf) = reg_field {
            let neg = fields.iter().any(|f| norm_ext(&f.extraction) == "neg" && f.value != 0);
            let prefix = if neg { "-" } else { "" };
            let e = norm_ext(&rf.extraction);
            if e == "ureg" {
                return if rf.value == 63 { format!("{prefix}URZ") }
                       else { format!("{prefix}UR{}", rf.value) };
            }
            return if rf.value == 255 { format!("{prefix}RZ") }
                   else { format!("{prefix}R{}", rf.value) };
        }
    }
    format_imm(fields, mod_group, "")
}

// ── ARI — address expression [R+off] or [R.64+UR+off] ───────────────────────

/// BUG-038 plain uniform-indexed global address: LDG.E/STG.E of class bytes
/// 0x81/0x86 render natively as "[Rn.U32+URm(+0xoff)]" (i108 goldens).
fn format_plain_u32_ur(fields: &[&DecodedField], raw: u128) -> String {
    let mut base: Option<u64> = None;
    let mut ur: Option<u64> = None;
    let mut off: u64 = 0;
    for f in fields {
        match norm_ext(&f.extraction).as_str() {
            "reg" | "sub_r0" | "sub_r1" => { if base.is_none() { base = Some(f.value); } }
            "ureg" => ur = Some(f.value),
            "imm" => off = f.value,
            _ => {}
        }
    }
    let b = match base {
        Some(255) => "RZ".to_string(),
        Some(v) => format!("R{v}"),
        None => "R0".to_string(),
    };
    let u = format!("UR{}", ur.unwrap_or(0));
    let o = if off != 0 { format!("+0x{off:x}") } else { String::new() };
    // BUG-099: the plain UR-indexed global form carries a real width mode in
    // bits [92:90]: vendor prints `[Rn.U32+URm]` for modes 2/6 (era anchors,
    // 82/82) and `[Rn.64+URm]` for mode 3 (corpus anchors, 15/15). Modes with
    // bit90=1 && bit91=1 print ".64"; everything else observed prints ".U32".
    let width = if (raw >> 90) & 0b11 == 0b11 { "64" } else { "U32" };
    format!("[{b}.{width}+{u}{o}]")
}

/// BUG-164 (port spark ERR-249 ze sm_121a; law vendor nvdisasm 13.0.88 +
/// potwierdzone flotowo na 13.3.73, arbitraz work/i77/arb): for a plain
/// ARI/AI address with base == RZ, no UR component and imm != 0 nvdisasm
/// prints ONLY the raw immediate window (unsigned hex, width-masked);
/// base, .Xn scale suffix and the "+-" sign notation disappear together.
/// Exceptions: imm == 0 prints "[RZ]"; a UR component or base != RZ keeps
/// the full form; LDSM/STSM print the elided immediate SIGNED ("[-0x10]").
/// Returns None when no elision applies.
fn rz_signed_elide(ins_key: &str) -> bool {
    let op = ins_key.split('_').next().unwrap_or("");
    op.starts_with("LDSM") || op.starts_with("STSM")
}

fn elide_rz_base(rn: u64, ur_reg: Option<u64>, offset: i64, has_offset: bool,
                 imm_width: u32, signed: bool) -> Option<String> {
    if rn != 255 || ur_reg.is_some() || !has_offset || offset == 0 {
        return None;
    }
    if signed {
        return Some(if offset < 0 {
            format!("[-0x{:x}]", (-offset) as u64)
        } else {
            format!("[0x{:x}]", offset as u64)
        });
    }
    let mask = if imm_width == 0 || imm_width >= 64 { !0u64 } else { (1u64 << imm_width) - 1 };
    Some(format!("[0x{:x}]", (offset as u64) & mask))
}

/// BUG-143: shared-atom UR address "[R+UR+off]" (ATOMS family). Same shape as
/// format_sts_lds_addr, but the URZ sink carried as 0xFF prints "URZ"
/// (vendor spelling), while narrow-window 63 stays URZ and wide 63 = UR63.
fn format_shared_atom_addr(fields: &[&DecodedField], _raw: u128) -> String {
    let mut base_reg: Option<u64> = None;
    let mut ur_reg:   Option<u64> = None;
    let mut offset:   i64 = 0;
    let mut has_off   = false;
    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "sub_r1" | "sub_r0"             => base_reg = Some(f.value),
            "reg"                           => { if base_reg.is_none() { base_reg = Some(f.value); } }
            "sub_ur0" | "sub_ur1" | "ureg"  => ur_reg = Some(f.value),
            s if s.starts_with("sub_imm") => {
                offset |= sub_imm_off(s, f.value, f.bits);
                has_off = true;
            }
            "imm" if f.bits >= 8 => { offset = sign_extend(f.value, f.bits); has_off = offset != 0; }
            _ => {}
        }
    }
    let rn = base_reg.unwrap_or(255);
    let reg_s = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };
    let mut inner = reg_s;
    if let Some(un) = ur_reg {
        let ur_s = if un == 0xFF || un == 63 { "URZ".to_string() } else { format!("UR{un}") };
        inner.push('+');
        inner.push_str(&ur_s);
    }
    if has_off && offset != 0 {
        if offset < 0 { inner.push_str(&format!("+-0x{:x}", (-offset) as u64)); }
        else { inner.push_str(&format!("+0x{offset:x}")); }
    }
    format!("[{inner}]")
}

/// BUG-038 LDS scaled shared address: "[R9.X16+0xc000]". The scale suffix comes
/// from the addr_scale field (2=X8, 3=X16; 1=X4 structural inverse). Scale=0
/// intentionally reproduces format_addr's plain output byte-for-byte.
fn format_lds_scaled_addr(fields: &[&DecodedField], signed_elide: bool) -> String {
    let mut base: Option<u64> = None;
    let mut off: i64 = 0;
    let mut has_off = false;
    let mut scale = 0u64;
    let mut imm_width: u32 = 0;
    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "reg" | "sub_r0" | "sub_r1" => { if base.is_none() { base = Some(f.value); } }
            "addr_scale" => scale = f.value,
            s if s.starts_with("sub_imm") => {
                off |= sub_imm_off(s, f.value, f.bits);
                has_off = true;
                imm_width += f.bits;
            }
            "imm" => { off = f.value as i64; has_off = true; imm_width += f.bits; }
            _ => {}
        }
    }
    let rn = base.unwrap_or(0);
    // BUG-164 (port spark ERR-249): base RZ + imm != 0 elides to the bare
    // window (scale suffix removed with the base).
    if let Some(el) = elide_rz_base(rn, None, off, has_off, imm_width, signed_elide) {
        return el;
    }
    let reg_s = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };
    let sfx = match scale { 1 => ".X4", 2 => ".X8", 3 => ".X16", _ => "" };
    let mut inner = format!("{reg_s}{sfx}");
    if has_off && off != 0 {
        if off < 0 {
            inner.push_str(&format!("+-0x{:x}", (-off) as u64));
        } else {
            inner.push_str(&format!("+0x{off:x}"));
        }
    }
    format!("[{inner}]")
}

fn format_addr(fields: &[&DecodedField], raw: u128, signed_elide: bool) -> String {
    let mut base_reg: Option<u64> = None;
    let mut base_wide = false;
    let mut ur_reg: Option<u64> = None;
    let mut offset: i64 = 0;
    let mut has_offset = false;
    let mut imm_width: u32 = 0;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "sub_r0" | "sub_r1" => base_reg = Some(f.value),
            "sub_r0_shr1" | "sub_r1_shr1" => { base_reg = Some(f.value << 1); base_wide = true; }
            "reg" => { if base_reg.is_none() { base_reg = Some(f.value); } }
            "sub_ur0_shr1" | "sub_ur1_shr1"   => ur_reg = Some(f.value << 1),
            "sub_ur0" | "sub_ur1" | "ureg"    => ur_reg = Some(f.value),
            s if s.starts_with("sub_imm") => {
                offset |= sub_imm_off(s, f.value, f.bits);
                has_offset = true;
                imm_width += f.bits;
            }
            "imm" => { offset = f.value as i64; has_offset = true; imm_width += f.bits; }
            _ => {}
        }
    }

    // Raw fallback: when no fields provided (e.g. InsKey with no learned field positions),
    // use standard register/offset positions. For LDL/STL and similar:
    // base register at bits[31:24] (Ra slot), offset at bits[47:40].
    if base_reg.is_none() {
        base_reg = Some((raw >> 24) as u64 & 0xFF);
        let raw_off = ((raw >> 40) & 0xFF) as i64;
        if raw_off != 0 { offset = raw_off; has_offset = true; imm_width = 8; }
    }

    // .64 only when explicitly bit-shifted sub-register extraction (64-bit addressing)
    let rn = base_reg.unwrap_or(0);
    // BUG-164 (port spark ERR-249): plain-ARI/AI with base RZ, no UR and
    // imm != 0 elides the base (and the .Xn scale suffix with it).
    if let Some(el) = elide_rz_base(rn, ur_reg, offset, has_offset, imm_width, signed_elide) {
        return el;
    }
    let reg_s = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };
    let wide_s = if base_wide { ".64" } else { "" };

    let mut inner = format!("{reg_s}{wide_s}");

    if let Some(un) = ur_reg {
        // BUG-143: shared-atom UR slot (ATOMS POPC.32 family) carries the URZ
        // sink as 0xFF (130 vendor anchors), same convention as format's
        // `un == 255 => URZ` at the LDS composer. 63 stays the legacy URZ alias.
        let ur_s = if un == 63 || un == 0xFF { "URZ".to_string() } else { format!("UR{un}") };
        inner.push('+');
        inner.push_str(&ur_s);
    }

    if has_offset && offset != 0 {
        if offset < 0 {
            inner.push_str(&format!("+-0x{:x}", (-offset) as u64));
        } else {
            inner.push_str(&format!("+0x{offset:x}"));
        }
    }

    format!("[{inner}]")
}

/// BUG-179/157: format_addr plus a spliced `+URZ` for ARI rows whose uniform
/// window is a baked sink constant (see the dispatch arm above).
fn format_syncs_ari(fields: &[&DecodedField], raw: u128, ins_key: &str) -> String {
    let s = format_addr(fields, raw, rz_signed_elide(ins_key));
    let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) else {
        return s;
    };
    let cut = inner.find("+0x").or_else(|| inner.find("+-0x"));
    match cut {
        Some(i) => format!("[{}+URZ{}]", &inner[..i], &inner[i..]),
        None => format!("[{inner}+URZ]"),
    }
}

// ── UTC* — tcgen05 MMA descriptor operands (gdesc/tmem/idesc) ───────────────

fn format_utc_desc(tok: i32, fields: &[&DecodedField], tok4_fields: &[&DecodedField]) -> String {
    let mut ur: Option<u64> = None;
    let mut off: u64 = 0;
    let mut dsel: Option<u64> = None;
    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "tdesc_ur" | "gdesc_ur" | "tmem_ur" | "idesc_ur" => ur = Some(f.value),
            // plain desc_ur (UTMALDG/UTMASTG single-bracket desc[URn]) carried
            // the value but never assigned it — desc[URZ] was printed always.
            "desc_ur" => ur = Some(f.value),
            "dsel2" => dsel = Some(f.value),
            s if s.ends_with("_off") => off |= f.value,
            _ => {}
        }
    }
    // Kind selection: tok1 may be mixed-kind (dsel2: gdesc=1, tmem=2);
    // idesc slot defaults to UR_tmem2+1 when hardware holds no own field.
    // Kind: prefer the extraction family actually present on this token
    // (works for LDTM/STTM tmem[] tokens as well); UTC tok1 is mixed-kind
    // and selects via dsel2 (gdesc=1, tmem=2).
    let kind = if fields.iter().any(|f| norm_ext(&f.extraction).starts_with("gdesc")) {
        "gdesc"
    } else if fields.iter().any(|f| norm_ext(&f.extraction).starts_with("tmem")) {
        "tmem"
    } else if fields.iter().any(|f| norm_ext(&f.extraction).starts_with("idesc")) {
        "idesc"
    } else if fields.iter().any(|f| norm_ext(&f.extraction).starts_with("desc_")) {
        // UTMALDG/UTMASTG single-bracket desc[URx(+0xoff)] operand.
        "desc"
    } else {
        match tok {
            1 => if dsel == Some(2) { "tmem" } else { "gdesc" },
            2 => "gdesc",
            3 | 4 => "tmem",
            _ => "idesc",
        }
    };
    if ur.is_none() && tok == 5 {
        for f in tok4_fields {
            if norm_ext(&f.extraction) == "tmem_ur" {
                ur = Some(f.value.wrapping_add(1));
                break;
            }
        }
    }
    // nvdisasm prints UR63 literally for desc operands (idesc[UR63]); only
    // 255 aliases to URZ in this family.
    let ur_s = match ur {
        Some(255) | None => "URZ".to_string(),
        Some(n) => format!("UR{n}"),
    };
    if off != 0 {
        format!("{kind}[{ur_s}+0x{off:x}]")
    } else {
        format!("{kind}[{ur_s}]")
    }
}

// ── AURI — UR-only indirect address ──────────────────────────────────────────
// Records store this form literally as "[URN]" / "[URN+0xN]" (UTMALDG/UTMASTG/
// SYNCS/UTMACCTL); the parser maps that bracket text back to an AURI operand.
// Printing the ARURI desc[UR][R.64] form here would fabricate a base register
// (raw-fallback reads the UR slot as R!) and produces text that re-parses as
// Desc — unencodable under an _AURI key.
fn format_auri_uronly(fields: &[&DecodedField], raw: u128) -> String {
    let mut ur: Option<u64> = None;
    let mut ur_wide = false; // the field exists and is 8-bit: then 63 means UR63, not URZ
    let mut offset: i64 = 0;
    let mut has_off_from_field = false;
    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "sub_ur0" | "sub_ur1" | "ureg" | "tdesc_ur" | "gdesc_ur" =>
                { ur = Some(f.value); ur_wide = f.bits >= 8; }
            "sub_ur0_shr1" | "sub_ur1_shr1" => ur = Some(f.value << 1),
            s if s.starts_with("sub_imm") => {
                offset |= sub_imm_off(s, f.value, f.bits);
                has_off_from_field = true;
            }
            "imm" if f.bits >= 8 => {
                offset = sign_extend(f.value, f.bits);
                has_off_from_field = true;
            }
            _ => {}
        }
    }
    // UR index fallback: uniform datapath register field at bits[31:24].
    let un = ur.unwrap_or(((raw >> 24) as u64) & 0xFF);
    // 255 = URZ always. 63 = URZ unless it came from a wide (8-bit) field,
    // where it is the real UR63 register (corpus: "LDS.128 R8, [UR63]").
    let ur_s = if un == 255 || (un == 63 && !ur_wide) { "URZ".to_string() }
               else { format!("UR{un}") };
    if !has_off_from_field {
        offset = 0;
    }
    if offset != 0 {
        if offset < 0 {
            return format!("[{ur_s}+-0x{:x}]", (-offset) as u64);
        }
        return format!("[{ur_s}+0x{offset:x}]");
    }
    format!("[{ur_s}]")
}

// ── SYNCS ARURI — plain uniform-datapath address (BUG-154) ──────────────────
// Format: [Rn+URm+0xoff]; UR window is 8-bit @64 with 0xff = URZ (printed
// explicitly, nvdisasm-parity), base Rn always present in these rows.

fn format_syncs_addr(fields: &[&DecodedField]) -> String {
    let mut base_reg: Option<u64> = None;
    let mut ur_reg:   Option<u64> = None;
    let mut offset:   i64 = 0;
    let mut has_off   = false;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "sub_r1" | "sub_r0"                => base_reg = Some(f.value),
            "reg"                              => { if base_reg.is_none() { base_reg = Some(f.value); } }
            "sub_ur0" | "sub_ur1" | "ureg"     => ur_reg = Some(f.value),
            s if s.starts_with("sub_imm") => {
                offset |= sub_imm_off(s, f.value, f.bits);
                has_off = true;
            }
            "imm" if f.bits >= 8 => {
                offset = sign_extend(f.value, f.bits);
                has_off = offset != 0;
            }
            _ => {}
        }
    }

    let rn = base_reg.unwrap_or(0);
    let reg_s = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };
    let ur_s = match ur_reg {
        Some(255) | None => "URZ".to_string(),
        Some(un) => format!("UR{un}"),
    };
    let off_s = if has_off && offset != 0 {
        if offset < 0 { format!("-0x{:x}", (-offset) as u64) } else { format!("+0x{offset:x}") }
    } else {
        String::new()
    };
    if rn == 255 {
        // defensive: RZ base is a silent sink; vendor prints the UR form alone
        format!("[{ur_s}{off_s}]")
    } else {
        format!("[{reg_s}+{ur_s}{off_s}]")
    }
}

// ── ARURI — descriptor address via UR ────────────────────────────────────────
// Format: desc[UR][R.64+off]

fn format_aruri(fields: &[&DecodedField], raw: u128) -> String {
    let mut base_reg: Option<u64> = None;
    let mut ur_reg:   Option<u64> = None;
    let mut ur_wide = false;   // ureg/sub_ur*/desc_ur field of >= 8 bits: 63 = UR63 (real register)
    let mut offset:   i64 = 0;
    let mut has_off   = false;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            // SubR(1) = main base register in desc[UR][R.64+off]
            "sub_r1" | "sub_r0"                => base_reg = Some(f.value),
            "sub_r1_shr1" | "sub_r0_shr1"      => base_reg = Some(f.value << 1),
            "reg"                               => { if base_reg.is_none() { base_reg = Some(f.value); } }
            "sub_ur0" | "sub_ur1" | "ureg" | "desc_ur"  => { ur_reg = Some(f.value); ur_wide = f.bits >= 8; }
            "sub_ur0_shr1" | "sub_ur1_shr1"    => ur_reg = Some(f.value << 1),
            s if s.starts_with("sub_imm") => {
                offset |= sub_imm_off(s, f.value, f.bits);
                has_off = true;
            }
            // Plain imm field in ARURI = address offset (large signed value)
            "imm" if f.bits >= 8 => {
                offset = sign_extend(f.value, f.bits);
                has_off = offset != 0;
            }
            _ => {}
        }
    }

    // Raw fallback: when no base register field is provided, use bits[31:24] (standard Ra slot).
    // Happens when the ISA table entry is missing the sub_r field (e.g. LDG_R_dARI::128,E).
    if base_reg.is_none() {
        base_reg = Some((raw >> 24) as u64 & 0xFF);
    }

    let rn = base_reg.unwrap_or(0);
    let reg_s = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };
    // BUG-160: vendor law for the 8-bit descriptor-UR window (nvdisasm 13.3.73
    // probes on sm_120a/sm_103a): 255 = URZ (the zero uniform register), 63 =
    // UR63 (a real register, printed literally; vendor corpus even carries
    // desc[UR64..76] in this window). Narrow (<8-bit) UR windows cap at
    // all-ones, which IS the URZ encoding there. Missing field: URZ default
    // (unchanged historical render for field-less rows).
    let un = ur_reg.unwrap_or(63);
    let ur_s = if un == 255 || (un == 63 && !ur_wide) { "URZ".to_string() }
               else { format!("UR{un}") };

    let off_s = if has_off && offset != 0 {
        if offset < 0 { format!("+-0x{:x}", (-offset) as u64) } else { format!("+0x{offset:x}") }
    } else {
        String::new()
    };

    format!("desc[{ur_s}][{reg_s}.64{off_s}]")
}

// ── dARI — descriptor address ────────────────────────────────────────────────

fn format_desc_addr(fields: &[&DecodedField], raw: u128) -> String {
    format_aruri(fields, raw)
}

// ── STS/LDS/LDSM address — [R+UR+off] ────────────────────────────────────────
// STS and LDS use [R+UR+off] format instead of desc[UR][R.64+off].
// The base register and UR are encoded the same way but formatted differently.

fn format_sts_lds_addr(fields: &[&DecodedField], raw: u128) -> String {
    let mut base_reg: Option<u64> = None;
    let mut ur_reg:   Option<u64> = None;
    let mut ur_wide = false;   // pole ureg/sub_ur* o >= 8 bitach: 63 = UR63 (realny)
    let mut offset:   i64 = 0;
    let mut has_off   = false;

    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "sub_r1" | "sub_r0"             => base_reg = Some(f.value),
            "sub_r1_shr1" | "sub_r0_shr1"  => base_reg = Some(f.value << 1),
            "reg"                           => { if base_reg.is_none() { base_reg = Some(f.value); } }
            "sub_ur0" | "sub_ur1" | "ureg"  => { ur_reg = Some(f.value); ur_wide = f.bits >= 8; }
            "sub_ur0_shr1" | "sub_ur1_shr1" => ur_reg = Some(f.value << 1),
            s if s.starts_with("sub_imm") => {
                offset |= sub_imm_off(s, f.value, f.bits);
                has_off = true;
            }
            "imm" if f.bits >= 8 => {
                offset = sign_extend(f.value, f.bits);
                has_off = offset != 0;
            }
            _ => {}
        }
    }

    // Raw fallback for UR when no ur field provided (sub_ur fields at hi64 positions)
    if ur_reg.is_none() {
        let raw_ur = ((raw >> 64) & 0xFF) as u64;
        if raw_ur != 255 { ur_reg = Some(if raw_ur == 63 { 63 } else { raw_ur }); }
    }
    // Raw fallback for offset: STS/LDS encode shared memory offset at bits[55:40] (16-bit).
    // This handles cases where the offset field is missing from the ISA table.
    if !has_off {
        let raw_off = ((raw >> 40) & 0xFFFF) as i64;
        if raw_off != 0 { offset = raw_off; has_off = true; }
    }

    let rn = base_reg.unwrap_or(0);
    let reg_s = if rn == 255 { "RZ".to_string() } else { format!("R{rn}") };
    let un = ur_reg.unwrap_or(63);
    let ur_s = if un == 63 && !ur_wide { "URZ".to_string() } else { format!("UR{un}") };

    // No UR component at all -> print base only ("[RZ]", "[R10]", "[R66+0x80]").
    if ur_reg.is_none() {
        if has_off && offset != 0 {
            let off_s = if offset < 0 {
                format!("-0x{:x}", (-offset) as u64)
            } else {
                format!("+0x{offset:x}")
            };
            return format!("[{reg_s}{off_s}]");
        }
        return format!("[{reg_s}]");
    }

    if has_off && offset != 0 {
        let off_s = if offset < 0 {
            format!("-0x{:x}", (-offset) as u64)
        } else {
            format!("+0x{offset:x}")
        };
        if rn == 255 {
            // nvdisasm never prints "[RZ+UR…]" — RZ is a silent sink in addresses:
            // "[UR63]", "[UR63+0x10]".
            format!("[{ur_s}{off_s}]")
        } else {
            format!("[{reg_s}+{ur_s}{off_s}]")
        }
    } else {
        if rn == 255 {
            return format!("[{ur_s}]");
        }
        format!("[{reg_s}+{ur_s}]")
    }
}

// ── cAI — constant memory ─────────────────────────────────────────────────────

fn format_const_addr(fields: &[&DecodedField], ins_key: &str) -> String {
    // Encoder-side inverse: bank = SubImm(0), offset = highest-index SubImm(k)
    // (c[B][off] → k=1, c[B][R+off] → k=2), cm16_off/cm17_off carry the
    // combined bank<<shift|offset when no split fields exist. Multiple fields
    // per token are common (e.g. LDC.64: cm16_off@38 + sub_imm0@50), so the
    // naive "last write wins" loses the offset whenever sub_imm0 (=bank) is
    // listed last. Compose instead of overwrite.
    let mut cm_val: Option<u64> = None;
    let mut bank_shift: u32 = 16;
    let mut is_cm17 = false;
    let mut bank_field: Option<(u32, u64)> = None;   // (bits, value) of SubImm(0)
    let mut off_field: Option<(u32, u64, u8)> = None; // (bits, value, idx) best so far
    let mut base_reg: Option<u64> = None;
    let mut ur_reg: Option<(u64, u32)> = None;       // (value, bits) of SubUR(*) token part

    for f in fields {
        let e = norm_ext(&f.extraction);
        if e == "cm17off" {
            cm_val = Some(f.value);
            bank_shift = 17;
            is_cm17 = true;
        } else if e == "cm16off" {
            cm_val = Some(f.value);
            bank_shift = 16;
        } else if e.starts_with("sub_imm") {
            // sub_imm{i}[...] — extract the leading sub-index digit.
            let idx = e.trim_start_matches("sub_imm").chars().next()
                .and_then(|ch| ch.to_digit(10)).map(|d| d as u8);
            match idx {
                Some(0) => bank_field = Some((f.bits, f.value)),
                Some(k) => {
                    let better = off_field.map(|(_, _, ok)| k >= ok).unwrap_or(true);
                    if better { off_field = Some((f.bits, f.value, k)); }
                }
                None => {
                    // generic sub_imm{...} without parseable index: treat as offset
                    off_field = Some((f.bits, f.value, 99));
                }
            }
        }
        // SubR(1) = base register for indirect constant access (c[bank][R+off])
        if e.starts_with("sub_r") {
            let v = if e.contains("shr1") { f.value << 1 } else { f.value };
            base_reg = Some(v);
        }
        // SubUR(0/1) = uniform index register for c[bank][UR+off] (BUG-151;
        // "sub_ur" prefix disjunct from "sub_r": 5th char is 'u')
        if e.starts_with("sub_ur") {
            let v = if e.contains("shr1") { f.value << 1 } else { f.value };
            ur_reg = Some((v, f.bits));
        }
    }

    let off_mask = (1u64 << bank_shift) - 1;
    let (bank, offset) = if let Some((_bits, v, _k)) = off_field {
        // Offset window may include bank copies in its high bits (widened fits);
        // bank itself comes from the dedicated SubImm(0) or the combined field.
        let bank = bank_field.map(|(_, b)| b)
            .or_else(|| cm_val.map(|cv| (cv >> bank_shift) & 0x1f))
            .unwrap_or(0);
        // Canonical form: window high bits can hold a widened copy of the
        // bank (the encoder rebuilds them via SubImm(0) anyway).
        (bank, v & off_mask)
    } else if let Some(cv) = cm_val {
        ((cv >> bank_shift) & 0x1f, cv & off_mask)
    } else if let Some((_, b)) = bank_field {
        (b, 0)
    } else {
        (0, 0)
    };

    // If base register is present and non-RZ (255), include it: c[bank][R+off]
    if let Some(reg) = base_reg {
        if reg != 255 {
            let reg_s = format!("R{reg}");
            if offset == 0 {
                return format!("c[0x{bank:x}][{reg_s}]");
            } else {
                return format!("c[0x{bank:x}][{reg_s}+0x{offset:x}]");
            }
        }
    }
    // BUG-151: uniform-register indexed constant access, c[bank][UR+off].
    // The only sm103a const-addr row carrying a sub_ur* token field is
    // LDCU_UR_cAI[""] (census 2026-08-25, work/i71: 101 live corpus
    // witnesses, UR numeral == bits[24:32), URZ sentinel 255 on all plain
    // forms). Sentinel/width rule mirrors format_auri_uronly: an 8-bit-wide
    // field reads 63 as real UR63, narrower fields keep 63 == URZ.
    if let Some((un, ubits)) = ur_reg {
        let is_zero_reg = un == 255 || (un == 63 && ubits < 8);
        if !is_zero_reg {
            return if offset == 0 {
                format!("c[0x{bank:x}][UR{un}]")
            } else {
                format!("c[0x{bank:x}][UR{un}+0x{offset:x}]")
            };
        }
    }
    // For cm17_off with offset=0, print URZ (uniform zero register, the default offset)
    if is_cm17 && offset == 0 {
        return format!("c[0x{bank:x}][URZ]");
    }
    // BUG-174 (F2): LDC-family zero offset prints the RZ sentinel glyph.
    // nvdisasm never prints `[0x0]` on the LDC const slot (0/32.2M vendor
    // anchors); every off==0 LDC const address comes out as `[RZ]`
    // (12/12 hexdb anchors + W1 U8 probe; the idx byte 0xff is structurally
    // the RZ sink on these rows). Scoped to the R-dest LDC family: LDCU
    // keeps its cm17 `[URZ]` convention above, and non-LDC const users
    // (zero anchors for off==0 anywhere) keep the legacy `[0x0]` print.
    if offset == 0 && ins_key.starts_with("LDC") && !ins_key.starts_with("LDCU") {
        return format!("c[0x{bank:x}][RZ]");
    }
    format!("c[0x{bank:x}][0x{offset:x}]")
}

// ── SR / L — system register ─────────────────────────────────────────────────

/// Sysreg names keyed by the RAW encoded value from the instruction field
/// (as returned by the decoder).  Names match the nvdisasm-13.3 sm_120
/// render verbatim (BUG-r043 sweep of all 256 codes through SR_0x<hex>;
/// SR_NTID additionally silicon-verified on sm120, i120).  The earlier
/// literature block was wrong for this arch: 0x29/0x2a are
/// SR_CirQueueIncrMinusOne / SR_NLATC (not NTID.Y/.Z), 0x2c..0x2e are
/// SR_SM_SPA_VERSION / SR_MULTIPASSSHADERINFO / SR_LWINHI (not NCTAID.*),
/// and 0x40/0x42/0x44 are *ERRORSTATUS / VIRTUALENGINEID (not
/// WARPID/SMID/GRIDID).
static SYSREG_NAMES: &[(u32, &str)] = &[
    (0x00, "SR_LANEID"),
    (0x0f, "SR_ORDERING_TICKET"),
    (0x20, "SR_TID"),
    (0x21, "SR_TID.X"),
    (0x22, "SR_TID.Y"),
    (0x23, "SR_TID.Z"),
    (0x25, "SR_CTAID.X"),
    (0x26, "SR_CTAID.Y"),
    (0x27, "SR_CTAID.Z"),
    (0x28, "SR_NTID"),
    (0x29, "SR_CirQueueIncrMinusOne"),
    (0x2a, "SR_NLATC"),
    (0x2c, "SR_SM_SPA_VERSION"),
    (0x2d, "SR_MULTIPASSSHADERINFO"),
    (0x2e, "SR_LWINHI"),
    (0x2f, "SR_SWINHI"),
    (0x30, "SR_SWINLO"),
    (0x31, "SR_SWINSZ"),
    (0x32, "SR_SMEMSZ"),
    (0x33, "SR_SMEMBANKS"),
    (0x34, "SR_LWINLO"),
    (0x35, "SR_LWINSZ"),
    (0x36, "SR_LMEMLOSZ"),
    (0x37, "SR_LMEMHIOFF"),
    (0x38, "SR_EQMASK"),
    (0x39, "SR_LTMASK"),
    (0x3a, "SR_LEMASK"),
    (0x3b, "SR_GTMASK"),
    (0x3c, "SR_GEMASK"),
    (0x40, "SR_GLOBALERRORSTATUS"),
    (0x41, "SR_CGAERRORSTATUS"),
    (0x42, "SR_WARPERRORSTATUS"),
    (0x43, "SR_VIRTUALSMID"),
    (0x44, "SR_VIRTUALENGINEID"),
    (0x50, "SR_CLOCKLO"),
    (0x51, "SR_CLOCKHI"),
    (0x52, "SR_GLOBALTIMERLO"),
    (0x53, "SR_GLOBALTIMERHI"),
    (0x84, "SR_VARIABLE_RATE"),
    (0x88, "SR_CgaCtaId"),
    (0x89, "SR_GpcLocalCgaId"),
    (0x8a, "SR_CgaSize"),
    (0x8b, "SR_CTARegPoolSz"),
    (0x8d, "SR_TMemSz"),
    (0xff, "SRZ"),
];

fn format_sysreg(fields: &[&DecodedField], raw: u128) -> String {
    // Most reliable: read bits [79:72] of the raw instruction directly.
    // For S2R and S2UR, the full sysreg ID is always encoded in this byte.
    let raw_id = ((raw >> 72) & 0xFF) as u32;
    if raw_id != 0 {
        for (code, name) in SYSREG_NAMES {
            if *code == raw_id { return name.to_string(); }
        }
        // Fallback to field reconstruction if raw_id not in table
    }

    // Field-based reconstruction (used when raw bits are not the sysreg byte)
    let mut id: u32 = raw_id; // start from raw, fill in
    for f in fields {
        let e = norm_ext(&f.extraction);
        match e.as_str() {
            "sysreg" | "sysreg_lo7" => id = (id & !0x7F) | (f.value as u32 & 0x7F),
            "sysreg_lo4"            => id = (id & !0x0F) | (f.value as u32 & 0x0F),
            "sysreg_hi4"            => id = (id & !0xF0) | ((f.value as u32 & 0xF) << 4),
            "sysreg_hi1"            => id = (id & !0x80) | ((f.value as u32 & 1)   << 7),
            _ => {}
        }
    }
    for (code, name) in SYSREG_NAMES {
        if *code == id { return name.to_string(); }
    }
    format!("SR_0x{id:04x}")
}

// ── B — barrier ───────────────────────────────────────────────────────────────

fn format_barrier(fields: &[&DecodedField]) -> String {
    let mut b: Option<u64> = None;
    for f in fields {
        let e = norm_ext(&f.extraction);
        if e == "barrier" || e == "imm" {
            b = Some(f.value);
        }
    }
    match b {
        Some(n) => format!("B{n}"),
        None    => "B0".to_string(),
    }
}

// ── float formatting ──────────────────────────────────────────────────────────

fn half_to_f32_bits(hf: u16) -> u32 {
    let sign = (hf >> 15) as u32;
    let exp  = ((hf >> 10) & 0x1f) as u32;
    let mant = (hf & 0x3ff) as u32;
    if exp == 0 && mant == 0 {
        sign << 31  // ±0.0
    } else if exp == 0 {
        // Subnormal half-float: (-1)^sign × 2^(-14) × (mant/1024)
        // Normalize for f32 representation
        let mut m = mant;
        let mut e: i32 = -14;
        while m & 0x200 == 0 { m <<= 1; e -= 1; }
        m = (m << 1) & 0x3ff;  // remove implicit leading 1
        // After the loop: m = 0x200, with implicit leading 1 at bit 9.
        // The normal form exponent n = e - 1 (since 2^e × 2^9 × 2^(-10) = 2^(e-1)).
        let f32_exp = (e - 1 + 127) as u32;
        (sign << 31) | (f32_exp << 23) | (m << 13)
    } else if exp == 31 {
        (sign << 31) | 0x7f800000 | (mant << 13)  // ±Inf or NaN
    } else {
        (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13)
    }
}

fn format_float(f: f32, neg: bool) -> String {
    let neg_s = if neg { "-" } else { "" };
    if f.is_infinite() {
        // Sign lives in the value bits themselves (e.g. FSEL's literal
        // 0xff800000 = -INF); a bare "+INF" would re-encode as +INF and drop
        // bit31. Compose with the explicit neg flag when present.
        let sneg = neg != f.is_sign_negative();
        return if sneg { "-INF ".to_string() } else { "+INF ".to_string() };
    }
    // NaN glyph law (BUG-177; nvdisasm 13.3.73 arbitration on FSEL+FMUL
    // skeletons, sm_103a + sm_120a, work/bug177/arb/arb177.json): sign bit
    // picks "+"/"-" (composed with the explicit neg flag like the INF arm);
    // quiet bit (f32 mantissa bit 22) picks QNAN vs SNAN; the rest of the
    // payload is glyph-irrelevant (vendor: 0x7FC00000 and 0x7FF80000 both
    // render "+QNAN"). Decode-side render parity only: re-encode of any
    // *NAN token stays parked (bimodal bit lanes, see parser.rs comment).
    if f.is_nan() {
        let sneg = if neg != f.is_sign_negative() { "-" } else { "+" };
        let kind = if f.to_bits() & 0x0040_0000 != 0 { "QNAN" } else { "SNAN" };
        return format!("{sneg}{kind} ");
    }
    if f == 0.0 {
        // -0.0 is a distinct bit pattern (0x80000000); nvdisasm prints "-0" and
        // the encoder must hear the sign (HFMA2 imm pair "0, -0").
        let neg0 = neg || (f.is_sign_negative());
        return if neg0 { "-0.0".to_string() } else { "0".to_string() };
    }
    // Integral values print bare (nvdisasm: "FFMA R0, R1, R2, 1" not "1.0e+00").
    if f == f.trunc() && f.abs() < 16_777_216.0 {
        return format!("{neg_s}{}", f as i64);
    }
    // Non-integral: nvdisasm prints C %.20g of the value ("4.1917929649353027344").
    let s = format_g20((if neg { -f } else { f }) as f64);
    if !s.is_empty() {
        return s;
    }
    let s = normalize_sci_exp(format!("{neg_s}{:.18e}", f));
    // Verify roundtrip: string→f64→f32 must give same bits
    let rt: f32 = s.parse::<f64>().map(|d| d as f32).unwrap_or(0.0);
    if rt.to_bits() == f.to_bits() {
        s
    } else {
        // Use hex literal for exact roundtrip
        format!("{neg_s}0x{:08x}F", f.to_bits())
    }
}

fn format_double(f: f64, neg: bool) -> String {
    let neg_s = if neg { "-" } else { "" };
    // nvdisasm always signs INF ("+INF"/"-INF") in FP64-immediate context.
    if f.is_infinite() { return format!("{}INF ", if neg || f.is_sign_negative() { "-" } else { "+" }); }
    if f.is_nan()      { return format!("{neg_s}QNAN "); }
    if f == 0.0        { return "1".to_string(); } // integer 1 used as double constant
    if f == f.trunc() && f.abs() < 16_777_216.0 {
        return format!("{neg_s}{}", f as i64);
    }
    let s = format_g20(if neg { -f } else { f });
    if !s.is_empty() {
        // BUG-146: format_g20 already applies the nvdisasm sci law
        // (%.20e untrimmed for exp>=0); normalize_sci_exp would trim the
        // zero padding back off. Only the exponent padding is re-applied.
        return pad_sci_exp(s);
    }
    normalize_sci_exp(format!("{neg_s}{:.16e}", f))
}

/// nvdisasm float-immediate style: C `%.20g` on the f64 value
/// ("4.1917929649353027344", "0.0034000000450760126114", "1.1641532182693481445e-10").
fn format_g20(f: f64) -> String {
    if f == 0.0 || !f.is_finite() {
        return String::new();
    }
    let a = f.abs();
    if (1e-4..1e9).contains(&a) {
        // fixed notation with 20 significant digits: decimals = 20 - floor(log10(a)) - 1
        let f10 = a.log10().floor() as i32;
        let dec = (19 - f10).max(0) as usize;
        let s = format!("{:.*}", dec, f);
        // strip trailing zeros but keep the number parseable
        if s.contains('.') {
            let t = s.trim_end_matches('0').trim_end_matches('.');
            return t.to_string();
        }
        s
    } else {
        // nvdisasm scientific-notation law (BUG-146 census 2026-08-25, 32M
        // nvdisasm-13.3 lines): exponent >= 0 prints C %.20e UNTRIMMED
        // (21 significant digits, zero padding kept: 0x5e2aaaab ->
        // "3.07445743724422758400e+18"); exponent < 0 rounds to 20
        // significant digits with trailing zeros stripped ("...e-07").
        let e20 = format!("{:.20e}", f);
        let epos = e20.rfind('e').unwrap();
        let exp: i32 = e20[epos + 1..].parse().unwrap();
        if exp >= 0 {
            let mantissa = &e20[..epos];
            return format!("{}e+{:02}", mantissa, exp);
        }
        let s = format!("{:.19e}", f);
        normalize_sci_exp(s)
    }
}

/// Exponent padding only (no trailing-zero trim). Used where the sci law
/// requires the %.20e padding preserved ("...840000e+16").
fn pad_sci_exp(s: String) -> String {
    if let Some(e_pos) = s.rfind('e') {
        let mantissa = &s[..e_pos];
        let exp = &s[e_pos + 1..];
        let (esign, edigits) = if let Some(rest) = exp.strip_prefix('-') {
            ("-", rest)
        } else if let Some(rest) = exp.strip_prefix('+') {
            ("+", rest)
        } else {
            ("+", exp)
        };
        let edigits_padded = if edigits.len() < 2 {
            format!("{:0>2}", edigits)
        } else {
            edigits.to_string()
        };
        return format!("{}e{}{}", mantissa, esign, edigits_padded);
    }
    s
}

/// Normalize scientific notation: pad exponent to 2 digits and strip trailing zeros.
/// "1.370906829833984375000e-06" → "1.370906829833984375e-06"
fn normalize_sci_exp(s: String) -> String {
    if let Some(e_pos) = s.rfind('e') {
        let mantissa = &s[..e_pos];
        let exp = &s[e_pos + 1..];
        let (esign, edigits) = if let Some(rest) = exp.strip_prefix('-') {
            ("-", rest)
        } else if let Some(rest) = exp.strip_prefix('+') {
            ("+", rest)
        } else {
            ("+", exp)
        };
        let edigits_padded = if edigits.len() < 2 {
            format!("{:0>2}", edigits)
        } else {
            edigits.to_string()
        };
        // Strip trailing zeros from mantissa decimal part
        let mantissa_stripped = if mantissa.contains('.') {
            let trimmed = mantissa.trim_end_matches('0');
            // Keep at least one digit after the decimal point
            if trimmed.ends_with('.') { &mantissa[..trimmed.len() + 1] } else { trimmed }
        } else {
            mantissa
        };
        return format!("{}e{}{}", mantissa_stripped, esign, edigits_padded);
    }
    s
}

// ── misc helpers ──────────────────────────────────────────────────────────────

fn parse_shr_suffix(s: &str) -> u32 {
    // "sub_imm0_shr3" → 3, "sub_imm1" → 0, "imm_shr8" → 8
    if let Some(pos) = s.rfind("shr") {
        s[pos + 3..].parse().unwrap_or(0)
    } else {
        0
    }
}

/// sub_imm* field -> address-offset contribution. `_shr{n}u` marks the
/// unsigned scaled window (BUG-070: STG.256 desc offset is an unsigned
/// 16-bit field per nvdisasm-13.3 oracle) — no sign extension; every other
/// sub_imm variant keeps sign-extending from its top bit.
fn sub_imm_off(s: &str, value: u64, bits: u32) -> i64 {
    let unsigned = s.ends_with('u') && s.contains("_shr");
    let sh = parse_shr_suffix(s.strip_suffix('u').unwrap_or(s));
    let v = if unsigned { value as i64 } else { sign_extend(value, bits) };
    v << sh
}

/// Public sign-extension for the encoder's scaled-window validation (BUG-070
/// fail-closed checks reuse the decoder's sign model verbatim).
pub fn sign_extend_pub(val: u64, bits: u32) -> i64 {
    sign_extend(val, bits)
}

fn sign_extend(val: u64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 { return val as i64; }
    let sign_bit = 1u64 << (bits - 1);
    if val & sign_bit != 0 {
        (val | !((1u64 << bits) - 1)) as i64
    } else {
        val as i64
    }
}

// ── impl Display for DecodedInst ──────────────────────────────────────────────

impl std::fmt::Display for DecodedInst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ;", to_sass(self))
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ins_key_basic() {
        let (op, ops) = parse_ins_key("IADD3_R_P_P_R_R_R");
        assert_eq!(op, "IADD3");
        assert_eq!(ops, &["R", "P", "P", "R", "R", "R"]);
    }

    #[test]
    fn test_parse_ins_key_addr() {
        let (op, ops) = parse_ins_key("LDG_R_dARI");
        assert_eq!(op, "LDG");
        assert_eq!(ops, &["R", "dARI"]);
    }

    #[test]
    fn test_parse_ins_key_aruri() {
        let (op, ops) = parse_ins_key("LDG_R_ARURI");
        assert_eq!(op, "LDG");
        assert_eq!(ops, &["R", "ARURI"]);
    }

    #[test]
    fn test_parse_ins_key_cai() {
        let (op, ops) = parse_ins_key("LDC_R_cAI");
        assert_eq!(op, "LDC");
        assert_eq!(ops, &["R", "cAI"]);
    }

    #[test]
    fn test_norm_ext_sysreg() {
        assert_eq!(norm_ext("SysReg"), "sysreg");
        assert_eq!(norm_ext("SysRegHi1"), "sysreg_hi1");
        assert_eq!(norm_ext("SubImm(1)"), "sub_imm1");
        assert_eq!(norm_ext("guard"), "guard");
    }

    #[test]
    fn test_sign_extend() {
        assert_eq!(sign_extend(0xffffff8, 24), -8);
        assert_eq!(sign_extend(0x100, 32), 256);
        assert_eq!(sign_extend(0x80000000, 32), i32::MIN as i64);
    }
}
