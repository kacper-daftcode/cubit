//! Decoder: 128-bit instruction binary → structured DecodedInst.
//!
//! Matching algorithm: for each (key, mod_group) entry in the table,
//! check if `(code & ~variable_mask) == and_base`. Since all 379 bases
//! are unique, this gives an unambiguous match.
//!
//! For performance, we build an index on the opcode bits [15:0] for O(1) lookup.

use crate::table::{IsaTable, Field, Extraction};
use anyhow::Result;
use std::collections::HashMap;

/// A decoded operand field.
#[derive(Debug, Clone)]
pub struct DecodedField {
    /// Field name derived from extraction type and shift.
    pub name: String,
    /// Bit position.
    pub shift: u32,
    /// Number of bits.
    pub bits: u32,
    /// Raw extracted value.
    pub value: u64,
    /// Which operand token this field belongs to.
    pub token_idx: i32,
    /// Extraction type used.
    pub extraction: String,
}

/// A fully decoded instruction.
#[derive(Debug, Clone)]
pub struct DecodedInst {
    /// Instruction key (e.g., "IADD3_R_P_P_R_R_R").
    pub key: String,
    /// Modifier group (e.g., "X", "64,E", "").
    pub mod_group: String,
    /// Base opcode (e.g., "IADD3").
    pub opcode: String,
    /// Decoded fields with values.
    pub fields: Vec<DecodedField>,
    /// Control code (scheduling).
    pub ctrl: scheduling_decode::DecodedCtrl,
    /// Raw 128-bit code.
    pub raw_code: u128,
    /// Instruction address.
    pub addr: u32,
}

/// Decoded scheduling/control information.
pub mod scheduling_decode {
    #[derive(Debug, Clone)]
    pub struct DecodedCtrl {
        pub stall: u8,
        pub yield_flag: bool,
        pub write_bar: u8,
        pub read_bar: u8,
        pub wait_mask: u8,
    }
}

/// Pre-built decode index for fast matching.
pub struct DecodeIndex {
    /// Map from (and_base & 0xFFFF) → Vec of (key, mod_group, and_base, variable_mask)
    opcode_map: HashMap<u16, Vec<DecodeCandidate>>,
}

#[derive(Clone)]
struct DecodeCandidate {
    key: String,
    mod_group: String,
    and_base: u128,
    match_mask: u128,              // ~variable_mask: bits that must match
    relaxed_match_mask: u128,      // match_mask but with imm-field bits treated as variable
    broad_relaxed_match_mask: u128, // relaxed_match_mask also ignoring standard reg slots
    #[allow(dead_code)]
    record_count: usize,           // for disambiguation
}

impl DecodeIndex {
    /// Build a decode index from the ISA table.
    pub fn build(table: &IsaTable) -> Self {
        let mut opcode_map: HashMap<u16, Vec<DecodeCandidate>> = HashMap::new();

        for (key, ike) in &table.entries {
            for (mods, mg) in &ike.mod_groups {
                // Use bits [11:0] as opcode key (bits [15:12] are predicate guard, variable)
                let opcode_lo16 = (mg.and_base & 0x0FFF) as u16;
                // A declared field occupies OPERAND bits, which are variable by definition.
                // The learned `variable_mask` can be too narrow when the training records
                // lacked operand diversity — e.g. QMMA.SF's scale-register field at [59:52]
                // only saw registers <16, so bits [59:56] looked constant and decode failed
                // for any R>=16. Treat every declared field's full bit-range as variable so
                // encode/decode round-trips for all operand values.
                let mut field_mask: u128 = 0;
                for f in &mg.fields {
                    let fm: u128 = if f.bits >= 128 { u128::MAX }
                        else { ((1u128 << f.bits) - 1) << f.shift };
                    field_mask |= fm;
                }
                let match_mask = !mg.variable_mask & !field_mask;

                // Relaxed match: also treat imm-typed field bits as variable.
                // This handles cases where the variable_mask learned from records was too
                // narrow (e.g. IMAD_R_R_II_R with a 32-bit immediate where some bits
                // appeared constant in training data but aren't truly constant).
                let mut imm_extra_mask: u128 = 0;
                for f in &mg.fields {
                    // Treat imm-like, sub-register, AND flag fields as variable in the relaxed mask.
                // These may be missing from variable_mask when training data lacked diversity.
                let is_imm = matches!(f.extraction,
                        crate::table::Extraction::Imm
                        | crate::table::Extraction::ImmShr(_)
                        | crate::table::Extraction::ImmDec
                        | crate::table::Extraction::ImmDecU32
                        | crate::table::Extraction::F32
                        | crate::table::Extraction::F16
                        | crate::table::Extraction::F16d
                        | crate::table::Extraction::F64hi
                        // Sub-register fields for address expressions
                        | crate::table::Extraction::SubR(_)
                        | crate::table::Extraction::SubUR(_)
                        | crate::table::Extraction::SubImm(_)
                        | crate::table::Extraction::SubImmS24(_)
                        | crate::table::Extraction::SubRShr(_, _)
                        | crate::table::Extraction::SubURShr(_, _)
                        | crate::table::Extraction::SubImmShr(_, _)
                        );
                    if is_imm {
                        let fm: u128 = if f.bits >= 128 { u128::MAX }
                            else { ((1u128 << f.bits) - 1) << f.shift };
                        imm_extra_mask |= fm;
                    }
                }
                let relaxed_match_mask = match_mask & !imm_extra_mask;

                // For entries with very few variable bits (likely learned from a single record
                // or small corpus), also build a broad relaxed mask that treats all standard
                // register slots as variable. This handles InsKeys like LDL_R_ARI::LU where
                // the variable_mask covers almost nothing because all training records had
                // the same register values.
                let std_reg_mask: u128 = (0xFF_u128 << 16)   // Rd [23:16]
                    | (0xFF_u128 << 24)  // Ra [31:24]
                    | (0xFFFFFFFF_u128 << 32)  // Rb/imm [63:32]
                    | (0xFF_u128 << 64); // Rc [71:64]
                let _ = std_reg_mask; // used below in broad_relaxed_match_mask
                let broad_relaxed_match_mask = relaxed_match_mask & !std_reg_mask;

                // Derived sm_103a tables AND the corpus' scheduling words into
                // the high32 of and_base (e.g. mode bits 113..115), but decode()
                // strips code's upper32 before matching. Strip and_base too, so
                // the strict mask compare is over operand/opcode bits only.
                let and_base = mg.and_base & !(0xFFFFFFFF_u128 << 96);
                let c = DecodeCandidate {
                    key: key.clone(),
                    mod_group: mods.clone(),
                    and_base,
                    match_mask,
                    relaxed_match_mask,
                    broad_relaxed_match_mask,
                    record_count: 0,
                };
                // The opcode map key uses and_base bits [11:0], but declared
                // fields may own some of those bits (e.g. UTCHMMA dsel2@10):
                // real instructions then carry different opcode-key values and
                // would INDEX-MISS entirely. Register the candidate under every
                // key variant reachable by toggling field-owned bits < 12.
                let fm12 = field_mask & 0x0FFF;
                let varbits: Vec<u32> = (0..12).filter(|b| (fm12 >> b) & 1 == 1).collect();
                if !varbits.is_empty() && varbits.len() <= 8 {
                    let base12 = opcode_lo16 & !fm12 as u16;
                    for comb in 0u32..(1u32 << varbits.len()) {
                        let mut k = base12;
                        for (i, b) in varbits.iter().enumerate() {
                            if (comb >> i) & 1 == 1 { k |= 1 << b; }
                        }
                        opcode_map.entry(k).or_default().push(c.clone());
                    }
                } else {
                    opcode_map.entry(opcode_lo16).or_default().push(c);
                }
            }
        }

        DecodeIndex { opcode_map }
    }

    /// Decode a 128-bit instruction.
    pub fn decode(&self, code: u128, addr: u32, table: &IsaTable) -> Result<DecodedInst> {
        // Strip upper32 (scheduling + mode bits) for matching.
        // SM120 upper32 contains only scheduling/mode/reuse — no opcode encoding.
        let sched_mask: u128 = 0xFFFFFFFF_u128 << 96;
        let code_clean = code & !sched_mask;

        // Look up by opcode bits [15:0]
        // Use bits [11:0] as opcode key (bits [15:12] are predicate guard)
        let opcode_lo16 = (code_clean & 0x0FFF) as u16;
        let candidates = self.opcode_map.get(&opcode_lo16)
            .ok_or_else(|| anyhow::anyhow!("no instruction matches opcode 0x{:04x}", opcode_lo16))?;

        // Find matching candidates using strict match_mask first, then relaxed fallback.
        // Strict: (code & match_mask) == (and_base & match_mask)
        // Relaxed: same but with imm-field bits also treated as variable, for cases where
        // the variable_mask was learned from a narrow set of training records and missed
        // some immediate bit patterns (e.g. IMAD_R_R_II_R with unusual immediate values).
        // Collect all candidates that match under strict, relaxed, or broad criteria.
        // Strict: (code & match_mask) == (and_base & match_mask) — exact variable_mask match
        // Relaxed: imm-field bits also treated as variable (handles narrow variable_mask)
        // Broad: also standard register slots free — ONLY for entries with no fields,
        //        where register values were baked into and_base from a single training record.
        //
        // Guard bits [15:12] encode the predicate guard (@P0..@!P6). They are always
        // variable (the opcode key already strips them via `& 0x0FFF`), but some table
        // entries may not include them in variable_mask if all training records had PT
        // (no predicate guard). Exclude guard bits from the match check so that an
        // instruction like `@!P0 LDCU.64 UR4, ...` still matches its table entry.
        let guard_mask: u128 = 0xF000; // bits [15:12] = predicate guard
        let mut matches: Vec<(&DecodeCandidate, u8)> = candidates.iter().filter_map(|c| {
            let strict = (code_clean & c.match_mask & !guard_mask) == (c.and_base & c.match_mask & !guard_mask);
            let relaxed = (code_clean & c.relaxed_match_mask & !guard_mask) == (c.and_base & c.relaxed_match_mask & !guard_mask);
            if strict { return Some((c, 0u8)); }       // priority 0 = strict
            if relaxed { return Some((c, 1u8)); }      // priority 1 = relaxed-only
            // Broad match: for entries with no learned fields, OR for memory-addressing
            // InsKeys (containing ARI/AI/dARI/ARURI) where the base register field is
            // commonly missing from the table but is always at the standard Ra slot.
            let no_fields = table.get(&c.key, &c.mod_group)
                .map(|e| e.fields.is_empty()).unwrap_or(false);
            let is_mem_addr = c.key.contains("_ARI") || c.key.contains("_AI")
                || c.key.contains("dARI") || c.key.contains("ARURI");
            if no_fields || is_mem_addr {
                let broad = (code_clean & c.broad_relaxed_match_mask & !guard_mask) == (c.and_base & c.broad_relaxed_match_mask & !guard_mask);
                if broad { return Some((c, 2u8)); }    // priority 2 = broad-only
            }
            // Priority 3 (last resort): ALU sign-bit tolerant match. The generic
            // abs/neg modifier bits (Rb: 62/63, Ra: 72/73, Rc: 74/75) are added
            // AFTER matching by the is_alu block below; entries whose variable_mask
            // never covered them (training set had no signed sample) otherwise fail
            // to decode entirely (e.g. DFMA R16, R32, |R36|, R16 in cusolver).
            let base = c.key.split('_').next().unwrap_or("").split('.').next().unwrap_or("");
            let is_memlike = matches!(base,
                "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "STG" | "STL" | "STS" |
                "ATOM" | "RED" | "BRA" | "BSSY" | "BSYNC" | "EXIT" | "RET" |
                "BAR" | "S2R" | "S2UR" | "LDSM" | "LDGSTS" | "QMMA");
            if !is_memlike {
                let sign_bits: u128 = (3u128 << 62) | (3u128 << 72) | (3u128 << 74);
                let m2 = c.match_mask & !sign_bits;
                if (code_clean & m2 & !guard_mask) == (c.and_base & m2 & !guard_mask) {
                    return Some((c, 3u8));
                }
            }
            None
        }).collect();

        // Disambiguation: prefer strict matches, then shorter key, then consistency score.
        // For same InsKey: prefer LONGEST mod_group (most specific variant).
        matches.sort_by_key(|(c, priority)| {
            let score = key_field_consistency_score(&c.key, &c.mod_group, table);
            let is_negative = score < 0;
            // A modgroup that decodes modifiers via `opaque_mod` (raw bits printed as
            // `?NAME`) is a generic LAST-RESORT fallback. Whenever a properly-named
            // modgroup also matches (its signature bits agree), it must win — otherwise
            // the match_mask popcount tiebreak can pick the opaque fallback and emit a
            // non-re-encodable `?`-form (e.g. UISETP.?NE.?S32.?OR). Penalise opaque
            // candidates so any concrete match outranks them.
            let opaque_penalty: i32 = table.get(&c.key, &c.mod_group)
                .map(|e| e.fields.iter().any(|f|
                    matches!(f.extraction, crate::table::Extraction::OpaqueModifier)) as i32)
                .unwrap_or(0);
            // Descriptor-addressed GLOBAL memory keys (`_dARI`/`_dAI`) are MORE specific
            // than the plain `_ARI`/`_AI` forms: the descriptor bytes also match the plain
            // key (its mask ignores the descriptor slot), and the plain key, being shorter,
            // would win the key-length tiebreak and silently drop the descriptor (e.g. SM120
            // `LDG.E.U8 desc[UR][R]` mis-decoded as `LDG.E.U8 [R]`). Prefer the descriptor
            // key when both match — but ONLY for global ops (LDG/STG/…): shared/local
            // (LDS/LDL) and constant loads use plain addressing and have no descriptor form,
            // so penalising their `_ARI` would wrongly steer them to a bogus descriptor key.
            let is_global_mem = c.key.starts_with("LDG") || c.key.starts_with("STG")
                || c.key.starts_with("LDGSTS") || c.key.starts_with("ATOMG")
                || c.key.starts_with("REDG");
            let plain_addr_penalty: i32 = if !is_global_mem
                || c.key.contains("dARI") || c.key.contains("dAI") {
                0
            } else if c.key.contains("_ARI") || c.key.contains("_AI") {
                1
            } else {
                0
            };
            // Bonus for high-scoring keys (overrides key-length preference)
            let bonus: i32 = if score >= 3 { 10 } else { 0 };
            let adjusted_len = c.key.len() as i32 - bonus;
            let neg_popcount = -(c.match_mask.count_ones() as i32);
            // Tiebreak between same-key modgroups whose distinguishing modifier bits are
            // NOT in match_mask (op baked only in and_base, e.g. REDUX MAX vs MIN, where
            // MIN's signature is a subset of MAX's): prefer the candidate whose and_base
            // signature bits are MAXIMALLY present in the code (the most-specific modifier
            // match — what the encoder would have produced). Without this, the wrong
            // modgroup can win an order-undefined tie (MAX decoded as MIN).
            let neg_andbase_in_code = -(((c.and_base & code_clean).count_ones()) as i32);
            // Prefer longer mod_groups (more specific match)
            let neg_mg_len = -(c.mod_group.len() as i32);
            // Penalize Phase-17-style underdiscovered operand keys (InsKey ends with _? or
            // contains _?_). These entries have incomplete field coverage and should lose to
            // fully-specified entries like _R, _II, _UR that cover all operand positions.
            // Also penalize keys with excess operands (e.g. _II_II_UR suffix) when those
            // extra fields have zero/default values in the instruction — these are
            // over-specified entries that matched by coincidence.
            let has_undiscovered = c.key.ends_with("_?")
                || c.key.contains("_?_")
                || c.key.contains("_II_?");
            let has_excess_trailing = c.key.contains("_II_II_UR")
                || c.key.contains("_II_UR")
                || c.key.contains("_UR_II")
                || c.key.contains("_II_II_?")
                || c.key.contains("_R_II_?")
                || c.key.contains("_P_II_II");
            let undiscovered_penalty: i32 = if has_undiscovered { 50 }
                                            else if has_excess_trailing { 30 }
                                            else { 0 };
            // BRA_P_* owns the branch predicate-operand slot [89:87]+neg@90
            // (nvdisasm prints "@Pg BRA [!]Pn, target"). A plain BRA_II must not
            // claim words carrying a real operand there — otherwise decode prints
            // without Pn and the round-trip loses the bits. Corpus convention has
            // PT (=7)+no-neg only for true plain BRAs.
            let bra_p_penalty: i32 =
                if c.key.starts_with("BRA_II")
                    && (((code_clean >> 87) & 0x7) != 0x7 || ((code_clean >> 90) & 1) != 0) {
                    5
                } else { 0 };
            // Unexplained-variance tiebreak: bits that are variable per the learned
            // variable_mask but belong to NO declared field and differ between the
            // code and this entry's and_base. The RIGHT mod_group explains all its
            // set/clear bits via fields+constants and scores 0; a wrong sibling
            // (e.g. LDC mg='64' on a 32-bit LDC word) must absorb its signature
            // bits as unexplained variance and scores >0.
            let unexplained_var: i32 = table.get(&c.key, &c.mod_group)
                .map(|e| {
                    let mut fm: u128 = 0;
                    for f in &e.fields {
                        fm |= if f.bits >= 128 { u128::MAX }
                              else { ((1u128 << f.bits) - 1) << f.shift };
                    }
                    let free = e.variable_mask & !fm;
                    ((code_clean ^ c.and_base) & free).count_ones() as i32
                })
                .unwrap_or(0);
            // Sort order: (is_negative, priority, undiscovered_penalty, unexplained_var, adjusted_len, -score, neg_popcount, neg_mg_len)
            // neg_mg_len last: only tiebreaks between same key+popcount
            (is_negative as i32, *priority as i32, opaque_penalty, plain_addr_penalty, undiscovered_penalty + bra_p_penalty, unexplained_var, adjusted_len, -score, neg_andbase_in_code, neg_popcount, neg_mg_len)
        });

        let matches: Vec<&DecodeCandidate> = matches.into_iter().map(|(c, _)| c).collect();

        // Additional check: if the best match has a variable output-predicate field,
        // but the actual predicate value in the code is PT (7 = no real predicate),
        // prefer the simpler key that has this predicate baked-in (no output-pred operand).
        let matched = select_best_candidate(&matches, code_clean, table)
            .ok_or_else(|| anyhow::anyhow!("no instruction matches code 0x{:032x} at opcode 0x{:04x}", code_clean, opcode_lo16))?;

        // Get the entry from the table
        let entry = table.get(&matched.key, &matched.mod_group)
            .ok_or_else(|| anyhow::anyhow!("table entry not found for {}::{}", matched.key, matched.mod_group))?;

        // Extract fields
        let mut fields = Vec::with_capacity(entry.fields.len());
        for f in &entry.fields {
            let mask = if f.bits >= 64 { u64::MAX } else { (1u64 << f.bits) - 1 };
            // Fields are extracted from the FULL word (not code_clean, which has
            // bits [127:96] stripped): reuse/pred fields live at 122..124 and would
            // otherwise decode as constant 0 (lost in decode->text->encode).
            let value = ((code >> f.shift) as u64) & mask;
            let name = field_name(f);
            let extraction = extraction_name(&f.extraction);
            fields.push(DecodedField {
                name, shift: f.shift, bits: f.bits, value,
                token_idx: f.token_idx, extraction,
            });
        }

        // Generic ALU register abs/neg bits — exact inverse of the encoder's generic
        // path (encoder.rs ~line 79): for an ALU op whose table entry has NO field-level
        // abs/neg for an operand, the modifier lives at fixed bits
        //   62 = abs Rb, 63 = neg Rb, 72 = neg Ra, 73 = abs Ra.
        // Without this, the decoder drops e.g. `-Rb` on FFMA/FADD/FMUL/HMMA/... and the
        // round-trip loses bit 62/63/72/73 (the single biggest lo64 fidelity gap).
        {
            let base_op = matched.key.split('_').next().unwrap_or("")
                .split('.').next().unwrap_or("");
            let is_alu = !matches!(base_op,
                "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "STG" | "STL" | "STS" |
                "ATOM" | "RED" | "BRA" | "BSSY" | "BSYNC" | "EXIT" | "RET" |
                "BAR" | "S2R" | "S2UR" | "LDSM" | "LDGSTS" | "QMMA");
            if is_alu {
                let optypes: Vec<&str> = matched.key.split('_').skip(1).collect();
                let skip_preds = optypes.iter().take_while(|t| **t == "P" || **t == "UP").count();
                let ra_tok = (skip_preds + 2) as i32;
                let rb_tok = (skip_preds + 3) as i32;
                // A table field already covers this bit (immediate, named modifier, …) —
                // leave it to that field (mirrors encoder's has_field_* guard + avoids
                // double-decoding an immediate bit as a sign flag).
                let bit_covered = |bit: u64| entry.fields.iter()
                    .any(|f| (f.shift as u64) <= bit && bit < (f.shift as u64) + f.bits as u64);
                let mut add = |bit: u64, tok: i32, ext: &str| {
                    // Skip bits baked into the modgroup's and_base: those are constant
                    // variant identity bits, not a per-instruction sign modifier.
                    let baked = ((matched.and_base >> bit) & 1) == 1;
                    if (code_clean >> bit) & 1 == 1 && !baked && !bit_covered(bit) {
                        fields.push(DecodedField {
                            name: ext.to_string(), shift: bit as u32, bits: 1, value: 1,
                            token_idx: tok, extraction: ext.to_string(),
                        });
                    }
                };
                add(63, rb_tok, "neg");
                add(62, rb_tok, "abs");
                add(72, ra_tok, "neg");
                add(73, ra_tok, "abs");
            }
        }

        // Decode scheduling
        let ctrl_bits = ((code >> (64 + 41)) & 0x1FFFF) as u32;
        let ctrl = scheduling_decode::DecodedCtrl {
            stall: (ctrl_bits & 0xF) as u8,
            yield_flag: (ctrl_bits >> 4) & 1 != 0,
            write_bar: ((ctrl_bits >> 5) & 0x7) as u8,
            read_bar: ((ctrl_bits >> 8) & 0x7) as u8,
            wait_mask: ((ctrl_bits >> 11) & 0x3F) as u8,
        };

        let opcode = {
            let parts: Vec<&str> = matched.key.split('_').collect();
            let mut op_parts: Vec<&str> = Vec::new();
            for part in &parts {
                if OP_TYPES.contains(part) {
                    // "_B" right after a (UN)PACK opcode is a lane suffix
                    // (F2FP...PACK_B / UNPACK_B), not a Barrier operand.
                    let pack_b = *part == "B"
                        && op_parts.last().is_some_and(|p| p.ends_with("PACK"));
                    if !pack_b { break; }
                }
                op_parts.push(part);
            }
            if op_parts.is_empty() { parts[0].to_string() } else { op_parts.join("_") }
        };

        Ok(DecodedInst {
            key: matched.key.clone(),
            mod_group: matched.mod_group.clone(),
            opcode,
            fields,
            ctrl,
            raw_code: code,
            addr,
        })
    }
}

/// Select the best matching candidate from a sorted list.
///
/// The sorted list already prefers shorter keys. This function applies one additional
/// heuristic: if the first candidate has a variable output-predicate operand but the
/// actual predicate value in the instruction is PT (7 = always true / no predicate),
/// try to find a candidate without the output-predicate operand instead.
fn select_best_candidate<'a>(
    matches: &[&'a DecodeCandidate],
    code_clean: u128,
    table: &IsaTable,
) -> Option<&'a DecodeCandidate> {
    let first = matches.first()?;

    // Check if the first candidate has an OUTPUT predicate field (shift 80-85, tok 1-3).
    // This handles P-prefix InsKeys like LOP3_P_... where PT means "no pred result".
    // Deliberately exclude trailing pred fields (shift > 85) like IMAD_R_R_R_R's
    // pred@shift=87, which is NOT an output pred and shouldn't trigger this fallback.
    if let Some(entry) = table.get(&first.key, &first.mod_group) {
        for f in &entry.fields {
            if f.token_idx >= 1 && f.token_idx <= 3
                && f.shift >= 80 && f.shift <= 85
                && matches!(f.extraction, crate::table::Extraction::Pred)
            {
                let mask = (1u64 << f.bits) - 1;
                let pred_val = ((code_clean >> f.shift) as u64) & mask;
                // PT = 7 for 3-bit pred, or 63/127 for wider pred
                let pt_val = mask; // all 1s = PT
                if pred_val == pt_val {
                    // The instruction has no real output predicate.
                    // Try to find a matching candidate without an output-pred operand.
                    for alt in matches {
                        if !key_has_output_pred_field(&alt.key, &alt.mod_group, table) {
                            return Some(alt);
                        }
                    }
                }
                break; // Only check the first output-pred field
            }
        }
    }

    // SHL disambiguation: if one candidate has "SHL" in its mod_group and the instruction
    // bits[71:64]=0xff (Rc=RZ), prefer the SHL candidate over the non-SHL one.
    // IMAD.SHL always requires Rc=RZ (baked into and_base as constant 0xff at bits[71:64]).
    // Only prefer SHL if it's a non-negative-scoring candidate (avoid bad key matches).
    let rc_bits = (code_clean >> 64) & 0xff;
    if rc_bits == 0xff {
        for candidate in matches {
            let score = key_field_consistency_score(&candidate.key, &candidate.mod_group, table);
            if score >= 0 && candidate.mod_group.contains("SHL") {
                return Some(candidate);
            }
        }
    }

    // Trailing pred disambiguation: if the instruction has a non-PT/non-!PT trailing
    // predicate at bits[90:87], prefer candidates with an explicit field covering those bits.
    // "Trailing" means shift in [87, 90] range (distinct from output pred at bits[83:81]).
    let trailing_pred_bits = (code_clean >> 87) & 0xF;  // 4 bits at [90:87]
    if trailing_pred_bits != 0x7 && trailing_pred_bits != 0xF {
        // For LEA/ULEA: prefer _P suffix variant whose trailing pred field has a
        // unique high token_idx (dedicated trailing-pred operand, not shared with
        // output pred). This avoids the _II variant where tok=2 is shared.
        let is_lea = first.key.starts_with("LEA_") || first.key.starts_with("ULEA_");
        if is_lea {
            let output_is_pt = ((code_clean >> 81) & 0x7) == 7;
            for candidate in matches {
                let ends_p = candidate.key.ends_with("_P") || candidate.key.ends_with("_UP");
                if !ends_p { continue; }
                // When output pred is PT, skip candidates with middle P
                if output_is_pt {
                    let op_types = parse_ins_key_op_types(&candidate.key);
                    let has_mid_p = op_types.len() > 2
                        && op_types[1..op_types.len()-1].iter().any(|t| t == "P" || t == "UP");
                    if has_mid_p { continue; }
                }
                if let Some(entry) = table.get(&candidate.key, &candidate.mod_group) {
                    let has_tp = entry.fields.iter().any(|f| {
                        f.shift >= 87 && matches!(f.extraction, crate::table::Extraction::Pred)
                    });
                    if has_tp { return Some(candidate); }
                }
            }
        }
        // General fallback: any candidate with pred field at shift >= 87.
        for candidate in matches {
            if let Some(entry) = table.get(&candidate.key, &candidate.mod_group) {
                let has_trailing_pred = entry.fields.iter().any(|f| {
                    f.shift >= 87 && matches!(f.extraction, crate::table::Extraction::Pred)
                });
                if has_trailing_pred {
                    return Some(candidate);
                }
            }
        }
    }

    // ULOP3/uniform instruction disambiguation: for uniform instructions (starting with U
    // e.g. ULOP3), prefer InsKeys ending with _UP (uniform pred) over _P (vector pred)
    // when they otherwise tie. This handles ULOP3_UP_UR..._UP vs ULOP3_UP_UR..._P.
    if first.key.starts_with("ULOP3") || first.key.starts_with("UPLOP3") {
        for candidate in matches {
            if candidate.key.ends_with("_UP") {
                return Some(candidate);
            }
        }
    }

    // Output pred disambiguation: if bits[83:81] (standard output pred slot) is non-PT,
    // prefer candidates with an output-pred field at an EARLY token position (tok <= 3)
    // at the output pred bit range (shift 80..85).
    // - tok=1 covers P-prefix InsKeys (e.g. LOP3_P_..., LOP3.LUT P0, Rd, ...)
    // - tok=2 covers P-middle InsKeys (e.g. LEA_R_P_R_R_II_P)
    // Explicitly exclude large tok values (tok >= 4) which encode non-output preds.
    let output_pred_bits = (code_clean >> 81) & 0x7;
    if output_pred_bits != 7 {  // P0..P6 = real output pred
        for candidate in matches {
            if let Some(entry) = table.get(&candidate.key, &candidate.mod_group) {
                let has_output_pred = entry.fields.iter().any(|f| {
                    f.token_idx >= 1 && f.token_idx <= 3
                        && matches!(f.extraction, crate::table::Extraction::Pred)
                        && f.shift >= 80 && f.shift <= 85
                });
                if has_output_pred {
                    return Some(candidate);
                }
            }
        }
    }

    // P-in-middle disambiguation: when the best candidate has a predicate operand in the
    // MIDDLE of its InsKey (neither first nor last), but bits[83:81]=PT (no real output pred),
    // prefer a candidate without that middle predicate (typically a shorter, cleaner form).
    // Example: IMAD_R_P_R_R_R wins by variable_mask width but IMAD_R_R_II_R is the correct
    // form when no output predicate is actually encoded.
    if output_pred_bits == 7 {
        let first_key_op_types = parse_ins_key_op_types(&first.key);
        let first_has_middle_pred = first_key_op_types.len() > 2
            && first_key_op_types[1..first_key_op_types.len()-1]
               .iter().any(|t| t == "P" || t == "UP");
        if first_has_middle_pred {
            for alt in matches {
                let alt_op_types = parse_ins_key_op_types(&alt.key);
                let alt_has_middle_pred = alt_op_types.len() > 2
                    && alt_op_types[1..alt_op_types.len()-1]
                       .iter().any(|t| t == "P" || t == "UP");
                if !alt_has_middle_pred {
                    return Some(alt);
                }
            }
        }
    }

    Some(first)
}

/// Check if this key/mod_group has a variable output-predicate field (tok >= 2, pred/upred).
///
/// Also returns true if the InsKey itself declares P/UP operand tokens — this handles
/// underdiscovered `_?` entries that have P tokens in the key name but missing pred fields
/// in the table (so they shouldn't be treated as "simpler/no-pred" variants).
fn key_has_output_pred_field(key: &str, mod_group: &str, table: &IsaTable) -> bool {
    // Check key structure: if key declares P or UP operand tokens, treat as having pred.
    // This prevents underdiscovered _? entries (with P in key but no field in table) from
    // being preferred over fully-specified entries that have an actual pred field.
    let op_types = parse_ins_key_op_types(key);
    if op_types.len() > 1 && op_types[1..].iter().any(|t| t == "P" || t == "UP") {
        return true;
    }
    if let Some(entry) = table.get(key, mod_group) {
        for f in &entry.fields {
            if f.token_idx >= 1 && matches!(f.extraction,
                crate::table::Extraction::Pred)
            {
                return true;
            }
        }
    }
    false
}

/// Operand type tokens parsed from an InsKey (same logic as in printer.rs).
const OP_TYPES: &[&str] = &[
    "ARURR", "ARURI", "ARUR", "AURI", "AURR", "AUR",
    "cAI", "dARI", "ARI",
    "UP", "UR", "SR", "FI", "II", "IM", "LO",
    "R", "P", "L", "B", "?",
];

fn parse_ins_key_op_types(key: &str) -> Vec<String> {
    let parts: Vec<&str> = key.split('_').collect();
    let mut op_parts: Vec<String> = Vec::new();
    let mut in_ops = false;
    for part in &parts {
        if !in_ops && OP_TYPES.contains(part) { in_ops = true; }
        if in_ops { op_parts.push(part.to_string()); }
    }
    op_parts
}

/// Compute a consistency score for a key: how well do the field token_idx assignments
/// match the expected operand types declared in the InsKey?
/// Returns higher values for more consistent keys. Negative = bad match.
fn key_field_consistency_score(key: &str, mod_group: &str, table: &IsaTable) -> i32 {
    let entry = match table.get(key, mod_group) {
        Some(e) => e,
        None => return 0,
    };
    let op_types = parse_ins_key_op_types(key);
    let mut score: i32 = 0;

    for f in &entry.fields {
        if f.token_idx <= 0 { continue; }
        let idx = (f.token_idx - 1) as usize;
        let op_type = op_types.get(idx).map(|s| s.as_str()).unwrap_or("");
        let ext_lower = extraction_name(&f.extraction);
        let is_pred    = ext_lower == "pred" || ext_lower == "guard";
        let is_upred   = ext_lower == "upred";
        let is_reg     = matches!(ext_lower.as_str(), "reg" | "ureg" | "ureg_ff" | "reg_ff"
            | "reg_shr1" | "reg_shr2" | "reg_shr3");
        let is_imm     = ext_lower.starts_with("imm") || matches!(ext_lower.as_str(),
            "f32" | "f16" | "f16_d" | "f64hi");
        let is_barrier = ext_lower == "barrier";
        let expected_pred    = op_type == "P";
        let expected_upred   = op_type == "UP";
        let expected_reg     = matches!(op_type, "R" | "UR");
        let expected_imm     = matches!(op_type, "II" | "IM" | "LO" | "FI");
        let expected_barrier = op_type == "B";

        if expected_pred  && is_pred   { score += 2; }
        else if expected_upred && is_upred  { score += 4; } // UP with upred = strong match
        else if expected_barrier && is_barrier { score += 4; } // B with barrier = strong match
        else if (expected_upred && is_pred) || (expected_pred && is_upred) { score -= 2; }
        else if (expected_reg && is_reg) || (expected_imm && is_imm)      { score += 2; }
        else if (expected_pred && is_reg) || (expected_reg && is_pred)    { score -= 5; }
        else if expected_reg  && is_imm     { score -= 4; }  // R/UR slot has imm field — significant mismatch
        else if expected_imm  && is_reg     { score -= 2; }  // II slot has reg field
        // Penalize: expected barrier slot but found pred field (BREAK_P_B instead of BREAK_B)
        else if expected_barrier && is_pred { score -= 5; }
        // ARI/dARI type operands: give bonus to dARI/ARURI keys (descriptor addressing)
        // when they have a sub_ur field in the address, vs plain ARI with no such field.
        let is_subur = ext_lower.starts_with("sub_ur");
        let expected_desc = matches!(op_type, "dARI" | "ARURI");
        if expected_desc && is_subur { score += 3; }
    }
    score
}

fn field_name(f: &Field) -> String {
    match f.shift {
        16 if f.bits == 8 => "Rd".to_string(),
        24 if f.bits == 8 => "Ra".to_string(),
        32 if f.bits == 8 => "Rb".to_string(),
        64 if f.bits == 8 => "Rc".to_string(),
        12 if f.bits == 4 => "guard".to_string(),
        _ => format!("[{}:{}]", f.shift + f.bits - 1, f.shift),
    }
}

fn extraction_name(e: &Extraction) -> String {
    match e {
        Extraction::Guard => "guard".into(),
        Extraction::Reg => "reg".into(),
        Extraction::UReg => "ureg".into(),
        Extraction::URegFf => "ureg_ff".into(),
        Extraction::RegFf => "reg_ff".into(),
        Extraction::RegShr(n) => format!("reg_shr{n}"),
        Extraction::URegShr(n) => format!("ureg_shr{n}"),
        Extraction::Pred => "pred".into(),
        Extraction::Imm => "imm".into(),
        Extraction::ImmShr(n) => format!("imm_shr{n}"),
        Extraction::Reuse => "reuse".into(),
        Extraction::Neg => "neg".into(),
        Extraction::F32 => "f32".into(),
        Extraction::F16d => "f16_d".into(),
        Extraction::SubR(n) => format!("sub_r{n}"),
        Extraction::SubUR(n) => format!("sub_ur{n}"),
        Extraction::SubImm(n) => format!("sub_imm{n}"),
        Extraction::SubRShr(n, s) => format!("sub_r{n}_shr{s}"),
        Extraction::SubURShr(n, s) => format!("sub_ur{n}_shr{s}"),
        Extraction::SubImmShr(n, s) => format!("sub_imm{n}_shr{s}"),
        Extraction::SubImmS24(n) => format!("sub_imm{n}_s24"),
        Extraction::OpaqueModifier => "opaque_mod".into(),
        Extraction::OpModFlag(n) => format!("opmod:{n}"),
        Extraction::HalfSel => "hsel".into(),
        Extraction::BF16 => "bf16".into(),
        Extraction::MnemMod(i, n) => format!("mnemod{}:{}", i, n),
        Extraction::LblPat(p) => p.clone(),
        _ => format!("{:?}", e).to_lowercase(),
    }
}
