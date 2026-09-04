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
    /// Table ef_flags this instruction was decoded against (BUG-181: per-arch
    /// printer laws, e.g. ATOMS ARI glyph split sm120 vs sm103a-family).
    pub ef_flags: u32,
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

        // BUG-068: iterate the table in a *deterministic* order. `table.entries`
        // is a HashMap with a per-process random iteration order; candidates were
        // pushed in that order and the stable tie sort below preserved it, so
        // equal-score ties resolved differently across processes (FSETP.NEU
        // AND/XOR, FMUL.FTZ 0/0x0/UR0, HFMA2 RZ-imma, IMAD.MOV/ISETP rsd runs).
        // Sorted (key, mod_group) iteration + the terminal tiebreak make decode
        // a pure function of (table, word).
        let mut ordered: Vec<(&String, &_, &String, &_)> = Vec::new();
        for (key, ike) in &table.entries {
            // BUG-090: encode_only rows (frozen-era text compatibility) are
            // invisible to the decoder -- canonical rows own the decode
            // surface; these exist only so pinned legacy text re-encodes
            // byte-exact (silicon-proven published words).
            if ike.encode_only {
                continue;
            }
            for (mods, mg) in &ike.mod_groups {
                // BUG-092: mod-group-level encode_only retention rows are
                // likewise decode-invisible; canonical mod groups on the same
                // key own decode, the retention exists only so pinned legacy
                // '(base_key, "")' text re-encodes byte-exact.
                if mg.encode_only {
                    continue;
                }
                ordered.push((key, ike, mods, mg));
            }
        }
        ordered.sort_by(|a, b| (a.0, a.2).cmp(&(b.0, b.2)));
        for (key, _ike, mods, mg) in ordered {
            {
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
                        | crate::table::Extraction::F32Cast
                        // Sub-register fields for address expressions
                        | crate::table::Extraction::SubR(_)
                        | crate::table::Extraction::SubUR(_)
                        | crate::table::Extraction::SubImm(_)
                        | crate::table::Extraction::SubImmS24(_)
                        | crate::table::Extraction::SubRShr(_, _)
                        | crate::table::Extraction::SubURShr(_, _)
                        | crate::table::Extraction::SubImmShr(_, _)
                        | crate::table::Extraction::SubImmShrU(_, _)
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
            // b4fill4: generic LD/ST are plain memory ops (no abs/neg operand
            // modifiers) — they were missing here, so the priority-3 ALU
            // sign-bit fallback absorbed words 1-sign-bit-adjacent to a real
            // LD row as that row (e.g. size-enum INVALID7 (v=e/f) decoding as
            // the valid .128 sibling). Fail closed instead.
            // BUG-199: ATOMG/REDG carry the width law in bits [74:73]
            // (arb195b/arb199b) — inside the prio-3 sign window. The rows
            // assert width via vm-exclusion (strict/relaxed/broad all reject
            // width flips), but prio-3 re-absorbed them as junk renders
            // ("ATOMG.E.INC ...PT, |R5|", 253 JUNK_LEGAL + 18 JUNK_INVALID on
            // flipdec_ctl). Fail closed; legal-but-unwitnessed widths are
            // coverage gaps, see blindlab results/cubitfix/199.md sec.6.
            let is_memlike = matches!(base,
                "LD" | "ST" |
                "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "STG" | "STL" | "STS" |
                "ATOM" | "RED" | "ATOMG" | "REDG" | "BRA" | "BSSY" | "BSYNC" | "EXIT" | "RET" |
                // BUG-211: ATOMS (shared-memory atomic) carries the width law
                // in bits [74:73] like ATOMG/REDG (arb211: b73=.S32 glyph
                // toggle on AND/OR/XOR ARI/AURI forms, b74=.64 — inside the
                // prio-3 sign window). Without the arm, b73-set words were
                // silently absorbed as the bare sibling (roundtrip-lossy) or
                // hijacked by phantom rows. Fail closed; witnessed widths are
                // coverage rows in tables (patch211).
                "ATOMS" |
                "BAR" | "S2R" | "S2UR" | "LDSM" | "LDGSTS" | "QMMA" |
                // BUG-224: SYNCS carries neighbor-form law at b72
                // (.IVALL/.WBALL), b73 (opaque enum), b91 (operandful
                // SYNCS.CCTL.IV [R+UR]) — all inside/adjacent to the prio-3
                // sign window (arb224 graft x3). The era row has no signed
                // operands; without the arm, b72-set words silently rendered
                // as the plain .IVALL sibling (+ junk neg field) instead of
                // failing closed. Coverage gap for unwitnessed forms stands
                // (222-class).
                "SYNCS" |
                // BUG-125: F2I carries its dst-type in bits [76:75][72] (fresh
                // f32-imm form, F2I_R_FI) — the prio-3 sign-bit window {72..75}
                // absorbed vendor-INVALID type indices 6/7 (nvdisasm `F2I.???6/
                // ???7`) as the U32/S32 sibling. Fail closed instead.
                "F2I" |
                // BUG-308: F2IP sibling of the F2I arm. The prio-3 sign
                // window on F2IP is selector/modifier law (hsel-H1 b72,
                // .RELU b75, .NTZ b74; b62/b63/b73 vendor-inert) measured by
                // arb308 x4 models. Corpus exposure ZERO (census308 x4 legs:
                // no F2IP word at any sign-window distance from a row).
                // Fail closed.
                "F2IP" |
                // BUG-126: USHF packs direction/sign/width/W in bits
                // {76,73,74,75} — all inside the prio-3 window. Shows up as the
                // lossy "!rsd[74:1]" path (R,U32 imm-form words absorbed by the
                // R,U64 row). Fail closed; every legal combo is already a row.
                "USHF" |
                // BUG-282: I2IP carries a real op-suffix law inside the Rc
                // sign window (arb282 + arb276b, nvdisasm x4 models):
                // b74=.SAT b75=.SATRELU on the 0x7239 4-op lattice;
                // b74+b75 = vendor '.INVALID3'. The two legal suffixes are
                // armed as strict full-key rows (canonical bug282 cut);
                // without this arm the prio-3 sign window absorbed BOTH
                // suffix forms (suffix silently dropped = wrong text,
                // measured on pub pyo3-303bd1e) and the INVALID3 marker
                // word (would print plain or mis-win a suffix row on the
                // prio-3 tiebreak). Fail closed; corpus exposure of the
                // whole family is measured ZERO (routex282 FULL 2,406-cubin
                // battery, both legs; routex276 likewise).
                "I2IP" |
                // BUG-283: MOVM.16 carries the vendor name-space law in bits
                // [79:75] (arb283 G x4 models: [77:75] 0=16 / 1=U4TO8 /
                // 5..7=INVALID5..7, [79:78] 0=MT88 / 1=M832 / 2=M864 /
                // 3=INVALID3). b75 (= [77:75] value 1 = U4TO8 sibling lane)
                // sits inside the prio-3 Rc sign window {62,63,72,73,74,75}
                // and was absorbed as plain '16.MT88' = vendor-WRONG name
                // (measured post-graft on the canonical-1beab0f tables: word
                // 0x23a|(1<<75) decoded '@P0 MOVM.16.MT88 R0, R0'). The MT88
                // lane itself is armed table-side (care [79:75]); the sibling
                // lanes stay unclaimed coverage gaps (316-kand). Fail closed.
                "MOVM");
            // BUG-225: census-driven arm batch (cross-census prio-3 absorb,
            // work/bug225). These bases have NO sign-able register operands
            // (pure control/sync + tmem/tensor lanes: dests, UR/desc, preds,
            // imms), yet the generic sign fallback absorbed their and_base
            // neighbors — worst class silently (prio3_same_glypheq: the
            // flipped bit never reaches the printed text, e.g. NANOSLEEP
            // b62..75 absorbed text-invisible x3 tables). Corpus exposure is
            // measured ZERO on all three tables (pass-2 census over the A/B
            // 2014-corpus, 4.86M unique words x3): no real word relies on
            // prio-3 for any of these bases, so the arm only closes silent
            // absorption of unwitnessed neighbors (219/224 fail-closed
            // doctrine). Bases with measured exposure (VOTE/VOTEU/
            // USETMAXREG/FENCE) and plain-R-source ops with unknown sign
            // law (BREV/FLO/PRMT/POPC/MOV-family) are intentionally NOT
            // armed — 226/227 class with the full vendor-parity table in
            // results/cubitfix/225.md.
            let is_225_armed = matches!(base,
                "NANOSLEEP" | "DEPBAR" | "LDGDEPBAR" | "ERRBAR" | "CGAERRBAR" |
                "UCGABAR" | "UTCBAR" | "BPT" | "MEMBAR" | "ACQBULK" |
                "ACQSHMINIT" | "ENDCOLLECTIVE" | "CCTL" | "YIELD" | "PREEXIT" |
                "WARPSYNC" | "ELECT" | "MATCH" | "B2R" | "CS2R" | "CS2UR" |
                "P2R" | "BREAK" | "BRX" | "CALL" | "BMOV" |
                "UGETNEXTWORKID" | "UVIRTCOUNT" | "QSPC" | "RPCMOV" | "SHFL" |
                "UBLKCP" | "UBLKPF" | "UBLKRED" | "R2P" | "R2UR" | "UP2UR" |
                "LDTM" | "STTM" | "STAS" | "STSM" | "UTCCP" | "UTMALDG" |
                "UTMAPF" | "UTMAREDG" | "UTMASTG" | "UTMACCTL" |
                "UTMACMDFLUSH" | "UTCATOMSWS" | "UTCHMMA" | "UTCIMMA" |
                "UTCQMMA" | "SULD");
            if is_225_armed {
                return None;
            }
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
            // Family-hijack detector: bits claimed by this entry's FIELDS but NOT
            // marked variable (constant in the training slice) that DISAGREE with
            // and_base. Wide composite fields can swallow opcode/family
            // discriminator bits (e.g. UTCHMMA's 17-bit gdesc_off spanning the
            // byte9 H/Q/I family code): a sibling-family word then matches the
            // entry's match_mask, and the pure popcount tiebreak picks the wrong
            // family (UTCQMMA printed as UTCHMMA). The true entry explains those
            // bits as constants and scores 0 here. Insertion point: after -score
            // (key consistency), before neg_andbase_in_code — ties that previously
            // fell to raw popcount.
            let field_ab_disagree: i32 = table.get(&c.key, &c.mod_group)
                .map(|e| {
                    let mut fm: u128 = 0;
                    for f in &e.fields {
                        fm |= if f.bits >= 128 { u128::MAX }
                              else { ((1u128 << f.bits) - 1) << f.shift };
                    }
                    let probe = fm & !e.variable_mask & !(0xFFFFFFFF_u128 << 96);
                    ((code_clean ^ c.and_base) & probe).count_ones() as i32
                })
                .unwrap_or(0);
            // Sort order: (priority, is_negative, undiscovered_penalty, ...) — match
            // strength dominates: a strict (prio 0) candidate with a weak key-consistency
            // score must still beat any relaxed/prio3 candidate (e.g. 6-op EX XSETP
            // forms scoring 0 would otherwise hijack strict-matching 5-op words).
            // neg_mg_len last: only tiebreaks between same key+popcount
            // Terminal total-order tiebreak (BUG-068): (key, mod_group) is
            // unique per table entry, so the ordering is a pure function of
            // the table — independent of HashMap iteration order. Numerics
            // are packed into [i64; 12] to stay under tuple-arity limits.
            let nums: [i64; 12] = [*priority as i64, is_negative as i64, opaque_penalty as i64, plain_addr_penalty as i64, (undiscovered_penalty + bra_p_penalty) as i64, unexplained_var as i64, adjusted_len as i64, -score as i64, field_ab_disagree as i64, neg_andbase_in_code as i64, neg_popcount as i64, neg_mg_len as i64];
            let tup = (nums, c.key.clone(), c.mod_group.clone());
            if std::env::var_os("CUBIT_DEBUG_DECODE").is_some() {
                eprintln!("CAND {:?} prio={:?} tup={:?}", (c.key.clone(), c.mod_group.clone()), priority, tup);
            }
            tup
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

        // BUG-362a (fail-closed, vendor-ILLEGAL reuse window): any of the
        // reuse bits [124:122] set on an F2I TRUNC/F64/FLOOR lattice word is
        // nvdisasm-ILLEGAL (rc=1) on all 4 models -- arb362 R-group 24
        // probes + arb362b 6 probes, x4 models AGREE on every probe (incl
        // the yield=1 variants the BUG-325/326 print law would otherwise
        // stamp a ghost `.reuse` on). The stripped-upper32 claim zone
        // cannot see these bits (the and_base match mask is 96-bit), so the
        // era-row claims leaked through: pre-fix the engine printed a plain
        // word (or `.reuse` under yield) where the vendor refuses the word
        // (donor tables claim identically = 362-nota donor-parity
        // overclaim). Fail closed with attribution.
        if (code >> 122) & 0x7 != 0 {
            // BUG-363 extension: the F2I R_R FTZ (byte10=0x21) / BF16
            // (byte10=0x40) era rows (grafted as keyed `F2I.FTZ[.T][.R]_R_R`
            // / `F2I[.T].BF16[.R]_R_R` rows, claim window 96-bit only) carry
            // NO reuse field because ANY reuse bit on those lattices is
            // vendor-ILLEGAL (arb363 R-group 16 probes: lanes 0x31/0xf0 x
            // {0x21,0x40} x {122,123,124,all}, nvdisasm 13.3.73 raw -b, x4
            // models AGREE). Same stripped-upper32 blind spot as BUG-362a:
            // fail closed here with attribution.
            let key = matched.key.as_str();
            let is_363_ftz_bf16 = matched.mod_group.is_empty()
                && matched.key.ends_with("_R_R")
                && (key.starts_with("F2I.FTZ") || key.contains(".BF16.") || key == "F2I.BF16_R_R");
            let reuse_bad = (matched.key == "F2I_R_R"
                && matches!(
                    matched.mod_group.as_str(),
                    "S64,TRUNC"
                        | "TRUNC,U64"
                        | "F64,TRUNC"
                        | "F64,TRUNC,U32"
                        | "F64,TRUNC,U64"
                        | "F64,S64,TRUNC"
                        | "F64,FLOOR"
                ))
                || (matched.mod_group.is_empty()
                    && matches!(
                        matched.key.as_str(),
                        "F2I.S64.TRUNC_R_R"
                            | "F2I.U64.TRUNC_R_R"
                            | "F2I.U32.F64.TRUNC_R_R"
                            | "F2I.U64.F64.TRUNC_R_R"
                            | "F2I.S64.F64.TRUNC_R_R"
                            | "F2I.F64.TRUNC_R_R"
                            | "F2I.F64.FLOOR_R_R"
                    ))
                || is_363_ftz_bf16;
            if reuse_bad {
                return Err(anyhow::anyhow!(
                    "vendor-ILLEGAL reuse bit [124:122] set on the F2I lattice row {}::{} (BUG-362/BUG-363; code 0x{:032x})",
                    matched.key, matched.mod_group, code
                ));
            }
        }

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

        // BUG-271: b86 '.H0_NH1' is the third bit of a tok3 hsel-suffix window
        // on the armed rows (imm family [82:81]+b86; sm121a BF16_V2 hosts
        // [61:60]+b86; era opmod:H0_NH1@86 rows armed by the same law).
        // arb271 x4 models: window values 5..7 (b86 set with nonzero hsel) are
        // vendor '.INVALID{5,6,7}' markers, never legal text. Fail closed
        // (decode hole; 282-INVALID3 doctrine) instead of printing a garbage
        // double-suffix operand. Corpus exposure measured ZERO for every armed
        // surface (routex271 FULL 2,406-cubin battery; the 32 pre-armed era
        // R4-row words all carry hsel=0).
        for hf in fields
            .iter()
            .filter(|f| f.value != 0 && (f.extraction == "h0nh1" || f.extraction == "opmod:H0_NH1"))
        {
            let tok = hf.token_idx;
            if fields
                .iter()
                .any(|f| f.extraction == "hsel" && f.token_idx == tok && f.value != 0)
            {
                return Err(anyhow::anyhow!(
                    "vendor-INVALID b86/hsel window combo at tok{} (code 0x{:032x})",
                    tok, code
                ));
            }
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
                // BUG-224: SYNCS has no sign-modifiable register operands
                // (state dst / address uses); the generic neg arm polluted
                // SYNCS.CCTL decodes with a phantom neg@72 field (arb224).
                "BAR" | "S2R" | "S2UR" | "LDSM" | "LDGSTS" | "SYNCS" | "QMMA" |
                // BUG-282: I2IP has no sign-modifiable register operands -
                // vendor x4 prints b62/b63 text-inert across the family
                // (arb282 E2: plain / regs payloads / with-suffix combos).
                // The generic post-pass printed ghost '-Rb'/'|Rb|' =
                // vendor-WRONG. b73 stays table-side (vm don't-care bit;
                // 275-kand opaque 2-bit enum [73:72] on tok4).
                "I2IP" |
                // BUG-281: I2I (2-op .SAT family on the 0x238 lattice) has
                // no sign-modifiable register operands either -- arb281
                // x4 models print b62/b63/b72/b73 text-INERT there
                // (singles + guard/payload compositions). The ghost arm
                // printed '-R38'/'|R38|' for b72/b73 = vendor-WRONG.
                "I2I" |
                // BUG-283: MOVM has no sign-modifiable register operands --
                // arb283 D x4 models print b62/b63/b72/b73 text-INERT on the
                // 0x23a MT88 lane (b74/b75 + b78/b79 = the [79:75] sub-op
                // name-space, armed care-side). The post-graft lane row is
                // strict-matched on the inert band, so the ghost post-pass
                // printed '-R0' (b72) / '|R0|' (b73) = vendor-WRONG (measured
                // on the canonical-1beab0f tables pre-arm). Fail closed.
                "MOVM" |
                // BUG-308: F2I/F2IP/USHF sign-window bits carry family law
                // (type S/U idx b72, USHF size/W b73..b75, F2IP hsel-H1 b72 /
                // .RELU b75; b62/b63/b73 vendor-inert on F2IP) -- arb308 x4
                // models on the full measure308b mint census. Corpus
                // exposure ZERO (census308 x4 legs: no claimed word prints a
                // ghost sign). Field-carried era F2I.*_R_R rows (neg@63/
                // abs@62 tok2, vendor-parity) are bit_covered and never pass
                // through here. Fail closed on the bare ghost glyphs.
                "F2I" | "F2IP" | "USHF"
            );
            // BUG-225: same census-driven family as the prio-3 gate above —
            // control/sync + tmem/tensor bases have no sign-modifiable
            // register operands; the generic neg/abs post-pass printed
            // phantom modifiers on absorbed words (R2UR `-UR4`, ELECT
            // `-URZ`/`|URZ|`, B2R `!P0` at b72 — all bogus; census
            // prio3_same_glyphjunk class). Corpus exposure of the prio-3
            // path is measured zero for these bases x3 tables.
            let is_225_armed = matches!(base_op,
                "NANOSLEEP" | "DEPBAR" | "LDGDEPBAR" | "ERRBAR" | "CGAERRBAR" |
                "UCGABAR" | "UTCBAR" | "BPT" | "MEMBAR" | "ACQBULK" |
                "ACQSHMINIT" | "ENDCOLLECTIVE" | "CCTL" | "YIELD" | "PREEXIT" |
                "WARPSYNC" | "ELECT" | "MATCH" | "B2R" | "CS2R" | "CS2UR" |
                "P2R" | "BREAK" | "BRX" | "CALL" | "BMOV" |
                "UGETNEXTWORKID" | "UVIRTCOUNT" | "QSPC" | "RPCMOV" | "SHFL" |
                "UBLKCP" | "UBLKPF" | "UBLKRED" | "R2P" | "R2UR" | "UP2UR" |
                "LDTM" | "STTM" | "STAS" | "STSM" | "UTCCP" | "UTMALDG" |
                "UTMAPF" | "UTMAREDG" | "UTMASTG" | "UTMACCTL" |
                "UTMACMDFLUSH" | "UTCATOMSWS" | "UTCHMMA" | "UTCIMMA" |
                "UTCQMMA" | "SULD");
            if is_alu && !is_225_armed {
                let optypes: Vec<&str> = matched.key.split('_').skip(1).collect();
                let skip_preds = optypes.iter().take_while(|t| **t == "P" || **t == "UP").count();
                // Token indexing mirrors the encoder (ra_idx/rb_idx there), including
                // the predicate-dest offset: [..P, Ra, Rb..] — Ra = ops[skip_preds].
                // (Previously skip+2/skip+3, off-by-one for _P_/_P_P_-prefixed keys —
                // FSETP/DSETP raise/abs then landed on the adjacent operand.)
                let dest_is_reg = optypes.first().map(|t| *t == "R" || *t == "UR").unwrap_or(false);
                let ra_tok = if dest_is_reg { (skip_preds + 2) as i32 } else { (skip_preds + 1) as i32 };
                let rb_tok = if dest_is_reg { (skip_preds + 3) as i32 } else { (skip_preds + 2) as i32 };
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
            ef_flags: table.ef_flags,
        })
    }
}

/// Recompute the prio-0 strict mask-match for a candidate (as in decode()'s
/// candidate filter). Used by select_best_candidate fallbacks: a heuristic may
/// only swap `first` for an alternative that ALSO strictly matches the word —
/// never for a weaker relaxed/prio3 match (e.g. DSETP AND,LT [prio0] must not
/// be displaced by LT,OR [prio3] through the trailing-pred heuristic).
fn cand_strict(c: &DecodeCandidate, code_clean: u128) -> bool {
    let guard_mask: u128 = 0xF000;
    (code_clean & c.match_mask & !guard_mask) == (c.and_base & c.match_mask & !guard_mask)
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

    // BUG-363: F2I R_UR harvest rows (UR-src sisters) claim the SAME window as
    // the _R_R keyed era rows on the shared FTZ lanes (`F2I_R_UR::FTZ,NTZ` /
    // `FTZ,NTZ,TRUNC,U32` x `F2I.FTZ[.U32[.TRUNC]].NTZ_R_R` on sm120/121a --
    // lane 0xf0 row pairs a live reg@16 dst with a ureg src, so the generic
    // score bonus routes R-sourced words to the UR print). nvdisasm's
    // canonical display on the shared window is the R form (arb341b G/H +
    // arb363, x4 models AGREE on every lane): when BOTH the _R_UR harvest row
    // and a _R_R keyed row match, prefer the _R_R row. Words authored through
    // the UR row still re-derive the same bits (shared window), so the UR
    // text path stays encodable; decode is vendor-true.
    if matches
        .iter()
        .any(|c| c.key.starts_with("F2I") && c.key.ends_with("_R_UR"))
    {
        if let Some(rr) = matches
            .iter()
            .copied()
            .find(|c| c.key.starts_with("F2I") && c.key.ends_with("_R_R"))
        {
            return Some(rr);
        }
    }

    // BRA mode is encoded in bits[33:32]: 0=plain, 1=U, 2=DIV, 3=CONV.
    // Broad legacy entries mask these bits and can otherwise outrank the
    // explicit dotted-opcode records by key length.
    if matches.iter().any(|candidate| candidate.key.starts_with("BRA")) {
        let mode_name = match (code_clean >> 32) & 0x3 {
            1 => Some("U"),
            2 => Some("DIV"),
            3 => Some("CONV"),
            _ => None,
        };
        let explicit_mode = |candidate: &DecodeCandidate, expected: &str| {
            candidate.key.split('_').next().unwrap_or("").split('.').skip(1)
                .any(|modifier| modifier == expected)
        };
        let grouped_mode = |candidate: &DecodeCandidate, expected: &str| {
            candidate.mod_group.split(',').any(|modifier| modifier.trim() == expected)
        };

        if let Some(expected) = mode_name {
            if let Some(candidate) = matches.iter().copied()
                .find(|candidate| explicit_mode(candidate, expected)) {
                return Some(candidate);
            }
            if let Some(candidate) = matches.iter().copied()
                .find(|candidate| grouped_mode(candidate, expected)) {
                return Some(candidate);
            }
        } else if let Some(candidate) = matches.iter().copied().find(|candidate| {
            !["U", "DIV", "CONV"].iter()
                .any(|mode| explicit_mode(candidate, mode) || grouped_mode(candidate, mode))
        }) {
            return Some(candidate);
        }
    }

    // Check if the first candidate has an OUTPUT predicate field (shift 80-85, tok 1-3).
    // This handles P-prefix InsKeys like LOP3_P_... where PT means "no pred result".
    // Deliberately exclude trailing pred fields (shift > 85) like IMAD_R_R_R_R's
    // pred@shift=87, which is NOT an output pred and shouldn't trigger this fallback.
    if let Some(entry) = table.get(&first.key, &first.mod_group) {
        for f in &entry.fields {
            if f.token_idx >= 1 && f.token_idx <= 3
                && f.shift >= 80 && f.shift <= 85
                && matches!(f.extraction, crate::table::Extraction::Pred
                        | crate::table::Extraction::UPred | crate::table::Extraction::PredInv4)
            {
                let mask = (1u64 << f.bits) - 1;
                let pred_val = ((code_clean >> f.shift) as u64) & mask;
                // PT = 7 for 3-bit pred, or 63/127 for wider pred
                let pt_val = mask; // all 1s = PT
                if pred_val == pt_val {
                    // The instruction has no real output predicate.
                    // Try to find a matching candidate without an output-pred operand.
                    for alt in matches {
                        if !cand_strict(alt, code_clean) { continue; }
                        if key_root(&alt.key) != key_root(&first.key) { continue; } // BUG-007
                        // BUG-012: underdiscovered `_?` keys have incomplete field
                        // coverage — diverting to them drops/halves operands (SHFL.BFLY
                        // dst [23:16] printed as [24:17], imm slot lost, phantom UR0).
                        if alt.key.ends_with("_?") || alt.key.contains("_?_") { continue; }
                        if !key_has_output_pred_field(&alt.key, &alt.mod_group, table) {
                            return Some(alt);
                        }
                    }
                }
                break; // Only check the first output-pred field
            }
        }
    }

    // BUG-083: the former "SHL disambiguation" (Rc==RZ => prefer mg SHL) was a
    // category error: plain `IMAD Rd, Rs, imm, RZ` (bit73=1, signed-id bit) also
    // carries Rc=RZ and was hijacked into `IMAD.SHL.U32 ... |Ra|` (4,080 uniq in
    // the 2049-cubin vendor census). SHL vs plain is fully decided by the row
    // masks (SHL,U32 requires bit73=0; '' requires bit73=1, prio0 beats the
    // sign-tolerant prio3 on ''), so no override is needed here.

    // Trailing pred disambiguation: if the instruction has a non-PT/non-!PT trailing
    // predicate at bits[90:87], prefer candidates with an explicit field covering those bits.
    // "Trailing" means shift in [87, 90] range (distinct from output pred at bits[83:81]).
    let trailing_pred_bits = (code_clean >> 87) & 0xF;  // 4 bits at [90:87]
    if trailing_pred_bits != 0x7 && trailing_pred_bits != 0xF {
        // If `first` already decodes a pred field on its LAST operand token
        // (any shift — e.g. SM103a DSETP AND,LT carries the combine pred at
        // [22:19], not [90:87]), nothing is lost: do not divert to a sibling
        // (e.g. LT,OR) just because it has a literal [90:87] field.
        let first_explains_trailing = table.get(&first.key, &first.mod_group)
            .map(|e| {
                let last_tok = parse_ins_key_op_types(&first.key).len() as i32;
                e.fields.iter().any(|f| {
                    f.token_idx >= last_tok
                        && matches!(f.extraction, crate::table::Extraction::Pred
                        | crate::table::Extraction::UPred | crate::table::Extraction::PredInv4)
                })
            })
            .unwrap_or(false);
        // For LEA/ULEA: prefer _P suffix variant whose trailing pred field has a
        // unique high token_idx (dedicated trailing-pred operand, not shared with
        // output pred). This avoids the _II variant where tok=2 is shared.
        let is_lea = first.key.starts_with("LEA_") || first.key.starts_with("ULEA_");
        if !first_explains_trailing {
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
                        f.shift >= 87 && matches!(f.extraction, crate::table::Extraction::Pred
                        | crate::table::Extraction::UPred | crate::table::Extraction::PredInv4)
                    });
                    if has_tp { return Some(candidate); }
                }
            }
        }
        // General fallback: any candidate with pred field at shift >= 87.
        for candidate in matches {
            if !cand_strict(candidate, code_clean) { continue; }
            if key_root(&candidate.key) != key_root(&first.key) { continue; } // BUG-007
            // BUG-012: the divert must stay inside the SAME mod_group — a sibling mg
            // is a different instruction variant whose discriminator bits also live at
            // [90:87] (BAR RED.OR stole SYNC words under the "trailing pred" claim).
            if candidate.mod_group != first.mod_group { continue; }
            if candidate.key.ends_with("_?") || candidate.key.contains("_?_") { continue; }
            if let Some(entry) = table.get(&candidate.key, &candidate.mod_group) {
                let has_trailing_pred = entry.fields.iter().any(|f| {
                    f.shift >= 87 && matches!(f.extraction, crate::table::Extraction::Pred
                        | crate::table::Extraction::UPred | crate::table::Extraction::PredInv4)
                });
                if has_trailing_pred {
                    // sm_121a inv4 convention: trailing window == 0 means "no
                    // guard pred" (PT) — diverting into the _P row would print
                    // a phantom ", PT". Skip inv4 candidates on zero window.
                    let inv4_zero = entry.fields.iter().any(|f| {
                        f.shift >= 87
                            && matches!(f.extraction, crate::table::Extraction::PredInv4)
                    }) && trailing_pred_bits == 0;
                    if inv4_zero { continue; }
                    return Some(candidate);
                }
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
    //
    // BUT: when the leading candidate already has ANY field covering [83:81] (e.g. the
    // ISETP/UISETP `_P_P` EX-form with a second dest-pred at tok5/6 on [83:81]), those
    // bits are semantically claimed by it and nothing is lost — do NOT divert to a
    // shorter sibling (e.g. plain `UISETP_UP_UP_UR_UR_UP`), which would drop the EX
    // operand and misrender the second pred slot as a fabricated `-URn`.
    let output_pred_bits = (code_clean >> 81) & 0x7;
    if output_pred_bits != 7 {  // P0..P6 = real output pred
        let first_covers = table.get(&first.key, &first.mod_group).map(|e| {
            e.fields.iter().any(|f| f.shift <= 81 && f.shift + f.bits >= 84)
        }).unwrap_or(false);
        if !first_covers {
        for candidate in matches {
            if !cand_strict(candidate, code_clean) { continue; }
            if key_root(&candidate.key) != key_root(&first.key) { continue; } // BUG-007
            if let Some(entry) = table.get(&candidate.key, &candidate.mod_group) {
                let has_output_pred = entry.fields.iter().any(|f| {
                    f.token_idx >= 1 && f.token_idx <= 3
                        && matches!(f.extraction, crate::table::Extraction::Pred
                        | crate::table::Extraction::UPred | crate::table::Extraction::PredInv4)
                        && f.shift >= 80 && f.shift <= 85
                });
                if has_output_pred {
                    return Some(candidate);
                }
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
                if !cand_strict(alt, code_clean) { continue; }
                if key_root(&alt.key) != key_root(&first.key) { continue; } // BUG-007
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
/// Opcode-family root of an InsKey (text up to the first '_' or '.').
/// Used to confine the disambiguation diverts below to SAME-family siblings:
/// the output/trailing/middle-pred diverts were built for LOP3_P_ vs LOP3_,
/// IMAD variants, LEA _P forms — but they once diverted an STG.E word to an
/// LDG.E.LTC128B key (BUG-007): the store's desc/size bits alias the
/// "output predicate" slot [83:81], the LDG candidate had a pred field there,
/// and the unscoped divert picked it, printing a load that never re-assembles
/// back. Cross-family diverts are never legitimate when both candidates match
/// the SAME word strictly: same-family preference is enforced instead.
fn key_root(key: &str) -> &str {
    let before_ops = key.split('_').next().unwrap_or(key);
    before_ops.split('.').next().unwrap_or(before_ops)
}

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
                crate::table::Extraction::Pred | crate::table::Extraction::UPred | crate::table::Extraction::PredInv4)
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
        // BUG-288: "bf16" is an immediate format too (HFMA2.BF16_V2 imm rows);
        // without it the armed keys lost the (II-slot x BF16-field) consistency
        // score and the decode route fell back to the II_FI_P "0x0" printer.
        let is_imm = ext_lower.starts_with("imm")
            || matches!(
                ext_lower.as_str(),
                "f32" | "f16" | "f16_d" | "f64hi" | "f32cast" | "bf16"
            );
        let is_barrier = ext_lower == "barrier";
        let expected_pred    = op_type == "P";
        let expected_upred   = op_type == "UP";
        let expected_reg     = matches!(op_type, "R" | "UR");
        let expected_imm     = matches!(op_type, "II" | "IM" | "LO" | "FI");
        let expected_barrier = op_type == "B";

        if (expected_pred && is_pred) || (expected_reg && is_reg) || (expected_imm && is_imm) { score += 2; }
        else if (expected_upred && is_upred) || (expected_barrier && is_barrier) { score += 4; } // UP/B slot with a matching field = strong match
        else if (expected_upred && is_pred) || (expected_pred && is_upred) { score -= 2; }
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
        Extraction::PredInv4 => "pred_inv4".into(),
        Extraction::UPredGate => "upred_gate".into(),
        Extraction::Imm => "imm".into(),
        Extraction::ImmShr(n) => format!("imm_shr{n}"),
        Extraction::Reuse => "reuse".into(),
        Extraction::Neg => "neg".into(),
        // BUG-251: NegAbs must not fall to the catch-all ("negabs" from Debug
        // lowercase never matches the printer's "neg_abs" arm) — the sm121a DSETP
        // rows' sign window would be silently dropped from decoded text.
        Extraction::NegAbs => "neg_abs".into(),
        // BUG-253: NegShl1 must not fall to the catch-all either ("negshl1"
        // never matches the printer's "neg_shl1" arm): the sm121a DFMA rows'
        // sign windows (tok3 2b@62 / tok4 2b@74; II_R/FI-RM/RP/UR_R forms)
        // were silently dropped from decoded text (61,436 uniq corpus words).
        Extraction::NegShl1 => "neg_shl1".into(),
        Extraction::F32 => "f32".into(),
        Extraction::F32Cast => "f32cast".into(),
        Extraction::F16d => "f16_d".into(),
        Extraction::SubR(n) => format!("sub_r{n}"),
        Extraction::SubUR(n) => format!("sub_ur{n}"),
        Extraction::SubImm(n) => format!("sub_imm{n}"),
        Extraction::SubRShr(n, s) => format!("sub_r{n}_shr{s}"),
        Extraction::SubURShr(n, s) => format!("sub_ur{n}_shr{s}"),
        Extraction::SubImmShr(n, s) => format!("sub_imm{n}_shr{s}"),
        Extraction::SubImmShrU(n, s) => format!("sub_imm{n}_shr{s}u"),
        Extraction::SubImmS24(n) => format!("sub_imm{n}_s24"),
        Extraction::OpaqueModifier => "opaque_mod".into(),
        Extraction::OpModFlag(n) => format!("opmod:{n}"),
        Extraction::HalfSel => "hsel".into(),
        Extraction::H0NH1 => "h0nh1".into(),
        Extraction::AddrScale => "addr_scale".into(),
        Extraction::BF16 => "bf16".into(),
        Extraction::MnemMod(i, n) => format!("mnemod{}:{}", i, n),
        Extraction::LblPat(p) => p.clone(),
        _ => format!("{:?}", e).to_lowercase(),
    }
}
