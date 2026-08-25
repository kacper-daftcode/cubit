//! BUG-131: FADD cluster in tables/sm120.json (a stale junk field behind a
//! decoder hole + toolchain load block). Three layers:
//! (a) FLEET BLOCKER [closed by merge c851e847; t131_3 = the pinning invariant]:
//!     FADD_R_L_R::{RZ,SAT} carried a junk field {shift:122, bits:8,
//!     token_idx:3, extraction:"reg"} -> 122+8=130 > 128 -> the post-hardening
//!     table validation rejected the WHOLE table at load (fleet: champion asm
//!     + ts2 corpus fail). The field = a degenerate tok3-reg import
//!     (the true tok3 geometry = 8b@[39:32], as in every R_R_R).
//! (b) A pre-existing DECODER HOLE (not a merge effect): the FADD.FTZ.RZ form
//!     (FTZ = bit80, RZ = bits[79:78]=0b11, base 0x221) had no group in
//!     sm120.json -> corpus slots decoded as `/* ? */`. Fix:
//!     a canonical "FTZ,RZ" mod group on FADD_R_R_R (and_base
//!     0x000000000001c0000000000000000221, the same 9 fields and mask as the
//!     RZ/FTZ siblings), evidence = 2 corpus cubins (cutlass
//!     70_blackwell_fp16_gemm.1 + 77_blackwell_mla_2sm_fp8, 4 vendor words).
//! (c) RESIDUAL after (a): with the junk field cut, the FADD_R_L_R::{RZ,SAT}
//!     rows were left with a WHOLLY missing tok3 field (decode = silent operand
//!     drop) AND a 0x04/0x05 bake in the tok3 window (count=1, harvest junk,
//!     the R_L_R sig contradicting the reg fields; zero *L forms in the 2051
//!     vendor-cubin corpus). Fix: REMOVE both junk groups; their canonical
//!     words decode through the correct FADD_R_R_R::{RZ,SAT} with a full tok3
//!     (t131_4). Corpus A/B evidence: the internal fix archive
//! Obserwacja pre-fix (raport 131.md; oddzielny kandydat BUG-132): encode
//! Pre-fix observation (report 131.md; a separate candidate BUG-132): pre-fix
//! encode of '@P1 FADD.FTZ.RZ ...' "passed" with bits 78..80
//! ZEROED (a silent mod-drop through the fallback lookup chain to the "" group;
//! the encoder/wrong-code class). Pre-fix control (HEAD 32ac8108): t131_1/2
//! FAIL (the hole), t131_3 PASS (invariant), t131_4 PASS (FADD_R_R_R
//! won anyway; behavior strengthened after the junk-group removal).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

/// Real vendor words from the cutlass corpus (sm120 table).
const GOLD: &[(u128, &str)] = &[
    (0x000fe2000000c0000000000a0d151221u128, "@P1 FADD.RZ R21, R13, R10"),
    (0x000fe2000000c0000000000a13121221u128, "@P1 FADD.RZ R18, R19, R10"),
    (0x000fe4000001c0000000001a1b221221u128, "@P1 FADD.FTZ.RZ R34, R27, R26"),
    (0x000fe2000001c0000000000a13161221u128, "@P1 FADD.FTZ.RZ R22, R19, R10"),
];

#[test]
fn t131_1_decode_render_reencode_vendor_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let mut fails = Vec::new();
    for &(word, golden) in GOLD {
        let d = match idx.decode(word, 0, &t) {
            Ok(d) => d,
            Err(e) => { fails.push(format!("word {word:032x}: decode fail: {e}")); continue; }
        };
        let text = cubit::printer::to_sass(&d);
        if text != golden {
            fails.push(format!("word {word:032x}: render {text:?} != golden {golden:?}"));
            continue;
        }
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        let e = t.get(&d.key, &d.mod_group).unwrap();
        let mut fm: u128 = 0;
        for f in &e.fields {
            if f.extraction == cubit::table::Extraction::None { continue; }
            fm |= ((1u128 << f.bits) - 1) << f.shift;
        }
        let keep = (!e.variable_mask | fm) & !SCHED;
        if (w2 & keep) != (word & keep) {
            fails.push(format!("re-encode diff {w2:032x} vs {word:032x} (keep {keep:032x})"));
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn t131_2_ftzrz_routes_to_canonical_group() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(GOLD[2].0, 0, &t).expect("decode FTZRZ3");
    assert_eq!(d.key, "FADD_R_R_R");
    assert_eq!(d.mod_group, "FTZ,RZ");
}

/// Invariant (a): every table must load (fail-closed validation
/// klasy "field outside 128-bit" pokrywa wszystkie wiersze przy load).
#[test]
fn t131_3_all_tables_load_no_field_outside_128() {
    for tab in ["tables/sm120.json", "tables/sm103a.json"] {
        IsaTable::load(std::path::Path::new(tab))
            .unwrap_or_else(|e| panic!("{tab} must load: {e}"));
    }
}

/// Invariant (c): with the junk groups removed, their canonical words decode
/// through the correct rows with a FULL tok3 (zero operand drop).
#[test]
fn t131_4_junk_canonical_words_full_render() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(word, want) in &[
        (0x000fe2000000c0000000000400000221u128, "@P0 FADD.RZ R0, R0, R4"),
        (0x000fe200000020000000000500000221u128, "@P0 FADD.SAT R0, R0, R5"),
    ] {
        let d = idx.decode(word, 0, &t)
            .unwrap_or_else(|e| panic!("decode junk-canon 0x{word:032x}: {e}"));
        assert_eq!(cubit::printer::to_sass(&d), want);
        assert_eq!(d.key, "FADD_R_R_R");
    }
}
