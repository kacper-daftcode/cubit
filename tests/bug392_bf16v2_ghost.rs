//! BUG-392 pins (F2-iter213, loop5/blind front2, 2026-09-06): decoder
//! generic sign post-pass (ghost arm) token misplacement -- naive
//! `key.split('_').skip(1)` op-type algebra left a non-op head component
//! ('V2.RELU' / 'AB' / 'P0') as fake op-types[0] on multi-component dotted
//! prefixes, so ghost ra/rb shifted one token left and neg@63/abs@62/
//! neg@72/abs@73 were PRINTED ON THE WRONG OPERAND = silent wrong-text
//! decode of vendor-legal words. Fix: robust parse_ins_key_op_types
//! algebra + reg-class guard (BUG-392b: ghost signs never attach to
//! II/FI-typed slots -- there they are immediate payload, vendor re-reads
//! them inside the imm, e.g. '+INF'/'-1').
//!
//! MEASUREMENT (pre-fix publish cubit_py-964a321f, canonical 2285a05;
//! work/bug392/): extent392_pre 230/532 MISS x4 legs across every
//! BF16_V2-named dotted reg-family key (R_R_R_R_P / R_R_UR_R_P /
//! R_R_R_UR_P x RELU/FMZ/FTZ/OOB axes); extent392_post = 94 residual,
//! EXACT SUBSET of pre, ALL in two pre-existing classes pinned open as
//! registrations: 405-kand (dense HADD2 claim-preempt of II_FI/FI_FI
//! dotted words, () base rows MISS already pre) and 406-kand
//! (HFMA2.BF16_V2_R_R_II_II_R imm-slot era-bake, () base MISS on sm121a).
//! CURED = 136/136 vendor-legal cells (extent392_pre vs post set diff).
//! audit392 (36-mg main-family x 13 probes x x4 legs = 1872 cells) +
//! audit392_mint (216 authored mints, x4-ident + vendor-cross + roundtrip)
//! = MATCH 100% pre and post = ghost path covers the main family both
//! sides already pre (392-kand's "sparse HOLE" premise measured FALSE
//! post-381: the HOLE was mg-key absence, cured by the 381 graft).
//! corpus392: battery 2,406 cubins, 50,868 family words, ZERO sign-bit
//! carriers => fix is corpus-invisible.
//! Encode side: NOT touched (parser-anchored minting was measured
//! correct pre on the same authored texts).
//! Witness data: work/bug392/pin392data.json + gen392data.py.

use cubit::decoder::DecodeIndex;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}

include!("bug392_data.inc");

/// t392_1: every cured ghost-misplacement cell decodes to the vendor text.
/// (136 cells; texts verbatim nvdisasm x4 AGREE from extent392_pre.)
#[test]
fn t392_1_cured_cells_vendor_text() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (li, w, ven) in CURED {
        let got = dec96(&tabs[li], w).expect("cured cell must decode (no HOLE)");
        let got = got.trim_end_matches(';').trim().to_string();
        assert_eq!(got, ven, "leg {} word 0x{w:024x}", LEGS4[li]);
    }
}

/// t392_2: reg-class guard -- on the II-imm-slot key the sign bits are
/// immediate payload; decoded fields may NOT carry ghost neg/abs on any
/// II-typed token (tok3 for R_R_II_II). (406 imm-bake itself stays open.)
#[test]
fn t392_2_ii_slot_no_ghost_sign() {
    let t = tab("sm120");
    let idx = DecodeIndex::build(&t);
    for (w, b_lo, b_hi) in GUARD406 {
        let d = match idx.decode(w & M96, 0, &t) {
            Ok(d) => d,
            Err(_) => continue, // HOLE is acceptable posture for imm artifacts
        };
        for f in &d.fields {
            if (f.extraction == "neg" || f.extraction == "abs")
                && (f.shift == 62 || f.shift == 63)
                && f.value != 0
            {
                panic!(
                    "ghost sign on II slot: word 0x{w:024x} bits {b_lo}..{b_hi} field tok{} @{}",
                    f.token_idx, f.shift
                );
            }
        }
    }
}

/// t392_3: main-family sign witnesses stay vendor-exact (regression of the
/// 36-mg ghost path that part-A measured MATCH 100% pre and post).
#[test]
fn t392_3_main_family_spots() {
    for (w, ven) in A_SPOT {
        for leg in LEGS4 {
            let t = tab(leg);
            let got = dec96(&t, w).expect("main-family spot must decode");
            assert_eq!(
                got.trim_end_matches(';').trim(),
                ven,
                "leg {leg} word 0x{w:024x}"
            );
        }
    }
}

/// t392_4: field-level proof of token placement -- sign fields of the
/// dotted BF16_V2 RELU family now attach to the SAME token the text
/// carries them on (tok2 for 72/73, tok3 for 62/63), x4 legs.
#[test]
fn t392_4_field_token_placement() {
    // HFMA2.BF16_V2.RELU_R_R_R_R_P and_base (same value on x4 legs)
    let ab: u128 = 0x000e8000002000000000000000072311 & M96; // placeholder, replaced below
    let _ = ab;
    let tabs_raw: Vec<serde_json::Value> = LEGS4
        .iter()
        .map(|a| {
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{a}.json")).unwrap())
                .unwrap()
        })
        .collect();
    for (li, leg) in LEGS4.iter().enumerate() {
        let ab_s = tabs_raw[li]["instructions"]["HFMA2.BF16_V2.RELU_R_R_R_R_P"]["mod_groups"][""]
            ["and_base"]
            .as_str()
            .unwrap();
        let ab = u128::from_str_radix(ab_s.trim_start_matches("0x"), 16).unwrap();
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (bit, want_tok, want_ext) in [
            (63u32, 3i32, "neg"),
            (62, 3, "abs"),
            (72, 2, "neg"),
            (73, 2, "abs"),
        ] {
            let w = ab | (1u128 << bit);
            let d = idx.decode(w & M96, 0, &t).expect("decodes");
            let hit = d
                .fields
                .iter()
                .find(|f| f.extraction == want_ext && f.shift == bit && f.value == 1);
            assert!(hit.is_some(), "{leg} bit{bit}: sign field missing");
            assert_eq!(
                hit.unwrap().token_idx,
                want_tok,
                "{leg} bit{bit} wrong token"
            );
        }
    }
}

/// t392_5: encode-side spot -- authored signs mint the SAME word vendor
/// reads back (parser-anchored emission unchanged by the decode fix), and
/// decode-back returns the authored text (full circle).
#[test]
fn t392_5_mint_circle() {
    use cubit::encoder::encode_instruction;
    use cubit::parser::parse_sass;
    let cases: [&str; 4] = [
        "HFMA2.BF16_V2.RELU R2, -R3, R4, R5, P0",
        "HFMA2.BF16_V2.RELU R2, R3, -R4, R5, P0",
        "HFMA2.BF16_V2.FMZ.RELU R2, R3, -|R4|, R5, P0",
        "HFMA2.SAT R2, -R3, R4, R5",
    ];
    for leg in LEGS4 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for auth in cases {
            let insn = parse_sass(auth, 0).unwrap();
            let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("{leg}: mint {auth}"));
            let back = idx.decode(w & M96, 0, &t).map(|d| to_sass(&d)).unwrap();
            let back = back.trim_end_matches(';').trim().to_string();
            assert_eq!(back, auth, "{leg}: mint circle {auth}");
        }
    }
}
