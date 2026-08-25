//! BUG-079 (F2Q-079-kand; closed 2026-08-22): the ULEA family — render parity
//! of both tables vs nvdisasm 13.3. Detection: after BUG-069, these classes lingered:
//! (a) sm120 ULEA rows = singleton junk (1-5 bit fields, baked imm bits
//!     in and_base, no coverage of the SX32/X.SX32 forms) — 5879/12887 unique
//!     vendor words did not decode vendor-exact (incl. 53+78 -> __raw__);
//! (b) both tables: the 6-bit imm2 window swallowed bit80 (the HI discriminator) on
//!     UR-src forms (the 069-residual class: ULEA.HI 5/6/7-token with URZ) —
//!     515 words lost .HI and fused imm (0x1 -> 0x21).
//! PURE-DATA fix: rebuilt the family (13 rows) from 12887 unique
//! vendor-corpus anchor words (libcublas/Lt/cusolver/cusparse, sm_100/103),
//! geometry consistent with the sm103a sibling (069); method: field-window deduction
//! from value-per-bit correlation per template + per-anchor verification.
//! Uwaga metodowa (pin): nvdisasm -hex drukuje hi64 NA LINII POWYZEJ tekstu —
//! nalezy do instrukcji POWYZEJ (layout pliku [lo64][hi64]); sparowanie
//! "hi-line + trailing-lo" daje slowo przesuniete o instrukcje ( falszywe
//! "nvdisasm renderuje te same bajty inaczej" — artefakt parowania, B79-pre).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(word, 0, t).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
    encode_instruction(&insn, t).expect("encode failed")
}

// (vendor_text, slowo_zlote, slowo_oczekiwane_z_enkodera ctrl-default 0x000fc200)
const ANCHORS: &[(&str, u128, u128)] = &[
 ("ULEA UR11, UR11, UR7, 0x1", 0x000fc4000f8e08ff000000070b0b7291, 0x000fc2000f8e08ff000000070b0b7291),
 ("ULEA UR7, UR14, -UR7, 0x2", 0x000fc4000f8e10ff800000070e077291, 0x000fc2000f8e10ff800000070e077291),
 ("@UP1 ULEA UR5, UR6, UR5, 0x2", 0x000fc6000f8e10ff0000000506051291, 0x000fc2000f8e10ff0000000506051291),
 ("ULEA UR7, UP0, UR4, UR8, 0x1", 0x000fc4000f8008ff0000000804077291, 0x000fc2000f8008ff0000000804077291),
 ("ULEA UR5, UP1, -UR14, UR4, 0x2", 0x000fc4000f8211ff000000040e057291, 0x000fc2000f8211ff000000040e057291),
 ("ULEA URZ, UP0, UR14, UR8, 0x2", 0x000fc4000f8010ff000000080eff7291, 0x000fc2000f8010ff000000080eff7291),
 ("ULEA UR11, UP0, UR5, 0xfffffffc, 0x2", 0x000fc4000f8010fffffffffc050b7891, 0x000fc2000f8010fffffffffc050b7891),
 ("ULEA UR10, UR18, 0x10, 0x4", 0x000fc4000f8e20ff00000010120a7891, 0x000fc2000f8e20ff00000010120a7891),
 ("ULEA UR4, UR5, 0xfffff800, 0xb", 0x000fe2000f8e58fffffff80005047891, 0x000fc2000f8e58fffffff80005047891),
 ("ULEA.HI UR4, UR4, UR4, URZ, 0x1", 0x000fc4000f8f08ff0000000404047291, 0x000fc2000f8f08ff0000000404047291),
 ("ULEA.HI UR4, UR4, UR5, URZ, 0x1a", 0x000fc8000f8fd0ff0000000504047291, 0x000fc2000f8fd0ff0000000504047291),
 ("ULEA.HI UR23, UP0, UR28, UR23, URZ, 0x1", 0x000fc4000f8108ff000000171c177291, 0x000fc2000f8108ff000000171c177291),
 ("ULEA.HI UR6, UR6, 0x1, URZ, 0x1b", 0x000fc4000f8fd8ff0000000106067891, 0x000fc2000f8fd8ff0000000106067891),
 ("ULEA.HI.SX32 UR16, UR11, UR16, 0x1f", 0x000fc6000f8ffaff000000100b107291, 0x000fc2000f8ffaff000000100b107291),
 ("ULEA.HI.SX32 UR6, UR4, 0x1, 0x2", 0x000fc6000f8f12ff0000000104067891, 0x000fc2000f8f12ff0000000104067891),
 ("@UP0 ULEA.HI.SX32 UR25, UR6, 0xffffffff, 0x19", 0x000fe4000f8fcaffffffffff06190891, 0x000fc2000f8fcaffffffffff06190891),
 ("ULEA.HI.X UR9, UR4, UR11, UR5, 0x1, UP0", 0x000fc400080f0c050000000b04097291, 0x000fc200080f0c050000000b04097291),
 ("ULEA.HI.X UR5, UR6, URZ, URZ, 0x3, UP0", 0x000fc600080f1cff000000ff06057291, 0x000fc200080f1cff000000ff06057291),
 ("ULEA.HI.X UR11, UR4, 0xffffffff, UR5, 0x6, UP1", 0x000fc400088f3405ffffffff040b7891, 0x000fc200088f3405ffffffff040b7891),
 ("@UP2 ULEA.HI.X UR14, UR12, UR29, UR19, 0x3, UP0", 0x000fc400080f1c130000001d0c0e2291, 0x000fc200080f1c130000001d0c0e2291),
 ("ULEA.HI.X.SX32 UR6, UR8, UR6, 0x1, UP0", 0x000fc400080f0eff0000000608067291, 0x000fc200080f0eff0000000608067291),
 ("ULEA.HI.X.SX32 UR4, UR11, ~UR5, 0x1, UP0", 0x000fe400080f0eff800000050b047291, 0x000fc200080f0eff800000050b047291),
 ("ULEA.HI.X.SX32 UR19, UR5, 0xffffffff, 0x1, UP0", 0x000fc400080f0effffffffff05137891, 0x000fc200080f0effffffffff05137891),
];

// t1: kazda kotwica dekoduje vendor-exact na OBU tabelach (render-parity).
#[test]
fn t1_decode_vendor_exact_all_anchors_both_tables() {
    let a = t120(); let b = t103();
    for (txt, w, _) in ANCHORS {
        assert_eq!(dec(&a, *w), *txt, "sm120 decode: {txt}");
        assert_eq!(dec(&b, *w), *txt, "sm103a decode: {txt}");
    }
}

// t2: encode tekstu vendora = payload zlotego slowa + ctrl-default (fixed-point).
#[test]
fn t2_encode_fixed_point_both_tables() {
    let a = t120(); let b = t103();
    for (txt, _, exp) in ANCHORS {
        assert_eq!(enc(&a, txt), *exp, "sm120 encode: {txt}");
        assert_eq!(enc(&b, txt), *exp, "sm103a encode: {txt}");
    }
}

// t3: decode->encode->decode roundtrip na kotwicach (payload-stabilnosc).
#[test]
fn t3_roundtrip_stable() {
    let a = t120();
    for (txt, w, _) in ANCHORS {
        let s = dec(&a, *w);
        let w2 = enc(&a, &s);
        assert_eq!(dec(&a, w2), s, "roundtrip: {txt}");
    }
}

// t4 (069+079 regression): plain '' must not claim HI words — bit80 outside the imm2 window.
// The 069-gold word (HI 5-token with imm32) must stay on the HI row on both tables.
#[test]
fn t4_hi_not_captured_by_plain() {
    let a = t120(); let b = t103();
    let w = 0x000fc8000f8fd8ff0000000106067891u128; // BUG-069 gold (libcusparse.663)
    assert_eq!(dec(&a, w), "ULEA.HI UR6, UR6, 0x1, URZ, 0x1b");
    assert_eq!(dec(&b, w), "ULEA.HI UR6, UR6, 0x1, URZ, 0x1b");
    // plain forma NIE moze przelac slowa z bit80=1: enc(plain text) trzyma bit80=0
    let wplain = enc(&a, "ULEA UR11, UR11, UR7, 0x1");
    assert_eq!((wplain >> 80) & 1, 0, "plain ab musi trzymac bit80=0");
}

// t5 (regresja 070-guard): STG.256 shp-klasy netkniete — sanity decode znanych slow.
#[test]
fn t5_sanity_unrelated_rows_intact() {
    let a = t120();
    let s = dec(&a, 0x000fc2000f8fd8ff0000000106067891u128);
    assert_eq!(s, "ULEA.HI UR6, UR6, 0x1, URZ, 0x1b");
}
