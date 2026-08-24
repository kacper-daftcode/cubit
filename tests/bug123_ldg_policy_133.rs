//! BUG-123 (F2-Q, depozyt loop5 DESCCAMP-D1 iter52, severity b4-klasy):
//! swieze formy cache-policy nvcc-13.3 (sm_103a) dekodowaly sie jako "?" /
//! !rsd, a enkoder nie mial wierszy. Klasa zoknknieta w calosci po stronie
//! D1-korpusu + sweepu (work/bug123/sweep.ptx, ptxas 13.3.73):
//!
//!   * II-wiersze .256 z trailer-imm (LDG_R_R_dARI_II — NOWY klucz):
//!       256,E,EL,ENL2 / 256,E,EF,ENL2 / 256,E,ENL2,LTC256B /
//!       256,CONSTANT,E,ENL2,LTC256B
//!     geometria trailer-imm: imm[5:0]@57 (pole 6b, no-imm default 0x3f)
//!     + imm_shr7[7]@72 -> druk ", 0x93"/", 0x83"/", 0x81"/", 0x1".
//!     Formy no-imm (pole=0x3f, bit72=1) = osobne wiersze 4-tokenowe —
//!     disambiguacja tylko przez klucz (liczba tokenow), zero kolizji w
//!     match_mask (noimm wymaga [57:63]=0x7f & bit72=1 stanami stalymi).
//!   * noimm .256 polityki na LDG_R_R_dARI: 256,E,EL,ENL2 / 256,E,EF,ENL2 /
//!     256,E,ENL2,EU (nibble b10: ENL2=0x12, EL=0x22, EF=0x02, EU=0x42).
//!   * STG_dARI_R_R: 256,E,EF,ENL2 (EF = clear bit84 jak po stronie LDG).
//!   * single-reg LDG_R_dARI: E,LU / 128,E,LU / E,EL / 128,E,EL / 64,E,EL /
//!     E,NA / E,EU (b10 nibble swap ze wzorca; 128/64 = b9 size jak siostry).
//!   * LTC marker (b8 hi-nibble 0x10/0x20/0x30; CONSTANT=bit79):
//!     E,LTC64B / E,LTC256B / CONSTANT,E,LTC128B / 64,CONSTANT,E,LTC64B.
//!   * printer: EU dodane do bucketa L1-hint (LDG.E.EU.ENL2.256, bylo
//!     LDG.E.ENL2.EU.256 — render-parity b11 pernvidisam).
//!
//! Wszystkie teksty = nvdisasm-13.3 golden (korpus pol*+sweep, 904 slow);
//! wszystkie slowa krzemiowo OK (D1 matrix.json, run_legality). Raport:
//! results/cubitfix/123.md.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn enc103(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t103()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}
fn dec103(word: u128) -> String {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(word, 0, &t).expect("decode failed");
    to_sass(&d)
}
const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// (slowo, tekst nvdisasm-13.3) — golden korpus pol*/sweep (LE-int 128b).
const GOLD: &[(u128, &str)] = &[
    (0x000ee8000822191026000104020e797e, "LDG.E.EL.ENL2.256 R16, R14, desc[UR4][R2.64+0x20], 0x93"),
    (0x001ea800082218ff020000040200797e, "LDG.E.EL.ENL2.256 RZ, R0, desc[UR4][R2.64], 0x1"),
    (0x001ea80008021900060000040206797e, "LDG.E.EF.ENL2.256 R0, R6, desc[UR4][R2.64], 0x83"),
    (0x000ea200080218ff020001040207797e, "LDG.E.EF.ENL2.256 RZ, R7, desc[UR4][R2.64+0x20], 0x1"),
    (0x001eaa0008129f03020000040202797e, "LDG.E.ENL2.LTC256B.256.CONSTANT R3, R2, desc[UR4][R2.64], 0x81"),
    (0x001eaa0008129f05020002040404797e, "LDG.E.ENL2.LTC256B.256.CONSTANT R5, R4, desc[UR4][R4.64+0x40], 0x81"),
    (0x001eaa0008129eff020000040203797e, "LDG.E.ENL2.LTC256B.256.CONSTANT RZ, R3, desc[UR4][R2.64], 0x1"),
    (0x000ea20008121eff020001040207797e, "LDG.E.ENL2.LTC256B.256 RZ, R7, desc[UR4][R2.64+0x20], 0x1"),
    (0x001eaa000822190cfe0000040208797e, "LDG.E.EL.ENL2.256 R12, R8, desc[UR4][R2.64]"),
    (0x001eaa000802190cfe0000040208797e, "LDG.E.EF.ENL2.256 R12, R8, desc[UR4][R2.64]"),
    (0x001eaa000842190cfe0000040208797e, "LDG.E.EU.ENL2.256 R12, R8, desc[UR4][R2.64]"),
    (0x004fe2000f021804f8000008040c797f, "STG.E.EF.ENL2.256 desc[UR4][R4.64], R8, R12"),
    (0x001ea8000c3e19000000000402007981, "LDG.E.LU R0, desc[UR4][R2.64]"),
    (0x000ea8000c3e19000000080402077981, "LDG.E.LU R7, desc[UR4][R2.64+0x8]"),
    (0x000f22000c3e1d000000400402087981, "LDG.E.LU.128 R8, desc[UR4][R2.64+0x40]"),
    (0x001ea8000c2e19000000000402007981, "LDG.E.EL R0, desc[UR4][R2.64]"),
    (0x000ea8000c2e190000000c0402097981, "LDG.E.EL R9, desc[UR4][R2.64+0xc]"),
    (0x001eaa000c2e1b000000000402027981, "LDG.E.EL.64 R2, desc[UR4][R2.64]"),
    (0x001eaa000c2e1d000000000402087981, "LDG.E.EL.128 R8, desc[UR4][R2.64]"),
    (0x000ea2000c5e19000000080402067981, "LDG.E.NA R6, desc[UR4][R2.64+0x8]"),
    (0x001ea8000c4e19000000080402067981, "LDG.E.EU R6, desc[UR4][R2.64+0x8]"),
    (0x000ea8000c1e19300000040402077981, "LDG.E.LTC256B R7, desc[UR4][R2.64+0x4]"),
    (0x000ea2000c1e19100000080402067981, "LDG.E.LTC64B R6, desc[UR4][R2.64+0x8]"),
    (0x001ea8000c1e99200000000402007981, "LDG.E.LTC128B.CONSTANT R0, desc[UR4][R2.64]"),
    (0x000ea2000c1e992000000c0402077981, "LDG.E.LTC128B.CONSTANT R7, desc[UR4][R2.64+0xc]"),
    (0x001eaa000c1e9b100000000402027981, "LDG.E.LTC64B.64.CONSTANT R2, desc[UR4][R2.64]"),
];

/// t123_1: kazde golden-slowo dekoduje sie do DOKLADNEGO tekstu nvdisasm-13.3
/// (render-parity; brak "?" i brak !rsd).
#[test]
fn t123_1_decode_golden_words_to_nvdisasm_text() {
    for (w, want) in GOLD {
        let got = dec103(*w);
        let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
        assert_eq!(&got, want, "decode parity dla {w:#034x}");
        assert!(!got.contains("!rsd"), "zero lossy-markerow: {got}");
    }
}

/// t123_2: encode kazdego tekstu golden == slowo golden (maska ctrl>=96;
/// sched z krzemu jadrem testa niegenerowany — porownanie na payload).
#[test]
fn t123_2_encode_golden_texts_byte_exact() {
    for (w, text) in GOLD {
        let got = enc103(text);
        assert_eq!(got & NOSCHED, w & NOSCHED,
                   "encode {text:?}: payload musi byc bajt-w-bajt golden: \
                    got {got:#034x} want {w:#034x}");
    }
}

/// t123_3: roundtrip text->word->text stabilny (parse+encode+decode+render).
#[test]
fn t123_3_roundtrip_text_stable() {
    for (_, text) in GOLD {
        let w = enc103(text);
        let got = dec103(w);
        let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
        assert_eq!(&got, text, "roundtrip {text:?}");
    }
}

/// t123_4: disambiguacja noimm vs II — slowo noimm NIE dostaje trailer-imm
/// (pole [57:62]=0x3f+bit72=1 renderuje sie bez ", 0xbf"), forma z trailerem
/// laduje w kluczu II. Oba teksty enc/roundtrip byte-exact.
#[test]
fn t123_4_noimm_ii_disambiguation() {
    let noimm = 0x001eaa000822190cfe0000040208797eu128;
    let got = dec103(noimm);
    assert!(!got.trim_end_matches(';').trim().ends_with(", 0xbf"),
            "noimm text bez trailer-imm 0xbf: {got}");
    let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
    assert_eq!(got, "LDG.E.EL.ENL2.256 R12, R8, desc[UR4][R2.64]");
    // II-form dostaje swoj klucz i trailer
    let w = enc103("LDG.E.EL.ENL2.256 R16, R14, desc[UR4][R2.64+0x20], 0x93");
    assert_eq!(w & NOSCHED, 0x000ee8000822191026000104020e797eu128 & NOSCHED);
}

/// t123_5: geometria trailer-imm — imm[5:0]@57 + imm_shr7[7]@72
/// (kompozycja 0x93 = 0x80|0x13 w pinie; guard-reszta klasy w t123_1).
#[test]
fn t123_5_trailer_imm_geometry() {
    let w = enc103("LDG.E.EF.ENL2.256 R0, R6, desc[UR4][R2.64], 0x83");
    assert_eq!((w >> 57) & 0x3f, 0x03, "imm lo6 @57: {w:#034x}");
    assert_eq!((w >> 72) & 1, 1, "imm bit7 @72: {w:#034x}");
    let w2 = enc103("LDG.E.EL.ENL2.256 RZ, R0, desc[UR4][R2.64], 0x1");
    assert_eq!((w2 >> 57) & 0x3f, 0x01);
    assert_eq!((w2 >> 72) & 1, 0, "prefetch 0x1: bit72=0: {w2:#034x}");
    // bit63 zostaje 0 (stan II-formy; noimm default 0x3f+bit72=1 NIE jest
    // akceptowalny w wierszach II przez match_mask)
    assert_eq!((w >> 63) & 1, 0);
    assert_eq!((w2 >> 63) & 1, 0);
}

/// t123_6 (kotwica printera): EU w bucket L1-hint — render-parity
/// LDG.E.EU.ENL2.256 (regresja: LDG.E.ENL2.EU.256).
#[test]
fn t123_6_eu_mod_order_render_parity() {
    let w = 0x001eaa000842190cfe0000040208797eu128;
    let got = dec103(w);
    let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
    assert_eq!(got, "LDG.E.EU.ENL2.256 R12, R8, desc[UR4][R2.64]");
}

/// t123_7 (kotwica): policy nibbles rozdzielcze w match_mask — .256 noimm
/// wiersze sa parami rozlaczne (EL wymaga bit85, EU bit86, EF !bit84),
/// a II-vs-noimm siostry nie koliduja (sprawdzone t123_4).
/// Tu: klucz II istnieje z 4 wierszami, nowe single-reg mody obecne.
#[test]
fn t123_7_table_shape_anchor() {
    let t = t103();
    let ii = t.entries.get("LDG_R_R_dARI_II").expect("klucz II");
    for m in ["256,E,EL,ENL2", "256,E,EF,ENL2", "256,E,ENL2,LTC256B",
              "256,CONSTANT,E,ENL2,LTC256B"] {
        assert!(ii.mod_groups.contains_key(m), "II mod {m}");
    }
    let rr = t.entries.get("LDG_R_R_dARI").expect("klucz noimm");
    for m in ["256,E,EL,ENL2", "256,E,EF,ENL2", "256,E,ENL2,EU"] {
        assert!(rr.mod_groups.contains_key(m), "noimm mod {m}");
    }
    let r = t.entries.get("LDG_R_dARI").expect("LDG_R_dARI");
    for m in ["E,LU", "128,E,LU", "E,EL", "128,E,EL", "64,E,EL", "E,NA",
              "E,EU", "E,LTC64B", "E,LTC256B", "CONSTANT,E,LTC128B",
              "64,CONSTANT,E,LTC64B"] {
        assert!(r.mod_groups.contains_key(m), "single mod {m}");
    }
    let s = t.entries.get("STG_dARI_R_R").expect("STG_dARI_R_R");
    assert!(s.mod_groups.contains_key("256,E,EF,ENL2"));
}
