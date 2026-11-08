//! BUG-123: fresh nvcc-13.3 (sm_103a) cache-policy forms decoded as "?" /
//! !rsd, and the encoder had no rows. Class fixed in full.
//! D1 corpus + sweep (work/bug123/sweep.ptx, ptxas 13.3.73):
//!
//!   * the .256 II rows with the trailing immediate (LDG_R_R_dARI_II — a NEW key):
//!     256,E,EL,ENL2 / 256,E,EF,ENL2 / 256,E,ENL2,LTC256B /
//!     256,CONSTANT,E,ENL2,LTC256B
//!     the trailing-imm geometry: imm[5:0]@57 (a 6-bit field, the no-imm default 0x3f)
//!     + imm_shr7[7] -> printing ", 0x93"/", 0x83"/", 0x81"/", 0x1".
//!       No-imm forms (field=0x3f, bit72=1) = separate 4-token rows —
//!       disambiguation purely by key (token count), zero match_mask collisions
//!       (noimm requires [57:63]=0x7f & bit72=1 as fixed states).
//!   * noimm .256 policies on LDG_R_R_dARI: 256,E,EL,ENL2 / 256,E,EF,ENL2 /
//!     256,E,ENL2,EU (b10 nibble: ENL2=0x12, EL=0x22, EF=0x02, EU=0x42).
//!   * STG_dARI_R_R: 256,E,EF,ENL2 (EF = clear bit84 as on the LDG side).
//!   * single-reg LDG_R_dARI: E,LU / 128,E,LU / E,EL / 128,E,EL / 64,E,EL /
//!   * LTC marker (b8 hi-nibble 0x10/0x20/0x30; CONSTANT=bit79):
//!     E,LTC64B / E,LTC256B / CONSTANT,E,LTC128B / 64,CONSTANT,E,LTC64B.
//!   * printer: EU added to the L1-hint bucket (LDG.E.EU.ENL2.256; it was
//!     LDG.E.ENL2.EU.256 — render parity with nvdisasm, b11).
//!
//! Every text = the nvdisasm 13.3 golden (the pol* corpus + the sweep, 904 words);
//! every word silicon-OK (D1 matrix.json, run_legality). Report:
//! the internal fix archive

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
/// (render parity; no "?" and no !rsd).
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

/// t123_4: noimm vs II disambiguation — a noimm word does NOT get a trailer imm
/// (field [57:62]=0x3f+bit72=1 renders without ", 0xbf"), the trailer form
/// laduje w kluczu II. Oba teksty enc/roundtrip byte-exact.
#[test]
fn t123_4_noimm_ii_disambiguation() {
    let noimm = 0x001eaa000822190cfe0000040208797eu128;
    let got = dec103(noimm);
    assert!(!got.trim_end_matches(';').trim().ends_with(", 0xbf"),
            "noimm text bez trailer-imm 0xbf: {got}");
    let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
    assert_eq!(got, "LDG.E.EL.ENL2.256 R12, R8, desc[UR4][R2.64]");
    // the II form gets its key and trailer
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
    // bit63 stays 0 (the II-form state; the noimm default 0x3f+bit72=1 is NOT
    // acceptable in II rows via match_mask)
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
/// and the II-vs-noimm sisters do not collide (checked in t123_4).
/// Tu: klucz II istnieje z 4 wierszami, nowe single-reg mody obecne.
#[test]
fn t123_7_table_shape_anchor() {
    let t = t103();
    // RIDE475R3b-w3 (INC-291a, TESTS-ONLY): kotwice ENL2 ltc=0 na
    // widthless kluczach usuniete swiadomie przez 475-R2 (defekt okien
    // 462-mgs; arb475r3 27-sond MIS x4). Klase pokrywaly dedykowane
    // klucze graftu 475 (R1 lattice + R3 NA/EU restore).
    // 2026-11-08 (T-21 batch 4; tools/probes/re_sm120_ldg256.py --form dARI --arch SM103 and
    // tools/probes/re_sm120_stg256.py --arch SM103, nvdisasm 13.1 -- every form word prints the SM120 text):
    // the 256-bit descriptor forms are measured whole on sm103a, as on sm120 since G's batches 10 / 13 --
    // `LDG_R_R_dARI[_II]` carry 1 152 measured groups each (the 475-R2 "deleted" EL / EF / EU ENL2 groups are legal
    // words the vendor names; the 2026-09 deletion stood on the harvest's window defect), `STG_dARI_R_R[_II]` 288
    // each, and the dedicated 475-lattice keys are `_meta.key_aliases` of the plain keys. The ordinary descriptor
    // load `LDG_R_dARI` (opcode 0x981) is outside the batch and keeps its 2026-09 shape.
    let ii = t.entries.get("LDG_R_R_dARI_II").expect("klucz II");
    assert_eq!(ii.mod_groups.len(), 1152, "LDG_R_R_dARI_II: the measured group count (T-21 batch 4)");
    for m in ["256,E,ENL2,LTC256B", "256,CONSTANT,E,ENL2,LTC256B", "256,E,EL,ENL2", "256,E,EF,ENL2"] {
        assert!(ii.mod_groups.contains_key(m), "II mod {m} (measured)");
    }
    let rr = t.entries.get("LDG_R_R_dARI").expect("klucz noimm");
    assert_eq!(rr.mod_groups.len(), 1152, "LDG_R_R_dARI: the measured group count (T-21 batch 4)");
    for m in ["256,E,ENL2", "256,E,EL,ENL2", "256,E,EF,ENL2", "256,E,ENL2,EU"] {
        assert!(rr.mod_groups.contains_key(m), "noimm mod {m} (measured)");
    }
    let raw: serde_json::Value =
        serde_json::from_str(&cubit::table::read_table_text("tables/sm103a.json").unwrap()).unwrap();
    let aliases = raw["_meta"]["key_aliases"].as_object().expect("_meta.key_aliases");
    for (k, target) in [
        ("LDG.E.EL.ENL2.256_R_R_dARI", "LDG_R_R_dARI"),
        ("LDG.E.EL.ENL2.256_R_R_dARI_II", "LDG_R_R_dARI_II"),
        ("LDG.E.EF.ENL2.256_R_R_dARI", "LDG_R_R_dARI"),
        ("LDG.E.EF.ENL2.256_R_R_dARI_II", "LDG_R_R_dARI_II"),
        ("LDG.E.ENL2.256_R_R_dARI", "LDG_R_R_dARI"),
        ("LDG.E.EU.ENL2.256_R_R_dARI", "LDG_R_R_dARI"),
        ("STG.E.ENL2.256_dARI_R_R", "STG_dARI_R_R"),
        ("STG.E.EL.ENL2.256.STRONG.GPU_dARI_R_R", "STG_dARI_R_R"),
        ("STG.E.EF.ENL2.256.STRONG.GPU_dARI_R_R", "STG_dARI_R_R"),
    ] {
        // the loader materialises alias clones as entries (BUG-487); the raw table has no such instruction key
        assert!(raw["instructions"].get(k).is_none(), "475-lattice key {k} retired into the measured plain key");
        assert_eq!(aliases[k].as_str(), Some(target), "{k}: alias of the measured plain key");
        assert!(t.entries.contains_key(k), "{k}: the loader's alias clone");
    }
    let r = t.entries.get("LDG_R_dARI").expect("LDG_R_dARI");
    for m in ["E,LU", "128,E,LU", "E,EL", "128,E,EL", "64,E,EL", "E,NA",
              "E,EU", "E,LTC64B", "E,LTC256B", "CONSTANT,E,LTC128B",
              "64,CONSTANT,E,LTC64B"] {
        assert!(r.mod_groups.contains_key(m), "single mod {m}");
    }
    let stg = t.entries.get("STG_dARI_R_R").expect("STG_dARI_R_R: the measured plain key (T-21 batch 4)");
    assert_eq!(stg.mod_groups.len(), 288, "STG_dARI_R_R: the measured group count");
    assert!(stg.mod_groups.contains_key("256,E,EF,ENL2,GPU,STRONG"), "EF-ENL2 class is a measured group of the plain key");
}
