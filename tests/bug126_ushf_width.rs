//! BUG-126: USHF imm-form (USHF_UR_UR_II_UR) — corpus words
//! (`USHF.R.U32 UR4, UR4, 0x4, URZ`) decoded lossily as USHF.R.U64
//! !rsd[74:1]: rows were missing for most of the family.
//! of width/sign classes, and the prio-3 sign-bit fallback ({62,63,72,73,74,75}) swallowed
//! bit74=1 (32-bit) words into the bit74=0 (U64) row. Closed CLASS-WIDE:
//!
//!   * 26 new rows under the USHF_UR_UR_II_UR key (the x32 class):
//!     dir bit76 (0=L,1=R), sign bit73 (0=S,1=U), width bit74 (0=64,1=32),
//!     W bit75, HI bit80. Vendor render: USHF.<L|R>[.W].<U32|S32|U64|S64>[.HI]
//!     — the generic mod priorities agree (dir=3, W=4, type=5, HI=7),
//!     zero printer changes.
//!   * decoder prio-3: USHF added to fail-closed (bits {72..75} = form
//!     semantics, not sign/abs; nvdisasm: even the "don't-care" bit72 stays
//!     fail-closed — the strict-row doctrine).
//!   * legacy F sections untouched; reg-form keys (USHF_UR_UR_UR_UR etc.)
//!     in restrictions of the seen corpus out of scope (complete for the
//!     corpus; a full reg-form sweep = a b4-queue item if the corpus grows).
//!
//! Golden = nvdisasm-13.3.73 oracle sweep (pol3.cubin k_st+0x60 patch probe,
//! work/bug126/oracle126.py). Corpus anchors: 14 !rsd[74:1] words ->
//! USHF.R.U32; render-parity 15/15 stringow na pol*+sweep. Raport:
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
fn dec103(word: u128) -> Option<String> {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    idx.decode(word, 0, &t).ok().map(|d| to_sass(&d))
}
const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// (slowo, tekst nvdisasm-13.3) — oracle sweep x32 na klasie imm-form USHF;
/// guard UPT / UR4,UR4 / imm 4 / URZ.
const GOLD: &[(u128, &str)] = &[
    (0x000fe200080000ff0000000404047899, "USHF.L.S64 UR4, UR4, 0x4, URZ"),
    (0x000fe200080002ff0000000404047899, "USHF.L.U64 UR4, UR4, 0x4, URZ"),
    (0x000fe200080004ff0000000404047899, "USHF.L.S32 UR4, UR4, 0x4, URZ"),
    (0x000fe200080006ff0000000404047899, "USHF.L.U32 UR4, UR4, 0x4, URZ"),
    (0x000fe200080008ff0000000404047899, "USHF.L.W.S64 UR4, UR4, 0x4, URZ"),
    (0x000fe20008000aff0000000404047899, "USHF.L.W.U64 UR4, UR4, 0x4, URZ"),
    (0x000fe20008000cff0000000404047899, "USHF.L.W.S32 UR4, UR4, 0x4, URZ"),
    (0x000fe20008000eff0000000404047899, "USHF.L.W.U32 UR4, UR4, 0x4, URZ"),
    (0x000fe200080010ff0000000404047899, "USHF.R.S64 UR4, UR4, 0x4, URZ"),
    (0x000fe200080012ff0000000404047899, "USHF.R.U64 UR4, UR4, 0x4, URZ"),
    (0x000fe200080014ff0000000404047899, "USHF.R.S32 UR4, UR4, 0x4, URZ"),
    (0x000fe200080016ff0000000404047899, "USHF.R.U32 UR4, UR4, 0x4, URZ"),
    (0x000fe200080018ff0000000404047899, "USHF.R.W.S64 UR4, UR4, 0x4, URZ"),
    (0x000fe20008001aff0000000404047899, "USHF.R.W.U64 UR4, UR4, 0x4, URZ"),
    (0x000fe20008001cff0000000404047899, "USHF.R.W.S32 UR4, UR4, 0x4, URZ"),
    (0x000fe20008001eff0000000404047899, "USHF.R.W.U32 UR4, UR4, 0x4, URZ"),
    (0x000fe200080100ff0000000404047899, "USHF.L.S64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080102ff0000000404047899, "USHF.L.U64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080104ff0000000404047899, "USHF.L.S32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080106ff0000000404047899, "USHF.L.U32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080108ff0000000404047899, "USHF.L.W.S64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe20008010aff0000000404047899, "USHF.L.W.U64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe20008010cff0000000404047899, "USHF.L.W.S32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe20008010eff0000000404047899, "USHF.L.W.U32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080110ff0000000404047899, "USHF.R.S64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080112ff0000000404047899, "USHF.R.U64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080114ff0000000404047899, "USHF.R.S32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080116ff0000000404047899, "USHF.R.U32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe200080118ff0000000404047899, "USHF.R.W.S64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe20008011aff0000000404047899, "USHF.R.W.U64.HI UR4, UR4, 0x4, URZ"),
    (0x000fe20008011cff0000000404047899, "USHF.R.W.S32.HI UR4, UR4, 0x4, URZ"),
    (0x000fe20008011eff0000000404047899, "USHF.R.W.U32.HI UR4, UR4, 0x4, URZ"),
];

/// t126_1: kazde golden-slowo dekoduje sie do DOKLADNEGO tekstu nvdisasm-13.3
/// (no "?", no !rsd).
#[test]
fn t126_1_decode_parity_32() {
    assert_eq!(GOLD.len(), 32);
    for (w, want) in GOLD {
        let got = dec103(*w).unwrap_or_else(|| panic!("decode fail {w:#034x}"));
        let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
        assert_eq!(&got, want, "decode parity dla {w:#034x}");
        assert!(!got.contains("!rsd"), "zero lossy-markerow: {got}");
    }
}

/// t126_2: encode kazdego tekstu golden == payload slowa golden (maska >=96).
#[test]
fn t126_2_encode_payload_32() {
    for (w, text) in GOLD {
        let got = enc103(text);
        assert_eq!(got & NOSCHED, w & NOSCHED,
                   "encode {text:?}: payload: got {got:#034x} want {w:#034x}");
    }
}

/// t126_3: word -> text -> word round-trip for the whole class.
#[test]
fn t126_3_roundtrip_32() {
    for (w, _text) in GOLD {
        let got = dec103(*w).unwrap();
        let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
        let w2 = enc103(&got);
        assert_eq!(w2 & NOSCHED, w & NOSCHED, "roundtrip {got:?}");
    }
}

/// t126_4: corpus anchor — the 14 pol* words (ex-!rsd[74:1]) decode
/// jako USHF.R.U32 i re-enkoduje payload-identycznie.
#[test]
fn t126_4_corpus_anchor_r_u32() {
    for w in [
        0x000fe200080016ff0000000404047899u128, // pol3 k_st+0x60
    ] {
        let got = dec103(w).unwrap();
        assert!(got.contains("USHF.R.U32 UR4, UR4, 0x4, URZ"), "{got}");
        assert!(!got.contains("!rsd"), "{got}");
        let text = got.split("/*").next().unwrap().trim().trim_end_matches(';');
        let w2 = enc103(text);
        assert_eq!(w2 & NOSCHED, w & NOSCHED, "anchor roundtrip");
    }
}

/// t126_5: prio-3 exclusion — slowo klasy z odwroconym bit72 (nvdisasm
/// don't-care) pozostaje fail-closed (doktryna strict-row).
#[test]
fn t126_5_prio3_exclusion_fail_closed() {
    let w = 0x000fe200080016ff0000000404047899u128 | (1u128 << 72);
    assert!(dec103(w).is_none(), "bit72-zmiennosc MUSI pozostac fail-closed");
}

/// t126_6: guard uniform rozklada sie (@UP3).
#[test]
fn t126_6_uniform_guard() {
    let w = (0x000fe200080016ff0000000404047899u128 & !(0xFu128<<12)) | (3u128<<12);
    let got = dec103(w).unwrap();
    assert!(got.starts_with("@UP3 USHF.R.U32"), "{got}");
}

/// t126_7: table shape — the imm-form key has the full 32 rows; the reg-form
/// klucze nietkniete.
#[test]
fn t126_7_table_shape() {
    let t = t103();
    let ins = &t.entries;
    let imm = ins.get("USHF_UR_UR_II_UR").expect("USHF_UR_UR_II_UR");
    assert_eq!(imm.mod_groups.len(), 32);
    let rr = ins.get("USHF_UR_UR_UR_UR").expect("USHF_UR_UR_UR_UR");
    assert_eq!(rr.mod_groups.len(), 4);
}
