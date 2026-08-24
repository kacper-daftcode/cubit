//! BUG-125 (F2-Q, 125-kand z depozytu 123, severity b4-klasy): swieza
//! f32-imm forma F2I (nvcc-13.3 sm_103a, kwalifikator createpolicy.range
//! lowering) dekodowala sie jako "?" / "no instruction matches opcode
//! 0x0905", a enkoder nie mial wiersza. Klasa zdomknieta w calosci:
//!
//!   * NOWY klucz `F2I_R_FI` (96 wierszy): dst-type idx = bits
//!     {76:width-msb,75,72:sign} (0..5 = U8,S8,U16,S16,U32,S32-blank;
//!     6/7 = invalid na sm_103a por. t125_4), rounding bits [79:78]
//!     (0=RN-blank,1=FLOOR,2=CEIL,3=TRUNC), NTZ bit77, FTZ bit80
//!     (druk pierwszy: `F2I.FTZ.U32.CEIL.NTZ`), imm = f32 @[63:32],
//!     dest R @[23:16], guard @[15:12].
//!   * vm pokrywa [96:127]\{105} (okno sched — dekoder i tak maskuje
//!     upper32; bit105 = kotwica semantyczna wg nvdisasm).
//!   * printer: key-scoped porzadek modow dla F2I_R_FI
//!     (FTZ < type < rounding < NTZ) — legacy F2I_R_R nietkniete
//!     (gold-lock pre-125).
//!   * parser: F2I w FLOAT_OPCODES (tekst "16" = FloatImm f32
//!     0x41800000; inaczej klasa BUG-034 trap z Imm32(16)).
//!   * decoder prio-3 sign-bit fallback: F2I dodane do fail-closed
//!     (invalid type idx 6/7 wchodzil w okno {72..75} i dekodowal sie
//!     jako U32/S32 sibling — nvdisasm-13.3 mowi F2I.???6/???7).
//!
//! Golden = nvdisasm-13.3.73 oracle sweep po pol3.cubin patch-probe
//! (work/bug125/oracle.py + gen125.py; klasa 6x4x2x2=96 legalnych,
//! Anchory korpusu: pol3 k_pr+0x10 imm16 / pol4 k_pr2+0x10 imm17.
//! Raport: results/cubitfix/125.md.

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

/// (slowo, tekst nvdisasm-13.3) — oracle sweep po patch-probie pol3.cubin,
/// guard PT / dest R0 / imm f32=16.0; wszystkie 96 legalnych kombinacji.
const GOLD: &[(u128, &str)] = &[
    (0x000e2200002020004180000000007905, "F2I.U8.NTZ R0, 16"),
    (0x000e2200002120004180000000007905, "F2I.FTZ.U8.NTZ R0, 16"),
    (0x000e2200002000004180000000007905, "F2I.U8 R0, 16"),
    (0x000e2200002100004180000000007905, "F2I.FTZ.U8 R0, 16"),
    (0x000e2200002060004180000000007905, "F2I.U8.FLOOR.NTZ R0, 16"),
    (0x000e2200002160004180000000007905, "F2I.FTZ.U8.FLOOR.NTZ R0, 16"),
    (0x000e2200002040004180000000007905, "F2I.U8.FLOOR R0, 16"),
    (0x000e2200002140004180000000007905, "F2I.FTZ.U8.FLOOR R0, 16"),
    (0x000e22000020a0004180000000007905, "F2I.U8.CEIL.NTZ R0, 16"),
    (0x000e22000021a0004180000000007905, "F2I.FTZ.U8.CEIL.NTZ R0, 16"),
    (0x000e2200002080004180000000007905, "F2I.U8.CEIL R0, 16"),
    (0x000e2200002180004180000000007905, "F2I.FTZ.U8.CEIL R0, 16"),
    (0x000e22000020e0004180000000007905, "F2I.U8.TRUNC.NTZ R0, 16"),
    (0x000e22000021e0004180000000007905, "F2I.FTZ.U8.TRUNC.NTZ R0, 16"),
    (0x000e22000020c0004180000000007905, "F2I.U8.TRUNC R0, 16"),
    (0x000e22000021c0004180000000007905, "F2I.FTZ.U8.TRUNC R0, 16"),
    (0x000e2200002021004180000000007905, "F2I.S8.NTZ R0, 16"),
    (0x000e2200002121004180000000007905, "F2I.FTZ.S8.NTZ R0, 16"),
    (0x000e2200002001004180000000007905, "F2I.S8 R0, 16"),
    (0x000e2200002101004180000000007905, "F2I.FTZ.S8 R0, 16"),
    (0x000e2200002061004180000000007905, "F2I.S8.FLOOR.NTZ R0, 16"),
    (0x000e2200002161004180000000007905, "F2I.FTZ.S8.FLOOR.NTZ R0, 16"),
    (0x000e2200002041004180000000007905, "F2I.S8.FLOOR R0, 16"),
    (0x000e2200002141004180000000007905, "F2I.FTZ.S8.FLOOR R0, 16"),
    (0x000e22000020a1004180000000007905, "F2I.S8.CEIL.NTZ R0, 16"),
    (0x000e22000021a1004180000000007905, "F2I.FTZ.S8.CEIL.NTZ R0, 16"),
    (0x000e2200002081004180000000007905, "F2I.S8.CEIL R0, 16"),
    (0x000e2200002181004180000000007905, "F2I.FTZ.S8.CEIL R0, 16"),
    (0x000e22000020e1004180000000007905, "F2I.S8.TRUNC.NTZ R0, 16"),
    (0x000e22000021e1004180000000007905, "F2I.FTZ.S8.TRUNC.NTZ R0, 16"),
    (0x000e22000020c1004180000000007905, "F2I.S8.TRUNC R0, 16"),
    (0x000e22000021c1004180000000007905, "F2I.FTZ.S8.TRUNC R0, 16"),
    (0x000e2200002028004180000000007905, "F2I.U16.NTZ R0, 16"),
    (0x000e2200002128004180000000007905, "F2I.FTZ.U16.NTZ R0, 16"),
    (0x000e2200002008004180000000007905, "F2I.U16 R0, 16"),
    (0x000e2200002108004180000000007905, "F2I.FTZ.U16 R0, 16"),
    (0x000e2200002068004180000000007905, "F2I.U16.FLOOR.NTZ R0, 16"),
    (0x000e2200002168004180000000007905, "F2I.FTZ.U16.FLOOR.NTZ R0, 16"),
    (0x000e2200002048004180000000007905, "F2I.U16.FLOOR R0, 16"),
    (0x000e2200002148004180000000007905, "F2I.FTZ.U16.FLOOR R0, 16"),
    (0x000e22000020a8004180000000007905, "F2I.U16.CEIL.NTZ R0, 16"),
    (0x000e22000021a8004180000000007905, "F2I.FTZ.U16.CEIL.NTZ R0, 16"),
    (0x000e2200002088004180000000007905, "F2I.U16.CEIL R0, 16"),
    (0x000e2200002188004180000000007905, "F2I.FTZ.U16.CEIL R0, 16"),
    (0x000e22000020e8004180000000007905, "F2I.U16.TRUNC.NTZ R0, 16"),
    (0x000e22000021e8004180000000007905, "F2I.FTZ.U16.TRUNC.NTZ R0, 16"),
    (0x000e22000020c8004180000000007905, "F2I.U16.TRUNC R0, 16"),
    (0x000e22000021c8004180000000007905, "F2I.FTZ.U16.TRUNC R0, 16"),
    (0x000e2200002029004180000000007905, "F2I.S16.NTZ R0, 16"),
    (0x000e2200002129004180000000007905, "F2I.FTZ.S16.NTZ R0, 16"),
    (0x000e2200002009004180000000007905, "F2I.S16 R0, 16"),
    (0x000e2200002109004180000000007905, "F2I.FTZ.S16 R0, 16"),
    (0x000e2200002069004180000000007905, "F2I.S16.FLOOR.NTZ R0, 16"),
    (0x000e2200002169004180000000007905, "F2I.FTZ.S16.FLOOR.NTZ R0, 16"),
    (0x000e2200002049004180000000007905, "F2I.S16.FLOOR R0, 16"),
    (0x000e2200002149004180000000007905, "F2I.FTZ.S16.FLOOR R0, 16"),
    (0x000e22000020a9004180000000007905, "F2I.S16.CEIL.NTZ R0, 16"),
    (0x000e22000021a9004180000000007905, "F2I.FTZ.S16.CEIL.NTZ R0, 16"),
    (0x000e2200002089004180000000007905, "F2I.S16.CEIL R0, 16"),
    (0x000e2200002189004180000000007905, "F2I.FTZ.S16.CEIL R0, 16"),
    (0x000e22000020e9004180000000007905, "F2I.S16.TRUNC.NTZ R0, 16"),
    (0x000e22000021e9004180000000007905, "F2I.FTZ.S16.TRUNC.NTZ R0, 16"),
    (0x000e22000020c9004180000000007905, "F2I.S16.TRUNC R0, 16"),
    (0x000e22000021c9004180000000007905, "F2I.FTZ.S16.TRUNC R0, 16"),
    (0x000e2200002030004180000000007905, "F2I.U32.NTZ R0, 16"),
    (0x000e2200002130004180000000007905, "F2I.FTZ.U32.NTZ R0, 16"),
    (0x000e2200002010004180000000007905, "F2I.U32 R0, 16"),
    (0x000e2200002110004180000000007905, "F2I.FTZ.U32 R0, 16"),
    (0x000e2200002070004180000000007905, "F2I.U32.FLOOR.NTZ R0, 16"),
    (0x000e2200002170004180000000007905, "F2I.FTZ.U32.FLOOR.NTZ R0, 16"),
    (0x000e2200002050004180000000007905, "F2I.U32.FLOOR R0, 16"),
    (0x000e2200002150004180000000007905, "F2I.FTZ.U32.FLOOR R0, 16"),
    (0x000e22000020b0004180000000007905, "F2I.U32.CEIL.NTZ R0, 16"),
    (0x000e22000021b0004180000000007905, "F2I.FTZ.U32.CEIL.NTZ R0, 16"),
    (0x000e2200002090004180000000007905, "F2I.U32.CEIL R0, 16"),
    (0x000e2200002190004180000000007905, "F2I.FTZ.U32.CEIL R0, 16"),
    (0x000e22000020f0004180000000007905, "F2I.U32.TRUNC.NTZ R0, 16"),
    (0x000e22000021f0004180000000007905, "F2I.FTZ.U32.TRUNC.NTZ R0, 16"),
    (0x000e22000020d0004180000000007905, "F2I.U32.TRUNC R0, 16"),
    (0x000e22000021d0004180000000007905, "F2I.FTZ.U32.TRUNC R0, 16"),
    (0x000e2200002031004180000000007905, "F2I.NTZ R0, 16"),
    (0x000e2200002131004180000000007905, "F2I.FTZ.NTZ R0, 16"),
    (0x000e2200002011004180000000007905, "F2I R0, 16"),
    (0x000e2200002111004180000000007905, "F2I.FTZ R0, 16"),
    (0x000e2200002071004180000000007905, "F2I.FLOOR.NTZ R0, 16"),
    (0x000e2200002171004180000000007905, "F2I.FTZ.FLOOR.NTZ R0, 16"),
    (0x000e2200002051004180000000007905, "F2I.FLOOR R0, 16"),
    (0x000e2200002151004180000000007905, "F2I.FTZ.FLOOR R0, 16"),
    (0x000e22000020b1004180000000007905, "F2I.CEIL.NTZ R0, 16"),
    (0x000e22000021b1004180000000007905, "F2I.FTZ.CEIL.NTZ R0, 16"),
    (0x000e2200002091004180000000007905, "F2I.CEIL R0, 16"),
    (0x000e2200002191004180000000007905, "F2I.FTZ.CEIL R0, 16"),
    (0x000e22000020f1004180000000007905, "F2I.TRUNC.NTZ R0, 16"),
    (0x000e22000021f1004180000000007905, "F2I.FTZ.TRUNC.NTZ R0, 16"),
    (0x000e22000020d1004180000000007905, "F2I.TRUNC R0, 16"),
    (0x000e22000021d1004180000000007905, "F2I.FTZ.TRUNC R0, 16"),
    (0x000e22000020b0004188000000007905, "F2I.U32.CEIL.NTZ R0, 17"), // pol4 k_pr2+0x10
];

/// t125_1: kazde golden-slowo dekoduje sie do DOKLADNEGO tekstu
/// nvdisasm-13.3 (render-parity; brak "?" i brak !rsd).
#[test]
fn t125_1_decode_parity_96() {
    assert_eq!(GOLD.len(), 97);
    for (w, want) in GOLD {
        let got = dec103(*w).unwrap_or_else(|| panic!("decode fail {w:#034x}"));
        let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
        assert_eq!(&got, want, "decode parity dla {w:#034x}");
        assert!(!got.contains("!rsd"), "zero lossy-markerow: {got}");
    }
}

/// t125_2: encode kazdego tekstu golden == slowo golden na payloadzie
/// (maska ctrl >=96; sched z krzemu testem negenerowany).
#[test]
fn t125_2_encode_payload_96() {
    for (w, text) in GOLD {
        let got = enc103(text);
        assert_eq!(got & NOSCHED, w & NOSCHED,
                   "encode {text:?}: payload bajt-w-bajt: got {got:#034x} want {w:#034x}");
    }
}

/// t125_3: pelny roundtrip word -> text -> word dla calej klasy.
#[test]
fn t125_3_roundtrip_96() {
    for (w, _text) in GOLD {
        let got = dec103(*w).unwrap();
        let got = got.split("/*").next().unwrap().trim().trim_end_matches(';').trim().to_string();
        let w2 = enc103(&got);
        assert_eq!(w2 & NOSCHED, w & NOSCHED, "roundtrip {got:?}");
    }
}

/// t125_4: invalid dst-type idx 6/7 (nvdisasm: F2I.???6/???7) pozostaje
/// fail-closed — NIE wolno zrelaksowac na U32/S32 przez prio-3 sign-bit
/// okno {72..75}.
#[test]
fn t125_4_invalid_type_idx_fail_closed() {
    for w in [0x000e22000020b8004180000000007905u128,   // type 6
              0x000e22000020b9004180000000007905u128] { // type 7
        assert!(dec103(w).is_none(),
                "invalid type-idx word MUSI pozostac niezdekodowane: {w:#034x}");
    }
}

/// t125_5: guard/dest/imm rozkladaja sie poprawnie (oracle pary
/// poza seedem klasy: @P0, dest R5, imm 17, imm 4.5).
#[test]
fn t125_5_guard_dest_imm_diversity() {
    // @P0 (guard val 0) + U32.CEIL.NTZ dest R0 imm 16
    let t = dec103(0x000e22000020b0004180000000000905).unwrap();
    assert!(t.starts_with("@P0 F2I.U32.CEIL.NTZ R0, 16"), "{t}");
    // dest R5
    let t = dec103(0x000e22000020b0004180000000057905).unwrap();
    assert!(t.contains("F2I.U32.CEIL.NTZ R5, 16"), "{t}");
    // imm f32 = 4.5 (0x40900000) — nvdisasm drukuje "4.5"
    let t = dec103(0x000e22000020b0004090000000007905).unwrap();
    assert!(t.contains("F2I.U32.CEIL.NTZ R0, 4.5"), "{t}");
    // imm 17 == korpus pol4 k_pr2
    let t = dec103(0x000e22000020b0004188000000007905).unwrap();
    assert!(t.contains("F2I.U32.CEIL.NTZ R0, 17"), "{t}");
}

/// t125_6: parser-anchor — tekst "16" pod F2I to FloatImm f32
/// (0x41800000), NIE Imm32(16) (trap BUG-034).
#[test]
fn t125_6_float_imm_parser_anchor() {
    let insn = parse_sass("F2I.U32.CEIL.NTZ R0, 16", 0).unwrap();
    let w = encode_instruction(&insn, &t103()).unwrap();
    assert_eq!((w >> 32) as u32, 0x41800000,
               "imm musi byc f32(16.0) bity, got {:#010x}", (w >> 32) as u32);
}

/// t125_7: ksztalt tabeli — nowy klucz z 96 wierszami; legacy F2I_R_R
/// nietkniety (16 wierszy jak przed 125); zadna R-forma nie ma pola f32.
#[test]
fn t125_7_table_shape() {
    let t = t103();
    let ins = &t.entries;
    let fi = ins.get("F2I_R_FI").expect("brak klucza F2I_R_FI");
    assert_eq!(fi.mod_groups.len(), 96);
    let rr = ins.get("F2I_R_R").expect("brak F2I_R_R");
    assert_eq!(rr.mod_groups.len(), 16);
    for (mg, e) in &fi.mod_groups {
        assert_eq!(e.fields.len(), 3, "guard+dest+imm: {mg}");
        assert!(e.fields.iter().any(|f|
                matches!(f.extraction, cubit::table::Extraction::F32)),
                "pole f32: {mg}");
    }
}
