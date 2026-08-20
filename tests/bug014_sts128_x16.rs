//! BUG-014/017 (rejestr sm120: pliki 014/017, iter79/81): `STS.128 [Rn.X16], Rm`
//! — renderer gubil operandy (drukowal `STS.128_AR.X16 0x0`), a parser/trasa
//! encoda gubil dyskryminant X16 (bity 78/79): `[R5.X16]` i `[R5]` dawaly
//! IDENTYCZNE slowo. 4 slowa w kernelu RC zostawaly __raw__.
//!
//! Fix: wiersz `STS_ARI_R` mg "128" dostal pole `addr_scale` 2b@[79:78]
//! (semantyka BUG-038: 0 brak, 1=X4, 2=X8, 3=X16); printerowa sciezka
//! scaled-addr z 038 rozszerzona LDS -> STS. Geometria okien zweryfikowana
//! bitami-sonda nvdisasm (probe cubiny): addr Rn @[31:24], val Rm @[39:32],
//! imm 24b @[63:40] ZE ZNAKIEM 1:1, guard @[15:12]. Generycznym completeness
//! w encodera suffix adrosa .X4/.X8/.X16 jest teraz fail-closed gdy wiersz nie
//! ma pola addr_scale (wczesniej: cicho dropil).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(text: &str) -> Result<u128, String> {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).map_err(|e| format!("{e}"))
}

fn dec(word: u128) -> String {
    let idx = DecodeIndex::build(&t120());
    let d = idx.decode(word, 0, &t120()).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}

/// 4 zlote slowa z kernela RC (rejestr 014; nvdisasm = oracle) + forma plain
/// (bity 78/79 = 0; slowo sprawdzone sonda nvdisasm na rt98_pub.cubin clone).
const GOLD: &[(u128, &str)] = &[
    (0x001be4000000cc00000000c805007388, "STS.128 [R5.X16], R200"),
    (0x000be4000000cc00000010cc05007388, "STS.128 [R5.X16+0x10], R204"),
    (0x001be4000000cc000000001c1b007388, "STS.128 [R27.X16], R28"),
    (0x000be4000000cc00000010201b007388, "STS.128 [R27.X16+0x10], R32"),
    (0x001be40000000c00000000c805007388, "STS.128 [R5], R200"),
];

#[test]
fn bug014_gold_decode_and_reencode_byte_exact() {
    for (word, text) in GOLD {
        assert_eq!(&dec(*word), text, "render differs for {word:#034x}");
        let insn = parse_sass(text, 0).unwrap();
        let code = encode_instruction(&insn, &t120()).unwrap();
        assert_eq!(code & !SCHED, word & !SCHED, "re-encode differs for {text:?}");
    }
}

#[test]
fn bug014_x16_suffix_no_longer_dropped() {
    let plain = enc("STS.128 [R5], R200").unwrap();
    let x16 = enc("STS.128 [R5.X16], R200").unwrap();
    assert_ne!(plain & !SCHED, x16 & !SCHED, "X16 suffix must change the word");
    assert_eq!((x16 >> 78) & 3, 3, "X16 = addr_scale 3");
    assert_eq!((plain >> 78) & 3, 0);
    let x4 = enc("STS.128 [R5.X4], R200").unwrap();
    let x8 = enc("STS.128 [R5.X8], R200").unwrap();
    assert_eq!((x4 >> 78) & 3, 1);
    assert_eq!((x8 >> 78) & 3, 2);
    assert_eq!(dec(x4), "STS.128 [R5.X4], R200");
}

#[test]
fn bug014_suffix_on_row_without_field_fails_closed() {
    // STS.64 nie ma w tabeli pola addr_scale (brak zlotego pokrycia): suffix
    // musi odpasc GLONO, a nie cicho skonczyc jako slowo scale=0.
    let e = enc("STS.64 [R4.X8], R8").expect_err("unsupported suffix must refuse");
    assert!(e.contains("addr scale suffix"), "completeness must name it: {e}");
}

#[test]
fn bug014_sondom_windows() {
    // okna z sond nvdisasm: addr @[31:24], val @[39:32], imm @[63:40] 1:1
    let w = enc("STS.128 [R7.X16+0x100], R32").unwrap();
    assert_eq!(((w >> 24) & 0xff) as u64, 7);
    assert_eq!(((w >> 32) & 0xff) as u64, 32);
    assert_eq!(((w >> 40) & 0xff_ffff) as u64, 0x100);
    // znak imm: bit63 = -0x800000 (24b signed)
    let neg = enc("STS.128 [R5.X16+-0x1], R200").unwrap();
    assert_eq!(((neg >> 40) & 0xff_ffff) as u64, 0xff_ffff);
}
