//! BUG-030 (rejestr sm120: 030 / iter67+i91): dziury enkodera UP-write rodzin
//! UPLOP3/ULOP3.
//!  a) `UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x3, 0x0` akceptowane bez WARN ->
//!     slowo POZA przestrzenia dekodowalna (nvdisasm: "undefined value 0x1e
//!     for TABLES_opex_1"). Przyczyna: wiersz `UPLOP3.LUT_UP_UP_UP_UP_UP_II_II`
//!     mial pole `token_idx: 7` (poza siedmiotokenowym sig) i 2-bit szerokosci
//!     bez skalowania — zlote slowa DEKODOWALY SIE ZLE ("0x40, 0x4" drukowane
//!     jako "0x1, 0x1") i encode != slowo.
//!     Fix data-level na zlocie i93 (2635 slow SASS, cublasLt/cudnn sm_120):
//!       dest-UP tok1 3b@81 straight, src4-UP tok5 3b@68 straight,
//!       tok6 = 2b@75 render value<<6, tok7 = 2b@18 render value<<2;
//!     plus fail-closed check lattice (0x3/0x44 itd. odrzucane — jak mk54
//!     po stronie mercury).
//!  b) `ULOP3.LUT UP1, UPT, URZ, 0x1, 0xff, 0x0` — 6-tokenowa forma UP-write
//!     NIE istnieje w zlotym korpusie (206k rekordow UP): realna forma to
//!     7-token `ULOP3.LUT UPd, URd, URa, imm_b, URc, lut8, !UPx` (BUG-012).
//!     Dwa fantomowe wiersze `_?` (scrambled-pola) usuniete; lookup-fail
//!     niesie wskazowke z kanoniczna forma.

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

/// Zlote slowa z i93 harvest (nvdisasm -c, cublasLt sm_120). Render musi byc
/// identyczny z tekstem oracle, a re-encode = oryginalne bajty (mod sched).
const GOLD: &[(u128, &str)] = &[
    (0x000fc40003f0e870000000000004789c, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f0f070000000000008789c, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe80003f6e870000000000004789c, "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f2f000000000000008789c, "UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    (0x000fd60003f6e830000000000004789c, "UPLOP3.LUT UP3, UPT, UPT, UPT, UP3, 0x40, 0x4"),
    (0x000fc80003fae870000000000004789c, "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    // ULOP3 UP-write 7-token (wiersz z BUG-012) — regresja po usunieciu fantomow
    (0x000fe2000f82c03f00000001133f7892, "ULOP3.LUT UP1, UR63, UR19, 0x1, UR63, 0xc0, !UPT"),
];

#[test]
fn bug030_gold_decode_and_reencode_byte_exact() {
    for (word, text) in GOLD {
        let got = dec(*word);
        assert_eq!(&got, text, "render differs for {word:#034x}");
        let insn = parse_sass(text, 0).unwrap();
        let code = encode_instruction(&insn, &t120()).unwrap();
        assert_eq!(code & !SCHED, word & !SCHED, "re-encode differs for {text:?}");
    }
}

#[test]
fn bug030_repro_uplop3_lattice_fail_closed() {
    // oryginalny repro: tok5=0x3 jest niewyrazalny (2-bit lattice, value<<6)
    let e = enc("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x3, 0x0")
        .expect_err("out-of-lattice lut must be refused");
    assert!(e.contains("BUG-030"), "error must name BUG-030: {e}");
    // brzegi kraty: tok5 {0,0x40,0x80,0xc0}, tok6 {0,0x4,0x8,0xc} — legalne
    for (a, b) in [(0x0, 0x0), (0x40, 0x4), (0x80, 0x8), (0xc0, 0xc), (0xc0, 0x0), (0x0, 0xc)] {
        enc(&format!("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, {a:#x}, {b:#x}"))
            .unwrap_or_else(|e| panic!("lattice edge {a:#x},{b:#x} must encode: {e}"));
    }
    // poza krata: wartosci z ustawionymi dolnymi bitami / za duza wartosc
    for t in [
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x44, 0x4",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x100, 0x0",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x5",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x10",
    ] {
        enc(t).expect_err(&format!("{t:?} must be refused"));
    }
}

#[test]
fn bug030_ulop3_short_up_write_phantom_rejected() {
    // 030b repro: 6-tokenowa "forma" nigdy nie istniala w krzemowym korpusie
    let e = enc("ULOP3.LUT UP1, UPT, URZ, 0x1, 0xff, 0x0")
        .expect_err("phantom UP-write shape must stay rejected");
    assert!(
        e.contains("BUG-030") && e.contains("ULOP3.LUT UPd, URd, URa, imm_b, URc, lut8, !UPx"),
        "lookup failure must carry the canonical-form hint: {e}"
    );
    // kanoniczna 7-tokenowa forma UP-write ENKODUJE (podniesiona z BUG-012)
    enc("ULOP3.LUT UP1, URZ, URZ, 0x1, URZ, 0xff, !UPT")
        .expect("canonical 7-token UP-write must encode (lut 8b@72)");
}

#[test]
fn bug030_uplop3_non_upt_sources_fail_closed() {
    // tok1-3 NIE maja pol w zlocie (zawsze UPT): nie-UPT musi odpasc
    // fail-closed przez completeness (brak pola), NIE cicho wypasc z slowa.
    let e = enc("UPLOP3.LUT UP0, UP1, UPT, UPT, UPT, 0x40, 0x4")
        .expect_err("non-UPT source at tok1 must be refused");
    assert!(e.contains("no field"), "completeness error expected: {e}");
}
