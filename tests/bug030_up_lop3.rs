//! BUG-030 (sm120 registry: 030 / iter67+i91): encoder holes of the UP-write families
//! UPLOP3/ULOP3.
//!  a) `UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x3, 0x0` accepted without WARN ->
//!     a word OUTSIDE the decodable space (nvdisasm: "undefined value 0x1e
//!     for TABLES_opex_1"). Cause: the `UPLOP3.LUT_UP_UP_UP_UP_UP_II_II` row
//!     had a `token_idx: 7` field (beyond the seven-token sig) at 2-bit width
//!     with no scaling — golden words DECODED WRONG ("0x40, 0x4" printed
//!     as "0x1, 0x1") and encode != word.
//!     Data-level fix on the i93 goldens (2635 SASS words, cublasLt/cudnn sm_120):
//!       dest-UP tok1 3b straight, src4-UP tok5 3b straight,
//!       tok6 = 2b renders value<<6, tok7 = 2b renders value<<2;
//!     plus a fail-closed lattice check (0x3/0x44 etc. rejected — like mk54
//!     on the mercury side).
//!  b) `ULOP3.LUT UP1, UPT, URZ, 0x1, 0xff, 0x0` — the 6-token UP-write form
//!     does NOT exist in the golden corpus (206k UP records): the real form is
//!     the 7-token `ULOP3.LUT UPd, URd, URa, imm_b, URc, lut8, !UPx` (BUG-012).
//!     The two phantom `_?` rows (scrambled fields) removed; lookup-fail
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

/// Golden words from the i93 harvest (nvdisasm -c, cublasLt sm_120). The render must be
/// identical to the oracle text, and re-encode = original bytes (mod sched).
const GOLD: &[(u128, &str)] = &[
    (0x000fc40003f0e870000000000004789c, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f0f070000000000008789c, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    (0x000fe80003f6e870000000000004789c, "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    (0x000fe20003f2f000000000000008789c, "UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    (0x000fd60003f6e830000000000004789c, "UPLOP3.LUT UP3, UPT, UPT, UPT, UP3, 0x40, 0x4"),
    (0x000fc80003fae870000000000004789c, "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    // ULOP3 UP-write 7-token (the BUG-012 row) — regression after phantom removal
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
    // RE-PIN (BUG-168, iter78): korekta prawa kraty. Stara kerta
    // ({0,0x40,0x80,0xc0} x {0,0x4,0x8,0xc}) byla over-fitem ery-030 --
    // vendor (nvdisasm 13.3.73 matryca, work/i78): v1 in [0,0xfe] EVEN,
    // v2 in [0,0xff] niezalezny. 0x3 odrzucane dalej (v1 ODD: bit0 bez
    // magazynu), ale komunikat niesie BUG-168 (rev BUG-030).
    let e = enc("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x3, 0x0")
        .expect_err("out-of-lattice lut must be refused");
    assert!(e.contains("BUG-030") && e.contains("BUG-168"),
        "error must name BUG-168 (rev BUG-030): {e}");
    // brzegi kraty: stare krawedzie legalne jak dawniej...
    for (a, b) in [(0x0, 0x0), (0x40, 0x4), (0x80, 0x8), (0xc0, 0xc), (0xc0, 0x0), (0x0, 0xc)] {
        enc(&format!("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, {a:#x}, {b:#x}"))
            .unwrap_or_else(|e| panic!("lattice edge {a:#x},{b:#x} must encode: {e}"));
    }
    // ...a formy odkryte przez BUG-168 z korpusu (64 linie) TEZ legalne:
    for (a, b) in [(0xf8, 0x8f), (0x2, 0x20)] {
        enc(&format!("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, {a:#x}, {b:#x}"))
            .unwrap_or_else(|e| panic!("BUG-168 corpus form {a:#x},{b:#x} must encode: {e}"));
    }
    // poza krata post-168: v1 nieparzyste / >0xfe, v2 >0xff
    for t in [
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x43, 0x4",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x100, 0x0",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x100",
    ] {
        enc(t).expect_err(&format!("{t:?} must be refused"));
    }
    // legalne w nowym prawie (dowod arbitrazu nvdisasm; pre-168 refuse):
    for t in [
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x44, 0x4",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x5",
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x10",
    ] {
        enc(t).unwrap_or_else(|e| panic!("{t:?} legal per BUG-168 law: {e}"));
    }
}

#[test]
fn bug030_ulop3_short_up_write_phantom_rejected() {
    // 030b repro: the 6-token "form" never existed in the silicon corpus
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
    // RE-PIN 2026-08-25 (BUG-169, z atrybucja): ery-030 zalozenie "tok2 bez pola
    // = zawsze UPT" OBALONE arbitrazem nvdisasm-13.3.73 (work/bug169/arb):
    // tok2 = [84:87) upred jest polem rzeczywistym (sondy tok2_84_0/2/5 ->
    // "UP0/UP2/UP5"). Enkoder zapisuje je bajtowo dokladnie z arbitrem;
    // fail-closed przez completeness zostaje dla form bez wiersza (klasa
    // skasowana UP_P_P_P_P: zero kotwic, nvdisasm nie zna P-zrodel w UPLOP3).
    let w = enc("UPLOP3.LUT UP0, UP5, UPT, UPT, UPT, 0x80, 0x8")
        .expect("tok2=UP5 must encode (arb byte-exact)");
    assert_eq!(w & !(0xFFFF_FFFFu128 << 96),
        0x000fc40003d0f070_000000000008789cu128 & !(0xFFFF_FFFFu128 << 96),
        "payload [0:96) == arb word (tok2_84_5)");
    let e = enc("UPLOP3.LUT UP0, PT, P0, P1, PT, 0x80, 0x8")
        .expect_err("deleted P-source-in-UPLOP3 class must stay refused");
    assert!(e.contains("no instruction") || e.contains("no row") || e.contains("no field") || e.contains("no operand-compatible"),
        "lookup failure expected (lattice-passing imms): {e}");
}
