//! BUG-297 (F2-iter151, loop5/blind front2, 2026-08-30): hsel value-validity
//! law on the UR half-select tokens of the packed-f16 pair families.
//! Registered 297-kand LOW at F2-iter148 (273 report sec.6): hsel=1 on the
//! HFMA2/HMUL2 UR opclass = vendor '.INVALID1'; engine printed '.H0_H1'.
//!
//! LAW (arb273 A1/A5/C4 + arb297/arb297b/arb297c: nvdisasm 13.3.73 raw -b,
//! x4 models SM100a/SM103a/SM120/SM121a agree on EVERY probe):
//!   rows carrying an hsel field on a UR token (iter151 tables census, the
//!   ONLY such rows): HFMA2_R_R_R_UR (tok4), HMUL2_R_R_UR ''+'BF16_V2'
//!   (tok3), HSETP2_P_P_R_UR_P (tok4, all mod-groups) --
//!     hsel 1 -> '.INVALID1' (UR4.INVALID1, |UR4.INVALID1|, -UR4.INVALID1,
//!                            -|UR4.INVALID1|)
//!     hsel 2 -> '.H0_H0'   hsel 3 -> '.H1_H1'   (legal, unchanged)
//! PRE-FIX (measure_pre297, pub pyo3-7f618e4): engine decode printed
//! '.H0_H1' on every scoped probe (misprint both legs); encode-side the
//! generic op_hsel scrape MINTED the vendor-illegal hsel==1 word from
//! authored 'URn.H0_H1' text (silent wrong-code: 'HMUL2 R2, R0, UR4.H0_H1',
//! 'HFMA2 R1, R2, R3, UR4.H0_H1', HSETP2 forms all minted).
//! CORPUS EXPOSURE ZERO: routex297 full 2,406-cubin battery x2 bundle legs
//! -- no hsel==1 word on any scoped row (only legal 2/3 values occur).
//! Sibling laws measured but NOT armed here (own registrations):
//!   305-kand: HFMA2_R_R_UR_R tok3 UR hsel=1 -> vendor '.F32' (G1/I1/G41).
//!   306-kand: R-domain per-window v1 laws (HFMA2 win@74 and HADD2 win@60
//!             v1 -> 'Rn.INVALID1' K3/K2c; win@81 v1 = '.F32' BUG-279 era).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
fn w(bits: &[(u32, u128)], base: u128) -> u128 {
    bits.iter().fold(base, |acc, &(sh, v)| acc | (v << sh))
}
// sm120/sm121a HFMA2_R_R_R_UR '' : payload R1@16, R2@24, R3@64, UR4@32
fn a(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0x80000000000000000000e31 | (1 << 16) | (2 << 24) | (4 << 32) | (3 << 64),
    )
}
// sm120/sm103a HMUL2_R_R_UR '' : and_base bakes hsel=3 + ureg=8 + tok1=R2
// (arb297b Hc base, vendor text 'HMUL2 R2, R0, UR4...')
fn hc(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        (0x000fc000080000003000000800027c32 & !(3u128 << 60) & !(0xFFu128 << 32)) | (4 << 32),
    )
}
// sm120 HSETP2_P_P_R_UR_P 'AND,F' : payload R3@24, UR4@32
fn j(bits: &[(u32, u128)]) -> u128 {
    w(bits, 0x80000000000000000000e34 | (3 << 24) | (4 << 32))
}
// sm121a HSETP2_P_P_R_UR_P 'AND,F' : and_base bakes hsel=2 -- clean base
fn j2c(bits: &[(u32, u128)]) -> u128 {
    w(bits, 0x4fca000bf008002000000402007e34 & !(3u128 << 60))
}
// sm120/sm103a HFMA2_R_R_UR_R '' (legacy lattice): R1@16, R2@24, UR4@32
fn g(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0xfc000080000000000000000007c31 | (1 << 16) | (2 << 24) | (4 << 32),
    )
}
// sm103a HADD2_R_R_R.F32 : and_base bakes hsel=2 at win@60 -- clean base
fn dc(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        (0x000fc0000000410020000000ff000230 & !(3u128 << 60)) | (1 << 16) | (2 << 24) | (3 << 32),
    )
}
const H1: (u32, u128) = (60, 1);
const H2: (u32, u128) = (60, 2);
const H3: (u32, u128) = (60, 3);
const ABS: (u32, u128) = (62, 1);
const NEG: (u32, u128) = (63, 1);

#[test]
fn t297_1_decode_invalid1_sm120() {
    let t = tab("sm120");
    let cases: [(u128, &str); 5] = [
        (a(&[H1]), "@P0 HFMA2 R1, R2, R3, UR4.INVALID1"),
        (a(&[ABS, NEG, H1]), "@P0 HFMA2 R1, R2, R3, -|UR4.INVALID1|"),
        (hc(&[H1]), "HMUL2 R2, R0, UR4.INVALID1"),
        (hc(&[ABS, H1]), "HMUL2 R2, R0, |UR4.INVALID1|"),
        (j(&[H1]), "@P0 HSETP2.F.AND P0, P0, R3, UR4.INVALID1, P0"),
    ];
    for (word, want) in cases {
        let got = dec(&t, word).unwrap_or_else(|| panic!("HOLE on {word:#034x}"));
        assert_eq!(
            got, want,
            "word {word:#034x} (arb273 A1/A5 + arb297b Hc1/Hc4 + arb297 J1)"
        );
    }
}

#[test]
fn t297_2_decode_invalid1_sm121a_and_legal_values() {
    let t121 = tab("sm121a");
    let t120 = tab("sm120");
    let cases: [(&IsaTable, u128, &str); 7] = [
        (&t121, a(&[H1]), "@P0 HFMA2 R1, R2, R3, UR4.INVALID1"),
        (
            &t121,
            j2c(&[H1]),
            "HSETP2.F.AND P0, PT, R2.H0_H0, UR4.INVALID1, PT",
        ),
        (&t120, a(&[H2]), "@P0 HFMA2 R1, R2, R3, UR4.H0_H0"),
        (&t120, a(&[H3]), "@P0 HFMA2 R1, R2, R3, UR4.H1_H1"),
        (&t120, hc(&[H2]), "HMUL2 R2, R0, UR4.H0_H0"),
        (
            &t120,
            j(&[H2]),
            "@P0 HSETP2.F.AND P0, P0, R3, UR4.H0_H0, P0",
        ),
        (
            &t121,
            j2c(&[H2]),
            "HSETP2.F.AND P0, PT, R2.H0_H0, UR4.H0_H0, PT",
        ),
    ];
    for (t, word, want) in cases {
        let got = dec(t, word).unwrap_or_else(|| panic!("HOLE on {word:#034x}"));
        assert_eq!(got, want, "word {word:#034x}");
    }
}

#[test]
fn t297_3_encode_legal_values_word_exact() {
    let t120 = tab("sm120");
    // Legal hsel values 2/3 mint the expected payload windows and the text
    // round-trips to its canonical vendor spelling (unchanged path).
    for (text, band) in [
        ("HFMA2 R1, R2, R3, UR4.H0_H0", 0b0010u128),
        ("HFMA2 R1, R2, R3, UR4.H1_H1", 0b0011u128),
        ("HFMA2 R1, R2, R3, |UR4.H0_H0|", 0b0110u128),
        ("HFMA2 R1, R2, R3, -|UR4.H0_H0|", 0b1110u128),
    ] {
        let word = enc(&t120, text).unwrap();
        assert_eq!((word >> 60) & 0xF, band, "payload band of {text}");
        assert_eq!(dec(&t120, word).as_deref(), Some(text), "roundtrip {text}");
    }
    let t121 = tab("sm121a");
    assert_eq!(
        dec(
            &t121,
            enc(&t121, "HMUL2.BF16_V2 R1, R2, |UR4.H0_H0|").unwrap()
        )
        .as_deref(),
        Some("HMUL2.BF16_V2 R1, R2, |UR4.H0_H0|")
    );
}

#[test]
fn t297_4_encode_h0h1_on_scoped_ur_fails_closed() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for text in [
            "HFMA2 R1, R2, R3, UR4.H0_H1",
            "HFMA2 R1, R2, R3, |UR4.H0_H1|",
            "HFMA2 R1, R2, R3, |UR4|.H0_H1", // legacy tail spelling, same law
        ] {
            let e = enc(&t, text).expect_err(&format!("{arch}: `{text}` must fail closed"));
            assert!(
                e.contains("BUG-297"),
                "{arch}: `{text}` -- expected BUG-297 attribution, got: {e}"
            );
        }
    }
    let t120 = tab("sm120");
    for text in [
        "HMUL2 R2, R0, UR4.H0_H1",
        "@P2 HMUL2 R2, R0, UR4.H0_H1",
        "HSETP2.F.AND P0, P0, R3, UR4.H0_H1, P0",
    ] {
        let e = enc(&t120, text).expect_err(&format!("`{text}` must fail closed"));
        assert!(e.contains("BUG-297"), "`{text}` -- got: {e}");
    }
    // '.INVALID1' text stays refused upstream (BUG-272 suffix gate).
    let e =
        enc(&t120, "HFMA2 R1, R2, R3, UR4.INVALID1").expect_err("INVALID1 text must fail closed");
    assert!(
        e.contains("unknown operand suffix"),
        "272-gate message, got: {e}"
    );
}

#[test]
fn t297_5_sibling_laws_untouched_era() {
    // 305-kand era CLOSED (BUG-305, F2-iter152): HFMA2_R_R_UR_R tok3 UR
    // hsel=1 now prints the vendor law '.F32' (arb297 G1/I1 + arb297b G41
    // x4). This expectation was the 297-era pin of the then-unarmed
    // sibling print; flipped with attribution.
    let t120 = tab("sm120");
    let got = dec(&t120, g(&[H1])).expect("G1 decode");
    assert_eq!(
        got, "HFMA2 R1, R2, UR4.F32, R0",
        "BUG-305 armed: vendor law on the sibling row"
    );
    // FLIPPED F2-iter154 (BUG-306 armed): the 306-kand R-domain census is
    // DONE and value 1 on the HADD2 tok3 R slot (win@60) now prints the
    // vendor law '.INVALID1' (arb297 K2c x4 was exactly this word). This
    // expectation was the 297-era pin of the then-unarmed R-side print;
    // flipped with attribution.
    let t103 = tab("sm103a");
    let got = dec(&t103, dc(&[H1])).expect("K2c decode");
    assert_eq!(
        got, "@P0 HADD2.F32 R1, -RZ, R3.INVALID1",
        "BUG-306 armed: R-domain vendor law"
    );
    // R-domain legal control unchanged (arb273 D1).
    let got = dec(&t103, dc(&[H2])).expect("D1 decode");
    assert_eq!(got, "@P0 HADD2.F32 R1, -RZ, R3.H0_H0");
}
