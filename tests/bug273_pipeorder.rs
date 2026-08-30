//! BUG-273 (F2-iter148, loop5/blind front2, 2026-08-30): printer pipe-order
//! for UR operands carrying a lane suffix (hsel / h0nh1) together with the
//! abs/neg sign wrapper. Registered LOW at F2-iter136 (264 report) with
//! vendor evidence refreshed in arb271 ("|UR6.H0_NH1|" WEW pipes vs engine
//! tail form), corpus-zero.
//!
//! LAW (arb273: 132 probes, nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a agree on EVERY probe):
//!   UR domain -- suffix composes INSIDE the abs pipes:
//!     |UR4|        |UR4.H0_H0|   |UR4.H1_H1|
//!     -UR4.H0_H0   -|UR4|        -|UR4.H0_H0|
//!     BF16_V2 host: UR4.H0_NH1, |UR4.H0_NH1|, -UR4.H0_NH1, -|UR4.H0_NH1|
//!   R domain -- suffix stays OUTSIDE the pipes (engine unchanged):
//!     |R3|.H0_H0, -|R3|.H0_H0   (arb273 D-group control)
//!   reuse on the probed HFMA2/HMUL2 UR rows is vendor-ILLEGAL x4
//!     (arb273 A12..A14/B6 rc=1) -- no pipe/reuse interplay to pin.
//! PRE-FIX (measure_pre273, pub pyo3-102fcc9): engine printed the R-domain
//! tail form on the UR path: "|UR4|.H0_H0", "-|UR4|.H0_NH1", ... Post-fix
//! the UR path composes the suffix inside the wrapper. Encode-side is
//! spelling-agnostic both pre and post (272 gate + reg scrape accept
//! in-pipes and legacy tail forms -- pinned in t273_4).
//! hsel=1 reads ".INVALID1" on the HFMA2/HMUL2 UR opclass per vendor
//! (arb273 A1/A5/C4): value-validity print law = 297-kand, NOT this fix.
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
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).unwrap()
}

fn w(bits: &[(u32, u128)], base: u128) -> u128 {
    bits.iter().fold(base, |acc, &(sh, v)| acc | (v << sh))
}
// sm120 HFMA2_R_R_R_UR '' : payload R1@16, R2@24, R3@64, UR4@32
fn a(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0x80000000000000000000e31 | (1 << 16) | (2 << 24) | (4 << 32) | (3 << 64),
    )
}
// sm121a HFMA2_R_R_UR_R BF16_V2 : payload R1@16, R2@24, UR4@32, R4@64
fn b(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0x80000000000000000000c31 | (1 << 16) | (2 << 24) | (4 << 32) | (4 << 64),
    )
}
// sm121a HMUL2_R_R_UR BF16_V2 : payload R1@16, R2@24, UR4@32
fn c(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0x80000000000000000000c32 | (1 << 16) | (2 << 24) | (4 << 32),
    )
}
// sm103a HADD2_R_R_R.F32 : payload R1@16, R2@24, R3@32
fn d(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0x000fc0000000410020000000ff000230 | (1 << 16) | (2 << 24) | (3 << 32),
    )
}
const H2: (u32, u128) = (60, 2);
const H3: (u32, u128) = (60, 3);
const ABS: (u32, u128) = (62, 1);
const NEG: (u32, u128) = (63, 1);
const NH1: (u32, u128) = (86, 1);

#[test]
fn t273_1_ur_suffix_inside_pipes_sm120() {
    let t = tab("sm120");
    let cases: [(u128, &str); 7] = [
        (a(&[H2]), "@P0 HFMA2 R1, R2, R3, UR4.H0_H0"),
        (a(&[ABS]), "@P0 HFMA2 R1, R2, R3, |UR4|"),
        (a(&[ABS, H2]), "@P0 HFMA2 R1, R2, R3, |UR4.H0_H0|"),
        (a(&[ABS, H3]), "@P0 HFMA2 R1, R2, R3, |UR4.H1_H1|"),
        (a(&[NEG, H2]), "@P0 HFMA2 R1, R2, R3, -UR4.H0_H0"),
        (a(&[ABS, NEG]), "@P0 HFMA2 R1, R2, R3, -|UR4|"),
        (a(&[ABS, NEG, H2]), "@P0 HFMA2 R1, R2, R3, -|UR4.H0_H0|"),
    ];
    for (word, want) in cases {
        let got = dec(&t, word).unwrap_or_else(|| panic!("HOLE on {word:#034x}"));
        assert_eq!(got, want, "word {word:#034x}");
    }
}

#[test]
fn t273_2_ur_suffix_inside_pipes_bf16_sm121a() {
    let t = tab("sm121a");
    let cases: [(u128, &str); 6] = [
        (b(&[NH1]), "@P0 HFMA2.BF16_V2 R1, R2, UR4.H0_NH1, R4"),
        (b(&[ABS, NH1]), "@P0 HFMA2.BF16_V2 R1, R2, |UR4.H0_NH1|, R4"),
        (b(&[NEG, NH1]), "@P0 HFMA2.BF16_V2 R1, R2, -UR4.H0_NH1, R4"),
        (
            b(&[ABS, NEG, NH1]),
            "@P0 HFMA2.BF16_V2 R1, R2, -|UR4.H0_NH1|, R4",
        ),
        (c(&[ABS, H2]), "@P0 HMUL2.BF16_V2 R1, R2, |UR4.H0_H0|"),
        (c(&[ABS, H3]), "@P0 HMUL2.BF16_V2 R1, R2, |UR4.H1_H1|"),
    ];
    for (word, want) in cases {
        let got = dec(&t, word).unwrap_or_else(|| panic!("HOLE on {word:#034x}"));
        assert_eq!(got, want, "word {word:#034x}");
    }
}

#[test]
fn t273_3_r_domain_tail_form_unchanged() {
    let t = tab("sm103a");
    let cases: [(u128, &str); 4] = [
        (d(&[H2]), "@P0 HADD2.F32 R1, -RZ, R3.H0_H0"),
        (d(&[ABS]), "@P0 HADD2.F32 R1, -RZ, |R3|.H0_H0"),
        (d(&[ABS, NEG, H2]), "@P0 HADD2.F32 R1, -RZ, -|R3|.H0_H0"),
        (d(&[NEG, H2]), "@P0 HADD2.F32 R1, -RZ, -R3.H0_H0"),
    ];
    for (word, want) in cases {
        let got = dec(&t, word).unwrap_or_else(|| panic!("HOLE on {word:#034x}"));
        assert_eq!(
            got, want,
            "word {word:#034x} -- R suffix must stay OUTSIDE pipes (arb273 D)"
        );
    }
}

#[test]
fn t273_4_encode_both_spellings_same_word() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // Vendor in-pipes spelling and the pre-fix legacy tail spelling must mint
    // the SAME word (parser is spelling-agnostic; both consumed by the hsel
    // field and the 272-gate admits both shapes).
    let eq = [
        (
            "HFMA2 R1, R2, R3, |UR4.H0_H0|",
            "HFMA2 R1, R2, R3, |UR4|.H0_H0",
        ),
        (
            "HFMA2 R1, R2, R3, -|UR4.H0_H0|",
            "HFMA2 R1, R2, R3, -|UR4|.H0_H0",
        ),
        (
            "HFMA2 R1, R2, R3, |UR4.H1_H1|",
            "HFMA2 R1, R2, R3, |UR4|.H1_H1",
        ),
        (
            "HFMA2 R1, R2, R3, -UR4.H0_H0",
            "HFMA2 R1, R2, R3, -UR4.H0_H0",
        ),
    ];
    for (vendor, legacy) in eq {
        assert_eq!(
            enc(&t120, vendor),
            enc(&t120, legacy),
            "{vendor} vs {legacy}"
        );
    }
    let eq121 = [
        (
            "HFMA2.BF16_V2 R1, R2, |UR4.H0_NH1|, R4",
            "HFMA2.BF16_V2 R1, R2, |UR4|.H0_NH1, R4",
        ),
        (
            "HMUL2.BF16_V2 R1, R2, |UR4.H0_H0|",
            "HMUL2.BF16_V2 R1, R2, |UR4|.H0_H0",
        ),
    ];
    for (vendor, legacy) in eq121 {
        assert_eq!(
            enc(&t121, vendor),
            enc(&t121, legacy),
            "{vendor} vs {legacy}"
        );
    }
    // Payload pins on the minted word (arb273 composition bits).
    let w1 = enc(&t120, "HFMA2 R1, R2, R3, |UR4.H0_H0|");
    assert_eq!((w1 >> 60) & 0xF, 0b0110, "hsel=2 + abs on the UR tok4 band");
    let w2 = enc(&t120, "HFMA2 R1, R2, R3, -|UR4.H0_H0|");
    assert_eq!((w2 >> 60) & 0xF, 0b1110, "hsel=2 + abs + neg");
    let w3 = enc(&t121, "HFMA2.BF16_V2 R1, R2, |UR4.H0_NH1|, R4");
    assert_eq!((w3 >> 60) & 0x7, 0b100, "abs on band, hsel=0");
    assert_eq!((w3 >> 86) & 1, 1, "h0nh1 minted at b86");
}

#[test]
fn t273_5_roundtrip_canonical_is_in_pipes() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // decode(encode(vendor text)) == vendor text (machine-checked canonical).
    for (tab_, text) in [
        (&t120, "HFMA2 R1, R2, R3, |UR4.H0_H0|"),
        (&t120, "HFMA2 R1, R2, R3, -|UR4.H0_H0|"),
        (&t121, "HFMA2.BF16_V2 R1, R2, |UR4.H0_NH1|, R4"),
        (&t121, "HMUL2.BF16_V2 R1, R2, |UR4.H0_H0|"),
    ] {
        let word = enc(tab_, text);
        let got = dec(tab_, word).expect("re-decode");
        assert_eq!(
            got, text,
            "canonical roundtrip of {text} (unpredicated = PT-elided)"
        );
    }
    // Legacy tail-form input re-prints canonical in-pipes (vendor) form.
    let word = enc(&t120, "HFMA2 R1, R2, R3, |UR4|.H0_H0");
    assert_eq!(
        dec(&t120, word).unwrap(),
        "HFMA2 R1, R2, R3, |UR4.H0_H0|",
        "legacy tail form upgrades to canonical vendor spelling"
    );
}
