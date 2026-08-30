//! BUG-305 (F2-iter152, loop5/blind front2, 2026-08-30): sibling
//! value-validity law of BUG-297 -- on the `HFMA2_R_R_UR_R` rows (UR tok3,
//! hsel window [61:60]) value 1 reads as the vendor `.F32` operand
//! modifier, NOT '.H0_H1' (generic fallback misprint) and NOT '.INVALID1'
//! (that law is keyed to the HFMA2_R_R_R_UR / HMUL2_R_R_UR /
//! HSETP2_P_P_R_UR_P rows only).
//!
//! LAW (arb297 G1/I1 + arb297b G41: nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a agree on EVERY probe):
//!   key HFMA2_R_R_UR_R, UR tok3:  hsel 0 -> ''        hsel 1 -> '.F32'
//!                                 hsel 2 -> '.H0_H0'  hsel 3 -> '.H1_H1'
//!   signs compose inside the pipes (sm121a BF16_V2 lattice carries
//!   abs@62/neg@63 on tok3): '|UR4.F32|', '-UR4.F32' (arb297 I2/I3).
//! PRE-FIX (measure_pre305, pub pyo3-5abb6f4): decode printed '.H0_H1' on
//! every hsel=1 probe of this key (both lattices, all legs); encode-side
//! authored 'URn.F32' was refused by the BUG-272 suffix gate (fail-closed,
//! safe) while authored 'URn.H0_H1' MINTED the value-1 word that vendor
//! reads back as '.F32' (silent text-vs-vendor divergence).
//! CORPUS EXPOSURE ZERO (routex297 x2 bundle legs + routex305 re-run: no
//! hsel==1 word on any HFMA2_R_R_UR_R row).
//! Siblings measured and NOT armed here: 306-kand (R-domain per-window v1
//! laws), 307-note (era key `HFMA2.BF16_V2_R_R_UR_R` / sm121a BF16 encode
//! mnemod routing -- IDENT old==new), the pre-existing abs-less sm120/103a
//! '' rows (tok3 sign-drop class, BUG-303 lane).
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
// sm120/sm103a HFMA2_R_R_UR_R '' (legacy lattice): R1@16, R2@24, UR4@32 (arb297 G)
fn g(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0xfc000080000000000000000007c31 | (1 << 16) | (2 << 24) | (4 << 32),
    )
}
// sm120 HFMA2_R_R_UR_R 'BF16_V2' donor lattice (arb297b G4)
fn g4(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0xfc000082000000000000000007c31 | (1 << 16) | (2 << 24) | (4 << 32),
    )
}
// sm121a HFMA2_R_R_UR_R 'BF16_V2' : @P0 guard + R1@16, R2@24, UR4@32, R4@64 (arb297 I)
fn i(bits: &[(u32, u128)]) -> u128 {
    w(
        bits,
        0x80000000000000000000c31 | (1 << 16) | (2 << 24) | (4 << 32) | (4 << 64),
    )
}
const H1: (u32, u128) = (60, 1);
const H2: (u32, u128) = (60, 2);
const H3: (u32, u128) = (60, 3);
const ABS: (u32, u128) = (62, 1);
const NEG: (u32, u128) = (63, 1);

#[test]
fn t305_1_decode_f32_law_both_lattices() {
    let t120 = tab("sm120");
    let t103 = tab("sm103a");
    // hsel=1 -> vendor '.F32' (arb297 G1, x4 models), legacy lattice, 2 legs
    for t in [&t120, &t103] {
        let got = dec(t, g(&[H1])).expect("G1 decode");
        assert_eq!(got, "HFMA2 R1, R2, UR4.F32, R0", "arb297 G1 law");
    }
    // BF16_V2 donor lattice (arb297b G41, x4 models)
    assert_eq!(
        dec(&t120, g4(&[H1])).expect("G41 decode"),
        "HFMA2.BF16_V2 R1, R2, UR4.F32, R0"
    );
    // Legal values and the empty window keep their generic mapping
    // (arb297 G0/G2/G3, vendor parity unchanged).
    assert_eq!(
        dec(&t120, g(&[])).expect("G0 decode"),
        "HFMA2 R1, R2, UR4, R0"
    );
    assert_eq!(
        dec(&t120, g(&[H2])).expect("G2 decode"),
        "HFMA2 R1, R2, UR4.H0_H0, R0"
    );
    assert_eq!(
        dec(&t120, g(&[H3])).expect("G3 decode"),
        "HFMA2 R1, R2, UR4.H1_H1, R0"
    );
}

#[test]
fn t305_2_decode_sm121a_signwraps_compose_in_pipes() {
    let t121 = tab("sm121a");
    // arb297 I1/I2/I3 (x4 models): the marker composes INSIDE the sign
    // wrapper exactly like the BUG-297 INVALID1 marker (post-273 position).
    assert_eq!(
        dec(&t121, i(&[H1])).expect("I1 decode"),
        "@P0 HFMA2.BF16_V2 R1, R2, UR4.F32, R4"
    );
    assert_eq!(
        dec(&t121, i(&[ABS, H1])).expect("I2 decode"),
        "@P0 HFMA2.BF16_V2 R1, R2, |UR4.F32|, R4"
    );
    assert_eq!(
        dec(&t121, i(&[NEG, H1])).expect("I3 decode"),
        "@P0 HFMA2.BF16_V2 R1, R2, -UR4.F32, R4"
    );
}

#[test]
fn t305_3_encode_f32_word_exact_and_roundtrip() {
    let t120 = tab("sm120");
    // '.F32' mints hsel value 1: engine payload == the arb297 G1 vendor
    // word in the 96-bit payload model (the [127:96] control stub is
    // composed by the epoch law, not by the row and_base -- same
    // comparison basis as verify_enc305_post and the t297_3 bands).
    let word = enc(&t120, "HFMA2 R1, R2, UR4.F32, R0").expect("enc .F32 sm120");
    assert_eq!(word & M96, g(&[H1]) & M96, "payload-exact vs arb297 G1");
    assert_eq!((word >> 60) & 3, 1, "hsel band minted");
    assert_eq!(
        dec(&t120, word).as_deref(),
        Some("HFMA2 R1, R2, UR4.F32, R0"),
        "roundtrip canonical"
    );
    // Guarded form mints only the guard bits on top of the same law.
    let wg = enc(&t120, "@P2 HFMA2 R1, R2, UR4.F32, R0").expect("enc guarded .F32");
    assert_eq!((wg >> 60) & 3, 1, "guarded .F32 hsel band");
    assert_eq!(
        dec(&t120, wg).as_deref(),
        Some("@P2 HFMA2 R1, R2, UR4.F32, R0")
    );
    // Legal half-select spellings unchanged (encode + canonical roundtrip).
    for text in ["HFMA2 R1, R2, UR4.H0_H0, R0", "HFMA2 R1, R2, UR4.H1_H1, R0"] {
        let word = enc(&t120, text).unwrap();
        assert_eq!(dec(&t120, word).as_deref(), Some(text), "roundtrip {text}");
    }
    // sm121a (BF16_V2 lattice carries abs@62 on tok3): the legacy tail
    // spelling '|UR4|.F32' mints the same word as the in-pipes spelling
    // '|UR4.F32|' (parser spelling-agnostic, BUG-273 doctrine), and the
    // abs bit lands in the auth band.
    let t121 = tab("sm121a");
    let inp = enc(&t121, "HFMA2.BF16_V2 R1, R2, |UR4.F32|, R0").expect("in-pipes enc");
    let tail = enc(&t121, "HFMA2.BF16_V2 R1, R2, |UR4|.F32, R0");
    assert_eq!(tail, Ok(inp), "tail spelling aliases in-pipes");
    assert_eq!((inp >> 62) & 1, 1, "abs band minted");
    assert_eq!((inp >> 60) & 3, 1, "hsel band minted via .F32");
    assert_eq!(
        dec(&t121, inp).as_deref(),
        Some("HFMA2.BF16_V2 R1, R2, |UR4.F32|, R0"),
        "canonical roundtrip of the in-pipes form"
    );
    // NB: the sm120/sm103a '' rows carry NO abs/neg field on tok3
    // (pre-existing under-coverage, BUG-303 sibling lane) -- sign-wrap
    // encode is pinned on the fielded sm121a lattice only.
}

#[test]
fn t305_4_encode_h0h1_on_this_key_fails_closed_attributed() {
    for arch in ["sm120", "sm103a"] {
        let t = tab(arch);
        for text in [
            "HFMA2 R1, R2, UR4.H0_H1, R0",
            "@P0 HFMA2 R1, R2, UR4.H0_H1, R0",
            "HFMA2 R1, R2, |UR4.H0_H1|, R0",
            "HFMA2 R1, R2, |UR4|.H0_H1, R0", // legacy tail spelling, same law
        ] {
            let e = enc(&t, text).expect_err(&format!("{arch}: `{text}` must fail closed"));
            assert!(
                e.contains("BUG-305"),
                "{arch}: `{text}` -- expected BUG-305 attribution, got: {e}"
            );
        }
    }
    // sm121a carries ONLY the BF16_V2 mod-group for this key, so the
    // authored text routes through the mnemod form (same key/law).
    let t121 = tab("sm121a");
    for text in [
        "HFMA2.BF16_V2 R1, R2, UR4.H0_H1, R0",
        "HFMA2.BF16_V2 R1, R2, |UR4.H0_H1|, R0",
    ] {
        let e = enc(&t121, text).expect_err(&format!("sm121a: `{text}` must fail closed"));
        assert!(e.contains("BUG-305"), "sm121a: `{text}` -- got: {e}");
    }
    // '.F32' stays refused on the BUG-297 INVALID1 rows (gate scope check)
    // and '.INVALID1' is refused upstream everywhere by the 272 gate.
    let t120 = tab("sm120");
    let e = enc(&t120, "HMUL2 R2, R0, UR4.F32").expect_err("F32 on 297-row closed");
    assert!(e.contains("unknown operand suffix"), "272-gate, got: {e}");
    let e = enc(&t120, "HFMA2 R1, R2, UR4.INVALID1, R0").expect_err("INVALID1 text closed");
    assert!(e.contains("unknown operand suffix"), "272-gate, got: {e}");
}

#[test]
fn t305_5_doctrine_siblings_hold() {
    let t120 = tab("sm120");
    // BUG-297 law intact on its own scope: decode '.INVALID1' + encode
    // fail-closed with BUG-297 attribution.
    let hm = w(
        &[H1],
        (0x000fc000080000003000000800027c32 & !(3u128 << 60) & !(0xFFu128 << 32)) | (4 << 32),
    );
    assert_eq!(
        dec(&t120, hm).expect("Hc1 decode"),
        "HMUL2 R2, R0, UR4.INVALID1"
    );
    let e = enc(&t120, "HMUL2 R2, R0, UR4.H0_H1").expect_err("297-arm holds");
    assert!(e.contains("BUG-297"), "got: {e}");
    // FLIPPED F2-iter154 (BUG-306 armed): the R-domain census is DONE and
    // the tok2 R slot at win@74 prints the vendor law '.INVALID1' (arb297
    // K3 x4 was exactly this word). This expectation was the 305-era pin
    // of the then-pending R-side print; flipped with attribution.
    let k3 = w(
        &[(74, 1)],
        0x80000000000000000000e31 | (1 << 16) | (2 << 24) | (4 << 32) | (3 << 64),
    );
    assert_eq!(
        dec(&t120, k3).expect("K3 decode"),
        "@P0 HFMA2 R1, R2.INVALID1, R3, UR4"
    );
    // Era holds: the era-baked word keeps IDENT prints pre/post on both
    // routes (engine-measured): its [61:60] value is 2 (legal '.H0_H0',
    // the fix only re-keys value 1) and the era stub key has no hsel
    // field at all, so the printer law never fires on either.
    let era = 0x00000000082408052000000402057c31u128;
    assert_eq!(
        dec(&t120, era).expect("era-word decode sm120"),
        "HFMA2.BF16_V2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0"
    );
    let t121 = tab("sm121a");
    assert_eq!(
        dec(&t121, era).expect("era-word decode sm121a"),
        "HFMA2.BF16_V2 R5, R2, UR0, R5"
    );
}
