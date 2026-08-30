//! BUG-306 (F2-iter154, loop5/blind front2, 2026-08-30): R-domain
//! half-select value-1 slot laws -- per-window census arm of the 306-kand
//! registered at F2-iter151 (297 report sec.6, evidence arb297 K3/K2c).
//!
//! LAW (arb306: nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/
//! SM121a agree on every probe; full slot inventory = every table row x4
//! legs carrying an hsel field on an R-class token (306 row-instances,
//! 172 lattice groups, 171 decodable, ZERO mixed classes)):
//!   * v1 = vendor '.INVALID1' on EVERY R-class hsel slot of
//!     HADD2 (tok2@74, tok3@60), HMUL2 (tok2@74, tok3@60), HMNMX2
//!     (tok2@74, tok3@60), HSETP2 (tok3@74, tok4@60), and on HFMA2 tok2
//!     (win@74; arb297 K3) + HFMA2 tok4 (win@81);
//!   * v1 = vendor '.F32' on the HFMA2 tok3 R-class slots (win@60 on the
//!     HFMA2_R_R_R_R rows, win@81 on the other R-carrying HFMA2 rows;
//!     arb297 K1 + arb306 G7/G9/G57) -- R-side mirror of the BUG-305 UR
//!     law, subsuming the BUG-279 imm-family arm on its R tokens;
//!   * values 2/3 keep the shared '.H0_H0'/'.H1_H1' mapping everywhere.
//! PRE-FIX (measure_pre306, pub pyo3-740b191): decode printed '.H0_H1' on
//! every INVALID1-class v1 probe and on the plain-row '.F32' slots
//! (misprints); encode MINTED v1 from authored '.H0_H1' on HADD2/HMUL2/
//! HFMA2 slots (silent wrong-code class), while '.F32' on non-immfam rows
//! was 272-refused (safe). HSETP2/HMNMX2 authored hsel-v1 spellings were
//! already entry-lookup refused (safe; unchanged here).
//! CORPUS EXPOSURE ZERO (routex306, 2,406-cubin battery x4 legs: no
//! hsel==1 word on ANY R-class hsel slot; the 117,894 fingerprint
//! collisions on the weak sm121a FI_FI row decode as LEA/ULEA/UTMASTG,
//! verify_fifi: H-family claims 0). Sibling scopes stay disjoint: UR
//! tokens = BUG-297/305 laws; imm/FI tokens = BUG-279 lanes.
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

#[test]
fn t306_1_decode_invalid1_classes_vendor_exact() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // arb306 v1 words == vendor text, one representative per INVALID1
    // slot-class (x4 models agree in arb; engine checked on the leg whose
    // lattice carries the row).
    let cases: &[(&IsaTable, u128, &str)] = &[
        (
            &t120,
            0x000fc000000004000000000403020230,
            "@P0 HADD2 R2, R3.INVALID1, R4",
        ), // G0 tok2@74
        (
            &t120,
            0x000fc000000000001000000403020230,
            "@P0 HADD2 R2, R3, R4.INVALID1",
        ), // G1 tok3@60
        (
            &t120,
            0x000fc000000004000000000403020232,
            "@P0 HMUL2 R2, R3.INVALID1, R4",
        ), // G16 tok2@74
        (
            &t120,
            0x000fc000000000001000000403020232,
            "@P0 HMUL2 R2, R3, R4.INVALID1",
        ), // G17 tok3@60
        (
            &t120,
            0x00000000000004000000000403020240,
            "@P0 HMNMX2 R2, R3.INVALID1, R4, P0",
        ), // G106 tok2@74
        (
            &t120,
            0x00000000000000001000000403020240,
            "@P0 HMNMX2 R2, R3, R4.INVALID1, P0",
        ), // G107 tok3@60
        (
            &t120,
            0x000fc000000004050000000403020231,
            "@P0 HFMA2 R2, R3.INVALID1, R4, R5",
        ), // G6 tok2@74
        (
            &t120,
            0x000fc000000200050000000403020231,
            "@P0 HFMA2 R2, R3, R4, R5.INVALID1",
        ), // G8 tok4@81
        (
            &t121,
            0x000fc00003f024002000000504000234,
            "@P0 HSETP2.EQ.AND P0, PT, R4.INVALID1, R5.H0_H0, PT",
        ), // G22 tok3@74
        (
            &t121,
            0x000fc00003f028001000000504000234,
            "@P0 HSETP2.EQ.AND P0, PT, R4.H0_H0, R5.INVALID1, PT",
        ), // G23 tok4@60
    ];
    for (t, wv, want) in cases {
        assert_eq!(
            dec(t, wv & M96).as_deref(),
            Some(*want),
            "INVALID1 law {want}"
        );
    }
}

#[test]
fn t306_2_decode_f32_law_and_legal_values() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // '.F32' law on the HFMA2 tok3 R slot: win@60 (arb306 G7) and win@81
    // (arb306 G57, II_FI row) both legs where the lattice lives.
    assert_eq!(
        dec(&t120, 0x000fc000000000051000000403020231 & M96).as_deref(),
        Some("@P0 HFMA2 R2, R3, R4.F32, R5")
    );
    for t in [&t120, &t121] {
        assert_eq!(
            dec(t, 0x00000000000200040000000003020431 & M96).as_deref(),
            Some("@P0 HFMA2 R2, R3, R4.F32, 0, 0")
        );
    }
    // Legal values 2/3 keep the shared mapping (G0/G6/G7/G8/G22 bands).
    for (t, wv, want) in [
        (
            &t120,
            0x000fc000000008000000000403020230u128,
            "@P0 HADD2 R2, R3.H0_H0, R4",
        ),
        (
            &t120,
            0x000fc00000000c000000000403020230u128,
            "@P0 HADD2 R2, R3.H1_H1, R4",
        ),
        (
            &t120,
            0x000fc000000000052000000403020231u128,
            "@P0 HFMA2 R2, R3, R4.H0_H0, R5",
        ),
        (
            &t120,
            0x000fc000000000053000000403020231u128,
            "@P0 HFMA2 R2, R3, R4.H1_H1, R5",
        ),
        (
            &t120,
            0x000fc000000400050000000403020231u128,
            "@P0 HFMA2 R2, R3, R4, R5.H0_H0",
        ),
        (
            &t121,
            0x000fc00003f02c002000000504000234u128,
            "@P0 HSETP2.EQ.AND P0, PT, R4.H1_H1, R5.H0_H0, PT",
        ),
    ] {
        assert_eq!(
            dec(t, wv & M96).as_deref(),
            Some(want),
            "legal v2/v3 {want}"
        );
    }
    // v0 (empty window) prints no suffix.
    assert_eq!(
        dec(&t120, 0x000fc000000000050000000403020231 & M96).as_deref(),
        Some("@P0 HFMA2 R2, R3, R4, R5")
    );
}

#[test]
fn t306_3_encode_f32_mints_and_roundtrips() {
    let t120 = tab("sm120");
    // '.F32' on the HFMA2 tok3 R slot mints hsel value 1, payload-exact vs
    // the arb306 G7 vendor word in the 96-bit payload model (control stub
    // composed by the epoch law -- same basis as the t297_3/t305_3 bands).
    let word = enc(&t120, "@P0 HFMA2 R2, R3, R4.F32, R5").expect("enc .F32 tok3");
    assert_eq!(
        word & M96,
        0x000fc000000000051000000403020231u128 & M96,
        "payload-exact vs arb306 G7"
    );
    assert_eq!((word >> 60) & 3, 1, "win@60 minted");
    assert_eq!(
        dec(&t120, word).as_deref(),
        Some("@P0 HFMA2 R2, R3, R4.F32, R5"),
        "roundtrip canonical"
    );
    // Unguarded spelling mints the same law on top of no guard.
    let w2 = enc(&t120, "HFMA2 R1, R2, R3.F32, R4").expect("enc .F32 unguarded");
    assert_eq!((w2 >> 60) & 3, 1, "win@60 minted");
    assert_eq!(dec(&t120, w2).as_deref(), Some("HFMA2 R1, R2, R3.F32, R4"));
    // win@81 II_FI row (arb306 G57): the '.F32' arm mints the same band
    // and leaves every other band byte-identical to the legal-spelling
    // mints (law locality compare; payload-exact vs the vendor word is
    // BLOCKED by a pre-existing tok2 mint-drop on the II-tail HFMA2 rows
    // -- era pre-existing on pub 740b191 (plain texts IDENT), registered
    // F2-iter154 as 312-kand, NOT a 306-scope item).
    let base = enc(&t120, "@P0 HFMA2 R2, R3, R4.H0_H0, 0, 0").expect("enc .H0_H0 II_FI");
    let w3 = enc(&t120, "@P0 HFMA2 R2, R3, R4.F32, 0, 0").expect("enc .F32 II_FI");
    let w3b = enc(&t120, "@P0 HFMA2 R2, R3, R4.H1_H1, 0, 0").expect("enc .H1_H1 II_FI");
    assert_eq!((w3 >> 81) & 3, 1, "win@81 minted via .F32");
    assert_eq!((base >> 81) & 3, 2, "win@81 minted via .H0_H0");
    assert_eq!((w3b >> 81) & 3, 3, "win@81 minted via .H1_H1");
    assert_eq!(
        w3 & !(3u128 << 81) & M96,
        base & !(3u128 << 81) & M96,
        "law-local: .F32 vs .H0_H0 outside the window"
    );
    // Legal spellings unchanged on the F32 slot.
    for text in [
        "@P0 HFMA2 R2, R3, R4.H0_H0, R5",
        "@P0 HFMA2 R2, R3, R4.H1_H1, R5",
    ] {
        let word = enc(&t120, text).unwrap();
        assert_eq!(dec(&t120, word).as_deref(), Some(text), "roundtrip {text}");
    }
}

#[test]
fn t306_4_encode_h0h1_fails_closed_attributed() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // INVALID1-class slots: '.H0_H1' fail-closed with BUG-306 attribution
    // (pre-fix all of these MINTED the vendor-illegal word, measure_pre306).
    for (t, text) in [
        (&t120, "HADD2 R1, R2.H0_H1, R3"),
        (&t120, "HADD2 R1, R2, R3.H0_H1"),
        (&t120, "HMUL2 R1, R2.H0_H1, R3"),
        (&t120, "HMUL2 R1, R2, R3.H0_H1"),
        (&t120, "HFMA2 R1, R2.H0_H1, R3, R4"),
        (&t120, "HFMA2 R1, R2, R3, R4.H0_H1"),
        (&t121, "HADD2.F32 R1, R2, R3.H0_H1"),
    ] {
        let e = enc(t, text).expect_err("H0_H1 on INVALID1 slot must fail closed");
        assert!(
            e.contains("BUG-306"),
            "{text}: missing attribution, got: {e}"
        );
    }
    // '.F32'-class slot: '.H0_H1' fail-closed pointing at the vendor
    // spelling (would-read-back '.F32'; mirror of the BUG-305 arm).
    let e = enc(&t120, "HFMA2 R1, R2, R3.H0_H1, R4").expect_err("H0_H1 on F32 slot closed");
    assert!(e.contains("BUG-306"), "got: {e}");
    // HSETP2/HMNMX2 authored v1 spellings stay entry-refused (pre-existing
    // safe path; NOT re-keyed here).
    assert!(enc(&t120, "HSETP2.LT.AND P0, PT, R4.H0_H1, R5.H1_H1, PT").is_err());
    assert!(enc(&t120, "HMNMX2 R1, R2.H0_H1, R3").is_err());
}

#[test]
fn t306_5_gates_and_sibling_laws_hold() {
    let t120 = tab("sm120");
    // '.F32' refused on INVALID1-only slots (no F32 law there): 272 gate.
    for text in [
        "HFMA2 R1, R2, R3, R4.F32",
        "HADD2.F32 R1, -RZ, R3.F32",
        "HMUL2 R1, R2.F32, R3",
    ] {
        let e = enc(&t120, text).expect_err("F32 on INVALID1 slot refused");
        assert!(
            e.contains("unknown operand suffix"),
            "{text}: 272-gate, got: {e}"
        );
    }
    // '.INVALID1' text refused upstream everywhere by the 272 gate.
    let e = enc(&t120, "HADD2 R1, R2.INVALID1, R3").expect_err("INVALID1 text closed");
    assert!(e.contains("unknown operand suffix"), "272-gate, got: {e}");
    // BUG-297 UR INVALID1 law intact (own scope, UR path disjoint).
    let hm = (0x000fc000080000003000000800027c32u128 & !(3u128 << 60) & !(0xFFu128 << 32))
        | (4 << 32)
        | (1 << 60);
    assert_eq!(
        dec(&t120, hm).as_deref(),
        Some("HMUL2 R2, R0, UR4.INVALID1")
    );
    let e = enc(&t120, "HMUL2 R2, R0, UR4.H0_H1").expect_err("297-arm holds");
    assert!(e.contains("BUG-297"), "got: {e}");
    // BUG-305 UR '.F32' law intact: decode law + encode arm + attribution.
    let g1 = 0xfc000080000000000000000007c31u128 | (1 << 16) | (2 << 24) | (4 << 32) | (1 << 60);
    assert_eq!(dec(&t120, g1).as_deref(), Some("HFMA2 R1, R2, UR4.F32, R0"));
    let e = enc(&t120, "HFMA2 R1, R2, UR4.H0_H1, R0").expect_err("305-arm holds");
    assert!(e.contains("BUG-305"), "got: {e}");
    // BUG-279 immfam arm intact on its own tokens (FI hsel, 271 h0nh1).
    let era = 0x00000000082408052000000402057c31u128;
    assert_eq!(
        dec(&t120, era).as_deref(),
        Some("HFMA2.BF16_V2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0"),
        "era anchor word IDENT"
    );
}
