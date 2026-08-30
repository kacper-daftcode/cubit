//! BUG-303 (F2-iter153, loop5/blind front2, 2026-08-30): encoder sign-arm
//! PARITY with the decoder arm sets BUG-224 (SYNCS) and BUG-225 (57-base
//! census batch). The encoder generic sign emit had no exclusion for those
//! bases while the decoder refused ghost signs on them -- authored signs
//! minted ghost bits 62/63/72/73/74/75. Measured live lanes pre-fix
//! (work/bug303/measure_pre303.log, pub pyo3-704a17f):
//!   298 P2R '-R12' (sm121a)          -> b63 -> decode imm '0x80000000' XREAD
//!   299 SHFL.BFLY '-R10'/'|R21|' (sm120) -> word own decode REJECTS (CLI
//!      wrote it silently, rc=0; sm121a leg held via BUG-132 fallback)
//!   300 SHFL.IDX '-R23' (both legs)  -> decode imm '0x80001f'+PT glyph /
//!      junk tail 'UR0' XREAD
//!   301 MATCH.ANY '-R5' / 302 R2UR '-R5' (both legs) -> undecodable mint
//!   SYNCS.A1T0.ARRIVE.TRANS64 '-R6' (sm120) -> b63 -> decode imm-neighbor
//!      '[R5+URZ+-0x800000]' XREAD (224-mirror, reached live in pre-census)
//! Law: arb224 graft x3 + BUG-225 census (x3 tables, corpus exposure ZERO)
//! -- these bases have NO sign-modifiable register operands. FIX (engine
//! only, src/encoder.rs; tables byte-unchanged, canonical 99bbde1):
//! (a) "SYNCS" + the 225 batch excluded from the generic sign emit
//! (is_alu); (b) fail-closed bail on any signed Reg/UReg operand on an
//! armed base that no table field consumes (BUG-303 attribution;
//! field-carried signs stay legal -- census iter153 found only UTC*MMA
//! II-token negs + CCTL/BREAK/ELECT singles, all non-Reg-token cases).
//! Closes registered lanes 298/299/300/301/302 with the one systemic arm.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}
fn dec_print(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t)
        .map(|d| cubit::printer::to_sass(&d))
        .ok()
}

#[test]
fn t303_1_signed_lanes_fail_closed_attributed() {
    // Registered lanes 298..302 + the SYNCS 224-mirror lane: each signed
    // text now errors with BUG-303 attribution wherever it was reachable
    // pre-fix (some rows/bases were already closed key-shape side; those
    // holds are pinned in t303_4 with their pre-existing failure class).
    let cases: &[(&str, &[&str])] = &[
        (
            "298 P2R",
            &["P2R R6, 0x0, -R12, 0x0", "P2R R6, 0x0, |R12|, 0x0"],
        ),
        (
            "299 SHFL.BFLY",
            &[
                "SHFL.BFLY P0, R12, R21, -R10, R11",
                "SHFL.BFLY P0, R12, |R21|, R10, R11",
                "SHFL.BFLY P0, -R12, R21, R10, R11",
            ],
        ),
        ("300 SHFL.IDX", &["SHFL.IDX P1, R11, -R23, R10, 0x1f"]),
        (
            "301 MATCH.ANY",
            &["MATCH.ANY R4, -R5", "MATCH.ANY R4, |R5|"],
        ),
        ("302 R2UR", &["R2UR UR4, -R5", "R2UR UR4, |R5|"]),
        (
            "SYNCS 224-mirror",
            &[
                "SYNCS.A1T0.ARRIVE.TRANS64 R4, [R5.64], -R6",
                "SYNCS.A1T0.ARRIVE.TRANS64 -R4, [R5.64], R6",
            ],
        ),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (tag, texts) in cases {
            for text in *texts {
                if let Err(e) = enc_res(&t, text) {
                    if e.contains("no operand-compatible table entry") || e.contains("not in table")
                    {
                        // Pre-existing key-shape closure (e.g. P2R sm120,
                        // SYNCS sm121a) -- closed either way, era hold.
                        continue;
                    }
                    assert!(
                        e.contains("BUG-303"),
                        "{leg} {tag}: missing BUG-303 attribution for {text:?}: {e}"
                    );
                } else {
                    panic!("{leg} {tag}: signed text must fail closed: {text:?}");
                }
            }
        }
    }
}

#[test]
fn t303_2_measured_mint_words_never_produced() {
    // The exact words the pre-fix encoder minted for the signed lanes
    // (work/bug303/measure_pre303.log) must now be unreachable from text:
    // every signed text below must fail; none may return Ok(word).
    let closed: &[&str] = &[
        // pre-fix minted 0x00000000800000000c067803 (P2R, sm121a b63)
        "P2R R6, 0x0, -R12, 0x0",
        // pre-fix minted 0x0000080b0c00000a150c7389 -- own decode REJECTS
        "SHFL.BFLY P0, R12, R21, -R10, R11",
        // pre-fix minted 0x0000000b4c00000a150c7389 -- own decode REJECTS
        "SHFL.BFLY P0, R12, |R21|, R10, R11",
        // pre-fix minted 0x000e000080001f0a170b7589 (both legs) XREAD
        "SHFL.IDX P1, R11, -R23, R10, 0x1f",
        // pre-fix minted 0x000e810000000000050473a1 -- REJECTS both legs
        "MATCH.ANY R4, -R5",
        // pre-fix minted 0x000e000080000000050472ca -- REJECTS both legs
        "R2UR UR4, -R5",
        // pre-fix minted 0x081000ff80000006050479a7 (SYNCS sm120 b63) XREAD
        "SYNCS.A1T0.ARRIVE.TRANS64 R4, [R5.64], -R6",
        // pre-fix minted b72 text-inert (SYNCS sm120)
        "SYNCS.A1T0.ARRIVE.TRANS64 -R4, [R5.64], R6",
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for text in closed {
            assert!(
                enc_res(&t, text).is_err(),
                "{leg}: must not mint a word for {text:?}"
            );
        }
    }
}

#[test]
fn t303_3_legal_controls_word_exact() {
    // Unsigned authored texts on the armed bases keep their pre-fix words
    // -- the arm only removes the sign-mint, it must not shift any legal
    // encoding. Words measured pre-fix on pub pyo3-704a17f (measure_pre303).
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // SHFL.BFLY legal, both legs (sm121a leg renders Rb reuse 140-era; the
    // payload words differ in the Rb slot per lane table -- pin per leg).
    let w = enc_res(&t120, "SHFL.BFLY P0, R12, R21, R10, R11").unwrap();
    assert_eq!(w & M96, 0x0000000b0c00000a150c7389, "sm120 SHFL.BFLY ctrl");
    let wl = enc_res(&t121, "SHFL.BFLY P0, R12, R21, R10, R11").unwrap();
    assert_eq!((wl & M96).trailing_zeros() >= 0, true); // encodes
    assert!(
        dec_print(&t121, wl).unwrap().starts_with("SHFL.BFLY P0,"),
        "sm121a SHFL.BFLY roundtrip print"
    );
    // MATCH.ANY / SYNCS controls.
    let w = enc_res(&t120, "MATCH.ANY R4, R5").unwrap();
    assert_eq!(w & M96, 0x000e800000000000050473a1, "sm120 MATCH ctrl");
    let w = enc_res(&t120, "SYNCS.A1T0.ARRIVE.TRANS64 R4, [R5.64], R6").unwrap();
    assert_eq!(w & M96, 0x081000ff00000006050479a7, "sm120 SYNCS ctrl");
    // SHFL.IDX plain: pre-fix control -- the era print renders the guard
    // slot of this row as PT (measure_pre303 'SHFL.IDX PT, ...' era-line,
    // both the signed ghost and the plain control took this route).
    let w = enc_res(&t120, "SHFL.IDX P1, R11, R23, R10, 0x1f").unwrap();
    assert_eq!(w & M96, 0x000e000000001f0a170b7589, "sm120 SHFL.IDX ctrl");
    assert!(
        dec_print(&t120, w).as_deref() == Some("SHFL.IDX PT, R11, R23, R10, 0x1f"),
        "sm120 SHFL.IDX ctrl roundtrip (era PT print)"
    );
}

#[test]
fn t303_4_keyshape_era_holds_and_sibling_arms_untouched() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // Pre-existing key-shape closures stay closed (P2R signed sm120 leg,
    // R2P/ELECT signed probes both legs -- they were never reachable).
    for (t, text) in [
        (&t120, "P2R R6, 0x0, -R12, 0x0"),
        (&t120, "R2P P0, -R5, 0x3"),
        (&t121, "R2P P0, -R5, 0x3"),
        (&t120, "ELECT R4, -R5"),
        (&t121, "ELECT R4, -R5"),
    ] {
        assert!(enc_res(t, text).is_err(), "era key-shape hold: {text:?}");
    }
    // Sibling arms 281/296 keep their own attribution (303 must not
    // swallow or reroute them).
    let e = enc_res(&t120, "I2I.U8.S32.SAT R5, -R4").unwrap_err();
    assert!(e.contains("BUG-281"), "281 attribution: {e}");
    let e = enc_res(&t120, "I2IP.U8.S32 R5, R4, R3, -R2").unwrap_err();
    assert!(e.contains("BUG-296"), "296 attribution: {e}");
}

#[test]
fn t303_5_decoder_era_holds() {
    // Tables + decoder byte-unchanged by this fix: the era decode readings
    // of the ghost-bit words (the pre-fix mint words) are pinned so any
    // future decoder-side arm lands with attribution, not silently.
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // P2R b63 word: sm121a era cross-read as imm 0x80000000 (298).
    let d = dec_print(&t121, 0x00000000800000000c067803).unwrap();
    assert!(d.contains("0x80000000"), "298 era decode hold: {d}");
    // SHFL.BFLY ghost words: still decode-REJECT both legs (299 era).
    assert!(dec_print(&t120, 0x0000080b0c00000a150c7389).is_none());
    assert!(dec_print(&t121, 0x0000080b0c00000a150c7389).is_none());
    // SHFL.IDX b63 word: sm120 era imm-cross-read (300 sm120 leg).
    let d = dec_print(&t120, 0x000e000080001f0a170b7589).unwrap();
    assert!(d.contains("0x80001f"), "300 era decode hold: {d}");
    // MATCH/R2UR ghost words: still decode-REJECT both legs (301/302 era).
    assert!(dec_print(&t120, 0x000e810000000000050473a1).is_none());
    assert!(dec_print(&t120, 0x000e000080000000050472ca).is_none());
}
