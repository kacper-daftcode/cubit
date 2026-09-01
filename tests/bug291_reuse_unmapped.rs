//! BUG-291 (F2-iter162, loop5/blind front2, 2026-08-31): encoder-side
//! R-domain `.reuse` on a slot the vendor reuse encoding does NOT reach
//! was SILENTLY DROPPED (272-era registered residual; tripwires t272_5 +
//! smoke272 291-residual-trip, both flipped by THIS fix).
//! PRE-FIX (measured on pub pyo3-e6774b4, work/bug291/measure_pre291.json):
//!   `IMAD R1.reuse, R2, R3, R4`, `FFMA R5.reuse, R24, R20, R5`,
//!   `IADD3 R4.reuse, P1, PT, R4, UR10, RZ` all encoded the EXACT plain
//!   word on all four table legs (sm100a/103a/120/121a) = silent loss of
//!   an authored modifier at byte production.
//! VENDOR LAW (arb291, nvdisasm 13.3.73 raw -b, x4 models agree on every
//! probe; work/bug291/arb291_verdicts.json): the ONLY bits in the 128-bit
//! word that ever print `.reuse` are 122/123/124, wired per-row to the
//! 8-bit register slots at bits 24/32/64 (full 128-bit single-flip sweep
//! on the IMAD R_R_R_R lattice + [127:104] sweeps on FFMA/LOP3/FADD/
//! HFMA2-0x231). census291 (29,685,268 corpus words, 2,406-cubin battery):
//! 2,481,633 `.reuse` prints, ALL on operand tokens 2..6, ZERO on the
//! dest token, ZERO prints with bits [124:122] clear; 21 suppressed words
//! (UR-slot hosts). There is no destination-slot reuse on Blackwell.
//! FIX (engine, src/encoder.rs check_operand_suffixes -- extension of the
//! BUG-272 suffix gate): `.reuse` must be mintable -- a data-taught
//! explicit Reuse field on the token (BUG-144 class) or the row's 8-bit
//! reg/ureg slot at bits 24/32/64 that apply_reuse_encoding's generic
//! fallback owns (mirror-exact, incl. the explicit-bit suppression rule);
//! otherwise fail closed with BUG-291 attribution. UR-at-mapped-slot
//! reuse stays OWNED by the BUG-252 guard. Gate scope stays
//! CUBIT_FIT_LINT-skippable, NOT CUBIT_DISABLE_ERRATA-unlockable.
//! REGISTERED, NOT FIXED HERE: 325-kand (encode mint of reuse bits on the
//! vendor-HOLE HFMA2 R-form class -> word nvdisasm rejects rc=1; arb
//! + publish evidence in work/bug291) and 326-kand (decode sideband
//! prints `.reuse` on those vendor-hole words; corpus exposure ZERO per
//! census291 suppressed-table).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    enc_res(t, text).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

#[test]
fn t291_1_registered_class_failclosed_all_legs() {
    // the measured pre-fix silent-drop class, now fail-closed with
    // BUG-291 attribution, on every table leg
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (plain, dst) in [
            ("IMAD R1, R2, R3, R4", "IMAD R1.reuse, R2, R3, R4"),
            ("FFMA R5, R24, R20, R5", "FFMA R5.reuse, R24, R20, R5"),
        ] {
            let e = enc_res(&t, dst)
                .expect_err(&format!("{leg}: dest-slot .reuse must fail closed: {dst}"));
            assert!(e.contains("BUG-291"), "{leg}: unexpected error text: {e}");
            // plain form untouched by the gate
            let p = enc(&t, plain);
            assert!(!e.is_empty() && p != 0);
        }
    }
    // IADD3 6-operand row, dest reuse (sm120 leg, measured pre-fix drop)
    let t = tab("sm120");
    let e = enc_res(&t, "IADD3 R4.reuse, P1, PT, R4, UR10, RZ")
        .expect_err("IADD3 dest .reuse must fail closed");
    assert!(e.contains("BUG-291"), "unexpected: {e}");
}

#[test]
fn t291_2_keep_lanes_mint_unchanged() {
    // mapped-slot lanes (generic fallback + data-taught explicit rows)
    // must mint exactly as before the fix.
    for leg in ["sm120", "sm103a"] {
        let t = tab(leg);
        let base = enc(&t, "IMAD R1, R2, R3, R4");
        assert_eq!(
            enc(&t, "IMAD R1, R2.reuse, R3, R4"),
            base | (1 << 122),
            "{leg} tok2@24"
        );
        assert_eq!(
            enc(&t, "IMAD R1, R2, R3.reuse, R4"),
            base | (1 << 123),
            "{leg} tok3@32"
        );
        assert_eq!(
            enc(&t, "IMAD R1, R2, R3, R4.reuse"),
            base | (1 << 124),
            "{leg} tok4@64"
        );
    }
    // t266_5 sibling pin, unchanged-on-purpose: the LEA_P0 reuse lane on
    // sm121a (slot bits from the operand flag)
    let t121 = tab("sm121a");
    let w = enc(&t121, "LEA_P0 R22, R18, R19.reuse, 0x1");
    assert_eq!((w >> 122) & 7, 2, "LEA_P0 .reuse slot bit lost");
    // data-taught explicit UR reuse field (BUG-144 class, sm120)
    let t = tab("sm120");
    let a = enc(&t, "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7");
    let b = enc(&t, "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7.reuse");
    assert_eq!(b, a | (1 << 124), "explicit UR reuse @124 stays minted");
    // explicit-field decode anchors stay exact (bug241 style)
    assert_eq!(
        dec(&t, 0x040fe2000780a009000000ff0c087212),
        Some("LOP3.LUT P0, R8, R12.reuse, RZ, R9, 0xa0, !PT".into())
    );
    assert_eq!(
        dec(&t, 0x140fe200000102070000000406197819),
        Some("SHF.L.U64.HI R25, R6.reuse, 0x4, R7.reuse".into())
    );
}

#[test]
fn t291_3_disjoint_from_bug_252_ur_guard() {
    // UR at a MAPPED slot with .reuse: still the BUG-252 attributed
    // failure (gate order: 291 mintability passes, 252 owns the verdict)
    let t = tab("sm120");
    let e = enc_res(&t, "FSEL R5, |R3|.reuse, |UR11|.reuse, !P2")
        .expect_err("UR mapped-slot reuse must keep failing");
    assert!(
        e.contains("BUG-252"),
        "expected BUG-252 attribution, got: {e}"
    );
    assert!(!e.contains("BUG-291"), "must not fall to the 291 gate: {e}");
    let e = enc_res(&t, "IMAD R4, R5, UR6.reuse, R7")
        .expect_err("UR reuse on IMAD UR-slot must keep failing");
    assert!(
        e.contains("BUG-252"),
        "expected BUG-252 attribution, got: {e}"
    );
    // all-R FSEL twin unchanged (mints)
    let p = enc(&t, "FSEL R9, |R4|, |R5|, P0");
    let r = enc(&t, "FSEL R9, |R4|.reuse, |R5|.reuse, P0");
    // FSEL_R_R_R_P: tok2->b122, tok3->b123 (explicit row fields)
    assert_eq!(r, p | (1 << 122) | (1 << 123), "FSEL all-R reuse lanes");
}

#[test]
fn t291_4_decode_law_untouched() {
    // decoder sideband/inline reuse law: vendor reuse prints map
    // bit122->tok@24 / bit123->tok@32 / bit124->tok@64 (arb291 S5).
    // BUG-326 flip: the prints are additionally YIELD-GATED (arb325 law) --
    // this default-control word is yield=0, where vendor prints plain; the
    // decode expectations move to the yield=1 twin (byte mint unchanged).
    let t = tab("sm120");
    let base = enc(&t, "IMAD R1, R2, R3, R4");
    let mut d = dec(&t, base | (1 << 122) | (1 << 109)).expect("decode b122 y1");
    assert_eq!(d, "IMAD R1, R2.reuse, R3, R4");
    d = dec(&t, base | (1 << 124) | (1 << 109)).expect("decode b124 y1");
    assert_eq!(d, "IMAD R1, R2, R3, R4.reuse");
    // yield=0 twins print plain (vendor-exact; the bits ride !rsd in
    // fidelity flows -- byte authority covered by t326_2)
    assert_eq!(
        dec(&t, base | (1 << 122)).as_deref(),
        Some("IMAD R1, R2, R3, R4")
    );
    assert_eq!(
        dec(&t, base | (1 << 124)).as_deref(),
        Some("IMAD R1, R2, R3, R4")
    );
    // inverse roundtrip through the printed text returns the bits
    let w = enc(&t, "IMAD R1, R2.reuse, R3.reuse, R4.reuse");
    assert_eq!(w, base | (7 << 122), "all-three reuse inverse");
}

#[test]
fn t291_5_unmapped_variants_and_registered_325_evidence() {
    let t = tab("sm120");
    // dest reuse on other shapes (R dest MOV row, UR dest UMOV row)
    for text in ["MOV R17.reuse, UR6", "UMOV UR2.reuse, UR3"] {
        let e = enc_res(&t, text).expect_err(&format!("unmapped reuse must fail: {text}"));
        assert!(e.contains("BUG-291"), "{text}: unexpected error: {e}");
    }
    // guarded form: fail-closed too (registration covers guard+suffix)
    let e = enc_res(&t, "@P1 IMAD R1.reuse, R2, R3, R4").expect_err("guarded dest reuse");
    assert!(e.contains("BUG-291"), "guarded: {e}");
    // REGISTERED-NOT-FIXED (325-kand): the HFMA2 R-form lattice is a
    // vendor-HOLE for any reuse bit (arb291 S2/S4: nvdisasm rc=1 x4), yet
    // the generic fallback mints b122 today. Pin current behavior (mint)
    // so the future 325 fix flips this test.
    let p = enc(&t, "HFMA2 R1, R2, R3, R4");
    assert_eq!(
        enc(&t, "HFMA2 R1, R2.reuse, R3, R4"),
        p | (1 << 122),
        "325-kand: vendor-hole reuse mint changed -- flip with its fix"
    );
    // ROUNDTRIP EDGE (326-kand lane): corpus lines carry the disassembler's
    // `!rsd[...]` byte-authority overlay (encoder.rs:2793 doctrine) exactly
    // where donor-grafted rows mismatch vendor semantics; the 291 gate
    // defers to the authored overlay there (text authored WITHOUT it still
    // fails closed below). Witness: cusolver/libcusolver.so.1574
    //   /*06d0*/ LEA.HI.X R9, R15.reuse, R6, R16.reuse, 0x2, P0 !rsd[122:0]
    // (vendor x4 prints reuse ONLY on R16: the row's reuse@124 field is
    // grafted onto tok2 -- phantom print + rsd cancel keep bytes exact).
    let w = enc_res(
        &t,
        "LEA.HI.X R9, R15.reuse, R6, R16.reuse, 0x2, P0 !rsd[122:0]",
    )
    .expect("rsd-authored overlay line must keep roundtripping byte-exact");
    let orig: u128 = 0x100fe400000f1410000000060f097211;
    // byte-exact on the instruction+reuse bits (ctl sched upper32 is the
    // encoder default; compare [127:96]-stripped plus reuse band)
    assert_eq!(
        w & !ctl_mask(),
        orig & !ctl_mask(),
        "rsd-authored LEA.HI-X witness byte drift"
    );
    // covered-alias lane (vendor-intent bit produced by another authored
    // .reuse through the quirk binding): dual-reuse text WITHOUT the
    // overlay keeps encoding the SAME hybrid word as pre-fix (tok2's
    // explicit 122+124 pair mints both band bits -- byte-preserving
    // w.r.t. the old behavior, rsd not required anymore for this shape);
    // tok4-ONLY authored text (no other reuse token covers b124) still
    // fails closed -- its intent would vanish byte-wise.
    let w2 = enc(&t, "LEA.HI.X R9, R15.reuse, R6, R16.reuse, 0x2, P0");
    assert_eq!(
        (w2 >> 122) & 7,
        0b101,
        "covered-alias dual reuse: b122+b124 both mint via tok2 pair"
    );
    let e = enc_res(&t, "LEA.HI.X R9, R15, R6, R16.reuse, 0x2, P0")
        .expect_err("tok4-only .reuse on this quirk row has no mint channel");
    assert!(e.contains("BUG-291"), "unexpected: {e}");
    let e = enc_res(&t, "FFMA.RP R23, R3, R27, R24.reuse")
        .expect_err("FFMA mg=RP tok4-only .reuse has no mint channel");
    assert!(e.contains("BUG-291"), "unexpected: {e}");
    // ...while the full authored set rides the alias and stays byte-exact
    // (cuobjdump corpus witness 0x1c0fe200000080180000001b03177223):
    let w3 = enc(&t, "FFMA.RP R23, R3.reuse, R27.reuse, R24.reuse");
    assert_eq!((w3 >> 122) & 7, 0b111, "FFMA.RP alias lane mints all three");
}
fn ctl_mask() -> u128 {
    // [127:96] scheduling/mode window, MINUS the reuse band 122/123/124
    // (the whole point of this pin is that the reuse bits are the byte
    // contract of the corpus witness)
    (0xffff_ffff_u128 << 96) & !(0b111u128 << 122)
}
