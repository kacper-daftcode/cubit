//! BUG-177 (F2-iter84, front2/blind; queue = fleet note 159 sec.5(b)
//! "FSEL/F32 QNAN dodatni drukuje bez '+'"): f32 NaN immediate glyph law
//! in the decode-side printer (format_float NaN arm).
//!
//! Census-first (hexdb 32.2M, work/bug177/anchors177.tsv): 6,380 vendor
//! lines with NaN immediates — FSEL +QNAN 4,132 (imm lanes 0x7FC00000
//! 2,961 + 0x7FF80000 1,171 = bimodal), FSEL -QNAN 412 (0xFFF00000 408 +
//! 0xFFFFFFFF 4), FMUL +QNAN 256 (0x7FC00000), MUFU.RSQ -QNAN 1,580
//! (0xFFC00000 = parked-159 domain, separate baked-constant arm, NOT in
//! scope here). Pre-fix cubit printed bare "QNAN" for every NaN lane
//! (both signs) — render-parity gap vs vendor on 4,800 non-MUFU anchors.
//!
//! nvdisasm 13.3.73 arbitration (work/bug177/arb/arb177.json; FSEL + FMUL
//! skeletons, both sm_103a and sm_120a tables, full-word probes):
//!   sign=0 quiet NaN  -> "+QNAN"  (0x7FC00000, 0x7FF80000, 0x7FE00000,
//!                                  0x7FC00001)
//!   sign=0 signaling  -> "+SNAN"  (0x7F800001)
//!   sign=1 quiet NaN  -> "-QNAN"  (0xFFC00000, 0xFFF00000, 0xFFF80000,
//!                                  0xFFFFFFFF)
//!   sign=1 signaling  -> "-SNAN"  (0xFF800001)
//!   INF controls      -> "+INF"/"-INF" (cubit already vendor-exact)
//! => glyph = sign bit + f32 quiet bit 22; payload otherwise irrelevant.
//!
//! Fix = printer-only (src/printer.rs format_float NaN arm): sign composed
//! like the INF arm (neg != f.is_sign_negative()), QNAN/SNAN by quiet bit.
//! Encode of any *NAN token stays parked-by-design (bimodal bit lanes, no
//! text-visible discriminator — parser.rs comment; fail-closed posture
//! pinned in t177_5). MUFU.RSQ -QNAN render = parked-159 lane, verified
//! pre==post in t177_4.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }

/// Render helper: strip @sched and !rsd[...] annotations; the glyph law is
/// asserted on the operand text.
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    let s = s.split("/* @sched").next().unwrap();
    let s = s.split(" !rsd[").next().unwrap();
    s.trim().to_string()
}
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }
fn enc_ok(t: &IsaTable, text: &str) -> bool {
    match parse_sass(text, 0) {
        Ok(insn) => encode_instruction(&insn, t).is_ok(),
        Err(_) => false,
    }
}

/// t177_1: FSEL positive-QNAN anchors (both bimodal payload lanes) decode
/// vendor-exact: "+QNAN".
#[test]
fn t177_1_fsel_pos_qnan_anchors() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in [
        ("000fe200048000007fc00000ff077808", "FSEL R7, RZ, +QNAN , !P1"),
        ("001fe400050000007ff80000ff0d7808", "FSEL R13, RZ, +QNAN , !P2"),
        ("000fe200000000007fc000000a189808", "@!P1 FSEL R24, R10, +QNAN , P0"),
        ("000fe200008000007fc000000f11a808", "@!P2 FSEL R17, R15, +QNAN , P1"),
    ] {
        assert_eq!(dec(&idx, w(hx), &t), want, "anchor {hx}");
    }
}

/// t177_2: FSEL negative-QNAN anchors + FMUL positive-QNAN anchor decode
/// vendor-exact.
#[test]
fn t177_2_neg_qnan_and_fmul_anchors() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in [
        ("000fce0000000000fff00000090b7808", "FSEL R11, R9, -QNAN , P0"),
        ("000fe20001000000fff000001d3f1808", "@P1 FSEL R63, R29, -QNAN , P2"),
        ("001fc80004000000ffffffff00007808", "FSEL R0, R0, -QNAN , !P0"),
        ("000fcc00004000007fc0000000007820", "FMUL R0, R0, +QNAN"),
    ] {
        assert_eq!(dec(&idx, w(hx), &t), want, "anchor {hx}");
    }
}

/// t177_3: synthetic probes on the FSEL skeleton (arb177.json): payload
/// variants keep the sign law; SNAN lanes print "+SNAN"/"-SNAN".
#[test]
fn t177_3_payload_and_snan_probes() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    // skeleton: FSEL R7, RZ, <imm>, !P1 (base word with imm lane zeroed)
    let base: u128 = w("000fe200048000007fc00000ff077808") & !(0xffff_ffffu128 << 32);
    let probe = |imm: u32| -> String {
        let w2 = base | ((imm as u128) << 32);
        let s = dec(&idx, w2, &t);
        s.strip_prefix("FSEL R7, RZ, ").unwrap().strip_suffix(" , !P1").unwrap().to_string()
    };
    assert_eq!(probe(0x7fc0_0000), "+QNAN");
    assert_eq!(probe(0x7ff8_0000), "+QNAN");
    assert_eq!(probe(0x7fe0_0000), "+QNAN");
    assert_eq!(probe(0x7fc0_0001), "+QNAN");
    assert_eq!(probe(0x7f80_0001), "+SNAN");
    assert_eq!(probe(0xffc0_0000), "-QNAN");
    assert_eq!(probe(0xfff0_0000), "-QNAN");
    assert_eq!(probe(0xfff8_0000), "-QNAN");
    assert_eq!(probe(0xffff_ffff), "-QNAN");
    assert_eq!(probe(0xff80_0001), "-SNAN");
}

/// t177_4: invariants — INF/zero lanes unchanged; MUFU.RSQ baked-constant
/// lane now expects the LANDED BUG-159 spelling ("-QNAN"; this invariant
/// originally guarded the parked-159 "0x0" posture and was rebased when
/// the 159 fix merged to main in the 2026-08-26 branch-landing wave).
#[test]
fn t177_4_inf_zero_invariants_mufu_untouched() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let base: u128 = w("000fe200048000007fc00000ff077808") & !(0xffff_ffffu128 << 32);
    for (imm, want) in [
        (0x7f80_0000u32, "FSEL R7, RZ, +INF , !P1"),
        (0xff80_0000u32, "FSEL R7, RZ, -INF , !P1"),
        (0x0000_0000u32, "FSEL R7, RZ, 0, !P1"),
    ] {
        assert_eq!(dec(&idx, base | ((imm as u128) << 32), &t), want, "{imm:#x}");
    }
    // MUFU.RSQ 0xFFC00000 lane = landed BUG-159 behavior (folded sign).
    let m = dec(&idx, w("000e220000001400ffc0000000007908"), &t);
    assert!(m.starts_with("MUFU.RSQ R0, -QNAN"), "landed-159 lane moved: {m}");
}

/// t177_5: encode-side posture pinned pre==post (parked bimodal quirk,
/// parser.rs "QNAN intentionally NOT special-cased" + 178-kand finding):
/// every NaN-ish token (and, by the Label-fallback, any unknown identifier)
/// silently encodes through the baked-imm `FSEL_R_R_II_P` row to the SAME
/// word with imm lane 0x7FC00000 — sign of "-QNAN" included. 177 changes
/// NOTHING here; the pin makes the parked posture machine-checkable.
#[test]
fn t177_5_encode_baked_nan_posture_pinned() {
    let t = t103();
    let encw = |text: &str| -> Option<u128> {
        parse_sass(text, 0).ok().and_then(|i| encode_instruction(&i, &t).ok())
    };
    let qnan = encw("FSEL R7, RZ, QNAN , !P1 ;").expect("baked lane encodes");
    assert_eq!((qnan >> 32) as u32, 0x7fc0_0000, "baked +QNAN imm lane");
    for tok in ["+QNAN", "-QNAN", "+SNAN", "FOOBAR"] {
        let w2 = encw(&format!("FSEL R7, RZ, {tok} , !P1 ;"));
        assert_eq!(w2, Some(qnan), "{tok}: label-fallback word drifted");
    }
    // honest numeric immediates stay honest through the FI row.
    let w5 = encw("FSEL R7, RZ, 5 , !P1 ;").expect("numeric imm encodes");
    assert_eq!((w5 >> 32) as u32, 5.0f32.to_bits(), "numeric imm lane");
    // sm120-side posture: NO baked-imm FSEL II row -> fail-closed
    // (encoder refuses; verified identical on clean 8e02983).
    let t2 = t120();
    let i2 = parse_sass("FSEL R7, RZ, QNAN , !P1 ;", 0).expect("parse");
    assert!(encode_instruction(&i2, &t2).is_err(), "sm120 must stay fail-closed");
}

/// t177_6: cross-table render parity — the same anchor word prints the
/// vendor glyph under the sm120 table too.
#[test]
fn t177_6_sm120_table_same_glyph() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&idx, w("000fe200048000007fc00000ff077808"), &t), "FSEL R7, RZ, +QNAN , !P1");
    assert_eq!(dec(&idx, w("000fce0000000000fff00000090b7808"), &t), "FSEL R11, R9, -QNAN , P0");
}
