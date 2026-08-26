//! BUG-144 pins (sm120.json repair of the `""` mod group of
//! `UIADD3_UR_UP_UP_UR_UR_UR`, follow-up of BUG-137):
//!
//! BUG-137 repaired the era table tb_i82p3; the shipped sm120.json kept the
//! same harvest defect: the 33-record `""` group saw only all-URZ drains, so
//! the tok6 window [64:72) was baked as `0xff` in `and_base` with NO field
//! for operand 6. Consequences (proven by the pins below against the pre-fix
//! table):
//!   * encode: authored forms with a non-URZ tok6 failed closed
//!     ("operand 6 (UR7) has no field able to encode it") — BUG-137's
//!     t137_5 pinned that hole;
//!   * decode: every word of this key, authored or idiom, was rendered by a
//!     `..._R_II_P` sibling row as `... UR6, R7, 0x0, !PT` — the
//!     decode-priority artefact from the BUG-137 note was real on sm120.
//!
//! Fix is data-only, mirroring the BUG-137 tb recipe: and_base drops the
//! baked tok6 window (0xf81e0ff.. -> 0xf81e000..) and the group gains the
//! tok6 fields `ureg_ff 8b@64`, `neg 1b@75`, `reuse 1b@124` (same shape as
//! the sm103a canon). Vendor evidence: the cusparse.899 anchor word stays
//! byte-exact, and an nvdisasm-13.3 (sm_120a) graft of cubit-assembled
//! authored probes renders 5/5 byte-exact (work/bug144/t144_mini.sass).
//!
//! Bonus: adding the field removes the decode-priority artefact on sm120 —
//! the all-URZ idiom now decodes via its own row (t144_3).

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0)
        .map_err(|e| anyhow::anyhow!("parse: {e}"))
        .unwrap();
    encode_instruction(&insn, t).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> String {
    t.decode_index()
        .decode(w, 0, t)
        .map(|d| cubit::printer::to_sass(&d))
        .expect("decode")
}

/// Vendor anchor (payload bits <105): cusparse/libcusparse.so.899.sm_103
/// slot 0x68d0 — `@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ`. Bits >=105 are
/// the scheduling/control zone embedded by the asm pipeline.
const W_VENDOR: u128 = 0x000fe4000fffe0ff000000fffffff290;
const KEEP: u128 = (1u128 << 105) - 1;

/// The idiom must remain byte-exact after the and_base surgery (the baked
/// 0xff tok6 window now rides the new field, not a constant).
#[test]
fn t144_1_drain_idiom_still_vendor_exact_sm120() {
    let t = t120();
    let w = enc(&t, "@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ");
    assert_eq!(w & KEEP, W_VENDOR & KEEP, "idiom drifted on fixed sm120");
    let w = enc(&t, "UIADD3 URZ, UPT, UPT, URZ, URZ, URZ");
    assert_eq!(
        w & KEEP,
        ((W_VENDOR & !(0xfu128 << 12)) | (0x7u128 << 12)) & KEEP,
        "plain-guard idiom drifted on fixed sm120"
    );
}

/// The actual hole: authored non-URZ tok6 forms now encode on sm120, byte
/// identical to the sm103a canon, and round-trip through decode.
#[test]
fn t144_2_authored_suffix_forms_encode_and_roundtrip_sm120() {
    let t120 = t120();
    let t103 = t103a();
    for c in [
        "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7",
        "@UP2 UIADD3 UR10, UP0, UP1, -UR11, UR12, UR13",
        "UIADD3 UR4, UPT, UPT, UR5, UR6, URZ",
        "UIADD3 URZ, UPT, UPT, URZ, -URZ, URZ",
        // corpus class (rt_noei2 KernelB 0x46f0-era): tok5 neg on a real
        // register + real UR63 in tok6 — nvdisasm-13.3 arbitrated, and the
        // re-encoding is byte-exact to the vendor word
        // 0x000fe2000fffe03f8000002c2d2d7290.
        "UIADD3 UR45, UPT, UPT, UR45, -UR44, UR63",
    ] {
        let w120 = enc(&t120, c);
        let w103 = enc(&t103, c);
        assert_eq!(w120 & KEEP, w103 & KEEP, "sm120 vs sm103a byte parity: {c}");
        let s = dec(&t120, w120);
        assert_eq!(s.split(" /*").next().unwrap(), c, "sm120 roundtrip: {c}");
    }
}

/// Decode-priority artefact is GONE on the fixed table: the pre-fix sm120
/// table rendered every word of this key (idiom included) through a
/// `..._R_II_P` sibling as `... UR6, R7, 0x0, !PT`. Pin every observed form
/// against that regression.
#[test]
fn t144_3_decode_clean_no_rii_p_artifact_sm120() {
    let t = t120();
    // Vendor idiom word, both guard spellings, and the authored forms
    // re-encoded above — none may mention the artefact tokens.
    let pt_guard = (W_VENDOR & !(0xfu128 << 12)) | (0x7u128 << 12);
    let mut cases = vec![
        (W_VENDOR, "@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ"),
        (pt_guard, "UIADD3 URZ, UPT, UPT, URZ, URZ, URZ"),
    ];
    for c in [
        "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7",
        "UIADD3 UR4, UPT, UPT, UR5, UR6, URZ",
        "UIADD3 UR45, UPT, UPT, UR45, -UR44, UR63",
    ] {
        cases.push((enc(&t, c), c));
    }
    for (w, want) in cases {
        let s = dec(&t, w);
        let text = s.split(" /*").next().unwrap();
        assert_eq!(text, want, "decode artefact tokens on sm120: {text}");
        for bad in ["0x0, !PT", "RZ, 0x0", ", R7", ", R13"] {
            assert!(!text.contains(bad), "artefact token {bad:?} in {text}");
        }
    }
}

/// New flag fields on tok6: neg (bit 75) and reuse (bit 124) decode to the
/// authored spelling on sm120 (grafted on the vendor anchor word).
#[test]
fn t144_4_tok6_neg_and_reuse_flags_sm120() {
    let t = t120();
    let base = enc(&t, "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7");
    let neg = dec(&t, base | (1u128 << 75));
    assert!(
        neg.split(" /*").next().unwrap().ends_with("-UR7"),
        "bit75 must decode as negated tok6: {neg}"
    );
    let reuse = dec(&t, base | (1u128 << 124));
    assert!(
        reuse.contains("UR7.reuse"),
        "bit124 must decode as tok6 reuse: {reuse}"
    );
    // and_base carried a stray constant only in [64:72); guard/neg/reuse of
    // the other operands are untouched (byte parity with sm103a).
    let t103 = t103a();
    let a = enc(&t, "UIADD3 URZ, UPT, UPT, URZ, -URZ, URZ");
    let b = enc(&t103, "UIADD3 URZ, UPT, UPT, URZ, -URZ, URZ");
    assert_eq!(a & KEEP, b & KEEP, "tok5 neg divergence sm120 vs sm103a");
}

/// Tight closure: operands outside the repaired domain still fail closed on
/// sm120 (e.g. an immediate in tok6 has no field on this key).
#[test]
fn t144_5_out_of_domain_still_fail_closed_sm120() {
    let t = t120();
    let insn = parse_sass("UIADD3 UR4, UPT, UPT, UR5, UR6, 33 ;", 0).unwrap();
    assert!(
        encode_instruction(&insn, &t).is_err(),
        "immediate tok6 must remain fail-closed on sm120"
    );
}
