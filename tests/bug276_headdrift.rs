//! BUG-276 (F2-iter140, loop5/blind front2, 2026-08-29): head-drift
//! junk-family closure, legs sm120+sm121a (canonical pending, ride-after
//! 740b225). Measurement-first (work/bug276): census276 base verdicts,
//! routex276 FULL 2,406-cubin battery (winner routing of EVERY deletee == 0
//! both legs), arb276 (200 probes) + arb276b (30) nvdisasm 13.3.73 raw -b,
//! x4 models SM100a/103a/120/121a agree on every probe.
//!
//! CLASS: era-harvest rows squatting three foreign lattices:
//!   0x27a  = QMMA.16816.F16.E4M3.E4M3 territory (vendor x4: always QMMA
//!            on 120/121a, rc=1 on donors; A-sweep guard/payload/signs/b74)
//!   0x23a-family (0x30000023a/0x70000023a/0xb0000023a) = MOVM.16.MT88
//!            (B-sweep subop<<32 v=0..1f NEVER prints I2IP.*_P)
//!   0x238/0x2000238 = 2-op I2I.U8.S32.SAT (C/E-sweeps; TRUE 4-op
//!            I2IP.U8.S32.SAT/.SATRELU live at 0x7239|b74/|b75 = 282-kand)
//! DELETED (13 both legs): I2I.{U16,S8,U8}.S32.SAT_P_R_R (QMMA-lattice
//!   clones), I2I.S8.S32.SAT_P0_R_R (witness-reg-baked head-mismatch),
//!   I2IP.{U8,S8,U16}.S32_P_R_R_R_R + I2IP.U2.S32_P_R_R_R_? (MOVM cluster),
//!   I2IP.U8.S32_P_R_R_R_? + I2IP.U8.S32{.SAT_P,.SATRELU_P} (0x238 lattice;
//!   SAT_P was live poison winning its own base; encode of predicated
//!   'I2IP.U8.S32.SAT ...' silently produced the vendor-2-op word = SILENT
//!   WRONG-CODE, now fail-closed), P2R_P_R_R_R_R (QMMA-lattice clone),
//!   F2FP.F16.F32.PACK_AB_P0_R_R_R (ab=0x27a literal, family lives at 0x23e).
//! DELETED (7 sm120-only): F2IP era cluster on 0x27a x5 + 0x238 x2 (incl.
//!   F2IP.U8.F32.RELU_P, the sm120 shadow-winner of the I2I.U8.S32.SAT base).
//! WIDENED (both legs): I2IP.U8.S32_R_R_R_R '' variable_mask |= 3<<80
//!   (arb276 D + arb276b B1/B2: (80,81) text-inert, vendor always prints
//!   I2IP.U8.S32 on those words = decode-hole reclaim; closes the 276-Q from
//!   the BUG-265 registration note; t265_2 hole word now decodes).
//! DONORS sm100a/sm103a BYTE-UNTOUCHED. and_base of every kept row byte-
//! unchanged; only the widened '' vmask moves.
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
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

const DEL_BOTH: [&str; 13] = [
    "I2I.U16.S32.SAT_P_R_R",
    "I2I.S8.S32.SAT_P_R_R",
    "I2I.U8.S32.SAT_P_R_R",
    "I2I.S8.S32.SAT_P0_R_R",
    "I2IP.U8.S32_P_R_R_R_R",
    "I2IP.S8.S32_P_R_R_R_R",
    "I2IP.U16.S32_P_R_R_R_R",
    "I2IP.U2.S32_P_R_R_R_?",
    "I2IP.U8.S32_P_R_R_R_?",
    "I2IP.U8.S32.SAT_P_R_R_R_R",
    "I2IP.U8.S32.SATRELU_P_R_R_R_R",
    "P2R_P_R_R_R_R",
    "F2FP.F16.F32.PACK_AB_P0_R_R_R",
];
const DEL_120: [&str; 7] = [
    "F2IP.INVALID2.F32_P_R_R_R_R",
    "F2IP.S8.F32_P_R_R_R_R",
    "F2IP.U8.F32.INVALID1_P_R_R_R_R",
    "F2IP.U8.F32.INVALID2_P_R_R_R_R",
    "F2IP.U8.F32_P_R_R_R_R",
    "F2IP.U8.F32.RELU_P_R_R_R_R",
    "F2IP.U8.F32_P_R_R_R_?",
];

#[test]
fn t276_1_structure_deletions_widen_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for k in DEL_BOTH {
            assert!(!t.entries.contains_key(k), "{leg}: {k} survived");
        }
    }
    let t120 = tab("sm120");
    for k in DEL_120 {
        assert!(!t120.entries.contains_key(k), "sm120: {k} survived");
    }
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // widen: (80,81) armed, and_base + fields untouched (BUG-265 H1 arm)
        let g = &t.entries["I2IP.U8.S32_R_R_R_R"].mod_groups[""];
        let ab: u128 = g.and_base.into();
        let vm: u128 = g.variable_mask.into();
        assert_eq!(ab, 0x7239, "{leg}: I2IP '' and_base drift");
        // BUG-282 flip: (62,63) Rb-sign-slot widened in too (arb282 E2:
        // text-inert x4; ghost sign-arm removed in decoder.rs same wave)
        // BUG-275 flip: b73 OUT of the vmask again (vendor-undefined '.???n'
        // payload-gap closed; decode hole per 125/274/282 doctrine).
        // BUG-284 flip: payload window [95:82] \ b91 armed vendor
        // text-inert (arb284 560 probes x4 models; b91 kill-bit rc=1 x4
        // stays care = hole preserved). 276 (80,81) doctrine extended.
        assert_eq!(
            vm,
            0x1c000000000001ff000000fffffff000u128
                | (3u128 << 80)
                | (3u128 << 62)
                | (0x3DFFu128 << 82),
            "{leg}: I2IP '' vmask missing (80,81)|(62,63)|win95-82-minus-b91 arm or b73 drift"
        );
        // keepers: real family rows intact
        for k in [
            "I2IP.U8.S32_R_R_R_R",
            "I2I.U8.S32.SAT_R_R",
            // BUG-283 flip: era guard-clones MOVM.16.MT88_{P0,P5}_R_R are
            // DELETED (canonical 1beab0f); keeper = the armed generic row
            "MOVM.16.MT88_R_R",
            "F2FP.F16.F32.PACK_AB_R_R_R",
        ] {
            assert!(t.entries.contains_key(k), "{leg}: keeper {k} lost");
        }
        // BUG-313 flip: sm121a P2R_R_R_R_II DELETED (phantom era row
        // dup-rendered the PR slot as 'R6,R12,R12,0x0'; vendor law = the
        // literal 'PR' on 6 probed imm values x4 models, arb313 D; mint-
        // neutral: encode routes via P2R_R_II_R_II['']). Keeper check for
        // the key stays armed on the donor legs.
        if leg != "sm121a" {
            assert!(
                t.entries.contains_key("P2R_R_R_R_II"),
                "{leg}: keeper P2R_R_R_R_II lost"
            );
        }
        // BUG-282 flip: op-suffixes armed as FULL KEYS (mg '' sibling
        // shape = I2I.U8.S32.SAT_R_R precedent; the encoder resolves
        // multi-segment base suffixes via full keys, not mg names);
        // the base key itself keeps exactly one mg ''. INVALID3 = no row
        // anywhere = fail-closed hole.
        let mgs = &t.entries["I2IP.U8.S32_R_R_R_R"].mod_groups;
        assert_eq!(mgs.len(), 1, "{leg}: I2IP base mg set drift");
        for nk in ["I2IP.U8.S32.SAT_R_R_R_R", "I2IP.U8.S32.SATRELU_R_R_R_R"] {
            assert!(
                t.entries.contains_key(nk),
                "{leg}: 282-armed key missing: {nk}"
            );
        }
    }
    // donor sentinels: deletees never existed on donors; donor family forms stay
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for k in DEL_BOTH.iter().chain(DEL_120.iter()) {
            assert!(!t.entries.contains_key(*k), "{leg}: donor carries {k}");
        }
        assert!(t.entries.contains_key("F2IP_R_R_R_R"));
        assert!(t.entries.contains_key("P2R_R_II_R_II"));
    }
    // leg-specific F2IP keeper: sm120 still has the real F2IP.U8.F32 family
    assert!(tab("sm120").entries.contains_key("F2IP.U8.F32_R_R_R_R"));
    assert!(tab("sm121a").entries.contains_key("F2IP_R_R_R_R"));
}

#[test]
fn t276_2_former_lattice_bases_post_state() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // 0x27a (vendor-only-QMMA lattice, 120/121a; donors illegal): the era
        // phantom chain {I2I.*.SAT_P x3, P2R_P, F2IP x5, F2FP.P0} was deleted
        // in walking order; the honest engine state WAS a HOLE there.
        // BUG-280 FLIP (F2-iter155, canonical 842aa05): b74 reclaimed as
        // vendor text-inert on the QMMA.16816.F16.E4M3.E4M3 lane (arb280 x4:
        // inert on the lane; INERT on all 106 QMMA sub-lane bases as the
        // family documentary for the owner audit). The bare word now decodes
        // VENDOR-EQUAL (arb276 A / arb280 A agree: '@P0' text identical with
        // b74 on/off). Sibling lanes keep their b74 bakes = owner scope.
        assert_eq!(
            dec(&t, 0x27a).as_deref(),
            Some("@P0 QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0"),
            "{leg}: 280-armed 0x27a decode drift"
        );
        // 0x238 / 0x2000238 (vendor 2-op I2I.U8.S32.SAT territory): junk
        // claimants (SAT_P live poison, SATRELU_P, U8_P_?, F2IP.RELU_P sm120)
        // deleted -> honest holes at 276. BUG-281 FLIP (F2-iter147,
        // canonical pending): family fully armed on the '' row (guard
        // 4b@[15:12], dest 8b@16, src 8b@32; inert bands incl. [31:24]);
        // both words now decode VENDOR-EQUAL (arb281 x4 models agree):
        // 0x238 = '@P0 ...', 0x2000238 carries bit25 inside the measured
        // text-inert window [31:24]. Era clones _P0/_P2/_P5 deleted (281).
        assert_eq!(
            dec(&t, 0x238).as_deref(),
            Some("@P0 I2I.U8.S32.SAT R0, R0"),
            "{leg}: 281-armed 0x238 decode drift"
        );
        assert_eq!(
            dec(&t, 0x2000238).as_deref(),
            Some("@P0 I2I.U8.S32.SAT R0, R0"),
            "{leg}: 281-armed 0x2000238 decode drift"
        );
        // MOVM lane: BUG-283 FLIP (F2-iter156, canonical 1beab0f). The era
        // guard-clone rows are deleted and the generic R_R row is armed to
        // the measured vendor law (arb283+283b x4): plain name, dst 8b@16,
        // src 8b@24, sub-op band [36:32] text-inert. The era status-quo
        // prints ('_P0'/'_P5' suffix lottery + 'R128'-for-'R0' misread)
        // are gone; corpus exposure ZERO (routex283 full battery).
        assert_eq!(
            dec(&t, 0x23a).as_deref(),
            Some("@P0 MOVM.16.MT88 R0, R0"),
            "{leg}: 283-armed 0x23a decode drift"
        );
        for w in [0x70000023au128, 0xb0000023au128, 0x30000023au128] {
            assert_eq!(
                dec(&t, w).as_deref(),
                Some("@P0 MOVM.16.MT88 R0, R0"),
                "{leg}: 283-armed MOVM cluster drift at {w:#x}"
            );
        }
        // corpus QMMA witness (qc_75_77.cubin routes here, routex276 n=1/leg)
        let w: u128 = 0xff600000004340000000c0834727au128 & M96;
        assert!(dec(&t, w).is_some(), "{leg}: corpus QMMA witness broke");
    }
    // BUG-283 (F2-iter156): the registered 283-kand cosmetics+misread class
    // is FIXED table+engine-side (canonical 1beab0f; pins
    // tests/bug283_movm_lane.rs) -- vendor prints plain
    // '@P0 MOVM.16.MT88 R0, R0' on all these words (arb276 B + arb283 x4).
}

#[test]
fn t276_3_encode_fail_closed_and_keepers() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // predicated I2IP op-suffix texts had encoders ONLY via the junk rows
        // (silent wrong-code into the I2I.U8.S32.SAT 2-op lattice) -- 276
        // closed that; BUG-282 flip: the TRUE 4-op forms are armed on the
        // 0x7239 lattice, so the texts now encode to the vendor-exact
        // b74/b75 words (arb282 C/D) and re-decode to themselves
        let w_sat = enc_res(&t, "@P0 I2IP.U8.S32.SAT R0, R0, R0, R0")
            .expect("{leg}: armed SAT encode must succeed");
        assert_eq!((w_sat >> 74) & 3, 1, "{leg}: SAT encode did not set b74");
        assert_eq!(
            dec(&t, w_sat & M96).as_deref(),
            Some("@P0 I2IP.U8.S32.SAT R0, R0, R0, R0"),
            "{leg}: SAT encode->decode roundtrip drift"
        );
        let w_srl = enc_res(&t, "@P0 I2IP.U8.S32.SATRELU R0, R0, R0, R0")
            .expect("{leg}: armed SATRELU encode must succeed");
        assert_eq!(
            (w_srl >> 74) & 3,
            2,
            "{leg}: SATRELU encode did not set b75"
        );
        assert_eq!(
            dec(&t, w_srl & M96).as_deref(),
            Some("@P0 I2IP.U8.S32.SATRELU R0, R0, R0, R0"),
            "{leg}: SATRELU encode->decode roundtrip drift"
        );
        assert!(
            enc_res(&t, "I2IP.S8.S32 R0, R1, R2, R3").is_err(),
            "{leg}: junk I2IP.S8 encode still routes"
        );
        // keepers still encode (regression fence): real F2IP/F2FP, I2IP ''
        assert!(enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2").is_ok(), "{leg}");
        assert!(
            enc_res(&t, "F2FP.F16.F32.PACK_AB R0, R1, R2").is_ok(),
            "{leg}"
        );
        assert!(enc_res(&t, "I2I.U8.S32.SAT R0, R1").is_ok(), "{leg}");
    }
    // sm120-only junk: predicated F2IP.U8.F32.RELU encoder routes closed on
    // both legs now (was: sm120 junk row), donor-side leg is unaffected
    let t120 = tab("sm120");
    assert!(enc_res(&t120, "@P0 F2IP.U8.F32.RELU R0, R1, R2, R3").is_err());
}

#[test]
fn t276_4_widen_laws_vendor_equal() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // arb276 D x4 models: (80,81) text-inert on the I2IP lattice
        assert_eq!(
            dec(&t, 0x7239).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: base"
        );
        for v in 1u128..4 {
            assert_eq!(
                dec(&t, 0x7239 | (v << 80)).as_deref(),
                Some("I2IP.U8.S32 R0, R0, R0, R0"),
                "{leg}: (80,81)={v} drift"
            );
        }
        // arb276b B2: payload regs compose through the window
        let w = 0x7239u128 | (1u128 << 80) | (5 << 16) | (19 << 24) | (7 << 32) | (42 << 64);
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("I2IP.U8.S32 R5, R19, R7, R42"),
            "{leg}: payload through window"
        );
        // arb276b B1: the t265_2 hole word is reclaimed vendor-exact
        assert_eq!(
            dec(&t, (0x239u128 | (3u128 << 80)) & M96).as_deref(),
            Some("@P0 I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: t265_2 reclaim"
        );
        // BUG-265 H1 arm coexists with the window
        let w1 = 0x7239u128 | (1u128 << 72) | (2u128 << 80);
        assert_eq!(
            dec(&t, w1).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0.H1"),
            "{leg}: H1 + window"
        );
    }
}

#[test]
fn t276_5_keepers_registrations_and_anchors() {
    // 278-kand HADD2-'?' keeper witness still decodes (265 doctrine chain)
    let w2: u128 = 0x0000000000ff13007231u128 | (0x40fe400000000000u128 << 64);
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert!(t.entries.contains_key("HADD2_R_R_II_II_II_II_?"), "{leg}");
        assert!(dec(&t, w2 & M96).is_some(), "{leg}: 278 witness holed");
        // 275-kand: I2IP '' bit73 still unfielded payload-gap
        let g = &t.entries["I2IP.U8.S32_R_R_R_R"].mod_groups[""];
        assert!(
            !g.fields.iter().any(|f| f.shift == 73),
            "{leg}: 275 payload-gap silently armed"
        );
    }
    // 280-kand: QMMA b74-set words still route to the real QMMA row (arb276
    // A_b74: b74=1 keeps the vendor decode == engine row); the gap is b74=0.
    let t120 = tab("sm120");
    let g = &t120.entries["QMMA.16816.F16.E4M3.E4M3_R_R_R_R"].mod_groups[""];
    let ab: u128 = g.and_base.into();
    assert_eq!(
        ab & (1u128 << 74),
        1u128 << 74,
        "280-kand: QMMA b74 barked off"
    );
    // 261-era chain anchors unchanged (FSET.BF.F + FMNMX hole + HFMA2 274 arm)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert!(dec(&t, 0).is_none(), "{leg}: zero word decodes");
        assert!(t.entries.contains_key("FSET.BF.F.AND_R_R_R_P"), "{leg}");
        assert!(
            t.entries["HFMA2_R_R_R_II_FI"]
                .mod_groups
                .contains_key("SAT"),
            "{leg}: 274 op-suffix arm lost"
        );
    }
}
