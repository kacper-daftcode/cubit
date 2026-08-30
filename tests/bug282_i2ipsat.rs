//! BUG-282 (F2-iter141, loop5/blind front2, 2026-08-29): I2IP.U8.S32 4-op
//! op-suffix arming on the 0x7239 lattice, legs sm120+sm121a (canonical
//! bug282 cut, ride-after 4f2f2e6). Measurement-first (work/bug282):
//! arb282 (108 probes) + arb282b (9) nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/103a/120/121a agree on every probe; routex282 FULL 2,406-cubin
//! battery (pub pyo3-303bd1e): ZERO routing to I2IP.U8.S32_R_R_R_R on
//! either leg (routex276 likewise) => graft + arms corpus-neutral.
//!
//! LAWS (x4 models): window [75:74] on 0x7239: 0='' 1='.SAT' 2='.SATRELU'
//!   3='.INVALID3' (re-confirm arb276b). Combos: regs payload, guard
//!   g0/g2, +H1 (b72), (80,81) text-inert under both suffixes.
//!   b62/b63 (Rb sign-slot): TEXT-INERT x4 (plain/regs/with-suffix) --
//!   the engine generic is_alu post-pass printed ghost '-Rb'/'|Rb|' =
//!   vendor-WRONG; paired decoder.rs arms: prio-3 sign-window gate +
//!   is_alu exclusion for I2IP. Trailing dst-pred window [90:87]
//!   v=0..7 (+inv@90): TEXT-INERT x4 => NO _P form exists vendor-side
//!   (276-junk '_P' rows stay deleted; hole = 284-kand registered).
//!   b73 = opaque 2-bit enum [73:72] on tok4 (''/.H1/.???2/.???3) =
//!   275-kand scope (window measured here; graft NOT done).
//! PRE-FIX (pub pyo3-303bd1e measured): b74/b75 words decoded as PLAIN
//!   'I2IP.U8.S32 ...' (prio-3 ALU sign-window absorption, suffix silently
//!   dropped = WRONG text); encode of the suffix forms was fail-closed.
//! GRAFT (both legs, sole key I2IP.U8.S32_R_R_R_R): mgs 'SAT'
//!   (and_base|1<<74) + 'SATRELU' (|1<<75), fields copy; '' variable_mask
//!   |= 3<<62 (text-inert reclaim, vendor-equal ONLY with the decoder arms
//!   in the same wave). INVALID3: no row anywhere = decode hole +
//!   fail-closed encode (274/264 doctrine). DONORS byte-untouched.
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

#[test]
fn t282_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // armed set: base key keeps exactly mg '' (widened (62,63); and_base
        // and 6 fields untouched); suffix forms are FULL KEYS with mg ''
        // (sibling shape of I2I.U8.S32.SAT_R_R -- the encoder resolves
        // multi-segment base suffixes via full keys: extract_mod_group
        // lumps ALL dotted suffixes into the mod-string, so the mg-name
        // shape used for HFMA2 in BUG-274 cannot resolve here).
        let base = &t.entries["I2IP.U8.S32_R_R_R_R"].mod_groups;
        assert_eq!(base.len(), 1, "{leg}: I2IP base mg set drift");
        let g0 = &base[""];
        let ab: u128 = g0.and_base.into();
        let vm: u128 = g0.variable_mask.into();
        assert_eq!(ab, 0x7239, "{leg}: I2IP '' and_base drift");
        assert_eq!(
            vm,
            0x1c000000000001ff000000fffffff000u128
                | (3u128 << 80)
                | (3u128 << 62)
                | (0x3DFFu128 << 82),
            "{leg}: I2IP '' vmask drift"
        ); // BUG-275 flip: b73 out of the vmask
           // BUG-284 flip: payload window [95:82] \ b91 armed vendor
           // text-inert (arb284 x4); b91 kill-bit stays care = hole.
        assert_eq!(g0.fields.len(), 6, "{leg}: I2IP '' field count drift");
        for (nk, bop, bit) in [
            ("I2IP.U8.S32.SAT_R_R_R_R", "I2IP.U8.S32.SAT", 74u32),
            ("I2IP.U8.S32.SATRELU_R_R_R_R", "I2IP.U8.S32.SATRELU", 75u32),
        ] {
            let e = t
                .entries
                .get(nk)
                .unwrap_or_else(|| panic!("{leg}: missing armed key {nk}"));
            let _ = bop; // base_op/sig proven by the decode-text pins (t282_2/3)
            assert_eq!(e.mod_groups.len(), 1, "{leg}: {nk} must be mg '' only");
            let g = &e.mod_groups[""];
            let gab: u128 = g.and_base.into();
            let gvm: u128 = g.variable_mask.into();
            assert_eq!(gab, 0x7239u128 | (1u128 << bit), "{leg}: {nk} and_base");
            assert_eq!(gvm, vm, "{leg}: {nk} vmask must equal widened base");
            assert_eq!(g.fields.len(), 6, "{leg}: {nk} fields copy");
        }
        // INVALID3 (b74+b75) has NO row anywhere (fail-closed doctrine)
        assert!(
            !t.entries.contains_key("I2IP.U8.S32.INVALID3_R_R_R_R"),
            "{leg}: INVALID3 row appeared"
        );
        // junk _P rows from 276 stay deleted; no _P sibling exists
        for jk in [
            "I2IP.U8.S32.SAT_P_R_R_R_R",
            "I2IP.U8.S32.SATRELU_P_R_R_R_R",
            "I2IP.U8.S32_P_R_R_R_R",
        ] {
            assert!(
                !t.entries.contains_key(jk),
                "{leg}: deleted junk {jk} resurrected"
            );
        }
        // keepers: the vendor sibling pattern reference row stays intact
        assert!(t.entries.contains_key("I2I.U8.S32.SAT_R_R"), "{leg}");
    }
    // donors never carried the family (byte-untouched doctrine)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for k in [
            "I2IP.U8.S32_R_R_R_R",
            "I2IP.U8.S32.SAT_R_R_R_R",
            "I2IP.U8.S32.SATRELU_R_R_R_R",
        ] {
            assert!(!t.entries.contains_key(k), "{leg}: donor carries {k}");
        }
    }
}

#[test]
fn t282_2_decode_laws_vendor_equal_and_holes() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // arb282 C/D matrix (nvdisasm 13.3.73 raw -b x4 models agree)
        let laws: [(u128, &str); 9] = [
            (0x7239, "I2IP.U8.S32 R0, R0, R0, R0"),
            (0x4000000000000007239, "I2IP.U8.S32.SAT R0, R0, R0, R0"),
            (0x8000000000000007239, "I2IP.U8.S32.SATRELU R0, R0, R0, R0"),
            (0x4000000000000002239, "@P2 I2IP.U8.S32.SAT R0, R0, R0, R0"),
            (0x42a0000000713057239, "I2IP.U8.S32.SAT R5, R19, R7, R42"),
            (
                0x82a0000000713057239,
                "I2IP.U8.S32.SATRELU R5, R19, R7, R42",
            ),
            (0x5000000000000007239, "I2IP.U8.S32.SAT R0, R0, R0, R0.H1"),
            (0x304000000000000007239, "I2IP.U8.S32.SAT R0, R0, R0, R0"),
            (
                0x308000000000000007239,
                "I2IP.U8.S32.SATRELU R0, R0, R0, R0",
            ),
        ];
        for (w, want) in laws {
            assert_eq!(
                dec(&t, w).as_deref(),
                Some(want),
                "{leg}: decode law drift at {w:#x}"
            );
        }
        // INVALID3 (b74+b75) = decode HOLE, incl. regs / with b62 (arb282b E2)
        for w in [
            0xc000000000000007239u128,
            0xc2a0000000713057239u128,
            0xc2a4000000713057239u128,
        ] {
            assert!(dec(&t, w).is_none(), "{leg}: INVALID3 decodes at {w:#x}");
        }
        // (62,63) text-inert reclaim: vendor prints PLAIN x4 (arb282b E2);
        // pre-arm the generic post-pass printed ghost '-Rb'/'|Rb|'
        let reclaim: [(u128, &str); 4] = [
            (0x2a8000000713057239, "I2IP.U8.S32 R5, R19, R7, R42"),
            (0x2a4000000713057239, "I2IP.U8.S32 R5, R19, R7, R42"),
            (0x2ac000000713057239u128, "I2IP.U8.S32 R5, R19, R7, R42"),
            (0x42a8000000713057239, "I2IP.U8.S32.SAT R5, R19, R7, R42"),
        ];
        for (w, want) in reclaim {
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg}: reclaim hole at {w:#x}"));
            assert_eq!(got, want, "{leg}: reclaim law drift at {w:#x}");
            assert!(
                !got.contains('|') && !got.contains('-'),
                "{leg}: ghost sign at {w:#x}: {got}"
            );
        }
    }
}

#[test]
fn t282_3_encode_inverse_and_fail_closed() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // armed suffix forms encode + re-decode exactly
        for (text, win) in [
            ("I2IP.U8.S32.SAT R0, R0, R0, R0", 1u128),
            ("I2IP.U8.S32.SATRELU R0, R0, R0, R0", 2u128),
            ("@P2 I2IP.U8.S32.SAT R5, R19, R7, R42", 1u128),
            ("@P0 I2IP.U8.S32.SATRELU R5, R19, R7, R42", 2u128),
            ("I2IP.U8.S32.SAT R0, R0, R0, R0.H1", 1u128),
        ] {
            let w = enc_res(&t, text).unwrap_or_else(|e| panic!("{leg}: encode {text}: {e}"));
            assert_eq!((w >> 74) & 3, win, "{leg}: suffix bits wrong for {text}");
            assert_eq!(
                dec(&t, w & M96).as_deref(),
                Some(text),
                "{leg}: encode->decode roundtrip drift for {text}"
            );
        }
        // both-set is vendor '.INVALID3' -> NO row -> fail-closed encode;
        // doubled-op-suffix text likewise has no mod_group
        for bad in [
            "I2IP.U8.S32.INVALID3 R0, R0, R0, R0",
            "I2IP.U8.S32.SAT.SATRELU R0, R0, R0, R0",
        ] {
            assert!(
                enc_res(&t, bad).is_err(),
                "{leg}: INVALID3-class text encodes: {bad}"
            );
        }
        // 5-operand _P form: deleted junk stays deleted (no such lattice
        // form vendor-side; arb282 F-window x4 text-inert)
        assert!(
            enc_res(&t, "@P0 I2IP.U8.S32.SAT R0, R0, R0, R0, P1").is_err(),
            "{leg}: phantom _P encode routes"
        );
    }
}

#[test]
fn t282_4_prio3_arm_scope() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // pre-fix these words were prio-3-absorbed by '' with the suffix
        // silently DROPPED (measured pub pyo3-303bd1e); now strict winners
        let sat = dec(&t, 0x4000000000000007239).unwrap();
        assert!(sat.contains(".SAT"), "{leg}: suffix still dropped: {sat}");
        assert!(!sat.contains("SATRELU"), "{leg}: wrong suffix won: {sat}");
        // prio-3 arm: no sign-window bit combo absorbs into '' any more
        assert!(
            dec(&t, 0xc000000000000007239).is_none(),
            "{leg}: INVALID3 absorbed"
        );
        // BUG-275 flip: the b73 '.???n' payload-gap is CLOSED -- vmask
        // narrowed (bit73 out), so the vendor-undefined marker word is now a
        // decode HOLE (was: plain decode via vm don't-care = silent
        // marker-drop; arb275 116 probes x4 models). Prio-3 arm (282) keeps
        // the sign-window path fail-closed, no second-chute absorption.
        assert!(
            dec(&t, 0x2000000000000007239).is_none(),
            "{leg}: b73 silent decode survived (275)"
        );
        assert!(
            dec(&t, 0x3000000000000007239).is_none(),
            "{leg}: b73+b72 .???3 silently decoded (275)"
        );
    }
}

#[test]
fn t282_5_registrations_and_anchors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // BUG-284 FLIP (was: 284-kand sentinel): the [90:87] window word
        // now decodes VENDOR-EQUAL -- payload window [95:82] \ b91 armed
        // vendor text-inert (arb284 560 probes x4 models: full sweep; b91
        // kill-bit rc=1 x4 stays care = hole preserved, pin in t284_3/5).
        assert_eq!(
            dec(&t, 0x30000000000000000007239u128).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: 284-window word decode drift"
        );
        // zero word never decodes
        assert!(dec(&t, 0).is_none(), "{leg}: zero word decodes");
        // 265/274/276 era anchors unchanged
        let h1 = dec(&t, 0x1000000000000007239);
        assert_eq!(
            h1.as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0.H1"),
            "{leg}: 265 H1 anchor drift"
        );
        assert!(
            t.entries["HFMA2_R_R_R_II_FI"]
                .mod_groups
                .contains_key("SAT"),
            "{leg}: 274 HFMA2 arm lost"
        );
        assert_eq!(
            dec(&t, 0x70000023a).as_deref(),
            Some("@P0 MOVM.16.MT88_P5 R0, R128"),
            "{leg}: 276 MOVM tripwire drift"
        );
        assert!(t.entries.contains_key("FSET.BF.F.AND_R_R_R_P"), "{leg}");
    }
}
