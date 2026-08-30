//! BUG-275 (F2-iter144, loop5/blind front2, 2026-08-29): I2IP.U8.S32 4-op
//! b73 vendor-undefined '.???n' payload-gap closure on the 0x7239 lattice,
//! legs sm120+sm121a (canonical bug275 cut, ride-after efa714a).
//! Measurement-first (work/bug275): arb275 (116 probes) nvdisasm 13.3.73
//! raw -b, x4 models SM100a/103a/120/121a agree on every probe; routex275
//! FULL 2,406-cubin battery (pub pyo3-445d222): ZERO family words on both
//! legs (routex282 likewise) => graft corpus-neutral by construction.
//!
//! LAW (x4 models; re-confirm arb265 A / arb282 E): tok4 enum [73:72]:
//!   v0 '' / v1 '.H1' (armed in 265, opmod:H1@72) / v2 '.???2' / v3 '.???3'
//!   = VENDOR-UNDEFINED markers. Marker is tok4-carried with ANY payload
//!   (RZ/Rn), composes every op-suffix (incl. INVALID3), guard forms, and
//!   the (80,81)/(62,63) text-inert windows; b86 neighbor untouched (284
//!   scope). Doctrine: vendor-undefined marker words get NO row (125
//!   '.???6/7', 274 '.INVALIDn', 276 junk-hole, 282 INVALID3) => decode
//!   HOLE. v0/v1 stay vendor-equal.
//! PRE-FIX (measured pub pyo3-445d222, work/bug275/measure_pre275.log):
//!   b73 words decoded PLAIN through the vm don't-care bit = SILENT
//!   marker-drop and word-roundtrip LOSSY (b73 cleared on re-encode).
//! GRAFT (both legs, 3 keys ''/SAT/SATRELU mg ''): variable_mask &=
//!   ~(1<<73). and_base byte-unchanged (b73=0 there), fields untouched
//!   (opmod:H1@72 intact). Engine ZERO changes: strict/relaxed matching
//!   rejects b73=1 via and_base b73=0, broad N/A (fields + non-mem), prio-3
//!   sign-window gate + is_alu exclusion for I2IP (BUG-282 arms) already
//!   fail-close the second chute. DONORS sm100a/sm103a byte-untouched.
//! ENCODE side: '.???n' tokens silently dropped by the operand-mod scrape
//!   = registered 272-class residual; CLOSED by BUG-272 (F2-iter146,
//!   encoder-side unknown-operand-suffix gate; t275_5 flipped).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const VM_POST275: u128 = 0x1c000000000001ff000000fffffff000u128 | (3u128 << 80) | (3u128 << 62);
// BUG-284: payload window [95:82] \ b91 armed vendor text-inert (arb284
// 560 probes x4 models; b91 = vendor kill-bit rc=1 x4 stays care = hole).
const VM_POST284: u128 = VM_POST275 | (0x3DFFu128 << 82);
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
fn t275_1_structure_narrow_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (nk, _bop, bit) in [
            ("I2IP.U8.S32_R_R_R_R", "I2IP.U8.S32", 0u32),
            ("I2IP.U8.S32.SAT_R_R_R_R", "I2IP.U8.S32.SAT", 74u32),
            ("I2IP.U8.S32.SATRELU_R_R_R_R", "I2IP.U8.S32.SATRELU", 75u32),
        ] {
            let e = t
                .entries
                .get(nk)
                .unwrap_or_else(|| panic!("{leg}: missing family key {nk}"));
            assert_eq!(e.mod_groups.len(), 1, "{leg}: {nk} must be mg '' only");
            let g = &e.mod_groups[""];
            let ab: u128 = g.and_base;
            let vm: u128 = g.variable_mask;
            assert_eq!(
                ab,
                0x7239u128 | ((bit != 0) as u128) << bit,
                "{leg}: {nk} and_base drift"
            );
            // BUG-284 flip: window widen on top of the 275 narrow
            assert_eq!(vm, VM_POST284, "{leg}: {nk} vmask drift (284 widen)");
            assert_eq!((vm >> 73) & 1, 0, "{leg}: {nk} b73 back in vmask");
            // field set unchanged: 6 fields, opmod:H1@72 tok4 intact (265 arm)
            assert_eq!(g.fields.len(), 6, "{leg}: {nk} field count drift");
            assert!(
                g.fields.iter().any(|f| f.token_idx == 4
                    && f.shift == 72
                    && f.bits == 1
                    && matches!(f.extraction, cubit::table::Extraction::OpModFlag(_))),
                "{leg}: {nk} opmod:H1@72 missing"
            );
        }
        // no marker rows may exist anywhere (hole doctrine, not text grafts)
        for jk in [
            "I2IP.U8.S32.???2_R_R_R_R",
            "I2IP.U8.S32.INVALID2_R_R_R_R",
            "I2IP.U8.S32.INVALID3_R_R_R_R",
        ] {
            assert!(
                !t.entries.contains_key(jk),
                "{leg}: marker row {jk} appeared"
            );
        }
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
fn t275_2_decode_laws_vendor_equal_anchors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // v0 plain + v1 '.H1' stay vendor-exact (265 anchors, arb275 A/A2)
        assert_eq!(
            dec(&t, 0x7239).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: v0 drift"
        );
        assert_eq!(
            dec(&t, 0x1000000000000007239).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0.H1"),
            "{leg}: v1 .H1 drift"
        );
        assert_eq!(
            dec(
                &t,
                0x1000000000000007239 | (5 << 16) | (4 << 24) | (3 << 32) | (2 << 64)
            )
            .as_deref(),
            Some("I2IP.U8.S32 R5, R4, R3, R2.H1"),
            "{leg}: v1 payload drift"
        );
        // suffix rows (b73=0) unaffected by the narrow: SAT/SATRELU decode
        let sat = dec(&t, 0x4000000000000007239).unwrap();
        assert!(
            sat.contains(".SAT") && !sat.contains("SATRELU"),
            "{leg}: {sat}"
        );
        let srl = dec(&t, 0x8000000000000007239).unwrap();
        assert!(srl.contains(".SATRELU"), "{leg}: {srl}");
    }
}

#[test]
fn t275_3_decode_holes_marker_window() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (tag, w) in [
            ("v2 .???2", 0x2000000000000007239u128),
            ("v3 .???3", 0x3000000000000007239u128),
            (
                "v2 payload",
                0x2000000000000007239u128 | (5 << 16) | (4 << 24) | (3 << 32) | (2 << 64),
            ),
            ("v2 guard @!PT", 0x2000000000000000f239u128),
            ("v2 +SAT", 0x6000000000000007239u128),
            ("v2 +SATRELU", 0xa0000000000000007239u128),
            ("v3 +SAT", 0x7000000000000007239u128),
            ("v2 +(80,81)", 0x2000000000000007239u128 | (3 << 80)),
            ("v2 +(62,63)", 0x2000000000000007239u128 | (3 << 62)),
            ("v3 +INVALID3", 0xf0000000000000007239u128),
        ] {
            assert!(
                dec(&t, w & M96).is_none(),
                "{leg}: {tag} silently decoded (275)"
            );
        }
    }
}

#[test]
fn t275_4_encode_legal_forms_exact_bits() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let w0 = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2").expect("plain encode");
        let w1 = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.H1").expect("h1 encode");
        assert_eq!(w1 & (3 << 72), 1 << 72, "{leg}: .H1 sets exactly b72");
        assert_ne!(w0, w1, "{leg}: .H1 dropped");
        let ws = enc_res(&t, "I2IP.U8.S32.SAT R5, R4, R3, R2.H1").expect("sat h1 encode");
        assert_eq!(ws & (3 << 72), 1 << 72, "{leg}: SAT .H1 b73 appeared");
        assert_eq!(ws & (3 << 74), 1 << 74, "{leg}: SAT bit drift");
        // legal words roundtrip word-exact through decode+encode
        for w in [w0, w1, ws] {
            let txt = dec(&t, w).expect("decode of own encode");
            let w2 = enc_res(&t, &txt).expect("re-encode");
            assert_eq!(w, w2, "{leg}: legal roundtrip lossy for {txt}");
        }
    }
}

#[test]
fn t275_5_registrations_anchors_tripwires() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // BUG-284 FLIP (was: 284-kand sentinel): the [90:87] window word
        // now decodes VENDOR-EQUAL -- payload window [95:82] \ b91 armed
        // vendor text-inert (arb284 560 probes x4 models; routes through
        // this exact word), twin pin in t284_5.
        assert_eq!(
            dec(&t, 0x30000000000000000007239u128).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: 284-window word decode drift"
        );
        // b73+b86 stays a hole: b86 armed text-inert by 284 but the b73
        // marker (275 narrow) keeps the word care-rejected.
        assert!(
            dec(&t, 0x2000000000000007239u128 | (1 << 86)).is_none(),
            "{leg}: b73+b86 silently decoded"
        );
        // zero word never decodes
        assert!(dec(&t, 0).is_none(), "{leg}: zero word decodes");
        // 265/276/282 era anchors unchanged
        assert!(t.entries.contains_key("I2I.U8.S32.SAT_R_R"), "{leg}");
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
        // BUG-272 FLIP (was: 272-class tripwire): '.???2'/unknown
        // operand-suffix text now FAILS CLOSED on encode (272 gate;
        // twin pin in t284_5 + full class pins in tests/bug272_enopsuffix.rs).
        let e = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.???2")
            .expect_err("272: unknown suffix must fail closed");
        assert!(e.contains("BUG-272"), "{leg}: 272 gate attribution: {e}");
    }
}
