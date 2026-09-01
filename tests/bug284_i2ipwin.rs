//! BUG-284 (F2-iter145, loop5/blind front2, 2026-08-29): I2IP.U8.S32 4-op
//! payload window [95:82] vendor text-inert reclaim on the 0x7239 lattice,
//! legs sm120+sm121a (canonical bug284 cut ea4af02, ride-after 889179c).
//! Measurement-first (work/bug284): arb284 (560 probes) nvdisasm 13.3.73
//! raw -b, x4 models SM100a/103a/120/121a agree on EVERY probe; routex284
//! FULL 2,406-cubin battery (pub pyo3-9ad9981): ZERO family words AND ZERO
//! near-miss words under the pre-widened mask (both legs) => graft
//! corpus-neutral by construction.
//!
//! LAW (x4 models): payload bits [95:82] are vendor TEXT-INERT on this
//! family -- rc=0 and the printed text is identical to the same-payload
//! v0 base for every single bit b82..b95 (plain + regs), every sub-window
//! value ([85:82]x16, [90:87]x16, [95:91]x32), and every composition with
//! guards, .H1 b72, .SAT b74, .SATRELU b75, (80,81), (62,63) -- EXCEPT
//! b91, which is a vendor KILL-BIT (rc=1 'Unrecognized operation' x4,
//! plain and regs): stays a care-bit => decode HOLE preserved (the vendor
//! rejects those words anyway). Reclaim doctrine: 276 (80,81) / 282
//! (62,63) text-inert vm-widen precedent.
//! PRE-FIX (measured pub pyo3-9ad9981, work/bug284/measure_pre284.log):
//! every window-bit word decoded as HOLE on both legs = silent rejection
//! of vendor-printable text (the 275-era '' row keeps [95:82] out of vm).
//! GRAFT (both legs, 3 keys ''/SAT/SATRELU mg ''): variable_mask |=
//! (0x3DFF << 82) = [95:82] minus b91. and_base byte-unchanged (window
//! bits 0 there), fields untouched (opmod:H1@72 intact), b73 narrow from
//! 275 intact. Engine ZERO changes. DONORS sm100a/sm103a byte-untouched.
//! LOAD-BEARING roundtrip note: decode(w|window) == decode(w) text
//! (vendor-equal); re-encode yields the canonical base word (inert bits
//! cleared) = text-stable, word-lossy ONLY on vendor-undefined payload
//! patterns the toolchain never emits (routex284: zero corpus exposure
//! including the near-miss surface).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
// 276 (80,81) + 282 (62,63) + 275 (-b73) + 284 (| window [95:82] \ b91)
const VM_POST284: u128 = 0x1c000000000301ffc00000fffffff000u128 | (0x3DFFu128 << 82);
const WIN284: u128 = 0x3FFFu128 << 82; // full vendor window incl. b91
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t284_1_structure_widen_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (nk, bit) in [
            ("I2IP.U8.S32_R_R_R_R", 0u32),
            ("I2IP.U8.S32.SAT_R_R_R_R", 74u32),
            ("I2IP.U8.S32.SATRELU_R_R_R_R", 75u32),
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
            assert_eq!(vm, VM_POST284, "{leg}: {nk} vmask drift (284 widen)");
            assert_eq!((vm >> 73) & 1, 0, "{leg}: {nk} b73 back in vmask");
            assert_eq!((vm >> 91) & 1, 0, "{leg}: {nk} kill-bit b91 in vmask");
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
fn t284_2_decode_laws_widened_words_vendor_equal() {
    let base = 0x7239u128;
    let regs = base | (5 << 16) | (4 << 24) | (3 << 32) | (2 << 64);
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // every single inert bit alone = base text (plain + regs)
        for b in [82u32, 83, 84, 85, 86, 87, 88, 89, 90, 92, 93, 94, 95] {
            assert_eq!(
                dec(&t, base | (1 << b)).as_deref(),
                Some("I2IP.U8.S32 R0, R0, R0, R0"),
                "{leg}: b{b} not text-inert (plain)"
            );
            assert_eq!(
                dec(&t, regs | (1 << b)).as_deref(),
                Some("I2IP.U8.S32 R5, R4, R3, R2"),
                "{leg}: b{b} not text-inert (regs)"
            );
        }
        // sub-windows + full inert window = base text
        for v in [1u128, 5, 0xF] {
            assert_eq!(
                dec(&t, base | (v << 82)).as_deref(),
                dec(&t, base).as_deref(),
                "{leg}: win[85:82] v{v} drift"
            );
            assert_eq!(
                dec(&t, base | (v << 87)).as_deref(),
                dec(&t, base).as_deref(),
                "{leg}: win[90:87] v{v} drift"
            );
        }
        for v in [2u128, 0x1E, 0x1F] {
            // b91 excluded from graft; use even values (b91=0) here
            let vv = v & !(1 << 9);
            assert_eq!(
                dec(&t, base | (vv << 82)).as_deref(),
                dec(&t, base).as_deref(),
                "{leg}: win[95:82] v{vv} drift"
            );
        }
        assert_eq!(
            dec(&t, regs | (0x3DFFu128 << 82)).as_deref(),
            Some("I2IP.U8.S32 R5, R4, R3, R2"),
            "{leg}: full inert window + regs drift"
        );
        // composability with family ops (suffix resolution intact)
        let fw = 0x3DFFu128 << 82;
        assert_eq!(
            dec(&t, base | fw | (1 << 72)).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0.H1"),
            "{leg}: FW+.H1 drift"
        );
        let sat = dec(&t, base | fw | (1 << 74)).unwrap();
        assert!(
            sat.contains(".SAT") && !sat.contains("SATRELU"),
            "{leg}: FW+SAT {sat}"
        );
        let srl = dec(&t, base | fw | (1 << 75)).unwrap();
        assert!(srl.contains(".SATRELU"), "{leg}: FW+SATRELU {srl}");
        assert_eq!(
            dec(&t, base | fw | (3 << 80) | (3 << 62) | (1 << 72)).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0.H1"),
            "{leg}: FW+(80,81)+(62,63)+H1 drift"
        );
    }
}

#[test]
fn t284_3_killbit_and_holes_stay() {
    let base = 0x7239u128;
    let fw = 0x3DFFu128 << 82;
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (tag, w) in [
            ("b91 kill plain", base | (1 << 91)),
            ("b91 kill regs", base | (1 << 91) | (5 << 16) | (2 << 64)),
            ("b91+FW full window", base | WIN284),
            ("b91+SAT", base | (1 << 91) | (1 << 74)),
            ("b73 marker", base | (1 << 73)),
            ("b73+FW", base | (1 << 73) | fw),
            ("v3 .???3+FW", base | (3 << 72) | fw),
            ("INVALID3", base | (3 << 74)),
            ("INVALID3+FW", base | (3 << 74) | fw),
        ] {
            assert!(dec(&t, w).is_none(), "{leg}: {tag} silently decoded (284)");
        }
        assert!(dec(&t, 0).is_none(), "{leg}: zero word decodes");
    }
}

#[test]
fn t284_4_encode_unchanged_and_text_stable() {
    let fw = 0x3DFFu128 << 82;
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let w0 = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2").expect("plain encode");
        let w1 = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.H1").expect("h1 encode");
        let ws = enc_res(&t, "I2IP.U8.S32.SAT R5, R4, R3, R2.H1").expect("sat encode");
        // encode never emits inert window bits
        for w in [w0, w1, ws] {
            assert_eq!(w & WIN284, 0, "{leg}: encode sets window bits");
        }
        // legal words roundtrip word-exact through decode+encode
        for w in [w0, w1, ws] {
            let txt = dec(&t, w).expect("decode of own encode");
            let w2 = enc_res(&t, &txt).expect("re-encode");
            assert_eq!(w, w2, "{leg}: legal roundtrip lossy for {txt}");
        }
        // text-stability on inert-window words: decode == base text, and
        // re-encode yields the canonical base word (inert bits cleared =
        // the documented word-lossy/text-stable reclaim behavior)
        for w in [w0 | fw, w1 | fw, ws | fw] {
            let txt = dec(&t, w).expect("widened word must decode");
            let w2 = enc_res(&t, &txt).expect("re-encode of widened decode");
            assert_eq!(w2, w & !WIN284, "{leg}: widen re-encode != base word");
        }
    }
}

#[test]
fn t284_5_registrations_anchors_tripwires() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // ex-sentinel words from t275_5/t282_5 now decode VENDOR-EQUAL
        assert_eq!(
            dec(&t, 0x30000000000000000007239u128).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: 284 window [90:87]=3 decode drift"
        );
        assert_eq!(
            dec(&t, 0x7239u128 | (1 << 86)).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: b86 (HFMA2 .H0_NH1 slot) not text-inert here"
        );
        // b73+b86 stays a hole (b73 care dominates; 275 narrow intact)
        assert!(
            dec(&t, 0x2000000000000007239u128 | (1 << 86)).is_none(),
            "{leg}: b73+b86 silently decoded"
        );
        // b91 kill-bit registration: vendor rc=1 x4 => hole kept on purpose
        assert!(
            dec(&t, 0x7239u128 | (1 << 91)).is_none(),
            "{leg}: kill-bit b91 armed"
        );
        // era anchors unchanged
        assert!(t.entries.contains_key("I2I.U8.S32.SAT_R_R"), "{leg}");
        assert!(
            t.entries["HFMA2_R_R_R_II_FI"]
                .mod_groups
                .contains_key("SAT"),
            "{leg}: 274 HFMA2 arm lost"
        );
        // BUG-283 flip (was: 276-era junk print '_P5 R0, R128' tripwire):
        // lane armed to the vendor law (canonical 1beab0f)
        assert_eq!(
            dec(&t, 0x70000023a).as_deref(),
            Some("@P0 MOVM.16.MT88 R0, R0"),
            "{leg}: 283-armed MOVM anchor"
        );
        // BUG-272 FLIP (was: 272-class tripwire): unknown operand-suffix
        // text now FAILS CLOSED on encode (272 gate; twin pin in t275_5 +
        // full class pins in tests/bug272_enopsuffix.rs).
        let e = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.???2")
            .expect_err("272: unknown suffix must fail closed");
        assert!(e.contains("BUG-272"), "{leg}: 272 gate attribution: {e}");
    }
}
