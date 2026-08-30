//! BUG-296 (F2-iter150, loop5/blind front2, 2026-08-30): I2IP encode-side
//! generic-sign residuum closure on the 0x7239 4-op lattice, legs
//! sm120+sm121a. Registered LOW at F2-iter147 (281 report sec.6):
//! 'I2IP.U8.S32 R5, -R4, R3, R2' minted b72 (cross-read '.H1' via the
//! opmod:H1@72 field on tok4) and 'R4, -R3' minted b63 = silent drop.
//! Measurement-first (work/bug296): measure_pre296 (pub pyo3-4941ec5)
//! CONFIRMED the two registered lanes and MEASURED TWO MORE:
//!   L1 '-Ra' -> b72 -> decode 'I2IP.U8.S32 R5, R4, R3, R2.H1'  (XREAD)
//!   L2 '-Rb' -> b63, '|Rb|' -> b62 -> decode plain             (DROP)
//!   L3 '-Rc' -> b75 == ''.SATRELU'' and_base -> decode '.SATRELU' (XREAD)
//!   L4 '|Rc|' -> b74 == ''.SAT'' and_base -> decode '.SAT'     (XREAD)
//! ('|Ra|' -> b73 already fail-closed encode-verify, BUG-275 table hole).
//! LAW (arb282 + arb284, nvdisasm 13.3.73 raw -b, x4 models agree every
//! probe): b62/b63 text-INERT on the family (E2); b74=.SAT b75=.SATRELU,
//! b74+b75='.INVALID3'; b72 = the '.H1' op-suffix; NO sign-modifiable
//! register operands anywhere on the lattice. Decoder ghost-sign
//! exclusion for the whole I2IP base armed by BUG-282; the ENCODER arm
//! was missing until this fix.
//! FIX (engine only, src/encoder.rs; tables byte-unchanged, canonical
//! 99bbde1): (b) "I2IP" excluded from the generic sign emit (is_alu);
//! (c) explicit fail-closed bail on any signed Reg/UReg operand on I2IP,
//! message attribution 'BUG-296'. Mirror of the BUG-281 I2I arms.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const BASE: u128 = 0x7239 | (7 << 12); // '' row and_base + PT guard
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| cubit::printer::to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t296_1_signed_lanes_fail_closed_attributed() {
    // Every pre-fix silent lane now errors loudly with BUG-296 attribution,
    // on all four operand slots and all three suffix rows, both legs.
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for form in ["I2IP.U8.S32", "I2IP.U8.S32.SAT", "I2IP.U8.S32.SATRELU"] {
            for (slot, text) in [
                ("negRa", format!("{form} R5, -R4, R3, R2")),
                ("absRa", format!("{form} R5, |R4|, R3, R2")),
                ("negRb", format!("{form} R5, R4, -R3, R2")),
                ("absRb", format!("{form} R5, R4, |R3|, R2")),
                ("negRc", format!("{form} R5, R4, R3, -R2")),
                ("absRc", format!("{form} R5, R4, R3, |R2|")),
            ] {
                let e = enc_res(&t, &text)
                    .expect_err(&format!("{leg}: {slot} must fail: {text}"));
                assert!(
                    e.contains("BUG-296"),
                    "{leg}: {slot} missing BUG-296 attribution: {e}"
                );
            }
        }
    }
}

#[test]
fn t296_2_no_bits_minted_before_bail() {
    // The bail must fire even when the generic sign emit is the only code
    // that would have set the bit: assert via a guard-bearing signed text
    // (guard plumbing intact, bail still attributed).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let e = enc_res(&t, "@P2 I2IP.U8.S32 R5, R4, -R3, R2")
            .expect_err("guarded signed text must fail");
        assert!(e.contains("BUG-296"), "{leg}: attribution: {e}");
    }
}

#[test]
fn t296_3_legal_forms_word_exact() {
    // Plain / op-suffix / sibling-suffix / guard controls unchanged
    // (words from the pre-fix published pyo3-4941ec5, measure_pre296 F).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let w_payload = BASE | (5 << 16) | (4 << 24) | (3 << 32) | (2u128 << 64);
        let w = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2").expect("plain");
        assert_eq!(w & M96, w_payload, "{leg}: plain word drift");
        let w = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.H1").expect(".H1");
        assert_eq!(w & M96, w_payload | (1u128 << 72), "{leg}: .H1 word drift");
        let w = enc_res(&t, "I2IP.U8.S32.SAT R5, R4, R3, R2").expect(".SAT");
        assert_eq!(w & M96, w_payload | (1u128 << 74), "{leg}: .SAT word drift");
        let w = enc_res(&t, "I2IP.U8.S32.SATRELU R5, R4, R3, R2").expect(".SATRELU");
        assert_eq!(w & M96, w_payload | (1u128 << 75), "{leg}: .SATRELU word drift");
        let w = enc_res(&t, "@P2 I2IP.U8.S32 R5, R4, R3, R2").expect("guard");
        assert_eq!(w & M96, (w_payload & !(0xF << 12)) | (2 << 12), "{leg}: guard drift");
    }
}

#[test]
fn t296_4_cross_read_siblings_still_decode() {
    // The decoder side is untouched by this fix: b72/b74/b75 semantics
    // remain the armed BUG-282/265 laws (sanity that the former encode
    // cross-read targets are still real, legible SILENT-WRONG-CODE
    // destinations -- i.e. the bail, not a table change, is what closes
    // the lanes).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let w_payload = BASE | (5 << 16) | (4 << 24) | (3 << 32) | (2u128 << 64);
        assert_eq!(
            dec(&t, w_payload | (1u128 << 72)).as_deref(),
            Some("I2IP.U8.S32 R5, R4, R3, R2.H1"),
            "{leg}: b72 .H1 decode law drift"
        );
        assert_eq!(
            dec(&t, w_payload | (1u128 << 74)).as_deref(),
            Some("I2IP.U8.S32.SAT R5, R4, R3, R2"),
            "{leg}: b74 .SAT decode law drift"
        );
        assert_eq!(
            dec(&t, w_payload | (1u128 << 75)).as_deref(),
            Some("I2IP.U8.S32.SATRELU R5, R4, R3, R2"),
            "{leg}: b75 .SATRELU decode law drift"
        );
        // b62/b63 stay text-inert (post-282 era: no ghost print)
        assert_eq!(
            dec(&t, w_payload | (1u128 << 62)).as_deref(),
            Some("I2IP.U8.S32 R5, R4, R3, R2"),
            "{leg}: b62 inert law drift"
        );
    }
}

#[test]
fn t296_5_encoder_decoder_parity_note() {
    // Encoder exclusion set must now contain every decoder is_alu exclusion
    // that affects the generic sign window for measured families: I2I (281)
    // and I2IP (282/296). Guarded by observing the fail-closed behavior of
    // both families on identical signed text.
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let e1 = enc_res(&t, "I2I.U8.S32.SAT R14, -R38").expect_err("I2I signed");
        assert!(e1.contains("BUG-281"), "{leg}: I2I arm regressed: {e1}");
        let e2 = enc_res(&t, "I2IP.U8.S32 R5, -R4, R3, R2").expect_err("I2IP signed");
        assert!(e2.contains("BUG-296"), "{leg}: I2IP arm regressed: {e2}");
        // non-armed ALU control keeps its real neg/abs law (IMAD b72 = true neg)
        let w = enc_res(&t, "IMAD R5, -R4, R3, R2").expect("IMAD signed");
        let d = dec(&t, w).expect("IMAD decodes");
        assert_eq!(d, "IMAD R5, -R4, R3, R2", "{leg}: IMAD sign law regressed");
    }
}
