//! BUG-252 (F2-iter133, loop5/blind front2, 2026-08-29): encode-side
//! fabrication of uniform-register `.reuse` via the generic reuse slot
//! fallback (apply_reuse_encoding). Mechanism: for an entry with a ureg
//! field at a reuse slot shift (24/32/64 -> bits 122/123/124) and NO
//! explicit per-row `reuse` field bound to that token, the legacy fixup
//! set the bit straight from the operand flag. Vendor law says that word
//! is illegal:
//!   arb249b (nvdisasm 13.3.73 raw -b, corpus FSEL hosts):
//!     host A (R-form): b122 '.reuse' on tok2 OK, b123 on tok3 OK, b124
//!                      (pred slot) ILLEGAL;
//!     host C (UR-form `FSEL R5, |R3|.reuse, |UR11|, !P2`): b123 set ->
//!                      ILLEGAL (nvdisasm drops the glyph row), b124 ILLEGAL.
//!   pop226d census: zero UR.reuse in 545,792 words; the decoder/ printer
//!   never emits UR.reuse (sideband law, bug226d) -> the fabricated class
//!   is corpus-empty and this guard is corpus-neutral.
//! Rows with a data-taught explicit `reuse` field bound to a UR token
//! (e.g. BUG-144 UIADD3 drain, reuse@124 grafted on a vendor anchor word)
//! stay authoritative: the fixup skips explicit bits and the field-level
//! extraction is untouched. The wider explicit-field inventory (122 sm120
//! + 705 sm121a + 5 sm103a/sm100a rows) is tracked as the 263-kand
//! (latent; needs per-family census+arb, owner severity).
//! Repro pre-fix (published cubit-b505503, probe252.py): on all four legs
//! `FSEL R5, |R3|.reuse, |UR11|.reuse, !P2` encoded silently with b123=1;
//! `IMAD R4, R5, UR6.reuse, R7` likewise (IMAD_UR carries no explicit
//! reuse field on any leg).
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn try_enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("{e:#}"))
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    try_enc(t, text).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

#[test]
fn t252_1_fsel_ur_tok3_reuse_fail_closed_sm103a() {
    let t = tab("sm103a");
    let e = try_enc(&t, "FSEL R5, |R3|.reuse, |UR11|.reuse, !P2")
        .expect_err("UR tok3 .reuse must fail closed");
    assert!(e.contains("BUG-252"), "error must name the guard: {e}");
    assert!(e.contains("123"), "error must name the fabricated bit: {e}");
}

#[test]
fn t252_2_fsel_ur_reuse_fail_closed_all_legs() {
    for arch in ["sm100a", "sm120", "sm121a"] {
        let t = tab(arch);
        let e = try_enc(&t, "FSEL R5, |R3|.reuse, |UR11|.reuse, !P2")
            .expect_err("UR tok3 .reuse must fail closed");
        assert!(e.contains("BUG-252"), "{arch}: {e}");
    }
}

#[test]
fn t252_3_legal_paths_byte_stable() {
    let t = tab("sm103a");
    // R-domain reuse through explicit row fields (FSEL_R_R_R_P): unchanged.
    let r = enc(&t, "FSEL R9, |R4|.reuse, |R5|.reuse, P0");
    assert_eq!(
        r, 0x0c0fc200000002004000000504097208,
        "R-form reuse byte drift"
    );
    assert_eq!((r >> 122) & 1, 1);
    assert_eq!((r >> 123) & 1, 1);
    // UR operand WITHOUT .reuse: unchanged word (guard is fabrication-only).
    let p = enc(&t, "FSEL R5, |R3|.reuse, |UR11|, !P2");
    assert_eq!(p, 0x040fc2000d0002004000000b03057c08, "plain UR byte drift");
    assert_eq!((p >> 123) & 1, 0);
}

#[test]
fn t252_4_explicit_ur_reuse_field_stays_authoritative() {
    // UIADD3_UR_UP_UP_UR_UR_UR '' on sm120 carries a data-taught explicit
    // reuse@124 (BUG-144 graft on a vendor anchor word); the generic guard
    // must not touch the explicit path. The sm121a sibling row without
    // mods is an era row (ureg/pred, no reuse fields at all) -- pre-fix it
    // fabricated the same word via the generic slot fallback (probe252;
    // byte-equal by coincidence); post-fix it must fail closed.
    let t = tab("sm120");
    let w = enc(&t, "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7.reuse");
    assert_eq!(
        w, 0x100fc2000fffe0070000000605047290,
        "sm120 explicit drift"
    );
    assert_eq!((w >> 124) & 1, 1, "sm120: explicit reuse@124 lost");
    let t121 = tab("sm121a");
    let e = try_enc(&t121, "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7.reuse")
        .expect_err("sm121a era row has no explicit reuse field");
    assert!(e.contains("BUG-252"), "sm121a: {e}");
}

#[test]
fn t252_5_generic_guard_covers_other_families() {
    // IMAD_UR_* has no explicit reuse field anywhere -> same generic
    // fabrication, same hard error; the no-reuse control stays byte-stable.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let e = try_enc(&t, "IMAD R4, R5, UR6.reuse, R7")
            .expect_err("IMAD UR tok3 .reuse must fail closed");
        assert!(e.contains("BUG-252"), "{arch}: {e}");
    }
    let t = tab("sm103a");
    let p = enc(&t, "IMAD R4, R5, UR6, R7");
    assert_eq!(
        p, 0x000fc2000f8e02070000000605047c24,
        "IMAD plain byte drift"
    );
}
