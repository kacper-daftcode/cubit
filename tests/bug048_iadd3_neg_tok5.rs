//! BUG-048 (rejestr sm120: 045_failed_encode_ghost.md, gnome-ghost class sink):
//! `IADD3.X Rd, Pc, PT, Ra, -Rb, Rc, P, P` — a real negation (`-Rn`) on
//! the second ORDINARY register argument (tok5) was SILENTLY LOST by
//! the "X" mod group of the `IADD3_R_P_P_R_R_R_P_P` row (it had `inv` but no
//! `neg`; the duplicated `IADD3.X_R_P_P_R_R_R_P_P` row has it, but the matcher
//! picks IADD3_R_P_P...). Effect: `R26 - R25` encoded as `R26 + R25`
//! (6d63ef37: encode-fail + ghost in .text; after the mk74 carry minis: fully
//! wrong code, 0 failed). Golden evidence:
//!  * nvcc 12.8 sm_120 (sub.cc/subc.cc probes, /tmp/p048 on sm120):
//!    `IADD3 R11, P0, PT, R0, -R7, RZ`            lo = 0x80000007000b7210
//!    `IADD3.X R13, P0, PT, R6, ~R9, RZ, P0, !PT` lo = 0x80000009060d7210
//!    => bit63 = invert of the tok5 input (one place for ~ and -; the semantics
//!    `-b` = `~b` + cin, with cin==PT (1): a + ~b + 1 = a - b — exactly).
//!  * rt98_pub.cubin /*d430*/ = 0x8000000d3b0d3210: `@P3 IADD3.X R13, P0, P1,
//!    R59, ~R13, -R92, P0, PT` (inv tok5 @63 + neg tok6 @75) — the full
//!    frozen RT rests on this word byte-wise.
//!  * nvdisasm 13.0 (sm103a) and 13.3 (sm120) PRINT `~Rn` for bit63 in the
//!    .X form regardless of the cin slot — the `-Rn` glyph in that slot comes from
//!    author records (s6 i122), not nvdisasm; the encoder maps `-` onto the canonical
//!    inversion bit (the printer shows `~` after the round-trip, like nvdisasm).
//! Fix (data level, symmetry with the IADD3.X_ row): + `neg` tok5 in the
//! "X" group of the `IADD3_R_P_P_R_R_R_P_P` row — tables/sm120.json + sm103a.json.
//! Extraction::Neg already degrades back to inv, so the existing golden
//! tok5 encodings (~R) are bitwise unchanged (frozen-RT rt98 == 3d15ab6a,
//! stale).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

fn lo(text: &str) -> u64 {
    (enc(text) & ((1u128 << 64) - 1)) as u64
}

#[test]
fn bug048_neg_tok5_encoded_not_dropped() {
    let neg = lo("IADD3.X R26, P2, PT, R26, -R25, RZ, !PT, !PT");
    let inv = lo("IADD3.X R26, P2, PT, R26, ~R25, RZ, !PT, !PT");
    let plain = lo("IADD3.X R26, P2, PT, R26, R25, RZ, !PT, !PT");
    assert_eq!(plain, 0x00000019_1a1a7210, "base form regressed: {plain:#018x}");
    assert_eq!(neg, inv, "`-` must land on the same invert bit as `~` (cin=PT arithmetic)");
    assert_ne!(neg, plain, "neg silently dropped again");
    assert!(neg & (1 << 63) != 0 && plain & (1 << 63) == 0);
}

#[test]
fn bug048_nvcc_golden_subcc_byte_exact() {
    // nvcc 12.8 sm_120, sub.cc.u32: lo64 exactly as nvcc (sched bits
    // above 96 taken by the probe are masked — we compare the full lo64).
    assert_eq!(lo("IADD3 R11, P0, PT, R0, -R7, RZ"), 0x80000007_000b7210);
    assert_eq!(lo("IADD3.X R13, P0, PT, R6, ~R9, RZ, P0, !PT"), 0x80000009_060d7210);
}

#[test]
fn bug048_rt98_golden_inv_tok5_neg_tok6() {
    // rt98_pub.cubin .text.KernelB /*d430*/ — frozen bajt w bajt.
    assert_eq!(
        lo("@P3 IADD3.X R13, P0, P1, R59, ~R13, -R92, P0, PT"),
        0x8000000d_3b0d3210
    );
    // tok4 neg (ra) i tok6 neg (rc) — pre-existing pokrycie, pin regresyjny:
    // -R59 -> bit 72; -R92 -> bit 75.
    let w4 = enc("@P3 IADD3.X R13, P0, P1, -R59, R13, R92, P0, PT");
    let w6 = enc("@P3 IADD3.X R13, P0, P1, R59, R13, -R92, P0, PT");
    assert!((w4 >> 72) & 1 == 1, "tok4 neg@72 lost");
    assert!((w6 >> 75) & 1 == 1, "tok6 neg@75 lost");
}

#[test]
fn bug048_render_canonical_inv_glyph() {
    // The golden rt98 word /*d430*/ renders to the canonical nvdisasm form.
    let idx = DecodeIndex::build(&t120());
    let word: u128 = 0x000fe800_0010ec5c_8000000d_3b0d3210;
    let d = idx.decode(word, 0, &t120()).expect("decode golden failed");
    let text = format!("{d}");
    assert!(
        text.contains("IADD3.X R13, P0, P1, R59, ~R13, -R92"),
        "golden render drifted: {text}"
    );
    // The newly encodable `-R25` form renders back as `~R25`
    // (the nvdisasm-13.x canon for bit63 in the .X form).
    let w = enc("IADD3.X R26, P2, PT, R26, -R25, RZ, !PT, !PT");
    let d2 = idx.decode(w, 0, &t120()).expect("decode new word failed");
    let text2 = format!("{d2}");
    assert!(
        text2.contains("IADD3.X R26, P2, PT, R26, ~R25, RZ"),
        "roundtrip glyph not canonical: {text2}"
    );
}

#[test]
fn bug048_sm103a_table_parity() {
    let t103 = IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    // Note: the sm103a.x group has no neg field for tok7 (trailing `!PT`) —
    // the BUG-006 fail-closed check has long rejected those endings (outside the
    // 048 scope). The parity pin covers ONLY tok5 (neg).
    let insn = parse_sass("IADD3.X R26, P2, PT, R26, -R25, RZ, PT, PT", 0).unwrap();
    let w = encode_instruction(&insn, &t103).expect("encode sm103a failed");
    assert!(w & (1u128 << 63) != 0, "sm103a table still drops tok5 neg");
}
