//! BUG-181 — sm120 ATOMS coverage repair (owner: front2/blind F2-iter85).
//! Found as kand-181 in fleet note 179 (sec. 8c): decode hole + two steals
//! in the sm120 table, all anchors from the ptx3_120.cubin gold
//! (bug142/hexdb) and arbitated with nvdisasm 13.3.73 (work/bug181/arb/).
//!
//! Census-first over the 32.2M-line hexdb (9,130 ATOMS words, both tables):
//! 8,647 IDENT pre-fix and every 181-domain anchor is sm_120a:
//!   (a) `ATOMS.POPC.INC.32 RZ, [UR4+0xc]` — FAIL-CLOSED (no key);
//!   (b) `ATOMS.EXCH R0, [UR4+0x1c], R0` — STEAL via ATOMS_R_ARI_R::EXCH
//!       (UR window + imm unread, printed `[RZ]`);
//!   (c) `ATOMS.CAS.64 R2, [R7+0x10], R8, R10` — FAIL-CLOSED;
//!   (d) `ATOMS.CAS R0, [R0+0x4], R6, R7` — STEAL via junk 3-token
//!       ATOMS_R_ARI_R::CAS (lost operand + imm);
//!   (e) `ATOMS.CAST.SPIN P0, [R0+0x14], R2, R3` — FAIL-CLOSED (no key);
//! plus the whole 478-anchor `[Rn+URZ..]` POPC class that stays this
//! branch's compose-sibling (parked BUG-179 owns the printer splice).
//!
//! Vendor law (nvdisasm 13.3.73, arb181d/e/f.json, sm_120a, in-place
//! patched gold cubin):
//!   - UR window [64:72): UR0..UR63 real legal, 0xff = URZ (sink law);
//!     RZ base elided from glyph ([UR4+0xc]), real base kept
//!     ([R6+UR4+0xc]).
//!   - CAS: width [73:75) = {0,.S32,.64,.128}; imm s32 @[40:64);
//!     guard 4b @[12:16); val @[64:72); cmp @[32:40).
//!   - CAST.SPIN: pred-dest 3b @[81:84); same width window (.64 = b74);
//!     guard 4b @[12:16).
//!
//! Fix: data-only tables/sm120.json (patch181.py replayable) + printer.rs
//! (ATOMS-scoped AURI/ARURI dispatch -> format_atoms_auri; POPC arm in
//! ATOMS mod priority — textually identical to parked-179's arm, compose
//! keeps one copy). sm103a.json untouched.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// (vendor text, raw128) — all five ptx3_120.cubin anchors.
const CASES: &[(&str, u128)] = &[
    ("ATOMS.POPC.INC.32 RZ, [UR4+0xc]",
     0x00000c00ffff7f8c | (0x000fe8000d800004u128 << 64)),
    ("ATOMS.EXCH R0, [UR4+0x1c], R0",
     0x00001c00ff00798c | (0x000e24000c000004u128 << 64)),
    ("ATOMS.CAS.64 R2, [R7+0x10], R8, R10",
     0x000010080702738d | (0x000e22000000040au128 << 64)),
    ("ATOMS.CAS R0, [R0+0x4], R6, R7",
     0x000004060000738d | (0x000e240000000007u128 << 64)),
    ("ATOMS.CAST.SPIN P0, [R0+0x14], R2, R3",
     0x000014020000758d | (0x000e240001800003u128 << 64)),
];

#[test]
fn t181_1_decode_vendor_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (v, w) in CASES {
        assert_eq!(&dec(&t, &idx, *w), v, "decode must reproduce vendor text");
    }
}

#[test]
fn t181_2_encode_payload_exact() {
    let t = t120();
    for (v, w) in CASES {
        assert_eq!(enc(&t, v), w & !SCHED, "encode payload must equal anchor");
    }
}

#[test]
fn t181_3_roundtrip_fixed_point() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (_, w) in CASES {
        let text = dec(&t, &idx, *w);
        assert_eq!(enc(&t, &text), w & !SCHED, "decode->encode fixed point");
    }
}

#[test]
fn t181_4_sink_and_realur_law() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let a = CASES[0].1;
    // 0xff window renders the URZ sink, 0x3f the real UR63 (8-bit law).
    let w = (a & !(0xFFu128 << 64)) | (0xFFu128 << 64);
    assert_eq!(dec(&t, &idx, w), "ATOMS.POPC.INC.32 RZ, [URZ+0xc]");
    let w = (a & !(0xFFu128 << 64)) | (0x3Fu128 << 64);
    assert_eq!(dec(&t, &idx, w), "ATOMS.POPC.INC.32 RZ, [UR63+0xc]");
    // real base survives the glyph elide rule.
    let w = (a & !(0xFFu128 << 24)) | (6u128 << 24);
    assert_eq!(dec(&t, &idx, w), "ATOMS.POPC.INC.32 RZ, [R6+UR4+0xc]");
}

#[test]
fn t181_5_cas_widths_and_guard() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let d = CASES[3].1;
    assert_eq!(dec(&t, &idx, d | (1u128 << 73)), "ATOMS.CAS.S32 R0, [R0+0x4], R6, R7");
    assert_eq!(dec(&t, &idx, d | (2u128 << 73)), "ATOMS.CAS.64 R0, [R0+0x4], R6, R7");
    assert_eq!(dec(&t, &idx, d | (3u128 << 73)), "ATOMS.CAS.128 R0, [R0+0x4], R6, R7");
    // guard field [12:16): @P1 form (arb181e D_guard1).
    assert_eq!(enc(&t, "@P1 ATOMS.CAS R0, [R0+0x4], R6, R7"),
               (d & !SCHED & !(0xFu128 << 12)) | (1u128 << 12));
    // encode widths payload-exact.
    assert_eq!(enc(&t, "ATOMS.CAS.64 R0, [R0+0x4], R6, R7"), (d & !SCHED) | (2u128 << 73));
}

#[test]
fn t181_6_junk_cas_key_gone() {
    // The 3-token junk CAS row was the steal winner for CASES[3]; removing
    // it must not re-open a print of the wrong arity.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let got = idx.decode(CASES[3].1, 0, &t).expect("decode");
    assert_eq!(got.key, "ATOMS_R_ARI_R_R");
}

#[test]
fn t181_7_sm103a_untouched() {
    // sm103a table was NOT part of this bug; its real-UR POPC form stays
    // fail-closed today (parked BUG-179 + forward work own that lane).
    // 2026-08-26 compose: "sm103a untouched" held for THIS branch's diff,
    // but the canonical wave itself filled ATOMS_R_ARURI on sm103a from the
    // 143-era adds -- POPC real-UR is live there now (UR63 prints UR63).
    // EXCH AURI has no sm103a row and stays fail-closed, as pinned here.
    let t = cubit::table::IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    let idx = cubit::decoder::DecodeIndex::build(&t);
    let good = "ATOMS.POPC.INC.32 RZ, [R0+UR63+0x3c]";
    let insn = parse_sass(good, 0).expect("parse");
    let w = encode_instruction(&insn, &t).expect("POPC real-UR live on sm103a (wave row)");
    assert_eq!(idx.decode(w, 0, &t).map(|d| cubit::printer::to_sass(&d)).unwrap(), good);
    let insn = parse_sass("ATOMS.EXCH R0, [UR4+0x1c], R0", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err(),
            "EXCH AURI stays fail-closed on sm103a (no row)");
}
