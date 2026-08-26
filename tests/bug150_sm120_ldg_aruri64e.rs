//! BUG-150 (F2-iter72, front2/blind; candidate from note 149 sec.5, lane F2):
//! tables/sm120.json carried the same junk row shape as BUG-149 (sm103a):
//! mod group LDG_R_ARURI::64,E with and_base byte [88:96) == 0x08
//! (mode-2 = nvcc sm_100/103 raw-U32+UR form, donor-verbatim from an sm120
//! import era) while vendor sm120 bakes mode-6 (byte11 == 0x18, 10/10 era
//! anchors, census 149/150) -- so the group could never win a vendor word,
//! yet it was decode-visible and fabricated descriptor semantics
//! `LDG.E.64 R8, desc[UR8][R6.64]` for any hypothetical mode-2 word
//! (pre-fix probe work/bug150/negctl_ctl_synth.txt; class mirrors BUG-095/
//! BUG-149 impersonator mechanics).
//!
//! Deadness is machine-proven (work/bug150/census150.json): the group's
//! matcher (mirror of src/decoder.rs strict/relaxed/broad tiers, guard-free)
//! matches 0 words across the whole sm120 vendor corpus (392 cubins /
//! 21,309 unique words), 0 across the frozen era rc4 bin (3,538), 0 of the
//! b4fill2 GOLD era anchors. Positive controls live: canonical raw row
//! LDG.E.64_R_ARURI (mode-6) matches 39 corpus uniques (all byte11==0x18,
//! strict tier), LDG.E_R_ARURI 1, LDG.E.128_R_ARURI 1, LDG_R_dARI::64,E 2.
//!
//! Fix (data-only, work/bug150/patch150.py): delete the group. Encode never
//! routed through it (raw text -> LDG.E.64_R_ARURI via addr_width=U32;
//! desc text -> LDG_R_dARI). A/B decode 392/392 cubins = 0 diff files.

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

fn parts(lo: u64, hi32: u32) -> u128 { (lo as u128) | ((hi32 as u128) << 64) }

// Vendor witnesses (sm120 corpus / frozen era bins, byte11 == 0x18, mode-6).
// First two are the tests/b4fill2_rows.rs GOLD era anchors.
const RAW_WITNESS: &[(u64, u32, &str)] = &[
    (0x0000000806087981, 0x181e0b00, "LDG.E.64 R8, [R6.U32+UR8]"),
    (0x00080008060a7981, 0x181e0b00, "LDG.E.64 R10, [R6.U32+UR8+0x800]"),
    (0x00040008060a7981, 0x181e0b00, "LDG.E.64 R10, [R6.U32+UR8+0x400]"),
    (0x0000002419fc7981, 0x181e0900, "LDG.E R252, [R25.U32+UR36]"),
    (0x00000026d2dc3981, 0x181e0d00, "@P3 LDG.E.128 R220, [R210.U32+UR38]"),
];

// Removed group LDG_R_ARURI::64,E, matcher spec frozen from the pre-fix
// table (md5 42924c73e7697898d08b8df949b07d2a epoch).
const IMP_AB: u128 = 0x000f2600081e0b0000000000ff007981;
const IMP_VM: u128 = 0x00000000000000000000000c00be0000;
// fields: reg@16/8, sub_ur1@32/9, sub_r0@24/8
const IMP_FM: u128 = (0xFF << 16) | (0x1FF << 32) | (0xFF << 24);
const GUARD: u128 = 0xF000;

fn imp_matches(w: u128) -> bool {
    // mirror src/decoder.rs: both sides stripped to low96 (upper32 = sched)
    let mm = (!IMP_VM) & (!IMP_FM);
    let strip = !((0xFFFF_FFFFu128) << 96);
    (w & strip & mm & !GUARD) == (IMP_AB & strip & mm & !GUARD)
}

#[test]
fn t150_1_table_class_invariants() {
    let t = t120();
    let aruri = t.entries.get("LDG_R_ARURI").expect("LDG_R_ARURI key");
    assert!(!aruri.mod_groups.contains_key("64,E"),
            "LDG_R_ARURI::64,E impersonator regressed");
    for keep in ["E", "E,LTC128B", "64,E,LTC128B", "128,E,LTC128B"] {
        assert!(aruri.mod_groups.contains_key(keep), "lost group {keep}");
    }
    // canonical raw rows keep vendor-true mode-6 byte11 (0x18) on sm120
    for (key, mg) in [
        ("LDG.E_R_ARURI", "E"),
        ("LDG.E.64_R_ARURI", "64,E"),
        ("LDG.E.128_R_ARURI", "128,E"),
        ("LDG.E.EL.STRONG.GPU_R_ARURI", "E,EL,GPU,STRONG"),
        ("LDG.E.NA.STRONG.SM_R_ARURI", "E,NA,SM,STRONG"),
    ] {
        let g = t.entries.get(key).unwrap().mod_groups.get(mg).unwrap();
        assert_eq!((g.and_base >> 88) & 0xff, 0x18, "{key}::{mg} byte11 != 0x18 (mode-6 vendor-true)");
    }
    // desc space untouched (mode-3, byte11 == 0x0c)
    let d = t.entries.get("LDG_R_dARI").unwrap().mod_groups.get("64,E").unwrap();
    assert_eq!((d.and_base >> 88) & 0xff, 0x0c);
}

#[test]
fn t150_2_vendor_anchor_decode_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in RAW_WITNESS {
        let got = dec(&t, &idx, parts(*lo, *hi32));
        assert_eq!(&got, want, "mode-6 anchor decode regressed");
        assert!(!got.contains("desc["), "desc fabrication regressed: {got}");
    }
    // desc sibling intact (corpus witness, mode-3)
    let got = dec(&t, &idx, 0x0e28000c1e1b000000400402727981u128);
    assert_eq!(got, "LDG.E.64 R114, desc[UR4][R2.64+0x40]");
}

#[test]
fn t150_3_encode_routing_byte_exact_mode6() {
    // Encode must never have needed the removed group: raw text routes by
    // addr_width=U32 to the canonical row and bakes the sm120-vendor byte.
    let t = t120();
    assert_eq!(enc(&t, "LDG.E.64 R8, [R6.U32+UR8]"),
               parts(0x0000000806087981, 0x181e0b00));
    assert_eq!(enc(&t, "LDG.E.64 R10, [R6.U32+UR8+0x800]"),
               parts(0x00080008060a7981, 0x181e0b00));
}

#[test]
fn t150_4_mode2_word_fail_closed_no_fabrication() {
    // The pre-fix fabrication probe: mode-2 (bit92=0, byte11=0x08) variant of
    // the GOLD anchor. Vendor sm120 never emits it; pre-fix it printed
    // fabricated `LDG.E.64 R8, desc[UR8][R6.64]` via the impersonator.
    // Post-fix: decode must fail closed (no row owns that space).
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let synth = parts(0x0000000806087981, 0x081e0b00);
    let r = idx.decode(synth, 0, &t);
    assert!(r.is_err(), "mode-2 synthetic word decoded: {r:?}");
    // sanity: the frozen spec really does own this word (mirror check)
    assert!(imp_matches(synth), "frozen impersonator spec must match the probe word");
}

#[test]
fn t150_5_frozen_spec_dead_on_anchors() {
    // The removed group's frozen matcher must NOT match any vendor word
    // class that lives on sm120: mode-6 (0x18) or desc (0x0c) raw space.
    for (lo, hi32, _) in RAW_WITNESS {
        assert!(!imp_matches(parts(*lo, *hi32)),
                "impersonator spec would match vendor mode-6 word {lo:#x}/{hi32:#x}");
    }
    assert!(!imp_matches(0x0e28000c1e1b000000400402727981u128),
            "impersonator spec would match a desc word");
}
