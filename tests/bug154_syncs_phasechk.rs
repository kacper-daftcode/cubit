//! BUG-154 (F2-iter74; candidate from the O2 depot, sev-A encoder gap):
//! SYNCS.PHASECHK.TRANS64[.TRYWAIT] R-address forms on sm_103a encoded
//! through an anchor-frozen junk singleton row (SYNCS_P_ARURI_R
//! ["PHASECHK,TRANS64"], count=1, vmask=0) with fabricated geometry
//! (pred@11, data-reg@16, baked operand sample) -- the O2 example
//! `@!P0 SYNCS.PHASECHK.TRANS64 P0, [R3+URZ], R4` emitted the word with R4 at
//! bits[23:16] instead of the vendor [39:32] and the decoded form printed
//! `desc[UR255][R3.64]`.
//!
//! Fix (data + printer): non-TRYWAIT ARURI group rebuilt from the healthy
//! TRYWAIT sibling (bit72 cleared); URZ-only ARI PHASECHK rows and the
//! desc-fabrication dARI key deleted (coverage transfers to the repaired
//! ARURI rows); AURI non-TRYWAIT sub_ur0 tightened 9->8 bits; printer arm
//! renders SYNCS ARURI as the vendor bracket form [Rn+URm(+0xoff)] with
//! URZ explicit (8-bit UR window @64, 0xff sentinel).
//!
//! Evidence: 11,531 section-paired vendor anchors (25 corpus cubins,
//! nvdisasm 13.3), 3,400 unique words: decode render-parity 3400/3400,
//! encode payload-parity 3400/3400 outside the sched zone [105:122)
//! (battery work/bug154/battery154_out.json). Pre-fix: 1201/3400 decode
//! parity; encode of [Rn+URZ] produced wrong bytes.
//!
//! Watch pins: (1,2) encode == vendor payload; (3,4,5) decode render-parity
//! incl. explicit URZ (no desc[] anywhere); (6) plain [Rn] PHASECHK is
//! fail-closed (vendor never prints it; forms are [Rn+URZ..]/[UR..]);
//! (7) AURI [URn(+imm)] class invariant.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

#[test]
fn t154_1_encode_urz_form_vendor_payload() {
    // O2 depot example: exp 0x00000000_080010ff_00000004_030085a7
    let t = t103a();
    let w = enc(&t, "@!P0 SYNCS.PHASECHK.TRANS64 P0, [R3+URZ], R4");
    assert_eq!(w, 0x00000000080010ff00000004030085a7u128 & !SCHED);
}

#[test]
fn t154_2_encode_real_ur_trywait_vendor_payload() {
    let t = t103a();
    let w = enc(&t, "SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [R2+UR29+0xd0], R3");
    assert_eq!(w, 0x000ea2000802111d0000d003020075a7u128 & !SCHED);
}

#[test]
fn t154_3_decode_urz_printed_explicitly() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let s = dec(&t, &idx, 0x000e6400080010ff00000000020085a7u128);
    assert_eq!(s, "@!P0 SYNCS.PHASECHK.TRANS64 P0, [R2+URZ], R0");
}

#[test]
fn t154_4_decode_real_ur_is_not_desc() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let s = dec(&t, &idx, 0x000ea2000802111d0000d003020075a7u128);
    assert_eq!(s, "SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [R2+UR29+0xd0], R3");
    assert!(!s.contains("desc["), "desc fabrication must be gone: {s}");
}

#[test]
fn t154_5_decode_urz_imm_nontrywait() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let s = dec(&t, &idx, 0x000e6400080010ff00014002030085a7u128);
    assert_eq!(s, "@!P0 SYNCS.PHASECHK.TRANS64 P0, [R3+URZ+0x140], R2");
}

#[test]
fn t154_6_plain_r_form_fail_closed() {
    // Vendor never prints plain [Rn] for PHASECHK -- after the ARI row
    // deletion the form must refuse (not silently fabricate a word).
    let t = t103a();
    let insn = parse_sass("SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R3], R4", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err());
    let insn = parse_sass("@!P0 SYNCS.PHASECHK.TRANS64 P0, [R3], R4", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err());
}

#[test]
fn t154_7_auri_class_invariant() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // @P0 TRYWAIT P1, [UR4], R0 -- UR-only form unchanged class
    let s = dec(&t, &idx, 0x0002a2000802110400000000ff0005a7u128);
    assert_eq!(s, "@P0 SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [UR4], R0");
    let w = enc(&t, "@P0 SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [UR4+0x8], R0");
    // roundtrip: encode -> decode must return the same text
    let idx2 = DecodeIndex::build(&t103a());
    let s2 = dec(&t103a(), &idx2, w);
    assert_eq!(s2, "@P0 SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [UR4+0x8], R0");
}
