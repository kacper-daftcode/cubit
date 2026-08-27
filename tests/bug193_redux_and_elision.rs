//! BUG-193 — sm120 REDUX bare-AND elision (owner: front2/blind F2-iter93).
//! Kand z noty 192 sec.6(b): 3 anchory sm_120a (bug142 gold: red1_120,
//! ptx1_120, ptx2_120) vendor drukuje BARE `REDUX UR5, R0`, dekoder main
//! 2bd2a82 drukowal `REDUX.AND` (mg 'AND' wygrywal tiebreak nad mg '' —
//! opaque_mod pola tok0 przegrywaly popcount; klasa tiebreak z BUG-089).
//!
//! Prawo vendora (arb193.json: ptxas+nvdisasm 13.3.73, sm_120a, sweep
//! 16-stanowy op[78:81) x bit73-S32): op=0 => BARE `REDUX` (AND elidowany
//! rowniez przy S32: `REDUX.S32`); op 1..5 => OR/XOR/SUM/MIN/MAX (+.S32);
//! 6/7 => INVALID6/7. Krzem-prawo op0=AND: BUG-191 (B300 patched-op).
//!
//! Fix data-only (patch193.py replayable, idempotent): mg 'AND' ->
//! encode_only (retencja tekstu legacy, decode-invisible), mg '' ->
//! usuniete opaque_mod pola (druk czystego bare; popcount tiebreak
//! wygrywa z wierszami op>0 bo ab-op=0 == code). sm103a/sm100a juz
//! kanonicznie bare — nietkniete. Residuum (194-kand): stany S32-sibir
//! (op0/1/2/3 + b73=1) i INVALID6/7 druk na main = junk/min-max z !rsd —
//! zero kotwic korpusowych, poprawny wymaga wierszy, ktorych render
//! XOR.S32/SUM.S32 zalezy od parked-192 printer-arm (ta sama fala ff).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}
fn w(lo: u64, hi: u64) -> u128 { lo as u128 | ((hi as u128) << 64) }

// The 3 hexdb anchors (2 distinct words; sched zone [96:128) ignored).
const ANCHORS: &[(u64, u64)] = &[
    (0x00000000000573c4, 0x001e220000000000),
    (0x00000000000573c4, 0x001e240000000000),
];
// Payload for the canonical bare encode (ctl-produced, byte-pinned).
const BARE_PAYLOAD: u128 = 0x00000000000573c4;

#[test]
fn t193_1_anchors_decode_bare() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (lo, hi) in ANCHORS {
        let got = dec(&t, &idx, w(*lo, *hi));
        assert_eq!(got, "REDUX UR5, R0", "anchor {lo:016x}{hi:016x} not bare");
    }
}

#[test]
fn t193_2_encode_bare_payload_exact() {
    let t = t120();
    assert_eq!(enc(&t, "REDUX UR5, R0"), BARE_PAYLOAD, "bare encode drift");
}

#[test]
fn t193_3_retention_legacy_and_byte_exact() {
    // Legacy authored glyph stays encodable (encode_only row), same word.
    let t = t120();
    assert_eq!(enc(&t, "REDUX.AND UR5, R0"), BARE_PAYLOAD, "AND retention drift");
    // ... and re-decodes vendor-true (bare), i.e. semantic roundtrip.
    let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&t, &idx, enc(&t, "REDUX.AND UR5, R0")), "REDUX UR5, R0");
}

#[test]
fn t193_4_guard_and_reg_walk() {
    // guard predicate + different UR/R numerals stay bare (op still 0).
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for text in ["@P0 REDUX UR9, R42", "@!P3 REDUX UR63, R254"] {
        let word = enc(&t, text);
        let got = dec(&t, &idx, word);
        assert_eq!(got, *text, "guard/reg walk roundtrip drift for {text}");
    }
}

#[test]
fn t193_5_legal_states_stay_vendor_true() {
    // States that were already vendor-exact on main must NOT move
    // (op1..5 b73=0 plus MIN/MAX .S32) — regression tripwire for the
    // ''-row reshape. Words built on the k_and witness base.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let base: u128 = 0x001e24000000000000000000000673c4;
    let cases = [
        (1u128, 0u128, "REDUX.OR UR6, R0"),
        (2, 0, "REDUX.XOR UR6, R0"),
        (3, 0, "REDUX.SUM UR6, R0"),
        (4, 0, "REDUX.MIN UR6, R0"),
        (4, 1, "REDUX.MIN.S32 UR6, R0"),
        (5, 0, "REDUX.MAX UR6, R0"),
        (5, 1, "REDUX.MAX.S32 UR6, R0"),
    ];
    for (op, b73, want) in cases {
        let word = (base & !(7u128 << 78) & !(1u128 << 73)) | (op << 78) | (b73 << 73);
        let got = dec(&t, &idx, word);
        assert_eq!(got, want, "legal state op{op} b73={b73} moved");
    }
}

#[test]
fn t193_6_sm103a_canon_untouched() {
    // Canon table keeps its bare-AND behaviour (sm103a '' row, cnt 61).
    let t = t103();
    let idx = DecodeIndex::build(&t);
    assert_eq!(enc(&t, "REDUX UR5, R0"), BARE_PAYLOAD, "sm103 bare encode drift");
    assert_eq!(dec(&t, &idx, BARE_PAYLOAD | 0x0004e40000000000u128 << 64), "REDUX UR5, R0");
}
