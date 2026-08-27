//! BUG-194 — sm120 REDUX_UR_R S32-sibling rows (owner: iter92, loop5/blind
//! front MAIN). Kand z noty 193 sec.8: stany op[78:81) in {0,1,2,3} z b73=1
//! sa legalne u vendora (arb193.json: ptxas+nvdisasm 13.3.73 sm_120a, pelny
//! sweep 16-stanowy) — `REDUX.S32` (AND elidowany tez przy S32),
//! `REDUX.OR.S32`, `REDUX.XOR.S32`, `REDUX.SUM.S32`. Zmergowana baza
//! (193+192) dekodowala je jako ZLY mnemonik: op0s1 `REDUX.MIN.S32`,
//! op1s1 `REDUX.MAX.S32`, op2/3s1 operand-junk `|R0|`; encode byl fail-closed
//! (guard BUG-132), czyli brak cichego zlego kodu, ale calkowita dziura RE.
//! Zero kotwic korpusowych dla tych stanow (census 193: hexdb REDUX lane ma
//! tylko 3 anchory sm_120a, wszystkie op0 b73=0).
//!
//! Fix data-only (work/i92/patch194.py replayable+idempotent): +4 wiersze
//! [S32 / OR,S32 / S32,XOR / S32,SUM] z ab = BASE|op<<78|1<<73, vm i pola
//! identyczne jak u rodzenstwa. Render porzadku `.SUM.S32` wymaga printer-arm
//! parked-192 (stad baza = merge 192+193, ride-after z noty 193 sec.8).
//! op6/7 (vendor INVALID6/INVALID7) POZA ZAKRESEM zgodnie z doktryna domu
//! (piny 135/172: stanom INVALID nie daje sie wierszy; dekoder NIE moze
//! fabrykowac czystego mnemonika). Residuum op6/7 = znany junk (t194_6);
//! ewentualna vm-narrowing robota -> hard fail-closed = decyzja wlasciciela.

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
fn enc_ok(t: &IsaTable, text: &str) -> bool {
    parse_sass(text, 0).map(|i| encode_instruction(&i, t).is_ok()).unwrap_or(false)
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}
/// Witness-shaped word (arb193 k_and base; UR6, R0; PT guard; [96:128) sched
/// zone carries the vendor epoch bits of the witness, stripped by matcher).
fn state_word(op: u128, b73: u128) -> u128 {
    (0x001e24000000000000000000000673c4u128 & !(7u128 << 78) & !(1u128 << 73))
        | (op << 78) | (b73 << 73)
}
/// Payload [0:96) for the bare UR6,R0 encode of a state.
fn state_payload(op: u128, b73: u128) -> u128 {
    0x673c4u128 | (op << 78) | (b73 << 73)
}

#[test]
fn t194_1_vendor_grid_all_legal_states() {
    // arb193 grid, all 12 legal states (ride-after ff-192: the .S32 order
    // here is the 192 printer-arm law — REDUX.SUM.S32, never S32-first).
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let cases = [
        (0u128, 0u128, "REDUX UR6, R0"),
        (0, 1, "REDUX.S32 UR6, R0"),
        (1, 0, "REDUX.OR UR6, R0"),
        (1, 1, "REDUX.OR.S32 UR6, R0"),
        (2, 0, "REDUX.XOR UR6, R0"),
        (2, 1, "REDUX.XOR.S32 UR6, R0"),
        (3, 0, "REDUX.SUM UR6, R0"),
        (3, 1, "REDUX.SUM.S32 UR6, R0"),
        (4, 0, "REDUX.MIN UR6, R0"),
        (4, 1, "REDUX.MIN.S32 UR6, R0"),
        (5, 0, "REDUX.MAX UR6, R0"),
        (5, 1, "REDUX.MAX.S32 UR6, R0"),
    ];
    for (op, b73, want) in cases {
        let got = dec(&t, &idx, state_word(op, b73));
        assert_eq!(got, want, "legal state op{op} b73={b73} drift");
    }
}

#[test]
fn t194_2_new_rows_encode_payload_and_roundtrip() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let cases = [
        (0u128, "REDUX.S32 UR6, R0"),
        (1u128, "REDUX.OR.S32 UR6, R0"),
        (2u128, "REDUX.XOR.S32 UR6, R0"),
        (3u128, "REDUX.SUM.S32 UR6, R0"),
    ];
    for (op, text) in cases {
        let w = enc(&t, text);
        assert_eq!(w, state_payload(op, 1), "payload drift for {text}");
        assert_eq!(dec(&t, &idx, w), text, "roundtrip drift for {text}");
    }
    // guard + operand numerals stay intact through the new rows
    let w = enc(&t, "@P0 REDUX.SUM.S32 UR9, R42");
    assert_eq!(dec(&t, &idx, w), "@P0 REDUX.SUM.S32 UR9, R42");
}

#[test]
fn t194_3_legacy_s32_first_spelling_alias() {
    // extract_mod_group sorts; the pre-192 corpus spelling `REDUX.S32.SUM`
    // encodes to the SAME word and re-decodes in vendor order.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let a = enc(&t, "REDUX.S32.SUM UR6, R0");
    let b = enc(&t, "REDUX.SUM.S32 UR6, R0");
    assert_eq!(a, b, "spelling-order alias broke");
    assert_eq!(dec(&t, &idx, a), "REDUX.SUM.S32 UR6, R0");
}

#[test]
fn t194_4_prior_domain_tripwire() {
    // 193 domain stays: bare anchors + AND retention payload-exact.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (lo, hi) in [(0x00000000000573c4u64, 0x001e220000000000u64),
                     (0x00000000000573c4u64, 0x001e240000000000u64)] {
        let got = dec(&t, &idx, lo as u128 | ((hi as u128) << 64));
        assert_eq!(got, "REDUX UR5, R0", "193 anchor moved");
    }
    assert_eq!(enc(&t, "REDUX UR5, R0"), 0x00000000000573c4u128);
    assert_eq!(enc(&t, "REDUX.AND UR5, R0"), 0x00000000000573c4u128);
}

#[test]
fn t194_5_invalid_states_encode_fail_closed() {
    // House doctrine (135/172): vendor-INVALID enum states get no rows;
    // the BUG-132 guard must refuse the authored glyph instead of
    // fabricating a different word.
    let t = t120();
    for text in ["REDUX.INVALID6 UR6, R0", "REDUX.INVALID6.S32 UR6, R0",
                 "REDUX.INVALID7 UR6, R0", "REDUX.INVALID7.S32 UR6, R0"] {
        assert!(!enc_ok(&t, text), "INVALID glyph encoded: {text}");
    }
}

#[test]
fn t194_6_invalid_decode_residual_known_state() {
    // Residual by decision: op6/7 words still decode to the best-effort
    // sibling glyph (wrong mnemonic, known junk — zero corpus anchors,
    // 193.md sec.2/sec.8). This pin is a TRIPWIRE only: the day the
    // vm-narrowing surgery makes these hard-fail-closed, re-pin with
    // attribution instead of treating it as a regression.
    // 2026-08-26/27 compose: the tripwire FIRED the way the header asked
    // for -- the wave-2 canonical sweep (arb210/probe206a + BUG-211 b72
    // vm-parity) narrowed the last loose rows, so op6/7 words are now hard
    // fail-closed at decode. Re-pin with attribution, per the header's own
    // instruction.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (op, b73) in [(6u128, 0u128), (6, 1), (7, 0), (7, 1)] {
        assert!(idx.decode(state_word(op, b73), 0, &t).is_err(),
            "op{op} b73={b73} hard fail-closed post-sweep");
    }
}
