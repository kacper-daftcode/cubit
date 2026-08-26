//! BUG-163 (F2-iter78, front2/blind; queue item = fleet note 162 sec.7(b)):
//! sm120 `LDC_R_cAI::""` carried `sub_imm1 @38/21` WITHOUT the bank
//! composition field, off the vendor geometry. nvdisasm-13.3.73 arbitration
//! on the SM120a arch itself (work/bug163/arb/arb163.json; gold + corpus
//! anchors of the 392-cubin sm120 corpus) proves the BUG-162 sm_103a law on
//! this arch too:
//!   LDC plain cAI: off = s16 @[38:54), bank = u5 @[54:59); bit37 inert,
//!   [59:64) inert; [24:32) is an R-index field (0xff sentinel elided on the
//!   plain anchor; such words route through LDC_R_cARI rows).
//! Measured pre-fix defects (main 8e02983, API probe work/bug163):
//!   (enc-reject) `LDC R4, c[0x1][0x20]` -> hard REJECT "no field able to
//!       encode it" though the form is vendor-legal;
//!   (enc-spill)  `LDC R4, c[0x0][0x10000]` -> silently wrote 0x10000 into
//!       the [38:59) window = vendor reads bank=1/off=0 (wrong payload);
//!   (dec-drop)   any word with bank bits [54:59)!=0 printed
//!       `c[0x0][off] !rsd[..]` -- bank lost from plain SASS text, so a
//!       text-level disasm->asm roundtrip silently zeroes the bank.
//! Census-first (work/bug163/census163.json): 39 corpus + 11 gold sm_120a
//! anchors on the row; bank==0 on 100% of them (bank!=0 exists on this
//! corpus ONLY inside LDC_R_cARI words, bank=0x2, 2 words, ldc_tri/
//! stg_tri) => pre-fix behaviour LATENT on the corpus; repair is
//! geometry-driven (matches BUG-147/148/150/152 handling).
//! Fix = ONE field record, data-only (work/bug163/patch163.py): extraction
//! swap sub_imm1 -> cm16_off @38/21 (donor geometry of the '64' sibling
//! row). Match semantics invariant (same field window + variable_mask).
//! Compose-disjoint with parked patch152 (owns LDCU_UR_cAI::'' on sm120),
//! patch148 (sub_r narrowing), patch162 (sm103a LDC/LDCU).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const L96: u128 = (1u128 << 96) - 1;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    s.split("/* @sched").next().unwrap().trim().to_string()
}

fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

/// t163_1 (polygon/compose): LDC_R_cAI::"" carries exactly one cm16_off
/// @38/21 carrier on token 2 and nothing else; sibling rows untouched;
/// compose sentinel: parked patch152's LDCU_UR_cAI::"" is still sub_imm1
/// @37/22 on this base (and cm17_off once 152 lands -- test must be
/// re-baselined then, like t162_1 allows sub_ur1 8|9).
#[test]
fn t163_1_window_polygon() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    let row = j.pointer("/instructions/LDC_R_cAI/mod_groups/").unwrap();
    let fields = row["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 2, "LDC_R_cAI[\"\"] field count: {fields:?}");
    let car: Vec<_> = fields.iter().filter(|f| f["extraction"] == "cm16_off").collect();
    assert_eq!(car.len(), 1);
    assert_eq!(car[0]["shift"].as_u64().unwrap(), 38);
    assert_eq!(car[0]["bits"].as_u64().unwrap(), 21);
    assert_eq!(car[0]["token_idx"].as_u64().unwrap(), 2);
    assert_eq!(car[0]["_src"].as_str().unwrap(), "bug163-2026-08-25");
    for f in fields {
        let e = f["extraction"].as_str().unwrap();
        assert!(e == "cm16_off" || e == "reg", "unexpected field {f:?}");
    }
    // siblings untouched
    let r64 = j.pointer("/instructions/LDC_R_cAI/mod_groups/64/fields").unwrap();
    assert!(r64.as_array().unwrap().iter().any(|f| f["extraction"] == "cm16_off"));
    let cari = j.pointer("/instructions/LDC_R_cARI/mod_groups//fields").unwrap();
    assert!(cari.as_array().unwrap().iter().any(|f| f["extraction"] == "sub_r1"));
}

/// t163_2 (encode bank materialization): vendor-legal bank!=0 plain forms
/// encode to the exact vendor word shape (arbitration-confirmed geometry;
/// expected words computed from and_base | reg | (bank<<16|off)<<38 and
/// cross-checked byte-for-byte against the measured encoder output).
#[test]
fn t163_2_encode_bank() {
    let t = t120();
    let w1 = enc(&t, "LDC R4, c[0x1][0x20]");
    assert_eq!(w1, w("000000000000080000400800ff047b82"), "bank=1 off=0x20");
    let w2 = enc(&t, "LDC R5, c[0x1f][0x7ffc]");
    assert_eq!(w2, w("000000000000080007dfff00ff057b82"), "bank=0x1f off=0x7ffc");
    let w0 = enc(&t, "LDC R6, c[0x0][0x388]");
    assert_eq!(w0, w("00000000000008000000e200ff067b82"), "bank=0 unchanged (corpus shape)");
}

/// t163_3 (decode bank): banked words print the bank; renders verified
/// against nvdisasm arbitration of the same mutated anchors (arb163).
#[test]
fn t163_3_decode_bank() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let corp = w("e2200000008000000df00ff017b82"); // corpus '' anchor
    assert_eq!(dec(&idx, corp, &t), "LDC R1, c[0x0][0x37c]");
    for b in [1u128, 2, 4, 0x1f] {
        let m = corp | (b << 54);
        let s = dec(&idx, m, &t);
        assert_eq!(s, format!("LDC R1, c[0x{b:x}][0x37c]"), "bank {b:#x} render");
        assert!(!s.contains("!rsd"), "no residual flag on arbitrated-legal word");
    }
}

/// t163_4 (corpus anchors byte-exact roundtrip): all 12 sampled corpus ''
/// anchors decode to plain-cAI text that re-encodes byte-identical on LOW96.
#[test]
fn t163_4_anchor_roundtrip() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let anchors = [
        "e2200000008000000df00ff017b82", "e2800000008000000e300ff177b82",
        "e3000000008000000e000ff008b82", "e3000000008000000e200ff0b8b82",
        "e6200000008000000e000ff077b82", "e6200000008000000e300ff070b82",
        "e6200000008000000e500ff007b82", "e6200000008000000e500ff057b82",
        "e6800000008000000e200ff017b82", "e6800000008000000e400ff067b82",
        "ea800000008000000e200ff347b82", "ea800000008000000e200ff3c7b82",
    ];
    for h in anchors {
        let word = w(h);
        let s = dec(&idx, word, &t);
        let re = enc(&t, &s);
        assert_eq!(re & L96, word & L96, "roundtrip identity LOW96 for {h} ({s})");
    }
}

/// t163_5 (no more silent bank spill): an over-16-bit plain offset keeps the
/// bank bits clean (the offset wraps inside its own 16-bit window; TIER-2
/// lint surfaces under CUBIT_FIT_LINT=warn; a hard range-check stay the
/// separate queued LOW item from 161/162 sec.5 "sub_imm*/cm_off
/// wrap-vs-reject").
#[test]
fn t163_5_no_bank_spill() {
    let t = t120();
    let w1 = enc(&t, "LDC R4, c[0x0][0x10000]");
    assert_eq!((w1 >> 54) & 0x1f, 0, "bank bits stay clean on offset overflow");
    assert_eq!((w1 >> 38) & 0xffff, 0, "overflowing offset wraps in-window (documented)");
}

/// t163_6 (window interpretation guardrail): bits [54:59) are the BANK now;
/// a word shaped like the pre-fix era's silent spill (0x10000 in the old
/// 21-bit window = bank=1/off=0x37c) decodes as bank=1 -- never as an
/// offset >= 0x10000 again. This is the pre-fix word that the era text
/// `c[0x0][0x1037c]` produced.
#[test]
fn t163_6_window_semantics() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let legacy_spill = w("000e2200000008000040df00ff017b82"); // '' anchor | (1<<54)
    let s = dec(&idx, legacy_spill, &t);
    assert_eq!(s, "LDC R1, c[0x1][0x37c]", "window bits are bank, not offset");
    // re-encode of that render must reproduce the SAME banked word
    let re = enc(&t, &s);
    assert_eq!(re & L96, legacy_spill & L96, "text-level roundtrip preserves bank");
}
