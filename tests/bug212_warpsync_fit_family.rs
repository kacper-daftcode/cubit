//! BUG-212 (branch-landing wave 2026-08-26): the BUG-140 aggregate-fit audit
//! gated the WARPSYNC.COLLECTIVE label-payload exemption (class c, fixup-owned
//! REL16; BUG-116 law) on the EXACT sm_103a ef_flags. The sm_100a derivative
//! table shares the encoding family 1:1, so the audit hard-failed re-encode of
//! every corpus WARPSYNC.COLLECTIVE there: 139,570 instructions of the b4
//! sm_100 population (cusolver/cusparse) flipped byte-exact match -> error.
//! Evidence: internal recon/o2/basewave_100a.rows.jsonl (encode-lint
//! "field union 0x3f" per WARPSYNC_R_II / WARPSYNC_II) + the fix restores the
//! O2 baseline coverage. Fix: exemption keyed on is_sm103a_encoding_family.
//!
//! Word construction mirrors the BUG-116 anchors: v=2 REL16 window, so at
//! text address 0x3cc0 the partner target renders as 0x3cc0+16+(2<<4)=0x3cf0
//! (target == addr + 16 + (v<<4)).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0x1FFFFu128 << (64 + 41);

/// and_base & ~variable_mask | R16 | v=2, COLLECTIVE mod (from the table row).
const WORD: u128 = 0xfea0003c000000000000010087348;
const ADDR: u32 = 0x3cc0;

fn dec(t: &IsaTable, idx: &DecodeIndex) -> String {
    idx.decode(WORD, ADDR, t)
        .map(|d| cubit::printer::to_sass(&d))
        .expect("decode")
}

fn rt(t: &IsaTable) -> u128 {
    let idx = DecodeIndex::build(t);
    let text = dec(t, &idx);
    assert!(text.starts_with("WARPSYNC"), "decoded: {text}");
    assert!(text.contains("0x3cf0"), "resolved partner target: {text}");
    let insn = parse_sass(&text, ADDR).expect("parse");
    encode_instruction(&insn, t).expect("encode (fit audit must exempt the REL16 payload)")
        & !SCHED
}

#[test]
fn t182_sm103a_control() {
    let t = IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    assert_eq!(rt(&t), WORD & !SCHED, "sm103a control roundtrip");
}

#[test]
fn t182_sm100a_family_exemption() {
    let t = IsaTable::load(std::path::Path::new("tables/sm100a.json")).unwrap();
    assert_eq!(rt(&t), WORD & !SCHED, "sm100a derivative roundtrip");
}
