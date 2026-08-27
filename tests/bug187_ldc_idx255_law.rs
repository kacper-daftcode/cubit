//! F-187 (F2-iter89, front2/blind; queue item = fleet note i87 sec.5(b),
//! "F-187-kand: LDC absolute-plain po LDC_R_II delete", marker t174_5
//! red in the i87 compose rehearsal).
//!
//! VERDICT: NEGATYW (not-a-bug).  The vendor `LDC Rx, 0xNNNNN`
//! absolute-plain render for the idx==0xff class does NOT exist; the
//! t174_5 expectation `LDC R24, 0x30000` (word
//! 000e24000000000000c00000ff187b82) was itself the LDC_R_II junk-row
//! fabrication that parked BUG-165 measured and deleted (165.md sec.1/3:
//! "FABR every `LDC.U8` -> `LDC R3, 0x5ec` via junk LDC_R_II").
//! Re-arbitration here (work/bug187/arb/):
//!   * nvdisasm-13.3.73 AND nvdisasm-13.0 agree on every probe;
//!   * idx=0xff is the `[RZ]` sentinel: width rows 0..5 all print
//!     `c[bank][RZ]` at off==0, signed off hex otherwise
//!     (arb187.json, widthmap in arb187_widths.log);
//!   * single-bit scan maps vendor geometry exactly to the 162/163/165
//!     law: off s16@[38:54) (bit53 => `-0x8000`), bank u5@[54:59),
//!     idx [24:32) (arb187_bitscan.json);
//!   * the ghost `0x30000` = bank=3 bits (54,55) misread by the junk row
//!     as [58:38] (3<<16) -- the "absolute address" was the bank number;
//!   * arb167_round2.json u8_idx255 always recorded the vendor render
//!     `LDC.U8 R24, c[0x3][RZ]`; fleet note i87 read the pin's own
//!     expectation as vendor truth (circular).
//!   * main 2bd2a82 parity: 22/22 sweep + widths 0..5 == vendor,
//!     INVALID6/7 fail-closed (arb187_sweep.json).
//! Action: re-pin t174_5 expectation to `LDC.U8 R24, c[0x3][RZ]` at
//! compose time (pin lives on parked-174/rehearsal branches); this file
//! pins the same law directly on main so a resurrection of the
//! absolute-plain shape goes red immediately.  No src/table change.
//! Neg-ctl: current binary + pre-165 table (wt/f2-174-ctl @ 8e02983)
//! renders `LDC R24, 0x30000` -- every pin below flips red there.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const L96: u128 = (1u128 << 96) - 1;

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
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    s.split("/* @sched").next().unwrap().trim().to_string()
}
fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

/// The i87 t174_5 anchor word, with real corpus ctrl bits.
const ANCHOR: &str = "000e24000000000000c00000ff187b82";

/// t187_1: the disputed word IS vendor `LDC.U8 R24, c[0x3][RZ]`
/// (arb187.json + arb167_round2 u8_idx255 + nvdisasm 13.0/13.3), never an
/// absolute-plain render.  Same on the sm103a table.
#[test]
fn t187_1_t1745_anchor_is_vendor_u8_sentinel() {
    for t in [t120(), t103()] {
        let idx = DecodeIndex::build(&t);
        let s = dec(&idx, w(ANCHOR), &t);
        assert_eq!(s, "LDC.U8 R24, c[0x3][RZ]");
        assert!(!s.starts_with("LDC R24, 0x"), "absolute-plain ghost resurrected");
    }
}

/// t187_2: idx=0xff sentinel law across the vendor-legal widths (width
/// window [73:76), real anchor ctrl): RZ glyph at off==0 for widths
/// 0..5 == nvdisasm widthmap; INVALID6/7 stay fail-closed (no fabricated
/// width glyph).
#[test]
fn t187_2_idxff_width_law() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let base = w(ANCHOR) & !(0x7u128 << 73);
    let law = [
        (0u128, "LDC.U8 R24, c[0x3][RZ]"),
        (1, "LDC.S8 R24, c[0x3][RZ]"),
        (2, "LDC.U16 R24, c[0x3][RZ]"),
        (3, "LDC.S16 R24, c[0x3][RZ]"),
        (4, "LDC R24, c[0x3][RZ]"),
        (5, "LDC.64 R24, c[0x3][RZ]"),
    ];
    for (wd, want) in law {
        assert_eq!(dec(&idx, base | (wd << 73), &t), want, "width {wd}");
    }
    for wd in [6u128, 7] {
        assert!(idx.decode(base | (wd << 73), 0, &t).is_err(),
                "INVALID{width} must fail-closed", width = wd);
    }
}

/// t187_3: vendor off/bank geometry at idx=0xff on main == nvdisasm
/// (arb187_sweep.json 22/22): off s16@[38:54) signed incl. bit53 =>
/// `-0x8000`, bank u5@[54:59), `[RZ]` only at off==0.  Plain-width family
/// cross-checked from the arb167 LDCplainidx donor.
#[test]
fn t187_3_idxff_off_bank_sign_sweep() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let set = |w: u128, lo: u32, v: u128, bits: u32| {
        let m = ((1u128 << bits) - 1) << lo;
        (w & !m) | ((v << lo) & m)
    };
    let anch = w(ANCHOR);
    let cases = [
        (set(anch, 38, 0x1, 16), "LDC.U8 R24, c[0x3][0x1]"),
        (set(anch, 38, 0x5ec, 16), "LDC.U8 R24, c[0x3][0x5ec]"),
        (set(anch, 38, 0x8000, 16), "LDC.U8 R24, c[0x3][-0x8000]"),
        (set(anch, 38, 0xffff, 16), "LDC.U8 R24, c[0x3][-0x1]"),
        (set(anch, 54, 0x0, 5), "LDC.U8 R24, c[0x0][RZ]"),
        (set(anch, 54, 0x5, 5), "LDC.U8 R24, c[0x5][RZ]"),
        (set(anch, 54, 0x1f, 5), "LDC.U8 R24, c[0x1f][RZ]"),
        // register-index control: idx!=0xff keeps [Rn+off]
        (set(w("000e24000000000000c0000018187b82"), 38, 0x5ec, 16),
         "LDC.U8 R24, c[0x3][R24+0x5ec]"),
    ];
    for (ww, want) in cases {
        assert_eq!(dec(&idx, ww, &t), want, "word {ww:032x}");
    }
    // plain-width donor family (arb167 LDCplainidx): LDC R2, c[0x2][R6]
    let plain = set(w("000e2400000008000080000006027b82"), 24, 0xff, 8);
    assert_eq!(dec(&idx, plain, &t), "LDC R2, c[0x2][RZ]");
    assert_eq!(dec(&idx, set(plain, 38, 0x4, 16), &t), "LDC R2, c[0x2][0x4]");
    assert_eq!(dec(&idx, set(plain, 54, 0x5, 5), &t), "LDC R2, c[0x5][RZ]");
}

/// t187_4 (negative control, coder-side): the absolute-plain TEXT form
/// stays refused by the encoder (no operand-compatible entry), so no
/// silent absolute-plain path can return; decode->encode roundtrip of the
/// true render is byte-exact on [0:96).
#[test]
fn t187_4_absolute_plain_encode_stays_refused() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for bad in ["LDC R24, 0x30000", "LDC.U8 R24, 0x30000"] {
        let insn = parse_sass(bad, 0).expect("parse");
        assert!(encode_instruction(&insn, &t).is_err(),
                "absolute-plain encode must fail-closed: {bad}");
    }
    let s = dec(&idx, w(ANCHOR), &t);
    assert_eq!(enc(&t, &s) & L96, w(ANCHOR) & L96, "roundtrip anchor");
    let s5 = dec(&idx, w(ANCHOR) | (5u128 << 73), &t);
    assert_eq!(enc(&t, &s5) & L96, (w(ANCHOR) | (5u128 << 73)) & L96,
               "roundtrip .64 sentinel");
}

/// t187_5: hexdb corpus anchors of the off==0 sentinel class (cross-arch;
/// census174.json: 12 raw lines / 3 uniq words on sm_100/103/103a).
#[test]
fn t187_5_hexdb_sentinel_anchors() {
    for t in [t120(), t103()] {
        let idx = DecodeIndex::build(&t);
        for (h, want) in [
            ("000e220000000a0001000000ff1e7b82", "LDC.64 R30, c[0x4][RZ]"),
            ("000e220000000a0001000000ff087b82", "LDC.64 R8, c[0x4][RZ]"),
            ("000e220000000a0001000000ff0c7b82", "LDC.64 R12, c[0x4][RZ]"),
        ] {
            assert_eq!(dec(&idx, w(h), &t), want, "anchor {h}");
        }
    }
}
