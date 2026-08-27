//! BUG-190 — UTCCP_II_II window-law rebuild (owner: front2/blind F2-iter92).
//! Nota 186 sec.7(b) = 190-kand: 7 mk296 dup mod-groups tok1/tok2 @(24,8)
//! overlap. Live both directions on main 2bd2a82 (ptxas-13.3.73 witnesses,
//! work/bug190/ucp_g{1,2}.{ptx,cubin}): decode hole 7/12 vendor forms ->
//! `/* ? */`, encode silently clobbers tmem<-gdesc (byte32 baked 0xff,
//! guard nib 0x8, vm=0).
//!
//! Vendor law (nvdisasm 13.3.73 bit-scan, arb190a.json; sm_100a words ==
//! sm_103a word-for-word; sm_120a has no tcgen05.cp):
//!   - guard UP    @[12:16)   (@UP0 for 0, unguard=7)
//!   - tmem_ur     @[24:32)   8-bit, 0xff = URZ (elided); UR0..UR64 literal
//!   - gdesc_ur    @[32:40)   8-bit, 0xff prints gdesc[URZ]
//!   - tmem_off    @[40:56)   full 16-bit; with URZ base the vendor elides
//!                            the register: `tmem[0x800]`, never URZ+off
//! Shape discriminants vs donor 'S,T' = subsets of {83,84,85,88} (2CTA=85).
//! Fix: tables sm103a/sm100a.json data-only (patch190.py replayable:
//! 7-row rebuild to donor clone, 3 mk306 rows off12->16 + guard field),
//! printer.rs tmem URZ+off elision, encoder.rs absolute tmem[0x..] scrape.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t100() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm100a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}
fn w(lo: u64, hi: u64) -> u128 { lo as u128 | ((hi as u128) << 64) }

// (cubit text, lo, hi) — all 12 ptxas witnesses, ctrl [96:128) ignored.
const WITNESS: &[(&str, u64, u64)] = &[
    ("UTCCP.T.S tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0033d80008000000),
    ("UTCCP.T.S.128dp128bit tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80008180000),
    ("UTCCP.T.S.4dp256bit tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80008100000),
    ("UTCCP.T.S.2x64dp128bit_lw01_lw23 tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80009080000),
    ("UTCCP.T.S.2x64dp128bit_lw02_lw13 tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80009000000),
    ("UTCCP.T.S.4x32dp128bit tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80009100000),
    ("UTCCP.T.S.2CTA tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0033d80008200000),
    ("UTCCP.T.S.2CTA.128dp128bit tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80008380000),
    ("UTCCP.T.S.2CTA.4dp256bit tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80008300000),
    ("UTCCP.T.S.2CTA.2x64dp128bit_lw01_lw23 tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80009280000),
    ("UTCCP.T.S.2CTA.2x64dp128bit_lw02_lw13 tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80009200000),
    ("UTCCP.T.S.2CTA.4x32dp128bit tmem[URZ], gdesc[UR4]", 0x00000004ff0079e7, 0x0011d80009300000),
];

#[test]
fn t190_1_decode_witness_12_both_tables() {
    for t in [t103(), t100()] {
        let idx = DecodeIndex::build(&t);
        for (text, lo, hi) in WITNESS {
            let got = dec(&t, &idx, w(*lo, *hi));
            assert_eq!(got, *text, "decode miss for {text}");
        }
    }
}

#[test]
fn t190_2_encode_payload_exact() {
    for t in [t103(), t100()] {
        for (text, lo, hi) in WITNESS {
            assert_eq!(enc(&t, text), w(*lo, *hi) & !SCHED, "encode drift for {text}");
        }
    }
}

#[test]
fn t190_3_window_variants_decode() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    // b24 = 0x06 -> tmem[UR6] (real UR, UR64-class legal)
    assert_eq!(dec(&t, &idx, w(0x00000004060079e7, 0x0011d80008180000)),
               "UTCCP.T.S.128dp128bit tmem[UR6], gdesc[UR4]");
    // b32 = 0x08 -> gdesc[UR8]; b32 = 0xff -> gdesc[URZ]
    assert_eq!(dec(&t, &idx, w(0x00000008ff0079e7, 0x0011d80008180000)),
               "UTCCP.T.S.128dp128bit tmem[URZ], gdesc[UR8]");
    assert_eq!(dec(&t, &idx, w(0x000000ffff0079e7, 0x0011d80008180000)),
               "UTCCP.T.S.128dp128bit tmem[URZ], gdesc[URZ]");
    // off with real base -> tmem[UR6+0x20]; off with URZ -> tmem[0x800] absolute
    let mut w_ur_off = 0x00000004ff0079e7u64;
    w_ur_off = (w_ur_off & !(0xffffu64 << 40)) | (0x20u64 << 40);
    w_ur_off = (w_ur_off & !(0xffu64 << 24)) | (6u64 << 24);
    assert_eq!(dec(&t, &idx, w(w_ur_off, 0x0011d80008180000)),
               "UTCCP.T.S.128dp128bit tmem[UR6+0x20], gdesc[UR4]");
    let w_abs = 0x00000004ff0079e7u64 | (0x800u64 << 40);
    assert_eq!(dec(&t, &idx, w(w_abs, 0x0011d80008180000)),
               "UTCCP.T.S.128dp128bit tmem[0x800], gdesc[UR4]");
    // 16-bit offset high nibble live (mk306 rows were off12 before BUG-190)
    let w_hi = 0x00000004ff0079e7u64 | (0x8000u64 << 40);
    assert_eq!(dec(&t, &idx, w(w_hi, 0x0011d80008380000)),
               "UTCCP.T.S.2CTA.128dp128bit tmem[0x8000], gdesc[UR4]");
    // guard UP0 / @!UPT
    let g0 = 0x00000004ff0079e7u64 & !(0xfu128 << 12) as u64;
    assert_eq!(dec(&t, &idx, w(g0, 0x0011d80008180000)),
               "@UP0 UTCCP.T.S.128dp128bit tmem[URZ], gdesc[UR4]");
    let gf = (0x00000004ff0079e7u64 & !(0xfu128 << 12) as u64) | (0xfu64 << 12);
    assert_eq!(dec(&t, &idx, w(gf, 0x0011d80008180000)),
               "@!UPT UTCCP.T.S.128dp128bit tmem[URZ], gdesc[UR4]");
}

#[test]
fn t190_4_encode_absolute_tmem_form() {
    let t = t103();
    // absolute glyph parses to URZ base + off; payload must equal the
    // byte-for-byte word the vendor emitted for the o50-class variant.
    let got = enc(&t, "UTCCP.T.S.128dp128bit tmem[0x800], gdesc[UR4]");
    assert_eq!(got, w(0x00000004ff0079e7u64 | (0x800u64 << 40), 0x0011d80008180000) & !SCHED);
    // canonical URZ form stays stable (off 0 = no offset bits anywhere)
    assert_eq!(enc(&t, "UTCCP.T.S.2CTA tmem[URZ], gdesc[URZ]"),
               w(0x000000ffff0079e7, 0x0033d80008200000) & !SCHED);
}

#[test]
fn t190_5_encode_no_clobber_tmem_gdesc() {
    let t = t103();
    // pre-fix clobber: tok2 wrote @(24,8). Post-fix the two windows are
    // disjoint and both values land in the word.
    let got = enc(&t, "UTCCP.T.S.128dp128bit tmem[UR6+0x20], gdesc[UR8]");
    assert_eq!(got & 0xffffffffff000000u128,
               w(0x0000200806000000u64, 0)); // b24=06, off=0x20, b32=08
    let got2 = enc(&t, "UTCCP.T.S.2CTA tmem[UR1], gdesc[UR9]");
    assert_eq!(got2 & 0xffffffffff000000u128, w(0x0000000901000000u64, 0));
}

#[test]
fn t190_6_fail_closed() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    // unknown shape discriminant (bit 86 set on the g1 '' witness) must not
    // silently decode as a UTCCP shape.
    let bad = w(0x00000004ff0079e7, 0x0033d80008000000 | (1u64 << (86 - 64)));
    let none = idx.decode(bad, 0, &t).map(|d| cubit::printer::to_sass(&d));
    assert!(!matches!(&none, Ok(s) if s.starts_with("UTCCP")),
            "invalid shape still decoded as UTCCP: {none:?}");
    // encode: missing operand must refuse, not guess.
    let insn = parse_sass("UTCCP.T.S tmem[URZ]", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err(), "1-operand UTCCP encoded");
}

#[test]
fn t190_7_roundtrip_fixed_point_all_shapes() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (_, lo, hi) in WITNESS {
        let orig = w(*lo, *hi);
        let text = dec(&t, &idx, orig);
        assert_eq!(enc(&t, &text), orig & !SCHED, "roundtrip drift on {text}");
    }
}
