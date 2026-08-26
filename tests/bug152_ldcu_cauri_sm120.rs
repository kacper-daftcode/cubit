//! BUG-152 (F2-iter73; zrodlo: nota 151 sec.5): tables/sm120.json carried a
//! separate signature LDCU_UR_cAURI (groups ""/U8/64/128) that no src path
//! supports: decode of UR-indexed words printed `?cAURI` (dowod:
//! work/i71/p120raw, probe word 0x...050577ac -> "LDCU UR5, ?cAURI"), and
//! encoding the text form `LDCU URn, c[0x0][URn+0xOFF]` failed closed
//! (parser key LDCU_UR_cAI vs UR-capable row only under cAURI).
//!
//! Census (work/bug152/census152.json; sm120 vendor corpus 392 cubins /
//! 292,616 uniq (file,word) anchors; hexdb 32.2M lines F2-iter67):
//!   (a) key cAURI is FULLY redundant vs cAI on the corpus: strict matchers
//!       of "" overlap on all 16,790 LDCU-class anchors (480 plain + 16,310
//!       .64) because match windows treat field windows as variable and
//!       every anchor's window[24:32) == 0xff (URZ sentinel);
//!   (b) ZERO UR-indexed LDCU witnesses on sm120, ZERO LDCU.U8 UR-indexed
//!       witnesses anywhere (4,966 U8 anchors all plain, window 0xff);
//!   (c) cAURI groups 64/128 are byte-identical duplicates of cAI's;
//!   (d) plain-anchor window[37:59) values 0x380..0x474 (no 0, none >
//!       0xffff) => cm17off print (offset=val&0x1ffff, bank=val>>17) ==
//!       sub_imm1 print for 100% of the corpus.
//!
//! Fix (data-only; F2 modeling decision = option A from note 151, unifying
//! sm120 to cAI with the BUG-151 geometry; branch bases on 0b133a9 because
//! the UR print path needs 151's format_const_addr SubUR support):
//!   1. LDCU_UR_cAI[""] adopts the donor geometry: fields ureg@16/8 +
//!      sub_ur1@24/8 + cm17_off@37/22 + reuse@122, and_base window ->
//!      0x00 (window is a field now = variable in match; encode bakes 0xff
//!      via the op_sub_ureg URZ default), vmask |= 0xff<<24. cm17_off
//!      replaces sub_imm1 because ConstMem with ur_reg=Some needs the
//!      offset as sub_imm2 -- Cm17Off is UR-presence independent.
//!   2. Key LDCU_UR_cAURI deleted ("" folded; 64/128 duplicates; U8-UR
//!      zero-witness: such words now fall to raw/fail-closed per doctrine
//!      instead of printing `?cAURI` junk).
//!
//! Neg-control on c9ef102 ctl: t152_1 / t152_2 / t152_5 FAIL (junk print /
//! encode rejected / key present), t152_3 / t152_4 PASS (invariance pins).

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

// Synthetic UR-indexed probe from note 151 (work/i71/p120raw; field-geometry
// of the vendor row, UR5 numerals in both windows).
const PROBE_UR: (u64, u32, &str) =
    (0x00004b00050577ac, 0x08000800, "LDCU UR5, c[0x0][UR5+0x258]");

// Live vendor anchors (sm120 corpus & hexdb; correct render on c9ef102).
const PLAIN_FIXEDPOINT: &[(u64, u32, &str)] = &[
    (0x0000ae00ff0477ac, 0x08000800, "LDCU UR4, c[0x0][0x570]"),
    (0x0000ae00ff0877ac, 0x08000800, "LDCU UR8, c[0x0][0x570]"),
    (0x0000bc80ff0477ac, 0x08000000, "LDCU.U8 UR4, c[0x0][0x5e4]"),
    (0x0000bd80ff0977ac, 0x08000000, "LDCU.U8 UR9, c[0x0][0x5ec]"),
];

// Width-mod anchors route through the untouched duplicate-free 64/128 groups.
const MOD_FIXEDPOINT: &[(u64, u32, &str)] = &[
    (0x00006b00ff0877ac, 0x08000a00, "LDCU.64 UR8, c[0x0][0x358]"),
    (0x00008400ff1477ac, 0x08000c00, "LDCU.128 UR20, c[0x0][0x420]"),
];

#[test]
fn t152_1_decode_ur_probe() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let sass = dec(&t, &idx, parts(PROBE_UR.0, PROBE_UR.1));
    assert_eq!(sass, PROBE_UR.2);
}

#[test]
fn t152_2_encode_ur_form_byte_exact() {
    let t = t120();
    let w = enc(&t, PROBE_UR.2);
    assert_eq!(w, parts(PROBE_UR.0, PROBE_UR.1), "encode UR form must reproduce the probe word (sched stripped)");
}

#[test]
fn t152_3_plain_decode_fixedpoint() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in PLAIN_FIXEDPOINT.iter().chain(MOD_FIXEDPOINT) {
        let sass = dec(&t, &idx, parts(*lo, *hi32));
        assert_eq!(&sass, want);
        // reverse pin: re-encode must give the vendor low96 back
        assert_eq!(enc(&t, want), parts(*lo, *hi32), "roundtrip byte-exact for {want}");
    }
}

#[test]
fn t152_4_encode_plain_bakes_urz_sentinel() {
    let t = t120();
    let w = enc(&t, "LDCU UR4, c[0x0][0x570]");
    assert_eq!((w >> 24) as u8 & 0xff, 0xff, "plain form must bake the URZ sentinel byte");
    assert_eq!(w, parts(PLAIN_FIXEDPOINT[0].0, PLAIN_FIXEDPOINT[0].1));
}

#[test]
fn t152_5_cauri_key_gone_and_u8_ur_fail_closed() {
    let t = t120();
    assert!(t.entries.get("LDCU_UR_cAURI").is_none(), "junk-signature key must be deleted");
    // U8+UR has zero vendor witnesses: the BUG-132 roundtrip guard must
    // refuse it instead of silently dropping the .U8 modifier.
    let insn = parse_sass("LDCU.U8 UR5, c[0x0][UR5+0x258]", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err(), "U8+UR form must fail closed");
}
