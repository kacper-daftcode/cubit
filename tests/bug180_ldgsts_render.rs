//! BUG-180 (iter84, loop5/blind front MAIN; queue = fleet note 179 sec.8(b)
//! "180-kand LDGSTS render troj-pakiet"): LDGSTS/STAS decode-render repair.
//!
//! Census-first (hexdb 32.2M, work/i84/ldgsts_all.tsv, 40,394 rows): pre-fix
//! 28,706 IDENT / 11,688 divergent from vendor text. Classes:
//!   (1) mod-order: mg strings are alpha ("128,BYPASS,E,.."), vendor prints
//!       E < BYPASS < LTC128B < size (LDGSTS.E.BYPASS.LTC128B.128) — 9,331 rows;
//!   (2) desc-offset sign: dARI tok2 window over-wide (14..21 bits claimed),
//!       vendor law = s12 @[32:44) sign-glyph `+-0x` (arb180 s1: 0xff8 ->
//!       `+-0x8`, sign bit 43) — the `+0xff8` class;
//!   (3) tok2 geometry: plain 64-bit src [Rn.64(+URm)(+s12off)] decoded by
//!       junk ARURI rows (narrow 5/6-bit base, shr5 junk imm, bogus desc
//!       form) — values destroyed on the '64,E,LTC128B'-family anchors;
//!   (4) tok1 shared dst = [Rn+URm(+off)] (sts_lds form; negative offset
//!       glyph `+-0x`, x32 residuum) — pre-fix printed fabricated desc[];
//!   (5) STAS/ARI-returns: unconditional `.64` glyph on the base register
//!       (arb180 s3: odd bases legal, [R3.64]).
//! UR law both slots: u8 @[64:72), 0xFF = sink elided, UR63 prints
//! literally (arb180c t1: bits 72/73/74 = LTC mod flags, NOT UR bits).
//!
//! Fix = printer (format_opcode LDGSTS mod arm; format_ldgsts_shdst/
//! format_ldgsts_src/format_addr_wide64 slot arms) + data (patch180.py:
//! tok2 canonical (24,8,sub_r0)+(32,12,sub_imm1)(+64,8,sub_ur0) on the
//! ARI/ARURI keys, sub_imm2 -> 12 on dARI keys, sub_ur1 9->8 on ARURI_ARI
//! tok1; and_base/vm UNCHANGED — decode match envelopes invariant).
//! Encoders untouched; battery covers encode acceptance.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn dec(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    let s = s.split("/* @sched").next().unwrap();
    s.split(" !rsd[").next().unwrap().trim().to_string()
}
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap();
    encode_instruction(&insn, t).unwrap()
}

/// t180_1: mod-order vendor law (E < BYPASS < LTC128B < width) — decode
/// exact on the '128,BYPASS,E,LTC128B' alpha-mg rows, both arch tables.
#[test]
fn t180_1_mod_order() {
    for tab in [t103(), t120()] {
        assert_eq!(
            dec(&tab, w("0007e20009181a1000000000205e7fae")),
            "LDGSTS.E.BYPASS.LTC128B.128 [R94], desc[UR16][R32.64], P2");
        assert_eq!(
            dec(&tab, w("0003e20008180aff000000001c8c7fae")),
            "LDGSTS.E.BYPASS.LTC128B.128 [R140], [R28.64], P0");
        assert_eq!(
            dec(&tab, w("0007f2000b9a0a0600880000e2dc2fae")),
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6]");
        assert_eq!(
            dec(&tab, w("0003e2000b9a0220041c0000e4e03fae")),
            "@P3 LDGSTS.E.LTC128B [R224+0x41c0], [R228.64+UR32]");
    }
}

/// t180_2: desc offset = s12 @[32:44), sign glyph `+-0x` (0xff8 -> -8 at
/// the boundary: table claimed 15+ bits and printed +0xff8).
#[test]
fn t180_2_desc_s12_sign() {
    for tab in [t103(), t120()] {
        assert_eq!(
            dec(&tab, w("0007e8000b9a141200000ff8722b7fae")),
            "LDGSTS.E.64 [R43], desc[UR18][R114.64+-0x8]");
        assert_eq!(
            dec(&tab, w("0003e2000b9a141200000ff8722b4fae")),
            "@P4 LDGSTS.E.64 [R43], desc[UR18][R114.64+-0x8]");
        assert_eq!(
            dec(&tab, w("0003e2000b98180800000800382f7fae")),
            "LDGSTS.E.BYPASS.128 [R47], desc[UR8][R56.64+-0x800]");
    }
}

/// t180_3: tok2 = plain 64-bit global src — UR 0xFF sink elided
/// (never "desc[UR255]"), real UR printed, s12 window sign.
#[test]
fn t180_3_src_plain64_ur_sink() {
    for tab in [t103(), t120()] {
        // 0xff desc-sink -> no UR, no desc[] (was: fabricated desc[UR255][..])
        assert_eq!(
            dec(&tab, w("0009ec000b980aff02a00000d4cd3fae")),
            "@P3 LDGSTS.E.BYPASS.LTC128B.128 [R205+0x2a00], [R212.64]");
        // junk-narrow row class (values were destroyed pre-fix)
        assert_eq!(
            dec(&tab, w("0003e200099a06ff0018018024737fae")),
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+0x180], P3");
        // real UR on tok2
        assert_eq!(
            dec(&tab, w("0007f2000b9a0a0600880000e2dc2fae")),
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6]");
        // s12 sign on the plain-src window (was -0x80 via shr5 junk)
        assert_eq!(
            dec(&tab, w("000fe40008980a1c0608008010847dae")),
            "LDGSTS.E.BYPASS.LTC128B.128 [R132+UR28+0x6080], [R16.64+0x80], P1");
    }
}

/// t180_4: tok1 = shared dst [Rn+URm(+off)], negative offset glyph `+-0x`;
/// UR63 literal (arb180c t1_urf).
#[test]
fn t180_4_sh_dst_ur_form() {
    for tab in [t103(), t120()] {
        assert_eq!(
            dec(&tab, w("0007e2000b980a2000000000ce8c0dae")),
            "@P0 LDGSTS.E.BYPASS.LTC128B.128 [R140+UR32], [R206.64]");
        assert_eq!(
            dec(&tab, w("000fe2000b9a021afc000020e0bb0dae")),
            "@P0 LDGSTS.E.LTC128B [R187+UR26+-0x4000], [R224.64+0x20]");
    }
    // UR63 on tok1 (arb180c probe word: window 0x3f)
    let t = t103();
    assert_eq!(
        dec(&t, w("0007e2000b980a3f00000000ce8c0dae")),
        "@P0 LDGSTS.E.BYPASS.LTC128B.128 [R140+UR63], [R206.64]");
}

/// t180_5: STAS unconditional `.64` on the shared addr (odd base legal).
#[test]
fn t180_5_stas_dot64() {
    // STAS rows exist only on sm103a (+ vendored sm100a, R1: not edited);
    // sm120 carries no STAS keys (zero corpus anchors).
    let tab = t103();
    assert_eq!(dec(&tab, w("0003e8000c0008ff0000000e02007dbd")),
               "STAS [R2.64], R14");
    // arb180 s3 probe: odd base prints [R3.64]
    let t = t103();
    assert_eq!(dec(&t, w("0003e8000c0008ff0000000e03007dbd")),
               "STAS [R3.64], R14");
}

/// t180_6: encode acceptance — every vendor-true form above encodes, and
/// the anchor words roundtrip byte-exact (incl. the pre-fix-hard-fail
/// `[R16.64+0x80]` scaled-window row).
#[test]
fn t180_6_encode_roundtrip() {
    let t = t103();
    let cases: &[(u128, &str)] = &[
        (w("0007e20009181a1000000000205e7fae"),
         "LDGSTS.E.BYPASS.LTC128B.128 [R94], desc[UR16][R32.64], P2 ;"),
        (w("0007e8000b9a141200000ff8722b7fae"),
         "LDGSTS.E.64 [R43], desc[UR18][R114.64+-0x8] ;"),
        (w("000fe200081a06ff0000000024737fae"),
         "LDGSTS.E.LTC128B.64 [R115], [R36.64], P0 ;"),
        (w("0003e200099a06ff0018018024737fae"),
         "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+0x180], P3 ;"),
        (w("0007f2000b9a0a0600880000e2dc2fae"),
         "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6] ;"),
        (w("0003e2000b9a0220041c0000e4e03fae"),
         "@P3 LDGSTS.E.LTC128B [R224+0x41c0], [R228.64+UR32] ;"),
        (w("0007e2000b980a2000000000ce8c0dae"),
         "@P0 LDGSTS.E.BYPASS.LTC128B.128 [R140+UR32], [R206.64] ;"),
        (w("000fe40008980a1c0608008010847dae"),
         "LDGSTS.E.BYPASS.LTC128B.128 [R132+UR28+0x6080], [R16.64+0x80], P1 ;"),
        (w("0003e8000c0008ff0000000e02007dbd"), "STAS [R2.64], R14 ;"),
    ];
    for (word, text) in cases {
        let got = enc(&t, text) & !(((1u128 << 32) - 1) << 96); // ctrl-free compare
        let want = word & !(((1u128 << 32) - 1) << 96);
        assert_eq!(got, want, "encode byte-parity failed for {text}");
        assert_eq!(dec(&t, got), text.trim_end_matches(" ;"), "decode-stable");
    }
}

/// t180_7 (neg-ctl): unrelated-family gold decodes unchanged (LDG dARI
/// desc world of BUG-038, LDC cAI, IMAD, LDS plain) — the LDGSTS/STAS
/// slot arms did not leak.
#[test]
fn t180_7_negctl_untouched_families() {
    for tab in [t103(), t120()] {
        assert_eq!(dec(&tab, w("000364000c1e1b0000000008044c7981")),
                   "LDG.E.64 R76, desc[UR8][R4.64]");
        assert_eq!(dec(&tab, w("000f220000000a0000019200ff027b82")),
                   "LDC.64 R2, c[0x0][0x648]");
        assert_eq!(dec(&tab, w("001fc400078e0002000000ffff037224")),
                   "IMAD.MOV.U32 R3, RZ, RZ, R2");
    }
    let t = t103();
    assert_eq!(dec(&t, w("000fe80000000400000000001e1d7984")),
               "LDS.U16 R29, [R30]");
}

/// t180_8: pre-fix LDGSTS-with-pred trailing form keeps the pred operand
/// (guard@P vs trailing `, Pn` both present on _P rows — no arity drift).
#[test]
fn t180_8_trailing_pred_and_arity() {
    let t = t103();
    let s = dec(&t, w("000be20008981a1000000000265d7fae"));
    assert_eq!(s, "LDGSTS.E.BYPASS.LTC128B.128 [R93], desc[UR16][R38.64], P1");
    assert!(s.matches(',').count() == 2);
}
