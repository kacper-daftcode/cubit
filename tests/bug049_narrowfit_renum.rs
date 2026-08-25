//! BUG-049 (from the M4.3b work): narrow-fit rows —
//! encode/decode asymmetry exposed by RA renumbering on the certified R0b.
//! Three classes on the legacy chain (tb_i82/p1) plus — for the UIMAD.WIDE
//! UR-dest variant — also in the repo `tables/sm120.json`. Bit pins: nvdisasm
//! 13.3 per-bit probes on the original rt98_pub words (KernelB:71, KernelA:1538,
//! 2158, 3188) + nvcc-12.8 gold capmerc (the 024d*32 record).
//!
//! Silicon truth (probes, not opinions):
//!  * UIMAD.WIDE.U32_UR_UR_II_UR: dest UR 8b, src1 UR 8b,
//!    imm s32 (bit63 = sign), src3 UR 8b — the era fit had 5b/5b/
//!    30b + operand bits baked into and_base; UR31 lost bits (silicon
//!    read different operands than the text).
//!  * REDG.E.AND/OR.EL.STRONG.GPU desc[URx]: the desc field = 8b = the
//!    physical register of the UR pair (nvdisasm prints it directly). The mercury record
//!    embeds the descriptor-table index = register/2 (nvcc: word has 20, record 10).
//!  * ISETP.GT.U32.AND P, PT, R, UR, PT: R 8b, UR 8b — the repo is already
//!    healthy; pins the renumbered round-trip (legacy pushed the word into EQ garbage).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}


fn dec120(word: u128) -> String {
    let idx = DecodeIndex::build(&t120());
    let d = idx.decode(word, 0, &t120()).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}

/// Region outside scheduling ([127:96] is lifted by the decoder on match).
const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// rt98_pub.cubin .text.KernelB ins71 — the original nvcc word.
const UIMAD_ORIG: u128 = 0x000fe2000f8e001000000400131a78a5;
/// rt98_pub.cubin .text.KernelA ins1538 (REDG.E.AND.EL.STRONG.GPU desc).
const REDG_AND_ORIG: u128 = 0x0009e4000aa0e1140a2400404200298e;
/// rt98_pub.cubin .text.KernelA ins3188 (REDG.E.OR.EL.STRONG.GPU desc).
const REDG_OR_ORIG: u128 = 0x0009e4000b20e1140a2400171900798e;
/// rt98_pub.cubin .text.KernelA ins2158 (ISETP.GT.U32 mixed form per era; nvdisasm 13.3: plain GT.AND).
const ISETP_ORIG: u128 = 0x001fda000bf24270000000161a007c0c;

#[test]
fn bug049_uimad_wide_origword_decodes_truth() {
    // nvdisasm 13.3 of this word: "UIMAD.WIDE.U32 UR26, UR19, 0x400, UR16".
    let got = dec120(UIMAD_ORIG);
    assert_eq!(got, "UIMAD.WIDE.U32 UR26, UR19, 0x400, UR16",
               "decoder narrow-fit wrocil? {got}");
}

#[test]
fn bug049_uimad_wide_renumbered_roundtrip_bit_exact() {
    let w = enc("UIMAD.WIDE.U32 UR31, UR19, 0x200, UR5");
    // Probe: dest 8b, src1 8b, imm s32, src3 8b.
    assert_eq!((w >> 16) & 0xff, 31, "dest UR31 musi przejsc w calosci");
    assert_eq!((w >> 24) & 0xff, 19);
    assert_eq!((w >> 32) & 0xffff_ffff, 0x200);
    assert_eq!((w >> 64) & 0xff, 5);
    let got = dec120(w);
    assert_eq!(got, "UIMAD.WIDE.U32 UR31, UR19, 0x200, UR5", "{got}");
}

#[test]
fn bug049_uimad_wide_reencode_origword_stable() {
    // Render truth -> encode: outside the sched region the original word is rebuilt.
    let w = enc("UIMAD.WIDE.U32 UR26, UR19, 0x400, UR16");
    assert_eq!(w & NOSCHED, UIMAD_ORIG & NOSCHED,
               "render+encode nie odtwarza nvcc-slowa: {w:#034x}");
}

#[test]
fn bug049_uimad_wide_phantom_rows_removed() {
    // Phantom narrow rows (1b/4b fields, baked dest bit) thrown out of the
    // repo table: they were quietly taking over the renumbered words (class 049).
    let raw = std::fs::read_to_string("tables/sm120.json").unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let ins = v["instructions"].as_object().unwrap();
    for k in ["UIMAD.WIDE_UR_UR_II_UR", "UIMAD.WIDE_UR_UR_UR_II",
              "UIMAD.WIDE.U32_UR_UR_UR_UR_UR", "UIMAD.WIDE.U32_UR_UP_UR_UR_UR"] {
        assert!(!ins.contains_key(k), "phantom row {k} back in table");
    }
}

#[test]
fn bug049_redg_desc_ur_is_register_field_8b_at_64() {
    let w = enc("@P2 REDG.E.AND.EL.STRONG.GPU [R66.U32+UR20+0xa2400], R64");
    assert_eq!((w >> 64) & 0xff, 20, "desc-UR nie laduje w polu @64");
    assert_eq!((w >> 24) & 0xff, 66, "addr R");
    assert_eq!((w >> 32) & 0xff, 64, "value R");
    assert_eq!((w >> 40) & 0xff_ffff, 0xa2400, "imm s24@40");
    // Parity with the nvcc rt98 word (outside sched/epoch):
    assert_eq!(w & NOSCHED, REDG_AND_ORIG & NOSCHED, "{w:#034x}");
    // Desc renumber: UR18 must not end up replaced by a baked 20.
    let w2 = enc("REDG.E.OR.EL.STRONG.GPU [R25.U32+UR18+0xa2400], R23");
    assert_eq!((w2 >> 64) & 0xff, 18, "desc-rename poRAZniony (bake)");
}

#[test]
fn bug049_redg_mercury_record_halves_register_to_table_index() {
    // nvcc gold from rt98_pub .nv.capmerc.text.KernelA: for the word with desc-field=20
    // the record holds b[17..19] = (10<<6)|2 = 0x0282 (table index = register/2).
    let r = cubit::mercury::merc_redg_record(
        "REDG.E.AND.EL.STRONG.GPU PT, desc[UR20][R66.64+0xa2400], R64 ;", 0x10)
        .expect("record expected for desc form");
    assert_eq!(r[0], 0x02);
    assert_eq!(r[1], 0x4d);
    assert_eq!(r[2], 0x24);
    assert_eq!(r[3], 0x32);
    assert_eq!(r[4], 0x10, "guard ladder");
    assert_eq!(r[6] & 0xf0, 0x50, "AND subclass");
    let desc_idx = ((u16::from_le_bytes([r[17], r[18]])) >> 6) & 0x3ff;
    assert_eq!(desc_idx, 10, "rekord = rejestr/2 (nvcc gold), nie rejestr");
    assert_eq!(&r[28..32], &0xa2400i32.to_le_bytes(), "imm LE w rekordzie");
}

#[test]
fn bug049_isetp_mixed_ur_renumbered_roundtrip() {
    // BUG-086 (2026-08-23): vendor semantics canonicalized per nvdisasm 13.3 +
    // 221k corpus anchors: bits[75:72]=cmp, bit73=1 signed (0 U32), bit74=bool.
    // ERA-glyph reading (U32 + |R26| abs for word with byte72=0x42) was a
    // pre-anchor RE-era mislabel: vendor probes render ISETP_ORIG as plain
    // signed GT.AND and the whole family has ZERO abs/neg-on-register anchors
    // in the corpus (abs is not a vendor-observed shape on ISETP sigs).
    // See the internal fix archive era-text flip decision stays with owner
    // (F2Q-058-kand; frozen publish path on tb_i82p2 is unaffected).
    let w = enc("ISETP.GT.U32.AND P1, PT, R6, UR15, PT");
    assert_eq!((w >> 24) & 0xff, 6, "R 8b@24");
    assert_eq!((w >> 32) & 0xff, 15, "UR 8b@32");
    assert_eq!((w >> 72) & 0xff, 0x40, "cmp/type byte: GT.U32.AND");
    let got = dec120(w);
    assert_eq!(got, "ISETP.GT.U32.AND P1, PT, R6, UR15, PT", "{got}");
    // The original nvcc word (era-text |R26|,UR22); nvdisasm 13.3 probe:
    // "ISETP.GT.AND P1, PT, R26, UR22, PT" (plain signed; re-encoded bit-exact).
    let got0 = dec120(ISETP_ORIG);
    assert_eq!(got0, "ISETP.GT.AND P1, PT, R26, UR22, PT", "{got0}");
    let w0 = enc(&got0);
    assert_eq!(w0 & NOSCHED, ISETP_ORIG & NOSCHED, "orig word re-encode");
}
