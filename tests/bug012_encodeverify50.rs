//! BUG-012 census gate (F2 iter4): the "encode-verify 50" set from
//! s6t_iter77/warn.log — words the decoder DID decode but whose text could not
//! be re-encoded (frozen path fell back to `__raw__`, so bytes were preserved
//! but the instruction was opaque). Root causes fixed at the source:
//!   * UIADD3 (uniform add, 6-token nv form): mg "" of UIADD3_UR_UP_UP_UR_II_UR
//!     lacked the tok6 URc field ([71:64]+neg@75); five auto-harvested junk
//!     rows (mg X / _P / _UP_UP clones sharing one and_base) shadowed it with
//!     a 7-token `.X .. !PT` render that dropped tok4/tok6 register values.
//!   * ULOP3.LUT_UP_UR_UR_II_UR_II_UP: no row at all (mis-decoded as UIADD3.X).
//!   * ISETP.{NE,LE,LT}.AND_P_P_R_UR_P: harvested rows printed the R source as
//!     `0xff` (imm-typed field on an R slot) and dropped the trailing predicate.
//!   * UISETP.EQ.AND_UP_UP_UR_II_UP: opaque-mod clones won over a proper row.
//!   * BAR.SYNC.DEFER_BLOCKING: a cross-modgroup divert in select_best_candidate
//!     swapped the strict-winning SYNC entry for RED.OR (bits [90:87] are an op
//!     discriminator there, not a predicate); generic BAR_II rows claimed the
//!     discriminator bits [11]/[9] as operand fields and got tightened.
//!   * SHFL.BFLY: output-pred-PT divert preferred an underdiscovered `_?` key
//!     (halved dst field, phantom 6th operand) over the complete entry.
//!   * IMAD_R_R_R_II mg "": junk `pred@[83:81]` field mis-keyed to tok2 made the
//!     (rendered-fine) text un-encodable; field dropped.
//!   * IMAD.MOV: printer/encoder alias for IMAD with both multiplier operands
//!     RZ (nvdisasm idiom; 149 renders in the R0 kernel aliased).
//! Pinned per word: decode == golden nvdisasm text, re-encode == word (mod
//! scheduling bits [127:96]).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

static WORDS: &[(u32, u128, &str)] = &[
    (0x00200, 0x000fcc00000100000000000000007b1d, "BAR.SYNC.DEFER_BLOCKING 0x0"),
    (0x00210, 0x000fec000fffe03f0000000a02357890, "UIADD3 UR53, UPT, UPT, UR2, 0xa, UR63"),
    (0x00240, 0x000ff2000fffe03fffffffff02237890, "UIADD3 UR35, UPT, UPT, UR2, -0x1, UR63"),
    (0x02880, 0x000ff2000fffe03f0000000a1d1d7890, "UIADD3 UR29, UPT, UPT, UR29, 0xa, UR63"),
    (0x03290, 0x000fe2000fffe03f0000000113137890, "UIADD3 UR19, UPT, UPT, UR19, 0x1, UR63"),
    (0x001c0, 0x000fec000fffe03f0000000a02397890, "UIADD3 UR57, UPT, UPT, UR2, 0xa, UR63"),
    (0x002f0, 0x000fcc00000100000000000000007b1d, "BAR.SYNC.DEFER_BLOCKING 0x0"),
    (0x00570, 0x000fe2000fffe13f0000000a02377890, "UIADD3 UR55, UPT, UPT, -UR2, 0xa, UR63"),
    (0x005a0, 0x000fe2000fffe03fffffffff02027890, "UIADD3 UR2, UPT, UPT, UR2, -0x1, UR63"),
    (0x00790, 0x000fe2000f82c03f00000001133f7892, "ULOP3.LUT UP1, UR63, UR19, 0x1, UR63, 0xc0, !UPT"),
    (0x00820, 0x000fe2000fffe03f0000000137371890, "@UP1 UIADD3 UR55, UPT, UPT, UR55, 0x1, UR63"),
    (0x00830, 0x000fe2000fffe03f0000000113137890, "UIADD3 UR19, UPT, UPT, UR19, 0x1, UR63"),
    (0x00d70, 0x000fe2000bf022700000000c0f00788c, "UISETP.EQ.AND UP0, UPT, UR15, 0xc, UPT"),
    (0x00db0, 0x000fe2000b7652700000000f17007c0c, "ISETP.NE.AND P3, PT, R23, UR15, P6"),
    (0x00ec0, 0x000fe2000fffe13fffff96101c1a7890, "UIADD3 UR26, UPT, UPT, -UR28, -0x69f0, UR63"),
    (0x01790, 0x000fe2000fffe03f000000010f0f7890, "UIADD3 UR15, UPT, UPT, UR15, 0x1, UR63"),
    (0x017c0, 0x000fe6000f82c03f00000001133f7892, "ULOP3.LUT UP1, UR63, UR19, 0x1, UR63, 0xc0, !UPT"),
    (0x017f0, 0x000fe2000fffe13fffff9f401c1a7890, "UIADD3 UR26, UPT, UPT, -UR28, -0x60c0, UR63"),
    (0x01900, 0x000fe2000bfa32700000000fff007c0c, "ISETP.LE.AND P5, PT, RZ, UR15, PT"),
    (0x01910, 0x000fe2000f7832700000000fff007c0c, "ISETP.LE.AND P4, PT, RZ, UR15, !P6"),
    (0x01920, 0x000fe2000b7632700000000fff007c0c, "ISETP.LE.AND P3, PT, RZ, UR15, P6"),
    (0x01930, 0x000fe2000bf412700000000fff007c0c, "ISETP.LT.AND P2, PT, RZ, UR15, PT"),
    (0x01a50, 0x000fe2000fffe13fffffa1a01c1a7890, "UIADD3 UR26, UPT, UPT, -UR28, -0x5e60, UR63"),
    (0x04580, 0x000fe2000fffe13fffffc6101c1a7890, "UIADD3 UR26, UPT, UPT, -UR28, -0x39f0, UR63"),
    (0x04710, 0x000fe2000fffe03fffffffff0f0f7890, "UIADD3 UR15, UPT, UPT, UR15, -0x1, UR63"),
    (0x04720, 0x000fe2000fffe03ffffffe0033337890, "UIADD3 UR51, UPT, UPT, UR51, -0x200, UR63"),
    (0x04760, 0x000e2200000e00000c201f00748c7f89, "SHFL.BFLY PT, R140, R116, 0x1, 0x1f"),
    (0x04780, 0x000e2200000e00000c201f00768e7f89, "SHFL.BFLY PT, R142, R118, 0x1, 0x1f"),
    (0x047a0, 0x000e2200000e00000c201f0078907f89, "SHFL.BFLY PT, R144, R120, 0x1, 0x1f"),
    (0x047c0, 0x000e2200000e00000c201f007a927f89, "SHFL.BFLY PT, R146, R122, 0x1, 0x1f"),
    (0x04ef0, 0x000e2200000e00000c401f0024847f89, "SHFL.BFLY PT, R132, R36, 0x2, 0x1f"),
    (0x04f10, 0x000e2200000e00000c401f0026867f89, "SHFL.BFLY PT, R134, R38, 0x2, 0x1f"),
    (0x04f30, 0x000e2200000e00000c401f0028887f89, "SHFL.BFLY PT, R136, R40, 0x2, 0x1f"),
    (0x04f50, 0x000e2200000e00000c401f002a8a7f89, "SHFL.BFLY PT, R138, R42, 0x2, 0x1f"),
    (0x056a0, 0x000e2200000e00000c801f00447c7f89, "SHFL.BFLY PT, R124, R68, 0x4, 0x1f"),
    (0x056c0, 0x000e2200000e00000c801f00467e7f89, "SHFL.BFLY PT, R126, R70, 0x4, 0x1f"),
    (0x056e0, 0x000e2200000e00000c801f0048807f89, "SHFL.BFLY PT, R128, R72, 0x4, 0x1f"),
    (0x05700, 0x000e2200000e00000c801f004a827f89, "SHFL.BFLY PT, R130, R74, 0x4, 0x1f"),
    (0x0c860, 0x000fe200078e02fffffffffeff1d7424, "IMAD.MOV R29, RZ, RZ, -0x2"),
    (0x0c880, 0x000fe200078e02ffffffffffff1f7424, "IMAD.MOV R31, RZ, RZ, -0x1"),
    (0x0c8a0, 0x000fe200078e02ffffffffffff217424, "IMAD.MOV R33, RZ, RZ, -0x1"),
    (0x0c8c0, 0x000fe200078e02ffffffffffff237424, "IMAD.MOV R35, RZ, RZ, -0x1"),
    (0x0c930, 0x000fe200078e02ff00000001ff2f7424, "IMAD.MOV R47, RZ, RZ, 0x1"),
    (0x0c950, 0x000fe200078e02ff00000000ff437424, "IMAD.MOV R67, RZ, RZ, 0x0"),
    (0x0ca50, 0x000fe400078e024fffffffff5c320424, "@P0 IMAD R50, R92, R79, -0x1"),
    (0x0d380, 0x000fe200078e02ff00000000ff547424, "IMAD.MOV R84, RZ, RZ, 0x0"),
    (0x0d3a0, 0x000fe200078e02ff00000000ff567424, "IMAD.MOV R86, RZ, RZ, 0x0"),
    (0x0d3c0, 0x000fe200078e02ff00000000ff587424, "IMAD.MOV R88, RZ, RZ, 0x0"),
    (0x0d6a0, 0x000fe200078e02ff0000001eff313424, "@P3 IMAD.MOV R49, RZ, RZ, 0x1e"),
    (0x0d7c0, 0x000fe400078e024fffffffff5c320424, "@P0 IMAD R50, R92, R79, -0x1"),
];

#[test]
fn bug012_decode_matches_nvdisasm() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (addr, word, want) in WORDS {
        let d = idx.decode(*word, *addr, &t)
            .unwrap_or_else(|e| panic!("0x{addr:05x}: decode failed: {e}"));
        let got = format!("{d}").trim_end_matches([' ', ';']).to_string();
        assert_eq!(&got, want, "0x{addr:05x}: render differs");
    }
}

#[test]
fn bug012_reencode_byte_exact() {
    let t = t120();
    for (addr, word, text) in WORDS {
        let insn = parse_sass(text, *addr)
            .unwrap_or_else(|e| panic!("0x{addr:05x}: parse failed for {text:?}: {e}"));
        let code = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("0x{addr:05x}: encode failed for {text:?}: {e}"));
        assert_eq!(code & !SCHED, word & !SCHED, "0x{addr:05x}: re-encode differs");
    }
}

/// The one remaining word of the original 51: `iadd3_x_imm__RIR_RIR` with
/// opex 0x51 — unknown even to nvdisasm 13.0 (undefined TABLES_opex_4 value).
/// It must stay verbatim-faithful: decode renders a text that encode-verify
/// REJECTS so the frozen path keeps the exact 128 bits via `__raw__`.
///
/// BUG-089 (2026-08-23): the rendered text shifted `0x1` -> `UR1.reuse` —
/// both forms are relaxed-match readings of a vendor-unknown opex word.
/// Pre-089 it was anchored in the harvest-junk key `IADD3_R_P_P_R_R_R` mg X
/// (deleted: sig tok5 'R' mapped onto the imm window); post-089 the relaxed
/// winner is `IADD3_R_P_P_R_UR_R` mg X (UR-domain read of the same window,
/// winning on the and_base tiebreak). The contract that actually matters is
/// unchanged and verified here: the rendered text must NOT re-encode to the
/// original word (today it fails encode outright), so `__raw__` keeps the
/// exact bits.
#[test]
fn bug012_unknown_opex51_stays_raw_faithful() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let word: u128 = 0x080fe200007e4dff00000001ff727810;
    let d = idx.decode(word, 0x34c0, &t).expect("decode must keep working");
    let text = format!("{d}").trim_end_matches([' ', ';']).to_string();
    assert_eq!(text, "IADD3.X R114, !PT, PT, RZ, UR1.reuse, ~RZ, P0, P2");
    let insn = parse_sass(&text, 0).unwrap();
    assert!(
        encode_instruction(&insn, &t)
            .map(|c| c & !SCHED == word & !SCHED)
            .unwrap_or(false)
            == false,
        "opex-0x51 word must NOT silently re-encode to itself"
    );
}

/// Guard against regression of the junk shapes this bug hid behind.
#[test]
fn bug012_junk_renders_gone() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    // SHFL.BFLY has exactly five operands (was: halved dst + phantom UR0).
    let d = idx.decode(0x000e2200000e00000c201f00748c7f89, 0, &t).unwrap();
    let s = format!("{d}");
    assert!(s.contains("SHFL.BFLY PT, R140, R116, 0x1, 0x1f"), "{s}");
    assert!(!s.contains("UR0"), "{s}");
    // BAR.SYNC.DEFER_BLOCKING renders the SYNC variant (was: RED.OR via divert).
    let d = idx.decode(0x000fcc00000100000000000000007b1d, 0, &t).unwrap();
    assert_eq!(format!("{d}").trim_end_matches([' ', ';']),
               "BAR.SYNC.DEFER_BLOCKING 0x0");
    // IMAD.MOV alias prints (and only for RZ,RZ multiplier slots).
    let d = idx.decode(0x000fe200078e02fffffffffeff1d7424, 0, &t).unwrap();
    assert_eq!(format!("{d}").trim_end_matches([' ', ';']),
               "IMAD.MOV R29, RZ, RZ, -0x2");
    // ... and the alias encodes back, while a non-RZ misuse fails closed.
    let insn = parse_sass("IMAD.MOV R29, RZ, RZ, -0x2", 0).unwrap();
    let code = encode_instruction(&insn, &t).unwrap();
    assert_eq!(code & !SCHED, 0x000fe200078e02fffffffffeff1d7424 & !SCHED);
    assert!(encode_instruction(&parse_sass("IMAD.MOV R29, RZ, R5, -0x2", 0).unwrap(), &t).is_err());
}
