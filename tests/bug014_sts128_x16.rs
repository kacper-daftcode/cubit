//! BUG-014/017 (sm120 registry: files 014/017, iter79/81): `STS.128 [Rn.X16], Rm`
//! — the renderer dropped operands (printing `STS.128_AR.X16 0x0`), and the parser/route
//! of the encoder dropped the X16 discriminator (bits 78/79): `[R5.X16]` and `[R5]` gave
//! IDENTICAL words. The 4 words in the RC kernel kept coming out __raw__.
//!
//! Fix: the `STS_ARI_R` row, mg "128", gained the `addr_scale` 2b@[79:78] field
//! (BUG-038 semantics: 0 none, 1=X4, 2=X8, 3=X16); the printer scaled-addr
//! path from 038 extended LDS -> STS. Window geometry verified with nvdisasm
//! probe bits (probe cubins): addr Rn @[31:24], val Rm @[39:32],
//! imm 24b @[63:40] SIGNED 1:1, guard @[15:12]. Via generic completeness
//! in the encoder, the address suffix .X4/.X8/.X16 is now fail-closed when the row
//! has no addr_scale field (previously: silently dropped).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(text: &str) -> Result<u128, String> {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).map_err(|e| format!("{e}"))
}

fn dec(word: u128) -> String {
    let idx = DecodeIndex::build(&t120());
    let d = idx.decode(word, 0, &t120()).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}

/// 4 golden words from the RC kernel (registry 014; nvdisasm = oracle) + the plain form
/// (bits 78/79 = 0; word verified with an nvdisasm probe on the rt98_pub.cubin clone).
const GOLD: &[(u128, &str)] = &[
    (0x001be4000000cc00000000c805007388, "STS.128 [R5.X16], R200"),
    (0x000be4000000cc00000010cc05007388, "STS.128 [R5.X16+0x10], R204"),
    (0x001be4000000cc000000001c1b007388, "STS.128 [R27.X16], R28"),
    (0x000be4000000cc00000010201b007388, "STS.128 [R27.X16+0x10], R32"),
    (0x001be40000000c00000000c805007388, "STS.128 [R5], R200"),
];

#[test]
fn bug014_gold_decode_and_reencode_byte_exact() {
    for (word, text) in GOLD {
        assert_eq!(&dec(*word), text, "render differs for {word:#034x}");
        let insn = parse_sass(text, 0).unwrap();
        let code = encode_instruction(&insn, &t120()).unwrap();
        assert_eq!(code & !SCHED, word & !SCHED, "re-encode differs for {text:?}");
    }
}

#[test]
fn bug014_x16_suffix_no_longer_dropped() {
    let plain = enc("STS.128 [R5], R200").unwrap();
    let x16 = enc("STS.128 [R5.X16], R200").unwrap();
    assert_ne!(plain & !SCHED, x16 & !SCHED, "X16 suffix must change the word");
    assert_eq!((x16 >> 78) & 3, 3, "X16 = addr_scale 3");
    assert_eq!((plain >> 78) & 3, 0);
    let x4 = enc("STS.128 [R5.X4], R200").unwrap();
    let x8 = enc("STS.128 [R5.X8], R200").unwrap();
    assert_eq!((x4 >> 78) & 3, 1);
    assert_eq!((x8 >> 78) & 3, 2);
    assert_eq!(dec(x4), "STS.128 [R5.X4], R200");
}

#[test]
fn bug014_suffix_on_row_without_field_fails_closed() {
    // STS.64 has no addr_scale field in the table (no golden coverage): the suffix
    // must fail LOUDLY, not silently end up as a scale=0 word.
    let e = enc("STS.64 [R4.X8], R8").expect_err("unsupported suffix must refuse");
    assert!(e.contains("addr scale suffix"), "completeness must name it: {e}");
}

#[test]
fn bug014_sondom_windows() {
    // windows from the nvdisasm probes: addr @[31:24], val @[39:32], imm @[63:40] 1:1
    let w = enc("STS.128 [R7.X16+0x100], R32").unwrap();
    assert_eq!(((w >> 24) & 0xff) as u64, 7);
    assert_eq!(((w >> 32) & 0xff) as u64, 32);
    assert_eq!(((w >> 40) & 0xff_ffff) as u64, 0x100);
    // imm sign: bit63 = -0x800000 (24b signed)
    let neg = enc("STS.128 [R5.X16+-0x1], R200").unwrap();
    assert_eq!(((neg >> 40) & 0xff_ffff) as u64, 0xff_ffff);
}
