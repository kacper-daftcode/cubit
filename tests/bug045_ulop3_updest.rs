//! BUG-045 (F2 canonical, a BUG-030 residual): the ULOP3 UP-dest form with tok4=UR
//! plus UPT-dest canonicalization.
//!
//! ULOP3.LUT decode map (i93 corpus, 14777 words, census of the internal fix archive
//!   bit11=1 -> tok4 imm32:  ULOP3_UR_UR_II_UR_II_UP (no UP dest)
//!                           ULOP3_UP_UR_UR_II_UR_II_UP (UP dest)
//!   bit11=0 -> tok4 UR:     ULOP3_UR_UR_UR_UR_II_UP  (no UP dest)
//!                           ULOP3_UP_UR_UR_UR_UR_II_UP (UP dest) <- THIS FIX
//!
//! (A) HOLE (46 records / 24 unique words from cublasLt/cudnn sm_120):
//!     `ULOP3.LUT UPd, URZ, URa, URb, URZ, 0xc0, !UPT` did not decode
//!     ("no instruction matches ... at opcode 0x292"). The table held a phantom
//!     row `ULOP3_UP_UR_UR_UR_UR_II_UP` (count=4, scrambled fields:
//!     imm 1b, no field extracted the dest UP). The row was replaced
//!     with a fit from 24 golden words: dest-UP 3b straight, tok2 [23:16]=ff
//!     (UR dest URZ — constant in the golden set, baked), tok3 ureg 6b (max UR38),
//!     tok4 ureg 5b (max UR27), tok5 [71:64]=ff (baked), tok6 lut 8b,
//!     tok7 !UPT ([90:87]=f), bit11=0 in and_base (discriminator vs the imm form).
//! (B) COSMETIC (7 records / 3 unique): UP dest == UPT encodes the form WITHOUT a
//!     dest — all dest-less golden words carry sel[83:81]=7 baked (histogram (7,*):
//!     6329+4238). nvdisasm drops the operand, cubit
//!     printed "UPT, " (bitwise-equivalent). Printer: drop the leading UPT for
//!     ULOP3 with a UP first operand; re-encode goes through the UR_* row (sel=7
//!     baked in and_base) -> identical bytes.
//! (C) ENCODER GAP: the ULOP3_UR_UR_II_UR_II_UP row had no tok4 field
//!     ([71:64]=ff baked) -> text with URc!=URZ was rejected ("operand 4 (UR7)
//!     has no field able to encode it") despite 7 golden words in the corpus.
//!     tok4 ureg_ff 8b field added, vm widened, and_base[71:64] = 0,
//!     count 35 -> 42.

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

/// 24+3 zlote slowa z i93 harvest (nvdisasm -c, cublasLt/cudnn sm_120).
/// Dowody: the internal fix archive
const GOLD: &[(u128, &str)] = &[
    (0x000fe2000f80c0ff0000000410ff7292, "ULOP3.LUT UP0, URZ, UR16, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000412ff7292, "ULOP3.LUT UP0, URZ, UR18, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000414ff7292, "ULOP3.LUT UP0, URZ, UR20, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000416ff7292, "ULOP3.LUT UP0, URZ, UR22, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000418ff7292, "ULOP3.LUT UP0, URZ, UR24, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000041aff7292, "ULOP3.LUT UP0, URZ, UR26, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000041eff7292, "ULOP3.LUT UP0, URZ, UR30, UR4, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000051cff7292, "ULOP3.LUT UP0, URZ, UR28, UR5, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000000812ff7292, "ULOP3.LUT UP0, URZ, UR18, UR8, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001112ff7292, "ULOP3.LUT UP0, URZ, UR18, UR17, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001114ff7292, "ULOP3.LUT UP0, URZ, UR20, UR17, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000111cff7292, "ULOP3.LUT UP0, URZ, UR28, UR17, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff000000131cff7292, "ULOP3.LUT UP0, URZ, UR28, UR19, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001518ff7292, "ULOP3.LUT UP0, URZ, UR24, UR21, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001614ff7292, "ULOP3.LUT UP0, URZ, UR20, UR22, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001924ff7292, "ULOP3.LUT UP0, URZ, UR36, UR25, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001926ff7292, "ULOP3.LUT UP0, URZ, UR38, UR25, URZ, 0xc0, !UPT"),
    (0x000fe2000f80c0ff0000001b26ff7292, "ULOP3.LUT UP0, URZ, UR38, UR27, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000608ff7292, "ULOP3.LUT UP1, URZ, UR8, UR6, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000706ff7292, "ULOP3.LUT UP1, URZ, UR6, UR7, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000804ff7292, "ULOP3.LUT UP1, URZ, UR4, UR8, URZ, 0xc0, !UPT"),
    (0x002fe2000f82c0ff0000000906ff7292, "ULOP3.LUT UP1, URZ, UR6, UR9, URZ, 0xc0, !UPT"),
    (0x004fe2000f82c0ff0000000608ff7292, "ULOP3.LUT UP1, URZ, UR8, UR6, URZ, 0xc0, !UPT"),
    (0x008fe4000f82c0ff0000000504ff7292, "ULOP3.LUT UP1, URZ, UR4, UR5, URZ, 0xc0, !UPT"),
    // (B)+(C): UPT dest -> the dest-less form; URc != URZ is encodable
    (0x000fc8000f8ef8070000000704047892, "ULOP3.LUT UR4, UR4, 0x7, UR7, 0xf8, !UPT"),
    (0x000fe2000f8ef8170000000707077892, "ULOP3.LUT UR7, UR7, 0x7, UR23, 0xf8, !UPT"),
    (0x000fe2000f8ef8180000000707077892, "ULOP3.LUT UR7, UR7, 0x7, UR24, 0xf8, !UPT"),
];

/// Regression of the neighboring forms (6322/451 classes from the census — render unchanged).
const NEIGHBORS: &[(u128, &str)] = &[
    (0x000fe2000f8ec0fffffffff00b0b7892, "ULOP3.LUT UR11, UR11, 0xfffffff0, URZ, 0xc0, !UPT"),
    (0x000fe2000f8eb807000000060a067292, "ULOP3.LUT UR6, UR10, UR6, UR7, 0xb8, !UPT"),
    // imm-forma UP-dest (wiersz z BUG-012; rowniez 2 linie w rt98_pub)
    (0x000fe2000f82c03f00000001133f7892, "ULOP3.LUT UP1, UR63, UR19, 0x1, UR63, 0xc0, !UPT"),
];

#[test]
fn bug045_gold_decode_and_reencode_byte_exact() {
    for (word, text) in GOLD.iter().chain(NEIGHBORS) {
        let got = dec(*word);
        assert_eq!(&got, text, "render differs for {word:#034x}");
        let code = enc(text).unwrap();
        assert_eq!(code & !SCHED, word & !SCHED, "re-encode differs for {text:?}");
    }
}

#[test]
fn bug045_upt_explicit_dest_encodes_same_as_canonical() {
    // Text with an explicit UPT dest (imm form) and the dest-less form give the same word.
    let explicit = enc("ULOP3.LUT UPT, UR4, UR4, 0x7, UR7, 0xf8, !UPT").unwrap();
    let canonical = enc("ULOP3.LUT UR4, UR4, 0x7, UR7, 0xf8, !UPT").unwrap();
    assert_eq!(explicit & !SCHED, canonical & !SCHED);
    // and decodes to the canonical form (after the print round-trip the same word)
    let text = dec(explicit);
    assert_eq!(text, "ULOP3.LUT UR4, UR4, 0x7, UR7, 0xf8, !UPT");
}

#[test]
fn bug045_hole_fail_closed_outside_gold() {
    // tok2 (UR dest) baked URZ in the goldens — a different UR = a loud error, not a silent drop
    enc("ULOP3.LUT UP0, UR5, UR16, UR4, URZ, 0xc0, !UPT")
        .expect_err("UR dest other than URZ is outside fitted gold evidence");
    // tok5 zaszyty URZ analogicznie
    enc("ULOP3.LUT UP0, URZ, UR16, UR4, UR5, 0xc0, !UPT")
        .expect_err("src URc other than URZ is outside fitted gold evidence");
}
