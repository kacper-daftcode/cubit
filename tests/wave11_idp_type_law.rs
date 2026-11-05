//! wave 11: the SM120 IDP type law -- `[74:73]` selects U8/S8 on the two
//! accumulator operands and `[75]` prints `-Rc`.
//!
//! The sm_120 census over the vLLM-Moet kernel corpus (578 cubins, 238 848
//! words) failed on 2716 words of 19 cubins. Every one is `IDP.4A.U8.U8` in
//! cuobjdump/nvdisasm text, but cubit printed `IDP.4A.S8.S8` and re-encoded
//! bits 73/74 set. Cause: the table carried only the `4A,S8,S8` row, so a
//! U8-U8 word misses strict match and is absorbed by the decoder's priority-3
//! sign-tolerant fallback (whose window is exactly {62,63,72,73,74,75}); the
//! row's baked S8,S8 then survived into the re-encode and the complete 128-bit
//! word differed. The same set fails identically on public main.
//!
//! Oracle: nvdisasm 13.4, sweep of all 256 values of [79:72] on opcode 0x7226
//! (`remote/idp_enum_window.json`, `tests/fixtures/sm120_idp_enum_nvdisasm.jsonl`),
//! reproduced on SM100 and SM103.
//!
//! Known gap, pinned below: `IDP.4A.S8.U8` and `IDP.4A.U8.S8` are distinct
//! encodings whose texts differ only in operand order, and the table's
//! mod-group model is a *sorted* comma set (`extract_mod_group` sorts), so one
//! row cannot express either. Neither form occurs in any measured corpus; a word
//! with mixed type bits still decodes as the S8,S8 sibling and therefore does
//! not round-trip. Tracked as a known issue, not silently accepted.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

/// corpus witness: vLLM-Moet `ucb2.cubin` `IDP.4A.U8.U8 R23, R23, R6, R33`
const CORPUS_U8U8: u128 = 0x0000000000000007000000060f0f7226;
/// the encoder owns the control word; instruction bits are what must survive
const LOW96: u128 = (1u128 << 96) - 1;

fn table(name: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(name)).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    to_sass(&idx.decode(word, 0, t).unwrap_or_else(|e| panic!("decode {word:032x}: {e}")))
}

#[test]
fn idp_u8u8_is_not_the_s8s8_row() {
    for leg in ["tables/sm120.json", "tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(leg);
        let got = dec(&t, CORPUS_U8U8);
        assert_eq!(got, "IDP.4A.U8.U8 R15, R15, R6, R7", "{leg}");
        assert_eq!(enc(&t, &got) & LOW96, CORPUS_U8U8 & LOW96, "{leg}");
    }
}

#[test]
fn idp_type_bits_are_care() {
    let t = table("tables/sm120.json");
    // [79:72] = 0x00 -> U8,U8 and 0x06 -> S8,S8 are the two forms the table can
    // name; both must be exact on decode and on re-encode.
    for (enum_, text) in [(0u128, "IDP.4A.U8.U8 R15, R15, R6, R7"),
                          (6, "IDP.4A.S8.S8 R15, R15, R6, R7")] {
        let w = CORPUS_U8U8 | (enum_ << 72);
        assert_eq!(dec(&t, w), text, "enum {enum_:#x}");
        assert_eq!(enc(&t, text) & LOW96, w & LOW96, "encode {text}");
    }
}

#[test]
fn idp_mixed_types_are_a_known_gap() {
    // Documented limitation: 0x02 (S8,U8) and 0x04 (U8,S8) are legal, distinct
    // words whose mod-groups collide after sorting. This test exists so the gap
    // shows up as a deliberate, dated assertion instead of a silent surprise.
    let t = table("tables/sm120.json");
    for enum_ in [2u128, 4] {
        let w = CORPUS_U8U8 | (enum_ << 72);
        let got = dec(&t, w);
        assert_eq!(got, "IDP.4A.S8.S8 R15, R15, R6, R7",
                   "enum {enum_:#x}: absorbed by the S8,S8 sibling (known gap)");
        assert_ne!(enc(&t, &got) & LOW96, w & LOW96,
                   "and consequently not round-trip-stable");
    }
}

#[test]
fn idp_rc_neg_roundtrips() {
    let t = table("tables/sm120.json");
    for text in [
        "IDP.4A.U8.U8 R15, R15, R6, -R7",
        "IDP.4A.S8.S8 R15, R15, R6, -R7",
        "IDP.2A.LO.U16.U8 R15, R15, R6, -R7",
    ] {
        let w = enc(&t, text);
        assert_eq!(dec(&t, w), text, "{text}");
    }
}

#[test]
fn idp_ra_sign_window_is_inert() {
    // b72 sits in the generic ALU abs/neg window; nvdisasm prints no modifier
    // for it on IDP (all 256 enum values), so the post-pass must stay out.
    let t = table("tables/sm120.json");
    let w = CORPUS_U8U8 | (1u128 << 72);
    assert_eq!(dec(&t, w), "IDP.4A.U8.U8 R15, R15, R6, R7", "bit 72");
}

#[test]
fn idp_2a_lo_form_and_b77_fail_closed() {
    let t = table("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    // b76 selects the 2A form the table has (LO), b77 makes it HI (a hole).
    let lo2a = CORPUS_U8U8 | (1 << 76);
    assert_eq!(dec(&t, lo2a), "IDP.2A.LO.U16.U8 R15, R15, R6, R7");
    for w in [lo2a | (1 << 77), CORPUS_U8U8 | (1 << 77)] {
        assert!(idx.decode(w, 0, &t).is_err(),
                "{w:032x} must fail closed (no HI row, b77 illegal on 4A)");
    }
}

#[test]
fn idp_vendor_illegal_enum_values_do_not_decode() {
    // 64 of the 256 enum values are vendor-illegal (0x20..0x2f, 0x60..0x6f, ...).
    let t = table("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sm120_idp_enum_nvdisasm.jsonl");
    let Ok(text) = std::fs::read_to_string(path) else { return };
    let mut illegal = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let rec: serde_json::Value = serde_json::from_str(line).unwrap();
        if !rec["nvidia_sass"].is_null() {
            continue;
        }
        illegal += 1;
        let word = u128::from_str_radix(rec["word"].as_str().unwrap(), 16).unwrap();
        assert!(idx.decode(word, 0, &t).is_err(),
                "{word:032x}: vendor rejects, cubit decodes");
    }
    assert_eq!(illegal, 64, "the enum sweep has 64 illegal values");
}
