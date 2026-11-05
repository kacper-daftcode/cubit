//! B300-2a (2026-11-05): the desc offset of `LDG_R_dARI / E,SM,STRONG,U16` is real.
//!
//! 13 680 census words on sm100a (libcublasLt.so.480/492 et al.) re-encoded with
//! the desc offset zeroed: nvdisasm reads the vendor word as
//! `LDG.E.U16.STRONG.SM R41, desc[UR16][R114.64+0x2]` while cubit's re-encode
//! said `desc[UR16][R114.64]` — the address changed. The offset window
//! (`sub_imm2`, 24b SIGNED @ [40..64)) is measured in BUG-388 and declared in
//! every sibling STRONG group (E,GPU / E,SYS / E,GPU,LTC*); only the SM-scope
//! group lacked the field. blackwell-isa (B300-2) restores it 1:1 from the
//! siblings. Roundtrip-strict proof: cublasLt.480 8208 -> 0 failed words
//! (577600/577600), cublasLt.492 5472 -> 0 (357744/357744).
//!
//! Oracle: nvdisasm-13.3 `-b SM100a -hex` (census fixture
//! pubwave/wave11/b300/ + census/fail_sm100a_final.jsonl).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// corpus word: libcublasLt.so.480.sm_100.cubin sec591 @0x63f0 (census LDG class)
const CORPUS: u128 = 0x000f28000c1eb5000000021072297981;
/// same word, next offset step (+0x6) — sec591 @0x6430
const CORPUS_6: u128 = 0x000f68000c1eb50000000610722d7981;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm100a.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    to_sass(&idx.decode(word, 0, t).unwrap_or_else(|e| panic!("decode {word:032x}: {e}")))
}
fn clean(s: &str) -> &str {
    s.trim_end_matches([' ', ';'])
}

#[test]
fn b3002_ldg_desc_offset_survives_the_round_trip() {
    let t = table();
    for w in [CORPUS, CORPUS_6] {
        let text = dec(&t, w);
        assert!(clean(&text).contains(".64+0x"), "{text}");
        assert_eq!(enc(&t, &text) & NOSCHED, w & NOSCHED, "round trip of {text}");
    }
    assert_eq!(clean(&dec(&t, CORPUS)),
               "LDG.E.U16.STRONG.SM R41, desc[UR16][R114.64+0x2]");
    assert_eq!(clean(&dec(&t, CORPUS_6)),
               "LDG.E.U16.STRONG.SM R45, desc[UR16][R114.64+0x6]");
    // explicit text encodes the offset back into the window
    let w = enc(&t, "LDG.E.U16.STRONG.SM R41, desc[UR16][R114.64+0x2]");
    assert_eq!(w & NOSCHED, CORPUS & NOSCHED);
}
