//! B300-2b (2026-11-05): the LDGSTS second-operand imm is a plain 12-bit
//! SIGNED field @ [43:32] -- its sign never comes from bit 87.
//!
//! The pre-fix group `LDGSTS_ARURI_ARI_P / 128,BYPASS,E,LTC128B` carried a
//! phantom `sub_imm1_shr5` field (3b @ [87..85), tok 2); cubit read the imm
//! sign off bit 87 -- the predicate LSB -- so every census word with an odd
//! predicate (P1/P3) rendered `-0x80` and re-encoded to 0xf80 (nvdisasm:
//! `+0x80`; 28 census words, libcublas.so.1070 sm_100). nvdisasm-13.3 field
//! sweep (pubwave/wave11/b300/): bit 43 is the sign (0x080 -> +0x80,
//! 0x880 -> -0x780, 0xf80 -> -0x80); bits [87:85] are .LU/.NA modifiers and
//! the predicate LSB. Sibling groups carry no shr5 and round-trip fine.
//! blackwell-isa (B300-2) removes the field; roundtrip-strict proof:
//! libcublas.so.1070 30 -> 2 failed words (exactly the 28 census LDGSTS
//! words healed).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// corpus word: libcublas.so.1070.sm_100.cubin (census LDGSTS class, pred P1)
const CORPUS_P1: u128 = 0x000fe40008980a1c0608008010847dae;
/// same class, pred P3
const CORPUS_P3: u128 = 0x0003e20009980a080048008014837dae;

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
fn b3002b_ldgsts_imm_sign_is_bit43_not_the_predicate_lsb() {
    let t = table();
    for w in [CORPUS_P1, CORPUS_P3] {
        let text = dec(&t, w);
        assert!(clean(&text).contains("+0x80"), "sign must be positive: {text}");
        assert!(!clean(&text).contains("+-0x80"), "phantom negative: {text}");
        assert_eq!(enc(&t, &text) & NOSCHED, w & NOSCHED, "round trip of {text}");
    }
    // the 12-bit window is really signed: 0xf80 renders and re-bakes as -0x80
    let neg = (CORPUS_P1 & !(0xFFFu128 << 32)) | (0xF80u128 << 32);
    let text = dec(&t, neg);
    assert!(clean(&text).contains("+-0x80") || clean(&text).contains("-0x80"), "{text}");
    assert_eq!(enc(&t, &text) & NOSCHED, neg & NOSCHED, "negative round trip");
}
