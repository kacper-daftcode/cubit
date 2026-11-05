//! B300-3 (2026-11-05): UTMALDG_AURI_AURI / '2D' owns the plain [URa],[URb] form again.
//!
//! BUG-090 retired this group to encode-only because the 1.25M-word era corpus
//! had zero [UR],[UR] words and the harvest-era fields (5b sub_ur0 @32 +
//! overlapping 24b/18b imms) ate desc words (106 strict conflicts with the
//! _II::2D row). The sm100a census corpus (19.9M words) carries 70 such words
//! (16 distinct codes, libcublas.so.75) -- the form is real. blackwell-isa
//! (B300-3) reactivates the group with fields rebuilt from the nvdisasm-13.3
//! single-bit sweep (UP-guard [15:12], URa [39:32], URb [31:24] -- 16/16 exact
//! fit against the vendor text) and and_base pinning every modifier bit except
//! 79 (GATHER4 bit 84 stays pinned 0, so the _II/desc forms cannot be eaten).
//!
//! Proof (roundtrip-strict, sm100a): libcublas.so.75 70 decode failures + 34
//! stream_count errors -> 103264/103264 PASS; cublasLt.so.480 stays
//! 577600/577600 PASS (no desc-eating regression).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// corpus word: libcublas.so.75.sm_100.cubin (UTMALDG.2D [UR4], [UR10])
const CORPUS: u128 = 0x0000000008008000000000040a0075b4;
/// same family, wider registers (UTMALDG.2D [UR20], [UR24])
const CORPUS_20_24: u128 = 0x000000000800800000000014180075b4;

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
fn b3003_utmaldg_2d_owns_the_plain_ur_ur_form() {
    let t = table();
    assert_eq!(clean(&dec(&t, CORPUS)), "UTMALDG.2D [UR4], [UR10]");
    assert_eq!(clean(&dec(&t, CORPUS_20_24)), "UTMALDG.2D [UR20], [UR24]");
    for w in [CORPUS, CORPUS_20_24] {
        let text = dec(&t, w);
        assert_eq!(enc(&t, &text) & NOSCHED, w & NOSCHED, "round trip of {text}");
    }
    // the UP-guard window is live: a bit-12 flip renders @UP6 and re-bakes
    let g = dec(&t, CORPUS ^ (1 << 12));
    assert!(clean(&g).starts_with("@UP6 UTMALDG.2D"), "guard render {g}");
    assert_eq!(enc(&t, &g) & NOSCHED, (CORPUS ^ (1 << 12)) & NOSCHED, "guard round trip");
}
