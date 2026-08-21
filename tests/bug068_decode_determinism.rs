//! BUG-068 (F2Q-068): decode was process-nondeterministic on candidate ties.
//!
//! DecodeIndex::build pushed candidates in `HashMap` iteration order (per-
//! process RandomState); the final `sort_by_key` is stable, so fully-tying
//! candidates resolved to a *random* winner per process. Proven pre-fix on
//! 6x sampling in both tables: FSETP.NEU AND/XOR+-rsd75, FMUL.FTZ 0/0x0/UR0,
//! HFMA2 R171/RZ-imma, IMAD.MOV/ISETP rsd series (census noise source on
//! every table edit; see results/cubitfix/067 census residuals).
//!
//! Fix (u zrodla): candidates are collected in sorted (key, mod_group)
//! order AND the disambiguation tuple ends in the total-order tiebreak
//! (key, mod_group) — unique per table entry. Decode is now a pure function
//! of (table, word).
//!
//! Pins below are tie words that flip-flopped pre-fix (rates in comments,
//! pre-fix binary cubit-a5fcb61, 6..12 samples each). For each: decode must
//! be identical across 4 fresh (table load + index build) pairs, equal the
//! pinned canonical render, and re-encode to the identical word (fixed
//! point — every tied variant was payload-equivalent).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn load() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

static GOLD: &[(u128, &str)] = &[
    // FMUL zero-imm tie (FI "0" vs II "0x0" vs UR "UR0"; 5/4/3 pre-fix)
    (0x000fcc00004100003f00000005047820u128, "FMUL.FTZ R4, R5, 0"),
    (0x000fcc00004100003f000000070b0820u128, "@P0 FMUL.FTZ R11, R7, 0"),
    // FSETP.NEU AND vs XOR (+!rsd[75]) tie (4/2 pre-fix)
    (0x000fdc0003f0d200000000020300720bu128, "FSETP.NEU.AND P0, PT, |R3|, R2, PT"),
    // HFMA2 RZ-imma vs R171 tie (4/2 pre-fix)
    (0x000fcc00000001ff5e2aaaabff027431u128, "HFMA2 R2, -RZ, RZ, 394.5, -0.052093505859375"),
];

#[test]
fn bug068_decode_is_process_deterministic() {
    // 4 independent table loads + index builds: each gets HashMaps with a
    // fresh RandomState; pre-fix this flipped renders between builds.
    let mut renders: Vec<Vec<String>> = Vec::new();
    for _ in 0..4 {
        let t = load();
        let idx = DecodeIndex::build(&t);
        let mut col = Vec::new();
        for &(word, _) in GOLD {
            let d = idx.decode(word, 0, &t).unwrap();
            col.push(cubit::printer::to_sass(&d));
        }
        renders.push(col);
    }
    for r in &renders[1..] {
        assert_eq!(r, &renders[0], "decode differs across fresh table/index builds");
    }
    // canonical (alphabetical total-order) snapshots
    for ((_, golden), got) in GOLD.iter().zip(&renders[0]) {
        assert_eq!(got, golden, "canonical render changed");
    }
}

#[test]
fn bug068_tie_renders_are_fixed_points() {
    let t = load();
    for &(word, golden) in GOLD {
        let insn = parse_sass(&format!("{golden} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & !SCHED, word & !SCHED,
            "canonical render {golden:?} is not a fixed point of {word:032x}");
    }
}
