//! BUG-407 pins (F2-iter215, loop5/blind base-prompt, 2026-09-06): sm121a
//! USETMAXREG misroute fix, canonical 8f2571b -> dd477eb (patch407.py graft,
//! replayable+idempotent). ENGINE src ZERO changes.
//!
//! Vendor law (arb407_census: ab240 battery all 2,406 cubins -> 344 words /
//! 18 distinct: 280 DEALLOC + 64 TRY_ALLOC, zero other forms; arb407_vendor:
//! nvdisasm 13.3.73 raw -b on full-128 words with native control prefixes,
//! x4 models SM100a/SM103a/SM120/SM121a AGREE on every word, DIVERGENT=0):
//!   USETMAXREG.DEALLOC.CTAPOOL <imm10@[41:32]>: b72=1, b73=0, b74=1,
//!     [83:81]=111 (UPT-coded, vendor prints NO UP token);
//!   USETMAXREG.TRY_ALLOC.CTAPOOL <UPn=[83:81]>, <imm10>: b73=1, b72=0,
//!     b74=1 (corpus UP0-only; upred field retained).
//! Pre-fix (publish 9819edaf): every DEALLOC word was claimed by the
//! TRY_ALLOC row (b74 unpinned in both rows' bases; DEALLOC base misses b74,
//! strict never hits) -> render "TRY_ALLOC.CTAPOOL._ALLOC.CTAPOOL UPT, 0xNN"
//! = direction misroute + phantom UPT token + doubled mod; TRUE TRY words
//! carried the same doubled mod. Other legs (sm100a/103a/120): vendor-exact
//! pre and post (measured isolated per leg) -- tables byte-invariant here.
//! Witness data: tests/bug407_data.inc (machine-built by
//! work/bug407/gen407pins.py from arb407_vendor.json verbatim).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}

include!("bug407_data.inc");

#[test]
fn t407_1_corpus_words_vendor_exact_121a() {
    // all 18 corpus words decode to the exact vendor text on sm121a.
    let t = tab("sm121a");
    for (word, want) in CORPUS407 {
        let got = dec96(&t, word);
        assert_eq!(got.as_deref(), Some(want), "word {word:024x}");
    }
}

#[test]
fn t407_2_direction_claim_partition() {
    // claim-level proof: DEALLOC words land on the DEALLOC row (mg ""),
    // TRY words on the TRY row (renamed mg ""), never crossed.
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (word, want) in CORPUS407 {
        let d = idx.decode(word & M96, 0, &t).expect("decodes");
        let is_try = want.contains("TRY_ALLOC");
        if is_try {
            assert_eq!(d.key, "USETMAXREG.TRY_ALLOC.CTAPOOL_UP_II");
        } else {
            assert_eq!(d.key, "USETMAXREG.DEALLOC.CTAPOOL_II");
        }
        assert_eq!(d.mod_group, "", "word {word:024x} mod_group");
    }
}

#[test]
fn t407_3_mint_circle_equals_corpus_payload() {
    // encode(vendor text) == corpus payload bits (M96 domain), and the
    // minted word decodes back to the vendor text.
    let t = tab("sm121a");
    for (word, want) in CORPUS407 {
        let ins = parse_sass(want, 0).unwrap_or_else(|e| panic!("parse '{want}': {e}"));
        let mint = encode_instruction(&ins, &t).unwrap_or_else(|e| panic!("encode '{want}': {e}"));
        assert_eq!(mint & M96, word, "mint drift on '{want}'");
        let round = dec96(&t, mint).expect("minted decodes");
        assert_eq!(round, want, "mint-circle drift on '{want}'");
    }
}

#[test]
fn t407_4_other_legs_vendor_exact_anchor() {
    // posture anchor: sm100a/103a/120 were vendor-exact pre-fix and the
    // graft is byte-invariant there -- the texts still decode vendor-exact.
    let tabs: Vec<IsaTable> = LEGS4[..3].iter().map(|a| tab(a)).collect();
    for (word, want) in CORPUS407 {
        for (leg, t) in tabs.iter().enumerate() {
            let got = dec96(t, word);
            assert_eq!(
                got.as_deref(),
                Some(want),
                "{} word {word:024x}",
                LEGS4[leg]
            );
        }
    }
}

#[test]
fn t407_5_no_doubled_mod_no_phantom_upt() {
    // syntactic guard on the defect strings: doubled mod and phantom UPT
    // must not appear in any decode of the corpus words on any leg.
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (word, _want) in CORPUS407 {
        for (leg, t) in tabs.iter().enumerate() {
            let got = dec96(t, word).expect("decodes");
            assert!(
                !got.contains("CTAPOOL._ALLOC.CTAPOOL"),
                "{} doubled mod: {}",
                LEGS4[leg],
                got
            );
            assert!(
                !got.contains("DEALLOC.CTAPOOL.UPT") && !got.contains("_ALLOC.CTAPOOL UPT"),
                "{} phantom UPT: {}",
                LEGS4[leg],
                got
            );
        }
    }
}
