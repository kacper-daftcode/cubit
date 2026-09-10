//! BUG-405 + BUG-406 pins (F2-iter222, loop5/blind front2, 2026-09-07):
//! HADD2_R_R_FI_FI '' claim-pin release + HFMA2 two-imm slot discipline
//! (ONE canonical graft 74a06b7 on top of 19363f6; ENGINE src ZERO changes;
//! pure table graft, data-only).
//!
//! 405 (registration 405-kand LOW, F2-iter213, 392.md sec.6): the dense
//! HADD2 FI FI row carried an era-junk empty-extraction field at shift 0,
//! freeing bit0 from the match mask -> it claimed EVERY .431 word (plain
//! HFMA2 FI FI space AND the dotted HFMA2.BF16_V2[.*].RELU_R_R_R_{II,FI}_FI_P
//! keyspace incl trailing-P) and PRINTED AS HADD2. Vendor law arb405 (124
//! probes x4 models AGREE EVERY, DIVERGENT=0): vendor never prints HADD2
//! with bit0=1 across the lattice. Corpus census (2,406 cubins x4): ZERO
//! live claims carry bit0=1 (tighten corpus-invisible). Graft on
//! sm120/sm121a (sm100a/sm103a already pinned bit0=0 correctly): junk
//! field deleted + variable_mask bit0 cleared; released words strict-claim
//! the dotted rows (which already carry bug288/bug330 bf16 imm fields).
//!
//! 406 (registration 406-kand LOW, same source): the R-final two-imm HFMA2
//! rows bound the 16-bit imm windows to the WRONG tokens (era-bake) or
//! bound nothing. Vendor law arb406 (78 probes) + arb406b (26 plain-frame),
//! x4 models AGREE EVERY, DIVERGENT=0: tok3 <- imm[48:64), tok4 <- imm[32:48)
//! on EVERY frame (''_f16 / BF16_V2_bf16, x4 legs); tok5 sign window
//! abs@83/neg@84 vendor-visible. Field swap on HFMA2_R_R_FI_FI_R ''/BF16_V2
//! (sm100a/103a/120; claim mask byte-invariant), field ADD on sm121a
//! HFMA2_R_R_II_II_R ''/BF16_V2 (pre-fix: '0, 0' print on 12,942 corpus
//! words incl cublasLt fp16 where vendor prints '1, 1'; imm-variant words
//! HOLE), +abs@83/neg@84 tok5 on all five rows (pre-fix HOLE).
//!
//! Witnesses: tests/bug405_406_data.inc (machine-built by
//! work/bug405x/gen405_406pins.py; no hand hex).
//!
//! Out of scope (stand registered): 417-kand (HADD2 FI FI window holes:
//! b64 HOLE sm120/121a, b84 HOLE x4, tok2 signs sm100a/103a); 261-latent
//! tok2 hsel INVALID1/H0_H0 on R-final HFMA2 rows; encode pre-existing
//! holes (sm121a R-final BF16_V2 mint, imm-special mints, .INVALID1 glyph)
//! -- posture refs in t405_6.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

mod data {
    include!("bug405_406_data.inc");
}
use data::*;

const M96: u128 = (1 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn text_of(t: &IsaTable, w: u128) -> Option<String> {
    dec96(t, w).map(|s| s.trim_end_matches(';').trim().to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

/// t405_1: vendor law -- released HFMA2-family .431 words decode vendor-exact
/// (plain FI FI frame + the dotted BF16_V2[.*].RELU trailing-P keyspace).
#[test]
fn t405_1_released_words_vendor_text() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, legmask, ven) in LAW405 {
        for (li, leg) in LEGS4.iter().enumerate() {
            if !legmask.split(',').any(|l| l == *leg) {
                continue;
            }
            let got = text_of(&tabs[li], *w)
                .unwrap_or_else(|| panic!("405 leg {leg} tag {tag}: HOLE on 0x{w:032x}"));
            assert_eq!(
                got.as_str(),
                *ven,
                "405 leg {leg} tag {tag} word 0x{w:032x}"
            );
        }
    }
}

/// t405_2: HADD2 keeps its home leg -- bit0=0 words still decode as HADD2,
/// vendor-exact (the claim-tighten must not touch the home class).
#[test]
fn t405_2_hadd2_home_class_kept() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, legmask, ven) in HOLD405 {
        for (li, leg) in LEGS4.iter().enumerate() {
            if !legmask.split(',').any(|l| l == *leg) {
                continue;
            }
            let got = text_of(&tabs[li], *w)
                .unwrap_or_else(|| panic!("HOLD leg {leg} tag {tag}: HOLE on 0x{w:032x}"));
            assert_eq!(
                got.as_str(),
                *ven,
                "HOLD leg {leg} tag {tag} word 0x{w:032x}"
            );
            assert!(
                ven.contains("HADD2"),
                "HOLD set must be the HADD2 home class: {tag}"
            );
        }
    }
}

/// t405_3: claim attribution -- released words route to the HFMA2-family
/// rows, never to HADD2 (decode key must not start with HADD2).
#[test]
fn t405_3_claim_route_no_hadd2() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, legmask, _ven) in LAW405 {
        for (li, leg) in LEGS4.iter().enumerate() {
            if !legmask.split(',').any(|l| l == *leg) {
                continue;
            }
            let idx = DecodeIndex::build(&tabs[li]);
            let d = idx
                .decode(*w & M96, 0, &tabs[li])
                .unwrap_or_else(|_| panic!("405 leg {leg} tag {tag}: HOLE"));
            assert!(
                !d.key.starts_with("HADD2"),
                "405 leg {leg} tag {tag}: claimed by {} after release",
                d.key
            );
            assert!(
                d.key.starts_with("HFMA2"),
                "405 leg {leg} tag {tag}: unexpected claimant {}",
                d.key
            );
        }
    }
}

/// t406_1: vendor law -- two-imm slot discipline (tok3 <- [48:64), tok4 <-
/// [32:48)) on the R-final rows, x4 legs, incl specials +INF/-1/+QNAN/-0.0.
#[test]
fn t406_1_imm_slot_law() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, legmask, ven) in LAW406 {
        for (li, leg) in LEGS4.iter().enumerate() {
            if !legmask.split(',').any(|l| l == *leg) {
                continue;
            }
            let got = text_of(&tabs[li], *w)
                .unwrap_or_else(|| panic!("406 leg {leg} tag {tag}: HOLE on 0x{w:032x}"));
            assert_eq!(
                got.as_str(),
                *ven,
                "406 leg {leg} tag {tag} word 0x{w:032x}"
            );
        }
    }
}

/// t406_2: sm121a corpus witnesses (cublasLt fp16 population; pre-fix the
/// engine printed '0, 0' on all 12,942 of them) decode vendor-exact.
#[test]
fn t406_2_corpus_witnesses_121a() {
    let t = tab("sm121a");
    for (w, ven) in CORPUS406_121A {
        let got =
            text_of(&t, *w).unwrap_or_else(|| panic!("406 corpus witness HOLE on 0x{w:024x}"));
        assert_eq!(got.as_str(), *ven, "406 corpus witness 0x{w:024x}");
    }
}

/// t406_3: mint circles -- vendor-true texts re-encode to the source words
/// on the classes with an encode path (low96 byte-exact).
#[test]
fn t406_3_mint_circle() {
    let circles: &[(&str, u128, &str)] = &[
        // dotted clean word (sm120 claim row = dotted key)
        (
            "sm120",
            0x2090000000000000000431,
            "@P0 HFMA2.BF16_V2.FMZ.RELU R0, R0, R0, 0, 0, P0",
        ),
        // R-final BF16_V2 witnesses x3 home legs
        (
            "sm120",
            0x002000193f803f8013137831,
            "HFMA2.BF16_V2 R19, R19, 1, 1, R25",
        ),
        (
            "sm100a",
            0x002000193f803f8013137831,
            "HFMA2.BF16_V2 R19, R19, 1, 1, R25",
        ),
        (
            "sm103a",
            0x002000193f803f8013137831,
            "HFMA2.BF16_V2 R19, R19, 1, 1, R25",
        ),
        // plain-F16 R-final
        (
            "sm120",
            0x000000003c003c0000007831,
            "HFMA2 R0, R0, 1, 1, R0",
        ),
        // plain FI FI sm121a (HFMA2_R_R_R_FI_FI home class)
        (
            "sm121a",
            0x0000000000003f8000000431,
            "@P0 HFMA2 R0, R0, R0, 0, 1.875",
        ),
    ];
    for (leg, w, text) in circles {
        let t = tab(leg);
        let eb =
            enc(&t, text).unwrap_or_else(|e| panic!("406 mint refuse leg {leg} text {text}: {e}"));
        assert_eq!(
            eb & M96,
            w & M96,
            "406 mint circle leg {leg} text {text}: {eb:032x} != {w:032x}"
        );
    }
    // refuse-closed: pre-existing encode holes stay LOUD (registration refs)
    let t121 = tab("sm121a");
    assert!(
        enc(&t121, "HFMA2.BF16_V2 R19, R19, 1, 1, R25").is_err(),
        "sm121a R-final BF16_V2 mint hole must stay loud (encode-hole kand)"
    );
    assert!(
        enc(&t121, "@P0 HFMA2 R0, R0, R0, +QNAN , 0").is_err(),
        "sm121a imm-special mint hole must stay loud"
    );
    let t120 = tab("sm120");
    assert!(
        enc(
            &t120,
            "@P0 HFMA2.BF16_V2.FMZ.RELU R0, R0.INVALID1, R0, 0, 0, P0"
        )
        .is_err(),
        ".INVALID1 mint hole must stay loud"
    );
}

/// t405_6: postures for the DELIBERATELY untouched pre-existing classes.
/// [417 F2-iter226]: the 24 originally-pinned cells (417-kand + 261-latent)
/// are CLOSED by the BUG-417 graft -- their expected text is now the VENDOR
/// text (tags '417-closed' in bug405_406_data.inc; machine-verified ==
/// vendor by gen417pins.py; the remaining untouched classes moved to
/// POSTURE417_419 in bug417_data.inc).
#[test]
fn t405_6_untouched_postures() {
    for (w, tag, leg, ven, post, src) in POSTURE405_6 {
        let t = tab(leg);
        let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            got.as_str(), *post,
            "posture drift ({src}) on {tag} leg {leg} word 0x{w:032x}: engine {got:?} != pinned {post:?} (vendor {ven:?})"
        );
        // and the class must not silently become vendor-WRONG-better-looking:
        // HOLE stays loud; text must differ from vendor (if it becomes
        // vendor-exact, flip this pin with the fix).
        let _ = ven;
    }
}
