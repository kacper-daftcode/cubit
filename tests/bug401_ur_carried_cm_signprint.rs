//! BUG-401 pins (F2-iter218, loop5/blind front2, 2026-09-06): printer arm
//! for the UR-carried cm sign-window (decode-side, ONE src change:
//! src/printer.rs format_const_addr UR branch; canonical 96f196b STOI,
//! tables ZERO changes).
//!
//! Defect: the UR-carried cAI address reprinted the composed cm16/cm17
//! sign-window raw UNSIGNED (`c[0x0][UR5+0x10394]`) where vendor reads
//! SIGNED-17 (`c[0x0][UR5+-0xfc6c]`). The R-carried branch and the plain
//! form already followed the signed law (BUG-162/389); the UR branch was
//! unarmed. Side effect: such words were un-round-trippable -- the
//! unsigned reprint mints REFUSE post-389 (fit_cm_off_soft fail-closed);
//! vendor-true `-0x10000` texts minted fine but flipped sign on reprint
//! (measure_post389 residua sm103a/sm120).
//!
//! Vendor law (arb401_law.json + arb402 401-class words; nvdisasm 13.3.73
//! raw -b x4 models AGREE EVERY, DIVERGENT=0), full-128 corpus-anchor
//! control prefixes: UR-carried negatives print `URn+-0x<mag>` across the
//! whole SIGNED-17 window [54:37) (boundaries 0x1/0x8000/0xffff/0x10000/
//! 0x1ffff + bank composite + URZ-sentinel plain collapse verified);
//! positives/zero unchanged (`URn+0xff..` / bare `[URn]`).
//!
//! Scope (census402/388-doc): the only const-addr row carrying a sub_ur*
//! token field is LDCU_UR_cAI|'' on sm100a/103a/120. sm121a routes
//! UR-carried words to LDCU_UR_cAURI (unarmed `?cAURI` marker =
//! 410-kand, print-arm 121a) -- pinned UNTOUCHED here (t401_4).
//!
//! Witness data: tests/bug401_data.inc (machine-built by
//! work/bug401/gen401pins.py; no hand hex). Corpus exposure (census401,
//! ab240 2,406 cubins x4 legs, publish cubit_py-f2f7e02c): sign-bit set
//! = 0 on every leg -> fix is corpus-invisible (CLAIMS401_* pin the
//! distinct UR-carried renders byte-stable; t402_2 foreign sample stands).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

include!("bug401_data.inc");

/// t401_1: vendor law x12 words on the three legacy legs (the arm's full
/// domain). sm121a is NOT part of this domain (t401_4 pins its posture).
#[test]
fn t401_1_vendor_law_three_legs() {
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, vendor) in LAW401 {
            let got =
                dec(&t, &idx, word).unwrap_or_else(|| panic!("[{leg}] {tag} must decode post-401"));
            assert_eq!(
                got, vendor,
                "[{leg}] {tag} render diverges from vendor x4 law"
            );
        }
    }
}

/// t401_2: the 401-class words round-trip through text for the first time
/// (pre-fix: decode -> unsigned text -> encode REFUSE, BUG-389 fail-closed).
/// Decode->text->encode->word must close the circle on x3 legs.
#[test]
fn t401_2_decode_text_encode_circle() {
    const M96: u128 = (1u128 << 96) - 1;
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, vendor) in LAW401 {
            if tag.contains("plain_negmax") {
                continue;
            } // URZ-sentinel plain collapse: UR slot re-mints as URZ, covered below
            let text = dec(&t, &idx, word).unwrap();
            let w2 = enc(&t, &format!("{text} ;"))
                .unwrap_or_else(|e| panic!("[{leg}] {tag} text must re-encode post-401: {e}"));
            // payload bits must match; ctrl prefix [127:96) is encoder-authored
            assert_eq!(
                w2 & M96,
                word & M96,
                "[{leg}] {tag} payload drift on re-encode"
            );
            let text2 = dec(&t, &idx, w2).unwrap();
            assert_eq!(text2, vendor, "[{leg}] {tag} second render drift");
        }
    }
    // the sentinel-collapse word round-trips through the plain form
    // (vendor 'c[0x0][-0x10000]', arb389 plain law; corpus-consistent).
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let (word, tag, _vendor) = LAW401
            .iter()
            .find(|(_, tag, _)| tag.contains("plain_negmax"))
            .copied()
            .unwrap();
        let text = dec(&t, &idx, word).unwrap();
        let w2 = enc(&t, &format!("{text} ;")).unwrap();
        assert_eq!(
            dec(&t, &idx, w2).unwrap(),
            text,
            "[{leg}] {tag} plain circle drift"
        );
    }
}

/// t401_3: mint-side vendor spelling law on the UR-carried shape: both
/// sign spellings (`-0x` / `+-0x`) mint one word (t389_2 contract) and
/// reprint as the vendor `+-` glyph; positive/zero spellings round-trip
/// with unchanged prints; the old UNSIGNED sign-window text mints refuse
/// closed (BUG-389 attribution kept -- the arm must NOT reopen it).
#[test]
fn t401_3_mint_spelling_law() {
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let w1 = enc(&t, "LDCU UR4, c[0x0][UR6-0x10000] ;").unwrap();
        let w2 = enc(&t, "LDCU UR4, c[0x0][UR6+-0x10000] ;").unwrap();
        assert_eq!(w1, w2, "[{leg}] - and +- spellings must mint one word");
        assert_eq!(
            dec(&t, &idx, w1).unwrap(),
            "LDCU UR4, c[0x0][UR6+-0x10000]",
            "[{leg}] sign-window reprint must be the vendor glyph (401 landed)"
        );
        for (text, want) in [
            ("LDCU UR4, c[0x0][UR6] ;", "LDCU UR4, c[0x0][UR6]"),
            (
                "LDCU UR4, c[0x0][UR6+0xffff] ;",
                "LDCU UR4, c[0x0][UR6+0xffff]",
            ),
            (
                "LDCU UR4, c[0x3][UR6-0x8000] ;",
                "LDCU UR4, c[0x3][UR6+-0x8000]",
            ),
        ] {
            let w = enc(&t, text).unwrap();
            assert_eq!(
                dec(&t, &idx, w).unwrap(),
                want,
                "[{leg}] spelling law {text}"
            );
        }
        for bad in [
            "LDCU UR4, c[0x0][UR6+0x10000] ;", // old unsigned print of negmax
            "LDCU UR4, c[0x0][UR6+0x1ffff] ;", // old unsigned print of -1
            "LDCU UR4, c[0x0][UR6+0x20000] ;", // over window
        ] {
            let err = enc(&t, bad).expect_err("[{leg}] unsigned sign-window mint must refuse");
            assert!(
                err.contains("BUG-389"),
                "[{leg}] attribution lost for {bad}: {err}"
            );
        }
    }
}

/// t401_4: sm121a 410-kand CLOSED [FLIPPED 2026-09-07 z atrybucja BUG-398/
/// F2-iter220: cAURI printer/parser/encoder arm wyladowal]: UR-carried slowa
/// LAW401 dekoduja vendor-exact takze na sm121a (teksty sa x4-unanimous jak
/// w arb401/arb398) i UR-carried minty ENKODUJA (dedicated row
/// LDCU_UR_cAURI). Plain collapse stoi (leg-invariant, vendor-exact).
/// Regresja ktorejkolwiek strony = zlamanie 398A armu.
#[test]
fn t401_4_sm121a_410_closed() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (word, tag, vendor) in LAW401 {
        let got = dec(&t, &idx, word)
            .unwrap_or_else(|| panic!("[sm121a] {tag} fell HOLE: route changed"));
        assert_eq!(
            got.as_str(),
            vendor,
            "[sm121a] {tag} 121a render != x4 vendor text post-398"
        );
        assert!(
            !got.contains("?cAURI"),
            "[sm121a] {tag} '?cAURI' powrocil: {got}"
        );
    }
    for good in [
        "LDCU UR4, c[0x0][UR6+-0x10000] ;",
        "LDCU UR4, c[0x0][UR6] ;",
    ] {
        let w = enc(&t, good)
            .unwrap_or_else(|e| panic!("[sm121a] UR-carried mint refuses post-398: {e}"));
        let d = idx.decode(w, 0, &t).map(|d| to_sass(&d)).unwrap();
        assert_eq!(
            d.trim_end_matches(';').trim(),
            good.trim_end_matches(';').trim(),
            "[sm121a] UR-carried mint roundtrip drifted"
        );
    }
}

/// t401_5: corpus invariance -- every distinct corpus UR-carried LDCU
/// claim render is byte-stable post-fix on the three legacy legs
/// (census401: sign-bit set = 0 on every corpus word; the arm only moves
/// sign-window renders). Guards future printer drift on live bytes.
#[test]
fn t401_5_corpus_ur_carried_renders_stable() {
    for (leg, claims) in [
        ("sm100a", CLAIMS401_SM100A.as_slice()),
        ("sm103a", CLAIMS401_SM103A.as_slice()),
        ("sm120", CLAIMS401_SM120.as_slice()),
    ] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, want) in claims {
            let got = dec(&t, &idx, *word)
                .unwrap_or_else(|| panic!("[{leg}] corpus UR-carried claim lost {word:032x}"));
            assert_eq!(&got, want, "[{leg}] corpus render drift {word:032x}");
        }
    }
}
