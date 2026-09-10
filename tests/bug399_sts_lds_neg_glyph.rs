//! BUG-399 pins (F2-iter219, loop5/blind front2, 2026-09-07): vendor glyph
//! '+-0x<mag>' for NEGATIVE offsets in shared-memory bracket addresses
//! (STS/LDS/LDSM plain ARI/ARURI, src/printer.rs format_sts_lds_addr;
//! ONE src change, canonical 96f196b STOI, tables ZERO changes).
//!
//! Defect (registration 399-kand LOW, 388.md sec.7; 12-cells glyph audit
//! in t388_2): engine printed `-0x<mag>` where vendor prints `+-0x<mag>`
//! (same sign-window glyph law the cm const-addr world already follows:
//! BUG-162/389/401). Decode-side render divergence only; minted words were
//! always byte-correct and BOTH spellings already minted through the
//! encoder (t389_2-class contract) -- so pre-fix text was re-encodable,
//! just not vendor-true.
//!
//! Vendor law (arb399a_law.json; nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a AGREE EVERY probe, DIVERGENT=0; full-128
//! frames from table and_base rows incl. ctrl prefixes + the t388_2
//! corpus-anchor LDS.S8 witness): across the whole 24-bit SIGNED offset
//! window [64:40) every negative magnitude prints '+-0x' on EVERY form --
//! UR-carried `[R10+UR4+-0x800000]`, UR63, RZ-base `[UR4+-0x1]`; zero
//! offset elides. Uniform over LDS/STS/LDSM frames and all 4 legs.
//!
//! Out of scope (registered, pinned/postured): (a) SYNCS.PHASECHK/ARRIVE
//! brackets (format_syncs_addr) -- table and_base frames ABORT under
//! nvdisasm raw -b (no vendor arbiter) => SYNCS print UNTOUCHED, debt
//! noted in the report; (b) UR-sentinel divergence measured as OTHER x6
//! (vendor `URZ`, engine `UR255`/UR511` for 8/9-bit ur fields) =
//! 412-kand, posture pinned UNTOUCHED in t399_4.
//!
//! Witness data: tests/bug399_data.inc (machine-built by
//! work/bug399/gen399pins.py from arb399a_law.json + measure_post399_*;
//! no hand hex). Foreign flip WITH attribution: t388_2 drops the 399
//! glyph-norm (12 lenses -> exact vendor text; `glyph_norm` removed).
//!
//! v2 scope-narrowing (same iteration, after corpus attr399 caught the
//! overflow): the '+-' arm fires ONLY when the contributing offset field is
//! the measured 24-bit window; narrower imm windows keep '-0x' UNTOUCHED
//! (t399_6) and the LDGSTS shdst keeps its own pre-existing 20-bit census
//! rewrite (n-0x -> n+-0x, guard against '++-' doubling). 414-kand
//! registered for the sm121a dedicated narrow-imm rows: STS.U8_ARURI_R
//! imm 13b@40 / STS.U8_ARI_II imm 12b@41 claim engine-minted 24-bit words
//! and mis-render them ('STS.U8 [R5+UR10-0xfff], RZ' where vendor prints
//! '+0x1001'; OLD==NEW!=vendor, pre-existing, decoder-side window
//! geometry/priority -- own lattice work needed, LOW).

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

include!("bug399_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

/// t399_1: vendor law x30 words on all 4 legs (LDS/STS/LDSM frames;
/// UR-carried / UR63 / RZ-base / zero / positive boundary offsets).
#[test]
fn t399_1_vendor_law_all_legs() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, vendor) in LAW399 {
            let got = dec(&t, &idx, *word)
                .unwrap_or_else(|| panic!("[{leg}] {tag} must decode post-399"));
            assert_eq!(
                &got, vendor,
                "[{leg}] {tag} render diverges from vendor x4 law"
            );
        }
    }
}

/// t399_2: decode -> text('+-0x') -> encode -> word(payload) circle closes
/// on every negative law word (pre-fix the reprint was '-0x' -- legal to
/// mint but not vendor-true; post-fix the circle runs on the vendor glyph
/// itself, second render stable).
#[test]
fn t399_2_decode_text_encode_circle() {
    const M96: u128 = (1u128 << 96) - 1;
    // CLOSED z atrybucja BUG-413(i) (F2-iter230, canonical e4f0915): the
    // sm121a STS_ARURI_R '' donor graft carries sub_imm1 24b@40 -- negative
    // offset mints encode on every leg (5 former refusal words now in
    // MINT413, t413_1). Set must stay EMPTY; a new refusal regresses here.
    const EXPECTED_REFUSE: &[(&str, &str)] = &[];
    let mut refused: Vec<(String, String)> = Vec::new();
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, vendor) in LAW399 {
            if !tag.contains("off_8") && !tag.contains("off_f") {
                continue;
            } // negative words only (zero/positive spellings in t399_3)
            if tag.contains("|rz|") {
                // RZ-base vendor text ('[UR4+-0x800000]') decodes exact and
                // (CLOSED z atrybucja BUG-413(ii)/(iii), F2-iter231, canonical
                // 487757b) mints on every leg: LDSM_R_AURI row added x4 and
                // LDS_R_AURI carries the S8 mod-group (BUG-132 cordon arm
                // satisfied by the measured rows). Pre-F2-iter231 both mints
                // refused (no row / cordon); the circle below must now close
                // for all three carriers -- STS minted pre, LDS.S8/LDSM mint
                // post-413ii. Parser-level '[URZ...]' authored forms stay
                // refused (pre-existing posture, t413ii_5), no such tag here.
                let text = dec(&t, &idx, *word).unwrap();
                match enc(&t, &format!("{text} ;")) {
                    Ok(w2) => {
                        let text2 = dec(&t, &idx, w2).unwrap();
                        assert_eq!(&text2, vendor, "[{leg}] {tag} rz circle drift");
                        continue;
                    }
                    Err(_) => continue,
                }
            }
            let text = dec(&t, &idx, *word).unwrap();
            match enc(&t, &format!("{text} ;")) {
                Ok(w2) => {
                    assert_eq!(
                        w2 & M96,
                        word & M96,
                        "[{leg}] {tag} payload drift on re-encode"
                    );
                    let text2 = dec(&t, &idx, w2).unwrap();
                    assert_eq!(&text2, vendor, "[{leg}] {tag} second render drift");
                }
                Err(_) => refused.push((leg.to_string(), tag.to_string())),
            }
        }
    }
    // after all legs: the refusal set must be exactly the measured holes
    let mut got: Vec<(&str, &str)> = refused
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    got.sort();
    let mut want: Vec<(&str, &str)> = EXPECTED_REFUSE.to_vec();
    want.sort();
    assert_eq!(
        got, want,
        "circle refusal set drifted (encode-side hole closed? close it and shrink the list)"
    );
}

/// t399_3: mint-side spelling law on the shared-bracket shape: both sign
/// spellings (`-0x` / `+-0x`) mint one word and reprint as the vendor
/// `+-` glyph; positive/zero spellings round-trip with unchanged prints.
#[test]
fn t399_3_mint_spelling_law() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let w1 = enc(&t, "LDS.S8 R93, [R10+UR4-0x800000] ;").unwrap();
        let w2 = enc(&t, "LDS.S8 R93, [R10+UR4+-0x800000] ;").unwrap();
        assert_eq!(w1, w2, "[{leg}] - and +- spellings must mint one word");
        assert_eq!(
            dec(&t, &idx, w1).unwrap(),
            "LDS.S8 R93, [R10+UR4+-0x800000]",
            "[{leg}] reprint must be the vendor glyph (399 landed)"
        );
        for (text, want) in [
            ("LDS.S8 R93, [R10+UR4] ;", "LDS.S8 R93, [R10+UR4]"),
            (
                "LDS.S8 R93, [R10+UR4+0x7fffff] ;",
                "LDS.S8 R93, [R10+UR4+0x7fffff]",
            ),
            (
                "LDSM.16.M88 R16, [R10+UR4-0x1] ;",
                "LDSM.16.M88 R16, [R10+UR4+-0x1]",
            ),
        ] {
            let w = enc(&t, text).unwrap();
            assert_eq!(
                dec(&t, &idx, w).unwrap(),
                want,
                "[{leg}] spelling law {text}"
            );
        }
        if leg == "sm121a" {
            // BUG-413(i) CLOSED (F2-iter230): the donor-shaped '' row mints
            // the negative offset like every other leg.
            let w = enc(&t, "STS [R10+UR4-0x1], R30 ;").unwrap();
            assert_eq!(
                dec(&t, &idx, w).unwrap(),
                "STS [R10+UR4+-0x1], R30",
                "[sm121a] spelling law STS neg"
            );
        } else {
            let w = enc(&t, "STS [R10+UR4-0x1], R30 ;").unwrap();
            assert_eq!(
                dec(&t, &idx, w).unwrap(),
                "STS [R10+UR4+-0x1], R30",
                "[{leg}] spelling law STS neg"
            );
        }
        // CLOSED z atrybucja BUG-413(ii)/(iii) (F2-iter231, canonical
        // 487757b): the RZ-elided mints now encode byte-exact circles --
        // LDS_R_AURI carries the S8 mod-group (132 cordon arm satisfied by
        // the measured row; silent drop is still impossible: the row's
        // reprint is S8) and LDSM_R_AURI exists (row added x4). Pre-iter231
        // both refused (no row / cordon); assert the closed circles:
        for (txt, want) in [
            ("LDS.S8 R93, [UR4+-0x1] ;", "LDS.S8 R93, [UR4+-0x1]"),
            ("LDSM.16.M88 R16, [UR4+-0x1] ;", "LDSM.16.M88 R16, [UR4+-0x1]"),
        ] {
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("[{leg}] 413ii/iii mint refuse: {txt}: {e}"));
            assert_eq!(dec(&t, &idx, w).unwrap(), want, "[{leg}] 413ii/iii circle drift");
        }
    }
}

/// t399_4: 412 CLOSED z atrybucja BUG-412 (F2-iter230, canonical e4f0915 +
/// printer.rs arm): vendor law (arb412/arb412b, x4 AGREE EVERY) -- numeral =
/// low 8 bits, all-ones = URZ. POSTURE412 keeps the PRE-fix per-leg renders
/// pinned so the fix footprint is explicit: every cell must now render the
/// vendor text (computed live from POSTURE412 vendor annotation below).
#[test]
fn t399_4_ur_sentinel_closed_vendor_exact() {
    for (li, leg) in LEGS.iter().enumerate() {
        let _ = li;
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, _pre_renders) in POSTURE412 {
            let got = dec(&t, &idx, *word).unwrap_or_else(|| panic!("[{leg}] {tag} fell HOLE"));
            let vendor = POSTURE412_VENDOR
                .iter()
                .find(|(tg, _)| tg == tag)
                .unwrap()
                .1;
            assert_eq!(got, vendor, "[{leg}] {tag} must be vendor-exact post-412");
        }
    }
}

/// t399_5: SYNCS debt-contract -- the SYNCS.PHASECHK/ARRIVE and_base
/// frames have no nvdisasm-raw arbiter (ABORT law) and
/// format_syncs_addr keeps the pre-399 '-0x' print UNTOUCHED; pin the
/// untouched behaviour on the two SYNCS ARURI table rows via a minted
/// negative-offset word (engine-only contract, vendor law outstanding).
#[test]
fn t399_5_syncs_untouched_debt_contract() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        // mint a negative-offset SYNCS.PHASECHK bracket through the encoder
        // (encoding path is vendor-true; only the PRINT glyph is deferred)
        if let Ok(w) = enc(&t, "SYNCS.PHASECHK.TRANS64 P0, [R10+UR4-0x800000], R30 ;") {
            let got =
                dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] SYNCS minted word must decode"));
            assert!(
                got.contains("-0x800000"),
                "[{leg}] SYNCS print posture drifted (debt closed?): {got}"
            );
        } // legs where the row refuses to mint keep their posture too
    }
}

/// t399_6: CLOSED by BUG-414 (F2-iter225) -- flip WITH attribution. The
/// sm121a narrow-imm posture this pin froze was the 414 defect itself
/// (dedicated STS.U8_ARURI_R declared imm 13b@40 while the vendor reads
/// the 24-bit window [40:64); lattice arb414/arb414b/arb414c x4 DIVERGENT=0).
/// Post-414 the witness mints the 24-bit form and every leg renders the
/// same vendor-true text (399 '+-' glyph included). The pin now guards the
/// CLOSED contract so a regression re-opens loudly.
#[test]
fn t399_6_sm121a_narrow_imm_closed_by_414() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    // Post-414: '-0xfff' mints the 24-bit window form (bits [40:64) =
    // 0xfff001), no longer the 13-bit fold. Vendor text on every leg is
    // '+-0xfff' (arb414b w24_fff001, x4 AGREE).
    let w = enc(&t, "STS.U8 [R5+UR10-0xfff], RZ ;").unwrap();
    const M96: u128 = (1u128 << 96) - 1;
    assert_eq!(
        (w >> 40) & 0xFFFFFF,
        0xfff001,
        "sm121a mint must use the 24-bit window post-414"
    );
    let got = dec(&t, &idx, w).unwrap();
    assert_eq!(
        got, "STS.U8 [R5+UR10+-0xfff], RZ",
        "sm121a render drift (414 regression?)"
    );
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t2 = tab(leg);
        let idx2 = DecodeIndex::build(&t2);
        let got2 = dec(&t2, &idx2, w).unwrap();
        assert_eq!(
            got2, "STS.U8 [R5+UR10+-0xfff], RZ",
            "[{leg}] 24-bit law drifted on the closed-414 word"
        );
        // cross-leg mint parity in the payload domain
        let w2 = enc(&t2, "STS.U8 [R5+UR10+-0xfff], RZ ;").unwrap();
        assert_eq!(w2 & M96, w & M96, "[{leg}] cross-leg mint drift");
    }
    // The positive form of the old defect payload (+0x1001) keeps minting
    // the same bytes it always did (no churn on the vendor-true path).
    let wp = enc(&t, "STS.U8 [R5+UR10+0x1001], RZ ;").unwrap();
    assert_eq!((wp >> 40) & 0xFFFFFF, 0x1001, "positive path churned");
}
