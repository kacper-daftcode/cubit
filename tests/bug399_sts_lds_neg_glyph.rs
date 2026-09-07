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
    // Measured encode-side refusal set (pre-existing holes, OUT OF SCOPE of
    // this decode-glyph fix; machine-pinned so the set can only shrink with
    // an explicit encode-side close-out): sm121a STS_ARURI_R rejects every
    // negative 24-bit offset value (parser carries the 64-bit signed value,
    // the row's offset field does not accept it) -- 5 law words.
    const EXPECTED_REFUSE: &[(&str, &str)] = &[
        ("sm121a", "arb399a|sts|ur03f|off_800000"),
        ("sm121a", "arb399a|sts|ur03f|off_ffffff"),
        ("sm121a", "arb399a|sts|ur4|off_800000"),
        ("sm121a", "arb399a|sts|ur4|off_800001"),
        ("sm121a", "arb399a|sts|ur4|off_ffffff"),
    ];
    let mut refused: Vec<(String, String)> = Vec::new();
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, vendor) in LAW399 {
            if !tag.contains("off_8") && !tag.contains("off_f") {
                continue;
            } // negative words only (zero/positive spellings in t399_3)
            if tag.contains("|rz|") {
                // RZ-base vendor text ('[UR4+-0x800000]') decodes exact but
                // mints refuse-closed: the RZ-elided form routes to *_AURI
                // rows and (a) LDSM has no AURI row at all, (b) LDS.S8's
                // ''-group AURI row cannot carry the S8 mod (BUG-132
                // silent-mod-drop cordon). Encode-side hole, pre-existing,
                // OUT OF SCOPE of this decode-glyph fix. STS has a working
                // AURI row, so its RZ-elided mint DOES close the circle.
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
            // sm121a encode-side hole (pinned in t399_2): the STS_ARURI_R
            // row there rejects every negative offset value. The decode-side
            // vendor law already holds on sm121a (t399_1); the mint must
            // keep refusing loudly until the encode row is repaired.
            assert!(
                enc(&t, "STS [R10+UR4-0x1], R30 ;").is_err(),
                "[sm121a] STS neg-offset mint unexpectedly encodes (hole closed? close it)"
            );
        } else {
            let w = enc(&t, "STS [R10+UR4-0x1], R30 ;").unwrap();
            assert_eq!(
                dec(&t, &idx, w).unwrap(),
                "STS [R10+UR4+-0x1], R30",
                "[{leg}] spelling law STS neg"
            );
        }
        // RZ-elided mint cordons (pre-existing encode-side holes; the
        // decode-side vendor render is pinned exact in t399_1): LDS.S8's
        // ''-group AURI row cannot carry S8 (BUG-132 cordon), LDSM has no
        // AURI row at all; both must keep refusing loudly, never
        // silently mint a different variant.
        for bad in ["LDS.S8 R93, [UR4+-0x1] ;", "LDSM.16.M88 R16, [UR4+-0x1] ;"] {
            assert!(
                enc(&t, bad).is_err(),
                "[{leg}] RZ-elided mint unexpectedly encodes: {bad}"
            );
        }
    }
}

/// t399_4: 412-kand posture UNTOUCHED -- UR-sentinel words keep the
/// pre-existing engine renders (UR255 on the 8-bit ur field, UR511 on the
/// 9-bit field; vendor prints URZ). Per-leg renders machine-pinned from
/// measure_post399. If this pin breaks, close 412, don't bend the pin.
#[test]
fn t399_4_ur_sentinel_posture_untouched() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, tag, renders) in POSTURE412 {
            let got = dec(&t, &idx, *word)
                .unwrap_or_else(|| panic!("[{leg}] {tag} fell HOLE: route changed"));
            assert_eq!(
                &got, &renders[li],
                "[{leg}] {tag} 412-arm landed? then close 412, don't bend this pin"
            );
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

/// t399_6: 414-kand posture UNTOUCHED -- sm121a dedicated narrow-imm rows
/// (STS.U8_ARURI_R with imm 13b@40; STS.U8_ARI_II with imm 12b@41; the
/// LDS.128 *-II/-? narrow family) keep the legacy '-0x' glyph and the
/// legacy claim route. The vendor '+-0x' law (t399_1) stays scoped to the
/// measured 24-bit sub_imm1 window; narrower windows are an unmeasured
/// class (posture pinned; closing them needs their own per-row vendor
/// lattice).
#[test]
fn t399_6_sm121a_narrow_imm_posture_untouched() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    // This word mints through the 24-bit STS_ARURI_R "U8" encoder row;
    // on sm121a the DECODER routes it to the dedicated narrow-imm row
    // STS.U8_ARURI_R (imm 13b@40) -- value 0x1001 reads as -0xfff there
    // and keeps the legacy '-0x' glyph. Vendor (nvdisasm SM121a raw -b)
    // prints '+0x1001' for the same payload => 414-kand decoder-side
    // narrow-window defect, PRE-EXISTING (engine '-0xfff' both before and
    // after 399); pinned as posture. If this pin breaks, close 414
    // properly -- don't bend the pin.
    let w = enc(&t, "STS.U8 [R5+UR10-0xfff], RZ ;").unwrap();
    let got = dec(&t, &idx, w).unwrap();
    assert_eq!(
        got, "STS.U8 [R5+UR10-0xfff], RZ",
        "sm121a narrow-imm posture drifted (414 arm landed?)"
    );
    // The identical payload on the legacy legs claims the 24-bit
    // sub_imm1 row: 0x1001 is positive there -- plain '+0x', no '+-'.
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t2 = tab(leg);
        let idx2 = DecodeIndex::build(&t2);
        let got2 = dec(&t2, &idx2, w).unwrap();
        assert_eq!(
            got2, "STS.U8 [R5+UR10+0x1001], RZ",
            "[{leg}] 24-bit law drifted on the migrated word"
        );
    }
}
