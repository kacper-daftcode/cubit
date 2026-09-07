//! BUG-398 (F2-iter220): sm121a cAI-family close-out
//!   A) ENGINE: cAURI printer dispatch + parser operand typing + encoder
//!      cAI-shaped fallback alias (legacy legs keep the BUG-151/152 world:
//!      UR index rides the _cAI key with sub_ur1@24; sm121a owns the
//!      dedicated LDCU_UR_cAURI row). Closes the '?cAURI' fallback render
//!      (398-kand: 17 WRONG cells in verify388post = 8 idx-lattice +
//!      9 '?AR-adjacent' -- the '?AR' LDS-class stays registered, see
//!      t398_5; plus the full 410-kand corpus class: 101 claims / 49
//!      distinct words on sm121a, census401c/398).
//!   C) TABLE graft (canonical 96f196b -> NEW, patch398.py): vendor-inert
//!      junk band [64..72) relaxed on LDC_R_cAI {"",64}, LDCU_UR_cAI
//!      {"",64,128,U8}, LDCU_UR_cAURI {"",64,128,U8}. The arb388d
//!      ball='[RZ]' reading was the BUG-174 zero-offset law (off0-without-
//!      ball control renders identically). LDC.U16_R_cAI EXCLUDED:
//!      b64..b67 is the pred window (400-class), pinned LOUD HOLE below.
//! Encode-side status: UR-carried mints were LOUD-REFUSED on every leg
//! pre-fix ("constmem UR has no place..." via the cAI key); post-fix they
//! encode on all four legs (alias to _cAI rows on legacy legs). The bare
//! `c[b][URZ]` mint stays refused everywhere (no row carries a pure URZ
//! const slot; pre-existing, up since BUG-162) -- pinned in t398_5.
//! Witness data: tests/bug398_data.inc (machine-built by
//! work/bug398/gen398pins.py; no hand hex).

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

include!("bug398_data.inc");

const JUNK_BAND: u128 = 0xffu128 << 64;

/// t398_1: vendor law on sm121a: every LAW398 + LAW398B word decodes to the
/// x4-unanimous vendor text (A idx/sign/bank/eled lattice + corp x49 +
/// C junk-band singles/balls/174-law + sized mgs).
#[test]
fn t398_1_vendor_law_sm121a() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (lo, hi, tag, vendor) in LAW398.iter().chain(LAW398B.iter()) {
        let got = dec(&t, &idx, ((*lo as u128) | ((*hi as u128) << 64)))
            .unwrap_or_else(|| panic!("[sm121a] {tag} fell HOLE -- graft routing lost"));
        assert_eq!(&got, vendor, "[sm121a] {tag} render != vendor x4 law");
    }
}

/// t398_2: claim-routing pins (post-fix partition; derived at pin-build).
/// cAURI iff idx != 255, cAI on the 255-elide tie (shorter-key tiebreak),
/// junk-band flips stay inside the family rows.
#[test]
fn t398_2_claim_routing() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let route: std::collections::HashMap<&str, (&str, &str)> =
        ROUTE398.iter().map(|(t, k, mg)| (*t, (*k, *mg))).collect();
    for (lo, hi, tag, _v) in LAW398.iter().chain(LAW398B.iter()) {
        let d = idx
            .decode(((*lo as u128) | ((*hi as u128) << 64)), 0, &t)
            .unwrap_or_else(|_| panic!("[sm121a] {tag} HOLE in route pin"));
        let (wk, wmg) = route[*tag];
        assert_eq!(
            (d.key.as_str(), d.mod_group.as_str()),
            (wk, wmg),
            "[sm121a] {tag} claim moved: {}|{}",
            d.key,
            d.mod_group
        );
    }
}

/// t398_3: decode -> text -> encode circle. A/corp words (junk-free): payload
/// = original word. C-class (junk band set): the canonical junk-drop law --
/// band bits (variable, no field) are dropped on re-encode (BUG-388 INC
/// doctrine), second render == same text.
#[test]
fn t398_3_decode_text_encode_circle() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (lo, hi, tag, _v) in LAW398.iter().chain(LAW398B.iter()) {
        let w = ((*lo as u128) | ((*hi as u128) << 64)) & !JUNK_BAND & ((1u128 << 96) - 1);
        let text = dec(&t, &idx, ((*lo as u128) | ((*hi as u128) << 64))).unwrap();
        let pw = (*lo as u128) | ((*hi as u128) << 64);
        if text.contains("URZ]") || text.contains("URZ+") {
            // bare-URZ const slot stays un-mintable on every leg (t398_5);
            // only the URZ glyph is excluded from the circle.
            continue;
        }
        let back = enc(&t, &format!(" {text} ;"))
            .unwrap_or_else(|e| panic!("[sm121a] {tag} mint failed: {e}"));
        assert_eq!(
            back & !JUNK_BAND & ((1u128 << 96) - 1),
            w,
            "[sm121a] {tag} circle payload diff"
        );
        // second render of the encoded word == the text (fixed point)
        let r2 = dec(&t, &idx, back).unwrap();
        assert_eq!(r2, text, "[sm121a] {tag} second render drifted: {r2}");
    }
}

/// t398_4: 410-kand closure -- all 49 corpus '?cAURI' words now decode to
/// the vendor-exact UR-carried const address (posture flips t388_5/t401_4
/// carry the attribution; this pin freezes the corpus set itself).
#[test]
fn t398_4_corpus_qcauri_closure() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0usize;
    for (lo, hi, tag, vendor) in LAW398 {
        if !tag.starts_with("corp|") {
            continue;
        }
        n += 1;
        let got = dec(&t, &idx, ((*lo as u128) | ((*hi as u128) << 64))).unwrap();
        assert_eq!(&got, vendor, "[sm121a] {tag} corpus word != vendor");
        assert!(!got.contains('?'), "[sm121a] {tag} still opaque: {got}");
    }
    assert_eq!(
        n, 49,
        "corpus coverage drifted (census401c: 101 claims / 49 distinct)"
    );
}

/// t398_5: postures OUT OF SCOPE of this fix, pinned loud/unchanged:
///  (a) 400-class: LDC.U16_R_cAI sm121a [64..72) = pred window, NOT
///      junk-relaxed -> flip words stay HOLE (no fake render);
///  (b) bare `c[b][URZ]` mint refuses on every leg (pre-existing encode
///      hole, up since BUG-162);
///  (c) legacy legs: corpus claim renders byte-stable pre==post
///      (LEGACY_PRE398 recorded on publish cubit_py-ccd2052e + canonical
///      96f196b; the parser/encoder alias must not change legacy decode,
///      and legacy encode of UR-carried text must keep working (t151_2).
#[test]
fn t398_5_postures() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (lo, hi, tag) in POSTURE_HOLE398 {
        assert!(dec(&t, &idx, ((*lo as u128) | ((*hi as u128) << 64))).is_none(),
            "[sm121a] {tag} (400-class pred window) unexpectedly decodes -- close 400 first, don't bend this pin");
    }
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let tb = tab(leg);
        assert!(enc(&tb, " LDCU UR5, c[0x0][URZ] ;").is_err(),
            "[{leg}] bare URZ const slot unexpectedly mints -- register as encode hole fix, don't bend this pin");
    }
    for (leg, lo, hi, tag, pre_text) in LEGACY_PRE398 {
        let tb = tab(leg);
        let i2 = DecodeIndex::build(&tb);
        let got = dec(&tb, &i2, ((*lo as u128) | ((*hi as u128) << 64)))
            .unwrap_or_else(|| panic!("[{leg}] {tag} corpus claim lost"));
        assert_eq!(
            &got, pre_text,
            "[{leg}] {tag} legacy render drifted post-398"
        );
    }
}

/// t398_6: mint side -- UR-carried const text encodes on all four legs now
/// (sm121a routes the dedicated cAURI row; legacy legs route _cAI via the
/// encoder alias). Pre-fix all four refused.
#[test]
fn t398_6_ur_carried_mint_all_legs() {
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let tb = tab(leg);
        let i2 = DecodeIndex::build(&tb);
        for txt in [
            "LDCU UR5, c[0x0][UR4+0x1]",
            "LDCU UR5, c[0x0][UR5+-0x10000]",
        ] {
            let w = enc(&tb, &format!(" {txt} ;"))
                .unwrap_or_else(|e| panic!("[{leg}] mint failed: {e}"));
            let r = dec(&tb, &i2, w).unwrap_or_else(|| panic!("[{leg}] redecode failed"));
            assert_eq!(&r, txt, "[{leg}] mint roundtrip drifted: {r}");
        }
        // URZ-sentinel spelling of the same address mints to 0xff and
        // re-renders in the URZ/elide glyph (leg-variant), keeps encoding.
        let w = enc(&tb, " LDCU UR5, c[0x0][UR255+0x1] ;")
            .unwrap_or_else(|e| panic!("[{leg}] UR255 mint failed: {e}"));
        let r = dec(&tb, &i2, w).unwrap();
        assert!(
            r == "LDCU UR5, c[0x0][0x1]" || r.contains("URZ") || r.contains("UR255"),
            "[{leg}] UR255 sentinel render unexpected: {r}"
        );
    }
}
