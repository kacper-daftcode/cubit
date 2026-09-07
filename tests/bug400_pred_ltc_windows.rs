//! BUG-400 pins (F2-iter221, loop5/blind front2, 2026-09-07): pred/LTC
//! window [64:72) vendor-true declarations on dARI/ARI LDG/LD rows (ONE
//! canonical graft 54973d3; ENGINE src ZERO changes; pure table graft +
//! measured-monotone inert relax).
//!
//! Defect (registration 400-kand LOW, 388.md sec.7; verify388post residuum
//! 400 = 77 WRONG cells x 11 carriers {b64..b69, p2:topbound}): claiming
//! rows declared nothing over [64:70) with vm pinning the window to 0, so
//! decode rode the mem-addr BROAD fallback and dropped the pred/LTC bits
//! from printed text, and the encoder loud-refused every vendor-true
//! trailing-pred/LTC variant text on these rows.
//!
//! Vendor law (arb400 307 probes + arb400b 198 cross-combo probes, on the
//! 11 corpus-derived carriers + sm121a synth frame; nvdisasm 13.3.73 raw
//! -b x4 models SM100a/SM103a/SM120/SM121a, DIVERGENT=0 on every probe;
//! arb400b 165/165 cross-checks vs the pv/ltc baselines MATCH):
//!   [64:68) = inv4 trailing-pred window: v=0 elided, v in 1..7 -> P(7-v),
//!             v=8 -> !PT, v in 9..15 -> !P(15-v)  (== shipped pred_inv4)
//!   [68:70) = LTC code: 1/2/3 -> .LTC64B/.LTC128B/.LTC256B (composes
//!             freely with pred and size/scope mods)
//!   b70/b71 = INERT on every measured row (also under pv x ltc crosses).
//!
//! Graft (adding-only + measured-monotone-relax; ab invariant on every
//! pre-existing row): plain keys += LTC mgs (ab |= code<<68), NEW
//! <KEY>_P keys with pred_inv4 4b@64 tok=last (sm121a LDG_R_dARI_P
//! precedent), vm |= (3<<70) on the 11 base mgs (measured-inert bits so
//! inert-junk strict-claims the PLAIN mg, never an LTC-named one via the
//! longest-mg broad tiebreak). v=0 strict-claims the shorter plain key;
//! v!=0 fails strict on plain (window constant) and strict-claims _P.
//!
//! Witness data: tests/bug400_data.inc (machine-built by
//! work/bug400/gen400pins.py from arb400_law.json + arb400b_law.json +
//! publish cubit_py-513226f9 posture renders; no hand hex).
//!
//! Out of scope (stands registered): 415-kand ('?AR' LDS.S8/U8_R_AR
//! claim-boundary, 9 WRONG cells verify388post) -- posture pinned UNTOUCHED
//! in t400_6; un-grafted sibling mgs junk-drop renders pinned UNTOUCHED
//! (t400_6, E,U16 class); encode refuse-closed for absent LTC combos
//! (t400_7).

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
fn leg_of(tag: &str) -> &'static str {
    if tag.starts_with("sm103a") { "sm103a" }
    else if tag.starts_with("sm120") { "sm120" }
    else if tag.starts_with("sm121a") || tag.starts_with("ldg121a") { "sm121a" }
    else { "sm100a" }
}

include!("bug400_data.inc");

/// payload mask: strip ctrl upper32 and the measured-inert b70/b71 window
/// (junk-drop canon for inert bits; BUG-388 INC doctrine).
const PAYLOAD: u128 = ((1u128 << 96) - 1) & !(0x3u128 << 70);

/// t400_1: vendor law x198 words on all 4 legs (11 carriers x18 probes).
#[test]
fn t400_1_vendor_law_all_legs() {
    let mut legs: std::collections::HashMap<&str, (IsaTable, DecodeIndex)> = Default::default();
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        legs.insert(leg, (t, idx));
    }
    for (word, tag, vendor) in LAW400 {
        let leg = leg_of(tag);
        let (t, idx) = legs.get(leg).unwrap();
        let got = dec(t, idx, *word)
            .unwrap_or_else(|| panic!("[{leg}] {tag} must decode post-400"));
        assert_eq!(&got, vendor, "[{leg}] {tag} render diverges from vendor x4 law");
    }
}

/// t400_2: claim routing x198 (v=0/inert -> plain key+base mg;
/// pred!=0 -> _P key; LTC -> LTC-named mg; combos -> _P x LTC mg).
#[test]
fn t400_2_claim_routing() {
    let route: std::collections::HashMap<&str, (&str, &str)> =
        ROUTE400.iter().map(|(t, k, m)| (*t, (*k, *m))).collect();
    let mut legs: std::collections::HashMap<&str, (IsaTable, DecodeIndex)> = Default::default();
    for (word, tag, _v) in LAW400 {
        let leg = leg_of(tag);
        legs.entry(leg).or_insert_with(|| {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            (t, idx)
        });
        let (t, idx) = legs.get(leg).unwrap();
        let d = idx
            .decode(*word, 0, t)
            .unwrap_or_else(|_| panic!("[{leg}] {tag} HOLE in route pin"));
        let (wk, wmg) = route[tag];
        assert_eq!(
            (d.key.as_str(), d.mod_group.as_str()),
            (wk, wmg),
            "[{leg}] {tag} claim moved: {}|{}",
            d.key,
            d.mod_group
        );
    }
}

/// t400_3: decode -> text -> encode circle. pred/LTC windows round-trip
/// byte-exact on the payload; inert b70/b71 junk drops canonically (mask);
/// second render == same text (fixed point).
#[test]
fn t400_3_decode_text_encode_circle() {
    let mut legs: std::collections::HashMap<&str, (IsaTable, DecodeIndex)> = Default::default();
    for (word, tag, vendor) in LAW400.iter().chain(LAW400_XB.iter()) {
        let leg = leg_of(tag);
        legs.entry(leg).or_insert_with(|| {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            (t, idx)
        });
        let (t, idx) = legs.get(leg).unwrap();
        let text = dec(t, idx, *word)
            .unwrap_or_else(|| panic!("[{leg}] {tag} must decode post-400"));
        assert_eq!(&text, vendor, "[{leg}] {tag} law diverge");
        let back = enc(t, &format!(" {text} ;"))
            .unwrap_or_else(|e| panic!("[{leg}] {tag} mint failed: {e}"));
        assert_eq!(
            back & PAYLOAD,
            word & PAYLOAD,
            "[{leg}] {tag} circle payload diff (back {back:#034x} vs word {word:#034x})"
        );
        let second = dec(t, idx, back)
            .unwrap_or_else(|| panic!("[{leg}] {tag} second decode HOLE"));
        assert_eq!(second, text, "[{leg}] {tag} render not a fixed point");
    }
}

/// t400_4: inert-cross law (arb400b): b70/b71/ball x pred x LTC words
/// render exactly the pv1ltc1 baseline.
#[test]
fn t400_4_inert_cross() {
    let mut legs: std::collections::HashMap<&str, (IsaTable, DecodeIndex)> = Default::default();
    for (word, tag, vendor) in LAW400_XB {
        let leg = leg_of(tag);
        legs.entry(leg).or_insert_with(|| {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            (t, idx)
        });
        let (t, idx) = legs.get(leg).unwrap();
        let got = dec(t, idx, *word)
            .unwrap_or_else(|| panic!("[{leg}] {tag} must decode post-400"));
        assert_eq!(&got, vendor, "[{leg}] {tag} inert-cross diverges");
    }
}

/// t400_5: sm121a dARI synth control frame (out-of-corpus; claims the
/// pre-existing LDG_R_dARI_P '128,E' family; decode == vendor law).
#[test]
fn t400_5_synth_control() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (word, tag, vendor) in LAW400_SYN {
        let got = dec(&t, &idx, *word)
            .unwrap_or_else(|| panic!("[sm121a] {tag} synth frame HOLE"));
        assert_eq!(&got, vendor, "[sm121a] {tag} synth diverges");
    }
}

/// t400_6: postures UNTOUCHED -- (a) un-grafted sibling mg (E,U16 class)
/// junk words keep the pre-graft broad-fallback clean render (junk drop);
/// (b) 415-kand ogon: '?AR' LDS.S8 claim-boundary render pinned.
#[test]
fn t400_6_postures_untouched() {
    let t100 = tab("sm100a");
    let i100 = DecodeIndex::build(&t100);
    let t121 = tab("sm121a");
    let i121 = DecodeIndex::build(&t121);
    for (word, tag, pre) in POSTURE400 {
        let (t, idx) = if tag.contains("|sm100a|") { (&t100, &i100) } else { (&t121, &i121) };
        let got = dec(t, idx, *word)
            .unwrap_or_else(|| panic!("{tag} posture HOLE"));
        assert_eq!(&got, pre, "{tag} posture moved (must stay status quo)");
    }
}

/// t400_7: encode refuse-closed on absent LTC combos (unaffected surface):
/// 'E,LTC64B,U8' / 'E,LTC256B,U16' mgs are NOT grafted (LTC lattice closed
/// only on the 11 measured carriers) -- mints must fail loud, not silently
/// drop the LTC mod.
#[test]
fn t400_7_encode_refuse_absent_combos() {
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        for text in [
            "LDG.E.LTC64B.U8 R33, desc[UR12][R12.64]",
            "LDG.E.LTC256B.U16 R33, desc[UR12][R12.64]",
            "LDG.E.LTC256B.U8 R33, desc[UR12][R12.64]",
        ] {
            assert!(
                enc(&t, text).is_err(),
                "[{leg}] absent LTC combo must refuse-closed: {text}"
            );
        }
    }
}
