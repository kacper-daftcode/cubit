//! BUG-409 pins (F2-iter224, loop5/blind front2, 2026-09-08): sm100a
//! LDC_R_cAI|S16 vs LDC_R_cARI|S16 claim priority on the S16 word window
//! (canonical d908ee9 -> 2f31522 one-row vm|b37 graft + cubit decoder arm
//! `select_best_candidate`; sm103a/sm120/sm121a byte-invariant, isolated by
//! attr409 delta=0 x34 cells).
//!
//! Vendor law (arb402 C-row 108 probes + arb409 34 probes, nvdisasm 13.3.73
//! raw -b x4 models SM100a/SM103a/SM120/SM121a unanimous on EVERY probe,
//! DIVERGENT=0): on the S16 window the sub_r1 slot [31:24] == 0xff (RZ
//! sentinel) renders the pure-imm cAI form `LDC.S16 Rn, c[bank][off]`; b37
//! (dead) and b59 (inert; BUG-402 D) are dropped from the print. Slot values
//! != 0xff render the register-carried form `c[bank][R<n>+off]` with the
//! same b37/b59 inertness.
//!
//! Defect (measure409_pre on publish cubit_py-7ee1f076, 2279bbb2, canonical
//! d908ee9 tables): the bug172-era cARI sibling row strict-matches the same
//! window (its sub_imm0/sub_imm2 fields exclude the family bits b39/b43 from
//! match_mask) and won the decoder unexplained-variance tiebreak whenever
//! the word's diff-from-cAI-and_base sat in the cAI variable-only zone
//! ({b59} pre-409, {b37, b59} with the graft): six sff-flip cells misrouted
//! to a bogus cARI print (e.g. b59 word -> `c[0x20][0x880]`; b37 word ->
//! `c[0x0][0x8a0]`). Core word (no flips) claimed cAI on the key-length
//! tiebreak, so the zero-corpus class hid behind 402 postures.
//!
//! Fix: ENGINE arm (src/decoder.rs): LDC_R_cARI|S16-first + a strict
//! LDC_R_cAI|S16 candidate -> prefer cAI. True cARI-shaped words (slot !=
//! 0xff) fail the cAI care window and are untouched (t409_2 pins them
//! byte-identical = 418-kand residual: the cARI|S16 row's own era geometry
//! prints unadjusted offsets e.g. `R5+0x880` vs vendor `R5+0x22` -- separate
//! follow-up, zero corpus exposure). Graft: sm100a LDC_R_cAI|S16
//! variable_mask |= (1<<37) (b37 class membership; b59 was BUG-402 D).
//! Corpus exposure ZERO (census402: no S16 claims on either row, ab240).
//!
//! Witness data: tests/bug409_data.inc (machine-built by
//! work/bug409x/gen409pins.py from arb409_law.json +
//! measure409_{pre,post}_*.json; no hand hex; self-checks abort rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug409_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t)
        .map(|d| (to_sass(&d), format!("{}|{}", d.key, d.mod_group)))
        .ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

/// t409_1: the S16 RZ-sentinel window (sff cells incl. the four registered
/// 402-era postures) decodes vendor-exact on sm100a and claims LDC_R_cAI.
#[test]
fn t409_1_sff_window_vendor_exact() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, vendor) in PROBES409 {
        if !SFF_FIXED409.contains(&tag) {
            continue;
        }
        let (got, km) = dec(&t, &idx, word).unwrap_or_else(|| panic!("[{tag}] hole"));
        assert_eq!(got, vendor, "[{tag}] render drift");
        assert_eq!(km, "LDC_R_cAI|S16", "[{tag}] misrouted: {km}");
        n += 1;
    }
    assert_eq!(n, 7, "sff set drifted");
}

/// t409_2 (CLOSED F2-iter227, BUG-418, with attribution): true
/// cARI-shaped words (sub_r1 slot != 0xff) decode VENDOR-EXACT since the
/// 418 donor-shape graft (era geometry `R5+0x880` defunct; historic byte
/// renders preserved in POSTURE418_100A and cross-pinned by t418_2 as
/// must-NOT-reappear attribution capture). This pin used to assert the
/// vendor-WRONG posture byte-identical (contract: flip here, not
/// silently); the 418 fix flips it to the closed contract.
#[test]
fn t409_2_cari_shaped_closed_vendor_exact() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, vendor) in PROBES409 {
        let Some((_, pre_txt)) = POSTURE418_100A.iter().find(|(tg, _)| *tg == tag) else {
            continue;
        };
        let (got, km) = dec(&t, &idx, word).unwrap_or_else(|| panic!("[{tag}] hole"));
        assert_eq!(&got, vendor, "[{tag}] 418-closed contract broken");
        assert_ne!(&got, pre_txt, "[{tag}] era render reappeared");
        assert_eq!(km, "LDC_R_cARI|S16", "[{tag}] arm fired where it must not");
        n += 1;
    }
    assert_eq!(n, 27, "closed set drifted");
}

/// t409_3: sibling legs byte-invariant end-to-end (engine text + claim),
/// 34 cells x3 legs == the pre-fix publish captures. 411/413/418 scope:
/// sm103a/sm120 = exact x6 + HOLE x28 (sibling S16 holes = donor-parity
/// owner decision per t172_6); sm121a = HOLE x34 (no S16 rows).
#[test]
fn t409_3_sibling_legs_byte_invariant() {
    for (arch, legtab) in [
        ("sm103a", LEG409_SM103A),
        ("sm120", LEG409_SM120),
        ("sm121a", LEG409_SM121A),
    ] {
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (word, tag, _vendor) in PROBES409 {
            let (_, want) = legtab.iter().find(|(tg, _)| *tg == tag).unwrap();
            let (wtxt, wkm) = want.rsplit_once("::").unwrap();
            if wtxt.starts_with("ERR") {
                assert!(
                    idx.decode(word, 0, &t).is_err(),
                    "[{arch} {tag}] expected HOLE, got decode"
                );
            } else {
                let (got, km) =
                    dec(&t, &idx, word).unwrap_or_else(|| panic!("[{arch} {tag}] hole"));
                assert_eq!(
                    (got.as_str(), km.as_str()),
                    (wtxt, wkm),
                    "[{arch} {tag}] drift"
                );
            }
            n += 1;
        }
        assert_eq!(n, 34);
    }
}

/// t409_4: mint circle on the landed row: authored pure-imm S16 texts mint
/// post-402 window geometry; decode of inert-lifted words (b37/b59) returns
/// the same text; re-encode drops exactly the vendor-inert bits and lands on
/// the canonical cell (roundtrip EXACT modulo {b37, b59} inerts).
#[test]
fn t409_4_mint_circle_inert_drop() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let probe = |tag: &str| -> u128 { PROBES409.iter().find(|(_, tg, _)| *tg == tag).unwrap().0 };
    let core = probe("sff|none");
    for (base_tag, want_text) in [("sff|b37", "core"), ("sff|b59", "core")] {
        let w = probe(base_tag);
        let (got, km) = dec(&t, &idx, w).unwrap();
        assert_eq!(km, "LDC_R_cAI|S16");
        let (want, _) = if want_text == "core" {
            dec(&t, &idx, core).unwrap()
        } else {
            unreachable!()
        };
        assert_eq!(got, want, "[{base_tag}] inert render drift");
        // re-encode drops the inert bit and lands on the canonical cell
        // (payload domain [95:0]; ctrl prefix [127:96) is authored by the
        // encoder from the epoch rules, not carried by the text):
        const M96: u128 = (1u128 << 96) - 1;
        let ins = parse_sass(&format!("{got} ;"), 0).unwrap();
        let remint = encode_instruction(&ins, &t).unwrap();
        assert_eq!(
            remint & M96,
            core & M96,
            "[{base_tag}] canonical cell drift"
        );
    }
    // maxpos17/allones22 land on their own canonical cells (window geometry):
    for tag in ["sff|maxpos17", "sff|allones22"] {
        let w = probe(tag);
        let (txt, _) = dec(&t, &idx, w).unwrap();
        let ins = parse_sass(&format!("{txt} ;"), 0).unwrap();
        let remint = encode_instruction(&ins, &t).unwrap();
        let (txt2, _) = dec(&t, &idx, remint).unwrap();
        assert_eq!(txt, txt2, "[{tag}] mint circle");
        // b37 is vendor-inert: the canonical mint does NOT carry it
        assert_eq!(remint >> 37 & 1, 0, "[{tag}] mint must not set inert b37");
    }
    // vendor text authored -> mints; decode circle closed
    let w = enc(&t, "@P0 LDC.S16 R0, c[0x0][0x22] ;").expect("core mint");
    const M96B: u128 = (1u128 << 96) - 1;
    assert_eq!(
        w & M96B,
        core & M96B,
        "core cell mint drift (payload domain)"
    );
}

/// t409_5: graft hygiene + canonical pin.
#[test]
fn t409_5_graft_hygiene_source_pin() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap() == "bd2e25464208f9be6abc1e3c7475ca34914ad095", // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 23976eb (ride F2-iter272 = BUG-465 modsub plain E*L2.256 lattice; was 4968113 (ride F2-iter270 = BUG-464 plain ARURI64; was 5078067 ride F2-iter268 = BUG-432R donor-128E; was a6e3c9e ride F2-iter267 = BUG-432 ari-cavity; was 700524e698304dcbf1a3884f72f05abff609b8aa BUG-453 graft / a64b82bf F2-iter266 BUG-463; = BUG-452 narrow, ride-after 4ee843162216e75d037135b5907c819759471296, = BUG-454 graft, ride-after 589be874 (= BUG-450) (= BUG-450 graft, ride-after 099faa0 (= BUG-447) [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, was 1810912 = BUG-435+434, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    // row shape: and_base invariant at the pinned value, vm carries b37+b59
    let tabj: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm100a.json").unwrap()).unwrap();
    let mg = &tabj["instructions"]["LDC_R_cAI"]["mod_groups"]["S16"];
    let vm = u128::from_str_radix(
        mg["variable_mask"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let ab = u128::from_str_radix(
        mg["and_base"].as_str().unwrap().trim_start_matches("0x"),
        16,
    )
    .unwrap();
    assert_eq!(
        mg["and_base"].as_str().unwrap(),
        "0xe20000000060000000880ff000b82"
    );
    assert_eq!(vm >> 37 & 1, 1, "graft missing b37");
    assert_eq!(vm >> 59 & 1, 1, "402 b59 inert bit lost");
    assert_eq!(ab >> 37 & 1, 0, "and_base must stay b37-clean");
}
