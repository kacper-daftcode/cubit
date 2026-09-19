//! BUG-463 pins (F2-iter266, loop5/blind front2, 2026-09-14): nNA EFL2.256
//! dARI frame donor-symmetric holes -- (a) vendor-noop band vm-relax
//! (STG {72,73,74,87,92..95}; LDG {92..95}), (b) LTC-width selektor [74:73]
//! klucze LTC64B/128B/256B absent x4 (ab |= selbits, forma = NA LTC64B
//! delta {73}; claim_forbid BUG-452 verbatim; count=None).
//! Vendor law (arb463 44 + arb463b 12 + arb463c 5 sond nvdisasm 13.3.73
//! raw -b x4 AGREE EVERY/DIVERGENT=0): band noop pod pole4/pol00/polff/
//! @P0/rich; pol sweep {00,01,64,7f,ff} (0xff elided, trailer PRZED
//! pred-out); kills b91 + ra255 (452) rc=1 x4 obu selektorow; URZ/RZ glyph
//! legalne; era-b118/reuse-b122 legalne; imm17 signed '+-'. Canonical
//! f58ed16 -> a64b82b (patch463.py replayable+idempotent, audity A0-A7
//! fail-closed; A1 NONE->GRAFT 3752 / STABLE 252 / BAD 0).
//! Witness: tests/bug463_data.inc (maszynowe gen463pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug463_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t463_1: heal-decode -- 200 slow band/LTC (50 tagow x4 nogi) dekoduje
/// DOKLADNIE tekst vendora (nvdisasm); pre-fix HOLE maszynowo potwierdzone
/// (gen, cold publish eace8461 + f58ed16).
#[test]
fn t463_1_heal_decode() {
    for (w, leg, want) in HEAL463 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t463_2: anchors -- 16 komorek (S.base/S.pol00.base/L.base/L.flip72 x4)
/// pre == post == vendor (L.flip72 = pol-bit7 keeper, NIE noop).
#[test]
fn t463_2_anchors() {
    for (w, leg, want) in ANCH463 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] anchor {w:#034x}");
    }
}

/// t463_3: kill-preserve -- b91 + ra255 (452) pod LTC64B/LTC128B dekoduje
/// HOLE x4 nogi (claim_forbid przeniesiony verbatim na nowe klucze).
#[test]
fn t463_3_kill_preserve() {
    for (w, leg) in KILL463 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(dec(&t, &idx, *w), None, "[{leg}] kill-claim {w:#034x}");
    }
}

/// t463_4: mint-circle -- 48 probek (12 form x4 nogi): encode textu
/// mintuje selektor b[74:73] poprawnie i decode(enc(txt)) == txt.
#[test]
fn t463_4_mint_circle() {
    for (leg, text) in MINTCIR463 {
        let t = tab(leg);
        let w = enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] mint {text}: {e}"));
        let sel = ((w >> 73) & 3) as u8;
        let want: u8 = if text.contains("LTC64B") {
            1
        } else if text.contains("LTC128B") {
            2
        } else if text.contains("LTC256B") {
            3
        } else {
            0
        };
        assert_eq!(sel, want, "[{leg}] selector {text} -> {sel}");
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, w);
        assert_eq!(got.as_deref(), Some(*text), "[{leg}] circle {text}");
    }
}

/// t463_5: mint-refuse -- ra=255/RZ pod kazdym selektorem LTC odmawia z
/// cytatem BUG-452 x4 nogi (claim_forbid arm encode-side z 452).
#[test]
fn t463_5_mint_refuse() {
    for (leg, text) in MINTREF463 {
        let t = tab(leg);
        let e = enc(&t, text).expect_err("mint must refuse");
        assert!(e.contains("BUG-452"), "[{leg}] cite: {e}");
    }
}

/// t463_6: data-attribution -- census kluczy/cf/LTC/_src463 per noga
/// (6791/33/12/12 x2, 7932/25/12/12, 15758/29/12/12; pseudo-rekordy
/// _errata_* pomijane), SOURCE pin a64b82b.
#[test]
fn t463_6_census_attribution() {
    // FLIP-ride (BUG-464, F2-iter270, canonical 4968113): +6 kluczy/noga
    // (plain nNA ARURI64 EFL2.256 lattice; cf/LTC/_src463 niezmienione) --
    // licznik loader-side jak poprzednio (121a loader-visible +6 -> 15764;
    // raw JSON 15766, offset -2 pre-existing).
    // FLIP-ride (BUG-465, F2-iter272, canonical 23976eb): +1146 kluczy/noga
    // (modsub plain E*L2.256 lattice; cf/LTC/_src463 niezmienione) --
    // loader-visible jak poprzednio (121a 16910; raw 16912, offset -2). flip-ride 467: po delete BUG-467 loader 16905 / raw 16907.
    let want = [
        ("sm100a", 14879u32, 1170u32, 12u32, 12u32), // RIDE476 (F2-iter299, canonical c88778e): +11 keys +1 cf (476a NA-graft + 476b forbid) -> 14879/1170 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 33->1166 (claim_forbid dziedziczone z donorow dARI modsub graft) // was: 13721/33 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm103a", 14879, 1170, 12, 12), // RIDE476 (F2-iter299, canonical c88778e): +11 keys +1 cf -> 14879/1170 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 33->1166 // was: 13721/33 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm120", 16015, 1168, 12, 12), // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim): +1 cf // RIDE459a (F2-iter301, canonical 96372cb): -1 sm120 key (459a junk-mg "" / 64 DELETE -> key-del UR_II_..._UP_UP) -> forms 16015, variants -4=17631; sm121a variants -4=26385; cf stoi // RIDE476 (F2-iter299, canonical c88778e): +11 keys +1 cf -> 16016/1167 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 25->1164 // was: 14859/25 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 11405 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) // was: flip-ride 467: -3 sm120 keys (degen era delete)
        ("sm121a", 23831, 1184, 12, 12), // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim) (121a): +1 cf // RIDE476 (F2-iter299, canonical c88778e): +8 keys -> 23831 (raw 23833 - 2 errata; licznik pomija rekordy bez mod_groups) // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 46->1181 // was: 22686/46 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 19231 ride RIDE469b (F2-iter285): cf-census 29->46 (+17 z graftu 469: mg 0x981 + EF-klucze; canonical bd48e63) // ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63) (loader-visible 19233-2), // ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) // was: flip-ride 467: -5 sm121a keys (degen era delete)
    ];
    for (leg, w_keys, w_cf, w_ltc, w_src463) in want {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = v["instructions"].as_object().unwrap();
        let mut n_keys = 0u32;
        let mut n_cf = 0u32;
        let mut n_ltc = 0u32;
        let mut n_src463 = 0u32;
        for (k, rec) in ins {
            let mgs = match rec["mod_groups"].as_object() {
                Some(m) => m,
                None => continue, // pseudo-rekordy _errata_*
            };
            n_keys += 1;
            for (_, g) in mgs {
                if g.get("claim_forbid").is_some() {
                    n_cf += 1;
                }
            }
            if k.contains("EFL2.LTC") && k.contains("_dARI") && !k.contains("NA.") {
                n_ltc += 1;
            }
            if rec["_src463"] == "bug463-2026-09-14" {
                n_src463 += 1;
            }
        }
        assert_eq!(
            (n_keys, n_cf, n_ltc, n_src463),
            (w_keys, w_cf, w_ltc, w_src463),
            "[{leg}] census drift"
        );
        let src: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
        assert!(
            src["base_revision"]
                .as_str()
                .unwrap()
                .starts_with("cc2f62c"),
            "SOURCE pin drift"
        );
    }
}

/// t463_7: era/glyph klasa -- era-b118 / reuse-b122 legalne, URZ/RZ glyph,
/// imm signed '+-', polff+pred bez trailerza (20 komorek x4 nogi).
#[test]
fn t463_7_era_glyph_legal() {
    for (w, leg, want) in ERAGLYPH463 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] era/glyph {w:#034x}");
    }
}
