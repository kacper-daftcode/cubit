//! BUG-429 pins (F2-iter237, loop5/blind front2, 2026-09-09): LDSM plain-ARI
//! frame [R+imm] enum x count closure -- LDSM_R_ARI gains the full 15-entry
//! lattice x4 legs: += {16,MT88; 16,2,MT88; 16,4,MT88; 16,M816; 16,2,M816;
//! 16,4,M816; 16,M832; 16,2,M832; 16,4,M832; 16,MT1616; 16,2,MT1616;
//! 16,4,MT1616} on sm100a/sm103a/sm120 and the same minus the pre-rowed
//! 16,4,MT88 on sm121a (byte-invariant, unchanged claim) = 47 new rows;
//! canonical graft a5e6d0a -> 616f185 (ride F2-iter238: 52cb73c = BUG-425; patch429.py replayable+idempotent,
//! replay-from-pristine byte-exact x4 [24b084ff/be521a0e/c1174b5c/9e99a505,
//! canonical-native dump], ENGINE cubit src ZERO changes). Vendor law arb429
//! (63 probes, nvdisasm 13.3.73 raw -b per-word, x4 models
//! SM100a/SM103a/SM120/SM121a AGREE EVERY/DIVERGENT=0): ride = the arb426
//! rA/rB 48-probe plain-ARI census re-probed with machine word+text parity
//! asserted per model; fresh 429 controls = rb axis [R10+0x155]/[R7+0x8000]/
//! [R4+0x1], guard @P0, dest axis, imm-axis 0x800000/-1. both count bits =
//! INVALID3 loud x4; enum 5/6/7 = INVALIDn loud x4. sm120 collision NEW=12
//! pairs (FSETP_P_P_R_UR_P|AND,GTU x new rows) = identical-in-kind to the
//! pre-existing FSETP x {16,M88; 16,2,M88; 16,4,M88} sm120 cloud (era-junk
//! row; ab requires dest[23:16]=0, law words dest>=2: 0/63 claims, machine-
//! asserted); LOST=0 x4.
//!
//! Witness data: tests/bug429_data.inc (machine-built by
//! work/bug429/gen429pins.py from arb429_law + measure429_post + fresh x4
//! mints; self-checks abort; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug429_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t).ok().map(|d| {
        (
            to_sass(&d).trim().trim_end_matches(';').to_string(),
            format!("{}|{}", d.key, d.mod_group),
        )
    })
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t429_1: the measured plain-ARI enum x count lattice (ride census e1..e4
/// x 1/2/4 x rA/rB + fresh rb/guard/imm-axis controls) decodes vendor-exact
/// x4 and claims exactly the grafted LDSM_R_ARI row. The sm121a 16,4,MT88
/// pre-row shares the km string; the pin is uniform x4 by construction.
#[test]
fn t429_1_plain_ari_lattice_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp, kms) in LAW429_DECODE {
            let (got, km) = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag} HOLE (must be vendor-exact)"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] {tag} text");
            assert_eq!(km, kms[li], "[{leg}] {tag} claim-km");
        }
    }
    assert_eq!(LAW429_DECODE.len(), 35);
}

/// t429_2: INVALID3 (both count bits) + INVALID5/6/7 loud glyphs stay
/// HOLE/unclaimed x4; refuse mints stay fail-closed x4.
#[test]
fn t429_2_invalid_postures_stay_unclaimed_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in HOLE429 {
            assert!(dec(&t, &idx, *w).is_none(), "[{leg}] {tag} not HOLE");
        }
        for text in REFUSE429 {
            assert!(enc(&t, text).is_none(), "[{leg}] refuse minted: {text}");
        }
    }
    assert_eq!(HOLE429.len(), 22);
    assert_eq!(REFUSE429.len(), 6);
}

/// t429_3: authored plain-ARI lattice texts mint byte-exact circles x4:
/// encode -> decode == authored text, low96 == law words, cross-leg
/// word-identical, claim km recorded.
#[test]
fn t429_3_mint_circles_x4() {
    const M96: u128 = (1 << 96) - 1;
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word, reprint, kms) in MINT429 {
            let got = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
            assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
            let (back, km) =
                dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
            assert_eq!(&back, reprint, "[{leg}] second render drift: {text}");
            assert_eq!(&km, &kms[li], "[{leg}] mint claim-km drift: {text}");
        }
    }
    assert_eq!(MINT429.len(), 14);
}

/// t429_4: census + donor shape: machine-read mg lists from the synced
/// tables == the recorded CENSUS429 consts (LDSM_R_ARI carries the full
/// 15-entry closed enum x count lattice x4, identical set per leg), every
/// grafted row keeps the donor geometry (fields shape + variable_mask ==
/// the frame-own 16,M88 row, and_base delta == exactly the measured
/// enum [80:78) + count b72/b73 bits), _src provenance on the 429 rows.
#[test]
fn t429_4_census_and_donor_shape() {
    const SRC: &str = "bug429-2026-09-09";
    let enums = [("MT88", 1u128), ("M816", 2), ("M832", 3), ("MT1616", 4)];
    let cnts = [("2", 1u128 << 72), ("4", 1u128 << 73)];
    for leg in LEGS {
        let want = match leg {
            "sm100a" => CENSUS429_SM100A_ARI,
            "sm103a" => CENSUS429_SM103A_ARI,
            "sm120" => CENSUS429_SM120_ARI,
            _ => CENSUS429_SM121A_ARI,
        };
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ari = &raw["instructions"]["LDSM_R_ARI"]["mod_groups"];
        let mut got: Vec<&str> = ari
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        got.sort();
        assert_eq!(got, want, "[{leg}] LDSM_R_ARI census drift");
        let num = |v: &serde_json::Value| -> u128 {
            u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let donor = &ari["16,M88"];
        let dab = num(&donor["and_base"]);
        let dvm = num(&donor["variable_mask"]);
        let donor_fields: Vec<(&str, u64, u64)> = donor["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["extraction"].as_str().unwrap(),
                    f["bits"].as_u64().unwrap(),
                    f["shift"].as_u64().unwrap(),
                )
            })
            .collect();
        for (en, ev) in enums {
            for pair in [format!("16,{en}")]
                .into_iter()
                .chain(cnts.iter().map(move |(cn, _)| format!("16,{cn},{en}")))
            {
                let g = &ari[pair.as_str()];
                let mut delta = ev << 78;
                for (cn, cb) in cnts {
                    if pair == format!("16,{cn},{en}") {
                        delta |= cb;
                    }
                }
                let pre_row = leg == "sm121a" && pair == "16,4,MT88";
                assert_eq!(num(&g["and_base"]), dab | delta, "[{leg}] {pair} ab delta");
                assert_eq!(num(&g["variable_mask"]), dvm, "[{leg}] {pair} vm drift");
                // sm121a 16,4,MT88 is the pre-429 corpus-era row: byte-invariant,
                // attested by the decode pins (count=1 vintage metadata kept)
                if !pre_row {
                    assert!(g["count"].is_null(), "[{leg}] {pair} count drift");
                    assert_eq!(g["_src"].as_str().unwrap(), SRC, "[{leg}] {pair} _src");
                }
                let fields: Vec<(&str, u64, u64)> = g["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| {
                        (
                            f["extraction"].as_str().unwrap(),
                            f["bits"].as_u64().unwrap(),
                            f["shift"].as_u64().unwrap(),
                        )
                    })
                    .collect();
                assert_eq!(
                    fields, donor_fields,
                    "[{leg}] {pair} fields drift (donor 16,M88)"
                );
            }
        }
    }
}

/// t429_5: SOURCE.json manifest pin + canonical provenance (ride-chain).
#[test]
fn t429_5_source_pins_52cb73c() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    // ride-after flip F2-iter240 (BUG-435+434 graft): 1810912 canonical (was 70eb0fe = BUG-416 F2-iter239, 52cb73c = BUG-425+425b F2-iter238, 616f185 = BUG-429 F2-iter237, a5e6d0a = BUG-427 F2-iter236, 2a631d5 = BUG-426 F2-iter235)
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("bd2e254"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    assert!(CANON429.starts_with("bd2e254"), "CANON429 const drift");
}

/// t429_6: the M88 lattice (always-rowed standing rows) and the sm121a
/// 16,4,MT88 pre-row decode vendor-exact x4 with text stable pre==post
/// (regression surface of the graft).
#[test]
fn t429_6_standing_m88_lattice_stable_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp) in LAW429_STANDING {
            let (got, _km) =
                dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] {tag} standing HOLE"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] {tag} text");
        }
    }
    assert_eq!(LAW429_STANDING.len(), 6);
}
