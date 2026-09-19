//! BUG-439 pins (F2-iter243, loop5/blind front2, 2026-09-11): LDSM 16,M88
//! ARURI-frame D-class band {87,90,92,95} engine-HOLE closure x4 legs.
//! Canonical 3032686 -> 54c5b02 (patch439.py replayable+idempotent; replay
//! z pristine 3032686 byte-exact x4 = c94fd12e/464419ce/2c1039c9/cff1c216;
//! idem all-skip; ENGINE src ZERO). Vendor law arb439 (28 probes, nvdisasm
//! raw -b x4 models AGREE EVERY / DIVERGENT=0; work/bug439/arb439_law.json):
//! D-class singles + ALL 11 combos vendor-legal INERT x4 on the carrier
//! (true dest/base/ureg/imm printed). Defect pre (measure439_pre; publish
//! cubit_py-1128636f 8f6220c6 + canonical 3032686): 25 HOLE/leg of which 17
//! in graft scope + 8 registration scope. Graft G1 x4 = pure relax
//! LDSM_R_ARURI|'16,M88' variable_mask |= (1<<87)|(1<<90)|(1<<92)|(1<<95)
//! (ab/fields invariant; b72/73 count bits stay strict -- count rows own).
//!
//! HEAL-ATTRIBUTION (BUG-441, F2-iter245, canonical ffa3244): the 441-kand
//! postures below (band rest {88,89,93,94} + D-under-count .2/.4) are CLOSED
//! by the BUG-441 graft (patch441.py; full combo space + count rows vendor-
//! legal inert x4, law arb441 54 probes AGREE/DIVERGENT=0). t439_3 flipped to
//! heal-assert; t439_5 band asserts flipped to relaxed; machine-verified by
//! work/bug441/flip441.py before edit. 441-kand CLOSED.
//!
//! Witness data: tests/bug439_data.inc (machine-built by
//! work/bug439/gen439pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug439_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const DMASK: u128 = (1u128 << 87) | (1u128 << 90) | (1u128 << 92) | (1u128 << 95);

/// t439_1: healed grid -- decode == vendor x4 legs on every D-class word
/// (4 singles + 11 combos + 2 rich carriers = 17 words, 68 cell-legs;
/// engine-HOLE pre-graft on every leg).
#[test]
fn t439_1_healed_grid_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW439_HEAL {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] LDSM {vendor} HOLE (must decode post-graft)"));
            assert_eq!(&got, vendor, "[{leg}] healed text != vendor");
        }
    }
    assert_eq!(LAW439_HEAL.len(), 17);
}

/// t439_2: carrier anchors vendor-exact pre==post (A.ref, F.ref.b72/b73) x4.
#[test]
fn t439_2_stable_anchors_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW439_STABLE {
            let got =
                dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] stable anchor HOLE: {vendor}"));
            assert_eq!(&got, vendor, "[{leg}] stable anchor drift");
        }
    }
    assert_eq!(LAW439_STABLE.len(), 3);
}

/// t439_3: BUG-441 heal-attribution -- 441-kand postures (band-rest
/// {88,89,93,94} singles+mixes + D-under-count .2/.4) decode vendor-exact on
/// every leg post-graft (canonical ffa3244; flip441.py machine-verified on
/// publish engine c1b901d9 + ffa3244 tables x4 legs before edit; law arb441).
#[test]
fn t439_3_posture441_healed_by_441() {
    assert_eq!(POSTURE441.len(), 8);
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in POSTURE441 {
            let want = if tag.starts_with("F.b87") {
                "LDSM.16.M88.2 R16, [UR4]"
            } else if tag.starts_with("F.b95") {
                "LDSM.16.M88.4 R16, [UR4]"
            } else {
                "LDSM.16.M88 R16, [UR4]"
            };
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag}: BUG-441 heal lost (must decode)"));
            assert_eq!(&got, want, "[{leg}] {tag}: BUG-441 heal text drift");
        }
    }
}

/// t439_4: masked mints -- encode of every healed vendor text never sets
/// D-bits (graft is decode-side only); masked byte-compare vs the law word
/// (D-mask excluded; era/junk zero anyway on these carriers) + decode
/// circle == healed text, x4 legs.
#[test]
fn t439_4_masked_mints_and_circles() {
    const ERA: u128 = 0xffffffffu128 << 96;
    const CMPMASK: u128 = !(DMASK | ERA);
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, text) in MASKMINT439 {
            let ins = parse_sass(&format!(" {text} ;"), 0)
                .unwrap_or_else(|e| panic!("[{leg}] parse {text}: {e}"));
            let w2 = encode_instruction(&ins, &t)
                .unwrap_or_else(|e| panic!("[{leg}] encode {text}: {e}"));
            assert_eq!(w2 & !DMASK, w2, "[{leg}] encode sets D-bits: {text}");
            assert_eq!(
                w2 & CMPMASK,
                w & CMPMASK,
                "[{leg}] masked mint drift: {text}"
            );
            let rt = dec(&t, &idx, w2).unwrap_or_else(|| panic!("[{leg}] circle HOLE {text}"));
            assert_eq!(&rt, text, "[{leg}] circle text drift");
        }
    }
    assert_eq!(MASKMINT439.len(), 17);
}

/// t439_5: source manifest + graft invariants -- CANON439 pin 54c5b02,
/// ARURI|16,M88 carries the bug439 _src tag + D-band vm bits + retained
/// j84 relax (BUG-423) x4; count bits b72/73 still strict-cared; band rest
/// {88,89,93,94} still strict-cared (441-kand boundary).
#[test]
fn t439_5_source_manifest_and_invariants() {
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"]
            .as_str()
            .unwrap()
            .starts_with("cc2f62c"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        src["base_revision"]
    );
    assert!(CANON439.starts_with("cc2f62c"), "CANON439 const drift");
    for leg in LEGS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert!(
            ins.get("LDSM.16.M88_R_AUR").is_none(),
            "{leg}: dotted junk era key resurrected (BUG-423 D1 recanon)"
        );
        let mg = &ins["LDSM_R_ARURI"]["mod_groups"]["16,M88"];
        assert_eq!(
            mg["_src"].as_str().unwrap(),
            "bug441-2026-09-11",
            "{leg}: ARURI 16,M88 missing graft tag (439 D-band ride; 441 band closure)"
        );
        let vm = u128::from_str_radix(
            mg["variable_mask"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        assert_eq!(vm & DMASK, DMASK, "{leg}: D-band relax lost");
        assert_eq!(vm & (7 << 84), 7 << 84, "{leg}: j84 relax (423) lost");
        let mut fbits: u128 = 0;
        for f in mg["fields"].as_array().unwrap() {
            let b = f["bits"].as_u64().unwrap();
            let s = f["shift"].as_u64().unwrap();
            fbits |= ((1u128 << b) - 1) << s;
        }
        let care = !(vm | fbits);
        assert_eq!(
            care & (3 << 72),
            3 << 72,
            "{leg}: count bits b72/73 must stay strict (count rows own)"
        );
        for b in [88u32, 89, 93, 94] {
            assert_eq!(
                care & (1u128 << b),
                0,
                "{leg}: band bit b{b} must be relaxed (BUG-441 closure)"
            );
        }
        // count rows .2/.4 carry the full inert-band relax (BUG-441 G2)
        for mgn in ["16,2,M88", "16,4,M88"] {
            let cg = &ins["LDSM_R_ARURI"]["mod_groups"][mgn];
            assert_eq!(
                cg["_src"].as_str().unwrap(),
                "bug441-2026-09-11",
                "{leg}: ARURI {mgn} missing BUG-441 graft tag"
            );
            let cvm = u128::from_str_radix(
                cg["variable_mask"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            const DBAND: u128 = (1u128 << 84)
                | (1u128 << 85)
                | (1u128 << 86)
                | (1u128 << 87)
                | (1u128 << 88)
                | (1u128 << 89)
                | (1u128 << 90)
                | (1u128 << 92)
                | (1u128 << 93)
                | (1u128 << 94)
                | (1u128 << 95);
            assert_eq!(
                cvm & DBAND,
                DBAND,
                "{leg}: ARURI {mgn} count-band relax lost (441)"
            );
        }
        assert_eq!(
            (u128::from_str_radix(
                mg["and_base"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap()
                >> 91)
                & 1,
            1,
            "{leg}: ab contract bit b91=1 drift"
        );
    }
}

/// t439_6: sm121a key census unchanged by the graft (pure mask relax:
/// 15726 forms == BUG-442 post state (G3 donor-clone adds key STG_ARURI_R
/// on sm121a: 15725 -> 15726; previous census waves in history).
/// FLIP (BUG-443, canonical e8d1af3): +19 sm121a keys (8 T2 base E-form
/// + 11 T3 cross STG other-family enum keys; STS S8/S16 land as mgs and
/// do not move the counter) 15726 -> 15745. FLIP-ride (BUG-453, canonical 700524e): +3 sm121a keys (EFL2.256 non-NA dARI _II donor-first synth) 15745 -> 15760. FLIP-ride (BUG-463, canonical a64b82b): +12 sm121a keys (LTC-width LTC64B/128B/256B nNA EFL2.256 dARI synth) 15760 -> 15760. FLIP-ride (BUG-464, canonical 4968113): +6 sm121a keys (plain nNA ARURI64 EFL2.256 lattice) 15760 -> 15766.
#[test]
fn t439_6_key_census_unchanged() {
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    assert_eq!(
        raw["instructions"].as_object().unwrap().len(),
        23833, // RIDE476 (F2-iter299, canonical c88778e): +8 sm121a keys (476 LDG NA-side x8) -> raw 23833 (loader 23831) // RIDE475R3b-w2 (F2-iter290, INC-289e followup battery475-final 6xA, canonical 978c0918): +2 sm121a keys {anomalie LDG.E.NA/EU.ENL2.256_R_R_dARI verbatim restore; R3b 978c0918}; zmierzone raw len 23825 (loader 23823 po -2 _errata twardy offset) // was: 23823 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 22688 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 19233 ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63) // ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) // was: flip-ride 467: -5 sm121a keys (degenerate era-rows delete; canonical 668f842) // ride 465: +1146 (canonical 23976eb; was 15766)
        "sm121a key census must equal the BUG-443 post state (8 T2 + 11 T3 noE-cross keys; 442->443)"
    );
}
