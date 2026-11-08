//! BUG-438 pins (F2-iter244, loop5/blind front2, 2026-09-11): STSM.16
//! MT88/MT168 + b80-alias closure x4 legs + STS.AURI width-era band x3 +
//! STG.E ARURI junk/UR-width/imm-sign cavity closure x4.
//! Canonical 54c5b02 -> bb1ba6c (patch438.py replayable+idempotent; replay
//! z pristine byte-exact x4 [65a7c46e/e366c52d/9c1f9031/303ca76d]; idem
//! all-skip; ENGINE canonical-side ZERO; ONE cubit ENGINE printer-arm fix:
//! format_plain_u32_ur imm 24b@40 signed, heals immMIN/immNEG1 x4).
//! Graft:
//!  - G1 x4 STSM_ARI_R += {16,{2,4,},MT88|MT168} (ab |= 1<<78/1<<79);
//!  - G2 x4 all 9 STSM.16 mgs vm |= 1<<80 (b80 alias ring);
//!  - G3 x3 STS_AURI_R {'',U8,64,128} vm |= 1<<95 + G3b ureg 9->8b @64
//!    (sm121a + own U16 donor-parity; 412-law b72 print-inert on AURI window);
//!  - G4a x3 STG.E_ARURI_R|'E' ureg 6->8b @64 + vm |= {70,71}
//!    (own sm121a 8-bit donor-parity; j70/j71 silent-truncation healed);
//!  - G4b x4 STG.E_ARURI_R|'E' vm |= junk whitelist {81,82,83,87,88,89,92,
//!    93,94,95} x4.
//!    NOT grafted (pinned standing here): INVALID3 STSM loud class; STS
//!    S16/INVALID7 width maps; STG other-family enums (j72-j86) + desc
//!    j90-misroute (442-kand, x3 snapped text) + kill singles j76/j91; era-rc1
//!    carriers posture continuity.
//!
//! Witness data: tests/bug438_data.inc (machine-built by
//! work/bug438/gen438pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug438_data.inc");

/// 2026-11-08 (T-18, rows-memory-2026-11-07): on sm120 these law-grid words carry a bit the measured
/// LDS / STS / LDSM / STSM rows fail closed on -- the text-inert control / sub-UR / gap bits nvdisasm
/// names as the base word (verified: nvdisasm text == the base text, 0 census witnesses). The measured-row
/// convention; the three other legs keep the harvest tolerance.
const SM120_FAIL_CLOSED: &[u128] = &[
    0x0007c200880005e0ffffff04ff00e988u128,
    0x0007e200880005e0ffffff04ff00e988u128,
    0x000fc200880005e0ffffff04ff00e988u128,
    0x000fe200880005e0ffffff04ff00e988u128,
    // 2026-11-08 (T-19, rows-memory-2026-11-07): the measured STS_ARURI_R / STL_AURI_R rows read the UR base in 8 bits --
    // bit 72 is text-inert for nvdisasm 13.1 on every width (tools/probes/re_sm120_rows.py --family memory) -- so the
    // grid's bit-72 carriers are holes on sm120 now (0 census witnesses; T-19 whole-census parity)
    0x0007c200080005e0ffffff04ff00e988u128,  // was @!P6 STS.U16 [UR224+-0x1], R4
    0x0007c200880001e0ffffff04ff00e988u128,  // was @!P6 STS.U8 [UR224+-0x1], R4
    0x0007c200880009e0ffffff04ff00e988u128,  // was @!P6 STS [UR224+-0x1], R4
    0x0007c20088000be0ffffff04ff00e988u128,  // was @!P6 STS.64 [UR224+-0x1], R4
    0x0007c20088000de0ffffff04ff00e988u128,  // was @!P6 STS.128 [UR224+-0x1], R4
    0x0007e200080001e0ffffff04ff00e988u128,  // was @!P6 STS.U8 [UR224+-0x1], R4
    0x0007e200080005e0ffffff04ff00e988u128,  // was @!P6 STS.U16 [UR224+-0x1], R4
    0x0007e200080007e0ffffff04ff00e988u128,  // was @!P6 STS.S16 [UR224+-0x1], R4
    0x0007e200080009e0ffffff04ff00e988u128,  // was @!P6 STS [UR224+-0x1], R4
    0x0007e20008000be0ffffff04ff00e988u128,  // was @!P6 STS.64 [UR224+-0x1], R4
    0x0007e20008000de0ffffff04ff00e988u128,  // was @!P6 STS.128 [UR224+-0x1], R4
    0x000fc200080001e0ffffff04ff00e988u128,  // was @!P6 STS.U8 [UR224+-0x1], R4
    0x000fc200080005e0ffffff04ff00e988u128,  // was @!P6 STS.U16 [UR224+-0x1], R4
    0x000fc200080009e0ffffff04ff00e988u128,  // was @!P6 STS [UR224+-0x1], R4
    0x000fc20008000be0ffffff04ff00e988u128,  // was @!P6 STS.64 [UR224+-0x1], R4
    0x000fc20008000de0ffffff04ff00e988u128,  // was @!P6 STS.128 [UR224+-0x1], R4
    0x000fc200880001e0ffffff04ff00e988u128,  // was @!P6 STS.U8 [UR224+-0x1], R4
    0x000fc200880007e0ffffff04ff00e988u128,  // was @!P6 STS.S16 [UR224+-0x1], R4
    0x000fc200880009e0ffffff04ff00e988u128,  // was @!P6 STS [UR224+-0x1], R4
    0x000fc20088000be0ffffff04ff00e988u128,  // was @!P6 STS.64 [UR224+-0x1], R4
    0x000fc20088000de0ffffff04ff00e988u128,  // was @!P6 STS.128 [UR224+-0x1], R4
    0x000fe200080005e0ffffff04ff00e988u128,  // was @!P6 STS.U16 [UR224+-0x1], R4
    0x000fe200880001e0ffffff04ff00e988u128,  // was @!P6 STS.U8 [UR224+-0x1], R4
    0x000fe200880009e0ffffff04ff00e988u128,  // was @!P6 STS [UR224+-0x1], R4
    0x000fe20088000be0ffffff04ff00e988u128,  // was @!P6 STS.64 [UR224+-0x1], R4
    0x000fe20088000de0ffffff04ff00e988u128,  // was @!P6 STS.128 [UR224+-0x1], R4
];


fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn leg_of(tag: &str) -> &'static str {
    ["sm121a", "sm120", "sm103a", "sm100a"]
        .iter()
        .find(|l| tag.ends_with(&format!(".{l}")))
        .copied()
        .expect("posture tag without leg suffix")
}

/// t438_1: STSM.16 MT88/MT168 + b80-alias count lattice closure -- decode ==
/// vendor x4 legs (G1+G2; healed from HOLE x4 pre).
#[test]
fn t438_1_stsm_mt_alias_closure_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW438_STSM_HEAL {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] STSM {vendor} HOLE (must decode)"));
            assert_eq!(&got, vendor, "[{leg}] STSM text != vendor");
        }
    }
    assert_eq!(LAW438_STSM_HEAL.len(), 25);
}

/// t438_2: STS.AURI width-family era-band -- decode == vendor x4 (G3+G3b; x3
/// healed, 121a pre-healed by 425b; UR numeral = low8 of the window, 412-law).
#[test]
fn t438_2_sts_auri_width_era_band_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW438_STS_HEAL {
            if leg == "sm120" && SM120_FAIL_CLOSED.contains(w) {
                assert!(dec(&t, &idx, *w).is_none(), "[{leg}] STS {vendor}: measured row tolerates a text-inert bit");
                continue;
            }
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] STS {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] STS text != vendor");
        }
    }
    assert_eq!(LAW438_STS_HEAL.len(), 12);
}

/// t438_3: STG.E ARURI junk band + 8-bit UR + signed-imm heal -- decode ==
/// vendor x4 (G4a+G4b + format_plain_u32_ur signed-24b printer fix).
#[test]
fn t438_3_stg_auri_cavity_closure_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW438_STG_HEAL {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] STG {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] STG text != vendor");
        }
    }
    assert_eq!(LAW438_STG_HEAL.len(), 16);
}

/// t438_4: vendor anchors stable (pre==post, machine-measured) x4.
#[test]
fn t438_4_stable_anchors_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW438_STABLE {
            if leg == "sm120" && SM120_FAIL_CLOSED.contains(w) {
                assert!(dec(&t, &idx, *w).is_none(), "[{leg}] STABLE {vendor}: measured row tolerates a text-inert bit");
                continue;
            }
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] STABLE {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] STABLE text != vendor (drift!)");
        }
    }
    assert_eq!(LAW438_STABLE.len(), 83);
}

/// t438_5: postures stay pinned HOLE pre==post (loud INVALID3/.6, INVALID7
/// width [STS.S16 healed by 443 with vendor-snapped text], other-family, kill singles); j90 standing defect snapped text;
/// RC1 carriers posture continuity snapped.
#[test]
fn t438_5_postures_pinned_pre_post() {
    for (w, tag, snapped) in POSTURE438 {
        let (t, idx, leg) = {
            let l = leg_of(tag);
            let t = tab(l);
            let idx = DecodeIndex::build(&t);
            (t, idx, l)
        };
        let got = dec(&t, &idx, *w);
        // T-19 (2026-11-08): the sm120 postures whose word the measured STS rows fail closed on (SM120_FAIL_CLOSED) are
        // holes; the snapped text stays the record of the harvest-era tolerance
        let expect = if *snapped == "HOLE" || (leg == "sm120" && SM120_FAIL_CLOSED.contains(w)) {
            None
        } else {
            Some(snapped.to_string())
        };
        assert_eq!(
            got, expect,
            "[{leg}] posture {tag} drift (snap {snapped}, got {got:?}; S16 cells healed 443, snap carries vendor text)"
        );
    }
    assert_eq!(POSTURE438.len(), (21 + 9) * 4);
    for (w, tag, snapped) in STGJ90_442 {
        let leg = leg_of(tag);
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        let expect = if *snapped == "HOLE" {
            None
        } else {
            Some(snapped.to_string())
        };
        assert_eq!(
            got, expect,
            "[{leg}] 442-kand j90 standing snap drift {tag}"
        );
    }
    assert_eq!(STGJ90_442.len(), 4);
    for (w, tag, snapped) in RC1CARRIERS438 {
        let leg = leg_of(tag);
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        let expect_claim = *snapped == "CLAIM";
        assert_eq!(
            got.is_some(),
            expect_claim,
            "[{leg}] RC1 carrier posture drift {tag} (snap {snapped}, got {got:?})"
        );
    }
    assert_eq!(RC1CARRIERS438.len(), 17 * 4);
}

/// t438_6: masked mints -- encode(vendor text) masked-compares vs law word,
/// never-circle-drifts, x4 legs.
#[test]
fn t438_6_masked_mints_x4() {
    let era: u128 = 0xFFFF_FFFFu128 << 96;
    for leg in LEGS {
        let t = tab(leg);
        for (w, text, drop) in MASKMINT438 {
            let w2 = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] encode refused {text}"));
            let m = !(drop | era);
            assert_eq!(w2 & m, w & m, "[{leg}] masked mint mismatch {text}");
            let idx = DecodeIndex::build(&t);
            let back = dec(&t, &idx, w2).unwrap_or_else(|| panic!("[{leg}] circle HOLE {text}"));
            assert_eq!(back, *text, "[{leg}] circle text drift {text}");
        }
    }
    assert_eq!(MASKMINT438.len(), 7);
}

/// t438_7: graft invariants on the tables themselves + manifest pin.
#[test]
fn t438_7_graft_invariants_and_manifest() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "27b127251edd465fbc462d7e8017f54ff43ad4d1" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;

    let man: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    let pin = man["base_revision"].as_str().unwrap().to_string();
    assert!(
        pin.starts_with(CURRENT_VENDORED_CANON), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd (= BUG-447, ride-after e8d1af3 = BUG-443, 57e7ecd = BUG-442, ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439): {pin}"
    );
    assert!(CANON438.starts_with("9c0e4ce"), "CANON438 const drift");
    for leg in LEGS {
        let raw: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = &raw["instructions"];
        let stsm = &ins["STSM_ARI_R"]["mod_groups"];
        for mg in [
            "16,MT88",
            "16,2,MT88",
            "16,4,MT88",
            "16,MT168",
            "16,2,MT168",
            "16,4,MT168",
        ] {
            assert!(stsm.get(mg).is_some(), "[{leg}] new STSM mg {mg} missing");
        }
        for mg in [
            "16,M88",
            "16,2,M88",
            "16,4,M88",
            "16,MT88",
            "16,2,MT88",
            "16,4,MT88",
            "16,MT168",
            "16,2,MT168",
            "16,4,MT168",
        ] {
            let vm = stsm[mg]["variable_mask"].as_str().unwrap();
            let vm = u128::from_str_radix(vm.trim_start_matches("0x"), 16).unwrap();
            assert_eq!(
                vm & (1u128 << 80),
                1u128 << 80,
                "[{leg}] STSM {mg} b80 alias lost"
            );
        }
        let stg = &ins["STG.E_ARURI_R"]["mod_groups"]["E"];
        let fs = stg["fields"].as_array().unwrap();
        let ur = fs
            .iter()
            .find(|f| f["extraction"].as_str().unwrap() == "ureg")
            .unwrap();
        assert_eq!(
            ur["bits"].as_u64().unwrap(),
            8,
            "[{leg}] STG ureg not 8-bit"
        );
        let vm = stg["variable_mask"].as_str().unwrap();
        let vm = u128::from_str_radix(vm.trim_start_matches("0x"), 16).unwrap();
        let junk: u128 = [81u32, 82, 83, 87, 88, 89, 92, 93, 94, 95]
            .iter()
            .fold(0u128, |a, b| a | (1u128 << b));
        assert_eq!(vm & junk, junk, "[{leg}] STG junk-band relax lost");
        assert_eq!(
            vm & (3u128 << 70),
            3u128 << 70,
            "[{leg}] STG ur-band relax lost"
        );
        if leg != "sm121a" {
            for wd in ["", "U8", "64", "128"] {
                let g = &ins["STS_AURI_R"]["mod_groups"][wd];
                let vm = g["variable_mask"].as_str().unwrap();
                let vm = u128::from_str_radix(vm.trim_start_matches("0x"), 16).unwrap();
                // 2026-11-08 (T-18, rows-memory-2026-11-07): on sm120 STS_AURI_R is measured field by field now -- its
                // mask is exactly its fields, so the harvest "era-band relax" (vm |= 1<<95, a text-inert bit) is gone:
                // the row fails closed on bit 95 (the measured-row convention). sm100a / sm103a keep the harvest relax.
                let measured = g["_src"].as_str().is_some_and(|s| s.starts_with("rows-"));
                if leg == "sm120" && measured {
                    assert_eq!(vm & (1u128 << 95), 0, "[{leg}] STS AURI {wd} measured: fails closed on text-inert b95");
                } else {
                    assert_eq!(
                        vm & (1u128 << 95),
                        1u128 << 95,
                        "[{leg}] STS AURI {wd} b95 relax lost"
                    );
                }
                let fs = g["fields"].as_array().unwrap();
                let uf = fs
                    .iter()
                    .find(|f| f["extraction"].as_str().unwrap() == "sub_ur0")
                    .unwrap();
                assert_eq!(
                    uf["bits"].as_u64().unwrap(),
                    8,
                    "[{leg}] STS AURI {wd} ureg not 8-bit"
                );
            }
        }
    }
}
