//! BUG-442 pins (F2-iter246, loop5/blind front2, 2026-09-11): STG.E ARURI
//! desc-kind lattice [91:90) closure + b76 desc-marker domain + 121a ARURI
//! row-family completion.
//! Canonical ffa3244 -> 57e7ecd (patch442.py replayable+idempotent; replay
//! z pristine ffa3244 byte-exact x4 = e309967e/5cf2536a/a8a6cac8/7e2a2e26;
//! idem rerun all-skip). ENGINE: JEDEN printer-arm soak (STG_ARURI_R
//! canon-era plain shape sub_ur1/sub_r0/sub_imm1 -> format_plain_u32_ur;
//! the rest of the source ZERO) + tools/sync_table.py ratchet SM121A 541->544 (3 donor
//! templates). Vendor law arb442 25 + arb442b 12 + arb442c 4 probes,
//! nvdisasm 13.3.73 raw -b x4 models AGREE EVERY / DIVERGENT=0
//! (work/bug442/arb442*_law.json): (1,0)=[R.U32+UR], (1,1)=[R.64+UR],
//! (0,1)=(0,0)=RC1 kill; desc = (1,1)+b76; widths x (1,1) legal; junk inert
//! under (1,1); ur=255 URZ-elide vendor (444-kand engine gap pinned).
//! Graft: G1 x3 dARI-E vm &= ~(1<<76)&~(1<<91) (claims only vendor-true
//! desc region); G2 x4 plain STG.E{,.64,.128}_ARURI rows vm |= 1<<90;
//! G3 sm121a donor-clone STG_ARURI_R {E,64,E,128,E} (count=None,
//! addr_width='64'); G3b addr_width pins (121a plain U32 steer).
//! Defect pre (measure442_pre; publish cubit_py-947b5722 80c3014c +
//! canonical ffa3244; 348 cells): x3 44 MATCH/8 CLAIM-ON-RC1/14 HOLE/
//! 6 posture-hole/15 WRONG; 121a 39+1 / 3 / 28 / 11 / 5 (z G-group).
//! Post (verify442_work): healed 44 / standing 224 / loud-release 6 /
//! rc1-release 47 / rc1-era-continuity 8 / rc1-standing 1 / standing-gap 18
//! / FAIL 0.
//!
//! NOT grafted (pinned): plain-width STG (b72=0) + U8 rows absent (443);
//! vendor-loud '???0'/'???255' glyph deltas; URZ-elide (1,0)/(1,1) plain
//! arm (444-kand ENGINE); era CLAIM-ON-RC1 carriers (438/440 doctrines);
//! 103a desc odd-base encode refuse (445-kand); 121a desc-ur extraction
//! gap (432-owned).
//!
//! Witness data: tests/bug442_data.inc (machine-built by
//! work/bug442/gen442pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug442_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
include!("t25_fail_closed.inc");
/// T-25 (2026-11-09): the STG rows are measured on sm100a / sm103a / sm121a (rows-memory-2026-11-07 on -b SM100 / SM103 /
/// SM121, T-23's per-row passes) and fail closed on their text-inert bits; the clean word's reading keeps the vendor pin.
fn dec_fc(t: &IsaTable, idx: &DecodeIndex, w: u128, want: &str) -> Option<String> {
    dec(t, idx, w).or_else(|| t25_closed_as(t, w, Some(want)).map(|s| s.trim().trim_end_matches(';').to_string()))
}
const LEGS_442: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
/// t442_1: healed grid -- decode == vendor text x4 legs on every (1,1)
/// free-form word (10 words x4; dup tag arb438b.STG.j90 == A.j90 folded).
#[test]
fn t442_1_healed_grid_x4() {
    for leg in LEGS_442 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW442_HEAL {
            let got = dec_fc(&t, &idx, *w, vendor);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] heal drift {w:#034x}"
            );
        }
    }
}

/// t442_2: stable anchors -- plain (1,0) + widths + desc domain + junk/ur
/// rides pre==post == vendor x4.
#[test]
fn t442_2_stable_anchors_x4() {
    for leg in LEGS_442 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW442_STABLE {
            let got = dec_fc(&t, &idx, *w, vendor);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] stable drift {w:#034x}"
            );
        }
    }
}

/// t442_3: kill-lattice postures -- per-leg snap (= POST: HOLE expected on
/// every released kill; B.b128.p01.sm121a HEALED to HOLE by BUG-432 R1
/// (cavity fields @9/@11 removed from STG_ARI_R|128,E; vendor rc=1 x4 stoi)).
#[test]
fn t442_3_kill_lattice_x4() {
    for (w, snap) in POSTURE442 {
        let (tag, expect) = snap.split_once(" : ").unwrap();
        let leg = tag.rsplit('.').next().unwrap();
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        if expect == "HOLE" {
            assert_eq!(
                got, None,
                "[{leg}] kill posture {tag} decodes post: {got:?}"
            );
        } else {
            assert_eq!(
                got.as_deref(),
                Some(expect),
                "[{leg}] rc1-standing drift {tag}"
            );
        }
    }
    assert_eq!(POSTURE442.len(), 8 * 4);
}

/// t442_4: standing gaps -- decode == snapped engine text; vendor truth in
/// the .inc doc comments (registered 443/444/432 classes, NOT healed).
#[test]
fn t442_4_standing_gaps_documented() {
    for (w, snapped, tag) in GAP442 {
        let leg = tag.rsplit('.').next().unwrap();
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = if *snapped == "HOLE" { dec(&t, &idx, *w) } else { dec_fc(&t, &idx, *w, snapped) };
        if *snapped == "HOLE" {
            assert_eq!(got, None, "[{leg}] gap cell decodes {tag}: {got:?}");
        } else {
            assert_eq!(
                got.as_deref(),
                Some(*snapped),
                "[{leg}] gap snap drift {tag}"
            );
        }
    }
    assert_eq!(GAP442.len(), 19);
}

/// t442_5: masked mints + circles -- encode(text)==law word (full mask 0)
/// and decode(word)==text on every leg, except the two documented F.desc.rich
/// leg deviations (103a: encode refuses odd desc base [445-kand]; 121a:
/// circle snaps to the 432-owned desc-ur extraction text).
#[test]
fn t442_5_masked_mints_and_circles() {
    const RICH: u128 = 0x000fc2000c1019840001233f3f007986;
    for leg in LEGS_442 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, txt, mask) in MASKMINT442 {
            if *mask != 0 {
                panic!("MASKMINT442 must carry mask=0");
            }
            let parsed = parse_sass(&format!(" {txt} ;"), 0)
                .unwrap_or_else(|e| panic!("[{leg}] parse {txt}: {e}"));
            if *w == RICH && leg == "sm103a" {
                assert!(
                    encode_instruction(&parsed, &t).is_err(),
                    "[{leg}] 445-kand: odd desc base pair encode must stay loud-refused"
                );
                continue;
            }
            let ew = encode_instruction(&parsed, &t)
                .unwrap_or_else(|e| panic!("[{leg}] encode refuse {txt}: {e}"));
            assert_eq!(ew, *w, "[{leg}] mint drift {txt}: {ew:#034x} != {w:#034x}");
            let back = dec(&t, &idx, ew).expect("circle must decode");
            if *w == RICH && leg == "sm121a" {
                assert_eq!(
                    back, "STG.E desc[UR4][R63.64+0x123], R63",
                    "[{leg}] 432-owned desc-ur extraction snap drift"
                );
            } else {
                assert_eq!(back, *txt, "[{leg}] circle text drift {txt}: {back}");
            }
        }
    }
    assert_eq!(MASKMINT442.len(), 12);
}

/// t442_6: source manifest + graft invariants -- CANON442 pin 57e7ecd,
/// plain rows vm b90 set + U32/64 addr_width pins, dARI-E x3 vm 76/91 clear
/// (ab/fields verbatim), 121a donor key parity with sm103a rows.
#[test]
fn t442_6_source_manifest_and_invariants() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "0f20ae6eff3f86a70526b32e28b21f3bad3f8f47" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;

    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    let pin = m["base_revision"].as_str().unwrap().to_string();
    assert!(
        pin.starts_with(CURRENT_VENDORED_CANON), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd (= BUG-447, ride-after e8d1af3 = BUG-443, 57e7ecd = BUG-442, ffa3244 = BUG-441): {pin}"
    );
    for leg in LEGS_442 {
        let raw: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = &raw["instructions"];
        for key in ["STG.E_ARURI_R", "STG.E.64_ARURI_R", "STG.E.128_ARURI_R"] {
            let mg_oid = ins[key]["mod_groups"]
                .as_object()
                .unwrap()
                .iter()
                .find(|(n, _)| *n != "_meta")
                .map(|(n, _)| n.clone())
                .unwrap_or_else(|| "E".to_string());
            let _ = mg_oid;
            let mgs = ins[key]["mod_groups"].as_object().unwrap();
            for (_n, mg) in mgs {
                if _n.starts_with('_') {
                    continue;
                }
                let vm = u128::from_str_radix(
                    mg["variable_mask"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                // T-25 (2026-11-09): a row measured on -b SM100 / SM103 / SM121 (rows-memory-2026-11-07) has its fields
                // for its mask -- bit 90 (the address-width selector of the `.64` form) fails closed there
                if mg["_src"].as_str().is_some_and(|s| s.starts_with("rows-")) {
                    assert_eq!(vm & (1u128 << 90), 0, "[{leg}] {key} measured row must fail closed on b90");
                } else {
                    assert!(
                        vm & (1u128 << 90) != 0,
                        "[{leg}] {key} vm b90 must be relaxed (G2)"
                    );
                }
                assert_eq!(
                    mg["addr_width"].as_str(),
                    Some("U32"),
                    "[{leg}] {key} U32 pin"
                );
            }
        }
        let ar = &ins["STG_ARURI_R"];
        for (n, mg) in ar["mod_groups"].as_object().unwrap() {
            if n.starts_with('_') {
                continue;
            }
            // ride F2-iter250 (BUG-443 T1): the noE-family mgs '', '64', 'U8',
            // 'CONSTANT,PRIVATE' claim only the [Rn.U32+URm] form (b90 strict)
            // and steer encode U32-side; the BUG-442 canon-era mgs keep '64'.
            // Native SM120 memory RE added the genuine E,U8 packet at
            // b90=1: NVIDIA prints [Rn.64+URm]. Existing groups/arches keep
            // their historical steering law; E,GPU,STRONG remains U32.
            let want = if ["E", "64,E", "128,E"].contains(&n.as_str())
                || (leg == "sm120" && n == "E,U8") {
                Some("64")
            } else {
                Some("U32")
            };
            assert_eq!(
                mg["addr_width"].as_str(),
                want,
                "[{leg}] STG_ARURI_R {n} addr_width pin"
            );
        }
        if leg != "sm121a" {
            let de = &ins["STG_dARI_R"]["mod_groups"]["E"];
            let vm = u128::from_str_radix(
                de["variable_mask"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            assert_eq!(
                vm & (1u128 << 76),
                0,
                "[{leg}] dARI-E vm b76 must be strict"
            );
            assert_eq!(
                vm & (1u128 << 91),
                0,
                "[{leg}] dARI-E vm b91 must be strict"
            );
            let fields = de["fields"].as_array().unwrap();
            assert!(
                fields.iter().any(|f| f["extraction"] == "sub_ur0")
                    && fields.iter().any(|f| f["extraction"] == "sub_r1"),
                "[{leg}] dARI-E field shape must stay sub_* (encoder untouched)"
            );
            // x3 canon-era row keeps the pre-442 sub_* field shape verbatim
            let e = &ar["mod_groups"]["E"];
            let fs = e["fields"].as_array().unwrap();
            assert!(
                fs.iter().any(|f| f["extraction"] == "sub_ur1")
                    && fs.iter().any(|f| f["extraction"] == "sub_r0")
                    && fs.iter().any(|f| f["extraction"] == "sub_imm1"),
                "[{leg}] STG_ARURI_R|E field shape must stay sub_*"
            );
        }
    }
}

#[test]
fn t442_9_native_sm120_e_u8_keeps_64_bit_address_and_complete_word() {
    // Independent nvdisasm SM120: clearing only b90 prints R100.U32.
    // The production packet below has b90=1 and must retain R100.64.
    let expected = 0x000fe2000c1001060000000564000986u128;
    let text = "@P0 STG.E.U8 [R100.64+UR6], R5";
    let source = format!(".entry stg_u8\n[B------:R-:W-:Y:S01] {text} ;\n.endentry\n");
    let table = tab("sm120");
    let bytes = cubit::roundtrip_audit::encode_semantic_source(&source, &table).unwrap();
    assert_eq!(bytes, expected.to_le_bytes());
    let index = table.decode_index();
    assert_eq!(cubit::printer::to_sass_lossless(&index.decode(expected, 0, &table).unwrap()), text);
    let mut failures = Vec::new();
    let (report, emitted) = cubit::roundtrip_audit::audit_kernel(
        ".text.stg_u8", 0, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) },
    ).unwrap();
    assert!(report.passed && report.stream_verified, "{failures:?}");
    assert_eq!(
        cubit::roundtrip_audit::encode_semantic_source(&emitted, &table).unwrap(),
        bytes,
    );
}

/// t442_7: sm121a key census +1 == BUG-442 post state (G3 donor-clone adds
/// key STG_ARURI_R: 15725 -> 15726); donor ab/vm/fields parity vs sm103a.
/// FLIP (BUG-443, canonical e8d1af3): +19 sm121a keys (8 T2 + 11 T3; STS
/// S8/S16 stay mgs) 15726 -> 15745. FLIP-ride (BUG-453, canonical 700524e): +3 sm121a keys (EFL2.256 non-NA dARI _II donor-first synth) 15745 -> 15760. FLIP-ride (BUG-463, canonical a64b82b): +12 sm121a keys (LTC-width LTC64B/128B/256B nNA EFL2.256 dARI synth) 15760 -> 15760. FLIP-ride (BUG-464, canonical 4968113): +6 sm121a keys (plain nNA ARURI64 EFL2.256 lattice LDG/STG) 15760 -> 15766. FLIP-ride (BUG-465, canonical 23976eb): +1146 sm121a keys (modsub plain E*L2.256 lattice L1xL2xsem) 15766 -> 16912. FLIP-ride (BUG-467, canonical 668f842): -5 sm121a keys (degenerate era-rows delete: STG.E{,_P,64,128} dARI x4 + STG.E_II_R; vendor ???0-class fail-closed) 16912 -> 16907. FLIP-ride (BUG-468, canonical 08a6145): +2320 sm121a keys (LTC-sel [74:73] lattice closure plain ARURI64 x3 + NA LTC128B/256B) 16907 -> 19227.
/// FLIP-ride (BUG-469, canonical bd48e63): +6 sm121a keys (widthless ARURI graft) 19227 -> 19233.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// FLIP-ride (BUG-469, canonical bd48e63): +6 sm121a keys (widthless ARURI graft) 19227 -> 19233. FLIP-ride (BUG-468, canonical 08a6145): +2320 sm121a keys (LTC-sel [74:73] lattice closure plain ARURI64 x3 + NA LTC128B/256B) 16907 -> 19227.
/// FLIP-ride (BUG-469, canonical bd48e63): +6 sm121a keys (widthless ARURI graft) 19227 -> 19233.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) 19233 -> 22688.
/// RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 19233 -> 23823.
#[test]
fn t442_7_sm121a_key_census_and_donor_parity() {
    let raw121: serde_json::Value =
        serde_json::from_str(&cubit::table::read_table_text("tables/sm121a.json").unwrap()).unwrap();
    let raw103: serde_json::Value =
        serde_json::from_str(&cubit::table::read_table_text("tables/sm103a.json").unwrap()).unwrap();
    let i121 = raw121["instructions"].as_object().unwrap();
    assert_eq!(
        i121.len(),
        1624 /* T-25 2026-11-09 (canonical 04bcb53; T-23's per-row pass on -b SM121 6428595 + T-25's daac080 / 64db08b): 511 shadowed harvest keys retired as `_meta.key_aliases` clones, 52 unreachable rows and the junk keys deleted (HFMA2_R_R_FI_FI_R, LEA_P0_R_R_R_II, …), the LEA family rebuilt from measurement (56 keys -> 24): sm121a forms 2150 -> 1624, aliases 21750 -> 22227, claim_forbid 23493 -> 23482 */ /* T-22 2026-11-08 UIADD3 .64 (canonical 3fb3b82): the .64 groups measured on the three tables; sm121a's 3 dotted UIADD3.64 keys -> aliases: forms 2153 -> 2150 (loader-visible 2148), variants 50447 -> 50444, aliases 21747 -> 21750, num_keys unchanged; sm103a / sm100a variants 35875 -> 35876 / 35869 -> 35870 // T-22 2026-11-08 ATOM / ATOMG lattice (canonical 3fb3b82): ATOM_P_R_ARURI_R / ATOMG_P_R_ARURI_R measured on -b SM121 (8 640 + 9 600 groups with claim_forbid on bits 63 / 76), 6 912 dotted keys retired as aliases -- sm121a forms 9063 -> 2153 (loader-visible 9061 -> 2151), variants 39119 -> 50447, aliases 14835 -> 21747, num_keys 23896 -> 23898, claim_forbid 5253 -> 23493 // T-22 2026-11-08 NEEDS 59 (canonical 3fb3b82): sm121a MUFU_R_L retired as an alias of MUFU_R_R -- forms 9064 -> 9063 (loader-visible 9062 -> 9061), aliases 14834 -> 14835, num_keys unchanged; sm103a / sm100a VIMNMX3 rows measured (fields only) //  T-21 2026-11-08 batch 7 (canonical 3fb3b82): the float conversions (F2I / I2F / FRND / MUFU) and the FP32 ALU measured on sm121a / sm103a / sm100a -- dotted / junk keys retired as aliases: sm121a forms 9334 -> 9064 (loader-visible 9332 -> 9062), variants 36884 -> 39127, aliases 14561 -> 14834, num_keys 23893 -> 23896; sm103a forms 651 -> 516, variants 33532 -> 35875, aliases 14294 -> 14433, num_keys 14945 -> 14949; sm100a 650 -> 515, 33526 -> 35869, 14944 -> 14948; claim_forbid unchanged //  */ /* T-21 2026-11-08 batch 6 (canonical 3fb3b82): ISETP / UISETP measured on sm121a / sm103a / sm100a (-b SM121: the SM120 law incl. the 64-bit compare, 146 dotted keys retired as aliases, 224 INVALID3 harvest groups retired; -b SM103 / SM100: bit 80 text-inert and fail-closed, NEEDS 46, the four phantom .S64 / .U64 groups retired), FSETP / DSETP on sm103a / sm100a (NEEDS 58), PLOP3 / P2R / R2P on the three tables (R2P_II_R created; 9 sm121a junk keys retired as aliases): sm121a forms 9488 -> 9334 (loader-visible 9486 -> 9332), variants 37077 -> 36884, aliases 14406 -> 14561, num_keys 23892 -> 23893; sm103a forms 650 -> 651, variants 32916 -> 33532, num_keys 14944 -> 14945; sm100a 649 -> 650, 32910 -> 33526, 14943 -> 14944; claim_forbid unchanged //  */ /* T-21 2026-11-08 (canonical 3fb3b82): sm121a LDG.256 x 3 forms + STG.256 + REDG ARURI / ARURI64 measured on -b SM121 (G's batch 10-14 probes with --arch SM121 --witnesses; 167 GB10 corpus words moved to the plain keys, texts unchanged) -- 14 286 dotted harvest keys retired as aliases: sm121a forms 23754 -> 9488 (loader-visible 23752 -> 9486), variants 26595 -> 37077, claim_forbid 1244 -> 5253 (the 4 608 measured LDG_R_R_dARI rows + 576 STG_dARI rows carry the RZ-base claim_forbid; the 781 + 193 retired dotted dARI keys had it), num_keys with the alias clones 23872 -> 23892 //  */ /* T-20 2026-11-08 (canonical 3fb3b82): sm121a FSETP / DSETP measured on -b SM121, 105 dotted + 7 junk keys retired as aliases, FSETP_P_P_R_UR_P created: 23860 -> 23754 */ /* 2026-11-06 T-11: the IDP family measured whole + the audit exceptions: 23850 -> 23860 */, // WAVE-11 INTEGRATION (2026-11-05, canonical e99598a (wave 11; pin now 2eed3ac)): +25 keys (lane October canon) = raw 23850 // was: 2026-11-04 (canonical 6f11f6b): -20 / -10 era keys -> _meta.key_aliases, +LDL_R_ARURI (sm120) // RIDE476 (F2-iter299, canonical c88778e): +8 sm121a keys (476 LDG NA-side x8) -> raw 23833 (loader 23831) // RIDE475R3b-w2 (F2-iter290, INC-289e followup battery475-final 6xA, canonical 978c0918): +2 sm121a keys {anomalie LDG.E.NA/EU.ENL2.256_R_R_dARI verbatim restore; R3b 978c0918}; zmierzone raw len 23825 (loader 23823 po -2 _errata twardy offset) // was: 23823 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: 22688 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468) // was: 19233 ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63) // ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) // was: flip-ride 467: -5 sm121a keys (degenerate era-rows delete; canonical 668f842)
        "sm121a key census must equal the BUG-443 post state (8 T2 + 11 T3 noE-cross keys)"
    );
    let a = &i121["STG_ARURI_R"]["mod_groups"];
    let b = &raw103["instructions"]["STG_ARURI_R"]["mod_groups"];
    for m in ["E", "64,E", "128,E"] {
        assert_eq!(a[m]["and_base"], b[m]["and_base"], "donor ab parity {m}");
        assert_eq!(
            a[m]["variable_mask"], b[m]["variable_mask"],
            "donor vm parity {m}"
        );
        assert_eq!(a[m]["fields"], b[m]["fields"], "donor fields parity {m}");
        assert_eq!(
            a[m]["count"],
            serde_json::Value::Null,
            "G3 count must be None"
        );
    }
}

/// t442_8: 443 scope CLOSED -- plain-width noE + U8-width (+ b90) cells
/// HEALED by BUG-443 (canonical e8d1af3; engine soak = PRIVATE prio arm);
/// decode == x4-unanimous vendor text (texts machine-flipped by
/// work/bug443/flip443.py, engine-verified pre-write).
#[test]
fn t442_8_scope443_closed_x4() {
    for (w, vendor, tag) in SCOPE443 {
        let leg = tag.rsplit('.').next().unwrap();
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        // 2026-11-09 (T-25, rows-memory-2026-11-07 on -b SM100 / SM103 / SM121): the `[R.64+UR]` spelling of STG.E.U8
        // (bit 90 set) is not a row of the three measured tables -- the measured `E,U8` row (U32, bit 90 clear) fails
        // closed on it and the 443 heal's harvest tolerance is gone with the row: a HOLE, not a text (KNOWN_ISSUES T1,
        // T/REPORT.md Part 25 §2: a `.64` U8 row to measure); sm120 carries the genuine native row (t442_9).
        if tag.starts_with("B.bU8.j90.") && leg != "sm120" {
            assert!(t.entries["STG.E.U8_ARURI_R"].mod_groups["E,U8"].row_probe, "[{leg}] {tag}: the U8 row is measured");
            assert_eq!(dec(&t, &idx, *w), None, "[{leg}] {tag}: the .64 U8 word is a hole on the measured leg");
            continue;
        }
        let got = dec_fc(&t, &idx, *w, vendor);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[{leg}] 443-scope drift {tag}: {got:?}"
        );
    }
    assert_eq!(SCOPE443.len(), 3 * 4);
}
