//! BUG-442 pins (F2-iter246, loop5/blind front2, 2026-09-11): STG.E ARURI
//! desc-kind lattice [91:90) closure + b76 desc-marker domain + 121a ARURI
//! row-family completion.
//! Canonical ffa3244 -> 57e7ecd (patch442.py replayable+idempotent; replay
//! z pristine ffa3244 byte-exact x4 = e309967e/5cf2536a/a8a6cac8/7e2a2e26;
//! idem rerun all-skip). ENGINE: JEDEN printer-arm soak (STG_ARURI_R
//! canon-era plain shape sub_ur1/sub_r0/sub_imm1 -> format_plain_u32_ur;
//! reszta src ZERO) + tools/sync_table.py ratchet SM121A 541->544 (3 donor
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
const LEGS_442: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn leg_of(tag: &str) -> String {
    tag.rsplit('.')
        .next()
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_string()
}

/// t442_1: healed grid -- decode == vendor text x4 legs on every (1,1)
/// free-form word (10 words x4; dup tag arb438b.STG.j90 == A.j90 folded).
#[test]
fn t442_1_healed_grid_x4() {
    for leg in LEGS_442 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW442_HEAL {
            let got = dec(&t, &idx, *w);
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
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] stable drift {w:#034x}"
            );
        }
    }
}

/// t442_3: kill-lattice postures -- per-leg snap (= POST: HOLE expected on
/// every released kill; the single rc1-standing claim B.b128.p01.121a is
/// the invariant STG_ARI_R|128,E pre==post breadth claim).
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
        let got = dec(&t, &idx, *w);
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
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    let pin = m["base_revision"].as_str().unwrap().to_string();
    assert!(
        pin.starts_with("9b60b92"),
        "SOURCE.json must pin canonical 57e7ecd (= BUG-447, ride-after e8d1af3 = BUG-443, 57e7ecd = BUG-442, ffa3244 = BUG-441): {pin}"
    );
    for leg in LEGS_442 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
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
                assert!(
                    vm & (1u128 << 90) != 0,
                    "[{leg}] {key} vm b90 must be relaxed (G2)"
                );
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
            let want = if ["E", "64,E", "128,E"].contains(&n.as_str()) {
                Some("64")
            } else {
                Some("U32")
            };
            assert_eq!(mg["addr_width"].as_str(), want, "[{leg}] STG_ARURI_R {n} addr_width pin");
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

/// t442_7: sm121a key census +1 == BUG-442 post state (G3 donor-clone adds
/// key STG_ARURI_R: 15725 -> 15726); donor ab/vm/fields parity vs sm103a.
/// FLIP (BUG-443, canonical e8d1af3): +19 sm121a keys (8 T2 + 11 T3; STS
/// S8/S16 stay mgs) 15726 -> 15745.
#[test]
fn t442_7_sm121a_key_census_and_donor_parity() {
    let raw121: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    let raw103: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm103a.json").unwrap()).unwrap();
    let i121 = raw121["instructions"].as_object().unwrap();
    assert_eq!(
        i121.len(),
        15745,
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
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*vendor), "[{leg}] 443-scope drift {tag}: {got:?}");
    }
    assert_eq!(SCOPE443.len(), 3 * 4);
}
