//! BUG-376 (F2-iter198, loop5/blind front2, 2026-09-04): LDGSTS desc LTC
//! lattice completion. Registered 376-kand LOW at F2-iter190 (360.md sec.6):
//! "reszta kraty LTC"; the arb matrix also exposed the code-2 ZFILL cross
//! gap (np '128,BYPASS,E,LTC128B,ZFILL' absent x3 era legs = MEASURED silent
//! phantom ', PT' via the _P row on nib-0 words on sm100a/sm103a, sm120
//! HOLE both sides; the class 374 cured for the non-LTC sibling).
//!
//! MEASUREMENT (pre-fix publish cubit-d0655a1c CLI 1b1ba6e4../pyo3
//! 04934802.., canonical e7f3e6f; measure_pre376{,_extra}.json): all graft
//! cells decode HOLE + encode loud REFUSE x4 legs BOTH key-sides, ZERO
//! silent wrong-text beyond the one phantom class cured here.
//!
//! LAW (arb376 108 donor-row sweeps + arb376b 99 lattice probes + sondy,
//! nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a AGREE on
//! EVERY probe, DIVERGENT=0): LTC code [73:72] upright (0 none / 1 LTC64B /
//! 2 LTC128B / 3 LTC256B); BYPASS = b81 CLEAR (inverted polarity; XOR-delta
//! b81); size = [75:74] (0 E / 1 64 / 2 128 / 3 INVALID3 kill); ZFILL = b82;
//! EVERY (size,BYPASS,ZFILL)xLTC cell legal on BOTH np and _P geometries;
//! print order 'LDGSTS.E[.BYPASS][.LTCxB][.64|.128][.ZFILL]'.
//!
//! FIX = canonical graft ONLY (canonical 6742fdf, patch376.py; ENGINE src
//! ZERO): donor-clone grafts, deltas asserted pure pre-graft (f1..f11 np /
//! p3..p12 _P, TOPD=0x1e<<108 convention per leg; g1..g8/g1p..g5p 121a).
//! Lattice post EXACT: era np == _P == 24 cells; 121a == 48 keys.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B72: u128 = 1 << 72;
const B73: u128 = 1 << 73;
const B74: u128 = 1 << 74;
const B75: u128 = 1 << 75;
const B81: u128 = 1 << 81;
const B82: u128 = 1 << 82;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const LEGS3: [&str; 3] = ["sm100a", "sm103a", "sm120"];
const F: u128 = 0x000000000b9a180e0000000016038fae_u128; // np '@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]'
const BW: u128 = 0x0003e20008981a0e018800801c5a7fae_u128; // _P nib=1

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}
fn mold(base: u128, size: u32, nobyp: bool, ltc: u32, zf: bool) -> u128 {
    let mut w = base & !(B74 | B75 | B72 | B73 | B81 | B82);
    if size & 1 != 0 {
        w |= B74;
    }
    if size & 2 != 0 {
        w |= B75;
    }
    if ltc & 1 != 0 {
        w |= B72;
    }
    if ltc & 2 != 0 {
        w |= B73;
    }
    if nobyp {
        w |= B81; // no BYPASS == b81 set (inverted polarity)
    }
    if zf {
        w |= B82;
    }
    w
}

#[test]
fn t376_1_structure_lattice_exact() {
    // X3 era legs: LDGSTS_ARI_dARI{,_P} mod-group sets == the exact 24-cell
    // lattice (6 size/BYPASS/ZFILL groups x4 LTC codes), every grafted row
    // _src-tagged bug376.
    let exp: std::collections::BTreeSet<&str> = [
        "E",
        "E,LTC64B",
        "E,LTC128B",
        "E,LTC256B",
        "64,E",
        "64,E,LTC64B",
        "64,E,LTC128B",
        "64,E,LTC256B",
        "128,E",
        "128,E,LTC64B",
        "128,E,LTC128B",
        "128,E,LTC256B",
        "128,E,ZFILL",
        "128,E,LTC64B,ZFILL",
        "128,E,LTC128B,ZFILL",
        "128,E,LTC256B,ZFILL",
        "128,BYPASS,E",
        "128,BYPASS,E,LTC64B",
        "128,BYPASS,E,LTC128B",
        "128,BYPASS,E,LTC256B",
        "128,BYPASS,E,ZFILL",
        "128,BYPASS,E,LTC64B,ZFILL",
        "128,BYPASS,E,LTC128B,ZFILL",
        "128,BYPASS,E,LTC256B,ZFILL",
        // BUG-386 flip (canonical dbe5e91): the 6 LTC=0 base-gap groups
        // complete the lattice to the exact 30-cell set per side.
        "BYPASS,E",
        "64,BYPASS,E",
        "E,ZFILL",
        "64,E,ZFILL",
        "BYPASS,E,ZFILL",
        "64,BYPASS,E,ZFILL",
    ]
    .into_iter()
    .collect();
    for leg in LEGS3 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
            let mgz = ins[key]["mod_groups"].as_object().unwrap();
            let names: std::collections::BTreeSet<&str> = mgz.keys().map(|s| s.as_str()).collect();
            assert_eq!(names, exp, "{leg} {key}: lattice != 30 cells (post-386)");
            let tagged = mgz
                .values()
                .filter(|g| g["_src"].as_str() == Some("bug376-2026-09-04"))
                .count();
            let want_tagged = match (leg, key) {
                (_, "LDGSTS_ARI_dARI") => 11,
                ("sm120", _) => 11,
                _ => 10,
            };
            assert_eq!(tagged, want_tagged, "{leg} {key}: bug376 _src census drift");
        }
    }
    // 121a dotted: exact 30 np + 30 _P keys post-386 (24 + 12 base-gap);
    // all 26 376-grafts keep their _src tag.
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let npp = ins
        .keys()
        .filter(|k| k.starts_with("LDGSTS") && k.ends_with("_ARI_dARI"))
        .count();
    let pp = ins
        .keys()
        .filter(|k| k.starts_with("LDGSTS") && k.ends_with("_ARI_dARI_P"))
        .count();
    assert_eq!(
        (npp, pp),
        (30, 30),
        "sm121a desc dotted census drift (post-386)"
    );
    let mut dotted_tagged = 0usize;
    for (k, e) in ins {
        if k.starts_with("LDGSTS.E.LTC") || k.starts_with("LDGSTS.E.BYPASS.LTC") {
            let mg = &e["mod_groups"][""];
            assert!(!mg.is_null());
            if mg["_src"].as_str() == Some("bug376-2026-09-04") {
                dotted_tagged += 1;
            }
        }
    }
    assert_eq!(dotted_tagged, 26, "sm121a bug376 dotted tag census drift");
}

#[test]
fn t376_2_decode_minted_grid_vendor_verbatim() {
    // Minted vendor-legal words (arb376b AGREE x4) decode byte-verbatim per
    // leg, np and _P geometry; the phantom-cured code-2 cross included.
    struct C(u32, bool, u32, bool, &'static str, &'static str);
    let cells = [
        C(
            0,
            true,
            1,
            false,
            "E,LTC64B",
            "@!P0 LDGSTS.E.LTC64B [R3], desc[UR14][R22.64]",
        ),
        C(
            1,
            true,
            1,
            false,
            "64,E,LTC64B",
            "@!P0 LDGSTS.E.LTC64B.64 [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            true,
            1,
            false,
            "128,E,LTC64B",
            "@!P0 LDGSTS.E.LTC64B.128 [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            true,
            1,
            true,
            "128,E,LTC64B,ZFILL",
            "@!P0 LDGSTS.E.LTC64B.128.ZFILL [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            false,
            1,
            false,
            "128,BYPASS,E,LTC64B",
            "@!P0 LDGSTS.E.BYPASS.LTC64B.128 [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            false,
            1,
            true,
            "128,BYPASS,E,LTC64B,ZFILL",
            "@!P0 LDGSTS.E.BYPASS.LTC64B.128.ZFILL [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            true,
            3,
            false,
            "128,E,LTC256B",
            "@!P0 LDGSTS.E.LTC256B.128 [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            true,
            3,
            true,
            "128,E,LTC256B,ZFILL",
            "@!P0 LDGSTS.E.LTC256B.128.ZFILL [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            false,
            3,
            false,
            "128,BYPASS,E,LTC256B",
            "@!P0 LDGSTS.E.BYPASS.LTC256B.128 [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            false,
            3,
            true,
            "128,BYPASS,E,LTC256B,ZFILL",
            "@!P0 LDGSTS.E.BYPASS.LTC256B.128.ZFILL [R3], desc[UR14][R22.64]",
        ),
        C(
            2,
            false,
            2,
            true,
            "128,BYPASS,E,LTC128B,ZFILL",
            "@!P0 LDGSTS.E.BYPASS.LTC128B.128.ZFILL [R3], desc[UR14][R22.64]",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for C(sz, nb, l, z, name, want) in &cells {
            let w = mold(F, *sz, *nb, *l, *z);
            assert_eq!(dec(&t, w).as_deref(), Some(*want), "{leg} np {name}");
        }
    }
    // _P side spot grid (nib=1 -> ', P1')
    struct CP(u32, bool, u32, bool, &'static str);
    let pcells = [
        CP(
            0,
            true,
            1,
            false,
            "LDGSTS.E.LTC64B [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        CP(
            2,
            false,
            1,
            true,
            "LDGSTS.E.BYPASS.LTC64B.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        CP(
            2,
            false,
            2,
            true,
            "LDGSTS.E.BYPASS.LTC128B.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        CP(
            2,
            true,
            3,
            false,
            "LDGSTS.E.LTC256B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for CP(sz, nb, l, z, want) in &pcells {
            let w = mold(BW, *sz, *nb, *l, *z);
            assert_eq!(dec(&t, w).as_deref(), Some(*want), "{leg} _P l{l}");
        }
    }
}

#[test]
fn t376_3_encode_cured_and_phantom_killed() {
    // Authored texts encode on all legs (post-graft coverage); the phantom
    // nib-0 word round-trips WITHOUT ', PT' through the np row.
    let texts_np = [
        "@!P0 LDGSTS.E.LTC64B [R3], desc[UR14][R22.64]",
        "@!P0 LDGSTS.E.LTC64B.64 [R3], desc[UR14][R22.64]",
        "@!P0 LDGSTS.E.LTC64B.128.ZFILL [R3], desc[UR14][R22.64]",
        "@!P0 LDGSTS.E.BYPASS.LTC256B.128 [R3], desc[UR14][R22.64]",
        "@!P0 LDGSTS.E.BYPASS.LTC128B.128.ZFILL [R3], desc[UR14][R22.64]",
    ];
    let texts_p = [
        "LDGSTS.E.LTC64B [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        "LDGSTS.E.BYPASS.LTC256B.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
    ];
    for leg in LEGS {
        let t = tab(leg);
        for tx in texts_np.iter().chain(texts_p.iter()) {
            let w = enc(&t, tx).unwrap_or_else(|e| panic!("{leg} encode FAIL {tx}: {e}"));
            let back = dec(&t, w).unwrap_or_else(|| panic!("{leg} roundtrip HOLE {tx}"));
            assert_eq!(&back, tx, "{leg} roundtrip drift {tx}");
        }
    }
    // phantom class: the nib-0 np word on the code-2 BYPASS+ZFILL cross
    for leg in LEGS {
        let t = tab(leg);
        let w = mold(F, 2, false, 2, true);
        let d = dec(&t, w).expect(&format!("{leg}: code-2 cross HOLE (376 regression)"));
        assert!(
            !d.contains(", PT"),
            "{leg}: phantom ', PT' resurrected: {d}"
        );
    }
}

#[test]
fn t376_4_fail_closed_outside_graft() {
    // size code 3 (INVALID3 vendor kill, rc=0 pseudo-op line) stays engine
    // HOLE on every leg, with and without LTC64B.
    for leg in LEGS {
        let t = tab(leg);
        for w in [
            (F | B74 | B75),
            (F | B74 | B75 | B72),
            mold(BW, 3, true, 1, false),
        ] {
            assert_eq!(dec(&t, w), None, "{leg}: INVALID3 word must stay HOLE");
        }
        // BUG-386 flip (canonical dbe5e91): the LTC=0 base-gap lattice
        // CLOSED ('E,ZFILL' & siblings now grafted) -- decode/mint/roundtrip
        // positives in t386_2/t386_3; the fail-closed stance moved to the
        // LTC crosses of the new base groups (t386_4 pins them HOLE).
        assert!(
            dec(&t, mold(F, 0, false, 1, false)).is_none(),
            "{leg}: BYPASS,E,LTC64B must stay HOLE (386 scope = LTC=0 only)"
        );
    }
}

#[test]
fn t376_5_template_inheritance_and_vm_cleanliness() {
    // (a) none of the lattice bits [75:74]/[73:72]/b81/b82 is vm-covered
    // in ANY LDGSTS desc row post-graft (claim integrity).
    // (b) baked-template inheritance: every grafted row's and_base[127:96]
    // equals its in-side in-leg donor's window VERBATIM; per-leg census of
    // grafted rows baking [127:105] pinned (measured 17/17/22).
    // (c) 121a: every desc dotted row keeps hi32 == 0.
    const DONORS: [(&str, &str); 11] = [
        ("E,LTC64B", "E"),
        ("64,E,LTC64B", "64,E"),
        ("128,E,LTC64B", "128,E"),
        ("128,E,LTC64B,ZFILL", "128,E,ZFILL"),
        ("128,BYPASS,E,LTC64B", "128,BYPASS,E"),
        ("128,BYPASS,E,LTC64B,ZFILL", "128,BYPASS,E,ZFILL"),
        ("128,E,LTC256B", "128,E"),
        ("128,E,LTC256B,ZFILL", "128,E,ZFILL"),
        ("128,BYPASS,E,LTC256B", "128,BYPASS,E"),
        ("128,BYPASS,E,LTC256B,ZFILL", "128,BYPASS,E,ZFILL"),
        ("128,BYPASS,E,LTC128B,ZFILL", "128,BYPASS,E,ZFILL"),
    ];
    let hi_of = |g: &serde_json::Value| -> u128 {
        u128::from_str_radix(g["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
            >> 96
    };
    for leg in LEGS3 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let mut baked = 0usize;
        for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
            let mgz = ins[key]["mod_groups"].as_object().unwrap();
            for (n, g) in mgz {
                let vm = u128::from_str_radix(
                    g["variable_mask"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(
                    vm & (B74 | B75 | B72 | B73 | B81 | B82),
                    0,
                    "{leg} {key} {n}: lattice bit vm-covered"
                );
            }
            for (n, d) in DONORS {
                let Some(g) = mgz.get(n) else { continue };
                if g["_src"].as_str() != Some("bug376-2026-09-04") {
                    continue;
                }
                assert_eq!(
                    hi_of(g),
                    hi_of(&mgz[d]),
                    "{leg} {key} {n}: donor template drift (donor {d})"
                );
                if hi_of(g) & (((1u128) << 23) - 1) << 9 != 0 || hi_of(g) >> 9 != 0 {
                    baked += 1;
                }
            }
        }
        let want = if leg == "sm120" { 22 } else { 17 };
        assert_eq!(baked, want, "{leg}: grafted baked-template census drift");
    }
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    for (k, e) in raw["instructions"].as_object().unwrap() {
        if !k.contains("LDGSTS.E") || !(k.ends_with("_ARI_dARI") || k.ends_with("_ARI_dARI_P")) {
            continue;
        }
        let ab = u128::from_str_radix(
            e["mod_groups"][""]["and_base"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        assert_eq!(ab >> 96, 0, "{k}: sm121a desc row gained baked hi32");
    }
}
