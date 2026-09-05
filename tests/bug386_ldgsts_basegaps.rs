//! BUG-386 (F2-iter204, loop5/blind front2, 2026-09-05): LDGSTS desc
//! base-gap lattice completion. Registered 386-kand LOW at F2-iter198
//! (376.md sec.7): the 6 (size,BYPASS,ZFILL) base groups at LTC=0 missing
//! era np/_P x3 legs + x12 dotted sm121a keys: 'BYPASS,E' (s32) /
//! '64,BYPASS,E' / 'E,ZFILL' / '64,E,ZFILL' / 'BYPASS,E,ZFILL' /
//! '64,BYPASS,E,ZFILL'.
//!
//! MEASUREMENT (pre-fix publish cubit_py-4fc11250 b26fa243.., canonical
//! 3cb31e4; work/bug386/measure_pre386.json): all 6 cells decode HOLE x4
//! legs on BOTH np/_P geometries + encode loud FAIL x8; controls OK=V x4.
//! ZERO silent wrong-text (the 360 Part C ur0 9b->8b hardening routes
//! unclaimed words to loud HOLE).
//!
//! LAW (arb386 31 per-cell probes + arb376b 99-probe matrix, nvdisasm
//! 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a AGREE on EVERY
//! probe, DIVERGENT=0): every cell legal x4; print order
//! 'LDGSTS.E[.BYPASS][.LTCxB][.sz][.ZFILL]'; BYPASS = b81 CLEAR (inverted
//! polarity); size [75:74]; ZFILL b82. INVALID3 (size=3) stays a vendor
//! pseudo-op (engine HOLE fail-closed).
//!
//! FIX = canonical graft ONLY (canonical dbe5e91, patch386.py; ENGINE src
//! ZERO): donor-clone grafts from in-side in-ZFILL-carrier donors
//! (composite purity deltas asserted; _P ZFILL-carrier crossing rides
//! B82|TOPD on 100a/103a via the donor, pure on sm120); baked control
//! templates [127:105] ride VERBATIM (grafted baked census 8/8/12/0 per
//! leg; 121a hi32==0 asserted). Lattice post EXACT: era np == _P == 30
//! cells; sm121a == 60 keys (30 np + 30 _P).
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
fn t386_1_structure_lattice_exact_30() {
    // x3 era legs: LDGSTS_ARI_dARI{,_P} mod-group sets == the exact 30-cell
    // lattice (the 24-cell post-376 set + the 6 base-gap groups); every
    // grafted row _src-tagged bug386.
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
            assert_eq!(names, exp, "{leg} {key}: lattice != 30 cells");
            let tagged = mgz
                .values()
                .filter(|g| g["_src"].as_str() == Some("bug386-2026-09-05"))
                .count();
            assert_eq!(tagged, 6, "{leg} {key}: bug386 _src census drift");
        }
    }
    // 121a dotted: exact 30 np + 30 _P keys; 12 grafts _src-tagged.
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
    assert_eq!((npp, pp), (30, 30), "sm121a desc dotted census drift");
    let dotted: std::collections::BTreeSet<&str> = ins
        .iter()
        .filter(|(k, e)| {
            k.starts_with("LDGSTS.E.")
                && (k.ends_with("_ARI_dARI") || k.ends_with("_ARI_dARI_P"))
                && e["mod_groups"][""]["_src"].as_str() == Some("bug386-2026-09-05")
        })
        .map(|(k, _)| k.as_str())
        .collect();
    let exp121: std::collections::BTreeSet<&str> = [
        "LDGSTS.E.BYPASS_ARI_dARI",
        "LDGSTS.E.BYPASS.64_ARI_dARI",
        "LDGSTS.E.ZFILL_ARI_dARI",
        "LDGSTS.E.64.ZFILL_ARI_dARI",
        "LDGSTS.E.BYPASS.ZFILL_ARI_dARI",
        "LDGSTS.E.BYPASS.64.ZFILL_ARI_dARI",
        "LDGSTS.E.BYPASS_ARI_dARI_P",
        "LDGSTS.E.BYPASS.64_ARI_dARI_P",
        "LDGSTS.E.ZFILL_ARI_dARI_P",
        "LDGSTS.E.64.ZFILL_ARI_dARI_P",
        "LDGSTS.E.BYPASS.ZFILL_ARI_dARI_P",
        "LDGSTS.E.BYPASS.64.ZFILL_ARI_dARI_P",
    ]
    .into_iter()
    .collect();
    assert_eq!(dotted, exp121, "sm121a base-gap dotted graft set drift");
}

#[test]
fn t386_2_decode_minted_grid_vendor_verbatim() {
    // Minted vendor-legal words (arb386 AGREE x4) decode byte-verbatim per
    // leg on BOTH geometries.
    struct C(u32, bool, bool, &'static str);
    let cells = [
        C(0, false, false, "LDGSTS.E.BYPASS"),
        C(1, false, false, "LDGSTS.E.BYPASS.64"),
        C(0, true, true, "LDGSTS.E.ZFILL"),
        C(1, true, true, "LDGSTS.E.64.ZFILL"),
        C(0, false, true, "LDGSTS.E.BYPASS.ZFILL"),
        C(1, false, true, "LDGSTS.E.BYPASS.64.ZFILL"),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for C(s, nb, z, core) in &cells {
            let want_np = format!("@!P0 {core} [R3], desc[UR14][R22.64]");
            let d =
                dec(&t, mold(F, *s, *nb, 0, *z)).unwrap_or_else(|| panic!("{leg} np HOLE {core}"));
            assert_eq!(d, want_np, "{leg} np decode drift {core}");
            let want_p = format!("{core} [R90+0x1880], desc[UR14][R28.64+0x80], P1");
            let d =
                dec(&t, mold(BW, *s, *nb, 0, *z)).unwrap_or_else(|| panic!("{leg} _P HOLE {core}"));
            assert_eq!(d, want_p, "{leg} _P decode drift {core}");
        }
    }
}

#[test]
fn t386_3_encode_mint_and_roundtrip() {
    // Authored texts encode on all legs + round-trip byte-exact (np and _P
    // shapes); the minted low96 equals the arb-witnessed word.
    let texts_np = [
        (
            0u32,
            false,
            false,
            "@!P0 LDGSTS.E.BYPASS [R3], desc[UR14][R22.64]",
        ),
        (
            1u32,
            false,
            false,
            "@!P0 LDGSTS.E.BYPASS.64 [R3], desc[UR14][R22.64]",
        ),
        (
            0u32,
            true,
            true,
            "@!P0 LDGSTS.E.ZFILL [R3], desc[UR14][R22.64]",
        ),
        (
            1u32,
            true,
            true,
            "@!P0 LDGSTS.E.64.ZFILL [R3], desc[UR14][R22.64]",
        ),
        (
            0u32,
            false,
            true,
            "@!P0 LDGSTS.E.BYPASS.ZFILL [R3], desc[UR14][R22.64]",
        ),
        (
            1u32,
            false,
            true,
            "@!P0 LDGSTS.E.BYPASS.64.ZFILL [R3], desc[UR14][R22.64]",
        ),
    ];
    let texts_p = [
        (
            0u32,
            false,
            false,
            "LDGSTS.E.BYPASS [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            1u32,
            false,
            true,
            "LDGSTS.E.BYPASS.64.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (s, nb, z, tx) in texts_np.iter().chain(texts_p.iter()) {
            let w = enc(&t, tx).unwrap_or_else(|e| panic!("{leg} encode FAIL {tx}: {e}"));
            let base = if tx.contains("R90") { BW } else { F };
            assert_eq!(
                w & M96,
                mold(base, *s, *nb, 0, *z) & M96,
                "{leg} mint low96 drift {tx}"
            );
            let back = dec(&t, w).unwrap_or_else(|| panic!("{leg} roundtrip HOLE {tx}"));
            assert_eq!(&back, tx, "{leg} roundtrip drift {tx}");
        }
    }
}

#[test]
fn t386_4_fail_closed_invalid3_and_outside() {
    // size=3 (INVALID3 vendor pseudo-op, arb386 K1-K3) stays engine HOLE on
    // every leg with the new base combos' BYPASS/ZFILL play; junk b70/b71
    // variants stay vendor-rendered UR-field windows (NOT pinned here --
    // they ride the desc_ur field, law of 376b).
    for leg in LEGS {
        let t = tab(leg);
        for (s, nb, z) in [
            (3u32, false, false),
            (3u32, true, true),
            (3u32, false, true),
        ] {
            assert_eq!(
                dec(&t, mold(F, s, nb, 0, z)),
                None,
                "{leg}: INVALID3 np base-gap word must stay HOLE"
            );
        }
        // LTC crosses of the base-gap groups are deliberately NOT grafted
        // (386 scope = LTC=0 cells; the LTC>0 crosses of the s32/s64 B/Z
        // groups stay loud until their own census-driven ticket).
        assert_eq!(
            dec(&t, mold(F, 0, false, 1, false)),
            None,
            "{leg}: BYPASS,E,LTC64B stays HOLE"
        );
        assert_eq!(
            dec(&t, mold(F, 1, false, 3, true)),
            None,
            "{leg}: 64,BYPASS,E,LTC256B,ZFILL stays HOLE"
        );
        assert!(enc(&t, "@!P0 LDGSTS.E.BYPASS.LTC64B [R3], desc[UR14][R22.64]").is_err());
        assert!(enc(
            &t,
            "@!P0 LDGSTS.E.64.LTC256B.ZFILL [R3], desc[UR14][R22.64]"
        )
        .is_err());
    }
}

#[test]
fn t386_5_template_inheritance_and_vm_cleanliness() {
    // (a) lattice bits [75:74]/[73:72]/b81/b82 never vm-covered on the 386
    //     donors (claim integrity);
    // (b) baked-template inheritance: every grafted row's and_base
    //     [127:105] equals its donor's window VERBATIM; per-leg census of
    //     grafted rows baking [127:105]: 8 / 8 / 12 (measured, like 376:
    //     100a/103a _P ZFILL-class donors bake none; sm120 _P uniform);
    // (c) 121a: every dotted desc row keeps hi32 == 0.
    let donors: [(&str, &str); 6] = [
        ("BYPASS,E", "128,BYPASS,E"),
        ("64,BYPASS,E", "128,BYPASS,E"),
        ("E,ZFILL", "128,E,ZFILL"),
        ("64,E,ZFILL", "128,E,ZFILL"),
        ("BYPASS,E,ZFILL", "128,BYPASS,E,ZFILL"),
        ("64,BYPASS,E,ZFILL", "128,BYPASS,E,ZFILL"),
    ];
    let lattice_bits = B72 | B73 | B74 | B75 | B81 | B82;
    for leg in LEGS3 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let mut baked = 0usize;
        for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
            let mgz = ins[key]["mod_groups"].as_object().unwrap();
            for (new, donor) in &donors {
                let g = &mgz[*donor];
                let vm: String = g["variable_mask"].as_str().unwrap_or("0x0").to_string();
                let vmv = u128::from_str_radix(vm.trim_start_matches("0x"), 16).unwrap();
                assert_eq!(
                    vmv & lattice_bits,
                    0,
                    "{leg} {key} {donor}: lattice bit vm-covered"
                );
                let gh = u128::from_str_radix(
                    mgz[*new]["and_base"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                let dh = u128::from_str_radix(
                    g["and_base"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(
                    gh >> 105,
                    dh >> 105,
                    "{leg} {key} {new}: baked-template window drift vs donor {donor}"
                );
                if gh >> 105 != 0 {
                    baked += 1;
                }
            }
        }
        let want = if leg == "sm120" { 12 } else { 8 };
        assert_eq!(baked, want, "{leg}: grafted baked census drift");
    }
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    for (k, e) in ins {
        if k.starts_with("LDGSTS") && k.contains("_ARI_dARI") {
            let ab = u128::from_str_radix(
                e["mod_groups"][""]["and_base"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            assert_eq!(ab >> 96, 0, "{k}: 121a dotted hi32 drift");
        }
    }
}
