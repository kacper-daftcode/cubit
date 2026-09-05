//! BUG-374 (F2-iter197, loop5/blind front2, 2026-09-04): LDGSTS desc
//! BYPASS+ZFILL non-alloc row closures. Registered 374-kand LOW at
//! F2-iter189 (359.md sec.6); the measured class is WIDER than the note
//! (BUG-371 precedent): '_P 128,BYPASS,E' plain was HOLE on x3 legs
//! era+120, not only sm120.
//!
//! MEASUREMENT (pre-fix publish cubit-e5804637 CLI d7cd92a3../pyo3
//! e17a8b67.., canonical 6b7a120; measure_pre373_375.json):
//!  * np '128,BYPASS,E,ZFILL': sm120 = loud HOLE; sm100a/103a = SILENT
//!    mis-claim of nib-7 words by the _P row printing a phantom ', PT'
//!    (era-side text corruption on a vendor-legal word; arb359 N5);
//!  * _P '128,BYPASS,E' plain: HOLE x3 legs era+120 (vendor-legal x4);
//!  * _P '128,BYPASS,E,ZFILL': HOLE sm120 (era legs rowed; arb359 N2).
//!
//! LAW (arb359 88 + arb373_375 109 + bisect 6 probes, nvdisasm 13.3.73
//! raw -b, x4 models AGREE EVERY, DIVERGENT=0): b81=BYPASS / b82=ZFILL /
//! b73=LTC128B pure ab deltas asserted per carrier; nibble [90:87] =
//! era-map trailing pred (v&7 pred, v&8 invert, v=7 PT-elided) on BOTH
//! F-class and B-class geometries (bisect: no extra discriminator bit);
//! sm120 ZFILL-carrier _P rows carry the documented TOPD=0x1e000000<<96
//! convention (outside M96 care; claim-identical to the sm103a sibling).
//!
//! FIX = canonical graft ONLY (canonical e7f3e6f, patch373_375.py;
//! ENGINE src ZERO): LDGSTS_ARI_dARI += '128,BYPASS,E,ZFILL' x3 legs;
//! LDGSTS_ARI_dARI_P += '128,BYPASS,E' x3 legs era+120 and
//! '128,BYPASS,E,ZFILL' on sm120. New rows care-match the vendor
//! witnesses N5/N6/N2 (asserted in-patch); no-new-collisions audit
//! fam-overlap pairs IDENT pre/post.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B73: u128 = 1 << 73;
const B81: u128 = 1 << 81;
const B82: u128 = 1 << 82;
const LEGS3: [&str; 3] = ["sm100a", "sm103a", "sm120"];
const F: u128 = 0x000000000b9a180e0000000016038fae_u128;
const BW: u128 = 0x0003e20008981a0e018800801c5a7fae_u128;
const N5: u128 = F ^ B81 ^ B82; // np BYPASS+128+ZFILL, nib 7 (PT-elided)
const N2: u128 = (BW & !B73) ^ B82; // _P BYPASS+128+ZFILL, ', P1'
const N6: u128 = BW & !B73; // _P BYPASS+128 plain, ', P1'

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

#[test]
fn t374_1_structure_rows_and_attribution() {
    for leg in LEGS3 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let np = raw["instructions"]["LDGSTS_ARI_dARI"]["mod_groups"]
            .as_object()
            .unwrap();
        let p = raw["instructions"]["LDGSTS_ARI_dARI_P"]["mod_groups"]
            .as_object()
            .unwrap();
        // BUG-376 flip (canonical 6742fdf): LTC-lattice completion brings
        // the desc family to the exact 24-cell lattice (6 groups x4 LTC
        // codes) per side on every era leg; the 373/374/375 attribution
        // checks below stand.
        // BUG-386 flip (canonical dbe5e91): +6 LTC=0 base-gap groups per
        // side -> exact 30-cell lattice per side on every era leg.
        assert_eq!(
            np.len(),
            30,
            "{leg}: np mg census drift (post-386 lattice 30)"
        );
        assert_eq!(
            np["128,BYPASS,E,ZFILL"]["_src"].as_str(),
            Some("bug373_375-2026-09-04"),
            "{leg}: np graft attribution"
        );
        assert_eq!(
            p["128,BYPASS,E"]["_src"].as_str(),
            Some("bug373_375-2026-09-04"),
            "{leg}: _P plain-BYPASS graft attribution"
        );
        assert_eq!(
            p.len(),
            30,
            "{leg}: _P mg census drift (post-386 lattice 30)"
        );
        if leg == "sm120" {
            assert_eq!(
                p["128,BYPASS,E,ZFILL"]["_src"].as_str(),
                Some("bug373_375-2026-09-04"),
                "sm120: _P BYPASS+ZFILL graft attribution"
            );
        }
    }
}

#[test]
fn t374_2_np_bypass_zfill_vendor_exact_no_phantom_pt() {
    // THE silent-corruption class: nib-7 np words must route to the np row
    // (no trailing ', PT'); mint+roundtrip byte-exact x3 legs.
    for leg in LEGS3 {
        let t = tab(leg);
        let d = dec(&t, N5).unwrap_or_else(|| panic!("{leg}: N5 HOLE"));
        assert_eq!(
            d.trim(),
            "@!P0 LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64]",
            "{leg}: np route lost / phantom pred survives: {d:?}"
        );
        for txt in [
            "@!P0 LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64]",
            "LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64]",
            "@P2 LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64+0x40]",
        ] {
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("{leg} {txt}: {e}"));
            let back = dec(&t, w).expect("roundtrip decode");
            let re = enc(&t, back.trim()).expect("re-encode");
            assert_eq!(re & M96, w & M96, "{leg} roundtrip {back}");
        }
        let w = enc(
            &t,
            "@!P0 LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64]",
        )
        .unwrap();
        assert_eq!(w & M96, N5 & M96, "{leg}: np mint != vendor witness N5");
    }
}

#[test]
fn t374_3_p_plain_bypass_vendor_exact_x3() {
    // Wider-than-note class: _P plain BYPASS was HOLE x3 era+120.
    let want = "LDGSTS.E.BYPASS.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1";
    for leg in LEGS3 {
        let t = tab(leg);
        let d = dec(&t, N6).unwrap_or_else(|| panic!("{leg}: N6 HOLE"));
        assert_eq!(d.trim(), want, "{leg}: _P plain-BYPASS decode drift");
        let w = enc(&t, want).unwrap_or_else(|e| panic!("{leg}: {e}"));
        assert_eq!(w & M96, N6 & M96, "{leg}: _P plain-BYPASS mint drift");
        // inverted trailing pred (era pred 3b@87 + neg 1b@90)
        let wn = enc(
            &t,
            "LDGSTS.E.BYPASS.128 [R90+0x1880], desc[UR14][R28.64+0x80], !P1",
        )
        .expect("neg mint");
        assert_eq!(wn & M96, (N6 | (1 << 90)) & M96, "{leg}: neg@90 mint");
        let d = dec(&t, wn).unwrap();
        assert!(d.ends_with("!P1"), "{leg}: neg render {d:?}");
    }
}

#[test]
fn t374_4_p_bypass_zfill_sm120_vendor_exact() {
    // sm120-only graft (era legs pre-rowed; arb359 N2 witness).
    let want = "LDGSTS.E.BYPASS.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1";
    for leg in ["sm120", "sm103a", "sm100a"] {
        let t = tab(leg);
        let d = dec(&t, N2).unwrap_or_else(|| panic!("{leg}: N2 HOLE"));
        assert_eq!(d.trim(), want, "{leg}: _P BYPASS+ZFILL decode drift");
        let w = enc(&t, want).expect("mint");
        assert_eq!(w & M96, N2 & M96, "{leg}: _P BYPASS+ZFILL mint drift");
    }
    // sm120 ZFILL-carrier TOPD convention: the _P ZFILL carriers keep the
    // 359-era inert upper region (ab>>96 == 0x1e000 on those rows; the
    // M96 claim window is untouched).
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    let p = raw["instructions"]["LDGSTS_ARI_dARI_P"]["mod_groups"]
        .as_object()
        .unwrap();
    let ab = u128::from_str_radix(
        p["128,BYPASS,E,ZFILL"]["and_base"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    // convention delta measured: ab>>96 == 0x1e000 (inert bits >104, no
    // M96 care impact -- the patch asserts claim-space identity vs the
    // sm103a sibling and care-matches the vendor witness N2).
    assert_eq!(ab >> 96, 0x1e000, "sm120 TOPD convention drift");
}

#[test]
fn t374_5_kill_lint_and_provenance() {
    // desc offset beyond signed-12 stays lint-loud on the new rows.
    for leg in LEGS3 {
        let t = tab(leg);
        assert!(
            enc(
                &t,
                "LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64+0x1000]"
            )
            .is_err(),
            "{leg}: np desc overflow must stay lint loud"
        );
        assert!(
            enc(
                &t,
                "LDGSTS.E.BYPASS.128 [R3], desc[UR14][R22.64+0x1000], P1"
            )
            .is_err(),
            "{leg}: _P desc overflow must stay lint loud"
        );
        // BUG-376 flip: arb376b proved BYPASS combines with EVERY LTC code
        // x4 (vendor text 'LDGSTS.E.BYPASS.LTC256B.128'); the class is
        // grafted since 6742fdf -> encodes + decodes vendor-verbatim.
        let w = enc(&t, "LDGSTS.E.BYPASS.LTC256B.128 [R3], desc[UR14][R22.64]")
            .unwrap_or_else(|e| panic!("{leg}: BYPASS+LTC256B must encode post-376: {e}"));
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("LDGSTS.E.BYPASS.LTC256B.128 [R3], desc[UR14][R22.64]"),
            "{leg}: BYPASS+LTC256B roundtrip drift"
        );
    }
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    assert!(
        raw["_meta"]["bug374"]
            .as_str()
            .unwrap_or("")
            .contains("BUG-374"),
        "bug374 provenance missing"
    );
}
