//! BUG-375 (F2-iter197, loop5/blind front2, 2026-09-04): sm121a trailing-
//! _P LDGSTS desc family ported (11 dotted keys). Registered 375-kand LOW
//! at F2-iter189 (359.md sec.6): complete absence of _P rows for the
//! dARI{,_P} desc family on sm121a -- HOLE incl the corpus witness B
//! (flora: 164-cubin SHFL-era corpus anchors it as a real-world form).
//!
//! MEASUREMENT (pre-fix publish cubit-e5804637, canonical 6b7a120;
//! measure_pre373_375.json): decode HOLE on sm121a for B (BYPASS+LTC _P),
//! T3 (alloc+LTC _P), N3/N4 (ZFILL _P classes) -- all vendor-legal x4.
//!
//! LAW (arb359 + arb373_375 P375 sweeps + P374, nvdisasm 13.3.73 raw -b,
//! x4 models SM100a/SM103a/SM120/SM121a AGREE on EVERY probe,
//! DIVERGENT=0): trailing pred nibble [90:87] = v&7 pred, v&8 inverted,
//! v=7 PT-elided, v=15 '!PT' -- the ERA map, NOT the sm121a pred_inv4
//! inverted map used by e.g. LDG.E.*_dARI_P rows. The LDGSTS desc family
//! follows the era map on SM121a (pred_inv4 lane probed and REJECTED:
//! nibble1 renders ', P1', not P6).
//!
//! FIX = canonical graft ONLY (canonical e7f3e6f, patch373_375.py;
//! ENGINE src ZERO): each of the 11 dotted non-_P keys K cloned to K_P
//! with era-style pred 3b@87 + neg 1b@90 tok3 appended (post-373 guard
//! 4b@12 geometry inherited), and_base/variable_mask = donor (the engine
//! carves field bits at match, decoder.rs:131). no-new-collisions audit
//! fam-overlap pairs IDENT pre/post (rows 17970 -> 17981).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B73: u128 = 1 << 73;
const B74: u128 = 1 << 74;
const B75: u128 = 1 << 75;
const B81: u128 = 1 << 81;
const B82: u128 = 1 << 82;
const F: u128 = 0x000000000b9a180e0000000016038fae_u128;
const BW: u128 = 0x0003e20008981a0e018800801c5a7fae_u128;

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
fn t375_1_structure_11_p_clones_era_pred() {
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let base: Vec<&String> = ins
        .keys()
        .filter(|k| k.contains("LDGSTS") && k.ends_with("_ARI_dARI"))
        .collect();
    // BUG-376 flip (canonical 6742fdf): +13 non-_P dotted keys
    // (LTC-lattice completion) -- 11 + 13 = 24; every base keeps its _P clone.
    // BUG-386 flip (canonical dbe5e91): +6 base-gap dotted keys -- 30; every
    // base keeps its _P clone.
    assert_eq!(
        base.len(),
        30,
        "121a non-_P dARI key census drift (post-386 = 30)"
    );
    let mut clones = 0usize;
    for k in &base {
        let pk = format!("{k}_P");
        let e = ins
            .get(&pk)
            .unwrap_or_else(|| panic!("{pk}: _P clone missing"));
        let mg = &e["mod_groups"][""];
        let fs = mg["fields"].as_array().unwrap();
        let pred: Vec<&serde_json::Value> = fs
            .iter()
            .filter(|f| f["extraction"].as_str() == Some("pred"))
            .collect();
        let neg: Vec<&serde_json::Value> = fs
            .iter()
            .filter(|f| f["extraction"].as_str() == Some("neg"))
            .collect();
        assert_eq!(pred.len(), 1, "{pk}: pred count");
        assert_eq!(pred[0]["bits"].as_u64(), Some(3));
        assert_eq!(pred[0]["shift"].as_u64(), Some(87));
        assert_eq!(pred[0]["token_idx"].as_u64(), Some(3));
        assert_eq!(pred[0]["_src"].as_str(), Some("bug373_375-2026-09-04"));
        assert_eq!(neg.len(), 1, "{pk}: neg count");
        assert_eq!(neg[0]["shift"].as_u64(), Some(90));
        // NO pred_inv4 anywhere in the LDGSTS family (rejected lane)
        assert!(
            !fs.iter()
                .any(|f| f["extraction"].as_str() == Some("pred_inv4")),
            "{pk}: pred_inv4 lane must stay rejected"
        );
        // ab/vm inherit the donor byte-true
        assert_eq!(
            mg["and_base"], ins[*k]["mod_groups"][""]["and_base"],
            "{pk}: ab != donor"
        );
        assert_eq!(
            mg["variable_mask"], ins[*k]["mod_groups"][""]["variable_mask"],
            "{pk}: vm != donor"
        );
        clones += 1;
    }
    // BUG-386 flip (canonical dbe5e91): +6 base-gap dotted keys per side.
    assert_eq!(clones, 30, "post-386: every base has its _P clone");
}

#[test]
fn t375_2_witness_decode_vendor_exact_121a() {
    // Pre-fix ALL of these were HOLE on sm121a (B = corpus witness).
    let t = tab("sm121a");
    for (w, want) in [
        (
            BW,
            "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            BW ^ B81,
            "LDGSTS.E.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            BW ^ B81 ^ B82,
            "LDGSTS.E.LTC128B.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            BW ^ B81 ^ B73 ^ B82,
            "LDGSTS.E.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            BW & !B73,
            "LDGSTS.E.BYPASS.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            (BW & !B73) ^ B82,
            "LDGSTS.E.BYPASS.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
    ] {
        let d = dec(&t, w).unwrap_or_else(|| panic!("121a HOLE {w:#034x}"));
        assert_eq!(d.trim(), want, "121a decode drift");
    }
}

#[test]
fn t375_3_pred_nibble_sweep_era_map_121a() {
    // v&7 pred / v&8 inverted / v=7 PT-elided / v=15 '!PT' -- era map on
    // SM121a for this family (vendor sweep P375-B x4 AGREE).
    let t = tab("sm121a");
    let body = "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80]";
    for n in 0u64..16 {
        let w = (BW & !(0xFu128 << 87)) | ((n as u128) << 87);
        let d = dec(&t, w).unwrap_or_else(|| panic!("121a HOLE nib{n}"));
        let want = match n {
            7 => body.to_string(),
            0..=6 => format!("{body}, P{n}"),
            15 => format!("{body}, !PT"),
            v => format!("{body}, !P{}", v - 8),
        };
        assert_eq!(d.trim(), want, "121a era-map drift nib{n}");
    }
}

#[test]
fn t375_4_encode_and_roundtrip_121a() {
    let t = tab("sm121a");
    for (txt, want) in [
        (
            "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            BW,
        ),
        (
            "LDGSTS.E.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            BW ^ B81,
        ),
        (
            "LDGSTS.E.128 [R3], desc[UR14][R22.64], P1",
            // F-class nib-1 word, guard elided (g=7), era-map pred
            (F & !(0xFu128 << 12) | (7u128 << 12)) & !(0xFu128 << 87) | (1u128 << 87),
        ),
        (
            "@!P2 LDGSTS.E.BYPASS.128.ZFILL [R3], desc[UR14][R22.64], !P3",
            (((F ^ B81 ^ B82) & !(0xFu128 << 12) | (10u128 << 12)) & !(0xFu128 << 87))
                | (11u128 << 87),
        ),
    ] {
        let w = enc(&t, txt).unwrap_or_else(|e| panic!("121a {txt}: {e}"));
        assert_eq!(w & M96, want & M96, "121a mint drift {txt}");
        let d = dec(&t, w).expect("roundtrip decode");
        let re = enc(&t, d.trim()).expect("re-encode");
        assert_eq!(re & M96, w & M96, "121a roundtrip {d}");
    }
}

#[test]
fn t375_5_kill_and_provenance() {
    let t = tab("sm121a");
    // desc overflow stays lint-loud on the clones.
    assert!(
        enc(&t, "LDGSTS.E.128 [R3], desc[UR14][R22.64+0x1000], P1").is_err(),
        "121a: clone desc overflow must stay lint loud"
    );
    // [FLIP with attribution, BUG-386 / F2-iter204, canonical dbe5e91]:
    // "no BYPASS.64 donor on 121a" is CLOSED -- the base-gap dotted graft
    // adds 'LDGSTS.E.BYPASS.64_ARI_dARI_P' (clone of the _P BYPASS.128
    // donor, delta B75|B74 asserted in patch386.py). Mint = the F-class
    // nib-1 era-map word (guard-elided g=7; pred law of t375_4).
    let w = enc(&t, "LDGSTS.E.BYPASS.64 [R3], desc[UR14][R22.64], P1").unwrap();
    let want = (((F ^ B81 ^ B74 ^ B75) & !(0xFu128 << 12) | (7u128 << 12)) & !(0xFu128 << 87))
        | (1u128 << 87);
    assert_eq!(w & M96, want & M96, "121a BYPASS.64 _P mint drift");
    let d = dec(&t, w).expect("121a BYPASS.64 roundtrip");
    assert_eq!(d.trim(), "LDGSTS.E.BYPASS.64 [R3], desc[UR14][R22.64], P1");
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    assert!(
        raw["_meta"]["bug375"]
            .as_str()
            .unwrap_or("")
            .contains("BUG-375"),
        "bug375 provenance missing"
    );
    // key census moved exactly +11 in 375; BUG-376 (canonical 6742fdf)
    // adds +13 per side (t289_1 flip owns the raw count 15630); BUG-386
    // (canonical dbe5e91) adds +6 per side
    let ins = raw["instructions"].as_object().unwrap();
    let pkeys = ins
        .keys()
        .filter(|k| k.contains("LDGSTS") && k.ends_with("_ARI_dARI_P"))
        .count();
    assert_eq!(pkeys, 30, "121a _P dARI key census drift (post-386 = 30)");
}
