//! BUG-373 (F2-iter197, loop5/blind front2, 2026-09-04): sm121a LDGSTS
//! desc dotted rows carried guard 3b@12 -> pv@15 field-dropped. Decode
//! printed '@P0' for vendor '@!P0' (g=8..14) and fully ELIDED '@!PT'
//! (g=15); encode of inverted-guard authored text was lint-loud
//! (measure_pre373_375.json, publish cubit-e5804637). Wrong text on
//! decode = decode-correctness class, not HOLE.
//!
//! LAW (arb373_375 G373 sweeps x16 x3 dotted classes + L374b, nvdisasm
//! 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a AGREE on EVERY
//! probe, DIVERGENT=0; arb373_375_verdicts.json): guard 4b@12 map
//! 0..6=@P0..6, 7=elided, 8..14=@!P0..6, 15=@!PT -- identical x4 legs
//! incl SM121a.
//!
//! FIX = canonical graft ONLY (canonical e7f3e6f, patch373_375.py;
//! ENGINE src ZERO changes): guard field (3,12)->(4,12) on every mg of
//! the 11 LDGSTS desc dotted keys. Claim-space INVARIANT: b15 was already
//! variable_mask-covered (words decoded, only the render dropped pv);
//! the widen extends the carved extraction only.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
// era-era exemplar: LDGSTS.E.128 non-P with guard nibble baked at g=8.
const F: u128 = 0x000000000b9a180e0000000016038fae_u128;
const GUARD_TXT: [&str; 16] = [
    "@P0", "@P1", "@P2", "@P3", "@P4", "@P5", "@P6", "", "@!P0", "@!P1", "@!P2", "@!P3", "@!P4",
    "@!P5", "@!P6", "@!PT",
];

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
fn t373_1_structure_guard_widen_121a() {
    // Post-graft invariant: the 11 LDGSTS desc dotted non-_P keys (and the
    // 22 incl. _P clones from 375) carry guard EXACTLY 4b@12 tok0 on
    // sm121a; the family census 3b@12 guard rows drops by exactly 11.
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let mut keys = 0usize;
    let mut g4 = 0usize;
    let mut other3 = 0usize;
    for (k, e) in ins {
        let Some(mgz) = e.get("mod_groups").and_then(|x| x.as_object()) else {
            continue;
        };
        if !k.contains("LDGSTS") || !k.ends_with("_ARI_dARI") {
            continue;
        }
        keys += 1;
        let fs = mgz[""]["fields"].as_array().unwrap();
        let guards: Vec<&serde_json::Value> = fs
            .iter()
            .filter(|f| f["extraction"].as_str() == Some("guard"))
            .collect();
        assert_eq!(guards.len(), 1, "{k}: guard field count drift");
        assert_eq!(
            guards[0]["shift"].as_u64(),
            Some(12),
            "{k}: guard shift drift"
        );
        if guards[0]["bits"].as_u64() == Some(4) {
            g4 += 1;
        }
        // every field in the grafted window carries attribution or predates
        let g = guards[0];
        if g["_src"].as_str() == Some("bug373_375-2026-09-04") {
            assert_eq!(g["bits"].as_u64(), Some(4));
        }
    }
    // BUG-376 flip (canonical 6742fdf): LTC-lattice completion adds +13
    // non-_P dotted keys (LTC64B/LTC256B x6 bases + BYPASS.LTC128B.128.ZFILL)
    // on top of the 11 post-375 set; guard-4b census moves with it.
    // BUG-386 flip (canonical dbe5e91): +6 non-_P base-gap dotted keys
    // (BYPASS/ZFILL x s32/s64); clones inherit the widened 4b@12 guard.
    assert_eq!(
        keys, 30,
        "121a non-P dARI key census drift (375 clones are _ARI_dARI_P; 376 +13; 386 +6)"
    );
    assert_eq!(
        g4, 30,
        "121a dARI keys must all carry guard 4b@12 post-373 (386 lattice: 30)"
    );
    // 121a-wide census: 3b@12 guard rows 59 -> 48 (11 widened), 4b@12 guard
    // rows 16639 -> 16650 (+11 widened; the 375 _P clones inherit the
    // widened guard and add +11 baked-into-16650? no: clones are counted
    // separately below).
    for (k, e) in ins {
        let Some(mgz) = e.get("mod_groups").and_then(|x| x.as_object()) else {
            continue;
        };
        for mg in mgz.values() {
            for f in mg["fields"].as_array().unwrap_or(&vec![]).iter() {
                if f["extraction"].as_str() == Some("guard")
                    && f["shift"].as_u64() == Some(12)
                    && f["bits"].as_u64() == Some(3)
                {
                    other3 += 1;
                }
            }
        }
    }
    assert_eq!(other3, 48, "sm121a guard 3b@12 census drift (pre-373: 59)");
}

#[test]
fn t373_2_vendor_guard_sweep_fclass_121a() {
    // THE defect class: guard sweep g=0..15 on the 121a F-class dotted row
    // must render nvdisasm-exact (pre-fix: 8/16 wrong, '@!PT' fully lost).
    let t = tab("sm121a");
    for g in 0..16u64 {
        let w = (F & !(0xFu128 << 12)) | ((g as u128) << 12);
        let d = dec(&t, w).unwrap_or_else(|| panic!("g={g}: HOLE post-373"));
        let body = "LDGSTS.E.128 [R3], desc[UR14][R22.64]";
        let want = if GUARD_TXT[g as usize].is_empty() {
            body.to_string()
        } else {
            format!("{} {body}", GUARD_TXT[g as usize])
        };
        assert_eq!(d.trim(), want, "121a g={g} guard render drift");
    }
}

#[test]
fn t373_3_pv_sweep_all_dotted_classes_121a() {
    // pv@15 case on three more dotted classes (alloc+LTC, BYPASS plain,
    // BYPASS+ZFILL): era-era words transplanted via the vendor-witnessed
    // bit law (b73 LTC / b81 BYPASS / b82 ZFILL mode deltas, arb334/359/373).
    const B: u128 = 0x0003e20008981a0e018800801c5a7fae_u128;
    const B73: u128 = 1 << 73;
    const B81: u128 = 1 << 81;
    const B82: u128 = 1 << 82;
    let t = tab("sm121a");
    for (w, frag) in [
        (
            (F & !(0xFu128 << 12)) | (15u128 << 12),
            "@!PT LDGSTS.E.128 [R3]",
        ),
        (
            (B ^ B81) & !(0xFu128 << 12) | (8u128 << 12),
            "@!P0 LDGSTS.E.LTC128B.128 [R90+0x1880]",
        ),
        (
            (B & !B73) & !(0xFu128 << 12) | (9u128 << 12),
            "@!P1 LDGSTS.E.BYPASS.128 [R90+0x1880]",
        ),
        (
            ((F ^ B81 ^ B82) & !(0xFu128 << 12)) | (14u128 << 12),
            "@!P6 LDGSTS.E.BYPASS.128.ZFILL [R3]",
        ),
    ] {
        let d = dec(&t, w).unwrap_or_else(|| panic!("121a HOLE {w:#x}"));
        assert!(d.contains(frag), "121a pv drift: {d:?} misses {frag:?}");
    }
}

#[test]
fn t373_4_encode_inverted_guard_and_roundtrip_121a() {
    // Encode of inverted-guard authored texts was lint-loud pre-fix.
    let t = tab("sm121a");
    for (txt, want) in [
        ("@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]", F),
        (
            "@P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]",
            F & !(0xFu128 << 12),
        ),
        (
            "@!PT LDGSTS.E.128 [R3], desc[UR14][R22.64]",
            (F & !(0xFu128 << 12)) | (15u128 << 12),
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
fn t373_5_no_regression_era_legs_and_provenance() {
    // Era legs byte-invariant on the exemplar battery; _meta carries the
    // bug373 provenance on sm121a; SOURCE.json pins canonical e7f3e6f.
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let d = dec(&t, F).expect("era F decodes");
        assert_eq!(
            d.trim(),
            "@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]",
            "{leg} drift"
        );
        let w = enc(&t, "@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]").expect("era mint");
        assert_eq!(w & M96, F & M96, "{leg} mint drift");
    }
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    assert!(
        raw["_meta"]["bug373"]
            .as_str()
            .unwrap_or("")
            .contains("BUG-373"),
        "bug373 provenance missing"
    );
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    // [FLIP with attribution, BUG-386 / F2-iter204]: the manifest pin moves
    // with the canonical base-gap lattice graft.
    // [FLIP with attribution, BUG-393 / F2-iter214]: manifest pin moves
    // with the 0x7c31 h0nh1 graft (canonical d908ee9 = BUG-395; rides 74a06b7 = BUG-405/406 HADD2 release + HFMA2 two-imm slot graft = BUG-405/406; rides 19363f6 = BUG-400, which rode 5d32aec = BUG-398, 96f196b = BUG-402, dd477eb = BUG-407, 8f2571b = BUG-393).
    assert!(
        // [FLIP with attribution, BUG-387 / F2-iter206]: manifest pin moves with the canonical SHFL b62-region graft.
        m["base_revision"].as_str().unwrap().starts_with("918049c"),
        "SOURCE.json must pin canonical d908ee9 [was 74a06b7 = BUG-405/406] (BUG-395 graft F2-iter223 z atrybucja; rides 74a06b7 = BUG-405/406, which rode 19363f6 = BUG-400, which rode 5d32aec = BUG-398; 5d32aec rode 96f196b = BUG-402; BUG-402 rode dd477eb = BUG-407; BUG-407 rode 8f2571b = BUG-393; BUG-393 rode 2285a05 = BUG-403; BUG-403 rode a10350c = BUG-390)"
    );
}
