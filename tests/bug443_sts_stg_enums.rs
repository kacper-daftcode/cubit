//! BUG-443 pins (F2-iter250, loop5/blind front2, 2026-09-12): STS AURI
//! width-map completion + STS_ARURI_R b95 inert band + STG other-family
//! enum closure. Canonical e8d1af3 (graft S1/S2/S3/T1/T2/T3, patch443.py
//! replayable+idempotent, byte-exact x4 from 57e7ecd). Engine: ONE soak --
//! printer mod_priority arm PRIVATE=>9 (vendor `STG.CONSTANT.PRIVATE`; arm
//! provably inert pre-443: zero rows carry a non-verbatim PRIVATE mod on x4
//! legs, machine-census). Vendor law arb443 223 + arb443b 15 + arb443c 4
//! probes (nvdisasm 13.3.73 raw -b x4 models AGREE EVERY/DIVERGENT=0):
//! STS width enum [73:76) full map {U8,S8,U16,S16,U32,64,128,INVALID7-loud},
//! b72 print-inert on the bare-UR window; STG 9 base enum forms legal with
//! per-form junk whitelist + carrier walks 1:1 + b90 (1,1) free-form under
//! every E-form; class-enum multi-bit combos render as enum compositions
//! (CTA.PRIVATE/STRONG.SM/MMIO.SYS/EL/EU legal, INVALID7 loud); b76/b91
//! kill under every form; noE+b90 = loud ???0. NOT grafted (pinned):
//! INVALID7 cells (keep-HOLE), noE.b90 (keep-HOLE).
//!
//! Witness data: tests/bug443_data.inc (machine-built by
//! work/bug443/gen443pins.py; rc=2 fail-closed; no hand hex; mints
//! nvdisasm-crossed x4 at generation time).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug443_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS443: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t443_1: healed grid -- every law cell HOLE pre now decodes to the exact
/// x4-unanimous vendor text on every leg.
#[test]
fn t443_1_heal_grid() {
    for leg in LEGS443 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW443_HEAL {
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] heal drift {w:#034x}"
            );
        }
    }
}

/// t443_2: stable grid -- pre-existing matches (STS b72 window / low8-print
/// law / URZ elision / family baselines) must not drift over the graft.
#[test]
fn t443_2_stable_grid() {
    for leg in LEGS443 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW443_STABLE {
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] stable drift {w:#034x}"
            );
        }
    }
}

/// t443_3: loud-keep doctrine -- INVALID7/???0 cells stay decode-HOLE on
/// x4 legs (vendor renders the loud glyph; engine never claims it).
#[test]
fn t443_3_loud_keep() {
    for leg in LEGS443 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, loud) in LOUD443_KEPT {
            let got = dec(&t, &idx, *w);
            assert!(
                got.is_none(),
                "[{leg}] loud cell claimed: {got:?} (vendor-loud {loud})"
            );
        }
        // encode-side fail-closed on the loud glyph texts
        for bad in [
            "STS.INVALID7 [UR224], R4",
            "STS.INVALID7 [R0+UR224+-0x1], R4",
            "STG.E.INVALID7 [R4.U32+UR4], R4",
        ] {
            assert!(enc(&t, bad).is_err(), "[{leg}] loud text encoded: {bad}");
        }
    }
}

/// t443_4: kill posture -- b76/b91 under every probed form stays HOLE x4.
#[test]
fn t443_4_kill_posture() {
    for leg in LEGS443 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in POST443_KILL {
            let got = dec(&t, &idx, *w);
            assert!(got.is_none(), "[{leg}] kill cell claimed {tag}: {got:?}");
        }
    }
}

/// t443_5: era-standing claim class -- era-0 EF/LU/NA words (vendor rc=1)
/// are claimed post with the correct form glyph (same era-frozen class as
/// the pre-existing plain-form carriers; 438/440 doctrine).
#[test]
fn t443_5_erastand_snap() {
    for leg in LEGS443 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, snap) in ERASTAND443 {
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*snap),
                "[{leg}] era-standing drift {w:#034x}: {got:?}"
            );
        }
    }
}

/// t443_6: mints -- encode(vendor text)==mint per leg (canonical encode era
/// 0x000fc200 machine-asserted at generation) + decode(mint)==text.
#[test]
fn t443_6_mints() {
    for (leg, mint, text) in MASKMINT443 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] encode fail {text}: {e}"));
        assert_eq!(got, *mint, "[{leg}] mint drift {text}");
        let back = dec(&t, &idx, got);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] circle drift {text}");
    }
}

/// t443_7: noE family lives under the canon-era key STG_ARURI_R with plain
/// bracket print guarded by field shape (data-design pin): E-form keys own
/// their verbatim print texts, noE mgs print STG/.64/.U8/CONSTANT.PRIVATE.
#[test]
fn t443_7_noe_key_design() {
    let t = tab("sm103a");
    let src = std::fs::read_to_string("tables/sm103a.json").unwrap();
    let v: serde_json::Value = serde_json::from_str(&src).unwrap();
    let mgs = v["instructions"]["STG_ARURI_R"]["mod_groups"]
        .as_object()
        .unwrap();
    for m in ["", "64", "U8", "CONSTANT,PRIVATE"] {
        assert!(mgs.contains_key(m), "STG_ARURI_R mg {m:?} missing");
    }
    // canon-era siblings stay put (442 state)
    for m in ["E", "64,E", "128,E"] {
        assert!(mgs.contains_key(m), "STG_ARURI_R canon mg {m:?} missing");
    }
    // T2/T3 keys present with _src443 markers
    for k in [
        "STG.E.U8_ARURI_R",
        "STG.E.CONSTANT.PRIVATE_ARURI_R",
        "STG.E.CONSTANT.CTA_ARURI_R",
        "STG.E.STRONG.SM.PRIVATE_ARURI_R",
        "STG.E.MMIO.GPU_ARURI_R",
        "STG.E.EF_ARURI_R",
        "STG.E.LU_ARURI_R",
        "STG.E.NA_ARURI_R",
        "STG.E.64.CONSTANT.PRIVATE_ARURI_R",
        "STG.E.128.MMIO.GPU_ARURI_R",
        "STG.E.EF.U8_ARURI_R",
        "STG.E.CONSTANT.CTA.PRIVATE_ARURI_R",
        "STG.E.STRONG.SM_ARURI_R",
        "STG.E.MMIO.SYS_ARURI_R",
        "STG.E.EL_ARURI_R",
        "STG.E.EU_ARURI_R",
    ] {
        assert!(v["instructions"].get(k).is_some(), "key {k} missing");
    }
    // STS rows
    for key in ["STS_AURI_R", "STS_ARURI_R"] {
        let m = v["instructions"][key]["mod_groups"].as_object().unwrap();
        for w in ["S8", "S16"] {
            assert!(m.contains_key(w), "{key} mg {w} missing");
        }
    }
}

/// t443_8: canonical pin -- the vendored manifest tracks the BUG-443 graft
/// revision (e8d1af3), never a silent table state.
#[test]
fn t443_8_canonical_pin() {
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    let v: serde_json::Value = serde_json::from_str(&src).unwrap();
    let rev = v["base_revision"].as_str().unwrap();
    assert!(
        rev.starts_with(CANON443),
        "canonical drift: manifest {rev} (need {CANON443}*)"
    );
}
