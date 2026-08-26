//! BUG-171 (iter79, loop5/blind; queue item = "@UP-glif b11", carried since
//! fleet note 165 sec.5: battery-A residuum "565 @UP-glif (b11 render-parity
//! @P-vs-@UP)").
//!
//! Root cause: printer to_sass() had TWO divergent uniform-guard predicates.
//! The guard-field path used `is_uni` (U*, LDCU, SYNCS_UR, S2UR); the
//! raw-fallback path (table row without a guard field, guard bits [15:12]
//! decoded straight from the word) used a narrower list WITHOUT "LDCU"
//! (and with a redundant "UIADD3"). Vendor nvdisasm-13.3 prints @UPn guards
//! for the LDCU family -- e.g. `@UP2 LDCU.64 UR10, c[0x0][0x490]` -- while
//! cubit printed `@P2 ...` whenever the matching row carried no guard field
//! (sm120 LDCU_UR_cAI ''/64/128/U8, the cARI/cAURI families; sm103a
//! LDCU_UR_cAI U8/U16/S8 -- the '' /64 /128 rows there DO carry the field
//! and were already correct, hence zero sm103-corpus symptoms).
//!
//! Census-first (work/i79/census171.{json,log}; hexdb all.tsv 32.2M lines +
//! sm120 nv-harvest): the COMPLETE vendor uniform-guard family universe is
//! U* (UIADD3/UIMAD/UISETP/ULEA/ULOP3/UMOV/UPLOP3/UPRMT/USEL/USHF/
//! UTCATOMSWS/UTCBAR/UTMACCTL/UTMALDG/UTMAPF/UTMASTG/UGETNEXTWORKID),
//! LDCU (3479 guarded anchors across sm_100/103/103a), SYNCS_UR (EXCH.64;
//! the only uniform-guarded SYNCS sub-form -- the P-guarded ARRIVE/
//! PHASECHK ride disjoint SYNCS_P_/SYNCS_R_ keys), S2UR. Odd-glyph scan:
//! zero other guard glyph shapes in the harvest.
//! Pass-2 decode probe (work/i79/probe171.json; 1,630 ctl-vs-fix decodes of
//! vendor UP-guard anchor words): change is confined to the LDCU glyph;
//! two pre-existing `other` residues documented in results/cubitfix/171.md
//! (sm_100a UGETNEXTWORKID on a foreign table = probe artifact; sm120
//! UIADD3 !UPT ogon = exactly the parked BUG-169 class, heals at ff).
//! Guarded LDCU.U8/U16/S8: ZERO anchors corpus-wide (rg all.tsv) -- the
//! sm103a-side fix is latent coverage, sm103 corpus A/B stays 0-diff.
//!
//! Fix: single source of truth `guard_is_uniform_family()` used by BOTH
//! print arms (printer.rs only; tables untouched; encode/parser untouched --
//! `@UPn` and `@Pn` spellings already encode to the same [15:12] bits).
//! Compose: disjoint by function from parked printer fixes 151
//! (format_const_addr), 160 (format_aruri), 162 (cm-off sign), 164
//! (elide_rz_base/format_addr) -- machine scan in the report.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const L96: u128 = (1u128 << 96) - 1;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    s.split("/* @sched").next().unwrap().trim().to_string()
}
fn w96(h: &str) -> u128 { u128::from_str_radix(h, 16).unwrap() }
fn wf(lo: &str, hi: &str) -> u128 {
    u128::from_str_radix(lo, 16).unwrap() | (u128::from_str_radix(hi, 16).unwrap() << 64)
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    encode_instruction(&parse_sass(text, 0).expect("parse"), t).expect("encode") & !SCHED
}

/// t171_1 (defect polygon, anchor words frozen from fleet battery-A
/// residuum, work/bug165/battery165.json mism_sample): guarded LDCU words
/// decoding through sm120 rows WITHOUT a guard field must print the vendor
/// @UPn guard glyph. FAILS on pre-fix (prints @Pn).
#[test]
fn t171_1_sm120_ldcu_no_guard_row_glyph() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (hexw, want) in [
        ("08000a0000009200ff0a27ac", "@UP2 LDCU.64 UR10, c[0x0][0x490]"),
        ("08000a0000008f00ff1407ac", "@UP0 LDCU.64 UR20, c[0x0][0x478]"),
        ("080008000000b280ff1897ac", "@!UP1 LDCU UR24, c[0x0][0x594]"),
        ("08000a0000007200ff0c27ac", "@UP2 LDCU.64 UR12, c[0x0][0x390]"),
        ("08000a0000007600ff1227ac", "@UP2 LDCU.64 UR18, c[0x0][0x3b0]"),
    ] {
        assert_eq!(dec(&idx, w96(hexw), &t), want, "glyph {hexw}");
    }
}

/// t171_2 (invariants, sm103a full vendor words from hexdb; PASS pre ==
/// post): P-families keep @Pn, already-covered uniform families keep @UPn,
/// drain/idle guards keep @!UPT/@!PT. Guards the fix against spillover.
#[test]
fn t171_2_invariants_p_and_covered_uni() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (lo, hi, want) in [
        ("0000ea00ff2f0b82", "000ea20000000800", "@P0 LDC R47, c[0x0][0x3a8]"),
        ("0000ea00ff028b82", "000e300000000800", "@!P0 LDC R2, c[0x0][0x3a8]"),
        ("000150040dff85b2", "0022a20008000100", "@!UP0 SYNCS.EXCH.64 URZ, [UR13+0x150], UR4"),
        ("00000006ffff09a7", "0009e20008000011", "@P0 SYNCS.ARRIVE.TRANS64 RZ, [UR17], R6"),
        ("000000fffffff290", "000ff6000fffe0ff", "@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ"),
        ("00000000fffff984", "000fe20000000800", "@!PT LDS RZ, [RZ]"),
    ] {
        assert_eq!(dec(&idx, wf(lo, hi), &t), want, "invariant {lo}/{hi}");
    }
}

/// t171_3 (encode symmetry, sm120): the @UP/@P spellings carry identical
/// payload and round-trip to the vendor word bits [0:96). PASS pre == post.
#[test]
fn t171_3_encode_glyph_symmetry() {
    let t = t120();
    let a = enc(&t, "@UP2 LDCU.64 UR10, c[0x0][0x490]");
    let b = enc(&t, "@P2 LDCU.64 UR10, c[0x0][0x490]");
    assert_eq!(a, b, "glyph is a print-level distinction, bits [15:12] equal");
    assert_eq!(a & L96, w96("08000a0000009200ff0a27ac"), "vendor word");
}

/// t171_4 (no spillover to P-families, synthetic guard flips; PASS pre ==
/// post): a guarded LDC word stays @Pn while no-guard rows
/// in play; the sm103a LDCU '' row (which HAS a guard field) keeps @UPn
/// through the field path, drift-free relative to the unified helper.
#[test]
fn t171_4_no_spillover_to_p_family() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    // flip guard bits [15:12] to pred=3,neg=1 (0xB) on the vendor LDC word
    let wldc = (wf("0000ea00ff2f0b82", "000ea20000000800") & !0xF000u128) | (0xB << 12);
    let s = dec(&idx, wldc, &t);
    assert!(s.starts_with("@!P3 LDC "), "LDC stays P-domain: {s}");
    // same flip through the sm103a LDCU '' row (guard field present):
    // the field path already printed @UP -- the helper must agree with it.
    let wu = (wf("0000ae00ff0477ac", "000e6c0008000800") & !0xF000u128) | (0x9 << 12);
    let s2 = dec(&idx, wu, &t);
    assert!(s2.starts_with("@!UP1 LDCU "), "LDCU field path: {s2}");
}

/// t171_5 (census polygon, machine): every no-guard-field row of a vendor
/// uniform-guard family in EITHER table must print a @UP guard for a
/// synthesized guarded word; rows WITH the field print via the field path.
/// Rows whose and_base collides with a higher-priority match are skipped by
/// construction (decode must succeed and keep the family prefix).
#[test]
fn t171_5_no_guard_rows_of_uniform_families_print_up() {
    for path in ["tables/sm120.json", "tables/sm103a.json"] {
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let t = IsaTable::load(std::path::Path::new(path)).unwrap();
        let idx = DecodeIndex::build(&t);
        let mut checked = 0u32;
        for (key, body) in j["instructions"].as_object().unwrap() {
            let uni = key.starts_with('U') || key.starts_with("LDCU")
                || key.starts_with("SYNCS_UR") || key.starts_with("S2UR");
            if !uni { continue; }
            for (_mg, row) in body["mod_groups"].as_object().unwrap() {
                let fields = row["fields"].as_array().unwrap();
                let has_guard = fields.iter().any(|f| {
                    let e = f["extraction"].as_str().unwrap_or("");
                    e == "guard" || e == "guard_neg"
                });
                if has_guard { continue; }
                let ab = u128::from_str_radix(
                    row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                // guard bits [15:12] = pred 1, neg 0 -> 0x1
                let w = (ab & !0xF000u128) | (1 << 12);
                if let Ok(d) = idx.decode(w, 0, &t) {
                    let s = cubit::printer::to_sass(&d);
                    if d.key == *key {
                        assert!(s.starts_with("@UP1 "),
                                "{path}:{key} no-guard row must print @UP1, got {s}");
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked >= 10, "{path}: polygon too thin ({checked})");
    }
}
