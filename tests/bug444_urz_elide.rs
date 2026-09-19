//! BUG-444 pins (F2-iter247, loop5/blind front2, 2026-09-11): vendor
//! URZ-elide on the plain-u32-ur ARURI print arm + matching parser law.
//! Canonical UNCHANGED 57e7ecd (ENGINE-only bug: ONE printer arm soak in
//! format_plain_u32_ur [Some(255) -> "URZ"] + parser URZ-with-suffixed-base
//! admission in parse_address). Vendor law arb444 (22) + arb444b (17)
//! probes, nvdisasm 13.3.73 raw -b x4 models AGREE EVERY/DIVERGENT=0
//! (work/bug444/arb444_law.json, arb444b_law.json): STG.E plain
//! (1,0)/.64/desc ur=255 prints URZ x4; ATOMG.E.ADD.64 (ureg b8@64,
//! sm121a canonical row) ur=255 prints URZ x4; UR4/UR63/UR0/UR254 print
//! literally everywhere measured; sibling shared-bracket arm
//! (format_sts_lds_addr, BUG-412 law) already prints URZ (ride).
//! Defect pre (measure444_pre; PRISTINE parent 8600574d build
//! /tmp/pre444; 88 cells): x3 13 MATCH/2 WRONG/5 HOLE/2 ref; 121a
//! 14/6/2. Post (measure444_post): x3 15/0/5/2; 121a 17/3/2 -- heals
//! exactly the 9 registered cells (GAP442 C.j90.ur255/G.ref.ur255 rides +
//! the 121a ATOMG carrier), zero drift elsewhere. Remaining 121a WRONG
//! x3 = 432-owned desc-ur extraction gap (UR62 snap; standing, NOT 444).
//! NOT covered (documented): REDG-121a/ST.E/LD.E/LDG-LTC plain carriers
//! (same b8 window, same arm -- heal by the shared helper, carrier-law
//! unmeasured; print flips UR255->URZ align with the architecture-wide
//! 8-bit 0xff=URZ law BUG-160/412); narrow b6 windows unreachable for 255.
//!
//! Witness data: tests/bug444_data.inc (machine-built by
//! work/bug444/gen444pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug444_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS444: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t444_1: healed decode grid -- vendor URZ-elide text. STG words x4 legs;
/// the ATOMG carrier on sm121a only (x3 legs stand HOLE: no canonical row,
/// 408/121a-parity standing coverage class).
#[test]
fn t444_1_healed_grid() {
    for (w, vendor, scope) in LAW444_HEAL {
        for leg in LEGS444 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            if *scope == "x4" {
                assert_eq!(
                    got.as_deref(),
                    Some(*vendor),
                    "[{leg}] heal drift {w:#034x}"
                );
            } else if leg == "sm121a" {
                assert_eq!(
                    got.as_deref(),
                    Some(*vendor),
                    "[{leg}] heal drift {w:#034x}"
                );
            } else {
                assert_eq!(got, None, "[{leg}] x3 must stand HOLE {w:#034x}: {got:?}");
            }
        }
    }
}

/// t444_2: literal guards -- UR4/UR63/UR0/UR254 print vendor-literal; x4
/// scope rows assert all legs, x3 scope rows assert the non-121a legs
/// (121a desc snap = t444_3), sm121a-only rows assert that leg and stand
/// HOLE on x3.
#[test]
fn t444_2_literal_guards() {
    for (w, vendor, scope) in GUARD444 {
        for leg in LEGS444 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            match *scope {
                "x4" => assert_eq!(
                    got.as_deref(),
                    Some(*vendor),
                    "[{leg}] guard drift {w:#034x}"
                ),
                "x3" => {
                    if leg != "sm121a" {
                        assert_eq!(
                            got.as_deref(),
                            Some(*vendor),
                            "[{leg}] guard drift {w:#034x}"
                        );
                    }
                }
                "sm121a-only" => {
                    if leg == "sm121a" {
                        assert_eq!(
                            got.as_deref(),
                            Some(*vendor),
                            "[{leg}] guard drift {w:#034x}"
                        );
                    } else {
                        assert_eq!(got, None, "[{leg}] x3 must stand HOLE {w:#034x}");
                    }
                }
                s => panic!("unknown scope {s}"),
            }
        }
    }
}

/// t444_3: desc-mode URZ-elide pre-existing (BUG-160 arm) == vendor x3;
/// sm121a keeps the 432-owned extraction snap; desc-guard snap cells.
#[test]
fn t444_3_desc_stable_and_snaps() {
    for (w, expect, scope) in DESC444_STABLE {
        let t = tab(scope);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*expect),
            "[{scope}] desc drift {w:#034x}"
        );
    }
    for (w, snap) in GUARD444_121A_SNAP {
        let t = tab("sm121a");
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*snap), "[sm121a] snap drift {w:#034x}");
    }
}

/// t444_4: mints + circles -- encode(vendor URZ text) == law word; UR255
/// spelling mints the SAME word (parse alias, BUG-412 norm); decode of the
/// minted word prints the canonical URZ text.
#[test]
fn t444_4_mint_circles() {
    for (w, text, note) in MASKMINT444 {
        for leg in LEGS444 {
            if *note != "alias-UR255" && text.starts_with("@P0 ATOMG") && leg != "sm121a" {
                continue; // canonical row sm121a-only
            }
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] mint refuse {text}: {e}"));
            assert_eq!(got, *w, "[{leg}] mint drift {text}");
            let back = dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] mint HOLE {text}"));
            let canon = text.replace("UR255", "URZ");
            assert_eq!(back, canon, "[{leg}] circle drift {text} -> {back}");
        }
    }
}

/// t444_5: parser fail-closed guard -- double-URZ / URZ carrying its own
/// suffix stay refused. BUG-448 LIFTED the bare-[URZ+off] refuse: arb448
/// x4 attests "[URZ]"/"[URZ+0x20]" vendor rendering on the EFL2.256 NA
/// ARURI family (base-RZ elision); parser admission + encoder ARURI
/// fallback encode it (448 ride; t448_4 pins the mints).
#[test]
fn t444_5_urz_parse_fail_closed() {
    let t = tab("sm103a");
    for bad in [
        " STG.E [R4.64+URZ+URZ], R4 ;",
        " STG.E [URZ.64+UR4], R4 ;",
        " STG.E [R4.64+UR4+URZ], R4 ;",
    ] {
        let full = format!("{bad}");
        let refused = match parse_sass(&full, 0) {
            Err(_) => true,
            Ok(p) => encode_instruction(&p, &t).is_err(),
        };
        assert!(refused, "not fail-closed: {bad}");
    }
}

/// t444_6: sibling shared-bracket arm ride -- format_sts_lds_addr prints
/// URZ pre==post==vendor x4 (BUG-412 law; NOT in 444 engine scope).
#[test]
fn t444_6_shared_arm_ride() {
    for leg in LEGS444 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in RIDE444 {
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] shared-arm drift {w:#034x}"
            );
        }
    }
}

/// t444_7: canonical pin -- ENGINE-only bug content; canonical HEAD rides
/// (450: 589be87). Historical: blackwell-isa HEAD was the
/// BUG-442 canonical 57e7ecd and the x4 leg tables are byte-identical to
/// the parent state (no vendored-table diff rides this commit).
#[test]
fn t444_7_canonical_unchanged() {
    // public-line hygiene: lane-side live rev-parse hermetized to the vendored manifest pin
    let head = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(head.contains("cc2f62c"), "canonical moved: {head}");
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(src.contains("cc2f62c"), "tables SOURCE drift (ride F2-iter275 BUG-466 ELL2-plain; was 23976eb F2-iter272 BUG-465; ride F2-iter267 BUG-432 ari-cavity; was a64b82b BUG-463 ltc-widths; ride F2-iter263 BUG-453 graft; was e03e034 F2-iter260 BUG-452 narrow; ride F2-iter258 BUG-454 graft; was 589be87 F2-iter255 BUG-450 graft; was 099faa0 F2-iter252 BUG-447): {src}"); // flip-ride 467: pin 67b54f4 -> 668f842
}

/// t444_8: GAP442 heal attribution -- the eight plain-arm gap entries in
/// the 442 pack were flipped to vendor text by BUG-444 (machine flip, see
/// work/bug444/flip444_log.json); loud-glyph ???255 / 432-owned desc
/// entries stay standing.
#[test]
fn t444_8_gap442_attribution() {
    let inc = std::fs::read_to_string("tests/bug442_data.inc").unwrap();
    assert_eq!(
        inc.matches("healed 444").count(),
        8,
        "GAP442 444-heals != 8"
    );
    assert!(
        inc.contains("C.j90.raRZ"),
        "loud-glyph standing entry must stay"
    );
    assert!(
        inc.contains("432-owned"),
        "432-owned desc extraction entries must stay"
    );
}
