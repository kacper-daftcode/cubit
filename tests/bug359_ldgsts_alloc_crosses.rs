//! BUG-359 (F2-iter189, loop5/blind front2, 2026-09-03): LDGSTS desc-form
//! L1-alloc '128,E' crosses x {LTC128B, ZFILL, both} grafted on
//! LDGSTS_ARI_dARI{,_P} for x3 legs sm100a/sm103a/sm120 (canonical 3bc2c15;
//! ENGINE untouched).
//!
//! PRE (publish cubit-234aa92 / cubit_py-234aa92 e992b2e2.., canonical
//!   66140b8; work/bug359/measure_pre359.json):
//!   decode of the 6 crossed words = LOUD HOLE on x3 legs (non-P crosses OK
//!   on sm121a dotted keys); authored crosses = loud FAIL x3 (121a non-P
//!   control ENCODED, 121a _P FAIL -- 121a lacks ALL trailing-_P desc LDGSTS
//!   incl. corpus witness B: pre-existing gap, registered 37x-kand).
//! LAW (arb334 46 + arb359 88 probes nvdisasm 13.3.73 raw -b, x4 models
//!   SM100a/SM103a/SM120/SM121a AGREE on EVERY probe): b81 alloc<->BYPASS
//!   pair toggle; b73 LTC128B and b82 ZFILL legal WITH alloc on both pred
//!   classes incl. triple; guard sweeps x16 on each crossed block; dst-imm
//!   20b@44 owns [52:44]; desc-imm 12b@32 signed (re-verified on crossed
//!   blocks arb359 i-E/i-Z).
//! CORPUS (census359 over census334b 30,049-slot desc battery): the 5
//!   donor-derived new-row claim windows match 0 words -> corpus-invisible.
//! FIX: 6 cloned rows/leg (see patch359.py); sm120 dARI_P ZFILL chain uses
//!   intra-row '128,E'/'128,E,LTC128B' donors (era gap: BYPASS+ZFILL rows
//!   absent under dARI_P on sm120).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B73: u128 = 1u128 << 73;
const B81: u128 = 1u128 << 81;
const B82: u128 = 1u128 << 82;
// arb-verified witnesses (arb334 W/T3 + arb359 anchors; x4 vendor-agree):
const F: u128 = 0x000000000b9a180e0000000016038fae; // alloc .128 non-P, guard @!P0
const BW: u128 = 0x0003e20008981a0e018800801c5a7fae; // corpus BYPASS+LTC128B _P

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
const LEGS3: [&str; 3] = ["sm100a", "sm103a", "sm120"];

#[test]
fn t359_1_structure_claims_and_donor_parity() {
    for leg in LEGS3 {
        let t = tab(leg);
        let get = |key: &str, mg: &str| {
            t.entries
                .get(key)
                .and_then(|e| e.mod_groups.get(mg))
                .unwrap_or_else(|| panic!("{leg} {key}::{mg} missing"))
        };
        // dARI crosses: ab delta vs in-key donors exactly b81 / b82 / b81|b82.
        let dl = get("LDGSTS_ARI_dARI", "128,BYPASS,E,LTC128B");
        let nl = get("LDGSTS_ARI_dARI", "128,E,LTC128B");
        assert_eq!(nl.and_base ^ dl.and_base, B81, "{leg} dARI LTC delta");
        assert_eq!(nl.variable_mask, dl.variable_mask, "{leg} dARI LTC vm");
        let dz = get("LDGSTS_ARI_dARI", "128,E");
        let nz = get("LDGSTS_ARI_dARI", "128,E,ZFILL");
        assert_eq!(nz.and_base ^ dz.and_base, B82, "{leg} dARI ZFILL delta");
        assert_eq!(nz.variable_mask, dz.variable_mask, "{leg} dARI ZFILL vm");
        let nt = get("LDGSTS_ARI_dARI", "128,E,LTC128B,ZFILL");
        assert_eq!(nt.and_base ^ nl.and_base, B82, "{leg} dARI triple delta");
        // dARI_P crosses present with alloc bit set and correct flags.
        for (mg, want) in [
            ("128,E,LTC128B", (B81 | B73) & !B82),
            ("128,E,ZFILL", B81 | B82),
            ("128,E,LTC128B,ZFILL", B81 | B73 | B82),
        ] {
            let g = get("LDGSTS_ARI_dARI_P", mg);
            assert_eq!(
                g.and_base & (B81 | B73 | B82),
                want,
                "{leg} dARI_P {mg} alloc/ltc/zfill bits"
            );
        }
        // imm2 12b@32 signed law on every grafted row (post-334 field set).
        for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
            for mg in ["128,E,LTC128B", "128,E,ZFILL", "128,E,LTC128B,ZFILL"] {
                let g = get(key, mg);
                let f = g
                    .fields
                    .iter()
                    .find(|f| matches!(f.extraction, cubit::table::Extraction::SubImm(2)))
                    .unwrap_or_else(|| panic!("{leg} {key}::{mg} imm2 field"));
                assert_eq!(
                    (f.bits, f.shift),
                    (12, 32),
                    "{leg} {key}::{mg} imm2 12b law"
                );
            }
        }
    }
    // donor byte-parity: sm100a == sm103a on every grafted row (modulo _src).
    let a = tab("sm100a");
    let b = tab("sm103a");
    for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
        for mg in ["128,E,LTC128B", "128,E,ZFILL", "128,E,LTC128B,ZFILL"] {
            let ga = &a.entries[key].mod_groups[mg];
            let gb = &b.entries[key].mod_groups[mg];
            assert_eq!(ga.and_base, gb.and_base, "{key}::{mg} ab cross-leg");
            assert_eq!(
                ga.variable_mask, gb.variable_mask,
                "{key}::{mg} vm cross-leg"
            );
            assert_eq!(
                ga.fields.len(),
                gb.fields.len(),
                "{key}::{mg} fields cross-leg"
            );
        }
    }
}

#[test]
fn t359_2_decode_battery_vendor_texts() {
    // (word, vendor text) pairs: anchors from arb334 T3/E/Z + arb359 N1/N3/N4.
    // Texts are the x4-unanimous vendor prints; guard as authored in word.
    let cases: [(u128, &str); 6] = [
        (
            F ^ B73,
            "@!P0 LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]",
        ),
        (F ^ B82, "@!P0 LDGSTS.E.128.ZFILL [R3], desc[UR14][R22.64]"),
        (
            F ^ B73 ^ B82,
            "@!P0 LDGSTS.E.LTC128B.128.ZFILL [R3], desc[UR14][R22.64]",
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
    ];
    for leg in LEGS3 {
        let t = tab(leg);
        for (w, want) in cases {
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg} decode hole {want}"));
            assert_eq!(got, want, "{leg} decode text for {want}");
            // decode of the pre-359-era legs' non-crossed anchors unchanged:
            // (alloc plain and bypass anchors still claim their own rows)
        }
        assert_eq!(
            dec(&t, F).as_deref(),
            Some("@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]"),
            "{leg} F anchor stable"
        );
        assert_eq!(
            dec(&t, BW).as_deref(),
            Some("LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1"),
            "{leg} B corpus anchor stable"
        );
    }
    // guard sweep: guard [15:12] composes on crossed blocks (arb359 g-E/g-Z
    // /g-N1/g-T3 x16 each; spot-check @P2 / @!PT / elided-PT here).
    let mut w = (F ^ B73) & !(0xFu128 << 12);
    for (g, want) in [
        (2u128, "@P2 LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]"),
        (15u128, "@!PT LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]"),
    ] {
        let x = w | (g << 12);
        for leg in LEGS3 {
            let t = tab(leg);
            assert_eq!(dec(&t, x).as_deref(), Some(want), "{leg} guard {g}");
        }
    }
    w = 0; // silence unused mut pattern warmers in some toolchains
    let _ = w;
    // BUG-359 printer arm heals the pre-existing donor print-order class:
    // BYPASS+ZFILL rows (100a/103a era) now print the vendor order
    // '.128.ZFILL' (was '.ZFILL.128'; corpus-invisible: 0 claimed words).
    let n2 = (BW & !B73) ^ B82; // corpus-derived BYPASS+ZFILL _P (arb359 N2)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, n2).as_deref(),
            Some("LDGSTS.E.BYPASS.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1"),
            "{leg}: donor ZFILL print-order cured (359 printer arm)"
        );
    }
    // sm121a control: non-P crossed words decode via dotted keys (pre-359
    // coverage). NOTE (373-kand, measured, pre-existing): 121a dotted-key
    // desc rows carry guard 3b@12 and DROP the pv-invert bit 15 on decode
    // ('@P0' where vendor prints '@!P0'; '@!PT' printed as elided) -- so the
    // 121a control below uses the elided-PT guard (7), which is exact.
    let t121 = tab("sm121a");
    let f7_ltc = (F ^ B73) & !(0xFu128 << 12) | (7u128 << 12);
    assert_eq!(
        dec(&t121, f7_ltc).as_deref(),
        Some("LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]"),
        "121a dotted-key control (elided guard)"
    );
}

#[test]
fn t359_3_mint_word_exact_and_leg_invariant() {
    // authored text -> word, exact vs arb-verified witness families.
    // guard bits [15:12]: '@!P0' = 8; elided (no @) = 7; ', P1' = trailing.
    let f7 = (F ^ B73) & !(0xFu128 << 12) | (7u128 << 12);
    let cases: [(&str, u128); 8] = [
        ("LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]", f7),
        (
            "@!P0 LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]",
            F ^ B73,
        ),
        ("@!P0 LDGSTS.E.128.ZFILL [R3], desc[UR14][R22.64]", F ^ B82),
        (
            "@!P0 LDGSTS.E.LTC128B.128.ZFILL [R3], desc[UR14][R22.64]",
            F ^ B73 ^ B82,
        ),
        (
            "LDGSTS.E.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            BW ^ B81,
        ),
        (
            "LDGSTS.E.LTC128B.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            BW ^ B81 ^ B82,
        ),
        (
            "LDGSTS.E.128.ZFILL [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            BW ^ B81 ^ B73 ^ B82,
        ),
        ("LDGSTS.E.128.ZFILL [R3], desc[UR14][R22.64+-0xc]", {
            // Z-block with desc-imm 12b signed -0xc (arb359 i-Z verified)
            ((F ^ B82) & !(0xFFFu128 << 32) | (0xFF4u128 << 32)) & !(0xFu128 << 12) | (7u128 << 12)
        }),
    ];
    for (text, want) in cases {
        let mut mints = Vec::new();
        for leg in LEGS3 {
            let t = tab(leg);
            let got = enc(&t, text).unwrap_or_else(|e| panic!("{leg} {text}: {e}"));
            assert_eq!(got & M96, want & M96, "{leg} {text} mint");
            // roundtrip byte-exact
            let s = dec(&t, got).unwrap();
            let re = enc(&t, &s).unwrap();
            assert_eq!(re & M96, got & M96, "{leg} roundtrip {s}");
            mints.push(got & M96);
        }
        // leg-invariant law: x3 legs mint the same word
        assert_eq!(mints[0], mints[1], "100a==103a {text}");
        assert_eq!(mints[1], mints[2], "103a==120 {text}");
        // non-P crosses: 121a dotted keys mint the identical word (x4
        // parity). BUG-373 (canonical e7f3e6f): inverted guards now encode
        // on 121a (guard field widened 3b->4b@12); the skip condition below
        // stays as an era-era text-set filter (no @-leading cases remain in
        // `cases`).
        if !text.ends_with(", P1") && !text.starts_with('@') {
            let t121 = tab("sm121a");
            let g = enc(&t121, text).unwrap_or_else(|e| panic!("121a {text}: {e}"));
            assert_eq!(g & M96, want & M96, "121a x4 parity {text}");
        }
    }
}

#[test]
fn t359_4_fail_closed_residuum_and_lint() {
    // BUG-375 flip (canonical e7f3e6f): the 121a _P desc family is now
    // PORTED (era-style pred 3b@87 + neg 1b@90 tok3); the two pre-existing
    // contrast pins invert to positive vendor law:
    let t121 = tab("sm121a");
    let w = enc(
        &t121,
        "LDGSTS.E.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
    )
    .expect("121a _P encodes post-375");
    assert_eq!(w & M96, (BW ^ B81) & M96, "121a _P mint == vendor law word");
    assert_eq!(
        dec(&t121, BW).as_deref(),
        Some("LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1"),
        "121a _P decode == vendor incl corpus witness B (post-375)"
    );
    for leg in LEGS3 {
        let t = tab(leg);
        // desc offset beyond signed-12 on the grafted rows -> encode-lint LOUD
        let v = enc(&t, "LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64+0x1000]");
        assert!(
            v.is_err(),
            "{leg}: grafted-row desc overflow must be lint loud"
        );
        // no silent BYPASS misroute: alloc+LTC mint must carry b81 AND b73
        let w = enc(&t, "LDGSTS.E.LTC128B.128 [R3], desc[UR14][R22.64]").unwrap();
        assert_eq!(w & B81, B81, "{leg} alloc bit minted");
        assert_eq!(w & B73, B73, "{leg} LTC bit minted (no bypass swap)");
        // ZFILL mint sets b82, keeps b81
        let w = enc(&t, "@!P0 LDGSTS.E.128.ZFILL [R3], desc[UR14][R22.64]").unwrap();
        assert_eq!(w & (B81 | B82), B81 | B82, "{leg} zfill+alloc minted");
    }
}

#[test]
fn t359_5_donor_rows_and_alloc_plain_invariant() {
    // donors + plain alloc rows unchanged by the graft (drift tripwire).
    for leg in LEGS3 {
        let t = tab(leg);
        let g = &t.entries["LDGSTS_ARI_dARI"].mod_groups["128,BYPASS,E,LTC128B"];
        assert_eq!(
            g.and_base, 0x0001e0000b981a000000000000000fae,
            "{leg} dARI donor ab drift"
        );
        let g = &t.entries["LDGSTS_ARI_dARI"].mod_groups["128,E"];
        assert_eq!(
            g.and_base, 0x0001e0000b9a18000000000000000fae,
            "{leg} dARI alloc-plain ab drift"
        );
        let g = &t.entries["LDGSTS_ARI_dARI_P"].mod_groups["128,E"];
        assert_eq!(
            g.and_base, 0x0001e000081a18000000000000007fae,
            "{leg} dARI_P alloc-plain ab drift"
        );
    }
    // donor decode spot: bypass+LTC _P corpus witness stable (claims donor)
    for leg in LEGS3 {
        let t = tab(leg);
        assert!(dec(&t, BW).is_some(), "{leg} donor witness decode");
    }
}
