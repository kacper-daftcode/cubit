//! BUG-348 (F2-iter188, loop5/blind front2, 2026-09-03): sm121a HMUL2_R_R_R
//! (krata 0x232) era dead-row rebuild + squatter cleanup. Registration
//! 348-kand LOW (324.md sec.6, F2-iter173). Canonical graft patch348.py
//! (canonical 4983b7e), ride-after fa99a40/BUG-352. ENGINE src zero changes.
//!
//! MEASUREMENT (pre-fix publish cubit_py-fa99a40.so e992b2e2.., canonical
//! 93304a6; work/bug348/measure_pre348.json): 2,278 distinct corpus words
//! on krata 0x232 (battery ab240, census348: 4,942 plain + 707 BF16 + 1
//! INVALID1-class occurrences) decode on sm121a as 885 LOUD HOLE + 1,393
//! WRONG-TEXT (289 hsel-drop, 978 phantom-4th-operand thru fleet-unique
//! HMUL2_R_R_R_R, 126 era wrong-text thru HMUL2.BF16_V2_R_R_R 3b @[14:12]
//! guard dropping inv@15: '@P6' vs vendor '@!P6'). Vendor accepts ALL.
//!
//! LAW: arb348 78 probes + arb324 469 probes, nvdisasm 13.3.73 raw -b, x4
//! models AGREE on EVERY probe: guard full 4b@[15:12] (pv<7/!inv=@Pv,
//! pv=7/!inv elides, pv<7/inv=@!Pv, pv=7/inv=@!PT); hsel 2b@[75:74]tok2 /
//! 2b@[61:60]tok3 (0 plain, 2 .H0_H0, 3 .H1_H1, 1 .INVALID1 operand);
//! signs neg@72 tok2 + abs@62/neg@63 tok3 compose; carriers b76/b77/b80/
//! b85 + crosses (324 law). DOCTRINE HOLE kept fail-closed (donor parity,
//! 289-era status quo): b78 INVALID1-word, b76+b80 INVALID3-word, b91 rc=1
//! hard reject, stray [90:87], b84, b79 RELU window, band [55:40].
//!
//! GRAFT: mod_groups strict-cloned from the post-324 sm120 donor 12-mg set
//! (key-level attrs kept sm121a-native); deleted era squatters
//! HMUL2.BF16_V2_R_R_R + HMUL2_R_R_R_R (asserted absent on the 3 donor
//! legs). Donor legs sm100a/sm103a/sm120 untouched.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    DecodeIndex::build(t)
        .decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

const MGS12: &[&str] = &[
    "",
    "FMZ",
    "SAT",
    "FMZ,SAT",
    "FTZ",
    "FTZ,SAT",
    "BF16_V2",
    "BF16_V2,FMZ",
    "BF16_V2,SAT",
    "BF16_V2,FMZ,SAT",
    "BF16_V2,FTZ",
    "BF16_V2,FTZ,SAT",
];

#[test]
fn t348_1_structure_donor_mirror_and_squatter_removal() {
    let t = tab("sm121a");
    let d = tab("sm120");
    let e = &t.entries["HMUL2_R_R_R"];
    let de = &d.entries["HMUL2_R_R_R"];
    assert_eq!(
        e.mod_groups.len(),
        MGS12.len(),
        "sm121a HMUL2_R_R_R mg census drift"
    );
    let tf = |mg: &cubit::table::ModGroupEntry| {
        let mut v: Vec<(u32, String, u32, u32)> = mg
            .fields
            .iter()
            .map(|f| {
                (
                    f.bits,
                    format!("{:?}", f.extraction),
                    f.shift,
                    f.token_idx as u32,
                )
            })
            .collect();
        v.sort();
        v
    };
    for mgn in MGS12 {
        let a = &e.mod_groups[*mgn];
        let b = &de.mod_groups[*mgn];
        assert_eq!(a.and_base, b.and_base, "mg[{mgn}] ab not donor-mirrored");
        assert_eq!(
            a.variable_mask, b.variable_mask,
            "mg[{mgn}] vm not donor-mirrored"
        );
        assert_eq!(tf(a), tf(b), "mg[{mgn}] fields not donor-mirrored");
    }
    // dead-row geometry gone: no junk field at shift 25, tok2 reg@24 + hsels
    let p = &e.mod_groups[""];
    assert!(
        p.fields.iter().all(|f| f.shift != 25),
        "junk ''@25 field still present"
    );
    let has = |bits: u32, shift: u32, tok: i32| {
        p.fields
            .iter()
            .any(|f| f.bits == bits && f.shift == shift && f.token_idx == tok)
    };
    assert!(has(4, 12, 0), "full 4b guard field missing");
    assert!(has(8, 24, 2), "tok2 reg@24 missing (dead-row geometry)");
    assert!(has(2, 74, 2), "tok2 hsel@[75:74] missing");
    assert!(has(2, 60, 3), "tok3 hsel@[61:60] missing");
    // the era guard was 3b@[14:12] (inv-blind); assert the 4b form
    assert!(
        p.fields
            .iter()
            .any(|f| f.extraction == Extraction::Guard && f.bits == 4 && f.shift == 12),
        "guard must see inv bit 15"
    );
    // squatters deleted (sm100a/sm103a/sm120 never carried them)
    assert!(!t.entries.contains_key("HMUL2.BF16_V2_R_R_R"));
    assert!(!t.entries.contains_key("HMUL2_R_R_R_R"));
    for leg in ["sm100a", "sm103a", "sm120"] {
        let x = tab(leg);
        assert!(
            !x.entries.contains_key("HMUL2.BF16_V2_R_R_R")
                && !x.entries.contains_key("HMUL2_R_R_R_R"),
            "{leg}: squatter key appeared??"
        );
    }
}

#[test]
fn t348_2_decode_law_vendor_text_x_probe_battery() {
    let t = tab("sm121a");
    let d = tab("sm120");
    // (word, vendor) from arb348 (unanimous x4) + corpus anchors (census348)
    let cases: &[(u128, &str)] = &[
        // G: full 4b guard law (pv<7/!inv, elide pv7 !inv, @!Pv, @!PT)
        (
            0x00000c003000000c030a9232,
            "@!P1 HMUL2 R10, R3.H1_H1, R12.H1_H1",
        ), // G_i_base
        (
            0x00000c003000000c030a1232,
            "@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1",
        ), // G_p_base
        (0x00000c003000000c030a7232, "HMUL2 R10, R3.H1_H1, R12.H1_H1"), // G_p_p6 (pv7 elides)
        (
            0x00000c003000000c030af232,
            "@!PT HMUL2 R10, R3.H1_H1, R12.H1_H1",
        ), // G_i_p6
        // H: hsel sweep (0/2/3 + INVALID1 operand glyph), x4 unanimous
        (0x000000000000000c030a1232, "@P1 HMUL2 R10, R3, R12"),
        (0x000000002000000c030a1232, "@P1 HMUL2 R10, R3, R12.H0_H0"),
        (
            0x000004000000000c030a1232,
            "@P1 HMUL2 R10, R3.INVALID1, R12",
        ),
        (
            0x000004001000000c030a1232,
            "@P1 HMUL2 R10, R3.INVALID1, R12.INVALID1",
        ),
        (
            0x000008003000000c030a1232,
            "@P1 HMUL2 R10, R3.H0_H0, R12.H1_H1",
        ),
        // C: carriers x plain/inv guard + BF16 crosses
        (
            0x00001c003000000c030a1232,
            "@P1 HMUL2.FMZ R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00002c003000000c030a1232,
            "@P1 HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00010c003000000c030a1232,
            "@P1 HMUL2.FTZ R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00200c003000000c030a1232,
            "@P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00210c003000000c030a1232,
            "@P1 HMUL2.BF16_V2.FTZ R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00203c003000000c030a1232,
            "@P1 HMUL2.BF16_V2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00002c003000000c030a9232,
            "@!P1 HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00200c003000000c030a9232,
            "@!P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
        ),
        // S: sign compose
        (
            0x00000d003000000c030a1232,
            "@P1 HMUL2 R10, -R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00002d003000000c030a1232,
            "@P1 HMUL2.SAT R10, -R3.H1_H1, R12.H1_H1",
        ),
        (
            0x00000c00f000000c030a1232,
            "@P1 HMUL2 R10, R3.H1_H1, -|R12|.H1_H1",
        ),
        (
            0x00000c00f000000c030a9232,
            "@!P1 HMUL2 R10, R3.H1_H1, -|R12|.H1_H1",
        ),
        // corpus anchors (census348 / measure_pre348, all vendor-legal):
        (
            0x00000c003000000c030a1232,
            "@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1",
        ), // plain 4,942-class
        (
            0x00200c003000000c030a1232,
            "@P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
        ), // BF16 707-class
        (
            0x00000800200000000717e232,
            "@!P6 HMUL2 R23, R7.H0_H0, R0.H0_H0",
        ), // hsel-drop witness
        (
            0x0000080020000000230fc232,
            "@!P4 HMUL2 R15, R35.H0_H0, R0.H0_H0",
        ), // phantom-4reg witness
        // control kraty (untouched rows):
        (0x008000000300000080c0b7c32, "HMUL2 R11, R12, UR8.H1_H1"),
        (
            0x00816080b200000080c097c31,
            "HFMA2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
        ),
    ];
    for (w, want) in cases {
        let got = dec(&t, *w);
        assert_eq!(got.as_deref(), Some(*want), "sm121a decode {w:#x}");
        let got120 = dec(&d, *w);
        assert_eq!(got120.as_deref(), Some(*want), "sm120 donor parity {w:#x}");
    }
}

#[test]
fn t348_3_encode_word_exact_goldens_and_roundtrips() {
    let t = tab("sm121a");
    let d = tab("sm120");
    let lanes: &[(&str, u128)] = &[
        (
            "HMUL2 R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000000c003000000c030a7232,
        ),
        ("HMUL2 R10, R3, R12", 0x000fc200000000000000000c030a7232),
        ("@P1 HMUL2 R10, R3, R12", 0x000fc200000000000000000c030a1232),
        (
            "@!P6 HMUL2 R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000000c003000000c030ae232,
        ),
        (
            "@!PT HMUL2 R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000000c003000000c030af232,
        ),
        (
            "HMUL2.FMZ R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000001c003000000c030a7232,
        ),
        (
            "HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000002c003000000c030a7232,
        ),
        (
            "HMUL2.FTZ R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000010c003000000c030a7232,
        ),
        (
            "HMUL2.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000012c003000000c030a7232,
        ),
        (
            "HMUL2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000003c003000000c030a7232,
        ),
        (
            "HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000200c003000000c030a7232,
        ),
        (
            "HMUL2.BF16_V2.FMZ R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000201c003000000c030a7232,
        ),
        (
            "HMUL2.BF16_V2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000203c003000000c030a7232,
        ), // canonical mod order
        (
            "HMUL2.BF16_V2.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000212c003000000c030a7232,
        ),
        (
            "@!P6 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
            0x000fc20000200c003000000c030ae232,
        ),
        (
            "HMUL2 R10, -R3.H1_H1, R12.H1_H1",
            0x000fc20000000d003000000c030a7232,
        ),
        (
            "HMUL2 R10, R3.H1_H1, -|R12|.H1_H1",
            0x000fc20000000c00f000000c030a7232,
        ),
        (
            "HMUL2 R10, R3.H0_H0, R12.H0_H0",
            0x000fc200000008002000000c030a7232,
        ),
    ];
    for (text, want) in lanes {
        let w = enc(&t, text).unwrap_or_else(|e| panic!("sm121a mint {text}: {e}"));
        assert_eq!(w, *want, "sm121a mint drift {text}");
        let w120 = enc(&d, text).unwrap_or_else(|e| panic!("sm120 mint {text}: {e}"));
        assert_eq!(w120, *want, "sm120 mint drift {text} (leg-invariant law)");
        let back = dec(&t, w & M96).expect("own mint must roundtrip");
        assert_eq!(back, text.trim_end_matches(';'), "roundtrip drift {text}");
    }
}

#[test]
fn t348_4_doctrine_fail_closed_and_era_text_regressions() {
    let t = tab("sm121a");
    // INVALID word classes stay HOLE (arb348: vendor prints INVALIDx glyph /
    // b91 hard-rejects rc=1; 289-era status-quo care => HOLE, donor parity)
    let holes: &[(u128, &str)] = &[
        (
            0x00004c003000000c030a1232,
            "b78 INVALID1-word (nvdisasm prints INVALID1 glyph)",
        ),
        (
            0x00011c003000000c030a1232,
            "b76+b80 INVALID3-word (no OOB alias)",
        ),
        (0x08000c003000000c030a1232, "b91 kill bit (nvdisasm rc=1)"),
        (0x00011c003000000c030a9232, "inv-guard INVALID3-word"),
        (
            0x00800c003000000c030a1232,
            "stray s87 single (289-era inert status quo)",
        ),
        (
            0x00100c003000000c030a1232,
            "stray b84 (no tok4 slot on HMUL2)",
        ),
        (0x00000c003000340c030a1232, "band [55:40] stray 0x34"),
        (0x08000c003000000c030a9232, "inv-guard b91 kill bit"),
    ];
    for (w, why) in holes {
        assert_eq!(dec(&t, *w), None, "sm121a doctrine must stay HOLE: {why}");
        let d = tab("sm120");
        assert_eq!(dec(&d, *w), None, "sm120 donor parity: {why}");
    }
    // w324 INVALID1-class corpus witness stays HOLE (pre AND post doctrine)
    assert_eq!(dec(&t, 0x00405d080000342c28087232u128), None);
    // b79 (RELU bit, no P-dest on HMUL2) is vendor text-inert AND accepted
    // via the donor 324 vm-relax: prints the base text (K_p_relu x4)
    assert_eq!(
        dec(&t, 0x00008c003000000c030a1232u128).as_deref(),
        Some("@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1"),
        "b79 must decode text-inert (donor parity)"
    );
    // era-text regression A: inv-guard survives mint+redecode (was the era
    // key's 3b guard dropping inv@15 => '@P6' vs vendor '@!P6')
    let w = enc(&t, "@!P6 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1").unwrap();
    assert_eq!(
        dec(&t, w & M96).as_deref(),
        Some("@!P6 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1")
    );
    // era-text regression B: hsels survive mint+redecode (was hsel-drop)
    let w = enc(&t, "HMUL2 R10, R3.H0_H0, R12.H0_H0").unwrap();
    assert_eq!(
        dec(&t, w & M96).as_deref(),
        Some("HMUL2 R10, R3.H0_H0, R12.H0_H0")
    );
    // fail-closed authored residua (loud refuse, no silent wrong code)
    for text in [
        "HMUL2.F32 R10, R3.H1_H1, R12.H1_H1",      // INVALID1 doctrine
        "HMUL2.OOB R10, R3.H1_H1, R12.H1_H1",      // INVALID3 doctrine
        "HMUL2 R15, R35, R0, R0",                  // phantom-4reg squatter gone
        "HMUL2.RELU R10, R3.H1_H1, R12.H1_H1, P2", // no P-dest on HMUL2
    ] {
        assert!(enc(&t, text).is_err(), "must loud-refuse: {text}");
    }
}

#[test]
fn t348_5_scope_guard_donor_legs_untouched() {
    // sm100a/sm103a HMUL2_R_R_R rows pre-date 348 and decode the plain
    // anchor identically; assert no accidental cross-leg drift.
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let x = tab(leg);
        let got = dec(&x, 0x000000c003000000c030a1232u128);
        assert_eq!(
            got.as_deref(),
            Some("@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1"),
            "{leg} plain anchor drift"
        );
    }
    // donor mg census tripwire (sm120 set is the graft source of truth)
    assert_eq!(tab("sm120").entries["HMUL2_R_R_R"].mod_groups.len(), 12);
    // sibling kraty on sm121a untouched by 348 (324-era rows stand)
    let t = tab("sm121a");
    assert_eq!(t.entries["HMUL2_R_R_UR"].mod_groups.len(), 12);
    assert_eq!(
        dec(&t, 0x8200000300000080c0b7c32u128).as_deref(),
        Some("HMUL2.BF16_V2 R11, R12, UR8.H1_H1")
    );
}
