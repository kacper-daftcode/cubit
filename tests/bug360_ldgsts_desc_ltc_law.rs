//! BUG-360 (F2-iter190, loop5/blind front2, 2026-09-03): LDGSTS desc non-128
//! imm2 era widths on sm100a (15/18/14b -> 12b@32 signed; i84-180 port of the
//! 334 class) + b72 LTC-lattice law: b73,b72 = none/LTC64B/LTC128B/LTC256B,
//! b72 is NOT a UR bit (UR = 8b@[71:64]; arb180c t1 long documented) --
//! claim-dual 64,E,LTC128B<->64,E,LTC256B closed and the fleet-era ghost-UR
//! class (b72=1 words printing UR+256) converted to loud HOLE where rows
//! absent. canonical 0fc03f9; ENGINE untouched.
//!
//! PRE (publish cubit-9a1e300 / cubit_py-9a1e300 d9272210.., canonical
//!   3bc2c15; work/bug360/measure_pre360.json):
//!   D1: 'E,LTC256B'-shape word decodes WRONG x3 legs ('LTC128B' + UR276
//!       ghost); '128,BYPASS,LTC256B _P' WRONG x3 (UR270 ghost);
//!       '128,BYPASS,LTC64B' WRONG x3 (UR274 ghost); '64,E,LTC256B' OK-text
//!       on 100a/103a but sign-RAW on 100a ('+0x800' vs vendor '+-0x800');
//!       sm121a HOLE everywhere (dotted keys, stays -- 376).
//!   D2: authored desc '+0x1000' on the 7 era mgs = SILENT drop on sm100a
//!       (roundtrip loses the offset) vs loud encode-lint on 103a/120;
//!       authored '+-0x800' on era mgs roundtrips as '+0x800' on sm100a
//!       (silent sign flip); authored LTC256B (E-class / _P) = loud FAIL x3.
//! LAW (arb360 106 + arb360b 11 probes, nvdisasm 13.3.73 raw -b, x4 models
//!   SM100a/SM103a/SM120/SM121a AGREE on EVERY probe;
//!   work/bug360/arb360_verdicts.json + arb360b_verdicts.json):
//!   desc-imm 12b@32 signed on every non-128 desc class ('+-0x800' for raw
//!   0x800); ext bits [49:44] of the era widths render as DST-imm
//!   (ghost sweep 44..52 on 6 corpus witnesses incl both _P sides);
//!   b72 = LTC size discriminator (128B/256B pair vs 64B-without-b73);
//!   UR field = 8b@[71:64] (vendor UR56/88/152 legal = b69/b70/b71).
//! CORPUS (census334b 30,049-slot desc battery): ghost ext-bits [49:44] = 0;
//!   b72=1 = 0; b71 (UR>=128) = 0; sign-window [0x800..0xfff] = 28 slots
//!   sm_100 ONLY ('E' x24 {0xff4,0xff8,0xffc} + '64,E' x4 {0xff8}) = the
//!   only measured abtext class, each cured to vendor text.
//! FIX parts (patch360.py):
//!   A sm100a: 7 imm2 flips -> 12b@32 (dARI 64,E / 64,E,LTC128B /
//!     64,E,LTC256B / E / E,LTC128B; dARI_P 64,E,LTC128B / E,LTC128B).
//!   B x3 legs: ur0 9b->8b on '64,E,LTC128B'+'E,LTC128B' both keys; grafts
//!     dARI 'E,LTC256B', dARI_P '64,E,LTC256B' + 'E,LTC256B' (clone
//!     post-adjust donors, ab|=b72); anchor dARI '64,E,LTC256B' verified.
//!   C x3 legs: ur0 9b->8b on ALL remaining LDGSTS_ARI_dARI{,_P} rows
//!     (b72=1 -> loud HOLE on LTC64B/128-family-256B/BYPASS crosses = 376).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B72: u128 = 1u128 << 72;

// corpus witnesses (census334b sm_100; arb360 anchors):
const W64E: u128 = 0x0003e2000b9a14080010000042367fae; // LDGSTS.E.64 [R54+0x100], desc[UR8][R66.64]
const W64LTC: u128 = 0x0007e2000b9a16180000000006097fae; // LDGSTS.E.LTC128B.64 [R9], desc[UR24][R6.64]
const WE: u128 = 0x0003e2000b9a100c000800001a137fae; // LDGSTS.E [R19+0x80], desc[UR12][R26.64]
const WELTC: u128 = 0x0005e8000b9a12140000000006417fae; // LDGSTS.E.LTC128B [R65], desc[UR20][R6.64]
const W64LTCP: u128 = 0x000fe200081a161804840000561e7fae; // .64 LTC _P
const WELTCP: u128 = 0x000fe200081a12140220000044337fae; // LTC _P
const B128: u128 = 0x0003e20008981a0e018800801c5a7fae; // 128 BYPASS LTC _P
const A128: u128 = 0x0007e2000b98181206000000181b7fae; // 128 BYPASS plain

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
fn t360_1_structure_widths_dual_closed() {
    // Part A: 7 sm100a mgs now 12b@32; cross-leg parity vs sm103a.
    let a = tab("sm100a");
    let b = tab("sm103a");
    for (key, mg) in [
        ("LDGSTS_ARI_dARI", "64,E"),
        ("LDGSTS_ARI_dARI", "64,E,LTC128B"),
        ("LDGSTS_ARI_dARI", "64,E,LTC256B"),
        ("LDGSTS_ARI_dARI", "E"),
        ("LDGSTS_ARI_dARI", "E,LTC128B"),
        ("LDGSTS_ARI_dARI_P", "64,E,LTC128B"),
        ("LDGSTS_ARI_dARI_P", "E,LTC128B"),
    ] {
        let f = a.entries[key].mod_groups[mg]
            .fields
            .iter()
            .find(|f| matches!(f.extraction, cubit::table::Extraction::SubImm(2)))
            .unwrap();
        assert_eq!((f.bits, f.shift), (12, 32), "sm100a {key}::{mg} imm2 law");
        let strip = |fl: &Vec<cubit::table::Field>| {
            fl.iter()
                .map(|f| (f.shift, f.bits, f.token_idx, format!("{:?}", f.extraction)))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            strip(&a.entries[key].mod_groups[mg].fields),
            strip(&b.entries[key].mod_groups[mg].fields),
            "{key}::{mg} cross-leg parity"
        );
    }
    for leg in LEGS3 {
        let t = tab(leg);
        // EVERY row in the two desc keys: ur0 = 8b@64 (b72 in match, not fm)
        for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
            for (mg, g) in &t.entries[key].mod_groups {
                let u = g
                    .fields
                    .iter()
                    .find(|f| matches!(f.extraction, cubit::table::Extraction::SubUR(0)))
                    .unwrap_or_else(|| panic!("{leg} {key}::{mg} ur0 missing"));
                assert_eq!((u.bits, u.shift), (8, 64), "{leg} {key}::{mg} ur0 law");
                assert_eq!(
                    g.variable_mask & B72,
                    0,
                    "{leg} {key}::{mg} vm must not mask b72"
                );
            }
            // grafted LTC256B lattice rows
            for (donor, new) in [("E,LTC128B", "E,LTC256B"), ("64,E,LTC128B", "64,E,LTC256B")] {
                let d = &t.entries[key].mod_groups[donor];
                let n = &t.entries[key]
                    .mod_groups
                    .get(new)
                    .unwrap_or_else(|| panic!("{leg} {key}::{new} graft missing"));
                assert_eq!(n.and_base ^ d.and_base, B72, "{leg} {key}::{new} ab delta");
                assert_eq!(n.variable_mask, d.variable_mask, "{leg} {key}::{new} vm");
            }
        }
        // pairwise claim-disjoint (strict; the pre-360 dual is closed)
        for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
            let items: Vec<_> = t.entries[key].mod_groups.iter().collect();
            let mask = |g: &cubit::table::ModGroupEntry| {
                let mut m = g.variable_mask;
                for f in &g.fields {
                    m |= ((1u128 << f.bits) - 1) << f.shift;
                }
                m
            };
            for (i, (ka, va)) in items.iter().enumerate() {
                for (kb, vb) in &items[i + 1..] {
                    let inter = !mask(va) & !mask(vb) & M96;
                    assert_ne!(
                        va.and_base & inter,
                        vb.and_base & inter,
                        "{leg} {key}: claim overlap {ka} <-> {kb}"
                    );
                }
            }
        }
    }
}

#[test]
fn t360_2_decode_battery_vendor_texts() {
    // (word, vendor text) -- arb360/arb360b x4-unanimous prints.
    let cases: [(u128, &str); 12] = [
        (W64E, "LDGSTS.E.64 [R54+0x100], desc[UR8][R66.64]"),
        (W64LTC, "LDGSTS.E.LTC128B.64 [R9], desc[UR24][R6.64]"),
        (WE, "LDGSTS.E [R19+0x80], desc[UR12][R26.64]"),
        (WELTC, "LDGSTS.E.LTC128B [R65], desc[UR20][R6.64]"),
        (
            W64LTCP,
            "LDGSTS.E.LTC128B.64 [R30+0x4840], desc[UR24][R86.64], P0",
        ),
        (
            WELTCP,
            "LDGSTS.E.LTC128B [R51+0x2200], desc[UR20][R68.64], P0",
        ),
        // desc-imm 12b signed (era sign-RAW class cured on sm100a):
        (
            (W64E & !(0xFFFu128 << 32)) | (0x800u128 << 32),
            "LDGSTS.E.64 [R54+0x100], desc[UR8][R66.64+-0x800]",
        ),
        (
            (WE & !(0xFFFu128 << 32)) | (0xFF4u128 << 32),
            "LDGSTS.E [R19+0x80], desc[UR12][R26.64+-0xc]",
        ),
        // b72 lattice: LTC256B now vendor-exact on x3 legs (+_P):
        (W64LTC | B72, "LDGSTS.E.LTC256B.64 [R9], desc[UR24][R6.64]"),
        (WELTC | B72, "LDGSTS.E.LTC256B [R65], desc[UR20][R6.64]"),
        (
            W64LTCP | B72,
            "LDGSTS.E.LTC256B.64 [R30+0x4840], desc[UR24][R86.64], P0",
        ),
        // UR = 8b@64 (b71 toggle: UR24+128 = UR152; b72 must NOT enter UR):
        (
            W64LTC ^ (1u128 << 71),
            "LDGSTS.E.LTC128B.64 [R9], desc[UR152][R6.64]",
        ),
    ];
    for leg in LEGS3 {
        let t = tab(leg);
        for (w, want) in cases {
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg} hole on {want}"));
            assert_eq!(got, want, "{leg} decode");
        }
    }
}

#[test]
fn t360_3_mint_word_exact_roundtrip() {
    let cases: [(&str, u128); 7] = [
        ("LDGSTS.E.LTC256B [R65], desc[UR20][R6.64]", WELTC | B72),
        ("LDGSTS.E.LTC256B.64 [R9], desc[UR24][R6.64]", W64LTC | B72),
        (
            "LDGSTS.E.LTC256B.64 [R30+0x4840], desc[UR24][R86.64], P0",
            W64LTCP | B72,
        ),
        (
            "LDGSTS.E.LTC256B [R51+0x2200], desc[UR20][R68.64], P0",
            WELTCP | B72,
        ),
        (
            "LDGSTS.E.LTC128B.64 [R9], desc[UR24][R6.64+-0x800]",
            (W64LTC & !(0xFFFu128 << 32)) | (0x800u128 << 32),
        ),
        (
            "LDGSTS.E.64 [R54+0x100], desc[UR8][R66.64+-0x800]",
            (W64E & !(0xFFFu128 << 32)) | (0x800u128 << 32),
        ),
        (
            "LDGSTS.E [R19+0x80], desc[UR12][R26.64+-0x1]",
            (WE & !(0xFFFu128 << 32)) | (0xFFFu128 << 32),
        ),
    ];
    for (text, want) in cases {
        let mut mints = Vec::new();
        for leg in LEGS3 {
            let t = tab(leg);
            let got = enc(&t, text).unwrap_or_else(|e| panic!("{leg} {text}: {e}"));
            assert_eq!(got & M96, want & M96, "{leg} mint {text}");
            let s = dec(&t, got).unwrap();
            assert_eq!(s, text, "{leg} roundtrip text drift");
            mints.push(got & M96);
        }
        assert_eq!(mints[0], mints[1], "100a==103a {text}");
        assert_eq!(mints[1], mints[2], "103a==120 {text}");
    }
}

#[test]
fn t360_4_fail_closed_and_lint() {
    for leg in LEGS3 {
        let t = tab(leg);
        // authored desc offsets beyond signed-12 now lint-loud on sm100a too
        // (was silent drop on the 7 era mgs pre-360):
        for text in [
            "LDGSTS.E.64 [R54+0x100], desc[UR8][R66.64+0x1000]",
            "LDGSTS.E.LTC128B.64 [R9], desc[UR24][R6.64+0x1000]",
            "LDGSTS.E [R19+0x80], desc[UR12][R26.64+0x1000]",
            "LDGSTS.E.LTC128B [R65], desc[UR20][R6.64+0x1000], P1",
        ] {
            assert!(enc(&t, text).is_err(), "{leg} {text} must lint loud");
        }
        // BUG-376 flip (canonical 6742fdf): the LTC64B/256B lattice is
        // grafted (arb376b x4 AGREE); authored LTC64B now encodes and
        // round-trips vendor-verbatim:
        let w = enc(&t, "LDGSTS.E.LTC64B.64 [R9], desc[UR24][R6.64]")
            .unwrap_or_else(|e| panic!("{leg}: LTC64B must encode post-376: {e}"));
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("LDGSTS.E.LTC64B.64 [R9], desc[UR24][R6.64]"),
            "{leg}: LTC64B roundtrip drift"
        );
        // formerly un-rowed b72=1 classes decode vendor-verbatim post-376
        // (silent ghost-UR era long gone); the size-64 BYPASS base gap is
        // NOT grafted (386-kand) and stays HOLE:
        assert_eq!(
            dec(&t, A128 | B72).as_deref(),
            Some("LDGSTS.E.BYPASS.LTC64B.128 [R27+0x6000], desc[UR18][R24.64]"),
            "{leg}: BYPASS.LTC64B.128 decode drift"
        );
        assert_eq!(
            dec(&t, B128 | B72).as_deref(),
            Some("LDGSTS.E.BYPASS.LTC256B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1"),
            "{leg}: _P BYPASS.LTC256B.128 decode drift"
        );
        assert!(
            dec(&t, W64LTC ^ (1u128 << 81) | B72).is_none(),
            "{leg}: 64,BYPASS base gap stays HOLE (386)"
        );
    }
    // sm121a: covered by the 376 dotted graft -- LTC256B.64 decodes
    // vendor-verbatim (was HOLE pre-376):
    let t121 = tab("sm121a");
    assert_eq!(
        dec(&t121, W64LTC | B72).as_deref(),
        Some("LDGSTS.E.LTC256B.64 [R9], desc[UR24][R6.64]"),
        "121a LTC256B.64 decode drift (post-376)"
    );
}

#[test]
fn t360_5_anchor_invariants() {
    // dARI '64,E,LTC256B' anchor (100a/103a): ab carries b72, ur0 8b era.
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let g = &t.entries["LDGSTS_ARI_dARI"].mod_groups["64,E,LTC256B"];
        assert!(g.and_base & B72 != 0, "{leg} anchor ab b72");
        let u = g
            .fields
            .iter()
            .find(|f| matches!(f.extraction, cubit::table::Extraction::SubUR(0)))
            .unwrap();
        assert_eq!((u.bits, u.shift), (8, 64), "{leg} anchor ur0 era-8b");
    }
    // ghost-UR ghost must be gone: pre-360 sm120 '64,E,LTC256B' word printed
    // 'LTC128B.64 ... desc[UR280]'; post-360 it prints vendor text (Part B):
    for leg in LEGS3 {
        let t = tab(leg);
        let s = dec(&t, W64LTC | B72 | (0x800u128 << 32)).unwrap();
        assert_eq!(
            s, "LDGSTS.E.LTC256B.64 [R9], desc[UR24][R6.64+-0x800]",
            "{leg} ghost class cured (sign + UR + LTC) in one"
        );
    }
    // donors of 311/334/359 waves unchanged in ab:
    for leg in LEGS3 {
        let t = tab(leg);
        let g = &t.entries["LDGSTS_ARI_dARI"].mod_groups["128,E"];
        assert_eq!(
            g.and_base & M96,
            0x000000000b9a18000000000000000fae,
            "{leg} alloc-plain ab drift"
        );
    }
}
