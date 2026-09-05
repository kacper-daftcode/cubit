//! BUG-343/344 (F2-iter182, loop5/blind front2, 2026-09-02): HFMA2 pure-reg
//! krata 0x231 neg-window closure (343) + mod-window closure (344), legs
//! sm120+sm121a (canonical a013f88; branch fix/f2-343-344-hfma2-modwin,
//! ride-after 6b52ad4/BUG-341). Registered 343/344-kand LOW at 320.md sec.6
//! (arb320b I/J/K/L in hand), 343 narrowed post-327 to neg@63 tok3 (all mgs)
//! + neg@72 tok2 on the non-BF16 mgs.
//!
//! LAW (arb320b 48 + arb343 = 48 new probes, nvdisasm 13.3.73 raw -b, x4
//! models SM100a/103a/120/121a AGREE on EVERY probe, zero DIVERGENT;
//! work/bug343/arb343_verdicts.json + ../bug320/arb320b_verdicts.json):
//! the full 324-sibling mod window is vendor-legal on the PURE family:
//! DIRECT combos FMZ,SAT / F32,SAT / F32,FMZ,SAT / FTZ / OOB / FTZ,SAT /
//! OOB,SAT / F32,FTZ / F32,OOB / F32,FTZ,SAT / F32,OOB,SAT + all 6 BF16_V2
//! crosses with SAT/FTZ/OOB; RELU(b79) + pred 3b@[89:87] + inv@90 tok5:
//! pv=0..6 prints Pv, pv=7+inv0 ELIDES the token, pv=7+inv1 prints '!PT',
//! pv+inv prints '!Pv'; signs neg@72 tok2 / neg@63 tok3 (+abs) compose on
//! EVERY mod carrier x4. KILLS staying HOLE fail-closed: SAT x RELU =
//! rc=1 x4; F32 x BF16_V2 = '.INVALID3' print (285 doctrine); b91 = KILL
//! with SAT/RELU on.
//!
//! PRE-FIX (publish 1a2a5a0, canonical 2353989; work/bug343/measure_pre343):
//! 343 dense decode 12/12 + mints 9/9 vendor-exact via the generic sign
//! rescue/emit (320/327 mechanism) -- parity PRE-EXISTED, so N1 = pure
//! FIELD-CLOSURE + has_field_neg defer parity, zero behavior delta by data.
//! 344: decode HOLE 15/15 + encode loud-REFUSE 10/10 (BUG-132 lint) x4.
//! Corpus exposure census343 (53,653 lattice words): SAT/FTZ/RELU/neg63 =
//! ZERO; neg72 non-BF16 = exactly 1 word (t10.cubin .text.b0_31@0x410, the
//! tracked 320-era instrument lane; F32,FMZ decode parity pre-exists).
//! DONORS sm100a/sm103a byte-invariant (BUG-315 owner scope).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const B62: u128 = 1 << 62;
const B63: u128 = 1 << 63;
const B73: u128 = 1 << 73;
const B72: u128 = 1 << 72;
const B76: u128 = 1 << 76;
const B77: u128 = 1 << 77;
const B78: u128 = 1 << 78;
const B79: u128 = 1 << 79;
const B80: u128 = 1 << 80;
const B85: u128 = 1 << 85;
const B91: u128 = 1 << 91;
// HOST lattice: 0x231 | PT | R1@16, R2@24, R3@32, R4@64
const HOST: u128 = 0x231 | (7 << 12) | (1 << 16) | (2 << 24) | (3 << 32) | (4 << 64);
const BASE_MGS: [&str; 6] = ["", "BF16_V2", "F32", "FMZ", "F32,FMZ", "BF16_V2,FMZ"];
const NEW_MGS: [&str; 30] = [
    "SAT",
    "FMZ,SAT",
    "F32,SAT",
    "F32,FMZ,SAT",
    "FTZ",
    "OOB",
    "FTZ,SAT",
    "OOB,SAT",
    "F32,FTZ",
    "F32,OOB",
    "F32,FTZ,SAT",
    "F32,OOB,SAT",
    "BF16_V2,SAT",
    "BF16_V2,FMZ,SAT",
    "BF16_V2,FTZ",
    "BF16_V2,OOB",
    "BF16_V2,FTZ,SAT",
    "BF16_V2,OOB,SAT",
    "RELU",
    "F32,RELU",
    "FMZ,RELU",
    "F32,FMZ,RELU",
    "FTZ,RELU",
    "OOB,RELU",
    "F32,FTZ,RELU",
    "F32,OOB,RELU",
    "BF16_V2,RELU",
    "BF16_V2,FMZ,RELU",
    "BF16_V2,FTZ,RELU",
    "BF16_V2,OOB,RELU",
];
const DOTTED_P: [&str; 12] = [
    "HFMA2.RELU_R_R_R_R_P",
    "HFMA2.F32.RELU_R_R_R_R_P",
    "HFMA2.FMZ.RELU_R_R_R_R_P",
    "HFMA2.F32.FMZ.RELU_R_R_R_R_P",
    "HFMA2.FTZ.RELU_R_R_R_R_P",
    "HFMA2.OOB.RELU_R_R_R_R_P",
    "HFMA2.F32.FTZ.RELU_R_R_R_R_P",
    "HFMA2.F32.OOB.RELU_R_R_R_R_P",
    "HFMA2.BF16_V2.RELU_R_R_R_R_P",
    "HFMA2.BF16_V2.FMZ.RELU_R_R_R_R_P",
    "HFMA2.BF16_V2.FTZ.RELU_R_R_R_R_P",
    "HFMA2.BF16_V2.OOB.RELU_R_R_R_R_P",
];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t343_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_R"];
        assert_eq!(e.mod_groups.len(), 36, "{leg}: krata 0x231 mg count drift");
        for mg in BASE_MGS {
            assert!(
                e.mod_groups.contains_key(mg),
                "{leg}: mandatory mg {mg:?} missing"
            );
        }
        for mg in NEW_MGS {
            assert!(
                e.mod_groups.contains_key(mg),
                "{leg}: graft lane {mg:?} missing"
            );
        }
        // N1 sign-field closure on the mandatory rows (exactly once each)
        for mg in BASE_MGS {
            let g = &e.mod_groups[mg];
            let has = |ext: Extraction, shift: u32, tok: i32| {
                g.fields
                    .iter()
                    .filter(|f| f.extraction == ext && f.shift == shift && f.token_idx == tok)
                    .count()
            };
            assert_eq!(has(Extraction::Neg, 63, 3), 1, "{leg}[{mg:?}]: neg@63 tok3");
            // every mandatory mg carries neg@72 tok2 exactly once post-graft:
            // on the BF16 rows the field is PRE-EXISTING (era-2d); on the
            // other four it is the N1 closure of this graft.
            assert_eq!(has(Extraction::Neg, 72, 2), 1, "{leg}[{mg:?}]: neg@72 tok2");
            // 320/327 anchors stay fielded exactly once
            assert_eq!(has(Extraction::Abs, 62, 3), 1, "{leg}[{mg:?}]: 327 abs@62");
            assert_eq!(has(Extraction::Abs, 83, 4), 1, "{leg}[{mg:?}]: 320 abs@83");
        }
        // base-key RELU mg = pv7 elision bake (donor delta law), no pred fields
        let pl = &e.mod_groups[""];
        let re = &e.mod_groups["RELU"];
        assert_eq!(
            (re.and_base ^ pl.and_base) & ((0x7u128 << 87) | B79),
            (0x7u128 << 87) | B79,
            "{leg}: RELU mg pv7+b79 bake drift"
        );
        assert_eq!(
            re.variable_mask, pl.variable_mask,
            "{leg}: RELU mg vm drift vs plain"
        );
        assert!(
            !re.fields.iter().any(|f| f.extraction == Extraction::Pred),
            "{leg}: base RELU mg gained a pred field"
        );
        // dotted _P keys: pred@87 + inv@90 tok5, ab = lane|b79 (no pv bake),
        // vm |= 0xf<<87
        for dk in DOTTED_P {
            let d = &t.entries[dk];
            let g = &d.mod_groups[""];
            assert!(
                g.fields.iter().any(|f| {
                    f.extraction == Extraction::Pred
                        && f.shift == 87
                        && f.bits == 3
                        && f.token_idx == 5
                }),
                "{leg} {dk}: pred 3b@87 tok5 missing"
            );
            assert!(
                g.fields.iter().any(|f| {
                    f.extraction == Extraction::Inv
                        && f.shift == 90
                        && f.bits == 1
                        && f.token_idx == 5
                }),
                "{leg} {dk}: inv 1b@90 tok5 missing"
            );
            assert_eq!(g.and_base & B79, B79, "{leg} {dk}: b79 bake missing");
            assert_eq!(
                g.and_base & (0x7u128 << 87),
                0,
                "{leg} {dk}: pv bake leaked"
            );
            assert_eq!(
                g.variable_mask & (0xfu128 << 87),
                0xfu128 << 87,
                "{leg} {dk}: vm pv window missing"
            );
        }
        // 324 sibling anchor intact (its own family untouched by this graft)
        assert!(t.entries["HFMA2_R_R_R_UR"]
            .mod_groups
            .contains_key("OOB,SAT"));
        assert!(t.entries.contains_key("HFMA2.OOB.RELU_R_R_R_UR_P"));
    }
    // donors: neg@63 never grafted in the family; neg@72 rides the BF16
    // donor geometry.
    // FLIP (BUG-381, F2-iter203, canonical 3cb31e4): the sparse 0x231
    // lattice completion grafts the full 36-lane set + the 12 dotted
    // _R_R_R_R_P keys on the donor legs -- the 'no new lanes/no dotted
    // keys' invariant is CLOSED (presence now asserted); neg@63 still
    // absent; neg@72 = exactly the BF16-class rows (donor descendants).
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_R"];
        assert_eq!(e.mod_groups.len(), 36, "{leg}: donor family census");
        for (mg, g) in &e.mod_groups {
            assert!(
                !g.fields
                    .iter()
                    .any(|f| f.extraction == Extraction::Neg && f.shift == 63),
                "{leg}[{mg}]: donor neg@63 grafted"
            );
            let want72: usize = if mg.contains("BF16_V2") { 1 } else { 0 };
            assert_eq!(
                g.fields
                    .iter()
                    .filter(|f| f.extraction == Extraction::Neg && f.shift == 72)
                    .count(),
                want72,
                "{leg}[{mg}]: donor neg@72 state drift (BF16-class only)"
            );
        }
        for dk in DOTTED_P {
            assert!(
                t.entries.contains_key(dk),
                "{leg}: BUG-381 dotted key {dk} missing"
            );
        }
    }
}

#[test]
fn t343_2_decode_law_vendor_equal() {
    // (word, nvdisasm-verified text) -- every expectation is arb-verified
    // x4-agree on ALL FOUR models; decode asserted on the two dense legs.
    let cases: &[(u128, &str)] = &[
        (
            0x000030040000000302017231u128,
            "HFMA2.FMZ.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x000070040000000302017231u128,
            "HFMA2.F32.FMZ.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x000130040000000302017231u128,
            "HFMA2.OOB.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x000150040000000302017231u128,
            "HFMA2.F32.OOB R1, R2, R3, R4",
        ), // arb343
        (
            0x000160040000000302017231u128,
            "HFMA2.F32.FTZ.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x000170040000000302017231u128,
            "HFMA2.F32.OOB.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x002020040000000302017231u128,
            "HFMA2.BF16_V2.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x002100040000000302017231u128,
            "HFMA2.BF16_V2.FTZ R1, R2, R3, R4",
        ), // arb343
        (
            0x002110040000000302017231u128,
            "HFMA2.BF16_V2.OOB R1, R2, R3, R4",
        ), // arb343
        (
            0x002030040000000302017231u128,
            "HFMA2.BF16_V2.FMZ.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x002120040000000302017231u128,
            "HFMA2.BF16_V2.FTZ.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x002130040000000302017231u128,
            "HFMA2.BF16_V2.OOB.SAT R1, R2, R3, R4",
        ), // arb343
        (
            0x000080040000000302017231u128,
            "HFMA2.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x0000c0040000000302017231u128,
            "HFMA2.F32.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x000090040000000302017231u128,
            "HFMA2.FMZ.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x0000d0040000000302017231u128,
            "HFMA2.F32.FMZ.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x000180040000000302017231u128,
            "HFMA2.FTZ.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x000190040000000302017231u128,
            "HFMA2.OOB.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x0001c0040000000302017231u128,
            "HFMA2.F32.FTZ.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x0001d0040000000302017231u128,
            "HFMA2.F32.OOB.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x002080040000000302017231u128,
            "HFMA2.BF16_V2.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x002090040000000302017231u128,
            "HFMA2.BF16_V2.FMZ.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x002180040000000302017231u128,
            "HFMA2.BF16_V2.FTZ.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x002190040000000302017231u128,
            "HFMA2.BF16_V2.OOB.RELU R1, R2, R3, R4, P0",
        ), // arb343
        (
            0x0180c0040000000302017231u128,
            "HFMA2.F32.RELU R1, R2, R3, R4, P3",
        ), // arb343
        (
            0x0380c0040000000302017231u128,
            "HFMA2.F32.RELU R1, R2, R3, R4",
        ), // arb343
        (
            0x0780c0040000000302017231u128,
            "HFMA2.F32.RELU R1, R2, R3, R4, !PT",
        ), // arb343
        (
            0x068080040000000302017231u128,
            "HFMA2.RELU R1, R2, R3, R4, !P5",
        ), // arb343
        (
            0x03a090040000000302017231u128,
            "HFMA2.BF16_V2.FMZ.RELU R1, R2, R3, R4",
        ), // arb343
        (0x000020048000000302017231u128, "HFMA2.SAT R1, R2, -R3, R4"), // arb343
        (0x000101040000000302017231u128, "HFMA2.FTZ R1, -R2, R3, R4"), // arb343
        (
            0x00011004c000000302017231u128,
            "HFMA2.OOB R1, R2, -|R3|, R4",
        ), // arb343
        (
            0x000081048000000302017231u128,
            "HFMA2.RELU R1, -R2, -R3, R4, P0",
        ), // arb343
        (
            0x000061040000000302017231u128,
            "HFMA2.F32.SAT R1, -R2, R3, R4",
        ), // arb343
        (
            0x002020048000000302017231u128,
            "HFMA2.BF16_V2.SAT R1, R2, -R3, R4",
        ), // arb343
        (0x000011040000000302017231u128, "HFMA2.FMZ R1, -R2, R3, R4"), // arb343
        (
            0x000051040000000302017231u128,
            "HFMA2.F32.FMZ R1, -R2, R3, R4",
        ), // arb343
        (0x000041040000000302017231u128, "HFMA2.F32 R1, -R2, R3, R4"), // arb343
        (
            0x002010048000000302017231u128,
            "HFMA2.BF16_V2.FMZ R1, R2, -R3, R4",
        ), // arb343
        (
            0x000020041000000302017231u128,
            "HFMA2.SAT R1, R2, R3.F32, R4",
        ), // arb343
        (
            0x004080040000000302017231u128,
            "HFMA2.RELU R1, R2, R3.H0_NH1, R4, P0",
        ), // arb343
        (0x000000044000000302017231u128, "HFMA2 R1, R2, |R3|, R4"),    // arb320b
        (0x000000048000000302017231u128, "HFMA2 R1, R2, -R3, R4"),     // arb320b
        (0x00000004c000000302017231u128, "HFMA2 R1, R2, -|R3|, R4"),   // arb320b
        (
            0x00000004a000000302017231u128,
            "HFMA2 R1, R2, -R3.H0_H0, R4",
        ), // arb320b
        (0x000003040000000302017231u128, "HFMA2 R1, -|R2|, R3, R4"),   // arb320b
        (
            0x00000f040000000302017231u128,
            "HFMA2 R1, -|R2|.H1_H1, R3, R4",
        ), // arb320b
        (0x000020040000000302017231u128, "HFMA2.SAT R1, R2, R3, R4"),  // arb320b
        (0x000100040000000302017231u128, "HFMA2.FTZ R1, R2, R3, R4"),  // arb320b
        (
            0x000060040000000302017231u128,
            "HFMA2.F32.SAT R1, R2, R3, R4",
        ), // arb320b
        (
            0x000140040000000302017231u128,
            "HFMA2.F32.FTZ R1, R2, R3, R4",
        ), // arb320b
        (0x000110040000000302017231u128, "HFMA2.OOB R1, R2, R3, R4"),  // arb320b
        (
            0x000120040000000302017231u128,
            "HFMA2.FTZ.SAT R1, R2, R3, R4",
        ), // arb320b
        (
            0x000080040000000302017231u128,
            "HFMA2.RELU R1, R2, R3, R4, P0",
        ), // arb320b
        (0x038080040000000302017231u128, "HFMA2.RELU R1, R2, R3, R4"), // arb320b
        (
            0x048080040000000302017231u128,
            "HFMA2.RELU R1, R2, R3, R4, !P1",
        ), // arb320b
        (
            0x001840040000000302017231u128,
            "HFMA2.F32 R1, R2, R3, -|R4|",
        ), // arb320b
        (
            0x004410040000000302017231u128,
            "HFMA2.FMZ R1, R2, R3.H0_NH1, R4.H0_H0",
        ), // arb320b
        (
            0x00405f040000000302017231u128,
            "HFMA2.F32.FMZ R1, -|R2|.H1_H1, R3.H0_NH1, R4",
        ), // arb320b
        (
            0x00405d080000002c28087231u128,
            "HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8",
        ), // arb320b
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (w, want) in cases {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg}: HOLE on armed lane {w:024x}"));
            assert_eq!(&got, want, "{leg}: decode drift on {w:024x}");
        }
    }
}

#[test]
fn t343_3_encode_word_exact_and_roundtrip() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // 343: sign mints word-exact through the fielded lanes
        let w = enc(&t, "HFMA2 R1, R2, -R3, R4").unwrap();
        assert_eq!(w & M96, (HOST | B63) & M96, "{leg}: tok3 neg mint drift");
        let w = enc(&t, "HFMA2 R1, -R2, R3, R4").unwrap();
        assert_eq!(w & M96, (HOST | B72) & M96, "{leg}: tok2 neg mint drift");
        let w = enc(&t, "HFMA2 R1, -|R2|, -|R3|, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B62 | B63 | B72 | B73) & M96,
            "{leg}: full sign-set mint drift"
        );
        // 344: carrier + RELU mints word-exact
        let w = enc(&t, "HFMA2.SAT R1, R2, R3, R4").unwrap();
        assert_eq!(w & M96, (HOST | B77) & M96, "{leg}: SAT mint drift");
        let w = enc(&t, "HFMA2.F32.FTZ.SAT R1, -R2, R3, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B77 | B78 | B80 | B72) & M96,
            "{leg}: F32.FTZ.SAT + neg72 mint drift"
        );
        let w = enc(&t, "HFMA2.BF16_V2.OOB R1, R2, -R3, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B85 | B76 | B80 | B63) & M96,
            "{leg}: BF16_V2.OOB + neg63 mint drift"
        );
        // RELU _P: explicit pred mints through the dotted keys
        let w = enc(&t, "HFMA2.RELU R1, R2, R3, R4, P0").unwrap();
        assert_eq!(w & M96, (HOST | B79) & M96, "{leg}: RELU P0 mint drift");
        let w = enc(&t, "HFMA2.F32.RELU R1, R2, R3, R4, P3").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B78 | B79 | (3 << 87)) & M96,
            "{leg}: F32.RELU P3 mint drift"
        );
        let w = enc(&t, "HFMA2.RELU R1, R2, R3, R4, !P5").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B79 | (5 << 87) | (1 << 90)) & M96,
            "{leg}: RELU !P5 mint drift"
        );
        // RELU elision: authored without pred -> pv7 elision bake word
        let w = enc(&t, "HFMA2.RELU R1, R2, R3, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B79 | (0x7 << 87)) & M96,
            "{leg}: RELU no-pred mint must carry the pv7 elision bake"
        );
        // roundtrips byte-stable on the armed lanes
        for txt in [
            "HFMA2 R1, R2, -R3, R4",
            "HFMA2 R1, -|R2|, R3, R4",
            "HFMA2.SAT R1, R2, R3, R4",
            "HFMA2.OOB R1, R2, -|R3|, R4",
            "HFMA2.F32.FMZ.SAT R1, R2, R3, R4",
            "HFMA2.BF16_V2.SAT R1, R2, -R3, R4",
            "HFMA2.RELU R1, -R2, -R3, R4, P0",
            "HFMA2.RELU R1, R2, R3, R4, !P5",
            "HFMA2.F32.RELU R1, R2, R3, R4, P3",
            "HFMA2.BF16_V2.FMZ.RELU R1, R2, R3, R4, P0",
            "HFMA2.F32.FTZ R1, R2, R3.H0_NH1, R4",
        ] {
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("{leg}: encode hole: {txt}: {e}"));
            assert_eq!(
                &dec(&t, w).unwrap_or_else(|| panic!("{leg}: decode hole post-encode: {txt}")),
                txt,
                "{leg}: text roundtrip drift: {txt}"
            );
        }
        // elision roundtrips: authored elided forms decode back elided
        for txt in [
            "HFMA2.RELU R1, R2, R3, R4",
            "HFMA2.F32.RELU R1, R2, R3, R4",
            "HFMA2.BF16_V2.FMZ.RELU R1, R2, R3, R4",
        ] {
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("{leg}: encode hole: {txt}: {e}"));
            assert_eq!(
                &dec(&t, w).unwrap_or_else(|| panic!("{leg}: decode hole post-encode: {txt}")),
                txt,
                "{leg}: elision roundtrip drift: {txt}"
            );
        }
    }
}

#[test]
fn t343_4_fail_closed_doctrine_edges() {
    let holes: &[(u128, &str)] = &[
        (0x0000a0040000000302017231u128, "E1_satrelu"),
        (0x080020040000000302017231u128, "E3_b91sat"),
        (0x080080040000000302017231u128, "E4_b91relu"),
        (0x002040040000000302017231u128, "E2_f32bf16"),
        (0x080040040000000302017231u128, "M_f32b91"),
        (0x080001040000000302017231u128, "M_negb91"),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (w, name) in holes {
            assert!(dec(&t, *w).is_none(), "{leg}: {name} decoded post-graft!");
        }
        // SAT x RELU authored forms stay loud-fail (vendor rc=1 x4)
        assert!(enc(&t, "HFMA2.SAT.RELU R1, R2, R3, R4, P0").is_err());
        // INVALID3-authored text never mints (285 doctrine)
        assert!(enc(&t, "HFMA2.F32.BF16_V2 R1, R2, R3, R4").is_err());
        // b91 KILL mint side: SAT lane with stray b91 word stays HOLE (above),
        // and the elision pv7 word without RELU stays unarmed (289 stray band)
        assert!(
            dec(&t, HOST | (0x7 << 87)).is_none(),
            "{leg}: stray pv band decoded!"
        );
    }
    // donors: mod lanes were HOLE pre-381 (byte-invariant tables).
    // FLIP (BUG-381, F2-iter203, canonical 3cb31e4): the sparse 0x231
    // completion arms the lanes on the donor legs -- SAT decode/mint +
    // RELU decode are now vendor-exact LIVE on donors (positively
    // asserted); the pre-existing parity subset is unchanged.
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        // HOST here = the R_R_R_R window base with R1..R4 carriers
        assert_eq!(
            dec(&t, HOST | B77).as_deref(),
            Some("HFMA2.SAT R1, R2, R3, R4"),
            "{leg}: BUG-381 donor SAT decode drift"
        );
        assert!(
            enc(&t, "HFMA2.SAT R1, R2, R3, R4").is_ok(),
            "{leg}: BUG-381 donor SAT mint refused!"
        );
        assert_eq!(
            dec(&t, HOST | B79 | (0x7 << 87)).as_deref(),
            Some("HFMA2.RELU R1, R2, R3, R4"),
            "{leg}: BUG-381 donor RELU (pv7) decode drift"
        );
        // SAT x RELU kill stands on donors (vendor rc=1 all models)
        assert!(enc(&t, "HFMA2.SAT.RELU R1, R2, R3, R4").is_err());
        // donor pre-existing dense parity subset unchanged
        assert_eq!(
            dec(&t, HOST | B63).as_deref(),
            Some("HFMA2 R1, R2, -R3, R4"),
            "{leg}: donor plain neg63 decode drifted"
        );
    }
}

#[test]
fn t343_5_instrument_lane_and_anchors() {
    // the one corpus-visible word of the armed windows (census343):
    // t10.cubin .text.b0_31@0x410 = 0x405d080000342c28087231 (F32,FMZ|neg72);
    // decode must be byte-identical to the pre-graft generic-rescue result on
    // both dense legs (field-closure neutrality), vendor-verified by
    // arb320b P_w321clean class probes.
    const W321: u128 = 0x405d080000342c28087231;
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, W321).as_deref(),
            Some("HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8"),
            "{leg}: instrument word decode drift (F32,FMZ neg72 lane)"
        );
    }
    // 320/327-era decode anchors byte-stable on the dense legs
    let anchors: &[(u128, &str)] = &[
        (HOST, "HFMA2 R1, R2, R3, R4"),
        (HOST | B85, "HFMA2.BF16_V2 R1, R2, R3, R4"),
        (HOST | B76, "HFMA2.FMZ R1, R2, R3, R4"),
        (HOST | B78, "HFMA2.F32 R1, R2, R3, R4"),
        (HOST | B76 | B78, "HFMA2.F32.FMZ R1, R2, R3, R4"),
        (HOST | (1 << 62), "HFMA2 R1, R2, |R3|, R4"),
        (HOST | (1 << 83), "HFMA2 R1, R2, R3, |R4|"),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (w, want) in anchors {
            assert_eq!(
                dec(&t, *w).as_deref(),
                Some(*want),
                "{leg}: anchor {w:024x} drift"
            );
        }
    }
}
