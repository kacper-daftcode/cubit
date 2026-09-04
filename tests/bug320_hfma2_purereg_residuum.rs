//! BUG-320/321 (F2-iter171, loop5/blind front2, 2026-09-01): HFMA2 pure-reg
//! 0x231-lattice residuum closure, legs sm120+sm121a (canonical bug320/321
//! cut 1e2b7ba, ride-after 8e12541/BUG-316). Registered 320/321-kand LOW at
//! F2-iter159 (287 report sec.6; arb287 H-set in hand). Measurement-first:
//! arb320 a/b/c = 312 probes + arb287 H/I-set, nvdisasm 13.3.73 raw -b, x4
//! models SM100a/103a/120/121a agree on EVERY probe.
//!
//! LAW (x4 agree): lattice 0x231 pure-reg (guard 4b@[15:12], Rd@16, Ra@24,
//! Rb@32, Rc@64): tok2 neg@72/abs@73/hsel[75:74]; tok3 hsel[61:60]
//! (+neg@63/abs@62 vendor-legal, era-rescued decode-side pre-graft;
//! field-closure deferred = 343-kand), h0nh1@86; tok4 neg@84/abs@83/
//! hsel[82:81]. Mod bits: b76=FMZ, b78=F32 (b77=SAT, b79=RELU(+P@87,inv@90),
//! b80=FTZ vendor-legal but NOT armed = 344-kand); BF16_V2(b85) leg: tok
//! signs + FMZ legal (prints 'HFMA2.BF16_V2.FMZ'), BF16 x F32 = '.INVALID3'
//! (285 doctrine: stays HOLE). b91 = unit KILL (rc=1, also with mods).
//! [55:40] band = text-INERT (all 8 singles + composes x4): decode-relaxed
//! in variable_mask, mint stays canonical = 316-doctrine; this is what makes
//! the lone corpus word t10.cubin@0x410 (0x405d080000342c28087231 = w321,
//! vendor 'HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8' x4) roundtrip with
//! a band-canonicalized word (delta = inert bits only).
//!
//! PRE-FIX (publish 8e12541, measure_pre320): (320-DEC) b83 words decode
//! HOLE both legs (vendor '|Rc|'); (320-ENC) authored 'HFMA2 ... |Rc|'
//! minted bit 74 via the era generic sign-emit FFMA-class Rc fallback
//! (abs@74/neg@75) because no field owned bit 83 -- silent wrong-code
//! (vendor reads b74 on this lattice as tok2 '.INVALID1'); (321) all
//! F32/FMZ/F32,FMZ/BF16_V2.FMZ forms decode+encode HOLE both legs.
//! FIX: pure table graft (patch320.py, replayable+idempotent, src ZERO):
//! +abs 1b@83 tok4 on mg ''+BF16_V2 (the generic emit's has_field_abs then
//! defers to the field and mints b83), variable_mask |= (0xffff<<40), and
//! clone-bake lanes F32 / FMZ / F32,FMZ / BF16_V2,FMZ. NO engine change.
//! DONORS (sm100a/sm103a) untouched (BUG-315 owner scope; their residuum =
//! measured decode-holes on the same lanes, documented in the report).
//! [ADDENDUM 2026-09-04, BUG-371: the abs@83 residuum closed on the thin
//! legs via the donor field (arb371/arb371b x4 AGREE); t320_1 flipped
//! with attribution. F32/FMZ lanes + band relax stay absent (pins kept).]
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const BAND: u128 = 0xffffu128 << 40;
// HOST lattice: 0x231 | PT | R1@16, R2@24, R3@32, R4@64
const HOST: u128 = 0x231 | (7 << 12) | (1 << 16) | (2 << 24) | (3 << 32) | (4 << 64);
const W321: u128 = 0x405d080000342c28087231;

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
fn t320_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_R"];
        for mgn in ["", "BF16_V2", "F32", "FMZ", "F32,FMZ", "BF16_V2,FMZ"] {
            let mg = e
                .mod_groups
                .get(mgn)
                .unwrap_or_else(|| panic!("{leg}: missing mg [{mgn}]"));
            // abs@83 tok4 fielded, exactly once, and only on grafted lanes
            let abs83 = mg
                .fields
                .iter()
                .filter(|f| {
                    f.extraction == cubit::table::Extraction::Abs
                        && f.shift == 83
                        && f.token_idx == 4
                })
                .count();
            assert_eq!(abs83, 1, "{leg}[{mgn}]: abs@83 tok4 field count");
            // inert band [55:40] decode-relaxed
            assert_eq!(
                mg.variable_mask & BAND,
                BAND,
                "{leg}[{mgn}]: band not relaxed"
            );
            // no field covers the inert band (mint stays canonical)
            for f in &mg.fields {
                let fm = ((1u128 << f.bits) - 1) << f.shift;
                assert_eq!(fm & BAND, 0, "{leg}[{mgn}]: field covers band");
            }
        }
        // lane bakes
        let ab = |m: &str| e.mod_groups[m].and_base;
        let base = ab("");
        assert_eq!(base & 0xfff, 0x231, "{leg}: '' kratka drift");
        assert_eq!(ab("F32") ^ base, 1 << 78, "{leg}: F32 lane bake drift");
        assert_eq!(ab("FMZ") ^ base, 1 << 76, "{leg}: FMZ lane bake drift");
        assert_eq!(
            ab("F32,FMZ") ^ base,
            (1 << 76) | (1 << 78),
            "{leg}: F32,FMZ bake drift"
        );
        assert_eq!(
            ab("BF16_V2,FMZ") ^ ab("BF16_V2"),
            1 << 76,
            "{leg}: BF16_V2,FMZ bake drift"
        );
        assert_eq!(
            ab("BF16_V2") & (1 << 85),
            1 << 85,
            "{leg}: BF16 carrier drift"
        );
        // no F32 lane on the BF16 leg (vendor INVALID3, 285 doctrine)
        assert!(
            !e.mod_groups.contains_key("BF16_V2,F32"),
            "{leg}: INVALID3 lane armed!"
        );
        assert!(
            !e.mod_groups.contains_key("BF16_V2,F32,FMZ"),
            "{leg}: INVALID3 lane armed!"
        );
    }
    // donors shape: abs@83 field present since BUG-371 (canonical 6b7a120,
    // 2026-09-04): the bug320-deferred thin-leg residuum closed via the
    // donor field after arb371/arb371b proved b83 = tok4 abs x4 models on
    // the thin lattice too (and measured the generic b74 mint here as the
    // silent 'R2.INVALID1' cross-read class). The OTHER residua of this
    // pin stay: no F32/FMZ lanes, no band relax on thin legs.
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_R"];
        for (mgn, mg) in &e.mod_groups {
            assert!(
                mg.fields
                    .iter()
                    .any(|f| f.shift == 83 && f.extraction == cubit::table::Extraction::Abs),
                "{leg}[{mgn}]: abs@83 donor field missing (BUG-371 closure expected)"
            );
        }
        for lane in ["F32", "FMZ", "F32,FMZ", "BF16_V2,FMZ"] {
            assert!(
                !e.mod_groups.contains_key(lane),
                "{leg}: donor lane {lane} armed!"
            );
        }
    }
}

#[test]
fn t320_2_decode_law_vendor_equal() {
    // (word-extra-bits, expected vendor text); vendor law from arb320 a/b/c + arb287 H
    let cases: &[(u128, &str)] = &[
        (1 << 83, "HFMA2 R1, R2, R3, |R4|"),
        ((1 << 83) | (1 << 84), "HFMA2 R1, R2, R3, -|R4|"),
        ((1 << 83) | (2 << 81), "HFMA2 R1, R2, R3, |R4|.H0_H0"),
        (1 << 78, "HFMA2.F32 R1, R2, R3, R4"),
        (1 << 76, "HFMA2.FMZ R1, R2, R3, R4"),
        ((1 << 76) | (1 << 78), "HFMA2.F32.FMZ R1, R2, R3, R4"),
        ((1 << 85) | (1 << 83), "HFMA2.BF16_V2 R1, R2, R3, |R4|"),
        ((1 << 85) | (1 << 76), "HFMA2.BF16_V2.FMZ R1, R2, R3, R4"),
        (0x34 << 40, "HFMA2 R1, R2, R3, R4"), // inert band on plain
        (
            (1 << 76) | (1 << 78) | (0xff << 40),
            "HFMA2.F32.FMZ R1, R2, R3, R4",
        ),
        (
            (1 << 76) | (1 << 78) | (1 << 86) | (1 << 72),
            "HFMA2.F32.FMZ R1, -R2, R3.H0_NH1, R4",
        ),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (extra, want) in cases {
            let got =
                dec(&t, HOST | extra).unwrap_or_else(|| panic!("{leg}: HOLE on extra={extra:#x}"));
            assert_eq!(&got, want, "{leg}: decode law drift on extra={extra:#x}");
        }
        // the lone corpus word verbatim and band-canonicalized
        for w in [W321, W321 & !BAND] {
            let got = dec(&t, w).expect("w321 HOLE");
            assert_eq!(
                got, "HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8",
                "{leg}: w321 drift"
            );
        }
    }
}

#[test]
fn t320_3_encode_word_exact_and_ghost_eliminated() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // ghost-mint eliminated: authored |R4| mints b83 and MUST NOT mint b74
        let w = enc(&t, "HFMA2 R1, R2, R3, |R4|").unwrap();
        assert_eq!(w >> 83 & 1, 1, "{leg}: abs@83 not minted");
        assert_eq!((w ^ HOST) >> 74 & 1, 0, "{leg}: b74 ghost still minted!");
        assert_eq!(&dec(&t, w).unwrap(), "HFMA2 R1, R2, R3, |R4|");
        // neg+abs compose field-carried
        let w = enc(&t, "HFMA2 R1, R2, R3, -|R4|").unwrap();
        assert_eq!(
            (w ^ HOST) & M96,
            ((1u128 << 83) | (1u128 << 84)),
            "{leg}: -|R4| word drift"
        );
        // authored w321 text mints the band-canonical word, low96 exact
        let w = enc(&t, "HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8").unwrap();
        assert_eq!(
            w & M96,
            (W321 & !BAND) & M96,
            "{leg}: w321-authored mint drift"
        );
        assert_eq!(
            &dec(&t, w).unwrap(),
            "HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8"
        );
        // every armed lane text-roundtrips
        for txt in [
            "HFMA2.F32 R1, R2, R3, R4",
            "HFMA2.FMZ R1, R2, R3, R4",
            "HFMA2.F32.FMZ R1, R2, R3, R4",
            "HFMA2.BF16_V2.FMZ R1, R2, R3, R4",
            "HFMA2.BF16_V2 R1, R2, R3, |R4|",
            "HFMA2 R1, -|R2|.H1_H1, R3.H0_NH1, R4",
        ] {
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("{leg}: encode hole: {txt}: {e}"));
            assert_eq!(
                &dec(&t, w).unwrap_or_else(|| panic!("{leg}: decode hole post-encode: {txt}")),
                txt,
                "{leg}: text roundtrip drift: {txt}"
            );
        }
    }
}

#[test]
fn t320_4_fail_closed_doctrine_residuum() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // INVALID3 lane: vendor prints HFMA2.INVALID3; engine stays HOLE (285 doctrine) + encode loud-fails
        assert!(
            dec(&t, HOST | (1 << 85) | (1 << 78)).is_none(),
            "{leg}: INVALID3 lane decoded!"
        );
        assert!(
            enc(&t, "HFMA2.BF16_V2.F32 R1, R2, R3, R4").is_err(),
            "{leg}: INVALID3 lane encoded!"
        );
        // FLIP (BUG-343/344, F2-iter182, canonical a013f88): the formerly
        // un-armed vendor-legal lanes (this kand) are now armed -- decode +
        // word-exact mint through the closure, full battery in t343_2/3:
        assert_eq!(
            dec(&t, HOST | (1 << 77)).as_deref(),
            Some("HFMA2.SAT R1, R2, R3, R4"),
            "{leg}: 343/344 SAT lane decode drift"
        );
        assert_eq!(
            enc(&t, "HFMA2.SAT R1, R2, R3, R4").unwrap() & M96,
            (HOST | (1 << 77)) & M96,
            "{leg}: 343/344 SAT lane mint drift"
        );
        assert_eq!(
            enc(&t, "HFMA2.FTZ R1, R2, R3, R4").unwrap() & M96,
            (HOST | (1 << 80)) & M96,
            "{leg}: 343/344 FTZ lane mint drift"
        );
        assert_eq!(
            enc(&t, "HFMA2.OOB R1, R2, R3, R4").unwrap() & M96,
            (HOST | (1 << 76) | (1 << 80)) & M96,
            "{leg}: 343/344 OOB lane mint drift"
        );
        // b91 unit-KILL stays HOLE (also with mods)
        assert!(
            dec(&t, HOST | (1 << 91)).is_none(),
            "{leg}: b91 KILL decoded!"
        );
        assert!(
            dec(&t, HOST | (1 << 91) | (1 << 78)).is_none(),
            "{leg}: b91 KILL+F32 decoded!"
        );
    }
}

#[test]
fn t320_5_anchors_287_289_293_intact() {
    // era-armed 0x231 pure-reg behaviors the graft must not disturb
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // plain + hsel/neg/h0nh1/reuse anchors unchanged
        let anchors: &[(u128, &str)] = &[
            (0, "HFMA2 R1, R2, R3, R4"),
            (3 << 74, "HFMA2 R1, R2.H1_H1, R3, R4"),
            (1 << 84, "HFMA2 R1, R2, R3, -R4"),
            (1 << 86, "HFMA2 R1, R2, R3.H0_NH1, R4"),
            ((1 << 72) | (3 << 74), "HFMA2 R1, -R2.H1_H1, R3, R4"),
            (1 << 85, "HFMA2.BF16_V2 R1, R2, R3, R4"),
        ];
        for (extra, want) in anchors {
            let got = dec(&t, HOST | extra)
                .unwrap_or_else(|| panic!("{leg}: anchor HOLE extra={extra:#x}"));
            assert_eq!(&got, want, "{leg}: anchor drift extra={extra:#x}");
        }
        // 289-family neighbor untouched: R_R_UR_R route stability (census t289)
        assert!(
            t.entries.contains_key("HFMA2_R_R_UR_R"),
            "{leg}: R_R_UR_R missing"
        );
    }
}
