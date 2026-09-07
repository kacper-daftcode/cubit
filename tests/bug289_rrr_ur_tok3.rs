//! BUG-289 (F2-iter161, loop5/blind front2, 2026-08-31; canonical 57d1448):
//! HFMA2_R_R_R_UR '' (lattice 0xe31) tok2/tok3 sign/opmod window closure,
//! sm120+sm121a (TABLE-only graft patch289.py; engine src ZERO changes).
//!
//! Pre-fix (pub pyo3-96ba77b + canonical c359172; measure_pre289.py, 93
//! arb289 probes x2 legs: match 53 / hole 24 / drift 16):
//!   DECODE silent wrong-text: every word with b86=1 printed WITHOUT
//!     '.H0_NH1' (13 probes; bit covered by variable_mask but no field);
//!     b86+hsel[82:81]!=0 words printed the bogus plain suffix ('R3.F32'
//!     where vendor prints '.INVALID5' x3) -- the 271 INVALID decode gate
//!     only fires on rows that carry the h0nh1/opmod field;
//!   DECODE hole: every abs@83 word (13 probes: '|R3|'/'-|R3|' and hsel
//!     composes) -- b83 sat outside the variable_mask;
//!   ENCODE silent wrong-code (nvdisasm-verified x4): authored
//!     'HFMA2 R1, R2, -|R3|, UR4' minted a word with abs@62 (NOT @83) --
//!     vendor reads it back as 'HFMA2 R1, R2, -R3, |UR4|' (abs misrouted
//!     onto the UR token); 'R3.H0_NH1' texts loud-failed (272 gate).
//! Law arb289 (93 probes; work/bug289/arb289_verdicts.json; nvdisasm
//! 13.3.73 raw -b; x4 models SM100a/103a/120/121a agree on EVERY probe):
//!   guard 4b@[15:12] standard ('@P0' kept for 0; 7 elided); dst 8b@16
//!   (255=RZ); tok2 (R@24): neg@72, abs@73, hsel [75:74] 0='' 1=
//!   '.INVALID1' (printed; 306 R-domain law) 2='.H0_H0' 3='.H1_H1';
//!   tok3 (R@64): abs@83 composes, neg@84, hsel [82:81] 1='.F32'
//!   2='.H0_H0' 3='.H1_H1'; b86 = tok3 '.H0_NH1' single-bit composing
//!   signs suffix-OUTSIDE-pipes ('-|R3|.H0_NH1'); b86+hsel3!=0 => vendor
//!   '.INVALID5/6/7' printed = engine hole (271 doctrine); tok4 (UR@32):
//!   hsel [61:60] 1='.INVALID1' 2/3='.H0_H0'/.H1_H1', abs@62, neg@63
//!   compose; b86 is tok3-local (cross-sets D/E); reuse 122/123/124
//!   text-neutral x b86 (F-set x8). Suffix-window carriers b76/b77/b78/
//!   b79/b80/b85 stay hole (engine loud-fail on encode) = registered
//!   324-kand structural class (R_R_R_R/R_R_UR_R ship '' mg only too).
//! Graft: +2 fields {abs 1b@83 tok3, opmod:H0_NH1 1b@86 tok3, _src
//! bug289-2026-08-31} + vm |= 1<<83 (b86 was already covered). Donors
//! sm100a/sm103a byte-untouched (asserts; they never shipped the row).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction as X, IsaTable};

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse {text}: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
/// lattice 0xe31 host: guard PT(7)@12, dst R1@16, tok2 R2@24, tok3 R3@64,
/// tok4 UR4@32 -> vendor 'HFMA2 R1, R2, R3, UR4'
fn host() -> u128 {
    (0x80000000000000000000e31u128 | (7 << 12) | (1 << 16) | (2 << 24) | (3 << 64) | (4 << 32))
        & ((1u128 << 96) - 1)
}

#[test]
fn t289_1_structure_census_tags() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let g = &t.entries["HFMA2_R_R_R_UR"].mod_groups[""];
        // exactly the two grafted fields on tok3, both tagged
        let tok3_new: Vec<_> = g
            .fields
            .iter()
            .filter(|f| f.token_idx == 3 && (f.shift == 83 || f.shift == 86))
            .collect();
        assert_eq!(tok3_new.len(), 2, "{arch}: tok3 window census drift");
        assert!(
            tok3_new
                .iter()
                .any(|f| f.shift == 83 && f.bits == 1 && f.extraction == X::Abs),
            "{arch}: abs 1b@83 tok3 missing"
        );
        // FLIP (BUG-293, F2-iter163, canonical 46ff277): the 289-grafted
        // field's extraction was swapped opmod:H0_NH1 -> h0nh1 (same
        // bit/token/window; arms the encode-side 271 INVALID-combo gate;
        // mint/decode byte-stable -- locked by t293_5). Census stands.
        assert!(
            tok3_new
                .iter()
                .any(|f| f.shift == 86 && f.bits == 1 && f.extraction == X::H0NH1),
            "{arch}: h0nh1 1b@86 tok3 missing (BUG-293 swap)"
        );
        assert!(
            g.variable_mask & (1u128 << 83) == (1u128 << 83),
            "{arch}: vm missing bit83"
        );
        assert!(
            g.variable_mask & (1u128 << 86) == (1u128 << 86),
            "{arch}: vm lost bit86"
        );
        // era residuum never returns: no Neg/Abs-typed field @86 anywhere
        // (t270_1 sister pin locks the same on this row)
        assert!(
            !g.fields
                .iter()
                .any(|f| f.shift == 86 && matches!(f.extraction, X::Neg | X::Abs | X::NegAbs)),
            "{arch}: era neg/abs@86 resurrected"
        );
        // BUG-324 flip (canonical a0dbda7): the suffix-window carrier
        // closure armed the full donor-II_II window on this key (36
        // mod-groups + 12 RELU _P dotted keys per parent, measured
        // arb324 x4); the scope sentinel is retired by its own ticket.
        assert_eq!(
            t.entries["HFMA2_R_R_R_UR"].mod_groups.len(),
            36,
            "{arch}: RRUR 324-lane count drift"
        );
        // key census unchanged by the graft
        // BUG-313 flip: sm121a 15420 -> 15419 (phantom era key
        // P2R_R_R_R_II deleted, canonical 720d240; mint-neutral /
        // dup-render 'PR' closure, arb313 D x4 models).
        // BUG-316 flip: sm120 1465 -> 1469 and sm121a 15419 -> 15423
        // (+4 keys per leg: MOVM name-space sibling closure on the 0x23a
        // lattice; the U4TO8.M832 phantom lives on under its rewritten key so
        // it does not move the counter; canonical 0821445).
        // BUG-324 flip: +24 RELU _P trailing dst-pred dotted keys per leg
        // (12 per parent x HFMA2_R_R_R_UR / HFMA2_R_R_UR_R; canonical
        // a0dbda7) = 1493 / 15447.
        // BUG-339/340 flip: sm120 1493 -> 1500 (+7 F2I era keys) and
        // sm121a 15447 -> 15449 (+2: F2I.S64.TRUNC_R_R, F2I.U64.F64.TRUNC_R_R;
        // canonical 02c147d).
        // BUG-341 flip (canonical 774c130): F2I small-int R_R lattice
        // (op 0x0305) normalisation+closure: sm120 1500 -> 1542 (+42: 40 closure + 2 era mirrors 0x30/0xb1),
        // sm121a 15449 -> 15488 (+39 era-style vendor-named rows JSON-side = +37 loaded; the 2 _errata_ annotations are annotation-reserved).
        // BUG-343/344 flip (canonical a013f88): HFMA2 pure-reg krata 0x231
        // mod-window closure: +12 RELU _P trailing dst-pred dotted keys per
        // dense leg (12 per parent x 1 parent HFMA2_R_R_R_R; the 30 mod-lane
        // mg rows live inside mod_groups and do not move the counter) =
        // 1554 / 15500.
        // BUG-348 flip (canonical 4983b7e): sm121a HMUL2_R_R_R era dead-row
        // rebuild -- the two deleted era squatters (HMUL2.BF16_V2_R_R_R,
        // HMUL2_R_R_R_R) move the key census 15500 -> 15498 (the 12 grafted
        // mg rows live inside mod_groups and do not move the counter).
        // BUG-363 flip (canonical fbcef1c): F2I R_R FTZ+BF16 lattice
        // closure adds keyed era rows: +95 on sm120/sm121a
        // (F2I.FTZ.U32.TRUNC.NTZ_R_R normalized in place) and +96 on
        // sm100a/sm103a; legacy mg deletions don't move the key census.
        // BUG-375 flip (canonical 883323c): sm121a 15593 -> 15604 (+11
        // trailing-_P dotted keys from the LDGSTS desc family port; the
        // 373 guard widen rewrites fields in place and does not move the
        // counter).
        // BUG-376 flip (canonical 6742fdf): sm121a 15604 -> 15630 (+26
        // LDGSTS desc dotted keys: 13 np + 13 _P LTC-lattice completion
        // cells LTC64B/LTC256B x6 bases + BYPASS.LTC128B.128.ZFILL twins;
        // era-leg grafts live inside mod_groups and do not move the
        // counter).
        // BUG-380 flip (canonical a53eb20): sm120 1649 -> 1671, sm121a
        // 15630 -> 15652 (+22 keyed F64-src lattice rows per leg; era-leg
        // grafts live inside F2I_R_R mod_groups and do not move the
        // counter).
        // BUG-381 flip (canonical 3cb31e4): sm100a/sm103a 15516 -> 15540
        // (+24 RELU _P dotted keys per era leg on HFMA2_R_R_R_R /
        // HFMA2_R_R_UR_R; the 68 new mgs per leg live inside mod_groups
        // and do not move the counter; dense legs untouched).
        // BUG-386 flip (canonical dbe5e91): sm121a 15652 -> 15664 (+12
        // LDGSTS desc base-gap dotted keys: BYPASS/ZFILL x s32/s64 x np/_P;
        // era-leg grafts live inside mod_groups and do not move the
        // counter).
        // BUG-384 flip (canonical 9713fd6): sm120 1671 -> 1669, sm121a
        // 15664 -> 15662 (-2 harvest-junk dense era keys per leg:
        // HFMA2.BF16_V2_R_R_R_R + HFMA2_R_R_R_R_R deleted; sparse legs
        // byte-untouched, they never shipped the rows).
        // BUG-390 flip (canonical a10350c): sm120 1669 -> 1701, sm121a
        // 15662 -> 15694 (+32 keyed F2I F64-src b76=0 narrow-dst lattice
        // rows per leg; era-leg grafts live inside F2I_R_R mod_groups
        // and do not move the counter).
        // BUG-403 flip (canonical 2285a05): sm120 1701 -> 1705, sm121a
        // 15694 -> 15698 (+4 keyed F2I F64-src WIDE b76=1 TRUNC.NTZ
        // donor-closure rows per leg; era-leg grafts live inside
        // F2I_R_R mod_groups and do not move the counter).
        // BUG-400 flip (canonical 19363f6): sm120 1705 -> 1706, sm121a
        // 15698 -> 15700 (+1 LDG_R_dARI_P on sm120; +2 LD_R_ARI_P +
        // LD_R_dARI_P on sm121a -- pred/LTC window [64:72) graft; the
        // LTC mgs live inside mod_groups and do not move the counter;
        // sm100a/sm103a not pinned here).
        let want = if arch == "sm120" {
            1706
        } else if arch == "sm121a" {
            15700
        } else {
            15540
        };
        assert_eq!(t.entries.len(), want, "{arch}: key census drift");
    }
    // provenance tag census on the raw vendored JSON: 2 per leg, donors tagless
    let count_tags = |arch: &str, tag: &str| -> usize {
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{arch}.json")).unwrap())
                .unwrap();
        let mut n = 0usize;
        for (_k, e) in j["instructions"].as_object().unwrap() {
            let Some(mgz) = e.get("mod_groups").and_then(|x| x.as_object()) else {
                continue;
            };
            for (_mg, g) in mgz {
                for f in g["fields"].as_array().unwrap() {
                    if f.get("_src").and_then(|x| x.as_str()) == Some(tag) {
                        n += 1;
                    }
                }
            }
        }
        n
    };
    // FLIP (BUG-293): the h0nh1@86 field was re-tagged bug293-2026-08-31 by
    // the extraction swap; only abs@83 still carries the 289 tag.
    assert_eq!(count_tags("sm120", "bug289-2026-08-31"), 1);
    assert_eq!(count_tags("sm121a", "bug289-2026-08-31"), 1);
    assert_eq!(count_tags("sm100a", "bug289-2026-08-31"), 0);
    assert_eq!(count_tags("sm103a", "bug289-2026-08-31"), 0);
    // donors never shipped the row and must not gain it
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        assert!(
            !t.entries.contains_key("HFMA2_R_R_R_UR"),
            "{arch}: donor gained the RRUR row"
        );
    }
}

#[test]
fn t289_2_decode_law_vendor_exact() {
    let h = host();
    // (bits-or, expected text) -- every expectation = arb289 x4-agreed vendor text
    let cases: &[(u128, &str)] = &[
        // tok3 b86 single-bit + sign composes (suffix OUTSIDE pipes, x4)
        (1u128 << 86, "HFMA2 R1, R2, R3.H0_NH1, UR4"),
        ((1 << 86) | (1 << 83), "HFMA2 R1, R2, |R3|.H0_NH1, UR4"),
        ((1 << 86) | (1 << 84), "HFMA2 R1, R2, -R3.H0_NH1, UR4"),
        (
            (1 << 86) | (1 << 83) | (1 << 84),
            "HFMA2 R1, R2, -|R3|.H0_NH1, UR4",
        ),
        // abs@83 composes (pre-fix holes)
        (1u128 << 83, "HFMA2 R1, R2, |R3|, UR4"),
        ((1 << 83) | (1 << 84), "HFMA2 R1, R2, -|R3|, UR4"),
        ((1 << 83) | (2 << 81), "HFMA2 R1, R2, |R3|.H0_H0, UR4"),
        (
            (1 << 83) | (1 << 81) | (1 << 84),
            "HFMA2 R1, R2, -|R3|.F32, UR4",
        ),
        // b86 cross-token composes (tok2 hsel, tok4 UR window) -- arb D/E sets
        ((1 << 86) | (2 << 74), "HFMA2 R1, R2.H0_H0, R3.H0_NH1, UR4"),
        ((1 << 86) | (3 << 60), "HFMA2 R1, R2, R3.H0_NH1, UR4.H1_H1"),
        (
            (1 << 86) | (1 << 62) | (1 << 63),
            "HFMA2 R1, R2, R3.H0_NH1, -|UR4|",
        ),
        // reuse x b86: vendor text-neutral (arb289 F-set x8). BUG-326 flip:
        // the pre-326 ENGINE printed '.reuse' markers field-consistently on
        // every armed row; the vendor print of R-domain reuse is yield-gated
        // (arb325 law: this synthetic host is yield=0 => plain, same as the
        // arb289 "text-neutral" verdict). UR4.reuse stays: the UR print lane
        // is table-taught authored spelling (not yield-gated; 326 scope).
        (
            (1 << 122) | (1 << 123) | (1 << 124) | (1 << 86),
            "HFMA2 R1, R2, R3.H0_NH1, UR4.reuse",
        ),
        // dst / RZ variants x b86 (G-set)
        ((1 << 86) | (0xff << 16) - (1 << 16), "unreachable"),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (bits, want) in cases {
            if *want == "unreachable" {
                continue;
            }
            let got = dec(&t, h | bits);
            assert_eq!(
                got.as_deref(),
                Some(*want),
                "{arch} drill bits {:x}: got {:?}",
                bits,
                got
            );
        }
        // dst=RZ + b86; tok3 RZ + b86 (G-set, separate hosts)
        let grz = (h & !(0xffu128 << 16)) | (255u128 << 16) | (1 << 86);
        assert_eq!(
            dec(&t, grz).as_deref(),
            Some("HFMA2 RZ, R2, R3.H0_NH1, UR4"),
            "{arch} dst-RZ+b86"
        );
        let t3rz = (h & !(0xffu128 << 64)) | (255u128 << 64) | (1 << 86);
        assert_eq!(
            dec(&t, t3rz).as_deref(),
            Some("HFMA2 R1, R2, RZ.H0_NH1, UR4"),
            "{arch} tok3-RZ+b86"
        );
        let t3rz_an = (h & !(0xffu128 << 64)) | (255u128 << 64) | (1 << 83) | (1 << 84);
        assert_eq!(
            dec(&t, t3rz_an).as_deref(),
            Some("HFMA2 R1, R2, -|RZ|, UR4"),
            "{arch} tok3-RZ abs+neg (pre-fix hole)"
        );
    }
}

#[test]
fn t289_3_doctrine_holes() {
    let h = host();
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // 271 INVALID5/6/7 carriers: vendor prints the marker, engine hole
        for v in [1u128, 2, 3] {
            let w = h | (1 << 86) | (v << 81);
            assert!(
                dec(&t, w).is_none(),
                "{arch}: b86+hsel3={v} must hole (vendor INVALID{}), got {:?}",
                v + 4,
                dec(&t, w)
            );
        }
        // BUG-324 flip: the six singles are now ARMED (arb324 A-set x4);
        // the doctrine holes that stay closed: SAT x RELU (rc=1 kill x4)
        // and F32 x BF16 (INVALID3, 285 doctrine).
        for bits in [(1u128 << 77) | (1u128 << 79), (1u128 << 78) | (1u128 << 85)] {
            assert!(
                dec(&t, h | bits).is_none(),
                "{arch}: kill-class bits {bits:#x} must hole (324 doctrine)"
            );
        }
    }
}

#[test]
fn t289_4_mint_law_roundtrip() {
    let h = host();
    // authored text -> exact word -> text (words are the arb289 host forms)
    let cases: &[(&str, u128)] = &[
        ("HFMA2 R1, R2, R3.H0_NH1, UR4", h | (1 << 86)),
        (
            "HFMA2 R1, R2, -|R3|.H0_NH1, UR4",
            h | (1 << 86) | (1 << 83) | (1 << 84),
        ),
        ("HFMA2 R1, R2, |R3|, UR4", h | (1 << 83)),
        ("HFMA2 R1, R2, -|R3|, UR4", h | (1 << 83) | (1 << 84)),
        (
            "HFMA2 R1, R2.H0_H0, R3.H0_NH1, UR4",
            h | (1 << 86) | (2 << 74),
        ),
        (
            "HFMA2 R1, R2, R3.H0_NH1, -|UR4|",
            h | (1 << 86) | (1 << 62) | (1 << 63),
        ),
        ("HFMA2 R1, |R2|.H1_H1, R3, UR4", h | (1 << 73) | (3 << 74)),
        (
            "@P1 HFMA2 R1, R2, -|R3|.H0_NH1, UR4",
            (h & !(0xfu128 << 12)) | (1 << 12) | (1 << 86) | (1 << 83) | (1 << 84),
        ),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (text, want) in cases {
            let w = enc_res(&t, text).unwrap_or_else(|e| panic!("{arch} encode {text}: {e}"));
            assert_eq!(
                w & ((1u128 << 96) - 1),
                *want,
                "{arch} mint drift for {text}"
            );
            let back = dec(&t, w).unwrap_or_else(|| panic!("{arch} roundtrip hole for {text}"));
            assert_eq!(&back, text, "{arch} roundtrip text drift for {text}");
        }
        // BUG-289 wrong-code regression sentinel: '|R3|' must NOT set abs@62
        // (pre-fix mint moved the abs onto the UR token: vendor read-back
        // 'HFMA2 R1, R2, -R3, |UR4|').
        let w = enc_res(&t, "HFMA2 R1, R2, |R3|, UR4").unwrap();
        assert_eq!(
            w & (1u128 << 62),
            0,
            "{arch}: abs misroute to tok4 resurrected"
        );
        assert!(w & (1u128 << 83) != 0, "{arch}: abs@83 not minted");
    }
}

#[test]
fn t289_5_fail_closed_and_anchors() {
    let h = host();
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // INVALIDn authored suffixes = loud fail (272 doctrine)
        for bad in [
            "HFMA2 R1, R2, R3.INVALID5, UR4",
            "HFMA2 R1, R2, R3.INVALID6, UR4",
            "HFMA2 R1, R2.H0_H1, R3, UR4",
        ] {
            assert!(
                enc_res(&t, bad).is_err(),
                "{arch}: authored INVALID suffix {bad} must fail-closed"
            );
        }
        // BUG-324 flip: the pre-324 fail-closed trio is now armed --
        // mint each with word-level assertions (arb324 + int roundtrip).
        for good in [
            "HFMA2.FMZ R1, R2, R3, UR4",
            "HFMA2.BF16_V2 R1, R2, R3.H0_NH1, UR4",
            "HFMA2.RELU R1, R2, R3, UR4, P0",
        ] {
            let w = enc_res(&t, good)
                .unwrap_or_else(|e| panic!("{arch}: 324-armed {good} mints now: {e}"));
            let back = dec(&t, w).unwrap_or_else(|| panic!("{arch}: roundtrip hole {good}"));
            assert_eq!(&back, good, "{arch}: 324-armed roundtrip {good}");
        }
        // ...while the KILL/INVALID classes stay loud:
        for bad in [
            "HFMA2.SAT.RELU R1, R2, R3, UR4",
            "HFMA2.BF16_V2.F32 R1, R2, R3, UR4",
        ] {
            assert!(
                enc_res(&t, bad).is_err(),
                "{arch}: kill-class {bad} must fail-closed (324 doctrine)"
            );
        }
        // anchors 288/287/283 (route-shift tripwires): imm-family tok2 law
        // and the R4-era release stay byte-exact
        let imm = 0x1ff00000000ff007431u128 | (7 << 12) | (1 << 16);
        let w = imm | (1 << 73) | (2 << 74); // '-|RZ|.H0_H0' host (BUG-288)
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("HFMA2 R1, -|RZ|.H0_H0, RZ, 0, 0"),
            "{arch}: 288 imm-family anchor drift"
        );
        let _ = h;
    }
    // 287 anchor: sm121a R4-era row unchanged (decode a plain R4-era word)
    let t = tab("sm121a");
    let g = &t.entries["HFMA2_R_R_R_R"].mod_groups[""];
    assert!(
        g.fields.iter().any(|f| f.shift == 86 && f.token_idx == 3),
        "sm121a R4-era opmod field lost"
    );
}
