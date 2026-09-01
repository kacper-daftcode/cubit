//! BUG-287 (F2-iter159, loop5/blind front2, 2026-08-31; canonical 0aed02f):
//! HFMA2_R_R_R_R '' era-row closure on sm121a. The 2aE/243 wholesale repair
//! armed the all-reg HFMA2 host on donors sm100a/sm103a + sm120, and 271/
//! 279/285/286 armed the sm121a FI/II imm hosts -- but the pure-reg sm121a
//! row survived in the pre-2aE era shape: guard 2b@13 + b12 bake, hsel
//! 0b10 bakes frozen at b61/b75/b82, NO hsel/neg/opmod fields at all.
//! Consequences measured pre-fix on pub pyo3-f0f9d53 (scan287.py, the
//! 2,406-cubin battery; measure_pre287.py):
//!   DECODE: 41,301/53,653 (77%) of the corpus 0x231-lattice words engine-
//!     HOLE on sm121a (any hsel != the era bake combo, every inverted guard);
//!   DECODE silent wrong-text on the 8,921 era-claimed words: guard ghost
//!     (era 2b@13 + b12=1 reads the middle of the real 4b guard nibble:
//!     corpus PT=0b0111 -> '@P3', vendor '@P1' -> '@P0') + operand hsel
//!     elision ('.H0_H0' dropped) -- 3,064 drift words / 3,048 ghost-guard
//!     words in a 400-cubin slice;
//!   ENCODE silent text-drift mint: '@Pn HFMA2 R1, R2, R3, R4' (plain)
//!     minted the era-BAKE word (hsel=0b10 x3) -- readback on healthy legs
//!     prints '.H0_H0' suffixes != authored text (hs=0 is the natural H1_H0
//!     form per the 2aE discovery; semantics differ on silicon);
//!   ENCODE hole: every hsel/opmod/neg/inverted-guard authored text
//!     loud-failed (fail-closed; kept fail-closed where doctrine says hole).
//! Law arb287 (41 labels, 152 probes, work/bug287/arb287_verdicts.json;
//! nvdisasm 13.3.73 raw -b; x4 models SM100a/103a/120/121a agree on EVERY
//! probe): hsel tok2 [75:74] / tok4 [82:81]: 0='', 1=vendor '.INVALID1'
//! (printed), 2/3='.H0_H0'/'.H1_H1'; hsel tok3 [61:60]: 0='', 1='.F32',
//! 2/3='.H0_H0'/'.H1_H1'; opmod:H0_NH1@86 tok3 composes hs3=0; hs3!=0 +
//! b86=1 => vendor '.INVALID6' (printed; engine hole per the 271
//! fail-closed doctrine); neg@84 tok4 '-Rc' composes; guard 4b@[15:12]:
//! 0..6=@Pn, 7=PT elided, 8..14=@!Pn, 15=@!PT; dst/srcs 8b@16/24/32/64
//! (255=RZ); abs@83 => vendor '|Rc|' = engine hole BOTH legs pre/post
//! (registered NOT fixed here -- both-leg class).
//! Graft patch287.py (replayable+idempotent, re-run skip-idem x1): the
//! sm121a '' row gets and_base<96 / variable_mask<96 / fields := the sm120
//! counterpart verbatim (era b12 + b61/b75/b82 bakes dropped; 13 fields
//! _src=bug287-2026-08-31; mg['_bug287'] tag). Bits >=96: era ctl
//! convention kept (decoder strips; reuse b122-124 vm kept). sm120 +
//! donors sm100a/sm103a byte-untouched (census pins below). Engine src:
//! ZERO changes (pure table graft; verified by verify287_post on the
//! published binary + patched tables: LEGDELTA 0/38, vendor-exact 33,
//! encode cross-leg parity 10/10).
//! Registered pre-existing, NOT this bug: abs@83 '|Rc|' both-leg hole;
//! the lone corpus word 0x..28087231 (t10.cubin) with bits in the [55:40]
//! band staying a both-leg hole.
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
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

#[test]
fn t287_1_structure_transplant_census() {
    // sm121a '' row == sm120 counterpart on the <96 bits + field list/order;
    // >=96 ctl = era convention kept (ab>=96 == 0, reuse vm b122-124).
    let a = tab("sm121a");
    let b = tab("sm120");
    let g = &a.entries["HFMA2_R_R_R_R"].mod_groups[""];
    let r = &b.entries["HFMA2_R_R_R_R"].mod_groups[""];
    assert_eq!(g.and_base & M96, r.and_base & M96, "ab <96 != sm120");
    assert_eq!(
        g.variable_mask & M96,
        r.variable_mask & M96,
        "vm <96 != sm120"
    );
    assert_eq!(g.and_base & !M96, 0, "ab >=96 era convention moved");
    assert_eq!(g.variable_mask >> 96, 0x1c000000, "vm >=96 era ctl moved");
    let has = |ex: Extraction, sh: u32, ti: i32, bits: u32| {
        g.fields
            .iter()
            .any(|f| f.extraction == ex && f.shift == sh && f.token_idx == ti && f.bits == bits)
    };
    assert!(has(Extraction::Guard, 12, 0, 4), "guard 4b@12");
    // FLIP (BUG-320/321, F2-iter171, canonical 1e2b7ba): +abs 1b@83 tok4
    // (era-287 residuum, registered 320-kand; arb320 a/b/c x4); the
    // [55:40] inert band moves care->vm on the same row, sm120 in mirror.
    // FLIP (BUG-327, F2-iter175, canonical 2761da4): +abs 1b@73 tok2 +
    // +abs 1b@62 tok3 (era-287 sign-window residuum, registered 327-kand;
    // arb327 72 probes x4; pure field-closure of lanes that were behavior-
    // ally exact via the generic sign rescue; corpus exposure 0/53,653).
    assert_eq!(
        g.fields.len(),
        16,
        "field count (BUG-320: +abs@83 tok4; BUG-327: +abs@73 tok2/+abs@62 tok3)"
    );
    assert!(has(Extraction::Abs, 73, 2, 1), "abs@73 tok2 (BUG-327)");
    assert!(has(Extraction::Abs, 62, 3, 1), "abs@62 tok3 (BUG-327)");
    assert!(has(Extraction::Reg, 16, 1, 8) && has(Extraction::Reg, 24, 2, 8));
    assert!(has(Extraction::Reg, 32, 3, 8) && has(Extraction::Reg, 64, 4, 8));
    assert!(has(Extraction::HalfSel, 74, 2, 2), "hsel@74 tok2");
    assert!(has(Extraction::HalfSel, 60, 3, 2), "hsel@60 tok3");
    assert!(has(Extraction::HalfSel, 81, 4, 2), "hsel@81 tok4");
    // FLIP (BUG-293, F2-iter163, canonical 46ff277): extraction swap
    // opmod:H0_NH1 -> h0nh1 on the '' row (same window; arms encode-side
    // 271 INVALID-combo gate; decode/print byte-stable -- t293_5 locks).
    assert!(
        has(Extraction::H0NH1, 86, 3, 1),
        "h0nh1@86 tok3 (BUG-293 swap)"
    );
    assert!(has(Extraction::Neg, 84, 4, 1), "neg@84 tok4");
    assert!(
        !g.fields
            .iter()
            .any(|f| f.extraction == Extraction::Guard && f.bits == 2 && f.shift == 13),
        "era guard 2b@13 survived"
    );
    for (sh, ti) in [(122u32, 2i32), (123, 3), (124, 4)] {
        assert!(
            g.fields.iter().any(|f| f.extraction == Extraction::Reuse
                && f.shift == sh
                && f.token_idx == ti
                && f.bits == 1),
            "reuse@{sh} tok{ti}"
        );
    }
    // provenance census: exactly 13 bug287 tags on sm121a, ZERO elsewhere.
    let count_tags = |arch: &str| -> usize {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{arch}.json")).unwrap())
                .unwrap();
        let mut n = 0usize;
        for (_k, e) in v["instructions"].as_object().unwrap() {
            if let Some(mgs) = e.get("mod_groups") {
                for (_m, mg) in mgs.as_object().unwrap() {
                    for f in mg["fields"].as_array().unwrap() {
                        if f.get("_src").and_then(|x| x.as_str()) == Some("bug287-2026-08-31") {
                            n += 1;
                        }
                    }
                }
            }
        }
        n
    };
    // FLIP (BUG-293, F2-iter163): the ''-row h0nh1@86 swap re-tagged one
    // field bug293-2026-08-31 (13 -> 12; see t293_1/t293_1b census).
    assert_eq!(count_tags("sm121a"), 12, "sm121a bug287 tag census");
    assert_eq!(count_tags("sm120"), 0, "sm120 byte-untouched");
    assert_eq!(count_tags("sm100a"), 0, "donor sm100a untouched");
    assert_eq!(count_tags("sm103a"), 0, "donor sm103a untouched");
    // _bug287 provenance tag present on the mg.
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    assert!(
        v["instructions"]["HFMA2_R_R_R_R"]["mod_groups"][""]
            .get("_bug287")
            .is_some(),
        "_bug287 tag missing"
    );
}

#[test]
fn t287_2_decode_law_vendor_exact_both_legs() {
    // arb287 law subset (host lattice 0x231, dst R1@16 / Ra R2@24 / Rb R3@32
    // / Rc R4@64, guard PT unless varied): vendor-exact on BOTH legs.
    let host: u128 = 0x231 | (7 << 12) | (1 << 16) | (2 << 24) | (3 << 32) | (4u128 << 64);
    let cases: &[(u128, &str)] = &[
        (host, "HFMA2 R1, R2, R3, R4"),
        (host | (2 << 74), "HFMA2 R1, R2.H0_H0, R3, R4"),
        (host | (3 << 74), "HFMA2 R1, R2.H1_H1, R3, R4"),
        (host | (1 << 74), "HFMA2 R1, R2.INVALID1, R3, R4"),
        (host | (1 << 60), "HFMA2 R1, R2, R3.F32, R4"),
        (host | (2 << 60), "HFMA2 R1, R2, R3.H0_H0, R4"),
        (host | (3 << 60), "HFMA2 R1, R2, R3.H1_H1, R4"),
        (host | (2 << 81), "HFMA2 R1, R2, R3, R4.H0_H0"),
        (host | (3 << 81), "HFMA2 R1, R2, R3, R4.H1_H1"),
        (host | (1 << 81), "HFMA2 R1, R2, R3, R4.INVALID1"),
        (host | (1 << 86), "HFMA2 R1, R2, R3.H0_NH1, R4"),
        (host | (1 << 86) | (1 << 84), "HFMA2 R1, R2, R3.H0_NH1, -R4"),
        (host | (1 << 84), "HFMA2 R1, R2, R3, -R4"),
        (host | (1 << 84) | (2 << 81), "HFMA2 R1, R2, R3, -R4.H0_H0"),
        (
            (host & !(0xf << 12)) | (0 << 12),
            "@P0 HFMA2 R1, R2, R3, R4",
        ),
        (
            (host & !(0xf << 12)) | (6 << 12),
            "@P6 HFMA2 R1, R2, R3, R4",
        ),
        (
            (host & !(0xf << 12)) | (8 << 12),
            "@!P0 HFMA2 R1, R2, R3, R4",
        ),
        (
            (host & !(0xf << 12)) | (15 << 12),
            "@!PT HFMA2 R1, R2, R3, R4",
        ),
        ((host & !(0xff << 16)) | (255 << 16), "HFMA2 RZ, R2, R3, R4"),
        (
            (host & !(0xffu128 << 64)) | (255u128 << 64),
            "HFMA2 R1, R2, R3, RZ",
        ),
        (
            (host & !(0xff << 16) & !(0xff << 24) & !(0xff << 32) & !(0xffu128 << 64))
                | (127 << 16)
                | (100 << 24)
                | (99 << 32)
                | (77u128 << 64),
            "HFMA2 R127, R100, R99, R77",
        ),
        (
            (host & !(0xf << 12)) | (1 << 12) | (3 << 74) | (1 << 86) | (2 << 81) | (1 << 84),
            "@P1 HFMA2 R1, R2.H1_H1, R3.H0_NH1, -R4.H0_H0",
        ),
    ];
    for arch in ["sm121a", "sm120"] {
        let t = tab(arch);
        for (w, want) in cases {
            assert_eq!(
                dec(&t, w & M96).as_deref(),
                Some(*want),
                "{arch} {w:#x} decode"
            );
        }
    }
    // doctrine: hs3!=0 + b86=1 (vendor '.INVALID6' print) = engine hole on
    // BOTH legs (271 fail-closed).
    for arch in ["sm121a", "sm120"] {
        let t = tab(arch);
        assert_eq!(
            dec(&t, (host | (2 << 60) | (1 << 86)) & M96),
            None,
            "{arch} INVALID6 not hole"
        );
    }
    // FLIP (BUG-320/321, F2-iter171, canonical 1e2b7ba): abs@83 '|Rc|' is
    // ARMED on both legs (was registered both-leg hole pre-320; arb320
    // x4). t320_* owns the full law; here the era-287 witness flips.
    for arch in ["sm121a", "sm120"] {
        let t = tab(arch);
        assert_eq!(
            dec(&t, (host | (1 << 83)) & M96).as_deref(),
            Some("HFMA2 R1, R2, R3, |R4|"),
            "{arch} abs@83 armed (BUG-320)"
        );
    }
}

#[test]
fn t287_3_corpus_shadow_words_guard_ghost_closed() {
    // Measured corpus words (scan287): sm120==vendor prints; sm121a must now
    // agree byte-for-byte. Pre-fix sm121a printed ghost '@P3'/dropped hsels.
    let words: &[(u128, &str)] = &[
        (
            0x0000408112000000f0e0e7231 & M96,
            "HFMA2 R14, R14.H0_H0, R15.H0_H0, R17.H0_H0",
        ),
        (
            0x00004080e200000121b1b7231 & M96,
            "HFMA2 R27, R27.H0_H0, R18.H0_H0, R14.H0_H0",
        ),
    ];
    let t = tab("sm121a");
    for (w, want) in words {
        let got = dec(&t, w & M96).unwrap_or_else(|| panic!("{w:#x} hole"));
        assert_eq!(got, *want, "{w:#x}");
        assert!(!got.starts_with('@'), "{w:#x} ghost guard survived: {got}");
    }
}

#[test]
fn t287_4_encode_parity_and_roundtrip() {
    // Cross-leg mint parity on authored matrix + word-exact anchors (arb287
    // law): plain text mints the hsel=0 word; era-mint drift is closed.
    let a = tab("sm121a");
    let b = tab("sm120");
    let texts = [
        "HFMA2 R1, R2, R3, R4",
        "HFMA2 R1, R2.H0_H0, R3, R4",
        "HFMA2 R1, R2.H1_H1, R3, R4",
        "HFMA2 R1, R2, R3.F32, R4",
        "HFMA2 R1, R2, R3.H0_H0, R4",
        "HFMA2 R1, R2, R3.H0_NH1, R4",
        "HFMA2 R1, R2, R3, R4.H0_H0",
        "HFMA2 R1, R2, R3, -R4",
        "HFMA2 R1, R2, R3, -R4.H1_H1",
        "@P1 HFMA2 R1, R2, R3, R4",
        "@!P0 HFMA2 R1, R2, R3, R4",
        "@!PT HFMA2 R1, R2, R3, R4",
        "HFMA2 RZ, R2, R3, R4",
        "HFMA2 R127, R100, R99, R77",
        "@P1 HFMA2 R1, R2.H1_H1, R3.H0_NH1, -R4.H0_H0",
    ];
    for tx in texts {
        let wa = enc(&a, tx);
        let wb = enc(&b, tx);
        assert_eq!(wa, wb, "{tx} cross-leg mint");
        let rb = dec(&a, wa & M96).unwrap_or_else(|| panic!("{tx} readback hole"));
        assert_eq!(rb, tx, "{tx} roundtrip");
    }
    // word-exact: plain form is the hsel=0 natural-H1_H0 encode (2aE law).
    let plain = enc(&a, "HFMA2 R14, R14, R15, R17") & M96;
    assert_eq!(plain & (1 << 61), 0, "b61 era bake minted");
    assert_eq!(plain & (1 << 75), 0, "b75 era bake minted");
    assert_eq!(plain & (1 << 82), 0, "b82 era bake minted");
}

#[test]
fn t287_5_doctrine_holds_and_no_new_claims() {
    let t = tab("sm121a");
    // INVALID carriers keep the 271/306 doctrine: authored INVALID text
    // fails closed; INVALID6-combo words hole (checked in t287_2).
    assert!(parse_sass("HFMA2 R1, R2.INVALID1, R3, R4;", 0).is_ok());
    let bad = parse_sass("HFMA2 R1, R2, R3.H0_NH1.H0_H0, R4;", 0);
    assert!(bad.is_err() || encode_instruction(&bad.unwrap(), &t).is_err());
    // invalid op-suffix keeps the BUG-132 class loud-fail.
    let ins = parse_sass("HFMA2 R1, R2, R3.H0_NH1, R4;", 0).unwrap();
    assert!(
        encode_instruction(&ins, &t).is_ok(),
        "opmod encode regression"
    );
    // BF16_V2 sibling mg untouched: b85=1 words still claim |BF16_V2 with
    // the 285 law on both legs.
    for arch in ["sm121a", "sm120"] {
        let tt = tab(arch);
        let w = (0x231u128
            | (7 << 12)
            | (1 << 16)
            | (2 << 24)
            | (3 << 32)
            | (4u128 << 64)
            | (1u128 << 85))
            & M96;
        assert_eq!(
            dec(&tt, w).as_deref(),
            Some("HFMA2.BF16_V2 R1, R2, R3, R4"),
            "{arch} BF16_V2 sibling moved"
        );
    }
}
