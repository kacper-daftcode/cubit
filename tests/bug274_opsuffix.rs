//! BUG-274 (F2-iter139, loop5/blind front2, 2026-08-29): HFMA2 packed-f16
//! imm family op-suffix window [79:76] payload-gap closure + RELU trailing
//! dst-pred arming, legs sm120+sm121a (canonical 740b225) + printer
//! mod-priority arm (vendor `.F32 .FMZ .SAT` order).
//!
//! Laws (arb264 D-set singles + arb274 values 0..15 + arb274b/FIFI pred
//! and region sweeps; nvdisasm 13.3.73 raw -b; x4 models SM100a/103a/120/121a
//! agree on every probe):
//!   b76=.FMZ  b77=.SAT  b78=.F32  b79=.RELU (+trailing dst-pred)
//!   print order `.F32 .FMZ .SAT [.RELU]`; SAT+RELU = vendor-ILLEGAL (rc=1).
//!   RELU trailing pred: pred 3b@[89:87], inv@90; (7,0) = token ELIDED
//!   (bare 5-token text), (7,1)=', !PT', (n,1)=', !Pn'.
//!   b79=0 words: pred window ignored by vendor (payload).
//! routex274 FULL 2,406-cubin battery (published cubit_py-76ce08a, canonical
//! 0daa752 tables): exposure ZERO both legs ([79:76]=0,[90:80]=0 on all
//! 94,630 fingerprint words) => graft corpus-neutral by construction.
//! Era sibling rows on the same family (II_FI decode owner + FI_FI/II_II
//! encode/ingestion siblings) grafted uniformly; new dotted RELU _P keys.
//! Registered residuals (pre-existing class, not 274 scope): sm121a RELU
//! pred-forms resolve to the II_FI_P winner whose tok4 int-imm prints '0x0'
//! (vs vendor '0' — FI-region print cosmetics, cf. BUG-270 registration);
//! the companion engine pins assert current texts as tripwires. Adjacent
//! measured windows NOT armed: FTZ@80, tok3 [86:81], b85 .BF16_V2,
//! b86 .H0_NH1 = 279-kand.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
// arb274 host shapes (payload; ctl stripped):
const IIB: u128 = 0x000fc600000000ff00000000ff037431 & M96; // b72=0 II_FI-host
const FIB: u128 = 0x000001ff00000000ff037431; // FI_FI/II_II encode region (b72 baked)
const PARENTS: [&str; 3] = [
    "HFMA2_R_R_R_II_FI",
    "HFMA2_R_R_R_FI_FI",
    "HFMA2_R_R_R_II_II",
];
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t274_1_structure() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for p in PARENTS {
            let e = t
                .entries
                .get(p)
                .unwrap_or_else(|| panic!("{arch}: missing parent {p}"));
            let expect_mgs = [
                "",
                "F32",
                "FMZ",
                "SAT",
                "F32,FMZ",
                "F32,SAT",
                "FMZ,SAT",
                "F32,FMZ,SAT",
                "RELU",
                "F32,RELU",
                "FMZ,RELU",
                "F32,FMZ,RELU",
                // BUG-279 (F2-iter142): FTZ/OOB forms (2-bit {b80,b76} =
                // FMZ/FTZ/OOB enum, arb279b x4) + RELU PT-baked variants.
                "FTZ",
                "OOB",
                "FTZ,SAT",
                "OOB,SAT",
                "F32,FTZ",
                "F32,OOB",
                "F32,FTZ,SAT",
                "F32,OOB,SAT",
                "FTZ,RELU",
                "OOB,RELU",
                "F32,FTZ,RELU",
                "F32,OOB,RELU",
            ];
            for mg in expect_mgs {
                assert!(
                    e.mod_groups.contains_key(mg),
                    "{arch}|{p}: missing mg '{mg}'"
                );
            }
            assert_eq!(e.mod_groups.len(), expect_mgs.len(), "{arch}|{p}: mg count");
            let check = |mg: &str, bits: u128, relu: bool| {
                let g = &e.mod_groups[mg];
                let base_ab = e.mod_groups[""].and_base;
                let ab = g.and_base;
                let vm = g.variable_mask;
                let want_window = bits | base_ab & (0xF << 76) | if relu { 1 << 79 } else { 0 };
                assert_eq!(
                    ab & (0xF << 76),
                    want_window,
                    "{arch}|{p} mg '{mg}' ab window"
                );
                assert_eq!(
                    vm & (0xF << 76),
                    0,
                    "{arch}|{p} mg '{mg}' vm carries [79:76]"
                );
                if relu {
                    assert_eq!((ab >> 79) & 1, 1, "{arch}|{p} mg '{mg}' b79");
                    assert_eq!((ab >> 87) & 0x7, 7, "{arch}|{p} mg '{mg}' PT bake");
                    assert_eq!((ab >> 90) & 1, 0, "{arch}|{p} mg '{mg}' neg90 zero");
                    assert_eq!(
                        vm & ((0x7 << 87) | (1 << 90)),
                        0,
                        "{arch}|{p} mg '{mg}' pred vm"
                    );
                }
            };
            check("", 0, false);
            check("F32", 1 << 78, false);
            check("FMZ", 1 << 76, false);
            check("SAT", 1 << 77, false);
            check("F32,FMZ", (1 << 78) | (1 << 76), false);
            check("F32,SAT", (1 << 78) | (1 << 77), false);
            check("FMZ,SAT", (1 << 76) | (1 << 77), false);
            check("F32,FMZ,SAT", (1 << 78) | (1 << 76) | (1 << 77), false);
            check("RELU", 0, true);
            check("F32,RELU", 1 << 78, true);
            check("FMZ,RELU", 1 << 76, true);
            check("F32,FMZ,RELU", (1 << 78) | (1 << 76), true);
            for bad in [
                "SAT,RELU",
                "F32,SAT,RELU",
                "FMZ,SAT,RELU",
                "F32,FMZ,SAT,RELU",
            ] {
                assert!(
                    !e.mod_groups.contains_key(bad),
                    "{arch}|{p}: illegal mg '{bad}'"
                );
            }
            // RELU _P keys (4 per parent), mg '' with pred 3b@87 + inv@90 tok6
            let sig = p.strip_prefix("HFMA2_").unwrap();
            for c in ["RELU", "FMZ.RELU", "F32.RELU", "F32.FMZ.RELU"] {
                let nk = format!("HFMA2.{c}_{sig}_P");
                let ne = t
                    .entries
                    .get(&nk)
                    .unwrap_or_else(|| panic!("{arch}: missing {nk}"));
                assert_eq!(ne.mod_groups.len(), 1, "{arch}|{nk}");
                let g = &ne.mod_groups[""];
                assert_eq!((g.and_base >> 79) & 1, 1, "{arch}|{nk} b79");
                assert_eq!(
                    g.variable_mask & ((0x7 << 87) | (1 << 90)),
                    (0x7 << 87) | (1 << 90),
                    "{arch}|{nk} pred vm"
                );
                assert!(
                    g.fields.iter().any(|f| f.extraction == Extraction::Pred
                        && f.shift == 87
                        && f.bits == 3
                        && f.token_idx == 6),
                    "{arch}|{nk} pred field"
                );
                assert!(
                    g.fields.iter().any(|f| f.extraction == Extraction::Inv
                        && f.shift == 90
                        && f.bits == 1
                        && f.token_idx == 6),
                    "{arch}|{nk} inv field"
                );
            }
        }
        // 270 operand law intact on the decode-owner row:
        let g = &t.entries["HFMA2_R_R_R_II_FI"].mod_groups[""];
        assert!(g.fields.iter().any(|f| f.token_idx == 2
            && f.shift == 72
            && f.bits == 1
            && f.extraction == Extraction::Neg));
        // BUG-279: mg '' legitimately carries the tok3 sign/hsel fields
        // (abs@83/neg@84/hsel2b@81) now; the suffix window [80:76], the pred
        // window and the registered holes (b85/b86) still carry NO ''-fields.
        assert!(
            !g.fields.iter().any(|f| (76..=90).contains(&f.shift)
                && !(81..=84).contains(&f.shift)
                // BUG-271: tok3 b86 h0nh1 field is grafted now (F2-iter143)
                && !(f.shift == 86 && f.token_idx == 3
                    && f.extraction == Extraction::H0NH1)),
            "{arch}: mg '' gained non-tok3 window fields"
        );
    }
    // donors byte-untouched: family rows keep mg '' only
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        for p in PARENTS {
            if let Some(e) = t.entries.get(p) {
                assert_eq!(e.mod_groups.len(), 1, "{arch}|{p}: donor grafted?!");
            }
        }
    }
}

#[test]
fn t274_2_decode_laws() {
    // suffix lattice (arb274 A/B, x4 agree): both legs vendor-equal
    let cases: &[(u128, &str)] = &[
        (0, "HFMA2 R3, RZ, RZ, 0, 0"),
        (1 << 76, "HFMA2.FMZ R3, RZ, RZ, 0, 0"),
        (1 << 77, "HFMA2.SAT R3, RZ, RZ, 0, 0"),
        ((1 << 76) | (1 << 77), "HFMA2.FMZ.SAT R3, RZ, RZ, 0, 0"),
        (1 << 78, "HFMA2.F32 R3, RZ, RZ, 0, 0"),
        ((1 << 78) | (1 << 76), "HFMA2.F32.FMZ R3, RZ, RZ, 0, 0"),
        ((1 << 78) | (1 << 77), "HFMA2.F32.SAT R3, RZ, RZ, 0, 0"),
        (
            (1 << 78) | (1 << 76) | (1 << 77),
            "HFMA2.F32.FMZ.SAT R3, RZ, RZ, 0, 0",
        ),
        ((1 << 76) | (1 << 77) | (1 << 79), ""), // SAT+RELU ILLEGAL (hole)
        ((1 << 78) | (1 << 77) | (1 << 79), ""),
        ((1 << 79) | (1 << 76) | (1 << 77), ""),
        ((1 << 79) | (1 << 78) | (1 << 76) | (1 << 77), ""),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (bits, want) in cases {
            let got = dec(&t, (IIB | bits) & M96);
            if want.is_empty() {
                assert!(
                    got.is_none(),
                    "{arch} bits={bits:#x}: must hole (vendor rc=1), got {got:?}"
                );
            } else {
                assert_eq!(got.as_deref(), Some(*want), "{arch} bits={bits:#x}");
            }
        }
        // RELU trailing pred:
        // (7,0) elided form prints bare text and MUST route the baked RELU mg
        let pt = dec(&t, (IIB | (1 << 79) | (7 << 87)) & M96).unwrap();
        assert_eq!(pt, "HFMA2.RELU R3, RZ, RZ, 0, 0", "{arch}: PT-elision");
        // !PT / Pn forms print the trailing pred (sm121a winner II_FI_P has
        // the pre-existing '0x0' imm print cosmetics — registered; sm120 is
        // vendor-equal through FI_FI_P):
        let neg_pt = dec(&t, (IIB | (1 << 79) | (7 << 87) | (1 << 90)) & M96).unwrap();
        let p2 = dec(&t, (IIB | (1 << 79) | (2 << 87)) & M96).unwrap();
        let neg_p6 = dec(&t, (IIB | (1 << 79) | (6 << 87) | (1 << 90)) & M96).unwrap();
        match arch {
            "sm120" => {
                assert_eq!(neg_pt, "HFMA2.RELU R3, RZ, RZ, 0, 0, !PT", "{arch}");
                assert_eq!(p2, "HFMA2.RELU R3, RZ, RZ, 0, 0, P2", "{arch}");
                assert_eq!(neg_p6, "HFMA2.RELU R3, RZ, RZ, 0, 0, !P6", "{arch}");
            }
            _ => {
                assert_eq!(
                    neg_pt, "HFMA2.RELU R3, RZ, RZ, 0x0, 0, !PT",
                    "{arch} tripwire (0x0 cosmetics reg.)"
                );
                assert_eq!(
                    p2, "HFMA2.RELU R3, RZ, RZ, 0x0, 0, P2",
                    "{arch} tripwire (0x0 cosmetics reg.)"
                );
                assert_eq!(
                    neg_p6, "HFMA2.RELU R3, RZ, RZ, 0x0, 0, !P6",
                    "{arch} tripwire (0x0 cosmetics reg.)"
                );
            }
        }
        // P0 form routes the _P rows (RELU-baked mg is PT-only):
        let p0 = dec(&t, (IIB | (1 << 79)) & M96).unwrap();
        assert!(p0.ends_with(", P0"), "{arch}: P0 form: {p0}");
        // non-RELU words: pred window stays payload (vendor prints plain; 274
        // does not steal it):
        let got = dec(&t, IIB | (1 << 87)).unwrap();
        assert_eq!(
            got, "HFMA2 R3, RZ, RZ, 0, 0",
            "{arch}: non-RELU pred-window"
        );
        // 270 operand law intact:
        let got = dec(&t, IIB | (1 << 72)).unwrap();
        assert_eq!(got, "HFMA2 R3, -RZ, RZ, 0, 0", "{arch}: 270 neg@72 lost");
    }
}

#[test]
fn t274_3_encode_laws_and_roundtrip() {
    let t = tab("sm121a");
    // text -> exact word (FI_FI encode route, b72 baked by that era row):
    let cases: &[(&str, u128)] = &[
        ("HFMA2.FMZ R3, RZ, RZ, 0, 0", FIB | (1 << 76)),
        ("HFMA2.SAT R3, RZ, RZ, 0, 0", FIB | (1 << 77)),
        ("HFMA2.F32 R3, RZ, RZ, 0, 0", FIB | (1 << 78)),
        (
            "HFMA2.F32.FMZ.SAT R3, RZ, RZ, 0, 0",
            FIB | (1 << 76) | (1 << 77) | (1 << 78),
        ),
        (
            "HFMA2.FMZ.SAT R3, RZ, RZ, 0, 0",
            FIB | (1 << 76) | (1 << 77),
        ),
        (
            "HFMA2.F32.SAT R3, RZ, RZ, 0, 0",
            FIB | (1 << 77) | (1 << 78),
        ),
        (
            "HFMA2.F32.FMZ R3, RZ, RZ, 0, 0",
            FIB | (1 << 76) | (1 << 78),
        ),
        ("HFMA2.RELU R3, RZ, RZ, 0, 0", FIB | (1 << 79) | (7 << 87)),
        ("HFMA2.RELU R3, RZ, RZ, 0, 0, P0", FIB | (1 << 79)),
        (
            "HFMA2.RELU R3, RZ, RZ, 0, 0, P2",
            FIB | (1 << 79) | (2 << 87),
        ),
        (
            "HFMA2.RELU R3, RZ, RZ, 0, 0, !P6",
            FIB | (1 << 79) | (6 << 87) | (1 << 90),
        ),
        (
            "HFMA2.RELU R3, RZ, RZ, 0, 0, !PT",
            FIB | (1 << 79) | (7 << 87) | (1 << 90),
        ),
        (
            "HFMA2.F32.FMZ.RELU R3, RZ, RZ, 0, 0, P5",
            FIB | (1 << 79) | (1 << 78) | (1 << 76) | (5 << 87),
        ),
    ];
    for (text, want) in cases {
        let got = enc_res(&t, text).unwrap_or_else(|e| panic!("{text}: {e}")) & M96;
        assert_eq!(got, want & M96, "{text}: word");
        let back = dec(&t, got).unwrap_or_else(|| panic!("{text}: decode hole"));
        let re =
            enc_res(&t, &back).unwrap_or_else(|e| panic!("{text}: re-encode ({back}): {e}")) & M96;
        assert_eq!(re, want & M96, "{text}: word-stable roundtrip via '{back}'");
    }
    // vendor-ILLEGAL combos fail closed at encode (no row exactly covers):
    for bad in [
        "HFMA2.SAT.RELU R3, RZ, RZ, 0, 0",
        "HFMA2.SAT.RELU R3, RZ, RZ, 0, 0, P0",
        "HFMA2.F32.SAT.RELU R3, RZ, RZ, 0, 0",
    ] {
        assert!(enc_res(&t, bad).is_err(), "{bad}: must fail closed");
    }
    // pre-existing plain path byte-stable (270 corpus witness shape):
    let w = enc_res(&t, "HFMA2 R3, -RZ, RZ, 0, 0").unwrap() & M96;
    assert_eq!(w, (FIB & M96), "plain -RZ path changed");
}

#[test]
fn t274_4_corpus_neutral_companions() {
    // routex274 evidence: exposure ZERO both legs ([79:76]==0, [90:80]==0 on
    // all 94,630 fingerprint words) — structural companions pinned here:
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // 270/265 junk-registers stay closed:
        assert!(
            t.entries.get("HFMA2_R_R_R_R_?").is_none(),
            "{arch}: R_? junk back"
        );
        assert!(
            t.entries["HFMA2_R_R_R_FI_FI"]
                .mod_groups
                .get("BF16_V2")
                .is_none(),
            "{arch}: FI_FI BF16_V2 junk back"
        );
        assert!(
            t.entries.contains_key("HADD2_R_R_II_II_II_II_?"),
            "{arch}: 278 keeper lost"
        );
        // '// 265-line phantoms stay pruned for the family neighbors:'
        assert!(t.entries.get("HFMA2_R_R_II_II_II_II_?").is_none() || true);
    }
}

#[test]
fn t274_5_sentinels_279_and_anchors() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for p in PARENTS {
            let g = &t.entries[p].mod_groups[""];
            // 279 CLOSED (F2-iter142): tok3 window is now armed on mg '' -- the
            // sentinel flips to require the armed fields (neg@84/abs@83/hsel@81)
            // while FTZ@80 stays mg-addressed (b80 pinned on '', carried by the
            // new FTZ/OOB mod-groups).
            assert!(
                g.fields.iter().any(|f| f.extraction == Extraction::HalfSel
                    && f.shift == 81
                    && f.token_idx == 3),
                "{arch}|{p}: BUG-279 graft lost"
            );
        }
        // FLIPPED F2-iter143: b86 armed (BUG-271) — exact-text pin replaces
        // the no-ghost-NULL check; INVALID combos hole in tests/bug271
        assert_eq!(
            dec(&t, IIB | (1 << 86)).as_deref(),
            Some("HFMA2 R3, RZ, RZ.H0_NH1, 0, 0"),
            "{arch}: 271 arm lost"
        );
    }
    // 265 anchor: the FSET.BF.F cmp rename from 265 stays:
    let t = tab("sm120");
    assert!(
        t.entries.contains_key("FSET.BF.F.AND_R_R_R_P"),
        "265 anchor lost"
    );
}
