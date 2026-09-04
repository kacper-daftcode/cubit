//! BUG-288 (F2-iter160, loop5/blind front2, 2026-08-31; canonical c359172):
//! HFMA2 packed-f16 imm family (lattice 0x7431) closure of the tok2
//! sign/hsel window [75:73] + BF16_V2 bf16-constant semantics, sm120+sm121a.
//!
//! Pre-fix (pub pyo3-d38e5a0 + canonical 0aed02f tables; measure_pre288.py):
//!   DECODE silent wrong-text on FI_FI/II_II-won lattice words with tok2
//!     modifiers: '-|RZ|' printed for vendor '-|RZ|.H0_H0' (hsel dropped;
//!     the abs pipe alone came from the decoder's generic abs/neg post-pass),
//!     '|RZ|' for '-|RZ|' on II_II-won slots (neg drop via the no-field
//!     recovery path) -- the 270 arm reached only the II_FI parent (free-reg
//!     tok2); the RZ-baked parents FI_FI/II_II (+24 dotted RELU _P keys)
//!     never carried tok2 fields;
//!   DECODE/ENCODE wrong constant semantics under BF16_V2 (b85): vendor
//!     reads both 16b imm halves (tok4@48, tok5@32) as bf16; the engine
//!     printed f16 values ('2.375' for vendor '6' at 0x40c0) and MINTED
//!     f16-coded immediates for authored texts ('6' -> f16 0x4600 word;
//!     vendor decodes that word's constant as bf16 0x4600 = 2.06e36 --
//!     silent wrong-code at ISA level). The 285 graft had carried the
//!     post-279 f16/f16_d fields verbatim into the BF16_V2 mgs; the era
//!     sibling HFMA2_R_R_FI_FI_R mg BF16_V2 (_src 2e) already carried the
//!     vendor-correct 'bf16' extraction;
//!   DECODE '0x0' zero-imm print on dotted-key winners (HFMA2.*RELU_
//!     II_FI_P lineage, imm48==0 + tok2-hsel words) -- closed by the
//!     graft's route shift (armed II_II_P/FI_FI_P win and print '0' via
//!     their f16_d fields); the underlying is_hfma_ins dotted-head
//!     weakness stays registered (latent, zero live exposure).
//! Law arb288 (101 labels/404 probes + 300 random lattice probes;
//! work/bug288/arb288_verdicts.json + rand300_post.json; nvdisasm 13.3.73
//! raw -b; x4 models SM100a/103a/120/121a agree on EVERY probe): tok2 on
//! the RZ-baked imm parents: abs@73 composes ('-|RZ|'), hsel [75:74]
//! 0='' 1='.INVALID1' (vendor prints; BUG-306 R-domain law) 2='.H0_H0'
//! 3='.H1_H1'; composes with b86(h0nh1 tok3), window [80:76] suffixes,
//! RELU pred 3b@[89:87]+inv@90 (PT elide, '!PT' kept); stray pred-region
//! on non-RELU forms vendor-ignored (engine already matched, no graft);
//! b85 + any F32 bit => '.INVALID3' print = engine hole (285 doctrine);
//! constants under b85 print/read as bf16 (E-set x8 x4).
//! Graft patch288.py (replayable+idempotent, re-run skip-idem x2; engine
//! src ZERO changes): Part A adds {abs 1b@73 tok2, hsel 2b@74 tok2,
//! _src=bug288-2026-08-31} + vm |= 7<<73 to 96 rows/leg (72 parent mgs on
//! HFMA2_R_R_R_{FI_FI,II_II} + 24 dotted RELU _P keys); Part B swaps
//! f16/f16_d -> bf16 on 80 fields/leg (72 parent BF16_V2 mg fields + 20
//! dotted-key fields). Donors sm100a/sm103a byte-untouched; the era
//! shells HFMA2_R_R_R_II_II_II{,_?} stay untouched (never-win residual,
//! registered; zero corpus exposure). Post-graft pub-engine: arb battery
//! 92/92 vendor-exact (+9 doctrine holes), 300 random probes 0 drift /
//! 0 leg-divergence / 0 x2-divergence, encode matrix 13/13 x2 legs
//! roundtrip AND vendor-minted (nvdisasm cross-readback), '.H0_H1' mint
//! fail-closed by the pre-existing generic HalfSel arm.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

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
fn host() -> u128 {
    // lattice 0x7431: guard PT(7)@12, dst R1@16, neg-baked tok2 RZ
    0x1ff00000000ff007431u128 | (7 << 12) | (1 << 16)
}

#[test]
fn t288_1_structure_census_tags() {
    use cubit::table::Extraction as X;
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let mut part_a = 0usize;
        let mut bf16_fields = 0usize;
        for (key, entry) in &t.entries {
            if !key.starts_with("HFMA2") {
                continue;
            }
            for (mg_name, mg) in &entry.mod_groups {
                let fs = &mg.fields;
                let h = fs
                    .iter()
                    .any(|f| f.extraction == X::HalfSel && f.shift == 74 && f.token_idx == 2);
                let a = fs
                    .iter()
                    .any(|f| f.extraction == X::Abs && f.shift == 73 && f.token_idx == 2);
                let is_target = key == "HFMA2_R_R_R_FI_FI"
                    || key == "HFMA2_R_R_R_II_II"
                    || (key.starts_with("HFMA2.")
                        && (key.ends_with("FI_FI_P") || key.ends_with("II_II_P")));
                if is_target {
                    assert!(
                        h && a,
                        "{arch} {key}|{mg_name}: partial tok2 window ({h}/{a})"
                    );
                    part_a += 1;
                    assert!(
                        mg.variable_mask & (0x7u128 << 73) == (0x7u128 << 73),
                        "{arch} {key}|{mg_name}: vm missing [75:73]"
                    );
                    // neg@72 stays baked in and_base (no neg field on these RZ-baked parents)
                    let has_neg72 = fs
                        .iter()
                        .any(|f| f.extraction == X::Neg && f.shift == 72 && f.token_idx == 2);
                    if key.ends_with("II_II") || key.ends_with("II_II_P") {
                        assert!(!has_neg72, "{key}|{mg_name}: II_II must keep neg@72 baked");
                    }
                }
                for f in fs {
                    if f.bits == 16 && (f.shift == 32 || f.shift == 48) {
                        match f.extraction {
                            X::BF16 => bf16_fields += 1,
                            X::F16 | X::F16d => {
                                let is_bf12 =
                                    mg_name.starts_with("BF16_V2") || key.contains("BF16_V2");
                                assert!(
                                    !is_bf12,
                                    "{arch} {key}|{mg_name}: f16/f16_d left on BF16_V2 row @{}",
                                    f.shift
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        assert_eq!(part_a, 96, "{arch}: Part A armed rows != 96");
        assert!(
            bf16_fields >= 80,
            "{arch}: bf16 field census too small ({bf16_fields})"
        );
    }
    // provenance tag census on the raw vendored JSON (Part A 96 rows x2
    // fields + Part B 80 fields = 272 per leg; donors must stay tagless)
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
    assert_eq!(count_tags("sm120", "bug288-2026-08-31"), 272);
    assert_eq!(count_tags("sm121a", "bug288-2026-08-31"), 272);
    assert_eq!(count_tags("sm100a", "bug288-2026-08-31"), 0);
    assert_eq!(count_tags("sm103a", "bug288-2026-08-31"), 0);

    // donors byte-stable: they never carried the imm-family parents, and the
    // 288 graft adds nothing there (the pure-reg donor rows' own hsel@74 =
    // pre-existing 2aE shape, asserted here as a presence-anchored census).
    // FLIP (BUG-354, F2-iter184, canonical 5c12995): the 354 mod-lane
    // closure on the sparse FI_FI key CLONES the '' geometry (incl. tok2
    // hsel@74/abs@73, tag bug354-2026-09-02) onto all 11 new mgs + swaps
    // tok4/tok5 f16->bf16 on exactly the two BF16 families' lanes
    // {BF16_V2, BF16_V2,FMZ} (+RELU variants) -- and the 6 dotted RELU _P
    // keys now exist (HFMA2[.<mods>].RELU_R_R_R_FI_FI_P). II_II stays
    // untouched; tags remain bug354-tagged (bug288 tag counts unchanged).
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        use cubit::table::Extraction as X;
        for k in ["HFMA2_R_R_R_FI_FI", "HFMA2_R_R_R_II_II"] {
            if let Some(e) = t.entries.get(k) {
                for (mgn, mg) in &e.mod_groups {
                    // BUG-329 attribution (iter176): the sparse FI_FI mg ''
                    // deliberately gained the tok2 arm (abs@73 + hsel@74;
                    // tag bug329-2026-09-01) as a measured vendor-parity
                    // closure -- NOT the 288 tag and NOT beyond mg ''.
                    // BUG-354 attribution (iter184): ALL FI_FI mgs carry the
                    // tok2 arm now (lane clones of '').
                    let n_hsel = mg
                        .fields
                        .iter()
                        .filter(|f| f.extraction == X::HalfSel && f.shift == 74 && f.token_idx == 2)
                        .count();
                    let n_abs = mg
                        .fields
                        .iter()
                        .filter(|f| f.extraction == X::Abs && f.shift == 73 && f.token_idx == 2)
                        .count();
                    let expect = usize::from(k == "HFMA2_R_R_R_FI_FI");
                    assert_eq!(n_hsel, expect, "{arch}: donor {k}[{mgn}] hsel@74 count");
                    assert_eq!(n_abs, expect, "{arch}: donor {k}[{mgn}] abs@73 count");
                    let allow_bf16 = k == "HFMA2_R_R_R_FI_FI" && mgn.contains("BF16_V2");
                    assert_eq!(
                        mg.fields.iter().any(|f| f.extraction == X::BF16),
                        allow_bf16,
                        "{arch}: donor {k}[{mgn}] bf16 extraction scope"
                    );
                }
            }
        }
        // dotted RELU descendants: post-354 exactly the six 354 keys exist;
        // the II_II dotted descendants still never existed on donors.
        const KEYS354: [&str; 6] = [
            "HFMA2.RELU_R_R_R_FI_FI_P",
            "HFMA2.F32.RELU_R_R_R_FI_FI_P",
            "HFMA2.FMZ.RELU_R_R_R_FI_FI_P",
            "HFMA2.F32.FMZ.RELU_R_R_R_FI_FI_P",
            "HFMA2.BF16_V2.RELU_R_R_R_FI_FI_P",
            "HFMA2.BF16_V2.FMZ.RELU_R_R_R_FI_FI_P",
        ];
        for k in KEYS354 {
            assert!(t.entries.contains_key(k), "{arch}: 354 dotted key lost {k}");
        }
        assert!(
            !t.entries.contains_key("HFMA2.BF16_V2.RELU_R_R_R_II_II_P"),
            "{arch}: donor gained II_II dotted key"
        );
    }
}

#[test]
fn t288_2_decode_law_vendor_exact() {
    let h = host();
    // (bits-or, expected text) -- every expectation = arb288 x4-agreed vendor text
    let cases: &[(u128, &str)] = &[
        (0, "HFMA2 R1, -RZ, RZ, 0, 0"),
        (2 << 74, "HFMA2 R1, -RZ.H0_H0, RZ, 0, 0"),
        (3 << 74, "HFMA2 R1, -RZ.H1_H1, RZ, 0, 0"),
        ((1 << 74) | (1 << 73), "HFMA2 R1, -|RZ|.INVALID1, RZ, 0, 0"),
        ((2 << 74) | (1 << 73), "HFMA2 R1, -|RZ|.H0_H0, RZ, 0, 0"),
        (2 << 81, "HFMA2 R1, -RZ, RZ.H0_H0, 0, 0"),
        (
            (2 << 74) | (1 << 86),
            "HFMA2 R1, -RZ.H0_H0, RZ.H0_NH1, 0, 0",
        ),
        ((1 << 79) | (2 << 87), "HFMA2.RELU R1, -RZ, RZ, 0, 0, P2"),
        (
            (1 << 79) | (3 << 87) | (1 << 90),
            "HFMA2.RELU R1, -RZ, RZ, 0, 0, !P3",
        ),
        (
            (1 << 85) | (0x40c0 << 48),
            "HFMA2.BF16_V2 R1, -RZ, RZ, 6, 0",
        ),
        (
            (1 << 85) | (0x3c00 << 48),
            "HFMA2.BF16_V2 R1, -RZ, RZ, 0.0078125, 0",
        ),
        (
            (1 << 85) | (0xff80 << 48),
            "HFMA2.BF16_V2 R1, -RZ, RZ, -INF , 0",
        ),
        (
            (1 << 85) | (0x40c0 << 48) | (2 << 74),
            "HFMA2.BF16_V2 R1, -RZ.H0_H0, RZ, 6, 0",
        ),
        (
            (2 << 74) | (0x3c00 << 48) | (0x4000 << 32),
            "HFMA2 R1, -RZ.H0_H0, RZ, 1, 2",
        ),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (bits, want) in cases {
            let w = (h | bits) & ((1u128 << 96) - 1);
            let got = dec(&t, w).unwrap_or_else(|| panic!("{arch} HOLE on {want}"));
            assert_eq!(got, *want, "{arch} decode {bits:#x}");
        }
    }
}

#[test]
fn t288_3_doctrine_holes() {
    // vendor-PRINTED INVALID carriers stay engine holes (271/282/285 doctrine)
    let h = host();
    let doctrine: &[u128] = &[
        (1 << 85) | (1 << 78), // INVALID3 (BF16_V2+F32)
        (5 << 76) | (1 << 85), // INVALID3.FMZ
        (2 << 81) | (1 << 86), // INVALID6 (hsel + h0nh1 tok3)
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for bits in doctrine {
            let w = (h | bits) & ((1u128 << 96) - 1);
            assert!(
                dec(&t, w).is_none(),
                "{arch}: doctrine-hole decoded at {bits:#x}"
            );
        }
    }
}

#[test]
fn t288_4_encode_inverse_and_bitlaw() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // authored hsel/abs mints the measured window bits; roundtrip == vendor text
        let w = enc_res(&t, "HFMA2 R1, -RZ.H0_H0, RZ, 0, 0").expect("mint hsel2");
        assert_eq!((w >> 74) & 3, 2, "hsel bits");
        assert_eq!((w >> 72) & 1, 1, "neg bake");
        assert_eq!(dec(&t, w).as_deref(), Some("HFMA2 R1, -RZ.H0_H0, RZ, 0, 0"));
        let w = enc_res(&t, "HFMA2 R1, -|RZ|.H1_H1, RZ, 0, 0").expect("mint abs+hsel3");
        assert_eq!((w >> 73) & 7, 0b111, "abs+neg+hsel3 bits");
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("HFMA2 R1, -|RZ|.H1_H1, RZ, 0, 0")
        );
        // BF16_V2 constants mint bf16 bit patterns (NOT f16)
        let w = enc_res(&t, "HFMA2.BF16_V2 R1, -RZ, RZ, 6, 8").expect("mint bf16 6,8");
        assert_eq!((w >> 48) & 0xffff, 0x40c0, "tok4 bf16(6)");
        assert_eq!((w >> 32) & 0xffff, 0x4100, "tok5 bf16(8)");
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("HFMA2.BF16_V2 R1, -RZ, RZ, 6, 8")
        );
        let w = enc_res(&t, "HFMA2.BF16_V2.FTZ.SAT R1, -RZ, RZ, 1, 2").expect("ftzs");
        assert_eq!((w >> 48) & 0xffff, 0x3f80, "tok4 bf16(1)");
        // RELU inverse + pred window
        let w = enc_res(&t, "HFMA2.RELU R1, -RZ.H1_H1, RZ, 0, 0, !P3").expect("relu");
        assert_eq!((w >> 87) & 0xf, 0b1011, "pred3+inv");
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("HFMA2.RELU R1, -RZ.H1_H1, RZ, 0, 0, !P3")
        );
    }
}

#[test]
fn t288_5_fail_closed_and_siblings_untouched() {
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        // vendor-INVALID1 mint = fail-closed (generic HalfSel spelling arm)
        for bad in [
            "HFMA2 R1, -RZ.H0_H1, RZ, 0, 0",
            "HFMA2 R1, -RZ.INVALID1, RZ, 0, 0",
            "HFMA2 R1, -RZ.F32, RZ, 0, 0",
        ] {
            assert!(
                enc_res(&t, bad).is_err(),
                "{arch}: '{bad}' must fail closed"
            );
        }
        // SAT+RELU carrier = fail-closed encode (274/285 doctrine)
        assert!(enc_res(&t, "HFMA2.SAT.RELU R1, -RZ, RZ, 0, 0").is_err());
        // sibling rows untouched: II_FI keeps its free-reg tok2 field set (neg@72 tok2 present)
        let iifi = &t.entries["HFMA2_R_R_R_II_FI"].mod_groups[""];
        assert!(iifi
            .fields
            .iter()
            .any(|f| f.shift == 72 && f.token_idx == 2));
        // era shells stay 2-field, never re-armed here (registered residual)
        for k in ["HFMA2_R_R_R_II_II_II", "HFMA2_R_R_R_II_II_II_?"] {
            let mg = &t.entries[k].mod_groups[""];
            assert_eq!(mg.fields.len(), 2, "{k} era shell moved");
            assert!(!mg
                .fields
                .iter()
                .any(|f| f.shift == 74 || (f.shift == 73 && f.token_idx == 2)));
        }
    }
    // donors byte-stable via the presence census in t288_1 (the donors' own
    // 2aE pure-reg rows use abs@73 legitimately -- no freeze-by-field here).
}
