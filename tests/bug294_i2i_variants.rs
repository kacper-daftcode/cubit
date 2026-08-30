//! BUG-294/295 (F2-iter149, loop5/blind front2, 2026-08-30): close the
//! remaining dst-width variants of the 2-op 0x238-lattice I2I.*.S32.SAT
//! family, legs sm120+sm121a. Registered 294/295-kand LOW at F2-iter146/
//! 147 (arb281 labeled b76='.S8' / b77='.U16' vendor-side, no rows).
//! Measurement-first (work/bug294): measure_pre294 (pub pyo3-0de37cf),
//! arb294+arb294b (1184 probes, nvdisasm 13.3.73 raw -b, x4 models
//! SM120/121a/100a/103a agree on EVERY probe), routex294 FULL 2,406-cubin
//! battery.
//!
//! LAW (x4 models): bits [77:76] = dst-width enum: 00='.U8' (281 row),
//! 01='.S8', 10='.U16', 11='.S16'. Guard 4b@[15:12] (PT-elide + inv@15 +
//! '@!PT'); dest 8b@16, src 8b@32 (255=RZ both slots). TEXT-INERT per
//! variant: [31:24] incl 0xFF, [75:40], (62,63), (80,81), [90:78],
//! [95:92], b72/73. b91 = KILL on EVERY variant (rc=1 x4) -> stays care.
//!
//! PRE-FIX (measured pub pyo3-0de37cf): decode HOLE for all three
//! variants both legs; encode fail-closed ("no operand-compatible table
//! entry; (I2I.S8.S32.SAT_R_R, "S32,S8,SAT") not in table") -- NO silent
//! wrong-code lane (unlike the 281 era row).
//! GRAFT (patch294.py, both legs): ADD I2I.S8.S32.SAT_R_R /
//! I2I.U16.S32.SAT_R_R / I2I.S16.S32.SAT_R_R with ab=0x238|{1,2,3}<<76
//! and fields+vm copied from the 281-armed U8 row (b76/77 stay care =>
//! care-space disjoint from everything: pre-fix HOLE proven two ways).
//! DONORS sm100a/sm103a byte-untouched. Engine ZERO changes (281/282
//! sign arms keyed on base "I2I" cover the new rows).
//! Corpus exposure (routex294): exactly ONE word per leg -- t10.cubin
//! .text.b0_38@0x410 = 0x405d080000342c28087238 = vendor
//! 'I2I.S8.S32.SAT R8, R44' x4 = the intended hole-closure decode
//! improvement; .U16/.S16 fingerprints ZERO both legs.
//! Roundtrip note: text-stable; word-lossy ONLY on vendor-undefined
//! inert-bit patterns (re-encoded canonical form clears them).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const VM: u128 = 0xf7ffcffffffffffffffff000u128;
const ROWS: [(&str, u128); 3] = [
    ("I2I.S8.S32.SAT_R_R", 0x238u128 | (1u128 << 76)),
    ("I2I.U16.S32.SAT_R_R", 0x238u128 | (1u128 << 77)),
    ("I2I.S16.S32.SAT_R_R", 0x238u128 | (3u128 << 76)),
];
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t294_1_structure_adds_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (k, ab) in ROWS {
            let e = t
                .entries
                .get(k)
                .unwrap_or_else(|| panic!("{leg}: variant key {k} missing"));
            assert_eq!(e.mod_groups.len(), 1, "{leg}|{k}: must be mg '' only");
            let g = &e.mod_groups[""];
            assert_eq!(g.and_base, ab, "{leg}|{k}: and_base drift");
            assert_eq!(
                g.variable_mask, VM,
                "{leg}|{k}: vm drift (must equal the 281 U8 row: b76/77 stay care)"
            );
            assert_eq!((g.variable_mask >> 91) & 1, 0, "{leg}|{k}: kill b91 in vm");
            assert_eq!(g.fields.len(), 3, "{leg}|{k}: field count drift");
            assert!(
                g.fields.iter().any(|f| f.token_idx == 0
                    && f.bits == 4
                    && f.shift == 12
                    && matches!(f.extraction, cubit::table::Extraction::Guard)),
                "{leg}|{k}: guard field missing"
            );
            assert!(
                g.fields.iter().any(|f| f.token_idx == 1
                    && f.bits == 8
                    && f.shift == 16
                    && matches!(f.extraction, cubit::table::Extraction::Reg)),
                "{leg}|{k}: dest field missing"
            );
            assert!(
                g.fields.iter().any(|f| f.token_idx == 2
                    && f.bits == 8
                    && f.shift == 32
                    && matches!(f.extraction, cubit::table::Extraction::Reg)),
                "{leg}|{k}: src field missing"
            );
        }
        // enum care-space disjointness: word of variant A must not fit row B
        let u8 = &t.entries["I2I.U8.S32.SAT_R_R"].mod_groups[""];
        assert_eq!(u8.and_base & (3u128 << 76), 0, "{leg}: U8 row enum drift");
        for (k, ab) in ROWS {
            assert_ne!(
                ab & (3u128 << 76),
                0,
                "{leg}|{k}: variant bit not pinned in and_base"
            );
        }
    }
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            !t.entries.keys().any(|k| k.starts_with("I2I.")),
            "{leg}: donor carries the family"
        );
    }
}

#[test]
fn t294_2_decode_laws_vendor_equal() {
    let wr8 = 0x7238u128 | (1u128 << 76) | (5 << 16) | (38 << 32);
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (k, ab) in ROWS {
            let sfx = k.strip_prefix("I2I").unwrap().split('_').next().unwrap();
            let base = ab | (7u128 << 12); // PT baked -> bare text
            assert_eq!(
                dec(&t, base).as_deref(),
                Some(format!("I2I{sfx} R0, R0").as_str()),
                "{leg}|{sfx}: PT base drift"
            );
            // full guard spectrum incl. invert (arb294 A, x4 models)
            for g in 0..7u128 {
                let w = base & !(0xF << 12) | (g << 12) | (5 << 16) | (38 << 32);
                assert_eq!(
                    dec(&t, w).as_deref(),
                    Some(format!("@P{g} I2I{sfx} R5, R38").as_str()),
                    "{leg}|{sfx}: guard g{g} drift"
                );
                assert_eq!(
                    dec(&t, w | (1 << 15)).as_deref(),
                    Some(format!("@!P{g} I2I{sfx} R5, R38").as_str()),
                    "{leg}|{sfx}: inv guard g{g} drift"
                );
            }
            assert_eq!(
                dec(&t, base | (1 << 15)).as_deref(),
                Some(format!("@!PT I2I{sfx} R0, R0").as_str()),
                "{leg}|{sfx}: @!PT drift"
            );
            // RZ printers (255 = RZ both slots, arb294 B x4)
            assert_eq!(
                dec(&t, base | (0xFF << 16)).as_deref(),
                Some(format!("I2I{sfx} RZ, R0").as_str()),
                "{leg}|{sfx}: RZ dest drift"
            );
            assert_eq!(
                dec(&t, base | (0xFF << 32)).as_deref(),
                Some(format!("I2I{sfx} R0, RZ").as_str()),
                "{leg}|{sfx}: RZ src drift"
            );
            // inert bands: text identical under same guard (arb294 C x4)
            let wr = base & !(0xF << 12) | (5 << 16) | (38 << 32);
            for (tag, bits) in [
                ("mid[31:24]=FF", 0xFFu128 << 24),
                ("(62,63)=3", 0x3u128 << 62),
                ("b72", 1u128 << 72),
                ("b74", 1u128 << 74),
                ("(80,81)=3", 0x3u128 << 80),
                ("b95", 1u128 << 95),
                ("b40", 1u128 << 40),
            ] {
                assert_eq!(
                    dec(&t, wr | bits).as_deref(),
                    dec(&t, wr).as_deref(),
                    "{leg}|{sfx}: inert {tag} not text-stable"
                );
            }
        }
        // corpus witness (routex294): t10.cubin .text.b0_38@0x410
        assert_eq!(
            dec(&t, 0x405d080000342c28087238u128).as_deref(),
            Some("I2I.S8.S32.SAT R8, R44"),
            "{leg}: routex294 witness not vendor-equal"
        );
        let _ = wr8;
    }
}

#[test]
fn t294_3_killbit_and_holds() {
    let base = 0x7238u128 | (5 << 16) | (38 << 32);
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (_, ab) in ROWS {
            let vb = ab | (base & !(0xF << 12)) | (0x0u128 << 12); // variant + guard0 payload
            for (tag, w) in [
                ("variant+b91 kill", vb | (1 << 91)),
                ("variant+b91 kill PT", (vb | (7 << 12)) | (1 << 91)),
                ("variant+b91 kill @!PT", (vb | (0xF << 12)) | (1 << 91)),
            ] {
                assert!(
                    dec(&t, w).is_none(),
                    "{leg}: {tag} ab={ab:#x} silently decoded (294/295)"
                );
            }
        }
        // family holdouts: kill on the U8 row, zero word, dead era clone base
        assert!(dec(&t, base | (1 << 91)).is_none(), "{leg}: U8+b91 decodes");
        assert!(dec(&t, 0u128).is_none(), "{leg}: zero word decodes");
        assert!(
            dec(&t, 0x200).is_none(),
            "{leg}: vendor-illegal 0x200 decodes"
        );
    }
}

#[test]
fn t294_4_encode_vendor_exact_and_roundtrip() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (k, ab) in ROWS {
            let sfx = k.strip_prefix("I2I").unwrap().split('_').next().unwrap();
            let cases: [(String, u128); 8] = [
                (format!("I2I{sfx} R0, R0"), ab | (7 << 12)),
                (format!("I2I{sfx} R0, R1"), ab | (7 << 12) | (1 << 32)),
                (
                    format!("I2I{sfx} R5, R38"),
                    ab | (7 << 12) | (5 << 16) | (38 << 32),
                ),
                (
                    format!("I2I{sfx} RZ, RZ"),
                    ab | (7 << 12) | (0xFF << 16) | (0xFF << 32),
                ),
                (format!("@P0 I2I{sfx} R0, R0"), ab),
                (
                    format!("@P2 I2I{sfx} R7, R19"),
                    ab | (2 << 12) | (7 << 16) | (19 << 32),
                ),
                (
                    format!("@!P2 I2I{sfx} R7, R19"),
                    ab | (2 << 12) | (1 << 15) | (7 << 16) | (19 << 32),
                ),
                (format!("@!PT I2I{sfx} R0, R0"), ab | (0xF << 12)),
            ];
            for (text, want) in cases {
                let w = enc_res(&t, &text).unwrap_or_else(|e| panic!("{leg}: enc '{text}': {e}"));
                assert_eq!(w & M96, want, "{leg}: enc '{text}' word drift");
                assert_eq!(
                    dec(&t, w & M96).as_deref(),
                    Some(text.as_str()),
                    "{leg}: decode(encode('{text}')) roundtrip drift"
                );
            }
        }
    }
}

#[test]
fn t294_5_fail_closed_and_roundtrip_semantics() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (tag, text) in [
            // 281 fail-closed arm covers the whole I2I base: signs have no
            // vendor encoding on ANY variant (arb294 C x4 text-inert == no
            // sign field) -- refuse the silent drop
            ("S8 neg src", "I2I.S8.S32.SAT R5, -R38"),
            ("S8 abs src", "I2I.S8.S32.SAT R5, |R38|"),
            ("U16 neg dst", "I2I.U16.S32.SAT -R5, R38"),
            ("S16 guard+abs", "@P2 I2I.S16.S32.SAT R5, |R38|"),
            // 272-gate: unknown operand suffix on bare regs
            ("S8 garbage suffix", "I2I.S8.S32.SAT R0.GARBAGE, R1"),
            ("S16 invalid suffix", "I2I.S16.S32.SAT R5, R38.INVALID2"),
            // wrong operand classes / arity
            ("S8 UR operand", "I2I.S8.S32.SAT R0, UR1"),
            ("U16 3-op", "I2I.U16.S32.SAT R0, R1, R2"),
            ("S16 reg out of range", "I2I.S16.S32.SAT R0, R256"),
            // unknown guard
            ("S8 P7 guard", "@P7 I2I.S8.S32.SAT R0, R0"),
            // mixed suffix texts are NOT rows (measure arb294: [77:76]
            // enum owns exactly one dst-width mod per word)
            ("cross S8.U16", "I2I.S8.U16.SAT R0, R1"),
            ("cross S8.U8", "I2I.S8.U8.SAT R5, R7"),
        ] {
            assert!(
                enc_res(&t, text).is_err(),
                "{leg}: {tag} '{text}' silently encodes (294/295)"
            );
        }
        // text-stable / word-lossy-only-on-inert: dirty inert bits decode
        // to the same text, re-encode clears them (arb294 C inert x4)
        let dirty = (0x7238u128 | (1 << 76) | (14 << 16) | (38 << 32))
            | (0xAB << 24)
            | (1 << 40)
            | (1 << 90);
        let text = dec(&t, dirty).expect("dirty S8 word must decode");
        assert_eq!(text, "I2I.S8.S32.SAT R14, R38", "{leg}: dirty text drift");
        let canon = enc_res(&t, &text).expect("re-encode");
        assert_eq!(
            canon & M96,
            0x7238u128 | (1 << 76) | (14 << 16) | (38 << 32),
            "{leg}: canonical form drift"
        );
        assert_ne!(canon & M96, dirty, "{leg}: inert bits must not roundtrip");
    }
}
