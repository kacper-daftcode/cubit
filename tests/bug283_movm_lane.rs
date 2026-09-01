//! BUG-283 (F2-iter156, loop5/blind front2, 2026-08-30): MOVM.16.MT88 lane
//! closure on the 0x23a lattice, legs sm120+sm121a (canonical bug283 cut
//! 1beab0f, ride-after 7a1a108/BUG-280). Registered 283-kand LOW at
//! F2-iter141 (276 report sec.6). Measurement-first (work/bug283):
//! arb283 + arb283b = 362 probes x4 models SM100a/103a/120/121a (ZERO
//! disagreement); routex283 FULL 2,406-cubin battery x4 legs: ZERO
//! true-lane words (lone t10.cubin hit ns=11 = vendor rc0-empty sibling
//! class, hole pre AND post) => corpus-neutral by construction.
//!
//! LAW (x4 models agree on every probe): guard 4b@[15:12] (g=7 PT-elided,
//! inv='@!', '@!PT' legal); dst 8b@16, src 8b@24 (255 prints RZ);
//! TEXT-INERT: sub-op band [36:32] full sweep + singles 37..74 / 80..90 /
//! 92..95; name-space [79:75] = vendor sub-op selects ([77:75] 0=16 /
//! 1=U4TO8 / 5..7=INVALID5..7; [79:78] 0=MT88 / 1=M832 / 2=M864 /
//! 3=INVALID3); b91 = unit KILL; b109/b122/b123/b124 = opex KILL (above
//! the 96-bit decode cut = engine-invariant, documented).
//! PRE-FIX (pub pyo3-7a1a108, measure_pre283): 316 mismatches on the
//! 181-probe arb matrix x2 legs -- era guard-clone rows '_P0'/'_P2'/'_P5'
//! print their name suffix on a winner lottery, the _P5 clone's shifted
//! src window (8b@25) leaks sub-op bit32 as 'R128' (vendor 'R0'), 52
//! vendor-legal probes decode HOLE, b75 sibling mis-claimed as MT88, and
//! the era ghost post-pass printed '-R0'/'|R0|' for text-inert b72/b73.
//! Encode: vendor spellings failed loud; era '_Pn' suffixed texts minted
//! (text-lie: authored 'R128' minted the inert sub-op bit32), and a signed
//! operand minted a ghost b80 word.
//! FIX: table graft (patch283.py, replayable+idempotent) -- DELETE the 4
//! era clone rows (P0/P2/P5/P _R_R); REWRITE MOVM.16.MT88_R_R '' (ab
//! 0x723a->0x23a, vm 0xf7ff07fffffffffffffff000 = fields+measured inert
//! bands, care [0:11]|[79:75]|91|[127:96] per 281; fields guard 4b@12
//! tok0 + dst 8b@16 tok1 + src 8b@24 tok2). Engine arms: MOVM excluded
//! from the prio-3 sign gate + the ghost-sign post-pass (decoder.rs) and
//! from the generic sign emit + attributed fail-closed bail on signed
//! operands (encoder.rs).
//! NEIGHBORS NOT ARMED (registered): 315-kand = the lane decodes legal on
//! vendor SM100a/SM103a but donor tables carry no MOVM rows (donor tables
//! era-frozen per fleet invariant; owner scope); 316-kand = sibling lanes
//! U4TO8.*/M832/M864/INVALIDn decode-hole today (era U4TO8.M832 row never
//! matched; law measured in arb283 G). [316-kand CLOSED by BUG-316
//! (2026-09-01, canonical 0821445): the 5 vendor-legal siblings armed as
//! strict clones of this geometry; INVALIDn/rc0-empty stay doctrine
//! holes -- pins in tests/bug316_movm_namespace.rs.]
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const NEW_VM: u128 = 0xf7ff07fffffffffffffff000u128;
const JUNK: [&str; 4] = [
    "MOVM.16.MT88_P0_R_R",
    "MOVM.16.MT88_P2_R_R",
    "MOVM.16.MT88_P5_R_R",
    "MOVM.16.MT88_P_R_R",
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
fn t283_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for k in JUNK {
            assert!(!t.entries.contains_key(k), "{leg}: junk clone {k} survived");
        }
        let e = &t.entries["MOVM.16.MT88_R_R"];
        let mg = &e.mod_groups[""];
        assert_eq!(mg.and_base, 0x23au128, "{leg}: R_R ab drift");
        assert_eq!(mg.variable_mask, NEW_VM, "{leg}: R_R vm drift");
        let want = [
            (4u32, 12u32, 0i32),
            (8u32, 16u32, 1i32),
            (8u32, 24u32, 2i32),
        ];
        let got: Vec<(u32, u32, i32)> = mg
            .fields
            .iter()
            .map(|f| (f.bits, f.shift, f.token_idx))
            .collect();
        assert_eq!(got, want, "{leg}: R_R field shape drift");
        // sibling-era row untouched (316-kand: it never matched; registered)
        assert!(t.entries.contains_key("MOVM.U4TO8.M832_R_R"), "{leg}");
    }
    // donors byte-untouched: still no MOVM keys at all (315-kand, owner scope)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for k in t.entries.keys() {
            assert!(!k.starts_with("MOVM"), "{leg}: donor carries {k}");
        }
    }
}

#[test]
fn t283_2_decode_law_vendor_equal() {
    // every expected string below is the nvdisasm 13.3.73 print, x4 models
    // agreeing (arb283 A/B2/C/E/F + arb283b F/H)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for g in 0u128..8 {
            let exp = if g == 7 {
                "MOVM.16.MT88 R0, R0".to_string()
            } else {
                format!("@P{g} MOVM.16.MT88 R0, R0")
            };
            assert_eq!(
                dec(&t, 0x23a | (g << 12)).as_deref(),
                Some(exp.as_str()),
                "{leg} g{g}"
            );
            let expi = if g == 7 {
                "@!PT MOVM.16.MT88 R0, R0".to_string()
            } else {
                format!("@!P{g} MOVM.16.MT88 R0, R0")
            };
            assert_eq!(
                dec(&t, 0x23a | (1 << 15) | (g << 12)).as_deref(),
                Some(expi.as_str()),
                "{leg} inv g{g}"
            );
        }
        // sub-op band fully inert, incl. the era 'R128' misread words
        for w in [
            0x23au128,
            0x30000023a,
            0x70000023a,
            0xb0000023a,
            0x1f0000023a,
        ] {
            assert_eq!(
                dec(&t, w).as_deref(),
                Some("@P0 MOVM.16.MT88 R0, R0"),
                "{leg}: sub-op inertness drift at {w:#x}"
            );
        }
        // payload + sub-op composition (era hole), RZ alias, named payloads
        let cases: [(u128, &str); 5] = [
            (0x23a | (5 << 16) | (4 << 24), "@P0 MOVM.16.MT88 R5, R4"),
            (
                0x23a | (3 << 32) | (3 << 16) | (2 << 24),
                "@P0 MOVM.16.MT88 R3, R2",
            ),
            (0x23a | (255 << 16) | (255 << 24), "@P0 MOVM.16.MT88 RZ, RZ"),
            (
                0x23a | (5 << 12) | (7 << 16) | (19 << 24),
                "@P5 MOVM.16.MT88 R7, R19",
            ),
            (
                0x23a | (1 << 15) | (254 << 16),
                "@!P0 MOVM.16.MT88 R254, R0",
            ),
        ];
        for (w, exp) in cases {
            assert_eq!(dec(&t, w).as_deref(), Some(exp), "{leg} payload {w:#x}");
        }
        // text-inert singles on the armed inert bands print plain (no ghosts)
        for b in (37u32..75).chain(80..91).chain(92..96) {
            let w = 0x23au128 | (1u128 << b);
            assert_eq!(
                dec(&t, w).as_deref(),
                Some("@P0 MOVM.16.MT88 R0, R0"),
                "{leg}: ghost/inert drift at b{b}"
            );
        }
    }
}

#[test]
fn t283_3_encode_vendor_word_exact() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // authored vendor spellings now encode; minted payload (M96) equals
        // the arb-observed vendor words; decode of the mint reproduces the
        // authored text
        let cases: [(&str, u128); 4] = [
            ("MOVM.16.MT88 R5, R4", 0x723a | (5 << 16) | (4 << 24)),
            (
                "@P5 MOVM.16.MT88 R7, R19",
                0x23a | (5 << 12) | (7 << 16) | (19 << 24),
            ),
            (
                "@!P0 MOVM.16.MT88 R254, R2",
                0x23a | (1 << 15) | (254 << 16) | (2 << 24),
            ),
            (
                "@!PT MOVM.16.MT88 RZ, RZ",
                0xf23a | (255 << 16) | (255 << 24),
            ),
        ];
        for (text, wexp) in cases {
            let w = enc_res(&t, text).unwrap_or_else(|e| panic!("{leg}: {text} encode: {e}"));
            assert_eq!(w & M96, wexp & M96, "{leg}: {text} minted word drift");
            assert_eq!(
                dec(&t, w).as_deref(),
                Some(text),
                "{leg}: {text} encode->decode roundtrip drift"
            );
        }
        // era suffixed junk texts fail closed (were minting text-lies)
        for text in [
            "@P0 MOVM.16.MT88_P0 R0, R0",
            "@P0 MOVM.16.MT88_P5 R0, R128",
            "@P1 MOVM.16.MT88_P5 R0, R128",
            "MOVM.16.MT88_P2 R1, R2",
        ] {
            assert!(
                enc_res(&t, text).is_err(),
                "{leg}: junk text still mints: {text}"
            );
        }
    }
}

#[test]
fn t283_4_fail_closed_holes_and_sign_gate() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // rc0-empty + INVALIDn + unit kill + lone corpus sibling: holes
        // stand. BUG-316 flip (2026-09-01, canonical 0821445): the three
        // legal siblings formerly pinned here as holes (b75 U4TO8.MT88,
        // b78 16.M832, b79 16.M864) are now ARMED as strict clones of this
        // row's geometry -- their decode/encode law lives in
        // tests/bug316_movm_namespace.rs.
        let holes: [(u128, &str); 5] = [
            (0x23a | (2 << 75), "ns2 rc0-empty"),
            (0x23a | (5 << 75), "ns5 INVALID5"),
            (0x23a | (24 << 75), "ns24 16.INVALID3"),
            (0x23a | (1 << 91), "b91 unit KILL"),
            (
                0x405d080000342c2808723au128 & M96,
                "lone corpus sibling (t10, ns=11)",
            ),
        ];
        for (w, what) in holes {
            assert!(dec(&t, w).is_none(), "{leg}: {what} claimed at {w:#x}");
        }
        // signed operands fail closed with attribution (were ghost mints)
        for text in [
            "@P0 MOVM.16.MT88 R0, -R4",
            "MOVM.16.MT88 -R1, R2",
            "@P3 MOVM.16.MT88 R0, |R4|",
            "@P0 MOVM.16.MT88 R5, -RZ",
        ] {
            let e = enc_res(&t, text).expect_err("{leg}: signed MOVM text mints");
            assert!(e.contains("BUG-283"), "{leg}: 283 gate attribution: {e}");
        }
        // sign-window bits stay text-inert on decode (ghost post-pass gated)
        for b in [62u32, 63, 72, 73] {
            let w = 0x23au128 | (1u128 << b);
            assert_eq!(
                dec(&t, w).as_deref(),
                Some("@P0 MOVM.16.MT88 R0, R0"),
                "{leg}: ghost sign resurrected at b{b}"
            );
        }
    }
}

#[test]
fn t283_5_doctrine_anchors_and_keepers() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // neighboring family closures stay intact (281 / 280 anchors)
        assert_eq!(
            dec(&t, 0x238).as_deref(),
            Some("@P0 I2I.U8.S32.SAT R0, R0"),
            "{leg}: 281-armed 0x238 decode drift"
        );
        assert_eq!(
            dec(&t, 0x27a).as_deref(),
            Some("@P0 QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0"),
            "{leg}: 280-armed 0x27a decode drift"
        );
        assert!(t.entries.contains_key("I2IP.U8.S32.SAT_R_R_R_R"), "{leg}");
        // flipped era tripwire (was: '@P0 MOVM.16.MT88_P5 R0, R128' junk
        // print; BUG-283 armed the vendor law): cluster words decode plain
        for w in [0x30000023au128, 0x70000023a, 0xb0000023a] {
            assert_eq!(
                dec(&t, w).as_deref(),
                Some("@P0 MOVM.16.MT88 R0, R0"),
                "{leg}: 283-armed cluster drift at {w:#x}"
            );
        }
    }
}
