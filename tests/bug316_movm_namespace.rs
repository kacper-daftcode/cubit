//! BUG-316 (F2-iter170, loop5/blind front2, 2026-09-01): MOVM name-space
//! sibling closure on the 0x23a lattice, legs sm120+sm121a (canonical
//! bug316 cut 0821445, ride-after 80400cd/BUG-308). Registered 316-kand
//! LOW at F2-iter156 (283 report sec.6). Measurement-first: arb316 = 380
//! fresh probes x4 models SM100a/103a/120/121a (ZERO disagreement) on top
//! of the arb283 G-sweep law. routex316 FULL 2,406-cubin battery x4 legs:
//! ZERO words claim the armed lanes (the lone t10.cubin lattice hit carries
//! ns=11 = vendor rc0-empty combo = hole pre AND post) => corpus-neutral
//! by construction.
//!
//! LAW (x4 models agree on every probe): name-space band [79:75] splits
//! as b75 = 16 <-> U4TO8, [77:76] 00 = named lanes / 01,10 = vendor
//! rc0-empty (hole class) / 11 = vendor INVALIDn print ([76:75]
//! 01/10/11 -> INVALID5/6/7), [79:78] 00=MT88 / 01=M832 / 10=M864 /
//! 11=INVALID3. Guard 4b@[15:12] (7=PT elided, inv bit15 = '@!', '@!PT'
//! legal), dst 8b@16, src 8b@24 (255 prints RZ), sub-op band [36:32] +
//! singles 37..74/80..90/92..95 text-INERT, b91 unit KILL and
//! b109/b122 opex KILL (rc=1) hold on the new lanes too.
//! PRE-FIX (pub pyo3-80400cd, measure_pre316): all 95 arb316 probes decode
//! HOLE on both legs; the era row MOVM.U4TO8.M832_R_R was a phantom (its
//! vm covered [12:31]|[122:124], so every real sibling word with b75/b78
//! set failed its care complement -- it never matched a single word);
//! vendor spellings loud-failed encode; the MT88 lane from BUG-283 worked.
//! FIX: pure table graft (patch316.py, replayable+idempotent) -- ADD
//! MOVM.U4TO8.MT88_R_R (ns 1), MOVM.16.M832_R_R (ns 8), MOVM.16.M864_R_R
//! (ns 16), MOVM.U4TO8.M864_R_R (ns 17) and REWRITE the U4TO8.M832 phantom
//! (ns 9), all as strict clones of the verified BUG-283 MT88 geometry
//! (fields guard 4b@12 / dst 8b@16 / src 8b@24; vm
//! 0xf7ff07fffffffffffffff000 = care [0:11]|[79:75]|91|[127:96]).
//! NO engine change: decode works strictly from the rows; INVALID names
//! carry no rows at all, so encode loud-fails and decode stays HOLE.
//! NOT ARMED (doctrine residuum, bug210/bug215 precedent -- vendor-INVALID
//! words stay fail-closed, not printed): INVALID5/6/7 x {MT88,M832,M864,
//! INVALID3} + {16,U4TO8}.INVALID3 (decode HOLE + encode loud-fail, pinned
//! below); rc0-empty combos (ns with [77:76] in {01,10}) stay HOLE.
//! 315-kand (donor tables sm100a/sm103a carry no MOVM rows at all) stays
//! owner scope per fleet sha-invariant -- asserted untouched here.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const NEW_VM: u128 = 0xf7ff07fffffffffffffff000u128;
const LANES: [(&str, u32); 5] = [
    ("MOVM.U4TO8.MT88", 1),
    ("MOVM.16.M832", 8),
    ("MOVM.U4TO8.M832", 9),
    ("MOVM.16.M864", 16),
    ("MOVM.U4TO8.M864", 17),
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
fn t316_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (name, ns) in LANES {
            let key = format!("{name}_R_R");
            let e = t
                .entries
                .get(key.as_str())
                .unwrap_or_else(|| panic!("{leg}: missing {key}"));
            let mg = &e.mod_groups[""];
            assert_eq!(
                mg.and_base,
                0x23au128 | ((ns as u128) << 75),
                "{leg}: {key} ab drift"
            );
            assert_eq!(mg.variable_mask, NEW_VM, "{leg}: {key} vm drift");
            let got: Vec<(u32, u32, i32)> = mg
                .fields
                .iter()
                .map(|f| (f.bits, f.shift, f.token_idx))
                .collect();
            assert_eq!(
                got,
                vec![
                    (4u32, 12u32, 0i32),
                    (8u32, 16u32, 1i32),
                    (8u32, 24u32, 2i32)
                ],
                "{leg}: {key} field shape drift"
            );
        }
        // the BUG-283 MT88 lane keeps its verified shape
        let mg = &t.entries["MOVM.16.MT88_R_R"].mod_groups[""];
        assert_eq!(mg.and_base, 0x23au128, "{leg}: MT88 ab drift");
        // pairwise ns-disjointness across every MOVM row (mechanical)
        let mut seen = std::collections::HashMap::new();
        for k in t.entries.keys().filter(|k| k.starts_with("MOVM")) {
            let ab = t.entries[k].mod_groups[""].and_base;
            let ns = (ab >> 75) & 0x1f;
            if let Some(prev) = seen.insert(ns, k.clone()) {
                panic!("{leg}: ns {ns} claimed by both {prev} and {k}");
            }
        }
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
fn t316_2_decode_law_vendor_equal() {
    // every expected string below is the nvdisasm 13.3.73 print, x4 models
    // agreeing (arb316 A/B + arb283b G)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (name, ns) in LANES {
            let base = 0x23au128 | ((ns as u128) << 75);
            for g in 0u128..8 {
                let exp = if g == 7 {
                    format!("{name} R0, R0")
                } else {
                    format!("@P{g} {name} R0, R0")
                };
                assert_eq!(
                    dec(&t, base | (g << 12)).as_deref(),
                    Some(exp.as_str()),
                    "{leg} {name} g{g}"
                );
                let expi = if g == 7 {
                    format!("@!PT {name} R0, R0")
                } else {
                    format!("@!P{g} {name} R0, R0")
                };
                assert_eq!(
                    dec(&t, base | (1 << 15) | (g << 12)).as_deref(),
                    Some(expi.as_str()),
                    "{leg} {name} inv g{g}"
                );
            }
            let cases: [(u128, String); 3] = [
                (base | (5 << 16) | (4 << 24), format!("@P0 {name} R5, R4")),
                (
                    base | (254 << 16) | (128 << 24),
                    format!("@P0 {name} R254, R128"),
                ),
                (
                    base | (255 << 16) | (255 << 24),
                    format!("@P0 {name} RZ, RZ"),
                ),
            ];
            for (w, exp) in cases {
                assert_eq!(
                    dec(&t, w).as_deref(),
                    Some(exp.as_str()),
                    "{leg} {name} payload {w:#x}"
                );
            }
            // inert bands print plain on the new lanes (no ghosts): sub-op + spot singles
            assert_eq!(
                dec(&t, base | (7 << 32)).as_deref(),
                Some(format!("@P0 {name} R0, R0").as_str()),
                "{leg} {name} sub-op inertness drift"
            );
            for b in [62u32, 63, 72, 73] {
                assert_eq!(
                    dec(&t, base | (1u128 << b)).as_deref(),
                    Some(format!("@P0 {name} R0, R0").as_str()),
                    "{leg} {name} sign-window ghost at b{b}"
                );
            }
        }
    }
}

#[test]
fn t316_3_encode_vendor_word_exact() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let cases: [(&str, u128); 6] = [
            (
                "MOVM.U4TO8.M832 R5, R4",
                0x723a | (9 << 75) | (5 << 16) | (4 << 24),
            ),
            (
                "@P3 MOVM.16.M832 R7, R19",
                0x23a | (8 << 75) | (3 << 12) | (7 << 16) | (19 << 24),
            ),
            (
                "@!P0 MOVM.U4TO8.MT88 R254, R2",
                0x23a | (1 << 75) | (1 << 15) | (254 << 16) | (2 << 24),
            ),
            (
                "@!PT MOVM.16.M864 RZ, RZ",
                0xf23a | (16 << 75) | (255 << 16) | (255 << 24),
            ),
            (
                "@P5 MOVM.U4TO8.M864 R40, R41",
                0x23a | (17 << 75) | (5 << 12) | (40 << 16) | (41 << 24),
            ),
            (
                "MOVM.16.M832 RZ, R9",
                0x723a | (8 << 75) | (255 << 16) | (9 << 24),
            ),
        ];
        for (text, wexp) in cases {
            let w = enc_res(&t, text).unwrap_or_else(|e| panic!("{leg}: {text} encode: {e}"));
            assert_eq!(w & M96, wexp & M96, "{leg}: {text} minted word drift");
            assert_eq!(
                dec(&t, w).as_deref(),
                Some(text),
                "{leg}: {text} roundtrip drift"
            );
        }
    }
}

#[test]
fn t316_4_fail_closed_residuum_doctrine() {
    // INVALIDn / INVALID3 and rc0-empty lanes: vendor prints or accepts them
    // (arb316), but they carry NO rows -- decode HOLE + encode loud-fail is
    // the pinned doctrine state (bug210/bug215 precedent).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for ns in [5u32, 6, 7, 13, 14, 15, 21, 22, 23, 24, 25, 29, 30, 31] {
            let base = 0x23au128 | ((ns as u128) << 75);
            for w in [base, base | (3 << 12), base | (5 << 16) | (4 << 24)] {
                assert!(
                    dec(&t, w).is_none(),
                    "{leg}: INVALID lane ns{ns} decoded {w:#x}"
                );
            }
        }
        for ns in [2u32, 3, 4, 10, 11, 12, 18, 19, 20, 26, 27, 28] {
            let base = 0x23au128 | ((ns as u128) << 75);
            assert!(
                dec(&t, base | (43 << 16)).is_none(),
                "{leg}: rc0-empty lane ns{ns} decoded"
            );
        }
        // kill law on an armed lane: b91 (unit kill, inside the 96-bit cut)
        // stays HOLE; b109/b122 (opex kill) sit above the engine's 96-bit
        // decode cut = documented BUG-283 invariant (not re-testable here)
        let m832u = 0x23au128 | (9 << 75);
        assert!(
            dec(&t, m832u | (1u128 << 91)).is_none(),
            "{leg}: kill b91 decoded"
        );
        for text in [
            "MOVM.INVALID5.MT88 R0, R0",
            "@P1 MOVM.INVALID7.INVALID3 R1, R2",
            "MOVM.16.INVALID3 R3, R4",
            "MOVM.U4TO8.INVALID3 R5, R6",
        ] {
            assert!(
                enc_res(&t, text).is_err(),
                "{leg}: INVALID text encoded: {text}"
            );
        }
        // BUG-283 sign bail stays armed on the new lanes (no vendor encoding)
        let err = enc_res(&t, "MOVM.U4TO8.M864 R5, -R4").unwrap_err();
        assert!(
            err.contains("BUG-283"),
            "{leg}: sign bail attribution lost: {err}"
        );
    }
}
