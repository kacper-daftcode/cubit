//! BUG-280 (F2-iter155, loop5/blind front2, 2026-08-30): QMMA.16816
//! .F16.E4M3.E4M3 lane (0x27a lattice, ab 0x400000000000000027a) b74 vendor
//! text-inert reclaim, legs sm120+sm121a (canonical bug280 cut 842aa05,
//! ride-after d97734f/BUG-306). Registered 280-kand LOW at F2-iter141 (276
//! report sec.6; evidence arb276 A). Measurement-first (work/bug280):
//! arb280 = 1,216 probes (304 words x4 models SM100a/103a/120/121a, ZERO
//! disagreement); routex280 FULL 2,406-cubin battery x4 legs (pub
//! pyo3-d97734f): exactly 1 family word (qc_75_77.cubin .text.qd@0xe0,
//! b74=1, decodes vendor-exact) and ZERO near-miss words under the widened
//! mask => graft corpus-neutral by construction.
//!
//! LAW (x4 models agree on every probe): b74 is vendor TEXT-INERT on the
//! lane for every guard {0,1,2,5,7} x payload regs x tok2@72/tok3@63 negs
//! x vm-window fill (decode text identical with b74 on/off, rc=0). The
//! INERT law holds on ALL 106 unique QMMA sub-lane bases of the 0x27a
//! lattice (arb280 C family documentary, feed for the owner-scope family
//! audit) -- only the registered lane is armed here. Neighbor singles on
//! the bare lattice: b75=.16832, b76=INVALID2, b77=F32, b78/b79=E5M2
//! selects, b80=SP 6-tok, b83=E2M3.E4M3, b87/b88=UP suffix, b91=KILL
//! (rc=1 x4) => all stay care-bits. Donor legs (sm100a/sm103a) reject
//! the whole lattice (rc=1 every probe; zero QMMA rows there).
//! PRE-FIX (pub pyo3-d97734f, work/bug280/measure_pre280.json): every
//! b74=0 lane word = decode HOLE on both legs (LOUD, never silent);
//! b74=1 words decode vendor-exact. Encode mints and_base => b74=1 on
//! every authored form (no authored path to b74=0; the graft leaves
//! minting byte-identical).
//! GRAFT (patch280.py, replayable+idempotent, re-run skip-idem x8):
//! variable_mask |= (1<<74) on the 4 lane rows (R + P0/P2/P5) x2 legs =
//! 8 row-instances; and_base (b74 bake kept = canonical mint) and fields
//! BYTE-UNCHANGED. Reclaim doctrine 276 (80,81) / 282 (62,63) / 284
//! ([95:82]\b91). LOAD-BEARING roundtrip note: decode(b74=0 word) ==
//! vendor-equal lane text; re-encode mints the canonical b74=1 word =
//! text-stable and coincidentally byte-equal to the one corpus witness;
//! word-lossy ONLY on vendor-inert payload the toolchain never emits.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B74: u128 = 1u128 << 74;
const LANE_AB: u128 = 0x400000000000000027au128;
const VM_R: u128 = 0x1c000000000005ff800000fffffff000u128; // _R post-widen
// 2026-11-04 (blackwell-isa, session T-3): the three `_P0/_P2/_P5` era keys are retired into
// `_meta.key_aliases` -> `QMMA.16816.F16.E4M3.E4M3_R_R_R_R` (nvdisasm names their words with the
// plain mnemonic; the plain row's mask was a superset, the fields identical). cubit resolves the
// alias as an encoder-visible copy of the plain row, so the keys still exist for these pins and
// carry VM_R; the old `_Pn` mask (0x8000000000005ff800000fffffff000) is history.
const VM_PN: u128 = VM_R;
// 2026-11-07 (session G run 5, tools/probes/re_sm120_rows.py --family tensor, nvdisasm 13.1): the sm120 lane row is
// measured field by field over the whole word -- the mask is exactly its fields (guard, the four registers, `-Ra` 72,
// `-Rb` 63 and the `.reuse` of the B operand at 123, which the vendor names and the harvest never declared); the
// text-inert bit 74 fails closed like every measured family's inert bits (T-10's convention), the bake b74 = 1 stays
// the canonical mint. The BUG-280 reclaim (b74 tolerated) stands on sm121a.
const VM_R_120: u128 = 0x8000000000001ff800000fffffff000u128;
const KEYS_R: &str = "QMMA.16816.F16.E4M3.E4M3_R_R_R_R";
const KEYS_PN: [&str; 3] = [
    "QMMA.16816.F16.E4M3.E4M3_P0_R_R_R_R",
    "QMMA.16816.F16.E4M3.E4M3_P2_R_R_R_R",
    "QMMA.16816.F16.E4M3.E4M3_P5_R_R_R_R",
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
fn t280_1_structure_widen_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (nk, vmexp) in [
            (KEYS_R, VM_R),
            (KEYS_PN[0], VM_PN),
            (KEYS_PN[1], VM_PN),
            (KEYS_PN[2], VM_PN),
        ] {
            let e = t
                .entries
                .get(nk)
                .unwrap_or_else(|| panic!("{leg}: missing lane key {nk}"));
            assert_eq!(e.mod_groups.len(), 1, "{leg}: {nk} must be mg '' only");
            let g = &e.mod_groups[""];
            assert_eq!(
                g.and_base, LANE_AB,
                "{leg}: {nk} and_base drift (b74 bake must stay = canonical mint)"
            );
            let measured = leg == "sm120";
            assert_eq!(
                g.variable_mask, if measured { VM_R_120 } else { vmexp },
                "{leg}: {nk} vmask drift (280 widen / G run 5 measurement)"
            );
            // b74 widened on sm121a; on sm120 the measured row fails closed on it (text-inert); the measured
            // discriminants + kill-bit stay care on both
            assert_eq!(
                (g.variable_mask >> 74) & 1,
                if measured { 0 } else { 1 },
                "{leg}: {nk} b74 in vmask (280 widen vs the sm120 measurement)"
            );
            for b in [91u32, 75, 76, 77, 78, 79, 80, 83] {
                assert_eq!(
                    (g.variable_mask >> b) & 1,
                    0,
                    "{leg}: {nk} discriminant/kill b{b} leaked into vmask"
                );
                assert_eq!(
                    (g.and_base >> b) & 1,
                    0,
                    "{leg}: {nk} and_base drift on b{b}"
                );
            }
            // fields: guard@12 + {reg@16, neg@72+reg@24, neg@63+reg@32, reg@64} (+ the measured `.reuse`@123 of the
            // B operand on sm120)
            assert_eq!(g.fields.len(), if measured { 8 } else { 7 }, "{leg}: {nk} field count drift");
        }
    }
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for nk in [KEYS_R].iter().chain(KEYS_PN.iter()) {
            assert!(
                !t.entries.contains_key(*nk),
                "{leg}: donor carries {nk} (lattice is 120/121a-only)"
            );
        }
    }
}

#[test]
fn t280_2_decode_law_vendor_exact() {
    // arb280 A pairs: b74 on/off must print IDENTICAL vendor text, x2 legs.
    let pay: u128 = (7 << 16) | (19 << 24) | (42 << 32) | (55 << 64);
    let cases: [(u128, &str); 8] = [
        (0x27a, "@P0 QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0"),
        (0x27a | B74, "@P0 QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0"),
        (
            0x27a | (5 << 12),
            "@P5 QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0",
        ),
        (
            0x27a | (5 << 12) | B74,
            "@P5 QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0",
        ),
        (
            0x27a | pay,
            "@P0 QMMA.16816.F16.E4M3.E4M3 R7, R19, R42, R55",
        ),
        (
            0x27a | pay | B74,
            "@P0 QMMA.16816.F16.E4M3.E4M3 R7, R19, R42, R55",
        ),
        (
            0x27a | (1 << 72) | (1 << 63),
            "@P0 QMMA.16816.F16.E4M3.E4M3 R0, -R0, -R0, R0",
        ),
        (
            0x27a | (1 << 72) | (1 << 63) | B74,
            "@P0 QMMA.16816.F16.E4M3.E4M3 R0, -R0, -R0, R0",
        ),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (w, exp) in cases {
            // sm120 (G run 5 measurement): the b74 = 0 twin fails closed (text-inert bit outside the measured
            // fields); the canonical b74 = 1 word carries the vendor text. sm121a: the 280 reclaim, both decode.
            if leg == "sm120" && (w >> 74) & 1 == 0 {
                assert_eq!(dec(&t, w).as_deref(), None, "{leg}: b74 = 0 twin must fail closed {w:#x}");
                continue;
            }
            assert_eq!(
                dec(&t, w).as_deref(),
                Some(exp),
                "{leg}: lane law drift {w:#x}"
            );
        }
        // PT-guard bare form (guard=7) prints without prefix, b74-free and not
        if leg == "sm120" {
            assert_eq!(dec(&t, 0x27a | (7 << 12)).as_deref(), None, "{leg}: guard7 b74 = 0 twin must fail closed");
        } else {
            assert_eq!(
                dec(&t, 0x27a | (7 << 12)).as_deref(),
                dec(&t, 0x27a | (7 << 12) | B74).as_deref(),
                "{leg}: guard7 b74 pair drift"
            );
        }
        assert_eq!(
            dec(&t, 0x27a | (7 << 12) | B74).as_deref(),
            Some("QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0"),
            "{leg}: guard7 lane text drift"
        );
    }
}

#[test]
fn t280_3_encode_mint_and_reclaim_semantics() {
    let t = tab("sm120");
    for text in [
        "QMMA.16816.F16.E4M3.E4M3 R0, R0, R0, R0",
        "@P5 QMMA.16816.F16.E4M3.E4M3 R7, R19, R42, R55",
        "@P0 QMMA.16816.F16.E4M3.E4M3 R0, -R0, -R0, R0",
        "@!P2 QMMA.16816.F16.E4M3.E4M3 R1, R2, R3, R4",
    ] {
        let w = enc_res(&t, text).unwrap_or_else(|e| panic!("encode {text} failed: {e}"));
        assert_eq!(
            (w >> 74) & 1,
            1,
            "mint must keep the ab b74 bake: {text} -> {w:#x}"
        );
        let idx = DecodeIndex::build(&t);
        let rt = to_sass(&idx.decode(w & M96, 0, &t).unwrap());
        assert_eq!(rt, text, "authored roundtrip drift: {text}");
    }
    // The one corpus witness (routex280): decode(b74=0 twin) == text of the
    // b74=1 word, and re-encode of that text == the canonical b74=1 word.
    const WIT: u128 = 0x4340000000c0834727au128;
    for leg in ["sm120", "sm121a"] {
        let tl = tab(leg);
        let t1 = dec(&tl, WIT).unwrap();
        assert_eq!(
            t1, "QMMA.16816.F16.E4M3.E4M3 R52, R8, R12, R52",
            "{leg}: witness text drift"
        );
        // sm120 (G run 5 measurement): the b74 = 0 twin fails closed; sm121a keeps the reclaim
        let t0 = if leg == "sm120" {
            assert!(dec(&tl, WIT & !B74).is_none(), "{leg}: b74=0 twin must fail closed on the measured row");
            t1.clone()
        } else {
            let t0 = dec(&tl, WIT & !B74).unwrap();
            assert_eq!(t0, t1, "{leg}: b74=0 twin must decode vendor-equal");
            t0
        };
        let w = enc_res(&tl, &t0).expect("re-encode of reclaimed text");
        assert_eq!(
            w & M96,
            WIT & M96,
            "{leg}: re-encode must mint canonical b74=1 word"
        );
    }
}

#[test]
fn t280_4_care_neighbors_hold() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // vendor kill-bit b91 stays a hole
        assert!(
            dec(&t, 0x27a | (1 << 91)).is_none(),
            "{leg}: b91 kill word must NOT decode"
        );
        assert!(
            dec(&t, 0x27a | (1 << 91) | B74).is_none(),
            "{leg}: b91+b74 must NOT decode"
        );
        // measured discriminants stay care: single-bit probes never claim the
        // armed E4M3.E4M3 lane (engine holes the bare singles today; sibling
        // family arming = owner audit scope per the 280 registration).
        for (b, what) in [
            (75u32, ".16832"),
            (76, ".INVALID2"),
            (77, ".F32"),
            (83, ".E2M3.E4M3"),
        ] {
            let d = dec(&t, 0x27a | (1 << b));
            if let Some(txt) = &d {
                assert!(
                    !txt.contains("QMMA.16816.F16.E4M3.E4M3"),
                    "{leg}: b{b} single ({what}) must not claim the armed lane: {txt}"
                );
            }
        }
    }
    // donors reject the entire lattice (rc=1 x4 models vendor-side too)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            dec(&t, 0x27a).is_none(),
            "{leg}: donor decodes bare lattice"
        );
        assert!(
            dec(&t, 0x27a | B74).is_none(),
            "{leg}: donor decodes b74 lane"
        );
    }
}

#[test]
fn t280_5_family_scope_documented() {
    // Family documentary anchors (arb280 C, NOT armed): sibling lanes bake b74
    // as part of their own signatures and their b74=0 words stay honest holes
    // by registration scope (family-wide arm = owner audit). b74=1 variants
    // decode vendor-exact via their own rows.
    const E2M3_AB: u128 = 0x280400000000000000027au128; // QMMA.16816.F16.E2M3.E2M3 row ab
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, E2M3_AB).as_deref(),
            Some("@P0 QMMA.16816.F16.E2M3.E2M3 R0, R0, R0, R0"),
            "{leg}: E2M3.E2M3 b74=1 row drift"
        );
        assert!(
            dec(&t, E2M3_AB & !B74).is_none(),
            "{leg}: E2M3.E2M3 b74=0 word unexpectedly armed (280 arms ONLY the E4M3.E4M3 lane)"
        );
    }
}
