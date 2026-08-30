//! BUG-279 (F2-iter142, loop5/blind front2, 2026-08-29): HFMA2 packed-f16
//! imm family tok3 sign/hsel arming + FTZ/OOB suffix forms, legs
//! sm120+sm121a (canonical e819129) + printer/encoder arms.
//!
//! Laws (arb279 B-F sets + arb279b FULL 5-bit suffix sweep [80:76] x b85,
//! nvdisasm 13.3.73 raw -b; x4 models SM100a/103a/120/121a agree byte-for-byte
//! on every probe):
//!   tok3: [82:81] 2-bit = 0 '' / 1 '.F32' / 2 '.H0_H0' / 3 '.H1_H1';
//!   abs@83 | neg@84 compose freely ('-|RZ|.F32' etc.).
//!   mnemonic: b78=.F32, b77=.SAT, b79=.RELU(+trailing pred 3b@87/inv@90,
//!   PT(7,0) elided), {b80,b76} = 2-bit enum 0='' 1=.FMZ 2=.FTZ 3=.OOB.
//!   legal non-RELU: all F in 0..7 and 16..23; RELU: F in {8,9,12,13,24,25,
//!   28,29}; SAT+RELU (and FTZ+SAT+RELU) = vendor rc=1 => holes.
//! routex279 FULL 2,406-cubin battery (published cubit_py-dc3a59e, canonical
//! 56d241d tables): 97,337 family-fingerprint decodes both legs, ALL mg '';
//! [86:80]==0 and [75:72]==1 (neg only) on every word; 0 in-fingerprint
//! holes => graft corpus-neutral by construction.
//! PRE-FIX (pub dc3a59e measured, nvdisasm-verified): decode of every probe
//! was a HOLE (fail-closed); ENCODE silently misrouted tok3 signs into the
//! tok4-imm sign bit ('HFMA2 R3, -RZ, -RZ, 0, 0' encoded to a word nvdisasm
//! reads 'HFMA2 R3, -RZ, RZ, -0.0, 0' = SILENT WRONG-CODE; '|RZ|' -> '2',
//! '-|RZ|' -> '-2') and silently DROPPED tok3 hsel and '.H0_NH1' texts.
//! GRAFT (both legs, parents II_FI/FI_FI/II_II): tok3 fields (neg@84, abs@83,
//! hsel2b@81) on all rows + 8 FTZ/OOB suffix mgs + 4 RELU PT-baked mgs +
//! 4 dotted _P keys (HFMA2.{FTZ|OOB|F32.FTZ|F32.OOB}.RELU_*_P). Engine arms:
//! printer tok3 hsel v1='.F32' + mod_priority {FMZ,FTZ,OOB}=slot2; encoder
//! '.F32' on tok3 -> 1, '.H0_H1'/'.H0_NH1' on tok3 -> fail-closed.
//! Registered (stay holes, fail-closed): b85 .BF16_V2 cross-key family
//! (b85+b78 = .INVALID3 x4) = next-candidate; b86 '.H0_NH1' (271-class,
//! INVALID5/6 combos); tok2 hsel v1 era-vs-'.INVALID1' residual (270-era).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
// FI_FI/II_II encode region (b72 baked neg@72 on the era rows) = arb279 host
// D0 payload; decode law host.
const FIB: u128 = 0x000001ff00000000ff037431;
const B76: u128 = 1 << 76;
const B77: u128 = 1 << 77;
const B78: u128 = 1 << 78;
const B79: u128 = 1 << 79;
const B80: u128 = 1 << 80;
const PARENTS: [&str; 3] = [
    "HFMA2_R_R_R_II_FI",
    "HFMA2_R_R_R_FI_FI",
    "HFMA2_R_R_R_II_II",
];
fn ex_matches_shift_bits(got_s: u32, got_b: u32, s: u32, b: u32) -> bool {
    got_s == s && got_b == b
}
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
fn t279_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for p in PARENTS {
            let mgs = &t.entries[p].mod_groups;
            // 12 era mgs (274 state) + 8 FTZ/OOB + 4 RELU PT-baked
            assert_eq!(mgs.len(), 24, "{leg}|{p}: mg count drift");
            for mg in mgs.values() {
                // tok3 sign/hsel armed on EVERY row, with vm covering the bits
                let vm: u128 = mg.variable_mask.into();
                for (ex, shift, bits) in [
                    (Extraction::Neg, 84u32, 1u32),
                    (Extraction::Abs, 83, 1),
                    (Extraction::HalfSel, 81, 2),
                ] {
                    assert!(
                        mg.fields.iter().any(|f| f.extraction == ex
                            && ex_matches_shift_bits(f.shift, f.bits, shift, bits)
                            && f.token_idx == 3),
                        "{leg}|{p}: missing tok3 ({ex:?}, {shift}, {bits})"
                    );
                }
                assert_eq!(
                    vm & ((3 << 81) | (3 << 83)),
                    (3 << 81) | (3 << 83),
                    "{leg}|{p}: vm missing tok3 window"
                );
            }
            for mg in [
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
            ] {
                assert!(mgs.contains_key(mg), "{leg}|{p}: mg {mg} missing");
            }
            let sig = p.strip_prefix("HFMA2_").unwrap();
            for dot in ["FTZ", "OOB", "F32.FTZ", "F32.OOB"] {
                let k = format!("HFMA2.{dot}.RELU_{sig}_P");
                let e = t
                    .entries
                    .get(&k)
                    .unwrap_or_else(|| panic!("{leg}: {k} missing"));
                let g = &e.mod_groups[""];
                assert!(
                    g.fields
                        .iter()
                        .any(|f| f.extraction == Extraction::Pred && f.shift == 87),
                    "{k}: pred field missing"
                );
                assert!(
                    g.fields
                        .iter()
                        .any(|f| f.extraction == Extraction::HalfSel && f.shift == 81),
                    "{k}: tok3 hsel field missing"
                );
            }
            // illegal carrier combos keep NO row
            for mg in [
                "SAT,RELU",
                "F32,SAT,RELU",
                "FMZ,SAT,RELU",
                "FTZ,SAT,RELU",
                "F32,FTZ,SAT,RELU",
                "OOB,SAT,RELU",
                "F32,OOB,SAT,RELU",
            ] {
                assert!(!mgs.contains_key(mg), "{leg}|{p}: illegal mg {mg} present");
            }
        }
        // b85 stays masked out (decode hole); b86 = BUG-271 h0nh1-armed
        // window (F2-iter143 flip: vm bit + field on every armed row —
        // the full 271 structure pin lives in tests/bug271_h0nh1.rs)
        for p in PARENTS {
            let g = &t.entries[p].mod_groups[""];
            let vm: u128 = g.variable_mask.into();
            assert_eq!(vm & (1 << 85), 0, "{leg}|{p}: b85 variable");
            assert_ne!(vm & (1 << 86), 0, "{leg}|{p}: 271 b86 arm lost");
        }
    }
    // donors byte-untouched by construction: sm100a/sm103a family rows keep
    // the pre-279 shape (no tok3 hsel, no FTZ mg); a donor leg without the
    // family row at all is equally fine
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        if let Some(e) = t.entries.get("HFMA2_R_R_R_II_FI") {
            assert!(e.mod_groups.len() == 1, "{leg}: donor grafted?!");
            let g = &e.mod_groups[""];
            assert!(
                !g.fields
                    .iter()
                    .any(|f| f.extraction == Extraction::HalfSel && f.shift == 81),
                "{leg}: donor touched (tok3 hsel)"
            );
        }
    }
}

#[test]
fn t279_2_decode_laws() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let cases: &[(u128, &str)] = &[
            // FTZ/OOB mnemonic forms (arb279b sweep, x4-agree texts)
            (FIB | B80, "HFMA2.FTZ R3, -RZ, RZ, 0, 0"),
            (FIB | B80 | B76, "HFMA2.OOB R3, -RZ, RZ, 0, 0"),
            (FIB | B80 | B77, "HFMA2.FTZ.SAT R3, -RZ, RZ, 0, 0"),
            (FIB | B80 | B76 | B77, "HFMA2.OOB.SAT R3, -RZ, RZ, 0, 0"),
            (FIB | B80 | B78, "HFMA2.F32.FTZ R3, -RZ, RZ, 0, 0"),
            (FIB | B80 | B78 | B76, "HFMA2.F32.OOB R3, -RZ, RZ, 0, 0"),
            (FIB | B80 | B78 | B77, "HFMA2.F32.FTZ.SAT R3, -RZ, RZ, 0, 0"),
            (
                FIB | B80 | B78 | B76 | B77,
                "HFMA2.F32.OOB.SAT R3, -RZ, RZ, 0, 0",
            ),
            // PT-elided (7,0) prints bare text both legs
            (
                FIB | B80 | B79 | (7 << 87),
                "HFMA2.FTZ.RELU R3, -RZ, RZ, 0, 0",
            ),
            // tok3 sign/hsel laws (arb279 B)
            (FIB | (1 << 81), "HFMA2 R3, -RZ, RZ.F32, 0, 0"),
            (FIB | (2 << 81), "HFMA2 R3, -RZ, RZ.H0_H0, 0, 0"),
            (FIB | (3 << 81), "HFMA2 R3, -RZ, RZ.H1_H1, 0, 0"),
            (FIB | (1 << 83), "HFMA2 R3, -RZ, |RZ|, 0, 0"),
            (FIB | (1 << 84), "HFMA2 R3, -RZ, -RZ, 0, 0"),
            (FIB | (3 << 83), "HFMA2 R3, -RZ, -|RZ|, 0, 0"),
            (FIB | (1 << 81) | (1 << 83), "HFMA2 R3, -RZ, |RZ|.F32, 0, 0"),
            (
                FIB | (3 << 81) | (1 << 84),
                "HFMA2 R3, -RZ, -RZ.H1_H1, 0, 0",
            ),
            (
                FIB | (1 << 81) | (3 << 83),
                "HFMA2 R3, -RZ, -|RZ|.F32, 0, 0",
            ),
            // combination with suffix mg (arb279 A/B composability)
            (
                FIB | B80 | (3 << 81) | (1 << 84),
                "HFMA2.FTZ R3, -RZ, -RZ.H1_H1, 0, 0",
            ),
        ];
        for (w, want) in cases {
            let got = dec(&t, w & M96).unwrap_or_else(|| panic!("{leg}: hole at {want}"));
            assert_eq!(got, *want, "{leg}: decode {want}");
        }
        // explicit trailing-pred RELU forms on the new _P keys: sm121a winner
        // prints the pre-existing '0x0' imm cosmetics (274 registration),
        // sm120 prints '0' — pin current behavior per leg as tripwire.
        let imm0 = if leg == "sm121a" { "0x0" } else { "0" };
        let pred_cases: &[(u128, &str, &str)] = &[
            (FIB | B80 | B79, "HFMA2.FTZ.RELU R3, -RZ, RZ, ", ", P0"),
            (
                FIB | B80 | B76 | B79,
                "HFMA2.OOB.RELU R3, -RZ, RZ, ",
                ", P0",
            ),
            (
                FIB | B80 | B78 | B79,
                "HFMA2.F32.FTZ.RELU R3, -RZ, RZ, ",
                ", P0",
            ),
            (
                FIB | B80 | B78 | B76 | B79,
                "HFMA2.F32.OOB.RELU R3, -RZ, RZ, ",
                ", P0",
            ),
            (
                FIB | B80 | B79 | (6 << 87) | (1 << 90),
                "HFMA2.FTZ.RELU R3, -RZ, RZ, ",
                ", !P6",
            ),
        ];
        for (w, head, tail) in pred_cases {
            let want = format!("{head}{imm0}, 0{tail}");
            let got = dec(&t, w & M96).unwrap_or_else(|| panic!("{leg}: hole at {want}"));
            assert_eq!(got, want, "{leg}: decode {want}");
        }
    }
}

#[test]
fn t279_3_encode_laws_and_roundtrip() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let cases: &[(&str, u128)] = &[
            // the pre-fix silent wrong-code class, now exact:
            ("HFMA2 R3, -RZ, -RZ, 0, 0", FIB | (1 << 84)),
            ("HFMA2 R3, -RZ, |RZ|, 0, 0", FIB | (1 << 83)),
            ("HFMA2 R3, -RZ, -|RZ|, 0, 0", FIB | (3 << 83)),
            ("HFMA2 R3, -RZ, RZ.F32, 0, 0", FIB | (1 << 81)),
            ("HFMA2 R3, -RZ, RZ.H0_H0, 0, 0", FIB | (2 << 81)),
            ("HFMA2 R3, -RZ, RZ.H1_H1, 0, 0", FIB | (3 << 81)),
            ("HFMA2 R3, -RZ, |RZ|.F32, 0, 0", FIB | (1 << 81) | (1 << 83)),
            (
                "HFMA2 R3, -RZ, -|RZ|.H0_H0, 0, 0",
                FIB | (2 << 81) | (3 << 83),
            ),
            ("HFMA2.FTZ R3, -RZ, RZ, 0, 0", FIB | B80),
            ("HFMA2.OOB R3, -RZ, RZ, 0, 0", FIB | B80 | B76),
            ("HFMA2.FTZ.SAT R3, -RZ, RZ, 0, 0", FIB | B80 | B77),
            ("HFMA2.OOB.SAT R3, -RZ, RZ, 0, 0", FIB | B80 | B76 | B77),
            ("HFMA2.F32.FTZ R3, -RZ, RZ, 0, 0", FIB | B80 | B78),
            ("HFMA2.F32.OOB R3, -RZ, RZ, 0, 0", FIB | B80 | B78 | B76),
            ("HFMA2.F32.FTZ.SAT R3, -RZ, RZ, 0, 0", FIB | B80 | B78 | B77),
            (
                "HFMA2.F32.OOB.SAT R3, -RZ, RZ, 0, 0",
                FIB | B80 | B78 | B76 | B77,
            ),
            (
                "HFMA2.FTZ.RELU R3, -RZ, RZ, 0, 0",
                FIB | B80 | B79 | (7 << 87),
            ),
            ("HFMA2.FTZ.RELU R3, -RZ, RZ, 0, 0, P0", FIB | B80 | B79),
            (
                "HFMA2.OOB.RELU R3, -RZ, RZ, 0, 0, P3",
                FIB | B80 | B76 | B79 | (3 << 87),
            ),
            (
                "HFMA2.F32.FTZ.RELU R3, -RZ, -RZ, 0, 0, !P6",
                FIB | B80 | B78 | B79 | (6 << 87) | (1 << 90) | (1 << 84),
            ),
            (
                "HFMA2.F32.OOB.RELU R3, -RZ, RZ.H1_H1, 0, 0, !PT",
                FIB | B80 | B78 | B76 | B79 | (7 << 87) | (1 << 90) | (3 << 81),
            ),
        ];
        for (text, want) in cases {
            let got = enc_res(&t, text).unwrap_or_else(|e| panic!("{leg}|{text}: {e}")) & M96;
            assert_eq!(got, want & M96, "{leg}|{text}: word");
            let back = dec(&t, got).unwrap_or_else(|| panic!("{leg}|{text}: decode hole"));
            let re = enc_res(&t, &back)
                .unwrap_or_else(|e| panic!("{leg}|{text}: re-encode ({back}): {e}"))
                & M96;
            assert_eq!(re, want & M96, "{leg}|{text}: roundtrip via '{back}'");
        }
        // pre-existing plain path byte-stable (corpus canonical shape):
        let w = enc_res(&t, "HFMA2 R3, -RZ, RZ, 0, 0").unwrap() & M96;
        assert_eq!(w, FIB & M96, "{leg}: plain -RZ path changed");
    }
}

#[test]
fn t279_4_fail_closed() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // vendor-ILLEGAL carriers (rc=1 x4 measured) stay fail-closed:
        for bad in [
            "HFMA2.SAT.RELU R3, -RZ, RZ, 0, 0",
            "HFMA2.FTZ.SAT.RELU R3, -RZ, RZ, 0, 0",
            "HFMA2.F32.OOB.SAT.RELU R3, -RZ, RZ, 0, 0, P0",
            // b85 BF16_V2 cross-key family: registered next-candidate
            "HFMA2.BF16_V2 R3, -RZ, RZ, 0, 0",
            "HFMA2.BF16_V2.SAT R3, -RZ, -RZ, 0, 0",
            // '.H0_NH1' single-bit is ARMED by BUG-271 (F2-iter143 flip);
            // the era-global token has no vendor encoding on this tok3:
            // era-global token has no vendor encoding on this family's tok3:
            "HFMA2 R3, -RZ, RZ.H0_H1, 0, 0",
        ] {
            assert!(enc_res(&t, bad).is_err(), "{leg}|{bad}: must fail closed");
        }
        // decode hole preserved for b85; b86 armed by BUG-271 (F2-iter143
        // flip): v4 decodes vendor-exact, INVALID combos (v5..7) hole
        assert!(
            dec(&t, (FIB | (1 << 85)) & M96).is_none(),
            "{leg}: b85 hole lost"
        );
        assert_eq!(
            dec(&t, (FIB | (1 << 86)) & M96).as_deref(),
            Some("HFMA2 R3, -RZ, RZ.H0_NH1, 0, 0"),
            "{leg}: 271 arm lost"
        );
        assert!(
            dec(&t, (FIB | (1 << 86) | (1 << 81)) & M96).is_none(),
            "{leg}: INVALID5"
        );
        assert!(
            dec(&t, (FIB | (1 << 86) | (2 << 81)) & M96).is_none(),
            "{leg}: INVALID6"
        );
        assert!(
            dec(&t, (FIB | (1 << 86) | (3 << 81)) & M96).is_none(),
            "{leg}: INVALID7"
        );
    }
}

#[test]
fn t279_5_sentinels_and_anchors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // FLIPPED F2-iter143 (BUG-271 armed): b86 = '.H0_NH1' vendor-exact
        // decode (was a hard hole; t271_2 carries the full law battery)
        assert_eq!(
            dec(&t, (FIB | (1 << 86)) & M96).as_deref(),
            Some("HFMA2 R3, -RZ, RZ.H0_NH1, 0, 0"),
            "{leg}: 271 decode"
        );
        // FLIPPED F2-iter154 (BUG-306 armed): the registered tok2 hsel v1
        // residual is CLOSED -- v1 now prints the vendor law '.INVALID1'
        // on this family too (arb279 C lattice sits inside the arb306
        // win@74 INVALID1 census, x4 models). Was the 279-era tripwire
        // pin ('.H0_H1'); flipped with attribution.
        let got = dec(&t, (FIB | (1 << 74)) & M96)
            .unwrap_or_else(|| panic!("{leg}: tok2 hsel word fell out"));
        assert_eq!(
            got, "HFMA2 R3, -RZ.INVALID1, RZ, 0, 0",
            "{leg}: BUG-306 tok2 v1 vendor law"
        );
        // corpus-canonical witness (routex279 anchor): D0 decode unchanged
        let got = dec(&t, FIB & M96).unwrap_or_else(|| panic!("{leg}: D0 hole"));
        assert_eq!(got, "HFMA2 R3, -RZ, RZ, 0, 0", "{leg}: D0 decode drift");
        // 274 graft intact (one dotted key per quadrant spot-checked)
        assert!(
            t.entries.contains_key("HFMA2.RELU_R_R_R_II_FI_P"),
            "{leg}: 274 lost"
        );
        assert!(
            t.entries.contains_key("HFMA2.F32.FMZ.RELU_R_R_R_FI_FI_P"),
            "{leg}: 274 lost"
        );
    }
    let t = tab("sm120");
    assert!(
        t.entries.contains_key("FSET.BF.F.AND_R_R_R_P"),
        "265 anchor lost"
    );
}
