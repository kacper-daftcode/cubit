//! BUG-371 (F2-iter196, loop5/blind front2, 2026-09-04): HFMA2 tok4 abs
//! field closure x4 legs. Sibling of 352 (dest side) -- registered
//! 371-kand LOW at F2-iter187 (352.md sec.6, pin t352_3 escope).
//!
//! MEASUREMENT (pre-fix publish cubit-dc696dc0 CLI 7ad082cf.. / pyo3
//! 9e1c1c26.., canonical c913faa; work/bug371/measure_pre371{,b}.json):
//! authored '|R4|' on dense thin legs and '|R5|' on the UR_R forms of ALL
//! legs (incl. the 12 thick RELU _P dotted keys) silently minted the
//! GENERIC b74 = tok2 hsel cross-read (vendor decode 'R2.INVALID1'); the
//! 108 field-less rows also loud-HOLE'd b83-set vendor words on decode.
//! tok4 NEG was already field-carried @84 everywhere (correct mints).
//!
//! LAW (arb371 2,560 + arb371b 1,728 probes, nvdisasm 13.3.73 raw -b, x4
//! models SM100a/SM103a/SM120/SM121a AGREE on EVERY probe, DIVERGENT=0;
//! work/bug371/arb371_verdicts.json + arb371b_verdicts.json): b83 = tok4
//! ABS, b84 = tok4 NEG on EVERY HFMA2 Reg/UReg-tok4 shape (dense
//! ''/BF16_V2/F32/guarded, UR_R all mgs, UR_R_P dotted, keyed BF16 era
//! row, 5-reg era row), b83|b84 = '-|R|'; full 128-bit sweep on 5 bases:
//! ONLY {83,84} render a signed tok4 glyph; b74/b75 = tok2 hsel
//! cross-read ('INVALID1'/'H0_H0'); tok4 hsel [82:81] stands.
//!
//! FIX = canonical graft ONLY (canonical c913faa -> 6b7a120, patch371.py
//! replayable+idempotent; ENGINE src ZERO changes): appended
//! {bits:1, abs, shift:83, token_idx:4, _src: bug371-2026-09-04} to the
//! 108 HFMA2 mod_groups with Reg/UReg tok4 lacking the field (dense thin
//! x4 == BUG-320 donor geometry; UR_R x76; UR_R_P x24; keyed BF16 x2;
//! 5-reg x2). R_R_R_UR excluded (tok4 = UR in the Rb@32 position,
//! abs@62/neg@63 field-carried since bug270). and_base/variable_mask
//! byte-invariant (the engine carves field bits out of the match mask,
//! decoder.rs:131), no-new-claim-collisions audit per leg PASS.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B83: u128 = 1u128 << 83;
const B84: u128 = 1u128 << 84;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
// plain anchors (vendor-decoded goldens + publish-era mints)
const W_PLAIN: u128 = 0x000fc200000000040000000302017231_u128;
const W_ABS_R4: u128 = W_PLAIN | B83; // == 352's W_ABS_R4_120 (thick-legs law)
const W_NEG_R4: u128 = W_PLAIN | B84;
const W_NEGABS_R4: u128 = W_PLAIN | B83 | B84;
const W_UR: u128 = 0x000fc200080000050000000402017c31_u128;
const W_UR_ABS_R5: u128 = W_UR | B83;
const W_UR_NEG_R5: u128 = W_UR | B84;
const W_UR_NEGABS_R5: u128 = W_UR | B83 | B84;
const W_BF16: u128 = 0x000fc200002000040000000302017231_u128;
const W_BF16_ABS_R4: u128 = W_BF16 | B83;
const W_UR_BF16: u128 = 0x000fc200082000050000000402017c31_u128;
const W_UR_BF16_ABS_R5: u128 = W_UR_BF16 | B83;
const W_F32: u128 = 0x000fc200000040040000000302017231_u128;
const W_F32_ABS_R4: u128 = W_F32 | B83;
const W_GUARD_P0: u128 = 0x000fc200000000040000000302010231_u128;
const W_GUARD_P0_ABS_R4: u128 = W_GUARD_P0 | B83;
// thick RELU dotted _P base (arb371b minted, nvdisasm-verified)
const W_RELU_P1: u128 = 0x000fc200088080050000000402017c31_u128;
const W_RELU_P1_ABS_R5: u128 = W_RELU_P1 | B83;
// 352 src-sign anchors (must stay untouched)
const W_NEG_R2: u128 = 0x000fc200000001040000000302017231_u128;
const W_ABS_R2: u128 = 0x000fc200000002040000000302017231_u128;
const W_ABS_R3: u128 = 0x000fc200000000044000000302017231_u128;

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
fn t371_1_structure_census_tok4_abs_closed() {
    // Post-graft invariant: EVERY HFMA2 mod_group with a Reg/UReg token-4
    // carries a tok4 abs field; exactly one at 83 for the 108 grafted
    // rows; b83 is carved out of the claim care-mask on those rows.
    // BUG-384 flip (canonical 9713fd6): the two deleted dense era keys
    // (HFMA2.BF16_V2_R_R_R_R + HFMA2_R_R_R_R_R) carried one abs@83 field
    // each (the 371 graft on the keyed-BF16 + 5-reg rows), so dense 98->96.
    let want83 = [
        ("sm100a", 96usize),
        ("sm103a", 96usize),
        ("sm120", 96usize),
        ("sm121a", 96usize),
    ];
    for (leg, n83) in want83 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let mut cnt83 = 0usize;
        for (key, row) in raw["instructions"].as_object().unwrap() {
            if !key.starts_with("HFMA2") {
                continue;
            }
            for (mgn, mg) in row["mod_groups"].as_object().unwrap() {
                let fs = mg["fields"].as_array().unwrap();
                let t4reg = fs.iter().any(|f| {
                    f["token_idx"].as_u64() == Some(4)
                        && matches!(f["extraction"].as_str(), Some("reg") | Some("ureg"))
                });
                if !t4reg {
                    continue;
                }
                let abs: Vec<&serde_json::Value> = fs
                    .iter()
                    .filter(|f| {
                        f["token_idx"].as_u64() == Some(4)
                            && f["extraction"].as_str() == Some("abs")
                    })
                    .collect();
                assert!(
                    !abs.is_empty(),
                    "{leg} {key}[{mgn}]: Reg/UReg tok4 without an abs field"
                );
                if abs.iter().any(|f| f["shift"].as_u64() == Some(83)) {
                    cnt83 += 1;
                    assert_eq!(
                        abs.iter()
                            .filter(|f| f["shift"].as_u64() == Some(83))
                            .count(),
                        1,
                        "{leg} {key}[{mgn}]: duplicate abs@83"
                    );
                    // count basis: thin = 2 dense + 2 UR_R (371 graft); thick = 36 dense
                    // (BUG-320) + 12 dense _P dotted (pre-existing) + 36 UR_R + 12 UR_R_P +
                    // keyed BF16 + 5-reg (371 graft) = 98.
                    // BUG-381 basis (canonical 3cb31e4): era legs 4 -> 96
                    // (sparse 0x231/0x7c31 lattice completion: 68 new mgs +
                    // 24 new dotted keys all clone donors carrying abs@83).
                    let vm = u128::from_str_radix(
                        mg["variable_mask"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(0);
                    let mut fld = 0u128;
                    for f in fs {
                        let (b, s) = (
                            f["bits"].as_u64().unwrap() as u32,
                            f["shift"].as_u64().unwrap() as u32,
                        );
                        fld |= ((1u128 << b) - 1) << s;
                    }
                    let care = M96 & !(vm | fld);
                    assert_eq!((care >> 83) & 1, 0, "{leg} {key}[{mgn}]: b83 still pinned");
                }
            }
        }
        assert_eq!(cnt83, n83, "{leg}: abs@83 tok4 field count drift");
    }
}

#[test]
fn t371_2_authored_mints_law_words_x4() {
    for leg in LEGS {
        let t = tab(leg);
        for (txt, want) in [
            ("HFMA2 R1, R2, R3, R4", W_PLAIN),
            ("HFMA2 R1, R2, R3, |R4|", W_ABS_R4),
            ("HFMA2 R1, R2, R3, -R4", W_NEG_R4),
            ("HFMA2 R1, R2, R3, -|R4|", W_NEGABS_R4),
            ("HFMA2 R1, R2, UR4, R5", W_UR),
            ("HFMA2 R1, R2, UR4, |R5|", W_UR_ABS_R5),
            ("HFMA2 R1, R2, UR4, -R5", W_UR_NEG_R5),
            ("HFMA2 R1, R2, UR4, -|R5|", W_UR_NEGABS_R5),
            ("HFMA2.BF16_V2 R1, R2, R3, |R4|", W_BF16_ABS_R4),
            ("HFMA2.BF16_V2 R1, R2, UR4, |R5|", W_UR_BF16_ABS_R5),
        ] {
            let w = enc_res(&t, txt).unwrap_or_else(|e| panic!("{leg}: mint failed {txt:?}: {e}"));
            assert_eq!(w, want, "{leg}: law-word drift for {txt:?}");
            assert_eq!(
                w & (1u128 << 74),
                0,
                "{leg}: {txt:?} still mints the b74 cross-read"
            );
        }
        // guarded variant (predicate-independence of the sign window)
        let w = enc_res(&t, "@P0 HFMA2 R1, R2, R3, |R4|").expect("guarded mint");
        assert_eq!(w, W_GUARD_P0_ABS_R4, "{leg}: guarded abs word drift");
        // RELU _P dotted key on the thick legs (12 grafted keys)
        if leg == "sm120" || leg == "sm121a" {
            for (txt, want) in [
                ("HFMA2.F32 R1, R2, R3, |R4|", W_F32_ABS_R4),
                ("HFMA2.RELU R1, R2, UR4, |R5|, P1", W_RELU_P1_ABS_R5),
            ] {
                let w = enc_res(&t, txt).unwrap_or_else(|e| panic!("{leg}: {txt:?}: {e}"));
                assert_eq!(w, want, "{leg}: law-word drift for {txt:?}");
            }
        }
    }
}

#[test]
fn t371_3_decode_hole_closed_and_roundtrip_x4() {
    for leg in LEGS {
        let t = tab(leg);
        for (w, frag) in [
            (W_ABS_R4, "|R4|"),
            (W_NEG_R4, "-R4"),
            (W_NEGABS_R4, "-|R4|"),
            (W_UR_ABS_R5, "|R5|"),
            (W_UR_NEGABS_R5, "-|R5|"),
            (W_BF16_ABS_R4, "|R4|"),
            (W_UR_BF16_ABS_R5, "|R5|"),
            (W_GUARD_P0_ABS_R4, "|R4|"),
        ] {
            let d = dec(&t, w).unwrap_or_else(|| panic!("{leg}: b83/b84 word still HOLE: {w:#x}"));
            assert!(d.contains(frag), "{leg}: decode lost {frag:?} in {d:?}");
            assert!(
                !d.contains("INVALID"),
                "{leg}: cross-read glyph survives in {d:?}"
            );
            let re = enc_res(&t, d.trim()).expect("re-encode");
            assert_eq!(re, w, "{leg}: roundtrip drift for {d:?}");
        }
        if leg == "sm120" || leg == "sm121a" {
            let d = dec(&t, W_RELU_P1_ABS_R5).expect("dotted _P decode");
            assert!(d.contains("|R5|"), "{leg}: _P decode lost |R5|: {d:?}");
            assert!(d.contains("P1"), "{leg}: _P decode lost pred: {d:?}");
        }
    }
}

#[test]
fn t371_4_no_regression_plain_and_src_signs() {
    // The grafts touch ONLY tok4-abs coverage: plain mints byte-exact,
    // src-sign anchors (352/343/327/320 laws) byte-exact, and no text
    // drifts across the decode->render->encode loop.
    for leg in LEGS {
        let t = tab(leg);
        for (txt, want) in [
            ("HFMA2 R1, R2, R3, R4", W_PLAIN),
            ("HFMA2 R1, -R2, R3, R4", W_NEG_R2),
            ("HFMA2 R1, |R2|, R3, R4", W_ABS_R2),
            ("HFMA2 R1, R2, |R3|, R4", W_ABS_R3),
            ("HFMA2 R1, R2, UR4, R5", W_UR),
        ] {
            let w = enc_res(&t, txt).expect("mint");
            assert_eq!(w, want, "{leg}: regression for {txt:?}");
        }
        let d = dec(&t, W_PLAIN).expect("plain decodes");
        assert_eq!(
            d.trim(),
            "HFMA2 R1, R2, R3, R4",
            "{leg}: plain decode drift"
        );
        let d = dec(&t, W_UR).expect("UR plain decodes");
        assert_eq!(d.trim(), "HFMA2 R1, R2, UR4, R5", "{leg}: UR plain drift");
    }
}

#[test]
fn t371_5_provenance_and_manifest_ratchet() {
    // Every grafted field carries the 371 attribution; the vendored tables
    // pin canonical 6b7a120 in tables/SOURCE.json; record/mg counts stay
    // pinned (the graft adds FIELDS only, no mgs/rows).
    for leg in LEGS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        assert!(
            raw["_meta"]["bug371"]
                .as_str()
                .unwrap_or("")
                .contains("BUG-371"),
            "{leg}: _meta bug371 provenance missing"
        );
        let mut src_cnt = 0usize;
        for (key, row) in raw["instructions"].as_object().unwrap() {
            if !key.starts_with("HFMA2") {
                continue;
            }
            for mg in row["mod_groups"].as_object().unwrap().values() {
                for f in mg["fields"].as_array().unwrap() {
                    if f["_src"].as_str() == Some("bug371-2026-09-04") {
                        src_cnt += 1;
                        assert_eq!(f["extraction"].as_str(), Some("abs"));
                        assert_eq!(f["shift"].as_u64(), Some(83));
                        assert_eq!(f["token_idx"].as_u64(), Some(4));
                        assert_eq!(f["bits"].as_u64(), Some(1));
                    }
                }
            }
        }
        // BUG-384 flip (canonical 9713fd6): the two deleted dense era keys
        // (HFMA2.BF16_V2_R_R_R_R + HFMA2_R_R_R_R_R on sm120 + sm121a)
        // carried one 371-grafted abs@83 field each, so the dense
        // attribution count is 50 - 2 = 48.
        let want = match leg {
            "sm100a" | "sm103a" => 4,
            "sm120" | "sm121a" => 48,
            _ => unreachable!(),
        };
        assert_eq!(src_cnt, want, "{leg}: graft attribution count drift");
    }
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    // BUG-373/374/375 flip (canonical e7f3e6f): the LDGSTS desc graft wave
    // re-pins the manifest; BUG-371's own graft invariants above stand.
    // [FLIP with attribution, BUG-409 / F2-iter224]: manifest pin moves
    // with the canonical sm100a LDC_R_cAI|S16 vm|b37 graft (+cubit decoder arm).
    // [FLIP with attribution, BUG-393 / F2-iter214]: manifest pin moves
    // with the 0x7c31 h0nh1 graft (canonical d908ee9 = BUG-395; rides 74a06b7 = BUG-405/406 HADD2 release + HFMA2 two-imm slot graft = BUG-405/406; rides 19363f6 = BUG-400, which rode 5d32aec = BUG-398, 96f196b = BUG-402, dd477eb = BUG-407, 8f2571b = BUG-393).
    assert!(
        // [FLIP with attribution, BUG-384 / F2-iter205]: manifest pin moves
        // with the canonical era-key hygiene delete (9713fd6).
        m["base_revision"].as_str().unwrap().starts_with("d560e99"),
        "SOURCE.json must pin canonical 52cb73c [was 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422, 0eddad5 = BUG-420] (BUG-425+425b grafts F2-iter238(A/B) z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
}
