//! BUG-352 (F2-iter187, loop5/blind front2, 2026-09-03): HFMA2 dest-sign
//! fail-closed arm. Registered LOW at F2-iter175 (327 report sec.6,
//! evidence corner327 dest_sign x3 + nvdisasm cross; out of 327 scope).
//! Pre-fix measured on publish cubit-d1f3abc (md5 158d892601575a21af454019a
//! 010f5c0; work/bug352/measure_pre352): EVERY legal plain-mintable HFMA2
//! shape with an authored signed dest ('-Rd'/'|Rd|'/'-|Rd|') minted the
//! byte-identical PLAIN word rc=0 (134/134 silent drops across x4 legs;
//! the other 18 texts = plain form itself refused, no armed row). The
//! generic sign emit only addresses the Ra/Rb/Rc source slots; the dest
//! glyph fell through untouched == silent author-intent drop.
//!
//! LAW (arb352, nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/
//! SM121a agreeing on every probe): per-bit sweep 0..127 on the deduped
//! set of legal plain HFMA2 base words (R_R_R_R x all live mgs,
//! R_R_UR_R '', R_R_R_FI_FI x mgs, R_R_FI_FI_R '', RELU/RELU_P dotted):
//! no single-bit perturbation of a legal HFMA2 word EVER renders a signed
//! DEST glyph on any model (dest-sign hits = 0), while signed SOURCE
//! glyphs do print from their law bits (sweep self-validation).
//! Table census x4 (this file, t352_1): zero tok1 neg/abs/negshl1 fields
//! on any HFMA2 row (the only tok1 sign fields anywhere in the shipped
//! tables are BRA/BREAK predicate slots, never Reg dests). Src signs stay
//! legal (field-carried + generic b62/63/72/73 paths, arb352 spot-cross +
//! t352_3 pins). Sibling finding OUT OF SCOPE, registered 371-kand LOW:
//! sm100a/sm103a authored '|R4|' mints b74 via the generic rc-emit and the
//! vendor reads it back as 'R2.INVALID1' (cross-read into the tok2 hsel
//! window); sm120/sm121a carry tok4 abs field-carried at b83 and decode
//! '|R4|' correctly.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
// matches the vendor-decoded goldens + publish-era mints (measure_pre352)
const W_PLAIN: u128 = 0x000fc200000000040000000302017231_u128;
const W_NEG_R2: u128 = 0x000fc200000001040000000302017231_u128;
const W_ABS_R2: u128 = 0x000fc200000002040000000302017231_u128;
const W_NEGABS_R2: u128 = 0x000fc200000003040000000302017231_u128;
const W_ABS_R3: u128 = 0x000fc200000000044000000302017231_u128;
const W_ABS_R4_120: u128 = 0x000fc200000800040000000302017231_u128;
const W_UR: u128 = 0x000fc200080000050000000402017c31_u128;
const W_UR_NEG_R2: u128 = 0x000fc200080001050000000402017c31_u128;
const W_UR_ABS_UR4: u128 = 0x000fc200080000054000000402017c31_u128;
const W_RELU_P0: u128 = 0x000fc200000080040000000003027431_u128;
const W_RELU_NP0: u128 = 0x000fc200040080040000000003027431_u128;
const W_F32_MG: u128 = 0x000fc200000040040000000302017231_u128;

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
fn t352_1_structure_census_zero_tok1_sign_fields() {
    // Data-level arm anchor: no HFMA2 row on any leg may carry a sign field
    // on token 1 (the dest). Census locked 2026-09-03 (F2-iter187):
    // HFMA2* key counts {sm100a: 10, sm103a: 10, sm120: 90, sm121a: 90}
    // after the 358-era sm121a grafts; flip WITH attribution on future
    // table grafts (the invariant itself -- zero tok1 sign fields -- is
    // the load-bearing assertion, not the count).
    // FLIP (BUG-367, F2-iter193, canonical 0933cf6): +6 HFMA2* keys on
    // the sparse legs (RELU _P dotted keys of the SAT/FTZ/OOB closure:
    // .FTZ.RELU/.OOB.RELU/.F32.FTZ.RELU/.F32.OOB.RELU/.BF16_V2.FTZ.RELU/
    // .BF16_V2.OOB.RELU _R_R_R_FI_FI_P) = 16/16; dense stand.
    // FLIP (BUG-381, F2-iter203, canonical 3cb31e4): +24 HFMA2* keys on
    // the sparse legs (sparse 0x231/0x7c31 lattice completion: 12 RELU _P
    // dotted keys per family on HFMA2_R_R_R_R + HFMA2_R_R_UR_R) = 40/40;
    // dense stand.
    // FLIP (BUG-384, F2-iter205, canonical 9713fd6): -2 HFMA2* keys per
    // dense leg (harvest-junk era keys HFMA2.BF16_V2_R_R_R_R +
    // HFMA2_R_R_R_R_R deleted; arb384 measured live WRONG decode cells on
    // the 5-reg row) = 88/88.
    let want_counts = [
        ("sm100a", 40usize),
        ("sm103a", 40),
        ("sm120", 88),
        ("sm121a", 88),
    ];
    for (leg, n) in want_counts {
        let t = tab(leg);
        let keys: Vec<&String> = t
            .entries
            .keys()
            .filter(|k| k.starts_with("HFMA2"))
            .collect();
        assert_eq!(keys.len(), n, "{leg}: HFMA2* key census drift");
        for k in keys {
            let e = t.entries.get(k).unwrap();
            for (mg, g) in e.mod_groups.iter() {
                for f in g.fields.iter() {
                    assert!(
                        !(f.token_idx == 1
                            && matches!(
                                f.extraction,
                                cubit::table::Extraction::Neg
                                    | cubit::table::Extraction::NegShl1
                                    | cubit::table::Extraction::Abs
                            )),
                        "{leg}: {k} mg {mg:?} MUST NOT carry a tok1 sign field (352)"
                    );
                }
            }
        }
        // plain legacy mint stays byte-exact per leg
        let w = enc_res(&t, "HFMA2 R1, R2, R3, R4").expect("plain must mint");
        assert_eq!(w, W_PLAIN, "{leg}: plain word drift");
    }
}

#[test]
fn t352_2_signed_dest_refused_with_attribution() {
    // Wherever the plain form is encodable, EVERY signed-dest spelling must
    // now fail closed with the BUG-352 tag; where the plain form has no row
    // (e.g. dense F32/FMZ mgs on sm100a/sm103a) the text was already
    // refused pre-fix and is out of the arm's reach by construction.
    let dense_mgs = ["", ".F32", ".FMZ", ".F32.FMZ", ".BF16_V2"];
    let dest_signs = ["-R1", "|R1|", "-|R1|"];
    let mut armed_refusals = 0usize;
    for leg in LEGS {
        let t = tab(leg);
        for mg in dense_mgs {
            let plain = format!("HFMA2{mg} R1, R2, R3, R4");
            let plain_ok = enc_res(&t, &plain).is_ok();
            for s in dest_signs {
                let r = enc_res(&t, &format!("HFMA2{mg} {s}, R2, R3, R4"));
                if plain_ok {
                    let e = r.expect_err(&format!("{leg}: signed dest must refuse [{mg} {s}]"));
                    assert!(
                        e.contains("BUG-352"),
                        "{leg}: refusal needs attribution: {e}"
                    );
                    armed_refusals += 1;
                }
            }
        }
        // guard interplay: guard must not rescue the signed dest
        let r = enc_res(&t, "@P1 HFMA2 -R1, R2, R3, R4");
        let e = r.expect_err(&format!("{leg}: guarded signed dest must refuse"));
        assert!(
            e.contains("BUG-352"),
            "{leg}: guarded refusal attribution: {e}"
        );
        armed_refusals += 1;
        // UR-source row shape (dest still tok1)
        let r = enc_res(&t, "HFMA2 -R1, R2, UR4, R5");
        let e = r.expect_err(&format!("{leg}: UR-row signed dest must refuse"));
        assert!(
            e.contains("BUG-352"),
            "{leg}: UR-row refusal attribution: {e}"
        );
        armed_refusals += 1;
        // sparse legs: RELU dotted + _P tail (354-era lattice)
        for txt in [
            "HFMA2.RELU -R2, R3, R4, 0, 0",
            "HFMA2.RELU -R2, R3, R4, 0, 0, P1",
            "HFMA2.RELU -R2, R3, R4, 0, 0, !P0",
            "HFMA2.F32 -R2, R3, R4, 0, 0",
            "HFMA2.BF16_V2.FMZ -R2, R3, R4, 1, 0",
        ] {
            if enc_res(&t, &txt.replacen("-R2", "R2", 1)).is_ok() {
                let r = enc_res(&t, txt);
                let e = r.expect_err(&format!("{leg}: sparse signed dest must refuse [{txt}]"));
                assert!(
                    e.contains("BUG-352"),
                    "{leg}: sparse refusal attribution: {e}"
                );
                armed_refusals += 1;
            }
        }
    }
    // measurement-era expectation: x4 legs x (3 dense '' signs) + guards/UR
    // >= 12 armed refusals, plus sm120/sm121a mgs (12 more) minimum.
    assert!(
        armed_refusals >= 24,
        "armed refusal census too low: {armed_refusals}"
    );
}

#[test]
fn t352_3_src_signs_stay_legal_word_exact() {
    // Negative control: nothing about the arm touches legal signed sources.
    for leg in LEGS {
        let t = tab(leg);
        for (txt, want) in [
            ("HFMA2 R1, -R2, R3, R4", W_NEG_R2),
            ("HFMA2 R1, |R2|, R3, R4", W_ABS_R2),
            ("HFMA2 R1, -|R2|, R3, R4", W_NEGABS_R2),
            ("HFMA2 R1, R2, |R3|, R4", W_ABS_R3),
            ("HFMA2 R1, R2, UR4, R5", W_UR),
            ("HFMA2 R1, -R2, UR4, R5", W_UR_NEG_R2),
            ("HFMA2 R1, R2, |UR4|, R5", W_UR_ABS_UR4),
            ("HFMA2.RELU R2, R3, R4, 0, 0, P0", W_RELU_P0),
            ("HFMA2.RELU R2, R3, R4, 0, 0, !P0", W_RELU_NP0),
        ] {
            let w = enc_res(&t, txt).expect(&format!("{leg}: legal src sign must mint [{txt}]"));
            assert_eq!(w, want, "{leg}: word drift for {txt:?}");
        }
        if leg == "sm120" || leg == "sm121a" {
            // field-carried tok4 abs (b83); sm100a/103a = 371-kand cross-read
            let w = enc_res(&t, "HFMA2 R1, R2, R3, |R4|").expect("tok4 abs mints on thick legs");
            assert_eq!(w, W_ABS_R4_120, "{leg}: tok4 abs word drift");
            let w = enc_res(&t, "HFMA2.F32 R1, R2, R3, R4").expect("F32 mg mints on thick legs");
            assert_eq!(w, W_F32_MG, "{leg}: F32 mg word drift");
        }
    }
}

#[test]
fn t352_4_decode_untouched_plain_never_signed_dest() {
    // Decode-side invariant: the decoder has NO dest-sign claim for HFMA2,
    // so the armed encode path can never bite the decode->render->encode
    // loop (rt A/B 2,406 battery proves fleet-wide; these are the pins).
    for leg in LEGS {
        let t = tab(leg);
        let d = dec(&t, W_PLAIN).expect("plain decodes");
        assert_eq!(
            d.trim(),
            "HFMA2 R1, R2, R3, R4",
            "{leg}: plain decode drift"
        );
        for (w, frag) in [
            (W_NEG_R2, "-R2"),
            (W_ABS_R2, "|R2|"),
            (W_NEGABS_R2, "-|R2|"),
            (W_ABS_R3, "|R3|"),
            (W_UR, "UR4"),
            (W_RELU_P0, "P0"),
        ] {
            let d = dec(&t, w).expect(&format!("{leg}: signed-src word decodes"));
            assert!(d.contains(frag), "{leg}: decode lost {frag:?} in {d:?}");
            // roundtrip parity: re-encode the decoded text == source word
            let re = enc_res(&t, d.trim()).expect("re-encode");
            assert_eq!(re, w, "{leg}: roundtrip parity drift for {frag:?}");
        }
        if leg == "sm120" || leg == "sm121a" {
            let d = dec(&t, W_ABS_R4_120).expect("tok4 abs decodes");
            assert!(d.contains("|R4|"), "{leg}: vendor-exact |R4| print");
            let re = enc_res(&t, d.trim()).expect("re-encode");
            assert_eq!(re, W_ABS_R4_120, "{leg}: tok4 abs roundtrip");
        }
    }
}

#[test]
fn t352_5_arm_scope_and_refusal_surface() {
    // (a) Other opcodes are untouched by the arm: FFMA plain still mints,
    //     and if a signed FFMA dest ever errors it is NOT tagged BUG-352.
    // (b) The refusal surfaces through BOTH public encode doors (lib call
    //     here + the aarch asm path parses the same parse_sass line).
    // (c) RZ-dest signed spellings refuse too (RZ is Reg 255 internally).
    for leg in LEGS {
        let t = tab(leg);
        let w = enc_res(&t, "FFMA R1, R2, R3, R4").expect(&format!("{leg}: FFMA plain mints"));
        assert_ne!(w, 0, "{leg}: FFMA mint sanity");
        if let Err(e) = enc_res(&t, "FFMA -R1, R2, R3, R4") {
            assert!(
                !e.contains("BUG-352"),
                "{leg}: arm must not leak past HFMA2: {e}"
            );
        }
        for txt in ["HFMA2 -RZ, R2, R3, R4", "HFMA2 |RZ|, R2, R3, R4"] {
            if enc_res(&t, &txt.replacen("-RZ", "RZ", 1).replacen("|RZ|", "RZ", 1)).is_ok() {
                let r = enc_res(&t, txt);
                let e = r.expect_err(&format!("{leg}: signed RZ dest must refuse [{txt}]"));
                assert!(e.contains("BUG-352"), "{leg}: RZ refusal attribution: {e}");
            }
        }
        // hsel-qualified dest sign still refuses: either by this arm or
        // (as measured post-arm) earlier by BUG-272 -- a dest hsel suffix
        // has no row field either; both doors are fail-closed WITH
        // attribution, which is exactly the failure surface we pin here.
        let r = enc_res(&t, "HFMA2 -R1.H0_H0, R2, R3, R4");
        let e = r.expect_err(&format!("{leg}: signed hsel dest must refuse"));
        assert!(
            e.contains("BUG-352") || e.contains("BUG-272"),
            "{leg}: hsel-dest refusal needs attribution (272 or 352): {e}"
        );
    }
}
