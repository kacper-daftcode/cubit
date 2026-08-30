//! BUG-261 (F2-iter134, loop5/blind front2, 2026-08-29): closure of the
//! post-258 2-bit 'neg' residuum class on sm120/sm121a (canonical dac676b).
//! Measurement-first (the "corpus-zero" registry claim of 258 was NOT
//! verified on the full battery; routex261 corrected that):
//!   census261: 51 sm120 (34 rows) + 66 sm121a (45 rows) 2-bit 'neg' fields,
//!              donors 0;  routex261 FULL 2,406-cubin battery per-leg decode.
//!   INJURED (live classes): sm121a FFMA_R_R_R_R[''] tok2 value-2 x2,384
//!     words (ghost '-|' pre; vendor '|R|' - the printer raw-abs overlay
//!     already made value-3 print law-equal); HADD2_R_R_FI_FI x7 (suffix
//!     drop); HADD2 II-'?' x104 (phantom row, suffix class); HFMA2 BF16_V2
//!     x35 (hsel suffix drop). All other rows {0,1}-only / zero routing.
//! Graft (patch261.py, canonical dac676b, replayable+idempotent, 103 ops):
//!   A sign neg-lines  neg 2b@s -> neg 1b@s + abs 1b@s+1 (arb: -/|./-|.|);
//!   B sign swapped    neg 2b@s -> abs 1b@s + neg 1b@s+1 (arb: |.|-/-|.|);
//!   C hsel retype     'neg' 2b -> 'hsel' 2b (arb: v2 .H0_H0 v3 .H1_H1;
//!                     engine v1 '.H0_H1' = donor law, corpus-zero).
//! SKIPPED rows (registry = 265-kand b3-line, no arb-able vendor law):
//!   I2I.S16/U16.S32.SAT_P0_R_R + I2IP.U8.S32_[P0,P2,P5,'']_R_R_R_R
//!   (and_base self-decodes to I2IP.U8.S32 - head mismatch), FMNMX
//!   _R_R_II_II_II_II_? (all corpus witnesses vendor rc=1).
//! Residua pinned as status-quo sentinels:
//!   264-kand: era 4-bit 'neg'@60 tok3 (HMUL2/HFMA2 BF16_V2) = hsel 2b@60
//!     (donor shape); ghost '-UR8' on 16 corpus words (HMUL2.BF16_V2 wit).
//!   266-kand: era 1-bit 'neg' mislabels around the grafted rows:
//!     HADD2_R_R_FI_FI tok2 neg@73 (arb: real sign pair = neg@72/abs@73;
//!     7 corpus words '-RZ.H0_H0' drop '-') + HFMA2_R_R_UR_R|BF16_V2
//!     duplicate neg@122/124 overlapping reuse bits (ghost '-' on 35 words).
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
fn and_base(t: &IsaTable, key: &str, mg: &str) -> u128 {
    let g = t.entries[key].mod_groups.get(mg).expect("mg");
    u128::from(g.and_base)
}

// routex261 corpus witnesses (full 128-bit; engine matches 96-bit payload).
const W_FFV0: u128 = 0xfc800000000080000000708077223; // FFMA R7, R8, R7, R8
const W_FFV1: u128 = 0xfc800000001ff0000000704087223; // FFMA R8, -R4, R7, RZ
const W_FFV2: u128 = 0xfc800000002ff00000021041e7223; // FFMA R30, |R4|, R33, RZ
const W_FFV3: u128 = 0xfc800000003090000000209037223; // FFMA R3, -|R9|, R2, R9
const W_HMA: u128 = 0x2fca00080408052000000402057c31; // HFMA2.BF16_V2 wit A (v2/v2)
const W_HMB: u128 = 0x140fe4000816080b200000080c097c31; // HFMA2 BF16_V2 wit B (v3/v3)
const W_HDF: u128 = 0xfc60000000900bf80bf80ff0b2430; // HADD2 FI witness (v2, b72 neg)
const W_HML: u128 = 0x10fc80008000000300000080c0b7c32; // HMUL2 BF16_V2 witness v0

#[test]
fn t261_1_structure() {
    // FLIPPED 2026-08-29 (BUG-265): the 261 SKIP registry is CLOSED. The
    // five phantom/poison rows were deleted (junk-rows b3-line closure:
    // base-decodes vendor-invalid or head-mismatch, zero battery routing),
    // I2IP.U8.S32_R_R_R_R retyped neg2b@72 -> opmod:H1 1b@72 (arb265 A:
    // v1='.H1'), FMNMX-'?' deleted (ab=0 vendor-Illegal); exact 2-bit 'neg'
    // census post-265 = ZERO per leg.
    let registry: &[(&str, i32, u32)] = &[];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let mut hits: Vec<(String, i32, u32)> = Vec::new();
        for (k, row) in &t.entries {
            for (_mg, g) in &row.mod_groups {
                for f in &g.fields {
                    if f.extraction == Extraction::Neg && f.bits == 2 {
                        hits.push((k.clone(), f.token_idx, f.shift));
                    }
                }
            }
        }
        hits.sort();
        let mut want: Vec<(String, i32, u32)> = registry
            .iter()
            .map(|(k, t2, s)| (k.to_string(), *t2, *s))
            .collect();
        want.sort();
        assert_eq!(hits, want, "{leg} 2b-neg census drift post-261");
    }
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (k, row) in &t.entries {
            for (_mg, g) in &row.mod_groups {
                for f in &g.fields {
                    assert!(
                        !(f.extraction == Extraction::Neg && f.bits == 2),
                        "{leg} {k}: donor 2b-neg appeared"
                    );
                }
            }
        }
    }
    // A-class split shapes (t258_1 pattern): sm121a FFMA '' + DFMA FI RM/RP.
    let t = tab("sm121a");
    for (key, mg) in [
        ("FFMA_R_R_R_R", ""),
        ("DFMA_R_R_R_FI", "RM"),
        ("DFMA_R_R_R_FI", "RP"),
    ] {
        let g = t.entries[key].mod_groups.get(mg).expect("mg");
        let mut tok2: Vec<(u32, u32, &str)> = g
            .fields
            .iter()
            .filter(|f| f.token_idx == 2 && (f.shift == 72 || f.shift == 73))
            .map(|f| {
                (
                    f.shift,
                    f.bits,
                    match f.extraction {
                        Extraction::Neg => "neg",
                        Extraction::Abs => "abs",
                        _ => "other",
                    },
                )
            })
            .collect();
        tok2.sort();
        assert_eq!(
            tok2,
            vec![(72u32, 1u32, "neg"), (73u32, 1u32, "abs")],
            "sm121a {key}/{mg} tok2 A-split drifted"
        );
    }
    // B-class swapped shape: DMMA tok4 both legs.
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let g = &t.entries["DMMA.8x8x4_R_R_R_R"].mod_groups[""];
        let mut tok4: Vec<(u32, &str)> = g
            .fields
            .iter()
            .filter(|f| f.token_idx == 4 && (f.shift == 74 || f.shift == 75))
            .map(|f| {
                (
                    f.shift,
                    match f.extraction {
                        Extraction::Neg => "neg",
                        Extraction::Abs => "abs",
                        _ => "other",
                    },
                )
            })
            .collect();
        tok4.sort();
        assert_eq!(
            tok4,
            vec![(74u32, "abs"), (75u32, "neg")],
            "{leg} DMMA tok4 B-drift"
        );
    }
    // C-class hsel retypes present (neg 2b gone).
    let t = tab("sm121a");
    let g = &t.entries["HADD2_R_R_FI_FI"].mod_groups[""];
    assert!(g.fields.iter().any(|f| f.extraction == Extraction::HalfSel
        && f.bits == 2
        && f.shift == 74
        && f.token_idx == 2));
    let g = &t.entries["HFMA2_R_R_UR_R"].mod_groups["BF16_V2"];
    for (tok, sh) in [(2, 74), (4, 81)] {
        assert!(g.fields.iter().any(|f| f.extraction == Extraction::HalfSel
            && f.bits == 2
            && f.shift == sh
            && f.token_idx == tok));
    }
    // and_base/vmask invariant sample: windows variable + zero-baked.
    let t = tab("sm120");
    for (key, mg, sh) in [
        ("DMMA.8x8x4_R_R_R_R", "", 72u32),
        ("FADD.SAT_R_R_R", "", 72u32),
        ("HADD2.F32_R_R_R", "", 60u32),
        ("HSETP2_P_P_R_UR_P", "AND,F", 74u32), // BUG-265 rename (arb265 B: cmp [79:76]=0=F)
        ("UFFMA_UR_UR_UR_UR", "", 74u32),
    ] {
        let g = &t.entries[key].mod_groups[mg];
        let abm: u128 = g.and_base.into();
        let vm: u128 = g.variable_mask.into();
        assert_eq!((abm >> sh) & 3, 0, "{key} and_base window baked");
        assert_eq!((vm >> sh) & 3, 3, "{key} window lost variability");
    }
}

#[test]
fn t261_2_decode_sign_laws() {
    // arb261 vendor laws; corpus witnesses + and_base hosts; engine scope
    // sm120+sm121a (FFMA/DFMA FI rows exist only on sm121a).
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_FFV0 & M96).as_deref(),
        Some("FFMA R7, R8, R7, R8")
    );
    assert_eq!(
        dec(&t, W_FFV1 & M96).as_deref(),
        Some("FFMA R8, -R4, R7, RZ")
    );
    // THE 2,384-word class: value-2 is vendor '|R|' (was ghost '-|R|' pre).
    assert_eq!(
        dec(&t, W_FFV2 & M96).as_deref(),
        Some("FFMA R30, |R4|, R33, RZ")
    );
    assert_eq!(
        dec(&t, W_FFV3 & M96).as_deref(),
        Some("FFMA R3, -|R9|, R2, R9")
    );
    // A-class law on and_base hosts (arb: v1 '-' v2 '|x|' v3 '-|x|').
    let d = and_base(&t, "DFMA_R_R_R_FI", "RM");
    assert_eq!(
        dec(&t, (d | (1 << 72)) & M96).as_deref(),
        Some("@P1 DFMA.RM R0, -R0, R0, R0")
    );
    assert_eq!(
        dec(&t, (d | (2 << 72)) & M96).as_deref(),
        Some("@P1 DFMA.RM R0, |R0|, R0, R0")
    );
    assert_eq!(
        dec(&t, (d | (3 << 72)) & M96).as_deref(),
        Some("@P1 DFMA.RM R0, -|R0|, R0, R0")
    );
    let u = and_base(&t, "UFFMA_UR_UR_UR_UR", "");
    assert_eq!(
        dec(&t, (u | (2 << 72)) & M96).as_deref(),
        Some("@UP0 UFFMA UR0, |UR0|, UR0, UR0")
    );
    let s = and_base(&t, "UFSETP.GT.AND_UP_UP_UR_UR_UP", "");
    assert_eq!(
        dec(&t, (s | (3 << 72)) & M96).as_deref(),
        Some("@UP0 UFSETP.GT.AND UP0, UP0, -|UR0|, UR0, UP0")
    );
    // B-class swapped law both legs (arb: v1 '|x|' v2 '-' v3 '-|x|').
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let d = and_base(&t, "DMMA.8x8x4_R_R_R_R", "");
        assert_eq!(
            dec(&t, (d | (1 << 74)) & M96).as_deref(),
            Some("DMMA.8x8x4 R0, R0, R0, |R0|"),
            "{leg}"
        );
        assert_eq!(
            dec(&t, (d | (2 << 74)) & M96).as_deref(),
            Some("DMMA.8x8x4 R0, R0, R0, -R0"),
            "{leg}"
        );
        assert_eq!(
            dec(&t, (d | (3 << 74)) & M96).as_deref(),
            Some("DMMA.8x8x4 R0, R0, R0, -|R0|"),
            "{leg}"
        );
        assert_eq!(
            dec(&t, (d | (2 << 72)) & M96).as_deref(),
            Some("DMMA.8x8x4 R0, |R0|, R0, R0"),
            "{leg}"
        );
    }
    let t = tab("sm121a");
    let f = and_base(&t, "FADD.SAT_R_R_R", "");
    assert_eq!(
        dec(&t, (f | (2 << 72)) & M96).as_deref(),
        Some("@P0 FADD R0, |RZ|, R0")
    );
    let m = and_base(&t, "FMNMX_R_R_FI_P", "");
    assert_eq!(
        dec(&t, (m | (3 << 72)) & M96).as_deref(),
        Some("@P0 FMNMX R0, -|R0|, 0, P0")
    );
}

#[test]
fn t261_3_decode_hsel_laws() {
    // arb: v2 .H0_H0, v3 .H1_H1 (vendor verbs on corpus witnesses); v1 = the
    // engine/donor spelling '.H0_H1' (corpus-zero; vendor says .INVALID1 on
    // these rows = latent engine-vs-vendor note, NOT 261 scope).
    let t = tab("sm121a");
    let h = and_base(&t, "HADD2_R_R_FI_FI", "");
    assert_eq!(
        dec(&t, (h | (2 << 74)) & M96).as_deref(),
        Some("@P0 HADD2 R0, R0.H0_H0, 0, 0")
    );
    assert_eq!(
        dec(&t, (h | (3 << 74)) & M96).as_deref(),
        Some("@P0 HADD2 R0, R0.H1_H1, 0, 0")
    );
    // HFMA2 BF16_V2 corpus witnesses: tok2/tok4 suffixes vendor-equal post;
    // tok3-UR suffix FLIPPED 2026-08-29 (BUG-264): era 4-bit 'neg'@60 ->
    // hsel 2b@60 + abs@62 + neg@63 (arb264 x4 models). Vendor-equal now.
    assert_eq!(
        dec(&t, W_HMA & M96).as_deref(),
        Some("HFMA2.BF16_V2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0")
    );
    // wit B, harness convention ctl-zeroed (t258 pattern): vendor =
    // 'HFMA2 R9, R12.reuse.H0_H0, UR8.H0_H0, -R11.reuse.H1_H1' (nvdisasm,
    // ctl-carrying; zeroed: 'R12.H0_H0, UR8.H0_H0, -R11.H1_H1').
    // FLIPPED 2026-08-29 (BUG-266): the era dup neg@124 ctl-field shadowing
    // the true neg@84 window is deleted -> tok4 '-' restored (vendor-equal
    // UR8 suffix FLIPPED 2026-08-29 (BUG-264/267): hsel 2b@60 prints
    // '.H0_H0' (vendor-equal on the corpus witnesses, arb264 A-set)).
    assert_eq!(
        dec(&t, W_HMB & M96).as_deref(),
        Some("HFMA2.BF16_V2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1")
    );
    // sm120 leg law spot-checks.
    let t = tab("sm120");
    let h = and_base(&t, "HADD2.F32_R_R_R", "");
    assert_eq!(
        dec(&t, (h | (2 << 60)) & M96).as_deref(),
        Some("@P0 HADD2 R0, RZ, R0.H0_H0")
    );
    // FLIPPED 2026-08-29 (BUG-265): mg 'GEU.AND' renamed 'AND,F'; the base
    // decodes vendor 'HSETP2.F.AND' (arb265 B, x4 models) -- pre-flip text
    // was a cmp-name mislabel.
    let s = and_base(&t, "HSETP2_P_P_R_UR_P", "AND,F");
    assert_eq!(
        dec(&t, (s | (2 << 74)) & M96).as_deref(),
        Some("@P0 HSETP2.F.AND P0, P0, R0.H0_H0, UR0, P0")
    );
}

#[test]
fn t261_4_encode_inverse() {
    // sm121a authored sign text -> exact window bits -> decode-back text.
    let t = tab("sm121a");
    for (text, v) in [
        ("FFMA R8, |R4|, R7, RZ", 2u128),
        ("FFMA R8, -R4, R7, RZ", 1u128),
        ("FFMA R8, -|R4|, R7, RZ", 3u128),
    ] {
        let w = enc(&t, text);
        assert_eq!((w >> 72) & 3, v, "{text}: window bits");
        assert_eq!(
            dec(&t, w & M96).as_deref(),
            Some(text),
            "{text}: decode-back"
        );
    }
    // payload-exact roundtrips of the corpus witnesses (all window values).
    for w in [W_FFV0, W_FFV1, W_FFV2, W_FFV3] {
        let txt = dec(&t, w & M96).expect("decode witness");
        assert_eq!(enc(&t, &txt) & M96, w & M96, "witness {txt} payload drift");
    }
    // B-class encode: swapped window must not confuse inverse.
    for (text, v) in [
        ("DMMA.8x8x4 R0, R0, R0, |R0|", 1u128),
        ("DMMA.8x8x4 R0, R0, R0, -R0", 2u128),
        ("DMMA.8x8x4 R0, R0, R0, -|R0|", 3u128),
    ] {
        let w = enc(&t, text);
        assert_eq!((w >> 74) & 3, v, "{text}: swapped window bits");
        assert_eq!(
            dec(&t, w & M96).as_deref(),
            Some(text),
            "{text}: decode-back"
        );
    }
}

#[test]
fn t261_5_residuum_sentinels() {
    // HADD2 FI witness: suffix fixed ('.H0_H0' in 261); the dropped '-' on
    // RZ restored (FLIPPED 2026-08-29, BUG-266: era neg@73 tok2 -> pair
    // neg@72/abs@73 per arb261 law; vendor '@P2 HADD2 R11, -RZ.H0_H0, ...').
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_HDF & M96).as_deref(),
        Some("@P2 HADD2 R11, -RZ.H0_H0, -1.875, -1.875")
    );
    // HMUL2 witness FLIPPED 2026-08-29 (BUG-264): era 4-bit 'neg'@60 ghost
    // '-UR8' closed by hsel 2b@60 graft (vendor 'UR8.H1_H1', arb264 A-set).
    assert_eq!(
        dec(&t, W_HML & M96).as_deref(),
        Some("HMUL2.BF16_V2 R11, R12, UR8.H1_H1")
    );
    // FLIPPED 2026-08-29 (BUG-265): registry closure. I2IP '' retyped
    // (neg2b@72 gone, opmod:H1 1b@72 in -- arb265 A), FMNMX-'?' row DELETED
    // outright. bug265_junkrows.rs pins the full structure.
    {
        let t = tab("sm120");
        let g = &t.entries["I2IP.U8.S32_R_R_R_R"].mod_groups[""];
        let n = g
            .fields
            .iter()
            .filter(|f| f.extraction == Extraction::Neg && f.bits == 2)
            .count();
        assert_eq!(n, 0, "sm120 I2IP: era 2b-neg must be gone post-265");
        for leg in ["sm120", "sm121a"] {
            let t2 = tab(leg);
            assert!(!t2.entries.contains_key("FMNMX_R_R_II_II_II_II_?"));
        }
    }
    // t258 anchors keep law glyphs.
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, 0xfd4000000400a0000000e0c0a722b & M96).as_deref(),
        Some("DFMA.RM R10, R12, R14, R10")
    );
    assert_eq!(
        dec(&t, 0xfd0000000811a0000000c0a1a722b & M96).as_deref(),
        Some("DFMA.RP R26, -R10, R12, R26")
    );
    assert_eq!(
        dec(&t, 0x2fe200080000050000000004047254 & M96).as_deref(),
        Some("UFADD UR4, UR4, UR5")
    );
}
