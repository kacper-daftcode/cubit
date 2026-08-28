//! BUG-226e (F2-iter118, front2/blind, 2026-08-28): sm120 vendor-parity
//! patch 8 — 226-forward sev-B tail closure: I2F/F2F/FENCE/USETMAXREG
//! (canonical 6ba6ca4; patch226e.py replayable+idempotent).
//!
//! Defect census (pop226e, harvested from pop226d part/ with vendor ground
//! truth, true-ctrl (word96,ctrl) pairing per BUG-236, nvdisasm 13.3.73):
//! 9,639 DIFF words: I2F 5,415 (guard@13 shift pathology folding PT to a
//!   phantom @P3 print, era typed-zoo phantoms, ureg4@17 stub vs real
//!   ureg8@32, missing byte_sel@60 on S8, missing F64,U32/F64,U64/U64 cells,
//!   RP.U32 print order), F2F 4,201 (typed key dst read 8b@17 vs vendor
//!   8b@16 -> WIDE-pair halving on the F64-dest form, tok2 abs/neg erasure,
//!   UR-src HOLEs), FENCE 8 (era S-only key; T cell absent), USETMAXREG 15
//!   (TRY_ALLOC misroute for DEALLOC + _ALLOC.CTAPOOL ghost mods + !UPT
//!   pred ghost on DEALLOC).
//!
//! Law: donor sm100a == sm103a byte-identical per cloned key; donor-table
//! decode == vendor on all scope DIFF words modulo mg-name print order
//! (cured by printer arms bug226e: rounding last on I2F; VIEW first on
//! FENCE; op before CTAPOOL on USETMAXREG). Grafts: arb226e_b x{100a,103a,
//! 120a} print-identical (F2F.F64.F32 dst 8b@16, tok2 neg@63/abs@62, b123
//! inert); arb226e_c x3 arch (F2F_R_UR F64,F32 mg fields, b76/b84 vendor-
//! ILLEGAL corner pins). Post-patch full-pop: I2F 20,303/20,303 EQ, F2F
//! 5,291/5,291 EQ, FENCE 31/31, USETMAXREG 15/15, zero regressions on the
//! other residuum families (post226e).
//!
//! Fix: DELETE 15 era keys (I2F typed zoo x12, FENCE.VIEW.ASYNC.S,
//! USETMAXREG.DEALLOC/TRY_ALLOC pair); REPLACE mod_groups from donor on
//! I2F_R_R/I2F_R_UR (envelopes kept); ADD FENCE, USETMAXREG_II,
//! USETMAXREG_UP_II, F2F_R_UR (+grafted F64,F32 mg); grafts on era F2F
//! typed keys (dst shift 17->16, neg/abs fields). forms 1471->1460,
//! variants 2623->2620, baked-ctrl 803->823 (+20 donor templates).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const M96: u128 = (1u128 << 96) - 1;
fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}
fn decode(t: &IsaTable, w128: u128) -> Result<String, String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w128, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn mk(w96: u128, ctrl: u64) -> u128 {
    (w96 & ((1 << 96) - 1)) | ((ctrl as u128) << 96)
}

/// Cured anchors: (vendor glyph, word96, ctrl32) — pop226e occurrence-paired
/// corpus hits, one per cured class.
const CURED: &[(&str, u128, u64)] = &[
    // I2F: era guard@13 fold printed phantom @P3 (PT elision restored)
    ("I2F.S8 R26, R26", 0x000014000000001a001a7306, 0x004e6200),
    // I2F: F64 dest + U32 src cell (era dropped .U32)
    (
        "I2F.F64.U32 R38, R38",
        0x002018000000002600267312,
        0x000e5e00,
    ),
    // I2F: U64 cell (era mislabelled S64)
    (
        "I2F.F64.U64 R18, R18",
        0x003018000000001200127312,
        0x000e5e00,
    ),
    ("I2F.U64 R0, R4", 0x003010000000000400007312, 0x0002a200),
    ("I2F.S64 R0, R22", 0x003014000000001600007312, 0x001e3000),
    // I2F: UR-src HOLEs (era stub field; donor ureg8@32)
    ("I2F.F64 R12, UR4", 0x08201c0000000004000c7d12, 0x000e7000),
    ("I2F.RP R10, UR16", 0x0820940000000010000a7d06, 0x000e7000),
    (
        "I2F.F64.S64 R6, UR4",
        0x08301c000000000400067d12,
        0x000e2200,
    ),
    (
        "I2F.F64.U32 R2, UR8",
        0x082018000000000800027d12,
        0x000e2200,
    ),
    // F2F: F64-dest halving cured (dst 8b@17 -> 8b@16)
    (
        "F2F.F64.F32 R40, R10",
        0x002018000000000a00287310,
        0x000eb000,
    ),
    // F2F: tok2 abs/neg restored on the F64-dest form
    (
        "F2F.F64.F32 R6, |R0|",
        0x002018004000000000067310,
        0x000e6200,
    ),
    (
        "F2F.F64.F32 R16, -R16",
        0x002018008000001000107310,
        0x000e2400,
    ),
    // F2F: BF16/F16 abs erasures cured
    (
        "F2F.BF16.F32 R24, |R24|",
        0x002020004000001800187304,
        0x000ea200,
    ),
    (
        "F2F.F16.F32 R9, |R0|",
        0x002008004000000000097304,
        0x000e2400,
    ),
    // F2F: UR-src forms (donor F32,F64 mg + grafted F64,F32 mg)
    (
        "F2F.F32.F64 R0, UR4",
        0x083010000000000400007d10,
        0x001e2200,
    ),
    (
        "F2F.F64.F32 R2, UR6",
        0x082018000000000600027d10,
        0x002e9e00,
    ),
    // FENCE: T cell (era S-only key)
    ("FENCE.VIEW.ASYNC.T", 0x0000020000000000000073c6, 0x000ee400),
    // USETMAXREG: era misroutes/ghosts cured
    (
        "USETMAXREG.DEALLOC.CTAPOOL 0x18",
        0x080e050000000018000079c8,
        0x000fc000,
    ),
    (
        "USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0xe0",
        0x08000600000000e0000079c8,
        0x000e2400,
    ),
];

#[test]
fn t226e_1_structure() {
    let raw = std::fs::read_to_string(T120).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let ins = v["instructions"].as_object().unwrap();
    for gone in [
        "I2F.S8_R_R",
        "I2F.S8_R_R_R",
        "I2F.S16_R_R",
        "I2F.S16_R_R_R",
        "I2F.S16_R_R_II_?",
        "I2F.S16_R_R_II_II_?",
        "I2F.U16_R_R",
        "I2F.F64.U32_R_R",
        "I2F.F64_R_R",
        "I2F.U32.RP_R_R",
        "I2F.U32.RP_R_R_R",
        "I2F.U64.RP_R_R",
        "FENCE.VIEW.ASYNC.S",
        "USETMAXREG.DEALLOC.CTAPOOL_II",
        "USETMAXREG.TRY_ALLOC.CTAPOOL_UP_II",
    ] {
        assert!(ins.get(gone).is_none(), "era key survived: {gone}");
    }
    for want in [
        "I2F_R_R",
        "I2F_R_UR",
        "FENCE",
        "USETMAXREG_II",
        "USETMAXREG_UP_II",
        "F2F_R_UR",
    ] {
        assert!(ins.get(want).is_some(), "donor key missing: {want}");
    }
    let mg = |k: &str, m: &str| !ins[k]["mod_groups"][m].is_null();
    assert!(
        mg("F2F_R_UR", "F32,F64") && mg("F2F_R_UR", "F64,F32"),
        "F2F_R_UR must carry donor F32,F64 + grafted F64,F32"
    );
    for m in [
        "F64", "F64,S64", "F64,U32", "F64,U64", "RP", "RP,U32", "RP,U64", "S16", "S64", "S8", "U64",
    ] {
        assert!(mg("I2F_R_R", m), "I2F_R_R[{m}] missing");
    }
    assert!(mg("FENCE", "ASYNC,S,VIEW") && mg("FENCE", "ASYNC,T,VIEW"));
    // graft fields on the era F2F typed keys: dst 8b@16 + tok2 neg/abs
    let hasf = |k: &str, e: &str, sft: u64, tok: u64| {
        ins[k]["mod_groups"][""]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["extraction"] == e && f["shift"] == sft && f["token_idx"] == tok)
    };
    assert!(hasf("F2F.F64.F32_R_R", "reg", 16, 1), "dst must read 8b@16");
    assert!(
        !hasf("F2F.F64.F32_R_R", "reg", 17, 1),
        "dst 8b@17 must be gone"
    );
    assert!(hasf("F2F.F64.F32_R_R", "neg", 63, 2));
    assert!(hasf("F2F.F64.F32_R_R", "abs", 62, 2));
    assert!(hasf("F2F.F64.F32_R_R_R", "neg", 63, 2));
    assert!(hasf("F2F.F16.F32_R_R", "abs", 62, 2));
    assert!(hasf("F2F.BF16.F32_R_R", "neg", 63, 2));
    assert!(hasf("F2F.BF16.F32_R_R", "abs", 62, 2));
}

#[test]
fn t226e_2_cured_anchors() {
    let t = tab(T120);
    for (want, w96, ctrl) in CURED {
        let got = decode(&t, mk(*w96, *ctrl)).unwrap_or_else(|e| panic!("{want}: HOLE {e}"));
        assert_eq!(&got, want);
    }
}

#[test]
fn t226e_3_fail_closed() {
    let t = tab(T120);
    // era ghost texts must NOT encode anymore
    for ghost in [
        "USETMAXREG.TRY_ALLOC.CTAPOOL._ALLOC.CTAPOOL UP0, 0xe0 ;",
        "USETMAXREG.DEALLOC.CTAPOOL !UPT, 0x18 ;",
        "FENCE.VIEW.ASYNC.X ;",
    ] {
        if let Ok(ins) = parse_sass(ghost, 0) {
            let _ = encode_instruction(&ins, &t)
                .expect_err(&format!("ghost must fail-closed: {ghost}"));
        }
    }
    // wrong mod order on USETMAXREG is normalized by the encoder to the
    // vendor order (mods are set-matched, mg names are canonical)
    let ins = parse_sass("USETMAXREG.CTAPOOL.DEALLOC 0x18 ;", 0).expect("parse");
    let w = encode_instruction(&ins, &t).expect("order-normalizing encode");
    let idx = DecodeIndex::build(&t);
    let got = to_sass(&idx.decode(w & M96, 0, &t).unwrap());
    assert_eq!(got, "USETMAXREG.DEALLOC.CTAPOOL 0x18");
}

#[test]
fn t226e_4_encode_roundtrips() {
    let t = tab(T120);
    let idx = DecodeIndex::build(&t);
    // NOTE (240-kand LOW, pre-existing): encode-side candidate order
    // probes (base_key, sorted-mods) before (typed_key, ""), so the
    // F64-dest spelled form `F2F.F64.F32 R40, R10` resolves to the generic
    // F2F_R_R[F32,F64] row (F32-cell word), long predating BUG-226e (era
    // typed key printed the halved dst anyway). Decode path is correct
    // (t226e_2 anchors); zero corpus exposure. Roundtrips below cover only
    // unambiguous shapes.
    for txt in [
        "F2F.F32.F64 R40, R10 ;",
        "F2F.BF16.F32 R24, |R24| ;",
        "F2F.F16.F32 R9, |R0| ;",
        "I2F.U32.RP R0, R5 ;",
        "I2F.F64.U32 R38, R38 ;",
        "I2F.S8 R26, R26 ;",
        "I2F.F64 R12, UR4 ;",
        "FENCE.VIEW.ASYNC.S ;",
        "FENCE.VIEW.ASYNC.T ;",
        "USETMAXREG.DEALLOC.CTAPOOL 0x18 ;",
        "USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0xe0 ;",
    ] {
        let ins = parse_sass(txt, 0).unwrap_or_else(|e| panic!("parse fail {txt}: {e}"));
        let w = encode_instruction(&ins, &t).unwrap_or_else(|e| panic!("encode fail {txt}: {e}"));
        let got = to_sass(&idx.decode(w & M96, 0, &t).unwrap());
        assert_eq!(got, txt.trim_end_matches(" ;"), "roundtrip {txt}");
    }
}

#[test]
fn t226e_5_stability_xpatch() {
    let t = tab(T120);
    // cross-patch stability anchors (226c/234/230/229b/226d cured classes)
    for (want, w96, ctrl) in [
        (
            "FFMA R27, R19, -R17.reuse, R36",
            0x0000002480000011131b7223u128,
            0x080fe200u64,
        ),
        (
            "LEA R4, R3.reuse, -R4, 0x3",
            0x078e18ff8000000403047211u128,
            0x040fe200u64,
        ),
        (
            "UIMAD UR4, UR4, UR6, URZ",
            0x0f8e02ff00000006040472a4u128,
            0x000fe200u64,
        ),
        (
            "DFMA R8, -R22, R16, -R4",
            0x00000904000000101608722bu128,
            0x001e0800u64,
        ),
    ] {
        let got = decode(&t, mk(w96, ctrl)).unwrap();
        assert_eq!(got, want);
    }
}
