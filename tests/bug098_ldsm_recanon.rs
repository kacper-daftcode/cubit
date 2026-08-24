//! BUG-098 (F2Q, F2-iter35, 2026-08-23): LDSM.16.M88[.2/.4] re-canon.
//! Pre-fix state (head 5f91ca2, 21 uniq words / 32 slots in the 2049-cubin
//! vendor census, cuobjdump 13.3):
//! (1) canon sm103a: mg-name order junk (rendered LDSM.M88.16 / LDSM.2.M88.16),
//!     ARI '16,2,M88' imm field at shift 31 (rendered +0x8000 for vendor +0x40),
//!     NO plain-ARI mg at all -> `@P0 LDSM.16.M88 R5, [R0+0x80]` DECERR.
//! (2) sm120.json: 11 LDSM keys were pure harvest RE-noise (reg halved
//!     @17/@18, ureg 4-bit, imm 2..5-bit, `?AR` fallback, MT88 mis-route with
//!     [R0+UR0] baked) -- every single one of the 21 anchors mis-decoded.
//! Fix: canon fields+geometry repaired (guard 4b@[15:12] added family-wide
//! like the LDS family; sub_r0 9b; sub_imm1 @[63:40]; NEW plain-ARI mg
//! '16,M88'), printer gets an LDSM arm (width 16 < layout M88/MT88 < count
//! 2/4), sm120 gets the canon rows verbatim with sm120 sched/ctrl donors.
//! Report: the internal fix archive Anchors: the internal fix archive
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// (word, vendor-canonical text) -- anchors from the 2049-cubin vendor census
/// (the internal fix archive
const GOLD: &[(u128, &str)] = &[
    (0x000e620000000000000080000005083bu128, "@P0 LDSM.16.M88 R5, [R0+0x80]"), // mk19.cubin@00e0 sm103
    (0x000e640008000000000000040000783bu128, "LDSM.16.M88 R0, [R0+UR4]"), // p_ldsm.cubin@0200 sm103
    (0x000e220000000100000000000202783bu128, "LDSM.16.M88.2 R2, [R2]"), // libcublasLt.so.581.sm_100.cubin@0da0 sm100
    (0x000e620000000100000000000202783bu128, "LDSM.16.M88.2 R2, [R2]"), // libcublasLt.so.586.sm_100.cubin@0dc0 sm100
    (0x000ea80000000100000000000202783bu128, "LDSM.16.M88.2 R2, [R2]"), // libcublasLt.so.581.sm_100.cubin@0eb0 sm100
    (0x000fe20000000100000040000004783bu128, "LDSM.16.M88.2 R4, [R0+0x40]"), // mk19.cubin@00c0 sm103
    (0x000e220008000200000000040004783bu128, "LDSM.16.M88.4 R4, [R0+UR4]"), // b_ldmatrix.cubin@0090 sm103
    (0x000fe80008000000000000040606783bu128, "LDSM.16.M88 R6, [R6+UR4]"), // m15d_plain_ldsm.cubin@0100 sm103
    (0x000e240008000000000000040607783bu128, "LDSM.16.M88 R7, [R6+UR4]"), // m15b_bssy_ldsm.cubin@0110 sm103
    (0x000e280000000100000000004444783bu128, "LDSM.16.M88.2 R68, [R68]"), // libcublasLt.so.581.sm_100.cubin@0df0 sm100
    (0x000ea80000000100000000004444783bu128, "LDSM.16.M88.2 R68, [R68]"), // libcublasLt.so.586.sm_100.cubin@0e70 sm100
    (0x000ee20000000100000000004444783bu128, "LDSM.16.M88.2 R68, [R68]"), // libcublasLt.so.581.sm_100.cubin@0e30 sm100
    (0x000e220000000100000000004646783bu128, "LDSM.16.M88.2 R70, [R70]"), // libcublasLt.so.586.sm_100.cubin@0de0 sm100
    (0x000ea20000000100000000004646783bu128, "LDSM.16.M88.2 R70, [R70]"), // libcublasLt.so.581.sm_100.cubin@0df0 sm100
    (0x000f220000000100000000004848783bu128, "LDSM.16.M88.2 R72, [R72]"), // libcublasLt.so.581.sm_100.cubin@0e50 sm100
    (0x000e280000000100000000004848783bu128, "LDSM.16.M88.2 R72, [R72]"), // libcublasLt.so.581.sm_100.cubin@0e00 sm100
    (0x000ee80000000100000000004848783bu128, "LDSM.16.M88.2 R72, [R72]"), // libcublasLt.so.586.sm_100.cubin@0e80 sm100
    (0x000e280000000100000000004a4a783bu128, "LDSM.16.M88.2 R74, [R74]"), // libcublasLt.so.581.sm_100.cubin@0e10 sm100
    (0x000f280000000100000000004a4a783bu128, "LDSM.16.M88.2 R74, [R74]"), // libcublasLt.so.586.sm_100.cubin@0e90 sm100
    (0x000e620000000100000000004a4a783bu128, "LDSM.16.M88.2 R74, [R74]"), // libcublasLt.so.581.sm_100.cubin@0dc0 sm100
    (0x000e220000000100000000004c4c783bu128, "LDSM.16.M88.2 R76, [R76]"), // libcublasLt.so.581.sm_100.cubin@0e20 sm100
];

#[test]
fn bug098_decode_vendor_exact_sm103a() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("word {w:032x}: {e}"));
        assert_eq!(cubit::printer::to_sass(&d), golden, "sm103a word {w:032x}");
    }
}

#[test]
fn bug098_decode_vendor_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("word {w:032x}: {e}"));
        assert_eq!(cubit::printer::to_sass(&d), golden, "sm120 word {w:032x}");
    }
}

#[test]
fn bug098_roundtrip_word_exact_sm103a() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("sm103a encode {text}: {e}"));
        assert_eq!(w2 & M96, w & M96, "sm103a roundtrip: {text}");
    }
}

#[test]
fn bug098_roundtrip_word_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("sm120 encode {text}: {e}"));
        assert_eq!(w2 & M96, w & M96, "sm120 roundtrip: {text}");
    }
}

#[test]
fn bug098_sm120_junk_keys_gone() {
    let t = t120();
    let junk = ["LDSM.16.M88.2_R_AR", "LDSM.16.M88.4_R_AR", "LDSM.16.M88.4_R_ARI",
        "LDSM.16.M88.4_R_ARURI", "LDSM.16.M88_R_AUR", "LDSM.16.MT88.4_R_AR",
        "LDSM.16.MT88.4_R_ARURI"];
    for k in junk {
        assert!(t.entries.get(k).is_none(), "junk key still present: {k}");
    }
    assert!(t.entries.get("LDSM_R_ARI").is_some());
    assert!(t.entries.get("LDSM_R_ARURI").is_some());
    // same verdict on canon: plain-ARI modgroup must exist post-fix
    let c = t103();
    let ari = c.entries.get("LDSM_R_ARI").expect("canon LDSM_R_ARI");
    assert!(ari.mod_groups.get("16,M88").is_some(), "canon plain-ARI mg missing");
}
