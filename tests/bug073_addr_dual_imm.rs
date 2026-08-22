//! BUG-073 (sm120 i143 / 073_lds_sts_dual_imm.md; fixed F2 2026-08-22):
//! memory-address parser silently dropped every immediate component of a
//! bracketed address except the LAST one (`[R26+0x8+0x4]` encoded as
//! `[R26+0x4]`), and silently ignored unclassifiable components
//! (`[R26+foo]` -> `[R26]`). Reported from a real generator emitting
//! base+align window pairs (tcb143): 16 slots degraded quietly, silicon
//! CUDA_OK with wrong loads (EXACT-gate bad=8995/10240).
//!
//! Fix (src/parser.rs parse_address): every '+'-separated bracket component
//! must classify exactly once; immediates fold arithmetically (checked i64),
//! duplicate base/UR registers and unknown components fail closed (parse
//! error, rc=1 via strict parse on the asm path -- BUG-042/043 doctrine).
//!
//! Repro pre-fix (binary 2d255dac / ead128b, both tables):
//!   LDS R10, [R26+0x8+0x4] ;  -> 0x..04001a0a7984   (== [R26+0x4]: 0x8 lost)
//!   post-fix                 -> 0x..0c001a0a7984   (== [R26+0xc], folded)

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

// (1) The i143/i145 repro family: dual immediates fold to their sum and
// encode IDENTICALLY to the canonical single-offset form. Fixed-point
// words pinned from the post-fix encoder (payload with default ctrl; the
// offset lane [55:24] carries 0x0c).
#[test]
fn t1_dual_imm_folds_to_sum_fixed_points() {
    for t in [t103a(), t120()] {
        for (dual, mono) in [
            ("LDS R10, [R26+0x8+0x4]", "LDS R10, [R26+0xc]"),
            ("STS [R26+0x8+0x4], R10", "STS [R26+0xc], R10"),
            ("LDG.E R12, [R26+0x8+0x4]", "LDG.E R12, [R26+0xc]"),
            ("STG.E [R26+0x8+0x4], R12", "STG.E [R26+0xc], R12"),
            ("LDS R10, [R26+0x10+-0x4]", "LDS R10, [R26+0xc]"),
            ("LDS R10, [R26+0x8 +0x4]", "LDS R10, [R26+0xc]"),
        ] {
            assert_eq!(
                enc(dual, &t).unwrap(),
                enc(mono, &t).unwrap(),
                "dual-imm {dual:?} must encode like {mono:?}"
            );
        }
        // encoder fixed-point anchors (0x0c in the offset lane)
        assert_eq!(enc("LDS R10, [R26+0xc]", &t).unwrap(), 0x000fc2000000080000000c001a0a7984u128);
        assert_eq!(enc("STS [R26+0xc], R10", &t).unwrap(), 0x000fc2000000080000000c0a1a007388u128);
    }
}

// (2) Descriptor addresses share the bracket parser per component: the dual
// immediate folds BEFORE encoder-side alignment/width validation.
#[test]
fn t2_desc_dual_imm_folds_then_validates() {
    let t = t103a();
    assert_eq!(
        enc("STG.E.ENL2.256 desc[UR4][R2.64+0x20+0x40], R40, R44", &t).unwrap(),
        enc("STG.E.ENL2.256 desc[UR4][R2.64+0x60], R40, R44", &t).unwrap(),
    );
    // misaligned sum still rejected by the BUG-070 window guard
    enc("STG.E.ENL2.256 desc[UR4][R2.64+0x8+0x4], R40, R44", &t)
        .expect_err("misaligned 0xc must stay rejected (fold is pre-validation)");
}

// (3) Unclassifiable bracket components fail closed (previously ignored).
#[test]
fn t3_unknown_component_fails_closed() {
    let t = t103a();
    for bad in [
        "LDS R10, [R26+foo]",
        "LDS R10, [R26+0x8+0xZZ]",
        "LDS R10, [R26+0x1x]",
        "LDS R10, [R26-4]",
        "LDS R10, [URZ+0x8]",
    ] {
        let e = enc(bad, &t).expect_err(&format!("must fail closed: {bad}"));
        assert!(format!("{e:#}").contains("unencodable memory address"), "{bad}: got {e:#}");
    }
}

// (4) Duplicate register components fail closed (previously last-one-won).
#[test]
fn t4_duplicate_register_fails_closed() {
    let t = t103a();
    for bad in [
        "LDS R10, [R26+R27+0x8]",
        "LDS R10, [R26.64+R27+0x8]",
        "LDS R10, [UR4+UR5+0x8]",
        "LDS R10, [RZ+R26]",
    ] {
        enc(bad, &t).expect_err(&format!("duplicate register must fail: {bad}"));
    }
}

// (5) Immediate fold overflow fails closed instead of wrapping.
#[test]
fn t5_fold_overflow_fails_closed() {
    let t = t103a();
    enc("LDS R10, [R26+0x7fffffffffffffff+0x1]", &t)
        .expect_err("i64 overflow of folded offset must fail closed");
    enc("LDS R10, [R26+-0x8000000000000000+-0x1]", &t)
        .expect_err("neg overflow of folded offset must fail closed");
}

// (6) Decoder/render unaffected: the folded word round-trips through
// decode -> canonical single-offset text -> identical word.
#[test]
fn t6_decode_render_reencode_fixed_point() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let word = 0x000fc2000000080000000c001a0a7984u128;
    let d = idx.decode(word, 0, &t).unwrap();
    let text = cubit::printer::to_sass(&d);
    assert_eq!(text, "LDS R10, [R26+0xc]");
    assert_eq!(enc(&text, &t).unwrap(), word);
}

// (7) Legacy single-imm and suffix forms untouched by the rewrite.
#[test]
fn t7_legacy_forms_unchanged() {
    let t = t103a();
    assert_eq!(enc("LDS R10, [R26-0x4]", &t).unwrap(), 0x000fc20000000800fffffc001a0a7984u128);
    assert_eq!(
        enc("LDS R10, [R26.64+0x8+0x4]", &t).unwrap(),
        enc("LDS R10, [R26.64+0xc]", &t).unwrap(),
        "base suffix must survive the fold"
    );
}
