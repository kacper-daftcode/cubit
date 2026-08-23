//! BUG-103 + BUG-105 (F2Q deposit from mk300, 2026-08-23, iter 497):
//! the tcgen05 c1 UTC*MMA descriptor-form family (UTCHMMA/UTCIMMA/UTCQMMA/
//! UTCOMMA, `_II_II_II_II_...` operand sig) stamped a WRONG ctrl word on the
//! encode path — generic default 0x000fc200 (single encode) or the sched-pass
//! c3-stamp 0x000fca00 (`cubit asm` flow, 105-kand) — while vendor ptxas is
//! CONSTANT per (class, guard-presence), independent of dataflow:
//!   direct  (PT guard):   d3 = 0x0011d800 (stall=12 yield=0 rbar=0 wbar=7 wait=0x01)
//!   guarded (@!UP0/!UP1): d3 = 0x0001f200 (stall=9  yield=1 rbar=0 wbar=7 wait=0x00)
//! 750/750 mk300 vendor words split 1:1 (both arches, 7/8-op), plus the mk296
//! corpus control matrix: 6-op `_UP`, `.WS`, `.2CTA`, UTCOMMA*, UTCQMMA-bs
//! (tmem-tok6) all ride the DIRECT stamp even when guarded.
//!
//! Fix (ctrl_class.rs + encoder.rs; no table changes): `utc_mma_vendor_ctrl`
//! returns the vendor-constant ControlCode for the family; the encoder uses it
//! for non-hand_sched instructions (author `[B..]` prefixes always win).
//!
//! Pre-fix all full-word pins below FAIL on the d3 half (payload 96 bits were
//! already vendor-exact after BUG-104/956742d).

use cubit::ctrl_class::utc_mma_vendor_ctrl;
use cubit::encoder::encode_instruction;
use cubit::parser::{parse_cuasm_line, parse_sass};
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode")
}

fn d3(code: u128) -> u32 {
    (code >> 96) as u32
}

/// 105-kand: 6-op `_UP` class rode the c3-stamp 0x000fca00 in the asm flow
/// (and 0x000fc200 in single encode); vendor = direct 0x0011d800.
#[test]
fn t105_1_direct_6op_up() {
    let c = enc(
        "UTCHMMA gdesc[UR6], gdesc[UR8], tmem[UR11], tmem[UR4], idesc[UR5], UPT",
        &t103(),
    );
    assert_eq!(d3(c), 0x0011d800, "6-op _UP must stamp vendor direct d3");
}

/// 103-kand direct 7-op: full 128-bit vendor anchor (mk300 d_cv1s3_f16).
#[test]
fn t103_2_direct_7op_fullword() {
    let c = enc(
        "UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, UPT",
        &t103(),
    );
    assert_eq!(c, 0x0011d8000b800006000804ffff0075ea);
}

/// 103-kand guarded 7-op: full vendor anchor (mk300 d_v1s3_f16, @!UP1).
#[test]
fn t103_3_guarded_7op_fullword() {
    let c = enc(
        "@!UP1 UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR10], tmem[UR8], idesc[UR9], UR4, UPT",
        &t103(),
    );
    assert_eq!(c, 0x0001f2000b80000a000408ffff0095ea);
}

/// Guarded 8-op (imm tail) full vendor anchor (mk300 u2_sc1).
#[test]
fn t103_4_guarded_8op_imm_fullword() {
    let c = enc(
        "@!UP1 UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR10], tmem[UR8], idesc[UR9], UR4, !UPT, 0x1",
        &t103(),
    );
    assert_eq!(c, 0x0001f2000f80080a000408ffff0095ea);
}

/// Negative space: UTCQMMA block-scale sibling (tmem in tok6, `_II_II` sig)
/// must NOT take the guarded stamp even when guarded (mma_c1_mxf8f6f4_bs).
#[test]
fn t103_5_qmma_bs_guarded_is_direct() {
    let c = enc(
        "@!UP1 UTCQMMA gdesc[URZ], gdesc[URZ], tmem[UR8], tmem[UR4], idesc[UR5], tmem[UR6], !UPT",
        &t103(),
    );
    assert_eq!(d3(c), 0x0011d800, "bs sibling stays direct");
}

/// Negative space: UTCOMMA is always direct (mma_c1_mxf4nvf4_bs16).
#[test]
fn t103_6_utcomma_guarded_is_direct() {
    let c = enc(
        "@!UP1 UTCOMMA.BLOCK16 gdesc[URZ], gdesc[URZ], tmem[UR8], tmem[UR4], idesc[UR5], tmem[UR6], !UPT",
        &t103(),
    );
    assert_eq!(d3(c), 0x0011d800, "UTCOMMA stays direct");
}

/// Negative space: .2CTA always direct (mma_c2_mxf8f6f4_bs).
#[test]
fn t103_7_2cta_guarded_is_direct() {
    let c = enc(
        "@!UP1 UTCQMMA.2CTA gdesc[URZ], gdesc[URZ], tmem[UR8], tmem[UR4], idesc[UR5], tmem[UR6], !UPT",
        &t103(),
    );
    assert_eq!(d3(c), 0x0011d800, "2CTA stays direct");
}

/// Negative space: .WS 6-op always direct (mmaws_c1_f16).
#[test]
fn t103_8_ws_6op_guarded_is_direct() {
    let c = enc(
        "@!UP1 UTCHMMA.WS gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], !UPT",
        &t103(),
    );
    assert_eq!(d3(c), 0x0011d800, "WS stays direct");
}

/// Guard-law edge: `@PT` on the guarded class = direct; other uniform guards
/// outside the vendor-observed {{@!UP0,@!UP1}} set also ride direct (fail-closed).
#[test]
fn t103_9_guard_law_edges() {
    let t = t103();
    let pt = enc(
        "@PT UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, UPT",
        &t,
    );
    assert_eq!(d3(pt), 0x0011d800, "@PT is direct");
    let in_direct = parse_sass(
        "@!UP2 UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, UPT ;",
        0,
    )
    .unwrap();
    let cc = utc_mma_vendor_ctrl(&in_direct).unwrap();
    assert_eq!(
        (cc.stall, cc.yield_flag, cc.wait_mask),
        (12, false, 0x01),
        "@!UP2 is outside the vendor-observed guard set {{@!UP0,@!UP1}}: fail-closed ride direct"
    );
}

/// Author `[B..]` control prefixes (hand_sched) always win over the vendor law.
#[test]
fn t103_10_hand_sched_prefix_wins() {
    let t = t103();
    let insn = parse_cuasm_line(
        "[B0-----:R2:W1:Y:S07] UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, UPT",
        0,
    )
    .unwrap();
    assert!(insn.hand_sched);
    let c = encode_instruction(&insn, &t).unwrap();
    // packed = w1|r2|wait1|Y|S07 = 0xA37 -> <<9 = 0x146E00
    assert_eq!(d3(c), 0x00146e00, "author sched must pass through verbatim");
}

/// No-FP regression: non-family instructions keep the inherited default
/// (IMAD: epoch default 0x000fc200 base + stall=1 default ctrl).
#[test]
fn t103_11_non_family_default_unchanged() {
    let c = enc("IMAD.MOV.U32 R0, RZ, RZ, RZ", &t103());
    assert_eq!(d3(c), 0x000fc200, "non-family default ctrl must not move");
}

/// sm120 UR-form exclusion: `UTCHMMA.1CTA UR,UR,UR,UR,UR,UP` (UR signature,
/// no II descriptors) is outside the law — predicate returns None.
#[test]
fn t103_12_sm120_ur_form_excluded() {
    let insn = parse_sass("UTCHMMA.1CTA UR4, UR6, UR8, UR10, UR12, UPT ;", 0).unwrap();
    assert!(
        utc_mma_vendor_ctrl(&insn).is_none(),
        "UR-form (sm120 warszawa) must not match"
    );
}

/// 105-kand pipeline proof: in the full `cubit asm` flow (schedule +
/// reallocate_barriers), the vendor stamps survive the barrier reallocator
/// (it clears wait/rbar/wbar on non-frozen insns — the family is exempt via
/// the encode-time law, which ignores the mutated insn.ctrl for this family).
#[test]
fn t105_13_asm_pipeline_stamps() {
    let src = ".entry k\n    .reg R0-R1\n    .param u64 p0\n    S2R R0, SR_TID.X ;\n    UTCHMMA gdesc[UR6], gdesc[UR8], tmem[UR11], tmem[UR4], idesc[UR5], UPT ;\n    @!UP1 UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, UPT ;\n    EXIT ;\n.endentry\n";
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let t = t103();
    schedule(&mut insns, Some(&t));
    reallocate_barriers(&mut insns, Some(&t));
    let mma: Vec<u128> = insns
        .iter()
        .filter(|x| x.opcode == "UTCHMMA")
        .map(|x| encode_instruction(x, &t).unwrap())
        .collect();
    assert_eq!(mma.len(), 2);
    assert_eq!(d3(mma[0]), 0x0011d800, "pipeline vision: unguarded direct");
    assert_eq!(d3(mma[1]), 0x0001f200, "pipeline vision: guarded stamp");
    // The pipeline may have massaged insn.ctrl itself (105 c3-stamp region);
    // the encode-time law decides. Pin the end artifact only.
}
