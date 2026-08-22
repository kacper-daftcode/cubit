//! b11 render-parity (loop5 iter29, 2026-08-22; report results/b11/RP-1.md):
//! era truth-surface (rt98) vs `cubit disassemble` spelling, closed for the
//! three classes where the era reading is unambiguous and vendor-consistent
//! (12M-instr corpus / vendor_all.json anchors, b4fill-doctrine):
//!
//! * LOP3.LUT.PAND (was LOP3.PAND.LUT): era anchor (40 rt98 lines); PAND has
//!   no vendor-corpus representative (0 hits), era text + era table key
//!   (tb_i82p2 LOP3.LUT.PAND_P_R_R_II_R_II_P) converge; scoped printer rule,
//!   LOP3-family only.
//! * LDG/STG ...GPU.HINT order (was ...EFL2.HINT.256...): era anchor (4 slots;
//!   HINT prints after scope). EFL2 has no vendor-corpus presence either.
//! * IADD3.X imm-form tail-pred-1 neg@90 (was "PT" + !rsd[90:1]): era anchor
//!   (5 lines `@!P0 IADD3.X ..., !PT, !PT`), mirrors tok8 pred@77 + neg@80
//!   geometry. Vendor-neutral (66915 vendor IADD3.X all b90=0). The RR-form
//!   sibling (77 lines, era prints PT + rsd[90:1]) DELIBERATELY stays
//!   residue-carried -- era itself classifies bit90 there as residue
//!   (cross-tab in the report); adding the field to the RR row would flip 77
//!   era-matching lines to era-divergent.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn decode_text(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode must succeed")
}

fn enc_bytes(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode")
}

#[test]
fn lop3_lut_pand_order() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // rt98 KernelB+0x8a0 (era: LOP3.LUT.PAND P4, RZ, R71, 0x800, RZ, 0xc0, P5)
    let w = 0x000fe2000289c0ff0000080047ff7812u128;
    let txt = decode_text(&t, &idx, w);
    assert_eq!(txt, "LOP3.LUT.PAND P4, RZ, R71, 0x800, RZ, 0xc0, P5");
    // encoder accepts the era spelling byte-exact (sched excluded)...
    let re = enc_bytes(&t, &txt);
    assert_eq!(re & !SCHED, w & !SCHED, "LOP3.LUT.PAND asm byte-exact");
    // ...and the legacy flipped spelling keeps encoding to the same word
    let legacy = enc_bytes(&t, "LOP3.PAND.LUT P4, RZ, R71, 0x800, RZ, 0xc0, P5");
    assert_eq!(legacy & !SCHED, w & !SCHED, "PAND.LUT legacy spelling still byte-exact");
}

#[test]
fn ldg_efl2_hint_after_scope() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // rt98 KernelB+0x570 (HINT-pair, b4fill3 row; GOLD there updated)
    let w = 0x000824000850e0387e00000c0334797eu128;
    assert_eq!(
        decode_text(&t, &idx, w),
        "LDG.E.NA.EFL2.256.STRONG.GPU.HINT R56, R52, desc[UR12][R3.64]"
    );
}

#[test]
fn iadd3x_imm_tail_neg90() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // rt98 KernelB+0xc80; era renders tail1 !PT (neg@90), residue stays only bit123
    let w = 0x080fe80007f3e4fffffffc2f74748810u128;
    let txt = decode_text(&t, &idx, w);
    assert_eq!(txt, "@!P0 IADD3.X R116, P1, PT, R116, -0x3d1, RZ, !PT, !PT");
    // asm of the !PT tail sets bit90 (residue 123 via rsd overlay in full text)
    let re = enc_bytes(&t, &txt);
    assert_ne!(re & (1u128 << 90), 0, "bit90 written from !PT neg@90 field");
    // full fidelity incl. rsd suffix
    let full = enc_bytes(&t, "@!P0 IADD3.X R116, P1, PT, R116, -0x3d1, RZ, !PT, !PT !rsd[123:1]");
    assert_eq!(full & !SCHED, w & !SCHED, "II-form !PT + rsd[123:1] byte-exact");
}

#[test]
fn iadd3x_rr_keeps_residue_bit90() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // rt98 KernelB+0x760: era prints PT + rsd[90:1]; RR row must NOT claim neg@90
    let w = 0x002fe20007f1e4ff0000005834345210u128;
    let txt = decode_text(&t, &idx, w);
    assert_eq!(txt, "@P5 IADD3.X R52, P0, PT, R52, R88, RZ, PT, !PT");
}
