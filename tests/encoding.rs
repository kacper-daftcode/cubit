//! Integration tests for instruction encoding.

use cubit::table::IsaTable;
use cubit::parser::parse_sass;
use cubit::encoder::encode_instruction;

fn load_table() -> Option<IsaTable> {
    match IsaTable::load_default() {
        Ok(t) => Some(t),
        Err(e) => { eprintln!("Skipping: {e}"); None }
    }
}

#[test]
fn test_iadd3_encoding() {
    let table = match load_table() { Some(t) => t, None => return };
    let insn = parse_sass("IADD3 R5, PT, PT, R9, R4, R5 ;", 0).unwrap();
    let code = encode_instruction(&insn, &table).unwrap();
    let sched_mask: u128 = 0x1FFFF_u128 << (64 + 41);
    let _clean = code & !sched_mask;
    // Just verify it encodes without error
    assert!(code != 0, "IADD3 should produce non-zero encoding");
}

#[test]
fn test_iadd3_negative_immediate() {
    // IADD3 with a negative immediate must encode bit-exactly like ptxas: the 32-bit
    // immediate field (insn_lo[63:32]) is two's complement, so -0x20 -> 0xffffffe0.
    // Cross-checked vs ptxas sm_120a: IADD3 R5,PT,PT,R0,-0x20,R5 -> 0xffffffe000057810
    // (immediate field + 0x7810 opcode identical). Used by the in-place A-frag pointer
    // reset in the sparse-MLA decode kernel.
    let table = match load_table() { Some(t) => t, None => return };
    let insn = parse_sass("IADD3 R0, PT, PT, R5, -0x20, R7 ;", 0).unwrap();
    assert_eq!(insn.key, "IADD3_R_P_P_R_II_R");
    let code = encode_instruction(&insn, &table).unwrap();
    let lo = code as u64;
    assert_eq!((lo >> 32) & 0xffff_ffff, 0xffff_ffe0, "IADD3 -0x20 immediate field (two's complement)");
    assert_eq!(lo & 0xffff, 0x7810, "IADD3-immediate opcode");
}

#[test]
fn test_hadd2_f32_source_register() {
    // HADD2.F32 Rd, -RZ, Rsrc.H0_H0 (f16->f32 widening): the source register (Rb,
    // operand 2) must be encoded at bits[39:32]. The table field was token_idx:0
    // (get_op is 1-based -> None -> 0), so the source was silently dropped; fixed to
    // token_idx:3. Bit-exact vs ptxas sm_120a: HADD2.F32 R7,-RZ,R0.H0_H0 -> 0x...ff077230.
    // Use the shipped table (tables/sm120.json) explicitly.
    let table = match IsaTable::load(std::path::Path::new("tables/sm120.json")) {
        Ok(t) => t, Err(_) => return,
    };
    let enc = |s: &str| -> u64 {
        let insn = parse_sass(s, 0).unwrap();
        encode_instruction(&insn, &table).unwrap() as u64
    };
    assert_eq!(enc("HADD2.F32 R7, -RZ, R0.H0_H0 ;"), 0x20000000ff077230, "ptxas bit-exact");
    // source register lands at bits[39:32]
    assert_eq!((enc("HADD2.F32 R42, -RZ, R5.H0_H0 ;") >> 32) & 0xff, 5);
    assert_eq!((enc("HADD2.F32 R42, -RZ, R41.H0_H0 ;") >> 32) & 0xff, 41);
}

#[test]
fn test_lds_u16_addr_encoding() {
    // LDS.U16 [Rbase+off]: base reg at [31:24], 24-bit byte offset at [63:40].
    // cubit's LDS.U16_R_ARI had base at shift 25 (encoded R<<1) and offset at shift 44;
    // fixed to the LDS_R_ARI layout (sub_r0 @24, sub_imm1 @40). Bit-exact vs ptxas
    // sm_120a: LDS.U16 R7,[R5+0x2000] -> 0x0020000005077984. (Uses tables/sm120.json.)
    let table = match IsaTable::load(std::path::Path::new("tables/sm120.json")) {
        Ok(t) => t, Err(_) => return,
    };
    let insn = parse_sass("LDS.U16 R7, [R5+0x2000] ;", 0).unwrap();
    let code = encode_instruction(&insn, &table).unwrap() as u64;
    assert_eq!(code, 0x0020000005077984, "LDS.U16 base+offset bit-exact vs ptxas");
}

#[test]
fn test_ldg_u16_desc_offset_encoding() {
    // LDG.E.U16/U8 desc[UR][Rbase+off]: the dARI (E,U16 / E,U8) mod_groups had the
    // sub_imm2 (offset) field on token_idx 1 (the dest reg) instead of 2 (the Desc
    // operand), so op_sub_imm read the wrong operand and the immediate offset was
    // dropped (b0=b1=b2=b3 in transposing gathers). Fixed token_idx 1->2.
    // Offset 0x400 must land at [63:40]; base R26 at [31:24]; dest R56 at [23:16].
    let table = match IsaTable::load(std::path::Path::new("tables/sm120.json")) {
        Ok(t) => t, Err(_) => return,
    };
    let with = encode_instruction(&parse_sass("LDG.E.U16 R56, desc[UR4][R26.64+0x400] ;", 0).unwrap(), &table).unwrap() as u64;
    let without = encode_instruction(&parse_sass("LDG.E.U16 R56, desc[UR4][R26.64] ;", 0).unwrap(), &table).unwrap() as u64;
    // Offset 0x400 at [63:40]; descriptor UR4 at [39:32]=0x04 (verified vs cuobjdump
    // ground truth — previously the UR was wrongly baked as a constant 0x24); base
    // R26 at [31:24]=0x1a; dest R56 at [23:16]=0x38.
    assert_eq!(with, 0x000400041a387981, "LDG.E.U16 desc UR + offset must encode at [39:32]/[63:40]");
    assert_eq!(with - without, 0x400u64 << 40, "offset delta = 0x400<<40 (was dropped before fix)");
}

#[test]
fn test_parser_operands() {
    let insn = parse_sass("IADD3 R5, PT, PT, R9, R4, R5 ;", 0).unwrap();
    assert_eq!(insn.key, "IADD3_R_P_P_R_R_R");
    assert_eq!(insn.operands.len(), 6);
    assert_eq!(insn.opcode, "IADD3");
    assert!(insn.guard.is_none());
}

#[test]
fn test_parser_guard() {
    let insn = parse_sass("@P0 IADD3 R5, PT, PT, R9, R4, R5 ;", 0).unwrap();
    assert!(insn.guard.is_some());
    let g = insn.guard.unwrap();
    assert_eq!(g.pred, 0);
    assert!(!g.negated);
}

#[test]
fn test_parser_negated_guard() {
    let insn = parse_sass("@!P1 BRA 0x100 ;", 0).unwrap();
    let g = insn.guard.unwrap();
    assert_eq!(g.pred, 1);
    assert!(g.negated);
}

#[test]
fn test_parser_float_context() {
    let insn = parse_sass("DADD R2, R18, 1 ;", 0).unwrap();
    // "1" is parsed as FloatImm in DADD (float) context, so the key suffix is FI.
    assert_eq!(insn.key, "DADD_R_R_FI");
    match &insn.operands[2] {
        cubit::ir::Operand::FloatImm(_) => {}
        other => panic!("Expected FloatImm, got {:?}", other),
    }
}

#[test]
fn test_parser_descriptor() {
    let insn = parse_sass("LDG.E R10, desc[UR4][R2.64+0x8] ;", 0).unwrap();
    assert_eq!(insn.key, "LDG_R_dARI");
    match &insn.operands[1] {
        cubit::ir::Operand::Desc { ur_idx, base_reg, offset, .. } => {
            assert_eq!(*ur_idx, 4);
            assert_eq!(*base_reg, Some(2));
            assert_eq!(*offset, 8);
        }
        other => panic!("Expected Desc, got {:?}", other),
    }
}

#[test]
fn test_parser_barrier() {
    let insn = parse_sass("BSSY B7, 0x100 ;", 0).unwrap();
    assert_eq!(insn.key, "BSSY_B_II");
    match &insn.operands[0] {
        cubit::ir::Operand::Barrier(7) => {}
        other => panic!("Expected Barrier(7), got {:?}", other),
    }
}

#[test]
fn test_scheduling_roundtrip() {
    use cubit::scheduling::*;
    let cases = ["B------:R-:W-:-:S01", "B0----5:R0:W5:Y:S05", "B--2---:R0:W1:-:S07"];
    for s in cases {
        let cc = parse_control_code(s).unwrap();
        let code = encode_control_code(&cc);
        let cc2 = decode_control_code(code);
        let s2 = format_control_code(&cc2);
        assert_eq!(s, s2, "scheduling roundtrip failed for {s}");
    }
}

#[test]
fn test_decode_print_roundtrip() {
    let table = match load_table() { Some(t) => t, None => return };
    let index = cubit::decoder::DecodeIndex::build(&table);

    // Encode an instruction, decode it, print it
    let insn = parse_sass("IADD3 R5, PT, PT, R9, R4, R5 ;", 0).unwrap();
    let code = encode_instruction(&insn, &table).unwrap();
    let decoded = index.decode(code, 0, &table).unwrap();

    // Print should produce valid SASS text
    assert_eq!(decoded.opcode, "IADD3");
    assert!(decoded.fields.iter().any(|f| f.name == "Rd" && f.value == 5));
}

#[test]
fn test_metadata_from_table() {
    let table = match load_table() { Some(t) => t, None => return };
    // Scheduling metadata comes from the same sm120.json
    assert!(table.num_keys() > 0);
    // Check stats
    assert!(table.num_keys() > 0);
}

// ── Sparse-MLA PV round-trip regression set (refs/pv_ptx_kernel.cubin) ─────────
// These forms were missing/wrong in the ISA table or split logic and broke the
// byte-faithful round-trip of ptxas's PV kernel (cubit roundtrip 199/232 -> 232/232,
// cubit patch byte-identical, 20/20 @ 2-CTA). Each expected value is ptxas ground
// truth with the scheduling word (bits[121:105]) masked out.

const PV_SCHED_MASK: u128 = 0x1FFFF_u128 << (64 + 41);

fn pv_table() -> Option<IsaTable> {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).ok()
}

fn enc_clean(table: &IsaTable, s: &str) -> u128 {
    let insn = parse_sass(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap() & !PV_SCHED_MASK
}

#[test]
fn test_imad_wide_signed_encoding() {
    // Signed IMAD.WIDE (no .U32) shares the low opcode 0x7225 with IMAD.WIDE.U32 and
    // only differs by the S32 bit (73). The IMAD_R_R_R_R::WIDE and_base had the wrong
    // low opcode 0x7825 -> ptxas illegal-instruction crash in the PV address math.
    let table = match pv_table() { Some(t) => t, None => return };
    assert_eq!(enc_clean(&table, "IMAD.WIDE R8, R31, R6, R8 ;"),
               0x00000000078e0208000000061f087225);
    assert_eq!(enc_clean(&table, "IMAD.WIDE R8, R31, R6, R8 ;") as u64 & 0xffff, 0x7225,
               "signed IMAD.WIDE low opcode must be 0x7225 not 0x7825");
}

#[test]
fn test_shf_l_u64_hi_encoding() {
    // SHF.L.U64.HI_R_R_II_R was missing the .U64/.HI signature bits (73,80) in its
    // and_base, so the funnel-shift high word was wrong.
    let table = match pv_table() { Some(t) => t, None => return };
    assert_eq!(enc_clean(&table, "SHF.L.U64.HI R7, R6, 0x1, R7 ;"),
               0x00000000000102070000000106077819);
}

#[test]
fn test_ldg_u8_desc_offset_encoding() {
    // LDG.E.U8.CONSTANT desc[UR][R.64+imm]: the dARI fields were at the wrong shifts
    // (reg@25, ureg@33) with no offset field, so base/UR were doubled and the +0x9000
    // offset was dropped -> illegal memory access in the gather.
    let table = match pv_table() { Some(t) => t, None => return };
    assert_eq!(enc_clean(&table, "LDG.E.U8.CONSTANT R36, desc[UR6][R36.64+0x9000] ;"),
               0x000000000c1e91000090000624247981);
}

#[test]
fn test_fsetp_geu_and_float_imm_encoding() {
    // FSETP.GEU.AND P,PT,R,FI,P had a bogus pred@72 token-0 field that encoded PT (3)
    // into the Ra abs/neg bits (72,73); replaced with neg@72/abs@73 on the Ra reg.
    let table = match pv_table() { Some(t) => t, None => return };
    assert_eq!(enc_clean(&table, "FSETP.GEU.AND P0, PT, R33, -126, PT ;"),
               0x0000000003f0e000c2fc00002100780b);
}

#[test]
fn test_plop3_lut_imm_split_encoding() {
    // PLOP3.LUT immediate split was inverted: the LUT low 3 bits go to imm@64 and the
    // high 5 bits to imm_shr3@72 (was imm_shr5@64 / imm@72).
    let table = match pv_table() { Some(t) => t, None => return };
    assert_eq!(enc_clean(&table, "PLOP3.LUT P0, PT, PT, PT, PT, 0x80, 0x8 ;"),
               0x0000000003f0f070000000000008781c);
}

#[test]
fn test_uisetp_ge_and_imm_encoding() {
    // UISETP.GE.AND immediate form: the AND,GE entry used the register-form opcode
    // (0x7c8c) and opaque_mod fields that zeroed the baked GE/S32/AND; rebuilt to the
    // immediate opcode 0x788c with the correct upred/ureg/imm field layout.
    let table = match pv_table() { Some(t) => t, None => return };
    assert_eq!(enc_clean(&table, "UISETP.GE.AND UP0, UPT, UR5, 0x10, UPT ;"),
               0x000000000bf06270000000100500788c);
}

#[test]
fn test_flashattention_sm120_roundtrip_forms() {
    // Forms observed in ptxas_sm120_fmha_fwd.cubin. These were the remaining
    // round-trip blockers for using cubit as a full patcher for that cubin.
    let table = match pv_table() { Some(t) => t, None => return };

    assert_eq!(enc_clean(&table, "S2R R13, SR_SWINHI ;"),
               0x0000000000002f0000000000000d7919);
    assert_eq!(enc_clean(&table, "UVIMNMX.S32 UR4, UR5, 0x40, UPT ;"),
               0x000000000bfe0100000000400504784a);
    assert_eq!(enc_clean(&table, "UVIMNMX.S32 UR4, UR10, 0x1, !UPT ;"),
               0x000000000ffe0100000000010a04784a);
    assert_eq!(enc_clean(&table, "@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64] ;"),
               0x000000000b9a180e0000000016038fae);
    assert_eq!(enc_clean(&table, "LDGDEPBAR ;"),
               0x000000000000000000000000000079af);
    assert_eq!(enc_clean(&table, "DEPBAR.LE SB0, 0x1 ;"),
               0x0000000000000000000080400000791a);
    assert_eq!(enc_clean(&table, "STS.U16 [R20+UR13+0x4008], R129 ;"),
               0x000000000800040d0040088114007988);
    assert_eq!(enc_clean(&table, "FSEL R12, R3, RZ, P3 ;"),
               0x0000000001800000000000ff030c7208);
}

#[test]
fn test_f2fp_unpack_b_decode_print() {
    // F2FP...UNPACK_B / PACK_B: the "_B" lane suffix was mis-split as a Barrier operand,
    // so decode printed "F2FP.F16.E4M3.UNPACK B0, R8, R8" (dropping the dest reg). The
    // patch round-trip then re-encoded Rd=0 -> illegal memory access.
    let table = match pv_table() { Some(t) => t, None => return };
    let index = cubit::decoder::DecodeIndex::build(&table);
    // ptxas bytes for: F2FP.F16.E4M3.UNPACK_B R7, R8
    let code = 0x008fca00020006ff00000008ff07723e_u128;
    let d = index.decode(code, 0, &table).unwrap();
    assert_eq!(d.opcode, "F2FP.F16.E4M3.UNPACK_B");
    assert_eq!(cubit::printer::to_sass(&d), "F2FP.F16.E4M3.UNPACK_B R7, R8");
}

// ── Bug-1 regression: wrong-signature table entries must be REJECTED ──────────
// Hardware-confirmed failure mode: the lookup chain picked a (base-key, mod_group)
// entry harvested from the WRONG operand form (e.g. register-form fields under an
// immediate-form key), and the extract_value helpers silently returned 0 defaults —
// `ISETP.LT.AND P1,PT,R2,0x1c0,PT` encoded as `... R2, R0, PT` with "0 failed".

/// Synthetic single-entry table: an "imm-form" key whose fields were harvested from
/// the REGISTER form (tok 4 = reg@32/8) — the exact contamination seen in sm120.json.
fn synthetic_mismatched_table() -> IsaTable {
    use cubit::table::{Field, Extraction, ModGroupEntry, InsKeyEntry};
    use std::collections::HashMap;
    let fields = vec![
        Field { shift: 24, bits: 8, mask: 0xff, token_idx: 3, extraction: Extraction::Reg },
        Field { shift: 32, bits: 8, mask: 0xff, token_idx: 4, extraction: Extraction::Reg },
        Field { shift: 81, bits: 3, mask: 0x7, token_idx: 1, extraction: Extraction::Pred },
    ];
    let mg = ModGroupEntry { and_base: 0x720c, variable_mask: 0, fields, encode_only: false };
    let mut mod_groups = HashMap::new();
    mod_groups.insert("AND,LT".to_string(), mg);
    let mut entries = HashMap::new();
    entries.insert("ISETP_P_P_R_II_P".to_string(),
        InsKeyEntry { mod_groups, ctrl_class: None, epoch_upper32: None, encode_only: false });
    IsaTable { entries, ..Default::default() }
}

#[test]
fn test_reject_reg_form_entry_for_imm_operand() {
    // The only candidate entry has a reg-typed field for the immediate operand:
    // encode must FAIL (not silently produce "R0"), and the error must list the
    // attempted (key, mod_group) pairs with the rejection reason.
    let table = synthetic_mismatched_table();
    let insn = parse_sass("ISETP.LT.AND P1, PT, R2, 0x1c0, PT ;", 0).unwrap();
    let err = encode_instruction(&insn, &table).unwrap_err().to_string();
    assert!(err.contains("attempted keys"), "error must list attempted keys: {err}");
    assert!(err.contains("ISETP_P_P_R_II_P"), "error must name the rejected key: {err}");
    assert!(err.contains("REJECTED"), "error must mark the wrong-signature entry: {err}");
}

#[test]
fn test_reject_imm_form_entry_for_reg_operand() {
    // Converse contamination: an imm-typed field under a register-form key
    // (VIMNMX_R_R_R_P::U32 in the wild) encoded `VIMNMX.U32 R4,R4,R5,PT` as
    // `... R4, 0x0, PT`. A non-RZ register operand must reject an imm-only entry.
    use cubit::table::{Field, Extraction, ModGroupEntry, InsKeyEntry};
    use std::collections::HashMap;
    let fields = vec![
        Field { shift: 16, bits: 8, mask: 0xff, token_idx: 1, extraction: Extraction::Reg },
        Field { shift: 24, bits: 8, mask: 0xff, token_idx: 2, extraction: Extraction::Reg },
        Field { shift: 32, bits: 32, mask: 0xffff_ffff, token_idx: 3, extraction: Extraction::Imm },
    ];
    let mg = ModGroupEntry { and_base: 0x7848, variable_mask: 0, fields, encode_only: false };
    let mut mod_groups = HashMap::new();
    mod_groups.insert("U32".to_string(), mg);
    let mut entries = HashMap::new();
    entries.insert("VIMNMX_R_R_R_P".to_string(),
        InsKeyEntry { mod_groups, ctrl_class: None, epoch_upper32: None, encode_only: false });
    let table = IsaTable { entries, ..Default::default() };

    let insn = parse_sass("VIMNMX.U32 R4, R4, R5, PT ;", 0).unwrap();
    let err = encode_instruction(&insn, &table).unwrap_err().to_string();
    assert!(err.contains("REJECTED"), "imm-typed entry must be rejected for R5: {err}");

    // RZ through an imm field IS legitimate (RZ == 0): same entry, Rb=RZ must encode.
    let insn_rz = parse_sass("VIMNMX.U32 R4, R4, RZ, PT ;", 0).unwrap();
    assert!(encode_instruction(&insn_rz, &table).is_ok(),
        "RZ must be accepted by an imm-form entry (encodes as 0)");
}

#[test]
fn test_reject_fully_baked_entry_for_varying_regs() {
    // A fully-baked entry (no value-carrying fields, registers frozen in and_base —
    // the count=2 FSETP harvests) must be rejected when the instruction's operands
    // carry values the entry cannot encode.
    use cubit::table::{Field, Extraction, ModGroupEntry, InsKeyEntry};
    use std::collections::HashMap;
    let fields = vec![
        Field { shift: 123, bits: 1, mask: 1, token_idx: 4, extraction: Extraction::Reuse },
    ];
    let mg = ModGroupEntry { and_base: 0x0400000003f24000000000040500720b, variable_mask: 0, fields, encode_only: false };
    let mut mod_groups = HashMap::new();
    mod_groups.insert("AND,GT".to_string(), mg);
    let mut entries = HashMap::new();
    entries.insert("FSETP_P_P_R_R_P".to_string(),
        InsKeyEntry { mod_groups, ctrl_class: None, epoch_upper32: None, encode_only: false });
    let table = IsaTable { entries, ..Default::default() };

    let insn = parse_sass("FSETP.GT.AND P2, PT, R8, RZ, PT ;", 0).unwrap();
    let err = encode_instruction(&insn, &table).unwrap_err().to_string();
    assert!(err.contains("no field able to encode"),
        "baked entry must be rejected for P2/R8 it cannot encode: {err}");
}

#[test]
fn test_real_table_refuses_imnmx_imm_form() {
    // IMNMX.U32 reg,reg,imm,pred has no table entry anywhere in the chain — it must
    // hard-error and the message must list every attempted key.
    let table = match pv_table() { Some(t) => t, None => return };
    let insn = parse_sass("IMNMX.U32 R7, R7, 0xf, PT ;", 0).unwrap();
    let err = encode_instruction(&insn, &table).unwrap_err().to_string();
    assert!(err.contains("attempted keys"), "must list attempted keys: {err}");
    assert!(err.contains("IMNMX.U32_R_R_II_P") && err.contains("IMNMX_R_R_II_P"),
        "must list both full and base keys: {err}");
}

#[test]
fn test_wildcard_suffix_chain_still_matches() {
    // The `{fk}_?` wildcard fallback (entries learned with one trailing opaque
    // operand) must still resolve for entries that DO match — the F2FP E4M3 pack
    // form used by the qpack production kernel.
    let table = match pv_table() { Some(t) => t, None => return };
    let insn = parse_sass("F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R26, R14, R26 ;", 0).unwrap();
    assert!(encode_instruction(&insn, &table).is_ok(),
        "F2FP PACK_AB_MERGE_C register form must keep encoding");
}

// ── Bug-3 regression: LDC latency / hand-scheduled producer barriers ──────────
// Hardware-measured (tools/ldc_latency_validate.py, RTX 5090): a barrier-less
// LDC -> consumer needs >= 30 cycles idle and is UNBOUNDED under load; the
// scheduler previously modeled LDC as a 1-cycle fixed-latency producer and
// recorded hand-scheduled defs with no barrier, so an auto-scheduled consumer
// 1-2 instructions after a hand-prologue LDC read garbage CTA-dependently.

#[test]
fn test_hand_sched_ldc_consumer_waits_barrier() {
    use cubit::parser::parse_cuasm_line;
    use cubit::scheduling_pass::schedule;
    let table = load_table();
    // Hand-scheduled LDC sets W2; the auto-scheduled consumer MOV must WAIT B2.
    let mut insns = vec![
        parse_cuasm_line("[B------:R-:W2:-:S02] LDC R7, c[0x0][0x3d0] ;", 0).unwrap(),
        parse_sass("MOV R10, R7 ;", 16).unwrap(),
        parse_sass("EXIT ;", 32).unwrap(),
    ];
    schedule(&mut insns, table.as_ref());
    assert_eq!(insns[1].ctrl.wait_mask & (1 << 2), 1 << 2,
        "consumer of a hand-scheduled LDC (W2) must wait barrier 2, got wait_mask={:#x}",
        insns[1].ctrl.wait_mask);
}

#[test]
fn test_barrierless_ldc_consumer_gets_real_latency_stall() {
    use cubit::parser::parse_cuasm_line;
    use cubit::scheduling_pass::schedule;
    let table = load_table();
    // Hand-scheduled LDC WITHOUT a write barrier (W-): the consumer cannot wait,
    // so it must be stalled by the measured LDC latency (30 - elapsed, clamped to
    // the 15-cycle stall ceiling) instead of the old 1-cycle model.
    let mut insns = vec![
        parse_cuasm_line("[B------:R-:W-:-:S02] LDC R7, c[0x0][0x3d0] ;", 0).unwrap(),
        parse_sass("MOV R10, R7 ;", 16).unwrap(),
        parse_sass("EXIT ;", 32).unwrap(),
    ];
    schedule(&mut insns, table.as_ref());
    assert_eq!(insns[1].ctrl.wait_mask, 0, "no barrier to wait");
    assert!(insns[1].ctrl.stall >= 15,
        "consumer 2 cycles after a barrier-less LDC must stall >= 15 (measured \
         hit latency 30, stall field clamps at 15), got S{:02}",
        insns[1].ctrl.stall);
}

#[test]
fn test_uisetp_uniform_ne_reg_encoding() {
    // UISETP_UP_UP_UR_UR_UP "AND,NE" was a broken stub: and_base 0x...0c8c with the
    // reg-reg opcode (0x28c) and the NE compare code (0x5270) both missing, so it
    // produced an illegal instruction (CUDA 715) -- which blocked uniform-datapath
    // loops (UISETP -> BRA.U UP0), the form ptxas uses for warp-uniform loops.
    // ptxas encodes  UISETP.NE.AND UP0, UPT, UR5, URZ, UPT  as lo=0x000000ff0500728c.
    // (The hi word's upper bits are scheduling-epoch and are injected separately.)
    let table = match IsaTable::load(std::path::Path::new("tables/sm120.json")) {
        Ok(t) => t, Err(_) => return,
    };
    let lo = encode_instruction(
        &parse_sass("UISETP.NE.AND UP0, UPT, UR5, URZ, UPT ;", 0).unwrap(), &table)
        .unwrap() as u64;
    assert_eq!(lo, 0x000000ff0500728c,
        "UISETP.NE.AND uniform reg-reg form must encode like ptxas (opcode 0x28c + URZ cmp)");
}

// ===========================================================================
// SM103a (B300) regression battery — one test per landed fix class.
// All expectations bit-frozen from the run31g table; sched window [121:105]
// masked where we compare against corpus-observed words.
// ===========================================================================
#[cfg(test)]
mod sm103a {
    use cubit::encoder::encode_instruction;
    use cubit::parser::parse_sass;
    use cubit::table::IsaTable;
    use cubit::decoder::DecodeIndex;
    use cubit::printer::to_sass;

    const SCHED_MASK: u128 = (0x1FFFFu128) << 105;

    fn t() -> Option<IsaTable> {
        IsaTable::load(std::path::Path::new("tables/sm103a.json")).ok()
    }
    fn eq_masked(a: u128, b: u128) -> bool { (a & !SCHED_MASK) == (b & !SCHED_MASK) }
    fn rt(table: &IsaTable, sass: &str, addr: u32) -> String {
        let ix = DecodeIndex::build(table);
        let (_, hi) = {
            let c = encode_instruction(&parse_sass(sass, addr).unwrap(), table).unwrap();
            (c as u64, (c >> 64) as u64)
        };
        let _ = hi;
        let d = ix.decode(encode_instruction(&parse_sass(sass, addr).unwrap(), table).unwrap(), addr, table).unwrap();
        to_sass(&d)
    }

    #[test]
    fn bra_div_rel16() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("@!P0 BRA.DIV UR10, 0x3e20 ;", 0x11f0).unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc2000b8000000000002e0a088947),
            "BRA.DIV must use the REL16 layout with the UR operand preserved: got {c:032x}");
        assert!(rt(&tab, "@!P0 BRA.DIV UR10, 0x3e20 ;", 0x11f0).contains("UR10"));
    }

    #[test]
    fn bra_p_predicate_operand() {
        // "@!P3 BRA !P1, target": the branch P-operand lives at pred@[89:87]+neg@90.
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("@!P3 BRA !P1, 0xe050 ;", 56240).unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc20004800000000000040024b947), "{c:032x}");
    }

    #[test]
    fn warpsync_collective_target_resolution() {
        // WARPSYNC.COLLECTIVE Rn, <partner>: field = slots-of-16B ahead;
        // print resolved absolute target, encode must recover the raw field.
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("WARPSYNC.COLLECTIVE R10, 0x430 ;", 0x400).unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc20003c00000000000000a087348), "{c:032x}");
    }

    #[test]
    fn hadd2_hsel_and_neg_rz() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("HADD2.F32 R18, RZ, R24.H1_H1 ;", 0).unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc2000000410030000018ff127230), "{c:032x}");
    }

    #[test]
    fn reuse_124_decoded_from_full_word() {
        // reuse@122-124 must come from the full 128-bit word (not the stripped
        // code_clean) — otherwise the text round-trip silently drops .reuse.
        let Some(tab) = t() else { return };
        let ix = DecodeIndex::build(&tab);
        let w: u128 = 0x104fe400000041002000002eff34a230;
        let d = ix.decode(w, 0, &tab).unwrap();
        let s = to_sass(&d);
        assert!(s.contains(".reuse"), "reuse@124 lost on decode: {s}");
        let re = encode_instruction(&parse_sass(&format!("{s};"), 0).unwrap(), &tab).unwrap();
        assert!(eq_masked(re, w));
    }

    #[test]
    fn dfma_f64hi_immediate() {
        let Some(tab) = t() else { return };
        let w: u128 = 0x000e0000020100003ff000000e04742b & !(0xFFFFu128 << 112); // placeholder-safe
        let _ = w;
        // encode path is what carries the invariant: f64hi immediates with integral
        // values print bare like nvdisasm ("DFMA R4, -R14, R2, 1").
        let s = rt(&tab, "DFMA R4, -R14, R2, 1.0 ;", 0);
        assert!(s.trim_end_matches([';', ' ']).ends_with(", 1"), "f64hi printing: {s}");
    }

    #[test]
    fn syncs_phasechk_descriptor_form() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("SYNCS.PHASECHK.TRANS64.TRYWAIT P1, desc[UR29][R2.64+0xd0], R3 ;", 0)
                .unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc2000802111d0000d003020075a7), "{c:032x}");
    }

    #[test]
    fn desc_ur_not_dropped() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("UTMALDG.2CTA.3D.MULTICAST [UR16], [UR24], UR15, desc[UR4] ;", 0)
                .unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc2000821180f00000410180073b4), "{c:032x}");
    }

    #[test]
    fn hfma2_negative_zero_literal() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("HFMA2 R3, RZ, RZ, -0.0, 0 ;", 0).unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc200000001ff80000000ff037431), "{c:032x}");
    }

    #[test]
    fn sysreg_unknown_hex_preserved() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("CS2R.32 R40, SR_0x008a ;", 0).unwrap(), &tab).unwrap();
        assert!(eq_masked(c, 0x000fc20000008a000000000000287805), "{c:032x}");
    }

    #[test]
    fn ef_flags_arch_detection() {
        assert_eq!(cubit::elf::sm_from_ef_flags(0x06006402), 100);
        assert_eq!(cubit::elf::sm_from_ef_flags(0x06006702), 103);
        assert_eq!(cubit::elf::sm_from_ef_flags(0x06007802), 120);
    }

    #[test]
    fn rsd_overlay_bit_exact() {
        // Residue annotations: bits the text cannot express are carried inline
        // and applied by the encoder at the very end (after sched/epoch merge).
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("F2F.F32.F64 R18, R19 !rsd[75:1,84:0];", 0).unwrap(), &tab).unwrap();
        // canonical encode writes (75,84)=(0,1); the annotation flips to (1,0),
        // reproducing the corpus-observed second flavor bit-for-bit.
        assert_eq!(c & !SCHED_MASK, 0x000fc200002018000000001300127310 & !SCHED_MASK);
        let c2 = encode_instruction(
            &parse_sass("F2F.F32.F64 R18, R19;", 0).unwrap(), &tab).unwrap();
        assert_ne!(c & !SCHED_MASK, c2 & !SCHED_MASK);
    }

    #[test]
    fn rsd_range_form_and_parse() {
        let v = cubit::parser::parse_rsd_annotations("75:1, [24:23]=0x2");
        assert_eq!(v, vec![(75u8, 1u8), (23u8, 0u8), (24u8, 1u8)]);
    }

    #[test]
    fn sass_parser_multi_entry_without_endentry() {
        // `.entry` without `.endentry` must close the previous kernel
        // (frozen disasm output had all-but-last kernels eaten).
        let src = ".entry k1\n  NOP ;\n.entry k2\n  NOP ;\n";
        let f = cubit::sass_file::parse_sass_file_str(src).unwrap();
        assert_eq!(f.kernels.len(), 2);
        assert_eq!(f.kernels[0].name, "k1");
        assert_eq!(f.kernels[1].name, "k2");
    }

    /// IMAD.U32 Rd, RZ, RZ, URn — reczny MOV-from-UR (handoff LDCU param ->
    /// rejestr, ktest e2e). Wejscie wymaga fallbacku (key,"") przy mg "U32":
    /// rekord tabeli IMAD_R_R_R_UR/'' niesie ureg@32 tok4 + reg@64 tok2/3.
    #[test]
    fn imad_u32_mov_from_ur_fallback_key() {
        let Some(tab) = t() else { return };
        let c = encode_instruction(
            &parse_sass("IMAD.U32 R2, RZ, RZ, UR4 ;", 0).unwrap(), &tab).unwrap();
        assert_eq!(c as u64, 21458222628u64, "{c:032x}");
        assert_eq!((c >> 64) as u64, 4435430167412991u64, "{c:032x}");
        assert_eq!(rt(&tab, "IMAD.U32 R2, RZ, RZ, UR4 ;", 0),
                   "IMAD.U32 R2, RZ, RZ, UR4");
    }
}

