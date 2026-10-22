//! Production SM120 words which previously needed raw passthrough.
//! Golden words are independently disassembled by NVIDIA, not synthesized
//! by the encoder under test. Scheduling is part of each assertion.
use cubit::encoder::encode_instruction;
use cubit::{parse_cuasm_line, IsaTable};

#[test]
fn production_imad_hi_and_zero_mma_accumulator_encode_exactly() {
    let t = IsaTable::load(
        &std::env::var_os("CUBIT_TABLE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("tables/sm120.json")),
    )
    .unwrap();
    for (text, expected) in [
        (
            "[B------:R-:W-:Y:S01] IMAD.HI.U32 R2, R3, R5, R2 ;",
            0x000fe200078e00020000000503027227u128,
        ),
        (
            "[B------:R-:W-:-:S15] QMMA.16832.F32.E4M3.E4M3 R20, R20, R98, RZ ;",
            0x000fde0000002cff000000621414727au128,
        ),
    ] {
        let i = parse_cuasm_line(text, 0).unwrap();
        assert_eq!(encode_instruction(&i, &t).unwrap(), expected, "{text}");
    }
}

#[test]
fn hi_to_wide_fallback_still_rejected() {
    let mut t = IsaTable::load(
        &std::env::var_os("CUBIT_TABLE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("tables/sm120.json")),
    )
    .unwrap();
    // Poison every HI row's opcode to reproduce the original lookup defect.
    for (key, v) in &mut t.entries {
        if !key.starts_with("IMAD") {
            continue;
        }
        for (mods, row) in &mut v.mod_groups {
            if key.contains(".HI") || mods.split(',').any(|m| m == "HI") {
                row.and_base = (row.and_base & !0xfffu128) | 0x225;
            }
        }
    }
    let i = parse_cuasm_line("[B------:R-:W-:Y:S01] IMAD.HI.U32 R2, R3, R5, R2 ;", 0).unwrap();
    let error = encode_instruction(&i, &t).unwrap_err().to_string();
    assert!(error.contains("BUG-002"), "{error}");
}

#[test]
fn uniform_float_integral_literal_is_f32() {
    let i = cubit::parse_sass("UFFMA UR6, UR7, -UR6, 1 ;", 0).unwrap();
    assert!(matches!(i.operands[3],cubit::ir::Operand::FloatImm(bits) if bits == 1.0f64.to_bits()));
}
