//! Native NVIDIA float words; all 128 bits must come from semantic SASS.
use cubit::{decoder::DecodeIndex, IsaTable};
fn table() -> IsaTable {
    IsaTable::load(
        &std::env::var_os("CUBIT_TABLE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "tables/sm120.json".into()),
    )
    .unwrap()
}
fn check(t: &IsaTable, ix: &DecodeIndex, expected: u128, nvidia: Option<&str>) {
    let cc = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (expected >> 96) as u32,
    ));
    if let Some(s) = nvidia {
        let i = cubit::parse_cuasm_line(&format!("[{cc}] {s} ;"), 0).unwrap();
        assert_eq!(
            cubit::encoder::encode_instruction(&i, t).unwrap(),
            expected,
            "NVIDIA: {s}"
        );
    }
    let d = ix.decode(expected, 0, t).unwrap();
    let source = format!("[{cc}] {} ;", cubit::printer::to_sass_lossless(&d));
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let i = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert_eq!(
        cubit::encoder::encode_instruction(&i, t).unwrap(),
        expected,
        "{source}"
    );
}
#[test]
fn production_float_packets_preserve_named_operands_modes_and_literals() {
    let t = table();
    let ix = DecodeIndex::build(&t);
    for (w, s) in [
        (0x000fe2000040c0000000000706067220u128, "FMUL.RZ R6, R6, R7"),
        (0x000e2400000080000000000818087228, "DMUL.RP R8, R24, R8"),
        (
            0x000fc800000e00008000003216167221,
            "FHADD.BF16 R22, R22.H1, -R50",
        ),
        (
            0x000fca0003f268022000000708007234,
            "HSETP2.BF16_V2.GE.AND P1, PT, R8.H0_H0, R7.H0_H0, PT",
        ),
        (
            0x000fc80008000006c02df85404067855,
            "UFFMA UR6, UR4, -2.7182817459106445312, UR6",
        ),
        (
            0x004fe200084100003fb8aa3b04047856,
            "UFMUL.FTZ UR4, UR4, 1.4426950216293334961",
        ),
        (
            0x000fca000801002f00000006002f7c23,
            "FFMA.FTZ R47, R0, UR6, R47",
        ),
    ] {
        check(&t, &ix, w, Some(s));
    }
}
#[test]
fn packed_comparison_modes_do_not_alias_operand_half_selectors() {
    let t = table();
    let ix = DecodeIndex::build(&t);
    let mask = (15u128 << 76) | (3 << 69) | (1 << 65) | (1 << 80) | (1 << 71);
    let base = 0x000fe20003f268022000000708007234u128 & !mask;
    for cmp in 0..16u128 {
        for boolean in 0..3u128 {
            for bf16 in 0..2u128 {
                for ftz in 0..2u128 {
                    for horizontal in 0..2u128 {
                        check(
                            &t,
                            &ix,
                            base | (cmp << 76)
                                | (boolean << 69)
                                | (bf16 << 65)
                                | (ftz << 80)
                                | (horizontal << 71),
                            None,
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn independent_nvidia_modes_and_operand_probes_reassemble_without_residue() {
    let t = table();
    let ix = DecodeIndex::build(&t);
    // Captured independently by tools/re_sm120_float_fields.py --verify-oracle.
    // Expected words and text come from NVIDIA, not from the Cubit table.
    let mut count = 0;
    for line in include_str!("fixtures/sm120_float_nvdisasm.jsonl").lines() {
        let r: serde_json::Value = serde_json::from_str(line).unwrap();
        let w = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        check(&t, &ix, w, r["sass"].as_str());
        count += 1;
    }
    assert_eq!(count, 1029);
}

#[test]
fn captured_bf16_and_uniform_float_forms_follow_independent_nvidia_fields() {
    let t = table();
    let ix = DecodeIndex::build(&t);
    let mut count = 0;
    for line in include_str!("fixtures/sm120_float_capture_nvdisasm.jsonl").lines() {
        let r: serde_json::Value = serde_json::from_str(line).unwrap();
        let w = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap();
        check(&t, &ix, w, r["sass"].as_str());
        count += 1;
    }
    assert_eq!(count, 1800);
    let invalid = cubit::parse_sass("HMNMX2.BF16_V2 R70, R70, UR10.H0_H1, !PT ;", 0).unwrap();
    assert!(cubit::encoder::encode_instruction(&invalid, &t).is_err());
    for source in [
        "I2FP.F32.U32.RZ R0, -R1 ;",
        "I2FP.F32.S32 R6, |UR7| ;",
    ] {
        let invalid = cubit::parse_sass(source, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&invalid, &t).is_err(), "{source}");
    }
    for (word, nvidia) in [
        (0x100fe4000390e0022000005346007234u128,
         "HSETP2.BF16_V2.GEU.AND P0, P1, R70, R83.reuse.H0_H0, PT"),
        (0x004fe4000b90e0022000000a46007e34,
         "HSETP2.BF16_V2.GEU.AND P0, P1, R70, UR10.H0_H0, PT"),
        (0x000fc4000fa000002000000a46467c40,
         "HMNMX2.BF16_V2 R70, R70, UR10.H0_H0, !PT"),
        (0x010fc80008000c040000000403027e23,
         "FFMA R2, R3, -|R4|, UR4"),
        (0x0c0fe20003801000000000391c2c720a,
         "FSET.BF.LT.AND R44, R28.reuse, R57.reuse, PT"),
        (0x000fe2000020d0000000000000007245,
         "I2FP.F32.U32.RZ R0, R0"),
    ] {
        check(&t, &ix, word, Some(nvidia));
    }
}
