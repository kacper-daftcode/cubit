//! Hardware spelling is checked independently of the decoder/encoder inverse.
//! NVIDIA SM120 probes: re_sm120_bmsk_uf2i_nvdisasm.json, 2026-10-22.
use cubit::{
    decoder::DecodeIndex, encoder::encode_instruction, printer::to_sass_lossless, table::IsaTable,
};

fn table() -> IsaTable {
    let path = std::env::var("CUBIT_TABLE").unwrap_or_else(|_| "tables/sm120.json".into());
    IsaTable::load(std::path::Path::new(&path)).unwrap()
}

fn exact(t: &IsaTable, idx: &DecodeIndex, w: u128, want: &str) {
    let decoded = idx.decode(w, 0, t).unwrap();
    assert_eq!(to_sass_lossless(&decoded), want, "{w:032x}");
    let ctrl = cubit::scheduling::decode_sched_upper32((w >> 96) as u32);
    let text = format!(
        "[{}] {want} ;",
        cubit::scheduling::format_control_code(&ctrl)
    );
    let insn = cubit::parse_cuasm_line(&text, 0).unwrap();
    assert_eq!(encode_instruction(&insn, t).unwrap(), w, "{text}");
}

#[test]
fn bmsk_yield_is_schedule_and_never_source_negation() {
    let t = table();
    let idx = DecodeIndex::build(&t);
    let base = 0x000fe4000000000000000006090d721bu128;
    for yielding in [false, true] {
        for wrap in [false, true] {
            for reuse in 0u128..4 {
                let w = (base & !(1u128 << 109))
                    | ((yielding as u128) << 109)
                    | ((wrap as u128) << 75)
                    | (reuse << 122);
                let text = format!(
                    "BMSK{} R13, R9{}, R6{}",
                    if wrap { ".W" } else { "" },
                    if reuse & 1 != 0 { ".reuse" } else { "" },
                    if reuse & 2 != 0 { ".reuse" } else { "" }
                );
                exact(&t, &idx, w, &text);
            }
        }
    }
    for text in [
        "BMSK R13, -R9, R6 ;",
        "BMSK R13, R9, -R6 ;",
        "BMSK R13, |R9|, R6 ;",
        "BMSK R13, R9, |R6| ;",
    ] {
        let insn = cubit::parse_cuasm_line(text, 0).unwrap();
        assert!(
            encode_instruction(&insn, &t).is_err(),
            "unsupported source sign: {text}"
        );
    }
    // The generic decoder tolerates upper-word unknown bits. The strict
    // semantic audit must still refuse this independently vendor-illegal bit,
    // rather than inventing a third source or retaining the original word.
    let invalid = base | (1u128 << 124);
    let (report, _) = cubit::roundtrip_audit::audit_kernel(
        ".text.illegal_bmsk_reuse",
        2,
        &invalid.to_le_bytes(),
        &t,
        &idx,
        &mut |_| Ok(()),
    )
    .unwrap();
    assert!(!report.passed, "BMSK has no third source reuse encoding");
}

#[test]
fn uf2i_uses_full_byte_ur_selectors_and_real_source_signs() {
    let t = table();
    let idx = DecodeIndex::build(&t);
    let base = 0x000fcc000821f000000000040005725cu128;
    let name = |n| {
        if n == 255 {
            "URZ".into()
        } else {
            format!("UR{n}")
        }
    };
    for n in [0u128, 1, 2, 3, 5, 31, 32, 63, 64, 127, 128, 254, 255] {
        exact(
            &t,
            &idx,
            (base & !(255 << 16)) | (n << 16),
            &format!("UF2I.FTZ.U32.TRUNC.NTZ {}, UR4", name(n)),
        );
        exact(
            &t,
            &idx,
            (base & !(255 << 32)) | (n << 32),
            &format!("UF2I.FTZ.U32.TRUNC.NTZ UR5, {}", name(n)),
        );
    }
    for (bit, want) in [
        (62, "UF2I.FTZ.U32.TRUNC.NTZ UR5, |UR4|"),
        (63, "UF2I.FTZ.U32.TRUNC.NTZ UR5, -UR4"),
        (12, "@UP6 UF2I.FTZ.U32.TRUNC.NTZ UR5, UR4"),
        (13, "@UP5 UF2I.FTZ.U32.TRUNC.NTZ UR5, UR4"),
        (14, "@UP3 UF2I.FTZ.U32.TRUNC.NTZ UR5, UR4"),
        (15, "@!UPT UF2I.FTZ.U32.TRUNC.NTZ UR5, UR4"),
    ] {
        exact(&t, &idx, base ^ (1u128 << bit), want);
    }
    for text in [
        "UF2I.FTZ.U32.TRUNC.NTZ UR256, UR4 ;",
        "UF2I.FTZ.U32.TRUNC.NTZ UR5, UR256 ;",
    ] {
        let insn = cubit::parse_cuasm_line(text, 0).unwrap();
        assert!(
            encode_instruction(&insn, &t).is_err(),
            "out-of-range selector: {text}"
        );
    }
}

#[test]
fn fchk_output_predicate_never_overwrites_the_input_register() {
    let t = table();
    let idx = DecodeIndex::build(&t);
    // Full Ra byte and predicate selector sweeps, independently observed in
    // re_sm120_fchk_nvdisasm.json. The old pred@27 destroyed Ra bit3.
    for (packet, literal, operand) in [
        (0x902u128, 0x402df854u128, "2.7182817459106445312"),
        (0x302, 6, "R6"),
        (0xd02 | (1 << 91), 13, "UR13"),
    ] {
        for reg in [0u128, 8, 16, 31, 32, 127, 128, 255] {
            for pred in 0u128..8 {
                let w = (0x000e2200u128 << 96)
                    | packet
                    | (7 << 12)
                    | (reg << 24)
                    | (literal << 32)
                    | (pred << 81);
                let pname = if pred == 7 {
                    "PT".into()
                } else {
                    format!("P{pred}")
                };
                let rname = if reg == 255 {
                    "RZ".into()
                } else {
                    format!("R{reg}")
                };
                exact(&t, &idx, w, &format!("FCHK {pname}, {rname}, {operand}"));
            }
        }
    }
    for (literal, spelling) in [
        (0u128, "0"),
        (0x3f800000, "1"),
        (0xbf800000, "-1"),
        (0x7f800001, "0x7f800001F"),
        (0x7fc00001, "0x7fc00001F"),
    ] {
        exact(
            &t,
            &idx,
            0x000e2200000000000000000018007902u128 | (literal << 32),
            &format!("FCHK P0, R24, {spelling}"),
        );
    }
}

#[test]
fn hmnmx2_native_mode_order_has_exact_independent_witnesses() {
    let t = table();
    let idx = DecodeIndex::build(&t);
    // Every declared mode is independently verified in float_capture2_full_oracle.json;
    // composed modifier order was also checked in hmnmx_mod_order.bin.
    for mode in 0u128..16 {
        let w = 0x000fe4000f8000002000000a46467c40u128
            | ((mode & 1) << 85)
            | (((mode >> 1) & 1) << 80)
            | (((mode >> 2) & 1) << 81)
            | (((mode >> 3) & 1) << 82);
        let text = format!(
            "HMNMX2{}{}{}{} R70, R70, UR10.H0_H0, !PT",
            if mode & 1 != 0 { ".BF16_V2" } else { "" },
            if mode & 2 != 0 { ".FTZ" } else { "" },
            if mode & 4 != 0 { ".NAN" } else { "" },
            if mode & 8 != 0 { ".XORSIGN" } else { "" }
        );
        exact(&t, &idx, w, &text);
    }
}

#[test]
fn isetp_native_rr32_boolean_and_width_laws_are_independent() {
    let t = table();
    let idx = DecodeIndex::build(&t);
    // Each of these96 selector combinations was independently passed to
    // NVIDIA: re_sm120_capture_tail_alu_nvdisasm.json.
    for (cmp, compare) in ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"]
        .iter()
        .enumerate()
    {
        for (boolean, combine) in ["AND", "OR", "XOR"].iter().enumerate() {
            for signed in [false, true] {
                for extended in [false, true] {
                    let w = (0x000fe200u128 << 96)
                        | 0x720c
                        | (18 << 24)
                        | (26 << 32)
                        | ((cmp as u128) << 76)
                        | ((boolean as u128) << 74)
                        | ((signed as u128) << 73)
                        | ((extended as u128) << 72)
                        | (3 << 81)
                        | (7 << 84)
                        | (1 << 90)
                        | ((if extended { 4u128 } else { 7 }) << 68);
                    let text = format!(
                        "ISETP.{compare}{}.{combine}{} P3, PT, R18, R26, !P0{}",
                        if signed { "" } else { ".U32" },
                        if extended { ".EX" } else { "" },
                        if extended { ", P4" } else { "" }
                    );
                    exact(&t, &idx, w, &text);
                }
            }
        }
    }
}

#[test]
fn imad_hi_immediate_has_real_carry_and_bitwise_inverse_fields() {
    let t = table();
    let idx = DecodeIndex::build(&t);
    for (w, text) in [
        (
            0x000fca00000e041effffffff2d1f7827u128,
            "IMAD.HI.U32.X R31, R45, -0x1, R30, P0",
        ),
        (
            0x000fca00000e0c1effffffff2d1f7827,
            "IMAD.HI.U32.X R31, R45, -0x1, ~R30, P0",
        ),
        (
            0x000fca00000e061effffffff2d1f7827,
            "IMAD.HI.X R31, R45, -0x1, R30, P0",
        ),
        (
            0x000fca000006041effffffff2d1f7827,
            "IMAD.HI.U32.X R31, P3, R45, -0x1, R30, P0",
        ),
        (
            0x000fc8000f800c06000000040d067c27,
            "IMAD.HI.U32.X R6, P0, R13, UR4, ~R6, !PT",
        ),
        (
            0x000fc8000f800806000000040d067c27,
            "IMAD.HI.U32 R6, P0, R13, UR4, -R6",
        ),
    ] {
        exact(&t, &idx, w, text);
    }
}

#[test]
fn imad_hi_authored_modifiers_need_a_real_named_encoding() {
    let t = table();
    for text in [
        "IMAD.HI.U32.X R31, -R45, -0x1, R30, P0 ;",
        "IMAD.HI.U32.X R31, |R45|, -0x1, R30, P0 ;",
        "IMAD.HI.U32.X R31, ~R45, -0x1, R30, P0 ;",
        "IMAD.HI.U32.X R31, R45, -0x1, -R30, P0 ;",
        "IMAD.HI.U32.X R31, R45, -0x1, |R30|, P0 ;",
        "IMAD.HI.U32.X R6, P0, R13, -UR4, R6, !PT ;",
        "IMAD.HI.U32.X R6, P0, R13, |UR4|, R6, !PT ;",
        "IMAD.HI.U32.X R6, P0, R13, ~UR4, R6, !PT ;",
        "IMAD.HI.U32 R6, P0, R13, UR4, ~R6 ;",
    ] {
        let insn = cubit::parse_cuasm_line(text, 0).unwrap();
        let error = encode_instruction(&insn, &t).expect_err(text);
        assert!(
            error.to_string().contains("explicit named field"),
            "{text}: {error:#}"
        );
    }
    let idx = DecodeIndex::build(&t);
    // NVIDIA confirms72 is inert on the immediateHI packet. The strict
    // pipeline must not invent a -Ra semantic to carry that unexplained bit.
    let unexplained = 0x000fca00000e051effffffff2d1f7827u128;
    if let Ok(decoded) = idx.decode(unexplained, 0, &t) {
        assert!(!to_sass_lossless(&decoded).contains("-R45"));
    }
    let (report, _) = cubit::roundtrip_audit::audit_kernel(
        ".text.unexplained_hi_bit72",
        2,
        &unexplained.to_le_bytes(),
        &t,
        &idx,
        &mut |_| Ok(()),
    )
    .unwrap();
    assert!(
        !report.passed,
        "unexplained HI bit72 cannot become a fake source sign"
    );
}
