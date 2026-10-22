//! SM120 vendor witnesses that exposed lossy DSv4.1 instruction rows.
//!
//! Oracle: NVIDIA nvdisasm 13.1.80, independently captured by
//! tools/re_sm120_dsv41.py. No raw instructions or residue overlays enter
//! the assembler; every complete 128-bit word must come from editable SASS.

use cubit::{decoder::DecodeIndex, roundtrip_audit::audit_kernel, table::IsaTable};

fn load_table() -> IsaTable {
    let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tables/sm120.json"));
    IsaTable::load(&path).unwrap()
}

const WORDS: &[u128] = &[
    0x000fe2000001ff000000000000107805, // CS2R SRZ
    0x000fe2000000000000000040ff567803, // P2R PR, RZ, 0x40
    0x001fea0003800000000000000000791b, // ENDCOLLECTIVE
    0x000fe2000200000000000000ff00798f, // CCTL.IVALL
    0x080fe400020006ff00000016ff43723e, // F2FP UNPACK_B source.reuse
    0x000fe200030006ff00000018ff18723e, // F2FP UNPACK_B source.H1
    0x000168000c5e9d00000000080610a981, // LDG.E.NA.128.CONSTANT
    0x000fe2000fffe0ff0000000406067297, // UIADD3.64
    0x040fe200008f140f000000ff161b7211, // LEA.HI.X source1.reuse
    0x000fc600048000000000000814147407, // SEL.64 immediate
    0x000fe4000c8000000000000a18187c07, // SEL uniform source, !P1
    0x002fdc00087144700000000c10007c0c, // ISETP.GT.U64.OR
    0x0c0fe4000001021d00000014171d7219, // SHF two separate reuse bits
    0x000fc600080000073b12492506067455, // UFFMA f32 immediate
    0x000fe200080008063f80000007067455, // UFFMA negative uniform source
    0x000fe2000c0000000000000c06187c87, // USEL.64 uniform predicate
    0x000fc4000bfe01000000000c140c724a, // UVIMNMX full uniform sources
    0x000fe20003fe11000000000207027248, // VIMNMX.S32.RELU
    0x000fe20008010100bfe00000ff0a7454, // UFADD.FTZ float immediate
    0x001fea0003c00000000000000a087348, // WARPSYNC.COLLECTIVE R10
    0x00afea0003c000000000000002007343, // CALL.ABS.NOINC register target
    0x000fce0000000000000000001014794e, // LEPC PC-relative byte target
    0x000fe2000001000000c1000000007b1d, // BAR immediate ID/count
    0x0009ec000001000003c000030000791d, // BAR immediate ID/register count
    0x0001e40000010000000000200000731d, // BAR aliased register operands
    0x03afea0003c000000000000000187948, // WARPSYNC.COLLECTIVE.ALL
    0x000fea000b8000000000000304307947, // BRA.CONV uniform member mask
    0x000fdc0003f560700000001a2000720c, // ISETP register/register U64
    0x000fe40006fd4270ffffffff2e00780c, // ISETP register/immediate S64
    0x000fc8000bf112700000000402007c0c, // ISETP register/uniform S64
    0x000fe200042070ff000000070000723e, // SATFINITE E2M1 pack/merge
    0x000fec00000080000000000000007992, // MEMBAR.ALL.CTA
    0x000fec000000a0000000000000007992, // MEMBAR.ALL.GPU
    0x001fea0001000000000000000000994d, // EXIT execution predicate
    0x0001e400030148000000000d0000731d, // BAR.RED.OR register aliases
    0x0001ec000001480003c000210000791d, // BAR.RED.OR register count
    0x000fec00030148000343800000007b1d, // BAR.RED.OR immediate count
    0x000e2a00001000000000000009007355, // BMOV.32.CLEAR R0, B9
    0x0081ea00000000000000000506007356, // BMOV.32 B6, R5
    0x000e2400000c40000000000000ff731c, // B2R.RESULT RZ, P6
    0x000fc60000000000000000240c007804, // R2P PR, R12, mask
    0x000fea0003c000000000000000007943, // CALL.ABS.NOINC immediate zero
    0x000fc600000030ff0000001c2323723e, // SATFINITE BF16 PACK_AB
    0x000fc600000020ff0000001c2323723e, // SATFINITE F16 PACK_AB
    0x000fea0003c000000000000000007944, // CALL.REL.NOINC target pc+16
    0x000fea0003c000000000000000017943, // CALL.ABS.NOINC immediate 4
    0x000fe400048070ff0000002c2b2c823e, // Four-bit negated F2FP guard
    0x000fea000500000000000004002c9947, // Independent negated BRA operand
    0x000fec0003e000000000000014007950, // RET absolute target stays zero at any PC
    0x000fc8000c0000000000000404047e07, // SEL.64 full uniform-register source
    0x000fe400048032ff00000005ff05723e, // F16 source with compact-float merge
    0x000fea00038000000000000008007348, // Plain WARPSYNC register mask
    0x000fec00000030000000000000007992, // MEMBAR.SC.SYS
    0x002fea000393fffffffffffd00ec0947, // BRA.U.ANY backward target
    0x000fea000383ffffffffffd8225c7949, // BRX full signed byte offset
    0x001fea000b83fffffffffff404a47958, // BRXU uniform register and offset
    0x000fea0003800000000001180000795d, // NANOSLEEP fixed PT field
    0x000fe400020402ff00000011ff11723e, // F16 output from E2M1 input
    0x020fe2000c725a700000000710007c0c, // ISETP32 XOR must not become OR
    0x000fda00000000000000000000027353, // RPCMOV reads Rpc.LO
    0x000fcc00000000000000000200007352, // RPCMOV writes Rpc.LO
    0x000fea00038000000000000000030942, // Plain BREAK
    0x000ff0000000200001c6000000000b1d, // BAR.ARV immediate ID/count
    0x0003ec00000020000000001a0000731d, // BAR.ARV shared register slot
    0x000fec000800010000000000040073ca, // UGETNEXTWORKID adjacent address pair
    0x000fe2000ffe1100000000050412724a, // UVIMNMX.RELU
    0x000fec000800000000000000040073ca, // UGETNEXTWORKID.SELFCAST
    0x000fcc00000100000000000000007b1d, // BAR default count is elided
    0x000fea0000000000000000000000095d, // NANOSLEEP explicit member predicate P0
    0x000fea0004000000000000120000735d, // NANOSLEEP !P0 register delay
    0x000fea0000300000000000040000795c, // BPT.TRAP 3-bit immediate starts at34
    0x000fc8000bfe0000000000180404784a, // UVIMNMX immediate U32/UPT
    0x000fc6000ffe0000000000010607784a, // UVIMNMX immediate U32/!UPT
    0x000fec00038000000000000500740947, // BRA.U modebit32
    0x000fe40007000001ffffffff1e1a7407, // SEL.64 signed33-bit immediate
    0x000fea0000300000000000000000795c, // BPT.TRAP implicit zero immediate
    0x000fea00000e000000000000000003a1, // MATCH.ALL explicit result predicate PT
    0x000fea000004000000000000111373a1, // MATCH.ALL destination P2/R19
    0x000fea00000e800000000000130373a1, // MATCH.ANY separate modebit79
    0x000fea000000000000000000ff00098e, // REDG.ADD.EF, formerly mislabeled CCTL
    0x000fea0000000000000010131100798e, // REDG.ADD.EF register+offset fields
];

#[test]
fn vendor_witnesses_reassemble_all_128_bits_through_emitted_source() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let bytes: Vec<_> = WORDS.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut failures = Vec::new();
    let (report, source) = audit_kernel(".text.vendor_witnesses", 1, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
    assert!(report.passed, "vendor witness failures: {failures:#?}");
    assert_eq!(report.matched, WORDS.len());
    assert!(report.stream_verified);
    assert!(!source.contains("__raw__") && !source.contains("!rsd"));
}

#[test]
fn vendor_operand_semantics_are_not_replaced_by_self_consistent_aliases() {
    fn normalize_modifier_order(text: &str) -> String {
        let (opcode, operands) = text.split_once(' ').unwrap_or((text, ""));
        let mut parts = opcode.split('.');
        let base = parts.next().unwrap();
        let mut modifiers: Vec<_> = parts.collect();
        modifiers.sort_unstable();
        format!("{} {}", std::iter::once(base).chain(modifiers).collect::<Vec<_>>().join("."), operands)
    }
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let cases = [
        (WORDS[1], "P2R R86, PR, RZ, 0x40"),
        (WORDS[2], "ENDCOLLECTIVE"),
        (WORDS[3], "CCTL.IVALL"),
        (WORDS[5], "F2FP.F16.E4M3.UNPACK_B R24, R24.H1"),
        (WORDS[9], "SEL.64 R20, R20, 0x8, !P1"),
        (WORDS[10], "SEL R24, R24, UR10, !P1"),
        (WORDS[11], "ISETP.GT.U64.OR P0, PT, R16, UR12, P0"),
        (WORDS[15], "USEL.64 UR24, UR6, UR12, !UP0"),
        (WORDS[16], "UVIMNMX.S32 UR12, UR20, UR12, UPT"),
        (WORDS[18], "UFADD.FTZ UR10, -URZ, -1.75"),
        (WORDS[20], "CALL.ABS.NOINC R2"),
        (WORDS[21], "LEPC R20, 0x20"),
        (WORDS[22], "BAR.SYNC.DEFER_BLOCKING 0x3, 0x40"),
        (WORDS[23], "BAR.SYNC.DEFER_BLOCKING 0xf, R3"),
        (WORDS[24], "BAR.SYNC.DEFER_BLOCKING R32, R32"),
        (WORDS[25], "WARPSYNC.COLLECTIVE.ALL 0x70"),
        (WORDS[26], "BRA.CONV UR4, 0xd0"),
        (WORDS[27], "ISETP.GE.U64.AND P2, PT, R32, R26, PT"),
        (WORDS[28], "ISETP.GT.S64.AND P6, PT, R46, -0x1, !P5"),
        (WORDS[29], "ISETP.LT.S64.AND P0, PT, R2, UR4, PT"),
        (WORDS[30], "F2FP.SATFINITE.E2M1.F32.PACK_AB_MERGE_C R0, R0, R7, RZ"),
        (WORDS[31], "MEMBAR.ALL.CTA"),
        (WORDS[32], "MEMBAR.ALL.GPU"),
        (WORDS[33], "@!P1 EXIT P2"),
        (WORDS[34], "BAR.RED.OR.DEFER_BLOCKING R13, R13, P6"),
        (WORDS[35], "BAR.RED.OR.DEFER_BLOCKING 0xf, R33, P0"),
        (WORDS[36], "BAR.RED.OR.DEFER_BLOCKING 0xd, 0xe0, P6"),
        (WORDS[37], "BMOV.32.CLEAR R0, B9"),
        (WORDS[38], "BMOV.32 B6, R5"),
        (WORDS[39], "B2R.RESULT RZ, P6"),
        (WORDS[40], "R2P PR, R12, 0x24"),
        (WORDS[41], "CALL.ABS.NOINC 0x0"),
        (WORDS[42], "F2FP.SATFINITE.BF16.F32.PACK_AB R35, R35, R28"),
        (WORDS[43], "F2FP.SATFINITE.F16.F32.PACK_AB R35, R35, R28"),
        (WORDS[44], "CALL.REL.NOINC 0x10"),
        (WORDS[45], "CALL.ABS.NOINC 0x4"),
        (WORDS[46], "@!P0 F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R44, R43, R44, RZ"),
        (WORDS[47], "@!P1 BRA !P2, 0x4c0"),
        (WORDS[48], "RET.ABS.NODEC R20, 0x0"),
        (WORDS[49], "SEL.64 R4, R4, UR4, !P0"),
        (WORDS[50], "F2FP.SATFINITE.E4M3.F16.UNPACK_B_MERGE_C R5, R5, RZ"),
        (WORDS[51], "WARPSYNC R8"),
        (WORDS[52], "MEMBAR.SC.SYS"),
        (WORDS[54], "BRX R34, -0x2690"),
        (WORDS[55], "BRXU UR4, -0x970"),
        (WORDS[56], "NANOSLEEP 0x118"),
        (WORDS[57], "F2FP.F16.E2M1.UNPACK_B R17, R17"),
        (WORDS[58], "ISETP.NE.XOR P1, PT, R16, UR7, !P0"),
        (WORDS[59], "RPCMOV.32 R2, Rpc.LO"),
        (WORDS[60], "RPCMOV.32 Rpc.LO, R2"),
        (WORDS[61], "@P0 BREAK B3"),
        (WORDS[62], "@P0 BAR.ARV 0x7, 0x180"),
        (WORDS[63], "BAR.ARV R26, R26"),
        (WORDS[64], "UGETNEXTWORKID.BROADCAST [UR4], [UR5]"),
        (WORDS[65], "UVIMNMX.S32.RELU UR18, UR4, UR5, !UPT"),
        (WORDS[66], "UGETNEXTWORKID.SELFCAST [UR4], [UR5]"),
        (WORDS[67], "BAR.SYNC.DEFER_BLOCKING 0x0"),
        (WORDS[68], "@P0 NANOSLEEP P0, 0x0"),
        (WORDS[69], "NANOSLEEP !P0, R18"),
        (WORDS[70], "BPT.TRAP 0x1"),
        (WORDS[71], "UVIMNMX.U32 UR4, UR4, 0x18, UPT"),
        (WORDS[72], "UVIMNMX.U32 UR7, UR6, 0x1, !UPT"),
        (WORDS[73], "@P0 BRA.U 0x5e0"),
        (WORDS[74], "SEL.64 R26, R30, -0x1, !P6"),
        (WORDS[75], "BPT.TRAP"),
        (WORDS[76], "@P0 MATCH.ALL PT, R0, R0"),
        (WORDS[77], "MATCH.ALL P2, R19, R17"),
        (WORDS[78], "MATCH.ANY R3, R19"),
        (WORDS[79], "@P0 REDG.ADD.EF [RZ], R0"),
        (WORDS[80], "REDG.ADD.EF [R17+0x10], R19"),
    ];
    for (word, expected) in cases {
        let decoded = index.decode(word, 0, &table).unwrap();
        assert_eq!(normalize_modifier_order(&cubit::printer::to_sass_lossless(&decoded)),
            normalize_modifier_order(expected),
            "vendor semantic drift for {word:032x}");
    }
}

#[test]
fn aliased_barrier_operands_cannot_silently_overwrite_each_other() {
    let table = load_table();
    for source in ["BAR.SYNC.DEFER_BLOCKING R2, R3 ;", "BAR.RED.OR.DEFER_BLOCKING R2, R3, P0 ;", "BAR.ARV R2, R3 ;"] {
        let insn = cubit::parse_sass(source, 0).unwrap();
        let error = cubit::encoder::encode_instruction(&insn, &table).unwrap_err();
        assert!(error.to_string().contains("both must name the same register"), "{error:#}");
    }
}

#[test]
fn work_id_pair_and_pc_register_literals_reject_unrepresentable_operands() {
    let table = load_table();
    for source in [
        "UGETNEXTWORKID.BROADCAST [UR4], [UR7] ;",
        "UGETNEXTWORKID.SELFCAST [UR4+0x10], [UR5] ;",
        "UGETNEXTWORKID.BROADCAST [UR4], [UR5+0x10] ;",
        "UGETNEXTWORKID.BROADCAST [R4], [UR5] ;",
        "UGETNEXTWORKID.BROADCAST [UR254], [URZ] ;",
        "RPCMOV.32 R2, 0 ;", "RPCMOV.32 0, R2 ;",
        "RPCMOV.32 R2, Rpc.HI ;", "RPCMOV.32 Rpc.HI, R2 ;",
    ] {
        let parsed = cubit::parse_sass(source, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, &table).is_err(), "accepted {source}");
    }
}

#[test]
fn uniform_minmax_type_and_relu_selectors_match_vendor_grid() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let mut bytes = Vec::new();
    for (selector, datatype) in ["U32", "S32", "U16x2", "S16x2", "U8x4", "S8x4"].iter().enumerate() {
        for relu in [false, true] {
            let word = (WORDS[65] & !((7u128 << 72) | (1u128 << 76)))
                | ((selector as u128) << 72) | ((relu as u128) << 76);
            let decoded = index.decode(word, 0, &table).unwrap();
            let source = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(source, format!("UVIMNMX.{datatype}{} UR18, UR4, UR5, !UPT", if relu { ".RELU" } else { "" }));
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    let mut failures = Vec::new();
    let (report, _) = audit_kernel(".text.uniform_minmax_grid", 1, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
    assert!(report.passed, "NVIDIA uniform min/max grid failed: {failures:#?}");
}

#[test]
fn membar_sc_and_all_scopes_use_canonical_modifier_keys() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let cases = [
        (0x000fec00000000000000000000007992u128, "SC", "CTA"),
        (0x000fec00000010000000000000007992, "SC", "SM"),
        (0x000fec00000020000000000000007992, "SC", "GPU"),
        (0x000fec00000030000000000000007992, "SC", "SYS"),
        (0x000fec00000080000000000000007992, "ALL", "CTA"),
        (0x000fec00000090000000000000007992, "ALL", "SM"),
        (0x000fec000000a0000000000000007992, "ALL", "GPU"),
        (0x000fec000000b0000000000000007992, "ALL", "SYS"),
    ];
    let mut bytes = Vec::new();
    for (word, semantics, scope) in cases {
        let decoded = index.decode(word, 0, &table).unwrap();
        let source = cubit::printer::to_sass_lossless(&decoded);
        let mut actual: Vec<_> = source.split('.').collect();
        actual.sort_unstable();
        let mut expected = vec!["MEMBAR", semantics, scope];
        expected.sort_unstable();
        assert_eq!(actual, expected, "NVIDIA MEMBAR variant differs for {word:032x}");
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let mut failures = Vec::new();
    let (report, _) = audit_kernel(".text.membar_scope_grid", 1, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
    assert_eq!(report.instructions, 8);
    assert!(report.passed, "MEMBAR canonical modifier lookup failed: {failures:#?}");
}

#[test]
fn absolute_ret_target_is_independent_of_instruction_address() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    for address in [0, 16, 896, 0x10000] {
        let decoded = index.decode(WORDS[48], address, &table).unwrap();
        let source = cubit::printer::to_sass_lossless(&decoded);
        assert_eq!(source, "RET.ABS.NODEC R20, 0x0");
        let parsed = cubit::parse_sass(&format!("{source} ;"), address).unwrap();
        // Scheduling is intentionally independent of operand/address semantics.
        let encoded = cubit::encoder::encode_instruction(&parsed, &table).unwrap();
        assert_eq!(encoded & ((1u128 << 105) - 1), WORDS[48] & ((1u128 << 105) - 1));
    }
}

#[test]
fn compact_float_merge_fields_match_vendor_selector_grid() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let mut bytes = Vec::new();
    for e4m3 in [false, true] {
        for bf16 in [false, true] {
            for saturated in [false, true] {
                for relu in [false, true] {
                    for h1 in [false, true] {
                        for reuse in 0..4u128 {
                            let mut word = WORDS[50];
                            for (shift, value) in [(76, e4m3), (83, bf16), (77, saturated), (75, relu), (72, h1)] {
                                word = (word & !(1u128 << shift)) | ((value as u128) << shift);
                            }
                            word = (word & !(3u128 << 123)) | (reuse << 123);
                            let decoded = index.decode(word, 0, &table).unwrap();
                            let mut expected = vec![if e4m3 { "E4M3" } else { "E5M2" },
                                if bf16 { "BF16" } else { "F16" }, "UNPACK_B_MERGE_C"];
                            if saturated { expected.push("SATFINITE"); }
                            if relu { expected.push("RELU"); }
                            expected.sort_unstable();
                            let mut actual: Vec<_> = decoded.mod_group.split(',').collect();
                            actual.sort_unstable();
                            assert_eq!(actual, expected, "vendor modifiers differ for {word:032x}");
                            let source = cubit::printer::to_sass_lossless(&decoded);
                            let operands = source.split_once(' ').unwrap().1;
                            assert_eq!(operands.replace(".reuse.H1", ".H1.reuse"), format!("R5, R5{}, RZ{}{}",
                                if reuse & 1 != 0 { ".reuse" } else { "" },
                                if h1 { ".H1" } else { "" },
                                if reuse & 2 != 0 { ".reuse" } else { "" }));
                            bytes.extend_from_slice(&word.to_le_bytes());
                        }
                    }
                }
            }
        }
    }
    let mut failures = Vec::new();
    let (report, _) = audit_kernel(".text.compact_float_merge_grid", 1, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
    assert_eq!(report.instructions, 128);
    assert!(report.passed, "NVIDIA compact-float grid failed: {failures:#?}");
}

#[test]
fn isetp_32_uniform_source_selectors_match_vendor_matrix() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let mut bytes = Vec::new();
    for (compare, compare_name) in ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"].iter().enumerate() {
        for (combine, bool_name) in ["AND", "OR", "XOR"].iter().enumerate() {
            for signed in [false, true] {
                for extended in [false, true] {
                    let word = (WORDS[58] & !(0x7fu128 << 72)) | ((compare as u128) << 76)
                        | ((combine as u128) << 74) | ((signed as u128) << 73) | ((extended as u128) << 72);
                    let decoded = index.decode(word, 0, &table).unwrap();
                    let mut expected = vec![*compare_name, *bool_name];
                    if !signed { expected.push("U32"); }
                    if extended { expected.push("EX"); }
                    expected.sort_unstable();
                    let mut actual: Vec<_> = decoded.mod_group.split(',').collect();
                    actual.sort_unstable();
                    assert_eq!(actual, expected, "vendor modifiers differ for {word:032x}");
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
            }
        }
    }
    let mut failures = Vec::new();
    let (report, _) = audit_kernel(".text.isetp32_uniform_grid", 1, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
    assert_eq!(report.instructions, 96);
    assert!(report.passed, "NVIDIA ISETP32 grid failed: {failures:#?}");
}

#[test]
fn indirect_branch_payload_is_not_pc_relative_or_limited_to_17_bits() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    for (word, register, expected) in [(WORDS[54], "R34", "-0x2690"), (WORDS[55], "UR4", "-0x970")] {
        for address in [0, 16, 896] {
            let decoded = index.decode(word, address, &table).unwrap();
            let source = cubit::printer::to_sass_lossless(&decoded);
            assert!(source.ends_with(&format!("{register}, {expected}")), "{source}");
            let far = index.decode(word ^ (1 << 64), address, &table).unwrap();
            let source = cubit::printer::to_sass_lossless(&far);
            assert!(source.ends_with(if register == "R34" { "-0x10000002690" } else { "-0x10000000970" }), "{source}");
        }
    }
    let decoded = index.decode(WORDS[53], 0x100, &table).unwrap();
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), "@P0 BRA.ANY.U 0xc0");
}

#[test]
fn isetp_64_selector_grid_matches_independent_vendor_matrix() {
    let table = load_table();
    let index = DecodeIndex::build(&table);
    let selector_mask = 0x7fu128 << 72;
    let mut bytes = Vec::new();
    for anchor in &WORDS[27..30] {
        for compare in ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"].iter().enumerate() {
            for combine in ["AND", "OR", "XOR"].iter().enumerate() {
                for signed in [false, true] {
                    for extended in [false, true] {
                        let selectors = (compare.0 as u128) << 76 | (combine.0 as u128) << 74
                            | (signed as u128) << 73 | (extended as u128) << 72;
                        let word = (anchor & !selector_mask) | selectors;
                        let decoded = index.decode(word, 0, &table).unwrap();
                        let mut actual: Vec<_> = decoded.mod_group.split(',').collect();
                        actual.sort_unstable();
                        let mut expected = vec![*compare.1, *combine.1, if signed { "S64" } else { "U64" }];
                        if extended { expected.push("EX"); }
                        expected.sort_unstable();
                        assert_eq!(actual, expected, "vendor modifier mismatch for {word:032x}");
                        bytes.extend_from_slice(&word.to_le_bytes());
                    }
                }
            }
        }
    }
    let mut failures = Vec::new();
    let (report, _) = audit_kernel(".text.isetp_64_grid", 1, &bytes, &table, &index,
        &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
    assert_eq!(report.instructions, 288);
    assert!(report.passed, "NVIDIA selector grid failed: {failures:#?}");
}
