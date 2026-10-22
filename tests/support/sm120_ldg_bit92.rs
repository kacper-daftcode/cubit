//! Explicit historical limitation; no raw-bit field is added to semantic SASS.
#![allow(dead_code)]
use cubit::{IsaTable, decoder::DecodeIndex};
pub const HISTORICAL_UNSUPPORTED: &[u128] = &[
    0x181e09000000002419fc7981,
    0x181e09000000802419fc7981,
    0x181e090000000004ff007981,
    0x181e0b000000000806087981,
    0x181e0b0000040008060a7981,
    0x181e0b000008000806087981,
    0x181e0b0000080008060a7981,
    0x181e0b0000100008060c7981,
    0x181e0b0000180008060e7981,
    0x181e0b000020000806107981,
    0x181e0b000028000806127981,
    0x181e0b000030000806147981,
    0x181e0b000038000806167981,
    0x181e0b000040000806187981,
    0x181e0b0000480008061a7981,
    0x181e0b0000500008061c7981,
    0x181e0b0000580008061e7981,
    0x181e0b000060000806207981,
    0x181e0b000068000806227981,
    0x181e0b000070000806247981,
    0x181e0b000078000806267981,
    0x181e0b000080000806287981,
    0x181e0b0000880008062a7981,
    0x181e0b0000900008062c7981,
    0x181e0b0000980008062e7981,
];
pub fn unsupported(word: u128) -> bool {
    HISTORICAL_UNSUPPORTED.contains(&(word & ((1u128 << 96) - 1)))
}
// Exact native r15 SM120/layout2 CUPTI-era corpus witnesses, not edited era words.
// SHA da18f5e5cdb61be9d87aa62bfb9c264f313feb0e4b0dc5849990d4f321d4a71a,
// .text._ZN7cutlass7Kernel2I56cutlass_80_tensorop_s16816gemm_bf16_64x64_32x6_tn_align8EEvNT_6ParamsE,
// byte offsets 0x350 and 0x360 respectively. See inventory/memory_tail10_evidence.json.
// The final two witnesses come from the exact CUPTI native capture;
// capture_delta1_memory_evidence.json records their independent oracle proof.
pub const NATIVE_R15: &[(u128, &str)] = &[
    (0x000f6800081e0b000000000aff107981, "LDG.E.64 R16, [RZ.U32+UR10]"),
    (0x010f6400081e0b0000000004ff0c7981, "LDG.E.64 R12, [RZ.U32+UR4]"),
    (0x004ea800081e090000000008ff030981, "@P0 LDG.E R3, [RZ.U32+UR8]"),
    (0x000f2800081ee90000000012ff4a8981, "@!P0 LDG.E.STRONG.GPU R74, [RZ.U32+UR18]"),
];
pub fn assert_native_roundtrips(table: &IsaTable, ix: &DecodeIndex) {
    for &(word, sass) in NATIVE_R15 {
        let d = ix.decode(word, 0, table).expect("native r15 LDG64 is supported");
        assert_eq!(cubit::printer::to_sass(&d), sass);
        let cc = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
        let source = format!("[{cc}] {sass} ;");
        let insn = cubit::parse_cuasm_line(&source, 0).unwrap();
        assert_eq!(cubit::encoder::encode_instruction(&insn, table).unwrap(), word,
                   "full128 native semantic roundtrip: {source}");
    }
}
