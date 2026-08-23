//! BUG-094 (F2Q, F2-iter34, 2026-08-23): LDS/LDL/STL/ATOMG.E.CAS coverage.
//! (1) Junk decode modgroup LDG_R_dARI::128,E,LTC128B (both tables): pure
//!     harvest RE-noise -- zero vendor-true anchors in the 885,399-word census
//!     (2049-cubin gate corpus, cuobjdump 13.3) and 100% offender traffic:
//!     LDS.U8 words decoded to `LDG.E.LTC128B.128 Rn, desc[UR0][Rn.64]` etc.
//!     Deleted on BOTH tables; era-text encodability preserved byte-exact by an
//!     encode_only retention row (canon: NEW LDG.E.LTC128B.128_R_dARI mirroring
//!     pre-094 geometry; sm120: the existing BUG-090 row), see ERA_GIF pins.
//! (2) sm120.json LDS/LDL/STL family re-canonicalized to sm103a geometry
//!     (84 junk keys -> 7 canon keys [+ATOMG row]: LDS_R_ARI/ARURI/AURI,
//!     LDL_R_ARI/AURI, STL_ARI_R/AURI_R with U8/U16/S8/S16/LU/128/64 mgs):
//!     fixes LDS.U16 `?AR`-fallback/UR-halving, LDL.LU phantom `+UR0`,
//!     LDL.S16/STL.S16 hijack-or-DECERR, STL.128 imm top-byte truncation,
//!     STL/STL.64 pure-UR hijack.
//! (3) ATOMG_P_R_ARI_R_R (CAS family: 64,CAS,E,STRONG,SYS / CAS,E,STRONG,SYS /
//!     CAS,E,GPU,STRONG) added to sm120 from canon (was DECERR, opcode 0x03a9).
//! (4) printer: ATOM*/REDG size modifier prints between operation and STRONG
//!     (vendor `ATOMG.E.CAS.64.STRONG.SYS`, not `ATOMG.E.CAS.STRONG.64.SYS`).
//! Report: results/cubitfix/094.md. Anchors: results/cubitfix/094/anchors094.json.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// (word, vendor-canonical text, canon-encode guard) — anchors section-aligned
/// from the 2049-cubin vendor census (cuobjdump 13.3); sources in the repo
/// artifacts (results/cubitfix/094/anchors094.json). guard=true marks words
/// whose sm_103a encode is lawfully refused by the BUG-088 .128 alignment law
/// (decode stays full-fidelity; encode tested on sm120 only).
const GOLD: &[(u128, &str, bool)] = &[
    (0x000ea800000008000001f80000097984u128, "LDS R9, [R0+0x1f8]", false), // uq.cubin@0140
    (0x000e2200000008000060180003037984u128, "LDS R3, [R3+0x6018]", false), // sp2_akeep.cubin@0720
    (0x0001e40000100c000000000401007387u128, "STL.128 [R1], R4", false), // uq.cubin@0190
    (0x001fe80000100c000000000401007387u128, "STL.128 [R1], R4", false), // dop_up2.cubin@0280
    (0x000fe80000100c000000100401007387u128, "STL.128 [R1+0x10], R4", false), // uq.cubin@0200
    (0x0003e20000100c000000100801007387u128, "STL.128 [R1+0x10], R8", false), // dop_up2.cubin@00f0
    (0x000ea200001008000000040000007983u128, "LDL R0, [R0+0x4]", false), // uq.cubin@0210
    (0x000ea2000010080000000400010d7983u128, "LDL R13, [R1+0x4]", false), // libcublas.so.201.sm_100.cubin@0320
    (0x000fe80000100a000000000e00008387u128, "@!P0 STL.64 [R0], R14", false), // dop_up2.cubin@0300
    (0x0005e80000100a000000001000009387u128, "@!P1 STL.64 [R0], R16", false), // dop_up2.cubin@0290
    (0x000fe80000100a000000000c0e001387u128, "@P1 STL.64 [R14], R12", false), // dop_up2.cubin@0290
    (0x0001e80000100a000000000215003387u128, "@P3 STL.64 [R21], R2", false), // dop_pred.cubin@04b0
    (0x000ea400001008000000000003037983u128, "LDL R3, [R3]", false), // dop_pred.cubin@01d0
    (0x000ea400001008000000000003057983u128, "LDL R5, [R3]", false), // dop_up.cubin@0210
    (0x0021e600001008000000240001001387u128, "@P1 STL [R1+0x24], R0", false), // dop_pred.cubin@0210
    (0x010fe2000010080000000c0201001387u128, "@P1 STL [R1+0xc], R2", false), // libcublas.so.627.sm_100.cubin@0ef0
    (0x000e220000100800000000000303a983u128, "@!P2 LDL R3, [R3]", false), // dop_pred.cubin@0230
    (0x0003e20000100a000000500201007387u128, "STL.64 [R1+0x50], R2", false), // dop_pred.cubin@0360
    (0x000fe20000100a000000400201007387u128, "STL.64 [R1+0x40], R2", false), // dop_pred.cubin@0200
    (0x000fe800001008000000000003001387u128, "@P1 STL [R3], R0", false), // dop_up.cubin@0230
    (0x0001e800001008000000000201004387u128, "@P4 STL [R1], R2", false), // libcublas.so.627.sm_100.cubin@0b60
    (0x000e24000800000000000004ff027984u128, "LDS.U8 R2, [UR4]", false), // mx1k.cubin@0380
    (0x000f24000800000000000004ff027984u128, "LDS.U8 R2, [UR4]", false), // dc_b9_08.cubin@05b0
    (0x001e28000800080000601810ff027984u128, "LDS R2, [UR16+0x6018]", false), // mx1k.cubin@0770
    (0x010f2800080008000060180fff027984u128, "LDS R2, [UR15+0x6018]", false), // dc_b9_08.cubin@09c0
    (0x000e2800080008000000000cff057984u128, "LDS R5, [UR12]", false), // mx1k.cubin@0ac0
    (0x000e6800080008000000000aff057984u128, "LDS R5, [UR10]", false), // dc_b9_08.cubin@0ee0
    (0x004e2800001ee10700000006020773a9u128, "ATOMG.E.CAS.STRONG.GPU PT, R7, [R2], R6, R7", false), // g126_e_cas.cubin@0060
    (0x000ea400001ee10d0000000b040d73a9u128, "ATOMG.E.CAS.STRONG.GPU PT, R13, [R4], R11, R13", false), // libcusparse.so.246.sm_100.cubin@0ae0
    (0x000e2200000000000000000004047984u128, "LDS.U8 R4, [R4]", false), // probe54.cubin@02a0
    (0x000e6200000000000000000002027984u128, "LDS.U8 R2, [R2]", false), // v_alloc2.cubin@0090
    (0x000e2400000008000000000009047984u128, "LDS R4, [R9]", false), // probe54.cubin@04c0
    (0x000e2400000008000000000008047984u128, "LDS R4, [R8]", false), // probe54.cubin@06c0
    (0x00036400001ee1050000000406ff73a9u128, "ATOMG.E.CAS.STRONG.GPU PT, RZ, [R6], R4, R5", false), // cf.cubin@03c0
    (0x000fe200001f41050000000402ff73a9u128, "ATOMG.E.CAS.STRONG.SYS PT, RZ, [R2], R4, R5", false), // at_cas.cubin@0060
    (0x000fe200001f41050000000402ff73a9u128, "ATOMG.E.CAS.STRONG.SYS PT, RZ, [R2], R4, R5", false), // at_cas.cubin@0060
    (0x000e2200080008000000000400057984u128, "LDS R5, [R0+UR4]", false), // b_bulk_cp.cubin@0260
    (0x000e6800080008000000000400097984u128, "LDS R9, [R0+UR4]", false), // b_cpasync.cubin@0170
    (0x000fe2000000080000000000fffff984u128, "@!PT LDS RZ, [RZ]", false), // b_cpasync.cubin@0100
    (0x000fe2000000080000000000fffff984u128, "@!PT LDS RZ, [RZ]", false), // b_cpasync.cubin@0110
    (0x000ea800001f410700000006040573a9u128, "ATOMG.E.CAS.STRONG.SYS PT, R5, [R4], R6, R7", false), // p_cas.cubin@00e0
    (0x000ea800001f410700000006040573a9u128, "ATOMG.E.CAS.STRONG.SYS PT, R5, [R4], R6, R7", false), // p_cas.cubin@00e0
    (0x000e620000000c00000000001c0c7984u128, "LDS.128 R12, [R28]", false), // libcublas.so.1016.sm_100.cubin@0f70
    (0x001e280000000c0000000000210c7984u128, "LDS.128 R12, [R33]", false), // libcublas.so.231.sm_100.cubin@0fb0
    (0x001fea0000000a000000000009049984u128, "@!P1 LDS.64 R4, [R9]", false), // libcublas.so.135.sm_100.cubin@03d0
    (0x000e240000000a000000000006069984u128, "@!P1 LDS.64 R6, [R6]", false), // libcublas.so.135.sm_100.cubin@03e0
    (0x000e280008000a0000000004ff027984u128, "LDS.64 R2, [UR4]", false), // libcublas.so.135.sm_100.cubin@04a0
    (0x001e280008000a0000000004ff027984u128, "LDS.64 R2, [UR4]", false), // libcublas.so.135.sm_100.cubin@0480
    (0x000fe800000008000000000005049984u128, "@!P1 LDS R4, [R5]", false), // libcublas.so.135.sm_100.cubin@03d0
    (0x000e2400000008000000000006079984u128, "@!P1 LDS R7, [R6]", false), // libcublas.so.135.sm_100.cubin@03e0
    (0x000ea40000000a000000000009127984u128, "LDS.64 R18, [R9]", false), // libcublas.so.183.sm_100.cubin@09b0
    (0x000ea40000000a00000000001c187984u128, "LDS.64 R24, [R28]", false), // libcublas.so.183.sm_100.cubin@09e0
    (0x000e280000000a000000080009107984u128, "LDS.64 R16, [R9+0x8]", false), // libcublas.so.183.sm_100.cubin@0a20
    (0x000e260000000a000000100009107984u128, "LDS.64 R16, [R9+0x10]", false), // libcublas.so.183.sm_100.cubin@0ae0
    (0x0001e200001008000000000301007387u128, "STL [R1], R3", false), // libcublas.so.183.sm_100.cubin@0220
    (0x0001e200001008000000000301007387u128, "STL [R1], R3", false), // libcublas.so.183.sm_100.cubin@0220
    (0x000ea2000000080000003800181b0984u128, "@P0 LDS R27, [R24+0x38]", false), // libcublas.so.177.sm_100.cubin@0e80
    (0x000ea2000000080000003800181b0984u128, "@P0 LDS R27, [R24+0x38]", false), // libcublas.so.177.sm_100.cubin@0e80
    (0x001e240000000a00000000000a140984u128, "@P0 LDS.64 R20, [R10]", false), // libcublas.so.1021.sm_100.cubin@0c60
    (0x001fe80000000a000000000006141984u128, "@P1 LDS.64 R20, [R6]", false), // libcublas.so.1021.sm_100.cubin@0890
    (0x0001e60000100c00000000ff01007387u128, "STL.128 [R1], RZ", false), // libcublas.so.1021.sm_100.cubin@01e0
    (0x0001e60000100c00000000ff01007387u128, "STL.128 [R1], RZ", false), // libcublas.so.1021.sm_100.cubin@01e0
    (0x0001e80000100c00000010ff01007387u128, "STL.128 [R1+0x10], RZ", false), // libcublas.so.1021.sm_100.cubin@0200
    (0x0001e80000100c00000020ff01007387u128, "STL.128 [R1+0x20], RZ", false), // libcublas.so.1021.sm_100.cubin@0210
    (0x0043ea0000100a000000080601001387u128, "@P1 STL.64 [R1+0x8], R6", false), // libcublas.so.1021.sm_100.cubin@05d0
    (0x0041e80000100a000000100801000387u128, "@P0 STL.64 [R1+0x10], R8", false), // libcublas.so.1021.sm_100.cubin@0660
    (0x0041e40000100a000000000201007387u128, "STL.64 [R1], R2", false), // libcublas.so.1021.sm_100.cubin@0da0
    (0x0041e40000100a000000000201007387u128, "STL.64 [R1], R2", false), // libcublas.so.1021.sm_100.cubin@0da0
    (0x000e240008000c0000000007ff087984u128, "LDS.128 R8, [UR7]", false), // libcublas.so.279.sm_100.cubin@09b0
    (0x000e240008000c0000000007ff087984u128, "LDS.128 R8, [UR7]", false), // libcublas.so.279.sm_100.cubin@09b0
    (0x000ea200000008000000000008062984u128, "@P2 LDS R6, [R8]", false), // libcublas.so.279.sm_100.cubin@0ed0
    (0x000ea200000008000000000008062984u128, "@P2 LDS R6, [R8]", false), // libcublas.so.279.sm_100.cubin@0ed0
    (0x000e280000000c000000100033047984u128, "LDS.128 R4, [R51+0x10]", false), // libcublas.so.213.sm_100.cubin@0a60
    (0x000e280000000c000000200033047984u128, "LDS.128 R4, [R51+0x20]", false), // libcublas.so.213.sm_100.cubin@0d00
    (0x000e2400000008000000200005068984u128, "@!P0 LDS R6, [R5+0x20]", false), // libcublas.so.303.sm_100.cubin@0690
    (0x000e2200000008000000400005069984u128, "@!P1 LDS R6, [R5+0x40]", false), // libcublas.so.303.sm_100.cubin@0770
    (0x000e280000000a000000200006168984u128, "@!P0 LDS.64 R22, [R6+0x20]", false), // libcublas.so.309.sm_100.cubin@0710
    (0x000e280000000a000000400006169984u128, "@!P1 LDS.64 R22, [R6+0x40]", false), // libcublas.so.309.sm_100.cubin@0880
    (0x000e6600080008000000000507119984u128, "@!P1 LDS R17, [R7+UR5]", false), // libcublas.so.315.sm_100.cubin@0640
    (0x000e6800080008000000000506159984u128, "@!P1 LDS R21, [R6+UR5]", false), // libcublas.so.315.sm_100.cubin@06c0
    (0x001f620008000c000000100aff0c7984u128, "LDS.128 R12, [UR10+0x10]", false), // libcublas.so.25.sm_100.cubin@0e40
    (0x001f620008000c000000100aff0c7984u128, "LDS.128 R12, [UR10+0x10]", false), // libcublas.so.25.sm_100.cubin@0e40
    (0x0001e200001008000000040001007387u128, "STL [R1+0x4], R0", false), // libcublas.so.201.sm_100.cubin@0200
    (0x0001e200001008000000040a01007387u128, "STL [R1+0x4], R10", false), // libcublas.so.1026.sm_100.cubin@03f0
    (0x000e660008000a0000000005050e9984u128, "@!P1 LDS.64 R14, [R5+UR5]", false), // libcublas.so.321.sm_100.cubin@06a0
    (0x000e680008000a00000000080e0ab984u128, "@!P3 LDS.64 R10, [R14+UR8]", false), // libcublas.so.321.sm_100.cubin@06e0
    (0x000e660008000a0000000005050e7984u128, "LDS.64 R14, [R5+UR5]", false), // libcublas.so.321.sm_100.cubin@0810
    (0x000e260008000a0000000005050e7984u128, "LDS.64 R14, [R5+UR5]", false), // libcublas.so.321.sm_100.cubin@09d0
    (0x000e6800080008000001000408297984u128, "LDS R41, [R8+UR4+0x100]", false), // libcublas.so.255.sm_100.cubin@0be0
    (0x000ea8000800080000020004082a7984u128, "LDS R42, [R8+UR4+0x200]", false), // libcublas.so.255.sm_100.cubin@0bf0
    (0x000fe8000800080000002008071a8984u128, "@!P0 LDS R26, [R7+UR8+0x20]", false), // libcublas.so.339.sm_100.cubin@0730
    (0x000ee200080008000000200707188984u128, "@!P0 LDS R24, [R7+UR7+0x20]", false), // libcublas.so.339.sm_100.cubin@0750
    (0x000fe80008000a0000002007000e7984u128, "LDS.64 R14, [R0+UR7+0x20]", false), // libcublas.so.333.sm_100.cubin@0c50
    (0x000f220008000a0000002004000a7984u128, "LDS.64 R10, [R0+UR4+0x20]", false), // libcublas.so.333.sm_100.cubin@0c70
    (0x001fe80000000c00000000000308a984u128, "@!P2 LDS.128 R8, [R3]", false), // libcublas.so.1026.sm_100.cubin@0b10
    (0x0001e80000000c00000000001810a984u128, "@!P2 LDS.128 R16, [R24]", false), // libcublas.so.1026.sm_100.cubin@0b20
    (0x00afe80000000c000000000004082984u128, "@P2 LDS.128 R8, [R4]", false), // libcublas.so.1026.sm_100.cubin@0b20
    (0x000e240000000c000000000005142984u128, "@P2 LDS.128 R20, [R5]", false), // libcublas.so.1026.sm_100.cubin@0b40
    (0x0041ea0000100c000000000401000387u128, "@P0 STL.128 [R1], R4", false), // libcublas.so.1026.sm_100.cubin@0790
    (0x0041ea0000100c000000000401000387u128, "@P0 STL.128 [R1], R4", false), // libcublas.so.1026.sm_100.cubin@0590
    (0x0043ea0000100c000000100801001387u128, "@P1 STL.128 [R1+0x10], R8", false), // libcublas.so.1026.sm_100.cubin@0800
    (0x004fea0000100c000000200c01000387u128, "@P0 STL.128 [R1+0x20], R12", false), // libcublas.so.1026.sm_100.cubin@08a0
    (0x000fe2000000040000000200091b7984u128, "LDS.U16 R27, [R9+0x2]", false), // libcublas.so.375.sm_100.cubin@0590
    (0x000fe20000000400000022000a127984u128, "LDS.U16 R18, [R10+0x22]", false), // libcublas.so.375.sm_100.cubin@05c0
    (0x000fe8000000040000000000090e7984u128, "LDS.U16 R14, [R9]", false), // libcublas.so.375.sm_100.cubin@0640
    (0x000e280000000400000000000a0f7984u128, "LDS.U16 R15, [R10]", false), // libcublas.so.375.sm_100.cubin@0650
    (0x000e680000000a0000008000180c2984u128, "@P2 LDS.64 R12, [R24+0x80]", false), // libcublas.so.531.sm_100.cubin@06d0
    (0x000ea80000000a000001000018021984u128, "@P1 LDS.64 R2, [R24+0x100]", false), // libcublas.so.531.sm_100.cubin@06f0
    (0x000fe20000000c0000009000000c2984u128, "@P2 LDS.128 R12, [R0+0x90]", false), // libcublas.so.603.sm_100.cubin@0f40
    (0x000e240000000c000000100005102984u128, "@P2 LDS.128 R16, [R5+0x10]", false), // libcublas.so.603.sm_100.cubin@0f60
    (0x000e240008000c0000000005170c1984u128, "@P1 LDS.128 R12, [R23+UR5]", false), // libcublas.so.603.sm_100.cubin@0da0
    (0x000e240008000c000000000819081984u128, "@P1 LDS.128 R8, [R25+UR8]", false), // libcublas.so.603.sm_100.cubin@0b70
    (0x000fe20008000c0000009005170c2984u128, "@P2 LDS.128 R12, [R23+UR5+0x90]", false), // libcublas.so.603.sm_100.cubin@0e50
    (0x000fe20008000c0000012005170c1984u128, "@P1 LDS.128 R12, [R23+UR5+0x120]", false), // libcublas.so.603.sm_100.cubin@0f30
    (0x000e240008000a0000000005130e1984u128, "@P1 LDS.64 R14, [R19+UR5]", false), // libcublas.so.603.sm_100.cubin@0e70
    (0x000e240008000a00000000050b101984u128, "@P1 LDS.64 R16, [R11+UR5]", false), // libcublas.so.603.sm_100.cubin@0ce0
    (0x000fe20008000a0000004805130e2984u128, "@P2 LDS.64 R14, [R19+UR5+0x48]", false), // libcublas.so.603.sm_100.cubin@0f00
    (0x000fe20008000a0000009005130e1984u128, "@P1 LDS.64 R14, [R19+UR5+0x90]", false), // libcublas.so.603.sm_100.cubin@0fc0
    (0x0041e2000810080e00000004ff007987u128, "STL [UR14], R4", false), // libcublas.so.627.sm_100.cubin@0c00
    (0x0041e2000810080e00000004ff007987u128, "STL [UR14], R4", false), // libcublas.so.609.sm_100.cubin@0c00
    (0x0003e4000810080e00000003ff006987u128, "@P6 STL [UR14], R3", false), // libcublas.so.627.sm_100.cubin@0fa0
    (0x0003e4000810080e00000003ff006987u128, "@P6 STL [UR14], R3", false), // libcublas.so.609.sm_100.cubin@0fa0
    (0x0007e20000100800000000ff01007387u128, "STL [R1], RZ", false), // libcublas.so.721.sm_100.cubin@0080
    (0x0005e20000100800000000ff01007387u128, "STL [R1], RZ", false), // libcurand.so.78.sm_100.cubin@0620
    (0x000e620000000c000000400002108984u128, "@!P0 LDS.128 R16, [R2+0x40]", false), // libcublas.so.811.sm_100.cubin@0750
    (0x000e620000000c000000800002109984u128, "@!P1 LDS.128 R16, [R2+0x80]", false), // libcublas.so.811.sm_100.cubin@08c0
    (0x0043e20008100a0d00000004ff007987u128, "STL.64 [UR13], R4", false), // libcublas.so.633.sm_100.cubin@0cf0
    (0x0043e20008100a0d00000004ff007987u128, "STL.64 [UR13], R4", false), // libcublas.so.609.sm_100.cubin@0cf0
    (0x000e680008000a000000200705109984u128, "@!P1 LDS.64 R16, [R5+UR7+0x20]", false), // libcublas.so.816.sm_100.cubin@07b0
    (0x000e680008000a000000400705108984u128, "@!P0 LDS.64 R16, [R5+UR7+0x40]", false), // libcublas.so.816.sm_100.cubin@08e0
    (0x000e660008000c000000000512089984u128, "@!P1 LDS.128 R8, [R18+UR5]", false), // libcublas.so.821.sm_100.cubin@0670
    (0x000e660008000c000000000712089984u128, "@!P1 LDS.128 R8, [R18+UR7]", false), // libcublas.so.821.sm_100.cubin@06d0
    (0x001e260008000c000000000512047984u128, "LDS.128 R4, [R18+UR5]", false), // libcublas.so.821.sm_100.cubin@0830
    (0x000e280008000c000000000512047984u128, "LDS.128 R4, [R18+UR5]", false), // libcublas.so.821.sm_100.cubin@0a20
    (0x000ee20008000c000000400700107984u128, "LDS.128 R16, [R0+UR7+0x40]", false), // libcublas.so.831.sm_100.cubin@0cb0
    (0x000e620008000c0000004004000c7984u128, "LDS.128 R12, [R0+UR4+0x40]", false), // libcublas.so.831.sm_100.cubin@0da0
    (0x000ea40008000a0000000005ff0c8984u128, "@!P0 LDS.64 R12, [UR5]", false), // libcublas.so.75.sm_100.cubin@0520
    (0x000ea40008000a0000000005ff0a9984u128, "@!P1 LDS.64 R10, [UR5]", false), // libcublas.so.75.sm_100.cubin@0550
    (0x000e280008000a0000000805ff0e7984u128, "LDS.64 R14, [UR5+0x8]", false), // libcublas.so.75.sm_100.cubin@0620
    (0x000e280008000a0000001005ff0c7984u128, "LDS.64 R12, [UR5+0x10]", false), // libcublas.so.75.sm_100.cubin@0750
    (0x000fe40000100a00000008600100a387u128, "@!P2 STL.64 [R1+0x8], R96", false), // libcublas.so.72.sm_100.cubin@0ea0
    (0x0007ee0000100a000000080601008387u128, "@!P0 STL.64 [R1+0x8], R6", false), // libcublasLt.so.502.sm_100.cubin@0160
    (0x0003e20000100a00000000ff01007387u128, "STL.64 [R1], RZ", false), // libcublas.so.72.sm_100.cubin@0470
    (0x0003e20000100a00000000ff01007387u128, "STL.64 [R1], RZ", false), // libcublas.so.72.sm_100.cubin@0720
    (0x000ea200003008000000000001147983u128, "LDL.LU R20, [R1]", false), // libcublasLt.so.329.sm_100.cubin@0fc0
    (0x000ea200003008000000000001137983u128, "LDL.LU R19, [R1]", false), // libcublasLt.so.329.sm_100.cubin@0f50
    (0x000ee800003008000000040001117983u128, "LDL.LU R17, [R1+0x4]", false), // libcublasLt.so.329.sm_100.cubin@0f90
    (0x000f2800003008000000040001117983u128, "LDL.LU R17, [R1+0x4]", false), // libcublasLt.so.329.sm_100.cubin@0f20
    (0x000fe80008000000000000045e147984u128, "LDS.U8 R20, [R94+UR4]", false), // libcublasLt.so.581.sm_100.cubin@0be0
    (0x000fe800080000000000000f591b7984u128, "LDS.U8 R27, [R89+UR15]", false), // libcublasLt.so.581.sm_100.cubin@0ce0
    (0x000e680008000000000090045e117984u128, "LDS.U8 R17, [R94+UR4+0x90]", false), // libcublasLt.so.581.sm_100.cubin@0bf0
    (0x000fe80008000000000120045e127984u128, "LDS.U8 R18, [R94+UR4+0x120]", false), // libcublasLt.so.581.sm_100.cubin@0c00
    (0x000f2800000000000000900019077984u128, "LDS.U8 R7, [R25+0x90]", false), // libcublasLt.so.581.sm_100.cubin@0c80
    (0x000fe800000000000001200019087984u128, "LDS.U8 R8, [R25+0x120]", false), // libcublasLt.so.581.sm_100.cubin@0c90
    (0x000e620008000a0000000005ff061984u128, "@P1 LDS.64 R6, [UR5]", false), // libcurand.so.33.sm_100.cubin@0520
    (0x000ea20008000a0000000005ff0a1984u128, "@P1 LDS.64 R10, [UR5]", false), // libcurand.so.33.sm_100.cubin@0510
    (0x000ea20008000a0000000805ff100984u128, "@P0 LDS.64 R16, [UR5+0x8]", false), // libcurand.so.33.sm_100.cubin@0580
    (0x000ee20008000a0000001005ff124984u128, "@P4 LDS.64 R18, [UR5+0x10]", false), // libcurand.so.33.sm_100.cubin@05f0
    (0x000e28000800080000000005ff050984u128, "@P0 LDS R5, [UR5]", false), // libcurand.so.33.sm_100.cubin@0350
    (0x000e28000800080000000005ff090984u128, "@P0 LDS R9, [UR5]", false), // libcurand.so.33.sm_100.cubin@0330
    (0x000e68000800080000000405ff091984u128, "@P1 LDS R9, [UR5+0x4]", false), // libcurand.so.33.sm_100.cubin@0360
    (0x000ea8000800080000000805ff0b2984u128, "@P2 LDS R11, [UR5+0x8]", false), // libcurand.so.33.sm_100.cubin@0370
    (0x000ee2000800080000100004ff0d9984u128, "@!P1 LDS R13, [UR4+0x1000]", false), // libcurand.so.33.sm_100.cubin@0640
    (0x000e24000800080000100004ff0d9984u128, "@!P1 LDS R13, [UR4+0x1000]", false), // libcurand.so.33.sm_100.cubin@0a40
    (0x0001e20000100800000028ff01007387u128, "STL [R1+0x28], RZ", false), // libcurand.so.78.sm_100.cubin@0740
    (0x0005e20000100800000028ff01007387u128, "STL [R1+0x28], RZ", false), // libcurand.so.78.sm_100.cubin@06a0
    (0x000e240008000a0000000806ff04e984u128, "@!P6 LDS.64 R4, [UR6+0x8]", false), // libcusolver.so.1258.sm_100.cubin@0a90
    (0x000e240008000a0000000806ff04e984u128, "@!P6 LDS.64 R4, [UR6+0x8]", false), // libcusolver.so.1258.sm_100.cubin@0990
    (0x000e240008000c0000001004ff049984u128, "@!P1 LDS.128 R4, [UR4+0x10]", false), // libcusolver.so.1582.sm_100.cubin@0ad0
    (0x000e240008000c0000001004ff049984u128, "@!P1 LDS.128 R4, [UR4+0x10]", false), // libcusolver.so.1582.sm_100.cubin@0ac0
    (0x0005e80000100a00000008ff01007387u128, "STL.64 [R1+0x8], RZ", false), // libcusolver.so.1573.sm_100.cubin@0f70
    (0x0003e20000100a00000028ff01007387u128, "STL.64 [R1+0x28], RZ", false), // libcusparse.so.199.sm_103.cubin@0bd0
    (0x0001e800001006000000000001007387u128, "STL.S16 [R1], R0", false), // libcusolver.so.1529.sm_103.cubin@04c0
    (0x0001e400001006000000000201007387u128, "STL.S16 [R1], R2", false), // libcusolver.so.1546.sm_100.cubin@01f0
    (0x0001e800001006000000040301007387u128, "STL.S16 [R1+0x4], R3", false), // libcusolver.so.1546.sm_100.cubin@01e0
    (0x0001e800001006000000040301007387u128, "STL.S16 [R1+0x4], R3", false), // libcusolver.so.1547.sm_103.cubin@01e0
    (0x000e220008000800000000050f0f1984u128, "@P1 LDS R15, [R15+UR5]", false), // libcusolver.so.438.sm_100.cubin@0fd0
    (0x000e220008000800000000050f0f1984u128, "@P1 LDS R15, [R15+UR5]", false), // libcusolver.so.439.sm_103.cubin@0fd0
    (0x001ea400001f450600000004020673a9u128, "ATOMG.E.CAS.64.STRONG.SYS PT, R6, [R2], R4, R6", false), // libcusolver.so.556.sm_103.cubin@03d0
    (0x002ea400001f4506000000040e0673a9u128, "ATOMG.E.CAS.64.STRONG.SYS PT, R6, [R14], R4, R6", false), // libcusolver.so.556.sm_103.cubin@0390
    (0x000fe80008000c0000000007ff088984u128, "@!P0 LDS.128 R8, [UR7]", false), // libcusolver.so.457.sm_103.cubin@0710
    (0x000e280008000c0000000004ff048984u128, "@!P0 LDS.128 R4, [UR4]", false), // libcusolver.so.457.sm_103.cubin@0c60
    (0x000fe6000800080000000005ff168984u128, "@!P0 LDS R22, [UR5]", false), // libcusolver.so.457.sm_103.cubin@0500
    (0x000fe8000800080000000005ff088984u128, "@!P0 LDS R8, [UR5]", false), // libcusolver.so.457.sm_103.cubin@07e0
    (0x0041e800001008000000040001008387u128, "@!P0 STL [R1+0x4], R0", false), // libcusparse.so.222.sm_100.cubin@0490
    (0x0001e800001008000000040001008387u128, "@!P0 STL [R1+0x4], R0", false), // libcusparse.so.222.sm_100.cubin@0540
    (0x0083e200001008000000000801008387u128, "@!P0 STL [R1], R8", false), // libcusparse.so.222.sm_100.cubin@04a0
    (0x0105e200001008000000000801008387u128, "@!P0 STL [R1], R8", false), // libcusparse.so.222.sm_100.cubin@0570
    (0x000f22000010060000001c00013d7983u128, "LDL.S16 R61, [R1+0x1c]", false), // libcusparse.so.183.sm_103.cubin@0f60
    (0x000f28000010060000001800013c7983u128, "LDL.S16 R60, [R1+0x18]", false), // libcusparse.so.183.sm_103.cubin@0f80
    (0x000f2800001006000000000001367983u128, "LDL.S16 R54, [R1]", false), // libcusparse.so.183.sm_103.cubin@0d70
    (0x000ee800001006000000000001367983u128, "LDL.S16 R54, [R1]", false), // libcusparse.so.183.sm_103.cubin@0e80
    (0x0005e6000010060000001c0f01002387u128, "@P2 STL.S16 [R1+0x1c], R15", false), // libcusparse.so.183.sm_103.cubin@0ee0
    (0x0007e200001006000000143701004387u128, "@P4 STL.S16 [R1+0x14], R55", false), // libcusparse.so.183.sm_103.cubin@0e50
    (0x000e28000000040000000000081b8984u128, "@!P0 LDS.U16 R27, [R8]", false), // libcusparse.so.735.sm_103.cubin@0bb0
    (0x000e28000000040000000000081b8984u128, "@!P0 LDS.U16 R27, [R8]", false), // libcusparse.so.735.sm_103.cubin@0b70
    (0x000e280008000400000000062a397984u128, "LDS.U16 R57, [R42+UR6]", false), // libcusparse.so.230.sm_100.cubin@0f60
    (0x000ea800080004000000000629337984u128, "LDS.U16 R51, [R41+UR6]", false), // libcusparse.so.230.sm_100.cubin@0f80
    (0x000e680008000400000080062a387984u128, "LDS.U16 R56, [R42+UR6+0x80]", false), // libcusparse.so.230.sm_100.cubin@0f70
    (0x000ee8000800040000004006293b7984u128, "LDS.U16 R59, [R41+UR6+0x40]", false), // libcusparse.so.230.sm_100.cubin@0f90
    (0x0003e200001006000000000401000387u128, "@P0 STL.S16 [R1], R4", false), // libcusparse.so.199.sm_103.cubin@09c0
    (0x0001e200001006000000004201003387u128, "@P3 STL.S16 [R1], R66", false), // libcusparse.so.199.sm_103.cubin@0e00
];

#[test]
fn bug094_decode_vendor_exact_sm103a() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for &(w, golden, _) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("word {w:032x}: {e}"));
        assert_eq!(cubit::printer::to_sass(&d), golden, "sm103a word {w:032x}");
    }
}

#[test]
fn bug094_decode_vendor_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden, _) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("word {w:032x}: {e}"));
        assert_eq!(cubit::printer::to_sass(&d), golden, "sm120 word {w:032x}");
    }
}

#[test]
fn bug094_roundtrip_word_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden, _) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, w & M96, "sm120 roundtrip: {text}");
    }
}

#[test]
fn bug094_roundtrip_word_exact_sm103a_guarded() {
    // sm103a: BUG-088 .128 alignment law refuses encode of odd-quad dests
    // (R44/52/60/68/100/132/196/204 trap on silicon); those anchors are
    // decode-only on canon by design (guard=true entries).
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let mut encoded = 0usize;
    for &(w, golden, guard) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        if guard {
            assert!(encode_instruction(&insn, &t).is_err(),
                "guard word must fail closed on sm103a: {text}");
            continue;
        }
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("sm103a encode {text}: {e}"));
        assert_eq!(w2 & M96, w & M96, "sm103a roundtrip: {text}");
        encoded += 1;
    }
    assert!(encoded > 0);
}

#[test]
fn bug094_atomg_cas64_vendor_order() {
    // Printer arm: size prints between operation and STRONG for ATOM*/REDG.
    let w: u128 = 0x0000e40006e11e00000000040773a9u128; // sample replaced below
    let _ = w;
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let anchor = GOLD.iter().find(|(_, g, _)| g.contains("ATOMG.E.CAS.64"))
        .expect("CAS.64 anchor present");
    let d = idx.decode(anchor.0, 0, &t).unwrap();
    let text = cubit::printer::to_sass(&d);
    assert_eq!(text, anchor.1);
    assert!(text.contains(".CAS.64.STRONG.SYS"), "vendor order: {text}");
    assert!(!text.contains("STRONG.64"), "old buggy order: {text}");
}

#[test]
fn bug094_junk_catchall_gone() {
    // Pre-BUG-094 these decoded to LDG.E.LTC128B.128 on both tables.
    for t in [t120(), t103()] {
        let idx = DecodeIndex::build(&t);
        for &(w, golden, _) in GOLD.iter().take(16) {
            let d = idx.decode(w, 0, &t).unwrap();
            let text = cubit::printer::to_sass(&d);
            assert!(!text.contains("LTC128B"), "junk catch-all still wins: {text}");
            assert_eq!(text, golden);
        }
    }
}

#[test]
fn bug094_era_glif_encode_retention_both_tables() {
    // Era text (b4fill2 era) carries the LDG.E.LTC128B.128 glif; the frozen
    // era encode (5,617-line era-enc gate, results/cubitfix/083/enc_postfix.json)
    // must stay byte-exact. After BUG-094 the encode routes via the encode_only
    // retention rows (canon LDG.E.LTC128B.128_R_dARI / sm120 BUG-090 row),
    // NOT via decode-visible state.
    const ERA: &[(&str, u128)] = &[
        ("LDG.E.LTC128B.128 R8, desc[UR8][R6.64] !rsd[0:1,72:1,73:1,75:1,81:1,82:1,83:1,84:1,91:1,92:1]", 0x000fc200181e0b000000000806087981u128),
        ("LDG.E.LTC128B.128 R28, desc[UR8][R6.64+0x5000] !rsd[0:1,72:1,73:1,75:1,81:1,82:1,83:1,84:1,91:1,92:1]", 0x000fc200181e0b0000500008061c7981u128),
        ("LDG.E.LTC128B.128 R10, desc[UR8][R6.64+0x800] !rsd[0:1,72:1,73:1,75:1,81:1,82:1,83:1,84:1,91:1,92:1]", 0x000fc200181e0b0000080008060a7981u128),
];
    // Canon (sm103a) retention row preserves the era encoding verbatim
    // (5,617-line era-enc gate = 0 diff vs results/cubitfix/083/enc_postfix.json).
    let t = t103();
    for &(line, want) in ERA {
        let insn = parse_sass(&format!("{line} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("era glif encode (sm103a): {e}"));
        assert_eq!(w2, want, "era glif retention (sm103a): {line}");
    }
    // The sm120 side routes through the BUG-090 scout row
    // (LDG.E.LTC128B.128_R_dARI), whose baked desc-policy constants at bits
    // 76/90 come from the v11-era geometry the scout was cloned from; the
    // text+rsd-owned bits are identical (this exact equality is what the
    // frozen-chain v13 vs v11 byte-parity gate proved in BUG-090).
    let t = t120();
    const SCOUT_CONST: u128 = (1u128 << 76) | (1u128 << 90);
    for &(line, want) in ERA {
        let insn = parse_sass(&format!("{line} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("era glif encode (sm120): {e}"));
        assert_eq!(w2 & !SCOUT_CONST, want & !SCOUT_CONST,
            "era glif retention (sm120, scout-const masked): {line}");
    }
}
