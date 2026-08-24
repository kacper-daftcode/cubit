//! BUG-097 (F2Q, 2026-08-23): generic-memory LD/ST family on sm120.json
//! carried harvest-junk geometry (dedicated dotted rows LD.E.128_R_dARI,
//! LD.E.128.STRONG.SYS_R_dARI, ST.E.64_dARI_R, ...): decode rendered descriptor
//! slots, address pairs and destinations shifted/halved (vendor
//! `LD.E.128.STRONG.SYS R24, desc[UR16][R32.64]` -> `desc[UR0][R16.64]`), and
//! all STRONG-scope rows were missing entirely (fail-closed DECODE error).
//! 23 legacy keys -> 6 canon keys with sm103a geometry ported verbatim —
//! same method as BUG-084. Canon sm103a.json geometry itself was vendor-true;
//! its residual was printer-side: mod_priority had no LD/ST arm, so STRONG /
//! scope / E all fell into the same bucket and a stable sort printed the
//! alphabetical mg order (LD.E.GPU.STRONG, LD.E.STRONG.SYS.128) instead of the
//! vendor order (LD.E.STRONG.GPU, LD.E.128.STRONG.SYS). Plus a one-word
//! plain-u32-ur shape (`LD.E R0, [RZ.U32+UR4]`) which printed as the desc-form
//! `desc[UR4][RZ.64]` — an UR index silently mislabelled as a descriptor
//! selector (encode of the desc text then builds a different instruction).
//!
//! Corpus evidence (2049-cubin vendor census, cuobjdump 13.3, 30,338 LD.E/ST.E
//! records, work/f2-097/w097_raw.json): pre-fix sm120.json exact 14,978 /
//! diff 13,990 / err 1,370; post-fix BOTH tables decode+encode-vendor-exact
//! 30,338/30,338 (RT96 included). Report: the internal fix archive

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// (full 128-bit instruction word, vendor canonical text) — anchors
/// section-aligned from the vendor census (cuobjdump 13.3); file @off below.
const GOLD: &[(u128, &str)] = &[
    (0x000ea4000c1019000002000e0617a980, "@!P2 LD.E R23, desc[UR14][R6.64+0x200]"), // libcublas.so.37.sm_100.cubin @0b00
    (0x000ee2000c101900000200081403a980, "@!P2 LD.E R3, desc[UR8][R20.64+0x200]"), // libcublasLt.so.329.sm_100.cubin @06b0
    (0x000ea4000c1019000000000e0617a980, "@!P2 LD.E R23, desc[UR14][R6.64]"), // libcublas.so.37.sm_100.cubin @0ad0
    (0x000ea2000c1019000000000c0e138980, "@!P0 LD.E R19, desc[UR12][R14.64]"), // libcublas.so.567.sm_100.cubin @0270
    (0x0001620000100d000000000032249980, "@!P1 LD.E.128 R36, [R50]"), // libcusolver.so.1066.sm_100.cubin @0fc0
    (0x000168000c101d000000200e06102980, "@P2 LD.E.128 R16, desc[UR14][R6.64+0x20]"), // libcublas.so.1026.sm_100.cubin @0a90
    (0x000ea2000c101d000000000c02088980, "@!P0 LD.E.128 R8, desc[UR12][R2.64]"), // libcublas.so.1026.sm_100.cubin @0ce0
    (0x000ea2000c101d000000000a08088980, "@!P0 LD.E.128 R8, desc[UR10][R8.64]"), // libcublas.so.567.sm_100.cubin @0290
    (0x004ea2000c115d000001000a02108980, "@!P0 LD.E.128.STRONG.SYS R16, desc[UR10][R2.64+0x100]"), // libcusolver.so.132.sm_100.cubin @0e00
    (0x000ea2000c115d00000000060c0c8980, "@!P0 LD.E.128.STRONG.SYS R12, desc[UR6][R12.64]"), // libcusolver.so.1879.sm_100.cubin @0a30
    (0x000962000c115d00000000040c048980, "@!P0 LD.E.128.STRONG.SYS R4, desc[UR4][R12.64]"), // libcusolver.so.267.sm_100.cubin @0420
    (0x0001620000100b0000000000221a9980, "@!P1 LD.E.64 R26, [R34]"), // libcusolver.so.1067.sm_103.cubin @0d80
    (0x000168000c101b000000080c022e1980, "@P1 LD.E.64 R46, desc[UR12][R2.64+0x8]"), // libcublas.so.1021.sm_100.zero.cubin @08e0
    (0x000ea2000c101b000000000e04040980, "@P0 LD.E.64 R4, desc[UR14][R4.64]"), // libcublas.so.1021.sm_100.zero.cubin @0500
    (0x000ea2000c1013000000000c0c0aa980, "@!P2 LD.E.S8 R10, desc[UR12][R12.64]"), // libcublasLt.so.311.sm_100.cubin @05b0
    (0x000ea2000c1013000000000620201980, "@P1 LD.E.S8 R32, desc[UR6][R32.64]"), // libcusparse.so.126.sm_100.cubin @0e20
    (0x000ea4000c1015000001000e0617a980, "@!P2 LD.E.U16 R23, desc[UR14][R6.64+0x100]"), // libcublas.so.61.sm_100.cubin @0b10
    (0x000ea4000c1015000000000e0616a980, "@!P2 LD.E.U16 R22, desc[UR14][R6.64]"), // libcublas.so.61.sm_100.cubin @0ad0
    (0x000ea4000c1011000000000e100b0980, "@P0 LD.E.U8 R11, desc[UR14][R16.64]"), // libcublasLt.so.233.sm_100.cubin @0f50
    (0x000ea4000c1011000000000e0a100980, "@P0 LD.E.U8 R16, desc[UR14][R10.64]"), // libcublasLt.so.239.sm_100.cubin @0fc0
    (0x0201e2000010092d000000002000e385, "@!P6 ST.E [R32], R45"), // libcusolver.so.1089.sm_103.cubin @0d00
    (0x0201e2000010092a000000002000d385, "@!P5 ST.E [R32], R42"), // libcusolver.so.1088.sm_100.cubin @0eb0
    (0x0001e2000c10190a000000130e008985, "@!P0 ST.E desc[UR10][R14.64], R19"), // libcublasLt.so.233.sm_100.cubin @0ad0
    (0x0001e2000c10190c000000ff02008985, "@!P0 ST.E desc[UR12][R2.64], RZ"), // libcublasLt.so.233.sm_100.cubin @0e00
    (0x020fe20000100d100000000026009385, "@!P1 ST.E.128 [R38], R16"), // libcusolver.so.1088.sm_100.cubin @0ca0
    (0x0003e2000c101d0e0000100c14000985, "@P0 ST.E.128 desc[UR14][R20.64+0x10], R12"), // libcublas.so.1026.sm_100.cubin @0cf0
    (0x0005e2000c101d0e0000001406002985, "@P2 ST.E.128 desc[UR14][R6.64], R20"), // libcublas.so.1026.sm_100.cubin @0f10
    (0x0005e2000c10fd080002001014008985, "@!P0 ST.E.128.STRONG.GPU desc[UR8][R20.64+0x200], R16"), // libcusparse.so.262.sm_100.cubin @0d70
    (0x0011e2000c115d0a0000001002008985, "@!P0 ST.E.128.STRONG.SYS desc[UR10][R2.64], R16"), // libcusolver.so.132.sm_100.cubin @0e40
    (0x0003e2000c115d08000000ff04008985, "@!P0 ST.E.128.STRONG.SYS desc[UR8][R4.64], RZ"), // libcublas.so.639.sm_100.cubin @0b50
    (0x0001e60000100b18000000001e00e385, "@!P6 ST.E.64 [R30], R24"), // libcusolver.so.1089.sm_103.cubin @0fb0
    (0x020fe20000100b12000000001a009385, "@!P1 ST.E.64 [R26], R18"), // libcusolver.so.1088.sm_100.cubin @0a70
    (0x0005e2000c101b0c000018080c001985, "@P1 ST.E.64 desc[UR12][R12.64+0x18], R8"), // libcublas.so.1021.sm_100.zero.cubin @0d80
    (0x0001e2000c101b06000010ff0600a985, "@!P2 ST.E.64 desc[UR6][R6.64+0x10], RZ"), // libcublasLt.so.522.sm_100.cubin @09d0
    (0x0001e6000c101b0c0000001412001985, "@P1 ST.E.64 desc[UR12][R18.64], R20"), // libcublas.so.1021.sm_100.zero.cubin @0a80
    (0x0001e2000c101b06000000ff06008985, "@!P0 ST.E.64 desc[UR6][R6.64], RZ"), // libcublasLt.so.522.sm_100.cubin @0a00
    (0x0011e2000c101b04000000ff02008985, "@!P0 ST.E.64 desc[UR4][R2.64], RZ"), // libcusparse.so.318.sm_100.cubin @0070
    (0x0005e2000c10fb080001000a22008985, "@!P0 ST.E.64.STRONG.GPU desc[UR8][R34.64+0x100], R10"), // libcusparse.so.262.sm_100.cubin @0a50
    (0x0001e2000c1015060000000c0e008985, "@!P0 ST.E.U16 desc[UR6][R14.64], R12"), // libcublasLt.so.239.sm_100.cubin @0980
    (0x0001e2000c10150c000000ff02008985, "@!P0 ST.E.U16 desc[UR12][R2.64], RZ"), // libcublasLt.so.239.sm_100.cubin @0e50
    (0x000ea40000100900000000040a0e7980, "LD.E R14, [R10+0x4]"), // libcusparse.so.126.sm_100.cubin @0890
    (0x001ee2000810090000000004ff007980, "LD.E R0, [RZ.U32+UR4]"), // libcusolver.so.1088.sm_100.cubin @0270
    (0x000e6200001009000000000002677980, "LD.E R103, [R2]"), // libcusolver.so.1089.sm_103.cubin @02a0
    (0x000e6200001009000000000002aa7980, "LD.E R170, [R2]"), // libcusolver.so.1088.sm_100.cubin @0290
    (0x003ea4000c101900fff000040c0f7980, "LD.E R15, desc[UR4][R12.64+-0x1000]"), // libcusolver.so.213.sm_100.cubin @08d0
    (0x009e22000c101900ffffe0060a0d7980, "LD.E R13, desc[UR6][R10.64+-0x20]"), // libcusparse.so.318.sm_100.cubin @0490
    (0x000e24000c1019000002000e06057980, "LD.E R5, desc[UR14][R6.64+0x200]"), // libcublas.so.37.sm_100.cubin @0c70
    (0x000e64000c1019000000100806097980, "LD.E R9, desc[UR8][R6.64+0x10]"), // libcublasLt.so.329.sm_100.cubin @0750
    (0x000ea2000c1019000000000c0a0d7980, "LD.E R13, desc[UR12][R10.64]"), // libcublas.so.37.sm_100.cubin @09a0
    (0x000ea8000c1019000000000a0c0d7980, "LD.E R13, desc[UR10][R12.64]"), // libcublas.so.567.sm_100.cubin @0b30
    (0x004ea8000c101d00ffffc00404147980, "LD.E.128 R20, desc[UR4][R4.64+-0x40]"), // libcusolver.so.456.sm_100.cubin @0310
    (0x004ea8000c101d00ffffc004160c7980, "LD.E.128 R12, desc[UR4][R22.64+-0x40]"), // libcusolver.so.457.sm_103.cubin @0310
    (0x001ea8000c101d000000101002047980, "LD.E.128 R4, desc[UR16][R2.64+0x10]"), // libcublas.so.1026.sm_100.cubin @0fe0
    (0x000ea4000c101d000008000e301c7980, "LD.E.128 R28, desc[UR14][R48.64+0x800]"), // libcublas.so.55.sm_100.cubin @0b90
    (0x000ea8000c101d000000001006047980, "LD.E.128 R4, desc[UR16][R6.64]"), // libcublas.so.1026.sm_100.cubin @0d50
    (0x000ea2000c101d000000000c2e1c7980, "LD.E.128 R28, desc[UR12][R46.64]"), // libcublas.so.55.sm_100.cubin @09d0
    (0x004ea2000c10fd000002000820107980, "LD.E.128.STRONG.GPU R16, desc[UR8][R32.64+0x200]"), // libcusparse.so.262.sm_100.cubin @0df0
    (0x000ea2000c10fd000002000814047980, "LD.E.128.STRONG.GPU R4, desc[UR8][R20.64+0x200]"), // libcusparse.so.839.sm_103.cubin @0ed0
    (0x000ea2000c115d00fffff00802047980, "LD.E.128.STRONG.SYS R4, desc[UR8][R2.64+-0x10]"), // libcusolver.so.1034.sm_100.cubin @02b0
    (0x006ea8000c115d00ffd000062e107980, "LD.E.128.STRONG.SYS R16, desc[UR6][R46.64+-0x3000]"), // libcusolver.so.1879.sm_100.cubin @0d20
    (0x000ee8000c115d0000020008040c7980, "LD.E.128.STRONG.SYS R12, desc[UR8][R4.64+0x200]"), // libcublas.so.639.sm_100.cubin @0480
    (0x000ea8000c115d00001000062a0c7980, "LD.E.128.STRONG.SYS R12, desc[UR6][R42.64+0x1000]"), // libcusolver.so.1879.sm_100.cubin @0350
    (0x000ea4000c115d00000000086a587980, "LD.E.128.STRONG.SYS R88, desc[UR8][R106.64]"), // libcublas.so.741.sm_100.cubin @0ef0
    (0x000ea4000c115d000000000c26207980, "LD.E.128.STRONG.SYS R32, desc[UR12][R38.64]"), // libcublas.so.936.sm_100.cubin @0ce0
    (0x000ea40000100b000000000814107980, "LD.E.64 R16, [R20+0x8]"), // libcusparse.so.126.sm_100.cubin @08b0
    (0x000ea40000100b000000000014107980, "LD.E.64 R16, [R20]"), // libcusparse.so.126.sm_100.cubin @0730
    (0x000f640000100b000000000018187980, "LD.E.64 R24, [R24]"), // libcusolver.so.1066.sm_100.cubin @0d20
    (0x001e62000c101b00ffff80040a0c7980, "LD.E.64 R12, desc[UR4][R10.64+-0x80]"), // libcusparse.so.318.sm_100.cubin @0dd0
    (0x000ea8000c101b00ff00000602047980, "LD.E.64 R4, desc[UR6][R2.64+-0x10000]"), // libcusparse.so.54.sm_100.cubin @05e0
    (0x001ea8000c101b000000080e04027980, "LD.E.64 R2, desc[UR14][R4.64+0x8]"), // libcublas.so.1021.sm_100.zero.cubin @0dd0
    (0x000ea8000c101b000000000e06047980, "LD.E.64 R4, desc[UR14][R6.64]"), // libcublas.so.1021.sm_100.zero.cubin @0b80
    (0x000ee2000c10fb000001000808107980, "LD.E.64.STRONG.GPU R16, desc[UR8][R8.64+0x100]"), // libcusparse.so.262.sm_100.cubin @0ad0
    (0x000ee2000c10fb000001000808127980, "LD.E.64.STRONG.GPU R18, desc[UR8][R8.64+0x100]"), // libcusparse.so.782.sm_100.cubin @0c90
    (0x000ea2000c10fb000000000808107980, "LD.E.64.STRONG.GPU R16, desc[UR8][R8.64]"), // libcusparse.so.262.sm_100.cubin @0e50
    (0x000ea2000c10fb000000000808127980, "LD.E.64.STRONG.GPU R18, desc[UR8][R8.64]"), // libcusparse.so.782.sm_100.cubin @0fd0
    (0x000ea4000c1013000000000808087980, "LD.E.S8 R8, desc[UR8][R8.64]"), // libcublasLt.so.203.sm_100.cubin @02a0
    (0x000324000c101300000000080e157980, "LD.E.S8 R21, desc[UR8][R14.64]"), // libcublasLt.so.311.sm_100.cubin @0660
    (0x000ea8000c10f9000000040612057980, "LD.E.STRONG.GPU R5, desc[UR6][R18.64+0x4]"), // libcusparse.so.318.sm_100.cubin @05f0
    (0x000ea8000c10f9000000000440007980, "LD.E.STRONG.GPU R0, desc[UR4][R64.64]"), // libcusolver.so.1089.sm_103.cubin @09d0
    (0x000ea8000c10f9000000000608067980, "LD.E.STRONG.GPU R6, desc[UR6][R8.64]"), // libcusolver.so.1879.sm_100.cubin @02a0
    (0x001eac000c1159000000000606077980, "LD.E.STRONG.SYS R7, desc[UR6][R6.64]"), // libcusparse.so.318.sm_100.cubin @06e0
    (0x000ea8000c101500fffffe040a027980, "LD.E.U16 R2, desc[UR4][R10.64+-0x2]"), // libcusparse.so.22.sm_100.cubin @0e60
    (0x000ea4000c1015000001000e06057980, "LD.E.U16 R5, desc[UR14][R6.64+0x100]"), // libcublas.so.61.sm_100.cubin @0cc0
    (0x000ea4000c1015000000080810167980, "LD.E.U16 R22, desc[UR8][R16.64+0x8]"), // libcublasLt.so.323.sm_100.cubin @07a0
    (0x000ea2000c1015000000000c1e2f7980, "LD.E.U16 R47, desc[UR12][R30.64]"), // libcublas.so.61.sm_100.cubin @0980
    (0x000ea2000c1015000000000c080b7980, "LD.E.U16 R11, desc[UR12][R8.64]"), // libcublas.so.67.sm_100.cubin @0980
    (0x000ea2000c1011000000001002137980, "LD.E.U8 R19, desc[UR16][R2.64]"), // libcublasLt.so.233.sm_100.cubin @0d00
    (0x0203e400001009020000000022007385, "ST.E [R34], R2"), // libcusolver.so.1089.sm_103.cubin @0ab0
    (0x0201e400001009370000000022007385, "ST.E [R34], R55"), // libcusolver.so.1088.sm_100.cubin @0ad0
    (0x0005e4000c101906000004090a007985, "ST.E desc[UR6][R10.64+0x4], R9"), // libcusparse.so.126.sm_100.cubin @0910
    (0x0005e4000c101908000080020c007985, "ST.E desc[UR8][R12.64+0x80], R2"), // libcusparse.so.182.sm_100.cubin @0ed0
    (0x0003e2000c101904000200ff0a007985, "ST.E desc[UR4][R10.64+0x200], RZ"), // libcusolver.so.213.sm_100.cubin @0240
    (0x0001e2000c1019080000001314007985, "ST.E desc[UR8][R20.64], R19"), // libcublasLt.so.233.sm_100.cubin @09e0
    (0x0005e4000c1019080000000306007985, "ST.E desc[UR8][R6.64], R3"), // libcublasLt.so.329.sm_100.cubin @0f30
    (0x0001e6000c10190c000000ff02007985, "ST.E desc[UR12][R2.64], RZ"), // libcublasLt.so.233.sm_100.cubin @0d00
    (0x0001e8000c101904000000ff0a007985, "ST.E desc[UR4][R10.64], RZ"), // libcusolver.so.213.sm_100.cubin @0230
    (0x0201e40000100d140000000028007385, "ST.E.128 [R40], R20"), // libcusolver.so.1088.sm_100.cubin @0a00
    (0x0003e4000c101d06000010ff06007985, "ST.E.128 desc[UR6][R6.64+0x10], RZ"), // libcublasLt.so.522.sm_100.cubin @0a60
    (0x0001e2000c101d0e0000000c14007985, "ST.E.128 desc[UR14][R20.64], R12"), // libcublas.so.1026.sm_100.cubin @0970
    (0x0003e8000c101d06000000ff06007985, "ST.E.128 desc[UR6][R6.64], RZ"), // libcublasLt.so.522.sm_100.cubin @0a50
    (0x000fe2000c101d06000000ff02007985, "ST.E.128 desc[UR6][R2.64], RZ"), // libcusparse.so.862.sm_100.cubin @0670
    (0x0011e2000c10fd080002001014007985, "ST.E.128.STRONG.GPU desc[UR8][R20.64+0x200], R16"), // libcusparse.so.262.sm_100.cubin @0830
    (0x0011e2000c10fd0a0002000c02007985, "ST.E.128.STRONG.GPU desc[UR10][R2.64+0x200], R12"), // libcusparse.so.782.sm_100.cubin @0a50
    (0x0041e8000c115d080002000812007985, "ST.E.128.STRONG.SYS desc[UR8][R18.64+0x200], R8"), // libcusolver.so.1825.sm_100.cubin @0410
    (0x00c5e2000c115d0a0000001002007985, "ST.E.128.STRONG.SYS desc[UR10][R2.64], R16"), // libcusolver.so.132.sm_100.cubin @0d60
    (0x0041e8000c115d080000000812007985, "ST.E.128.STRONG.SYS desc[UR8][R18.64], R8"), // libcusolver.so.1825.sm_100.cubin @03f0
    (0x0203e20000100b3a0000000044007385, "ST.E.64 [R68], R58"), // libcusolver.so.1089.sm_103.cubin @0f00
    (0x0201e20000100b40000000004e007385, "ST.E.64 [R78], R64"), // libcusolver.so.1088.sm_100.cubin @0fd0
    (0x0005e4000c101b0c000008080c007985, "ST.E.64 desc[UR12][R12.64+0x8], R8"), // libcublas.so.1021.sm_100.zero.cubin @0950
    (0x0001e2000c101b06000018ff06007985, "ST.E.64 desc[UR6][R6.64+0x18], RZ"), // libcublasLt.so.522.sm_100.cubin @0a30
    (0x0005e4000c101b0c000000080c007985, "ST.E.64 desc[UR12][R12.64], R8"), // libcublas.so.1021.sm_100.zero.cubin @0730
    (0x000fe2000c101b06000000ff02007985, "ST.E.64 desc[UR6][R2.64], RZ"), // libcusparse.so.862.sm_100.cubin @0620
    (0x0011e2000c10fb080001000a08007985, "ST.E.64.STRONG.GPU desc[UR8][R8.64+0x100], R10"), // libcusparse.so.262.sm_100.cubin @0760
    (0x0011e2000c10fb080001000a02007985, "ST.E.64.STRONG.GPU desc[UR8][R2.64+0x100], R10"), // libcusparse.so.782.sm_100.cubin @08d0
    (0x000fe2000c10f9040000000502007985, "ST.E.STRONG.GPU desc[UR4][R2.64], R5"), // libcusolver.so.1089.sm_103.cubin @0e10
    (0x010fe2000c1015060000000002007985, "ST.E.U16 desc[UR6][R2.64], R0"), // libcublasLt.so.293.sm_100.cubin @0ea0
    (0x0001e2000c101508000000140c007985, "ST.E.U16 desc[UR8][R12.64], R20"), // libcublasLt.so.239.sm_100.cubin @0a80
    (0x0001e6000c10150c000000ff02007985, "ST.E.U16 desc[UR12][R2.64], RZ"), // libcublasLt.so.239.sm_100.cubin @0d50
    (0x000fe2000c101506000000ff02007985, "ST.E.U16 desc[UR6][R2.64], RZ"), // libcusparse.so.862.sm_100.cubin @0760
    (0x0001e8000c1011100000001302007985, "ST.E.U8 desc[UR16][R2.64], R19"), // libcublasLt.so.233.sm_100.cubin @0df0
];

#[test]
fn bug097_decode_vendor_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("word {w:032x}: {e}"));
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden, "word {w:032x}");
    }
}

#[test]
fn bug097_decode_vendor_exact_sm103a() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap_or_else(|e| panic!("word {w:032x}: {e}"));
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden, "word {w:032x}");
    }
}

#[test]
fn bug097_roundtrip_word_exact_both_tables() {
    for t in [t120(), t103()] {
        let idx = DecodeIndex::build(&t);
        for &(w, golden) in GOLD {
            let d = idx.decode(w, 0, &t).unwrap();
            let text = cubit::printer::to_sass(&d);
            let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
            let w2 = encode_instruction(&insn, &t).unwrap();
            assert_eq!(w2 & M96, w & M96, "roundtrip 96-bit mismatch for {text}");
        }
    }
}

#[test]
fn bug097_encode_vendor_text_both_tables() {
    // The encoder must accept the vendor-canonical spelling directly
    // (STRONG after size: LD.E.128.STRONG.SYS) on both tables.
    for t in [t120(), t103()] {
        for &(w, golden) in GOLD {
            let insn = parse_sass(&format!("{golden} ;"), 0).unwrap();
            let w2 = encode_instruction(&insn, &t)
                .unwrap_or_else(|e| panic!("encode {golden}: {e}"));
            assert_eq!(w2 & M96, w & M96, "encode mismatch for {golden}");
        }
    }
}

#[test]
fn bug097_plain_u32_ur_shape_not_desc() {
    // [RZ.U32+UR4] is a plain uniform-indexed address; the UR is an index,
    // not a descriptor selector. Pin both the decode text and the roundtrip.
    let (w, golden) = GOLD.iter().copied()
        .find(|(_, g)| g.contains("[RZ.U32+UR4]")).expect("anchor present");
    for t in [t120(), t103()] {
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden);
        assert!(text.contains(".U32+UR"), "plain-u32-ur spelling: {text}");
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, w & M96, "plain-u32-ur roundtrip");
    }
}
