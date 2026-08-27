//! BUG-203 (F2, 2026-08-27): ATOM/RED coverage-gap closure.
//! patch203.py (data-only, 163 rows x3 tables) + printer.rs FIX B (FTZ/RN
//! in the ATOM data-type bucket — vendor `ATOMG.E.ADD.F32x2.FTZ.RN.STRONG.GPU`,
//! never `.E.FTZ.ADD.F32x2`; re-pins bug196/bug199 literals of the old order).
//! Witnesses: nvcc/ptxas+nvdisasm 13.3.73 probe203{a..d} on sm_100a/103a/120a
//! (arch-eq payload) + BUG-199 flip-arb graft pool (flipclass199 LEGAL+HOLE).
//! Law (arb203.json): WIDTH [74:73)+b76(vec class), SCOPE [77:81) 5/7/A,
//! OP [87:91) AND/DEC/XOR/OR/MIN/ADD/INC/MAX/SAFEADD/EXCH = 0..7,C,D.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| cubit::printer::to_sass(&d))
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

const PROBE_REDG: &[(&str, u64, u64)] = &[
    ("REDG.E.ADD.BF16x2.RN.STRONG.GPU desc[UR4][R2.64], R0", 0x00000000020079a6u64, 0x002fe2000c12e704u64),
    ("REDG.E.ADD.F16x2.RN.STRONG.GPU desc[UR4][R2.64], R0", 0x00000000020079a6u64, 0x002fe2000c12e104u64),
    ("REDG.E.ADD.F16x4.RN.STRONG.GPU desc[UR4][R2.64], R6", 0x00000006020079a6u64, 0x002fe8000c12e304u64),
    ("REDG.E.ADD.F16x4.RN.STRONG.GPU desc[UR4][R2.64], R8", 0x00000008020079a6u64, 0x002fe8000c12e304u64),
    ("REDG.E.ADD.F16x8.RN.STRONG.GPU desc[UR4][R2.64], R4", 0x00000004020079a6u64, 0x002fe2000c12e504u64),
    ("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR4][R2.64], R5", 0x00000005020079a6u64, 0x001fe2000c12f304u64),
    ("REDG.E.ADD.F32x2.FTZ.RN.STRONG.GPU desc[UR4][R2.64], R4", 0x00000004020079a6u64, 0x001fe2000c12f504u64),
    ("REDG.E.ADD.F32x4.FTZ.RN.STRONG.GPU desc[UR4][R2.64], R4", 0x00000004020079a6u64, 0x001fe2000c12f704u64),
    ("REDG.E.ADD.F64.RN.STRONG.GPU desc[UR4][R2.64], R4", 0x00000004020079a6u64, 0x001fe2000c12ff04u64),
    ("REDG.E.AND.64.STRONG.GPU desc[UR4][R2.64], R4", 0x000000040200798eu64, 0x001fe2000e92e504u64),
    ("REDG.E.DEC.STRONG.GPU desc[UR4][R2.64], R5", 0x000000050200798eu64, 0x001fe2000e12e104u64),
    ("REDG.E.INC.STRONG.GPU desc[UR4][R2.64], R5", 0x000000050200798eu64, 0x001fe2000d92e104u64),
    ("REDG.E.MIN.64.STRONG.GPU desc[UR4][R2.64], R4", 0x000000040200798eu64, 0x001fe2000c92e504u64),
    ("REDG.E.OR.64.STRONG.GPU desc[UR4][R2.64], R4", 0x000000040200798eu64, 0x001fe2000f12e504u64),
    ("REDG.E.XOR.64.STRONG.GPU desc[UR4][R2.64], R4", 0x000000040200798eu64, 0x001fe2000f92e504u64),
];

const PROBE_ATOMG: &[(&str, u64, u64)] = &[
    ("@P0 ATOMG.E.ADD.64.STRONG.GPU PT, R2, desc[UR6][R2.64], R6", 0x80000006020209a8u64, 0x004ea200081ef506u64),
    ("@P0 ATOMG.E.ADD.64.STRONG.SM PT, R2, desc[UR6][R2.64], R6", 0x80000006020209a8u64, 0x004ea200081eb506u64),
    ("@P0 ATOMG.E.ADD.64.STRONG.SYS PT, R2, desc[UR6][R2.64], R6", 0x80000006020209a8u64, 0x004ea200081f5506u64),
    ("@P0 ATOMG.E.ADD.STRONG.GPU PT, R3, desc[UR4][R2.64], R9", 0x80000009020309a8u64, 0x004ea200081ef104u64),
    ("@P0 ATOMG.E.ADD.STRONG.SM PT, R3, desc[UR4][R2.64], R9", 0x80000009020309a8u64, 0x004ea200081eb104u64),
    ("ATOMG.E.ADD.F32.FTZ.RN.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a3u64, 0x001eac000c1ef304u64),
    ("ATOMG.E.ADD.F32x2.FTZ.RN.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3u64, 0x001eac000c1ef504u64),
    ("ATOMG.E.ADD.F32x4.FTZ.RN.STRONG.GPU PT, R8, desc[UR4][R2.64], R8", 0x80000008020879a3u64, 0x001eaa000c1ef704u64),
    ("ATOMG.E.ADD.F32x4.FTZ.RN.STRONG.GPU PT, R8, desc[UR4][R2.64], R8", 0x80000008020879a3u64, 0x001eac000c1ef704u64),
    ("ATOMG.E.ADD.F64.RN.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3u64, 0x001eac000c1eff04u64),
    ("ATOMG.E.AND.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000a9ef504u64),
    ("ATOMG.E.AND.64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000a9f5504u64),
    ("ATOMG.E.AND.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000a9ef104u64),
    ("ATOMG.E.AND.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000a9eb104u64),
    ("ATOMG.E.CAS.64.STRONG.SM PT, R2, [R2], R8, R10", 0x00000008020273a9u64, 0x001ea200001ea50au64),
    ("ATOMG.E.CAS.64.STRONG.SM PT, R2, [R2], R8, R10", 0x00000008020273a9u64, 0x002ea200001ea50au64),
    ("ATOMG.E.CAS.64.STRONG.SYS PT, R2, [R2], R8, R10", 0x00000008020273a9u64, 0x001ea200001f450au64),
    ("ATOMG.E.CAS.64.STRONG.SYS PT, R2, [R2], R8, R10", 0x00000008020273a9u64, 0x002ea200001f450au64),
    ("ATOMG.E.CAS.STRONG.SM PT, R5, [R4], R6, R7", 0x00000006040573a9u64, 0x001ea200001ea107u64),
    ("ATOMG.E.CAS.STRONG.SYS PT, R5, [R4], R6, R7", 0x00000006040573a9u64, 0x001ea200001f4107u64),
    ("ATOMG.E.DEC.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000a1ef104u64),
    ("ATOMG.E.EXCH.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000c1ef504u64),
    ("ATOMG.E.EXCH.64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000c1f5504u64),
    ("ATOMG.E.EXCH.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000c1ef104u64),
    ("ATOMG.E.EXCH.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000c1eb104u64),
    ("ATOMG.E.EXCH.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000c1f5104u64),
    ("ATOMG.E.INC.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00099ef104u64),
    ("ATOMG.E.INC.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00099eb104u64),
    ("ATOMG.E.MAX.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac00091ef504u64),
    ("ATOMG.E.MAX.S32.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00091ef304u64),
    ("ATOMG.E.MAX.S32.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00091f5304u64),
    ("ATOMG.E.MAX.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac00091ef704u64),
    ("ATOMG.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac00091eb704u64),
    ("ATOMG.E.MAX.S64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac00091f5704u64),
    ("ATOMG.E.MAX.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00091ef104u64),
    ("ATOMG.E.MAX.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00091eb104u64),
    ("ATOMG.E.MIN.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac00089ef504u64),
    ("ATOMG.E.MIN.S32.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00089ef304u64),
    ("ATOMG.E.MIN.S32.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00089eb304u64),
    ("ATOMG.E.MIN.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac00089ef704u64),
    ("ATOMG.E.MIN.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00089ef104u64),
    ("ATOMG.E.MIN.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac00089f5104u64),
    ("ATOMG.E.OR.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000b1ef504u64),
    ("ATOMG.E.OR.64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000b1eb504u64),
    ("ATOMG.E.OR.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000b1ef104u64),
    ("ATOMG.E.OR.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000b1f5104u64),
    ("ATOMG.E.XOR.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8u64, 0x001eac000b9ef504u64),
    ("ATOMG.E.XOR.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000b9ef104u64),
    ("ATOMG.E.XOR.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000b9eb104u64),
    ("ATOMG.E.XOR.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x001eac000b9f5104u64),
];

const PROBE_ATOMS: &[(&str, u64, u64)] = &[
    ("@P0 REDG.E.ADD.64.STRONG.GPU desc[UR10][R2.64], R4", 0x000000040200098eu64, 0x004fe2000c12e50au64),
    ("@P0 REDG.E.ADD.STRONG.GPU desc[UR6][R2.64], R5", 0x000000050200098eu64, 0x004fe2000c12e106u64),
    ("@P0 REDG.E.ADD.STRONG.SM desc[UR6][R2.64], R5", 0x000000050200098eu64, 0x004fe2000c12a106u64),
    ("@P0 REDG.E.ADD.STRONG.SYS desc[UR6][R2.64], R5", 0x000000050200098eu64, 0x004fe2000c134106u64),
    ("ATOM.E.ADD.BF16x2.RN.STRONG.GPU P0, R5, desc[UR4][R2.64], R5", 0x80000005020579a2u64, 0x001162000c10e704u64),
    ("ATOM.E.ADD.BF16x2.RN.STRONG.GPU P0, RZ, desc[UR4][R2.64], R5", 0x8000000502ff79a2u64, 0x0011e4000c10e704u64),
    ("ATOM.E.ADD.F16x2.RN.STRONG.GPU P0, R5, desc[UR4][R2.64], R5", 0x80000005020579a2u64, 0x001162000c10e104u64),
    ("ATOM.E.ADD.F16x2.RN.STRONG.GPU P0, RZ, desc[UR4][R2.64], R5", 0x8000000502ff79a2u64, 0x0011e4000c10e104u64),
    ("ATOM.E.CAS.STRONG.GPU PT, R7, [R2], R5, R7", 0x000000050207738bu64, 0x000ea400001ee107u64),
    ("ATOMS.CAST.SPIN P0, [R2], R4, R5", 0x000000040200758du64, 0x000e240001800005u64),
    ("ATOMS.CAST.SPIN P0, [R4], R2, R3", 0x000000020400758du64, 0x000e240001800003u64),
];

const FLIP_ATOM: &[(&str, u64, u64)] = &[
    ("ATOM.E.ADD.F16x4.RN.STRONG.GPU P0, RZ, desc[UR6][R2.64], R0", 0x8000000002ff79a2u64, 0x0001e4000c10e306u64),
    ("ATOM.E.ADD.F16x4.RN.STRONG.GPU P4, RZ, desc[UR10][R6.64+-0xc], R15", 0xfffff40f06ff79a2u64, 0x0001e2000c18e30au64),
    ("ATOM.E.ADD.F16x8.RN.STRONG.GPU P0, RZ, desc[UR6][R2.64], R0", 0x8000000002ff79a2u64, 0x0001e4000c10e506u64),
    ("ATOM.E.ADD.F16x8.RN.STRONG.GPU P4, RZ, desc[UR10][R6.64+-0xc], R15", 0xfffff40f06ff79a2u64, 0x0001e2000c18e50au64),
    ("ATOM.E.ADD.F32.RN.STRONG.GPU P0, RZ, desc[UR6][R10.64], R14", 0x8000000e0aff79a2u64, 0x0005e2000c10f906u64),
    ("ATOM.E.ADD.F32x2.FTZ.RN.STRONG.GPU P1, RZ, desc[UR6][R2.64], R9", 0x8000000902ff79a2u64, 0x0001e2000c12f506u64),
    ("ATOM.E.ADD.F32x2.RN.STRONG.GPU P0, RZ, desc[UR6][R10.64], R14", 0x8000000e0aff79a2u64, 0x0005e2000c10fb06u64),
    ("ATOM.E.ADD.F32x4.FTZ.RN.STRONG.GPU P1, RZ, desc[UR6][R2.64], R9", 0x8000000902ff79a2u64, 0x0001e2000c12f706u64),
    ("ATOM.E.ADD.F32x4.RN.STRONG.GPU P0, RZ, desc[UR6][R10.64], R14", 0x8000000e0aff79a2u64, 0x0005e2000c10fd06u64),
    ("ATOM.E.ADD.S32.STRONG.GPU P1, R8, desc[UR8][R10.64+0x8], R8", 0x800008080a08798au64, 0x0000a2000812f308u64),
    ("ATOM.E.ADD.S32.STRONG.GPU PT, RZ, desc[UR4][R16.64+0x4], R15", 0x8000040f10ff798au64, 0x0001e800081ef304u64),
    ("ATOM.E.ADD.S64.STRONG.GPU P1, R8, desc[UR8][R10.64+0x8], R8", 0x800008080a08798au64, 0x0000a2000812f708u64),
    ("ATOM.E.ADD.S64.STRONG.GPU PT, RZ, desc[UR4][R16.64+0x4], R15", 0x8000040f10ff798au64, 0x0001e800081ef704u64),
    ("@P0 ATOM.E.AND.64.STRONG.SM PT, RZ, desc[UR12][R8.64+0x4], R11", 0x8000040b08ff098au64, 0x0011e4000a9eb50cu64),
    ("@P0 ATOM.E.AND.S32.STRONG.SM PT, RZ, desc[UR12][R8.64+0x4], R11", 0x8000040b08ff098au64, 0x0011e4000a9eb30cu64),
    ("@P0 ATOM.E.AND.S64.STRONG.SM PT, RZ, desc[UR12][R8.64+0x4], R11", 0x8000040b08ff098au64, 0x0011e4000a9eb70cu64),
    ("ATOM.E.CAS.64.STRONG.GPU PT, R4, [R2], R9, R5", 0x000000090204738bu64, 0x000ea400001ee505u64),
    ("ATOM.E.CAS.64.STRONG.SYS PT, R4, [R2], R9, R5", 0x000000090204738bu64, 0x000ea400001f4505u64),
    ("ATOM.E.CAS.S32.STRONG.GPU PT, R4, [R2], R9, R5", 0x000000090204738bu64, 0x000ea400001ee305u64),
    ("ATOM.E.CAS.S32.STRONG.SYS PT, R4, [R2], R9, R5", 0x000000090204738bu64, 0x000ea400001f4305u64),
    ("ATOM.E.CAST.SPIN.S32 PT, R5, [R2], R4, R5", 0x000000040205738bu64, 0x000ea400019e0305u64),
    ("ATOM.E.CAST.SPIN.S32 PT, R6, [R10], R4, R6", 0x000000040a06738bu64, 0x001ea400019e0306u64),
    ("ATOM.E.MAX.64.STRONG.GPU P0, RZ, desc[UR4][R10.64+0x8], R8", 0x800008080aff798au64, 0x0001e4000910f504u64),
    ("ATOM.E.MAX.64.STRONG.GPU PT, RZ, desc[UR4][R2.64+0x4], R7", 0x8000040702ff798au64, 0x000fe200091ef504u64),
    ("ATOM.E.MAX.64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x800000060202798au64, 0x001eac00091eb504u64),
    ("ATOM.E.MAX.S32.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x800000060202798au64, 0x001eac00091eb304u64),
    ("ATOM.E.MAX.STRONG.GPU P0, RZ, desc[UR4][R10.64+0x8], R8", 0x800008080aff798au64, 0x0001e4000910f104u64),
    ("ATOM.E.MAX.STRONG.GPU PT, RZ, desc[UR4][R2.64+0x4], R7", 0x8000040702ff798au64, 0x000fe200091ef104u64),
    ("ATOM.E.MAX.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x800000060202798au64, 0x001eac00091eb104u64),
];

const T103: &str = "tables/sm103a.json";
const T120: &str = "tables/sm120.json";
const T100: &str = "tables/sm100a.json";
const TABS: &[&str] = &[T103, T120, T100];

/// t203_1: REDG lane closure (widths/ops/vector ADD) — decode == vendor glyph.
/// Pre-patch: prio3-absorb junk (glyph of another op) or HOLE.
#[test]
fn t203_1_redg_probe_decode() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in PROBE_REDG {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} REDG {g}");
        }
    }
}
/// t203_2: REDG witnesses encode back to the witnessed payload (upper32 sched masked).
#[test]
fn t203_2_redg_probe_encode() {
    for tp in TABS {
        let t = tab(tp);
        for (g, lo, hi) in PROBE_REDG {
            assert_eq!(enc(&t, g), word(*lo, *hi) & !SCHED, "{tp} REDG {g}");
        }
    }
}
/// t203_3: ATOMG lane closure (scope widths/EXCH.64/CAS.64.SM/vec FTZ).
#[test]
fn t203_3_atomg_probe_decode() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in PROBE_ATOMG {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} ATOMG {g}");
        }
    }
}
#[test]
fn t203_4_atomg_probe_encode() {
    for tp in TABS {
        let t = tab(tp);
        for (g, lo, hi) in PROBE_ATOMG {
            if g.starts_with("@P") && tp.ends_with("sm103a.json") {
                // BUG-080 erratum lane: guarded non-EL ATOMG encode is refused
                // (fail-closed by design); decode stays full-fidelity (t203_3).
                let insn = parse_sass(&format!("{g} ;"), 0).expect("parse");
                assert!(encode_instruction(&insn, &t).is_err(), "{tp} guard-080 {g}");
                continue;
            }
            assert_eq!(enc(&t, g), word(*lo, *hi) & !SCHED, "{tp} ATOMG {g}");
        }
    }
}
/// t203_5: ATOMS lane untouched — pre-existing CAST.SPIN/ADD rows keep renders.
#[test]
fn t203_5_atoms_retention() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in PROBE_ATOMS {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} ATOMS {g}");
        }
    }
}
/// t203_6: ATOM-generic lane from the flip-graft pool (flips199 LEGAL+HOLE):
/// ADD.S32/S64/F16x4/x8/F32x2/x4 (+non-FTZ RN forms), MAX bare/64, AND.SM widths,
/// CAS.S32/64 GPU/SYS, CAST.SPIN.S32, and on sm120/sm100a the MAX.SM width run.
#[test]
fn t203_6_atom_flip_pool_decode() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in FLIP_ATOM {
            if g.contains("MAX.STRONG.SM") || g.contains("MAX.S32.STRONG.SM") || g.contains("MAX.64.STRONG.SM") {
                if tp.ends_with("sm103a.json") { continue; } // sm103a stays HOLE (no arch-local witness; BUG-199 stance)
            }
            if (g.contains("CAS.S32.STRONG.SYS") || g.contains("CAS.64.STRONG.SYS")) && tp.ends_with("sm120.json") {
                continue; // sm120 lacks the CAS.SYS donor row (no witness)
            }
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} ATOM {g}");
        }
    }
}
/// t203_7: fail-closed negatives — widths/ops with no witness stay rejected.
#[test]
fn t203_7_fail_closed_negatives() {
    let t = tab(T103);
    // INC/DEC have no widened forms on the REDG lane (no witness, no law exception)
    assert!(encode_instruction(&parse_sass("REDG.E.INC.64.STRONG.GPU desc[UR4][R2.64], R5 ;", 0).unwrap(), &t).is_err());
    assert!(encode_instruction(&parse_sass("REDG.E.DEC.S64.STRONG.GPU desc[UR4][R2.64], R5 ;", 0).unwrap(), &t).is_err());
    // ATOMG non-FTZ F32x2 was only witnessed on the ATOM-generic lane
    assert!(encode_instruction(&parse_sass("ATOMG.E.ADD.F32x2.RN.STRONG.GPU PT, R2, desc[UR4][R2.64], R6 ;", 0).unwrap(), &t).is_err());
    // CAST.SPIN.S64 does not exist (flip w3 of CAST was INVALID in flipdec199)
    assert!(encode_instruction(&parse_sass("ATOM.E.CAST.SPIN.S64 PT, R5, [R2], R4, R5 ;", 0).unwrap(), &t).is_err());
}
/// t203_8: FIX B printer law — FTZ/RN print in the data-type bucket between
/// type and STRONG on the whole ATOM lane (re-pins the bug196/bug199 literals).
#[test]
fn t203_8_ftz_vendor_order() {
    let t = tab(T103); let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&t, &idx, word(0x000080391c0079a6, 0x0c12f30a)).as_deref(),
               Some("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR10][R28.64+0x80], R57"));
    assert_eq!(dec(&t, &idx, word(0x8010007c86ff79a3, 0x000368000c1ef33e)).as_deref(),
               Some("ATOMG.E.ADD.F32.FTZ.RN.STRONG.GPU PT, RZ, desc[UR62][R134.64+0x1000], R124"));
    // reverse: the authored vendor order encodes byte-exact
    let w = enc(&t, "ATOMG.E.ADD.F32.FTZ.RN.STRONG.GPU PT, RZ, desc[UR62][R134.64+0x1000], R124");
    assert_eq!(w, word(0x8010007c86ff79a3, 0x000368000c1ef33e) & !SCHED);
}
