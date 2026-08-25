//! BUG-041 (rejestr sm120: 041_atomg_el_desc_u32.md, CONFIRMED krzem+sanitizer
//! i119): na 6d63ef37 `ATOMG.E.ADD.EL.*` z tekstem desc[UR4][Rx.64] bylo CICHO
//! kodowane forma [Rx.U32+UR4] (32-bit) -> krzem liczyl adres zext(Rx_lo) ->
//! CUDA_ERROR_ILLEGAL_ADDRESS on the first DP hit.
//! State at HEAD: the BUG-038/038a chain (e2298cc9, strict ATOM/REDG entries) +
//! BUG-F2-043 fail-closed already closes this class at the source — .EL + desc[.64]
//! gets "no operand-compatible table entry", while the nvcc form (without .EL)
//! encodes desc[.64] byte-exact. This test PINS both sides of the gate so that
//! no future ATOM* table edit re-opens the quiet 64->32 downcast.
//! downcastu 64->32.

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0x1FFFFu128 << 105;
fn enc(table: &IsaTable, s: &str) -> u128 {
    let insn = cubit::parse_cuasm_line(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap()
}
fn enc_err(table: &IsaTable, s: &str) -> String {
    let insn = parse_sass(s, 0).unwrap();
    encode_instruction(&insn, table).unwrap_err().to_string()
}

#[test]
fn bug041_el_with_desc64_is_a_hard_error() {
    let t = t120();
    // Wierna instrukcja z repro (repro/r041_atomg_el.sass).
    let e = enc_err(&t, "@P2 ATOMG.E.ADD.EL.STRONG.GPU PT, R28, desc[UR4][R16.64], R5");
    assert!(e.contains("no operand-compatible table entry"), "{e}");
    // Kuzyn REDG tez.
    let e2 = enc_err(&t, "@P0 REDG.E.ADD.EL.STRONG.GPU desc[UR4][R2.64], R5");
    assert!(e2.contains("no operand-compatible table entry"), "{e2}");
}

#[test]
fn bug041_plain_atomg_desc64_matches_nvcc_word() {
    let t = t120();
    // nvcc 12.8 sm_120 (atomicAdd) ground truth z bugreportu:
    //   @P0 ATOMG.E.ADD.STRONG.GPU PT, R13, desc[UR4][R2.64], R13
    //   lo64 = 0x8000000d020d09a8, hi64(+ctrl) = 0x004ea200081ef104
    let w = enc(&t, "@P0 ATOMG.E.ADD.STRONG.GPU PT, R13, desc[UR4][R2.64], R13 ;");
    let nvcc: u128 = ((0x004e_a200_081e_f104u128) << 64) | 0x8000_000d_020d_09a8u128;
    assert_eq!(w as u64, 0x8000_000d_020d_09a8, "lo64 payload must match nvcc");
    assert_eq!((w ^ nvcc) & !SCHED, 0, "hi64 payload (sched masked) must match nvcc");
}

#[test]
fn bug041_el_with_u32_ur_form_still_encodes() {
    let t = t120();
    // Legalna forma .EL (golden 038a census, i109): adres 32-bit [Rx.U32+URy].
    let _ = enc(&t, "@!P4 ATOMG.E.ADD.EL.STRONG.GPU PT, R115, [R115.U32+UR34], R23 ;");
    let _ = enc(&t, "@P0 REDG.E.ADD.EL.STRONG.GPU [R84.U32+UR20+0x400], R23 ;");
}

#[test]
fn bug041_report_repro_fails_visibly_via_cli() {
    let dir = std::env::temp_dir().join(format!("bug041_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("r041.sass");
    let out = dir.join("r041.cubin");
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, ".entry t\n    .param u64 m\n    LDCU.64 UR4, c[0x0][0x358] ;\n    @P2 ATOMG.E.ADD.EL.STRONG.GPU PT, R28, desc[UR4][R16.64], R5 ;\n    EXIT ;\n.endentry\n").unwrap();
    let res = std::process::Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", "tables/sm120.json", src.to_str().unwrap(),
               "-o", out.to_str().unwrap()])
        .output().unwrap();
    assert!(!res.status.success(), ".EL+desc[.64] must not assemble (was: silent 32-bit downcast)");
    assert!(!out.exists(), "fail-closed: no output cubin");
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("ATOMG"), "{stderr}");
}
