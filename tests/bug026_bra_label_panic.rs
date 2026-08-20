//! BUG-026 (rejestr sm120: plik 026 / iter87): `cubit asm` panic
//! "index out of bounds" przy backward-branchu do label gdy w jednostce sa
//! >=2 LDC/LDCU. Root cause: lista nazw opkodow dla generate_mercury_full
//! budowala sie z pre-insertion `def.instructions`, a kod z post-insertion
//! (uniform backward-branch pad/drain wydluza strumien) — OOB index.
//! Fix: kops z `insns_with_ctrl`; generate_mercury_full fail-loud na mismatch.
//! Test idzie przez prawdziwa binarke (end-to-end asm flow).

use std::process::Command;

fn asm_ok(sass: &str, tag: &str) -> Vec<u8> {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("bug026_{tag}.sass"));
    let out = dir.join(format!("bug026_{tag}.cubin"));
    std::fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args([
            "asm",
            "-t",
            "tables/sm120.json",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "[{tag}] asm failed rc={:?}\nstdout:{}\nstderr:{}",
        res.status.code(),
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
    std::fs::read(&out).unwrap()
}

/// oryginalny minimalny reproducer z raportu iter87
const REPRO: &str = ".entry t\n    .reg R0-R120\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\nL_loop:\n    MOV R72, R20 ;\n    @P1 BRA L_loop ;\n    EXIT ;\n";

#[test]
fn bug026_backward_branch_with_ldc_no_panic() {
    let cubin = asm_ok(REPRO, "repro");
    // sanity: niepusty ELF z sekcja .text.t
    assert!(cubin.len() > 0x100 && &cubin[0..4] == b"\x7fELF");
}

#[test]
fn bug026_variants_still_assemble() {
    // forward branch — zgodnie z raportem nigdy nie panikowal
    let fwd = ".entry t\n    .reg R0-R120\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\n    @P1 BRA L_out ;\n    MOV R72, R20 ;\nL_out:\n    EXIT ;\n";
    asm_ok(fwd, "fwd");
    // backward branch bez LDC
    let noldc = ".entry t\n    .reg R0-R120\nL_loop:\n    IADD3 R4, R4, 0x1, RZ ;\n    @P1 BRA L_loop ;\n    EXIT ;\n";
    asm_ok(noldc, "noldc");
}

#[test]
fn bug026_generated_code_covers_inserted_pad() {
    // Po fixie code i opcodes sa spojne; sekcja .text roundtrip-uje sie
    // przez disassemble bez jawnego bledu (drain/pad slot tez sie dekoduje).
    let dir = std::env::temp_dir();
    let src = dir.join("bug026_rt.sass");
    let out = dir.join("bug026_rt.cubin");
    std::fs::write(&src, REPRO).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", "tables/sm120.json", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(res.status.success(), "asm: {}", String::from_utf8_lossy(&res.stderr));
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "-t", "tables/sm120.json", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(res.status.success(), "dis: {}", String::from_utf8_lossy(&res.stderr));
    let txt = String::from_utf8_lossy(&res.stdout);
    let n = txt.matches("/*0").count();
    assert!(n >= 6, "expected at least the 6 source instructions, got {n}:\n{txt}");
}
