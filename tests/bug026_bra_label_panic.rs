//! BUG-026 (sm120 registry: file 026 / iter87): `cubit asm` panic
//! "index out of bounds" on a backward branch to a label when the unit has
//! >=2 LDC/LDCU. Root cause: the opcode-name list for generate_mercury_full
//! was built from the pre-insertion `def.instructions`, but code from post-insertion
//! (the uniform backward-branch pad/drain lengthens the stream) — OOB index.
//! Fix: scoop from `insns_with_ctrl`; generate_mercury_full fails loud on mismatch.
//! The test goes through the real binary (end-to-end asm flow).

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

/// the original minimal reproducer from the iter87 report
const REPRO: &str = ".entry t\n    .reg R0-R120\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\nL_loop:\n    MOV R72, R20 ;\n    @P1 BRA L_loop ;\n    EXIT ;\n";

#[test]
fn bug026_backward_branch_with_ldc_no_panic() {
    let cubin = asm_ok(REPRO, "repro");
    // sanity: non-empty ELF with the .text.t section
    assert!(cubin.len() > 0x100 && &cubin[0..4] == b"\x7fELF");
}

#[test]
fn bug026_variants_still_assemble() {
    // forward branch — per the report it never panicked
    let fwd = ".entry t\n    .reg R0-R120\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\n    @P1 BRA L_out ;\n    MOV R72, R20 ;\nL_out:\n    EXIT ;\n";
    asm_ok(fwd, "fwd");
    // backward branch without LDC
    // BUG-043: asm is now fail-closed — the loop body must be the canonical
    // sm120 shape (IADD3 with PT slots); the bare 4-token form has no row.
    let noldc = ".entry t\n    .reg R0-R120\nL_loop:\n    IADD3 R4, PT, PT, R4, 0x1, RZ ;\n    @P1 BRA L_loop ;\n    EXIT ;\n";
    asm_ok(noldc, "noldc");
}

#[test]
fn bug026_generated_code_covers_inserted_pad() {
    // After the fix, code and opcodes are consistent; the .text section round-trips
    // through disassemble without an explicit error (the drain/pad slot decodes too).
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
