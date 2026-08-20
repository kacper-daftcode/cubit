//! BUG-040 (rejestr sm120: 040_regcount_usable_n_minus_2.md, CONFIRMED krzem
//! i115): zadeklarowany regcount=N daje uzywalne R0..R(N-3) — ostatnie 2
//! rejestry sa cieniem granuly alokacji; MOV R(N-2)/R(N-1) =
//! CUDA_ERROR_ILLEGAL_INSTRUCTION (rc=64: R62/R63 ILLEGAL; rc=66 OK).
//! Fix: asm WARN-uje (nie odrzuca — narzedzia akceptuja forme) przy uzyciu
//! R(N-2)/R(N-1) wzgledem finalnego regcount kernela, tylko dla targetu
//! sm_120 (fakt mierzony wylacznie tam), honorujac CUBIT_DISABLE_ERRATA.

use std::process::Command;

fn asm(table: &str, sass: &str, tag: &str) -> (String, String, bool) {
    let dir = std::env::temp_dir().join(format!("bug040_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("k.sass");
    let out = dir.join("k.cubin");
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", table, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output().unwrap();
    (String::from_utf8_lossy(&res.stdout).into_owned(),
     String::from_utf8_lossy(&res.stderr).into_owned(),
     res.status.success())
}

const RC64_R62: &str = ".entry t\n    .reg R0-R63\n    .param u64 m\n    MOV R61, 0x1 ;\n    MOV R62, 0x2 ;\n    MOV R63, 0x3 ;\n    EXIT ;\n.endentry\n";
const RC66_R62: &str = ".entry t\n    .reg R0-R65\n    .param u64 m\n    MOV R62, 0x2 ;\n    EXIT ;\n.endentry\n";

#[test]
fn bug040_shadowed_registers_warn_on_sm120() {
    let (out, err, ok) = asm("tables/sm120.json", RC64_R62, "warn");
    assert!(ok, "WARN must not fail the build: {err}");
    assert!(err.contains("BUG-040"), "{err}");
    assert!(err.contains("R62/R63"), "{err}");
    assert!(err.contains("R0..R61"), "{err}");
    assert!(out.contains("regcount=64"), "{out}");
}

#[test]
fn bug040_usable_registers_stay_quiet() {
    let (_out, err, ok) = asm("tables/sm120.json", RC66_R62, "quiet");
    assert!(ok, "{err}");
    assert!(!err.contains("BUG-040"), "rc=66 makes R62 usable: {err}");
}

#[test]
fn bug040_warn_is_sm120_scoped() {
    // Measured on sm_120 only; sm_103a has no silicon evidence -> no WARN.
    let (_out, err, ok) = asm("tables/sm103a.json", RC64_R62, "archgate");
    assert!(ok, "{err}");
    assert!(!err.contains("BUG-040"), "{err}");
}

#[test]
fn bug040_errata_disable_flag_silences() {
    let dir = std::env::temp_dir().join(format!("bug040_dis_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("k.sass");
    std::fs::write(&src, RC64_R62).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", "tables/sm120.json", src.to_str().unwrap(),
               "-o", dir.join("k.cubin").to_str().unwrap()])
        .env("CUBIT_DISABLE_ERRATA", "1")
        .output().unwrap();
    assert!(res.status.success());
    assert!(!String::from_utf8_lossy(&res.stderr).contains("BUG-040"));
}
