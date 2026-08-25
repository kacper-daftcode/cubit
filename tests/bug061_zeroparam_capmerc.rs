//! BUG-061 (F2Q, follow-up from the 055 report): lane-anchored capmerc records
//! 024d (REDG desc) / 024e (ATOM-family desc) are counted by the feature scan
//! for every atomic lane, but EMITTED only on the "laned" path
//! (non-empty param_loads). A zero-param kernel without loads falls onto the
//! zero-param/legacy path and DROPS the records silently (repro: an .nv.capmerc
//! section without the 02 4d 24 32 bytes despite a desc[UR4] atom in .text).
//! Gold nvcc sm_103a (2026-08-21, work/f2-059 zp/zp3): zero-param nvcc
//! kernels ALWAYS load lanes (envreg/addresses), and the 024d/024e records are present —
//! the ultra-minimal shape belongs to hand-written kernels. No
//! golden position rule for zero-param => fix = WARN (visibility), not
//! fabricating records without an oracle.
//! Fixtures 2026-08-22 (BUG-080): atoms switched to the production-era
//! .EL forms (guarded non-EL atoms are silicon-broken on sm_103a and the encoder
//! won't glue them; the 024d/024e records cover .EL too -- era corpus).
use std::process::Command;

fn run_asm(sass: &str, tag: &str) -> (std::process::Output, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("bug061_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join(format!("{tag}.sass"));
    let out = dir.join(format!("{tag}.cubin"));
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args([
            "asm",
            "-t",
            "tables/sm103a.json",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    (res, out)
}

// zero-load desc-atom: 024d record dropped -> WARN must fire
const Z0_REDG: &str = ".entry z0\n    .param u64 p0\n    @P0 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR4][R2.64], R5 ;\n    EXIT ;\n";
const Z0_ATOMG: &str = ".entry z0a\n    .param u64 p0\n    @P0 ATOMG.E.ADD.EL.STRONG.GPU PT, R5, desc[UR4][R2.64], R5 ;\n    EXIT ;\n";
// control: lane loads present -> laned path, record emitted, no WARN
const ZP: &str = ".entry zp\n    LDC R1, c[0x0][0x37c] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDCU.64 UR4, c[0x0][0x358] ;\n    @P0 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR4][R2.64], R5 ;\n    EXIT ;\n";

#[test]
fn t1_zeroparam_redg_warns_and_drops_record() {
    let (res, out) = run_asm(Z0_REDG, "z0");
    assert!(res.status.success(), "rc!=0: {}", String::from_utf8_lossy(&res.stderr));
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(err.contains("BUG-061"), "WARN must fire, got: {err}");
    let bin = std::fs::read(&out).unwrap();
    let rec = [0x02u8, 0x4d, 0x24, 0x32]; // 024d record tag
    assert!(
        !bin.windows(4).any(|w| w == rec),
        "BUG-061 documents the drop: 024d must be absent for the zero-load shape"
    );
}

#[test]
fn t2_zeroparam_atomg_warns() {
    let (res, _out) = run_asm(Z0_ATOMG, "z0a");
    assert!(res.status.success());
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(err.contains("BUG-061"), "ATOMG (024e) must WARN too, got: {err}");
}

#[test]
fn t3_laned_path_control_quiet_and_recorded() {
    let (res, out) = run_asm(ZP, "zp");
    assert!(res.status.success());
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(!err.contains("BUG-061"), "laned path must not WARN, got: {err}");
    let bin = std::fs::read(&out).unwrap();
    let rec = [0x02u8, 0x4d, 0x24, 0x32];
    assert!(
        bin.windows(4).any(|w| w == rec),
        "laned path must emit the 024d record (nvcc gold invariant)"
    );
}
