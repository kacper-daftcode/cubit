//! BUG-044 (rejestr sm120: 044_param3_never_delivered.md, CONFIRMED i120):
//! the 3rd .param (u32) never reached a kernel built with an EIATTR
//! reference: rebuild_cubin copied EIATTR + .nv.constant0 from the reference 1:1,
//! so the driver formatted the parameter block at the REFERENCE size (12 B for
//! u64+u32) — c[0x0][0x38c] read cbank garbage instead of nthr.
//! Fix (fail-closed, at the source):
//!  - the EIATTR parser read CBANK_PARAM_SIZE (attr 0x19) only as HVAL —
//!    our own emit is BVAL (1 byte) — the meta parser returned 0; fixed;
//!  - asm with -T/--eiattr-from: pre-flight compares the sass .param footprint vs the
//!    reference; a mismatch = a hard error naming the instruction, no file.
//! Without a reference the emit is already correct (16 B, KPARAM_INFO x3) — the
//! regression pins that too.

use std::process::Command;

const SASS_2P: &str = ".entry t\n    .param u64 mem\n    .param u32 iters\n    LDC R4, c[0x0][0x388] ;\n    EXIT ;\n.endentry\n";
const SASS_3P: &str = ".entry t\n    .param u64 mem\n    .param u32 iters\n    .param u32 nthr\n    LDC R4, c[0x0][0x388] ;\n    LDC R5, c[0x0][0x38c] ;\n    EXIT ;\n.endentry\n";

struct H(std::path::PathBuf);
impl H {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("bug044_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        H(d)
    }
    fn write(&self, name: &str, text: &str) -> String {
        let p = self.0.join(name);
        std::fs::write(&p, text).unwrap();
        p.to_str().unwrap().to_string()
    }
    fn path(&self, name: &str) -> std::path::PathBuf { self.0.join(name) }
    fn paths(&self, name: String) -> String { self.0.join(name).to_str().unwrap().to_string() }
}

fn run_asm(args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(args)
        .output()
        .unwrap()
}

/// Without a reference: a 3-param kernel emits the full 16 B parameter block.
#[test]
fn bug044_direct_emit_has_full_param_block() {
    let h = H::new("direct");
    let src = h.write("k.sass", SASS_3P);
    let out = h.path("k.cubin");
    let res = run_asm(&["asm".into(), "-t".into(), "tables/sm120.json".into(),
                        src, "-o".into(), out.to_str().unwrap().into()]);
    assert!(res.status.success(), "{}", String::from_utf8_lossy(&res.stderr));
    // EIATTR CBANK_PARAM_SIZE = 16 (own parser, via the fixed BVAL path).
    let bytes = std::fs::read(&out).unwrap();
    let meta = cubit::eiattr::parse_cubin_metadata(&bytes).unwrap();
    assert_eq!(meta["t"].cbank_param_size, 16,
               "3 params (u64,u32,u32) = 16-byte cbank block");
}

/// Template 12 B + sass 16 B => hard error, no file (both paths).
#[test]
fn bug044_template_param_mismatch_fails_closed_both_paths() {
    let h = H::new("mismatch");
    let tpl_src = h.write("tpl.sass", SASS_2P);
    let tpl = h.path("tpl.cubin");
    let r1 = run_asm(&["asm".into(), "-t".into(), "tables/sm120.json".into(),
                       tpl_src, "-o".into(), tpl.to_str().unwrap().into()]);
    assert!(r1.status.success());
    // sanity: template naprawde ma 12 B
    let b = std::fs::read(&tpl).unwrap();
    assert_eq!(cubit::eiattr::parse_cubin_metadata(&b).unwrap()["t"].cbank_param_size, 12);

    let src = h.write("k.sass", SASS_3P);
    for via in ["-T", "--eiattr-from"] {
        let out = h.path(&format!("bad_{}.cubin", via.replace('-', "")));
        let res = run_asm(&["asm".into(), "-t".into(), "tables/sm120.json".into(),
                            via.into(), tpl.to_str().unwrap().into(),
                            src.clone(), "-o".into(), out.to_str().unwrap().into()]);
        assert!(!res.status.success(), "{via}: mismatch must fail");
        assert!(!out.exists(), "{via}: fail-closed — no output cubin");
        let stderr = String::from_utf8_lossy(&res.stderr);
        assert!(stderr.contains("12 byte(s)") && stderr.contains("16 byte(s)"),
                "{via}: message must name both footprints: {stderr}");
    }
}

/// Zgodna sygnatura => build przechodzi (kontrola pozytywna).
#[test]
fn bug044_matching_signature_still_builds() {
    let h = H::new("match");
    let tpl_src = h.write("tpl.sass", SASS_3P);
    let tpl = h.path("tpl.cubin");
    let r1 = run_asm(&["asm".into(), "-t".into(), "tables/sm120.json".into(),
                       tpl_src, "-o".into(), tpl.to_str().unwrap().into()]);
    assert!(r1.status.success());
    let src = h.write("k.sass", SASS_3P);
    for via in ["-T", "--eiattr-from"] {
        let out = h.path(&format!("ok_{}.cubin", via.replace('-', "")));
        let res = run_asm(&["asm".into(), "-t".into(), "tables/sm120.json".into(),
                            via.into(), tpl.to_str().unwrap().into(),
                            src.clone(), "-o".into(), out.to_str().unwrap().into()]);
        assert!(res.status.success(),
                "{via}: matching signature must build: {}",
                String::from_utf8_lossy(&res.stderr));
    }
}
