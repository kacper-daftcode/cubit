//! BUG-184 (iter86, loop5 front-main): LEPC II operand silently encoded the
//! baked v=0 word (label left unresolved and dropped; numeric != 0 rejected
//! with "no field"; decode printed the baked "0x0" instead of the resolved
//! code address). Vendor law (nvdisasm-13.3.73 bit-scan arbitration on the
//! MLB gold cubin -- work/i86/lepc/arb184*.py + battery184a 63/63 probes):
//! single signed window x = sext58(w[24:82)), target = addr + 0x10 + x,
//! i.e. the same pc-relative form as the REL16 branch law, byte-granular.
//! Vendor text renders resolved absolute targets as `(.L_x_N)` labels when
//! 16-aligned in-section; cubit prints the absolute numeric target (branch
//! doctrine). Encode: label resolves via the BUG-091 pass; numeric input IS
//! the absolute target. Refuse: unresolved label (091 gate), wrong shape,
//! |target-pc-0x10| overflow of s58 (fail-closed, with attribution).

use std::fs;
use std::process::Command;

fn tbl(sm103: bool) -> String {
    if sm103 { "tables/sm103a.json".to_string() } else { "tables/sm100a.json".to_string() }
}

fn asm(sass: &str, tag: &str, sm103: bool) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("bug184_{tag}.sass"));
    let out = dir.join(format!("bug184_{tag}.cubin"));
    fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", &tbl(sm103), src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output().unwrap();
    if !res.status.success() || !out.exists() {
        return Err(format!("rc={:?}\n{}{}",
            res.status.code(),
            String::from_utf8_lossy(&res.stdout),
            String::from_utf8_lossy(&res.stderr)));
    }
    Ok(fs::read(&out).unwrap())
}

fn asm_fail_text(sass: &str, tag: &str) -> String {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("bug184_{tag}.sass"));
    let out = dir.join(format!("bug184_{tag}.cubin"));
    fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", "tables/sm103a.json", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output().unwrap();
    format!("{}{}", String::from_utf8_lossy(&res.stdout), String::from_utf8_lossy(&res.stderr))
}

fn disasm(cubin: &[u8], tag: &str, sm103: bool) -> String {
    let dir = std::env::temp_dir();
    let p = dir.join(format!("bug184_{tag}.cubin"));
    fs::write(&p, cubin).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "-t", &tbl(sm103), p.to_str().unwrap()])
        .output().unwrap();
    assert!(res.status.success(), "disasm failed: {}{}",
        String::from_utf8_lossy(&res.stdout), String::from_utf8_lossy(&res.stderr));
    String::from_utf8_lossy(&res.stdout).to_string()
}

/// extract .text words of entry k as 128-bit values
fn text_words(cubin: &[u8]) -> Vec<u128> {
    let e = u64::from_le_bytes(cubin[0x28..0x30].try_into().unwrap()) as usize;
    let esz = u16::from_le_bytes(cubin[0x3a..0x3c].try_into().unwrap()) as usize;
    let en = u16::from_le_bytes(cubin[0x3c..0x3e].try_into().unwrap()) as usize;
    let es = u16::from_le_bytes(cubin[0x3e..0x40].try_into().unwrap()) as usize;
    let secs: Vec<_> = (0..en).map(|i| {
        let b = &cubin[e + i*esz..e + (i+1)*esz];
        (u32::from_le_bytes(b[0..4].try_into().unwrap()),
         u64::from_le_bytes(b[8..16].try_into().unwrap()),
         u64::from_le_bytes(b[16..24].try_into().unwrap()),
         u64::from_le_bytes(b[24..32].try_into().unwrap()),
         u64::from_le_bytes(b[32..40].try_into().unwrap()))
    }).collect();
    let stroff = secs[es].3 as usize;
    let names: Vec<String> = secs.iter().map(|s| {
        let off = stroff + s.0 as usize;
        let end = cubin[off..].iter().position(|&c| c == 0).unwrap();
        String::from_utf8_lossy(&cubin[off..off+end]).to_string()
    }).collect();
    let mut words = Vec::new();
    for (i, s) in secs.iter().enumerate() {
        if names[i].starts_with(".text.") {
            for o in 0..s.4 as usize / 16 {
                let b = &cubin[s.3 as usize + o*16..s.3 as usize + o*16 + 16];
                words.push(u128::from_le_bytes(b.try_into().unwrap()));
            }
        }
    }
    words
}

#[test]
fn t184_1_decode_anchor_view() {
    // 70 NOPs -> LEPC at addr 0x460; numeric absolute target 0x480 encodes
    // x = 0x480-0x460-0x10 = 0x10 (bit28), and decode prints it back to the
    // same absolute target (equal to the gold anchor view).
    let mut sass = String::from(".entry k\n    .reg R0-R255\n    .ureg UR0-UR63\n");
    for _ in 0..0x46 { sass.push_str("    NOP ;\n"); }
    sass.push_str("    LEPC R20, 0x480 ;\n    EXIT ;\n");
    let cubin = asm(&sass, "anchor", true).expect("asm");
    let w = text_words(&cubin)[0x46];
    assert_eq!((w >> 24) & 0x3FF_FFFF_FFFF_FFFF, 0x10, "window x");
    assert_eq!(w as u64, 0x1014794e, "low64 = gold anchor law (v=0x10 + reg@16)");
    let txt = disasm(&cubin, "anchor", true);
    let line = txt.lines().find(|l| l.contains("/*0460*/")).unwrap();
    assert!(line.contains("LEPC R20, 0x480"), "got: {line}");
    assert!(!line.contains("!rsd"), "bit-residue spam: {line}");
}

#[test]
fn t184_2_label_rules_window_zero() {
    let sass = ".entry k\n    .reg R0-R255\n    .ureg UR0-UR63\n    NOP ;\n    LEPC R7, `(.L_x_0) ;\n.L_x_0:\n    EXIT ;\n";
    let cubin = asm(sass, "label", true).expect("asm");
    let w = text_words(&cubin)[1];
    assert_eq!((w >> 24) & 0x3FF_FFFF_FFFF_FFFF, 0x0, "x = 0x20-0x10-0x10");
    let txt = disasm(&cubin, "label", true);
    assert!(txt.contains("LEPC R7, 0x20"), "got: {txt}");
}

#[test]
fn t184_3_unresolved_label_refused() {
    let sass = ".entry k\n    .reg R0-R255\n    LEPC R7, `(.L_undefined) ;\n    EXIT ;\n";
    let out = asm_fail_text(sass, "unresolved");
    assert!(out.contains("unresolved branch label"), "got: {out}");
    assert!(out.contains("LEPC"), "attribution lost: {out}");
}

#[test]
fn t184_4_s58_overflow_refused() {
    let sass = ".entry k\n    .reg R0-R255\n    .ureg UR0-UR63\n    NOP ;\n    LEPC R7, 0x200000000000020 ;\n    EXIT ;\n";
    let out = asm_fail_text(sass, "overflow");
    assert!(out.contains("out of the encodable window"), "got: {out}");
    assert!(out.contains("BUG-184"), "attribution lost: {out}");
}

#[test]
fn t184_5_negative_target_roundtrip() {
    let sass = ".entry k\n    .reg R0-R255\n    .ureg UR0-UR63\n    LEPC R20, -0x100 ;\n    EXIT ;\n";
    let cubin = asm(sass, "neg", true).expect("asm");
    let txt = disasm(&cubin, "neg", true);
    assert!(txt.contains("LEPC R20, -0x100"), "got: {txt}");
}

#[test]
fn t184_6_sm100a_same_law() {
    let sass = ".entry k\n    .reg R0-R255\n    .ureg UR0-UR63\n    NOP ;\n    LEPC R7, 0x30 ;\n    EXIT ;\n";
    let cubin = asm(sass, "sm100", false).expect("asm(sm100a)");
    let w = text_words(&cubin)[1];
    assert_eq!((w >> 24) & 0x3FF_FFFF_FFFF_FFFF, 0x10, "x = 0x30-0x10-0x10");
    let txt = disasm(&cubin, "sm100", false);
    assert!(txt.contains("LEPC R7, 0x30"), "got: {txt}");
}

#[test]
fn t184_7_wrong_shape_refused() {
    let sass = ".entry k\n    .reg R0-R255\n    LEPC R20, R21 ;\n    EXIT ;\n";
    let out = asm_fail_text(sass, "shape");
    assert!(out.contains("BUG-184") || out.contains("no operand-compatible")
        || out.contains("LEPC"), "must fail loudly and mention LEPC: {out}");
}

#[test]
fn t184_8_window_extremes_roundtrip() {
    // x = -2^57 -> target = addr+0x10-2^57 = -0x1fffffffffff_ff0 at addr 0
    let sass = ".entry k\n    .reg R0-R255\n    .ureg UR0-UR63\n    LEPC R20, -144115188075855840 ;\n    EXIT ;\n";
    let cubin = asm(sass, "extreme", true).expect("asm");
    let w = text_words(&cubin)[0];
    assert_eq!((w >> 24) & 0x3FF_FFFF_FFFF_FFFF, (1u128 << 57) | 0x10,
        "x = -2^57+0x10 (target - pc - 0x10), s58 floor");
    let txt = disasm(&cubin, "extreme", true);
    assert!(txt.contains("LEPC R20, -0x1ffffffffffffe0"), "expected -0x1ffffffffffffe0 print, got: {txt}");
}
