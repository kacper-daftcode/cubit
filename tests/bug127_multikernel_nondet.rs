//! BUG-127 (F2-Q F-1 z merc.md, severity encoder-side): legacy emisja
//! wielo-kernelowa (format adresowy `// name`) byla NIEDETERMINISTYCZNA
//! miedzy runami — kolejnosc kerneli brana z iteracji HashMap (randomizacja
//! per proces), co przewracalo ordynaly .text/.nv.info.*/capmerc/strtab/
//! symtab/.rela. Repro pre-fix (cubit-6b0dc52, k_two.sass, 8 runow):
//! 2 rozne md5 (3x vs 5x). Fix: parse_sass_file_full rejestruje kolejnosc
//! pierwszego pojawienia (source order), cmd_asm_build_elf emituje w tej
//! kolejnosci (mapa moze miec klucze spoza order vec — ida na koniec,
//! sortowane po nazwie; nigdy nondeterministycznie).

use std::process::Command;

const TABLE: &str = "tables/sm103a.json";

/// Blok instrukcji skopiowany z work/f2merc/ven/k_two.sass (czysty encode
/// pod sm103a.json; sched-commenty niezalezne od branego okna).
fn body(k: &str) -> String {
    // lekka mutacja imm per kernel zeby sekcje sie roznicowaly
    let salt: u32 = k.bytes().map(|b| b as u32).sum();
    format!(
        "  /*0000*/  LDC R1, c[0x0][0x37c] /* @sched 0x007f1 */ ;\n  /*0010*/  S2R R5, SR_TID.X /* @sched 0x00717 */ ;\n  /*0020*/  LDC.64 R2, c[0x0][0x380] /* @sched 0x00711 */ ;\n  /*0030*/  IMAD.WIDE.U32 R2, R5, 0x{:x}, R2 /* @sched 0x00fe5 */ ;\n  /*0040*/  EXIT /* @sched 0x007f5 */ ;\n  /*0050*/  BRA 0x50 /* @sched 0x007e0 */ ;\n  /*0060*/  NOP /* @sched 0x007e0 */ ;\n",
        (salt & 7) + 8
    )
}

fn sass(kernels: &[&str]) -> String {
    kernels
        .iter()
        .map(|k| format!("// {k}\n{}", body(k)))
        .collect::<Vec<_>>()
        .join("")
}

fn asm_runs(spec: &[&str], tag: &str, n_runs: usize) -> Vec<Vec<u8>> {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("bug127_{tag}.sass"));
    std::fs::write(&src, sass(spec)).unwrap();
    (0..n_runs)
        .map(|i| {
            let out = dir.join(format!("bug127_{tag}_{i}.cubin"));
            let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
                .args([
                    "asm",
                    "-t",
                    TABLE,
                    src.to_str().unwrap(),
                    "-o",
                    out.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                res.status.success(),
                "[{tag}/{i}] asm failed rc={:?}\nstdout:{}\nstderr:{}",
                res.status.code(),
                String::from_utf8_lossy(&res.stdout),
                String::from_utf8_lossy(&res.stderr)
            );
            std::fs::read(&out).unwrap()
        })
        .collect()
}

fn text_order(cubin: &[u8]) -> Vec<String> {
    let dir = std::env::temp_dir();
    let probe = dir.join(format!("bug127_probe_{:x}.cubin", cubin.len() + cubin[31] as usize));
    std::fs::write(&probe, cubin).unwrap();
    let cf = cubit::elf::CubinFile::load(&probe).unwrap();
    cf.text_sections.iter().map(|(n, _, _)| n.clone()).collect()
}

#[test]
fn t127_1_deterministic_across_processes() {
    // 6 odrebnych procesow (kazdy z wlasnym stanem RandomState) musi dac
    // bajtowo identyczny wynik; pre-fix to samo polecenie dawalo 2 md5 / 8.
    let outs = asm_runs(&["kb", "ka"], "det2", 6);
    for (i, o) in outs.iter().enumerate() {
        assert_eq!(&outs[0], o, "run {i} rozni sie od run 0 (F-1 regression)");
    }
}

#[test]
fn t127_2_section_order_follows_source_two_kernels() {
    let outs = asm_runs(&["kb", "ka"], "ord2", 1);
    // zrodlo: kb PRZED ka (niealfabetycznie) -> emisja musi isc za zrodlem,
    // jak vendor; pre-fix wariant odwrocony byl jednym z dwoch losowych.
    assert_eq!(text_order(&outs[0]), vec![".text.kb", ".text.ka"]);
}

#[test]
fn t127_3_three_kernels_nonalpha_order() {
    let outs = asm_runs(&["kc", "ka", "kb"], "ord3", 6);
    for o in &outs[1..] {
        assert_eq!(&outs[0], o, "3-kernel nondeterminism");
    }
    assert_eq!(
        text_order(&outs[0]),
        vec![".text.kc", ".text.ka", ".text.kb"]
    );
}

#[test]
fn t127_4_reversed_source_gives_reversed_sections() {
    let fwd = asm_runs(&["ka", "kb"], "fwd", 2);
    let rev = asm_runs(&["kb", "ka"], "rev", 2);
    assert_eq!(text_order(&fwd[0]), vec![".text.ka", ".text.kb"]);
    assert_eq!(text_order(&rev[0]), vec![".text.kb", ".text.ka"]);
    // kazdy wariant sam w sobie deterministyczny
    assert_eq!(fwd[0], fwd[1]);
    assert_eq!(rev[0], rev[1]);
}

#[test]
fn t127_5_split_header_blocks_single_entry_in_first_order() {
    // kernel rozbity na dwa bloki // ka ... // ka — jedna sekcja, kolejnosc
    // wg pierwszego pojawienia.
    let text = format!("// ka\n{}// kb\n{}// ka\n{}", body("ka"), body("kb"), body("ka2"));
    let dir = std::env::temp_dir();
    let src = dir.join("bug127_split.sass");
    let out = dir.join("bug127_split.cubin");
    std::fs::write(&src, text).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(res.status.success(), "split asm failed: {}", String::from_utf8_lossy(&res.stderr));
    assert_eq!(
        text_order(&std::fs::read(&out).unwrap()),
        vec![".text.ka", ".text.kb"]
    );
}

#[test]
fn t127_6_only_kernel_filter_stays_deterministic() {
    let dir = std::env::temp_dir();
    let src = dir.join("bug127_only.sass");
    std::fs::write(&src, sass(&["kb", "ka"])).unwrap();
    let mut outs = Vec::new();
    for i in 0..3 {
        let out = dir.join(format!("bug127_only_{i}.cubin"));
        let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
            .args([
                "asm", "-t", TABLE,
                src.to_str().unwrap(),
                "-o", out.to_str().unwrap(),
                "-k", "ka",
            ])
            .output()
            .unwrap();
        assert!(res.status.success());
        outs.push(std::fs::read(&out).unwrap());
    }
    assert_eq!(outs[0], outs[1]);
    assert_eq!(outs[0], outs[2]);
    assert_eq!(text_order(&outs[0]), vec![".text.ka"]);
}
