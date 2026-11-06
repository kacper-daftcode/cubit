//! BUG-483 (session K's finding of 2026-11-05, fixed 2026-11-06): the `.nv.shared.<K>` section
//! was sized `.shared smem[N]` + 0x400 for every kernel (b10 F-2, cubit `a0e5438`, 2026-08-24).
//! The +0x400 is ptxas's LAYOUT — user shared data starts at window offset 0x400 behind a 1 KB
//! system head, and `sh_size = user + 0x400` follows (all 668 nvcc sm_120 census kernels have
//! `sh_size >= 0x400`, exactly 0x400 for kernels without statics) — not a driver add-on: the
//! section size is the whole per-CTA static allocation (K, test host GPU 0: 4 CTAs x 8 192 B
//! fit the 32 KB carveout step, 4 x 9 216 need the next one → smaller L1 → the re-assembled
//! MC4/AFRAG MoE prefill kernels 1.4–2.0x slower than the shipped 2026-06 cubins, which declare
//! 8 192; patching the section back to 8 192 returns the shipped time, `K/k1/smem_probe2.py`).
//! The b10 PTX kernels faulted in 2026-08 because the PTX path laid their data out at 0x400+
//! but declared only the user bytes; the fix was applied one layer too low and every
//! hand-written kernel — which addresses the window from 0 — paid 1 KB per CTA.
//!
//! Fix: `.shared smem[N]` IS the section size (SASS path, `disassemble --frozen` output,
//! `asm -T` templates all agree); the PTX path declares its 0x400-based footprint
//! (`PtxKernel::shared_footprint`: the end of the static layout, 0x400 alone for extern-only
//! kernels) so its cubins are unchanged. Pins: SASS footprint verbatim, PTX footprint = head +
//! statics, extern-only head, PT_LOAD RW memsz = footprint + 0x40.

use std::process::Command;

use cubit::ptx_lower::lower_kernel;
use cubit::ptx_parse::parse_ptx;

fn run_asm(sass: &str, tag: &str, table: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("bug483_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join(format!("{tag}.sass"));
    let out = dir.join(format!("{tag}.cubin"));
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", table, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .expect("run cubit asm");
    assert!(res.status.success(), "asm failed: {}", String::from_utf8_lossy(&res.stderr));
    let data = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    data
}

/// (name, sh_size) of every section (ELF64 LE).
fn elf_sections(data: &[u8]) -> Vec<(String, u64)> {
    let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let shoff = rd64(0x28) as usize;
    let entsz = rd32(0x3A) as usize & 0xffff;
    let num = rd32(0x3C) as usize & 0xffff;
    let strndx = rd32(0x3E) as usize & 0xffff;
    let stroff = rd64(shoff + strndx * entsz + 0x18) as usize;
    let names = |o: usize| {
        let mut e = o;
        while data[e] != 0 {
            e += 1;
        }
        String::from_utf8_lossy(&data[o..e]).to_string()
    };
    (0..num)
        .map(|i| {
            let b = shoff + i * entsz;
            (names(stroff + rd32(b) as usize), rd64(b + 0x20))
        })
        .collect()
}

fn pt_load_rw_memsz(data: &[u8]) -> Option<u64> {
    let rd16 = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().unwrap());
    let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let phoff = rd64(0x20) as usize;
    let num = rd16(0x38) as usize;
    (0..num).map(|i| phoff + i * 56).find(|&b| rd32(b) == 1 && (rd32(b + 4) & 0x2) != 0).map(|b| rd64(b + 0x28))
}

fn shared_size(data: &[u8], kernel: &str) -> u64 {
    let want = format!(".nv.shared.{kernel}");
    elf_sections(data).into_iter().find(|(n, _)| *n == want).map(|(_, s)| s).unwrap_or_else(|| panic!("no {want}"))
}

/// The production MoE shape: `.shared .align 16 smem[8192]`, STS/LDS from offset 0 (the shipped
/// 2026-06 cubins declare 8 192). The section is exactly the declared footprint on both the
/// SM120 (Mercury) and the SM103a builder paths; PT_LOAD RW memsz = footprint + reserved.0.
#[test]
fn t483_1_sass_footprint_is_declared_verbatim() {
    let sass = ".entry k\n    .reg R0-R15\n    .shared .align 16 smem[8192]\n\n    MOV R0, 0x0 ;\n    STS [R0], R0 ;\n    EXIT ;\n.endentry\n";
    for (table, tag) in [("tables/sm120.json", "sm120"), ("tables/sm103a.json", "sm103a")] {
        let data = run_asm(sass, &format!("moe_{tag}"), table);
        assert_eq!(shared_size(&data, "k"), 8192, "{tag}: `.shared smem[8192]` must be the section size");
        assert_eq!(pt_load_rw_memsz(&data), Some(8192 + 0x40), "{tag}: PT_LOAD RW memsz = footprint + reserved.0");
    }
}

/// The carveout step that K measured: 4 CTAs x 8 192 B = 32 KB. Four kernels of the shipped set
/// (1 024 / 3 072 / 4 096 / 7 168 B) keep their declared sizes too — none is rounded or padded.
#[test]
fn t483_2_every_shipped_size_round_trips() {
    for n in [1024u64, 3072, 4096, 7168, 32768, 45376] {
        let sass = format!(".entry k\n    .reg R0-R15\n    .shared .align 16 smem[{n}]\n\n    MOV R0, 0x0 ;\n    STS [R0], R0 ;\n    EXIT ;\n.endentry\n");
        let data = run_asm(&sass, &format!("n{n}"), "tables/sm120.json");
        assert_eq!(shared_size(&data, "k"), n);
    }
}

const PTX_PROLOG: &str = ".version 9.3\n.target sm_103a\n.address_size 64\n";

/// The PTX path lays shared symbols out ptxas-style (head 0x400, statics aligned up) and now
/// DECLARES that footprint: `.shared .align 16 .b8 shm[1024]` → `.shared smem[2048]`, the symbol
/// at 0x400; the assembled section is 2 048 bytes — byte-for-byte what the b10 F-2 cubins got
/// from the old `+0x400` in the ELF builder (the STS past `user` that faulted in 2026-08 stays
/// inside the section).
#[test]
fn t483_3_ptx_path_declares_its_0x400_based_footprint() {
    let ptx = format!(
        "{PTX_PROLOG}.visible .entry k(\n    .param .u64 k_param_0\n)\n{{\n    .reg .b32 %r<8>;\n    .reg .b64 %rd<4>;\n    .shared .align 16 .b8 shm[1024];\n    ld.param.b64 %rd1, [k_param_0];\n    mov.u32 %r1, shm;\n    mov.u32 %r2, 7;\n    st.shared.u32 [%r1+1020], %r2;\n    st.global.u32 [%rd1], %r2;\n    ret;\n}}\n"
    );
    let kernels = parse_ptx(&ptx).expect("parse ptx");
    assert_eq!(kernels[0].shared_bytes, 1024, "the user's static bytes");
    assert_eq!(kernels[0].shared_footprint, 0x400 + 1024, "head + statics");
    assert_eq!(kernels[0].shared_syms.get("shm"), Some(&0x400), "ptxas layout: the first static at 0x400");
    let lk = lower_kernel(&kernels[0]).expect("lower");
    let text = lk.to_sass_text();
    assert!(text.contains("    .shared .align 16 smem[2048]\n"), "the lowered text declares the footprint:\n{text}");
    let data = run_asm(&text, "ptx1024", "tables/sm103a.json");
    assert_eq!(shared_size(&data, "k"), 2048, "PTX kernels keep their pre-fix section size");
    assert_eq!(pt_load_rw_memsz(&data), Some(2048 + 0x40));
}

/// Two statics align up inside the footprint; an extern-only kernel declares the head alone
/// (its dynamic region starts at 0x400 in the lowered addresses, so the static section must
/// cover the head — pre-fix such a kernel declared nothing and the driver's dynamic region
/// started 1 KB too early for its code).
#[test]
fn t483_4_ptx_footprint_aligns_statics_and_covers_the_head_for_externs() {
    let two = format!(
        "{PTX_PROLOG}.visible .entry k(\n    .param .u64 k_param_0\n)\n{{\n    .reg .b32 %r<8>;\n    .reg .b64 %rd<4>;\n    .shared .align 4 .b8 a[20];\n    .shared .align 16 .b8 b[64];\n    ld.param.b64 %rd1, [k_param_0];\n    mov.u32 %r1, b;\n    st.global.u32 [%rd1], %r1;\n    ret;\n}}\n"
    );
    let k = &parse_ptx(&two).expect("parse")[0];
    assert_eq!(k.shared_syms.get("a"), Some(&0x400));
    assert_eq!(k.shared_syms.get("b"), Some(&0x420), "20 bytes at 0x400, aligned up to 16");
    assert_eq!(k.shared_footprint, 0x420 + 64);

    let ext = format!(
        "{PTX_PROLOG}.visible .entry k(\n    .param .u64 k_param_0\n)\n{{\n    .reg .b32 %r<8>;\n    .reg .b64 %rd<4>;\n    .extern .shared .align 16 .b8 dyn[];\n    ld.param.b64 %rd1, [k_param_0];\n    mov.u32 %r1, dyn;\n    st.global.u32 [%rd1], %r1;\n    ret;\n}}\n"
    );
    let k = &parse_ptx(&ext).expect("parse")[0];
    assert_eq!(k.shared_bytes, 0);
    assert_eq!(k.shared_syms.get("dyn"), Some(&0x400));
    assert_eq!(k.shared_footprint, 0x400, "extern-only: the head alone");
    let text = lower_kernel(k).expect("lower").to_sass_text();
    assert!(text.contains("    .shared .align 16 smem[1024]\n"), "{text}");

    let none = format!(
        "{PTX_PROLOG}.visible .entry k(\n    .param .u64 k_param_0\n)\n{{\n    .reg .b32 %r<8>;\n    .reg .b64 %rd<4>;\n    ld.param.b64 %rd1, [k_param_0];\n    mov.u32 %r1, 7;\n    st.global.u32 [%rd1], %r1;\n    ret;\n}}\n"
    );
    let k = &parse_ptx(&none).expect("parse")[0];
    assert_eq!(k.shared_footprint, 0);
    assert!(!lower_kernel(k).expect("lower").to_sass_text().contains(".shared"));
}
