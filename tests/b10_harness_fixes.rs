//! b10 (HARNESS-P pilot catches, 2026-08-24 loop5/blind):
//!   F-1  %globaltimer silent-drop: `mov.u64 %rd, %globaltimer;` became
//!        `MOV Rd{lo,hi}, <never-written pair>` (parser did not classify
//!        %globaltimer as a special register) -- deterministic-zero time
//!        on silicon. Lane: CS2R Rd_lo, SR_GLOBALTIMERLO (vendor form,
//!        ptxas 13.3 sm_103a gtprobe). %globaltimer_lo/_hi stay fail-closed
//!        (no vendor anchor).
//!   F-2  static-smem ELF reserved-cap law: ptxas on sm_103a emits
//!        `.nv.shared.<K>` = user+0x400, PT_LOAD RW memsz = total+0x40,
//!        symbols .nv.reservedSmem.offset0=0x40 / .cap=0x400. Our cubins
//!        claimed only user bytes -> first STS past driver accounting
//!        raised ILLEGAL_ADDRESS (700). Vendor n=3 (16/1024/4096 B).
//!   F-3  shfl dst token `reg|pred` was collapsed into ONE pseudo-register
//!        operand ("r7|p2"); SHFL wrote a fresh allocation while readers
//!        of the plain name saw a different never-written register --
//!        nondeterministic across reps on silicon (H10e-k5). Split into
//!        two operands for shfl.* only (corpus: `|` operands occur only in
//!        shfl, 192 sites in 9 census files); pred-out lands on PT
//!        (never read before overwrite anywhere in the census).
use std::process::Command;

use cubit::ptx_lower::lower_kernel;
use cubit::ptx_parse::parse_ptx;

const PROLOG: &str = r#"
// b10 test prolog
.version 9.3
.target sm_103a
.address_size 64
"#;

fn lower_text(body: &str) -> String {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u64 k_param_1
)
{{
    .reg .pred %p<6>;
    .reg .b32 %r<24>;
    .reg .b64 %rd<8>;
    .reg .f32 %f<8>;
    ld.param.b64 %rd1, [k_param_0];
    ld.param.b64 %rd2, [k_param_1];
{}
    st.global.b64 [%rd2], %rd3;
    ret;
}}"#, PROLOG, body);
    let kernels = parse_ptx(&ptx).expect("parse ptx");
    let ks = lower_kernel(&kernels[0]).expect("lower");
    ks.instructions.iter().map(|i| format!("{:?}", i)).collect::<Vec<_>>().join("\n")
}

// ── F-1 ───────────────────────────────────────────────────────────────────
#[test]
fn b10_f1_globaltimer_lane() {
    // Debug render of the instruction shows operands textually.
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64 %rd<4>;
    ld.param.b64 %rd1, [k_param_0];
    mov.u64 %rd2, %globaltimer;
    st.global.b64 [%rd1], %rd2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let ks = lower_kernel(&kernels[0]).unwrap();
    let rendered: Vec<String> = ks.instructions.iter()
        .map(|i| format!("{} {}", i.opcode, i.operands.iter()
            .map(|o| format!("{:?}", o)).collect::<Vec<_>>().join(",")))
        .collect();
    assert!(rendered.iter().any(|l| l.starts_with("CS2R") && l.contains("SR_GLOBALTIMERLO")),
        "expected CS2R SR_GLOBALTIMERLO lane, got:\n{}", rendered.join("\n"));
    assert!(!rendered.iter().any(|l| l.starts_with("MOV ") && l.contains("SR_")),
        "no S2R/MOV fallback: {}", rendered.join("\n"));
}

#[test]
fn b10_f1_globaltimer_lohi_fail_closed() {
    for snippet in ["mov.u32 %r1, %globaltimer_lo;"] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<4>;
    .reg .b64 %rd<2>;
    ld.param.b64 %rd1, [k_param_0];
{}
    st.global.b32 [%rd1], %r1;
    ret;
}}"#, PROLOG, snippet);
        let kernels = parse_ptx(&ptx).unwrap();
        assert!(lower_kernel(&kernels[0]).is_err(),
            "unanchored special register must fail closed: {}", snippet);
    }
}

// ── F-3 ───────────────────────────────────────────────────────────────────
#[test]
fn b10_f3_shfl_reg_pipe_pred_split() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<4>;
    .reg .b32 %r<8>;
    .reg .b64 %rd<2>;
    ld.param.b64 %rd1, [k_param_0];
    ld.global.b32 %r1, [%rd1];
    shfl.sync.down.b32 %r2|%p1, %r1, 16, 31, -1;
    add.s32 %r3, %r1, %r2;
    st.global.b32 [%rd1], %r3;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let ki = &kernels[0];
    // parser-level: shfl must carry FIVE operands, dst[0] = plain reg name
    use cubit::ptx_parse::{PtxOperand, PtxStmt};
    let shfl = ki.body.iter().find_map(|s| match s {
        PtxStmt::Insn(i) if i.opcode.starts_with("shfl.") => Some(i),
        _ => None,
    }).unwrap();
    assert_eq!(shfl.operands.len(), 6, "operands after split (d,p,a,b,c,mask): {:?}", shfl.operands);
    assert!(matches!(&shfl.operands[0], PtxOperand::Reg(n) if n == "%r2"),
        "dst operand is the plain data register: {:?}", shfl.operands[0]);
    assert!(matches!(&shfl.operands[1], PtxOperand::Pred(_)));

    // lower-level: SHFL dst register == the register `add` reads for %r2
    let ks = lower_kernel(ki).unwrap();
    let lines: Vec<String> = ks.instructions.iter()
        .map(|i| format!("{} {}", i.opcode, i.operands.iter()
            .map(|o| format!("{:?}", o)).collect::<Vec<_>>().join(",")))
        .collect();
    let shfl_l = lines.iter().find(|l| l.starts_with("SHFL"))
        .unwrap_or_else(|| panic!("no SHFL.DOWN in:\n{}", lines.join("\n"))).clone();
    let add_l = lines.iter().find(|l| l.starts_with("IADD3"))
        .unwrap_or_else(|| panic!("no IADD3 in:\n{}", lines.join("\n"))).clone();
    // extract the SHFL dst reg num from `pt,Reg { num: X, ..` debug form
    let dst_num = shfl_l.split("Reg { num: ").nth(1).unwrap()
        .split(|c: char| !c.is_ascii_digit()).next().unwrap().to_string();
    assert!(add_l.contains(&format!("Reg {{ num: {}, ", dst_num)),
        "add must read the SHFL dst register: {}\n{}", shfl_l, add_l);
}

// ── F-2 ───────────────────────────────────────────────────────────────────
fn run_asm(sass: &str, tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("b10f2_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join(format!("{tag}.sass"));
    let out = dir.join(format!("{tag}.cubin"));
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", "tables/sm103a.json", src.to_str().unwrap(),
               "-o", out.to_str().unwrap()])
        .output().expect("run cubit asm");
    assert!(res.status.success(), "asm failed: {}", String::from_utf8_lossy(&res.stderr));
    out
}

fn elf_sections(data: &[u8]) -> Vec<(String, u64)> {
    // minimal ELF64 section sweep (LE): shoff@0x28, shentsize@0x3A, shnum@0x3C, shstrndx@0x3E
    let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let shoff = rd64(0x28) as usize;
    let entsz = rd32(0x3A) as usize & 0xffff;
    let num = rd32(0x3C) as usize & 0xffff;
    let strndx = rd32(0x3E) as usize & 0xffff;
    let stroff = rd64(shoff + strndx * entsz + 0x18) as usize;
    let names = |o: usize| {
        let mut e = o;
        while data[e] != 0 { e += 1; }
        String::from_utf8_lossy(&data[o..e]).to_string()
    };
    (0..num).map(|i| {
        let b = shoff + i * entsz;
        let noff = rd32(b) as usize;
        (names(stroff + noff), rd64(b + 0x20))
    }).collect()
}

fn sym_value(data: &[u8], want: &str) -> Option<u64> {
    let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let shoff = rd64(0x28) as usize;
    let entsz = rd32(0x3A) as usize & 0xffff;
    let num = rd32(0x3C) as usize & 0xffff;
    for i in 0..num {
        let b = shoff + i * entsz;
        if rd32(b + 4) == 2 { // SHT_SYMTAB
            let soff = rd64(b + 0x18) as usize;
            let ssz = rd64(b + 0x20) as usize;
            let sent = rd64(b + 0x38) as usize;
            let link = rd32(b + 0x28) as usize; // linked strtab
            let lb = shoff + link * entsz;
            let stroff = rd64(lb + 0x18) as usize;
            for j in 0..ssz / sent {
                let s = soff + j * sent;
                let noff = rd32(s) as usize;
                let mut e = stroff + noff;
                while data[e] != 0 { e += 1; }
                let name = String::from_utf8_lossy(&data[stroff + noff..e]).to_string();
                if name == want {
                    return Some(rd64(s + 0x08));
                }
            }
        }
    }
    None
}

fn pt_load_rw_memsz(data: &[u8]) -> Option<u64> {
    let rd16 = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().unwrap());
    let rd32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let phoff = rd64(0x20) as usize;
    let num = rd16(0x38) as usize;
    for i in 0..num {
        let b = phoff + i * 56;
        if rd32(b) == 1 && (rd32(b + 4) & 0x2) != 0 { // PT_LOAD + W
            return Some(rd64(b + 0x28));
        }
    }
    None
}

#[test]
fn b10_f2_smem_reserved_cap_law() {
    let sass = ".entry k\n    .reg R0-R15\n    .shared .align 16 smem[1024]\n\n    MOV R0, 0x0 ;\n    STS [R0], R0 ;\n    EXIT ;\n.endentry\n";
    let cubin = run_asm(sass, "k1024");
    let data = std::fs::read(&cubin).unwrap();
    let secs = elf_sections(&data);
    let shared = secs.iter().find(|(n, _)| n == ".nv.shared.k").unwrap();
    assert_eq!(shared.1, 1024 + 0x400, "user+cap: {:?}", secs);
    let reserved = secs.iter().find(|(n, _)| n == ".nv.shared.reserved.0").unwrap();
    assert_eq!(reserved.1, 0x40);
    assert_eq!(sym_value(&data, ".nv.reservedSmem.offset0"), Some(0x40));
    assert_eq!(sym_value(&data, ".nv.reservedSmem.cap"), Some(0x400));
    assert_eq!(pt_load_rw_memsz(&data), Some(1024 + 0x400 + 0x40));
}

#[test]
fn b10_f2_nonsmem_layout_unchanged() {
    let sass = ".entry k\n    .reg R0-R15\n\n    MOV R0, 0x0 ;\n    EXIT ;\n.endentry\n";
    let cubin = run_asm(sass, "k0");
    let data = std::fs::read(&cubin).unwrap();
    // no .nv.reservedSmem.cap symbol, memsz law stays at the 0x40 reserved only
    assert_eq!(sym_value(&data, ".nv.reservedSmem.cap"), None);
    assert_eq!(sym_value(&data, ".nv.reservedSmem.offset0"), Some(0x40));
    assert_eq!(pt_load_rw_memsz(&data), Some(0x40));
}
