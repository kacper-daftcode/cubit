//! Parser for a complete .sass source file with directives and instructions.
//!
//! Format:
//! ```text
//! .entry my_kernel
//!     .reg R0-R47
//!     .param u64 input_ptr
//!     .param u64 output_ptr
//!     .shared .align 16 smem[4096]
//!
//!     S2R R0, SR_TID.X ;                 [B------:R-:W0:-:S15]
//!     S2R R1, SR_CTAID.X ;
//!     loop:
//!       IMAD R2, R0, 0x4, R1 ;
//!       BRA loop ;
//! .endentry
//! ```

use crate::directives::{KernelResources, parse_directive};
use crate::ir::Instruction;
use crate::parser::{parse_multi_sass, resolve_labels};

/// A parsed kernel definition from a .sass source file.
#[derive(Debug, Clone)]
pub struct KernelDef {
    /// Kernel name (from `.entry name`).
    pub name: String,
    /// Resource declarations (.reg, .param, .shared, etc.).
    pub resources: KernelResources,
    /// Assembled instructions in order.
    pub instructions: Vec<Instruction>,
    /// Base address of first instruction (always 0 in a standalone file).
    pub base_addr: u32,
}

/// A complete parsed .sass file.
#[derive(Debug, Clone)]
pub struct SassFile {
    pub kernels: Vec<KernelDef>,
}

/// Parse a .sass source file string into a SassFile.
pub fn parse_sass_file_str(text: &str) -> anyhow::Result<SassFile> {
    let mut kernels = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_res = KernelResources::default();
    let mut body_lines: Vec<String> = Vec::new();

    for line in text.lines() {
        let t = line.trim();

        // Skip blank lines and comments at top level
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            if current_name.is_some() {
                body_lines.push(line.to_string());
            }
            continue;
        }

        // .entry <name> or .func <name>
        if let Some(rest) = t.strip_prefix(".entry").or_else(|| t.strip_prefix(".func")) {
            // A new .entry while another kernel is still open implicitly closes it
            // (emitters without .endentry previously lost all but the last kernel).
            if let Some(prev) = current_name.take() {
                let body = body_lines.join("\n");
                let insns = parse_kernel_body(&body, &mut current_res);
                kernels.push(KernelDef {
                    name: prev,
                    resources: current_res.clone(),
                    instructions: insns,
                    base_addr: 0,
                });
            }
            let name = rest.trim().to_string();
            current_name = Some(name);
            current_res = KernelResources::default();
            body_lines.clear();
            continue;
        }

        // .endentry / .endfunc — finish current kernel
        if t.starts_with(".endentry") || t.starts_with(".endfunc") {
            if let Some(name) = current_name.take() {
                let body = body_lines.join("\n");
                let insns = parse_kernel_body(&body, &mut current_res);
                kernels.push(KernelDef {
                    name,
                    resources: current_res.clone(),
                    instructions: insns,
                    base_addr: 0,
                });
            }
            body_lines.clear();
            continue;
        }

        // Within a kernel block
        if current_name.is_some() {
            body_lines.push(line.to_string());
        }
    }

    // If file ended without .endentry, finalize any open kernel
    if let Some(name) = current_name {
        let body = body_lines.join("\n");
        let insns = parse_kernel_body(&body, &mut current_res);
        kernels.push(KernelDef {
            name,
            resources: current_res,
            instructions: insns,
            base_addr: 0,
        });
    }

    Ok(SassFile { kernels })
}

/// Parse the body of a kernel: resource directives + instruction lines + labels.
fn parse_kernel_body(body: &str, res: &mut KernelResources) -> Vec<Instruction> {
    // Separate directive lines from instruction lines
    let mut instr_text = String::new();

    for line in body.lines() {
        // Strip inline // or # comments first, so a comment (and any ';' or text in
        // it) can't corrupt directive parsing (e.g. `.shared smem[N] // note`) or
        // instruction splitting downstream.
        let nocomment = if let Some(p) = line.find("//") { &line[..p] }
                        else if let Some(p) = line.find('#') { &line[..p] }
                        else { line };
        let t = nocomment.trim();
        if t.is_empty() { continue; }

        // Try directive first
        if t.starts_with('.') {
            parse_directive(t, res);
            continue;
        }

        // Everything else goes to instruction parser
        instr_text.push_str(t);
        instr_text.push('\n');
    }

    // Use the multi-instruction parser + label resolver
    let stmts = parse_multi_sass(&instr_text, 0);
    resolve_labels(stmts, 0)
}

/// Auto-detect max register from instruction list and update resources.
pub fn auto_detect_resources(def: &mut KernelDef) {
    if def.resources.max_reg.is_some() { return; }
    let mut max_reg = 0u32;
    for insn in &def.instructions {
        for op in &insn.operands {
            if let crate::ir::Operand::Reg { num, .. } = op {
                if *num != 255 { max_reg = max_reg.max(*num as u32); }
            }
        }
    }
    if max_reg > 0 {
        def.resources.max_reg = Some(max_reg);
    }
}

/// Build a KernelMeta from a KernelDef's resources and encoded instruction bytes.
/// The `code_bytes` are used to find EXIT instruction offsets.
pub fn kernel_def_to_meta(
    def: &KernelDef,
    code_bytes: &[u8],
) -> crate::eiattr::KernelMeta {
    use crate::eiattr::{KernelMeta, KernelParam as EiKernelParam};

    // Find EXIT instruction offsets by opcode pattern.
    // EXIT and_base = 0x...094d; with guard=PT bits[15:12]=7 → lo16=0x794d
    // EXIT_P and_base = 0x...894d → lo16=0x?94d with various guards
    // Match any instruction where lo12 (bits[11:0]) matches 0x94d (EXIT family)
    let mut exit_offsets = Vec::new();
    for (i, chunk) in code_bytes.chunks(16).enumerate() {
        if chunk.len() < 16 { break; }
        let lo16 = u16::from_le_bytes([chunk[0], chunk[1]]);
        let lo12 = lo16 & 0x0FFF;
        if lo12 == 0x094d || lo12 == 0x094e || lo12 == 0x094f {
            exit_offsets.push((i * 16) as u32);
        }
    }

    // Build parameter list from directives
    let mut offset = 0u32;
    let params: Vec<EiKernelParam> = def.resources.params.iter().enumerate()
        .map(|(i, p)| {
            let size = p.ty.size();
            let aligned_offset = (offset + size - 1) & !(size - 1);
            offset = aligned_offset + size;
            EiKernelParam {
                index: i as u32,
                ordinal: i as u32,
                offset: aligned_offset,
                size,
            }
        }).collect();

    let cbank_param_size = offset as u16;
    // QMMA uses internal registers beyond the explicit operands.
    // Tungsten uses regcount=48 for QMMA kernels.
    let has_qmma = def.instructions.iter().any(|insn| insn.opcode == "QMMA");
    let min_regs = if has_qmma { 48 } else { 4 };
    let regcount = def.resources.reg_count().max(min_regs);

    let (merc_param_order, merc_param_write, merc_stg_desc_pos, merc_bar_pred,
         merc_param_uniform, merc_param_regpath, merc_param_width) =
        merc_param_scan(&def.instructions);
    let (merc_bar_pos, merc_stg_pos, merc_stg_off) = merc_exec_positions(&def.instructions);
    let merc_xor = merc_xor_scan(&def.instructions);

    KernelMeta {
        name: def.name.clone(),
        regcount,
        frame_size: 0,
        min_stack_size: 0,
        maxreg_count: 0xFF,
        num_barriers: def.resources.num_barriers as u8,
        exit_offsets,
        cbank_param_size,
        params,
        cuda_api_version: 0x83,  // SM120 CUDA 12.8 API version
        shared_size: def.resources.shared_size(),
        merc_param_order,
        merc_param_write,
        merc_stg_desc_pos,
        merc_bar_pred,
        merc_dynldg: merc_select_dynldg(&def.instructions),
        merc_bar_pos,
        merc_stg_pos,
        merc_param_uniform,
        merc_param_regpath,
        merc_param_width,
        merc_xor,
        merc_stg_off,
    }
}

/// Mercury desc-order support: skanuje SASS po `LDC(.64)?.U?Rx, c[0x0][0x380+8k]`
/// (param slot k) i pierwszych uzyciach adresowych; zwraca
/// (kolejnosc pierwszego uzycia parametrow, bitmaska write-first).
/// Model zmierzony na mikrolabie r_*/s_* (mk8).
/// true gdy kernel ma LDG z rejestrowym offsetem [Rx.64+0x...] (era-103a
/// wyzwalacz rekordu cflow 0x41; dane: k_ld/k_ldcg/k_ldg2/c_ld_dyn vs c_ld_fix).
fn merc_select_dynldg(instructions: &[Instruction]) -> bool {
    instructions.iter().any(|ins| {
        let t = &ins.raw_text;
        ins.opcode == "LDG"
            && (t.contains(".64+0x") || t.contains(".64]") && t.contains('['))
    })
}

fn merc_exec_positions(instructions: &[Instruction]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let mut bar_pos = Vec::new();
    let mut stg_pos = Vec::new();
    let mut stg_off = Vec::new();
    for ins in instructions {
        let slot = (ins.addr / 16) as u32;
        match ins.opcode.as_str() {
            "BAR" | "SYNCS" => bar_pos.push(slot),
            "STG" => {
                stg_pos.push(slot);
                // [Rx.64+0x..] — imm w slicie adresowym
                let off = match ins.raw_text.find(".64+0x") {
                    Some(k) => {
                        let h = &ins.raw_text[k + 6..];
                        let e = h.find(']').unwrap_or(h.len());
                        u32::from_str_radix(&h[..e], 16).unwrap_or(0)
                    }
                    None => 0,
                };
                stg_off.push(off);
            }
            _ => {}
        }
    }
    (bar_pos, stg_pos, stg_off)
}

/// Mercury 0229: skan `LOP3.LUT Rd, Rs, imm32, RZ, 0x3c` (= SASS-forma C-level
/// `xor dst, src, imm`). Zwraca (lane, dst, src, imm, guard). fs6-lab:
/// tylko lut=0x3c z imm w slocie srcB i RZ w slocie srcC dostaje rekord 0229;
/// or/and (lut 0xfc/0xc0) zostaja zwyklymi bitami; nor/neg-formy rowniez nie.
/// lane takiej instrukcji NIE dostaje bitu bitmapy (rekord pelny zastepuje
/// wezel typu4-flag1).
fn merc_xor_scan(instructions: &[Instruction]) -> Vec<(u32, u32, u32, u32, u8)> {
    let mut out = Vec::new();
    for ins in instructions {
        if ins.opcode != "LOP3" {
            continue;
        }
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        let mut guard = 0u8;
        if first.starts_with('@') {
            guard = if first.starts_with("@!") { 2 } else { 1 };
            first = toks.next().unwrap_or("");
        }
        if !first.starts_with("LOP3") {
            continue;
        }
        let rest = toks.collect::<Vec<_>>().join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        if parts.len() < 5 {
            continue;
        }
        if parts[4] != "0x3c" || !parts[3].starts_with("RZ") {
            continue;
        }
        let Some(imm) = parts[2]
            .strip_prefix("0x")
            .and_then(|h| u32::from_str_radix(h, 16).ok())
        else {
            continue;
        };
        let reg = |t: &str| -> Option<u32> {
            t.strip_prefix('R')
                .and_then(|d| if d.chars().all(|c| c.is_ascii_digit()) { d.parse::<u32>().ok() } else { None })
        };
        let (Some(dst), Some(src)) = (reg(parts[0]), reg(parts[1])) else {
            continue;
        };
        out.push(((ins.addr / 16) as u32, dst, src, imm, guard));
    }
    out
}

fn merc_param_scan(
    instructions: &[Instruction],
) -> (Option<Vec<u32>>, u32, Vec<u32>, bool, u32, u32, Vec<u8>) {
    let mut reg_of: Vec<(String, u32)> = Vec::new(); // lead-reg name -> param idx
    let mut order: Vec<u32> = Vec::new();
    let mut write_mask: u32 = 0;
    let mut stg_desc_pos: Vec<u32> = Vec::new();
    let mut bar_predicated = false;
    let mut uniform_mask: u32 = 0; // bit pi: slot zaladowany przez LDCU*
    let mut regpath_mask: u32 = 0; // bit pi: slot zaladowany przez LDC*
    let mut widths: Vec<u8> = Vec::new(); // per-param: max transfer bytes

    #[allow(clippy::too_many_arguments)]
    fn note(m: &mut u32, pi: u32) {
        if pi < 32 {
            *m |= 1u32 << pi;
        }
    }
    for ins in instructions {
        let t = ins.raw_text.as_str();
        // LDC / LDCU load z okna parametrow [0x380..]
        let is_ldcu = ins.opcode == "LDCU";
        if ins.opcode == "LDC" || is_ldcu {
            if let Some(cp) = t.find("c[0x0][0x") {
                let hexs = &t[cp + 9..];
                let end = hexs.find(']').unwrap_or(0);
                if let Ok(off) = u32::from_str_radix(&hexs[..end], 16) {
                    if off >= 0x380 && (off - 0x380) % 8 == 0 {
                        let pi = (off - 0x380) / 8;
                        // lead operand = dest reg
                        let depth = t.find(',').unwrap_or(t.len());
                        let dest = t[..depth]
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .trim_end_matches(".64")
                            .to_string();
                        if !dest.is_empty() {
                            reg_of.push((dest.clone(), pi.min(31)));
                            // wide loads: high-half rejestrow pary (UR7 dla LDCU.64 UR6 itd.)
                            let full = ins.opcode_full.as_str();
                            if full.contains(".64") || full.contains(".128") {
                                let num: Option<(bool, u32)> =
                                    if let Some(n) = dest.strip_prefix("UR") {
                                        n.parse::<u32>().ok().map(|v| (true, v))
                                    } else if let Some(n) = dest.strip_prefix('R') {
                                        n.parse::<u32>().ok().map(|v| (false, v))
                                    } else {
                                        None
                                    };
                                if let Some((is_u, n)) = num {
                                    let pfx = if is_u { "UR" } else { "R" };
                                    reg_of.push((format!("{}{}", pfx, n + 1), pi.min(31)));
                                }
                            }
                        }
                        if is_ldcu {
                            note(&mut uniform_mask, pi);
                        } else {
                            note(&mut regpath_mask, pi);
                        }
                        // transfer width: .U8=1 .U16=2 plain=4 .64=8 .128=16
                        let full = ins.opcode_full.as_str();
                        let w: u8 = if full.contains(".128") {
                            16
                        } else if full.contains(".64") {
                            8
                        } else if full.contains(".U16") {
                            2
                        } else if full.contains(".U8") {
                            1
                        } else {
                            4
                        };
                        if (pi as usize) >= widths.len() {
                            widths.resize(pi as usize + 1, 0);
                        }
                        if widths[pi as usize] < w {
                            widths[pi as usize] = w;
                        }
                    }
                }
            }
        }
        // alias-flow UR/R: dest <- zrodla sledzone (shape IADD3 R2, P0, PT, R0, UR6, RZ)
        let b0 = ins.opcode_full.split('.').next().unwrap_or("");
        if matches!(
            b0,
            "MOV" | "IMAD" | "IADD3" | "LEA" | "SHF" | "SEL" | "UIADD3" | "UMOV" | "IMNMX"
                | "PRMT" | "IABS" | "SHFL"
        ) {
            if let Some(ci) = t.find(',') {
                let dest = t[..ci]
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_alphanumeric());
                if !dest.is_empty()
                    && (dest.starts_with('R') || dest.starts_with('U'))
                    && dest.chars().skip(1).all(|c| c == 'Z' || c.is_ascii_digit())
                {
                    let srcs = &t[ci + 1..];
                    for (rn, pi) in &reg_of {
                        // pasuj gole wystapienie tokenu rejestru w operandach zrodlowych
                        let mut hit = false;
                        for m in srcs.match_indices(rn.as_str()) {
                            let at = m.0;
                            let after = srcs[at + rn.len()..].chars().next();
                            let ok_end = after.map(|c| !c.is_ascii_digit()).unwrap_or(true);
                            if ok_end {
                                hit = true;
                                break;
                            }
                        }
                        if hit {
                            reg_of.push((dest.to_string(), *pi));
                            break;
                        }
                    }
                }
            }
        }
        // memory-desc use: desc[URx][Ry.64] / plain [Rx]
        let base = ins.opcode_full.split('.').next().unwrap_or("");
        let is_mem = matches!(
            base,
            "LDG" | "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "LDS" | "STS" | "LD" | "ST"
        );
        if is_mem {
            for (rn, pi) in &reg_of {
                // uzycie jako baza adresu: [Rx ...] lub desc[...Rx...]
                let needle1 = format!("[{}.", rn);
                let needle2 = format!("[{},", rn);
                let needle3 = format!("[{}]", rn);
                let used = t.contains(&needle1) || t.contains(&needle2) || t.contains(&needle3);
                if used && !order.contains(pi) {
                    order.push(*pi);
                    if matches!(base, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "STS" | "ST") {
                        write_mask |= 1u32 << pi;
                    }
                }
                if used
                    && matches!(base, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG")
                    && order.contains(pi)
                {
                    let pos = order.iter().position(|p| p == pi).unwrap_or(0) as u32;
                    stg_desc_pos.push(pos);
                }
            }
        }
        if matches!(base, "BAR") && ins.guard.is_some() {
            bar_predicated = true;
        }
    }
    (if order.is_empty() { None } else { Some(order) },
     write_mask,
     stg_desc_pos,
     bar_predicated,
     uniform_mask,
     regpath_mask,
     widths)
}
