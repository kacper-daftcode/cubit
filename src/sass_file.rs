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
         merc_param_uniform, merc_param_regpath, merc_param_width,
         merc_param_loads, merc_cbank_lane, merc_s2r_lanes, merc_predmem,
         merc_ldgconst) =
        merc_param_scan(&def.instructions);
    let (merc_bar_pos, merc_stg_pos, merc_stg_off, merc_bar_args) =
        merc_exec_positions(&def.instructions);
    let (merc_xor, merc_xor_reg) = merc_xor_scan(&def.instructions);
    let merc_atoms = merc_atom_scan(&def.instructions);
    let merc_stg_ser = merc_stg_series(&def.instructions);
    let (merc_stg_dreg, merc_stg_dur, merc_stg_guard) = merc_stg_meta(&def.instructions);
    let merc_mma = merc_mma_scan(&def.instructions);
    let merc_f64imm = merc_f64imm_scan(&def.instructions);
    let merc_pad_pos: Vec<u32> = def
        .instructions
        .iter()
        .filter(|i| crate::mercury::is_uiadd3_killpad(&i.raw_text))
        .map(|i| (i.addr / 16) as u32)
        .collect();
    // mk13: predykowany BRA -> bit bitmapy; LOP3 z destem Pn -> bez bitu,
    // mini-rekord 42 2a 02 06 w lane (gold q_switch/p_call/d_sw4_store).
    let mut merc_guarded_bra: Vec<u32> = Vec::new();
    let mut merc_lop3_pdest: Vec<u32> = Vec::new();
    let mut merc_s2r_sr: Vec<u8> = Vec::new();
    for ins in &def.instructions {
        let lane = (ins.addr / 16) as u32;
        if ins.opcode == "S2R" {
            // mk13: enum SR -> b12 anchor-rekordu (rownolegle do
            // merc_s2r_lanes z merc_param_scan — oba w kolejnosci adresow).
            let sr = crate::mercury::s2r_sr_name(&ins.raw_text);
            merc_s2r_sr.push(crate::mercury::merc_s2r_sr_enum(&sr));
        }
        if ins.opcode == "BRA" {
            if let Some(g) = &ins.guard {
                if g.pred != 7 {
                    merc_guarded_bra.push(lane);
                }
            }
        }
        if ins.opcode == "LOP3" && crate::mercury::lop3_writes_pred(&ins.raw_text) {
            merc_lop3_pdest.push(lane);
        }
    }

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
        merc_bar_args,
        merc_stg_pos,
        merc_param_uniform,
        merc_param_regpath,
        merc_param_width,
        merc_xor,
        merc_xor_reg,
        merc_stg_off,
        merc_stg_ser,
        merc_stg_dreg,
        merc_stg_dur,
        merc_stg_guard,
        merc_mma,
        merc_f64imm,
        merc_pad_pos,
        merc_param_loads,
        merc_cbank_lane,
        merc_s2r_lanes,
        merc_predmem,
        merc_ldgconst,
        merc_guarded_bra,
        merc_s2r_sr,
        merc_lop3_pdest,
        // mk14: duchy syncwarp widoczne tylko w EIATTR (nie w tekscie sass).
        merc_syncwarp: Vec::new(),
        merc_atoms,
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

fn merc_exec_positions(
    instructions: &[Instruction],
) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<(u32, u32)>) {
    let mut bar_pos = Vec::new();
    let mut bar_args = Vec::new();
    let mut stg_pos = Vec::new();
    let mut stg_off = Vec::new();
    for ins in instructions {
        let slot = (ins.addr / 16) as u32;
        match ins.opcode.as_str() {
            "BAR" | "SYNCS" => {
                bar_pos.push(slot);
                // mk13: named barrier args `BAR.SYNC.DEFER_BLOCKING 0x1, 0x20`
                // -> (id, cnt); zwykly BAR bez argumentow -> (0, 0).
                let tt = ins.raw_text.trim();
                let g2 = if tt.starts_with('@') {
                    tt.find(char::is_whitespace).map(|k| tt[k..].trim()).unwrap_or("")
                } else {
                    tt
                };
                let rest = g2
                    .find(char::is_whitespace)
                    .map(|k| g2[k..].trim())
                    .unwrap_or("");
                let mut it = rest.split(',');
                let pa = |t: &str| -> u32 {
                    let t = t.trim().trim_end_matches(';');
                    if let Some(h) = t.strip_prefix("0x") {
                        u32::from_str_radix(h, 16).unwrap_or(0)
                    } else {
                        t.parse::<u32>().unwrap_or(0)
                    }
                };
                let id = it.next().map(pa).unwrap_or(0);
                let cnt = it.next().map(pa).unwrap_or(0);
                bar_args.push((id, cnt));
            }
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
    (bar_pos, stg_pos, stg_off, bar_args)
}

/// Mercury 0229: skan `LOP3.LUT Rd, Rs, imm32, RZ, 0x3c` (= SASS-forma C-level
/// `xor dst, src, imm`). Zwraca (lane, dst, src, imm, guard). fs6-lab:
/// tylko lut=0x3c z imm w slocie srcB i RZ w slocie srcC dostaje rekord 0229;
/// or/and (lut 0xfc/0xc0) zostaja zwyklymi bitami; nor/neg-formy rowniez nie.
/// lane takiej instrukcji NIE dostaje bitu bitmapy (rekord pelny zastepuje
/// wezel typu4-flag1).
/// mk10b: indeks STG w biezacej serii blokowej + null-tail flag (bit7).
/// Granice serii: instrukcja-bedaca-targetem skoku oraz pozycja po EXIT/RET/
/// CALL/BRA/BRX/JMP/BREAK/BSSY/BSYNC (navic odpowiednia na s_stg_branch).
/// mk12: per-STG (dreg/dur/guard) — merc_stg_meta ponizej. dreg: kursor
/// rekordu 02 38 na bajtach [19],[20] (u16 LE) = dreg << 6; RZ jako 0x3ff
/// (R3->0x00c0, R5->0x0140, R7->0x01c0, R9->0x0240, R11->0x02c0,
/// R21->0x0540, RZ->0xffc0). Zastepuje model mk10b (40|par<<7, 1+(ser>>1)
/// == seria R5+2n). dur: desc-UR -> (b17,b18) = (dur<<6)|2 (fala A:
/// UR6 -> 0x0182 dla k_lds/v_sm*/k_smem). guard: @Pn -> b4=00,
/// @!Pn -> b4=01, brak -> f8 (jak w rekordzie 0229; d_ifearly_stg).
fn merc_stg_meta(instructions: &[Instruction]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // mk12 (kursor) + fala A: per-STG (dreg danych, desc-UR, wariant guardu).
    let mut dreg = Vec::new();
    let mut dur = Vec::new();
    let mut guard = Vec::new();
    for ins in instructions {
        if ins.opcode != "STG" {
            continue;
        }
        let txt = ins.raw_text.trim_end_matches([';', ' ']);
        let tail = txt.rsplit(',').next().unwrap_or("").trim();
        let d = if tail == "RZ" {
            255u8
        } else {
            tail
                .strip_prefix('R')
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok())
                .map(|v| v.min(255) as u8)
                .unwrap_or(255)
        };
        dreg.push(d);
        let u: u8 = txt
            .find("desc[UR")
            .and_then(|k| {
                txt[k + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
            })
            .map(|v| v.min(255) as u8)
            .unwrap_or(4);
        dur.push(u);
        let t = txt.trim_start();
        let g: u8 = if t.starts_with("@!") { 2 } else if t.starts_with('@') { 1 } else { 0 };
        guard.push(g);
    }
    (dreg, dur, guard)
}

fn merc_stg_series(instructions: &[Instruction]) -> Vec<u8> {
    let mut bounds: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for ins in instructions {
        let base = ins.opcode.as_str();
        if matches!(base,
            "BRA" | "BRX" | "JMP" | "JMPX" | "CALL" | "RET" | "EXIT" | "BREAK" |
            "BSSY" | "BSYNC") {
            bounds.insert(ins.addr / 16 + 1);
        }
        // target absolutny skoku (cubit drukuje 0xHEX w 16B-adresach)
        if matches!(base, "BRA" | "BRX" | "JMP" | "JMPX" | "CALL") {
            if let Some(pos) = ins.raw_text.find("0x") {
                let h = &ins.raw_text[pos + 2..];
                let hexdig: String =
                    h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                if let Ok(tv) = u32::from_str_radix(&hexdig, 16) {
                    if tv % 16 == 0 {
                        bounds.insert(tv / 16);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut ser = 0u8;
    for ins in instructions {
        let slot = ins.addr / 16;
        if bounds.contains(&slot) {
            ser = 0;
        }
        if ins.opcode == "STG" {
            let nulltail = ins.raw_text.trim_end_matches([';', ' ']).ends_with(", RZ");
            out.push(((nulltail as u8) << 7) | ser.min(126));
            ser = ser.saturating_add(1);
        }
    }
    out
}

/// mk14: skan rekordow atomowych ATOMG/ATOMS (RED* obsluguje legacy REC_ATOM).
/// Format tuple zgodny z eiattr::KernelMeta::merc_atoms.
fn merc_atom_scan(instructions: &[Instruction]) -> Vec<(u32, u8, u8, u8, u8, u8, u8, u8)> {
    let mut out = Vec::new();
    let reg_of = |t: &str| -> u8 {
        let t = t.trim().trim_end_matches(';').trim_end_matches(')');
        if t == "RZ" || t == "URZ" {
            return 255;
        }
        let d = t.trim_start_matches(['R', 'U']);
        if d.chars().all(|c| c.is_ascii_digit()) && !d.is_empty() {
            d.parse::<u32>().ok().map(|v| v.min(255) as u8).unwrap_or(255)
        } else {
            255
        }
    };
    for ins in instructions {
        let lane = (ins.addr / 16) as u32;
        let base = ins.opcode.as_str();
        if !base.starts_with("ATOM") {
            continue;
        }
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        let mut guard = 0u8;
        if first.starts_with('@') {
            guard = if first.starts_with("@!") { 2 } else { 1 };
            first = toks.next().unwrap_or("");
        }
        if !base.starts_with("ATOMS") && !first.starts_with(base) && !first.starts_with("ATOM") {
            continue;
        }
        let rest: Vec<&str> = toks.collect();
        let rest = rest.join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        let is_cas = base.contains("CAS");
        if base.starts_with("ATOMS") {
            // ATOMS.<op> Rd, [URx], Rv
            if parts.len() < 3 {
                continue;
            }
            out.push((lane, crate::mercury::MERC_ATOM_CLS_SHARED, guard,
                      reg_of(parts[0]), 255, reg_of(parts[2]), 255, 0));
        } else {
            // ATOMG.E.<sub>.STRONG.<scope> PT, Rd, <addr>, Rv[, Rd2]
            if parts.len() < 3 {
                continue;
            }
            let dst = reg_of(parts[0].trim_start_matches("PT,").trim());
            // dest tok moze zawierac "PT, R5" jako parts[0] po split(',')?
            // split(',') dzieli "PT" i "R5" osobno — obsluga ponizej.
            let (dst_idx, addr_idx) = if parts[0].contains("PT") && !parts[0].contains('R') {
                (1usize, 2usize)
            } else {
                (0usize, 1usize)
            };
            let dst = if dst_idx < parts.len() { reg_of(parts[dst_idx]) } else { dst };
            if addr_idx >= parts.len() {
                continue;
            }
            let addr_part = parts[addr_idx];
            // adres: [R4] albo desc[UR4][R2.64] — ostatni wewnetrzny [..]
            let addr = {
                let mut a = 255u8;
                let mut s2 = addr_part;
                while let Some(o) = s2.rfind('[') {
                    let inner = &addr_part[o + 1..];
                    let end = inner.find(']').unwrap_or(inner.len());
                    let tok = &inner[..end];
                    let r = reg_of(tok.split('+').next().unwrap_or("").split('.').next().unwrap_or(""));
                    if r != 255 {
                        a = r;
                        break;
                    }
                    s2 = &addr_part[..o];
                }
                a
            };
            if is_cas {
                if parts.len() < addr_idx + 3 {
                    continue;
                }
                out.push((lane, crate::mercury::MERC_ATOM_CLS_CAS, guard, dst, addr,
                          reg_of(parts[addr_idx + 1]), reg_of(parts[addr_idx + 2]), 0));
            } else {
                if parts.len() < addr_idx + 2 {
                    continue;
                }
                let sub6: u8 = if base.starts_with("ATOMG") && ins.raw_text.contains(".EXCH") {
                    0x80
                } else {
                    0
                };
                out.push((lane, crate::mercury::MERC_ATOM_CLS_G4, guard, dst, addr,
                          reg_of(parts[addr_idx + 1]), 255, sub6));
            }
        }
    }
    out
}

fn merc_xor_scan(
    instructions: &[Instruction],
) -> (Vec<(u32, u32, u32, u32, u8)>, Vec<(u32, u32, u32, u32, u8)>) {
    let mut out = Vec::new();
    let mut out_reg = Vec::new();
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
        let reg = |t: &str| -> Option<u32> {
            t.strip_prefix('R')
                .and_then(|d| if d.chars().all(|c| c.is_ascii_digit()) { d.parse::<u32>().ok() } else { None })
        };
        match parts[2]
            .strip_prefix("0x")
            .and_then(|h| u32::from_str_radix(h, 16).ok())
        {
            Some(imm) => {
                let (Some(dst), Some(src)) = (reg(parts[0]), reg(parts[1])) else {
                    continue;
                };
                out.push(((ins.addr / 16) as u32, dst, src, imm, guard));
            }
            None => {
                // mk13: forma rejestrowa A^B (0x3c, trzy rejestry) — osobny
                // 16B rekord 0129: dst@[10]=(d<<6)|1, srcA@[12]=a<<6,
                // srcB@[14]=b<<6; lane bez bitu bitmapy jak 0229 (gold lp1).
                let (Some(dst), Some(src_a), Some(src_b)) =
                    (reg(parts[0]), reg(parts[1]), reg(parts[2]))
                else {
                    continue;
                };
                out_reg.push(((ins.addr / 16) as u32, dst, src_a, src_b, guard));
            }
        }
    }
    (out, out_reg)
}

/// Mercury mk11: instrukcje MMA (HMMA/DMMA/IMMA/...) -> rekord 025a w lane.
/// Model byte-exact (mma_model.py, korpus 15.6k rekordow). Rekord trzyma
/// numery rejestrow D/A/B/C z tekstu SASS (znaki/-NIE istotne, .reuse tez).
/// b8flags (code63/code72) dopelnia main.rs po enkodacji (pole lane->word).
fn merc_mma_scan(instructions: &[Instruction]) -> Vec<(u32, u8, u8, u8, u8, u8, u8)> {
    let mut out = Vec::new();
    let regno = |t: &str| -> Option<u8> {
        let t = t.trim_end_matches(';').trim().trim_start_matches(['-', '+']);
        let t = t.split('.').next().unwrap_or(t);
        if t == "RZ" {
            return Some(255);
        }
        let d = t.strip_prefix('R')?;
        if d.chars().all(|c| c.is_ascii_digit()) {
            d.parse::<u8>().ok()
        } else {
            None
        }
    };
    for ins in instructions {
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        if first.starts_with('@') {
            first = toks.next().unwrap_or("");
        }
        let Some(cls) = crate::mercury::merc_mma_class(first) else {
            continue;
        };
        let rest = toks.collect::<Vec<_>>().join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        if parts.len() < 4 {
            continue;
        }
        let (Some(d), Some(a), Some(b), Some(c)) =
            (regno(parts[0]), regno(parts[1]), regno(parts[2]), regno(parts[3]))
        else {
            continue;
        };
        out.push(((ins.addr / 16) as u32, cls, d, a, b, c, 0u8));
    }
    out
}

/// Mercury mk11: DMUL/DADD z natychmiastowym f64 -> rekord 020f/020c.
/// Ostatni operand musi byc literalnym floatem (drukas: "%.*g" / decimal).
fn merc_f64imm_scan(instructions: &[Instruction]) -> Vec<(u32, u8, u8, u8, u32)> {
    let mut out = Vec::new();
    for ins in instructions {
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        if first.starts_with('@') {
            first = toks.next().unwrap_or("");
        }
        let variant = if first.starts_with("DMUL") {
            0u8
        } else if first.starts_with("DADD") {
            1u8
        } else {
            continue;
        };
        let rest = toks.collect::<Vec<_>>().join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        if parts.len() < 3 {
            continue;
        }
        let Some(immf) = parts[2].parse::<f64>().ok() else {
            continue; // forma reg-reg — bez rekordu (potwierdzenie: mk11-lab)
        };
        let regno = |t: &str| -> Option<u8> {
            let t = t.trim().split('.').next().unwrap_or(t.trim());
            let d = t.strip_prefix('R')?;
            if d.chars().all(|c| c.is_ascii_digit()) { d.parse::<u8>().ok() } else { None }
        };
        let (Some(d), Some(a)) = (regno(parts[0]), regno(parts[1])) else {
            continue;
        };
        let imm_top = ((immf.to_bits()) >> 32) as u32;
        out.push(((ins.addr / 16) as u32, variant, d, a, imm_top));
    }
    out
}

fn merc_param_scan(
    instructions: &[Instruction],
) -> (Option<Vec<u32>>, u32, Vec<u32>, bool, u32, u32, Vec<u8>, Vec<(u32, u32, u8, u8, u8)>, Option<u32>, Vec<u32>, bool, Vec<(u32, u32)>) {
    // reg name -> (param idx, idx w puli deskryptorow (pi,mech))
    let mut reg_of: Vec<(String, u32, u32)> = Vec::new();
    let mut order: Vec<u32> = Vec::new();
    let mut write_mask: u32 = 0;
    let mut stg_desc_pos: Vec<u32> = Vec::new();
    let mut bar_predicated = false;
    let mut uniform_mask: u32 = 0; // bit pi: slot zaladowany przez LDCU*
    let mut regpath_mask: u32 = 0; // bit pi: slot zaladowany przez LDC*
    let mut widths: Vec<u8> = Vec::new(); // per-param: max transfer bytes
    // mk10c: per-load rekordy + lane + pula deskryptorow (pi, unif01)
    let mut loads: Vec<(u32, u32, u8, u8, u8)> = Vec::new();
    let mut cbank_lane: Option<u32> = None;
    let mut s2r_lanes: Vec<u32> = Vec::new();
    let mut predmem = false;
    let mut pool: Vec<(u32, u8)> = Vec::new();
    let mut ldgconst: Vec<(u32, u32)> = Vec::new();

    fn note(m: &mut u32, pi: u32) {
        if pi < 32 {
            *m |= 1u32 << pi;
        }
    }
    for ins in instructions {
        // mk13b: tekst roboczy BEZ guarda prowadzacego (@Pn/@!Pn/@UPn) —
        // dest-parse LDC bral dotad nth(1) po surowym tekscie, co dla
        // predykowanych loadow dawalo smiec ("LDC.64" zamiast R2) i gubilo
        // binding STG (d_ifearly_exit/d_ifearly_stg: STG dp=MAX).
        let t_full = ins.raw_text.as_str();
        let t: &str = match t_full.trim_start().strip_prefix('@') {
            Some(rest) => rest
                .split_once(char::is_whitespace)
                .map(|(_, r)| r.trim_start())
                .unwrap_or(t_full),
            None => t_full,
        };
        let lane = (ins.addr / 16) as u32;
        let guard_v: u8 = match &ins.guard {
            None => 0,
            Some(g) => {
                if g.pred == 7 && !g.negated {
                    0
                } else if g.negated {
                    2
                } else {
                    1
                }
            }
        };
        let base0 = ins.opcode_full.split('.').next().unwrap_or("");
        if base0 == "S2R" {
            s2r_lanes.push(lane);
        }
        // LDC / LDCU load z okna parametrow [0x380..]
        let is_ldcu = ins.opcode == "LDCU";
        if ins.opcode == "LDC" || is_ldcu {
            if let Some(cp) = t.find("c[0x0][0x") {
                let hexs = &t[cp + 9..];
                let end = hexs.find(']').unwrap_or(0);
                if let Ok(off) = u32::from_str_radix(&hexs[..end], 16) {
                    if off == 0x358 && is_ldcu && cbank_lane.is_none() {
                        cbank_lane = Some(lane);
                    }
                    if off >= 0x380 && (off - 0x380) % 8 == 0 {
                        let pi = (off - 0x380) / 8;
                        let uflag: u8 = if is_ldcu { 1 } else { 0 };
                        // lead operand = dest reg
                        let depth = t.find(',').unwrap_or(t.len());
                        let dest = t[..depth]
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .trim_end_matches(".64")
                            .to_string();
                        // szerokosc transferu
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
                        loads.push((lane, pi, uflag, w, guard_v));
                        // pula deskryptorow (pi, mechanizm) — TYLKO loady
                        // szerokie (>=8B); skalarne (4B) rekordy nie maja
                        // slotu w puli STG-binding (k_stg2: (41,02) bez slota).
                        let pool_idx = if w >= 8 {
                            match pool.iter().position(|&e| e == (pi, uflag)) {
                                Some(k) => k as u32,
                                None => {
                                    pool.push((pi, uflag));
                                    (pool.len() - 1) as u32
                                }
                            }
                        } else {
                            u32::MAX
                        };
                        if !dest.is_empty() {
                            reg_of.push((dest.clone(), pi.min(31), pool_idx));
                            // wide loads: high-half rejestrow pary (UR7 dla LDCU.64 UR6 itd.)
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
                                    reg_of.push((format!("{}{}", pfx, n + 1), pi.min(31), pool_idx));
                                }
                            }
                        }
                        if is_ldcu {
                            note(&mut uniform_mask, pi);
                        } else {
                            note(&mut regpath_mask, pi);
                        }
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
        // mk13: LDG.E.CONSTANT przez desc[URx][Rn.64] = osobny klucz puli
        // (pi, 2) w kolejnosci kodu — nvcc numeruje sloty STG z tym wpisem
        // (gold v_ldg_u64: STG pi1 -> s=2, bo LDG.C@3 = (pi0,2) -> s=1).
        if base0 == "LDG" && ins.opcode_full.contains(".CONSTANT") {
            if let Some(lb) = t.rfind('[') {
                let inner = &t[lb + 1..t[lb + 1..].find(']').map(|e| lb + 1 + e).unwrap_or(t.len())];
                let root: String = inner
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                if let Some((_, pi, pidx)) = reg_of.iter().find(|(rn, _, _)| *rn == root) {
                    if *pidx != u32::MAX {
                        let key = (*pi, 2u8);
                        if !pool.contains(&key) {
                            pool.push(key);
                        }
                        ldgconst.push((lane, *pi));
                    }
                }
            }
        }
        // alias-flow UR/R: dest <- zrodla sledzone (shape IADD3 R2, P0, PT, R0, UR6, RZ)
        if matches!(
            base0,
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
                    for (rn, pi, pidx) in &reg_of {
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
                            reg_of.push((dest.to_string(), *pi, *pidx));
                            break;
                        }
                    }
                }
            }
        }
        // memory-desc use: desc[URx][Ry.64] / plain [Rx]
        let is_mem = matches!(
            base0,
            "LDG" | "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "LDS" | "STS" | "LD" | "ST"
        );
        let mut stg_binding: Option<u32> = None;
        if is_mem {
            if guard_v != 0 {
                predmem = true;
            }
            for (rn, pi, pidx) in &reg_of {
                // uzycie jako baza adresu: [Rx ...] lub desc[...Rx...]
                let needle1 = format!("[{}.", rn);
                let needle2 = format!("[{},", rn);
                let needle3 = format!("[{}]", rn);
                let used = t.contains(&needle1) || t.contains(&needle2) || t.contains(&needle3);
                if used && !order.contains(pi) {
                    order.push(*pi);
                }
                // mk10c: write-bit przy kazdym store-uzyciu (nie tylko przy
                // pierwszym) — r2_wr dowod, ze read->write param ginie inaczej.
                if used
                    && matches!(base0, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "STS" | "ST")
                {
                    write_mask |= 1u32 << pi;
                }
                // mk10c: STG binding -> indeks PULI deskryptorow (pi, mech)
                // zrodlowego loadu roota adresowego (nie pozycja param-queue).
                // mk13b: NIE pushowac tutaj (aliasowe duplikaty reg_of dawaly
                // wiele wpisow na STG) — jeden binding per instrukcja, patrz
                // nizej.
                if used
                    && matches!(base0, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG")
                    && stg_binding.is_none()
                {
                    stg_binding = Some(*pidx);
                }
            }
            // mk13b: nvcc numeruje slot per INSTRUKCJA STG — dokladnie jeden
            // wpis. Root adresu = ostatni nawias kwadratowy (jak mk_gold /
            // main-rs mirror); fallback = binding z petli, inaczej UNKNOWN.
            if matches!(base0, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG") {
                let binding = if let Some(lb) = t.rfind('[') {
                    let end = t[lb..].find(']').map(|e| lb + e).unwrap_or(t.len());
                    let root: String = t[lb + 1..end]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    reg_of
                        .iter()
                        .find(|(rn, _, _)| *rn == root)
                        .map(|(_, _, p)| *p)
                        .or(stg_binding)
                        .unwrap_or(u32::MAX)
                } else {
                    stg_binding.unwrap_or(u32::MAX)
                };
                stg_desc_pos.push(binding);
            }
        }
        if base0 == "BAR" && ins.guard.is_some() {
            bar_predicated = true;
        }
    }
    (if order.is_empty() { None } else { Some(order) },
     write_mask,
     stg_desc_pos,
     bar_predicated,
     uniform_mask,
     regpath_mask,
     widths,
     loads,
     cbank_lane,
     s2r_lanes,
     predmem,
     ldgconst)
}
