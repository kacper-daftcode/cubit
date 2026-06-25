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
    }
}
