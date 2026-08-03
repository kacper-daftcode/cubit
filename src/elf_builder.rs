//! ELF builder: construct a valid CUDA cubin from instruction bytes + metadata.
//!
//! Produces a minimal SM120 cubin with the sections required by the CUDA
//! driver.  Section layout and symbol table format match nvcc 12.8 output.
//!
//! # Section layout (per N kernels, total 17 + 5*N sections)
//!
//! Fixed sections:
//!   0  NULL
//!   1  .shstrtab
//!   2  .strtab
//!   3  .symtab
//!   4  .debug_frame          (empty PROGBITS)
//!   5  .note.nv.tkinfo       (toolkit version note, CUDA 12.8)
//!   6  .note.nv.cuinfo        (CUDA version note)
//!   7  .nv.info              (global REGCOUNT/FRAME_SIZE per kernel)
//!
//! Per-kernel (N×):
//!   8+ki          .nv.info.K[i]    (per-kernel attributes)
//!
//! Fixed after info:
//!   8+N           .nv.compat
//!   9+N           .nv.callgraph
//!  10+N           .rela.debug_frame (empty)
//!
//! Per-kernel (N×):
//!  11+N+ki        .text.K[i]       (SASS instructions)
//!
//! Fixed:
//!  11+2N          .nv.shared.reserved.0  (NOBITS, 0x40 minimum)
//!  12+2N+ki       .nv.shared.K[i]        (NOBITS, per-kernel shared_size)
//!
//! Per-kernel (N×):
//!  13+3N+ki       .nv.constant0.K[i]
//!  13+4N+ki       .nv.capmerc.text.K[i]  (Mercury EXIT stub)
//!
//! Fixed Mercury:
//!  13+5N          .nv.merc.debug_frame
//!  14+5N          .nv.merc.nv.info
//!
//! Per-kernel Mercury (N×):
//!  15+5N+ki       .nv.merc.nv.info.K[i]
//!
//! Fixed Mercury:
//!  15+6N          .nv.merc.rela.debug_frame
//!  16+6N          .nv.merc.nv.shared.reserved.0
//!  17+6N          .nv.merc.symtab

use anyhow::Result;

// ── ELF64 constants ───────────────────────────────────────────────────────────

const ELF_MAGIC: [u8; 4] = *b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_CUDA: u8 = 0x41;
const ET_EXEC: u16 = 2;
const EM_CUDA: u16 = 0x00BE;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_LOPROC: u32 = 0x7000_0000;

const SHT_CUDA_INFO: u32 = SHT_LOPROC; // 0x70000000
const SHT_CUDA_COMPAT: u32 = SHT_LOPROC + 0x86; // 0x70000086
const SHT_CUDA_CALLGRAPH: u32 = SHT_LOPROC + 0x01; // 0x70000001
const SHT_MERC_INFO: u32 = SHT_LOPROC + 0x83; // 0x70000083
const SHT_MERC_RELA: u32 = SHT_LOPROC + 0x82; // 0x70000082
const SHT_MERC_CAPMERC: u32 = SHT_LOPROC + 0x16; // 0x70000016
const SHT_MERC_RESERVED_SH: u32 = SHT_LOPROC + 0x15; // 0x70000015
const SHT_MERC_SYMTAB: u32 = SHT_LOPROC + 0x85; // 0x70000085

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_INFO_LINK: u64 = 0x40;
const SHF_NV_TKINFO: u64 = 0x0200_0000;
const SHF_NV_CUVER: u64 = 0x0100_0040; // includes SHF_INFO_LINK
const SHF_MERC: u64 = 0x1000_0000;
const SHF_MERC_LINK: u64 = SHF_MERC | SHF_INFO_LINK;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STV_DEFAULT: u8 = 0;
const STV_HIDDEN: u8 = 0x10; // used in Mercury symtab function entry

pub const EF_CUDA_SM120: u32 = 0x0600_7802;

// ── Hardcoded blobs matching CUDA 12.8 SM120 nvcc output ─────────────────────

/// .note.nv.tkinfo: 168 bytes from nvcc 13.1 ptxas (matches working cubins).
const TKINFO_BYTES: &[u8] = &[
    0x0c, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x4e, 0x56, 0x49, 0x44,
    0x49, 0x41, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00,
    0x00, 0x70, 0x74, 0x78, 0x61, 0x73, 0x00, 0x43, 0x75, 0x64, 0x61, 0x20, 0x63, 0x6f, 0x6d, 0x70,
    0x69, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2c, 0x20, 0x72,
    0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x20, 0x31, 0x33, 0x2e, 0x31, 0x2c, 0x20, 0x56, 0x31, 0x33,
    0x2e, 0x31, 0x2e, 0x31, 0x31, 0x35, 0x00, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x63, 0x75, 0x64,
    0x61, 0x5f, 0x31, 0x33, 0x2e, 0x31, 0x2e, 0x72, 0x31, 0x33, 0x2e, 0x31, 0x2f, 0x63, 0x6f, 0x6d,
    0x70, 0x69, 0x6c, 0x65, 0x72, 0x2e, 0x33, 0x37, 0x30, 0x36, 0x31, 0x39, 0x39, 0x35, 0x5f, 0x30,
    0x00, 0x2d, 0x61, 0x72, 0x63, 0x68, 0x20, 0x73, 0x6d, 0x5f, 0x31, 0x32, 0x30, 0x20, 0x2d, 0x6d,
    0x20, 0x36, 0x34, 0x20, 0x00, 0x00, 0x00, 0x00,
];

/// .note.nv.cuinfo desc: 12 bytes matching working nvcc 12.8 cubins.
const CUVER_DESC: &[u8] = &[0x02, 0x00, 0x78, 0x00, 0x83, 0x00, 0x00, 0x00];

/// .nv.compat section: 28 bytes matching working nvcc 13.1 cubins.
/// Format verified on driver 590.48 with SM120 Blackwell.
const NV_COMPAT: &[u8] = &[
    0x02, 0x09, 0x00, 0x00, 0x02, 0x02, 0x02, 0x00, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03, 0x00, 0x00,
    0x04, 0x0b, 0x08, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// .nv.callgraph: 4 × 8-byte entries (terminators, no kernel entries).
const NV_CALLGRAPH: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff,
];

/// .nv.capmerc.text.K: Full Mercury stub for kernels using global memory (126 bytes, nvcc 12.8).
/// The GPU runs SASS (.text.K), not this Mercury stub.
/// The driver reads this stub to decide which system resources to set up — in particular,
/// the global memory descriptor at c[0x0][0x358] (needed for STG.E/LDG.E desc[] forms).
/// A minimal EXIT-only stub (30 bytes) causes the driver to skip that setup → STG.E → crash.
#[allow(dead_code)] // reference data, kept for the full global-memory stub path
const CAPMERC_EXIT_STUB: &[u8] = &[
    0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xc0, 0x0a, 0x00, 0x00, 0x00, 0x4c, 0x01, 0x00, 0x00,
    0x01, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x01, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00,
    0x01, 0x0b, 0x0e, 0x0a, 0xfa, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x39, 0x04, 0x00, 0x00,
    0x02, 0x22, 0x0e, 0x06, 0xf8, 0x00, 0x52, 0x00, 0x00, 0x00, 0x83, 0x00, 0x40, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x38, 0x0e, 0x32, 0xf8, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd0, 0x07,
];
/// Symbol size of the Mercury stub (from nvcc 12.8 merc_symtab st_size = 0xb0 = 176).
const CAPMERC_STUB_PADDED: u64 = 0x82;

/// .nv.merc.debug_frame: 112 bytes from nvcc 12.8 (full global-memory Mercury stub variant).
/// FDE PC_range = 0xc0 = CAPMERC_STUB_PADDED; CFI advance_loc4 = 0xb0 (EXIT offset in stub).
const MERC_DEBUG_FRAME: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x03, 0x00, 0x01, 0x7c, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x0c, 0x81, 0x80,
    0x80, 0x28, 0x00, 0x08, 0xff, 0x81, 0x80, 0x28, 0x08, 0x81, 0x80, 0x80, 0x28, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // PC_range = 0xb0 = CAPMERC_STUB_PADDED (nvcc 12.8)
    0x04, 0x10, 0x00, 0x00, 0x00, 0x04, 0xa0,
    0x00, // DW_CFA_advance_loc4 0x10, then 0xa0 (EXIT at 0xa0)
    0x00, 0x00, 0x0c, 0x81, 0x80, 0x80, 0x28, 0x00, 0x04, 0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Mercury content hash (attr 0x5a, 36 bytes) for the full global-memory Mercury stub above.
/// Extracted from nvcc 12.8 .nv.merc.nv.info._Z12write_globalPi (kernel using STG.E).
const MERC_HASH: &[u8] = &[
    0x8a, 0x9d, 0x22, 0xa4, 0xb1, 0x9d, 0x14, 0x6d, 0x00, 0xb4, 0x2a, 0xf3, 0xf7, 0x58, 0x03, 0xa5,
    0x27, 0x2c, 0x21, 0x30, 0xc9, 0x1e, 0xc7, 0x8f, 0x0f, 0x0c, 0x49, 0x6c, 0x0a, 0x2f, 0x00, 0x00,
];

/// Generate Mercury section from SASS code analysis.
///
/// Mercury is a driver-interpreted bytecode that describes kernel resource requirements.
/// Reverse-engineered from nvcc 13.1 SM120 output across 14 test kernels.
///
/// Structure: [12B header] [4B bitstream] [N×16B/32B records] [2B tail]
///
/// Records describe: global memory descriptors, shared memory, barriers, constant bank.
pub fn generate_mercury_from_sass(code: &[u8], kernel_id: u32) -> Vec<u8> {
    generate_mercury_with_ops(code, kernel_id, None)
}

/// Feature switchboard for the grammar-v1 generator (per-feature records,
/// empirisch verankert an nvcc-Mikrolab-Deltas; siehe internal docs
/// MERCURY_UPLIFT_SM103A.md, iter U).
#[derive(Debug, Clone, Default)]
pub struct MercFeatures {
    /// Used 8-byte (pointer-class) kernel parameters -> per-param desc records.
    pub used_params: u32,
    /// Used scalar (<=4B class) parameters -> 02220806-class records.
    pub used_scalar_params: u32,
    pub smem_static: bool,
    pub bar_count: u32,
    pub n_stg: u32,
    pub n_atom: u32,
    pub extra_exit: bool,
}

impl MercFeatures {
    pub fn from_parts(meta: &KernelMeta, opcodes: &[String]) -> Self {
        let mut f = MercFeatures {
            used_params: meta.params.len() as u32,
            ..Default::default()
        };
        f.extra_exit = meta.exit_offsets.len() > 1;
        f.smem_static = meta.shared_size > 0;
        f.n_stg = opcodes.iter().filter(|o| o.starts_with("STG")).count() as u32;
        f.n_atom = opcodes
            .iter()
            .filter(|o| o.starts_with("REDG") || o.starts_with("ATOMS") || o.starts_with("ATOMG"))
            .count() as u32;
        f.bar_count = meta.num_barriers as u32;
        f
    }
}

const REC_PROLOG: [u8; 16] = [
    0x01, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x41, 0x00, 0x00, 0x04, 0x00, 0x00,
];
const REC_PARAM_DESC: [u8; 32] = [
    0x02, 0x22, 0x0e, 0x06, 0xf8, 0x00, 0x52, 0x00,
    0x00, 0x00, 0x83, 0x00, 0x40, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const REC_CBANK: [u8; 16] = [
    0x01, 0x0b, 0x0e, 0x0a, 0xfa, 0x00, 0x05, 0x00,
    0x00, 0x00, 0x03, 0x01, 0x39, 0x04, 0x00, 0x00,
];
const REC_BAR: [u8; 16] = [
    0x01, 0x47, 0x5a, 0x16, 0xf8, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];
const REC_SMEM: [u8; 16] = [
    0x01, 0x0b, 0x06, 0x0a, 0xfa, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x41, 0x01, 0x2c, 0x02, 0x00, 0x00,
];
const REC_STG: [u8; 32] = [
    0x02, 0x38, 0x0e, 0x32, 0xf8, 0x00, 0x40, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const REC_ATOM: [u8; 32] = [
    0x02, 0x4d, 0x24, 0x32, 0x00, 0x00, 0x00, 0xa0,
    0x01, 0x00, 0x00, 0x00, 0x82, 0x00, 0x0a, 0x00,
    0x00, 0x02, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const REC_EXTRA_EXIT: [u8; 16] = [
    0x01, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00,
];
const REC_SCALAR_PARAM: [u8; 32] = [
    0x02, 0x22, 0x08, 0x06, 0xfa, 0x00, 0x42, 0x00,
    0x00, 0x00, 0x81, 0x01, 0x40, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
];

/// Emit the capability-record stream given measured per-kernel features.
/// Layout mirrors nvcc output for simple kernels (gold-tested in tests).
fn emit_feature_records(out: &mut Vec<u8>, feat: &MercFeatures) {
    out.extend_from_slice(&REC_PROLOG);
    if feat.extra_exit {
        out.extend_from_slice(&REC_EXTRA_EXIT);
    }
    let total_params = feat.used_params + feat.used_scalar_params;
    if total_params > 0 {
        for _ in 0..feat.used_params {
            out.extend_from_slice(&REC_PARAM_DESC);
        }
        if feat.bar_count > 0 {
            out.extend_from_slice(&REC_BAR);
        }
        out.extend_from_slice(&REC_CBANK);
        for _ in 0..feat.used_scalar_params {
            out.extend_from_slice(&REC_SCALAR_PARAM);
        }
        if feat.smem_static {
            out.extend_from_slice(&REC_SMEM);
        }
        for _ in 1..total_params {
            let mut alt = REC_PARAM_DESC;
            alt[8] = 0x03;
            alt[9] = 0x01;
            out.extend_from_slice(&alt);
        }
        for _ in 0..feat.n_stg {
            out.extend_from_slice(&REC_STG);
        }
        for _ in 0..feat.n_atom {
            out.extend_from_slice(&REC_ATOM);
        }
        for _ in 1..feat.bar_count {
            out.extend_from_slice(&REC_BAR);
        }
    } else if feat.bar_count > 0 || feat.smem_static {
        for _ in 0..feat.bar_count {
            out.extend_from_slice(&REC_BAR);
        }
        if feat.smem_static {
            out.extend_from_slice(&REC_SMEM);
        }
    }
}

/// Grammar-v1 generator with measured per-feature record emission.
/// Used by cubit's Mercury build path when no external stub is provided.
pub fn generate_mercury_full(
    code: &[u8],
    kernel_id: u32,
    opcodes: Option<&[String]>,
    meta: &KernelMeta,
) -> Vec<u8> {
    use crate::mercury::{opcode_tracked_hint, tail_for_instr_count};
    let n_instr = code.len() / 16;
    let is_nop = |i: usize| {
        if let Some(ops) = opcodes {
            if i < ops.len() {
                return ops[i] == "NOP";
            }
        }
        let w = &code[i * 16..i * 16 + 2];
        w[0] == 0x18 && w[1] == 0x79
    };
    let mut bitmap: Vec<u32> = Vec::new();
    let mut cur = 0u32;
    let mut b_index = 0usize;
    for i in 0..n_instr {
        if is_nop(i) {
            continue;
        }
        let tracked = match opcodes {
            Some(ops) if i < ops.len() => opcode_tracked_hint(&ops[i]),
            _ => true,
        };
        if tracked {
            cur |= 1u32 << (b_index % 32);
        }
        b_index += 1;
        if b_index % 32 == 0 {
            bitmap.push(cur);
            cur = 0;
        }
    }
    if b_index % 32 != 0 {
        bitmap.push(cur);
    }
    let n_nonnop = b_index as u32;

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&kernel_id.to_le_bytes());
    buf.extend_from_slice(&crate::mercury::CAPMERC_MAGIC.to_le_bytes());
    buf.extend_from_slice(&n_nonnop.to_le_bytes());
    for w in &bitmap {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let feat = match opcodes {
        Some(ops) => MercFeatures::from_parts(meta, ops),
        None => MercFeatures::default(),
    };
    emit_feature_records(&mut buf, &feat);
    buf.extend_from_slice(&tail_for_instr_count(n_nonnop).to_le_bytes());
    buf
}

/// Mercury section generator (CUDA 13.x wire format, empirical 2026-08):
/// header {ordinal, 0xC0000001, B=#non-NOP}, bitmap ceil(B/32)*4
/// (bit = instruction tracked by scoreboard/replay, by opcode class),
/// capability records (descriptor shim, constant bank, global store,
/// write-back), tail = f(B).
///
/// `opcodes`: optional base mnemonics per instruction (e.g. "LDG", "IADD3");
/// when absent, NOPs are detected by the sm_100/103 NOP prefix 0x7918 and all
/// non-NOP instructions are marked tracked.
pub fn generate_mercury_with_ops(
    code: &[u8],
    kernel_id: u32,
    opcodes: Option<&[String]>,
) -> Vec<u8> {
    use crate::mercury::{opcode_tracked_hint, tail_for_instr_count};
    let n_instr = code.len() / 16;
    let is_nop = |i: usize| {
        if let Some(ops) = opcodes {
            if i < ops.len() {
                return ops[i] == "NOP";
            }
        }
        let w = &code[i * 16..i * 16 + 2];
        w[0] == 0x18 && w[1] == 0x79
    };
    let tracked: Vec<bool> = (0..n_instr)
        .map(|i| {
            if is_nop(i) {
                return false;
            }
            match opcodes {
                Some(ops) if i < ops.len() => opcode_tracked_hint(&ops[i]),
                _ => true,
            }
        })
        .collect();
    // Non-NOP index space: bit i corresponds to i-th non-NOP instruction.
    let mut bitmap_bits: Vec<u8> = Vec::new();
    let mut cur = 0u32;
    let mut cur_bits = 0u8;
    let mut b_index = 0usize;
    for i in 0..n_instr {
        if is_nop(i) {
            continue;
        }
        if tracked[i] {
            cur |= 1u32 << (b_index % 32);
        }
        b_index += 1;
        cur_bits += 1;
        if b_index % 32 == 0 {
            bitmap_bits.extend_from_slice(&cur.to_le_bytes());
            cur = 0;
        }
    }
    if b_index % 32 != 0 {
        bitmap_bits.extend_from_slice(&cur.to_le_bytes());
    }
    let n_nonnop = b_index as u32;

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&kernel_id.to_le_bytes());
    buf.extend_from_slice(&crate::mercury::CAPMERC_MAGIC.to_le_bytes());
    buf.extend_from_slice(&n_nonnop.to_le_bytes());
    buf.extend_from_slice(&bitmap_bits);

    // Capability records (load-bearing for descriptor addressing, LDG/STG path):
    buf.extend_from_slice(&[
        0x01, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x04, 0x00,
        0x00,
    ]);
    buf.extend_from_slice(&[
        0x01, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
        0x00,
    ]);
    buf.extend_from_slice(&[
        0x01, 0x0b, 0x0e, 0x0a, 0xfa, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x39, 0x04, 0x00,
        0x00,
    ]);
    buf.extend_from_slice(&[
        0x02, 0x22, 0x0e, 0x06, 0xf8, 0x00, 0x52, 0x00, 0x00, 0x00, 0x83, 0x00, 0x40, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    buf.extend_from_slice(&[
        0x02, 0x38, 0x0e, 0x32, 0xf8, 0x00, 0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x0a,
        0x00, 0x00, 0x02, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    buf.extend_from_slice(&tail_for_instr_count(n_nonnop).to_le_bytes());
    buf
}

// ── public API ────────────────────────────────────────────────────────────────

/// A kernel to be assembled into the cubin.
pub struct KernelEntry {
    pub name: String,
    /// Encoded instruction bytes (16 bytes per instruction).
    pub code: Vec<u8>,
    /// Metadata from parse_cubin_metadata or synthesised from directives.
    pub meta: KernelMeta,
    /// Optional custom Mercury stub (overrides CAPMERC_EXIT_STUB).
    /// Load from an existing cubin's .nv.capmerc.text.* section.
    pub mercury_stub: Option<Vec<u8>>,
    /// Base opcodes per instruction (for Mercury bitmap fidelity).
    pub opcodes: Option<Vec<String>>,
}

/// Build a standalone cubin ELF from a list of kernel entries.
///
/// Uses the Mercury-free layout (8+3N sections).  This is the default because
/// the hardcoded Mercury EXIT stub does not describe QMMA / tensor-core
/// resources, causing the driver to misconfigure register-file mapping —
/// LDG data never reaches QMMA operand registers (Bug 4).
///
/// Without Mercury the driver falls back to analysing the real `.text`
/// section for resource requirements, which works correctly for all
/// instruction types including QMMA.
///
/// For kernels that require descriptor-based addressing (`LDG.E desc[]`),
/// use [`build_cubin_mercury`] with a Mercury stub captured from an
/// nvcc-compiled cubin of the same kernel shape.
pub fn build_cubin(kernels: &[KernelEntry]) -> Result<Vec<u8>> {
    CubinBuilder::new().build_no_mercury(kernels)
}

/// `build_cubin` with explicit target e_flags (e.g. SM103a on B300).
pub fn build_cubin_for_arch(kernels: &[KernelEntry], ef_flags: u32) -> Result<Vec<u8>> {
    CubinBuilder::new()
        .with_ef_flags(ef_flags)
        .build_no_mercury(kernels)
}

/// Build a standalone cubin with Mercury sections.
///
/// Only use this when you have a correct Mercury stub (via
/// `KernelEntry::mercury_stub`) captured from an nvcc cubin that uses
/// the same instruction mix (LDG, QMMA, etc.) as your SASS kernel.
/// The default `CAPMERC_EXIT_STUB` only covers simple STG.E kernels.
pub fn build_cubin_mercury(kernels: &[KernelEntry]) -> Result<Vec<u8>> {
    CubinBuilder::new().build(kernels)
}

/// `build_cubin_mercury` with explicit target e_flags.
pub fn build_cubin_mercury_for_arch(kernels: &[KernelEntry], ef_flags: u32) -> Result<Vec<u8>> {
    CubinBuilder::new().with_ef_flags(ef_flags).build(kernels)
}

/// One patch for [`rebuild_cubin`]: `(kernel name, encoded SASS bytes, optional Mercury stub)`.
pub type CubinPatch<'a> = (&'a str, Vec<u8>, Option<Vec<u8>>);

/// Rebuild an existing cubin by patching .text sections in-place.
///
/// Patches are matched to template kernels by name. When names differ and both
/// the template and the patch list contain exactly one kernel, they are matched
/// by position and the template kernel is renamed in the output ELF.
pub fn rebuild_cubin(template_bytes: &[u8], patches: &[CubinPatch<'_>]) -> Result<Vec<u8>> {
    use crate::elf::CubinFile;
    let mut cubin = CubinFile::from_bytes(template_bytes.to_vec())?;
    let mut renames: Vec<(String, String)> = Vec::new();

    for sec_idx in 0..cubin.text_sections.len() {
        let sec_name = cubin.text_sections[sec_idx].0.clone();
        let kernel_name = sec_name.strip_prefix(".text.").unwrap_or(&sec_name);

        let matched = patches.iter().find(|(n, _, _)| *n == kernel_name);

        let (patch_name, patch_code, patch_merc) = if let Some((name, code, merc)) = matched {
            (*name, code.as_slice(), merc.as_deref())
        } else if cubin.text_sections.len() == 1 && patches.len() == 1 {
            (
                patches[0].0,
                patches[0].1.as_slice(),
                patches[0].2.as_deref(),
            )
        } else {
            continue;
        };

        let _orig_size = cubin.text_bytes(sec_idx)?.len();
        let mut code = patch_code.to_vec();
        let nop: [u8; 16] = [
            0x18, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
            0x0f, 0x00,
        ];
        // Target size: actual code aligned to 128 bytes (may be smaller than template)
        let aligned = code.len().div_ceil(128) * 128;
        let target_size = aligned;
        while code.len() + 16 <= target_size {
            code.extend_from_slice(&nop);
        }
        code.resize(target_size, 0);

        // Copy template scheduling for matching instructions (same lo-word).
        // This provides nvcc's battle-tested stall/barrier values for instructions
        // that happen to have the same opcode+operand encoding as the template.
        // NOP-padded slots are copied entirely.
        let orig_text = cubin.text_bytes(sec_idx)?.to_vec();
        for i in (0..code.len().min(orig_text.len())).step_by(16) {
            if i + 16 > code.len() || i + 16 > orig_text.len() {
                break;
            }
            let new_lo = u64::from_le_bytes(code[i..i + 8].try_into().unwrap());
            if new_lo == 0 && code[i + 8..i + 16] == [0u8; 8] {
                code[i..i + 16].copy_from_slice(&orig_text[i..i + 16]);
                continue;
            }
            let old_lo = u64::from_le_bytes(orig_text[i..i + 8].try_into().unwrap());
            if new_lo == old_lo {
                let new_hi = u64::from_le_bytes(code[i + 8..i + 16].try_into().unwrap());
                let old_hi = u64::from_le_bytes(orig_text[i + 8..i + 16].try_into().unwrap());
                let hi_sched_mask: u64 = 0x1FFFF << 41;
                let merged_hi = (new_hi & !hi_sched_mask) | (old_hi & hi_sched_mask);
                code[i + 8..i + 16].copy_from_slice(&merged_hi.to_le_bytes());
            }
        }

        // Always update regcount from the new code (template may have lower limit)
        {
            let max_reg = detect_max_register(&code);
            let regcount = ((max_reg + 32) & !31).max(32);
            patch_regcount_in_elf(&mut cubin.bytes, regcount);
        }

        cubin.patch_text(sec_idx, &code)?;

        // Patch Mercury section if stub provided
        if let Some(merc_data) = patch_merc {
            let merc_name = format!(".nv.capmerc.text.{}", patch_name);
            if let Some(merc_idx) = cubin.find_section(&merc_name) {
                cubin.patch_section(merc_idx, merc_data)?;
            } else {
                // Try matching by kernel name from template
                let merc_name2 = format!(".nv.capmerc.text.{}", kernel_name);
                if let Some(merc_idx) = cubin.find_section(&merc_name2) {
                    cubin.patch_section(merc_idx, merc_data)?;
                }
            }
        }

        if patch_name != kernel_name {
            renames.push((kernel_name.to_string(), patch_name.to_string()));
        }
    }

    for (old_name, new_name) in &renames {
        rename_kernel_in_elf(&mut cubin.bytes, old_name, new_name)?;
    }

    Ok(cubin.bytes)
}

/// Scan SASS instruction bytes for the highest-numbered GPR (R0..R254).
fn detect_max_register(code: &[u8]) -> u32 {
    let mut max_reg = 0u32;
    for i in (0..code.len()).step_by(16) {
        if i + 8 > code.len() {
            break;
        }
        // Heuristic: scan standard register positions.
        // Skip values >= 128 (likely non-register data — immediates, flags).
        // SM120 max practical register count is ~128 (256 regs / 2 hw reserved).
        let rd = code[i + 2] as u32;
        if rd < 128 && rd > max_reg {
            max_reg = rd;
        }
        let rs1 = code[i + 3] as u32;
        if rs1 < 128 && rs1 > max_reg {
            max_reg = rs1;
        }
        let rs2 = code[i + 4] as u32;
        if rs2 < 128 && rs2 > max_reg {
            max_reg = rs2;
        }
        if i + 9 <= code.len() {
            let rs3 = code[i + 8] as u32;
            if rs3 < 128 && rs3 > max_reg {
                max_reg = rs3;
            }
        }
    }
    max_reg
}

/// Patch REGCOUNT EIATTR records in the raw ELF bytes.
/// Finds SVAL attr=0x002f records in .nv.info sections and updates the regcount value.
fn patch_regcount_in_elf(bytes: &mut [u8], new_regcount: u32) {
    // EIATTR REGCOUNT format: [0x04][0x2f][size_lo=0x08][size_hi=0x00][sym4bytes][regcount4bytes]
    let pattern: [u8; 4] = [0x04, 0x2f, 0x08, 0x00];
    let rc_bytes = new_regcount.to_le_bytes();
    let mut i = 0;
    while i + 12 <= bytes.len() {
        if bytes[i..i + 4] == pattern {
            // Patch regcount at offset +8 (after 4-byte header + 4-byte sym)
            bytes[i + 8..i + 12].copy_from_slice(&rc_bytes);
            i += 12;
        } else {
            i += 1;
        }
    }
}

/// Rename a kernel in the raw ELF bytes (in-place replacement in string tables).
/// New name must be no longer than old name.
fn rename_kernel_in_elf(bytes: &mut [u8], old_name: &str, new_name: &str) -> Result<()> {
    if new_name.len() > old_name.len() {
        anyhow::bail!(
            "cannot rename kernel '{old_name}' → '{new_name}': \
             new name is longer ({} > {})",
            new_name.len(),
            old_name.len()
        );
    }

    let old_bytes = old_name.as_bytes();
    let mut replacement = new_name.as_bytes().to_vec();
    replacement.resize(old_bytes.len(), 0);

    let mut i = 0;
    while i + old_bytes.len() <= bytes.len() {
        if &bytes[i..i + old_bytes.len()] == old_bytes {
            let preceded_ok = i == 0 || bytes[i - 1] == 0 || bytes[i - 1] == b'.';
            let followed_ok = i + old_bytes.len() >= bytes.len() || bytes[i + old_bytes.len()] == 0;
            if preceded_ok && followed_ok {
                bytes[i..i + old_bytes.len()].copy_from_slice(&replacement);
                i += old_bytes.len();
                continue;
            }
        }
        i += 1;
    }

    Ok(())
}

// ── builder ───────────────────────────────────────────────────────────────────

struct CubinBuilder {
    shstrtab: StrTable,
    strtab: StrTable,
    ef_flags: u32,
}

struct StrTable {
    data: Vec<u8>,
}

impl StrTable {
    fn new() -> Self {
        Self { data: vec![0] }
    }
    /// Add a string; return its byte offset.
    fn add(&mut self, s: &str) -> u32 {
        let off = self.data.len() as u32;
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0);
        off
    }
    /// Find offset of an existing string (only works if already added).
    fn _find(&mut self, s: &str) -> u32 {
        let bytes = s.as_bytes();
        let mut i = 1usize;
        while i + bytes.len() < self.data.len() {
            if &self.data[i..i + bytes.len()] == bytes && self.data[i + bytes.len()] == 0 {
                return i as u32;
            }
            i += 1;
        }
        self.add(s)
    }
}

impl CubinBuilder {
    fn new() -> Self {
        Self {
            shstrtab: StrTable::new(),
            strtab: StrTable::new(),
            ef_flags: EF_CUDA_SM120,
        }
    }

    /// Target a non-default architecture (e.g. SM103a → e_flags 0x06006702).
    pub fn with_ef_flags(mut self, ef_flags: u32) -> Self {
        self.ef_flags = ef_flags;
        self
    }

    /// Build a cubin matching the 11-section layout proven on driver 570.211.
    ///
    /// Layout: NULL, .shstrtab, .strtab, .symtab, .note.nv.tkinfo, .note.nv.cuinfo,
    /// .nv.info, .nv.compat, .nv.info.K, .text.K, .nv.constant0.K
    #[allow(dead_code)]
    fn build_no_mercury(mut self, kernels: &[KernelEntry]) -> Result<Vec<u8>> {
        let n = kernels.len();

        // Section indices — exact match with working cubins (no debug_frame, callgraph, rela, shared)
        const IDX_SHSTR: usize = 1;
        const IDX_STRTAB: usize = 2;
        const IDX_SYMTAB: usize = 3;
        const IDX_TKINFO: usize = 4;
        let base = 8usize; // 0..7 fixed, 8+ per-kernel

        let idx_compat = base - 1; // 7
        let text_k = |ki: usize| base + n + ki; // 8+N .. 8+2N-1
                                                // .nv.shared.reserved.0 at 8+2N
        let idx_shared = base + 2 * n;
        // Per-kernel .nv.shared.<kernel> at 8+2N+1 .. 8+3N
        let shared_k = |ki: usize| base + 2 * n + 1 + ki;
        let const0_k = |ki: usize| base + 3 * n + 1 + ki; // shifted by N+1
        let total_sections = base + 4 * n + 1;

        // String tables — only sections that working cubins have
        let shn_shstrtab = self.shstrtab.add(".shstrtab");
        let shn_strtab = self.shstrtab.add(".strtab");
        let shn_symtab = self.shstrtab.add(".symtab");
        let shn_tkinfo = self.shstrtab.add(".note.nv.tkinfo");
        let shn_cuver = self.shstrtab.add(".note.nv.cuinfo");
        let shn_nv_info = self.shstrtab.add(".nv.info");
        let shn_compat = self.shstrtab.add(".nv.compat");

        let mut shn_nv_info_k = Vec::new();
        let mut shn_text_k = Vec::new();
        let mut shn_const0_k = Vec::new();
        let mut shn_shared_k: Vec<u32> = Vec::new();
        for k in kernels {
            shn_nv_info_k.push(self.shstrtab.add(&format!(".nv.info.{}", k.name)));
            shn_text_k.push(self.shstrtab.add(&format!(".text.{}", k.name)));
            shn_const0_k.push(self.shstrtab.add(&format!(".nv.constant0.{}", k.name)));
            shn_shared_k.push(self.shstrtab.add(&format!(".nv.shared.{}", k.name)));
        }
        let shn_shared = self.shstrtab.add(".nv.shared.reserved.0");

        // Compute max shared size for PT_LOAD RW memsz
        let max_shared: u64 = kernels
            .iter()
            .map(|k| k.meta.shared_size as u64)
            .max()
            .unwrap_or(0)
            .max(0x40);

        // Symtab layout matching working tungsten cubins:
        // [0]=null, [1]=.note.tkinfo, [2]=.note.cuver, [3..3+N-1]=.text.K section syms,
        // [3+N..3+2N-1]=func syms (GLOBAL), [3+2N..3+3N-1]=.nv.constant0 section syms,
        // [3+3N..3+4N-1]=.nv.shared.K section syms (for kernels with shared_size > 0)
        let first_global = (3 + n) as u32;
        let func_sym_idx = |ki: usize| 3 + n + ki;
        let const0_sym_idx = |ki: usize| 3 + 2 * n + ki;
        let _shared_sym_idx = |ki: usize| 3 + 3 * n + ki;

        let mut sn_funcs = Vec::new();
        for k in kernels {
            sn_funcs.push(self.strtab.add(&k.name));
        }
        let mut sn_const0 = Vec::new();
        for k in kernels {
            sn_const0.push(self.strtab.add(&format!(".nv.constant0.{}", k.name)));
        }
        let mut sn_shared = Vec::new();
        for k in kernels {
            sn_shared.push(self.strtab.add(&format!(".nv.shared.{}", k.name)));
        }

        // Build EIATTR data
        let global_info_data: Vec<u8> = {
            use crate::eiattr::{EiFmt, EiRecord, NvInfoSection};
            let mut records = Vec::new();
            for (ki, k) in kernels.iter().enumerate() {
                let sym = func_sym_idx(ki) as u32;
                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.regcount.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x002f,
                    fmt: EiFmt::Sized,
                    data: d,
                });
                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.frame_size.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x0011,
                    fmt: EiFmt::Sized,
                    data: d,
                });
                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.min_stack_size.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x0012,
                    fmt: EiFmt::Sized,
                    data: d,
                });
            }
            NvInfoSection {
                name: ".nv.info".into(),
                records,
            }
            .to_bytes()
        };

        let mut per_kernel_info = Vec::new();
        for (ki, k) in kernels.iter().enumerate() {
            let sym = func_sym_idx(ki) as u32;
            let csym = const0_sym_idx(ki) as u32;
            let data = k.meta.to_kernel_records_with_sym_and_const(sym, csym);
            per_kernel_info.push(data.to_bytes());
        }

        let mut const0_data = Vec::new();
        for k in kernels {
            let min_size = 0x380
                + k.meta
                    .params
                    .iter()
                    .map(|p| (p.offset + p.size) as usize)
                    .max()
                    .unwrap_or(0);
            const0_data.push(vec![0u8; min_size.div_ceil(4) * 4]);
        }

        // Pad text to 128B alignment
        let nop: &[u8] = &[
            0x18, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
            0x0f, 0x00,
        ];
        let bra_self: &[u8] = &[
            0x47, 0x79, 0xfc, 0x00, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0x83, 0x03, 0x00, 0xc0,
            0x0f, 0x00,
        ];
        let mut text_data = Vec::new();
        for k in kernels {
            let mut code = k.code.clone();
            let aligned = code.len().div_ceil(128) * 128;
            while code.len() < aligned {
                if code.len() + 16 == aligned {
                    code.extend_from_slice(bra_self);
                } else {
                    code.extend_from_slice(nop);
                }
            }
            text_data.push(code);
        }

        // Build symtab bytes — matching working tungsten cubins:
        // [0]=null, [1..N]=note section syms, [N+1..2N]=.text.K, [2N+1..3N]=func GLOBAL, [3N+1..4N]=const0
        let mut symtab = vec![0u8; 24]; // null
        macro_rules! sym {
            ($name:expr, $val:expr, $size:expr, $info:expr, $other:expr, $shndx:expr) => {{
                let mut s = vec![0u8; 24];
                s[0..4].copy_from_slice(&($name as u32).to_le_bytes());
                s[4] = $info;
                s[5] = $other;
                s[6..8].copy_from_slice(&($shndx as u16).to_le_bytes());
                s[8..16].copy_from_slice(&($val as u64).to_le_bytes());
                s[16..24].copy_from_slice(&($size as u64).to_le_bytes());
                symtab.extend_from_slice(&s);
            }};
        }
        // locals: note section syms (tkinfo, cuver)
        sym!(0, 0, 0, 0x03, 0, IDX_TKINFO);
        sym!(0, 0, 0, 0x03, 0, IDX_TKINFO + 1);
        // locals: .text.K section syms
        for ki in 0..n {
            sym!(0, 0, 0, 0x03, 0, text_k(ki));
        }
        // GLOBAL: kernel function syms
        for ki in 0..n {
            sym!(
                sn_funcs[ki],
                0u64,
                text_data[ki].len() as u64,
                0x12,
                0x10,
                text_k(ki)
            );
        }
        // locals: .nv.constant0.K section syms
        for (ki, sn) in sn_const0.iter().enumerate() {
            sym!(*sn, 0u64, 0u64, 0x03, 0, const0_k(ki));
        }
        // locals: .nv.shared.K section syms (for kernels with shared_size > 0)
        for ki in 0..n {
            sym!(sn_shared[ki], 0u64, 0u64, 0x03, 0, shared_k(ki));
        }

        // Assemble sections in working cubin order
        type Sec = (u32, u32, u64, Vec<u8>, u64, u32, u32, u64);
        let mut sections: Vec<Sec> = Vec::new();
        macro_rules! sec {
            ($n:expr,$t:expr,$f:expr,$d:expr,$a:expr,$l:expr,$i:expr,$e:expr) => {
                sections.push(($n, $t, $f, $d, $a, $l, $i, $e));
            };
        }

        sec!(0, 0, 0, vec![], 1, 0, 0, 0); // 0: NULL
        sec!(
            shn_shstrtab,
            SHT_STRTAB,
            0,
            self.shstrtab.data.clone(),
            1,
            0,
            0,
            0
        );
        sec!(
            shn_strtab,
            SHT_STRTAB,
            0,
            self.strtab.data.clone(),
            1,
            0,
            0,
            0
        );
        sec!(
            shn_symtab,
            SHT_SYMTAB,
            0,
            symtab,
            8,
            IDX_STRTAB as u32,
            first_global,
            24
        );
        sec!(
            shn_tkinfo,
            SHT_NOTE,
            SHF_NV_TKINFO,
            TKINFO_BYTES.to_vec(),
            4,
            0,
            0,
            0
        );
        sec!(
            shn_cuver,
            SHT_NOTE,
            SHF_NV_CUVER,
            build_cuver_note(),
            4,
            IDX_TKINFO as u32,
            idx_compat as u32,
            0
        );
        sec!(
            shn_nv_info,
            SHT_CUDA_INFO,
            0,
            global_info_data,
            4,
            IDX_SYMTAB as u32,
            0,
            0
        );
        sec!(
            shn_compat,
            SHT_CUDA_COMPAT,
            0,
            NV_COMPAT.to_vec(),
            4,
            0,
            0,
            0
        );
        for ki in 0..n {
            sec!(
                shn_nv_info_k[ki],
                SHT_CUDA_INFO,
                SHF_INFO_LINK,
                per_kernel_info[ki].clone(),
                4,
                IDX_SYMTAB as u32,
                text_k(ki) as u32,
                0
            );
        }
        for ki in 0..n {
            sec!(
                shn_text_k[ki],
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                text_data[ki].clone(),
                128,
                IDX_SYMTAB as u32,
                func_sym_idx(ki) as u32,
                0
            );
        }
        // .nv.shared.reserved.0 — always 64 bytes minimum
        sections.push((
            shn_shared,
            SHT_NOBITS,
            SHF_WRITE | SHF_ALLOC,
            vec![],
            1,
            0,
            0,
            0,
        ));
        // Per-kernel .nv.shared.<kernel> — actual shared memory size
        // sh_info = text section index (via SHF_INFO_LINK), sh_link = 0 (matches nvcc)
        for ki in 0..n {
            let flags = SHF_WRITE | SHF_ALLOC | SHF_INFO_LINK;
            sections.push((
                shn_shared_k[ki],
                SHT_NOBITS,
                flags,
                vec![],
                4,
                0,
                text_k(ki) as u32,
                0,
            ));
        }
        for ki in 0..n {
            sec!(
                shn_const0_k[ki],
                SHT_PROGBITS,
                SHF_ALLOC | SHF_INFO_LINK,
                const0_data[ki].clone(),
                4,
                0,
                text_k(ki) as u32,
                0
            );
        }

        assert_eq!(sections.len(), total_sections);

        // Program headers: placed right after ELF header (offset 0x40).
        // Layout: PHDR(self) + LOAD(text) + LOAD(notes) + LOAD(const0)
        // Matches working tungsten cubins (4 segments for 1 kernel).
        let n_phdrs: u16 = (1 + n + 1 + 1 + n) as u16; // +1 for shared RW
        let ph_offset: u64 = 64; // right after ELF header
        let ph_table_size = (n_phdrs as u64) * 56;

        // Section data starts after program headers
        let mut offset = ph_offset + ph_table_size;
        if !offset.is_multiple_of(4) {
            offset += 4 - (offset % 4);
        }
        let mut sec_offsets = Vec::new();
        for (i, (_, sh_type, _, data, align, _, _, _)) in sections.iter().enumerate() {
            if i == 0 {
                sec_offsets.push(0);
                continue;
            } // NULL section at offset 0
            if *sh_type == SHT_NOBITS {
                sec_offsets.push(offset);
                continue;
            }
            if *align > 1 && !offset.is_multiple_of(*align) {
                offset += *align - (offset % *align);
            }
            sec_offsets.push(offset);
            offset += data.len() as u64;
        }
        if !offset.is_multiple_of(8) {
            offset += 8 - (offset % 8);
        }
        let sh_offset = offset;
        let sh_table_size = (total_sections as u64) * 64;

        let ef_flags = self.ef_flags;
        let total_file_size = (sh_offset + sh_table_size) as usize;
        let mut buf = vec![0u8; total_file_size];
        write_elf_header_flags(
            &mut buf,
            sh_offset,
            total_sections as u16,
            IDX_SHSTR as u16,
            ph_offset,
            n_phdrs,
            ef_flags,
        );

        // Write section data
        for (i, (_, sh_type, _, data, _, _, _, _)) in sections.iter().enumerate() {
            if *sh_type == SHT_NOBITS || data.is_empty() {
                continue;
            }
            let off = sec_offsets[i] as usize;
            buf[off..off + data.len()].copy_from_slice(data);
        }

        // Write section headers
        for (i, (sh_name, sh_type, sh_flags, data, sh_align, sh_link, sh_info, sh_entsize)) in
            sections.iter().enumerate()
        {
            let o = (sh_offset + (i as u64) * 64) as usize;
            let sz = if *sh_type == SHT_NOBITS {
                // Check if this is a per-kernel shared section or reserved.0
                let sec_idx_in_file = i;
                if sec_idx_in_file == idx_shared {
                    0x40u64 // .nv.shared.reserved.0 = 64 bytes
                } else {
                    // Per-kernel .nv.shared.<kernel> — find which kernel
                    let mut found_sz = 0x40u64;
                    for ki in 0..n {
                        if sec_idx_in_file == shared_k(ki) {
                            found_sz = (kernels[ki].meta.shared_size as u64).max(0x40);
                            break;
                        }
                    }
                    found_sz
                }
            } else {
                data.len() as u64
            };
            buf[o..o + 4].copy_from_slice(&sh_name.to_le_bytes());
            buf[o + 4..o + 8].copy_from_slice(&sh_type.to_le_bytes());
            buf[o + 8..o + 16].copy_from_slice(&sh_flags.to_le_bytes());
            buf[o + 24..o + 32].copy_from_slice(&sec_offsets[i].to_le_bytes());
            buf[o + 32..o + 40].copy_from_slice(&sz.to_le_bytes());
            buf[o + 40..o + 44].copy_from_slice(&sh_link.to_le_bytes());
            buf[o + 44..o + 48].copy_from_slice(&sh_info.to_le_bytes());
            buf[o + 48..o + 56].copy_from_slice(&sh_align.to_le_bytes());
            buf[o + 56..o + 64].copy_from_slice(&sh_entsize.to_le_bytes());
        }

        // Write program headers (matching working tungsten cubins)
        let mut phi = 0usize;
        let write_ph = |buf: &mut Vec<u8>,
                        phi: usize,
                        p_type: u32,
                        p_flags: u32,
                        p_offset: u64,
                        p_filesz: u64,
                        p_memsz: u64,
                        p_align: u64| {
            let o = ph_offset as usize + phi * 56;
            buf[o..o + 4].copy_from_slice(&p_type.to_le_bytes());
            buf[o + 4..o + 8].copy_from_slice(&p_flags.to_le_bytes());
            buf[o + 8..o + 16].copy_from_slice(&p_offset.to_le_bytes());
            // p_vaddr = 0, p_paddr = 0
            buf[o + 32..o + 40].copy_from_slice(&p_filesz.to_le_bytes());
            buf[o + 40..o + 48].copy_from_slice(&p_memsz.to_le_bytes());
            buf[o + 48..o + 56].copy_from_slice(&p_align.to_le_bytes());
        };

        const PT_PHDR: u32 = 6;
        const PT_LOAD: u32 = 1;
        const PF_R: u32 = 4;
        const PF_X: u32 = 1;
        const PF_W: u32 = 2;

        // PHDR: points to the program header table itself
        write_ph(
            &mut buf,
            phi,
            PT_PHDR,
            PF_R,
            ph_offset,
            ph_table_size,
            ph_table_size,
            8,
        );
        phi += 1;

        // PT_LOAD for each .text.K
        for ki in 0..n {
            let t_off = sec_offsets[text_k(ki)];
            let t_sz = text_data[ki].len() as u64;
            write_ph(&mut buf, phi, PT_LOAD, PF_R | PF_X, t_off, t_sz, t_sz, 8);
            phi += 1;
        }

        // PT_LOAD for notes (tkinfo + cuver + nv.info + compat)
        let notes_start = sec_offsets[IDX_TKINFO];
        let notes_end = sec_offsets[idx_compat] + sections[idx_compat].3.len() as u64;
        write_ph(
            &mut buf,
            phi,
            PT_LOAD,
            PF_R,
            notes_start,
            notes_end - notes_start,
            notes_end - notes_start,
            8,
        );
        phi += 1;

        // PT_LOAD RW for shared memory (NOBITS)
        {
            let shared_off = sec_offsets[idx_shared];
            write_ph(
                &mut buf,
                phi,
                PT_LOAD,
                PF_R | PF_W,
                shared_off,
                0,
                max_shared,
                8,
            );
            phi += 1;
        }

        // PT_LOAD for each .nv.constant0.K
        for ki in 0..n {
            let c_off = sec_offsets[const0_k(ki)];
            let c_sz = const0_data[ki].len() as u64;
            write_ph(&mut buf, phi, PT_LOAD, PF_R, c_off, c_sz, c_sz, 8);
            phi += 1;
        }

        Ok(buf)
    }

    #[allow(clippy::needless_range_loop)]
    fn build(mut self, kernels: &[KernelEntry]) -> Result<Vec<u8>> {
        let n = kernels.len();
        // Compute shared memory size: max of 0x40 (minimum) and all kernels' shared_size
        let max_shared: u64 = kernels
            .iter()
            .map(|k| k.meta.shared_size as u64)
            .max()
            .unwrap_or(0)
            .max(0x40);
        // ── Pre-compute section indices ───────────────────────────────────
        // Fixed headers
        const IDX_SHSTR: usize = 1;
        const IDX_STRTAB: usize = 2;
        const IDX_SYMTAB: usize = 3;
        const IDX_DBG: usize = 4;
        const IDX_TKINFO: usize = 5;
        let base = 8usize; // first per-kernel slot

        // Per-kernel: .nv.info.K
        let _nv_info_k = |ki: usize| base + ki;
        // Fixed after info
        let idx_compat = base + n;
        let idx_cg = base + n + 1;
        let _idx_rela_dbg = base + n + 2;
        // Per-kernel: .text.K
        let text_k = |ki: usize| base + n + 3 + ki;
        // Shared reservation
        let idx_shared = base + 2 * n + 3;
        // Per-kernel: .nv.shared.<kernel>
        let shared_k = |ki: usize| base + 2 * n + 4 + ki;
        // Per-kernel: .nv.constant0.K
        let const0_k = |ki: usize| base + 3 * n + 4 + ki;
        // Per-kernel: .nv.capmerc.text.K
        let capmerc_k = |ki: usize| base + 4 * n + 4 + ki;
        // Fixed Mercury
        let idx_merc_dbg = base + 5 * n + 4;
        let _idx_merc_info = base + 5 * n + 5;
        // Per-kernel: .nv.merc.nv.info.K
        let _merc_info_k = |ki: usize| base + 5 * n + 6 + ki;
        // Fixed Mercury (rest)
        let _idx_merc_rela = base + 6 * n + 6;
        let idx_merc_shared = base + 6 * n + 7;
        let idx_merc_symtab = base + 6 * n + 8;
        let total_sections = base + 6 * n + 9;

        // ── Build string tables & symbol tables ───────────────────────────
        // Populate shstrtab with all section names in order.
        // We reserve names first so offsets are stable.
        // (StrTable::add returns offset and won't deduplicate; use find later.)

        // Reserve standard shstrtab names
        let shn_shstrtab = self.shstrtab.add(".shstrtab");
        let shn_strtab = self.shstrtab.add(".strtab");
        let shn_symtab = self.shstrtab.add(".symtab");
        let shn_dbg = self.shstrtab.add(".debug_frame");
        let shn_tkinfo = self.shstrtab.add(".note.nv.tkinfo");
        let shn_cuver = self.shstrtab.add(".note.nv.cuinfo");
        let shn_nv_info = self.shstrtab.add(".nv.info");
        let shn_compat = self.shstrtab.add(".nv.compat");
        let shn_cg = self.shstrtab.add(".nv.callgraph");
        let shn_rela_dbg = self.shstrtab.add(".rela.debug_frame");
        let shn_shared = self.shstrtab.add(".nv.shared.reserved.0");
        let shn_merc_dbg = self.shstrtab.add(".nv.merc.debug_frame");
        let shn_merc_info = self.shstrtab.add(".nv.merc.nv.info");
        let shn_merc_rela = self.shstrtab.add(".nv.merc.rela.debug_frame");
        let shn_merc_sh = self.shstrtab.add(".nv.merc.nv.shared.reserved.0");
        let shn_merc_symt = self.shstrtab.add(".nv.merc.symtab");

        // Per-kernel shstrtab names
        let mut shn_nv_info_k: Vec<u32> = Vec::new();
        let mut shn_text_k: Vec<u32> = Vec::new();
        let mut shn_const0_k: Vec<u32> = Vec::new();
        let mut shn_capmerc_k: Vec<u32> = Vec::new();
        let mut shn_merc_info_k: Vec<u32> = Vec::new();
        let mut shn_shared_k: Vec<u32> = Vec::new();
        for k in kernels {
            shn_nv_info_k.push(self.shstrtab.add(&format!(".nv.info.{}", k.name)));
            shn_text_k.push(self.shstrtab.add(&format!(".text.{}", k.name)));
            shn_const0_k.push(self.shstrtab.add(&format!(".nv.constant0.{}", k.name)));
            shn_shared_k.push(self.shstrtab.add(&format!(".nv.shared.{}", k.name)));
            shn_capmerc_k.push(self.shstrtab.add(&format!(".nv.capmerc.text.{}", k.name)));
            shn_merc_info_k.push(self.shstrtab.add(&format!(".nv.merc.nv.info.{}", k.name)));
        }

        // ── Build symbol table ────────────────────────────────────────────
        // Symbol layout (N kernels):
        //   [0]       : null
        //   [1..N]    : .text.Ki section syms  (local)
        //   [N+1]     : .nv.reservedSmem.offset0  (WEAK, OBJECT, abs, val=0x40)
        //   [N+2]     : __nv_reservedSMEM_offset_0_alias  (WEAK, shndx=idx_shared)
        //   [N+3]     : .debug_frame section sym  (local)
        //   [N+4]     : .nv.callgraph section sym (local)
        //   [N+5+ki]  : kernel function syms  (GLOBAL) ← sh_info = N+5
        //   [2N+5+ki] : .nv.constant0.Ki section syms (local)
        // (no note section syms — nvcc doesn't emit them)

        let merc_sym_first_global = n + 5; // first GLOBAL in mercury symtab
        let reg_sym_first_global = n + 5; // first GLOBAL in regular symtab = func syms at [N+5+ki]
        let func_sym_idx = |ki: usize| n + 5 + ki;
        let const0_sym_idx = |ki: usize| 2 * n + 5 + ki;
        let _shared_sym_idx = |ki: usize| 3 * n + 5 + ki;
        let _total_syms = 4 * n + 5;

        // Strtab entries for symbol names
        let _stn_empty = 0u32; // null byte at offset 0
        let mut stn_text_k: Vec<u32> = Vec::new();
        let stn_reserved_smem = self.strtab.add(".nv.reservedSmem.offset0");
        let stn_smem_alias = self.strtab.add("__nv_reservedSMEM_offset_0_alias");
        let stn_debug_frame = self.strtab.add(".debug_frame");
        let stn_callgraph = self.strtab.add(".nv.callgraph");
        let mut stn_func_k: Vec<u32> = Vec::new();
        let mut stn_const0_k: Vec<u32> = Vec::new();
        for k in kernels {
            stn_text_k.push(self.strtab.add(&format!(".text.{}", k.name)));
            stn_func_k.push(self.strtab.add(&k.name));
            stn_const0_k.push(self.strtab.add(&format!(".nv.constant0.{}", k.name)));
        }

        // Build raw symtab bytes
        let mut symtab: Vec<u8> = Vec::new();
        // [0] null
        emit_sym(&mut symtab, 0, 0, 0, 0, 0, 0, 0);
        // NOTE: no section syms for .note.nv.tkinfo/.cuver (nvcc doesn't emit them)
        // [1..N] .text.Ki section syms
        for ki in 0..n {
            emit_sym(
                &mut symtab,
                stn_text_k[ki],
                STB_LOCAL,
                STT_SECTION,
                STV_DEFAULT,
                text_k(ki) as u16,
                0,
                0,
            );
        }
        // [N+1] .nv.reservedSmem.offset0 WEAK OBJECT abs
        emit_sym(
            &mut symtab,
            stn_reserved_smem,
            STB_WEAK,
            STT_OBJECT,
            STV_DEFAULT,
            0,
            max_shared,
            4,
        );
        // [N+2] __nv_reservedSMEM_offset_0_alias WEAK NOTYPE shared
        emit_sym(
            &mut symtab,
            stn_smem_alias,
            STB_WEAK,
            STT_NOTYPE,
            0xa0,
            idx_shared as u16,
            max_shared,
            0,
        );
        // [N+3] .debug_frame section sym
        emit_sym(
            &mut symtab,
            stn_debug_frame,
            STB_LOCAL,
            STT_SECTION,
            STV_DEFAULT,
            IDX_DBG as u16,
            0,
            0,
        );
        // [N+4] .nv.callgraph section sym
        emit_sym(
            &mut symtab,
            stn_callgraph,
            STB_LOCAL,
            STT_SECTION,
            STV_DEFAULT,
            idx_cg as u16,
            0,
            0,
        );
        // [N+5+ki] kernel function syms (GLOBAL, st_other=0x10 per nvcc SM120)
        for ki in 0..n {
            let code_size = kernels[ki].code.len() as u64;
            emit_sym(
                &mut symtab,
                stn_func_k[ki],
                STB_GLOBAL,
                STT_FUNC,
                STV_HIDDEN,
                text_k(ki) as u16,
                0,
                code_size,
            );
        }
        // [2N+5+ki] .nv.constant0.Ki section syms
        for ki in 0..n {
            emit_sym(
                &mut symtab,
                stn_const0_k[ki],
                STB_LOCAL,
                STT_SECTION,
                STV_DEFAULT,
                const0_k(ki) as u16,
                0,
                0,
            );
        }
        // [3N+5+ki] .nv.shared.Ki section syms (for kernels with shared_size > 0)
        // Note: we add strtab entries for shared section names
        let mut stn_shared_k: Vec<u32> = Vec::new();
        for k in kernels {
            stn_shared_k.push(self.strtab.add(&format!(".nv.shared.{}", k.name)));
        }
        for ki in 0..n {
            emit_sym(
                &mut symtab,
                stn_shared_k[ki],
                STB_LOCAL,
                STT_SECTION,
                STV_DEFAULT,
                shared_k(ki) as u16,
                0,
                0,
            );
        }

        // ── Build Mercury symtab ──────────────────────────────────────────
        // Same layout as regular symtab, but for Mercury sections:
        //   [0]      null
        //   [1..N]   .nv.capmerc.text.Ki section syms  (local)
        //   [N+1]    .nv.reservedSmem.offset0  (WEAK, same name offsets from regular strtab)
        //   [N+2]    __nv_reservedSMEM_offset_0_alias  (WEAK, shndx=idx_merc_shared)
        //   [N+3]    .nv.merc.debug_frame section sym
        //   [N+4]    .nv.callgraph section sym (references main section)
        //   [N+5+ki] kernel function syms  (GLOBAL, shndx=capmerc_k, other=STV_HIDDEN)

        // Strtab entries for Mercury-specific section names
        let mut stn_capmerc_k: Vec<u32> = Vec::new();
        let stn_merc_debug = self.strtab.add(".nv.merc.debug_frame");
        for k in kernels {
            stn_capmerc_k.push(self.strtab.add(&format!(".nv.capmerc.text.{}", k.name)));
        }

        let mut merc_symtab: Vec<u8> = Vec::new();
        // [0] null
        emit_sym(&mut merc_symtab, 0, 0, 0, 0, 0, 0, 0); // null
                                                         // [1..N] capmerc section syms
        for ki in 0..n {
            emit_sym(
                &mut merc_symtab,
                stn_capmerc_k[ki],
                STB_LOCAL,
                STT_SECTION,
                STV_DEFAULT,
                capmerc_k(ki) as u16,
                0,
                0,
            );
        }
        // [N+1] .nv.reservedSmem.offset0 WEAK OBJECT abs
        emit_sym(
            &mut merc_symtab,
            stn_reserved_smem,
            STB_WEAK,
            STT_OBJECT,
            STV_DEFAULT,
            0,
            max_shared,
            4,
        );
        // [N+2] __nv_reservedSMEM_offset_0_alias WEAK NOTYPE merc_shared
        emit_sym(
            &mut merc_symtab,
            stn_smem_alias,
            STB_WEAK,
            STT_NOTYPE,
            0xa0,
            idx_merc_shared as u16,
            max_shared,
            0,
        );
        // [N+3] .nv.merc.debug_frame section sym
        emit_sym(
            &mut merc_symtab,
            stn_merc_debug,
            STB_LOCAL,
            STT_SECTION,
            STV_DEFAULT,
            idx_merc_dbg as u16,
            0,
            0,
        );
        // [N+4] .nv.callgraph section sym (references main callgraph)
        emit_sym(
            &mut merc_symtab,
            stn_callgraph,
            STB_LOCAL,
            STT_SECTION,
            STV_DEFAULT,
            idx_cg as u16,
            0,
            0,
        );
        // [N+5+ki] Mercury kernel function syms (GLOBAL, STV_HIDDEN)
        for ki in 0..n {
            let stub_sz = kernels[ki]
                .mercury_stub
                .as_ref()
                .map(|s| s.len() as u64)
                .unwrap_or(CAPMERC_STUB_PADDED);
            emit_sym(
                &mut merc_symtab,
                stn_func_k[ki],
                STB_GLOBAL,
                STT_FUNC,
                STV_HIDDEN,
                capmerc_k(ki) as u16,
                0,
                stub_sz,
            );
        }

        // ── Build section data ────────────────────────────────────────────
        // Section data for .nv.info (global): REGCOUNT, FRAME_SIZE, MIN_STACK_SIZE
        let global_info_data: Vec<u8> = {
            use crate::eiattr::{EiFmt, EiRecord, NvInfoSection};
            let mut records: Vec<EiRecord> = Vec::new();
            for ki in 0..n {
                let k = &kernels[ki];
                let sym = func_sym_idx(ki) as u32;
                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.regcount.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x002f,
                    fmt: EiFmt::Sized,
                    data: d,
                });

                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.frame_size.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x0011,
                    fmt: EiFmt::Sized,
                    data: d,
                });

                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.min_stack_size.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x0012,
                    fmt: EiFmt::Sized,
                    data: d,
                });
            }
            NvInfoSection {
                name: ".nv.info".into(),
                records,
            }
            .to_bytes()
        };

        // Per-kernel .nv.info.K
        let mut per_kernel_info: Vec<Vec<u8>> = Vec::new();
        for ki in 0..n {
            let k = &kernels[ki];
            let sym = func_sym_idx(ki) as u32;
            let const_sym = const0_sym_idx(ki) as u32;
            let data = k.meta.to_kernel_records_with_sym_and_const(sym, const_sym);
            per_kernel_info.push(data.to_bytes());
        }

        // Per-kernel .nv.merc.nv.info.K (Mercury EIATTR with hash)
        let merc_func_sym_idx = |ki: usize| n + 5 + ki; // same offset as regular
        let mut merc_per_kernel_info: Vec<Vec<u8>> = Vec::new();
        for ki in 0..n {
            let k = &kernels[ki];
            let sym = merc_func_sym_idx(ki) as u32;
            let data = build_merc_nv_info_k(&k.meta, sym);
            merc_per_kernel_info.push(data);
        }

        // .nv.merc.nv.info (global) — same as .nv.info but references merc sym
        let merc_global_info: Vec<u8> = {
            use crate::eiattr::{EiFmt, EiRecord, NvInfoSection};
            let mut records = Vec::new();
            for ki in 0..n {
                let k = &kernels[ki];
                let sym = merc_func_sym_idx(ki) as u32;
                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.regcount.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x002f,
                    fmt: EiFmt::Sized,
                    data: d,
                });

                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.frame_size.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x0011,
                    fmt: EiFmt::Sized,
                    data: d,
                });

                let mut d = sym.to_le_bytes().to_vec();
                d.extend_from_slice(&k.meta.min_stack_size.to_le_bytes());
                records.push(EiRecord {
                    attr: 0x0012,
                    fmt: EiFmt::Sized,
                    data: d,
                });
            }
            NvInfoSection {
                name: ".nv.merc.nv.info".into(),
                records,
            }
            .to_bytes()
        };

        // Per-kernel .nv.constant0.K — minimum 0x388 bytes to match nvcc 12.8 SM120
        let mut const0_data: Vec<Vec<u8>> = Vec::new();
        for k in kernels {
            // Parameters start at offset 0x380 in cbank0.
            // The section must cover bytes 0x0 .. 0x380 + total_param_bytes.
            // Minimum cbank size 0x3A0 (928B) to ensure COMPAT descriptor space at 0x358.
            let cbank_size = (0x380usize + k.meta.cbank_param_size as usize).max(0x3A0);
            const0_data.push(vec![0u8; pad_to(cbank_size, 4)]);
        }

        // .nv.merc.rela.debug_frame: one entry per kernel, referencing merc func sym
        let merc_rela_data: Vec<u8> = {
            let mut out = Vec::new();
            for ki in 0..n {
                let sym = merc_func_sym_idx(ki) as u64;
                out.extend_from_slice(&0x44u64.to_le_bytes()); // r_offset
                let r_info = (sym << 32) | 0x0001_003d_u64;
                out.extend_from_slice(&r_info.to_le_bytes());
                out.extend_from_slice(&0u64.to_le_bytes()); // r_addend
            }
            out
        };

        // ── Assemble ELF ──────────────────────────────────────────────────
        // Collect section records:
        // Each entry: (name_off, type, flags, data, align, link, info, entsize, nobits_size)

        type SecSpec = (u32, u32, u64, Vec<u8>, u64, u32, u32, u64, Option<u64>);

        let mut secs: Vec<SecSpec> = Vec::new();

        // Helper to push a section spec
        macro_rules! sec {
            ($name:expr, $ty:expr, $fl:expr, $data:expr, $al:expr, $lk:expr, $inf:expr, $es:expr) => {
                secs.push(($name, $ty, $fl, $data, $al, $lk, $inf, $es, None));
            };
            ($name:expr, $ty:expr, $fl:expr, $data:expr, $al:expr, $lk:expr, $inf:expr, $es:expr, nobits($sz:expr)) => {
                secs.push(($name, $ty, $fl, Vec::new(), $al, $lk, $inf, $es, Some($sz)));
            };
        }

        // Fixed sections 4-7
        sec!(shn_dbg, SHT_PROGBITS, 0, vec![], 1, 0, 0, 0); // 4: .debug_frame
        sec!(
            shn_tkinfo,
            SHT_NOTE,
            SHF_NV_TKINFO,
            TKINFO_BYTES.to_vec(),
            4,
            0,
            0,
            0
        ); // 5
           // 6: .note.nv.cuinfo
        let cuver_data = build_cuver_note();
        sec!(
            shn_cuver,
            SHT_NOTE,
            SHF_NV_CUVER,
            cuver_data,
            4,
            IDX_TKINFO as u32, // sh_link → .note.nv.tkinfo
            idx_compat as u32, // sh_info → .nv.compat
            0
        );
        // 7: .nv.info
        sec!(
            shn_nv_info,
            SHT_CUDA_INFO,
            0,
            global_info_data.clone(),
            4,
            IDX_SYMTAB as u32,
            0,
            0
        );

        // Per-kernel .nv.info.K (8..8+N)
        for ki in 0..n {
            sec!(
                shn_nv_info_k[ki],
                SHT_CUDA_INFO,
                SHF_INFO_LINK,
                per_kernel_info[ki].clone(),
                4,
                IDX_SYMTAB as u32,
                text_k(ki) as u32,
                0
            );
        }

        // .nv.compat, .nv.callgraph, .rela.debug_frame
        sec!(
            shn_compat,
            SHT_CUDA_COMPAT,
            0,
            NV_COMPAT.to_vec(),
            4,
            0,
            0,
            0
        );
        sec!(
            shn_cg,
            SHT_CUDA_CALLGRAPH,
            0,
            NV_CALLGRAPH.to_vec(),
            4,
            IDX_SYMTAB as u32,
            0,
            8
        );
        sec!(
            shn_rela_dbg,
            SHT_RELA,
            SHF_INFO_LINK,
            vec![],
            8,
            IDX_SYMTAB as u32,
            IDX_DBG as u32,
            24
        );

        // Per-kernel .text.K
        for ki in 0..n {
            sec!(
                shn_text_k[ki],
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                kernels[ki].code.clone(),
                128,
                IDX_SYMTAB as u32,
                func_sym_idx(ki) as u32,
                0
            );
        }

        // .nv.shared.reserved.0 (NOBITS, always 64 bytes minimum)
        sec!(
            shn_shared,
            SHT_NOBITS,
            SHF_WRITE | SHF_ALLOC,
            vec![],
            1,
            0,
            0,
            0,
            nobits(0x40)
        );

        // Per-kernel .nv.shared.<kernel> (NOBITS, actual shared memory size)
        // sh_info = text section index (via SHF_INFO_LINK), sh_link = 0 (matches nvcc)
        for ki in 0..n {
            let sh_size = kernels[ki].meta.shared_size as u64;
            if sh_size > 0 {
                secs.push((
                    shn_shared_k[ki],
                    SHT_NOBITS,
                    SHF_WRITE | SHF_ALLOC | SHF_INFO_LINK,
                    Vec::new(),
                    4,
                    0,
                    text_k(ki) as u32,
                    0,
                    Some(sh_size),
                ));
            } else {
                // Even if shared_size is 0, we still need the section for index consistency
                secs.push((
                    shn_shared_k[ki],
                    SHT_NOBITS,
                    SHF_WRITE | SHF_ALLOC | SHF_INFO_LINK,
                    Vec::new(),
                    4,
                    0,
                    text_k(ki) as u32,
                    0,
                    Some(0),
                ));
            }
        }

        // Per-kernel .nv.constant0.K
        for ki in 0..n {
            sec!(
                shn_const0_k[ki],
                SHT_PROGBITS,
                SHF_ALLOC | SHF_INFO_LINK,
                const0_data[ki].clone(),
                4,
                0,
                text_k(ki) as u32,
                0
            );
        }

        // Per-kernel .nv.capmerc.text.K
        for ki in 0..n {
            let stub_owned: Vec<u8>;
            let stub = if let Some(s) = kernels[ki].mercury_stub.as_deref() {
                s
            } else {
                stub_owned = generate_mercury_full(
                    &kernels[ki].code,
                    ki as u32 + 0x20,
                    kernels[ki].opcodes.as_deref(),
                    &kernels[ki].meta,
                );
                &stub_owned
            };
            sec!(
                shn_capmerc_k[ki],
                SHT_MERC_CAPMERC,
                SHF_MERC,
                stub.to_vec(),
                16,
                idx_merc_symtab as u32,
                (n + 5 + ki) as u32, // sh_info = Mercury func sym index
                0
            );
        }

        // .nv.merc.debug_frame
        sec!(
            shn_merc_dbg,
            SHT_PROGBITS,
            SHF_MERC,
            MERC_DEBUG_FRAME.to_vec(),
            1,
            0,
            0,
            0
        );
        // .nv.merc.nv.info
        sec!(
            shn_merc_info,
            SHT_MERC_INFO,
            SHF_MERC,
            merc_global_info,
            4,
            idx_merc_symtab as u32,
            0,
            0
        );

        // Per-kernel .nv.merc.nv.info.K
        for ki in 0..n {
            sec!(
                shn_merc_info_k[ki],
                SHT_MERC_INFO,
                SHF_MERC_LINK,
                merc_per_kernel_info[ki].clone(),
                4,
                idx_merc_symtab as u32,
                capmerc_k(ki) as u32,
                0
            );
        }

        // .nv.merc.rela.debug_frame
        sec!(
            shn_merc_rela,
            SHT_MERC_RELA,
            SHF_MERC_LINK,
            merc_rela_data,
            8,
            idx_merc_symtab as u32,
            idx_merc_dbg as u32,
            24
        );
        // .nv.merc.nv.shared.reserved.0 (NOBITS size=0)
        sec!(
            shn_merc_sh,
            SHT_MERC_RESERVED_SH,
            SHF_MERC | SHF_WRITE | SHF_ALLOC,
            vec![],
            1,
            0,
            0,
            0
        );
        // .nv.merc.symtab
        sec!(
            shn_merc_symt,
            SHT_MERC_SYMTAB,
            SHF_MERC,
            merc_symtab,
            8,
            IDX_STRTAB as u32, // sh_link = .strtab (regular)
            merc_sym_first_global as u32,
            24
        );

        assert_eq!(
            secs.len() + 4,
            total_sections,
            "section count mismatch: {} + 4 != {}",
            secs.len(),
            total_sections
        );

        // ── Write file ────────────────────────────────────────────────────
        let mut out: Vec<u8> = vec![0u8; 64]; // ELF header placeholder

        // 1. shstrtab
        let shstrtab_off = out.len() as u64;
        let shstrtab_data = self.shstrtab.data.clone();
        out.extend_from_slice(&shstrtab_data);

        // 2. strtab
        let strtab_off = out.len() as u64;
        let strtab_data = self.strtab.data.clone();
        out.extend_from_slice(&strtab_data);

        // 3. symtab (align 8)
        align_to(&mut out, 8);
        let symtab_off = out.len() as u64;
        out.extend_from_slice(&symtab);

        // 4+. content sections
        let mut sec_off: Vec<u64> = vec![0; total_sections];
        let mut sec_size: Vec<u64> = vec![0; total_sections];
        // sec[0] = NULL (off=0, size=0)
        // sec[1] = .shstrtab
        sec_off[IDX_SHSTR] = shstrtab_off;
        sec_size[IDX_SHSTR] = shstrtab_data.len() as u64;
        // sec[2] = .strtab
        sec_off[IDX_STRTAB] = strtab_off;
        sec_size[IDX_STRTAB] = strtab_data.len() as u64;
        // sec[3] = .symtab
        sec_off[IDX_SYMTAB] = symtab_off;
        sec_size[IDX_SYMTAB] = symtab.len() as u64;

        for (si, spec) in secs.iter().enumerate() {
            let abs = si + 4; // absolute section index
            let (_, ty, _, data, align, _, _, _, nobits) = spec;
            if *ty != SHT_NOBITS && *ty != SHT_MERC_RESERVED_SH {
                align_to(&mut out, *align as usize);
            }
            sec_off[abs] = out.len() as u64;
            sec_size[abs] = nobits.unwrap_or(data.len() as u64);
            if *ty != SHT_NOBITS && *ty != SHT_MERC_RESERVED_SH {
                out.extend_from_slice(data);
            }
        }

        // Section header table (align 8)
        align_to(&mut out, 8);
        let e_shoff = out.len() as u64;

        // NULL section
        write_shdr(&mut out, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
        // .shstrtab
        write_shdr(
            &mut out,
            shn_shstrtab,
            SHT_STRTAB,
            0,
            0,
            sec_off[IDX_SHSTR],
            sec_size[IDX_SHSTR],
            0,
            0,
            1,
            0,
        );
        // .strtab
        write_shdr(
            &mut out,
            shn_strtab,
            SHT_STRTAB,
            0,
            0,
            sec_off[IDX_STRTAB],
            sec_size[IDX_STRTAB],
            0,
            0,
            1,
            0,
        );
        // .symtab
        write_shdr(
            &mut out,
            shn_symtab,
            SHT_SYMTAB,
            0,
            0,
            sec_off[IDX_SYMTAB],
            sec_size[IDX_SYMTAB],
            IDX_STRTAB as u32,
            reg_sym_first_global as u32,
            8,
            24,
        );
        // Content sections
        for (si, spec) in secs.iter().enumerate() {
            let abs = si + 4;
            let (name_off, ty, flags, _, align, link, info, entsize, _) = spec;
            write_shdr(
                &mut out,
                *name_off,
                *ty,
                *flags,
                0,
                sec_off[abs],
                sec_size[abs],
                *link,
                *info,
                *align,
                *entsize,
            );
        }

        // ── Program headers ───────────────────────────────────────────────
        // Matching nvcc 12.8 layout:
        //  [0] PT_PHDR(R)  → covers PHDR table itself
        //  [1] PT_LOAD(R)  → same as PHDR table (standard CUDA convention)
        //  [2] PT_LOAD(RX) → .text sections
        //  [3] PT_LOAD(RW) → .nv.shared.reserved.0 (NOBITS, memsz only)
        //  [4] PT_LOAD(R)  → .nv.constant0 sections

        align_to(&mut out, 8);
        let e_phoff = out.len() as u64;

        const PHDR_COUNT: u16 = 5;
        let phdr_size = PHDR_COUNT as u64 * 56;

        // Find file ranges for text and const sections
        let text_start = sec_off[text_k(0)];
        let text_end = text_start + (0..n).map(|ki| sec_size[text_k(ki)]).sum::<u64>();

        let shared_memsz: u64 = max_shared; // max of all per-kernel shared sizes
        let shared_filesz: u64 = 0;

        let const_start = sec_off[const0_k(0)];
        let const_end = const_start + (0..n).map(|ki| sec_size[const0_k(ki)]).sum::<u64>();

        // PT_PHDR
        write_phdr(&mut out, 0x6, 0x4, e_phoff, 0, phdr_size, phdr_size, 8);
        // PT_LOAD R (same as PHDR, from start of file up to text)
        write_phdr(&mut out, 0x1, 0x4, e_phoff, 0, phdr_size, phdr_size, 8);
        // PT_LOAD RX (.text)
        write_phdr(
            &mut out,
            0x1,
            0x5,
            text_start,
            0,
            text_end - text_start,
            text_end - text_start,
            8,
        );
        // PT_LOAD RW (.nv.shared.reserved.0)
        let shared_file_off = sec_off[idx_shared]; // = text_end (NOBITS shares offset)
        write_phdr(
            &mut out,
            0x1,
            0x6,
            shared_file_off,
            0,
            shared_filesz,
            shared_memsz,
            8,
        );
        // PT_LOAD R (.nv.constant0)
        write_phdr(
            &mut out,
            0x1,
            0x4,
            const_start,
            0,
            const_end - const_start,
            const_end - const_start,
            8,
        );

        // ── Finalise ELF header ───────────────────────────────────────────
        let e_shnum = total_sections as u16;
        write_elf_header_flags(
            &mut out[..64],
            e_shoff,
            e_shnum,
            IDX_SHSTR as u16,
            e_phoff,
            PHDR_COUNT,
            self.ef_flags,
        );

        Ok(out)
    }
}

// ── Mercury EIATTR builder ────────────────────────────────────────────────────

/// Build .nv.merc.nv.info.K section data for a single kernel.
///
/// This is the Mercury version of per-kernel attributes.  It contains the
/// hardcoded Mercury EXIT stub hash plus attributes from the kernel metadata.
fn build_merc_nv_info_k(meta: &KernelMeta, _merc_func_sym: u32) -> Vec<u8> {
    use crate::eiattr::{EiFmt, EiRecord, NvInfoSection};
    let mut records = Vec::new();

    // CUDA_API_VERSION
    let api_ver = if meta.cuda_api_version != 0 {
        meta.cuda_api_version
    } else {
        0x83
    };
    records.push(EiRecord {
        attr: 0x0037,
        fmt: EiFmt::Sized,
        data: api_ver.to_le_bytes().to_vec(),
    });

    // ATTR_0x5a — Mercury code hash (36 bytes, hardcoded for EXIT stub)
    records.push(EiRecord {
        attr: 0x005a,
        fmt: EiFmt::Sized,
        data: MERC_HASH.to_vec(),
    });

    // MAX_THREADS (12 bytes)
    let mut d = vec![0u8; 12];
    d[8] = 0x00;
    d[9] = 0xf0;
    d[10] = 0x21;
    d[11] = 0x00;
    records.push(EiRecord {
        attr: 0x000a,
        fmt: EiFmt::Sized,
        data: d,
    });

    // SPARSE_MMA_MASK (BVAL=0 via fmt=0x03)
    records.push(EiRecord {
        attr: 0x0050,
        fmt: EiFmt::Byte,
        data: vec![0],
    });

    // MAXREG_COUNT (BVAL=0xff — unlimited in Mercury)
    records.push(EiRecord {
        attr: 0x001b,
        fmt: EiFmt::Byte,
        data: vec![0xff],
    });

    // VRC_CTA_INIT_COUNT (fmt=0x02, BVAL)
    records.push(EiRecord {
        attr: 0x004a,
        fmt: EiFmt::Half,
        data: vec![0, 0],
    });

    // EXIT_INSTR_OFFSETS: 0xa0 = offset of EXIT instruction in the Mercury stub (nvcc 12.8)
    records.push(EiRecord {
        attr: 0x001c,
        fmt: EiFmt::Sized,
        data: 0xa0u32.to_le_bytes().to_vec(),
    });

    NvInfoSection {
        name: "".into(),
        records,
    }
    .to_bytes()
}

// ── KernelMeta extension ──────────────────────────────────────────────────────

use crate::eiattr::KernelMeta;

impl KernelMeta {
    /// Generate per-kernel EIATTR records for .nv.info.K, matching nvcc 12.8.
    ///
    /// `func_sym_idx`  = symbol table index of the kernel function.
    /// `const0_sym_idx`= symbol table index of .nv.constant0.K (for KPARAM_INFO word0).
    pub fn to_kernel_records_with_sym_and_const(
        &self,
        _func_sym_idx: u32,
        const0_sym_idx: u32,
    ) -> crate::eiattr::NvInfoSection {
        use crate::eiattr::{EiFmt, EiRecord, NvInfoSection};
        let mut records = Vec::new();

        // 1. CUDA_API_VERSION (attr=0x37)
        let api_ver = if self.cuda_api_version != 0 {
            self.cuda_api_version
        } else {
            0x83
        };
        records.push(EiRecord {
            attr: 0x0037,
            fmt: EiFmt::Sized,
            data: api_ver.to_le_bytes().to_vec(),
        });

        // 2. KPARAM_INFO (attr=0x17): one 12-byte record per parameter,
        // in REVERSE ordinal order (matching working Tungsten cubins).
        // Format: [u32 index=0][u8 ordinal][u8 pad][u16 offset][u32 size_space_cbank]
        for param in self.params.iter().rev() {
            let mut d = vec![0u8; 12];
            d[4] = param.ordinal as u8;
            d[5] = 0x00;
            let off16 = param.offset as u16;
            d[6] = (off16 & 0xFF) as u8;
            d[7] = (off16 >> 8) as u8;
            // SM120 KPARAM_INFO word2 encodes: size class, address space, cbank.
            // Space 0x5 = GLOBAL (pointer params) — tells driver to set up address
            // translation for desc[] loads. Without this, desc[UR][R.64] gets wrong data.
            // Space 0x0 = scalar (no address translation).
            // KPARAM_INFO word2 byte layout (SM120, verified against nvcc 13.1):
            // d[8]  = logAlignment (0 for all params)
            // d[9]  = Space (0x5 = GLOBAL for pointer params, 0x0 for scalars)
            //         High nibble: additional flags (0xF0 observed in some cubins)
            // d[10] = size_class | (cbank << 4): e.g. 0x21 = 8-byte, cbank=2?
            //         nvcc uses 0x1f for cbank=31 in the cuobjdump output
            // d[11] = 0
            d[8] = 0x00; // logAlignment (always 0)
            d[9] = 0xf0; // address space flags (always 0xf0, matching nvcc SM120)
            d[10] = match param.size {
                1 | 2 => 0x01,
                4 => 0x11,
                8 => 0x21,
                16 => 0x31,
                _ => 0x21,
            };
            d[11] = 0x00;
            records.push(EiRecord {
                attr: 0x0017,
                fmt: EiFmt::Sized,
                data: d,
            });
        }

        // 3. Static metadata records
        records.push(EiRecord {
            attr: 0x0050,
            fmt: EiFmt::Byte,
            data: vec![0],
        });
        records.push(EiRecord {
            attr: 0x001b,
            fmt: EiFmt::Byte,
            data: vec![0xff],
        });
        // MAXREG_COUNT (attr 0x4c, HVAL, val=1) — required by SM120 driver
        records.push(EiRecord {
            attr: 0x004c,
            fmt: EiFmt::Half,
            data: vec![1, 0],
        });
        // SM120 capability flag (attr 0x5f, present in all nvcc SM120 cubins)
        // nvcc emits 0x035f0101 = fmt=Byte, attr=0x5f, bval=0x0101
        records.push(EiRecord {
            attr: 0x005f,
            fmt: EiFmt::Byte,
            data: vec![1, 1],
        });
        records.push(EiRecord {
            attr: 0x004a,
            fmt: EiFmt::Half,
            data: vec![0, 0],
        });

        // NUM_BARRIERS (attr 0x25) is intentionally omitted here: the SM120 driver
        // rejects the standalone cubin when this record is present, so it is never
        // emitted on this path (see `self.num_barriers` use in eiattr.rs for context).

        // Note: shared_size is conveyed via .nv.shared section size, NOT via EIATTR attr 0x08
        // (working nvcc cubins do not include shared_size in per-kernel EIATTR blob)

        // 4. EXIT_INSTR_OFFSETS
        if self.exit_offsets.is_empty() {
            records.push(EiRecord {
                attr: 0x001c,
                fmt: EiFmt::Sized,
                data: 0u32.to_le_bytes().to_vec(),
            });
        } else {
            let mut data = Vec::new();
            for off in &self.exit_offsets {
                data.extend_from_slice(&off.to_le_bytes());
            }
            records.push(EiRecord {
                attr: 0x001c,
                fmt: EiFmt::Sized,
                data,
            });
        }

        // 5. CBANK_PARAM_SIZE
        records.push(EiRecord {
            attr: 0x0019,
            fmt: EiFmt::Byte,
            data: vec![self.cbank_param_size as u8],
        });

        // 6. PARAM_CBANK (attr=0x0a): combined record for the parameter block
        // in constant bank 0. word0 = const0 symbol index,
        // word1 = (total_param_bytes << 16) | cbank_base_offset (0x380).
        if !self.params.is_empty() {
            let total = self.cbank_param_size as u32;
            let kparam_w1 = (total << 16) | 0x0380u32;
            let mut kparam_data = Vec::with_capacity(8);
            kparam_data.extend_from_slice(&const0_sym_idx.to_le_bytes());
            kparam_data.extend_from_slice(&kparam_w1.to_le_bytes());
            records.push(EiRecord {
                attr: 0x000a,
                fmt: EiFmt::Sized,
                data: kparam_data,
            });
        }

        // 7. IMAGE_SIZE (CTAID_OFFSETS removed — working nvcc cubins don't include it)
        records.push(EiRecord {
            attr: 0x0036,
            fmt: EiFmt::Sized,
            data: 0u32.to_le_bytes().to_vec(),
        });

        NvInfoSection {
            name: format!(".nv.info.{}", self.name),
            records,
        }
    }
}

// ── ELF writing helpers ───────────────────────────────────────────────────────

#[allow(dead_code)]
fn write_elf_header(
    buf: &mut [u8],
    e_shoff: u64,
    e_shnum: u16,
    e_shstrndx: u16,
    e_phoff: u64,
    e_phnum: u16,
) {
    write_elf_header_flags(
        buf,
        e_shoff,
        e_shnum,
        e_shstrndx,
        e_phoff,
        e_phnum,
        EF_CUDA_SM120,
    );
}

fn write_elf_header_flags(
    buf: &mut [u8],
    e_shoff: u64,
    e_shnum: u16,
    e_shstrndx: u16,
    e_phoff: u64,
    e_phnum: u16,
    e_flags: u32,
) {
    buf[0..4].copy_from_slice(&ELF_MAGIC);
    buf[4] = ELFCLASS64;
    buf[5] = ELFDATA2LSB;
    buf[6] = EV_CURRENT;
    buf[7] = ELFOSABI_CUDA;
    buf[8] = 8; // ABI version CUDA 12.8
    buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    buf[18..20].copy_from_slice(&EM_CUDA.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&0u64.to_le_bytes()); // e_entry
    buf[32..40].copy_from_slice(&e_phoff.to_le_bytes());
    buf[40..48].copy_from_slice(&e_shoff.to_le_bytes());
    buf[48..52].copy_from_slice(&e_flags.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&e_phnum.to_le_bytes());
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&e_shnum.to_le_bytes());
    buf[62..64].copy_from_slice(&e_shstrndx.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_shdr(
    out: &mut Vec<u8>,
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
) {
    out.extend_from_slice(&sh_name.to_le_bytes());
    out.extend_from_slice(&sh_type.to_le_bytes());
    out.extend_from_slice(&sh_flags.to_le_bytes());
    out.extend_from_slice(&sh_addr.to_le_bytes());
    out.extend_from_slice(&sh_offset.to_le_bytes());
    out.extend_from_slice(&sh_size.to_le_bytes());
    out.extend_from_slice(&sh_link.to_le_bytes());
    out.extend_from_slice(&sh_info.to_le_bytes());
    out.extend_from_slice(&sh_addralign.to_le_bytes());
    out.extend_from_slice(&sh_entsize.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_phdr(
    out: &mut Vec<u8>,
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
) {
    out.extend_from_slice(&p_type.to_le_bytes());
    out.extend_from_slice(&p_flags.to_le_bytes());
    out.extend_from_slice(&p_offset.to_le_bytes());
    out.extend_from_slice(&p_vaddr.to_le_bytes());
    out.extend_from_slice(&p_vaddr.to_le_bytes()); // p_paddr = p_vaddr
    out.extend_from_slice(&p_filesz.to_le_bytes());
    out.extend_from_slice(&p_memsz.to_le_bytes());
    out.extend_from_slice(&p_align.to_le_bytes());
}

/// Emit a 24-byte Elf64_Sym entry.
#[allow(clippy::too_many_arguments)]
fn emit_sym(
    out: &mut Vec<u8>,
    st_name: u32,
    binding: u8,
    sym_type: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
) {
    let info = (binding << 4) | (sym_type & 0xf);
    out.extend_from_slice(&st_name.to_le_bytes());
    out.push(info);
    out.push(other);
    out.extend_from_slice(&shndx.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
}

fn build_cuver_note() -> Vec<u8> {
    let name = b"NVIDIA Corp\0"; // 12 bytes
    let mut n = Vec::new();
    n.extend_from_slice(&(name.len() as u32).to_le_bytes()); // namesz = 12
    n.extend_from_slice(&(CUVER_DESC.len() as u32).to_le_bytes()); // descsz = 12
    n.extend_from_slice(&0x3e8u32.to_le_bytes()); // type
    n.extend_from_slice(name);
    // name already 12 bytes = 0 mod 4
    n.extend_from_slice(CUVER_DESC);
    n
}

fn pad_to(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

fn align_to(buf: &mut Vec<u8>, align: usize) {
    if align <= 1 {
        return;
    }
    let r = buf.len() % align;
    if r != 0 {
        buf.extend(std::iter::repeat_n(0u8, align - r));
    }
}
