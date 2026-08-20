//! cubit — SM120 CUDA assembler, table-driven bitfield encoding.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐    ┌──────────┐    ┌──────────────┐
//! │  Parser   │───▶│ Encoder  │───▶│ ELF Patcher  │
//! │(SASS→IR)  │    │(bit OR)  │    │ (bits→cubin) │
//! └──────────┘    └──────────┘    └──────────────┘
//!       │               │
//!       ▼               ▼
//! ┌──────────────────────────┐
//! │  Bitfield Table (JSON)   │
//! │  auto-discovered via     │
//! │  nvdisasm bit probing    │
//! └──────────────────────────┘
//! ```

// This is low-level, table- and index-driven assembler code. Explicit range
// loops and match-arm bodies read more clearly here than the iterator/guard
// rewrites these pedantic style lints suggest, so they are allowed crate-wide.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::collapsible_match)]

pub mod ctrl_class;
pub mod decoder;
pub mod directives;
pub mod eiattr;
pub mod elf;
pub mod elf_builder;
pub mod encoder;
pub mod ir;
pub mod mercury;
pub mod parser;
pub mod pred_liveness;
pub mod printer;
#[cfg(feature = "python")]
pub mod python;
pub mod sass_file;
pub mod scheduling;
pub mod scheduling_pass;
pub mod table;

pub use ir::{ControlCode, Instruction};
pub use parser::{parse_cuasm_line, parse_multi_sass, parse_sass, resolve_labels, Statement};
pub use table::IsaTable;

/// Assemble multiple SASS instructions with label resolution.
/// Returns `(bytes, count)` where `bytes` is raw 128-bit instruction bytes (little-endian)
/// and `count` is the number of instructions assembled.
pub fn assemble(code: &str, base_addr: u32, table: &IsaTable) -> anyhow::Result<(Vec<u8>, usize)> {
    let stmts = parse_multi_sass(code, base_addr);
    let mut insns = resolve_labels(stmts, base_addr);
    scheduling_pass::schedule(&mut insns, Some(table));
    scheduling_pass::reallocate_barriers(&mut insns, Some(table));
    let count = insns.len();
    let mut bytes = Vec::with_capacity(count * 16);
    for insn in &insns {
        let code128 = encoder::encode_instruction(insn, table)
            .map_err(|e| anyhow::anyhow!("encode error at addr 0x{:x}: {}", insn.addr, e))?;
        bytes.extend_from_slice(&code128.to_le_bytes());
    }
    Ok((bytes, count))
}
