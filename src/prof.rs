//! b8 PHASE-1 (front MAIN iter19): static control-word readback from
//! emitted cubins -- the "profiler readback" layer Nsight cannot give.
//!
//! What this module reads back, per instruction word, straight from the
//! emitted ELF .text sections (NOT from source text):
//!   * the embedded Blackwell control word (stall 4b, yield 1b,
//!     write/read barrier 3b+3b, wait_mask 6b) via the shipped decoder,
//!   * the canonical opcode form, re-derived through the *same* render ->
//!     re-parse chain the M4.6 scheduler consumes (single source of truth
//!     for opcode_full/modifiers -- no parallel classification here),
//!   * the m9 issue-credit price through the *same* `credit_of` lookup
//!     (full opcode -> base+single modifier -> base -> counted default).
//!
//! Failure doctrine: a word the decoder cannot resolve is a loud UNKNOWN
//! row (counted per kernel; the pyo3/CLI layer turns it into rc!=0 under
//! --strict), a render/re-parse failure is a loud `canon=false` row.
//! Nothing is guessed, nothing is silently dropped.

use anyhow::Result;
use std::path::Path;

use crate::decoder::DecodeIndex;
use crate::sched::CostModel;
use crate::table::IsaTable;

/// One 128-bit instruction word, fully read back.
#[derive(Debug, Clone)]
pub struct ProfRow {
    /// Instruction address within its .text section (16-byte units * 16).
    pub addr: u32,
    /// Decoder resolved the word under the active ISA table.
    pub known: bool,
    /// Render -> re-parse chain succeeded => opcode_full/credits come from
    /// the canonical instruction object (the M4.6 pricing substrate).
    pub canon: bool,
    /// Decode key (operand-shape), empty when !known.
    pub key: String,
    /// Modifier group label, empty when !known.
    pub mod_group: String,
    /// Base opcode from the decoder (e.g. "IADD3"), empty when !known.
    pub opcode: String,
    /// Canonical full opcode from render+reparse (e.g. "IMAD.WIDE.U32.X"),
    /// empty when !canon.
    pub opcode_full: String,
    pub stall: u8,
    pub yield_flag: bool,
    pub write_bar: u8,
    pub read_bar: u8,
    pub wait_mask: u8,
    /// m9 issue-credit price (credit_of); 0.0 when !canon.
    pub credits: f64,
    /// This row hit credits_default (tripwire semantics, like M4.6).
    pub credits_defaulted: bool,
    /// Raw 128-bit word (lo/hi), for traceability in readback reports.
    pub raw_lo: u64,
    pub raw_hi: u64,
}

/// One .text section (one kernel) read back end to end.
#[derive(Debug, Clone)]
pub struct ProfKernel {
    /// Section name with the .text. prefix stripped.
    pub name: String,
    pub rows: Vec<ProfRow>,
    pub n_unknown: usize,
    pub n_canon_err: usize,
    pub credits_defaulted: usize,
}

/// Read back every .text section of `cubin_path`.
///
/// `cost` prices each canonical instruction via credit_of; `table` is the
/// active ISA table (decoder + printer authority). `idx` may be reused by
/// the caller across kernels (build once per table).
pub fn prof_cubin(
    cubin_path: &Path,
    cost: &CostModel,
    table: &IsaTable,
    idx: &DecodeIndex,
) -> Result<Vec<ProfKernel>> {
    let cubin = crate::elf::CubinFile::load(cubin_path)?;
    let mut out = Vec::new();
    for (sec_name, sec_off, sec_size) in &cubin.text_sections {
        let data = &cubin.bytes[*sec_off as usize..(*sec_off + *sec_size) as usize];
        let mut k = ProfKernel {
            name: sec_name.trim_start_matches(".text.").to_string(),
            rows: Vec::new(),
            n_unknown: 0,
            n_canon_err: 0,
            credits_defaulted: 0,
        };
        let mut offset = 0u32;
        while (offset as usize) + 16 <= data.len() {
            let lo = u64::from_le_bytes(
                data[offset as usize..offset as usize + 8].try_into().unwrap(),
            );
            let hi = u64::from_le_bytes(
                data[offset as usize + 8..offset as usize + 16].try_into().unwrap(),
            );
            let code = ((hi as u128) << 64) | (lo as u128);
            match idx.decode(code, offset, table) {
                Ok(inst) => {
                    // Canonical form + price through the scheduler's own
                    // chain: printer::to_sass -> parse_sass -> credit_of.
                    let line = crate::printer::to_sass(&inst);
                    let (canon, opcode_full, credits, dflt) =
                        match crate::parse_sass(&line, inst.addr) {
                            Ok(parsed) => {
                                let mut d = 0usize;
                                let c = cost.credit_of(&parsed, &mut d);
                                (true, parsed.opcode_full.clone(), c, d > 0)
                            }
                            Err(_) => (false, String::new(), 0.0, false),
                        };
                    if !canon {
                        k.n_canon_err += 1;
                    }
                    if dflt {
                        k.credits_defaulted += 1;
                    }
                    k.rows.push(ProfRow {
                        addr: offset,
                        known: true,
                        canon,
                        key: inst.key.clone(),
                        mod_group: inst.mod_group.clone(),
                        opcode: inst.opcode.clone(),
                        opcode_full,
                        stall: inst.ctrl.stall,
                        yield_flag: inst.ctrl.yield_flag,
                        write_bar: inst.ctrl.write_bar,
                        read_bar: inst.ctrl.read_bar,
                        wait_mask: inst.ctrl.wait_mask,
                        credits,
                        credits_defaulted: dflt,
                        raw_lo: lo,
                        raw_hi: hi,
                    });
                }
                Err(_) => {
                    k.n_unknown += 1;
                    k.rows.push(ProfRow {
                        addr: offset,
                        known: false,
                        canon: false,
                        key: String::new(),
                        mod_group: String::new(),
                        opcode: String::new(),
                        opcode_full: String::new(),
                        stall: 0,
                        yield_flag: false,
                        write_bar: 0,
                        read_bar: 0,
                        wait_mask: 0,
                        credits: 0.0,
                        credits_defaulted: false,
                        raw_lo: lo,
                        raw_hi: hi,
                    });
                }
            }
            offset += 16;
        }
        out.push(k);
    }
    Ok(out)
}
