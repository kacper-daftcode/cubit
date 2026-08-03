//! EIATTR parser and writer for `.nv.info` sections in cubin ELF files.
//!
//! The `.nv.info` and `.nv.info.<kernel>` sections contain EIATTR records
//! with kernel metadata: register count, stack size, parameter info,
//! barrier count, exit instruction offsets, etc.
//!
//! Binary format: each record is `(u8 format, u8 data_size, u16 attr_id, data[data_size])`
//! aligned to 4 bytes.
//!
//! Format types:
//!   EIFMT_BVAL (0x01) — 1 byte value, padded to 4
//!   EIFMT_HVAL (0x03) — 2 byte value (u16), padded to 4
//!   EIFMT_SVAL (0x04) — sized value (data_size bytes follow)

use anyhow::{Context, Result};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// EIATTR attribute IDs
// ---------------------------------------------------------------------------

/// Known EIATTR attribute identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum EiAttr {
    SwWar             = 0x0007,
    SharedSize        = 0x0008,
    MinStackSize      = 0x0004,
    KParamInfo        = 0x000a,
    FrameSize         = 0x0011,
    MinStackSizeAlt   = 0x0012,
    CbankParamSize    = 0x0019,
    MaxregCount       = 0x001b,
    ExitInstrOffsets  = 0x001c,
    S2rCtaidOffsets   = 0x001d,
    CtaIdInstrOffsets = 0x001e,
    MaxThreads        = 0x0023,
    NumBarriers       = 0x0025,
    Regcount          = 0x002f,
    ImageSize         = 0x0036,
    CudaApiVersion    = 0x0037,
    VrcCtaInitCount   = 0x0039,
    SparseMmaMask     = 0x0050,
    // Note: ParamCbank uses same ID 0x000a as KParamInfo — context-dependent
}

impl EiAttr {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0004 => Some(EiAttr::MinStackSize),
            0x0007 => Some(EiAttr::SwWar),
            0x0008 => Some(EiAttr::SharedSize),
            0x000a => Some(EiAttr::KParamInfo),
            0x0011 => Some(EiAttr::FrameSize),
            0x0012 => Some(EiAttr::MinStackSizeAlt),
            0x0019 => Some(EiAttr::CbankParamSize),
            0x001b => Some(EiAttr::MaxregCount),
            0x001c => Some(EiAttr::ExitInstrOffsets),
            0x001d => Some(EiAttr::S2rCtaidOffsets),
            0x001e => Some(EiAttr::CtaIdInstrOffsets),
            0x0023 => Some(EiAttr::MaxThreads),
            0x0025 => Some(EiAttr::NumBarriers),
            0x002f => Some(EiAttr::Regcount),
            0x0036 => Some(EiAttr::ImageSize),
            0x0037 => Some(EiAttr::CudaApiVersion),
            0x0039 => Some(EiAttr::VrcCtaInitCount),
            0x0050 => Some(EiAttr::SparseMmaMask),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EiAttr::SwWar             => "EIATTR_SW_WAR",
            EiAttr::SharedSize        => "EIATTR_SHARED_SIZE",
            EiAttr::MinStackSize      => "EIATTR_MIN_STACK_SIZE",
            EiAttr::KParamInfo        => "EIATTR_KPARAM_INFO",
            EiAttr::FrameSize         => "EIATTR_FRAME_SIZE",
            EiAttr::MinStackSizeAlt   => "EIATTR_MIN_STACK_SIZE_ALT",
            EiAttr::CbankParamSize    => "EIATTR_CBANK_PARAM_SIZE",
            EiAttr::MaxregCount       => "EIATTR_MAXREG_COUNT",
            EiAttr::ExitInstrOffsets  => "EIATTR_EXIT_INSTR_OFFSETS",
            EiAttr::S2rCtaidOffsets   => "EIATTR_S2RCTAID_INSTR_OFFSETS",
            EiAttr::CtaIdInstrOffsets => "EIATTR_CTAID_INSTR_OFFSETS",
            EiAttr::MaxThreads        => "EIATTR_MAX_THREADS",
            EiAttr::NumBarriers       => "EIATTR_NUM_BARRIERS",
            EiAttr::Regcount          => "EIATTR_REGCOUNT",
            EiAttr::ImageSize         => "EIATTR_IMAGE_SIZE",
            EiAttr::CudaApiVersion    => "EIATTR_CUDA_API_VERSION",
            EiAttr::VrcCtaInitCount   => "EIATTR_VRC_CTA_INIT_COUNT",
            EiAttr::SparseMmaMask     => "EIATTR_SPARSE_MMA_MASK",
        }
    }
}

// ---------------------------------------------------------------------------
// EIATTR record
// ---------------------------------------------------------------------------

/// Format type for an EIATTR value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EiFmt {
    /// 1-byte value (EIFMT_BVAL, fmt=0x03) — standard nvcc encoding.
    Byte,
    /// 1-byte value (fmt=0x01) — alternate nvcc encoding used for attr=0x2b.
    BValAlt,
    /// 2-byte value (EIFMT_HVAL).
    Half,
    /// Variable-size value (EIFMT_SVAL).
    Sized,
}

impl EiFmt {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => EiFmt::BValAlt,
            0x02 => EiFmt::Byte,
            0x03 => EiFmt::Half,
            _ => EiFmt::Sized,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            EiFmt::Byte    => 0x03,
            EiFmt::BValAlt => 0x01,
            EiFmt::Half    => 0x02,
            EiFmt::Sized   => 0x04,
        }
    }
}

/// A single EIATTR record.
#[derive(Debug, Clone)]
pub struct EiRecord {
    /// Attribute ID.
    pub attr: u16,
    /// Format type.
    pub fmt: EiFmt,
    /// Raw data bytes.
    pub data: Vec<u8>,
}

impl EiRecord {
    /// Get attribute name if known.
    pub fn attr_name(&self) -> String {
        EiAttr::from_u16(self.attr)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("ATTR_0x{:04x}", self.attr))
    }

    /// Get value as u8 (for BVAL).
    pub fn as_u8(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Get value as u16 (for HVAL).
    pub fn as_u16(&self) -> Option<u16> {
        if self.data.len() >= 2 {
            Some(u16::from_le_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    /// Get value as u32 (first 4 bytes of SVAL).
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_le_bytes(self.data[..4].try_into().ok()?))
        } else {
            None
        }
    }

    /// Get as (func_sym_idx, value) for SVAL with 8 bytes.
    pub fn as_func_val(&self) -> Option<(u32, u32)> {
        if self.data.len() >= 8 {
            let func = u32::from_le_bytes(self.data[..4].try_into().ok()?);
            let val = u32::from_le_bytes(self.data[4..8].try_into().ok()?);
            Some((func, val))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Parsed .nv.info section
// ---------------------------------------------------------------------------

/// Parsed contents of a `.nv.info` or `.nv.info.<kernel>` section.
#[derive(Debug, Clone)]
pub struct NvInfoSection {
    /// Section name (e.g. ".nv.info" or ".nv.info.my_kernel").
    pub name: String,
    /// Records in order.
    pub records: Vec<EiRecord>,
}

impl NvInfoSection {
    /// Parse EIATTR records from raw section bytes (real NVIDIA format):
    ///   SVAL (0x04): [fmt][attr_byte][size_lo][size_hi][data...] 4-byte aligned
    ///   HVAL (0x02): [fmt][attr_byte][val_lo][val_hi]            (4 bytes total)
    ///   BVAL (0x03): [fmt][attr_byte][val][pad]                  (4 bytes total)
    pub fn parse(name: &str, data: &[u8]) -> Result<Self> {
        let mut records = Vec::new();
        let mut off = 0;

        while off + 4 <= data.len() {
            let fmt_byte = data[off];
            let attr = data[off + 1] as u16;  // single-byte attr in real NVIDIA format

            let (fmt, data_bytes, next_off) = match fmt_byte {
                0x04 => {
                    // SVAL: [0x04][attr][size_lo][size_hi][data...] aligned to 4
                    let size = u16::from_le_bytes([data[off+2], data[off+3]]) as usize;
                    let end = (off + 4 + size).min(data.len());
                    let d = data[off+4..end].to_vec();
                    let next = (off + 4 + size + 3) & !3;
                    (EiFmt::Sized, d, next)
                }
                0x02 => {
                    // HVAL: [0x02][attr][val_lo][val_hi] (4 bytes)
                    let d = if off + 4 <= data.len() {
                        data[off+2..off+4].to_vec()
                    } else { vec![0, 0] };
                    (EiFmt::Half, d, off + 4)
                }
                0x03 => {
                    // BVAL: [0x03][attr][val][pad] (4 bytes)
                    let val = if off + 3 <= data.len() { data[off+2] } else { 0 };
                    (EiFmt::Byte, vec![val], off + 4)
                }
                0x01 => {
                    // Legacy BVAL (some old cubins): same 4-byte layout
                    let val = if off + 3 <= data.len() { data[off+2] } else { 0 };
                    (EiFmt::Byte, vec![val], off + 4)
                }
                _ => { off += 4; continue; }
            };

            records.push(EiRecord { attr, fmt, data: data_bytes });
            off = next_off;
        }

        Ok(NvInfoSection { name: name.to_string(), records })
    }

    /// Serialize records to binary using real NVIDIA EIATTR format:
    ///   SVAL: [0x04][attr_byte][size_lo][size_hi][data...] aligned to 4 bytes
    ///   HVAL: [0x02][attr_byte][val_lo][val_hi]           (4 bytes, value=16-bit)
    ///   BVAL: [0x03][attr_byte][val][pad]                 (4 bytes, value=8-bit)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        for rec in &self.records {
            let attr_byte = (rec.attr & 0xFF) as u8;
            match rec.fmt {
                EiFmt::Byte => {
                    // BVAL: [0x03][attr][val_lo][val_hi] = 4 bytes
                    // val_hi is usually 0x00 but can be non-zero (e.g. attr 0x5f = 0x0101)
                    out.push(0x03);
                    out.push(attr_byte);
                    out.push(rec.data.first().copied().unwrap_or(0));
                    out.push(rec.data.get(1).copied().unwrap_or(0));
                }
                EiFmt::BValAlt => {
                    // BVAL alt: [0x01][attr][val][0x00] = 4 bytes (nvcc fmt for attr=0x2b)
                    out.push(0x01);
                    out.push(attr_byte);
                    out.push(rec.data.first().copied().unwrap_or(0));
                    out.push(0x00);
                }
                EiFmt::Half => {
                    // HVAL: [0x02][attr][val_lo][val_hi] = 4 bytes
                    out.push(0x02);
                    out.push(attr_byte);
                    if rec.data.len() >= 2 {
                        out.push(rec.data[0]);
                        out.push(rec.data[1]);
                    } else {
                        out.push(rec.data.first().copied().unwrap_or(0));
                        out.push(0);
                    }
                }
                EiFmt::Sized => {
                    // SVAL: [0x04][attr][size_lo][size_hi][data...] aligned to 4 bytes
                    let size = rec.data.len() as u16;
                    out.push(0x04);
                    out.push(attr_byte);
                    out.extend_from_slice(&size.to_le_bytes());
                    out.extend_from_slice(&rec.data);
                    // Align to 4 bytes
                    while out.len() % 4 != 0 { out.push(0); }
                }
            }
        }

        out
    }

    /// Serialize per-kernel records wrapped in a single attr=0x37 blob.
    /// nvcc packs all per-kernel EIATTR records inside one SVAL record with
    /// attr=0x37 (CUDA_API_VERSION / SWTOOLSEXP). The driver expects this
    /// format for per-kernel .nv.info sections.
    pub fn to_bytes_as_blob(&self) -> Vec<u8> {
        // First record (attr=0x37 with api_ver) stays as outer wrapper.
        // Remaining records are serialized into the blob body.
        if self.records.is_empty() { return Vec::new(); }

        // Serialize all records EXCEPT the first 0x37 record into inner bytes
        let inner_section = NvInfoSection {
            name: self.name.clone(),
            records: self.records[1..].to_vec(),
        };
        let inner_bytes = inner_section.to_bytes();

        // Build outer: attr=0x37, fmt=SVAL, data = [api_ver(4B)] + inner_bytes
        let first = &self.records[0];
        let mut blob_data = first.data.clone(); // api_ver (4 bytes)
        blob_data.extend_from_slice(&inner_bytes);

        let mut out = Vec::new();
        // SVAL header: [0x04][attr_lo][size_lo][size_hi]
        let size = blob_data.len() as u16;
        out.push(0x04);
        out.push((first.attr & 0xFF) as u8);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&blob_data);
        // Align to 4 bytes
        while out.len() % 4 != 0 { out.push(0); }
        out
    }
}

// ---------------------------------------------------------------------------
// High-level kernel metadata
// ---------------------------------------------------------------------------

/// High-level kernel metadata extracted from EIATTR records.
#[derive(Debug, Clone)]
pub struct KernelMeta {
    /// Kernel function name.
    pub name: String,
    /// Number of registers used.
    pub regcount: u32,
    /// Frame (stack) size in bytes.
    pub frame_size: u32,
    /// Minimum stack size in bytes.
    pub min_stack_size: u32,
    /// Maximum register count limit (0xFF = no limit).
    pub maxreg_count: u16,
    /// Number of barriers used (0-6).
    pub num_barriers: u8,
    /// Exit instruction byte offsets.
    pub exit_offsets: Vec<u32>,
    /// Constant bank parameter size.
    pub cbank_param_size: u16,
    /// Kernel parameters.
    pub params: Vec<KernelParam>,
    /// CUDA API version.
    pub cuda_api_version: u32,
    /// Static shared memory size in bytes (from .shared directives).
    pub shared_size: u32,
    /// Mercury: parametry w kolejnosci pierwszego uzycia w SASS (scan
    /// `LDC(.64)? Rx, c[0x0][0x380+8k]`); None = kolejnosc sygnaturowa.
    pub merc_param_order: Option<Vec<u32>>,
    /// Bitmaska parametrow zapisywanych (pierwsze uzycie pamieci = store).
    pub merc_param_write: u32,
    /// LDG z rejestrowo-dynamicznym adresowaniem ([Rx.64+0x..]) obecne.
    pub merc_dynldg: bool,
    /// Per-STG: pozycja desc-parametru w kolejce first-use (STG binding).
    pub merc_stg_desc_pos: Vec<u32>,
    /// Jakakolwiek BAR pod predykatem (wariant rekordu BAR payload[0]=01).
    pub merc_bar_pred: bool,
}

/// Kernel parameter info.
#[derive(Debug, Clone)]
pub struct KernelParam {
    pub index: u32,
    pub ordinal: u32,
    pub offset: u32,
    pub size: u32,
}

impl KernelMeta {
    /// Static shared memory size in bytes declared via .shared directives.
    pub fn shared_size(&self) -> u32 {
        self.shared_size
    }

    /// Build from parsed EIATTR records (both global .nv.info and per-kernel).
    pub fn from_sections(
        global: &NvInfoSection,
        per_kernel: &NvInfoSection,
        kernel_name: &str,
    ) -> Self {
        let mut meta = KernelMeta {
            name: kernel_name.to_string(),
            regcount: 0,
            frame_size: 0,
            min_stack_size: 0,
            maxreg_count: 0xFF,
            num_barriers: 0,
            exit_offsets: Vec::new(),
            cbank_param_size: 0,
            params: Vec::new(),
            cuda_api_version: 0x83,
            shared_size: 0,
            merc_param_order: None,
            merc_param_write: 0,
            merc_dynldg: false,
            merc_stg_desc_pos: Vec::new(),
            merc_bar_pred: false,
        };

        // Extract from global section (REGCOUNT, FRAME_SIZE, MIN_STACK_SIZE)
        for rec in &global.records {
            match rec.attr {
                0x002f => { // REGCOUNT
                    if let Some((_, val)) = rec.as_func_val() {
                        meta.regcount = val;
                    }
                }
                0x0011 => { // FRAME_SIZE
                    if let Some((_, val)) = rec.as_func_val() {
                        meta.frame_size = val;
                    }
                }
                0x0004 => { // MIN_STACK_SIZE
                    if let Some((_, val)) = rec.as_func_val() {
                        meta.min_stack_size = val;
                    }
                }
                _ => {}
            }
        }

        // Extract from per-kernel section
        for rec in &per_kernel.records {
            match rec.attr {
                0x0008 => { // SHARED_SIZE
                    if let Some(v) = rec.as_u32() { meta.shared_size = v; }
                }
                0x001b => { // MAXREG_COUNT
                    if let Some(v) = rec.as_u16() { meta.maxreg_count = v; }
                }
                0x0025 => { // NUM_BARRIERS
                    if let Some(v) = rec.as_u8() { meta.num_barriers = v; }
                }
                0x001c => { // EXIT_INSTR_OFFSETS
                    let mut i = 0;
                    while i + 4 <= rec.data.len() {
                        let off = u32::from_le_bytes(rec.data[i..i+4].try_into().unwrap());
                        meta.exit_offsets.push(off);
                        i += 4;
                    }
                }
                0x0019 => { // CBANK_PARAM_SIZE
                    if let Some(v) = rec.as_u16() { meta.cbank_param_size = v; }
                }
                0x0037 => { // CUDA_API_VERSION
                    if let Some(v) = rec.as_u32() { meta.cuda_api_version = v; }
                }
                0x000a => { // KPARAM_INFO
                    if rec.data.len() >= 16 {
                        let param = KernelParam {
                            index: u32::from_le_bytes(rec.data[0..4].try_into().unwrap()),
                            ordinal: u32::from_le_bytes(rec.data[4..8].try_into().unwrap()),
                            offset: u32::from_le_bytes(rec.data[8..12].try_into().unwrap()),
                            size: u32::from_le_bytes(rec.data[12..16].try_into().unwrap()),
                        };
                        meta.params.push(param);
                    }
                }
                _ => {}
            }
        }

        meta
    }

    /// Build EIATTR records for writing a new cubin.
    pub fn to_global_records(&self, func_sym_idx: u32) -> NvInfoSection {
        let mut records = Vec::new();

        // REGCOUNT
        let mut data = Vec::new();
        data.extend_from_slice(&func_sym_idx.to_le_bytes());
        data.extend_from_slice(&self.regcount.to_le_bytes());
        records.push(EiRecord { attr: 0x002f, fmt: EiFmt::Sized, data });

        // FRAME_SIZE
        let mut data = Vec::new();
        data.extend_from_slice(&func_sym_idx.to_le_bytes());
        data.extend_from_slice(&self.frame_size.to_le_bytes());
        records.push(EiRecord { attr: 0x0011, fmt: EiFmt::Sized, data });

        // MIN_STACK_SIZE (0x12 in real NVIDIA SM120, not 0x0004)
        let mut data = Vec::new();
        data.extend_from_slice(&func_sym_idx.to_le_bytes());
        data.extend_from_slice(&self.min_stack_size.to_le_bytes());
        records.push(EiRecord { attr: 0x0012, fmt: EiFmt::Sized, data });

        NvInfoSection { name: ".nv.info".to_string(), records }
    }

    /// Build per-kernel EIATTR records.
    pub fn to_kernel_records(&self) -> NvInfoSection {
        self.to_kernel_records_with_sym(0)
    }

    /// Generate per-kernel EIATTR records matching real NVIDIA SM120 format.
    /// `func_sym_idx` = function symbol table index (from .symtab).
    pub fn to_kernel_records_with_sym(&self, func_sym_idx: u32) -> NvInfoSection {
        let mut records = Vec::new();

        // 1. CUDA_API_VERSION (0x37): 4 bytes, value = 0x80 (CUDA 11.x SM120)
        let api_ver = if self.cuda_api_version != 0 { self.cuda_api_version } else { 0x80 };
        records.push(EiRecord {
            attr: 0x0037, fmt: EiFmt::Sized,
            data: api_ver.to_le_bytes().to_vec()
        });

        // 2. MAX_THREADS (0x17): 12 zero bytes (unlimited = use defaults)
        records.push(EiRecord {
            attr: 0x0017, fmt: EiFmt::Sized,
            data: vec![0u8; 12]
        });

        // 3. SPARSE_MMA_MASK (0x50): BVAL = 0
        records.push(EiRecord { attr: 0x0050, fmt: EiFmt::Byte, data: vec![0] });

        // 4. MAXREG_COUNT (0x1b): BVAL = actual register count used
        let maxreg = if self.maxreg_count == 0 || self.maxreg_count == 0xFF {
            self.regcount.min(255) as u8
        } else {
            self.maxreg_count as u8
        };
        records.push(EiRecord { attr: 0x001b, fmt: EiFmt::Byte, data: vec![maxreg] });

        // 4a. Attr 0x4c (HVAL=1): required SM120 capability flag (present in all SM120 cubins)
        records.push(EiRecord { attr: 0x004c, fmt: EiFmt::Half, data: vec![1, 0] });

        // 4b. Attr 0x4a (HVAL=0): VRC_CTA_INIT_COUNT
        records.push(EiRecord { attr: 0x004a, fmt: EiFmt::Half, data: vec![0, 0] });

        // 4c. NUM_BARRIERS (0x25): BVAL = number of convergence barriers used
        if self.num_barriers > 0 {
            records.push(EiRecord { attr: 0x0025, fmt: EiFmt::Byte, data: vec![self.num_barriers] });
        }

        // 4d. SHARED_SIZE (0x08): SVAL = static shared memory size in bytes
        if self.shared_size > 0 {
            records.push(EiRecord {
                attr: 0x0008, fmt: EiFmt::Sized,
                data: self.shared_size.to_le_bytes().to_vec(),
            });
        }

        // 5. EXIT_INSTR_OFFSETS (0x1c): list of EXIT byte offsets
        if !self.exit_offsets.is_empty() {
            let mut data = Vec::new();
            for off in &self.exit_offsets {
                data.extend_from_slice(&off.to_le_bytes());
            }
            records.push(EiRecord { attr: 0x001c, fmt: EiFmt::Sized, data });
        } else {
            // Emit one dummy offset at 0 if no exits found
            records.push(EiRecord {
                attr: 0x001c, fmt: EiFmt::Sized,
                data: 0u32.to_le_bytes().to_vec()
            });
        }

        // 6. Attr 0x05: 12 bytes, first word = 0x100 (unknown — thread count hint?)
        let mut data05 = vec![0u8; 12];
        data05[0..4].copy_from_slice(&256u32.to_le_bytes());
        records.push(EiRecord { attr: 0x0005, fmt: EiFmt::Sized, data: data05 });

        // 7. CTAID_OFFSETS (0x1e): 4 bytes = offset of first S2R CTAID instruction (0=none)
        records.push(EiRecord {
            attr: 0x001e, fmt: EiFmt::Sized,
            data: 0u32.to_le_bytes().to_vec()
        });

        // 8. CBANK_PARAM_SIZE (0x19): BVAL = total parameter space size in bytes
        let cbank_sz = self.cbank_param_size as u8;
        records.push(EiRecord { attr: 0x0019, fmt: EiFmt::Byte, data: vec![cbank_sz] });

        // 9. KPARAM_INFO (0x0a): one record per parameter.
        //    Correct formula from nvcc 12.8 reverse engineering:
        //    word1 = (param_size_bytes << 16) | cbank_byte_offset
        //    e.g. for u64: (8 << 16) | 0x380 = 0x00080380
        //    NOT (cbank_offset << 16) | (size >> 1) which was wrong.
        // word0 = function symbol table index (note: use const0_sym_idx for full correctness)
        // SM120/CUDA 12.8: parameters start at cbank offset 0x0380.
        for param in &self.params {
            let cbank_off = 0x0380u32 + param.offset;
            let kparam_w1 = (param.size << 16) | cbank_off;
            let mut kparam_data = Vec::with_capacity(8);
            kparam_data.extend_from_slice(&func_sym_idx.to_le_bytes());
            kparam_data.extend_from_slice(&kparam_w1.to_le_bytes());
            records.push(EiRecord { attr: 0x000a, fmt: EiFmt::Sized, data: kparam_data });
        }

        // 10. IMAGE_SIZE (0x36): 4 bytes = 0
        records.push(EiRecord {
            attr: 0x0036, fmt: EiFmt::Sized,
            data: 0u32.to_le_bytes().to_vec()
        });

        let sec_name = format!(".nv.info.{}", self.name);
        NvInfoSection { name: sec_name, records }
    }
}

// ---------------------------------------------------------------------------
// Convenience: parse all .nv.info sections from a cubin
// ---------------------------------------------------------------------------

/// Extract kernel metadata from cubin bytes by finding .nv.info sections.
pub fn parse_cubin_metadata(elf_data: &[u8]) -> Result<BTreeMap<String, KernelMeta>> {
    // Minimal ELF64 parser to find .nv.info sections
    if elf_data.len() < 64 || &elf_data[..4] != b"\x7fELF" {
        anyhow::bail!("not a valid ELF file");
    }

    let e_shoff = u64::from_le_bytes(elf_data[40..48].try_into()?) as usize;
    let e_shnum = u16::from_le_bytes(elf_data[60..62].try_into()?) as usize;
    let e_shentsize = u16::from_le_bytes(elf_data[58..60].try_into()?) as usize;
    let e_shstrndx = u16::from_le_bytes(elf_data[62..64].try_into()?) as usize;

    // Section header string table
    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstr_off = u64::from_le_bytes(elf_data[shstr_hdr + 24..shstr_hdr + 32].try_into()?) as usize;
    let shstr_size = u64::from_le_bytes(elf_data[shstr_hdr + 32..shstr_hdr + 40].try_into()?) as usize;
    let shstr = &elf_data[shstr_off..shstr_off + shstr_size];

    let get_string = |offset: usize| -> String {
        let end = shstr[offset..].iter().position(|&b| b == 0).unwrap_or(0) + offset;
        String::from_utf8_lossy(&shstr[offset..end]).to_string()
    };

    // Find .nv.info sections
    let mut global_info = None;
    let mut kernel_infos: BTreeMap<String, NvInfoSection> = BTreeMap::new();

    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + 64 > elf_data.len() { break; }
        let sh_name_off = u32::from_le_bytes(elf_data[sh..sh + 4].try_into()?) as usize;
        let sh_offset = u64::from_le_bytes(elf_data[sh + 24..sh + 32].try_into()?) as usize;
        let sh_size = u64::from_le_bytes(elf_data[sh + 32..sh + 40].try_into()?) as usize;

        let name = get_string(sh_name_off);
        if !name.starts_with(".nv.info") || name.contains("merc") {
            continue;
        }
        if sh_size == 0 { continue; }

        let section_data = &elf_data[sh_offset..sh_offset + sh_size];
        let parsed = NvInfoSection::parse(&name, section_data)
            .with_context(|| format!("parsing {name}"))?;

        if name == ".nv.info" {
            global_info = Some(parsed);
        } else if let Some(kernel_name) = name.strip_prefix(".nv.info.") {
            kernel_infos.insert(kernel_name.to_string(), parsed);
        }
    }

    let global = global_info.unwrap_or_else(|| NvInfoSection {
        name: ".nv.info".to_string(),
        records: Vec::new(),
    });

    let mut result = BTreeMap::new();
    for (kernel_name, per_kernel) in &kernel_infos {
        let meta = KernelMeta::from_sections(&global, per_kernel, kernel_name);
        result.insert(kernel_name.clone(), meta);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_roundtrip() {
        let rec = EiRecord {
            attr: 0x001b,
            fmt: EiFmt::Half,
            data: vec![0xFF, 0x00],
        };
        assert_eq!(rec.as_u16(), Some(0xFF));
        assert_eq!(rec.attr_name(), "EIATTR_MAXREG_COUNT");
    }

    #[test]
    fn test_section_serialize_roundtrip() {
        let section = NvInfoSection {
            name: ".nv.info.test".to_string(),
            records: vec![
                EiRecord { attr: 0x001b, fmt: EiFmt::Half, data: vec![0xFF, 0x00] },
                EiRecord { attr: 0x0025, fmt: EiFmt::Byte, data: vec![0x02] },
            ],
        };

        let bytes = section.to_bytes();
        let parsed = NvInfoSection::parse(".nv.info.test", &bytes).unwrap();
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].attr, 0x001b);
        assert_eq!(parsed.records[0].as_u16(), Some(0xFF));
        assert_eq!(parsed.records[1].attr, 0x0025);
        assert_eq!(parsed.records[1].as_u8(), Some(0x02));
    }

    #[test]
    fn test_kernel_meta_roundtrip() {
        let meta = KernelMeta {
            name: "test_kernel".to_string(),
            regcount: 16,
            frame_size: 0,
            min_stack_size: 0,
            maxreg_count: 0xFF,
            num_barriers: 1,
            exit_offsets: vec![0x40, 0x120],
            cbank_param_size: 12,
            params: vec![
                KernelParam { index: 0, ordinal: 0, offset: 0, size: 8 },
            ],
            cuda_api_version: 0x83,
            shared_size: 0,
            merc_param_order: None,
            merc_param_write: 0,
            merc_dynldg: false,
            merc_stg_desc_pos: Vec::new(),
            merc_bar_pred: false,
        };

        let global = meta.to_global_records(8);
        let kernel = meta.to_kernel_records();

        // Serialize and reparse
        let global_bytes = global.to_bytes();
        let kernel_bytes = kernel.to_bytes();
        assert!(global_bytes.len() > 0);
        assert!(kernel_bytes.len() > 0);

        let global_parsed = NvInfoSection::parse(".nv.info", &global_bytes).unwrap();
        let kernel_parsed = NvInfoSection::parse(".nv.info.test_kernel", &kernel_bytes).unwrap();

        let meta2 = KernelMeta::from_sections(&global_parsed, &kernel_parsed, "test_kernel");
        assert_eq!(meta2.regcount, 16);
        assert_eq!(meta2.num_barriers, 1);
        assert_eq!(meta2.exit_offsets, vec![0x40, 0x120]);
    }
}
