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
#[derive(Debug, Clone, Default)]
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
    /// Pozycje (16B-slot indeksy) BAR/SYNC w strumieniu (kolejnosc kodowa).
    pub merc_bar_pos: Vec<u32>,
    /// Pozycje STG (era-record binding ordering).
    pub merc_stg_pos: Vec<u32>,
    /// Per-STG: binding do deskryptora parametru — indeks w PULI
    /// deskryptorow (pi, mech) w kolejnosci pierwszego pojawienia loadu
    /// (mk10c; rozjem parametru przez LDCU i LDC to osobne pozycje puli;
    /// stary model: pozycja param-queue — zgodne gdy 1 deskryptor/param).
    /// u32::MAX = nieznane (fallback emitera).
    pub merc_stg_desc_pos: Vec<u32>,
    /// Jakakolwiek BAR pod predykatem (wariant rekordu BAR payload[0]=01).
    pub merc_bar_pred: bool,

    /// Mercury: bit per param — slot zaladowany przez LDCU* (uniform datapath).
    /// Deskryptor 0222 dla takiego parametru ma wariant tagu 08 06 / b4=fa
    /// (register-path LDC* daje 0e 06 / f8) — dekod fs-lab 2026-08-05.
    pub merc_param_uniform: u32,
    /// Mercury: bit per param — slot zaladowany przez LDC(.64) (register path).
    pub merc_param_regpath: u32,
    /// Mercury: per-param szerokosc transferu loadu z cbank (1/2/4/8/16 B;
    /// 0 = nieznana). Steruje bajtem b6 rekordu desc (ladder 02/22/42/52/62).
    pub merc_param_width: Vec<u8>,
    /// Mercury: rekordy 0229 dla PTX-level `xor Rd, Rs, imm32` (SASS:
    /// `LOP3.LUT Rd, Rs, imm, RZ, 0x3c, !PT` — fs6-lab 2026-08-05). Krotka:
    /// (lane, dst_reg, src_reg, imm, guard) gdzie guard: 0=brak (b4=0xf8),
    /// 1=@Pn (b4=0x00), 2=@!Pn (b4=0x01). Lane takich instrukcji NIE
    /// dostaje bitu bitmapy (rekord zastepuje wezel typu4).
    pub merc_xor: Vec<(u32, u32, u32, u32, u8)>,
    /// Mercury: per-STG natychmiastowy offset adresu ([Rx.64+0x..]) w bajtach
    /// — trafia do bajta 28 rekordu 02 38 (fs10-grid 2026-08-05).
    pub merc_stg_off: Vec<i32>,
    /// Mercury mk10b: per-STG pakiet kursora serii: bit7=null-tail
    /// (value==RZ, off==0), bity[6:0] = indeks w serii blokowej (reset na
    /// krawedziach cflow: targety skokow + po EXIT/RET/CALL/BRA/BRX/itd.).
    pub merc_stg_ser: Vec<u8>,
    /// mk12: per-STG numer rejestru danych (kursor b19/b20 = dreg<<6; 255=RZ).
    pub merc_stg_dreg: Vec<u8>,
    /// fala A mk12a: per-STG numer desc-UR (domyslnie 4; b17/b18 = ur<<6|2).
    pub merc_stg_dur: Vec<u8>,
    /// fala A: per-STG wariant predykatu (0=brak, 1=@Pn, 2=@!Pn; b4 rekordu).
    pub merc_stg_guard: Vec<u8>,
    /// mk32: per-STG niski rejestr pary adresowej [R<num>.64] (255=nieznany).
    pub merc_stg_areg: Vec<u8>,
    /// Mercury mk11: instrukcje MMA -> rekord 025a w lane. Krotka
    /// (lane, cls, d, a, b, c, b8flags); cls wg `mercury::merc_mma_class`.
    /// Model bajtowy 025a dekodowany byte-exact na pelnej probce korpusu
    /// (mma_model.py); b8flags = (code63?0x80)|(code72?0x20) ze slowa SASS.
    pub merc_mma: Vec<(u32, u8, u8, u8, u8, u8, u8)>,
    /// Mercury mk11+mk51: DMUL/DADD z natychmiastowym f64 -> rekord
    /// 020f120e/020c1e0e w lane:
    /// (lane, variant [0=DMUL,1=DADD], d, a, imm_top32, pred [mk41], b7).
    /// b7 = 2*negA + 4*absA; zrodlo RZ kodowane jako 0x3ff.
    pub merc_f64imm: Vec<(u32, u8, u16, u16, u32, u8, u8)>,
    /// Mercury mk51: DFMA z natychmiastowym f64 -> rekord 020d1c0e
    /// (imm ostatni) / 020d1a0e (imm srodkowy) w lane:
    /// (lane, variant [0=last,1=middle], pred, b7 = 2*negA+8*negB+4*absA
    /// +16*absB, d, a, b, imm64bits). Lane traci bit bitmapy jak mk11-f64.
    pub merc_dfmaimm: Vec<(u32, u8, u8, u8, u16, u16, u16, u64)>,
    /// Mercury mk11: pozycje killpad-UIADD3 (`UIADD3 URZ, UPT, UPT, URZ,
    /// URZ, URZ`) — brak bitu bitmapy, w lane atom 2B (empiria: tyko ta
    /// forma; live UIADD3 maja bit, korpus 32.5k vs 18).
    pub merc_pad_pos: Vec<u32>,
    /// Mercury mk10c: strumien ladowan cbank-parametrow jako rekordy lane:
    /// (lane, pi, uniform [0=LDC*,1=LDCU*], width_bajty, guard [0/1/2]) per
    /// instrukcja LDC/LDCU z okna c[0x0][0x380+]. nvcc emituje rekord 0222
    /// NA KAZDY LOAD (powtorne loady tego samego slotu => wiele rekordow),
    /// strumien posortowany po pozycjach kodu. Pusty = sciezka legacy
    /// (blok desc wg param_order).
    /// Mercury mk10c+: per-load rekordy desc: (lane, REL, unif01, widthB,
    /// guard). mk19: drugie pole = SUROWY offset bajtowy c_off-0x380
    /// (wczesniej indeks 8B pi; korpus ma paramy 4B-pakowane pod 0x384).
    pub merc_param_loads: Vec<(u32, u32, u8, u8, u8)>,
    /// Mercury mk10c: lane instrukcji LDCU.64 c[0x0][0x358] (rekord cbank
    /// 010b0e0a zajmuje lane swojego loadu w strumieniu; None = po desc[0]).
    pub merc_cbank_lane: Option<u32>,
    /// Mercury mk10c: lane kazdego S2R — anchor-rekord 010b040a powstaje
    /// per S2R (pek w gold: #anchors-1 == #S2R na 148/148 jadrach).
    pub merc_s2r_lanes: Vec<u32>,
    /// Mercury mk10c: predykowana operacja pamieci (@P LDG/STG/LDS/STS/
    /// ATOMS/REDG) obecna — gasi bramke f4=7 (d_ifelse_ld: 0, k_ldg2: 7).
    pub merc_predmem: bool,
    /// Mercury mk13: lane'y BRA pod predykatem (@Pn BRA) — dostaja bit
    /// bitmapy (niepredykowany BRA, w tym koncowy po EXIT, bitu nie ma;
    /// gold q_switch slot5). Zrodlo: guard z sass.
    pub merc_guarded_bra: Vec<u32>,
    /// Mercury mk13: LDG.E.CONSTANT przez desc[URx][Rn.64] = dodatkowy wpis
    /// w puli slotow deskryptorow (klucz (pi, mech=2), pozycja = lane
    /// uzycia). Gold v_ldg_u64: STG pi1 dostaje slot s=2 bo LDG.C@3 zajmuje
    /// s=1 (pi0,2). (lane, pi).
    /// (lane, REL) — mk19: takze w dziedzinie bajtowej jak merc_param_loads.
    pub merc_ldgconst: Vec<(u32, u32)>,
    /// Mercury mk13: argumenty named-barrier per lane BAR (rownolegle do
    /// merc_bar_pos): (id, count) — gold p_namedbar: bar.sync 1,32 -> rekord
    /// 0147 b10=id, b11=01, b12=00, b13=cnt (JEDNA probka — fallback (0,0)
    /// daje stary szablon). Pusty gdy zaden BAR nie ma argumentow.
    pub merc_bar_args: Vec<(u32, u32)>,
    /// Mercury mk13: LOP3-xor w formie REJESTROWEJ (Rd, Ra, Rb, RZ, 0x3c) —
    /// rekord 0129 (16B: dst@[10], srcA@[12], srcB@[14]); lane bez bitu.
    /// (lane, dst, srcA, srcB, guard).
    pub merc_xor_reg: Vec<(u32, u32, u32, u32, u8)>,
    /// Mercury mk13: enum SR per lane S2R (rownolegle do merc_s2r_lanes) —
    /// bajt b12 anchor-rekordu 010b040a (mk13; patrz mercury::merc_s2r_sr_enum).
    pub merc_s2r_sr: Vec<u8>,
    /// mk41: pelny kod predykatu per lane S2R (rownolegle merc_s2r_lanes);
    /// 0xf8 = bez guarda. Rekord-anchor 010b040a nosi b4=guard.
    pub merc_s2r_guard: Vec<u8>,
    /// Mercury mk17a: numer R dest per S2R (rownolegle do merc_s2r_lanes/
    /// merc_s2r_sr) — payload f4 anchor-rekordu 010b040a = (dest<<6)|1.
    /// Puste = legacy fallback na bramkowany anchor_f4 (iter AE model).
    pub merc_s2r_dest: Vec<u32>,
    /// mk56: geo-anchory LDC (rekord 010b040a b13=04) per lane:
    /// (lane, dest, b12-geometria, guard mk41). Per-LDC-lane, nie
    /// per-first-def (dup-def desta nosi rekord per instrukcja; mk56 c6).
    pub merc_ldcgeo: Vec<(u32, u32, u8, u8)>,
    /// Mercury mk18: flagi per wpis merc_param_loads (rownolegle):
    /// bit0 = wartosc loadu feeduje adres operacji atomowej (RED*/ATOM*),
    /// bit1 = load lezy PO instrukcji CALL (granica regionu ptxas).
    pub merc_load_flags: Vec<u8>,
    /// mk18: klucze puli deskryptorow (pi, mech) trafione adresem
    /// instrukcji atomowej (RED*/ATOM*; rekordy 024d/024e): rola (83,00).
    pub merc_atom_pool_hits: Vec<(u32, u8)>,
    /// Mercury mk13: lane'y LOP3 z destem predykatowym (LOP3.LUT Pn, ...) —
    /// NIE dostaja bitu bitmapy, za to mini-rekord 42 2a 02 06 w lane
    /// (gold d_sw4_store slot6).
    pub merc_lop3_pdest: Vec<u32>,
    /// Mercury mk14.3: rekord pinned LDGSTS (lane, dst, src) — 0/1 elem;
    /// i lane hosta wait-event 0123400a (ostatni slot przed DEPBAR).
    pub merc_ldgsts_pin: Vec<(u32, u8, u8)>,
    pub merc_ldgsts_wait: Vec<(u32, u8)>, // (host, imm) — mk55: imm z DEPBAR SB0
    /// mk53: bloby 02233034/3434 per desc-form LDGSTS (pelny silnik; mk14.3
    /// pin = fallback gdy brak desc-form).
    pub merc_ldgsts2: Vec<crate::mercury::Ldgsts2Blob>,
    /// mk53-w: (lane, imm) dla wait-eventow 0123400a per DEPBAR.
    pub merc_ldgsts2_waits: Vec<(u32, u8)>,
    /// Mercury mk14: rekordy atomowe (ATOMG/ATOMS) per instrukcja:
    /// (lane, cls [mercury::MERC_ATOM_CLS_*], guard 0/1/2, dst, addr,
    /// src1, src2, subop_b6); rejestry: 255 = RZ/brak. RED* zostaja na
    /// sciezce legacy REC_ATOM (k_atom/v_atom byte-exact).
    pub merc_atoms: Vec<(u32, u8, u8, u8, u8, u8, u8, u8)>,
    /// Mercury mk14: lane'y duchow __syncwarp (elided do NOP przez ptxas) —
    /// zrodlo: EIATTR attr 0x28 (site offsets) + 0x29 (masks; ghost tylko
    /// gdy maska==0xffffffff i instrukcja w tej lane to NOP). Rekord
    /// 01476c0a w lane (bez bitu bitmapy); lane ZACHOWUJE slot B nawet
    /// wewnatrz spanu BSSY (q_bsync_pair). Puste dla sass-only (tekst
    /// niewidoczny — ghost-NOP jest bit-identyczny z zwyklym NOP).
    pub merc_syncwarp: Vec<u32>,
    /// Mercury mk27: UTCATOMSWS (tcgen05 tmem alloc/dealloc na oknie smem):
    /// (lane, kind): 0 = FIND_AND_SET, 1 = AND. Rekord 51 01 01 63 (18B)
    /// dla FIND_AND_SET, mini 41 63 08 0a dla AND (gold mkvmem).
    pub merc_utca: Vec<(u32, u8)>,
    /// mk27: ATOMS.<op> z imm w adresie [URx+imm]: (lane, imm_bajty, op)
    /// op: 0 = OR, 1 = AND, 2 = inny. Rekord 024e8432 z imm w tail [28:32].
    pub merc_atom_smem: Vec<(u32, u32, u8)>,
    /// mk28: lane'y samo-petli BRA (`BRA L_x` gdzie cel == wlasny adres;
    /// martwy spin-trap za strefa funkcji wewnetrznych). W dialekcie UTCA
    /// (merc_utca niepuste) zwykly BRA dostaje bit bitmapy, ALE samo-petla
    /// nie (gold mkvmem sloty 48/51 tak, slot62 BRA L_400 nie).
    pub merc_bra_selfloop: Vec<u32>,
    /// mk28: EIATTR 0x31 (INT_WARP_WIDE_INSTR_OFFSETS): bajtowe offsety
    /// operacji warp-wide (VOTEU/SHFL/REDUX/MATCHANY) — nvcc listuje je,
    /// gdy kernel zawiera VOTEU (bramka laboratoryjna; korpus 119: 5 takich
    /// kerneli = wszystkie z VOTEU, zero bez). Puste = brak atrybutu.
    pub merc_wwide_sites: Vec<u32>,
    /// mk28: EIATTR 0x28/0x29 SUROWE listy (COOP_GROUP_INSTR_OFFSETS i
    /// COOP_GROUP_MASK_REGIDS) — pelna lista site'ow __syncwarp z oryginalu,
    /// NIE tylko udowodnione duchy (merc_syncwarp). Zrodlo: dyrektywa
    /// `.merc_cgsites` (disasm --frozen) albo parse z cubina. Bajtowe offsety.
    pub merc_cgsites: Vec<u32>,
    pub merc_cgmasks: Vec<u32>,
    /// mk28: kernel zawiera CALL (rekord EIATTR 0x1e CRS_STACK_SIZE + pusta
    /// sekcja .rela.text.K) / strukturalny BSSY (tez 0x1e).
    pub has_call: bool,
    pub has_bssy: bool,

    // ==== mk30: rodziny b_* (SYNCS/mbarrier/TMA/minis; sciezka laned) ====
    /// SYNCS.EXCH.64: (lane, guarded, addr_ur, val_ur) — rekord 021b5e06
    /// (+ marker 51 01 gdy BSSY w kernelu) + blob d1-011b36 przy
    /// UIADD3-count-prologu.
    pub merc_mc_exch: Vec<(u32, bool, u8, u8)>,
    /// SYNCS.ARRIVE.TRANS64: (lane, b4-guard 0xf8/0x00/0x01) — 021b2c32.
    pub merc_mc_arrive: Vec<(u32, u8)>,
    /// SYNCS.PHASECHK.TRANS64.TRYWAIT: lane — rekord 021b4c32.
    pub merc_mc_phase: Vec<u32>,
    /// UIADD3 z immediatem 0x100000 (mbarrier count-prolog): (lane, guarded).
    pub merc_mc_d1: Vec<(u32, bool)>,
    /// USHF.L z imm==0x1 majaca siostre USHF imm==0xb (prolog): mini 414c.
    pub merc_mc_ushf_fin: Vec<u32>,
    /// VOTEU.ALL (kazde wystapienie): mini 414c. (mk26 CLS=0x11d.)
    pub merc_mc_voteu_all: Vec<u32>,
    /// MOV Rn, 0x400 w rodzinie mbarrier (prolog register-path): bez rekordu,
    /// bez bitu gdy EXCH-family (b_mbarrier lane17); park: m_wait/m_arr
    /// maja bit (rozniecie regionowe, mk30b-next).
    pub merc_mc_mov400: Vec<u32>,
    /// LEA Rd, Rs, Rs2, 0x18 w rodzinie mbarrier: mini 41 00 00 0a.
    pub merc_mc_lea18: Vec<u32>,
    /// WARPSYNC.ALL: (lane, b2): 0x6e gdy region za nim zawiera BAR.SYNC,
    /// inaczej 0x76.
    pub merc_ws_minis: Vec<(u32, u8)>,
    /// mk65: WARPSYNC reg-form (plain/EXCLUSIVE): (lane, b2): 0x78 gdy lane
    /// jest site'em EIATTR-0x28 (.merc_cgsites), inaczej 0x70.
    pub merc_wsreg_minis: Vec<(u32, u8)>,
    /// UVIRTCOUNT.DEALLOC.*: mini 41 44 00 3c; lane ZACHOWUJE bit.
    pub merc_uvcount: Vec<u32>,
    /// UMOV URx, URy (reg-reg): mini 41 00 10 0a; lane kasuje bit.
    pub merc_umov_rr: Vec<u32>,
    /// UBLKCP (__raw__ passthrough, slowo ...73ba): lane -> rekord 02232826.
    pub merc_ublkcp: Vec<u32>,
    /// PLOP3-signatury sekwencji expect_tx: (lane, klasa 0=A/1=B/2=C).
    pub merc_plop3_tx: Vec<(u32, u8)>,
    /// mk44: rekordy 0110060a generalne (dual-output PLOP3, bez UP).
    pub merc_plop3_rec: Vec<(u32, [u8; 16])>,
    /// mk54: rekordy 02100214 (PLOP3.LUT z uniform Pc).
    pub merc_plop3u_rec: Vec<(u32, [u8; 32])>,
    /// mk54: rekordy 02100414 (UPLOP3.LUT).
    pub merc_uplop3_rec: Vec<(u32, [u8; 32])>,
    /// mk54: rekordy 0210160e/02100a0e (DSETP z imm f64).
    pub merc_dsetpimm_rec: Vec<(u32, [u8; 32])>,
    /// mk45: rekordy 010b0c0a generalne (CS2R Rd, SRZ).
    pub merc_cs2r_rec: Vec<(u32, [u8; 16])>,
    /// mk47: rekordy 012b{00|04}0a (LOP3.LUT NOT-MOV) — (lane, 16B).
    pub merc_lop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk58: rekordy 012b080a (ULOP3.LUT NOT-MOV) — (lane, 16B).
    pub merc_ulop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk71: rekordy 01291004 (ULOP3.LUT xor LUT=0x3c, 3xUR) — (lane, 16B).
    pub merc_ulop3xor_rec: Vec<(u32, [u8; 16])>,
    /// mk59: rekordy d10102 wariant 47 per WC-site NOP-region — (lane, maska R).
    /// None = sciezka bez skanu tekstu (mk15b-legacy fallback w elf_builder),
    /// Some(vec) = skan po instrukcjach (kernel_def_to_meta / mc_scan_lines).
    pub merc_d1wc47: Option<Vec<(u32, u8)>>,
    /// mk48: rekordy 024d*32 (REDG desc/non-desc) — (lane, 32B pelny payload).
    pub merc_redg2_rec: Vec<(u32, [u8; 32])>,
    /// mk49: rekordy 024e*32 (ATOM.E/ATOMG/ATOMS) — (lane, 32B pelny payload).
    pub merc_atomg2_rec: Vec<(u32, [u8; 32])>,
    /// mk46: rekordy 010b060a geo-anchor (lane, 16B).
    pub merc_geo_rec: Vec<(u32, [u8; 16])>,
    /// FENCE.*ASYNC.*: lane (wszystkie w kolku inwentarza bitowego — mk30b).
    pub merc_fence_async: Vec<u32>,
    /// LDGSTS z .128 (BYPASS.E.128) — wariant pinned-blob (b8=0x20, b10|=0x10).
    pub merc_ldgsts_b128: bool,
    /// HFMA2 z oboma zrodlami RZ + imm (stala materializacja): bez bitu.
    pub merc_hfma2_const: Vec<u32>,
    /// mk30: S2UR ?, SR_CgaCtaId: (lane, guarded) — rekord 010b060a per lane.
    /// mk41: (lane, guarded, dst-UR) — payload smem-anchora z dst.
    pub merc_s2ur_cga: Vec<(u32, bool, u8)>,
    /// mk30: lane'y BSYNC (zamkniecie spanu BSSY) — rekord 51+010109 regionu.
    pub merc_bsync_close: Vec<u32>,
    /// mk62: rekordy 51010109 per zamkniecie regionu BSSY.RECONVERGENT:
    /// (close_lane, barrier_id). None = sciezka legacy (microlab-gold).
    pub merc_region09: Option<Vec<(u32, u8)>>,
    /// mk30b: ULEA prologu mbarrier (dest == addr EXCH, imm 0x18) — bez bitu.
    pub merc_mc_ulea_x: Vec<u32>,
    /// mk30b: braided BRA bez " PT," w rodzinie mbarrier — bez bitu.
    pub merc_mc_bra_np: Vec<u32>,
    /// mk34 (node-model g5b): lane'e bez wezla capmerc (para USHF licznika
    /// mbarrier + FENCE.ASYNC w m-family) — NIE zajmuja slotu bitmapy.
    pub merc_mc_nodeless: Vec<u32>,
    /// mk35: dst-reg loadu param per wpis merc_param_loads (siatka
    /// (R<<6)|C w (b10,b11) rekordow desc — patrz mk35/README; 255=nieznany).
    pub merc_param_load_dreg: Vec<u8>,
    /// mk35: guard per wpis merc_bar_pos: 0=brak, 1=@Pn, 2=@!Pn (b4 rekordu
    /// BAR: 00/01/f8; nvcc bar_if2 vs v_barx).
    pub merc_bar_guard: Vec<u8>,
    /// mk35: ISETP.NE z operandem UR, bez .EX — mini 42 10 32 14, bez bitu
    /// (bar_if2 lane5; 1-probkowe, node-blob g5b tag 02103214 flag0).
    pub merc_isetp_ur: Vec<u32>,
    /// mk41: minis XSETP-par EX (korpu/lab): (lane HEAD-a, klasa taga).
    /// klasa: 0=42102e14 (para czysto-rejestrowa), 1=42103006 (imm w head),
    /// 2=42103214 (operand UR w parze). Head-lane traci bit bitmapy.
    pub merc_xsetp_pairs: Vec<(u32, u8)>,
    /// mk52: minis UISETP-par EX/lancuchow (lane, kind): kind 0=42103614,
    /// 1=42103406, 2=42104014 (kolejnosc = lane-asc; para class-mini+4014
    /// na lane heada). Bitmapowe bity NIE ruszane (decyzja po harnessie).
    pub merc_usetp_minis: Vec<(u32, u8)>,
    /// mk52: mini 42254214 — ULEA z carry-out (2. token UP<num>), wlasny lane.
    pub merc_ulea_upco: Vec<u32>,
    /// mk41: zrodlo sm_100 (marker ;; era=sm100 przez disasm --frozen).
    pub merc_era100: bool,
    /// mk35: rekordy 0132 lane-sorted: (lane, kind, dreg);
    /// kind 0 = REDUX.*-typowane (b6=4d), 1 = CREDUX (b6=51, b13=01);
    /// dreg = numer docelowego UR -> grid [10:12]=(dreg<<6)|1.
    /// Goly "REDUX" (bez kropki) rekordu NIE dostaje — zachowuje bit
    /// bitmapy (at_and lane6, mkvmem) — nie trafia do tej listy.
    pub merc_redux: Vec<(u32, u8, u8)>,   // mk60: legacy (tylko gold-synth)
    /// mk60: rekordy 0132100a ze skanu tekstu (lane, 16B). None = brak skanu.
    pub merc_redux2: Option<Vec<(u32, [u8; 16])>>,
    /// mk35: dst-reg loadu c[0x358] (wariant cbank (b10,b11)=(dreg<<6)|3).
    pub merc_cbank358_dreg: Option<u8>,
    /// mk40 (store-matrix z korpusu sm_100, analysis/merclab/mk40): lane'y
    /// ST.E (generic, rekord 0238 b2=2a b3=32) i STL (local, b2=20 b3=06).
    /// Krotki: (lane, cls 1=ST.E/2=STL, wsel 0=U8/1=U16/2=4B/3=64/4=128,
    /// areg [0xffff=N/A], dur [0xffff=brak desc], dreg [0x3ff=RZ], imm, b4
    /// = 0xf8 bez guarda / (pidx<<3)|neg).
    /// STG zostaje w legacy merc_stg_* (rekord 0238 0e32 nie ruszony).
    /// mk63: 9. pole = semafor b7 rekordu (ST.E: STRONG.SYS -> 0x22,
    /// STRONG.GPU -> 0x1a, inne 0x01; STL zawsze 0x01). Lane'e BEZ wpisu:
    /// STL z adresem czysto-uniform [URx..] (bez rekordu; c23/c15 getrf/
    /// trsv) i terminalny ST.E STRONG.* tuza przed EXIT z MEMBAR.ALL.* w
    /// epilogu (c24: skip 583/583 kerneli, KEEP tylko przy SC/brak).
    pub merc_store2: Vec<(u32, u8, u8, u16, u16, u16, i32, u8, u8)>,
    /// mk40: mini-slownik korpusowy per-lane (klasy z EXACT count-match,
    /// mk40/minidict): (lane, rekord-mini jako u32 LE). Klasy tracked
    /// kasuja bit bitmapy (rekord zastepuje wezel t4); untracked dodaja
    /// tylko rekord. Emisja lane-sorted tier 20.
    pub merc_mini2: Vec<(u32, u32)>,
    /// mk40: per-STG width (0=U8 1=U16 2=4B 3=64 4=128), rownolegle do
    /// merc_stg_pos; puste = legacy (kernel-globalne stg_u8/wide/w128 —
    /// laboratoria jednolite pod tym wzgledem; korpus mieszany).
    pub merc_stg_wsel: Vec<u8>,
    /// mk63: per-STG semafor (rownolegle do merc_stg_pos), bity [2:0]:
    /// kwalifikator semantyczny rekordu 02380e32 — 0 plain / 1 EF /
    /// 2 STRONG.SYS / 3 STRONG.GPU / 4 STRONG.SM, czyli (b7,b8) =
    /// (0x11,0)/(0x10,0)/(0x21,2)/(0xa1,1)/(0xa1,0) (korpus mk63 c13:
    /// EXACT zip 219277 rekordow); bit6 = ENL2.256 (02385232 park — NIE
    /// emitowac falszywego 0e32); bit7 = terminal-STRONG skip (jak mk63
    /// store2: STRONG tuz przed EXIT + MEMBAR.ALL.* w epilogu, syherk).
    pub merc_stg_sem: Vec<u8>,
    /// mk42: rekordy-krawedzie DEF-USE (tag 02 22 32 32) dla LD generic z
    /// desc[URm][Ry.64(+off)]. Selekcja EXACT na korpusie sm_100
    /// (mk42/edge9: 1721/1721 kerneli multiset (X,Y,C,off) == rekordy,
    /// duplikaty zgodne). Payload: b4=pred (pelny kod mk41), b6=klasa
    /// rozmiaru (U8=0x10,S8=0x11,U16=0x12,S16=0x13,32=0x14,64=0x15,
    /// 128=0x16), (b7,b8)=(08,00) lub (10,01) dla STRONG.SYS,
    /// b12..13=(X<<6)|C, b14..15=(Y<<6)|2, b22=0xf8, b28..32=off (u32 LE),
    /// [19:21) = (merc_edge_maxur<<6)|2 stale per kernel.
    /// Krotki: (lane, b4, b6, b7, b8, X, Y, C, off).
    pub merc_edge_ld: Vec<(u32, u8, u8, u8, u8, u16, u16, u8, u32)>,
    /// mk42: maksymalny numer UR w desc[URn] calego kernela (0 gdy brak).
    pub merc_edge_maxur: u16,
    /// mk50: rekordy-krawedzie (tag 02 22 1e 32) dla LDG z
    /// desc[URm][Ry.64(+off)] w kernelach *annotated_ptr* (korpus: tylko
    /// libcublas.so.72 sm_100, 72/72 kerneli EXACT — merclab/mk50 c8b;
    /// zero falszywych trafien na 18227 pozostalych kernelach korpusu).
    /// Dodatkowa bramka per UR: desc[URm] uzywany wylacznie przez lane'y
    /// bazowe LDG (wspoldzielenie ze STG/LDGSTS/REDG wylacza emisje —
    /// konfiguracja UR4 vs UR10/14 w cuds_symv). Payload: b4=pred (pelny
    /// kod mk41), b6=0x40/0x50/0x60 dla 4B/8B/16B, (b7,b8)=(0x81,0x40),
    /// b12..13=(X<<6)|C, b14..15=(Y<<6)|2, b17=0x0a,
    /// [19:21)=(V<<6)|2 z V = desc-UR LANE'U (odmienie niz mk42 maxur!),
    /// b22=0xf8, b28..32=off (u32 LE). Krotki: (lane, b4, b6, X, Y, C, V, off).
    pub merc_edge_ldg: Vec<(u32, u8, u8, u16, u16, u8, u16, u32)>,
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
            merc_bar_pos: Vec::new(),
            merc_stg_pos: Vec::new(),
            merc_stg_desc_pos: Vec::new(),
            merc_bar_pred: false,
            merc_param_uniform: 0,
            merc_param_regpath: 0,
            merc_param_width: Vec::new(),
            merc_xor: Vec::new(),
            merc_stg_off: Vec::new(),
            merc_stg_ser: Vec::new(),
            merc_stg_dreg: Vec::new(),
            merc_stg_dur: Vec::new(),
            merc_stg_guard: Vec::new(),
            merc_stg_areg: Vec::new(),
            merc_mma: Vec::new(),
            merc_f64imm: Vec::new(),
            merc_dfmaimm: Vec::new(),
            merc_pad_pos: Vec::new(),
            merc_param_loads: Vec::new(),
            merc_cbank_lane: None,
            merc_s2r_lanes: Vec::new(),
            merc_s2r_guard: Vec::new(),
            merc_predmem: false,
            merc_guarded_bra: Vec::new(),
            merc_ldgconst: Vec::new(),
            merc_xor_reg: Vec::new(),
            merc_bar_args: Vec::new(),
            merc_s2r_sr: Vec::new(),
            merc_s2r_dest: Vec::new(),
            merc_ldcgeo: Vec::new(),
            merc_load_flags: Vec::new(),
            merc_atom_pool_hits: Vec::new(),
            merc_lop3_pdest: Vec::new(),
            merc_syncwarp: Vec::new(),
            merc_utca: Vec::new(),
            merc_atom_smem: Vec::new(),
            merc_bra_selfloop: Vec::new(),
            merc_store2: Vec::new(),
            merc_mini2: Vec::new(),
            merc_stg_wsel: Vec::new(),
            merc_stg_sem: Vec::new(),
            merc_edge_ld: Vec::new(),
            merc_edge_maxur: 0,
            merc_edge_ldg: Vec::new(),
            merc_wwide_sites: Vec::new(),
            merc_cgsites: Vec::new(),
            merc_cgmasks: Vec::new(),
            has_call: false,
            has_bssy: false,
            merc_mc_exch: Vec::new(),
            merc_mc_arrive: Vec::new(),
            merc_mc_phase: Vec::new(),
            merc_mc_d1: Vec::new(),
            merc_mc_ushf_fin: Vec::new(),
            merc_mc_voteu_all: Vec::new(),
            merc_mc_mov400: Vec::new(),
            merc_mc_lea18: Vec::new(),
            merc_ws_minis: Vec::new(),
            merc_wsreg_minis: Vec::new(),
            merc_uvcount: Vec::new(),
            merc_umov_rr: Vec::new(),
            merc_ublkcp: Vec::new(),
            merc_plop3_tx: Vec::new(),
            merc_plop3_rec: Vec::new(),
            merc_plop3u_rec: Vec::new(),
            merc_uplop3_rec: Vec::new(),
            merc_dsetpimm_rec: Vec::new(),
            merc_cs2r_rec: Vec::new(),
            merc_lop3not_rec: Vec::new(),
            merc_ulop3not_rec: Vec::new(),
            merc_ulop3xor_rec: Vec::new(),
            merc_d1wc47: None,
            merc_redg2_rec: Vec::new(),
            merc_atomg2_rec: Vec::new(),
            merc_geo_rec: Vec::new(),
            merc_fence_async: Vec::new(),
            merc_ldgsts_b128: false,
            merc_hfma2_const: Vec::new(),
            merc_s2ur_cga: Vec::new(),
            merc_bsync_close: Vec::new(),
            merc_region09: None,
            merc_mc_ulea_x: Vec::new(),
            merc_mc_bra_np: Vec::new(),
            merc_mc_nodeless: Vec::new(),
            merc_param_load_dreg: Vec::new(),
            merc_bar_guard: Vec::new(),
            merc_isetp_ur: Vec::new(),
            merc_xsetp_pairs: Vec::new(),
            merc_usetp_minis: Vec::new(),
            merc_ulea_upco: Vec::new(),
            merc_era100: false,
            merc_redux: Vec::new(),
            merc_redux2: None,
            merc_cbank358_dreg: None,
            merc_atoms: Vec::new(),
            merc_ldgsts_pin: Vec::new(),
            merc_ldgsts_wait: Vec::new(),
            merc_ldgsts2: Vec::new(),
            merc_ldgsts2_waits: Vec::new(),
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

        // Mercury mk14: ghost __syncwarp sites. attr 0x28 = SVAL lista offsetow
        // (bajtowych) punktow warp-sync; rownolegle attr 0x29 = maski per site.
        // Duch (rekord 01476c0a) powstaje tylko dla site'a z maska
        // 0xffffffff (bezwarunkowy __syncwarp elidowany do NOP; site'y przy
        // realnych WARPSYNC.COLLECTIVE maja inne maski).
        {
            let mut sites: Vec<u32> = Vec::new();
            let mut masks: Vec<u32> = Vec::new();
            for rec in &per_kernel.records {
                if rec.attr == 0x0028 {
                    sites = rec
                        .data
                        .chunks_exact(4)
                        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                        .collect();
                } else if rec.attr == 0x0029 {
                    masks = rec
                        .data
                        .chunks_exact(4)
                        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                        .collect();
                }
            }
            for (k, &addr) in sites.iter().enumerate() {
                if masks.get(k).copied().unwrap_or(0xffff_ffff) == 0xffff_ffff {
                    meta.merc_syncwarp.push(addr / 16);
                }
            }
            // mk28: surowa kompletna lista 0x28/0x29 do re-emisji EIATTR
            // (disasm --frozen drukuje ja jako `.merc_cgsites`).
            meta.merc_cgsites = sites;
            meta.merc_cgmasks = masks;
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
            merc_bar_pos: Vec::new(),
            merc_stg_pos: Vec::new(),
            merc_stg_desc_pos: Vec::new(),
            merc_bar_pred: false,
            merc_param_uniform: 0,
            merc_param_regpath: 0,
            merc_param_width: Vec::new(),
            merc_xor: Vec::new(),
            merc_stg_off: Vec::new(),
            merc_stg_ser: Vec::new(),
            merc_stg_dreg: Vec::new(),
            merc_stg_dur: Vec::new(),
            merc_stg_guard: Vec::new(),
            merc_stg_areg: Vec::new(),
            merc_mma: Vec::new(),
            merc_f64imm: Vec::new(),
            merc_dfmaimm: Vec::new(),
            merc_pad_pos: Vec::new(),
            merc_param_loads: Vec::new(),
            merc_cbank_lane: None,
            merc_s2r_lanes: Vec::new(),
            merc_s2r_guard: Vec::new(),
            merc_predmem: false,
            merc_guarded_bra: Vec::new(),
            merc_ldgconst: Vec::new(),
            merc_xor_reg: Vec::new(),
            merc_bar_args: Vec::new(),
            merc_s2r_sr: Vec::new(),
            merc_s2r_dest: Vec::new(),
            merc_ldcgeo: Vec::new(),
            merc_load_flags: Vec::new(),
            merc_atom_pool_hits: Vec::new(),
            merc_lop3_pdest: Vec::new(),
            merc_syncwarp: Vec::new(),
            merc_utca: Vec::new(),
            merc_atom_smem: Vec::new(),
            merc_bra_selfloop: Vec::new(),
            merc_store2: Vec::new(),
            merc_mini2: Vec::new(),
            merc_stg_wsel: Vec::new(),
            merc_stg_sem: Vec::new(),
            merc_edge_ld: Vec::new(),
            merc_edge_maxur: 0,
            merc_edge_ldg: Vec::new(),
            merc_wwide_sites: Vec::new(),
            merc_cgsites: Vec::new(),
            merc_cgmasks: Vec::new(),
            has_call: false,
            has_bssy: false,
            merc_mc_exch: Vec::new(),
            merc_mc_arrive: Vec::new(),
            merc_mc_phase: Vec::new(),
            merc_mc_d1: Vec::new(),
            merc_mc_ushf_fin: Vec::new(),
            merc_mc_voteu_all: Vec::new(),
            merc_mc_mov400: Vec::new(),
            merc_mc_lea18: Vec::new(),
            merc_ws_minis: Vec::new(),
            merc_wsreg_minis: Vec::new(),
            merc_uvcount: Vec::new(),
            merc_umov_rr: Vec::new(),
            merc_ublkcp: Vec::new(),
            merc_plop3_tx: Vec::new(),
            merc_plop3_rec: Vec::new(),
            merc_plop3u_rec: Vec::new(),
            merc_uplop3_rec: Vec::new(),
            merc_dsetpimm_rec: Vec::new(),
            merc_cs2r_rec: Vec::new(),
            merc_lop3not_rec: Vec::new(),
            merc_ulop3not_rec: Vec::new(),
            merc_ulop3xor_rec: Vec::new(),
            merc_d1wc47: None,
            merc_redg2_rec: Vec::new(),
            merc_atomg2_rec: Vec::new(),
            merc_geo_rec: Vec::new(),
            merc_fence_async: Vec::new(),
            merc_ldgsts_b128: false,
            merc_hfma2_const: Vec::new(),
            merc_s2ur_cga: Vec::new(),
            merc_bsync_close: Vec::new(),
            merc_region09: None,
            merc_mc_ulea_x: Vec::new(),
            merc_mc_bra_np: Vec::new(),
            merc_mc_nodeless: Vec::new(),
            merc_param_load_dreg: Vec::new(),
            merc_bar_guard: Vec::new(),
            merc_isetp_ur: Vec::new(),
            merc_xsetp_pairs: Vec::new(),
            merc_usetp_minis: Vec::new(),
            merc_ulea_upco: Vec::new(),
            merc_era100: false,
            merc_redux: Vec::new(),
            merc_redux2: None,
            merc_cbank358_dreg: None,
            merc_atoms: Vec::new(),
            merc_ldgsts_pin: Vec::new(),
            merc_ldgsts_wait: Vec::new(),
            merc_ldgsts2: Vec::new(),
            merc_ldgsts2_waits: Vec::new(),
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
