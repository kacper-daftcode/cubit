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
    /// mk15: smem dotknieta WYLACZNIE przez ATOMS (bez STS/LDS/LDSM i bez
    /// .shared) — nvcc emituje rekord 010b060a przy lane pierwszego S2UR
    /// (producer bazowy okna smem; gold p_atoms: miedzy anchor@1 a anchor@6),
    /// a cbank zostaje w wariancie 0301 (nie 83).
    pub smem_atoms_only: bool,
    pub s2ur_first_lane: u32,
    /// mk15b: kernel laduje parametry przez LDCU/ULDC (cbank fa/0e vs f8/0c).
    pub has_ldcu: bool,
    /// mk15b: liczba blokow kolektywnych (ENDCOLLECTIVE) przy plain-BSSY;
    /// kazdy dostaje staly rekord d1-34B po glownym torze rekordow.
    pub bar_count: u32,
    pub n_stg: u32,
    pub n_atom: u32,
    /// Control-flow record (second `01 0b 04 0a`): emitted when the kernel has
    /// >1 EXIT or >1 branch (99.5% corpus rule; known residuals: kernels with
    /// ABI CALLs suppress it, rare early-exit patterns add it).
    pub cflow: bool,
    /// Atom-variant of the cflow record payload (n_atom > 0).
    pub cflow_atom: bool,
    /// Divergent-branch bit in the cflow record payload (BSSY present).
    pub cflow_bssy: bool,
    /// sm_103a-era: kernel dotyka S2R / SHFL (41-wariant rekordu cflow).
    pub os_uses_s2r: bool,
    pub os_shfl: bool,
    pub os_call: bool,
    pub os_mma: bool,
    /// LDG z rejestrowym offsetem (desc-structure) -> cflow 0x40 (era sm_103a).
    pub os_dynldg: bool,
    /// Pozycje kodowe BAR/SYNCS.
    pub bar_pos: Vec<u32>,
    /// Pozycje kodowe STG.
    pub stg_pos: Vec<u32>,
    /// Shift-region record (51010109): BSSY+BSYNC bez BRA.DIV i bez epilogow
    /// kolektywnych (WARPSYNC/ENDCOLLECTIVE) — mikrolab: sw*, p_ldsm, b_bulk_cp.
    pub diverge_region: bool,
    /// Dialekt emitera: true = sm_100-era (m.in. BAR0 przed CBANK), false = sm_103a.
    pub era_sm100: bool,
    /// Jakakolwiek szeroka transakcja zapisu (STG.E.64/128) — zmienia STG-desc.
    pub stg_wide: bool,
    /// STG.E.U8 obecny (wariant STG-desc).
    pub stg_u8: bool,
    /// mk35: kernel zawiera STG.E.128 (rekord 0238: b6=0x60, flaga dreg=6;
    /// nvcc stg128/ld128).
    pub stg_w128: bool,
    /// Per-STG: pozycja desc-parametru (u31 = unknown → fallback idx-row).
    pub stg_desc_pos: Vec<u32>,
    /// mk32: per-STG niski rejestr pary adresowej [R<num>.64] (255=gdy
    /// brak/nieznany). Zrodlo prawdy dla (b12,b13) rekordu 0238:
    /// u16 = (areg<<6)|2. Wypiera mk10b..mk31 modele "pozycji w puli
    /// deskryptorow" (zbiezne bo nvcc-styl allokacji); 144/144 lab.
    pub stg_areg: Vec<u8>,
    /// BAR pod predykatem obecny.
    pub bar_pred: bool,
    /// Kolejnosc pierwszego uzycia parametrow (z KernelMeta.merc_param_order).
    pub param_order: Option<Vec<u32>>,
    /// Bitmaska parametrow write-first (KernelMeta.merc_param_write).
    pub param_write: u32,
    /// Bitmaska parametrow ladowanych przez LDCU* (uniform datapath) —
    /// deskryptor 0222 w wariancie `08 06` + b4=fa zamiast `0e 06` + f8.
    pub param_uniform: u32,
    /// Bitmaska parametrow ladowanych przez LDC* (register path).
    pub param_regpath: u32,
    /// Per-param szerokosc transferu loadu cbank (1/2/4/8/16 B; 0=nieznana→8).
    pub param_width: Vec<u8>,
    /// Pozycje kodowe ELECT (mini-rekord 41 64 00 0a w lane kodu).
    pub elect_pos: Vec<u32>,
    /// Rekordy 0229 (C-level `xor Rd, Rs, imm32`; SASS LOP3.LUT lut=0x3c):
    /// (lane, dst, src, imm, b4) z b4 = 0xf8 brak predykatu / 0x00 @Pn /
    /// 0x01 @!Pn (fs6/fs7-lab 2026-08-05). Lane NIE dostaje bitu bitmapy.
    pub xor_lanes: Vec<(u32, u32, u32, u32, u8)>,
    /// Per-STG natychmiastowy offset adresu (bajty; bajt 28 rekordu 02 38;
    /// fs10-grid 2026-08-05).
    pub stg_off: Vec<i32>,
    /// mk10b: per-STG pakiet (nulltail<<7)|series_idx-z-blokow (sass scan).
    /// Uzywane TYLKO gdy wszystkie dp==0 (same-desc seria), inaczej legacy.
    pub stg_ser: Vec<u8>,
    /// mk12: per-STG rejestr danych (kursor 0238 b19/b20 = dreg<<6, LE).
    pub stg_dreg: Vec<u8>,
    /// fala A: per-STG desc-UR i wariant guardu (b17/b18, b4).
    pub stg_dur: Vec<u8>,
    pub stg_guard: Vec<u8>,
    /// Pozycje kodowe ACQBULK (rekord 01 62 00 0a w lane, bez bitu bitmapy;
    /// gold w_depsync / mk10c).
    pub acqbulk_pos: Vec<u32>,
    /// Pozycje kodowe CCTL.* (marker 51 02 + rekord 01 49 10 0a w lane,
    /// bez bitu; gold p_fence).
    pub cctl_pos: Vec<u32>,
    /// mk11: instrukcje MMA -> rekord 025a w lane: (lane, cls, d, a, b, c, b8f).
    pub mma_lanes: Vec<(u32, u8, u8, u8, u8, u8, u8)>,
    /// mk11+mk51: DMUL/DADD z imm f64 -> rekordy 020f120e/020c1e0e w lane:
    /// (lane, var, d, a, imm_top32, pred, b7=2*negA+4*absA; RZ-src = 0x3ff).
    pub f64_lanes: Vec<(u32, u8, u16, u16, u32, u8, u8)>,
    /// mk51: DFMA z imm f64 -> rekordy 020d1c0e (imm-last) / 020d1a0e
    /// (imm-middle) w lane: (lane, variant[0=last,1=mid], pred, b7, d, a, b,
    /// imm64bits; b7 = 2*negA+8*negB+4*absA+16*absB). Lane bez bitu bitmapy.
    pub dfmaim: Vec<(u32, u8, u8, u8, u16, u16, u16, u64)>,
    /// mk11: lane UIADD3 (killpad uniform) -> atom d0 00 w lane.
    pub pad_pos: Vec<u32>,
    /// mk12 (iter AD): payload rekordu cflow-anchor `01 0b 04 0a`:
    /// (b10,b11) = (f4<<6)|1, gdzie f4 = metryka regionu ptxas. Model
    /// empiryczny dopasowany na secie gold (70/70 pozycji; oraculum
    /// gdb-zmierzone, patrz anal/merclab/mk17). Pełna semantyka pola
    /// (region-tree node+0x38, klasa 1) = osobny watek mk12.
    pub anchor_f4: u32,
    /// mk12: >=2 instrukcje MMA rodziny (HMMA/IMMA) kasuja b12 rekordu anchor.
    pub os_mma_multi: bool,
    /// mk10c: loady param-window z kodu: (lane, pi, uniform01, width, guard).
    /// Puste = sciezka legacy (blok desc).
    pub param_loads: Vec<(u32, u32, u8, u8, u8)>,
    /// mk10c: lane loadu c[0x358] (rekord cbank/D).
    pub cbank_lane: Option<u32>,
    /// mk10c: lane instrukcji S2R (anchor 010b040a per S2R).
    pub s2r_lanes: Vec<u32>,
    /// mk10c: kernel ma predykowane operacje pamieci (gaszenie bramki f4=7).
    pub predmem: bool,
    /// mk13: lane'y LOP3 z destem predykatowym -> mini-rekord 42 2a 02 06
    /// w lane (lane same w sobie bitow bitmapy nie dostaja — obslugiwane
    /// w generate_mercury_full).
    pub lop3_pdest: Vec<u32>,
    /// mk13: enum SR per anchor-S2R (rownolegle do s2r_lanes) — b12 rekordu
    /// 010b040a (korpus: LANEID=0 -> b12=0 TID.X=1 CTAID.X=4 LTMASK=8).
    pub s2r_sr: Vec<u8>,
    /// mk41: pelny kod guarda per S2R (0xf8 domyslnie).
    pub s2r_guard: Vec<u8>,
    /// mk17a: numer R dest per anchor-S2R (rownolegle do s2r_lanes/s2r_sr) —
    /// payload f4 rekordu 010b040a bajty [10:11] = (dest<<6)|1. Empiria
    /// mk20-oraculum: 90/90 anchorow. Krotki/pusty wektor = fallback na
    /// bramkowany MercFeatures.anchor_f4 (model iter AE).
    pub s2r_dest: Vec<u32>,
    /// mk56: geo-anchory LDC 010b040a b13=04: (lane, dest, b12, guard).
    pub ldcgeo: Vec<(u32, u32, u8, u8)>,
    /// mk18: flagi per param_loads (bit1 = post-CALL); klucze puli (pi,mech)
    /// trafione adresem atomowym — oba steruja rola desc (83,00).
    pub load_flags: Vec<u8>,
    pub atom_pool_hits: Vec<(u32, u8)>,
    /// mk13: uzycia desc przez LDG.E.CONSTANT (lane, pi) — wpis (pi,2) w
    /// puli slotow STG (v_ldg_u64 s=2 przy 2 deskryptorach wide).
    pub ldgconst: Vec<(u32, u32)>,
    /// mk13: wariant roli (03,01) dla deskryptora uniform-8B zamiast (83,01)
    /// — gold: p_exit2 (exits>=2), p_cas (ATOMG.CAS), p_lds/p_ldsm/p_sts2
    /// (LDS/STS/LDSM). LDGSTS ma pierwszenstwo i dalej daje (03,02).
    pub u_role_alt1: bool,
    /// mk13: CCTL.E.RML2 (discard.global.L2) = mini-rekord 41 0e 02 0c w lane
    /// ZAMIAST markera 51 02 + rekordu 01 49 10 0a (gold p_cctl vs p_fence).
    pub cctl_rml2_pos: Vec<u32>,
    /// mk13: argumenty named-barrier per rekord BAR w strumieniu (rownolegle
    /// merc_bar_args po indeksie bar_pos): przy id!=0||cnt!=0 bajty b10=id,
    /// b11=01, b12=00, b13=cnt; (0,0) = szablon REC_BAR. Gold: p_namedbar
    /// (bar.sync 1,32). JEDNA probka gold.
    pub bar_args: Vec<(u32, u32)>,
    /// mk13: rejestrowa forma LOP3-xor (Rd, Ra, Rb, RZ, 0x3c) -> rekord 0129
    /// (16B) w lane; (lane, dst, srcA, srcB, b4 jak xor_lanes).
    pub xor_reg_lanes: Vec<(u32, u32, u32, u32, u8)>,
    /// mk13: REDUX.* (warp-reduce) -> event-rekord 01 32 10 0a (16B) w lane;
    /// lane NIE dostaje bitu bitmapy (rekord zastepuje wezel t4; gold p_redux
    /// slot10). Bajty [6]=0x4d + [10,11]=(lane-bity?) — jedna probka gold,
    /// model = stala obserwowana + dostosowanie [10..12] po rejestrze dest?
    /// (park: jesli drugi wzorzec REDUX sie pojawi, dopasowac b10/11).
    pub redux_pos: Vec<u32>,
    /// mk10c: LDGSTS obecne — rekord desc uniform przy atomikach/async
    /// p_lgsts (03,02).
    pub n_ldgsts: u32,
    /// mk14: rekordy atomowe per-instrukcja (lane, cls, guard, dst, addr,
    /// src1, src2, subop_b6); puste = zachowanie legacy (trailing REC_ATOM).
    pub atoms: Vec<(u32, u8, u8, u8, u8, u8, u8, u8)>,
    /// mk14: cbank wariant 8301 takze przy CAS.SYS (gold p_cas: kernel bez
    /// smem, cbank b10=0x83). Aktywne w Ev::Cbank obok smem_static.
    pub cbank83_cas: bool,
    /// mk14.3: pinned LDGSTS (lane,dst,src) -> marker 51 02 + blob 02233034;
    /// host traci bit bitmapy. wait-lane -> 0123400a (host tez traci bit).
    pub ldgsts_pin: Option<(u32, u8, u8)>,
    pub ldgsts_wait: Option<(u32, u8)>,
    /// mk53: bloby 02233034/3434 per desc-form LDGSTS (silnik nadrzedny).
    pub ldgsts2: Vec<crate::mercury::Ldgsts2Blob>,
    /// mk53-w: (lane, imm) wait-eventow 0123400a per DEPBAR (silnik mk53).
    pub ldgsts2_waits: Vec<(u32, u8)>,
    /// mk14.3: lane'y LDSM -> mini 42 5b 02 06 (rekord zastepuje wezel t4).
    pub ldsm_lanes: Vec<u32>,
    /// mk14: lane'y duchow __syncwarp (z KernelMeta.merc_syncwarp; EIATTR
    /// 0x28+0x29): rekord 01476c0a w lane; lane NIE traci slotu B w spanie
    /// BSSY (q_bsync_pair), w bitmapie zachowuje sie jak zwykly NOP
    /// (poza spanem: bez bitu; w spanie: bit per regula spanowa).
    pub syncwarp: Vec<u32>,
    /// mk27: UTCATOMSWS (lane, kind 0=FIND_AND_SET/1=AND/2=inny).
    pub utca: Vec<(u32, u8)>,
    /// mk27: ATOMS z imm w adresie [URx+imm]: (lane, imm, op 0=OR/1=AND/2=inny).
    pub atom_smem: Vec<(u32, u32, u8)>,
    /// mk27: wszystkie lane'y S2UR (rekord smem-anchor 010b060a per S2UR,
    /// gold mkvmem: lane 4 i 27); puste poza 0-param sciezka pozycyjna.
    pub s2ur_lanes: Vec<u32>,
    /// mk27: ghost-lane pokryte REALNA instrukcja kolektywna (site == nie-NOP)
    /// -> mini 41 47 76 0a zamiast pelnego 01 47 6c 0a (mkvmem lane 26).
    pub ghost_mini76: Vec<u32>,
    /// mk27: kernel zawiera wewnetrzne funkcje z RET (guardrail traps) —
    /// ogon strumienia ghostowy (mkvmem: czwarty ghost 01476c0a).
    pub has_ret_internal: bool,

    // ==== mk30: rodziny b_* (lustro z KernelMeta) ====
    pub mc_exch: Vec<(u32, bool, u8, u8)>,
    pub mc_arrive: Vec<(u32, u8)>,
    pub mc_phase: Vec<u32>,
    pub mc_d1: Vec<(u32, bool)>,
    pub mc_ushf_fin: Vec<u32>,
    pub mc_voteu_all: Vec<u32>,
    pub mc_mov400: Vec<u32>,
    pub mc_lea18: Vec<u32>,
    pub ws_minis: Vec<(u32, u8)>,
    pub uvcount: Vec<u32>,
    pub umov_rr: Vec<u32>,
    pub ublkcp: Vec<u32>,
    pub plop3_tx: Vec<(u32, u8)>,
    pub plop3_rec: Vec<(u32, [u8; 16])>,
    pub plop3u_rec: Vec<(u32, [u8; 32])>,
    pub uplop3_rec: Vec<(u32, [u8; 32])>,
    pub dsetpimm_rec: Vec<(u32, [u8; 32])>,
    pub cs2r_rec: Vec<(u32, [u8; 16])>,
    /// mk47: rekordy 012b{00|04}0a (LOP3.LUT NOT-MOV LUT=0x33).
    pub lop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk58: rekordy 012b080a (ULOP3 NOT-MOV).
    pub ulop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk59: rekordy d10102-47 per WC-site (NOP-region) — (lane, maska R).
    pub d1wc47: Vec<(u32, u8)>,
    /// mk59: skan tekstowy dostepny (Some) vs mk15b-legacy fallback.
    pub d1wc47_scanned: bool,
    /// mk15b-legacy: liczba rekordow const (fallback gdy !d1wc47_scanned).
    pub d1wc47_legacy: u32,
    /// mk48: rekordy 024d*32 (REDG desc/non-desc) — (lane, 32B pelny payload).
    pub redg2_rec: Vec<(u32, [u8; 32])>,
    /// mk49: rekordy 024e*32 (ATOM.E/ATOMG/ATOMS) — (lane, 32B pelny payload).
    pub atomg2_rec: Vec<(u32, [u8; 32])>,
    /// mk46: rekordy 010b060a geo-anchor (lane, 16B pelny payload).
    pub geo_rec: Vec<(u32, [u8; 16])>,
    pub fence_async: Vec<u32>,
    pub ldgsts_b128: bool,
    /// mk41: (lane, guarded, dst-UR) dla S2UR SR_CgaCtaId — payload
    /// smem-anchora b10/b11 = (dstUR<<6)|1 (corpus-exact smemfit 12151/12151).
    pub s2ur_cga: Vec<(u32, bool, u8)>,
    pub bsync_close: Vec<u32>,
    pub hfma2_const: Vec<u32>,
    /// mk30b: ULEA prologu mbarrier (dest==addr EXCH) — bez bitu (kasowany).
    pub mc_ulea_x: Vec<u32>,
    /// mk30b: braided BRA bez " PT," w rodzinie mbarrier — bez bitu.
    pub mc_bra_np: Vec<u32>,
    /// mk34 (node-model g5b): lane'e bez wezlow capmerc = bez slotu bitmapy.
    pub mc_nodeless: Vec<u32>,
    /// mk35: dst-reg per param-load (siatka (R<<6)|C w rolach desc).
    pub param_load_dreg: Vec<u8>,
    /// mk35: guard per BAR (rownolegle bar_pos): 0=brak 1=@P 2=@!P.
    pub bar_guard: Vec<u8>,
    /// mk35: ISETP-UR (bez .EX) — mini 42 10 32 14, bez bitu.
    pub isetp_ur: Vec<u32>,
    /// mk41: XSETP EX-pair minis: (head-lane, klasa).
    pub xsetp_pairs: Vec<(u32, u8)>,
    /// mk52: UISETP minis (lane, kind): 0=42103614, 1=42103406, 2=42104014.
    pub usetp_minis: Vec<(u32, u8)>,
    /// mk52: ULEA carry-out -> mini 42254214 (lane).
    pub ulea_upco: Vec<u32>,
    /// mk41: marker ery zrodla.
    pub era100: bool,
    /// mk35: redukcyjne rekordy 0132: (lane, kind, dreg); kind 0=REDUX
    /// typowany, 1=CREDUX. Goly REDUX nie dostaje rekordu (bit zostaje).
    pub redux: Vec<(u32, u8, u8)>,   // legacy (gold-synth; mk60: redux2)
    /// mk60: rekordy 0132100a ze skanu — (lane, 16B pelny rekord).
    pub redux2: Vec<(u32, [u8; 16])>,
    /// mk60: skan dostepny (wylacza legacy-synth z samych opcode'ow).
    pub redux2_scanned: bool,
    /// mk35: dst-reg loadu c[0x358] dla wariantu cbank (b10,b11).
    pub cbank358_dreg: Option<u8>,
    /// mk40: store-matrix rekordow 0238 dla ST.E (2a32) / STL (2006).
    /// (lane, cls 1=ST.E 2=STL, wsel 0=U8/1=U16/2=4B/3=64/4=128,
    /// areg/dur [0xffff=N/A], dreg [0x3ff=RZ], imm, b4).
    pub store2: Vec<(u32, u8, u8, u16, u16, u16, i32, u8)>,
    /// mk40: mini-slownik (lane, u32 LE 4B rekordu); lane bez bitu.
    pub mini2: Vec<(u32, u32)>,
    /// mk42: rekordy edge LD-desc (layout: eiattr.rs merc_edge_ld).
    pub edge_ld: Vec<(u32, u8, u8, u8, u8, u16, u16, u8, u32)>,
    /// mk42: stala per-kernel [19:21) = (edge_v<<6)|2 (max desc-UR).
    pub edge_v: u16,
    /// mk50: rekordy edge 02 22 1e 32 = LDG-desc w kernelach annotated_ptr
    /// (bramka: sass_file::merc_edge_ldg_scan; krotki (lane,b4,b6,X,Y,C,V,off)).
    pub edge_ldg: Vec<(u32, u8, u8, u16, u16, u8, u16, u32)>,
    /// mk40 (podkmatryca mk32): per-STG width (wsel) rownolegle do stg_pos;
    /// puste = legacy (kernel-global stg_u8/stg_wide/stg_w128).
    pub stg_wsel: Vec<u8>,
}

impl MercFeatures {
    pub fn from_parts(meta: &KernelMeta, opcodes: &[String]) -> Self {
        let mut f = MercFeatures {
            syncwarp: meta.merc_syncwarp.clone(),
            utca: meta.merc_utca.clone(),
            atom_smem: meta.merc_atom_smem.clone(),
            atoms: meta.merc_atoms.clone(),
            ldgsts_pin: meta.merc_ldgsts_pin.first().copied(),
            ldgsts_wait: meta.merc_ldgsts_wait.first().copied(),
            ldgsts2: meta.merc_ldgsts2.clone(),
            ldgsts2_waits: meta.merc_ldgsts2_waits.clone(),
            ldsm_lanes: opcodes
                .iter()
                .enumerate()
                .filter(|(_, o)| o.starts_with("LDSM"))
                .map(|(i, _)| i as u32)
                .collect(),
            used_params: meta.params.iter().filter(|p| p.size > 4).count() as u32,
            used_scalar_params: meta.params.iter().filter(|p| p.size <= 4).count() as u32,
            // mk30: rodziny b_* z meta (skan sass_file / lustro main.rs).
            mc_exch: meta.merc_mc_exch.clone(),
            mc_arrive: meta.merc_mc_arrive.clone(),
            mc_phase: meta.merc_mc_phase.clone(),
            mc_d1: meta.merc_mc_d1.clone(),
            mc_ushf_fin: meta.merc_mc_ushf_fin.clone(),
            mc_voteu_all: meta.merc_mc_voteu_all.clone(),
            mc_mov400: meta.merc_mc_mov400.clone(),
            mc_lea18: meta.merc_mc_lea18.clone(),
            ws_minis: meta.merc_ws_minis.clone(),
            uvcount: meta.merc_uvcount.clone(),
            umov_rr: meta.merc_umov_rr.clone(),
            ublkcp: meta.merc_ublkcp.clone(),
            plop3_tx: meta.merc_plop3_tx.clone(),
            plop3_rec: meta.merc_plop3_rec.clone(),
            plop3u_rec: meta.merc_plop3u_rec.clone(),
            uplop3_rec: meta.merc_uplop3_rec.clone(),
            dsetpimm_rec: meta.merc_dsetpimm_rec.clone(),
            cs2r_rec: meta.merc_cs2r_rec.clone(),
            lop3not_rec: meta.merc_lop3not_rec.clone(),
            ulop3not_rec: meta.merc_ulop3not_rec.clone(),
            d1wc47: meta.merc_d1wc47.clone().unwrap_or_default(),
            d1wc47_scanned: meta.merc_d1wc47.is_some(),
            // mk15b-legacy (sciezki bez skanu tekstu, np. microlab-gold surowe
            // mnemonic-listy): d1-34B const (maska R0) per ENDCOLLECTIVE gdy BSSY.
            d1wc47_legacy: if opcodes.iter().any(|o| o.as_str() == "BSSY") {
                opcodes.iter().filter(|o| o.starts_with("ENDCOLLECTIVE")).count() as u32
            } else {
                0
            },
            redg2_rec: meta.merc_redg2_rec.clone(),
            atomg2_rec: meta.merc_atomg2_rec.clone(),
            geo_rec: meta.merc_geo_rec.clone(),
            fence_async: meta.merc_fence_async.clone(),
            ldgsts_b128: meta.merc_ldgsts_b128,
            s2ur_cga: meta.merc_s2ur_cga.clone(),
            bsync_close: meta.merc_bsync_close.clone(),
            hfma2_const: meta.merc_hfma2_const.clone(),
            mc_ulea_x: meta.merc_mc_ulea_x.clone(),
            mc_bra_np: meta.merc_mc_bra_np.clone(),
            mc_nodeless: meta.merc_mc_nodeless.clone(),
            param_load_dreg: meta.merc_param_load_dreg.clone(),
            bar_guard: meta.merc_bar_guard.clone(),
            isetp_ur: meta.merc_isetp_ur.clone(),
            xsetp_pairs: meta.merc_xsetp_pairs.clone(),
            usetp_minis: meta.merc_usetp_minis.clone(),
            ulea_upco: meta.merc_ulea_upco.clone(),
            era100: meta.merc_era100,
            redux: meta.merc_redux.clone(),
            redux2: meta.merc_redux2.clone().unwrap_or_default(),
            redux2_scanned: meta.merc_redux2.is_some(),
            cbank358_dreg: meta.merc_cbank358_dreg,
            store2: meta.merc_store2.clone(),
            mini2: meta.merc_mini2.clone(),
            edge_ld: meta.merc_edge_ld.clone(),
            edge_v: meta.merc_edge_maxur,
            edge_ldg: meta.merc_edge_ldg.clone(),
            stg_wsel: meta.merc_stg_wsel.clone(),
            ..Default::default()
        };
        // mk30b: sciezki bez skanu sass (gold/manifest) wyprowadzaja
        // bsync_close/ws_minis z samych opcode'ow.
        if f.bsync_close.is_empty() {
            f.bsync_close = opcodes
                .iter()
                .enumerate()
                .filter(|(_, o)| o.starts_with("BSYNC"))
                .map(|(i, _)| i as u32)
                .collect();
        }
        if f.ws_minis.is_empty() {
            let bar_lanes: Vec<u32> = opcodes
                .iter()
                .enumerate()
                .filter(|(_, o)| o.starts_with("BAR.SYNC"))
                .map(|(i, _)| i as u32)
                .collect();
            let ws: Vec<u32> = opcodes
                .iter()
                .enumerate()
                .filter(|(_, o)| o.starts_with("WARPSYNC.ALL"))
                .map(|(i, _)| i as u32)
                .collect();
            for (k, w) in ws.iter().enumerate() {
                let end = ws.get(k + 1).copied().unwrap_or(u32::MAX);
                let has_bar = bar_lanes.iter().any(|&b| b > *w && b < end);
                f.ws_minis.push((*w, if has_bar { 0x6e_u8 } else { 0x76_u8 }));
            }
        }
        let n_bra = opcodes
            .iter()
            .filter(|o| {
                let b = o.split('.').next().unwrap_or(o);
                matches!(b, "BRA" | "BRX" | "JMP" | "JMPX")
            })
            .count();
        // mk49: ATOMS.CAST.SPIN (spin-loop CAS-emulacji) nie dostaje rekordow
        // capmerc — wylaczone z n_atom (korpus mk49/c8: 0 rekordow na 4465 lane'ow).
        f.n_atom = opcodes
            .iter()
            .filter(|o| {
                (o.starts_with("REDG") || o.starts_with("ATOMS") || o.starts_with("ATOMG"))
                    && !o.contains(".CAST.")
            })
            .count() as u32;
        f.cflow_atom = f.n_atom > 0;
        f.cflow_bssy = opcodes.iter().any(|o| o.starts_with("BSSY"));
        f.os_uses_s2r = opcodes.iter().any(|o| o.starts_with("S2R"));
        f.os_shfl = opcodes.iter().any(|o| o.starts_with("SHFL"));
        f.os_mma = opcodes.iter().any(|o| {
            let b = o.split('.').next().unwrap_or(o);
            matches!(b, "HMMA" | "IMMA" | "DMMA" | "QMMA" | "OMMA")
        });
        // obecnosc: >1 EXIT | >1 BRA | atom | BSSY | SHFL | S2R (era 103a
        // LDG-dynamic-path; zero kolizji na gold-zbiorze)
        f.cflow = (meta.exit_offsets.len() > 1 || n_bra > 1
            || f.n_atom > 0 || f.cflow_bssy || f.os_shfl
            || f.os_uses_s2r || f.os_dynldg)
            && !opcodes.iter().any(|o| o.starts_with("RET"));
        // mk13: rekord smem dla kazdego kernela dotykajacego smem — statyczne
        // (.shared -> shared_size>0) LUB dynamiczne (extern __shared__ wchodzi
        // tylko przez operacje STS/LDS/LDSM; gold v_dyn_smem: 010b060a +
        // cbank-variant 8301 mimo shared_size==0 z EIATTR).
        // mk30b: rekord smem wymaga okna UR (S2UR SR_CgaCtaId) — b_ldmatrix
        // (LDSM przez generic-adres, BEZ S2UR) zadnego nie dostaje (ani
        // wariantu cbank 83). Gold z S2UR zostaje (p_ldsm, v_dyn_smem).
        let smem_ops = opcodes
            .iter()
            .any(|o| matches!(o.split('.').next(), Some("STS") | Some("LDS") | Some("LDSM")))
            && !meta.merc_s2ur_cga.is_empty();
        // mk17b (2026-08-08): ptxas NIE promuje wariantu smem dla martwego
        // .shared — gate'uje wylacznie operacjami smem w kodzie. Dowod:
        // p_atoms ma __shared__ int sh[1] (1028B w .nv.shared) a nvcc
        // emituje wariant atoms-only (cbank 0301, rekord smem @lane S2UR).
        // W gold-srcie smem_static == smem_ops i tak (manifest smem:0).
        f.smem_static = smem_ops;
        let atoms_ops = opcodes
            .iter()
            .any(|o| o.split('.').next() == Some("ATOMS"));
        f.smem_atoms_only = atoms_ops && !f.smem_static;
        f.s2ur_first_lane = opcodes
            .iter()
            .position(|o| o.split('.').next() == Some("S2UR"))
            .map(|i| i as u32)
            .unwrap_or(u32::MAX);
        f.s2ur_lanes = opcodes
            .iter()
            .enumerate()
            .filter(|(_, o)| o.split('.').next() == Some("S2UR"))
            .map(|(i, _)| i as u32)
            .collect();
        // ghost pokryty realna instrukcja (nie-NOP) -> mini 76-wariant
        f.ghost_mini76 = f
            .syncwarp
            .iter()
            .copied()
            .filter(|&l| {
                opcodes
                    .get(l as usize)
                    .map(|o| o.split('.').next() != Some("NOP") && o.as_str() != "NOP")
                    .unwrap_or(false)
            })
            .collect();
        f.has_ldcu = opcodes.iter().any(|o| {
            let b = o.split('.').next().unwrap_or(o.as_str());
            b == "LDCU" || b == "ULDC"
        });
        f.has_ret_internal = opcodes.iter().any(|o| o.split('.').next() == Some("RET"));
        // mk14: cbank 8301 takze dla ATOMG.E.CAS.STRONG.SYS (gold p_cas).
        f.cbank83_cas = opcodes
            .iter()
            .any(|o| o.starts_with("ATOMG") && o.contains("CAS") && o.contains(".SYS"));
        f.n_stg = opcodes.iter().filter(|o| o.starts_with("STG")).count() as u32;
        f.bar_count = meta.num_barriers as u32;
        f.os_call = opcodes.iter().any(|o| o.starts_with("CALL"));
        f.os_dynldg = meta.merc_dynldg;
        let n_bssy = opcodes.iter().filter(|o| o.starts_with("BSSY")).count();
        let n_bsync = opcodes.iter().filter(|o| o.starts_with("BSYNC")).count();
        let n_bradiv = opcodes.iter().filter(|o| o.starts_with("BRA.DIV")).count();
        let n_ec = opcodes.iter().filter(|o| o.starts_with("ENDCOLLECTIVE")).count();
        let n_ws = opcodes.iter().filter(|o| o.starts_with("WARPSYNC")).count();
        f.diverge_region = n_bssy > 0 && n_bsync > 0 && n_bradiv == 0 && n_ec == 0 && n_ws == 0;
        f.stg_wide = opcodes
            .iter()
            .any(|o| o.starts_with("STG") && (o.contains(".64") || o.contains(".128")));
        f.param_order = meta.merc_param_order.clone();
        f.param_write = meta.merc_param_write;
        f.param_uniform = meta.merc_param_uniform;
        f.param_regpath = meta.merc_param_regpath;
        f.param_width = meta.merc_param_width.clone();
        f.xor_lanes = meta
            .merc_xor
            .iter()
            .map(|&(lane, d, src, imm, g)| {
                (lane, d, src, imm, match g { 0 => 0xf8, 1 => 0x00, _ => 0x01 })
            })
            .collect();
        f.bar_pos = meta.merc_bar_pos.clone();
        f.bar_args = meta.merc_bar_args.clone();
        f.stg_pos = meta.merc_stg_pos.clone();
        f.stg_desc_pos = meta.merc_stg_desc_pos.clone();
        f.bar_pred = meta.merc_bar_pred;
        f.stg_u8 = opcodes.iter().any(|o| o.starts_with("STG") && o.contains(".U8"));
        f.stg_w128 = opcodes
            .iter()
            .any(|o| o.starts_with("STG") && o.contains(".128"));
        f.elect_pos = opcodes
            .iter()
            .enumerate()
            .filter(|(_, o)| o.starts_with("ELECT"))
            .map(|(i, _)| i as u32)
            .collect();
        f.stg_off = meta.merc_stg_off.clone();
        // mk12: metryka f4 anchor#2 (pelna regula empiryczna z fitu gold+pommiary
        // gdb; klasa bramkowana per obecnosc klas opkodu w kernelu).
        let cnt = |pat: &str| {
            opcodes.iter().filter(|o| o.split('.').next() == Some(pat)).count() as u32
        };
        let ldg = cnt("LDG");
        let stg = cnt("STG");
        let mma_f = cnt("HMMA") + cnt("IMMA");
        f.os_mma_multi = mma_f >= 2;
        let f64g = cnt("DMMA") + cnt("DMUL") + cnt("DADD");
        let ldgsts = cnt("LDGSTS");
        let cctl = cnt("CCTL");
        let membar = cnt("MEMBAR");
        let bssy = cnt("BSSY");
        let sts = cnt("STS");
        let lds = cnt("LDS");
        let bar = cnt("BAR");
        let isetp = cnt("ISETP");
        let i2fp = cnt("I2FP");
        let f2i = cnt("F2I");
        f.anchor_f4 = if f64g > 0 {
            8
        } else if mma_f > 0 {
            if mma_f == 1 { 4 } else { 5 }
        } else if ldgsts > 0 || ldg >= 4 {
            11
        } else if cctl > 0 && membar == 0 {
            7
        } else if bssy > 0 && ldg >= 1 && sts >= 1 {
            7
        } else if ldg >= 1 && stg >= 1 && ldg + stg >= 3 && !meta.merc_predmem {
            // mk12a (k_ldg2/p_stg2/c_ld_dyn2: 7 vs d_ifelse_ld: 0 — gasi
            // bramke predykowana pamiec @P LDG/STG; pozostale gate'y pokrywaja)
            7
        } else if isetp >= 6 && bssy == 0 {
            4
        } else if sts >= 1 && lds >= 1 && bar >= 1 && bssy == 0 {
            0
        } else if i2fp >= 1 && f2i >= 1 {
            0
        } else if ldg >= 1 && ldg + stg >= 2 && f.os_dynldg {
            5
        } else {
            0
        };
        f.stg_ser = meta.merc_stg_ser.clone();
        f.stg_dreg = meta.merc_stg_dreg.clone();
        f.stg_dur = meta.merc_stg_dur.clone();
        f.stg_guard = meta.merc_stg_guard.clone();
        f.acqbulk_pos = opcodes
            .iter()
            .enumerate()
            .filter(|(_, o)| o.split('.').next() == Some("ACQBULK"))
            .map(|(i, _)| i as u32)
            .collect();
        // mk13: CCTL.E.RML2 ma wlasny mini-atom; pozostale CCTL -> cctl_pos.
        f.cctl_rml2_pos = opcodes
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                o.split('.').next() == Some("CCTL") && o.contains(".RML2")
            })
            .map(|(i, _)| i as u32)
            .collect();
        f.cctl_pos = opcodes
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                o.split('.').next() == Some("CCTL") && !o.contains(".RML2")
            })
            .map(|(i, _)| i as u32)
            .collect();
        f.pad_pos = meta.merc_pad_pos.clone();
        // mk35: rekord 0132 tylko dla TYPOWANYCH REDUX (z kropka/modami)
        // + CREDUX; goly "REDUX" zachowuje bit bitmapy (at_and slot6).
        f.redux_pos = opcodes
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                let b = o.split('.').next().unwrap_or(o);
                (b == "REDUX" && o.as_str() != "REDUX") || b == "CREDUX"
            })
            .map(|(i, _)| i as u32)
            .collect();
        // gold/manifest path (brak meta.merc_redux): syntetyzuj wpis z
        // opcode'ow; dreg=6 odtwarza historyczny szablon (UR6-shadow).
        if f.redux.is_empty() && !f.redux_pos.is_empty() && !f.redux2_scanned {
            for &pos in &f.redux_pos {
                let kind: u8 = if opcodes[pos as usize].split('.').next() == Some("CREDUX") {
                    1
                } else {
                    0
                };
                f.redux.push((pos, kind, 6));
            }
            f.redux.sort();
        }
        f.xor_reg_lanes = meta
            .merc_xor_reg
            .iter()
            .map(|&(lane, d, a, b, g)| {
                (lane, d, a, b, match g { 0 => 0xf8, 1 => 0x00, _ => 0x01 })
            })
            .collect();
        f.mma_lanes = meta.merc_mma.clone();
        f.f64_lanes = meta.merc_f64imm.clone();
        f.dfmaim = meta.merc_dfmaimm.clone();
        f.param_loads = meta.merc_param_loads.clone();
        f.cbank_lane = meta.merc_cbank_lane;
        f.s2r_lanes = meta.merc_s2r_lanes.clone();
        f.predmem = meta.merc_predmem;
        f.lop3_pdest = meta.merc_lop3_pdest.clone();
        f.s2r_sr = meta.merc_s2r_sr.clone();
        f.s2r_guard = meta.merc_s2r_guard.clone();
        f.s2r_dest = meta.merc_s2r_dest.clone();
        f.ldcgeo = meta.merc_ldcgeo.clone();
        f.load_flags = meta.merc_load_flags.clone();
        f.atom_pool_hits = meta.merc_atom_pool_hits.clone();
        f.ldgconst = meta.merc_ldgconst.clone();
        f.stg_areg = meta.merc_stg_areg.clone();
        f.n_ldgsts = opcodes.iter().filter(|o| o.starts_with("LDGSTS")).count() as u32;
        // mk13: MercFeatures.u_role_alt1 — klasy opcode'ow (full mnemonics
        // zawieraja .CAS) + liczba EXIT-ow.
        f.u_role_alt1 = meta.exit_offsets.len() >= 2
            || opcodes.iter().any(|o| {
                o.contains(".CAS")
                    || o.split('.').next() == Some("STS")
                    || o.split('.').next() == Some("LDSM")
                    || o.split('.').next() == Some("LDS")
            });

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
/// Wariant cbank przy kernels z shared memory (payload[6] |= 0x80; dane lab:
/// v_sm128/v_dyn_smem/k_lds/k_smem maja 83, bez-smem 03).
const REC_CBANK_SMEM: [u8; 16] = [
    0x01, 0x0b, 0x0e, 0x0a, 0xfa, 00, 0x05, 0x00,
    0x00, 0x00, 0x83, 0x01, 0x39, 0x04, 0x00, 0x00,
];
/// Rekord regionu divergent (51010109); payload staly (zmierzone na 5 kernelach
/// mk10: sw4..sw64 oraz b_bulk_cp/p_ldsm); emisja gdy BSSY+BSYNC bez BRX/BRA.DIV
/// i bez kolektyw-epilogow.
const REC_SHIFT_REGION: [u8; 18] = [
    0x51, 0x01, 0x01, 0x09, 0x02, 0x0a, 0xf8, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// mk15b: wariant cbank dla kerneli ladujacych parametry czystym LDC.
/// (bez LDCU): b2=0x0c, b4=0xf8 (gold q_bsync_pair); wariant korpus-dominujacy.
const REC_CBANK_LDC: [u8; 16] = [
    0x01, 0x0b, 0x0c, 0x0a, 0xf8, 0x00, 0x05, 0x00,
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
/// mk27: mini-ghost pod realna instrukcja kolektywna (mkvmem lane26
/// WARPSYNC): krotka forma 4B klasy 0x47 ghosta (zamiast MERC_SYNCWARP_GHOST).
const REC_MINI_GHOST76: [u8; 4] = [0x41, 0x47, 0x76, 0x0a];
/// mk27: UTCATOMSWS.FIND_AND_SET — rekord 18B (prefiks 51 01 + cialo
/// kandydata 0163 04 0a); b17 = 0x02 dla pierwszego w kodzie, 0x01 dla
/// kolejnych (spin-retry, mkvmem lanes 11/18).
const REC_UTCA_FNS: [u8; 18] = [
    0x51, 0x01, 0x01, 0x63, 0x04, 0x0a, 0xfa, 0x00,
    0x10, 0x48, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x02,
];
/// mk27: UTCATOMSWS.AND — mini 4B (mkvmem lane 47).
const REC_MINI_UTCA_AND: [u8; 4] = [0x41, 0x63, 0x08, 0x0a];
/// mk27: ATOMS.OR z imm w [URx+imm] — wariant b4=f8 (mkvmem lanes 23/24);
/// tail[28:32] = imm smem. ATOMS.AND — wariant b4=00 (lanes 48/49).
const REC_ATOMS_SMEM_OR: [u8; 32] = [
    0x02, 0x4e, 0x84, 0x32, 0xf8, 0x00, 0x64, 0x60,
    0x03, 0x00, 0x00, 0x00, 0xc1, 0xff, 0xc0, 0xff,
    0x00, 0xc0, 0x01, 0x0a, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const REC_ATOMS_SMEM_AND: [u8; 32] = [
    0x02, 0x4e, 0x84, 0x32, 0x00, 0x00, 0x54, 0x60,
    0x03, 0x00, 0x00, 0x00, 0xc1, 0xff, 0xc0, 0xff,
    0x00, 0x40, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

/// nvcc kanoniczny porzadek rekordow (zminowany na 6,3k sekcji korpusu +
/// mikrolab mk4-mk7):
///
/// ```text
/// PROLOG
/// [CFLOW]                gdy exits>1 | bra>1 (residua: CALL-ABI, early-exit)
/// desc(param0)           role 83 00
/// CBANK
/// [SMEM]
/// desc(param1..)         role 03 01 (ostatni przy n=2) / serie 83 00+ (n>=3)
/// [BAR x bar_count]
/// scalar-descs
/// STG x n_stg
/// ATOM x n_atom
/// ```
///
/// Znane residua (udokumentowane w MERCURY_UPLIFT_SM103A.md): pozycja rekordu
/// BAR wzgledem CBANK odstaje w ~4% kerneli (v_bar2-klasa), pola STG-counter
/// i desc-tail dw-zaleznosci od parametrow maja wyjatki (k_stg2/k_loop8);
/// kernele tcgen05/FA4-class dostaja osobne rekordy (0x31/025a/024e...) ktorych
/// emisja payloadowa nie jest jeszcze byte-exact.
/// Rekord 0229 (rekord PTX-level `xor Rd, Rs, imm32`, fs6-lab):
/// [4]=b4 guard variant (f8 brak / 00 @Pn / 01 @!Pn), [12:16]=
/// {u16 LE dst*0x40+1, u16 LE src*0x40}, [28:32]=imm LE (fs7 siatka
/// rejestrow: R0->0x0001, R4->0x0101, R5->0x0141 ... 0x40/reg).
/// Rekord ACQBULK (gold w_depsync): lane event przy GRIDDEPCONTROL acquire.
const REC_ACQBULK: [u8; 16] = [
    0x01, 0x62, 0x00, 0x0a, 0xf8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// mk40: rekordy store-matrix (stale korpusowe sm_100, mk40/stgfields fits
/// 192k+/56k+/22k+ przykladow; layout siatki (R<<6)|flag jak mk32/35):
/// - STG (0e32; legacy rec_stg — width-ladder b6: 00/20/40/50/60);
/// - ST.E (2a32): jak STG lecz b2=2a i b6-subladder 10/12/14/15/16;
///   brak desc[URx] -> [17:19] powtarza areg; b4=f8 stale (takze przy @Pn);
/// - STL (2006): [10:12]=areg<<6 (bez |2), [12:14]=0a00, [14:16]=
///   dreg<<6|wflag, b6-subladder 21/31/41/51/61, b4=(pidx<<3)|neg.
/// Subladder wflag dreg: (wsel==64b -> 2, ==128b -> 6, inaczej 0).
const STG_B6: [u8; 5] = [0x00, 0x20, 0x40, 0x50, 0x60];
const STE_B6: [u8; 5] = [0x10, 0x12, 0x14, 0x15, 0x16];
const STL_B6: [u8; 5] = [0x21, 0x31, 0x41, 0x51, 0x61];
fn rec_store2(st: (u32, u8, u8, u16, u16, u16, i32, u8)) -> [u8; 32]
{
    let (_lane, cls, wsel, areg, dur, dreg, imm, _b4) = st;
    let mut r = [0u8; 32];
    // flaga szerokosci NIE dotyczy RZ (korpus: STL.128 [R1], RZ -> c0ff).
    let wflag: u16 = if dreg == 0x3ff {
        0
    } else if wsel == 3 {
        2
    } else if wsel == 4 {
        6
    } else {
        0
    };
    if cls == 1 {
        r[0] = 0x02; r[1] = 0x38; r[2] = 0x2a; r[3] = 0x32;
        r[4] = _b4; // mk41: ST.E b4 = pelny kod predykatu (korpus; mk40 f8 bylo bledem)
        r[6] = STE_B6[(wsel as usize).min(4)];
        // mk41: b7=0x01 jest dominanta korpusowa (14066/15000+); warianty
        // 0x22/0x1a = niepoznany sub-driver (parked; mk41-resid store-b7).
        r[7] = 0x01;
        let a: u16 = ((areg.min(0x3ff)) << 6) | 2;
        r[12..14].copy_from_slice(&a.to_le_bytes());
        r[14] = 0x0a;
        let d2: u16 = ((if dur == 0xffff { areg.min(0x3ff) } else { dur.min(0x3ff) }) << 6) | 2;
        r[17..19].copy_from_slice(&d2.to_le_bytes());
        let dr: u16 = (dreg.min(0x3ff) << 6) | wflag;
        r[19..21].copy_from_slice(&dr.to_le_bytes());
        r[28..32].copy_from_slice(&imm.to_le_bytes());
    } else {
        r[0] = 0x02; r[1] = 0x38; r[2] = 0x20; r[3] = 0x06;
        r[4] = _b4;
        r[6] = STL_B6[(wsel as usize).min(4)];
        r[7] = 0x01;
        let a: u16 = areg.min(0x3ff) << 6;
        r[10..12].copy_from_slice(&a.to_le_bytes());
        r[12] = 0x0a;
        let dr: u16 = (dreg.min(0x3ff) << 6) | wflag;
        r[14..16].copy_from_slice(&dr.to_le_bytes());
        r[28..32].copy_from_slice(&imm.to_le_bytes());
    }
    r
}

/// Rekord CCTL.IVALL (gold p_fence): marker typ5 (f10=2,f20=1) + blob 16B.
const REC_CCTL: [u8; 18] = [
    0x51, 0x02, 0x01, 0x49, 0x10, 0x0a, 0xf8, 0x00, 0x0c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Zlozenie rekordu 02 38 (per-STG, fs10-grid/mapowanie na manifest gold):
/// - b6: width-ladder transferu (U8=00 / 4B=40 / .64=50 / .128=60)
/// - b12/b13: indeks slotu desc-stream powiazanego parametru:
///   s parzysty -> (82, s>>1), s nieparzysty -> (02, (s+1)>>1); s=0 -> (82,00)
///   (zbior: dp0=(82,00) dp1=(02,01) dp2=(82,01); 8B rejestruje odmiennie —
///   resid-wariant zostawiony bez zmian do fali mk10b)
/// - b18/b19: kursor biegu regionu (alt 0x40/0xc0) — OTWARTE (resid mk10b)
/// - b28: natychmiastowy offset adresu [Rx.64+imm] w bajtach (k_bra/e_loop:
///   +0,+4,+8,+c,+0 -> 00,04,08,0c,00)
/// mk30b: `wire` — opcjonalna mapa dp->slot nvcc (podpula: REG + LDG.C +
/// UNIF-(83,01)); None = zachowanie legacy (pool-pozycja globalna).
/// mk35: true gdy barwnik cbank base ma domyslna siatke b10/b11
/// ((03,01)/(83,01) — wolne do nadpisania siatka rejestrowa).
/// mk42: rekord edge 02 22 32 32 (dekod mk37/38; bramka EXACT mk42/edge9).
/// Pola: b4 pred, b6 klasa rozmiaru (U8=0x10,S8=0x11,U16=0x12,S16=0x13,
/// 32=0x14,64=0x15,128=0x16), (b7,b8) scope (08,00)/(10,01 STRONG.SYS),
/// b12..13=(X<<6)|C, b14..15=(Y<<6)|2, b17=0x0a, b22=0xf8,
/// [19:21)=(v<<6)|2 (v = max desc-UR kernela), b28..31 = off (u32 LE).
fn rec_edge32(e: (u32, u8, u8, u8, u8, u16, u16, u8, u32), v: u16) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[0] = 0x02;
    d[1] = 0x22;
    d[2] = 0x32;
    d[3] = 0x32;
    d[4] = e.1;
    d[6] = e.2;
    d[7] = e.3;
    d[8] = e.4;
    let xv = (e.5 << 6) | (e.7 as u16);
    d[12] = (xv & 0xff) as u8;
    d[13] = (xv >> 8) as u8;
    let yv = (e.6 << 6) | 2;
    d[14] = (yv & 0xff) as u8;
    d[15] = (yv >> 8) as u8;
    d[17] = 0x0a;
    let vv = (v << 6) | 2;
    d[19] = (vv & 0xff) as u8;
    d[20] = (vv >> 8) as u8;
    d[22] = 0xf8;
    d[28..32].copy_from_slice(&e.8.to_le_bytes());
    d
}

/// mk50: rekord edge 02 22 1e 32 (LDG-desc, "sibling" — dekod mk50 c1..c8).
/// Pola jak rec_edge32 poza: b6 = 0x40/0x50/0x60 (4B/8B/16B),
/// (b7,b8) = (0x81,0x40) stale per kernel, a [19:21) = (V<<6)|2 z
/// V = desc-UR SAMEGO lane'u (mk42 trzyma max-desc-UR kernela).
fn rec_edge1e32(e: (u32, u8, u8, u16, u16, u8, u16, u32)) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[0] = 0x02;
    d[1] = 0x22;
    d[2] = 0x1e;
    d[3] = 0x32;
    d[4] = e.1;
    d[6] = e.2;
    d[7] = 0x81;
    d[8] = 0x40;
    let xv = (e.3 << 6) | (e.5 as u16);
    d[12] = (xv & 0xff) as u8;
    d[13] = (xv >> 8) as u8;
    let yv = (e.4 << 6) | 2;
    d[14] = (yv & 0xff) as u8;
    d[15] = (yv >> 8) as u8;
    d[17] = 0x0a;
    let vv = (e.6 << 6) | 2;
    d[19] = (vv & 0xff) as u8;
    d[20] = (vv >> 8) as u8;
    d[22] = 0xf8;
    d[28..32].copy_from_slice(&e.7.to_le_bytes());
    d
}

fn feature_region_override_is_default(base: &[u8; 16]) -> bool {
    (base[10] == 0x03 || base[10] == 0x83) && base[11] == 0x01
}

fn rec_stg(feat: &MercFeatures, stg_i: usize, wire: Option<&[u32]>) -> [u8; 32] {
    let mut stg = REC_STG;
    let stg_narrow = feat.stg_u8;
    // mk40: per-lane width (korpus mieszany) nadrzedne nad kernel-global.
    let wsel_l: Option<u8> = feat.stg_wsel.get(stg_i).copied();
    if let Some(w) = wsel_l {
        stg[6] = STG_B6[(w as usize).min(4)];
    } else if feat.stg_w128 {
        stg[6] = 0x60;
    } else if stg_narrow {
        stg[6] = 0x00;
    } else if feat.stg_wide {
        stg[6] = 0x50;
    }
    // mk32 DOMKNIECIE siatki 0238 (rekurencyjna formula rejestrowa r<<6|f,
    // ta sama co w 0229/0129/atomach 024d/024e; zastepuje modele korelacyjne
    // "pozycja w puli desc" (mk10b..mk31) i "kursor serii" (mk10b/AC)):
    // - (b12,b13) = (areg<<6)|2: niski rejestr pary adresowej [R<num>.64]
    //   STG (dowod mk32: 144/144 gold+mk-lab; k_mma R4->(02,01),
    //   b_wmma R2->(82,00); taki sam rozklad dla s_*/p_*/r2_*/q_*);
    // - (b17,b18) = (desc_UR<<6)|2 (mk12a);
    // - (b19,b20) = (dreg<<6)|(2 dla .64, 0 dla wezszych) (RZ -> 0x3ff<<6);
    // - b4 = wariant guardu (mk12a), b28..b30 = imm offset adresu (mk10b).
    let dp_legacy = match feat.stg_desc_pos.get(stg_i).copied() {
        Some(u32::MAX) | None => stg_i as u32 % 2, // sentinel: nieznane
        Some(v) => v,
    };
    let dp_wire = match wire {
        Some(w) => w.get(stg_i).copied(),
        None => None,
    };
    let areg = feat.stg_areg.get(stg_i).copied().unwrap_or(255);
    if areg != 255 {
        let v = ((areg as u16) << 6) | 2;
        stg[12] = (v & 0xff) as u8;
        stg[13] = (v >> 8) as u8;
    } else {
        let dp = dp_wire.unwrap_or(dp_legacy);
        if !stg_narrow && (feat.n_stg > 1 || dp > 0) {
            // legacy (stg_desc_pos/pool): slot desc-stream (fs10b): parzysty
            // -> (82, s>>1); nieparzysty -> (02, (s+1)>>1); 0 -> (82,00).
            if dp % 2 == 1 {
                stg[12] = 0x02;
                stg[13] = ((dp + 1) >> 1) as u8;
            } else {
                stg[13] = (dp >> 1) as u8;
                if stg[13] > 0 {
                    stg[12] = 0x82;
                }
            }
        }
    }
    let dreg: u16 = match feat.stg_dreg.get(stg_i) {
        Some(&d) => {
            if d == 255 { 0x3ff } else { d as u16 }
        }
        None => {
            let pack = feat.stg_ser.get(stg_i).copied().unwrap_or(0);
            if pack >> 7 != 0 { 0x3ff } else { 5 + 2 * ((pack & 0x7f) as u16) }
        }
    };
    // flaga dreg (mk35): (w/4-1)*2 -> 4B->0, 8B->2, 16B->6 (nvcc:
    // stg128 R4->0x106, ld128 R8->0x206; mk32: .64 -> |2).
    let wflg: u16 = if let Some(w) = wsel_l {
        if w == 3 { 2 } else if w == 4 { 6 } else { 0 }
    } else if feat.stg_w128 {
        6
    } else if feat.stg_wide {
        2
    } else {
        0
    };
    let cur = (dreg << 6) | wflg;
    stg[19] = (cur & 0xff) as u8;
    stg[20] = (cur >> 8) as u8;
    let dur = feat.stg_dur.get(stg_i).copied().unwrap_or(4) as u16;
    stg[17..19].copy_from_slice(&((dur << 6) | 2).to_le_bytes());
    // mk41: pelny kod predykatu (0xf8 = brak); legacy {0,1,2} mapowane.
    match feat.stg_guard.get(stg_i).copied().unwrap_or(0xf8) {
        g if g != 0xf8 => stg[4] = g,
        _ => {}
    }
    let off = feat.stg_off.get(stg_i).copied().unwrap_or(0) as i32;
    stg[28..32].copy_from_slice(&off.to_le_bytes());
    stg
}

/// mk13: rekord 0129 dla rejestrowej formy LOP3-xor (0x3c, 3 rejestry):
/// 16B; dst@[10..12]=(d<<6)|1, srcA@[12..14]=a<<6, srcB@[14..16]=b<<6;
/// b4 = wariant guarda jak w 0229 (f8/00/01). Gold: lp1 lane5
/// (R5,R5,R0 -> ... 41 01 40 01 00 00), p_lds (R7,R6,R5 -> c1 01 80 01 40 01).
fn rec_xor_reg(dst: u32, src_a: u32, src_b: u32, b4: u8) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x29;
    r[3] = 0x04;
    r[4] = b4;
    r[6] = 0x04;
    r[8] = 0x01;
    r[9] = 0xf8;
    r[10..12].copy_from_slice(&(((dst << 6) | 1) as u16).to_le_bytes());
    r[12..14].copy_from_slice(&((src_a << 6) as u16).to_le_bytes());
    r[14..16].copy_from_slice(&((src_b << 6) as u16).to_le_bytes());
    r
}

fn rec_xor(dst: u32, src: u32, imm: u32, b4: u8) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0x02; r[1] = 0x29; r[2] = 0x04; r[3] = 0x06;
    r[4] = b4; r[6] = 0x04;
    r[10] = 0x01; r[11] = 0xf8;
    r[12..14].copy_from_slice(&(((dst << 6) | 1) as u16).to_le_bytes());
    r[14..16].copy_from_slice(&((src << 6) as u16).to_le_bytes());
    r[17] = 0x02;
    r[28..32].copy_from_slice(&imm.to_le_bytes());
    r
}


/// mk10c: role (b10,b11) rekordu desc 0222 z puli loadow. Tabela z fitu
/// pelnej macierzy gold fala mk10c (iter AF2-analiza + mk12a):
/// - uniform (0806): 16B->(07,02), 4B->(81,01), 1/2B->(01,01),
///   8B: atom-async/LDGSTS -> (03,02), inaczej (83,01).
///   [park: (03,01) dla p_cas/p_exit2/p_lds/p_ldsm — mk7-regiony, otwarte]
/// - regpath (0e06, w>=8): param tez ladowany przez LDCU -> (03,01);
///   n_w==1 -> (83,00);
///   n_w==2: oba STG-wiazane: pierwszy w kodzie (83,00), drugi (03,01);
///     inaczej read->(83,00), write->(83,01) przy STG.64/128 / (03,01);
///   n_w>=3: write->(83,01); najnizszy pi wsrod read -> (83,00); reszta read
///     -> (03,01).
/// - regpath w<=4 (skalar): (41,02) (k_stg2).
fn mk10c_roles(
    loads: &[(u32, u32, u8, u8, u8)],
    stg_write_pis: &std::collections::BTreeSet<u32>,
    n_atom: u32,
    n_ldgsts: u32,
    stg_wide: bool,
    u_role_alt1: bool,
    load_flags: &[u8],
    atom_pool_hits: &[(u32, u8)],
    has_ublkcp: bool,
    // mk35: numery dst-rejestrow loadow (rownolegle `loads`; 255=nieznany).
    // Gdy znany -> b10/b11 = (dreg<<6)|C, C = drabinka szerokosci
    // (16B->7, 8B->3, <8B->1). Wczesniejsza macierz rol mk10c..mk18 =
    // cien alokacji rejestrow nvcc (R2/R4/R6...). Puste = legacy.
    load_dregs: &[u8],
) -> Vec<(u8, u8)> {
    let mut roles = Vec::with_capacity(loads.len());
    // distinktywne pi wsrod szerokich regpath-loadow
    let mut wide_r: Vec<u32> = Vec::new();
    for &(_, pi, unif, w, _) in loads {
        if unif == 0 && w >= 8 && !wide_r.contains(&pi) {
            wide_r.push(pi);
        }
    }
    let uni_pis: std::collections::BTreeSet<u32> =
        loads.iter().filter(|l| l.2 == 1).map(|l| l.1).collect();
    let atomish = n_atom > 0 || n_ldgsts > 0;
    let n = wide_r.len();
    // pierwszy (najwczesniejszy lane) wsrod wide_r — do reguly 2-write
    let first_lane_pi = wide_r
        .iter()
        .copied()
        .min_by_key(|&piq| {
            loads
                .iter()
                .find(|l| l.1 == piq && l.2 == 0)
                .map(|l| l.0)
                .unwrap_or(u32::MAX)
        })
        .unwrap_or(u32::MAX);
    let lowest_read: u32 = wide_r
        .iter()
        .copied()
        .filter(|pi| !stg_write_pis.contains(pi))
        .min()
        .unwrap_or(u32::MAX);
    for (j, &(_, pi, unif, w, _)) in loads.iter().enumerate() {
        // mk35: dokladna regula jesli znamy dst-reg loadu.
        if let Some(&rg) = load_dregs.get(j) {
            if rg != 255 {
                let cf: u16 = if w == 16 { 7 } else if w >= 8 { 3 } else { 1 };
                let v = ((rg as u16) << 6) | cf;
                roles.push(((v & 0xff) as u8, (v >> 8) as u8));
                continue;
            }
        }
        let role = if unif == 1 {
            match w {
                16 => (0x07u8, 0x02u8),
                // mk31: kernely z UBLKCP (klasa __raw__ TMA bulk-copy) maja
                // dialekt rol unif: 4B skalar przez LDCU -> (41,02) jak przy
                // regpath; 8B LDCU -> (83,02). Dowod: b_bulk_cp (rekordy
                // @68/@134); korpus 17612 capmerc bez markerow UBLKCP
                // (regresja zero), 1-probkowe az do rozszerzenia siatki.
                4 if has_ublkcp => (0x41, 0x02),
                4 => (0x81, 0x01),
                1 | 2 => (0x01, 0x01),
                _ => {
                    if has_ublkcp {
                        (0x83, 0x02)
                    } else
                    // mk13: kolejnosc wazna — grupa (03,01) obejmuje CAS/
                    // exits>=2/LDS-klase; LDGSTS-licznik ja wygrywa (p_ldgsts
                    // ma LDS x3 i zostaje przy 03,02); potem reszta atomow.
                    if u_role_alt1 && n_ldgsts == 0 {
                        (0x03, 0x01)
                    } else if atomish {
                        (0x03, 0x02)
                    } else {
                        (0x83, 0x01)
                    }
                }
            }
        } else if w <= 4 {
            (0x41, 0x02)
        } else if uni_pis.contains(&pi) {
            // mk18 (2026-08-08, lab v_a..v_d + gold): dual reg+unif tego pi.
            // (83,00) gdy: (a) wartosc loadu feeduje adres atom-family
            // [p_atomg; v_b/v_c], (b) load PO CALL [q_tail_call + mk14.4-nutka].
            // Inaczej (03,01) [p_cctl (CCTL), p_stg2/v_d/v_a (STG)].
            let fl = load_flags.get(j).copied().unwrap_or(0);
            if (fl & 2) != 0 || atom_pool_hits.contains(&(pi, 0)) {
                (0x83, 0x00)
            } else {
                (0x03, 0x01)
            }
        } else if n == 1 {
            (0x83, 0x00)
        } else if n == 2 {
            let is_w = stg_write_pis.contains(&pi);
            let other_w = wide_r.iter().any(|&q| q != pi && stg_write_pis.contains(&q));
            if is_w && other_w {
                // oba wiazane STG: pierwszy w kodzie = (83,00)
                if pi == first_lane_pi { (0x83, 0x00) } else { (0x03, 0x01) }
            } else if is_w {
                if stg_wide { (0x83, 0x01) } else { (0x03, 0x01) }
            } else {
                (0x83, 0x00)
            }
        } else {
            let is_w = stg_write_pis.contains(&pi);
            if is_w {
                (0x83, 0x01)
            } else if pi == lowest_read {
                (0x83, 0x00)
            } else {
                (0x03, 0x01)
            }
        };
        roles.push(role);
    }
    roles
}

/// mk10c: budowa rekordu desc z pojedynczego loadu (wariant wg mechanizmu,
/// width-ladder b6, b4=guard, tail-dw=REL(off-0x380)).
/// mk19: dziedzina BAJTOWA klucza (nie 8*pi) — dowod korpusowy join2/join3
/// (19666/19666 rekordow: tail == c_off - 0x380; 4B paramy pod 0x384 itd.).
fn mk10c_rec_desc(ld: (u32, u32, u8, u8, u8), role: (u8, u8)) -> [u8; 32] {
    // mk41: slot `guard` niesie pelny kod predykatu: 0xf8 = brak,
    // @Pn -> (n<<3), @!Pn -> (n<<3)|1, @UPn -> (n<<3)|2, @!UPn -> (n<<3)|3
    // (korpus pred41: desc/store/BAR 99.5%+ zgodne na 570k+ parach).
    let (_, rel, unif, w, guard) = ld;
    let mut d = REC_PARAM_DESC;
    let b6: u8 = match w {
        1 => 0x02,
        2 => 0x22,
        4 => 0x42,
        16 => 0x62,
        _ => 0x52,
    };
    d[6] = b6;
    if unif == 1 {
        d[2] = 0x08;
        d[4] = if guard == 0xf8 { 0xfa } else { guard | 2 };
    } else {
        d[4] = guard;
    }
    d[10] = role.0;
    d[11] = role.1;
    d[28..32].copy_from_slice(&rel.to_le_bytes());
    d
}

/// mk10c (dowody: mercv3/order_* + mk10c-lane): strumien rekordow = sort po
/// pozycji kodowej ich instrukcji zrodlowej. Rekordy bez instr-korzeni
/// (cbank D = lane loadu c[358]; smem i pinned po cbanku; boot-anchor zawsze
/// pierwszy — emitowany przez wywolujacego). Anchory per S2R (lane).
fn emit_feature_records_laned(out: &mut Vec<u8>, feat: &MercFeatures, bar_rec: &[u8; 16]) {
    #[derive(Clone, Copy)]
    enum Ev {
        Desc(usize),
        Cbank,
        Smem,
        ShiftRegion,
        Anchor(usize),
        // mk56: geo-anchor LDC (b13=04) — indeks do feat.ldcgeo.
        AnchorGeo(usize),
        Bar(usize),
        Stg(usize),
        Elect(usize),
        Xor(usize),
        AcqBulk,
        Cctl,
        CctlRml2(usize),
        Pad,
        Mma(usize),
        F64i(usize),
        DfmaImm(usize),
        Lop3P,
        XorReg(usize),
        Redux(usize),
        IsetpUr,
        XsetpPair(u8),
        UsetpMini(u8),
        UleaUpco,
        Syncwarp,
        Atom(usize),
        LdgstsPin,
        LdgstsWait,
        Ldgsts2(usize),
        Ldgsts2Wait(usize),
        LdsmMini,
        // mk30: rodziny b_*
        SmemCga(usize),
        // mk46: geo-anchor 010b060a (payload prebaked, b12=rola, b13=klasa)
        GeoRec(usize),
        McD1(usize),
        McExch(usize),
        McArrive(usize),
        McPhase(usize),
        McMiniVoteu(usize),
        McMiniUshf(usize),
        McMiniLea(usize),
        McMiniWs(usize),
        McMiniUvirt(usize),
        McMiniUmovRR(usize),
        McUblkcp(usize),
        McPlop3Rec(usize),
        McPlop3uRec(usize),
        McUplop3Rec(usize),
        McDsetpImmRec(usize),
        McCs2rRec(usize),
        McLop3NotRec(usize),
        McUlop3NotRec(usize),
        McD1Wc47(usize),
        Redux2(usize),
        McRedg2(usize),
        McAtomg2(usize),
        ShiftAt(usize),
        Utca(usize),
        AtomSmem(usize),
        Store2(usize),
        Mini2(usize),
        EdgeLd(usize),
        EdgeLdg(usize),
    }
    // mk10c: zbior parametrow STG-wiazanych z PULI deskryptorow (nie ze
    // starej maski param_write — ta traci read->write gdy param czytany
    // wczesniej; r2_wr/r2_ww dowod).
    // mk13: pula slotow = wpisy (pi, mech) w KOLEJNOSCI LANE: loady wide
    // (mech = unif01) + uzycia desc przez LDG.E.CONSTANT (mech = 2).
    // mk10c zakladal same loady; LDG.C zajmuje slot (v_ldg_u64: s=2).
    let mut pool_ev: Vec<(u32, (u32, u8))> = Vec::new();
    for &(lane, pi, unif, w, _) in &feat.param_loads {
        if w >= 8 {
            pool_ev.push((lane, (pi, unif)));
        }
    }
    for &(lane, pi) in &feat.ldgconst {
        pool_ev.push((lane, (pi, 2)));
    }
    pool_ev.sort_by_key(|&(lane, _)| lane);
    let mut pool: Vec<(u32, u8)> = Vec::new();
    for &(_, k) in &pool_ev {
        if !pool.contains(&k) {
            pool.push(k);
        }
    }
    let mut stg_write_pis: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for &dp in &feat.stg_desc_pos {
        if dp != u32::MAX {
            if let Some(&(pi, _)) = pool.get(dp as usize) {
                stg_write_pis.insert(pi);
            }
        }
    }
    let roles = mk10c_roles(
        &feat.param_loads,
        &stg_write_pis,
        feat.n_atom,
        feat.n_ldgsts,
        feat.stg_wide,
        feat.u_role_alt1,
        &feat.load_flags,
        &feat.atom_pool_hits,
        !feat.ublkcp.is_empty(),
        &feat.param_load_dreg,
    );
    let mut ev: Vec<(u32, u8, Ev)> = Vec::new();
    for (j, ld) in feat.param_loads.iter().enumerate() {
        ev.push((ld.0, 20, Ev::Desc(j)));
    }
    // mk30b (PARKED, skontrawerifikowane): podpula-slot-model dla 0238 —
    // k_mma ma identyczna strukture co b_wmma i nvcc daje tam s=1 a tu 0.
    // Decyzja: zostaje legacy pool-pozycja; temat = RE oraculum mk30b-next.
    // mk15b: gdy brak lane hosta cbank (LDCU c[358]), nvcc sadza cbank tuz przed
    // pierwszym desc-em parametru (gold q_bsync_pair: lane=first-load-1 = 3).
    let clane = feat.cbank_lane.unwrap_or_else(|| {
        feat.param_loads
            .iter()
            .map(|l| l.0)
            .min()
            .map(|l0| l0.saturating_sub(1))
            .unwrap_or(u32::MAX - 64)
    });
    // mk35: nvcc emituje rekord cbank TYLKO gdy kernel laduje c[0x358]
    // (135-kernel falsyfikacja-zero na sealed+mk34-labach; at_cas = jedyne
    // poprzednio-nadmiarowe zrodlo rozjazdu — brak 358-loadu). Legacy
    // q_bsync_pair ma load przez LDC (nie LDCU) — wystarcza sama obecnosc.
    let has358 = feat.cbank358_dreg.is_some() || feat.cbank_lane.is_some();
    // ...ale sciezki bez swiezego skanu mk35 (gold manifest) zachowuja
    // dotychczasowe zachowanie (q_bsync_pair: fallback clane w mk15b).
    let legacy_emit = feat.param_load_dreg.is_empty();
    if has358 || legacy_emit {
        ev.push((clane, 10, Ev::Cbank));
    }
    // mk14.3: przy LDGSTS rekord smem poprzedza cbank (gold p_ldgsts: smem@[3]
    // przed cbank@[4]; bez LDGSTS: po (p_lds/p_sts2 exact — tier 11).
    // mk30: rekord smem-anchor 010b060a przy KAZDEJ lane S2UR CgaCtaId
    // (mk15-uwaga uogolniona; gold zgodny: p_ldsm 2x na 2 S2UR itd.).
    // Zastepuje legacy-clane gdy s2ur_cga niepuste; wpp legacy jak dawniej.
    // mk46: rodzina 010b060a = geo-anchory (S2UR-CTAID.*/CgaCtaId/SWINHI +
    // LDCU okna stalych drivera; korpus sm_100 17674/17674 EXACT multiset
    // (klasa,rola,dst), porzadek == porzadek lane). Niepusty zbior geo
    // wygasza legacy-rekord smem (korpus: rekordy == dokladnie multiset geo).
    let geo_nonempty = !feat.geo_rec.is_empty();
    let smem_via_s2ur = geo_nonempty || !feat.s2ur_cga.is_empty();
    if geo_nonempty {
        for (k, &(l, _)) in feat.geo_rec.iter().enumerate() {
            ev.push((l, 20, Ev::GeoRec(k)));
        }
    } else if !feat.s2ur_cga.is_empty() {
        for (k, &(l, _g, _d)) in feat.s2ur_cga.iter().enumerate() {
            ev.push((l, 20, Ev::SmemCga(k)));
        }
    } else {
        let smem_tier = if feat.n_ldgsts > 0 { 9 } else { 11 };
        if feat.smem_static {
            ev.push((clane, smem_tier, Ev::Smem));
        } else if feat.smem_atoms_only && feat.s2ur_first_lane < u32::MAX {
            // mk15: rekord smem hostowany przy lane pierwszego S2UR (gold p_atoms).
            ev.push((feat.s2ur_first_lane, 20, Ev::Smem));
        }
    }
    if feat.diverge_region {
        // mk30b: rekord regionu przy lane zamkniecia BSYNC (nie przy cbank) —
        // gold sw*/p_ldsm: nierozroznialne (nic miedzy); b_bulk_cp rozstrzyga.
        let region_lane = feat
            .bsync_close
            .first()
            .copied()
            .unwrap_or(clane);
        ev.push((region_lane, 12, Ev::ShiftAt(0)));
        // mk15 (2026-08-07): powdroczony rekord smem 010b060a tuz po rekordzie
        // regionu divergent 51010109 — tylko gdy kernel ma statyczna smem.
        // Lab: p_ldsm + b_bulk_cp (1 pin -> dokladnie 1 dup, bajty identyczne
        // z podstawowym rekordem smem); sw* (BSSY, bez smem): brak dupa.
        // mk30b: przy sciezce per-S2UR dup jest ZBEDNY (p_ldsm/b_bulk_cp maja
        // 2 S2UR = 2 rekordy smem lacznie z oryginalem mk15-dup).
        if feat.smem_static && !smem_via_s2ur {
            ev.push((clane, 13, Ev::Smem));
        }
    }
    for (k, &l) in feat.s2r_lanes.iter().enumerate() {
        ev.push((l, 20, Ev::Anchor(k)));
    }
    // mk56: geo-anchory LDC — ten sam tier 20, lane = lane instrukcji LDC.
    for (k, &(l, _, _, _)) in feat.ldcgeo.iter().enumerate() {
        ev.push((l, 20, Ev::AnchorGeo(k)));
    }
    for (i, &pos) in feat.bar_pos.iter().enumerate() {
        ev.push((pos, 20, Ev::Bar(i)));
    }
    for (i, &pos) in feat.stg_pos.iter().enumerate() {
        ev.push((pos, 20, Ev::Stg(i)));
    }
    for (i, &pos) in feat.elect_pos.iter().enumerate() {
        ev.push((pos, 20, Ev::Elect(i)));
    }
    for (i, xl) in feat.xor_lanes.iter().enumerate() {
        let _ = xl;
        ev.push((feat.xor_lanes[i].0, 20, Ev::Xor(i)));
    }
    for (i, xr) in feat.xor_reg_lanes.iter().enumerate() {
        let _ = xr;
        ev.push((feat.xor_reg_lanes[i].0, 20, Ev::XorReg(i)));
    }
    for (i, &(lane, _, _)) in feat.redux.iter().enumerate() {
        ev.push((lane, 20, Ev::Redux(i)));
    }
    for &pos in &feat.isetp_ur {
        ev.push((pos, 20, Ev::IsetpUr));
    }
    // mk41: para ISETP(non-EX)+ISETP.EX -> JEDEN mini na lane HEAD-a.
    for &(hl, cls) in &feat.xsetp_pairs {
        ev.push((hl, 20, Ev::XsetpPair(cls)));
    }
    // mk52: UISETP minis (kolejnosc z minis — stabilna dla par (class,4014)).
    for &(l, k) in &feat.usetp_minis {
        ev.push((l, 20, Ev::UsetpMini(k)));
    }
    for &l in &feat.ulea_upco {
        ev.push((l, 20, Ev::UleaUpco));
    }
    // mk14: ghost __syncwarp (rekord 01476c0a) — lane ducha-NOP.
    for &pos in &feat.syncwarp {
        ev.push((pos, 21, Ev::Syncwarp));
    }
    // mk14: rekordy atomowe w lane swoich instrukcji (byly: trailing append).
    for (i, a) in feat.atoms.iter().enumerate() {
        // mk30b: ATOMS z [URx+imm] obsluguje AtomSmem (nie generyczne).
        if feat.atom_smem.iter().any(|&(l, _, _)| l == a.0) {
            continue;
        }
        if a.1 != crate::mercury::MERC_ATOM_CLS_RED {
            ev.push((a.0, 20, Ev::Atom(i)));
        }
    }
    // mk14.3: LDGSTS pinned-blob + wait-event + LDSM mini.
    // mk53: pelny silnik blobow (lane per desc-form LDGSTS; legacy pin tylko
    // gdy silnik pusty).
    // klucz porzadku = host pinu (killpad) gdy pin, inaczej lane bloba —
    // inaczej czekaj 0123400a wskoczyloby miedzy pin a blob (b_cpasync).
    for (i2, x2) in feat.ldgsts2.iter().enumerate() {
        ev.push((x2.pin_host.unwrap_or(x2.lane), 20, Ev::Ldgsts2(i2)));
    }
    // mk55: multi-wait 0123400a per DEPBAR.SB0 (regula korpusowa c2/c3:
    // 2619/2619 EXACT; SB5 rekordu nie nosi). Tylko na sciezce blobow —
    // legacy single-wait (mk14.3) obsluguje kernele bez desc-form.
    for (w2, (wl2, _imm)) in feat.ldgsts2_waits.iter().enumerate() {
        ev.push((*wl2, 20, Ev::Ldgsts2Wait(w2)));
    }
    if feat.ldgsts2.is_empty() {
        if let Some((pl, _, _)) = feat.ldgsts_pin {
            ev.push((pl, 20, Ev::LdgstsPin));
        }
        if let Some((wl, _)) = feat.ldgsts_wait {
            ev.push((wl, 20, Ev::LdgstsWait));
        }
    }
    for &ll in &feat.ldsm_lanes {
        ev.push((ll, 20, Ev::LdsmMini));
    }
    for &pos in &feat.acqbulk_pos {
        ev.push((pos, 20, Ev::AcqBulk));
    }
    for &pos in &feat.cctl_pos {
        ev.push((pos, 20, Ev::Cctl));
    }
    for (k, &pos) in feat.cctl_rml2_pos.iter().enumerate() {
        ev.push((pos, 20, Ev::CctlRml2(k)));
    }
    for &pos in &feat.pad_pos {
        ev.push((pos, 20, Ev::Pad));
    }
    for &pos in &feat.lop3_pdest {
        ev.push((pos, 20, Ev::Lop3P));
    }
    for (i, m) in feat.mma_lanes.iter().enumerate() {
        ev.push((m.0, 20, Ev::Mma(i.min(255) as usize)));
    }
    for (i, m) in feat.f64_lanes.iter().enumerate() {
        ev.push((m.0, 20, Ev::F64i(i)));
    }
    // mk51: rekordy DFMA-imm 020d1c0e/020d1a0e — tier 20, strumien
    // lane-rosnaco (emulator korpusowy c10: 18932/18932 byte-exact).
    for (i, m) in feat.dfmaim.iter().enumerate() {
        ev.push((m.0, 20, Ev::DfmaImm(i)));
    }
    // mk30: rodziny b_* (SYNCS/TMA/minis) — wszystko w lane swej klasy,
    // tier 20-21 (porzadek jak w finalnym strumieniu nvcc).
    if !smem_via_s2ur {
    } else {
        // (rekordy SmemCga wlozone wyzej)
    }
    for (k, _) in feat.mc_d1.iter().enumerate() {
        ev.push((feat.mc_d1[k].0, 20, Ev::McD1(k)));
    }
    for (k, _) in feat.mc_exch.iter().enumerate() {
        ev.push((feat.mc_exch[k].0, 20, Ev::McExch(k)));
    }
    for (k, _) in feat.mc_arrive.iter().enumerate() {
        ev.push((feat.mc_arrive[k].0, 20, Ev::McArrive(k)));
    }
    for (k, _) in feat.mc_phase.iter().enumerate() {
        ev.push((feat.mc_phase[k], 20, Ev::McPhase(k)));
    }
    for (k, _) in feat.mc_voteu_all.iter().enumerate() {
        ev.push((feat.mc_voteu_all[k], 20, Ev::McMiniVoteu(k)));
    }
    // mk30b-korekta: minis 414c TYLKO na VOTEU.ALL (m_init/b_mbarrier:
    // 2 VOTEU -> 2 minis; wczesniejsza regula USHF-fin to artefakt
    // zip-driftu capture'u mk26). Bit na USHF-fin nadal kasowany.
    for (k, _) in feat.mc_lea18.iter().enumerate() {
        ev.push((feat.mc_lea18[k], 20, Ev::McMiniLea(k)));
    }
    for (k, _) in feat.ws_minis.iter().enumerate() {
        ev.push((feat.ws_minis[k].0, 20, Ev::McMiniWs(k)));
    }
    for (k, _) in feat.uvcount.iter().enumerate() {
        ev.push((feat.uvcount[k], 20, Ev::McMiniUvirt(k)));
    }
    for (k, _) in feat.umov_rr.iter().enumerate() {
        ev.push((feat.umov_rr[k], 20, Ev::McMiniUmovRR(k)));
    }
    for (k, _) in feat.ublkcp.iter().enumerate() {
        ev.push((feat.ublkcp[k], 20, Ev::McUblkcp(k)));
    }
    // mk40: store-matrix (ST.E/STL) + mini-slownik korpusowy.
    for (k, _) in feat.store2.iter().enumerate() {
        ev.push((feat.store2[k].0, 20, Ev::Store2(k)));
    }
    for (k, _) in feat.mini2.iter().enumerate() {
        ev.push((feat.mini2[k].0, 20, Ev::Mini2(k)));
    }
    // mk42: edge LD-desc (tier 20, lane-sorted; korpus edge3: kolejnosc
    // strumienia == adresy rosnaco, 1721/1721 kerneli).
    for (k, _) in feat.edge_ld.iter().enumerate() {
        ev.push((feat.edge_ld[k].0, 20, Ev::EdgeLd(k)));
    }
    // mk50: edge LDG-desc w kernelach annotated_ptr (tier 20, lane-rosnaco —
    // korpus mk50/c8b: porzadek strumienia == adresy rosnaco, 72/72).
    for (k, _) in feat.edge_ldg.iter().enumerate() {
        ev.push((feat.edge_ldg[k].0, 20, Ev::EdgeLdg(k)));
    }
    // mk44: generyczne rekordy 0110060a (subsumuja legacy trio A/B/C —
    // te same bajty); tier 20 jak dotad.
    for (k, _) in feat.plop3_rec.iter().enumerate() {
        ev.push((feat.plop3_rec[k].0, 20, Ev::McPlop3Rec(k)));
    }
    // mk54: rekordy 0210* (PLOP3-UP / UPLOP3 / DSETP-imm); tier 20.
    for (k, _) in feat.plop3u_rec.iter().enumerate() {
        ev.push((feat.plop3u_rec[k].0, 20, Ev::McPlop3uRec(k)));
    }
    for (k, _) in feat.uplop3_rec.iter().enumerate() {
        ev.push((feat.uplop3_rec[k].0, 20, Ev::McUplop3Rec(k)));
    }
    for (k, _) in feat.dsetpimm_rec.iter().enumerate() {
        ev.push((feat.dsetpimm_rec[k].0, 20, Ev::McDsetpImmRec(k)));
    }
    // mk45: rekordy 010b0c0a (CS2R SRZ); tier 20 jak PLOP3.
    for (k, _) in feat.cs2r_rec.iter().enumerate() {
        ev.push((feat.cs2r_rec[k].0, 20, Ev::McCs2rRec(k)));
    }
    // mk47: rekordy 012b{00|04}0a (LOP3 NOT-MOV LUT=0x33); tier 20 jak mk44/45.
    for (k, _) in feat.lop3not_rec.iter().enumerate() {
        ev.push((feat.lop3not_rec[k].0, 20, Ev::McLop3NotRec(k)));
    }
    // mk58: rekordy 012b080a (ULOP3 NOT-MOV); tier 20 jak mk47.
    for (k, _) in feat.ulop3not_rec.iter().enumerate() {
        ev.push((feat.ulop3not_rec[k].0, 20, Ev::McUlop3NotRec(k)));
    }
    // mk59: rekordy d10102-47 per WC-site (NOP-region); tier 20, lane WC.
    for (k, _) in feat.d1wc47.iter().enumerate() {
        ev.push((feat.d1wc47[k].0, 20, Ev::McD1Wc47(k)));
    }
    // mk60: rekordy 0132100a (redux2); tier 20, lane REDUX/CREDUX.
    for (k, _) in feat.redux2.iter().enumerate() {
        ev.push((feat.redux2[k].0, 20, Ev::Redux2(k)));
    }
    // mk48: rekordy 024d*32 (REDG); tier 20 jak Ev::Atom/mk44-47.
    for (k, _) in feat.redg2_rec.iter().enumerate() {
        ev.push((feat.redg2_rec[k].0, 20, Ev::McRedg2(k)));
    }
    // mk49: rekordy 024e*32 (ATOM-family); tier 20 jak mk48.
    for (k, _) in feat.atomg2_rec.iter().enumerate() {
        ev.push((feat.atomg2_rec[k].0, 20, Ev::McAtomg2(k)));
    }
    // mk30b: UTCA piny + ATOMS z imm [UR+off] takze w sciezce laned
    // (b_tcgen05; mk27 robil to dla zero-param mkvmem).
    for (k, _) in feat.utca.iter().enumerate() {
        ev.push((feat.utca[k].0, 4, Ev::Utca(k)));
    }
    for (k, _) in feat.atom_smem.iter().enumerate() {
        ev.push((feat.atom_smem[k].0, 5, Ev::AtomSmem(k)));
    }
    ev.sort_by_key(|&(lane, tier, _)| (lane, tier));
    let mut utca_fns_seen = 0usize;
    // payload anchor (jak cflow_rec legacy)
    // mk13: b13=0x02 stale; b12 = enum SR czytanego przez S2R per anchor
    // (zastepuje hack cf[12]=0 dla atom/mma — zbiezny z LANEID=0).
    let anchor_base = {
        let mut cf = REC_EXTRA_EXIT;
        let v: u32 = (feat.anchor_f4 << 6) | 1;
        cf[10] = (v & 0xff) as u8;
        cf[11] = (v >> 8) as u8;
        cf
    };
    for (_, _, kind) in ev {
        match kind {
            Ev::Desc(j) => out.extend_from_slice(&mk10c_rec_desc(feat.param_loads[j], roles[j])),
            Ev::Cbank => {
                // mk30b: bramki rodzin (b_*); bazowo (03,01) / (83,01).
                // utca -> (83,02); EXCH -> (03, b11=2 gdy cbank-early);
                // ARRIVE-only -> (03,01); PHASECHK -> (83,01).
                let base = if !feat.utca.is_empty() {
                    let mut r = REC_CBANK_SMEM;
                    r[11] = 0x02;
                    r
                } else if !feat.mc_exch.is_empty() {
                    let mut r = REC_CBANK;
                    if feat.cbank_lane.map(|l| l <= 8).unwrap_or(false) {
                        r[11] = 0x02;
                    }
                    r
                } else if !feat.mc_arrive.is_empty() {
                    REC_CBANK
                } else if !feat.mc_phase.is_empty() {
                    REC_CBANK_SMEM
                } else if !feat.has_ldcu {
                    REC_CBANK_LDC
                } else if feat.smem_static || feat.cbank83_cas {
                    REC_CBANK_SMEM
                } else {
                    REC_CBANK
                };
                // mk35: (b10,b11) = (dst358 << 6) | 3 gdy znamy rejestr
                // loadu c[0x358] (k_atom UR4->03 01; at_and/min UR6->83 01).
                let mut base = base;
                if let Some(d) = feat.cbank358_dreg {
                    if crate::elf_builder::feature_region_override_is_default(&base) {
                        let g: u16 = ((d as u16) << 6) | 3;
                        base[10] = (g & 0xff) as u8;
                        base[11] = (g >> 8) as u8;
                    }
                }
                out.extend_from_slice(&base);
            }
            Ev::Smem => out.extend_from_slice(&REC_SMEM),
            Ev::ShiftRegion => out.extend_from_slice(&REC_SHIFT_REGION),
            Ev::Anchor(k) => {
                let mut cf = anchor_base;
                // mk41: b4 = pelny kod predykatu lane S2R (korpus: @!Pn -> n<<3|1).
                if let Some(&g) = feat.s2r_guard.get(k) {
                    cf[4] = g;
                }
                cf[12] = feat.s2r_sr.get(k).copied().unwrap_or(1);
                // mk17a: f4 = numer R dest S2R tego anchora (mk20: 90/90);
                // zastepuje bramkowany anchor_base gdy meta niesie skan.
                if let Some(&rd) = feat.s2r_dest.get(k) {
                    let v: u32 = (rd << 6) | 1;
                    cf[10] = (v & 0xff) as u8;
                    cf[11] = (v >> 8) as u8;
                }
                out.extend_from_slice(&cf);
            }
            Ev::AnchorGeo(k) => {
                // mk56: b13=04 (klasa geometrii okna c[0x0][0x360..78]);
                // b12 = geometria, payload = (dest<<6)|1, b4 = guard.
                let (_, d, b12, g) = feat.ldcgeo[k];
                let mut cf = anchor_base;
                cf[4] = g;
                let v: u32 = (d << 6) | 1;
                cf[10] = (v & 0xff) as u8;
                cf[11] = (v >> 8) as u8;
                cf[12] = b12;
                cf[13] = 0x04;
                out.extend_from_slice(&cf);
            }
            Ev::Bar(i) => {
                let mut br = *bar_rec;
                // mk35: b4 = guard per-lane (1=@P->00, 2=@!P->01; 0=f8);
                // nvcc bar_if2 (@P0 BAR -> 00) vs legacy bar_pred-global.
                // mk41: pelny kod predykatu (0xf8 = brak, Pn<<3|neg...).
                if let Some(&g) = feat.bar_guard.get(i) {
                    br[4] = g;
                }
                if let Some(&(id, cnt)) = feat.bar_args.get(i) {
                    if id != 0 || cnt != 0 {
                        // mk13: named barrier: b11=id, b14=cnt (b12=01 stale;
                        // gold p_namedbar: bar.sync 1,32 -> b11=01 b14=0x20).
                        br[11] = id as u8;
                        br[14] = cnt as u8;
                    }
                }
                out.extend_from_slice(&br);
            }
            // mk30b: podpula-slot model b_wmma/b_cpasync SKONTRAWERFIKOWANY
            // przez k_mma (identyczny ksztalt -> nvcc chce tam s=1, tu 0).
            // STG-slot region/dialect-dependent — wrocic oraculum gdb.
            Ev::Stg(i) => out.extend_from_slice(&rec_stg(feat, i, None)),
            Ev::Elect(_) => out.extend_from_slice(&[0x41, 0x64, 0x00, 0x0a]),
            Ev::Xor(i) => {
                let xl = feat.xor_lanes[i];
                out.extend_from_slice(&rec_xor(xl.1, xl.2, xl.3, xl.4));
            }
            Ev::XorReg(i) => {
                let xr = feat.xor_reg_lanes[i];
                out.extend_from_slice(&rec_xor_reg(xr.1, xr.2, xr.3, xr.4));
            }
            Ev::AcqBulk => out.extend_from_slice(&REC_ACQBULK),
            Ev::Cctl => out.extend_from_slice(&REC_CCTL),
            Ev::CctlRml2(_) => out.extend_from_slice(&[0x41, 0x0e, 0x02, 0x0c]),
            Ev::Pad => out.extend_from_slice(&crate::mercury::MERC_LANE_PAD),
            Ev::Lop3P => out.extend_from_slice(&crate::mercury::MERC_LOP3_PWRITE_MINI),
            Ev::Syncwarp => out.extend_from_slice(&crate::mercury::MERC_SYNCWARP_GHOST),
            Ev::LdgstsPin => {
                let (_, d, sr) = feat.ldgsts_pin.unwrap_or((0, 255, 255));
                let mut blob = crate::mercury::build_ldgsts_blob(d, sr);
                if feat.ldgsts_b128 {
                    // mk30b: LDGSTS.BYPASS.E.128 (cp.async 16B): b8=0x20
                    // (zamiast 0x24), b10=0x10. Zmierzone: b_cpasync.
                    blob[8] = 0x20;
                    blob[10] = 0x10;
                }
                out.extend_from_slice(&blob);
            }
            Ev::LdgstsWait => {
                let (_l, imm) = feat.ldgsts_wait.unwrap_or((0, 0));
                out.extend_from_slice(&crate::mercury::build_ldgsts2_wait(imm));
            }
            // mk53: marker 51 02 (gdy pin) + blob 32B.
            Ev::Ldgsts2(i2) => {
                let x = &feat.ldgsts2[i2];
                if x.pin {
                    out.extend_from_slice(&[0x51, 0x02]);
                }
                out.extend_from_slice(&crate::mercury::build_ldgsts2_blob(
                    x,
                    feat.ldgsts2.len() == 1,
                ));
            }
            Ev::Ldgsts2Wait(w2) => {
                let (_l2, imm2) = feat.ldgsts2_waits[w2];
                out.extend_from_slice(&crate::mercury::build_ldgsts2_wait(imm2));
            }
            Ev::LdsmMini => out.extend_from_slice(&crate::mercury::MERC_LDSM_MINI),
            Ev::Atom(i) => {
                let a = feat.atoms[i];
                let gb4 = match a.2 { 1 => 0x00, 2 => 0x01, _ => 0xf8 };
                out.extend_from_slice(&crate::mercury::build_atom_rec(
                    a.1, gb4, a.7, a.3, a.4, a.5, a.6,
                ));
            }
            Ev::Redux(i) => {
                // gold p_redux lane10: 0132 100a f8 00 4d 00 00 00 81 01 ...
                // mk35: b6=4d typowany REDUX; b6=51,b13=01 CREDUX (at_min);
                // [10:12] = (dstUR<<6)|1 (p_redux UR6 -> 01 81; at_min
                // CREDUX.MIN.S32 UR5 -> 01 41).
                let (lane, kind, dreg) = feat.redux[i];
                let _ = lane;
                let b6: u8 = if kind == 1 { 0x51 } else { 0x4d };
                let b13: u8 = if kind == 1 { 0x01 } else { 0x00 };
                let g: u16 = (((if dreg==255 {6} else {dreg}) as u16) << 6) | 1;
                out.extend_from_slice(&[
                    0x01, 0x32, 0x10, 0x0a, 0xf8, 0x00, b6, 0x00,
                    0x00, 0x00, (g & 0xff) as u8, (g >> 8) as u8, 0x00, b13, 0x00, 0x00,
                ]);
            }
            Ev::IsetpUr => out.extend_from_slice(
                // mk35 (g5b bar_if2 n05): ISETP.NE z operandem UR, bez .EX
                // -> mini, zajelanej lane bez bitu; klasa 02103214 flag0.
                &[0x42, 0x10, 0x32, 0x14],
            ),
            // mk41: tagi mini XSETP-par wg operandow heada/pary
            // (lab sm_100a i sm_103a identyczne — era-inwariant).
            Ev::XsetpPair(0) => out.extend_from_slice(&[0x42, 0x10, 0x2e, 0x14]),
            Ev::XsetpPair(1) => out.extend_from_slice(&[0x42, 0x10, 0x30, 0x06]),
            Ev::XsetpPair(2) => out.extend_from_slice(&[0x42, 0x10, 0x32, 0x14]),
            Ev::XsetpPair(_) => out.extend_from_slice(&[0x42, 0x10, 0x2e, 0x14]),
            // mk52
            Ev::UsetpMini(1) => out.extend_from_slice(&[0x42, 0x10, 0x34, 0x06]),
            Ev::UsetpMini(2) => out.extend_from_slice(&[0x42, 0x10, 0x40, 0x14]),
            Ev::UsetpMini(_) => out.extend_from_slice(&[0x42, 0x10, 0x36, 0x14]),
            Ev::UleaUpco => out.extend_from_slice(&[0x42, 0x25, 0x42, 0x14]),
            Ev::Mma(i) => {
                let m = feat.mma_lanes[i];
                if crate::mercury::merc_mma_is_mini(m.1) {
                    out.extend_from_slice(&crate::mercury::MERC_MMA_MINI_SAT);
                } else {
                    out.extend_from_slice(&crate::mercury::build_mma_rec(
                        m.1, m.2, m.3, m.4, m.5, m.6,
                    ));
                }
            }
            Ev::F64i(i) => {
                let m = feat.f64_lanes[i];
                out.extend_from_slice(&crate::mercury::build_f64imm_rec(
                    m.1, m.2, m.3, m.4, m.5, m.6,
                ));
            }
            Ev::DfmaImm(i) => {
                let m = feat.dfmaim[i];
                out.extend_from_slice(&crate::mercury::build_dfmaimm_rec(
                    m.1 == 1, m.2, m.3, m.4, m.5, m.6, m.7,
                ));
            }
            // mk30: rodziny b_*
            Ev::GeoRec(k) => {
                let mut r = feat.geo_rec[k].1;
                // mk30-bulk1 carve-out: pierwszy anchor CgaCtaId niepredyko-
                // wany z dst==5 przy BSSY i mbarrier-EXCH -> (b10,b11)=(01,02)
                // (gold bulk1; p_ldsm bez EXCH zostaje z generic (41,01)).
                let dst = ((r[10] as u16) | ((r[11] as u16) << 8)) >> 6;
                if r[13] == 2 && r[12] == 0x2c
                    && r[4] == 0xfa
                    && dst == 5
                    && feat.geo_rec[..k]
                        .iter()
                        .all(|(_, g)| !(g[13] == 2 && g[12] == 0x2c))
                    && !feat.bsync_close.is_empty()
                    && !(feat.mc_exch.is_empty() && feat.mc_arrive.is_empty()
                        && feat.mc_phase.is_empty())
                {
                    r[10] = 0x01;
                    r[11] = 0x02;
                }
                out.extend_from_slice(&r);
            }
            Ev::SmemCga(k) => {
                let (_l, pred, dst) = feat.s2ur_cga[k];
                let mut r = REC_SMEM;
                if pred {
                    // wariant predykowany (m_init/b_mbarrier): b4=03, b10=c1
                    r[4] = 0x03;
                    r[10] = 0xc1;
                } else if k == 0 && dst == 5
                    && !feat.bsync_close.is_empty()
                    && !(feat.mc_exch.is_empty() && feat.mc_arrive.is_empty()
                        && feat.mc_phase.is_empty())
                {
                    // wariant pierwszego okna TYLKO w rodzinie mbarrier-EXCH
                    // (bulk1/b_bulk_cp); p_ldsm ma BSSY+BSYNC ale b10 zostaje
                    // 0x41 (zgold-test p_ldsm = (41,01)).
                    r[10] = 0x01;
                    r[11] = 0x02;
                } else if dst != 5 {
                    // mk41: siatka rol = (dstUR<<6)|1 (korpus sm_100; domysl
                    // 0x41,01 to dokladnie przypadek dst=5 — bez zmian tam).
                    let v: u16 = ((dst as u16) << 6) | 1;
                    r[10] = (v & 0xff) as u8;
                    r[11] = (v >> 8) as u8;
                }
                out.extend_from_slice(&r);
            }
            Ev::McD1(k) => {
                let (_l, g) = feat.mc_d1[k];
                out.extend_from_slice(&crate::mercury::merc_mbar_d1_blob(g));
            }
            Ev::McExch(k) => {
                let (_l, g, addr, val) = feat.mc_exch[k];
                out.extend_from_slice(&crate::mercury::merc_exch_rec(
                    g, feat.cflow_bssy, addr, val,
                ));
            }
            Ev::McArrive(k) => {
                let (_l, b4) = feat.mc_arrive[k];
                out.extend_from_slice(&crate::mercury::merc_arrive_rec(b4));
            }
            Ev::McPhase(_k) => {
                out.extend_from_slice(&crate::mercury::merc_phasechk_rec());
            }
            Ev::McMiniVoteu(_) | Ev::McMiniUshf(_) => {
                out.extend_from_slice(&crate::mercury::MERC_MINI_VOTEU);
            }
            Ev::McMiniLea(_) => out.extend_from_slice(&crate::mercury::MERC_MINI_LEA18),
            Ev::McMiniWs(k) => {
                let (_l, b2) = feat.ws_minis[k];
                out.extend_from_slice(if b2 == 0x6e {
                    &crate::mercury::MERC_MINI_WS6E
                } else {
                    &crate::mercury::MERC_MINI_WS76
                });
            }
            Ev::McMiniUvirt(_) => out.extend_from_slice(&crate::mercury::MERC_MINI_UVIRT),
            Ev::McMiniUmovRR(_) => out.extend_from_slice(&crate::mercury::MERC_MINI_UMOV_RR),
            Ev::McUblkcp(_) => out.extend_from_slice(&crate::mercury::MERC_UBLKCP),
            Ev::McPlop3Rec(k) => out.extend_from_slice(&feat.plop3_rec[k].1),
            Ev::McPlop3uRec(k) => out.extend_from_slice(&feat.plop3u_rec[k].1),
            Ev::McUplop3Rec(k) => out.extend_from_slice(&feat.uplop3_rec[k].1),
            Ev::McDsetpImmRec(k) => out.extend_from_slice(&feat.dsetpimm_rec[k].1),
            Ev::McCs2rRec(k) => out.extend_from_slice(&feat.cs2r_rec[k].1),
            Ev::McLop3NotRec(k) => out.extend_from_slice(&feat.lop3not_rec[k].1),
            Ev::McUlop3NotRec(k) => out.extend_from_slice(&feat.ulop3not_rec[k].1),
            // mk59: d10102-47 z rzeczywistym regiem maski (lane WC-site).
            Ev::McD1Wc47(k) => {
                out.extend_from_slice(&crate::mercury::merc_d1wc47_record(feat.d1wc47[k].1))
            }
            Ev::Redux2(k) => out.extend_from_slice(&feat.redux2[k].1),
            Ev::McRedg2(k) => out.extend_from_slice(&feat.redg2_rec[k].1),
            Ev::McAtomg2(k) => out.extend_from_slice(&feat.atomg2_rec[k].1),
            Ev::ShiftAt(_) => out.extend_from_slice(&REC_SHIFT_REGION),
            Ev::Store2(k) => out.extend_from_slice(&rec_store2(feat.store2[k])),
            Ev::Mini2(k) => out.extend_from_slice(&feat.mini2[k].1.to_le_bytes()),
            Ev::EdgeLd(k) => out.extend_from_slice(&rec_edge32(feat.edge_ld[k], feat.edge_v)),
            Ev::EdgeLdg(k) => out.extend_from_slice(&rec_edge1e32(feat.edge_ldg[k])),
            Ev::Utca(k) => {
                match feat.utca[k].1 {
                    0 => {
                        // mk27-rule: pierwszy FNS b17=0x02, kolejne 0x01.
                        let mut rc = REC_UTCA_FNS;
                        rc[17] = if utca_fns_seen == 0 { 0x02 } else { 0x01 };
                        utca_fns_seen += 1;
                        out.extend_from_slice(&rc);
                    }
                    1 => out.extend_from_slice(&REC_MINI_UTCA_AND),
                    _ => {}
                }
            }
            Ev::AtomSmem(k) => {
                let (_l, imm, op) = feat.atom_smem[k];
                let mut rc = if op == 1 {
                    REC_ATOMS_SMEM_AND
                } else {
                    REC_ATOMS_SMEM_OR
                };
                rc[28..32].copy_from_slice(&imm.to_le_bytes());
                out.extend_from_slice(&rc);
            }
        }
    }
    // mk15b/mk59-legacy: rekordy d1-34B za blokami kolektywnymi plain-BSSY
    // TYLKO gdy sciezka nie miala skanu tekstu (gold q_bsync_pair x2).
    if !feat.d1wc47_scanned {
        for _ in 0..feat.d1wc47_legacy {
            out.extend_from_slice(&crate::mercury::merc_d1wc47_record(0));
        }
    }
    // ATOM-klasa legacy: po strumieniu tylko gdy brak per-lane metadanych
    // (mk14). Klasy nie-RED emitowane juz w lane (Ev::Atom); RED zostaja tu.
    if feat.atoms.is_empty() {
        // mk48: lane'y REDG z wlasnymi rekordami (redg2_rec) nie dostaja
        // legacy trailing REC_ATOM (k_atom/v_atom: dublet po mk48-fixie).
        let covered = feat.redg2_rec.len() as u32 + feat.atomg2_rec.len() as u32;
        for _ in 0..feat.n_atom.saturating_sub(covered) {
            out.extend_from_slice(&REC_ATOM);
        }
    } else {
        for a in &feat.atoms {
            if a.1 == crate::mercury::MERC_ATOM_CLS_RED {
                out.extend_from_slice(&REC_ATOM);
            }
        }
    }
}

/// mk27: sciezka zero-param pozycyjna (mkvmem: kolejnosc rekordow po lane).
/// PROLOG wypisany juz przez wywolujacego. Brak redux/cbank w tym scope
/// (kandydat 0132 mkvmem odrzucany przez merger ptxas — patrz mk26 capture).
fn emit_zero_param_positioned(out: &mut Vec<u8>, feat: &MercFeatures) {
    #[derive(Clone, Copy)]
    enum ZE {
        Elect,
        Ghost,
        Ghost76,
        SmemA,
        Utca(usize),
        AtomSmem(usize),
        S2r(usize),
    }
    let mut ev: Vec<(u32, u8, ZE)> = Vec::new();
    for &l in &feat.elect_pos {
        ev.push((l, 1, ZE::Elect));
    }
    for &l in &feat.syncwarp {
        if feat.ghost_mini76.contains(&l) {
            ev.push((l, 2, ZE::Ghost76));
        } else {
            ev.push((l, 2, ZE::Ghost));
        }
    }
    for &l in &feat.s2ur_lanes {
        ev.push((l, 3, ZE::SmemA));
    }
    for (k, _) in feat.utca.iter().enumerate() {
        ev.push((feat.utca[k].0, 4, ZE::Utca(k)));
    }
    for (k, _x) in feat.atom_smem.iter().enumerate() {
        ev.push((feat.atom_smem[k].0, 5, ZE::AtomSmem(k)));
    }
    for (k, &l) in feat.s2r_lanes.iter().enumerate() {
        ev.push((l, 6, ZE::S2r(k)));
    }
    ev.sort_by_key(|&(l, t, _)| (l, t));
    let anchor_base = {
        let mut cf = REC_EXTRA_EXIT;
        let v: u32 = (feat.anchor_f4 << 6) | 1;
        cf[10] = (v & 0xff) as u8;
        cf[11] = (v >> 8) as u8;
        cf
    };
    let mut utca_fns_idx = 0usize;
    for (_, _, k) in &ev {
        match *k {
            ZE::Elect => out.extend_from_slice(&[0x41, 0x64, 0x00, 0x0a]),
            ZE::Ghost => out.extend_from_slice(&crate::mercury::MERC_SYNCWARP_GHOST),
            ZE::Ghost76 => out.extend_from_slice(&REC_MINI_GHOST76),
            ZE::SmemA => out.extend_from_slice(&REC_SMEM),
            ZE::Utca(i) => {
                match feat.utca[i].1 {
                    0 => {
                        let mut rc = REC_UTCA_FNS;
                        rc[17] = if utca_fns_idx == 0 { 0x02 } else { 0x01 };
                        utca_fns_idx += 1;
                        out.extend_from_slice(&rc);
                    }
                    1 => out.extend_from_slice(&REC_MINI_UTCA_AND),
                    _ => {}
                }
            }
            ZE::AtomSmem(i) => {
                let (_, imm, op) = feat.atom_smem[i];
                let mut rc = if op == 1 { REC_ATOMS_SMEM_AND } else { REC_ATOMS_SMEM_OR };
                rc[28..32].copy_from_slice(&imm.to_le_bytes());
                out.extend_from_slice(&rc);
            }
            ZE::S2r(i) => {
                let mut cf = anchor_base;
                if let Some(&d) = feat.s2r_dest.get(i) {
                    let v: u32 = ((d as u32) << 6) | 1;
                    cf[10] = (v & 0xff) as u8;
                    cf[11] = (v >> 8) as u8;
                }
                if let Some(&sr) = feat.s2r_sr.get(i) {
                    cf[12] = sr;
                }
                out.extend_from_slice(&cf);
            }
        }
    }
    // mk27: mkvmem ma 4. rekord 01476c0a po wszystkich atomach (kandydat
    // mk26 i82, przed trailerem) gdy kernel ma wewnetrzne fn z RET —
    // mechanizm dokladny mk27-otwarty; empiria: 1x za kernel z RET+utca.
    if feat.has_ret_internal && !feat.utca.is_empty() {
        out.extend_from_slice(&crate::mercury::MERC_SYNCWARP_GHOST);
    }
}

fn emit_feature_records(out: &mut Vec<u8>, feat: &MercFeatures) {
    let bar_bytes: [u8; 16] = if feat.bar_pred {
        let mut br = REC_BAR;
        br[4] = 0x01; // BAR pod predykatem/if: payload[0] = 01 (v_barx-era100)
        br
    } else {
        REC_BAR
    };
    let bar_rec = &bar_bytes;
    out.extend_from_slice(&REC_PROLOG);
    if !feat.param_loads.is_empty() {
        emit_feature_records_laned(out, feat, bar_rec);
        return;
    }
    // mk27: zero-param kernel z pozycyjnymi rodzinami (mkvmem: UTCATOMSWS,
    // ATOMS z imm, ghosty, ELECT, smem-anchory per S2UR) — harmonogram po
    // lane kodu, jak u nvcc (final TLV = podciag strumienia kandydatow po
    // soff, zmierzony oraculum mk26 na FUN_004ad1d0).
    if !feat.utca.is_empty() || !feat.atom_smem.is_empty() {
        emit_zero_param_positioned(out, feat);
        return;
    }
    // (mk27 note: pozny 4. ghost 01476c0a po lane 49 w mkvmem — emitowany
    // w sciezce zero-param-pozycyjnej gdy kernel ma wewnetrzne fn z RET)
    let cflow_rec = |feat: &MercFeatures| {
        let mut cf = REC_EXTRA_EXIT;
        // mk12 (iter AD, zweryfikowane na secie gold 70/70): payload =
        // (f4<<6)|1 na bajtach [10:11]; f4 = MercFeatures.anchor_f4.
        // znane residua: multi-anchor seryjnosci (c_ld_dyn2, p_atomg/p_atoms),
        // q_tail_call, d_ifelse_ld (pred-merge LDG), k_ldg2 (STG b20 kursora).
        let v: u32 = (feat.anchor_f4 << 6) | 1;
        cf[10] = (v & 0xff) as u8;
        cf[11] = (v >> 8) as u8;
        // wariant atom lub multi-MMA: bajt[12]=00, inaczej 01 (szablon 02 w b13).
        if feat.cflow_atom || feat.os_mma_multi {
            cf[12] = 0x00;
        }
        cf
    };
    let smem_mid = feat.smem_static && feat.cflow;
    if feat.cflow && !smem_mid {
        out.extend_from_slice(&cflow_rec(feat));
    }
    let total_params = feat.used_params + feat.used_scalar_params;
    // mk35: nvcc NIE emituje desc/cbank dla kerneli z parametrami, ktorych
    // nic nie laduje (div3/v_scalar/v_gconst: samo LDC envreg + EXIT).
    // Sciezka legacy fabrykuje rekordy z metadanych param — zamknieta dla
    // ery sm103 natywnej (bez param-loadow). Era sm100 zostaje.
    let legacy_fabricate = feat.era_sm100;
    if total_params > 0 && legacy_fabricate {
        // Descs w kolejnosci pierwszego uzycia parametru (regula mk8/v_*):
        // tail-dw bajtow[28..32] = 8 * idx-sygnaturowy parametru
        // (sciezka legacy BEZ param_loads: order w dziedzinie pi = slotow 8B;
        // paramy 8B-wyrowane => 8*pi == rel, mk19).
        // role (b10,b11): (83,00)=param iterowany pierwszy; (03,01)=kolejne
        // parametr write-first dla n_ptr<=2; (83,01)=write dla n_ptr>=3.
        // Wariant [b2/b4] wg mechanizmu ladowania slotu (fs-lab 2026-08-05):
        // slot przez LDCU* => 08 06 + b4=fa; przez LDC* => 0e 06 + f8.
        // Jeden desc NA INSTRUKCJE LADOWANIA (powtorne => wiele descs;
        // LDCU.128 pokrywa dwa sloty => 1 desc (07,02)).
        let order: Vec<u32> = match &feat.param_order {
            Some(o) if !o.is_empty() => o.clone(),
            _ => (0..feat.used_params).collect(),
        };
        let bar0_pre =
            feat.era_sm100 && !feat.smem_static && feat.bar_count > 0 && !feat.bar_pred;
        let mut descs: Vec<[u8; 32]> = Vec::new();
        let atom_async = feat.n_atom > 0;
        // mk11 (k_mma): slot pokryty przez 128-bit load sasiada (pi-1 ma
        // width 16, a sam nie ma wlasnego loadu [width 0, brak bitow unif/reg])
        // nie dostaje wlasnego desca — dane trafiaja rekordem sasiada.
        let covered = |pi: u32| -> bool {
            let i = pi as usize;
            i > 0
                && feat.param_width.get(i).copied().unwrap_or(0) == 0
                && feat.param_width.get(i - 1).copied().unwrap_or(0) == 16
                && ((feat.param_uniform >> pi) & 1) == 0
                && ((feat.param_regpath >> pi) & 1) == 0
        };
        for (j, &pi) in order.iter().enumerate() {
            if covered(pi) {
                continue;
            }
            let w = feat
                .param_width
                .get(pi as usize)
                .copied()
                .unwrap_or(0);
            let w = if w == 0 { 8 } else { w };
            // width ladder -> b6 (fs-lab): 1=>02, 2=>22, 4=>42, 8=>52, 16=>62
            let b6: u8 = match w {
                1 => 0x02,
                2 => 0x22,
                4 => 0x42,
                16 => 0x62,
                _ => 0x52,
            };
            let uniform = (feat.param_uniform >> pi) & 1 == 1;
            let regp = (feat.param_regpath >> pi) & 1 == 1;
            let regp = regp || !uniform; // brak danych o sciezce => register path
            if uniform {
                let mut d = REC_PARAM_DESC;
                d[2] = 0x08;
                d[4] = 0xfa;
                d[6] = b6;
                let (r0, r1) = match w {
                    16 => (0x07, 0x02),
                    4 => (0x81, 0x01),
                    1 | 2 => (0x01, 0x01),
                    _ => {
                        if atom_async {
                            (0x03, 0x02)
                        } else {
                            (0x83, 0x01)
                        }
                    }
                };
                d[10] = r0;
                d[11] = r1;
                d[28..32].copy_from_slice(&(8 * pi).to_le_bytes());
                descs.push(d);
            }
            if regp {
                let mut d = REC_PARAM_DESC;
                let is_write = (feat.param_write >> pi) & 1 == 1;
                let (b10, b11) = if feat.used_params == 1 {
                    (0x83, 0x00)
                } else if is_write {
                    if feat.used_params <= 2 { (0x03, 0x01) } else { (0x83, 0x01) }
                } else if j == 0 {
                    (0x83, 0x00)
                } else {
                    (0x03, 0x01)
                };
                d[6] = b6;
                if b6 != 0x52 {
                    // scalar-ish reg-path (k_stg2: (41,02) przy b6=42)
                    d[10] = 0x41;
                    d[11] = 0x02;
                } else {
                    d[10] = b10;
                    d[11] = b11;
                }
                d[28..32].copy_from_slice(&(8 * pi).to_le_bytes());
                descs.push(d);
            }
        }
        for (j, d) in descs.iter().enumerate() {
            if j == 0 {
                out.extend_from_slice(d);
                // era sm_100: BAR0 stoi PRZED cbank, reszta po STG.
                if bar0_pre {
                    out.extend_from_slice(bar_rec);
                }
                out.extend_from_slice(if feat.smem_static { &REC_CBANK_SMEM } else { &REC_CBANK });
                if feat.smem_static {
                    out.extend_from_slice(&REC_SMEM);
                }
                if smem_mid {
                    out.extend_from_slice(&cflow_rec(feat));
                }
                if feat.diverge_region {
                    out.extend_from_slice(&REC_SHIFT_REGION);
                    // mk15: patrz laned-path — dup rekordu smem po regionie.
                    if feat.smem_static {
                        out.extend_from_slice(&REC_SMEM);
                    }
                }
            } else {
                out.extend_from_slice(d);
            }
        }
        if order.is_empty() {
            // zero-param kerneli z bar/smem (dawniej sciezka else)
        }
        for _ in 0..feat.used_scalar_params {
            out.extend_from_slice(&REC_SCALAR_PARAM);
        }
        // Lane wykonawcza: BAR/STG/ATOM w kolejnosci kodu (nvcc pipeline;
        // dowody: d_2seq, v_bar2, k_smem). Gdy pozycje nieznane -> legacy
        // kolejnosc grupowa (bar-y pierwsze).
        let have_pos = feat.bar_pos.len() == feat.bar_count as usize
            && feat.stg_pos.len() == feat.n_stg as usize
            && (feat.n_stg + feat.bar_count) > 0
            && (!feat.bar_pos.is_empty() || !feat.stg_pos.is_empty());
        if have_pos && !bar0_pre {
            #[derive(Clone, Copy, PartialEq, Eq)]
            #[allow(dead_code)]
            enum Ev { Bar, Stg, Atom, Elect, Xor, AcqBulk, Cctl, CctlRml2, Pad, Mma, F64i, DfmaImm }
            const REC_MINI_ELECT: [u8; 4] = [0x41, 0x64, 0x00, 0x0a];
            let mut ev: Vec<(u32, Ev, u32)> = Vec::new();
            enum Ev2 {}
            for (i, &pos) in feat.bar_pos.iter().enumerate() {
                ev.push((pos, Ev::Bar, i as u32));
            }
            for (i, &pos) in feat.stg_pos.iter().enumerate() {
                ev.push((pos, Ev::Stg, i as u32));
            }
            for (i, &pos) in feat.elect_pos.iter().enumerate() {
                ev.push((pos, Ev::Elect, i as u32));
            }
            for (i, xl) in feat.xor_lanes.iter().enumerate() {
                ev.push((xl.0, Ev::Xor, i as u32));
            }
            for &pos in &feat.acqbulk_pos {
                ev.push((pos, Ev::AcqBulk, 0));
            }
            for &pos in &feat.cctl_pos {
                ev.push((pos, Ev::Cctl, 0));
            }
            for &pos in &feat.cctl_rml2_pos {
                ev.push((pos, Ev::CctlRml2, 0));
            }
            for &pos in &feat.pad_pos {
                ev.push((pos, Ev::Pad, 0));
            }
            for (i, m) in feat.mma_lanes.iter().enumerate() {
                ev.push((m.0, Ev::Mma, i as u32));
            }
            for (i, m) in feat.f64_lanes.iter().enumerate() {
                ev.push((m.0, Ev::F64i, i as u32));
            }
            for (i, m) in feat.dfmaim.iter().enumerate() {
                ev.push((m.0, Ev::DfmaImm, i as u32));
            }
            ev.sort_by_key(|&(pos, kind, _)| (pos, match kind {
                Ev::Bar => 1,
                Ev::Elect => 2,
                _ => 0,
            }));
            // spojnosc: sort stabilny utrzymuje kolejnosc rejestracji przy remisie
            for (_, kind, idx) in ev {
                match kind {
                    Ev::Xor => {
                        let xl = feat.xor_lanes[idx as usize];
                        out.extend_from_slice(&rec_xor(xl.1, xl.2, xl.3, xl.4));
                    }
                    Ev::AcqBulk => out.extend_from_slice(&REC_ACQBULK),
                    Ev::Cctl => out.extend_from_slice(&REC_CCTL),
                    Ev::CctlRml2 => out.extend_from_slice(&[0x41, 0x0e, 0x02, 0x0c]),
                    Ev::Pad => out.extend_from_slice(&crate::mercury::MERC_LANE_PAD),
                    Ev::Mma => {
                        let m = feat.mma_lanes[idx as usize];
                        if crate::mercury::merc_mma_is_mini(m.1) {
                            out.extend_from_slice(&crate::mercury::MERC_MMA_MINI_SAT);
                        } else {
                            out.extend_from_slice(&crate::mercury::build_mma_rec(
                                m.1, m.2, m.3, m.4, m.5, m.6,
                            ));
                        }
                    }
                    Ev::F64i => {
                        let m = feat.f64_lanes[idx as usize];
                        out.extend_from_slice(&crate::mercury::build_f64imm_rec(
                            m.1, m.2, m.3, m.4, m.5, m.6,
                        ));
                    }
                    Ev::DfmaImm => {
                        let m = feat.dfmaim[idx as usize];
                        out.extend_from_slice(&crate::mercury::build_dfmaimm_rec(
                            m.1 == 1, m.2, m.3, m.4, m.5, m.6, m.7,
                        ));
                    }
                    Ev::Bar => {
                        let mut br = *bar_rec;
                        if let Some(&(id, cnt)) = feat.bar_args.get(idx as usize) {
                            if id != 0 || cnt != 0 {
                                br[11] = id as u8;
                                br[14] = cnt as u8;
                            }
                        }
                        out.extend_from_slice(&br);
                    }
                    Ev::Elect => out.extend_from_slice(&REC_MINI_ELECT),
                    Ev::Atom => out.extend_from_slice(&REC_ATOM),
                    Ev::Stg => {
                        let stg_i = idx as usize;
                        out.extend_from_slice(&rec_stg(feat, stg_i, None));
                    }
                }
            }
            for _ in 0..feat.n_atom {
                out.extend_from_slice(&REC_ATOM);
            }
        } else {
            // brak pozycji kodowych — zachowanie grupowe: rekordy xor za
            // sekcja prologowa (anchor/desc/cbank), przed grupowym bar/stg.
            for xl in &feat.xor_lanes {
                out.extend_from_slice(&rec_xor(xl.1, xl.2, xl.3, xl.4));
            }
            for _ in 0..feat.acqbulk_pos.len() {
                out.extend_from_slice(&REC_ACQBULK);
            }
            for _ in 0..feat.cctl_pos.len() {
                out.extend_from_slice(&REC_CCTL);
            }
            if feat.bar_count > 0 && !bar0_pre {
                for _ in 0..feat.bar_count {
                    out.extend_from_slice(bar_rec);
                }
            }
            for stg_i in 0..feat.n_stg {
                out.extend_from_slice(&rec_stg(feat, stg_i as usize, None));
            }
            for _ in 0..feat.n_atom {
                out.extend_from_slice(&REC_ATOM);
            }
            if bar0_pre {
                for _ in 1..feat.bar_count {
                    out.extend_from_slice(bar_rec);
                }
            }
        }
    } else if feat.bar_count > 0 || feat.smem_static {
        if feat.smem_static && feat.bar_count == 0 {
            // samo smem bez parametrow — nieobserwowane; zachowaj pole
        }
        for _ in 0..feat.bar_count {
            out.extend_from_slice(bar_rec);
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
    era_sm100: bool,
) -> Vec<u8> {
    use crate::mercury::{opcode_tracked_hint, tail_for_instr_count, word_is_nop_hint};
    let n_instr = code.len() / 16;
    let is_nop = |i: usize| {
        if let Some(ops) = opcodes {
            if i < ops.len() {
                return ops[i] == "NOP";
            }
        }
        word_is_nop_hint(&code[i * 16..i * 16 + 2])
    };
    let is_w0 = |i: usize| -> bool {
        match opcodes {
            Some(ops) if i < ops.len() => crate::mercury::opcode_bitmap_zero_weight(&ops[i]),
            _ => false,
        }
    };
    // trim: ucinanie WYLACZNIE koncowych NOPow (midstream NOPy zajmuja sloty!)
    let mut end = n_instr;
    while end > 0 && is_nop(end - 1) {
        end -= 1;
    }
    // Regula regionowa (mk9+q_bsync_pair): bloki [WARPSYNC, NOP, ENDCOLLECTIVE]
    // (kolektywne epilogi) wyjmują z bitmapy WARPSYNC i NOP (2 sloty na blok;
    // ENDCOLLECTIVE zostaje, =1). Korpus: +42.8pp exact (40.4 -> 83.2%).
    let region_drop: Vec<bool> = match opcodes {
        Some(ops) => {
            let mut dr = vec![false; n_instr];
            for i in 0..end {
                if ops[i].starts_with("ENDCOLLECTIVE") {
                    // najblizszy poprzedzajacy WARPSYNC w oknie 6 i NOP miedzy
                    let start = i.saturating_sub(6);
                    let mut ws = None;
                    let mut nop = None;
                    for k in (start..i).rev() {
                        if ws.is_none() && ops[k].starts_with("WARPSYNC") {
                            ws = Some(k);
                        }
                        if nop.is_none() && ops[k] == "NOP" {
                            nop = Some(k);
                        }
                    }
                    if let Some(k) = ws { dr[k] = true; }
                    if let Some(k) = nop { dr[k] = true; }
                }
            }
            dr
        }
        None => Vec::new(),
    };
    // mk13d: spany [BSSY..BSYNC) (mikrolab sw4/8/16/32/64): wewnatrz spanu
    // WSZYSTKIE instrukcje dostaja bit bitmapy (takze BRA/BSSY/...), NOP
    // w spanie nie zajmuje slotu B-space (B zlicza mniej), BSYNC zamyka
    // span (sam bez bitu, ale slot zachowuje). Zgodnosc fitu: 5/5 wierszy.
    // mk16.3 (gold q_bsync_pair): TWO span dialects. Surowe "BSSY" (bez
    // .RECONVERGENT): ghost-NOP w spanie BEZ bitu, BSYNC-zamkniecie Z bitem,
    // ENDCOLLECTIVE bez bitu, BRA tuz po bloku kolektywnym/zamknieciu Z bitem.
    let plain_bssy = matches!(opcodes, Some(ops) if ops.iter().any(|o| o == "BSSY"));
    let mut bssy_close_lanes: Vec<u32> = Vec::new();
    let in_bssy_span: Vec<bool> = match opcodes {
        Some(ops) => {
            let mut v = vec![false; n_instr];
            let mut st: Option<usize> = None;
            for i in 0..end {
                let b = ops[i].split('.').next().unwrap_or(ops[i].as_str());
                if b == "BSSY" {
                    st = Some(i);
                    v[i] = true;
                } else if let Some(s0) = st {
                    if i > s0 {
                        v[i] = true;
                    }
                }
                if b == "BSYNC" && st.is_some() {
                    v[i] = false;
                    bssy_close_lanes.push(i as u32);
                    st = None;
                }
            }
            v
        }
        None => Vec::new(),
    };
    // mk14: ghost __syncwarp NOP-y ZACHOWUJA sloty B nawet w spanie BSSY
    // (sa na liscie site'ow EIATTR-0x28 -> rekord 01476c0a).
    let syncwarp_set: Vec<u32> = meta.merc_syncwarp.clone();
    // mk14.3: lane'y gryzione przez eventy LDGSTS.
    let mut feat_host_zero: Vec<u32> = meta
        .merc_ldgsts_pin
        .iter()
        .map(|p| p.0)
        .chain(meta.merc_ldgsts_wait.iter().map(|&(l, _)| l))
        .collect();
    if !meta.merc_ldgsts2.is_empty() {
        feat_host_zero = meta
            .merc_ldgsts2
            .iter()
            .filter_map(|x| x.pin_host)
            .chain(meta.merc_ldgsts_wait.iter().map(|&(l, _)| l))
            .collect();
    }
    let mut xor_lane_set: Vec<u32> =
        meta.merc_xor.iter().map(|&(lane, _, _, _, _)| lane).collect();
    // mk13: rejestrowa forma xor tez zastepuje wezel typu4 (brak bitu).
    xor_lane_set.extend(meta.merc_xor_reg.iter().map(|&(lane, _, _, _, _)| lane));
    let feat_f64_set: Vec<u32> = meta
        .merc_f64imm
        .iter()
        .map(|&(lane, ..)| lane)
        .chain(meta.merc_dfmaimm.iter().map(|&(lane, ..)| lane))
        .collect();
    let pad_set: Vec<u32> = meta.merc_pad_pos.clone();
    let bra_guard_set: Vec<u32> = meta.merc_guarded_bra.clone();
    let bra_selfloop_set: Vec<u32> = meta.merc_bra_selfloop.clone();
    let lop3_pdest_set: Vec<u32> = meta.merc_lop3_pdest.clone();
    // mk27: dialekt tcgen05/mkvmem (kernel z UTCATOMSWS na stosie
    // zero-param): bitmapa ustawia BRA.U/REDUX, kasuje UTCATOMSWS/WARPSYNC
    // (fit mk27 na mkvmem: 9 bitow rozbieznosci -> reguly klasowe).
    let dialect_utca = !meta.merc_utca.is_empty();
    let mut force_bit: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    // mk30: rodziny b_* — lane z kandydatem-rekordem (mini/pelny) albo
    // regionowe kasowanie bitow. m-family == kernel z klasa SYNCS.*.
    let m_family = !meta.merc_mc_exch.is_empty()
        || !meta.merc_mc_arrive.is_empty()
        || !meta.merc_mc_phase.is_empty();
    let mut bit0: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mc_nodeless: std::collections::BTreeSet<u32> =
        meta.merc_mc_nodeless.iter().copied().collect();
    for &(l, _) in &meta.merc_mc_d1 {
        bit0.insert(l);
    }
    for &l in &meta.merc_mc_voteu_all {
        bit0.insert(l);
    }
    // mk34: ushf_fin NIE kasuje bitu — lane'e prologu USHF sa NODELESS
    // (mc_nodeless; usuniecie calego slotu, nie tylko bitu).
    // lea4100-mini: mk26 — wezel zastapiony; bit kasowany.
    for &l in &meta.merc_mc_lea18 {
        bit0.insert(l);
    }
    for &l in &meta.merc_umov_rr {
        bit0.insert(l);
    }
    for &(l, _) in &meta.merc_ws_minis {
        bit0.insert(l);
    }
    // mk30b-korekta (slot-space'): HFMA2-const ZACHOWUJE bit (nvcc slot31 =
    // lane33 w b_tcgen05 — wczesniejszy odczyt lane-space byly pomylka).
    // Natomiast UVIRTCOUNT.DEALLOC z mini 4144 KASUJE bit wlasnej lane
    // (nvcc nie ustawia slotu 33; mini zastepuje wezel t4).
    for &l in &meta.merc_uvcount {
        bit0.insert(l);
    }
    if m_family {
        // mk34 (node-model, g5b na b_mbarrier bulk_cp): Pelny zestaw regul
        // m-family — walker nvcc daje lane'om wezly typu:
        //  * PHASECHK -> rekord 021b4c — bez bitu,
        for &l in &meta.merc_mc_phase {
            bit0.insert(l);
        }
        //  * ARRIVE (wszystkie warianty b4) -> rekord 021b2c — bez bitu,
        for &(l, _b4) in &meta.merc_mc_arrive {
            bit0.insert(l);
        }
        //  * EXCH -> rekord 021b5e — bez bitu,
        for &(l, _, _, _) in &meta.merc_mc_exch {
            bit0.insert(l);
        }
        //  * PLOP3 expect_tx -> trio rekordow 0110060a — bez bitu,
        for &(l, _) in &meta.merc_plop3_tx {
            bit0.insert(l);
        }
        //  * UBLKCP -> rekord 02232826 — bez bitu,
        for &l in &meta.merc_ublkcp {
            bit0.insert(l);
        }
        //  * S2UR CgaCtaId -> smem-anchor 010b060a — NIGDY bit (kasowanie
        //    mk30b s2ur_extra bylo lane-space artefaktem: nvcc node21
        //    b_mbarrier ma flag=0);
        //  * MOV R?,0x400 / ULEA prologu / braided-BRA: MAJA bity
        //    (g5b: n15/n17/n21/n32/n33) — reguly kasujace mk30b usuniete.
    }
    // mk35: ISETP z operandem UR (bez .EX) — mini 42 10 32 14 zastepuje
    // wezel t4, lane bez bitu (nvcc bar_if2 g5b).
    for &l in &meta.merc_isetp_ur {
        bit0.insert(l);
    }
    // mk41: head XSETP-pary traci bit (mini zamiast wezla t4; lab bitmapa).
    for &(l, _) in &meta.merc_xsetp_pairs {
        bit0.insert(l);
    }
    // mk40: mini-slownik korpusowy (FFMA2/HADD2/F2I.U64.FT/...): rekord
    // zastepuje wezel t4 — lane bez bitu (inwarinat EXACT count-match;
    // residuum: FFMA2 22% lanow z bitem wg korpusu = flag-rule mk41).
    for &(l, _) in &meta.merc_mini2 {
        bit0.insert(l);
    }
    // mk44: rekord 0110060a (PLOP3 dual-output nibswap-LUT) zastepuje
    // wezel t4 — lane bez bitu (lab brute k2/k7: slot == lane rekordu,
    // bit=0; tylko lane'owe rekordy z meta.merc_plop3_rec, nie-elig
    // PLOP3 (UP/nietyp-LUT) zachowuja dotychczasowe zachowanie).
    for &(l, _) in &meta.merc_plop3_rec {
        bit0.insert(l);
    }
    // mk45: rekord 010b0c0a zastepuje wezel t4 — lane CS2R bez bitu
    // (lanebits: 43621 bit=0 / 6853 bit=1, odczyty bit=1 = misalign-artefakt
    // big-kerneli jak w mk44; doktryna 'rekord zastepuje wezel').
    for &(l, _) in &meta.merc_cs2r_rec {
        bit0.insert(l);
    }
    // mk47: rekord 012b{00|04}0a zastepuje wezel t4 — lane LOP3 bez bitu
    // (lanebits: 3922 bit=0 / 549 bit=1, ogony = misalign big-kerneli).
    for &(l, _) in &meta.merc_lop3not_rec {
        bit0.insert(l);
    }
    // mk58: jak mk47 — lane ULOP3 NOT-MOV bez bitu (675/134 c5).
    for &(l, _) in &meta.merc_ulop3not_rec {
        bit0.insert(l);
    }
    // debug mk30: wypisz bit0/dialekt pod CUBIT_DEBUG_MC=1
    if std::env::var_os("CUBIT_DEBUG_MC").is_some() {
        eprintln!(
            "[mc] {}: m_family={} utca={} bit0={:?} nodeless={:?} hfma2c={:?} utca_meta={:?}",
            meta.name, m_family, dialect_utca, bit0, mc_nodeless, meta.merc_hfma2_const, meta.merc_utca
        );
    }
    // B = liczba slotow 0..end minus klasy zerowej wagi (nie dostaja bitu)
    let mut bitmap: Vec<u32> = Vec::new();
    let mut cur = 0u32;
    let mut b_index = 0usize;
    for i in 0..end {
        let nop_span_skip = in_bssy_span.get(i).copied().unwrap_or(false)
            && matches!(opcodes, Some(ops) if ops[i] == "NOP")
            && !syncwarp_set.contains(&(i as u32));
        // mk34: lane'e bez wezlow capmerc (mc_nodeless) wypadaja z
        // przestrzeni bitmapy calkowicie — brak slotu (g5b node-count).
        if is_w0(i)
            || region_drop.get(i).copied().unwrap_or(false)
            || nop_span_skip
            || mc_nodeless.contains(&(i as u32))
        {
            continue;
        }
        let tracked = match opcodes {
            Some(ops) if i < ops.len() => {
                let mut t = opcode_tracked_hint(&ops[i]);
                let base_i = ops[i].split('.').next().unwrap_or(ops[i].as_str());
                // mk13: CALL dostaje bit bitmapy (gold p_call slot11; RET ma
                // bit zawsze — nie figuruje w opcode_tracked_hint-exclude).
                if !t && base_i == "CALL" {
                    t = true;
                }
                // mk27: dialekt UTCA (tcgen05/mkvmem): UTCATOMSWS i WARPSYNC
                // bez bitu; BRA.U i REDUX z bitem.
                if dialect_utca {
                    if base_i == "UTCATOMSWS" || base_i == "WARPSYNC" {
                        t = false;
                    }
                    if ops[i] == "BRA.U" || base_i == "REDUX" {
                        t = true;
                    }
                    // mk28: zwykly BRA w dialekcie UTCA tez dostaje bit
                    // (epilog: BRA przeskakujacy strefy CALL thunkow do
                    // wspolnego landing NOP/EXIT; mkvmem sloty 48/51).
                    // WYJATEK: samo-petla spin (BRA L_x -> wlasny adres),
                    // martwy trap za obszarem funkcji wewnetrznych — bez
                    // bitu (mkvmem slot62 BRA L_400; dowod: orig dword1
                    // bitmapy 0x3fbf1fdf vs nasze 0x3fb61fdf).
                    if base_i == "BRA" && !bra_selfloop_set.contains(&(i as u32)) {
                        t = true;
                    }
                }
                // mk13: predykowany BRA dostaje bit (gold q_switch slot5);
                // koncowy BRA bez predykatu dalej bez bitu.
                if !t && base_i == "BRA" && bra_guard_set.contains(&(i as u32)) {
                    t = true;
                }
                // mk34 (node-model g5b): w m-family KAZDY BRA ma wezel t4
                // z flaga=1 (b_mbarrier 15/21/34/35, b_bulk_cp 4/28), chyba
                // ze samo-petla spin (bez wezla — mk28/mk33).
                if m_family && base_i == "BRA" && !bra_selfloop_set.contains(&(i as u32)) {
                    t = true;
                }
                // mk13: LOP3 z destem predykatowym bez bitu (mini-rekord
                // 42 2a 02 06 w lane, gold d_sw4_store slot6).
                if t && base_i == "LOP3" && lop3_pdest_set.contains(&(i as u32)) {
                    t = false;
                }
                // mk13d: wnetrze spanu BSSY — wszystko tracked (sw*-fit).
                // mk14.3: WYJATEK — klasy semantycznie niesledzone (LDC/S2R/
                // S2UR/LDCU config-uniform) bitu nie dostaja nawet w spanie
                // (gold p_ldsm slot12 S2UR=0; q_bsync_pair slot4 LDC.64=0).
                if in_bssy_span.get(i).copied().unwrap_or(false) {
                    // mk34: ELECT tez bez bitu w spanie (b_bulk_cp lane24:
                    // tylko mini 41 64 00 0a; g5b n21 flag=0).
                    if !matches!(base_i, "LDC" | "LDCU" | "S2R" | "S2UR" | "ELECT") {
                        t = true;
                    }
                }
                if plain_bssy {
                    if base_i == "NOP" {
                        t = false; // ghost-NOP w plain-spanie: slot tak, bit nie
                    }
                    if bssy_close_lanes.contains(&(i as u32)) {
                        t = true; // BSYNC zamykajacy plain-span: bit tak
                    }
                    if base_i == "ENDCOLLECTIVE" {
                        t = false;
                    }
                    if base_i == "BRA" && i > 0 {
                        let prev_plain_block = matches!(opcodes, Some(ops) if {
                            let p = ops[i - 1].split('.').next().unwrap_or(ops[i - 1].as_str());
                            p == "ENDCOLLECTIVE" || bssy_close_lanes.contains(&((i - 1) as u32))
                        });
                        if prev_plain_block {
                            t = true; // BRA tuz po ENDCOLLECTIVE/BSYNC-close: bit tak
                        }
                    }
                }
                // mk13: typowany REDUX -> rekord 0132 zamiast bitu
                // (gold p_redux). mk35 (node-model/g5b): CREDUX tez rekord
                // (at_min), ale GOLY "REDUX" = wezel t4 z bitem, bez
                // rekordu (at_and slot6/slot-bit6). mk27: dialekt UTCA
                // STAWIA bit z powrotem (mkvmem slot41).
                if base_i == "CREDUX" {
                    t = false;
                }
                if base_i == "REDUX" && !dialect_utca && ops[i] != "REDUX" {
                    t = false;
                }
                // mk14.3: hosty rekordow-event LDGSTS (pinned-blob + wait)
                // traca bit (rekord zastepuje wezel t4) — m15 lab 3/3.
                if t && feat_host_zero.contains(&(i as u32)) {
                    t = false;
                }
                t
            }
            _ => true,
        };
        // mk30b: wymuszenie bitu (S2UR#2+ poza spanem; region-fit mk30b).
        let tracked = tracked || force_bit.contains(&(i as u32));
        // 0229-xor lane: pelny rekord zastepuje wezel typu4 (fs6: brak bitu);
        // mk11: to samo dla MMA-025a (niepotrzebne — MMA i tak untracked),
        // dla DMUL/DADD-imm (020f/020c) i dla lane-padow UIADD3 (hint).
        let xor_here = xor_lane_set.contains(&(i as u32));
        let f64_here = feat_f64_set.contains(&(i as u32));
        let pad_here = pad_set.contains(&(i as u32));
        // mk30: b_* rodziny (rekord zastepuje wezel / reguly regionowe).
        let mc_here = bit0.contains(&(i as u32));
        if tracked && !xor_here && !f64_here && !pad_here && !mc_here {
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
    // mk30b: n = ostatni ustawiony bit + 2 (TWARDY inwariant producenta:
    // 17612/17612 blobow korpusu capmerc_all). Zastepuje heurystyke
    // trim-count — rozchodzily sie przy ogonkach po-EXIT (m-family:
    // YIELD/PHASECHK/BRA-trampoliny za EXIT) oraz przy padach BRA.
    let mut bitmax: i64 = -1;
    for (wi, w) in bitmap.iter().enumerate() {
        if *w != 0 {
            bitmax = (wi * 32 + (31 - w.leading_zeros() as usize)) as i64;
        }
    }
    let n_counted = (bitmax + 2).max(0) as u32;
    bitmap.truncate(((n_counted as usize) + 31) / 32);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&kernel_id.to_le_bytes());
    buf.extend_from_slice(&crate::mercury::CAPMERC_MAGIC.to_le_bytes());
    buf.extend_from_slice(&n_counted.to_le_bytes());
    for w in &bitmap {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let mut feat = match opcodes {
        Some(ops) => MercFeatures::from_parts(meta, ops),
        None => MercFeatures::default(),
    };
    feat.era_sm100 = era_sm100;
    emit_feature_records(&mut buf, &feat);
    // regula tail: f(trim-count) — NIE f(B)! (100% na 27,846-korpusie)
    buf.extend_from_slice(&tail_for_instr_count(end as u32).to_le_bytes());
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
    use crate::mercury::{opcode_tracked_hint, tail_for_instr_count, word_is_nop_hint};
    let n_instr = code.len() / 16;
    let is_nop = |i: usize| {
        if let Some(ops) = opcodes {
            if i < ops.len() {
                return ops[i] == "NOP";
            }
        }
        word_is_nop_hint(&code[i * 16..i * 16 + 2])
    };
    // trim: tylko koncowe NOP-y (midstream NOP-y maja sloty w bitmapie).
    let mut end = n_instr;
    while end > 0 && is_nop(end - 1) {
        end -= 1;
    }
    // Bitmap space: sloty 0..end minus klasy zerowej wagi (DEPBAR & co.).
    let mut bitmap_bits: Vec<u8> = Vec::new();
    let mut cur = 0u32;
    let mut b_index = 0usize;
    for i in 0..end {
        if let Some(ops) = opcodes {
            if i < ops.len() && crate::mercury::opcode_bitmap_zero_weight(&ops[i]) {
                continue;
            }
        }
        let tracked = match opcodes {
            Some(ops) if i < ops.len() => opcode_tracked_hint(&ops[i]) && ops[i] != "NOP",
            _ => true,
        };
        if tracked {
            cur |= 1u32 << (b_index % 32);
        }
        b_index += 1;
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
    buf.extend_from_slice(&tail_for_instr_count(end as u32).to_le_bytes());
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

        // mk28: kolejnosc sekcji zgodna z nvcc (sm_103a era):
        //   [7]  .nv.info
        //   [8]  .nv.compat            <- compat PRZED .nv.info.K (bylo po)
        //   [9..9+n) .nv.info.Ki
        //   [9+n]    .nv.callgraph
        //   []       .rela.text.Ki     <- pusta sekcja, TYLKO gdy kernel ma
        //                              CALL lub statyczny smem (nvcc regula,
        //                              fit 119 lab-kerneli: 0 pomyłek)
        //   []       .rela.debug_frame
        //   []       .text.Ki
        //   []       .nv.shared.Ki     <- per-kernel shared PRZED reserved
        //   []       .nv.shared.reserved.0
        //   []       .nv.constant0.Ki, .nv.capmerc.text.Ki, merc-rodzina.
        let kernel_needs_rela_text: Vec<bool> = kernels
            .iter()
            .map(|k| k.meta.has_call || k.meta.shared_size as u64 > 0)
            .collect();
        let n_rela_text = kernel_needs_rela_text.iter().filter(|b| **b).count();

        // .nv.compat pod fixed-numeracja
        let idx_compat = base;
        // Per-kernel: .nv.info.K
        let _nv_info_k = |ki: usize| base + 1 + ki;
        let idx_cg = base + 1 + n;
        // per-kernel .rela.text.Ki (subset transformowany na ciagly blok)
        // (indeksy wynikaja z rzedu push-ow; blok rela.text liczony jako
        // n_rela_text — patrz formuly ponizej)
        let _idx_rela_dbg = idx_cg + 1 + n_rela_text;
        // Per-kernel: .text.K
        let text_k = |ki: usize| idx_cg + 2 + n_rela_text + ki;
        // Per-kernel: .nv.shared.<kernel> (PRZED reserved.0)
        let shared_k = |ki: usize| idx_cg + 2 + n_rela_text + n + ki;
        // Shared reservation
        let idx_shared = idx_cg + 2 + n_rela_text + 2 * n;
        // Per-kernel: .nv.constant0.K
        let const0_k = |ki: usize| idx_cg + 3 + n_rela_text + 2 * n + ki;
        // Per-kernel: .nv.capmerc.text.K
        let capmerc_k = |ki: usize| idx_cg + 3 + n_rela_text + 3 * n + ki;
        // Fixed Mercury
        let idx_merc_dbg = idx_cg + 3 + n_rela_text + 4 * n;
        let _idx_merc_info = idx_merc_dbg + 1;
        // Per-kernel: .nv.merc.nv.info.K
        let _merc_info_k = |ki: usize| idx_merc_dbg + 2 + ki;
        // Fixed Mercury (rest)
        let _idx_merc_rela = idx_merc_dbg + 2 + n;
        let idx_merc_shared = idx_merc_dbg + 3 + n;
        let idx_merc_symtab = idx_merc_dbg + 4 + n;
        let total_sections = idx_merc_dbg + 5 + n;

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
        let mut shn_rela_text_k: Vec<u32> = Vec::new();
        for k in kernels {
            shn_nv_info_k.push(self.shstrtab.add(&format!(".nv.info.{}", k.name)));
            shn_text_k.push(self.shstrtab.add(&format!(".text.{}", k.name)));
            shn_const0_k.push(self.shstrtab.add(&format!(".nv.constant0.{}", k.name)));
            shn_shared_k.push(self.shstrtab.add(&format!(".nv.shared.{}", k.name)));
            shn_capmerc_k.push(self.shstrtab.add(&format!(".nv.capmerc.text.{}", k.name)));
            shn_merc_info_k.push(self.shstrtab.add(&format!(".nv.merc.nv.info.{}", k.name)));
            shn_rela_text_k.push(self.shstrtab.add(&format!(".rela.text.{}", k.name)));
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
            // mk28: nvcc sm_103a nie ma progu 0x3A0 (fit na 119 labach:
            // 0x380 dla bezparametrowych, 0x388..0x3a0 dla parametryzowanych).
            let cbank_size = 0x380usize + k.meta.cbank_param_size as usize;
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

        // mk28: .nv.compat PRZED .nv.info.K (kolejnosc nvcc sm_103a;
        // dawniej po — rozjazd listy sekcji z oryginalem).
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

        // Per-kernel .nv.info.K
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

        // .nv.callgraph
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

        // mk28: pusta .rela.text.K per kernel z CALL lub statycznym smem
        // (regula nvcc: sekcja RELA obecna z zerem wpisow; fit 119 labow).
        for ki in 0..n {
            if kernel_needs_rela_text[ki] {
                sec!(
                    shn_rela_text_k[ki],
                    SHT_RELA,
                    SHF_INFO_LINK,
                    vec![],
                    8,
                    IDX_SYMTAB as u32,
                    text_k(ki) as u32,
                    24
                );
            }
        }

        // .rela.debug_frame (tresc: mk30 — wpisy FDE wymagaja parystej
        // par frames/symboli wewnetrznych; sekcja bez tresci gdy pusto)
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

        // Per-kernel .nv.shared.<kernel> (NOBITS, actual shared memory size)
        // sh_info = text section index (via SHF_INFO_LINK), sh_link = 0 (matches nvcc)
        // mk28: kolejnosc nvcc — per-kernel .nv.shared.K PRZED reserved.0.
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

        // mk28: .nv.shared.reserved.0 PO per-kernel sekcjach; 0x60 gdy kernel
        // uzywa tmem (UTCA — mkvmem/b_tcgen05), inaczej 0x40 (fit korpusu).
        let reserved_sz: u64 = if kernels.iter().any(|k| !k.meta.merc_utca.is_empty()) {
            0x60
        } else {
            0x40
        };
        sec!(
            shn_shared,
            SHT_NOBITS,
            SHF_WRITE | SHF_ALLOC,
            vec![],
            1,
            0,
            0,
            0,
            nobits(reserved_sz)
        );

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
                    text_k(ki) as u32, // mk27: ordinal = shndx .text.K (nvcc: t103=12, mkvmem=13)
                    
                    kernels[ki].opcodes.as_deref(),
                    &kernels[ki].meta,
                    crate::elf::sm_from_ef_flags(self.ef_flags) == 100,
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
        // .nv.merc.nv.shared.reserved.0 (mk28: nvcc emituje 32 bajty zer;
        // dawniej 0)
        sec!(
            shn_merc_sh,
            SHT_MERC_RESERVED_SH,
            SHF_MERC | SHF_WRITE | SHF_ALLOC,
            vec![0u8; 32],
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

        // mk28: kanoniczna kolejnosc rekordow nvcc 13.x (era sm_103a) —
        // dopasowana na 119 kernelach labu (minieto bramki per atrybut):
        //   66 LANGUAGE=PTX(3), 37 API=0x85, 17 KPARAM*, [tmem: 4f,41],
        //   50 SPARSE_MMA, [tmem: 51], 1b MAXREG=ff, [4c NUM_BARRIERS jesli
        //   bary], 5f MERC-1.1, [31 INT_WARP_WIDE jesli VOTEU],
        //   [29+28 COOP_SITE jesli .merc_cgsites], 4a VRC_CTA_INIT,
        //   1c EXIT_OFFS, [1e CRS_STACK jesli call/bssy/bar+voteu/utca+bar],
        //   [19 CBANK_SIZE + 0a PARAM_CBANK jesli paramy], 36 SW_WAR=8,
        //   6b NVSAL_SW_WAR=1.
        let has_utca = !self.merc_utca.is_empty();
        let has_voteu_sites = !self.merc_wwide_sites.is_empty();

        // 1. EIATTR_LANGUAGE = PTX (0x66, SVAL u32=3)
        records.push(EiRecord {
            attr: 0x0066,
            fmt: EiFmt::Sized,
            data: 3u32.to_le_bytes().to_vec(),
        });

        // 2. CUDA_API_VERSION (attr=0x37); era sm_103a = nvcc 13.1 -> 0x85
        //    (lab: 213/214 kerneli ma 0x85; 0x82/0x83 = starsze nvcc).
        let api_ver = if self.cuda_api_version != 0 {
            self.cuda_api_version
        } else {
            0x85
        };
        let api_ver = if api_ver == 0x83 { 0x85 } else { api_ver };
        records.push(EiRecord {
            attr: 0x0037,
            fmt: EiFmt::Sized,
            data: api_ver.to_le_bytes().to_vec(),
        });

        // 3. KPARAM_INFO (attr=0x17): one 12-byte record per parameter,
        // in REVERSE ordinal order (matching working Tungsten cubins).
        // Format: [u32 index=0][u8 ordinal][u8 pad][u16 offset][u32 size_space_cbank]
        for param in self.params.iter().rev() {
            let mut d = vec![0u8; 12];
            d[4] = param.ordinal as u8;
            d[5] = 0x00;
            let off16 = param.offset as u16;
            d[6] = (off16 & 0xFF) as u8;
            d[7] = (off16 >> 8) as u8;
            d[8] = 0x00; // logAlignment (always 0)
            // mk28 (korpus lab): d[9] = 0xF0 | Space; Space 0x5 = GLOBAL dla
            // 8B (pointer-class), 0x0 dla skalarow (korpus: 190x F5/0x21 dla
            // 8B; 7x F0/0x11 dla u32-skalarow).
            d[9] = 0xf0 | if param.size == 8 { 0x05 } else { 0x00 };
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

        // 4. TMEM/UTCA (mkvmem, b_tcgen05): 4f AT_ENTRY_FRAGMENTS=TMEM_CTA1_V2,
        //    41 RESERVED_SMEM_USED (NVAL)
        if has_utca {
            records.push(EiRecord {
                attr: 0x004f,
                fmt: EiFmt::Sized,
                data: 6u32.to_le_bytes().to_vec(),
            });
            records.push(EiRecord {
                attr: 0x0041,
                fmt: EiFmt::BValAlt,
                data: vec![],
            });
        }

        // 5. SPARSE_MMA_MASK (attr 0x50, BVAL 0) — zawsze
        records.push(EiRecord {
            attr: 0x0050,
            fmt: EiFmt::Byte,
            data: vec![0],
        });

        // 6. TCGEN05_1CTA_USED (attr 0x51, NVAL) — tylko tmem
        if has_utca {
            records.push(EiRecord {
                attr: 0x0051,
                fmt: EiFmt::BValAlt,
                data: vec![],
            });
        }

        // 7. MAXREG_COUNT (attr 0x1b = 0xff) — zawsze
        records.push(EiRecord {
            attr: 0x001b,
            fmt: EiFmt::Byte,
            data: vec![0xff],
        });

        // 8. NUM_BARRIERS (attr 0x4c, HVAL=num_barriers) — gdy kernel ma bary
        //    (mk28: dawniej bezwarunkowo val=1; nvcc emituje tylko dla
        //    kerneli z BAR/SYNCS, val = liczba barrierow, p_namedbar=2)
        if self.num_barriers > 0 {
            records.push(EiRecord {
                attr: 0x004c,
                fmt: EiFmt::Half,
                data: vec![self.num_barriers, 0],
            });
        }

        // 9. MERCURY_ISA_VERSION 1.1 (attr 0x5f) — zawsze
        records.push(EiRecord {
            attr: 0x005f,
            fmt: EiFmt::Byte,
            data: vec![1, 1],
        });

        // 10. INT_WARP_WIDE_INSTR_OFFSETS (attr 0x31) — site'y operacji
        //     warp-wide (VOTEU/SHFL/REDUX/MATCHANY), nvcc: tylko gdy VOTEU
        //     w kernelu (sass_file::kernel_def_to_meta filtruje)
        if has_voteu_sites {
            let mut d = Vec::with_capacity(self.merc_wwide_sites.len() * 4);
            for off in &self.merc_wwide_sites {
                d.extend_from_slice(&off.to_le_bytes());
            }
            records.push(EiRecord {
                attr: 0x0031,
                fmt: EiFmt::Sized,
                data: d,
            });
        }

        // 11+12. COOP_GROUP masks(0x29) + sites(0x28) — surowa lista z
        //        `.merc_cgsites` (disasm --frozen); maski z oryginalu,
        //        brakujace = ff.
        if !self.merc_cgsites.is_empty() {
            let n = self.merc_cgsites.len();
            let mut m29 = Vec::with_capacity(4 * n);
            for i in 0..n {
                let m = self.merc_cgmasks.get(i).copied().unwrap_or(0xffff_ffff);
                m29.extend_from_slice(&m.to_le_bytes());
            }
            records.push(EiRecord {
                attr: 0x0029,
                fmt: EiFmt::Sized,
                data: m29,
            });
            let mut s28 = Vec::with_capacity(4 * n);
            for s in &self.merc_cgsites {
                s28.extend_from_slice(&s.to_le_bytes());
            }
            records.push(EiRecord {
                attr: 0x0028,
                fmt: EiFmt::Sized,
                data: s28,
            });
        }

        // 13. VRC_CTA_INIT_COUNT (attr 0x4a, HVAL = 0x80 dla tmem, inaczej 0)
        records.push(EiRecord {
            attr: 0x004a,
            fmt: EiFmt::Half,
            data: if has_utca { vec![0x80, 0] } else { vec![0, 0] },
        });

        // 14. EXIT_INSTR_OFFSETS
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

        // 15. CRS_STACK_SIZE (attr 0x1e, SVAL 0) — bramka (mk28, fit na
        //     korpusie): CALL | BSSY | (bary & VOTEU) | (UTCA & bary).
        //     WYJATEK znany: q_switch (switch-select z multi-EXIT) ma 1e
        //     bez powyzszych cech -> residual mk30.
        let has_1e = self.has_call
            || self.has_bssy
            || (self.num_barriers > 0 && has_voteu_sites)
            || (has_utca && self.num_barriers > 0);
        if has_1e {
            records.push(EiRecord {
                attr: 0x001e,
                fmt: EiFmt::Sized,
                data: 0u32.to_le_bytes().to_vec(),
            });
        }

        // 16+17. CBANK_PARAM_SIZE + PARAM_CBANK — tylko dla kerneli z
        //        parametrami (mk28: dawniej 19 bezwarunkowo -> mkvmem mial
        //        nadmiarowy rekord)
        if !self.params.is_empty() {
            records.push(EiRecord {
                attr: 0x0019,
                fmt: EiFmt::Byte,
                data: vec![self.cbank_param_size as u8],
            });
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

        // 18. SW_WAR (attr 0x36 = 8) — software war na era sm_103a (korpus:
        //     214/214 val=8; cubit dawniej emitowal 0)
        records.push(EiRecord {
            attr: 0x0036,
            fmt: EiFmt::Sized,
            data: 8u32.to_le_bytes().to_vec(),
        });

        // 19. NVSAL_SW_WAR (attr 0x6b = 1) — era sm_103a
        records.push(EiRecord {
            attr: 0x006b,
            fmt: EiFmt::Byte,
            data: vec![1],
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
