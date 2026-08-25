//! mk28: ELF/EIATTR fidelity sm_103a (nvcc 13.x):
//! - the canonical .nv.info.K record set and order (byte-wise like nvcc),
//! - bitmapowe reguly dialektu UTCA (BRA epilog vs samo-petla),
//! - bramki: tmem (4f/41/51, 4a=0x80), NUM_BARRIERS (4c), SW_WAR (36=8),
//!   NVSAL_SW_WAR (6b=1), LANGUAGE (66=3), API (37=0x85).
//!
//! Zrodla bajtow zlotych: oryginalne sekcje .nv.info.* z
//! merclab/mkvmem.sm_103a.cubin and merclab/k_sync.cubin.

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn base_meta(name: &str) -> KernelMeta {
    // Minimal shape as in sass_file::kernel_def_to_meta for a kernel
    // without parameters; filled in further per test.
    KernelMeta {
        name: name.into(),
        regcount: 8,
        frame_size: 0,
        min_stack_size: 0,
        maxreg_count: 0xFF,
        num_barriers: 0,
        exit_offsets: vec![],
        cbank_param_size: 0,
        params: vec![],
        cuda_api_version: 0, // fallback -> 0x85 (era nvcc 13.1)
        shared_size: 0,
        merc_param_order: None,
        merc_param_write: 0,
        merc_stg_desc_pos: Vec::new(),
        merc_bar_pred: false,
        merc_param_uniform: 0,
        merc_param_regpath: 0,
        merc_param_width: Vec::new(),
        merc_xor: Vec::new(),
        merc_xor_reg: Vec::new(),
        merc_stg_off: Vec::new(),
        merc_stg_ser: Vec::new(),
        merc_stg_dreg: Vec::new(),
        merc_stg_dur: Vec::new(),
        merc_stg_guard: Vec::new(),
        merc_mma: Vec::new(),
        merc_f64imm: Vec::new(),
        merc_dfmaimm: Vec::new(),
        merc_pad_pos: Vec::new(),
        merc_param_loads: Vec::new(),
        merc_cbank_lane: None,
        merc_s2r_lanes: Vec::new(),
        merc_s2r_sr: Vec::new(),
        merc_s2r_dest: Vec::new(),
        merc_load_flags: Vec::new(),
        merc_atom_pool_hits: Vec::new(),
        merc_lop3_pdest: Vec::new(),
        merc_predmem: false,
        merc_guarded_bra: Vec::new(),
        merc_ldgconst: Vec::new(),
        merc_bar_args: Vec::new(),
        merc_bar_pos: Vec::new(),
        merc_stg_pos: Vec::new(),
        merc_dynldg: false,
        merc_syncwarp: Vec::new(),
        merc_utca: Vec::new(),
        merc_atom_smem: Vec::new(),
        merc_atoms: Vec::new(),
        merc_ldgsts_pin: Vec::new(),
        merc_ldgsts_wait: Vec::new(),
        merc_bra_selfloop: Vec::new(),
        merc_wwide_sites: Vec::new(),
        merc_cgsites: Vec::new(),
        merc_cgmasks: Vec::new(),
        has_call: false,
        has_bssy: false,
        ..Default::default()
    }
}

/// mkvmem (t_tmem / tmem-via-UTCA): orig .nv.info._Z6t_tmemv = 128B.
/// Carries the tmem gates en route (4f/41/51, 4a=0x80), 31 (VOTEU+REDUX),
/// 29/28 (4 CG sites, incl. the non-ghost 0x380), 1e (CALL).
#[test]
fn mkvmem_info_k_byte_exact() {
    let mut m = base_meta("_Z6t_tmemv");
    m.exit_offsets = vec![0x390];
    m.merc_utca = vec![(11, 0), (18, 0), (47, 1)];
    m.merc_wwide_sites = vec![0x290, 0x2b0]; // VOTEU.ANY, REDUX
    m.merc_cgsites = vec![0x20, 0x1a0, 0x1d0, 0x380];
    m.merc_cgmasks = vec![0xffff_ffff; 4];
    m.has_call = true;

    let sec = m.to_kernel_records_with_sym_and_const(0, 0);
    let gold = hx("04660400030000000437040085000000044f040006000000014100000350000001510000031bff00035f01010431080090020000b002000004291000ffffffffffffffffffffffffffffffff0428100020000000a0010000d001000080030000024a8000041c040090030000041e0400000000000436040008000000036b0100");
    let got = sec.to_bytes();
    assert_eq!(got.len(), 128, "mkvmem .nv.info.K musi miec 128B");
    assert_eq!(got, gold, "mkvmem .nv.info.K byte-exact");
}

/// k_sync (czysty __syncthreads, 0 parametrow): 56B — zawiera 4c (NUM_BARRIERS
/// = 1), no 4f/41/51/31/29/28/1e/19/0a.
#[test]
fn k_sync_info_k_byte_exact() {
    let mut m = base_meta("_Z6k_syncv");
    m.num_barriers = 1;
    m.exit_offsets = vec![0x20];

    let sec = m.to_kernel_records_with_sym_and_const(0, 0);
    let gold = hx("0466040003000000043704008500000003500000031bff00024c0100035f0101024a0000041c0400200000000436040008000000036b0100");
    let got = sec.to_bytes();
    assert_eq!(got.len(), 56);
    assert_eq!(got, gold, "k_sync .nv.info.K byte-exact");
}

/// Dialekt UTCA (tmem): zwykly BRA w glownym torze DOSTAJE bit bitmapy,
/// a spin self-loop (BRA L_x -> its own address) does NOT. Evidence: mkvmem dword1
/// bitmapy 0x3fbf1fdf (bity slotow 48/51 ustawione, slot 62 pusty).
#[test]
fn utca_bra_bitmap_rule() {
    let code = vec![0u8; 3 * 16];
    let ops = vec!["BRA".to_string(), "BRA".to_string(), "EXIT".to_string()];
    let mut m = base_meta("t_dialect");
    m.merc_utca = vec![(0, 2)];
    m.merc_bra_selfloop = vec![1]; // lane1 = samo-petla

    let out = generate_mercury_full(&code, 0, Some(&ops), &m, false);
    // hdr: [ordinal4][magic c0000001][B][bitmap dword]
    assert_eq!(&out[4..8], &0xC0000001u32.to_le_bytes());
    // mk30b: n = ostatni ustawiony bit + 2 (17612/17612 korpus); tu bitmax=2.
    assert_eq!(&out[8..12], &4u32.to_le_bytes(), "B = bitmax+2");
    // bit0 = BRA (zwykly, dialekt UTCA), bit1 = pusty (samo-petla), bit2 = EXIT
    assert_eq!(
        out[12], 0b101,
        "bitmapa: BRA z bitem, samo-petla bez, EXIT z bitem"
    );
}

/// Without the UTCA dialect a plain BRA still gets NO bit (p_call & co
/// sa byte-exact od dawna; regresja zakazana).
#[test]
fn non_utca_bra_bitmap_unchanged() {
    let code = vec![0u8; 3 * 16];
    let ops = vec!["BRA".to_string(), "BRA".to_string(), "EXIT".to_string()];
    let m = base_meta("t_plain");
    let out = generate_mercury_full(&code, 0, Some(&ops), &m, false);
    assert_eq!(out[12], 0b100, "bez UTCA: tylko EXIT ma bit");
}
