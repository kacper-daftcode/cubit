//! mk66 (2026-08-13): regula rekordow CCTL.IVALL (dekod merclab/mk66 c3..c22,
//! EXACT 1931/1931 kerneli z kontekstem na l2):
//!  * rekord TYLKO gdy [i-2]==ERRBAR && [i-1]==CGAERRBAR (ctx);
//!    nie-ctx (petle LDG;CCTL;YIELD) nigdy — find_colors/xmma.
//!  * b1 = 0x04 gdy kernel ma LDGSTS*, inaczej 0x02 (separator 279/1652).
//!  * b8 = 0x0d gdy b1==0x04 i [i-3]==MEMBAR.ALL.GPU, inaczej 0x0c
//!    (imma_emu49/51 cublasLt.548; MEMBAR.SC.GPU daje 0x0c).
//!  * CCTL.E.RML2 ma wlasne mini 410e020c (mk13) — poza ta rodzina.

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::mercury::CapMerc;

fn dummy_code(n: usize) -> Vec<u8> {
    vec![0u8; n * 16]
}

fn meta_base() -> KernelMeta {
    KernelMeta {
        name: "t".into(),
        regcount: 16,
        exit_offsets: vec![0u32],
        cbank_param_size: 8,
        params: vec![KernelParam { index: 0, ordinal: 0, offset: 0, size: 8 }],
        merc_param_loads: vec![(1, 0, 0, 8, 0xf8)],
        merc_param_load_dreg: vec![4],
        ..Default::default()
    }
}

fn cctl_recs(cm: &CapMerc) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for r in &cm.records {
        if r.tag[0] == 0x51 && (r.tag[1] == 0x02 || r.tag[1] == 0x04) && r.tag[2] == 0x01 {
            let mut v = r.tag.to_vec();
            v.extend_from_slice(&r.payload);
            out.push(v);
        }
    }
    out
}

fn run(ops: &[&str]) -> Vec<Vec<u8>> {
    let m = meta_base();
    let o: Vec<String> = ops.iter().map(|s| s.to_string()).collect();
    let code = dummy_code(ops.len());
    let mut mm = m;
    mm.exit_offsets = vec![(ops.len() as u32 - 1) * 16];
    let out = generate_mercury_full(&code, 0x0c, Some(&o), &mm, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    cctl_recs(&cm)
}

#[test]
fn mk66_ctx_02_bez_ldgsts() {
    let r = run(&[
        "LDC", "LDC", "ERRBAR", "CGAERRBAR", "CCTL.IVALL", "BAR.SYNC", "EXIT",
    ]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][1], 0x02);
    assert_eq!(r[0][8], 0x0c);
}

#[test]
fn mk66_ctx_04_z_ldgsts() {
    let r = run(&[
        "LDGSTS.E.BYPASS", "LDC", "ERRBAR", "CGAERRBAR", "CCTL.IVALL", "EXIT",
    ]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][1], 0x04);
    // i-3 = LDC (nie MEMBAR.ALL.GPU) -> 0x0c
    assert_eq!(r[0][8], 0x0c);
}

#[test]
fn mk66_ctx_04_membar_all_gpu_0d() {
    let r = run(&[
        "LDGSTS.E.BYPASS",
        "LDC",
        "MEMBAR.GPU.ALL",
        "ERRBAR",
        "CGAERRBAR",
        "CCTL.IVALL",
        "EXIT",
    ]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][1], 0x04);
    assert_eq!(r[0][8], 0x0d);
}

#[test]
fn mk66_ctx_04_membar_sc_0c() {
    let r = run(&[
        "LDGSTS.E.BYPASS",
        "LDC",
        "MEMBAR.GPU.SC",
        "ERRBAR",
        "CGAERRBAR",
        "CCTL.IVALL",
        "EXIT",
    ]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][1], 0x04);
    assert_eq!(r[0][8], 0x0c);
}

#[test]
fn mk66_bez_ctx_brak_rekordu() {
    // find_colors/xmma: LDG.STRONG;CCTL;YIELD — zero rekordow.
    let r = run(&[
        "LDG.E.STRONG.GPU", "CCTL.IVALL", "YIELD", "NOP", "EXIT",
    ]);
    assert!(r.is_empty());
    // pomieszane: 1 ctx + 1 nie-ctx -> dokladnie 1 rekord.
    let r2 = run(&[
        "LDG.E.STRONG.GPU", "CCTL.IVALL", "YIELD", "ERRBAR", "CGAERRBAR",
        "CCTL.IVALL", "EXIT",
    ]);
    assert_eq!(r2.len(), 1);
    assert_eq!(r2[0][1], 0x02);
}
