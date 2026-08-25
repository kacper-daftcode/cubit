//! mk41 (2026-08-12): XSETP-pair mini records + full predicate codes.
//! Piny bajtowe: xlab probes (nvcc sm_100a & sm_103a era-inwariantne):
//! - para ISETP(non-EX)+ISETP.*.EX -> JEDEN mini 4B na lane HEAD-a,
//! - the head loses its bitmap bit (a mini instead of the t4 node),
//! - tag: 42102e14 (para czysto-rejestrowa) / 42103006 (imm w head)
//!   / 42103214 (operand UR w parze).

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::mercury::CapMerc;

fn dummy_code(n: usize) -> Vec<u8> {
    vec![0u8; n * 16]
}

fn meta() -> KernelMeta {
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

fn has_mini(cm: &CapMerc, tag: [u8; 4]) -> bool {
    cm.records.iter().any(|r| r.tag == tag)
}

#[test]
fn mk41_xsetp_pair_plain() {
    // ISETP head L3 + ISETP.EX L4 -> mini 42102e14 na L3, bit3 kasowany.
    let mut m = meta();
    m.merc_xsetp_pairs = vec![(3, 0)];
    let ops: Vec<String> = (0..8)
        .map(|i| match i {
            0 => "LDC".into(),
            7 => "EXIT".into(),
            _ => "NOP".into(),
        })
        .collect();
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&ops), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(has_mini(&cm, [0x42, 0x10, 0x2e, 0x14]), "mini 42102e14 obecne");
    assert!(!cm.set_bits().contains(&3), "head-lane bez bitu");
}

#[test]
fn mk41_xsetp_pair_variants() {
    let mut m = meta();
    m.merc_xsetp_pairs = vec![(2, 1), (4, 2)]; // imm-head i UR-head
    let ops: Vec<String> = (0..8)
        .map(|i| match i {
            0 => "LDC".into(),
            7 => "EXIT".into(),
            _ => "NOP".into(),
        })
        .collect();
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&ops), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(has_mini(&cm, [0x42, 0x10, 0x30, 0x06]), "mini 42103006 (imm-head)");
    assert!(has_mini(&cm, [0x42, 0x10, 0x32, 0x14]), "mini 42103214 (UR)");
    assert!(!cm.set_bits().contains(&2));
    assert!(!cm.set_bits().contains(&4));
}
