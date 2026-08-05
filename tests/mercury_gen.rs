//! Gold tests: cubit-emitovana sekcja capmerc == nvcc-emitted bytes,
//! dla wariantow mikrolabu (v_base / v_p1 / v_bar2).
use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn dummy_code(n_instr: usize) -> Vec<u8> {
    // Wystarcza niepuste; decyzje o bitmapie bierzemy z opcodes.
    vec![0u8; n_instr * 16]
}

fn meta(name: &str, n_params: u32, exits: u32, smem: u32, bars: u8, cbank: u16) -> KernelMeta {
    let params = (0..n_params)
        .map(|i| KernelParam {
            index: i,
            ordinal: i,
            offset: i * 8,
            size: 8,
        })
        .collect();
    KernelMeta {
        name: name.into(),
        regcount: 16,
        frame_size: 0,
        min_stack_size: 0,
        maxreg_count: 0xFF,
        num_barriers: bars,
        exit_offsets: (0..exits).map(|i| i * 16).collect(),
        cbank_param_size: cbank,
        params,
        cuda_api_version: 0x83,
        shared_size: smem,
        merc_param_order: None,
        merc_param_write: 0,
        merc_stg_desc_pos: Vec::new(),
        merc_bar_pred: false,
        merc_param_uniform: 0,
        merc_param_regpath: 0,
        merc_param_width: Vec::new(),
        merc_dynldg: false,
        merc_bar_pos: Vec::new(),
        merc_stg_pos: Vec::new(),
    }
}

/// Baseline: kernel bez parametrow i tylko LDC/EXIT/BRA — nvcc: prolog+tail.
#[test]
fn gen_v_base_matches_nvcc() {
    let ops = vec!["LDC".to_string(), "EXIT".to_string(), "BRA".to_string()];
    let out = generate_mercury_full(&dummy_code(3), 0x0c, Some(&ops), &meta("v_base", 0, 1, 0, 0, 0), true);
    let gold = hx("0c000000010000c00300000002000000010b040af800040000004100000400005007");
    assert_eq!(out, gold);
}

/// v_p1: 1 pointer param + 1 STG.
#[test]
fn gen_v_p1_matches_nvcc() {
    let ops: Vec<String> = ["LDC", "LDC", "LDCU", "MOV", "STG", "EXIT", "BRA"]
        .iter().map(|s| s.to_string()).collect();
    let out = generate_mercury_full(&dummy_code(7), 0x0c, Some(&ops), &meta("v_p1", 1, 1, 0, 0, 8), true);
    let gold = hx(concat!(
        "0c000000010000c00700000028000000",
        "010b040af80004000000410000040000",
        "02220e06f8005200000083004000020000000000000000000000000000000000",
        "010b0e0afa0005000000030139040000",
        "02380e32f80040110000000082000a0000020140010000000000000000000000",
        "5005"
    ));
    assert_eq!(out, gold);
}

/// v_bar2: 1 pointer param + 2 bariery + 1 STG (nvcc order verified).
#[test]
fn gen_v_bar2_matches_nvcc() {
    let ops: Vec<String> =
        ["LDC", "LDC", "LDC", "MOV", "STG", "BAR", "LDC", "EXIT", "BRA"]
            .iter().map(|s| s.to_string()).collect();
    let out = generate_mercury_full(&dummy_code(9), 0x0c, Some(&ops), &meta("v_bar2", 1, 1, 0, 2, 8), true);
    let gold = hx(concat!(
        "0c000000010000c00900000088000000",
        "010b040af80004000000410000040000",
        "02220e06f8005200000083004000020000000000000000000000000000000000",
        "01475a16f80004000000000001000000",
        "010b0e0afa0005000000030139040000",
        "02380e32f80040110000000082000a0000020140010000000000000000000000",
        "01475a16f80004000000000001000000",
        "5008"
    ));
    assert_eq!(out, gold);
}
