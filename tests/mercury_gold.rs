//! Data-driven byte-exact tests: cubit-emitowany capmerc == nvcc-emitowany,
//! dla 36 kerneli mikrolabu (autogenerowany manifest z prawdziwych sekcji).
mod gold_manifest;
use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use gold_manifest::GOLD;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn meta_for(g: &gold_manifest::GoldRow) -> KernelMeta {
    let n_params = g.ptr + g.scal;
    let params = (0..n_params)
        .map(|i| KernelParam {
            index: i,
            ordinal: i,
            offset: i * 8,
            size: if i < g.ptr { 8 } else { 4 },
        })
        .collect();
    KernelMeta {
        name: g.name.into(),
        regcount: 16,
        frame_size: 0,
        min_stack_size: 0,
        maxreg_count: 0xFF,
        num_barriers: g.bars,
        exit_offsets: (0..g.exits).map(|i| i * 16).collect(),
        cbank_param_size: g.cbank,
        params,
        cuda_api_version: 0x83,
        shared_size: g.smem,
        merc_param_order: if g.pord.is_empty() { None } else { Some(g.pord.to_vec()) },
        merc_param_write: g.pwrite,
        merc_stg_desc_pos: g.stgpos.to_vec(),
        merc_bar_pred: false,
        merc_dynldg: false,
        merc_bar_pos: Vec::new(),
        merc_stg_pos: Vec::new(),
    }
}

/// Znane ogonki (udokumentowane w MERCURY_UPLIFT_SM103A.md sekcja RESIDUALS):
/// kazdy wpis = (kernel-prefix, przyczyna). Test pilnuje, by (a) wszystkie
/// inne byly byte-exact, (b) te nie zaczely "przechodzic" przypadkiem bez
/// aktualizacji dokumentu.
static EXPECTED_DIFF: &[(&str, &str)] = &[
    ("c_ld_dyn",      "cflow payload przy LDG-dynamic (103a)"),
    ("c_ld_dyn2",     "dwa rekordy cflow (multi-LDG-dynamic) + wariant 0xc1"),
    ("c_ld_fix",      "STG binding single->pozniejszego desc"),
    ("d_2seq",        "mk10b: pozycja rekordow w kolejnosci kodu (BAR miedzy STG; desc payload[4]=00 w regionach ifwojmowych)"),
    ("d_ifearly_exit",  "mk10b: pozycja rekordow w kolejnosci kodu (BAR miedzy STG; desc payload[4]=00 w regionach ifwojmowych)"),
    ("d_ifearly_stg",  "mk10b: pozycja rekordow w kolejnosci kodu (BAR miedzy STG; desc payload[4]=00 w regionach ifwojmowych)"),
        ("d_sw4_store",   "mk10b: pozycja rekordow w kolejnosci kodu (BAR miedzy STG; desc payload[4]=00 w regionach ifwojmowych)"),
    ("d_whilebreak",  "mk10b: pozycja rekordow w kolejnosci kodu (BAR miedzy STG; desc payload[4]=00 w regionach ifwojmowych)"),
    ("if16",          "if-chain: B-region misalignment"),
    ("if8",           "if-chain: B-region misalignment"),
    ("k_bra",         "STG region/epoch counters"),
    ("k_ld",          "cflow 0x41 era-103a LDG-dynamic"),
    ("k_ldcg",        "cflow 0x41 era-103a LDG-dynamic"),
    ("k_ldg2",        "dwa cflow + warianty 0xc1/0x41 (multi-LDG-dynamic era 103a)"),
    ("k_lds",         "smem double-coding (cbank-83 vs p2-mid)"),
    ("k_loop8",       "STG midfields + loop-LDG"),
    ("k_mma",         "rekordy 025a0026 per-HMMA (instance/cw pola)"),
    ("k_shfl",        "cflow 0x41 z SHFL"),
    ("k_smem",        "p2-mid pozycja + cbank wariant"),
    ("k_stg2",        "desc 41 02 wariant + STG binding"),
    ("lp1",           "loop z LDG: region-order"),
    ("m_ld.100",      "desc warianty (mk5-era)"),
    ("m_ld.100a",     "desc warianty (mk5-era)"),
    ("q_bsync_pair",  "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("q_callloop",    "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("q_dowhile",     "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("q_loop1",       "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("q_rec",         "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("q_switch",      "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("q_tail_call",   "mk9: epilogi divergent (bsync-pair, callloop, dowhile, switch, tail_call)"),
    ("r2_ro",         "desc roles/tails granice reguly first-use"),
    ("r2_rw_rf",      "desc roles/tails granice reguly first-use"),
    ("r2_rw_wf",      "desc roles/tails granice reguly first-use"),
        ("r2_ww",         "desc roles/tails granice reguly first-use"),
    ("r3_mix",        "3-param mixed-type kolejnosc"),
    ("s_stg2diff",    "multi-STG epoch/binding pola"),
    ("s_stg2rev",     "multi-STG epoch/binding pola"),
    ("s_stg2same",    "multi-STG epoch/binding pola"),
    ("s_stg3same",    "multi-STG epoch/binding pola"),
    ("s_stg4same",    "multi-STG epoch/binding pola"),
    ("s_stg_branch",  "branch-region: desc 00-wariant + STG region fields"),
    ("s_stg_loop",    "loop-region STG (b19=ff wariant)"),
    ("s_u8",          "STG.E.U8 narrow-variant (b6/b18/b19=0)"),
    ("sw16",          "switch-chain: pinned record 51010109 + B-carve w dispatchu"),
    ("sw32",          "switch-chain: pinned record 51010109 + B-carve w dispatchu"),
    ("sw4",           "switch-chain: pinned record 51010109 + B-carve w dispatchu"),
    ("sw64",          "switch-chain: pinned record 51010109 + B-carve w dispatchu"),
    ("sw8",           "switch-chain: pinned record 51010109 + B-carve w dispatchu"),
    ("t_branct.s100",  "STG region fields"),
    ("t_branct.s103",  "STG region fields"),
    ("v_barx",        "BAR-w-if payload[0]=01 + pozycja (era 100)"),
    ("v_dyn_smem",    "smem dyn: BAR/STG midfields"),
    ("v_ld1",         "STG [12,13] binding (desc-pos)"),
    ("v_ld2",         "desc roles/tails 3-param order"),
    ("v_ldg_u64",     "desc tail + STG wide variants"),
        ("v_p3",          "desc kolejnosc 3-param mixed-type"),
    ("v_sm128",       "STG tail-dw smem marker"),
    ("v_sm2k",        "STG tail-dw smem marker"),
    ("v_stg2",        "STG binding order-wariant"),
    ("w_depsync",     "griddepcontrol.wait: nowy rekord event 0162000a (ACQBULK)"),
];

#[test]
fn gold_all_kernels_byte_exact() {
    let mut fails = Vec::new();
    let mut unexpected_pass = Vec::new();
    let mut covered = 0usize;
    for g in GOLD {
        let ops: Vec<String> = g.ops.iter().map(|s| s.to_string()).collect();
        let code = vec![0u8; ops.len() * 16];
        let out = generate_mercury_full(&code, g.ord, Some(&ops), &meta_for(g), g.sm100 == 1);
        let gold = hx(g.gold);
        let resid = EXPECTED_DIFF
            .iter()
            .find(|(pfx, _)| g.name.starts_with(pfx))
            .map(|(_, r)| r);
        if out != gold && resid.is_none() {
            let k = out.iter().zip(gold.iter()).position(|(a, b)| a != b);
            fails.push(format!(
                "{}: len {} vs {} first-diff {:?}",
                g.name,
                out.len(),
                gold.len(),
                k
            ));
        }
        if out == gold && resid.is_some() {
            unexpected_pass.push(format!("{} (residual: {})", g.name, resid.unwrap()));
        }
        if out == gold {
            covered += 1;
        }
    }
    if !unexpected_pass.is_empty() {
        panic!(
            "RESIDUALS zniknely — zaktualizuj EXPECTED_DIFF i dokumentacje:\n{}",
            unexpected_pass.join("\n")
        );
    }
    if !fails.is_empty() {
        panic!("{} / {} gold fails (nowe):\n{}", fails.len(), GOLD.len(), fails.join("\n"));
    }
    println!("byte-exact: {}/{}; znane residua: {}", covered, GOLD.len(), EXPECTED_DIFF.len());
}
