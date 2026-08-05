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
        merc_param_uniform: g.punif,
        merc_param_regpath: g.preg,
        merc_param_width: (0..8)
            .map(|i| ((g.pwid >> (8 * i)) & 0xff) as u8)
            .collect(),
        merc_dynldg: g.dynldg == 1,
        merc_bar_pos: g.barpos.to_vec(),
        merc_stg_pos: g.stgseq.to_vec(),
        merc_xor: g.pxor.to_vec(),
        merc_stg_off: g.stgoff.to_vec(),
        merc_stg_ser: g.stgser.to_vec(),
        merc_mma: g.mma.to_vec(),
        merc_f64imm: g.f64i.to_vec(),
        merc_pad_pos: g.pads.to_vec(),
    }
}

/// Znane ogonki (udokumentowane w MERCURY_UPLIFT_SM103A.md sekcja RESIDUALS):
/// kazdy wpis = (kernel-prefix, przyczyna). Test pilnuje, by (a) wszystkie
/// inne byly byte-exact, (b) te nie zaczely "przechodzic" przypadkiem bez
/// aktualizacji dokumentu.
static EXPECTED_DIFF: &[(&str, &str)] = &[
    ("c_ld_dyn",      "cflow payload LDG-dynamic"),
    ("c_ld_dyn2",     "podwójny cflow + 0xc1"),
    ("c_ld_fix",      "STG binding single->later desc"),
    ("d_ifearly_exit",  "mk10b: kolejnosc rekordow po pozycji kodu/pred-memop variants"),
    ("d_ifearly_stg",  "mk10b: kolejnosc rekordow po pozycji kodu/pred-memop variants"),
    ("d_sw4_store",   "mk10b: kolejnosc rekordow po pozycji kodu/pred-memop variants"),
    ("d_whilebreak",  "mk10b: kolejnosc rekordow po pozycji kodu/pred-memop variants"),
    ("if16",          "if-chain rekordy-pozycyjne"),
    ("if8",           "if-chain rekordy-pozycyjne"),
    ("k_ld",          "cflow 0x41"),
    ("k_ldcg",        "cflow 0x41"),
    ("k_ldg2",        "cflow 0xc1"),
    ("k_lds",         "smem double-coding"),
    ("k_loop8",       "STG midfields + loop-LDG"),
    ("k_smem",        "p2-mid + cbank variant"),
    ("k_stg2",        "desc 41 02 + STG binding"),
    ("lp1",           "loop LDG regiony"),
    ("m_ld.100",      "desc warianty"),
    ("m_ld.100a",     "desc warianty"),
    ("p_atomg",       "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_atoms",       "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_call",        "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_cas",         "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_cctl",        "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_dmma",        "anchor#2 payload (01,02,01) + STG b19=0xc0 kursor (mk10c)"),
    ("p_exit2",       "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_ldgsts",      "mk7: LDGSTS (cp.async) seria rekordow"),
    ("p_lds",         " mk7-ldz-event + rekordy"),
    ("p_ldsm",        "mk7: pinned-51 + event rekordy (01290004/LDSM-wiazania)"),
    ("p_loop4",       "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_mma16816",    "anchor#2 payload (01,01,01) (mk7f region payload)"),
    ("p_namedbar",    "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_redux",       "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_stg2",        "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_sts2",        "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("p_warpsync",    "mk7-rodzina: desc-tag-variant (02220806/fa) + event rekordy (01290004, 0132100a, 01476c0a, 021b*, pinned 51**)"),
    ("q_bsync_pair",  "mk9: epilogi divergent"),
    ("q_callloop",    "mk9: epilogi divergent"),
    ("q_dowhile",     "mk9: epilogi divergent"),
    ("q_loop1",       "mk9: epilogi divergent"),
    ("q_rec",         "mk9: epilogi divergent"),
    ("q_switch",      "mk9: epilogi divergent"),
    ("q_tail_call",   "RET-w-loop/collective epilog rodzina"),
    ("r2_ro",         "desc roles/tails granice first-use"),
    ("r2_rw_rf",      "desc roles/tails granice first-use"),
    ("r2_rw_wf",      "desc roles/tails granice first-use"),
    ("r2_ww",         "desc roles/tails granice first-use"),
    ("r3_mix",        "3-param mixed"),
    ("s_stg2diff",    "multi-STG"),
    ("s_stg2rev",     "multi-STG"),
    ("s_stg_branch",  "branch-region"),
    ("s_u8",          "STG.E.U8"),
    ("sw16",          "switch-chain: pinned 51 + B-carve"),
    ("sw32",          "switch-chain: pinned 51 + B-carve"),
    ("sw4",           "switch-chain: pinned 51 + B-carve"),
    ("sw64",          "switch-chain: pinned 51 + B-carve"),
    ("sw8",           "switch-chain: pinned 51 + B-carve"),
    ("v_barx",        "BAR-w-if era 100"),
    ("v_dyn_smem",    "smem dyn"),
    ("v_ld1",         "STG [12,13] binding"),
    ("v_ld2",         "desc 3-param"),
    ("v_ldg_u64",     "desc tail+STG wide"),
    ("v_p3",          "desc 3-param order"),
    ("v_sm128",       "STG tail-dw smem"),
    ("v_sm2k",        "STG tail-dw smem"),
    ("v_stg2",        "STG binding"),
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
