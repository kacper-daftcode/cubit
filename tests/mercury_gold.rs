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
        merc_bar_pred: g.barpred != 0,
        merc_param_uniform: g.punif,
        merc_param_regpath: g.preg,
        merc_param_width: (0..8)
            .map(|i| ((g.pwid >> (8 * i)) & 0xff) as u8)
            .collect(),
        merc_dynldg: g.dynldg == 1,
        merc_bar_pos: g.barpos.to_vec(),
        merc_bar_args: g.barg.to_vec(),
        merc_stg_pos: g.stgseq.to_vec(),
        merc_xor: g.pxor.to_vec(),
        merc_stg_off: g.stgoff.to_vec(),
        merc_stg_ser: g.stgser.to_vec(),
        merc_stg_dreg: g.dreg.to_vec(),
        merc_stg_dur: g.dur.to_vec(),
        merc_stg_guard: g.guard.to_vec(),
        merc_mma: g.mma.to_vec(),
        merc_f64imm: g.f64i.to_vec(),
        merc_pad_pos: g.pads.to_vec(),
        merc_param_loads: g.loads.to_vec(),
        merc_cbank_lane: if g.cblane >= 0 { Some(g.cblane as u32) } else { None },
        merc_s2r_lanes: g.s2r.to_vec(),
        merc_predmem: g.predmem != 0,
        merc_s2r_sr: g.s2rsr.to_vec(),
        merc_guarded_bra: g.gbra.to_vec(),
        merc_lop3_pdest: g.lpd.to_vec(),
        merc_syncwarp: g.swlanes.to_vec(),
        merc_atoms: g.atoms.to_vec(),
        merc_ldgsts_pin: g.ldgpin.to_vec(),
        merc_ldgsts_wait: if g.ldgwait < 0 { Vec::new() } else { vec![g.ldgwait as u32] },
        merc_ldgconst: g.ldgc.to_vec(),
        merc_xor_reg: g.pxr.to_vec(),
    }
}

/// Znane ogonki (udokumentowane w MERCURY_UPLIFT_SM103A.md sekcja RESIDUALS):
/// kazdy wpis = (kernel-prefix, przyczyna). Test pilnuje, by (a) wszystkie
/// inne byly byte-exact, (b) te nie zaczely "przechodzic" przypadkiem bez
/// aktualizacji dokumentu.
static EXPECTED_DIFF: &[(&str, &str)] = &[
    ("c_ld_dyn2",     "mk10c: trzeci anchor (S2R#2 lane4): f4n0=9 f4n1=0x204 — model multi-anchor mk13"),
    ("p_atomg",       "mk14.2: rekord ATOM 024e OK; residuum = anchor f4 multi (5,4,0: metryka regionu ptxas, mk17-park) + role desc (83,00) przy pi wspoldzielonym uni/reg"),
    ("p_atoms",       "mk15: rekord smem 010b060a przy lane S2UR WDROZONY (ok); residuum = anchor f4 multi (3,2,0) — mk16.1"),
    ("q_tail_call",   "RET-w-loop/collective epilog rodzina"),
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
