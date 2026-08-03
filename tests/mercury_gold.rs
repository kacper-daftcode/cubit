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
            size: 8,
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
    }
}

/// Znane ogonki (udokumentowane w MERCURY_UPLIFT_SM103A.md sekcja RESIDUALS):
/// kazdy wpis = (kernel-prefix, przyczyna). Test pilnuje, by (a) wszystkie
/// inne byly byte-exact, (b) te nie zaczely "przechodzic" przypadkiem bez
/// aktualizacji dokumentu.
static EXPECTED_DIFF: &[(&str, &str)] = &[
    ("k_bra",    "STG mid-fields (40/c0 + tail 4/8/c) = markery regionow CFG"),
    ("k_loop8",  "STG mid-fields dla loop-LDG"),
    ("k_stg2",   "STG desc-binding [4:6] 8200<->0201 wg parametru"),
    ("t_branct", "STG region/epoch fields"),
    ("v_p2",     "STG [4:6] binding-variant"),
    ("v_stg2",   "STG [4:6] binding + kolejnosc"),
    ("v_sm128",  "STG tail-dw=4 (smem marker)"),
    ("v_sm2k",   "STG tail-dw=4"),
    ("v_dyn_smem", "STG tail-dw=4"),
    ("v_ld1",    "desc tail-dw role-order swap (read/write role pary)"),
    ("v_ldg_u64", "desc tail-dw role-order"),
    ("m_ld.10",  "desc tail-dw role-order"),
    ("v_mix",    "desc tail-dw role-order"),
    ("v_ld2",    "desc tail-dw role-order (3 params)"),
    ("v_p3",     "desc tail-dw order przy 3 parametrach"),
    ("k_lds",    "smem: cbank-wariant 83 vs p2-mid — podwojny kodowanie"),
    ("k_smem",   "smem: p2-mid pozycja + cbank wariant"),
    ("k_diverge","p2 trigger dla predykowanego brancha (S2R+LOP3, bez LDG)"),
    ("v_barx",   "p2 trigger dla BAR-w-if na emiterze sm_100"),
    ("k_ld",     "rekord cflow wariant 0x41 (LDG dynamic-addr, era 103a)"),
    ("k_ldcg",   "cflow 0x41 (era 103a LDG)"),
    ("k_ldg2",   "cflow 0xc1 (era 103a, multi-LDG)"),
    ("k_shfl",   "cflow 0x41 z SHFL (era 103a)"),
    ("k_mma",    "cflow 0x41 + rekordy 025a0026 (HMMA) — payload cw/region pola"),
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
