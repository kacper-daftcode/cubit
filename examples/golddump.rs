//! Dev-only: dla kazdego gold-wiersza drukuje `name out_hex gold_hex` (1 linia).
#[path = "../tests/gold_manifest.rs"]
mod gold_manifest;
use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use gold_manifest::GOLD;

fn meta_for(g: &gold_manifest::GoldRow) -> KernelMeta {
    let n_params = g.ptr + g.scal;
    let params = (0..n_params)
        .map(|i| KernelParam {
            index: i, ordinal: i, offset: i * 8,
            size: if i < g.ptr { 8 } else { 4 },
        })
        .collect();
    KernelMeta {
        name: g.name.into(), regcount: 16, frame_size: 0, min_stack_size: 0,
        maxreg_count: 0xFF, num_barriers: g.bars,
        exit_offsets: (0..g.exits).map(|i| i * 16).collect(),
        cbank_param_size: g.cbank, params, cuda_api_version: 0x83,
        shared_size: g.smem,
        merc_param_order: if g.pord.is_empty() { None } else { Some(g.pord.to_vec()) },
        merc_param_write: g.pwrite, merc_stg_desc_pos: g.stgpos.to_vec(),
        merc_bar_pred: g.barpred != 0, merc_param_uniform: g.punif, merc_param_regpath: g.preg,
        merc_param_width: (0..8).map(|i| ((g.pwid >> (8 * i)) & 0xff) as u8).collect(),
        merc_dynldg: g.dynldg == 1, merc_bar_pos: g.barpos.to_vec(),
        merc_stg_pos: g.stgseq.to_vec(), merc_xor: g.pxor.to_vec(),
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
    }
}

fn hexs(d: &[u8]) -> String { d.iter().map(|b| format!("{b:02x}")).collect() }

fn main() {
    for g in GOLD {
        let ops: Vec<String> = g.ops.iter().map(|s| s.to_string()).collect();
        let code = vec![0u8; ops.len() * 16];
        let out = generate_mercury_full(&code, g.ord, Some(&ops), &meta_for(g), g.sm100 == 1);
        println!("ROW {} {} {}", g.name, hexs(&out), g.gold);
    }
}
