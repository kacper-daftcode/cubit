// probe: drukuje diff emit vs nvcc dla manifestu gold
#[path = "../tests/gold_manifest.rs"]
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    for g in GOLD {
        if args.len() > 1 && !args[1..].iter().any(|a| g.name == a) { continue; }
        let ops: Vec<String> = g.ops.iter().map(|s| s.to_string()).collect();
        let code = vec![0u8; ops.len() * 16];
        let params = (0..(g.ptr + g.scal))
            .map(|i| KernelParam { index: i, ordinal: i, offset: i * 8, size: if i < g.ptr { 8 } else { 4 } })
            .collect();
        let meta = KernelMeta {
            name: g.name.into(), regcount: 16, frame_size: 0, min_stack_size: 0,
            maxreg_count: 0xFF, num_barriers: g.bars,
            exit_offsets: (0..g.exits).map(|i| i * 16).collect(),
            cbank_param_size: g.cbank, params, cuda_api_version: 0x83, shared_size: g.smem,
            merc_param_order: if g.pord.is_empty() { None } else { Some(g.pord.to_vec()) },
            merc_param_write: g.pwrite,
            merc_stg_desc_pos: g.stgpos.to_vec(),
            merc_bar_pred: g.barpred != 0,
            merc_param_uniform: g.punif,
            merc_param_regpath: g.preg,
            merc_param_width: (0..8).map(|i| ((g.pwid >> (8 * i)) & 0xff) as u8).collect(),
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
            merc_s2r_dest: g.s2rd.to_vec(),
            merc_load_flags: g.loadfl.to_vec(),
            merc_atom_pool_hits: g.atompool.to_vec(),
            merc_guarded_bra: g.gbra.to_vec(),
            merc_lop3_pdest: g.lpd.to_vec(),
            merc_syncwarp: g.swlanes.to_vec(),
            merc_atoms: g.atoms.to_vec(),
            merc_ldgsts_pin: g.ldgpin.to_vec(),
            merc_ldgsts_wait: if g.ldgwait < 0 { Vec::new() } else { vec![g.ldgwait as u32] },
            merc_ldgconst: g.ldgc.to_vec(),
            merc_xor_reg: g.pxr.to_vec(),
        };
        let out = generate_mercury_full(&code, g.ord, Some(&ops), &meta, g.sm100 == 1);
        let gold = hx(g.gold);
        if out == gold {
            println!("{}: BYTE-EXACT", g.name);
        } else {
            println!("{}: DIFF (emit {}B vs nvcc {}B)", g.name, out.len(), gold.len());
            let op = max_prefix(&out, &gold);
            println!("  common prefix: {}B", op);
            if std::env::var("PROBE_FULL").is_ok() {
                println!("  EMIT {}", out.iter().map(|b| format!("{b:02x}")).collect::<String>());
                println!("  GOLD {}", gold.iter().map(|b| format!("{b:02x}")).collect::<String>());
                continue;
            }
            println!("  emit @{:#x}: {}", op, hexs(&out, op));
            println!("  gold @{:#x}: {}", op, hexs(&gold, op));
        }
    }
}

fn max_prefix(a: &[u8], b: &[u8]) -> usize {
    let mut i = 0;
    while i < a.len() && i < b.len() && a[i] == b[i] { i += 1; }
    i
}
fn hexs(v: &[u8], from: usize) -> String {
    v[from..std::cmp::min(from + 64, v.len())]
        .iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}
