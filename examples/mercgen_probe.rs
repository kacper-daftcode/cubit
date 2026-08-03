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
            merc_stg_desc_pos: Vec::new(),
            merc_bar_pred: false,
        };
        let out = generate_mercury_full(&code, g.ord, Some(&ops), &meta, g.sm100 == 1);
        let gold = hx(g.gold);
        if out == gold {
            println!("{}: BYTE-EXACT", g.name);
        } else {
            println!("{}: DIFF (emit {}B vs nvcc {}B)", g.name, out.len(), gold.len());
            let op = max_prefix(&out, &gold);
            println!("  common prefix: {}B", op);
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
