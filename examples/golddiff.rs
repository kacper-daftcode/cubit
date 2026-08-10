//! Dev-only: rekord-po-rekordzie diff cubit vs gold dla wybranych kerneli.
//! Uzycie: cargo run --release --example golddiff [substr]
#[path = "../tests/gold_manifest.rs"]
mod gold_manifest;
use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use gold_manifest::{GoldRow, GOLD};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn meta_for(g: &GoldRow) -> KernelMeta {
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
        merc_dynldg: g.dynldg == 1, merc_bar_pos: g.barpos.to_vec(), merc_bar_args: g.barg.to_vec(),
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
        merc_s2r_sr: g.s2rsr.to_vec(),
        merc_s2r_dest: g.s2rd.to_vec(),
        merc_load_flags: g.loadfl.to_vec(),
        merc_atom_pool_hits: g.atompool.to_vec(),
        merc_guarded_bra: g.gbra.to_vec(),
        merc_lop3_pdest: g.lpd.to_vec(),
        merc_syncwarp: g.swlanes.to_vec(),
        merc_utca: Vec::new(),
        merc_atom_smem: Vec::new(),
        merc_atoms: g.atoms.to_vec(),
        merc_ldgsts_pin: g.ldgpin.to_vec(),
        merc_ldgsts_wait: if g.ldgwait < 0 { Vec::new() } else { vec![g.ldgwait as u32] },
        merc_ldgconst: g.ldgc.to_vec(),
        merc_xor_reg: g.pxr.to_vec(),
        merc_bra_selfloop: Vec::new(),
        merc_wwide_sites: Vec::new(),
        merc_cgsites: Vec::new(),
        merc_cgmasks: Vec::new(),
        has_call: false,
        has_bssy: false,
        merc_s2ur_cga: g.ops.iter().enumerate()
            .filter(|(_, o)| o.starts_with("S2UR"))
            .map(|(i, _)| (i as u32, false))
            .collect(),
        ..Default::default()
    }
}

fn len_map(t: u8) -> Option<usize> {
    match t { 0x01 | 0x03 | 0x31 => Some(16), 0x02 => Some(32), 0x41 | 0x42 | 0x32 => Some(4), 0x11 => Some(8), _ => None }
}

fn recs(d: &[u8]) -> Vec<String> {
    if d.len() < 14 { return vec![]; }
    let b = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    let mut off = 12 + ((b + 31) / 32) * 4;
    let end = d.len() - 2;
    let mut v = Vec::new();
    while off + 4 <= end {
        if &d[off..off + 2] == b"\xd0\x00" || &d[off..off + 2] == b"\x00\x00" {
            v.push(d[off..off + 2].iter().map(|x| format!("{x:02x}")).collect()); off += 2; continue;
        }
        let ln = match len_map(d[off]) {
            Some(l) => l,
            None => match d[off] {
                0x51 | 0xd1 => if d[off + 2] == 1 { 18 } else { 34 },
                _ => { v.push(format!("UNK@{off}:{}", d[off..end.min(off+16)].iter().map(|x| format!("{x:02x}")).collect::<String>())); break; }
            },
        };
        v.push(d[off..(off + ln).min(end)].iter().map(|x| format!("{x:02x}")).collect());
        off += ln;
    }
    v
}

fn main() {
    let flts: Vec<String> = std::env::args().skip(1).filter(|a| a != "-f").collect();
    let flt = String::new();
    let _ = &flt;
    for g in GOLD {
        if !flts.is_empty() && !flts.iter().any(|f| g.name.contains(f)) { continue; }
        let ops: Vec<String> = g.ops.iter().map(|s| s.to_string()).collect();
        let code = vec![0u8; ops.len() * 16];
        let out = generate_mercury_full(&code, g.ord, Some(&ops), &meta_for(g), g.sm100 == 1);
        let gold = hx(g.gold);
        if out == gold { println!("== {} OK", g.name); continue; }
        let (ob, gb) = (
            u32::from_le_bytes(out[8..12].try_into().unwrap()),
            u32::from_le_bytes(gold[8..12].try_into().unwrap()),
        );
        let (om, gm) = (&out[4..8], &gold[4..8]);
        println!("== {} B out={ob} gold={gb} magic {} vs {}", g.name, hex(om), hex(gm));
        let bmax = ob.max(gb) as usize;
        let blen = ((bmax + 31) / 32) * 4;
        println!("   bitmap out={} gold={}", hex(&out[12..12 + blen]), hex(&gold[12..12 + blen]));
        if std::env::var_os("FULL").is_some() {
            println!("   OUT-full: {}", hex(&out));
            println!("   GLD-full: {}", hex(&gold));
        }
        let r = recs(&out);
        let q = recs(&gold);
        if std::env::var_os("FULL").is_some() {
            println!("   r={} q={}", r.len(), q.len());
            for (i,x) in r.iter().enumerate() { println!("   out[{i}] {x}"); }
            for (i,x) in q.iter().enumerate() { println!("   gld[{i}] {x}"); }
        }
        let n = r.len().max(q.len());
        for i in 0..n {
            let a = r.get(i).map(|s| s.as_str()).unwrap_or("-");
            let b = q.get(i).map(|s| s.as_str()).unwrap_or("-");
            if a != b { println!("   [{i}] OUT {a}\n       GLD {b}"); }
        }
        if std::env::var_os("SUMMARY").is_some() {
            let bm_o = &out[12..12 + blen]; let bm_g = &gold[12..12 + blen];
            let bdiff: usize = bm_o.iter().zip(bm_g.iter()).map(|(a, b)| (a ^ b).count_ones() as usize).sum();
            let rdiff = r.len() as isize - q.len() as isize;
            let same: usize = r.iter().zip(q.iter()).filter(|(a, b)| a == b).count();
            println!("   SUMMARY bmdiff_bits={} recs(out-gold)={} rec_same={}/{}", bdiff, rdiff, same, q.len().max(r.len()));
        } else {
        println!("   tail out={} gold={}", out[out.len()-2..].iter().map(|x| format!("{x:02x}")).collect::<String>(), gold[gold.len()-2..].iter().map(|x| format!("{x:02x}")).collect::<String>());
        }
    }
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
