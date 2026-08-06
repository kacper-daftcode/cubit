//! Dev-only probe: dump wybranych pol KernelMeta dla pliku sass.
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    let sf = cubit::sass_file::parse_sass_file_str(&text).unwrap();
    for def in &sf.kernels {
        let code = vec![0u8; def.instructions.len() * 16];
        let m = cubit::sass_file::kernel_def_to_meta(def, &code);
        println!("kernel {}", def.name);
        println!("  loads: {:?}", m.merc_param_loads);
        println!("  stg_desc_pos: {:?}", m.merc_stg_desc_pos);
        println!("  stg_pos: {:?}", m.merc_stg_pos);
        println!("  ldgconst: {:?}", m.merc_ldgconst);
        println!("  guarded_bra: {:?}  lop3_pdest: {:?}  s2r_sr: {:?}", m.merc_guarded_bra, m.merc_lop3_pdest, m.merc_s2r_sr);
    }
}
