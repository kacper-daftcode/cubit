use cubit::ptx_parse::parse_ptx;
fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage");
    let text = std::fs::read_to_string(&path)?;
    for k in parse_ptx(&text)? {
        println!("kernel {} params:", k.name);
        for p in &k.params { println!("  {} ty={} size={} offset=0x{:x}", p.name, p.ty, p.size, p.offset); }
    }
    Ok(())
}
