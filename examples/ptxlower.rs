//! b9 pilot harness: lower a .ptx file to SASS text (cubit .entry format).
//! Usage: ptxlower <input.ptx> [--opt none|basic|full]
use cubit::ptx_lower::lower_kernel;
use cubit::ptx_parse::parse_ptx;

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: ptxlower <input.ptx>");
    let text = std::fs::read_to_string(&path)?;
    let kernels = parse_ptx(&text)?;
    let mut out = String::new();
    for k in &kernels {
        let lowered = lower_kernel(k)?;
        out.push_str(&lowered.to_sass_text());
        out.push('\n');
    }
    println!("{}", out);
    Ok(())
}
