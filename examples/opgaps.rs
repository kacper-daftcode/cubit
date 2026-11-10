//! Where the scheduler's operand convention (`scheduling_pass::dest_regs` / `src_regs`) misses a definition or a
//! use that the certified transfer functions (`reg_liveness::reg_xfer`, `pred_liveness::pred_xfer`) list —
//! per opcode, over a frozen listing. Under `CUBIT_SYNC_CLASSES=1` the scheduler takes the union.
//!
//!     cargo run --release --example opgaps -- kernel.frozen.sass [--dump]
use cubit::sass_file::parse_sass_file_str;
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let sf = parse_sass_file_str(&std::fs::read_to_string(&args[1])?)?;
    let name = |(u, k): (bool, u16)| -> String {
        match (u, k) {
            (false, k) if k >= 256 => "P".into(),
            (false, _) => "R".into(),
            (true, k) if k >= 64 => "UP".into(),
            (true, _) => "UR".into(),
        }
    };
    if args.iter().any(|a| a == "--dump") {
        // every instruction with the certified sets, for reading one kernel
        for k in &sf.kernels {
            for (i, ins) in k.instructions.iter().enumerate() {
                let (sd, su) = cubit::sync_class::scheduler_xfer(ins);
                match cubit::sync_class::certified_xfer(ins) {
                    Some((d, u)) => println!("{i:5} {:60} certified: defs {d:?} uses {u:?} | scheduler: defs {sd:?} uses {su:?}", ins.raw_text),
                    None => println!("{i:5} {:60} (family not known) | scheduler: defs {sd:?} uses {su:?}", ins.raw_text),
                }
            }
        }
        return Ok(());
    }
    let mut gaps: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();
    let (mut n, mut unknown) = (0usize, 0usize);
    for k in &sf.kernels {
        for ins in &k.instructions {
            n += 1;
            if cubit::sync_class::certified_xfer(ins).is_none() {
                unknown += 1;
                continue;
            }
            let (d, u) = cubit::sync_class::operand_gaps(ins);
            for (what, v) in [("definition", d), ("use", u)] {
                for key in v {
                    let e = gaps.entry((ins.opcode.clone(), format!("{what} of {}", name(key)))).or_insert((0, ins.raw_text.clone()));
                    e.0 += 1;
                }
            }
        }
    }
    println!("{n} instructions, {unknown} of a family the certified functions do not know");
    let mut rows: Vec<_> = gaps.into_iter().collect();
    rows.sort_by_key(|(_, (c, _))| std::cmp::Reverse(*c));
    for ((op, what), (c, ex)) in rows {
        println!("  {c:7}  {op:12} misses a {what:18}  e.g. {ex}");
    }
    Ok(())
}
