// cdmp - corpus decode dump (op16 batch gate tool).
// Usage: cdmp <table.json> <records1.jsonl> [records2.jsonl ...]
// Prints one line per record:   <file>#<idx>\t<code>\t<sass>
// Designed for before/after full-corpus decode-text diffs.
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let table_path = args.next().expect("table path");
    let table = cubit::IsaTable::load(std::path::Path::new(&table_path)).expect("load table");
    let index = cubit::decoder::DecodeIndex::build(&table);
    let sched_mask: u128 = 0x1FFFF_u128 << (64 + 41);
    let mut n: u64 = 0;
    let mut nfails: u64 = 0;
    let stdout = std::io::stdout();
    use std::io::Write;
    let mut out = std::io::BufWriter::new(stdout.lock());
    for path in args {
        let data = std::fs::read_to_string(&path).expect("read records");
        let base = std::path::Path::new(&path)
            .file_name().unwrap().to_string_lossy().into_owned();
        for (i, line) in data.lines().enumerate() {
            if line.trim().is_empty() { continue; }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let code_str = v["code"].as_str().unwrap_or("0x0");
            let code = u128::from_str_radix(code_str.trim_start_matches("0x"), 16)
                .unwrap_or(0) & !sched_mask;
            let addr = v["addr"].as_u64().unwrap_or(0) as u32;
            match index.decode(code, addr, &table) {
                Ok(inst) => {
                    let sass = cubit::printer::to_sass(&inst);
                    writeln!(out, "{}#{}\t{}\t{}", base, i, code_str, sass).unwrap();
                }
                Err(e) => {
                    nfails += 1;
                    writeln!(out, "{}#{}\t{}\t!!DECODE-FAIL!! {}", base, i, code_str, e).unwrap();
                }
            }
            n += 1;
        }
    }
    eprintln!("cdmp: {} records, {} decode-fails", n, nfails);
}
