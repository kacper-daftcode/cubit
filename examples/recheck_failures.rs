//! Fast RE feedback only. A full corpus audit is still required for acceptance.
//! Usage: recheck_failures failures.jsonl table.json output.jsonl
use anyhow::{Context, Result};
use cubit::{decoder::DecodeIndex, IsaTable};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};
fn main() -> Result<()> {
    cubit::roundtrip_audit::check_strict_environment()?;
    let a: Vec<_> = std::env::args().skip(1).collect();
    anyhow::ensure!(
        a.len() == 3,
        "usage: recheck_failures failures.jsonl table.json output.jsonl"
    );
    let table = IsaTable::load(Path::new(&a[1]))?;
    let index = DecodeIndex::build(&table);
    let mut words: HashMap<(u128, u32), usize> = HashMap::new();
    for line in BufReader::new(File::open(&a[0])?).lines() {
        let item: Value = serde_json::from_str(&line?)?;
        let f = &item["failure"];
        if f["stage"].as_str().unwrap_or("").starts_with("stream") {
            continue;
        }
        if let (Some(word), Some(addr)) = (f["expected"].as_str(), f["addr"].as_u64()) {
            let raw = u128::from_str_radix(word.trim_start_matches("0x"), 16)?;
            *words.entry((raw, u32::try_from(addr)?)).or_default() += 1;
        }
    }
    let mut output = BufWriter::new(File::create(&a[2])?);
    let mut passed = 0;
    let total: usize = words.values().sum();
    let mut families = HashMap::<String, usize>::new();
    for ((expected, addr), count) in &words {
        let result = (|| -> Result<_> {
            let decoded = index.decode(*expected, *addr, &table)?;
            let sass = cubit::printer::to_sass_lossless(&decoded);
            let ctrl = cubit::scheduling::decode_sched_upper32((expected >> 96) as u32);
            let source = format!(
                "[{}] {sass} ;",
                cubit::scheduling::format_control_code(&ctrl)
            );
            cubit::roundtrip_audit::check_semantic_source(&source)?;
            let parsed = cubit::parse_cuasm_line(&source, *addr)?;
            anyhow::ensure!(
                parsed.hand_sched && parsed.rsd.is_none(),
                "nonsemantic source"
            );
            let actual = cubit::encoder::encode_instruction(&parsed, &table);
            Ok((decoded.key, decoded.mod_group, source, actual))
        })();
        let mut record =
            json!({"expected":format!("0x{expected:032x}"),"addr":addr,"instances":count});
        match result {
            Ok((_, _, _, Ok(actual))) if actual == *expected => {
                passed += count;
                continue;
            }
            Ok((key, mods, sass, actual)) => {
                *families.entry(format!("{key}/{mods}")).or_default() += count;
                record["key"] = json!(key);
                record["mods"] = json!(mods);
                record["sass"] = json!(sass);
                match actual {
                    Ok(actual) => {
                        record["actual"] = json!(format!("0x{actual:032x}"));
                        record["xor"] = json!(format!("0x{:032x}", expected ^ actual));
                    }
                    Err(e) => record["error"] = json!(format!("{e:#}")),
                }
            }
            Err(e) => {
                *families
                    .entry(format!("opcode_{:03x}", expected & 0xfff))
                    .or_default() += count;
                record["error"] = json!(format!("{e:#}"));
            }
        }
        writeln!(output, "{record}")?;
    }
    output.flush().context("failure output")?;
    let mut ranked: Vec<_> = families.into_iter().collect();
    ranked.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    println!("DIAGNOSTIC {passed}/{total} previous failed instances now encode; {} distinct words/addresses checked",words.len());
    for (family, n) in ranked {
        println!("{n:8} {family}");
    }
    Ok(())
}
