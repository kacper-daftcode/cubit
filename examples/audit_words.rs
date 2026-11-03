//! Dynamic table audit, cubit side: decode, print and re-encode a list of probe words in one
//! process (the table loads once) so `tools/audit_dynamic.py` can compare the result with
//! nvdisasm's text for every word.
//!
//! Usage: audit_words words.jsonl table.json output.jsonl
//!   input lines:  {"word": "<32 hex digits>", ...}   (any other keys are copied through)
//!   output lines: the input object plus
//!     "cubit_key", "cubit_group", "cubit_text"  when the word decodes,
//!     "cubit_error"                              when it does not,
//!     "reencode": "ok" | "mismatch:<hex>" | "error:<message>"  for decoded words
//!       (the text is re-parsed with the word's own control code and encoded again).
use anyhow::{Context, Result};
use cubit::{decoder::DecodeIndex, IsaTable};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    anyhow::ensure!(a.len() == 3, "usage: audit_words words.jsonl table.json output.jsonl");
    let table = IsaTable::load(Path::new(&a[1]))?;
    let index = DecodeIndex::build(&table);
    let mut out = BufWriter::new(File::create(&a[2])?);
    let (mut n, mut decoded_n, mut reencoded_n) = (0usize, 0usize, 0usize);
    for line in BufReader::new(File::open(&a[0])?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut item: Value = serde_json::from_str(&line).with_context(|| line.clone())?;
        let word = u128::from_str_radix(item["word"].as_str().context("word")?.trim_start_matches("0x"), 16)?;
        n += 1;
        match index.decode(word, 0, &table) {
            Err(e) => {
                item["cubit_error"] = Value::String(e.to_string());
            }
            Ok(d) => {
                decoded_n += 1;
                // The display print is what nvdisasm's text is compared with; the
                // lossless print (which may carry spellings the vendor elides, e.g.
                // `[RZ.U32+URm]` for the U32 twin of a UR-indexed address) is what
                // must re-encode bit for bit.
                let text = cubit::printer::to_sass_lossless(&d);
                let display = cubit::printer::to_sass(&d);
                item["cubit_key"] = Value::String(d.key.clone());
                item["cubit_group"] = Value::String(d.mod_group.clone());
                item["cubit_text"] = Value::String(display.trim_end_matches(';').trim().to_string());
                item["cubit_text_lossless"] = Value::String(text.clone());
                let ctrl = cubit::scheduling::decode_sched_upper32((word >> 96) as u32);
                let source = format!("[{}] {text} ;", cubit::scheduling::format_control_code(&ctrl));
                let reencode = (|| -> Result<u128> {
                    cubit::roundtrip_audit::check_semantic_source(&source)?;
                    let parsed = cubit::parse_cuasm_line(&source, 0)?;
                    anyhow::ensure!(parsed.hand_sched && parsed.rsd.is_none(), "nonsemantic source");
                    cubit::encoder::encode_instruction(&parsed, &table)
                })();
                item["reencode"] = Value::String(match reencode {
                    Ok(w) if w == word => {
                        reencoded_n += 1;
                        "ok".to_string()
                    }
                    Ok(w) => format!("mismatch:{w:032x}"),
                    Err(e) => format!("error:{}", e.to_string().lines().next().unwrap_or("")),
                });
            }
        }
        writeln!(out, "{item}")?;
    }
    eprintln!("{n} words: {decoded_n} decoded, {reencoded_n} re-encoded bit-exact");
    Ok(())
}
