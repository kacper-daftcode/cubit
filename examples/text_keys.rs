//! Key derivation for vendor texts, cubit side: parse a list of SASS texts in one process and
//! print the table keys the encoder would look them up under, so `tools/probes/re_sm120_rows.py`
//! can tell a harvest row whose key is the vendor's spelling from a mis-tokenised one (session G,
//! 2026-11-07; KNOWN_ISSUES T1).
//!
//! Usage: text_keys input.jsonl output.jsonl
//!   input lines:  {"text": "<SASS text without control code>", ...}  (other keys copied through)
//!   output lines: the input object plus
//!     "base_key"   the opcode + operand labels (`IADD3_R_P_P_R_R_R`, the encoder's base key),
//!     "full_key"   the dotted opcode + operand labels (`LDG.E.128_R_dARI`, the encoder's first lookup),
//!     "mod_group"  the sorted modifier group name (`128,E`),
//!     "parse_error" when the text does not parse.
use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    anyhow::ensure!(a.len() == 2, "usage: text_keys input.jsonl output.jsonl");
    let mut out = BufWriter::new(File::create(&a[1])?);
    for line in BufReader::new(File::open(&a[0])?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut item: Value = serde_json::from_str(&line).with_context(|| line.clone())?;
        let text = item["text"].as_str().context("text")?.to_string();
        match cubit::parser::parse_sass(&text, 0) {
            Err(e) => {
                item["parse_error"] = Value::String(e.to_string().lines().next().unwrap_or("").to_string());
            }
            Ok(insn) => {
                let clean: Vec<&str> =
                    insn.opcode_full.split('.').filter(|p| !p.is_empty() && !p.starts_with('?')).collect();
                let mut full = clean.join(".");
                for op in &insn.operands {
                    full.push('_');
                    full.push_str(cubit::parser::operand_type_label_pub(op));
                }
                item["base_key"] = Value::String(insn.key.clone());
                item["full_key"] = Value::String(full);
                item["mod_group"] = Value::String(cubit::table::extract_mod_group(&text));
            }
        }
        writeln!(out, "{item}")?;
    }
    Ok(())
}
