//! cubit CLI entry point.

// CLI driver: these patterns are fine on one-shot command paths — the regexes are
// built in cold per-file / per-kernel loops, and a couple of command builders take
// many parameters. Allow them so `-D warnings` stays meaningful for the rest.
#![allow(clippy::regex_creation_in_loops)]
#![allow(clippy::too_many_arguments)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use cubit::table::IsaTable;
use object::read::elf::{ElfFile, FileHeader, SectionHeader as _};
use object::{elf, Endianness};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "cubit",
    version,
    about = "SM120 CUDA assembler — bitfield encoding"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate encoder against records.jsonl.
    Validate {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        #[arg(short, long, default_value = "tables/records.jsonl")]
        records: PathBuf,
        /// Write failing records (with re-encoded code) to this JSONL file.
        #[arg(long)]
        dump_failures: Option<PathBuf>,
    },
    /// Encode a single SASS instruction.
    Encode {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        #[arg(short, long, default_value = "0")]
        addr: String,
        sass: String,
    },
    /// Decode a 128-bit instruction from hex.
    Decode {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        #[arg(short, long, default_value = "0")]
        addr: String,
        code: Vec<String>,
    },
    /// Disassemble a cubin or host ELF to SASS text (no cuobjdump required).
    Disassemble {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        /// Input cubin file.
        input: PathBuf,
        /// Kernel name (default: all kernels).
        #[arg(short, long)]
        kernel: Option<String>,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Emit a re-assemblable .entry that FREEZES the schedule: each instruction
        /// carries a `[B:R:W:S]` control-code prefix (instead of the `/* @sched */`
        /// comment), branch targets become labels, and `.entry`/`.reg` headers are
        /// emitted. Feeding this back to `cubit asm` reproduces the exact schedule
        /// (the scheduler is bypassed) — for faithful round-trips and bisection.
        #[arg(long)]
        frozen: bool,
        /// Proceed even if the cubin's ELF arch (e_flags SM field) does not match
        /// the ISA table's target arch. Default: refuse (mis-decoding sm_100 words
        /// with an sm_103 table silently produces wrong SASS).
        #[arg(long)]
        allow_arch_mismatch: bool,
    },
    /// Round-trip test: read cubin, disassemble, re-encode, compare.
    Roundtrip {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        #[arg(short, long, default_value = "tables/records.jsonl")]
        records: PathBuf,
        inputs: Vec<PathBuf>,
        /// Report arch mismatches but keep comparing (do not refuse).
        #[arg(long)]
        allow_arch_mismatch: bool,
    },
    /// Patch a cubin: disassemble → re-encode → write patched cubin.
    Patch {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        #[arg(short, long, default_value = "tables/records.jsonl")]
        records: PathBuf,
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Proceed even if the cubin arch does not match the table's target arch.
        #[arg(long)]
        allow_arch_mismatch: bool,
    },
    /// Dump parsed Mercury (capmerc) sections of a cubin.
    MercDump {
        /// Input cubin file.
        input: PathBuf,
        /// Kernel name filter (default: all kernels).
        #[arg(short, long)]
        kernel: Option<String>,
        /// Reject unknown record tags (default: lenient).
        #[arg(long)]
        strict: bool,
    },
    /// Assemble a .sass file into a cubin.
    Asm {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        /// Input .sass file. Two formats supported:
        ///
        /// 1. Directive format (recommended for standalone use):
        ///    `.entry kernel_name` / `.reg R0-R7` / `.param u64 out_ptr` / `EXIT ;` / `.endentry`
        ///
        /// 2. Address format (from cubit disassemble output):
        ///    // kernel_name
        ///    /*0000*/  INSTR ;
        ///    /*0010*/  INSTR ;
        input: PathBuf,
        /// Template cubin: provides ELF structure and scheduling ctrl words.
        #[arg(short = 'T', long)]
        template: Option<PathBuf>,
        /// Reference cubin for EIATTR records (.nv.info sections).
        /// Optional: when omitted, metadata is inferred from .reg/.param/.bar directives
        /// (directive format) or from the instructions themselves (address format).
        #[arg(long)]
        eiattr_from: Option<PathBuf>,
        /// Output cubin file.
        #[arg(short, long)]
        output: PathBuf,
        /// Kernel name to assemble (default: all kernels in sass file).
        #[arg(short, long)]
        kernel: Option<String>,
        /// Custom Mercury stub file (binary). Overrides the default stub for
        /// standalone cubins. Extract from a cubin: .nv.capmerc.text.* section.
        #[arg(long)]
        mercury_stub: Option<PathBuf>,
    },
    /// Show ISA table info.
    Info {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
    },
    /// Assemble multiple SASS instructions from a string (Keystone-like API).
    /// Handles labels, multi-instruction blocks, and branch target resolution.
    AsmText {
        #[arg(short, long, default_value = "tables/sm120.json")]
        table: PathBuf,
        /// Base address for first instruction (hex).
        #[arg(short, long, default_value = "0")]
        addr: String,
        /// SASS code string (instructions separated by ; or newlines).
        /// If omitted, read from stdin.
        code: Option<String>,
        /// Output format: hex (default) or raw.
        #[arg(long, default_value = "hex")]
        format: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate {
            table,
            records,
            dump_failures,
        } => cmd_validate(&table, &records, dump_failures.as_deref()),
        Commands::Encode { table, addr, sass } => cmd_encode(&table, &addr, &sass),
        Commands::Decode { table, addr, code } => cmd_decode(&table, &addr, &code),
        Commands::Disassemble {
            table,
            input,
            kernel,
            output,
            frozen,
            allow_arch_mismatch,
        } => cmd_disassemble(
            &table,
            &input,
            kernel.as_deref(),
            output.as_deref(),
            frozen,
            allow_arch_mismatch,
        ),
        Commands::Roundtrip {
            table,
            records,
            inputs,
            allow_arch_mismatch,
        } => cmd_roundtrip(&table, &records, &inputs, allow_arch_mismatch),
        Commands::Patch {
            table,
            records,
            input,
            output,
            allow_arch_mismatch,
        } => cmd_patch(&table, &records, &input, &output, allow_arch_mismatch),
        Commands::Asm {
            table,
            input,
            template,
            eiattr_from,
            output,
            kernel,
            mercury_stub,
        } => cmd_asm(
            &table,
            &input,
            template.as_deref(),
            eiattr_from.as_deref(),
            &output,
            kernel.as_deref(),
            mercury_stub.as_deref(),
        ),
        Commands::AsmText {
            table,
            addr,
            code,
            format,
        } => cmd_asm_text(&table, &addr, code.as_deref(), &format),
        Commands::MercDump {
            input,
            kernel,
            strict,
        } => cmd_merc_dump(&input, kernel.as_deref(), strict),
        Commands::Info { table } => cmd_info(&table),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse_hex_addr(s: &str) -> Result<u32> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        u32::from_str_radix(s, 16).context("invalid hex address")
    } else {
        s.parse::<u32>().context("invalid address")
    }
}

fn load_cuobjdump_sass(path: &Path) -> Result<String> {
    let out = std::process::Command::new("/usr/local/cuda/bin/cuobjdump")
        .args(["-sass", &path.to_string_lossy()])
        .output()
        .context("failed to run cuobjdump")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse_cuobjdump_output(
    sass: &str,
) -> std::collections::HashMap<String, Vec<(u32, u128, String)>> {
    use once_cell::sync::Lazy;
    static RE_FUNC: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"Function\s*:\s*(\S+)").unwrap());
    static RE_INSN: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"/\*([0-9a-f]+)\*/\s+(.+?)\s+/\*\s*0x([0-9a-fA-F]+)\s*\*/").unwrap()
    });
    static RE_HI: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"/\*\s*0x([0-9a-fA-F]+)\s*\*/").unwrap());
    static RE_ANN: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"\s*[?&]\S+").unwrap());

    let mut out: std::collections::HashMap<String, Vec<(u32, u128, String)>> =
        std::collections::HashMap::new();
    let mut cur_func = String::new();
    let lines: Vec<&str> = sass.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if let Some(c) = RE_FUNC.captures(line) {
            cur_func = c[1].to_string();
        }
        if let Some(c) = RE_INSN.captures(line) {
            if i + 1 < lines.len() {
                if let Some(c2) = RE_HI.captures(lines[i + 1]) {
                    let addr = u32::from_str_radix(&c[1], 16).unwrap_or(0);
                    let lo = u64::from_str_radix(&c[3], 16).unwrap_or(0);
                    let hi = u64::from_str_radix(&c2[1], 16).unwrap_or(0);
                    let code = ((hi as u128) << 64) | lo as u128;
                    let asm = RE_ANN
                        .replace_all(c[2].trim(), "")
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .to_string();
                    out.entry(cur_func.clone())
                        .or_default()
                        .push((addr, code, asm));
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Parsed SASS file: instructions + per-kernel directives.
struct ParsedSassFile {
    kernels: std::collections::HashMap<String, Vec<(u32, String)>>,
    shared_sizes: std::collections::HashMap<String, u32>,
}

fn parse_sass_file_full(text: &str) -> ParsedSassFile {
    use once_cell::sync::Lazy;
    static RE_INSN: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"^\s*/\*([0-9a-f]+)\*/\s+(.+?)\s*;").unwrap());
    // Also match raw instruction comments: /*addr*/  /* ? 0xNNNN...NNNN */
    static RE_RAW: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"^\s*/\*([0-9a-f]+)\*/\s+/\*\s*\?\s*0x([0-9a-fA-F]+)\s*\*/").unwrap()
    });
    static RE_SHARED: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"^\.shared\s+smem\[(\d+)\]").unwrap());

    let mut out: std::collections::HashMap<String, Vec<(u32, String)>> =
        std::collections::HashMap::new();
    let mut shared_sizes: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut cur_kernel = String::new();

    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("// ") && !t.contains("/*") {
            cur_kernel = t[3..].trim().to_string();
            continue;
        }
        if cur_kernel.is_empty() {
            continue;
        }
        // Parse .shared smem[N] directive
        if let Some(c) = RE_SHARED.captures(t) {
            if let Ok(sz) = c[1].parse::<u32>() {
                shared_sizes.insert(cur_kernel.clone(), sz);
            }
            continue;
        }
        if let Some(c) = RE_RAW.captures(t) {
            let addr = u32::from_str_radix(&c[1], 16).unwrap_or(0);
            let raw_hex = c[2].to_string();
            // Store as special __raw__ prefix so encoder can emit raw bytes
            out.entry(cur_kernel.clone())
                .or_default()
                .push((addr, format!("__raw__0x{}", raw_hex)));
        } else if let Some(c) = RE_INSN.captures(t) {
            let addr = u32::from_str_radix(&c[1], 16).unwrap_or(0);
            let asm = c[2].trim().to_string();
            out.entry(cur_kernel.clone()).or_default().push((addr, asm));
        }
    }
    ParsedSassFile {
        kernels: out,
        shared_sizes,
    }
}

const SCHED_MASK: u128 = (cubit::scheduling::CC_MASK as u128) << 64;

/// Compute the `!rsd[b:v, ...]` annotation carrying every bit the text cannot
/// reproduce (outside the scheduling window; that one is owned by the
/// control-code prefix / @sched comment). Returns None when fully faithful.
fn rsd_annotation(orig: u128, reenc: u128) -> Option<String> {
    let d = (orig ^ reenc) & !SCHED_MASK;
    if d == 0 {
        return None;
    }
    let mut items: Vec<String> = Vec::new();
    for b in 0..128u32 {
        if (d >> b) & 1 == 1 {
            items.push(format!("{}:{}", b, (orig >> b) & 1));
        }
    }
    if items.is_empty() {
        None
    } else {
        Some(format!("!rsd[{}]", items.join(",")))
    }
}

// ── commands ──────────────────────────────────────────────────────────────────

fn cmd_validate(
    table_path: &Path,
    records_path: &Path,
    dump_failures: Option<&Path>,
) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    println!(
        "Loaded {} keys, {} groups from {}",
        table.num_keys(),
        table.num_groups(),
        table_path.display()
    );

    let records = cubit::table::load_records(records_path)?;
    println!(
        "Loaded {} records from {}",
        records.len(),
        records_path.display()
    );

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut by_key: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut dump: Option<std::io::BufWriter<std::fs::File>> = match dump_failures {
        Some(p) => Some(std::io::BufWriter::new(std::fs::File::create(p)?)),
        None => None,
    };

    for rec in &records {
        total += 1;
        let mut insn = match cubit::parse_sass(&rec.asm, rec.addr) {
            Ok(i) => i,
            Err(_) => {
                *by_key.entry(format!("{} [parse]", rec.key)).or_default() += 1;
                continue;
            }
        };
        if insn.key != rec.key && table.get_key(&rec.key).is_some() {
            insn.key = rec.key.clone();
        }
        // Extract scheduling (incl. yield flag) from the original code so that
        // fields like YieldInv — which depend on yield — encode correctly.
        let orig_upper32 = (rec.code >> 96) as u32;
        insn.ctrl = cubit::scheduling::decode_sched_upper32(orig_upper32);
        let code = match cubit::encoder::encode_instruction(&insn, &table) {
            Ok(c) => c,
            Err(e) => {
                *by_key.entry(format!("{} [enc]", rec.key)).or_default() += 1;
                if let Some(w) = dump.as_mut() {
                    use std::io::Write;
                    let line = serde_json::json!({
                        "key": rec.key, "mg": rec.mod_group, "addr": rec.addr,
                        "code": format!("0x{:032x}", rec.code),
                        "error": e.to_string(),
                        "asm": rec.asm,
                    });
                    writeln!(w, "{line}")?;
                }
                continue;
            }
        };
        if (code & !SCHED_MASK) == (rec.code & !SCHED_MASK) {
            passed += 1;
        } else {
            *by_key.entry(rec.key.clone()).or_default() += 1;
            if let Some(w) = dump.as_mut() {
                use std::io::Write;
                let line = serde_json::json!({
                    "key": rec.key, "mg": rec.mod_group, "addr": rec.addr,
                    "code": format!("0x{:032x}", rec.code),
                    "reenc": format!("0x{:032x}", code),
                    "asm": rec.asm,
                });
                writeln!(w, "{line}")?;
            }
        }
    }

    if !by_key.is_empty() {
        let mut sorted: Vec<_> = by_key.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        println!("Failures by key (top 20):");
        for (k, n) in sorted.iter().take(20) {
            println!("  {k}: {n}");
        }
    }
    println!(
        "\nValidation: {passed}/{total} ({:.4}%)",
        100.0 * passed as f64 / total as f64
    );
    Ok(())
}

fn cmd_asm_text(table_path: &Path, addr_str: &str, code: Option<&str>, format: &str) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    let base_addr = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        parse_hex_addr(addr_str)?
    } else {
        addr_str.parse::<u32>().unwrap_or(0)
    };

    let text = match code {
        Some(t) => t.to_string(),
        None => {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
            s
        }
    };

    let (bytes, count) = cubit::assemble(&text, base_addr, &table).context("assembly failed")?;

    match format {
        "raw" => {
            use std::io::Write;
            std::io::stdout().write_all(&bytes)?;
        }
        _ => {
            // hex: print each 128-bit instruction as 0x... line
            for chunk in bytes.chunks(16) {
                let val = u128::from_le_bytes(chunk.try_into().unwrap_or([0u8; 16]));
                println!("0x{val:032x}");
            }
            eprintln!("Assembled {count} instruction(s)");
        }
    }
    Ok(())
}

fn cmd_encode(table_path: &Path, addr_str: &str, sass: &str) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    let addr = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        parse_hex_addr(addr_str)?
    } else {
        addr_str.parse::<u32>().context("invalid address")?
    };
    let insn = cubit::parse_sass(sass, addr)?;
    let mod_group = cubit::table::extract_mod_group(&insn.raw_text);
    println!("InsKey:     {}", insn.key);
    println!("ModGroup:   {:?}", mod_group);
    println!("Operands:   {:?}", insn.operands);
    let code = cubit::encoder::encode_instruction(&insn, &table)?;
    let (lo, hi) = cubit::elf::CubinFile::split_code128(code);
    println!("Code128:    0x{code:032x}");
    println!("  insn_lo:  0x{lo:016x}");
    println!("  ctrl_hi:  0x{hi:016x}");
    Ok(())
}

fn cmd_decode(table_path: &Path, addr_str: &str, code_parts: &[String]) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    let index = cubit::decoder::DecodeIndex::build(&table);
    let addr = parse_hex_addr(addr_str)?;
    let code: u128 = if code_parts.len() == 1 {
        let s = code_parts[0]
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        u128::from_str_radix(s, 16).context("invalid 128-bit hex")?
    } else if code_parts.len() == 2 {
        let lo = u64::from_str_radix(code_parts[0].trim_start_matches("0x"), 16)?;
        let hi = u64::from_str_radix(code_parts[1].trim_start_matches("0x"), 16)?;
        ((hi as u128) << 64) | lo as u128
    } else {
        anyhow::bail!("expected 1 or 2 hex values")
    };
    let d = index.decode(code, addr, &table)?;
    println!("InsKey:     {}", d.key);
    println!("ModGroup:   {:?}", d.mod_group);
    println!("Opcode:     {}", d.opcode);
    println!("SASS:       {d}");
    println!(
        "Scheduling: stall={} yield={} wbar={} rbar={} wait=0x{:02x}",
        d.ctrl.stall, d.ctrl.yield_flag as u8, d.ctrl.write_bar, d.ctrl.read_bar, d.ctrl.wait_mask
    );
    println!("Fields:");
    for f in &d.fields {
        println!(
            "  {:8} [{:3}:{:3}] = {:6} (0x{:x})  tok={} ext={}",
            f.name,
            f.shift + f.bits - 1,
            f.shift,
            f.value,
            f.value,
            f.token_idx,
            f.extraction
        );
    }
    Ok(())
}

/// Refuse to process a cubin whose ELF arch differs from the table's target
/// SM arch (mis-decoding cross-arch words silently produces wrong SASS, e.g.
/// sm_100 MOV occupies the sm_103 LDC.64 encoding slot).
fn check_arch(table: &IsaTable, sm: cubit::elf::SmVersion, path: &Path, allow: bool) -> Result<()> {
    let want = table.target_sm();
    let got = sm.sm;
    if want == 0 || got == 0 || want == got {
        return Ok(());
    }
    let msg = format!(
        "arch mismatch: {} is sm_{} but the table targets sm_{};          pass --allow-arch-mismatch to force",
        path.display(), got, want);
    if allow {
        eprintln!("warning: {msg}");
        Ok(())
    } else {
        anyhow::bail!("{msg}")
    }
}

fn cmd_disassemble(
    table_path: &Path,
    input: &Path,
    only_kernel: Option<&str>,
    output_path: Option<&std::path::Path>,
    frozen: bool,
    allow_arch_mismatch: bool,
) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    let index = cubit::decoder::DecodeIndex::build(&table);

    let cubin = cubit::elf::CubinFile::load(input)?;
    check_arch(&table, cubin.sm, input, allow_arch_mismatch)?;
    // mk19: EIATTR kernel-metry (m.in. merc_syncwarp — duchy __syncwarp,
    // niewidoczne w SASS) do znacznikow .merc_syncwarp w --frozen.
    let eiattr_meta: std::collections::BTreeMap<String, cubit::eiattr::KernelMeta> =
        cubit::eiattr::parse_cubin_metadata(&cubin.bytes).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();

    for (sec_idx, (sec_name, _off, _size)) in cubin.text_sections.iter().enumerate() {
        let kernel_name = sec_name.strip_prefix(".text.").unwrap_or(sec_name);
        if let Some(only) = only_kernel {
            if kernel_name != only {
                continue;
            }
        }

        if !lines.is_empty() {
            lines.push(String::new());
        }

        // Resolve from EIATTR (.nv.info.<kernel>): .shared smem[N] and the kernel
        // parameter layout (KPARAM_INFO, attr 0x17 — one 12-byte record per param:
        // index[0..4], ordinal[4..6], offset[6..8], sizefield[8..12] where
        // size_bytes = sizefield >> 18). Params let `--frozen` emit `.param`.
        let (shared_size, kparams): (u32, Vec<(u32, u32)>) = {
            let elf_obj: ElfFile<'_, elf::FileHeader64<Endianness>> =
                ElfFile::parse(cubin.bytes.as_slice()).expect("failed to re-parse ELF");
            let endian = elf_obj.endian();
            let hdr = elf_obj.elf_header();
            let sections = hdr
                .sections(endian, cubin.bytes.as_slice())
                .expect("sections");
            let mut shared_size: u32 = 0;
            let shared_sec_name = format!(".nv.shared.{kernel_name}");
            for section in sections.iter() {
                let sname = match sections.section_name(endian, section) {
                    Ok(n) => std::str::from_utf8(n).unwrap_or(""),
                    Err(_) => continue,
                };
                if sname == shared_sec_name {
                    let sz = section.sh_size(endian);
                    if sz > 0 {
                        shared_size = sz as u32;
                    }
                    break;
                }
            }
            let mut kparams: Vec<(u32, u32)> = Vec::new();
            let info_sec_name = format!(".nv.info.{kernel_name}");
            for section in sections.iter() {
                let sname = match sections.section_name(endian, section) {
                    Ok(n) => std::str::from_utf8(n).unwrap_or(""),
                    Err(_) => continue,
                };
                if sname == info_sec_name {
                    let off = section.sh_offset(endian) as usize;
                    let sz = section.sh_size(endian) as usize;
                    if off + sz <= cubin.bytes.len() {
                        let data = &cubin.bytes[off..off + sz];
                        let mut pos = 0;
                        while pos + 4 <= data.len() {
                            let fmt = data[pos];
                            let attr = data[pos + 1];
                            let dsz = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
                            pos += 4;
                            if pos + dsz > data.len() {
                                break;
                            }
                            let payload = &data[pos..pos + dsz];
                            if fmt == 0x04 && attr == 0x08 && dsz >= 4 && shared_size == 0 {
                                let v = u32::from_le_bytes([
                                    payload[0], payload[1], payload[2], payload[3],
                                ]);
                                if v > 0 {
                                    shared_size = v;
                                }
                            }
                            if fmt == 0x04 && attr == 0x17 && dsz >= 12 {
                                let ordinal = u16::from_le_bytes([payload[4], payload[5]]) as u32;
                                let sizefield = u32::from_le_bytes([
                                    payload[8],
                                    payload[9],
                                    payload[10],
                                    payload[11],
                                ]);
                                kparams.push((ordinal, sizefield >> 18));
                            }
                            pos += dsz;
                        }
                    }
                    break;
                }
            }
            (shared_size, kparams)
        };

        // Decode all instructions in this section.
        struct Dec {
            addr: u32,
            text: String,
            sched: u64,
            unknown: bool,
            code: u128,
        }
        let bytes = cubin.text_bytes(sec_idx)?;
        let mut decoded: Vec<Dec> = Vec::new();
        let mut addr = 0u32;
        for chunk in bytes.chunks(16) {
            if chunk.len() < 16 {
                break;
            }
            let lo = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            let code = ((hi as u128) << 64) | lo as u128;
            let (text, unknown) = match index.decode(code, addr, &table) {
                Ok(d) => (format!("{d}"), false),
                Err(_) => (format!("/* ? 0x{code:032x} */"), true),
            };
            let sched = (hi >> 41) & 0x1FFFF;
            let text = text
                .trim_end_matches(" ;")
                .trim_end_matches(";")
                .to_string();
            decoded.push(Dec {
                addr,
                text,
                sched,
                unknown,
                code,
            });
            addr += 16;
        }

        // opcode (after an optional `@guard`) for branch-target detection.
        let opcode_of = |t: &str| -> String {
            let t = t.trim();
            let rest = if let Some(s) = t.strip_prefix('@') {
                s.split_once(char::is_whitespace).map(|x| x.1).unwrap_or("")
            } else {
                t
            };
            rest.trim()
                .split(|c: char| c.is_whitespace() || c == '.')
                .next()
                .unwrap_or("")
                .to_string()
        };
        let is_branch = |t: &str| {
            matches!(
                opcode_of(t).as_str(),
                "BRA" | "JMP" | "CALL" | "BRX" | "BSSY" | "BSYNC"
            )
        };
        // last 0xHEX token in a string (= branch target operand).
        let last_hex = |t: &str| -> Option<u32> {
            let mut found = None;
            for cap in regex::Regex::new(r"0x([0-9a-fA-F]+)")
                .unwrap()
                .captures_iter(t)
            {
                if let Ok(v) = u32::from_str_radix(&cap[1], 16) {
                    found = Some(v);
                }
            }
            found
        };

        if frozen {
            // Re-assemblable .entry: freeze the schedule as a [B:R:W:S] prefix, label
            // branch targets, declare .entry/.reg/.shared. `cubit asm` on this output
            // reproduces the exact schedule (scheduler bypassed via hand_sched).
            use std::collections::BTreeSet;
            let mut targets: BTreeSet<u32> = BTreeSet::new();
            for d in &decoded {
                if !d.unknown && is_branch(&d.text) {
                    if let Some(t) = last_hex(&d.text) {
                        targets.insert(t);
                    }
                }
            }
            let re_reg = regex::Regex::new(r"\bR(\d+)\b").unwrap();
            let mut max_reg = 1u32;
            for d in &decoded {
                for cap in re_reg.captures_iter(&d.text) {
                    if let Ok(n) = cap[1].parse::<u32>() {
                        if n != 255 && n > max_reg {
                            max_reg = n;
                        }
                    }
                }
            }
            let reg_decl = (max_reg + 4).min(255); // margin for .64/.128/WIDE register pairs

            // Parameters from the cubin's EIATTR (KPARAM_INFO) for a self-contained
            // .entry — so the text re-assembles WITHOUT --eiattr-from. Ordinal order;
            // size 8 -> u64, else u32 (matches the kernel's cbank param layout).
            let mut params = kparams.clone();
            params.sort_by_key(|(ord, _)| *ord);

            lines.push(format!(".entry {kernel_name}"));
            lines.push(format!("    .reg R0-R{reg_decl}"));
            for (i, (_ord, size)) in params.iter().enumerate() {
                let ty = if *size > 4 { "u64" } else { "u32" };
                lines.push(format!("    .param {ty} p{i}"));
            }
            if shared_size > 0 {
                lines.push(format!("    .shared smem[{shared_size}]"));
            }
            // mk19: duchy __syncwarp (EIATTR 0x28/0x29, elidowane do NOP)
            // jako dyrektywy — asm odtworzy rekordy 01476c0a i sloty bitmapy.
            if let Some(m) = eiattr_meta.get(kernel_name) {
                let proven = ghost_lanes_proven(&cubin.bytes, kernel_name, &m.merc_syncwarp);
                for &gl in &proven {
                    lines.push(format!("    .merc_syncwarp 0x{:x}", gl * 16));
                }
                // mk28: surowa lista site'ow __syncwarp (EIATTR 0x28/0x29) —
                // by asm mogl odtworzyc atrybuty 0x28/0x29 w .nv.info.K
                // (mkvmem: site 0x380 NIE jest duchem, ale stoi w 0x28).
                if !m.merc_cgsites.is_empty() {
                    let mut toks: Vec<String> = Vec::new();
                    for (i, &s) in m.merc_cgsites.iter().enumerate() {
                        let mask = m.merc_cgmasks.get(i).copied().unwrap_or(0xffff_ffff);
                        toks.push(format!("0x{s:x}:0x{mask:08x}"));
                    }
                    lines.push(format!("    .merc_cgsites {}", toks.join(" ")));
                }
            }
            for d in &decoded {
                let label = if targets.contains(&d.addr) {
                    format!("L_{:x}:  ", d.addr)
                } else {
                    "    ".to_string()
                };
                let cc_str = cubit::scheduling::format_control_code(
                    &cubit::scheduling::decode_control_code(d.sched as u32),
                );

                // Undecodable -> emit exact bytes.
                if d.unknown {
                    lines.push(format!("{label}__raw__0x{:032x} ;", d.code));
                    continue;
                }
                // Branches round-trip via label resolution (re-encode depends on addr).
                if is_branch(&d.text) {
                    let mut text = d.text.clone();
                    let mut relabeled = false;
                    if let Some(t) = last_hex(&text) {
                        let hexs = format!("0x{t:x}");
                        if let Some(pos) = text.rfind(&hexs) {
                            // Only ABSOLUTE targets get labels. BRX "-0xN" is a
                            // reg-relative byte offset: rewrite would fabricate
                            // "-L_x" (unparseable) and lose the value.
                            if !text[..pos].trim_end().ends_with('-') {
                                text.replace_range(pos..pos + hexs.len(), &format!("L_{t:x}"));
                                relabeled = true;
                            }
                        }
                    }
                    if relabeled {
                        // Labeled branches skipped the fidelity check below: verify the
                        // numeric form at the ORIGINAL addr; annotate residual bits
                        // (e.g. convergence-barrier IDs at [31:24], negative CALL
                        // sign-extension windows) so the frozen flow stays exact.
                        let ann = cubit::parse_sass(&d.text, d.addr)
                            .and_then(|insn| cubit::encoder::encode_instruction(&insn, &table))
                            .ok()
                            .and_then(|rc| rsd_annotation(d.code, rc))
                            .map(|a| format!(" {a}"))
                            .unwrap_or_default();
                        lines.push(format!("{label}[{cc_str}] {text}{ann} ;"));
                        continue;
                    }
                    // offset-form branch: fall through to the fidelity check below
                }
                // Non-branch: verify decode -> re-encode is byte-faithful (non-sched
                // bits). If a table gap makes it lossy, emit exact bytes as __raw__ so
                // the round-trip stays bit-perfect (scheduler/encoder bypassed).
                let reenc = cubit::parse_sass(&d.text, 0)
                    .and_then(|insn| cubit::encoder::encode_instruction(&insn, &table));
                match reenc {
                    Ok(rc) if (rc & !SCHED_MASK) == (d.code & !SCHED_MASK) => {
                        lines.push(format!("{label}[{cc_str}] {} ;", d.text));
                    }
                    Ok(rc) => {
                        // Lossy in bits the text never shows -> carry them inline:
                        // `!rsd[..]` keeps the instruction editable/readable while
                        // the encoder reproduces the exact word (overlay, applied
                        // last). __raw__ remains only for true non-decoding words.
                        let ann = rsd_annotation(d.code, rc).unwrap_or_default();
                        lines.push(format!("{label}[{cc_str}] {} {ann} ;", d.text));
                    }
                    Err(_) => {
                        eprintln!(
                            "  WARN [{kernel_name}] 0x{:04x}: decode->encode failed, \
                                   emitting __raw__: {:?}",
                            d.addr, d.text
                        );
                        lines.push(format!("{label}__raw__0x{:032x} ;", d.code));
                    }
                }
            }
            // Close the block: without .endentry a following .entry would silently
            // discard this kernel's body (parser used to lose every kernel but the
            // last in multi-kernel frozen outputs).
            lines.push(".endentry".to_string());
        } else {
            lines.push(format!("// {kernel_name}"));
            if shared_size > 0 {
                lines.push(format!("    .shared smem[{shared_size}]"));
            }
            for d in &decoded {
                if d.unknown {
                    lines.push(format!("  /*{:04x}*/  {}", d.addr, d.text));
                } else {
                    // Fidelity check: annotate with !rsd[..] when the text alone
                    // does not re-encode to the original non-sched bits.
                    let ann = cubit::parse_sass(&d.text, d.addr)
                        .and_then(|insn| cubit::encoder::encode_instruction(&insn, &table))
                        .ok()
                        .and_then(|rc| rsd_annotation(d.code, rc))
                        .map(|a| format!(" {a}"))
                        .unwrap_or_default();
                    // @sched BEFORE the ; so the re-encode path captures it.
                    lines.push(format!(
                        "  /*{:04x}*/  {}{} /* @sched 0x{:05x} */ ;",
                        d.addr, d.text, ann, d.sched
                    ));
                }
            }
        }
    }

    // mk41: marker ery zrodla capmerc (era-100 vs 103a roznia sie w
    // niektorych mini-klasach). Czytane z powrotem przez parser sass.
    let era_hdr = if frozen && cubin.sm.sm == 100 { ";; era=sm100\n" } else { "" };
    let out = format!("{era_hdr}{}\n", lines.join("\n"));
    if let Some(path) = output_path {
        std::fs::write(path, &out)?;
        println!("Written {} lines to {}", lines.len(), path.display());
    } else {
        print!("{out}");
    }
    Ok(())
}

fn cmd_roundtrip(
    table_path: &Path,
    _records_path: &PathBuf,
    inputs: &[PathBuf],
    allow_arch_mismatch: bool,
) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    println!(
        "Loaded {} keys, {} groups",
        table.num_keys(),
        table.num_groups()
    );

    let (mut grand_total, mut grand_match, mut grand_mismatch, mut grand_error) =
        (0u64, 0u64, 0u64, 0u64);

    for input in inputs {
        println!("\n{}", "=".repeat(60));
        println!("File: {}", input.display());
        if let Ok(cub) = cubit::elf::CubinFile::load(input) {
            check_arch(&table, cub.sm, input, allow_arch_mismatch)?;
        }
        let sass = load_cuobjdump_sass(input)?;
        let func_insns = parse_cuobjdump_output(&sass);

        let all_insns: Vec<_> = func_insns.values().flatten().collect();
        println!(
            "  {} instructions, {} functions",
            all_insns.len(),
            func_insns.len()
        );

        let (mut n_match, mut n_mismatch, mut n_error) = (0u64, 0u64, 0u64);
        let mut examples: Vec<String> = Vec::new();
        let example_cap = if std::env::var("CUBIT_RT_ALL").is_ok() {
            usize::MAX
        } else {
            3
        };

        for (addr, expected, asm) in &all_insns {
            match (|| -> Result<u128> {
                let insn = cubit::parse_sass(asm, *addr)?;
                cubit::encoder::encode_instruction(&insn, &table)
            })() {
                Ok(code) => {
                    if (code & !SCHED_MASK) == (expected & !SCHED_MASK) {
                        n_match += 1;
                    } else {
                        n_mismatch += 1;
                        if examples.len() < example_cap {
                            examples.push(format!(
                                "    0x{addr:04x}: {}\n      exp: 0x{:032x}\n      got: 0x{:032x}",
                                &asm[..asm.len().min(50)],
                                expected & !SCHED_MASK,
                                code & !SCHED_MASK
                            ));
                        }
                    }
                }
                Err(e) => {
                    n_error += 1;
                    if examples.len() < example_cap {
                        examples.push(format!("    ERR 0x{addr:04x}: {e}"));
                    }
                }
            }
        }

        let total = all_insns.len() as u64;
        let pct = if total > 0 {
            100.0 * n_match as f64 / total as f64
        } else {
            0.0
        };
        println!(
            "  Match: {n_match}/{total} ({pct:.1}%)  Mismatch: {n_mismatch}  Error: {n_error}"
        );
        for ex in &examples {
            println!("{ex}");
        }
        grand_total += total;
        grand_match += n_match;
        grand_mismatch += n_mismatch;
        grand_error += n_error;
    }

    println!("\n{}", "=".repeat(60));
    println!("ROUNDTRIP SUMMARY");
    println!("  Total: {grand_total}");
    println!(
        "  Match: {grand_match} ({:.1}%)",
        100.0 * grand_match as f64 / grand_total as f64
    );
    println!("  Mismatch: {grand_mismatch}");
    println!("  Error: {grand_error}");
    Ok(())
}

fn cmd_patch(
    table_path: &Path,
    _records_path: &PathBuf,
    input: &PathBuf,
    output: &PathBuf,
    allow_arch_mismatch: bool,
) -> Result<()> {
    use cubit::decoder::DecodeIndex;
    use cubit::elf::CubinFile;
    let table = IsaTable::load(table_path)?;
    let index = DecodeIndex::build(&table);
    let mut cubin = CubinFile::load(input.as_path())?;
    check_arch(&table, cubin.sm, input, allow_arch_mismatch)?;
    println!(
        "Input: {} (SM{}, {} text sections)",
        input.display(),
        cubin.sm.sm,
        cubin.text_sections.len()
    );

    for sec_idx in 0..cubin.text_sections.len() {
        let sec_name = cubin.text_sections[sec_idx].0.clone();
        let code_bytes = cubin.text_bytes(sec_idx)?.to_vec();
        let n_insns = code_bytes.len() / 16;
        let mut new_code = code_bytes.clone();
        let (mut encoded, mut kept) = (0u64, 0u64);

        for i in 0..n_insns {
            let offset = i * 16;
            let orig_code =
                u128::from_le_bytes(code_bytes[offset..offset + 16].try_into().unwrap());
            let addr = (i * 16) as u32;

            // Decode with our own decoder
            let decoded = match index.decode(orig_code, addr, &table) {
                Ok(d) => d,
                Err(_) => {
                    kept += 1;
                    continue;
                }
            };

            // Print to SASS text
            let sass_text = cubit::printer::to_sass(&decoded);

            // Re-encode from our own SASS text
            match (|| -> Result<u128> {
                let insn = cubit::parse_sass(&sass_text, addr)?;
                cubit::encoder::encode_instruction(&insn, &table)
            })() {
                Ok(code) => {
                    // Diagnostic: full decode->re-encode fidelity (lo64 AND hi64 operands),
                    // comparing everything except the scheduling word [121:105]. The normal
                    // patch path preserves orig_hi, which MASKS hi64 decode bugs (Rc, abs/neg,
                    // R-vs-UR). CUBIT_PATCH_DIAG surfaces them.
                    if std::env::var("CUBIT_PATCH_DIAG").is_ok() {
                        let sm = 0x1FFFF_u128 << (64 + 41);
                        if (code & !sm) != (orig_code & !sm) {
                            println!("  DIFF 0x{addr:04x}: {}", sass_text.trim_end_matches(" ;"));
                            println!("    key: {}::{}", decoded.key, decoded.mod_group);
                            println!("    exp: 0x{:032x}", orig_code & !sm);
                            println!("    got: 0x{:032x}", code & !sm);
                        }
                    }
                    // Preserve original scheduling (upper 32 bits) AND original hi data
                    // bits that the encoder doesn't know about (modifier flags, reuse, etc.)
                    let enc_lo = code as u64;
                    let orig_hi = (orig_code >> 64) as u64;
                    let final_code = ((orig_hi as u128) << 64) | enc_lo as u128;
                    let lo = final_code as u64;
                    let hi = (final_code >> 64) as u64;
                    new_code[offset..offset + 8].copy_from_slice(&lo.to_le_bytes());
                    new_code[offset + 8..offset + 16].copy_from_slice(&hi.to_le_bytes());
                    encoded += 1;
                }
                Err(_) => {
                    kept += 1;
                }
            }
        }
        cubin.patch_text(sec_idx, &new_code)?;
        println!("  {sec_name}: {encoded}/{n_insns} re-encoded ({kept} kept original)");
    }

    cubin.write(output.as_path())?;
    println!("Written: {}", output.display());
    let orig = std::fs::read(input)?;
    let new = std::fs::read(output)?;
    if orig == new {
        println!("PERFECT: byte-identical to input");
    } else {
        println!(
            "Differences: {} bytes",
            orig.iter().zip(new.iter()).filter(|(a, b)| a != b).count()
        );
    }
    Ok(())
}

// Keep the single-instruction variant for the non-directive code path (cmd_asm_build_elf).
// It is less accurate (no state) but safe as a fallback.
fn apply_dependency_ctrl(insn: &mut cubit::Instruction) {
    use cubit::ir::Operand;
    // Skip user-overridden control codes.
    if insn.ctrl.write_bar != 7 || insn.ctrl.wait_mask != 0 {
        return;
    }
    const NO_WRITE_OPS: &[&str] = &[
        "EXIT", "BRA", "NOP", "RET", "BREAK", "CONT", "KILL", "STG", "STS", "ST", "STL", "STGX",
        "MEMBAR", "BAR", "BARRIER", "FENCE",
    ];
    let op = insn.opcode.as_str();
    if insn.guard.is_none() && !NO_WRITE_OPS.contains(&op) {
        if let Some(first_op) = insn.operands.first() {
            if matches!(first_op, Operand::Reg { .. } | Operand::UReg { .. }) {
                insn.ctrl.write_bar = 1;
            }
        }
    }
}

/// Infer KernelMeta from encoded instruction bytes using the decoder.
fn infer_kernel_meta(name: &str, code_bytes: &[u8], table: &IsaTable) -> cubit::eiattr::KernelMeta {
    use cubit::decoder::DecodeIndex;
    use cubit::eiattr::KernelMeta;

    let index = DecodeIndex::build(table);
    let mut max_reg: u32 = 0;
    let mut exit_offsets: Vec<u32> = Vec::new();
    let mut barrier_seen = [false; 8];

    for (i, chunk) in code_bytes.chunks(16).enumerate() {
        if chunk.len() < 16 {
            break;
        }
        let lo = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let code = ((hi as u128) << 64) | lo as u128;
        let addr = (i * 16) as u32;

        if let Ok(decoded) = index.decode(code, addr, table) {
            // Extract register values from decoded fields
            for f in &decoded.fields {
                let e = f.extraction.as_str();
                if e == "reg" || e == "Reg" {
                    let r = f.value as u32;
                    if r < 255 && r > max_reg {
                        max_reg = r;
                    }
                }
            }
            // Detect EXIT by opcode
            if decoded.opcode == "EXIT" {
                exit_offsets.push(addr);
            }
            // Detect BSSY for barrier count
            if decoded.opcode == "BSSY" {
                for f in &decoded.fields {
                    if f.extraction == "barrier" || f.extraction == "imm" {
                        let b = f.value as usize;
                        if b < 8 && !barrier_seen[b] {
                            barrier_seen[b] = true;
                        }
                    }
                }
            }
        } else {
            // Fallback: read standard register positions directly
            for shift in [16u64, 24, 32, 64] {
                let r = if shift < 64 {
                    ((lo >> shift) & 0xFF) as u32
                } else {
                    (hi & 0xFF) as u32
                };
                if r < 255 && r > max_reg {
                    max_reg = r;
                }
            }
            // Check opcode for EXIT (0x7918) and BSSY (0x7945)
            let opcode = lo & 0x0FFF;
            if opcode == 0x0918 {
                exit_offsets.push(addr);
            }
            if opcode == 0x0945 {
                let b = ((lo >> 16) & 0x7) as usize;
                if b < 8 {
                    barrier_seen[b] = true;
                }
            }
        }
    }

    // regcount: SM120 allocates registers in blocks of 32
    let regcount = ((max_reg + 32) & !31).max(32);
    let num_barriers = barrier_seen.iter().filter(|&&x| x).count() as u8;

    KernelMeta {
        name: name.to_string(),
        regcount,
        frame_size: 0,
        min_stack_size: 0,
        maxreg_count: 0xFF,
        num_barriers,
        exit_offsets,
        // Without .param directives we have no parameter info; use 0 to avoid
        // misleading the driver. Callers using the directive format get correct
        // values from kernel_def_to_meta() instead.
        cbank_param_size: 0,
        params: Vec::new(),
        cuda_api_version: 0x83,
        shared_size: 0,
        merc_param_order: None,
        merc_param_write: 0,
        merc_stg_desc_pos: Vec::new(),
        merc_bar_pred: false,
        merc_dynldg: false,
        merc_bar_pos: Vec::new(),
        merc_stg_pos: Vec::new(),
        merc_xor: Vec::new(),
        merc_stg_off: Vec::new(),
        merc_stg_ser: Vec::new(),
        merc_stg_dreg: Vec::new(),
        merc_stg_dur: Vec::new(),
        merc_stg_guard: Vec::new(),
        merc_stg_areg: Vec::new(),
        merc_mma: Vec::new(),
        merc_f64imm: Vec::new(),
        merc_dfmaimm: Vec::new(),
        merc_pad_pos: Vec::new(),
        merc_param_uniform: 0,
        merc_param_regpath: 0,
        merc_param_width: Vec::new(),
        merc_param_loads: Vec::new(),
        merc_cbank_lane: None,
        merc_s2r_lanes: Vec::new(),
        merc_predmem: false,
        merc_guarded_bra: Vec::new(),
        merc_ldgconst: Vec::new(),
        merc_xor_reg: Vec::new(),
        merc_bar_args: Vec::new(),
        merc_s2r_sr: Vec::new(),
        merc_s2r_guard: Vec::new(),
        merc_s2r_dest: Vec::new(),
        merc_load_flags: Vec::new(),
        merc_atom_pool_hits: Vec::new(),
        merc_lop3_pdest: Vec::new(),
        merc_syncwarp: Vec::new(),
        merc_utca: Vec::new(),
        merc_atom_smem: Vec::new(),
        merc_atoms: Vec::new(),
        merc_ldgsts_pin: Vec::new(),
        merc_ldgsts_wait: Vec::new(),
        merc_ldgsts2: Vec::new(),
        merc_ldgsts2_waits: Vec::new(),
        merc_bra_selfloop: Vec::new(),
        merc_store2: Vec::new(),
        merc_mini2: Vec::new(),
        merc_stg_wsel: Vec::new(),
        merc_edge_ld: Vec::new(),
        merc_edge_maxur: 0,
        merc_edge_ldg: Vec::new(),
        merc_wwide_sites: Vec::new(),
        merc_cgsites: Vec::new(),
        merc_cgmasks: Vec::new(),
        has_call: false,
        has_bssy: false,
        merc_mc_exch: Vec::new(),
        merc_mc_arrive: Vec::new(),
        merc_mc_phase: Vec::new(),
        merc_mc_d1: Vec::new(),
        merc_mc_ushf_fin: Vec::new(),
        merc_mc_voteu_all: Vec::new(),
        merc_mc_mov400: Vec::new(),
        merc_mc_lea18: Vec::new(),
        merc_ws_minis: Vec::new(),
        merc_uvcount: Vec::new(),
        merc_umov_rr: Vec::new(),
        merc_ublkcp: Vec::new(),
        merc_plop3_tx: Vec::new(),
        merc_fence_async: Vec::new(),
        merc_ldgsts_b128: false,
        merc_s2ur_cga: Vec::new(),
        merc_bsync_close: Vec::new(),
        merc_hfma2_const: Vec::new(),
        merc_mc_ulea_x: Vec::new(),
        merc_mc_bra_np: Vec::new(),
        merc_mc_nodeless: Vec::new(),
        merc_param_load_dreg: Vec::new(),
        merc_bar_guard: Vec::new(),
        merc_isetp_ur: Vec::new(),
        merc_xsetp_pairs: Vec::new(),
        merc_usetp_minis: Vec::new(),
        merc_ulea_upco: Vec::new(),
        merc_era100: false,
        merc_redux: Vec::new(),
        merc_cbank358_dreg: None,
        merc_plop3_rec: Vec::new(),
        merc_plop3u_rec: Vec::new(),
        merc_uplop3_rec: Vec::new(),
        merc_dsetpimm_rec: Vec::new(),
        merc_cs2r_rec: Vec::new(),
        merc_lop3not_rec: Vec::new(),
        merc_redg2_rec: Vec::new(),
        merc_atomg2_rec: Vec::new(),
        merc_geo_rec: Vec::new(),
    }
}

/// mk14: dociagnij ghost __syncwarp z referencji --eiattr-from (EIATTR
/// 0x28/0x29 niewidoczne w tekscie sass; reszta merc-meta pochodzi ze skanu).
/// mk19b: filtr dowodowy duchow __syncwarp. EIATTR 0x28/0x29 listuje KAZDY
/// site __sync-family intrinsika (rowniez pochlonienty przez realna
/// instrukcje SHFL/REDUX/MATCH); rekord ghost 01476c0a powstaje tylko dla
/// podzbioru (ptxas eliduje WARPSYNC do NOP). Regula: liczba rekordow
/// 01476c0a w ORYGINALNEJ sekcji .nv.capmerc.text.<K> jest dowodem;
/// site'y parujemy po kolejnosci (lab: p_warpsync 1=1, q_bsync_pair 2=2;
/// p_shfl/k_shfl/p_redux/p_matchany: site bez rekordu -> 0 markerow).
fn ghost_lanes_proven(bytes: &[u8], kernel_name: &str, sites: &[u32]) -> Vec<u32> {
    if sites.is_empty() {
        return Vec::new();
    }
    let sec_name = format!(".nv.capmerc.text.{kernel_name}");
    let keep_all = || sites.to_vec();
    let Ok(sections) = elf64_sections(bytes) else { return keep_all() };
    let Some((_, off, size)) = sections.into_iter().find(|(n, _, _)| n == &sec_name)
    else {
        return keep_all(); // cubin bez capmerc (np. nasz build) — stara regula
    };
    let (off, size) = (off as usize, size as usize);
    if off + size > bytes.len() {
        return keep_all();
    }
    let n_ghost = match cubit::mercury::CapMerc::parse(&bytes[off..off + size], false) {
        Ok(cm) => cm.records.iter().filter(|r| r.tag == [0x01, 0x47, 0x6c, 0x0a]).count(),
        Err(_) => sites.len(),
    };
    let n = n_ghost.min(sites.len());
    if n != sites.len() {
        eprintln!(
            "  note [{kernel_name}]: EIATTR lists {} syncwarp site(s), capmerc proves {n_ghost} ghost record(s); marking first {n}",
            sites.len()
        );
    }
    sites.iter().copied().take(n).collect()
}

fn merge_syncwarp_from_reference(
    entries: &mut [cubit::elf_builder::KernelEntry],
    eiattr_path: Option<&std::path::Path>,
) {
    let Some(p) = eiattr_path else { return };
    let Ok(bytes) = std::fs::read(p) else { return };
    let Ok(refmeta) = cubit::eiattr::parse_cubin_metadata(&bytes) else { return };
    for e in entries.iter_mut() {
        if let Some(rm) = refmeta.get(&e.name) {
            if !rm.merc_syncwarp.is_empty() && e.meta.merc_syncwarp.is_empty() {
                // mk19b: tylko site'y z dowodem w oryginalnym capmerc.
                e.meta.merc_syncwarp = ghost_lanes_proven(&bytes, &e.name, &rm.merc_syncwarp);
            }
        }
    }
}

fn cmd_asm(
    table_path: &Path,
    sass_path: &PathBuf,
    template_path: Option<&std::path::Path>,
    eiattr_path: Option<&std::path::Path>,
    output_path: &PathBuf,
    only_kernel: Option<&str>,
    mercury_stub_path: Option<&std::path::Path>,
) -> Result<()> {
    use cubit::elf::CubinFile;

    let table = IsaTable::load(table_path)?;
    let sass_text = std::fs::read_to_string(sass_path)
        .with_context(|| format!("cannot read {}", sass_path.display()))?;

    let mercury_stub = if let Some(p) = mercury_stub_path {
        Some(
            std::fs::read(p)
                .with_context(|| format!("cannot read Mercury stub {}", p.display()))?,
        )
    } else {
        None
    };

    // Detect format: .entry/.endentry directives vs /*addr*/ cubit format
    let is_directive_format = sass_text
        .lines()
        .any(|l| l.trim().starts_with(".entry") || l.trim().starts_with(".func"));

    if is_directive_format {
        return cmd_asm_directive_format(
            &table,
            &sass_text,
            template_path,
            eiattr_path,
            output_path,
            only_kernel,
            mercury_stub.as_deref(),
        );
    }

    let parsed = parse_sass_file_full(&sass_text);
    let sass_kernels = parsed.kernels;
    let shared_sizes = parsed.shared_sizes;

    // ── no-template path: use ELF builder with optional EIATTR reference ─────
    if template_path.is_none() {
        return cmd_asm_build_elf(
            &table,
            &sass_text,
            &sass_kernels,
            &shared_sizes,
            eiattr_path,
            output_path,
            only_kernel,
            mercury_stub.as_deref(),
        );
    }

    let mut cubin = CubinFile::load(template_path.unwrap())?;

    println!(
        "Template: SM{}, {} sections",
        cubin.sm.sm,
        cubin.text_sections.len()
    );
    println!(
        "SASS: {} chars, kernels: {:?}",
        sass_text.len(),
        sass_kernels.keys().collect::<Vec<_>>()
    );

    let (mut total_enc, mut total_fail) = (0u64, 0u64);
    let mut total_insns = 0u64;

    for sec_idx in 0..cubin.text_sections.len() {
        let sec_name = cubin.text_sections[sec_idx].0.clone();
        let kernel_name = sec_name
            .strip_prefix(".text.")
            .unwrap_or(&sec_name)
            .to_string();

        if let Some(only) = only_kernel {
            if kernel_name != only {
                continue;
            }
        }

        let sass_insns = match sass_kernels.get(&kernel_name) {
            Some(v) => v,
            None => {
                println!("  {sec_name}: not in sass file — skipping");
                continue;
            }
        };

        let orig_bytes = cubin.text_bytes(sec_idx)?.to_vec();
        let mut new_code = orig_bytes.clone();
        let (mut encoded, mut failed, mut skipped) = (0u64, 0u64, 0u64);

        for (addr, asm) in sass_insns {
            let offset = *addr as usize;
            if offset + 16 > new_code.len() {
                skipped += 1;
                continue;
            }

            let orig_lo = u64::from_le_bytes(orig_bytes[offset..offset + 8].try_into().unwrap());
            let orig_hi =
                u64::from_le_bytes(orig_bytes[offset + 8..offset + 16].try_into().unwrap());
            let _orig_code = ((orig_hi as u128) << 64) | orig_lo as u128;

            match (|| -> Result<u128> {
                let insn = cubit::parse_sass(asm, *addr)?;
                cubit::encoder::encode_instruction(&insn, &table)
            })() {
                Ok(code) => {
                    let enc_lo = code as u64;
                    new_code[offset..offset + 8].copy_from_slice(&enc_lo.to_le_bytes());
                    encoded += 1;
                }
                Err(e) => {
                    failed += 1;
                    if failed <= 5 {
                        eprintln!("  WARN 0x{addr:04x} [{kernel_name}]: {e}  |  src: {asm:?}");
                    }
                }
            }
        }

        cubin.patch_text(sec_idx, &new_code)?;
        let total = sass_insns.len() as u64;
        total_enc += encoded;
        total_fail += failed;
        total_insns += total;
        println!("  {sec_name}: {encoded}/{total} encoded, {failed} failed, {skipped} skipped");
    }

    cubin.write(output_path.as_path())?;

    let orig = std::fs::read(template_path.unwrap())?;
    let new = std::fs::read(output_path)?;
    let diff = orig.iter().zip(new.iter()).filter(|(a, b)| a != b).count();

    println!("\nWritten: {}", output_path.display());
    println!("Total:   {total_enc}/{total_insns} encoded ({total_fail} failed)");
    if diff == 0 {
        println!("PERFECT: byte-identical to template!");
    } else {
        println!("Diff vs template: {diff} bytes changed");
    }
    Ok(())
}

fn cmd_asm_build_elf(
    table: &IsaTable,
    _sass_text: &str,
    sass_kernels: &std::collections::HashMap<String, Vec<(u32, String)>>,
    shared_sizes: &std::collections::HashMap<String, u32>,
    eiattr_path: Option<&std::path::Path>,
    output_path: &PathBuf,
    only_kernel: Option<&str>,
    mercury_stub_data: Option<&[u8]>,
) -> Result<()> {
    use cubit::elf_builder::KernelEntry;

    let mut entries: Vec<KernelEntry> = Vec::new();
    let mut total_enc = 0u64;
    let mut total_fail = 0u64;
    let mut total_insns = 0u64;
    let mut tensor_class_kernels = false;

    for (kernel_name, insns) in sass_kernels {
        if let Some(only) = only_kernel {
            if kernel_name != only {
                continue;
            }
        }

        // Encode all instructions into a flat byte buffer
        let text_size = insns
            .iter()
            .map(|(addr, _)| *addr as usize + 16)
            .max()
            .unwrap_or(0);
        let mut code_bytes = vec![0u8; text_size];

        let (mut enc, mut fail) = (0u64, 0u64);
        for (addr, asm) in insns {
            // Handle raw instruction bytes (__raw__0xNNNN)
            if let Some(raw_hex) = asm.strip_prefix("__raw__0x") {
                if let Ok(code) = u128::from_str_radix(raw_hex, 16) {
                    let off = *addr as usize;
                    if off + 16 <= code_bytes.len() {
                        let lo = code as u64;
                        let hi = (code >> 64) as u64;
                        code_bytes[off..off + 8].copy_from_slice(&lo.to_le_bytes());
                        code_bytes[off + 8..off + 16].copy_from_slice(&hi.to_le_bytes());
                        enc += 1;
                    }
                }
                continue;
            }

            // Parse @sched annotation if present (from cubit disassemble output)
            let sched_override: Option<u64> = if let Some(idx) = asm.find("/* @sched 0x") {
                let start = idx + 12;
                let end = asm[start..]
                    .find(' ')
                    .map(|e| start + e)
                    .unwrap_or(asm.len());
                let end = asm[start..].find("*/").map(|e| start + e).unwrap_or(end);
                u64::from_str_radix(asm[start..end].trim(), 16).ok()
            } else {
                None
            };

            // Strip @sched comment before parsing
            let clean_asm = if let Some(idx) = asm.find("/* @sched") {
                asm[..idx].trim()
            } else {
                asm.as_str()
            };

            match (|| -> Result<u128> {
                let mut insn = cubit::parse_sass(clean_asm, *addr)?;
                if sched_override.is_none() {
                    apply_dependency_ctrl(&mut insn);
                }
                cubit::encoder::encode_instruction(&insn, table)
            })() {
                Ok(code) => {
                    let off = *addr as usize;
                    if off + 16 <= code_bytes.len() {
                        let lo = code as u64;
                        let mut hi = (code >> 64) as u64;
                        // Apply @sched override if present
                        if let Some(sched) = sched_override {
                            let sched_mask: u64 = 0x1FFFF << 41;
                            hi = (hi & !sched_mask) | ((sched & 0x1FFFF) << 41);
                        }
                        code_bytes[off..off + 8].copy_from_slice(&lo.to_le_bytes());
                        code_bytes[off + 8..off + 16].copy_from_slice(&hi.to_le_bytes());
                        enc += 1;
                    }
                }
                Err(e) => {
                    fail += 1;
                    if fail <= 5 {
                        eprintln!(
                            "  WARN 0x{addr:04x} [{kernel_name}]: {e}  |  src: {clean_asm:?}"
                        );
                    }
                }
            }
        }

        total_enc += enc;
        total_fail += fail;
        total_insns += insns.len() as u64;
        println!(
            "  {kernel_name}: {enc}/{} encoded ({fail} failed)",
            insns.len()
        );

        let mut meta = infer_kernel_meta(kernel_name, &code_bytes, table);

        // Set shared_size from .shared smem[N] directive if present
        if let Some(&sz) = shared_sizes.get(kernel_name) {
            meta.shared_size = sz;
            eprintln!("  {kernel_name}: shared_size={sz} from .shared directive");
        }

        // Infer parameters from constant bank accesses in SASS text.
        // Parameters live at c[0x0][0x380..], so scan for c[0x0][0xNNN] where NNN >= 0x380.
        {
            use std::collections::BTreeSet;
            let re_cbank = regex::Regex::new(r"c\[0x0\]\[0x([0-9a-fA-F]+)\]").unwrap();
            let re_desc = regex::Regex::new(r"desc\[UR(\d+)\]").unwrap();
            let re_ldcu64 =
                regex::Regex::new(r"LDCU\.64\s+UR(\d+),\s*c\[0x0\]\[0x([0-9a-fA-F]+)\]").unwrap();

            let mut cbank_offsets: BTreeSet<u32> = BTreeSet::new();
            let mut desc_urs: BTreeSet<u32> = BTreeSet::new();
            let mut ldcu64_map: std::collections::HashMap<u32, u32> =
                std::collections::HashMap::new();

            for (_addr, asm) in insns {
                let clean = if let Some(idx) = asm.find("/* @sched") {
                    &asm[..idx]
                } else {
                    asm.as_str()
                };
                for cap in re_cbank.captures_iter(clean) {
                    if let Ok(off) = u32::from_str_radix(&cap[1], 16) {
                        if off >= 0x380 {
                            cbank_offsets.insert(off);
                        }
                    }
                }
                for cap in re_desc.captures_iter(clean) {
                    if let Ok(ur) = cap[1].parse::<u32>() {
                        desc_urs.insert(ur);
                    }
                }
                for cap in re_ldcu64.captures_iter(clean) {
                    if let (Ok(ur), Ok(off)) =
                        (cap[1].parse::<u32>(), u32::from_str_radix(&cap[2], 16))
                    {
                        if off >= 0x380 {
                            ldcu64_map.insert(ur, off);
                        }
                    }
                }
            }

            // Offsets loaded via LDCU.64 into UR regs that appear in desc[URn] are pointers
            let mut pointer_offsets: BTreeSet<u32> = BTreeSet::new();
            for (&ur, &off) in &ldcu64_map {
                if desc_urs.contains(&ur) {
                    pointer_offsets.insert(off);
                }
            }

            // Rozszerzenie (fs-lab 2026-08-05): param wskaznikowy moze isc przez
            // LDCU.64 do UR i NZ stac w desc[URn] — wartosc laduje w R przez
            // IADD3/IMAD.X i zula dopiero w desc[URx][Ry.64]. Sledz prosty
            // przeplyw UR->R (alias), by poprawnie klasyfikowac taki slot jako
            // 8B-wskaznik i ustawic merc_param_uniform.
            let re_ldc64 = regex::Regex::new(
                r"LDC\.64\s+R(\d+),\s*c\[0x0\]\[0x([0-9a-fA-F]+)\]",
            )
            .unwrap();
            let re_ldcu_any = regex::Regex::new(
                r"LDCU(?:\.64|\.128|\.U8|\.U16)?\s+UR(\d+),\s*c\[0x0\]\[0x([0-9a-fA-F]+)\]",
            )
            .unwrap();
            let re_alu = regex::Regex::new(
                r"^(?:\s*\/\*[0-9a-f]+\*\/\s*)?(?:@!?U?P\w+\s+)?(?:MOV|IMAD(?:\.[A-Z0-9]+)*|IADD3(?:\.[A-Z0-9]+)*|LEA(?:\.[A-Z0-9]+)*|SHF(?:\.[A-Z0-9]+)*|UIADD3(?:\.[A-Z0-9]+)*|UMOV)\s+((?:U?R)\d+)\s*,\s*(.*?)(?:;|\s*/\*|$)",
            )
            .unwrap();
            let re_reg = regex::Regex::new(r"(?:U?R)\d+").unwrap();
            // regname -> cbank off
            let mut reg_off: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            let mut unif_at: std::collections::HashMap<u32, bool> =
                std::collections::HashMap::new();
            let mut width_at: std::collections::HashMap<u32, u8> =
                std::collections::HashMap::new();
            for (_addr, asm) in insns {
                let clean = if let Some(idx) = asm.find("/* @sched") {
                    &asm[..idx]
                } else {
                    asm.as_str()
                };
                for cap in re_ldcu_any.captures_iter(clean) {
                    if let (Ok(ur), Ok(off)) =
                        (cap[1].parse::<u32>(), u32::from_str_radix(&cap[2], 16))
                    {
                        if off >= 0x380 {
                            let w: u8 = if clean.contains(".128") {
                                16
                            } else if clean.contains(".64") {
                                8
                            } else if clean.contains(".U16") {
                                2
                            } else if clean.contains(".U8") {
                                1
                            } else {
                                4
                            };
                            reg_off.insert(format!("UR{}", ur), off);
                            if w >= 8 {
                                reg_off.insert(format!("UR{}", ur + 1), off);
                            }
                            unif_at.insert(off, true);
                            width_at
                                .entry(off)
                                .and_modify(|cw| *cw = (*cw).max(w))
                                .or_insert(w);
                        }
                    }
                }
                for cap in re_ldc64.captures_iter(clean) {
                    if let (Ok(r), Ok(off)) =
                        (cap[1].parse::<u32>(), u32::from_str_radix(&cap[2], 16))
                    {
                        if off >= 0x380 {
                            reg_off.insert(format!("R{}", r), off);
                            reg_off.insert(format!("R{}", r + 1), off);
                            unif_at.insert(off, false);
                            width_at.entry(off).and_modify(|cw| *cw = (*cw).max(8)).or_insert(8);
                        }
                    }
                }
            }
            // fixpoint: propagacja wartosci przez lane ALU/MOV
            for _ in 0..8 {
                let mut changed = false;
                for (_addr, asm) in insns {
                    let clean = if let Some(idx) = asm.find("/* @sched") {
                        &asm[..idx]
                    } else {
                        asm.as_str()
                    };
                    for cap in re_alu.captures_iter(clean) {
                        let dest = cap[1].to_string();
                        let rest = &cap[2];
                        let mut src_off = None;
                        for rm in re_reg.find_iter(rest) {
                            if let Some(&off) = reg_off.get(rm.as_str()) {
                                src_off = Some(off);
                                break;
                            }
                        }
                        if let Some(off) = src_off {
                            match reg_off.get(&dest) {
                                Some(&cur) if cur == off => {}
                                _ => {
                                    reg_off.insert(dest, off);
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
            // uzycie jako adres: kazdy token [R.. w bracketach instrukcji pamieci
            for (_addr, asm) in insns {
                let clean = if let Some(idx) = asm.find("/* @sched") {
                    &asm[..idx]
                } else {
                    asm.as_str()
                };
                let op_head = clean
                    .split_whitespace()
                    .find(|t| !t.starts_with('@'))
                    .unwrap_or("");
                let base0 = op_head.split('.').next().unwrap_or("");
                if !matches!(
                    base0,
                    "LDG" | "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "LDGSTS"
                ) {
                    continue;
                }
                // tylko brackety adresowe
                for bm in regex::Regex::new(r"\[([^\]]+)\]").unwrap().captures_iter(clean) {
                    for rm in re_reg.find_iter(&bm[1]) {
                        if let Some(&off) = reg_off.get(rm.as_str()) {
                            pointer_offsets.insert(off);
                        }
                    }
                }
            }

            if !cbank_offsets.is_empty() {
                let offsets: Vec<u32> = cbank_offsets.iter().copied().collect();
                let mut params: Vec<cubit::eiattr::KernelParam> = Vec::new();
                let base = 0x380u32;
                let mut i = 0;
                while i < offsets.len() {
                    let start = offsets[i];
                    let is_desc_ptr = pointer_offsets.contains(&start);
                    let is_ldc64 = insns.iter().any(|(_a, asm)| {
                        let clean = if let Some(idx) = asm.find("/* @sched") {
                            &asm[..idx]
                        } else {
                            asm.as_str()
                        };
                        clean.contains(&format!("c[0x0][0x{:x}]", start))
                            && clean.contains("LDC.64")
                    });
                    let is_ldcu64_nondesc =
                        ldcu64_map.values().any(|&v| v == start) && !is_desc_ptr;

                    if is_desc_ptr || is_ldc64 {
                        // 8-byte pointer or 64-bit value
                        if i + 1 < offsets.len() && offsets[i + 1] == start + 4 {
                            i += 2;
                        } else {
                            i += 1;
                        }
                        params.push(cubit::eiattr::KernelParam {
                            index: 0,
                            ordinal: params.len() as u32,
                            offset: start - base,
                            size: 8,
                        });
                    } else if is_ldcu64_nondesc {
                        // LDCU.64 but NOT desc[] -> two consecutive 4-byte scalars
                        let off1 = start - base;
                        params.push(cubit::eiattr::KernelParam {
                            index: 0,
                            ordinal: params.len() as u32,
                            offset: off1,
                            size: 4,
                        });
                        params.push(cubit::eiattr::KernelParam {
                            index: 0,
                            ordinal: params.len() as u32,
                            offset: off1 + 4,
                            size: 4,
                        });
                        i += 1;
                    } else {
                        // 4-byte scalar
                        params.push(cubit::eiattr::KernelParam {
                            index: 0,
                            ordinal: params.len() as u32,
                            offset: start - base,
                            size: 4,
                        });
                        i += 1;
                    }
                }

                let total = params.iter().map(|p| p.offset + p.size).max().unwrap_or(0);
                meta.cbank_param_size = ((total + 7) & !7) as u16;
                meta.params = params;
                // Mercury param-load metadata (variant/b6-width deskryptorow 0222):
                // z alias-flow reg_off/unif_at/width_at zebranymi wyzej.
                let mut punif = 0u32;
                let mut preg = 0u32;
                let mut pwid: Vec<u8> = Vec::new();
                for p in &meta.params {
                    let off = 0x380 + p.offset;
                    let pi = (off - 0x380) / 8;
                    if (pi as usize) >= pwid.len() {
                        pwid.resize(pi as usize + 1, 0);
                    }
                    match unif_at.get(&off) {
                        Some(true) => {
                            punif |= 1u32 << pi;
                            pwid[pi as usize] = *width_at.get(&off).unwrap_or(&8);
                        }
                        Some(false) => {
                            preg |= 1u32 << pi;
                            pwid[pi as usize] = *width_at.get(&off).unwrap_or(&8);
                        }
                        None => {}
                    }
                }
                meta.merc_param_uniform = punif;
                meta.merc_param_regpath = preg;
                meta.merc_param_width = pwid;
                eprintln!(
                    "  {kernel_name}: inferred {} params, cbank_param_size=0x{:x}",
                    meta.params.len(),
                    meta.cbank_param_size
                );
            }

            // Mercury lane positions + dynldg z tekstu sass (fs-lab 2026-08-05):
            // BAR/STG positions po indeksach instrukcji; dynldg: taint S2R ->
            // lane ALU/MOV -> LDG z takim rejestrem w adresie (regula z
            // mercv3/mk_gold.py).
            {
                let mut bar_pos: Vec<u32> = Vec::new();
                let mut stg_pos: Vec<u32> = Vec::new();
                let mut bar_pred = false;
                let mut bar_args: Vec<(u32, u32)> = Vec::new();
                let re_s2r = regex::Regex::new(r"S2R\s+").unwrap();
                let re_regw = regex::Regex::new(r"^(?:U?R)\d+$").unwrap();
                let mut lastw: std::collections::HashMap<String, &str> =
                    std::collections::HashMap::new();
                let mut dynldg = false;
                let re_alu2 = regex::Regex::new(
                    r"^(?:\s*\/\*[0-9a-f]+\*\/\s*)?(?:@!?U?P\w+\s+)?([A-Z][A-Za-z0-9.]*)\s*([^;]*?);?\s*$",
                )
                .unwrap();
                let mut xor_lanes: Vec<(u32, u32, u32, u32, u8)> = Vec::new();
                let mut xor_reg_l: Vec<(u32, u32, u32, u32, u8)> = Vec::new();
                let mut stg_off: Vec<i32> = Vec::new();
                let mut stg_dreg: Vec<u8> = Vec::new();
                let mut stg_dur: Vec<u8> = Vec::new();
                let mut stg_guard: Vec<u8> = Vec::new();
                let mut stg_areg: Vec<u8> = Vec::new();
                for (ii, (_addr, asm)) in insns.iter().enumerate() {
                    let clean = if let Some(idx) = asm.find("/* @sched") {
                        &asm[..idx]
                    } else {
                        asm.as_str()
                    };
                    let clean = clean.trim();
                    let m = re_alu2.captures_iter(clean).next();
                    let (base, rest) = match &m {
                        Some(c) => (c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str()),
                        None => continue,
                    };
                    // 0229: LOP3.LUT Rd, Rs, imm, RZ, 0x3c (fs6-lab) — lane bez
                    // bitu bitmapy + pelny rekord; guard polarity -> b4.
                    if base.split('.').next() == Some("LOP3") {
                        let parts5: Vec<&str> =
                            rest.split(',').map(|x| x.trim().trim_end_matches(';')).collect();
                        if parts5.len() >= 5
                            && parts5[4] == "0x3c"
                            && parts5[3].starts_with("RZ")
                            && parts5.len() >= 5
                        {
                            let preg = |t: &str| -> Option<u32> {
                                t.strip_prefix('R').and_then(|d| {
                                    if d.chars().all(|c| c.is_ascii_digit()) {
                                        d.parse::<u32>().ok()
                                    } else {
                                        None
                                    }
                                })
                            };
                            let body_x = match clean.find("*/") {
                                Some(k) => clean[k + 2..].trim_start(),
                                None => clean,
                            };
                            let guard_x: u8 = if body_x.starts_with("@!") {
                                2
                            } else if body_x.starts_with('@') {
                                1
                            } else {
                                0
                            };
                            if let Some(ih) =
                                parts5[2].strip_prefix("0x").and_then(|h| u32::from_str_radix(h, 16).ok())
                            {
                                if let (Some(dreg), Some(sreg)) = (preg(parts5[0]), preg(parts5[1])) {
                                    xor_lanes.push((ii as u32, dreg, sreg, ih, guard_x));
                                }
                            } else if let (Some(dreg), Some(sa), Some(sb)) =
                                (preg(parts5[0]), preg(parts5[1]), preg(parts5[2]))
                            {
                                // mk13: forma rejestrowa 0x3c (3 rejestry)
                                // -> rekord 0129 (16B); lane bez bitu.
                                xor_reg_l.push((ii as u32, dreg, sa, sb, guard_x));
                            }
                        }
                    }
                    let base0 = base.split('.').next().unwrap_or(base);
                    if base0 == "BAR" {
                        bar_pos.push(ii as u32);
                        if clean.starts_with('@') {
                            bar_pred = true;
                        }
                        // mk13: named-barrier args `BAR.SYNC... 0x1, 0x20`
                        // -> (id, cnt); szablon bezargumentowy -> (0, 0).
                        let pa = |t: &str| -> u32 {
                            let t = t.trim().trim_end_matches(';');
                            if let Some(h) = t.strip_prefix("0x") {
                                u32::from_str_radix(h, 16).unwrap_or(0)
                            } else {
                                t.parse::<u32>().unwrap_or(0)
                            }
                        };
                        let mut it = rest.split(',');
                        let bid = it.next().map(pa).unwrap_or(0);
                        let bcnt = it.next().map(pa).unwrap_or(0);
                        bar_args.push((bid, bcnt));
                    }
                    if base0 == "STG" {
                        stg_pos.push(ii as u32);
                        // mk41: imm z ostatniego '[' — dowolna szerokosc + '+-0x..'
                        let off: i32 = match clean.rfind('[') {
                            Some(lb) => {
                                let rb = clean[lb..].find(']').map(|k| lb + k).unwrap_or(clean.len());
                                let inner = &clean[lb + 1..rb];
                                match inner.rfind('+') {
                                    Some(pl) => {
                                        let tail = inner[pl + 1..].trim();
                                        if tail.starts_with('U') {
                                            0
                                        } else {
                                            let neg = tail.starts_with('-');
                                            let tt = tail.trim_start_matches('-');
                                            i32::from_str_radix(
                                                tt.trim_start_matches("0x"),
                                                if tt.starts_with("0x") { 16 } else { 10 },
                                            )
                                            .map(|v| if neg { -v } else { v })
                                            .unwrap_or(0)
                                        }
                                    }
                                    None => 0,
                                }
                            }
                            None => 0,
                        };
                        stg_off.push(off);
                        let tail = clean.trim_end_matches([';', ' ']);
                        let last = tail.rsplit(',').next().unwrap_or("").trim();
                        let d: u8 = if last == "RZ" {
                            255
                        } else {
                            last
                                .strip_prefix('R')
                                .filter(|s| !s.is_empty() && s.bytes().all(|b2| b2.is_ascii_digit()))
                                .and_then(|s| s.parse::<u32>().ok())
                                .map(|v| v.min(255) as u8)
                                .unwrap_or(255)
                        };
                        stg_dreg.push(d);
                        // mk32: niski rejestr pary adresowej [R<num>.64]
                        // (ost. wystapienie "[R" przed koncem operandow).
                        let a: u8 = {
                            let mut out = 255u8;
                            let mut pos = 0usize;
                            while let Some(k) = clean[pos..].find("[R") {
                                let k2 = pos + k + 2;
                                let digits: String = clean[k2..]
                                    .chars()
                                    .take_while(|c2| c2.is_ascii_digit())
                                    .collect();
                                if !digits.is_empty() {
                                    if let Ok(v) = digits.parse::<u32>() {
                                        out = v.min(255) as u8;
                                    }
                                }
                                pos = k2;
                            }
                            out
                        };
                        stg_areg.push(a);
                        let dur8: u8 = clean
                            .find("desc[UR")
                            .and_then(|k| {
                                clean[k + 7..]
                                    .chars()
                                    .take_while(|c2| c2.is_ascii_digit())
                                    .collect::<String>()
                                    .parse::<u32>()
                                    .ok()
                            })
                            .map(|v| v.min(255) as u8)
                            .unwrap_or(4);
                        stg_dur.push(dur8);
                        let tt8 = clean.trim_start();
                        let g8: u8 = {
                            if !tt8.starts_with('@') {
                                0xf8
                            } else {
                                let neg = tt8.starts_with("@!");
                                let rest = tt8[1 + (neg as usize)..].trim_start();
                                if rest.starts_with("PT") || rest.starts_with("UPT") {
                                    0xf8
                                } else {
                                    let unif = rest.starts_with('U');
                                    let r2 = if unif { &rest[1..] } else { rest };
                                    let r3 = if let Some(x) = r2.strip_prefix('P') { x } else { r2 };
                                    let digits: String =
                                        r3.chars().take_while(|c| c.is_ascii_digit()).collect();
                                    let idx = digits.parse::<u8>().unwrap_or(0).min(7);
                                    (idx << 3) | if unif { 2 } else { 0 } | (neg as u8)
                                }
                            }
                        };
                        stg_guard.push(g8);
                    }
                    let parts: Vec<String> = rest
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                    let outreg = parts.first().cloned().unwrap_or_default();
                    let readers: Vec<&str> = regex::Regex::new(r"(?:U?R)\d+")
                        .unwrap()
                        .find_iter(rest)
                        .map(|mm| mm.as_str())
                        .collect();
                    if base0 == "LDG" {
                        for rn in &readers[1..] {
                            if lastw.get(*rn) == Some(&"MID") {
                                dynldg = true;
                            }
                        }
                    }
                    if re_regw.is_match(&outreg) {
                        if re_s2r.is_match(clean) {
                            lastw.insert(outreg.clone(), "MID");
                        } else if readers.iter().skip(1).any(|rn| lastw.get(*rn) == Some(&"MID")) {
                            lastw.insert(outreg.clone(), "MID");
                        } else {
                            lastw.insert(outreg.clone(), base0);
                        }
                    }
                }
                if !bar_pos.is_empty() && meta.num_barriers == 0 {
                    meta.num_barriers = bar_pos.len() as u8;
                }
                if !bar_pos.is_empty() {
                    meta.merc_bar_pos = bar_pos;
                    meta.merc_bar_args = bar_args;
                }
                if !stg_pos.is_empty() {
                    meta.merc_stg_pos = stg_pos;
                }
                if bar_pred {
                    meta.merc_bar_pred = true;
                }
                if dynldg {
                    meta.merc_dynldg = true;
                }
                if !xor_lanes.is_empty() {
                    meta.merc_xor = xor_lanes;
                }
                if !xor_reg_l.is_empty() {
                    meta.merc_xor_reg = xor_reg_l;
                }
                if !stg_off.is_empty() {
                    meta.merc_stg_off = stg_off;
                }
                if !stg_dreg.is_empty() {
                    meta.merc_stg_dreg = stg_dreg;
                }
                if !stg_areg.is_empty() {
                    meta.merc_stg_areg = stg_areg;
                }
                if !stg_dur.is_empty() {
                    meta.merc_stg_dur = stg_dur;
                }
                if !stg_guard.is_empty() {
                    meta.merc_stg_guard = stg_guard;
                }

                // mk10c: rekordy-lane dla strumienia capmerc (lustro
                // mercv3/mk_gold.py v7 i sass_file::merc_param_scan):
                // - loads: (lane, REL(off-0x380), unif01, widthB, guard)
                //   per LDC/LDCU param-window (mk19: dziedzina BAJTOWA,
                //   dowod join2/join3 19666/19666); - cbank_lane: LDCU.64
                //   c[0x358];
                // - s2r_lanes; - predmem (@P na operacji pamieci);
                // - stg_desc_pos: binding STG -> indeks puli (pi, mech)
                //   wide-loadow.
                {
                    let re_load = regex::Regex::new(
                        r"^(?:@!?U?P\w+\s+)?(LDCU?)(\.64|\.128|\.U8|\.U16)?\s+(U?R\d+),\s*c\[0x0\]\[0x([0-9a-fA-F]+)\]",
                    )
                    .unwrap();
                    let re_s2r2 = regex::Regex::new(r"(?:^| )S2R\s").unwrap();
                    let re_brak = regex::Regex::new(r"\[([A-Z0-9]+)(?:\.\w+)?[^\]]*\]").unwrap();
                    let re_tok = regex::Regex::new(r"^(?:@!?U?P\w+\s+)?([A-Z][A-Za-z0-9.]*)\s*(.*)$").unwrap();
                    let alias_ops = [
                        "MOV", "IMAD", "IADD3", "LEA", "SHF", "SEL", "UIADD3", "UMOV",
                        "IMNMX", "PRMT", "IABS", "SHFL",
                    ];
                    let mem_ops = [
                        "LDG", "STG", "ATOMG", "ATOMS", "RED", "REDG", "LDS", "STS", "LD",
                        "ST", "LDGSTS",
                    ];
                    let mut loads: Vec<(u32, u32, u8, u8, u8)> = Vec::new();
                    let mut s2r_lanes: Vec<u32> = Vec::new();
                    let mut cbank_lane: Option<u32> = None;
                    let mut predmem = false;
                    let mut pool: Vec<(u32, u8)> = Vec::new();
                    let mut regpool: std::collections::HashMap<String, u32> =
                        std::collections::HashMap::new();
                    let mut stg_pos2: Vec<u32> = Vec::new();
                    let mut guarded_bra: Vec<u32> = Vec::new();
                    let mut lop3_pdest: Vec<u32> = Vec::new();
                    let mut s2r_sr: Vec<u8> = Vec::new();
                    let mut s2r_dest: Vec<u32> = Vec::new();
                    let mut call_lanes: Vec<u32> = Vec::new();
                    let mut load_flags: Vec<u8> = Vec::new();
                    let mut atom_pool_hits: std::collections::BTreeSet<(u32, u8)> =
                        std::collections::BTreeSet::new();
                    let mut ldgconst: Vec<(u32, u32)> = Vec::new();
                    let mut atoms_scan: Vec<(u32, u8, u8, u8, u8, u8, u8, u8)> = Vec::new();
                    let mut redg2_scan: Vec<(u32, [u8; 32])> = Vec::new();
                    let mut atomg2_scan: Vec<(u32, [u8; 32])> = Vec::new();
                    // mk35: lustra sass_file::merc_mk35_scan
                    let mut load_dregs35: Vec<u8> = Vec::new();
                    let mut bar_guard35: Vec<u8> = Vec::new();
                    let mut s2r_guard35: Vec<u8> = Vec::new();
                    let mut isetp_ur35: Vec<u32> = Vec::new();
                    // mk41: XSETP-pary (lustro sass_file::merc_xsetp_scan)
                    let mut xsetp_pairs35: Vec<(u32, u8)> = Vec::new();
                    let mut xsetp_lastp: std::collections::HashMap<String, (u32, bool, bool)> =
                        std::collections::HashMap::new();
                    // mk52: lustro sass_file::merc_usetp_scan (UISETP minis +
                    // ULEA carry-out 42254214).
                    let mut usetp_minis35: Vec<(u32, u8)> = Vec::new();
                    let mut usetp_heads35: std::collections::HashMap<String, (u32, bool)> =
                        std::collections::HashMap::new();
                    let mut ulea_upco35: Vec<u32> = Vec::new();
                    // mk40: lustra merc_store2_scan / merc_mini2_scan / wsel.
                    let mut store2m: Vec<(u32, u8, u8, u16, u16, u16, i32, u8)> = Vec::new();
                    let mut mini2m: Vec<(u32, u32)> = Vec::new();
                    let mut edge_ldm: Vec<(u32, u8, u8, u8, u8, u16, u16, u8, u32)> = Vec::new();
                    let mut edge_maxur_m: u16 = 0;
                    // mk50: rekordy 02221e32 (LDG-desc w kernelach annotated_ptr
                    // — dlugosci (lane,b4,b6,X,Y,C,V,off); lustro
                    // sass_file::merc_edge_ldg_scan). Pre-pass: desc-UR-y
                    // uzywane wylacznie przez lane'y bazowe LDG.
                    let mut edge_ldgm: Vec<(u32, u8, u8, u16, u16, u8, u16, u32)> = Vec::new();
                    // mk51: lustra sass_file::merc_f64imm_scan /
                    // merc_dfmaimm_scan (rekordy 020f120e/020c1e0e oraz
                    // 020d1c0e/020d1a0e — D-FP z natychmiastowym f64).
                    let mut f64imm_sc: Vec<(u32, u8, u16, u16, u32, u8, u8)> = Vec::new();
                    let mut dfmaim_sc: Vec<(u32, u8, u8, u8, u16, u16, u16, u64)> =
                        Vec::new();
                    let mut ldg_only_urs: std::collections::HashSet<u16> =
                        std::collections::HashSet::new();
                    if kernel_name.contains("annotated_ptr") {
                        let mut ur_ldg = std::collections::HashSet::<u16>::new();
                        let mut ur_oth = std::collections::HashSet::<u16>::new();
                        for (_a2, asm2) in insns.iter() {
                            let c2 = if let Some(idx) = asm2.find("/* @sched") {
                                &asm2[..idx]
                            } else {
                                asm2.as_str()
                            };
                            let b2t = match c2.find("*/") {
                                Some(k) if c2.starts_with("/*") => c2[k + 2..].trim(),
                                _ => c2.trim(),
                            };
                            let base2 = match re_tok.captures(b2t) {
                                Some(c2m) => c2m
                                    .get(1)
                                    .map(|x| x.as_str())
                                    .unwrap_or("")
                                    .split('.')
                                    .next()
                                    .unwrap_or(""),
                                None => "",
                            };
                            let mut p = 0usize;
                            while let Some(pos) = b2t[p..].find("desc[UR") {
                                let s2 = &b2t[p + pos + 7..];
                                let k2 = s2.bytes().take_while(|c| c.is_ascii_digit()).count();
                                if k2 > 0 {
                                    if let Ok(v) = s2[..k2].parse::<u16>() {
                                        if base2 == "LDG" {
                                            ur_ldg.insert(v);
                                        } else {
                                            ur_oth.insert(v);
                                        }
                                    }
                                }
                                p += pos + 7 + k2.max(1);
                            }
                        }
                        ldg_only_urs = ur_ldg.difference(&ur_oth).copied().collect();
                    }
                    let mut stg_wselv: Vec<u8> = Vec::new();
                    let mut redux35: Vec<(u32, u8, u8)> = Vec::new();
                    let mut cbank358_dreg35: Option<u8> = None;
                    for (ii, (_addr, asm)) in insns.iter().enumerate() {
                        let clean = if let Some(idx) = asm.find("/* @sched") {
                            &asm[..idx]
                        } else {
                            asm.as_str()
                        };
                        let body = match clean.find("*/") {
                            Some(k) if clean.starts_with("/*") => clean[k + 2..].trim(),
                            _ => clean.trim(),
                        };
                        let guard_m: u8 = if body.starts_with("@!") {
                            2
                        } else if body.starts_with('@') {
                            1
                        } else {
                            0
                        };
                        // mk41: pelny kod predykatu (lustro merc_guard_code):
                        // 0xf8 brak; @Pn -> n<<3; @!Pn -> n<<3|1; UPn -> |2.
                        let guard_fc: u8 = {
                            let b2 = body.trim_start();
                            if !b2.starts_with('@') {
                                0xf8
                            } else {
                                let neg = b2.starts_with("@!");
                                let rest = b2[1 + (neg as usize)..].trim_start();
                                if rest.starts_with("PT") || rest.starts_with("UPT") {
                                    0xf8
                                } else {
                                    let unif = rest.starts_with('U');
                                    let r2 = if unif { &rest[1..] } else { rest };
                                    let r3 = if let Some(x) = r2.strip_prefix('P') { x } else { r2 };
                                    let digits: String =
                                        r3.chars().take_while(|c| c.is_ascii_digit()).collect();
                                    let idx = digits.parse::<u8>().unwrap_or(0).min(7);
                                    (idx << 3) | if unif { 2 } else { 0 } | (neg as u8)
                                }
                            }
                        };
                        let m2 = match re_tok.captures(body) {
                            Some(x) => x,
                            None => continue,
                        };
                        let base0 = m2.get(1).unwrap().as_str().split('.').next().unwrap_or("");
                        let rest = m2.get(2).map(|x| x.as_str()).unwrap_or("");
                        // mk35: BAR guard (rownolegle do bar_pos z petli-1)
                        if base0 == "BAR" {
                            bar_guard35.push(guard_fc);
                        }
                        // mk41: para ISETP(non-EX)+ISETP.EX -> mini na head.
                        // (zastepuje zawezona regule mk35 NE+UR-noEX.)
                        if base0 == "ISETP" {
                            // body zaczyna sie od opkodu+gwardu? guard piklej
                            // strip zrobiony wyzej (body po ...); odciete nizej
                            let body_xs = match body.find(char::is_whitespace) {
                                Some(k) => body[k..].trim_start(),
                                None => continue,
                            };
                            let toks: Vec<&str> = body_xs.split(',').map(|s| s.trim().trim_end_matches(';').trim_end()).collect();
                            let dstp = toks.first().copied().unwrap_or("");
                            if dstp.starts_with('P') && dstp != "PT" {
                                let has_ur = {
                                    let b = body.as_bytes();
                                    let mut f = false;
                                    let mut i = 0;
                                    while i + 2 < b.len() {
                                        if b[i] == b'U' && b[i + 1] == b'R' && b[i + 2].is_ascii_digit()
                                            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                                        {
                                            f = true;
                                        }
                                        i += 1;
                                    }
                                    f
                                };
                                let has_imm = toks.iter().skip(1).any(|tk| {
                                    let tk = tk.trim();
                                    tk.starts_with("0x")
                                        || tk.starts_with("-0x")
                                        || tk
                                            .trim_start_matches('-')
                                            .chars()
                                            .all(|c| c.is_ascii_digit())
                                            && !tk.is_empty()
                                });
                                if body.contains(".EX") {
                                    let last = toks.last().copied().unwrap_or("").trim_start_matches('!');
                                    if let Some(&(hlane, hu, hi)) = xsetp_lastp.get(last) {
                                        xsetp_pairs35.push((hlane, if hu || has_ur { 2u8 } else if hi { 1 } else { 0 }));
                                    }
                                } else {
                                    xsetp_lastp.insert(dstp.to_string(), (ii as u32, has_ur, has_imm));
                                }
                            }
                        }
                        // mk52 (lustro): UISETP minis + ULEA carry-out.
                        if base0 == "UISETP" || base0 == "ULEA" {
                            let body_u = match body.find(char::is_whitespace) {
                                Some(k) => body[k..].trim_start(),
                                None => "",
                            };
                            let toks: Vec<&str> = body_u
                                .split(',')
                                .map(|s| s.trim().trim_end_matches(';').trim_end())
                                .filter(|s| !s.is_empty())
                                .collect();
                            let is_up = |t: &str| -> bool {
                                let t = t.trim_start_matches('!');
                                t.len() > 2
                                    && t.starts_with("UP")
                                    && t[2..].chars().all(|c| c.is_ascii_digit())
                            };
                            if base0 == "ULEA" {
                                if toks.len() >= 2 && is_up(toks[1]) {
                                    ulea_upco35.push(ii as u32);
                                }
                            } else if !toks.is_empty() {
                                let has_imm = toks.iter().skip(1).any(|tk| {
                                    let tk = tk.trim();
                                    tk.starts_with("0x")
                                        || tk.starts_with("-0x")
                                        || tk
                                            .trim_start_matches('-')
                                            .chars()
                                            .all(|c| c.is_ascii_digit())
                                            && !tk.is_empty()
                                });
                                let last = toks.last().copied().unwrap_or("").trim_start_matches('!');
                                if body.contains(".EX") {
                                    if is_up(last) {
                                        if let Some(&(hlane, head_imm)) = usetp_heads35.get(last) {
                                            usetp_minis35.push((hlane, if head_imm || has_imm { 1 } else { 0 }));
                                            if !has_imm {
                                                usetp_minis35.push((hlane, 2));
                                            }
                                        }
                                    }
                                } else if is_up(last) {
                                    usetp_minis35.push((ii as u32, if has_imm { 1 } else { 0 }));
                                }
                                let dv = toks[0].trim_start_matches('!');
                                if dv.len() > 2 && dv.starts_with("UP")
                                    && dv[2..].chars().all(|c| c.is_ascii_digit())
                                {
                                    usetp_heads35.insert(dv.to_string(), (ii as u32, has_imm));
                                }
                            }
                        }
                        // mk40 (lustro): mini-slownik korpusowy per-lane.
                        let mini40: u32 = match base0 {
                            "FFMA2" => 0x26140d42,
                            "HADD2" => 0x0a260c41,
                            "BREAK" => 0x0a000541,
                            "PREEXIT" => 0x0a026241,
                            "BAR" if m2.get(1).map(|x| x.as_str()).unwrap_or("").contains(".ARV") => 0x16124741,
                            "F2I" if { let opf = m2.get(1).map(|x| x.as_str()).unwrap_or(""); opf.contains("TRUNC") && opf.ends_with(".U64") } => 0x45241241,
                            "F2F" if m2.get(1).map(|x| x.as_str()).unwrap_or("").starts_with("F2F.BF16.F32") => 0x0a0e1241,
                            "F2FP" if m2.get(1).map(|x| x.as_str()).unwrap_or("").contains("TF32") => 0x0b6c1241,
                            "IMAD" if m2.get(1).map(|x| x.as_str()).unwrap_or("") == "IMAD.WIDE.U32.X" => 0x06342042,
                            "UIMAD" if m2.get(1).map(|x| x.as_str()).unwrap_or("") == "UIMAD.WIDE.U32.X" => 0x06382042,
                            _ => 0,
                        };
                        if mini40 != 0 {
                            mini2m.push((ii as u32, mini40));
                        }
                        // mk40 (lustro): wsel per-STG (width; mieszane korpusy)
                        if base0 == "STG" {
                            let opf = m2.get(1).map(|x| x.as_str()).unwrap_or("");
                            stg_wselv.push(if opf.contains(".128") {
                                4
                            } else if opf.contains(".64") {
                                3
                            } else if opf.contains(".U16") || opf.contains(".S16") {
                                1
                            } else if opf.contains(".U8") || opf.contains(".S8") {
                                0
                            } else {
                                2
                            });
                        }
                        // mk40 (lustro): store-matrix ST.E/STL.
                        if base0 == "ST" || base0 == "STL" {
                            let opf = m2.get(1).map(|x| x.as_str()).unwrap_or("");
                            if !opf.contains("ENL2") {
                                let wsel: u8 = if opf.contains(".128") {
                                    4
                                } else if opf.contains(".64") {
                                    3
                                } else if opf.contains(".U16") || opf.contains(".S16") {
                                    1
                                } else if opf.contains(".U8") || opf.contains(".S8") {
                                    0
                                } else {
                                    2
                                };
                                let mut dur: u16 = 0xffff;
                                let mut areg: u16 = 0xffff;
                                let mut dreg: u16 = 0x3ff;
                                let mut imm: i32 = 0;
                                if let Some(dp) = body.find("desc[UR") {
                                    let rest9 = &body[dp + 7..];
                                    if let Some(end) = rest9.find(']') {
                                        if let Ok(v) = rest9[..end].trim().parse::<u16>() {
                                            dur = v.min(0x3ff);
                                        }
                                    }
                                }
                                if let Some(lb) = body.rfind('[') {
                                    if let Some(rb2) = body[lb..].find(']') {
                                        let inner = &body[lb + 1..lb + rb2];
                                        let bb = inner.as_bytes();
                                        if bb.first() == Some(&b'R') {
                                            let mut k = 1;
                                            while k < bb.len() && bb[k].is_ascii_digit() {
                                                k += 1;
                                            }
                                            if let Ok(v) = inner[1..k].parse::<u16>() {
                                                areg = v.min(0x3ff);
                                            }
                                        }
                                        if let Some(pl) = inner.rfind('+') {
                                            let tail = inner[pl + 1..].trim();
                                            if !tail.starts_with('U') {
                                                let neg = tail.starts_with('-');
                                                let tt = tail.trim_start_matches('-');
                                                if let Ok(v) = i32::from_str_radix(
                                                    tt.trim_start_matches("0x"),
                                                    if tt.starts_with("0x") { 16 } else { 10 },
                                                ) {
                                                    imm = if neg { -v } else { v };
                                                }
                                            }
                                        }
                                        let after = &body[lb + rb2 + 1..];
                                        if let Some(cm) = after.find(',') {
                                            let tok = after[cm + 1..]
                                                .split(',')
                                                .next()
                                                .unwrap_or("")
                                                .trim()
                                                .trim_end_matches(';');
                                            if tok == "RZ" {
                                                dreg = 0x3ff;
                                            } else if let Some(rn) = tok.strip_prefix('R') {
                                                if let Ok(v) = rn.parse::<u16>() {
                                                    dreg = v.min(0x3ff);
                                                }
                                            }
                                        }
                                    }
                                }
                                // b4: (pidx<<3)|neg dla STL; ST.E zawsze f8
                                // (korpus mk40/stgfields); emisja decyduje w
                                // elf_builder szablonem 2a/20.
                                let gk = body
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("");
                                let b4: u8 = if gk.starts_with('@')
                                    && gk != "@PT"
                                    && gk != "@UPT"
                                {
                                    let neg = gk.starts_with("@!");
                                    let digits: String = gk
                                        .trim_start_matches('@')
                                        .trim_start_matches('!')
                                        .trim_start_matches('P')
                                        .chars()
                                        .take_while(|c| c.is_ascii_digit())
                                        .collect();
                                    let pidx = digits.parse::<u8>().unwrap_or(0);
                                    ((pidx.min(7)) << 3) | (neg as u8)
                                } else {
                                    0xf8
                                };
                                store2m.push((ii as u32, if base0 == "ST" { 1 } else { 2 }, wsel, areg, dur, dreg, imm, b4));
                            }
                        }
                        // mk42 (lustro): edge LD -> rekord 02223232 + descmax.
                        {
                            let mut p = 0usize;
                            while let Some(pos) = body[p..].find("desc[UR") {
                                let s2 = &body[p + pos + 7..];
                                let k = s2.bytes().take_while(|c| c.is_ascii_digit()).count();
                                if k > 0 {
                                    if let Ok(v) = s2[..k].parse::<u16>() {
                                        edge_maxur_m = edge_maxur_m.max(v);
                                    }
                                }
                                p += pos + 7 + k.max(1);
                            }
                        }
                        if base0 == "LD" && body.contains("desc[UR") {
                            let opf = m2.get(1).map(|x| x.as_str()).unwrap_or("");
                            let c6: u8 = if opf.contains(".128") {
                                7
                            } else if opf.contains(".64") {
                                3
                            } else {
                                1
                            };
                            let b6: u8 = if opf.contains(".U8") {
                                0x10
                            } else if opf.contains(".S8") {
                                0x11
                            } else if opf.contains(".U16") {
                                0x12
                            } else if opf.contains(".S16") {
                                0x13
                            } else if opf.contains(".128") {
                                0x16
                            } else if opf.contains(".64") {
                                0x15
                            } else {
                                0x14
                            };
                            let (b7, b8) = if opf.contains("STRONG.SYS") {
                                (0x10u8, 0x01u8)
                            } else {
                                (0x08u8, 0x00u8)
                            };
                            let dst_tok = rest.split(',').next().unwrap_or("").trim();
                            let dst_tok = dst_tok.trim_start_matches(['!', '-', '|']);
                            let xv: Option<u16> = dst_tok.strip_prefix('R').and_then(|r| {
                                let r = r.trim_end_matches(';');
                                if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) {
                                    r.parse::<u16>().ok()
                                } else {
                                    None
                                }
                            });
                            if let Some(xv) = xv {
                                if let Some(dp) = body.find("desc[UR") {
                                    let mut parsed: Option<(u16, u32)> = None;
                                    if let Some(dc) = body[dp..].find(']') {
                                        let rest9 = &body[dp + dc + 1..];
                                        if rest9.starts_with('[') {
                                            if let Some(gc) = rest9.find(']') {
                                                parsed = (|| {
                                                    let inner = &rest9[1..gc];
                                                    let ib = inner.as_bytes();
                                                    if ib.first() != Some(&b'R') {
                                                        return None;
                                                    }
                                                    let k = ib.iter().skip(1).take_while(|c| c.is_ascii_digit()).count();
                                                    if k == 0 {
                                                        return None;
                                                    }
                                                    let y: u16 = inner[1..1 + k].parse().ok()?;
                                                    let off: u32 = if let Some(pl) = inner[1 + k..].find('+') {
                                                        let tail = inner[1 + k + pl + 1..].trim();
                                                        if tail.starts_with('U') {
                                                            return None;
                                                        }
                                                        let neg = tail.starts_with('-');
                                                        let tt = tail.trim_start_matches('-');
                                                        let radix = if tt.starts_with("0x") { 16 } else { 10 };
                                                        let v = i64::from_str_radix(tt.trim_start_matches("0x"), radix).ok()?;
                                                        (if neg { -v } else { v }) as u32
                                                    } else {
                                                        0
                                                    };
                                                    Some((y, off))
                                                })();
                                            }
                                        }
                                    }
                                    if let Some((yv, off)) = parsed {
                                        edge_ldm.push((ii as u32, guard_fc, b6, b7, b8, xv, yv, c6, off));
                                    }
                                }
                            }
                        }
                        // mk50 (lustro): rekord 02221e32 dla LDG-desc lane'ow
                        // w kernelach annotated_ptr z ldg-only UR.
                        if !ldg_only_urs.is_empty()
                            && base0 == "LDG"
                            && body.contains("desc[UR")
                        {
                            let opf = m2.get(1).map(|x| x.as_str()).unwrap_or("");
                            let b6c6: Option<(u8, u8)> = if opf.contains(".128") {
                                Some((0x60, 7))
                            } else if opf.contains(".64") {
                                Some((0x50, 3))
                            } else if opf == "LDG.E" {
                                Some((0x40, 1))
                            } else {
                                None // LDG.E.U8/.U16/STRONG... — korpusowo bez rekordow
                            };
                            if let Some((b6, c6)) = b6c6 {
                                let dst_tok = rest.split(',').next().unwrap_or("").trim();
                                let dst_tok = dst_tok.trim_start_matches(['!', '-', '|']);
                                let xv: Option<u16> = dst_tok.strip_prefix('R').and_then(|r| {
                                    let r = r.trim_end_matches(';');
                                    if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) {
                                        r.parse::<u16>().ok()
                                    } else {
                                        None
                                    }
                                });
                                if let Some(xv) = xv {
                                    if let Some(dp) = body.find("desc[UR") {
                                        let vv: Option<u16> = {
                                            let s2 = &body[dp + 7..];
                                            let k2 =
                                                s2.bytes().take_while(|c| c.is_ascii_digit()).count();
                                            if k2 == 0 {
                                                None
                                            } else {
                                                s2[..k2].parse::<u16>().ok()
                                            }
                                        };
                                        let mut parsed: Option<(u16, u32)> = None;
                                        if let Some(dc) = body[dp..].find(']') {
                                            let rest9 = &body[dp + dc + 1..];
                                            if rest9.starts_with('[') {
                                                if let Some(gc) = rest9.find(']') {
                                                    parsed = (|| {
                                                        let inner = &rest9[1..gc];
                                                        let ib = inner.as_bytes();
                                                        if ib.first() != Some(&b'R') {
                                                            return None;
                                                        }
                                                        let k = ib
                                                            .iter()
                                                            .skip(1)
                                                            .take_while(|c| c.is_ascii_digit())
                                                            .count();
                                                        if k == 0 {
                                                            return None;
                                                        }
                                                        // wymagana forma .64 (mk50 korpus)
                                                        if !inner[1 + k..].starts_with(".64") {
                                                            return None;
                                                        }
                                                        let y: u16 = inner[1..1 + k].parse().ok()?;
                                                        let off: u32 = if let Some(pl) =
                                                            inner[1 + k..].find('+')
                                                        {
                                                            let tail =
                                                                inner[1 + k + pl + 1..].trim();
                                                            if tail.starts_with('U') {
                                                                return None;
                                                            }
                                                            let neg = tail.starts_with('-');
                                                            let tt = tail.trim_start_matches('-');
                                                            let radix =
                                                                if tt.starts_with("0x") { 16 } else { 10 };
                                                            let v = i64::from_str_radix(
                                                                tt.trim_start_matches("0x"),
                                                                radix,
                                                            )
                                                            .ok()?;
                                                            (if neg { -v } else { v }) as u32
                                                        } else {
                                                            0
                                                        };
                                                        Some((y, off))
                                                    })();
                                                }
                                            }
                                        }
                                        if let (Some(vldc), Some((yv, off))) = (vv, parsed) {
                                            if ldg_only_urs.contains(&vldc) {
                                                edge_ldgm.push((
                                                    ii as u32, guard_fc, b6, xv, yv, c6, vldc, off,
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // mk51 (lustro): rekordy DFMA/DMUL/DADD z imm f64.
                        if base0 == "DFMA" || base0 == "DMUL" || base0 == "DADD" {
                            use cubit::sass_file::{merc_f64_lit, merc_f64_reg};
                            let parts: Vec<&str> =
                                rest.split(',').map(|x| x.trim()).collect();
                            if base0 == "DFMA" && parts.len() == 4 {
                                if let Some((d, _, _)) = merc_f64_reg(parts[0]) {
                                    if let (Some((a, n1, ab1)), Some((b, n2, ab2)), Some(im)) = (
                                        merc_f64_reg(parts[1]),
                                        merc_f64_reg(parts[2]),
                                        merc_f64_lit(parts[3]),
                                    ) {
                                        let b7: u8 = (if n1 { 2 } else { 0 })
                                            | (if n2 { 8 } else { 0 })
                                            | (if ab1 { 4 } else { 0 })
                                            | (if ab2 { 16 } else { 0 });
                                        dfmaim_sc.push((
                                            ii as u32, 0u8, guard_fc, b7, d, a, b,
                                            im.to_bits(),
                                        ));
                                    } else if let (
                                        Some((a, n1, ab1)),
                                        Some(im),
                                        Some((b, n2, ab2)),
                                    ) = (
                                        merc_f64_reg(parts[1]),
                                        merc_f64_lit(parts[2]),
                                        merc_f64_reg(parts[3]),
                                    ) {
                                        let b7: u8 = (if n1 { 2 } else { 0 })
                                            | (if n2 { 8 } else { 0 })
                                            | (if ab1 { 4 } else { 0 })
                                            | (if ab2 { 16 } else { 0 });
                                        dfmaim_sc.push((
                                            ii as u32, 1u8, guard_fc, b7, d, a, b,
                                            im.to_bits(),
                                        ));
                                    }
                                }
                            } else if parts.len() == 3 {
                                if let (Some((d, _, _)), Some((a, n1, ab1)), Some(im)) = (
                                    merc_f64_reg(parts[0]),
                                    merc_f64_reg(parts[1]),
                                    merc_f64_lit(parts[2]),
                                ) {
                                    let b7: u8 = (if n1 { 2 } else { 0 })
                                        | (if ab1 { 4 } else { 0 });
                                    f64imm_sc.push((
                                        ii as u32,
                                        if base0 == "DMUL" { 0u8 } else { 1u8 },
                                        d,
                                        a,
                                        (im.to_bits() >> 32) as u32,
                                        guard_fc,
                                        b7,
                                    ));
                                }
                            }
                        }
                        // mk35 (lustro): 0132-rekordy tylko dla typowanego
                        // REDUX i CREDUX; goly REDUX = bit (zob. bitmap).
                        if base0 == "REDUX" || base0 == "CREDUX" {
                            let dest = rest.split(',').next().unwrap_or("").trim();
                            let dd = dest.trim_start_matches(['R','U']);
                            let dreg = if !dd.is_empty() && dd.chars().all(|c| c.is_ascii_digit()) {
                                dd.parse::<u32>().unwrap_or(255).min(255) as u8
                            } else { 255 };
                            if base0 == "CREDUX" {
                                redux35.push((ii as u32, 1, dreg));
                            } else if body.contains("REDUX.") {
                                redux35.push((ii as u32, 0, dreg));
                            }
                        }
                        if base0 == "CALL" {
                            call_lanes.push(ii as u32);
                        }
                        if base0 == "S2R" {
                            s2r_lanes.push(ii as u32);
                            s2r_guard35.push(guard_fc);
                            // mk13: enum SR -> b12 anchor-rekordu
                            let sr_full = match rest.split("SR_").nth(1) {
                                Some(t) => {
                                    let e = t
                                        .find(|c: char| !(c.is_alphanumeric() || c == '.'))
                                        .unwrap_or(t.len());
                                    format!("SR_{}", &t[..e])
                                }
                                None => String::new(),
                            };
                            s2r_sr.push(cubit::mercury::merc_s2r_sr_enum(&sr_full));
                            // mk17a: numer R dest -> payload f4 anchor-rekordu.
                            s2r_dest.push(
                                cubit::mercury::merc_s2r_dest_reg(body).unwrap_or(0),
                            );
                        }
                        if guard_m != 0 && mem_ops.contains(&base0) {
                            predmem = true;
                        }
                        if let Some(cap) = re_load.captures(body) {
                            let off = u32::from_str_radix(&cap[4], 16).unwrap_or(0);
                            let wv: u8 = match cap.get(2).map(|x| x.as_str()) {
                                Some(".128") => 16,
                                Some(".64") => 8,
                                Some(".U16") => 2,
                                Some(".U8") => 1,
                                _ => 4,
                            };
                            if off == 0x358 && cbank358_dreg35.is_none() {
                                // mk35: dst loadu okna 0x358 (dowolny mech);
                                // b10/b11 cbank = (dreg<<6)|3 (k_atom UR4 ->
                                // 03 01; at_and/min UR6 -> 83 01).
                                let dd = cap[3].trim_start_matches(['R', 'U']);
                                cbank358_dreg35 = dd.parse::<u32>().ok().map(|v| v.min(255) as u8);
                            }
                            if off == 0x358 && &cap[1] == "LDCU" && cbank_lane.is_none() {
                                cbank_lane = Some(ii as u32);
                            }
                            if off >= 0x380 {
                                // mk19 (lustro sass_file): kluczem jest surowy
                                // offset rel = off-0x380, nie indeks 8B (pi).
                                let rel = off - 0x380;
                                let unif: u8 = if &cap[1] == "LDCU" { 1 } else { 0 };
                                loads.push((ii as u32, rel, unif, wv, guard_fc));
                                // mk35: dst-reg loadu (rownolegle do loads).
                                let ddb = cap[3].trim_start_matches(['R', 'U']);
                                load_dregs35.push(ddb.parse::<u32>().ok().map(|v| v.min(255) as u8).unwrap_or(255));
                                // mk18 bit1: load PO CALL.
                                load_flags.push(if call_lanes.is_empty() { 0 } else { 2 });
                                let mut pidx = u32::MAX;
                                if wv >= 8 {
                                    pidx = match pool.iter().position(|e| *e == (rel, unif)) {
                                        Some(k) => k as u32,
                                        None => {
                                            pool.push((rel, unif));
                                            (pool.len() - 1) as u32
                                        }
                                    };
                                }
                                let dname = cap[2 + 1].to_string();
                                regpool.insert(dname.clone(), pidx);
                                if wv >= 8 {
                                    if let Ok(n_) = dname[2..].parse::<u32>() {
                                        let mut hn = dname.clone();
                                        hn.replace_range(1.., &(n_ + 1).to_string());
                                        regpool.insert(hn, pidx);
                                    }
                                }
                            }
                        }
                        if alias_ops.contains(&base0) && rest.contains(',') {
                            if let Some(ci) = rest.find(',') {
                                let dst = rest[..ci]
                                    .trim()
                                    .trim_matches(|c: char| !c.is_alphanumeric())
                                    .to_string();
                                let srcs = &rest[ci + 1..];
                                if !dst.is_empty() {
                                    for (rn, pidx) in regpool.clone().iter() {
                                        let mut ok = false;
                                        for mm in srcs.match_indices(rn.as_str()) {
                                            let after =
                                                srcs[mm.0 + rn.len()..].chars().next();
                                            if after.map(|c| !c.is_ascii_digit()).unwrap_or(true)
                                            {
                                                ok = true;
                                                break;
                                            }
                                        }
                                        if ok {
                                            regpool.insert(dst.clone(), *pidx);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if base0 == "STG" {
                            let bks: Vec<String> = re_brak
                                .captures_iter(body)
                                .map(|c| c[1].to_string())
                                .collect();
                            if let Some(last) = bks.last() {
                                let mut bp = *regpool.get(last).unwrap_or(&u32::MAX);
                                // mk18: post-CALL STG -> pierwszy wpis puli tego pi
                                if !call_lanes.is_empty() && bp != u32::MAX {
                                    if let Some(&(pi_s, _)) = pool.get(bp as usize) {
                                        if let Some(f0) =
                                            pool.iter().position(|&(pp, _)| pp == pi_s)
                                        {
                                            bp = f0 as u32;
                                        }
                                    }
                                }
                                stg_pos2.push(bp);
                            }
                        }
                        // mk13: LDG.E.CONSTANT przez desc = osobny wpis puli
                        // slotow (klucz (pi,2)) w porzadku kodu (v_ldg_u64).
                        if base0 == "LDG" && m2.get(1).map(|x| x.as_str().contains(".CONSTANT")).unwrap_or(false) {
                            let bks: Vec<String> = re_brak
                                .captures_iter(body)
                                .map(|c| c[1].to_string())
                                .collect();
                            if let Some(last) = bks.last() {
                                if let Some(&pidx) = regpool.get(last) {
                                    if pidx != u32::MAX {
                                        let pi = pool[pidx as usize].0;
                                        let key = (pi, 2u8);
                                        if !pool.contains(&key) {
                                            pool.push(key);
                                        }
                                        ldgconst.push((ii as u32, pi));
                                    }
                                }
                            }
                        }
                        // mk13: predykowany BRA dostaje bit bitmapy (q_switch
                        // slot5); guard @PT/@UPT = de facto brak predykatu.
                        if base0 == "BRA" && guard_m != 0 {
                            let gk = body
                                .split_whitespace()
                                .next()
                                .unwrap_or("")
                                .trim_start_matches('@')
                                .trim_start_matches('!');
                            if gk != "PT" && gk != "UPT" {
                                guarded_bra.push(ii as u32);
                            }
                        }
                        // mk13: LOP3 z destem predykatowym (LOP3.LUT Pn, ..)
                        // bez bitu + mini-rekord w lane (d_sw4_store slot6).
                        if base0 == "LOP3" && cubit::mercury::lop3_writes_pred(body) {
                            lop3_pdest.push(ii as u32);
                        }
                        // mk48 (lustro): REDG desc/non-desc -> rekord 024d*32
                        // (pelna tabela klas; zastepuje mk35-tuple REDG_D).
                        if base0 == "REDG" {
                            if let Some(r) = cubit::mercury::merc_redg_record(body, guard_fc) {
                                redg2_scan.push((ii as u32, r));
                            }
                        }
                        // mk14: rekordy atomowe (lustro sass_file::merc_atom_scan).
                        if base0.starts_with("ATOM") {
                            // mk49 (lustro): rekordy 024e*32 konsumuja lane;
                            // CAST.SPIN/ATOM.E.CAS.* sa bezrekordowe (bez tuple).
                            if let Some(r) = cubit::mercury::merc_atomg2_record(body, guard_fc) {
                                atomg2_scan.push((ii as u32, r));
                            } else if !cubit::mercury::merc_atomg2_recordless(body) {
                            let reg_of = |t: &str| -> u8 {
                                let t = t.trim().trim_end_matches(';').trim_end_matches(')');
                                if t == "RZ" || t == "URZ" {
                                    return 255;
                                }
                                let d = t.trim_start_matches(['R', 'U']);
                                if !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()) {
                                    d.parse::<u32>().ok().map(|v| v.min(255) as u8).unwrap_or(255)
                                } else {
                                    255
                                }
                            };
                            let bfull = body
                                .split_whitespace()
                                .skip_while(|t| t.starts_with('@'))
                                .collect::<Vec<_>>()
                                .join(" ");
                            let parts: Vec<&str> = bfull
                                .trim_end_matches(';')
                                .splitn(2, ' ')
                                .nth(1)
                                .unwrap_or("")
                                .split(',')
                                .map(|x| x.trim())
                                .collect();
                            if base0.starts_with("ATOMS") {
                                if parts.len() >= 3 {
                                    atoms_scan.push((ii as u32, cubit::mercury::MERC_ATOM_CLS_SHARED,
                                                     guard_m, reg_of(parts[0]), 255,
                                                     reg_of(parts[2]), 255, 0));
                                }
                            } else if parts.len() >= 3 {
                                let (di, ai) = if parts[0] == "PT" { (1usize, 2usize) } else { (0, 1) };
                                if ai < parts.len() {
                                    let dst = if di < parts.len() { reg_of(parts[di]) } else { 255 };
                                    let mut addr = 255u8;
                                    let mut s2 = parts[ai];
                                    while let Some(o) = s2.rfind('[') {
                                        let inner = &parts[ai][o + 1..];
                                        let end = inner.find(']').unwrap_or(inner.len());
                                        let tok = &inner[..end];
                                        let r = reg_of(tok.split('+').next().unwrap_or("").split('.').next().unwrap_or(""));
                                        if r != 255 {
                                            addr = r;
                                            break;
                                        }
                                        s2 = &parts[ai][..o];
                                    }
                                    // mk18: oznacz wpis puli trafiony adresem atomu
                                    if addr != 255 {
                                        if let Some(&ph) =
                                            regpool.get(&format!("R{}", addr))
                                        {
                                            if ph != u32::MAX {
                                                if let Some(&(pa, ma)) = pool.get(ph as usize) {
                                                    atom_pool_hits.insert((pa, ma));
                                                }
                                            }
                                        }
                                    }
                                    if base0.contains("CAS") || body.contains(".CAS") {
                                        if parts.len() >= ai + 3 {
                                            atoms_scan.push((ii as u32, cubit::mercury::MERC_ATOM_CLS_CAS,
                                                             guard_m, dst, addr,
                                                             reg_of(parts[ai + 1]), reg_of(parts[ai + 2]), 0));
                                        }
                                    } else if parts.len() >= ai + 2 {
                                        let sub6: u8 = if body.contains(".EXCH") { 0x80 } else { 0 };
                                        atoms_scan.push((ii as u32, cubit::mercury::MERC_ATOM_CLS_G4,
                                                         guard_m, dst, addr,
                                                         reg_of(parts[ai + 1]), 255, sub6));
                                    }
                                }
                            }
                            }
                        }
                    }
                    meta.merc_param_loads = loads;
                    meta.merc_load_flags = load_flags;
                    meta.merc_atom_pool_hits = atom_pool_hits.into_iter().collect();
                    meta.merc_cbank_lane = cbank_lane;
                    meta.merc_s2r_lanes = s2r_lanes;
                    meta.merc_s2r_sr = s2r_sr;
                    meta.merc_s2r_guard = s2r_guard35;
                    meta.merc_s2r_dest = s2r_dest;
                    meta.merc_ldgconst = ldgconst;
                    meta.merc_predmem = predmem;
                    meta.merc_guarded_bra = guarded_bra;
                    meta.merc_lop3_pdest = lop3_pdest;
                    meta.merc_atoms = atoms_scan;
                    meta.merc_redg2_rec = redg2_scan;
                    meta.merc_atomg2_rec = atomg2_scan;
                    // mk27: lustra dla UTCATOMSWS i ATOMS-smem-imm
                    // (sass_file::merc_utca_scan / merc_atom_smem_scan).
                    let mut utca_v: Vec<(u32, u8)> = Vec::new();
                    let mut atom_smem_v: Vec<(u32, u32, u8)> = Vec::new();
                    // mk28 (lustro sass_file): samo-petle BRA (spin-trap),
                    // site'y warp-wide do EIATTR 0x31, flagi CALL/BSSY
                    // (EIATTR 0x1e, pusta .rela.text.K).
                    let mut bra_sl_v: Vec<u32> = Vec::new();
                    let mut wwide_v: Vec<u32> = Vec::new();
                    let mut has_voteu = false;
                    let re_bra_lbl =
                        regex::Regex::new(r"^BRA(\.[A-Z0-9]+)?\s+(?:PT,\s+)?L_([0-9a-fA-F]+)")
                            .unwrap();
                    for (ii, (_aa, body)) in insns.iter().enumerate() {
                        let btrim = body.trim();
                        let fw = btrim.split_whitespace().next().unwrap_or("");
                        let base_w = if fw.starts_with('@') {
                            btrim.split_whitespace().nth(1).unwrap_or("")
                        } else {
                            fw
                        }
                        .split('.')
                        .next()
                        .unwrap_or("");
                        // mk28: samo-petla `BRA L_x` gdzie cel == wlasny offset
                        // (martwy spin-trap za strefa RET; mkvmem BRA L_400).
                        if base_w == "BRA" {
                            if let Some(c) = re_bra_lbl.captures(btrim) {
                                let tgt = u32::from_str_radix(c.get(2).unwrap().as_str(), 16)
                                    .unwrap_or(0);
                                if tgt as usize == ii * 16 {
                                    bra_sl_v.push(ii as u32);
                                }
                            }
                        }
                        match cubit::mercury::wwide_class(base_w, "") {
                            Some(b'v') => {
                                has_voteu = true;
                                wwide_v.push((ii * 16) as u32);
                            }
                            Some(_) => wwide_v.push((ii * 16) as u32),
                            None => {}
                        }
                        if base_w == "CALL" {
                            meta.has_call = true;
                        }
                        if base_w == "BSSY" {
                            meta.has_bssy = true;
                        }
                        let bt = body.trim();
                        let fword = bt.split_whitespace().next().unwrap_or("");
                        let base0u = fword.split('.').next().unwrap_or("");
                        if base0u == "UTCATOMSWS" {
                            let kind = if bt.contains("FIND_AND_SET") {
                                0u8
                            } else if bt.contains(".AND") {
                                1
                            } else {
                                2
                            };
                            utca_v.push((ii as u32, kind));
                        }
                        if base0u == "ATOMS" {
                            if let Some(ob) = bt.find('[') {
                                let inner = &bt[ob + 1..];
                                if let Some(cb) = inner.find(']') {
                                    let tok = &inner[..cb];
                                    if let Some(pp) = tok.find('+') {
                                        let im = tok[pp + 1..].trim();
                                        let imm = u32::from_str_radix(
                                            im.trim_start_matches("0x"),
                                            16,
                                        )
                                        .or_else(|_| im.parse::<u32>())
                                        .unwrap_or(0);
                                        if imm != 0 {
                                            let op = if bt.contains(".OR") {
                                                0u8
                                            } else if bt.contains(".AND") {
                                                1
                                            } else {
                                                2
                                            };
                                            atom_smem_v.push((ii as u32, imm, op));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    meta.merc_utca = utca_v;
                    meta.merc_atom_smem = atom_smem_v;
                    meta.merc_bra_selfloop = bra_sl_v;
                    if has_voteu {
                        meta.merc_wwide_sites = wwide_v;
                    }
                    // mk14.3: LDGSTS pinned/wait hosty (lustro merc_ldgsts_scan).
                    // mk53: pelny silnik blobow (nadrzedny nad mk14-pin).
                    {
                        let lines: Vec<(u32, String)> = insns
                            .iter()
                            .enumerate()
                            .map(|(ii, (_a, t))| (ii as u32, t.clone()))
                            .collect();
                        let l2 = cubit::mercury::merc_ldgsts2_scan(&lines, kernel_name);
                        let l2w = cubit::mercury::merc_ldgsts2_waits(&lines);
                        let (pin, wait) = cubit::mercury::merc_ldgsts_scan(&lines);
                        let l2_nonempty = !l2.is_empty();
                        if l2_nonempty {
                            meta.merc_ldgsts2 = l2;
                            meta.merc_ldgsts2_waits = l2w;
                        }
                        // mk55: legacy pin tylko gdy silnik mk53 pusty; legacy
                        // wait-host ustawiany ZAWSZE (karmi feat_host_zero w
                        // bitmapie — jak mk53/54); emisje REKORDU w obu
                        // przypadkach rozstrzyga elf_builder (tylko sciezka
                        // bez desc-form; imm niesione od mk55).
                        if !l2_nonempty {
                            if let Some(p3) = pin {
                                meta.merc_ldgsts_pin = vec![p3];
                            }
                        }
                        if let Some(w) = wait {
                            meta.merc_ldgsts_wait = vec![w];
                        }
                    }
                    if !stg_pos2.is_empty() {
                        meta.merc_stg_desc_pos = stg_pos2;
                    }
                    // mk30: lustro merc_mc_scan (tekstowe; b_* rodziny).
                    {
                        use cubit::mercury::{McScanText as MC, mc_scan_lines};
                        let items: Vec<MC> = insns
                            .iter()
                            .enumerate()
                            .map(|(ii, (_a, asm))| {
                                let bt = asm.trim();
                                let (guard, rest, gcode) = {
                                    let st0 = bt.strip_prefix('@');
                                    match st0 {
                                        Some(st) => {
                                            let (neg, st1) = match st.strip_prefix('!') {
                                                Some(r) => (true, r),
                                                None => (false, st),
                                            };
                                            // mk44: peelen kod pred guarda
                                            // ( idx<<3 |u2|neg1; PT/absent -> f8).
                                            let mut w = st1.split_whitespace();
                                            let pt = w.next().unwrap_or("");
                                            let (uni, pn) = match pt.strip_prefix('U') {
                                                Some(r) => (true, r),
                                                None => (false, pt),
                                            };
                                            let num = pn.strip_prefix('P')
                                                .and_then(|n| n.parse::<u8>().ok());
                                            let code = match num {
                                                Some(n) if n <= 6 => (n << 3)
                                                    | (if uni { 2 } else { 0 })
                                                    | (if neg { 1 } else { 0 }),
                                                _ => 0xf8,
                                            };
                                            let rest = match st1.find(char::is_whitespace) {
                                                Some(k) => st1[k..].trim_start(),
                                                None => st1,
                                            };
                                            (if neg { 2u8 } else { 1u8 }, rest, code)
                                        }
                                        None => (0u8, bt, 0xf8),
                                    }
                                };
                                let fw = rest.split_whitespace().next().unwrap_or("");
                                let base = fw.split('.').next().unwrap_or("").to_string();
                                MC {
                                    lane: ii as u32,
                                    base,
                                    full: fw.to_string(),
                                    text: rest.to_string(),
                                    guarded: guard != 0,
                                    guard_code: gcode,
                                }
                            })
                            .collect();
                        let mc = mc_scan_lines(&items);
                        meta.merc_mc_exch = mc.exch;
                        meta.merc_mc_arrive = mc.arrive;
                        meta.merc_mc_phase = mc.phase;
                        meta.merc_mc_d1 = mc.uiadd3_1m;
                        meta.merc_mc_ushf_fin = mc.ushf_fin;
                        meta.merc_mc_voteu_all = mc.voteu_all;
                        meta.merc_mc_mov400 = mc.mov400;
                        meta.merc_mc_lea18 = mc.lea18;
                        meta.merc_ws_minis = mc.ws;
                        meta.merc_uvcount = mc.uvcount;
                        meta.merc_umov_rr = mc.umov_rr;
                        meta.merc_ublkcp = mc.ublkcp;
                        meta.merc_plop3_tx = mc.plop3_tx;
                        meta.merc_plop3_rec = mc.plop3_rec;
                        meta.merc_plop3u_rec = mc.plop3u_rec;
                        meta.merc_uplop3_rec = mc.uplop3_rec;
                        meta.merc_dsetpimm_rec = mc.dsetpimm_rec;
                        meta.merc_fence_async = mc.fence_async;
                        meta.merc_ldgsts_b128 = mc.ldgsts_b128;
                        meta.merc_s2ur_cga = mc.s2ur_cga;
                        meta.merc_geo_rec = mc.geo_rec;
                        meta.merc_bsync_close = mc.bsync_close;
                        meta.merc_hfma2_const = mc.hfma2_const;
                        meta.merc_mc_ulea_x = mc.ulea_x;
                        meta.merc_mc_bra_np = mc.bra_np_loop;
                        meta.merc_mc_nodeless = mc.nodeless;
                        meta.merc_param_load_dreg = load_dregs35.clone();
                        meta.merc_bar_guard = bar_guard35.clone();
                        meta.merc_isetp_ur = isetp_ur35.clone();
                        meta.merc_xsetp_pairs = xsetp_pairs35.clone();
                        usetp_minis35.sort_by_key(|e| e.0);
                        meta.merc_usetp_minis = usetp_minis35.clone();
                        meta.merc_ulea_upco = ulea_upco35.clone();
                        meta.merc_store2 = store2m;
                        meta.merc_f64imm = f64imm_sc;
                        meta.merc_dfmaimm = dfmaim_sc;
                        meta.merc_mini2 = mini2m;
                        edge_ldm.sort_by_key(|e| e.0);
                        meta.merc_edge_ld = edge_ldm;
                        meta.merc_edge_maxur = edge_maxur_m;
                        edge_ldgm.sort_by_key(|e| e.0);
                        meta.merc_edge_ldg = edge_ldgm;
                        meta.merc_stg_wsel = stg_wselv;
                        meta.merc_redux = redux35.clone();
                        meta.merc_cbank358_dreg = cbank358_dreg35;
                    }
                }
            }
        }

        println!(
            "  {kernel_name}: regcount={}, barriers={}, exits={}",
            meta.regcount,
            meta.num_barriers,
            meta.exit_offsets.len()
        );

        // tcgen05/TMA-class instruction mix: the static CAPMERC_EXIT_STUB does
        // not describe tensor-core resources. A wrong stub is worse than none:
        // with no Mercury sections the driver falls back to analysing .text
        // (SM120 evidence: works for QMMA; SM103a: FA4-class cubin loads and
        // resolves fine — see blackwell-isa MERCURY_SM103A_STATUS).
        let has_tensor_class = insns.iter().any(|(_a, asm)| {
            let m = asm
                .split_whitespace()
                .find(|t| !t.starts_with('@'))
                .unwrap_or("");
            let base = m.split('.').next().unwrap_or("");
            matches!(
                base,
                "UTCHMMA"
                    | "UTCQMMA"
                    | "UTCIMMA"
                    | "UTCMXQMMA"
                    | "UDLCQMMA"
                    | "UDLCIMMA"
                    | "UDLCFIMMA"
                    | "QMMA"
                    | "UTMALDG"
                    | "UTMASTG"
                    | "UTCBAR"
                    | "TCBAR"
                    | "TPCOMMIT"
            )
        });
        if has_tensor_class {
            tensor_class_kernels = true;
        }

        entries.push(KernelEntry {
            name: kernel_name.clone(),
            code: code_bytes,
            meta,
            mercury_stub: mercury_stub_data.map(|s| s.to_vec()),
            opcodes: Some(
                insns
                    .iter()
                    .map(|(_a, asm)| {
                        let m = asm
                            .split_whitespace()
                            .find(|t| !t.starts_with('@'))
                            .unwrap_or("");
                        // mk13a: pelny mnemoniczek (patrz kops w cmd_asm).
                        m.to_string()
                    })
                    .collect(),
            ),
        });
    }

    if entries.is_empty() {
        anyhow::bail!("no kernels assembled (check --kernel filter or sass file format)");
    }

    merge_syncwarp_from_reference(&mut entries, eiattr_path);
    // If --eiattr-from is provided, use rebuild_cubin (copies ELF structure +
    // EIATTR from reference, replaces only .text sections with new instruction bytes)
    let cubin_bytes = if let Some(ref_path) = eiattr_path {
        use cubit::elf_builder::rebuild_cubin;
        println!("Using EIATTR from: {}", ref_path.display());
        let ref_bytes = std::fs::read(ref_path)
            .with_context(|| format!("cannot read {}", ref_path.display()))?;
        let patches: Vec<cubit::elf_builder::CubinPatch> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.code.clone(), e.mercury_stub.clone()))
            .collect();
        rebuild_cubin(&ref_bytes, &patches)?
    } else {
        use cubit::elf_builder::{build_cubin_for_arch, build_cubin_mercury_for_arch};
        if tensor_class_kernels {
            eprintln!(
                "note: tcgen05/TMA-class instructions present and no explicit \
                           --mercury-stub — emitting a Mercury-free cubin so the driver \
                           falls back to .text analysis (the static stub does not \
                           describe tensor-core resources)."
            );
            build_cubin_for_arch(&entries, table.ef_flags)?
        } else {
            build_cubin_mercury_for_arch(&entries, table.ef_flags)?
        }
    };

    std::fs::write(output_path, &cubin_bytes)?;

    println!(
        "\nWritten: {} ({} bytes)",
        output_path.display(),
        cubin_bytes.len()
    );
    println!("Total:   {total_enc}/{total_insns} encoded ({total_fail} failed)");
    if eiattr_path.is_none() {
        println!("Note: metadata inferred from instructions — parameters/stack may be incomplete.");
        println!("Tip: use --eiattr-from <reference.cubin> for driver-compatible EIATTR records.");
    }
    Ok(())
}

/// Lint standalone kernels — no-op, kept for call-site compatibility.
///
/// NOTE: An earlier hypothesis that SM120 requires LDCU (not LDC) for kernel
/// parameter loads was INCORRECT.  Empirical testing on RTX 5090 confirms that
/// the CUDA 12.8 driver writes kernelParams[] to the regular constant bank
/// (accessible via LDC), not the uniform constant bank.  LDCU reads the UCB and
/// returns uninitialised values for parameter offsets, causing illegal memory
/// access.  nvcc 12.8 also emits LDC.64 for parameter loads on SM120.
fn lint_kparam_ldcu(_def: &cubit::sass_file::KernelDef, _standalone: bool) {}

/// Assemble a .sass file with .entry/.endentry directives.
fn cmd_asm_directive_format(
    table: &IsaTable,
    sass_text: &str,
    template_path: Option<&std::path::Path>,
    eiattr_path: Option<&std::path::Path>,
    output_path: &PathBuf,
    only_kernel: Option<&str>,
    mercury_stub: Option<&[u8]>,
) -> Result<()> {
    use cubit::elf_builder::KernelEntry;
    use cubit::sass_file::{auto_detect_resources, kernel_def_to_meta, parse_sass_file_str};

    let mut sass_file = parse_sass_file_str(sass_text).context("failed to parse .sass file")?;

    let mut tensor_class_kernels = false;

    // Auto-detect register counts if not declared
    for def in &mut sass_file.kernels {
        auto_detect_resources(def);
    }

    // tcgen05 (UTCHMMA & friends) / TMA gate: route to the Mercury-free builder
    // unless the user supplied an explicit stub. See blackwell-isa-internal
    // docs/MERCURY_SM103A_STATUS.md for the evidence trail.
    {
        let tensor_hit = sass_file.kernels.iter().any(|def| {
            def.instructions.iter().any(|ins| {
                matches!(
                    ins.opcode.as_str(),
                    "UTCHMMA"
                        | "UTCQMMA"
                        | "UTCIMMA"
                        | "UTCMXQMMA"
                        | "UDLCQMMA"
                        | "UDLCIMMA"
                        | "UDLCFIMMA"
                        | "QMMA"
                        | "UTMALDG"
                        | "UTMASTG"
                        | "UTCBAR"
                        | "TCBAR"
                        | "TPCOMMIT"
                )
            })
        });
        if tensor_hit {
            tensor_class_kernels = true;
        }
    }

    if sass_file.kernels.is_empty() {
        anyhow::bail!("no .entry definitions found in sass file");
    }

    // Standalone mode = no template and no eiattr reference.
    // In this mode kernel parameters come from the UCB (uniform constant memory),
    // so LDC accesses to the KPARAM range are always wrong.
    let standalone = template_path.is_none() && eiattr_path.is_none();
    for def in &sass_file.kernels {
        lint_kparam_ldcu(def, standalone);
    }

    let mut entries: Vec<KernelEntry> = Vec::new();
    let mut total_enc = 0u64;
    let mut total_fail = 0u64;

    for def in &sass_file.kernels {
        if let Some(only) = only_kernel {
            if def.name != only {
                continue;
            }
        }

        // Scheduling pass: register dependency tracking + multi-barrier allocation.
        // Pass the table so ctrl_class constraints are enforced (MUFU, IADD3+RZ, etc.).
        let mut insns_with_ctrl: Vec<cubit::Instruction> = def.instructions.to_vec();
        // Preserve mode: a fully [CC]-frozen kernel (every instruction carries an explicit
        // schedule prefix, e.g. from `disassemble --frozen`) owns its schedule verbatim.
        // schedule() honors hand_sched per-insn, but the inline post-passes below (MMA
        // drains, store WAR read-barriers, etc.) do NOT — so for a frozen kernel they must be
        // skipped wholesale, otherwise they rewrite ptxas's exact control codes (observed:
        // dropped barrier-waits, shortened branch/BAR stalls, reallocated rb, inserted drains).
        let fully_frozen =
            !insns_with_ctrl.is_empty() && insns_with_ctrl.iter().all(|x| x.hand_sched);
        cubit::scheduling_pass::schedule(&mut insns_with_ctrl, Some(table));
        // Barrier allocation: the unified interval-based allocator (reallocate_barriers, run
        // at the END below, after all instruction insertions) re-derives RAW write-barriers +
        // WAR read-barriers by liveness — occupancy-robust by construction.
        cubit::scheduling_pass::insert_stall_gaps(&mut insns_with_ctrl, Some(table));
        // NOTE: reallocate_barriers (the correct allocator) runs at the END, after the MMA
        // writeback-drain insertion below — those drains supply the cooperative-MMA
        // accumulator distance (MMA output is not scoreboarded), which barriers can't.

        // CUBIT_MMA_WAIT (env-gated): let the MMA KEEP its scheduler-assigned wait_mask
        // (ptxas discipline: the barrier wait sits directly on the HMMA, `[B-1----] HMMA`)
        // instead of cubit's strip + bursty input/writeback drain. ptxas's wait-on-the-MMA
        // schedule runs correctly at 2 CTAs/SM; cubit's strip+drain FAILS at 2 CTAs/SM.
        // Default (unset) keeps the legacy strip+drain behavior unchanged.
        // CUBIT_SCHED2 folds in the MMA-keeps-its-wait discipline (the consuming MMA waits
        // the shared input-load barrier directly; no strip + drain-all pre-drain).
        let mma_wait = (std::env::var("CUBIT_MMA_WAIT").is_ok()
            || std::env::var("CUBIT_SCHED2").is_ok())
            && std::env::var("CUBIT_NO_MMA_WAIT").is_err();

        // Post-scheduling: insert UIADD3 URZ drain before each warp MMA (QMMA/HMMA/…).
        // SM120 MMA wait_mask breaks warp-cooperative accumulation (each bit = 2x loss).
        // nvcc inserts UIADD3 URZ with barrier waits before the MMA, keeping it clean.
        // Runs for BOTH paths: the MMA writeback drains provide the cooperative-MMA
        // accumulator distance. In the new-allocator path reallocate_barriers (at the end)
        // re-derives the load/store barriers on top; here we keep the MMA stall/drain timing.
        if !fully_frozen {
            {
                let is_mma = |op: &str| matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA");
                let mut inserts: Vec<(usize, u8)> = Vec::new();
                for (i, insn) in insns_with_ctrl.iter().enumerate() {
                    // hand-scheduled MMAs own their input drain — don't auto-insert one.
                    // CUBIT_MMA_WAIT: the wait stays on the MMA itself, so no pre-drain at all.
                    if is_mma(&insn.opcode)
                        && insn.ctrl.wait_mask != 0
                        && !insn.hand_sched
                        && !mma_wait
                    {
                        inserts.push((i, insn.ctrl.wait_mask));
                    }
                }
                for (idx, wm) in inserts.into_iter().rev() {
                    let drain = cubit::Instruction {
                        addr: 0,
                        opcode: "UIADD3".into(),
                        opcode_full: "UIADD3".into(),
                        key: "UIADD3_UR_UP_UP_UR_UR_UR/".into(),
                        guard: None,
                        operands: vec![
                            cubit::ir::Operand::UReg {
                                num: 63,
                                neg: false,
                                abs: false,
                                inv: false,
                                reuse: false,
                                is_zero: true,
                            },
                            cubit::ir::Operand::UPred { num: 7, neg: false },
                            cubit::ir::Operand::UPred { num: 7, neg: false },
                            cubit::ir::Operand::UReg {
                                num: 63,
                                neg: false,
                                abs: false,
                                inv: false,
                                reuse: false,
                                is_zero: true,
                            },
                            cubit::ir::Operand::UReg {
                                num: 63,
                                neg: false,
                                abs: false,
                                inv: false,
                                reuse: false,
                                is_zero: true,
                            },
                            cubit::ir::Operand::UReg {
                                num: 63,
                                neg: false,
                                abs: false,
                                inv: false,
                                reuse: false,
                                is_zero: true,
                            },
                        ],
                        modifiers: vec![],
                        // stall>=12: a UIADD3 drain carrying a wait_mask needs >=12 cycles for the
                        // waited barriers to RETIRE before the consumer (the MMA) issues. At <12 the
                        // retirement is incomplete at high occupancy (2+ CTAs/SM = 4+ warps/SMSP) and
                        // the MMA reads STALE inputs -> deterministic wrong output. (SM120 barrier
                        // retirement latency; see SM120_BARRIER_SCHEDULING Finding 1. stall=1 worked
                        // only at 1 CTA/SM.) 15 = max, safe across occupancy.
                        ctrl: cubit::ir::ControlCode {
                            stall: 15,
                            wait_mask: wm,
                            ..Default::default()
                        },
                        hand_sched: false,
                        rsd: None,
                        raw_text: "/* QMMA barrier drain */".into(),
                    };
                    insns_with_ctrl.insert(idx, drain);
                }
                // SM120 does NOT honor a write_bar on cooperative MMA writeback (empirically
                // re-confirmed: a drain waiting the MMA's assigned barrier still reads a stale
                // accumulator at 2 CTAs/SM). The barrier is cleared; writeback sync is timing-based.
                // The MMA's own stall is part of the timing-based writeback sync. Default 11
                // (cubit heuristic); ptxas uses stall=1 on the cooperative HMMA and moves the
                // settle onto the following NOP/back-edge. CUBIT_MMA_STALL forces an exact value
                // (experiment: match ptxas's stall=1).
                let mma_stall_override: Option<u8> = std::env::var("CUBIT_MMA_STALL")
                    .ok()
                    .and_then(|s| s.parse().ok());
                for insn in insns_with_ctrl.iter_mut() {
                    // Bug fix: never rewrite ctrl of frozen (hand-scheduled) MMAs — the author
                    // owns their schedule. (Independent of CUBIT_MMA_WAIT.)
                    if is_mma(&insn.opcode) && !insn.hand_sched {
                        insn.ctrl.write_bar = 7;
                        // CUBIT_MMA_WAIT: KEEP the scheduler-assigned wait_mask on the MMA
                        // (ptxas puts the barrier wait directly on the HMMA). Default strips it.
                        if !mma_wait {
                            insn.ctrl.wait_mask = 0;
                        }
                        insn.ctrl.yield_flag = true;
                        insn.ctrl.stall = match mma_stall_override {
                            Some(v) => v,
                            // CUBIT_MMA_WAIT: ptxas runs the cooperative HMMA tight (small stall)
                            // and settles on the following NOP; default uses the heavy .max(11).
                            None => {
                                if mma_wait {
                                    insn.ctrl.stall.max(2)
                                } else {
                                    insn.ctrl.stall.max(11)
                                }
                            }
                        };
                    }
                }
                // CUBIT_MMA_WAIT/SCHED2: settle the cooperative writeback with a stall on the
                // instruction right AFTER the MMA (ptxas emits `NOP S13` there), rather than
                // cubit's @!UPT drain block. The MMA already waits its input barrier; this
                // guarantees the F32 accumulator (R4..R7) is fully committed to the register
                // file before the next iteration's MMA reads it back as the C accumulator and
                // before the loop-exit store reads D. Too short a settle leaves the LAST-
                // committed accumulator register (empirically R6/c2) stale on ~half the
                // d-slices -> wrong output. Tunable via CUBIT_MMA_WAIT_STALL (default 13).
                if mma_wait {
                    let settle: u8 = std::env::var("CUBIT_MMA_WAIT_STALL")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(13);
                    let mut bumps: Vec<usize> = Vec::new();
                    for (i, insn) in insns_with_ctrl.iter().enumerate() {
                        if is_mma(&insn.opcode)
                            && !insn.hand_sched
                            && insns_with_ctrl.get(i + 1).is_some_and(|n| !n.hand_sched)
                        {
                            bumps.push(i + 1);
                        }
                    }
                    for idx in bumps {
                        insns_with_ctrl[idx].ctrl.stall =
                            insns_with_ctrl[idx].ctrl.stall.max(settle);
                        // CUBIT_SCHED2 RULE 2: the settle stall is applied AFTER the scheduler
                        // set the yield, so re-apply the yield rule for the bumped instruction
                        // (a >=12 settle clears Y — ptxas emits the post-HMMA `NOP S13` as -Y).
                        if std::env::var("CUBIT_SCHED2").is_ok()
                            && std::env::var("CUBIT_SCHED2_NOYIELD").is_err()
                            && insns_with_ctrl[idx].ctrl.stall >= 12
                        {
                            insns_with_ctrl[idx].ctrl.yield_flag = false;
                        }
                    }
                }
                for (i, insn) in insns_with_ctrl.iter_mut().enumerate() {
                    insn.addr = (i * 16) as u32;
                }
            }

            // Post-scheduling: insert @!UPT UIADD3 URZ writeback drains after QMMA.
            //
            // SM120 QMMA cooperative writeback is NOT visible to ALU instructions
            // (FMUL, FADD, etc.) without explicit synchronization. Stores also need the
            // writeback to be committed: a STG.E.128 reading the full F32 accumulator
            // (R0..R3) will store a stale high half (R2,R3) unless enough delay follows
            // the drains (see drain #2 stall below).
            //
            // nvcc emits 2x `@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ` immediately
            // after QMMA to force writeback. The @!UPT guard (bit 15 = 1) is the
            // hardware-recognized QMMA writeback sync pattern.
            //
            // CRITICAL: drains must be IMMEDIATELY after QMMA (0 instructions between).
            // Loop instructions (IADD/ISETP/BRA) between QMMA and drain break sync.
            // Drains INSIDE a loop reset accumulation (all zeros).
            //
            // Strategy:
            // - Standalone QMMA: insert 2x @!UPT drain immediately after
            // - QMMA in loop: WARN — kernel must be unrolled for correct ALU access.
            //   (STG-based output still works without drains.)
            {
                let wb_drain = |stall: u8| cubit::ir::Instruction {
                    addr: 0,
                    opcode: "UIADD3".into(),
                    opcode_full: "UIADD3".into(),
                    key: "UIADD3_UR_UP_UP_UR_UR_UR".into(),
                    guard: Some(cubit::ir::Guard {
                        pred: 7,
                        negated: true,
                        uniform: true,
                    }),
                    operands: vec![
                        cubit::ir::Operand::UReg {
                            num: 63,
                            neg: false,
                            abs: false,
                            inv: false,
                            reuse: false,
                            is_zero: true,
                        },
                        cubit::ir::Operand::UPred { num: 7, neg: false },
                        cubit::ir::Operand::UPred { num: 7, neg: false },
                        cubit::ir::Operand::UReg {
                            num: 63,
                            neg: false,
                            abs: false,
                            inv: false,
                            reuse: false,
                            is_zero: true,
                        },
                        cubit::ir::Operand::UReg {
                            num: 63,
                            neg: false,
                            abs: false,
                            inv: false,
                            reuse: false,
                            is_zero: true,
                        },
                        cubit::ir::Operand::UReg {
                            num: 63,
                            neg: false,
                            abs: false,
                            inv: false,
                            reuse: false,
                            is_zero: true,
                        },
                    ],
                    modifiers: vec![],
                    ctrl: cubit::ir::ControlCode {
                        stall,
                        wait_mask: 0,
                        ..Default::default()
                    },
                    hand_sched: false,
                    rsd: None,
                    raw_text: "/* QMMA writeback sync drain (@!UPT) */".into(),
                };

                // Detect which QMMAs are inside loops.
                // A QMMA is "in a loop" if there's a backward BRA AFTER the QMMA
                // whose target is AT OR BEFORE the QMMA (i.e., the loop body spans the QMMA).
                struct LoopRegion {
                    target: u32,
                    bra_addr: u32,
                }
                let mut loops: Vec<LoopRegion> = Vec::new();
                for insn in insns_with_ctrl.iter() {
                    // Conditional backward BRA = loop back-edge. The condition is either a
                    // per-lane guard (@P3 BRA) OR a uniform predicate operand (BRA.U UP3) —
                    // uniform branches carry the predicate as an operand, not a guard.
                    let is_conditional = insn.guard.is_some()
                        || insn.operands.iter().any(|o| match o {
                            cubit::ir::Operand::Pred { num, .. }
                            | cubit::ir::Operand::UPred { num, .. } => *num != 7,
                            _ => false,
                        });
                    if insn.opcode == "BRA" && is_conditional {
                        // Only conditional BRAs are loop back-edges (unconditional = tail BRA)
                        if let Some(target) = insn.operands.iter().find_map(|o| match o {
                            cubit::ir::Operand::Imm32(v) => Some(*v as u32),
                            cubit::ir::Operand::BranchTarget(a) => Some(*a),
                            _ => None,
                        }) {
                            if target < insn.addr {
                                loops.push(LoopRegion {
                                    target,
                                    bra_addr: insn.addr,
                                });
                            }
                        }
                    }
                }

                let is_mma = |op: &str| matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA");

                // ── HARDENING GUARD (detect-only, no auto-rewrite) ──────────────────────────
                // SM120 hazard: a load whose address register is produced by `MOV Raddr, Rsrc`
                // (a fresh copy of an advancing base, refreshed every iteration) INSIDE a loop
                // that also contains an MMA returns WRONG data — even with byte-identical @sched
                // to the working form. ptxas never emits this: it uses base+immediate-offset
                // addressing and advances the base IN PLACE with IADD. We only WARN here (no
                // rewrite); the fix in the .sass is to advance the pointer in place
                // (`IADD[.64] Raddr, Raddr, <stride>`).
                //
                // The SAFE idiom — reset a pointer to a loop-INVARIANT base in an outer loop and
                // then advance it in place in the inner loop — must NOT be flagged. We therefore
                // require BOTH: (1) the load base is written by a register-source MOV in the loop,
                // AND (2) the load base is NOT advanced in place anywhere in that loop (no
                // IADD/IADD3/IMAD whose dest is the base and reads the base). In-place advance is
                // the ptxas-canonical pattern, so its presence means the address is safe.
                {
                    use std::collections::{HashMap, HashSet};
                    let is_load = |op: &str| matches!(op, "LDG" | "LD" | "LDS" | "LDL" | "LDSM");
                    let load_base = |insn: &cubit::ir::Instruction| -> Option<u8> {
                        insn.operands.iter().find_map(|o| match o {
                            cubit::ir::Operand::Addr { base_reg, .. } => *base_reg,
                            cubit::ir::Operand::Desc { base_reg, .. } => *base_reg,
                            cubit::ir::Operand::ConstMem { base_reg, .. } => *base_reg,
                            _ => None,
                        })
                    };
                    // MOV Rdst, Rsrc — only a register source is the advancing-base hazard;
                    // an immediate-source MOV materializes a constant address and is fine.
                    let mov_reg_dest = |insn: &cubit::ir::Instruction| -> Option<u8> {
                        if insn.opcode != "MOV" {
                            return None;
                        }
                        if !matches!(insn.operands.get(1), Some(cubit::ir::Operand::Reg { .. })) {
                            return None;
                        }
                        match insn.operands.first() {
                            Some(cubit::ir::Operand::Reg { num, .. }) => Some(*num),
                            _ => None,
                        }
                    };
                    // dest of an in-place self-update: IADD/IADD3/IMAD where dest reg also appears
                    // as a source (Rd = Rd + …) — i.e. the canonical in-place pointer advance.
                    let inplace_dest = |insn: &cubit::ir::Instruction| -> Option<u8> {
                        if !matches!(insn.opcode.as_str(), "IADD" | "IADD3" | "IMAD") {
                            return None;
                        }
                        let dest = match insn.operands.first() {
                            Some(cubit::ir::Operand::Reg { num, .. }) => *num,
                            _ => return None,
                        };
                        let self_read = insn.operands.iter().skip(1).any(
                            |o| matches!(o, cubit::ir::Operand::Reg { num, .. } if *num == dest),
                        );
                        if self_read {
                            Some(dest)
                        } else {
                            None
                        }
                    };
                    let mut warned_loads: HashSet<u32> = HashSet::new();
                    for l in loops.iter() {
                        let has_mma = insns_with_ctrl.iter().any(|x| {
                            is_mma(&x.opcode) && l.target <= x.addr && x.addr <= l.bra_addr
                        });
                        if !has_mma {
                            continue;
                        }
                        let mut mov_bases: HashMap<u8, u32> = HashMap::new();
                        let mut inplace: HashSet<u8> = HashSet::new();
                        for x in insns_with_ctrl
                            .iter()
                            .filter(|x| l.target <= x.addr && x.addr <= l.bra_addr)
                        {
                            if let Some(d) = mov_reg_dest(x) {
                                mov_bases.entry(d).or_insert(x.addr);
                            }
                            if let Some(d) = inplace_dest(x) {
                                inplace.insert(d);
                            }
                        }
                        if mov_bases.is_empty() {
                            continue;
                        }
                        for ld in insns_with_ctrl.iter().filter(|x| {
                            is_load(&x.opcode) && l.target <= x.addr && x.addr <= l.bra_addr
                        }) {
                            if let Some(b) = load_base(ld) {
                                if inplace.contains(&b) {
                                    continue;
                                } // safe: advanced in place
                                if let Some(&mov_addr) = mov_bases.get(&b) {
                                    if warned_loads.insert(ld.addr) {
                                        eprintln!("  WARN: SM120 MOV->load-address hazard: {} at 0x{:04x} \
                                               reads [R{}] whose address is set by `MOV R{}, <reg>` at \
                                               0x{:04x} (no in-place advance) inside an MMA loop \
                                               [0x{:04x}..0x{:04x}]. This pattern returns WRONG data on \
                                               SM120. Advance the pointer in place instead: \
                                               `IADD[.64] R{}, R{}, <stride>` (matches ptxas \
                                               base+imm / in-place-advance codegen).",
                                              ld.opcode, ld.addr, b, b, mov_addr,
                                              l.target, l.bra_addr, b, b);
                                    }
                                }
                            }
                        }
                    }
                }

                // Experimental "nvcc-style" writeback settle for accumulating MMA loops
                // (the sparse-MLA PV loop): instead of a rigid fixed-stall drain block right
                // after the MMA, settle the cooperative writeback the way nvcc does — a stall
                // on the loop back-edge branch plus the natural loop body. This keeps cubit's
                // correct barrier assignment but removes the rigid per-iteration block that
                // makes co-resident CTAs phase-lock. Gated (default = legacy rigid drain).
                //   CUBIT_PV_SETTLE=backedge          enable
                //   CUBIT_PV_SETTLE_STALL=<n>         per-back-edge stall (default 15, nvcc's)
                let pv_backedge =
                    std::env::var("CUBIT_PV_SETTLE").ok().as_deref() == Some("backedge");
                let backedge_stall: u8 = std::env::var("CUBIT_PV_SETTLE_STALL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(15);
                let mut backedge_bras: Vec<u32> = Vec::new();
                let mut inserts: Vec<usize> = Vec::new();
                for (i, insn) in insns_with_ctrl.iter().enumerate() {
                    if !is_mma(&insn.opcode) {
                        continue;
                    }
                    // Hand-scheduled MMA (`[CC]` in source): the author owns the writeback
                    // settle (e.g. an nvcc-mirrored PV loop). Skip the auto writeback-drain.
                    if insn.hand_sched {
                        continue;
                    }
                    // MMA is in a loop if any loop region [target, bra_addr] spans it
                    let in_loop = loops
                        .iter()
                        .any(|l| l.target <= insn.addr && insn.addr <= l.bra_addr);
                    if in_loop {
                        // Two kinds of in-loop MMA:
                        //  - ACCUMULATING (e.g. K-loop QK): the accumulator is loop-carried and
                        //    the result is read AFTER the loop. A mid-loop @!UPT drain resets the
                        //    tensor-core accumulation -> must be skipped.
                        //  - INDEPENDENT-per-iteration (e.g. PV: zero->MMA->store each iter): the
                        //    output is consumed WITHIN the loop body, so it needs the writeback
                        //    drain before that consumer (else the store reads the stale/zero accum).
                        // Distinguish by looking for an in-loop consumer of the MMA destination
                        // (a source read of D..D+3) between the MMA and the loop back-edge.
                        let dest_base = match insn.operands.first() {
                            Some(cubit::ir::Operand::Reg { num, .. }) => Some(*num),
                            _ => None,
                        };
                        let bra_addr = loops
                            .iter()
                            .filter(|l| l.target <= insn.addr && insn.addr <= l.bra_addr)
                            .map(|l| l.bra_addr)
                            .min()
                            .unwrap_or(insn.addr);
                        // SM120 cooperative-MMA writeback is UNSCOREBOARDED (wb=- forced), so the
                        // ONLY guarantee that the accumulator D..D+4 has committed before a reader is
                        // a timing settle. We must insert that settle after the MMA for EVERY consumer
                        // of D. A "consumer" reads D as a SOURCE operand (skip the dest, operand 0).
                        let reads_dest = |x: &cubit::ir::Instruction| -> bool {
                            match dest_base {
                                Some(base) => {
                                    let hi = base.saturating_add(4);
                                    x.operands.iter().skip(1).any(|o| matches!(o,
                                    cubit::ir::Operand::Reg { num, .. } if *num >= base && *num < hi))
                                }
                                None => false,
                            }
                        };
                        // Three consumer patterns, each needing the post-MMA writeback settle:
                        //  - INDEPENDENT-per-iter: a consumer (store) reads D within the loop body.
                        //  - LOOP-CARRIED accumulator: the MMA reads its own D as C-input, so the
                        //    NEXT iteration's MMA is the consumer and the settle must cover the loop
                        //    tail. (Previously MISSED -> no settle -> stale accumulator read, wrong
                        //    even at 1 CTA/SM. This was the systemic gap.)
                        //  - LOOP-EXIT: the instruction right after the back-edge reads D.
                        // An in-loop drain after the MMA does NOT reset accumulation (the cooperative
                        // writeback commits to the register file; the next MMA reads it back as C).
                        let consumed = insns_with_ctrl
                            .iter()
                            .filter(|x| x.addr > insn.addr && x.addr <= bra_addr)
                            .any(&reads_dest);
                        let bra_idx = insns_with_ctrl.iter().position(|x| x.addr == bra_addr);
                        let post = bra_idx
                            .and_then(|bidx| insns_with_ctrl.get(bidx + 1))
                            .is_some_and(|nxt| !is_mma(&nxt.opcode) && reads_dest(nxt));
                        // LOOP-CARRIED accumulator (MMA reads its own D as C): the consumer is the
                        // NEXT iteration's MMA. Only force a writeback drain if the loop's NATURAL
                        // settle (sum of stalls around the back-edge, MMA->bra->top->MMA) is below
                        // the commit target. A long K-loop already has ample natural settle, so
                        // piling on rigid drains there is pure waste AND worsens the 2-CTA writeback
                        // resonance (measured: it dropped our kernel 9/16 -> 2/16). A TIGHT
                        // accumulator loop (e.g. a bare P*V k-loop) has no natural settle and would
                        // otherwise read a stale accumulator (wrong even at 1 CTA/SM).
                        let accum_needs_settle = if reads_dest(insn) && !consumed && !post {
                            let target = std::env::var("CUBIT_MMA_WB_DRAIN")
                                .ok()
                                .and_then(|s| s.parse::<u32>().ok())
                                .unwrap_or(46);
                            let loop_top = loops
                                .iter()
                                .filter(|l| l.target <= insn.addr && insn.addr <= l.bra_addr)
                                .map(|l| l.target)
                                .min()
                                .unwrap_or(insn.addr);
                            // approx issue-cycle distance from this MMA around the back-edge back to it
                            let natural: u32 = insn.ctrl.stall as u32
                                + insns_with_ctrl
                                    .iter()
                                    .filter(|x| {
                                        (x.addr > insn.addr && x.addr <= bra_addr)
                                            || (x.addr >= loop_top && x.addr < insn.addr)
                                    })
                                    .map(|x| x.ctrl.stall as u32 + 1)
                                    .sum::<u32>();
                            natural < target
                        } else {
                            false
                        };
                        if consumed || post || accum_needs_settle {
                            inserts.push(i + 1);
                            // nvcc-style settle (gated): bulk delay on the loop back-edge.
                            if pv_backedge {
                                backedge_bras.push(bra_addr);
                            }
                        } else if reads_dest(insn) {
                            // loop-carried accumulator with ample natural settle -> no drain needed
                        } else {
                            eprintln!(
                                "  WARN: {} at 0x{:04x} is inside a loop but its accumulator has \
                                   no detected consumer; writeback settle NOT inserted.",
                                insn.opcode, insn.addr
                            );
                        }
                    } else {
                        // Standalone MMA: insert drains immediately after
                        inserts.push(i + 1);
                    }
                }
                inserts.sort();
                inserts.dedup();
                // MMA writeback commit delay (cycles AFTER the MMA's own stall).
                //
                // The SM120 cooperative MMA writeback commits to the register file some cycles
                // after issue; a consumer reading earlier (the next iteration's MMA reading the
                // accumulator back as its C input, or a STG.E.128 of R0..R3 — whose high half
                // R2,R3 commits last) gets a STALE/partial result.
                //
                // CRITICAL: this delay SCALES WITH OCCUPANCY. At 1 warp/SMSP the commit lands
                // ~+19 cycles (so QMMA(11)+1+10 = +22 sufficed). At 2 warps/SMSP (e.g. 8
                // warps/CTA) the tensor core is shared and the commit lands ~2x later, so the
                // old +22 raced intermittently (worse with more loop iterations). cubit cannot
                // know the launch occupancy at assembly time, so the delay is a tunable knob:
                // the default (46 drain cycles → ~57 total) is solid up to 2 warps/SMSP; raise
                // CUBIT_MMA_WB_DRAIN if you push occupancy higher and see flaky MMA results.
                //
                // drain #1 (stall=1) must stay IMMEDIATELY after the MMA (writeback trigger
                // window); the remaining drains supply the commit delay (ALU stall caps at 15).
                let drain_total: u32 = std::env::var("CUBIT_MMA_WB_DRAIN")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(46);
                // CUBIT_MMA_WAIT: ptxas emits a SINGLE NOP S13 after the cooperative HMMA rather
                // than cubit's long multi-drain block. With the wait kept on the MMA, the bursty
                // writeback block is what makes co-resident CTAs phase-lock and fail at 2 CTAs/SM.
                // Tunable for iteration (the unset env keeps the legacy multi-drain scheme):
                //   CUBIT_MMA_WAIT_DRAINS=<n>  number of post-MMA @!UPT drains (default 1)
                //   CUBIT_MMA_WAIT_STALL=<s>   stall per drain               (default 13)
                // n=0 skips the writeback drains entirely (rely on the MMA's own wait + stall).
                // In back-edge settle mode, keep only the minimal stall=1 "writeback trigger"
                // right after the MMA; the bulk settle moves onto the loop back-edge below.
                // Post-MMA writeback drain. The `inserts` list only contains MMAs that NEED a
                // separate settle: STANDALONE MMAs (e.g. pv_cache: HMMA → STG, no loop to hide the
                // commit latency) and in-loop MMAs whose natural settle is too short. A LONG K-loop
                // MMA (the PV gate kernel) has ample natural settle so it is NOT in `inserts` — its
                // writeback settle is the post-MMA NOP bumped to S13 in the MMA-stall pass above.
                // So whenever a drain IS inserted it must be the FULL commit delay (≈46), including
                // under CUBIT_MMA_WAIT/SCHED2: the earlier "single NOP S13" reduction starved the
                // standalone cooperative writeback (pv_cache read a stale/zero accumulator).
                let mut drains: Vec<u8> = vec![1];
                if !pv_backedge {
                    let mut rem = drain_total.saturating_sub(1);
                    while rem > 0 {
                        let s = rem.min(15) as u8;
                        drains.push(s);
                        rem -= s as u32;
                    }
                }
                // Move the settle onto the loop back-edge (nvcc-style). cubit's BRA is largely
                // static-ctrl (encoder ignores its stall), so place the stall on the last
                // non-static instruction BEFORE the back-edge BRA (covers the loop-exit store
                // settle; the next-iteration HMMA is already covered by the whole loop body).
                if pv_backedge && backedge_stall > 0 {
                    backedge_bras.sort();
                    backedge_bras.dedup();
                    for &ba in &backedge_bras {
                        if let Some(bidx) = insns_with_ctrl
                            .iter()
                            .position(|x| x.addr == ba && x.opcode == "BRA")
                        {
                            insns_with_ctrl[bidx].ctrl.stall =
                                insns_with_ctrl[bidx].ctrl.stall.max(backedge_stall);
                            if bidx > 0 && !insns_with_ctrl[bidx - 1].hand_sched {
                                insns_with_ctrl[bidx - 1].ctrl.stall =
                                    insns_with_ctrl[bidx - 1].ctrl.stall.max(backedge_stall);
                            }
                        }
                    }
                    if std::env::var("CUBIT_DEBUG").is_ok() {
                        eprintln!(
                            "  [pv_backedge] settle={} on back-edges {:x?}",
                            backedge_stall, backedge_bras
                        );
                    }
                }
                for idx in inserts.into_iter().rev() {
                    for &s in drains.iter().rev() {
                        insns_with_ctrl.insert(idx, wb_drain(s));
                    }
                }
                for (i, insn) in insns_with_ctrl.iter_mut().enumerate() {
                    insn.addr = (i * 16) as u32;
                }
            }

            // ── SM120 cooperative-MMA accumulator-store WAR read-barrier ────────────────
            // A store that reads an MMA accumulator (the F32 result, e.g. STG of R0.. /
            // R12..) must set a READ-BARRIER so the next MMA that re-writes that accumulator
            // waits for the store's read to complete. The MMA writeback is UNSCOREBOARDED
            // (wb=- forced on SM120), so without this the next MMA (next d-slice / next loop
            // iteration, possibly across a back-edge) overwrites the accumulator while the
            // store is still reading it (WAR). At 1 CTA/SM the natural spacing usually hides
            // it; at >=2 CTAs/SM the store/MMA latency shifts and the store captures a
            // half-overwritten accumulator -> the intermittent ~5e-2 PV error. ptxas sets rb
            // on the store; cubit previously relied only on a 4-cycle producer stall, which
            // cannot cross a loop back-edge. scheduling_pass reserved barrier 0 (no load
            // aliases it); here we set rb=0 on the accumulator stores and make every MMA
            // input-drain wait B0 before the MMA re-writes the accumulator.
            if std::env::var("CUBIT_WAR_RB").ok().as_deref() != Some("0") {
                const WAR_RB: u8 = 0;
                let is_mma = |op: &str| matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA");
                let accs: Vec<u8> = insns_with_ctrl
                    .iter()
                    .filter(|x| is_mma(&x.opcode))
                    .filter_map(|x| match x.operands.first() {
                        Some(cubit::ir::Operand::Reg { num, .. }) => Some(*num),
                        _ => None,
                    })
                    .collect();
                let is_store = |op: &str| matches!(op, "STG" | "STS" | "STL" | "ST" | "STGX");
                let mut any_acc_store = false;
                for insn in insns_with_ctrl.iter_mut() {
                    if is_store(&insn.opcode)
                        && insn.operands.iter().any(|o| {
                            matches!(o,
                    cubit::ir::Operand::Reg { num, .. }
                        if accs.iter().any(|&a| *num >= a && *num < a.saturating_add(4)))
                        })
                    {
                        insn.ctrl.read_bar = WAR_RB;
                        any_acc_store = true;
                    }
                }
                if any_acc_store {
                    // Every MMA input-drain (the `@!UPT/UIADD3 ... barrier drain` inserted
                    // before each MMA) now also waits the accumulator-store read barrier, so
                    // the MMA cannot overwrite the accumulator until the prior store read it.
                    //
                    // CUBIT_MMA_WAIT has NO input pre-drain (the input wait lives on the MMA),
                    // so the WAR read-barrier must be carried by the MMA itself: OR B0 into the
                    // MMA's wait_mask so it cannot overwrite the accumulator until the prior
                    // store has read it. (ptxas achieves the same WAR ordering by waiting B0 on
                    // the next iteration's address advance; waiting it on the MMA is equivalent
                    // and strictly safer.)
                    for insn in insns_with_ctrl.iter_mut() {
                        let carries_war = insn.raw_text.contains("barrier drain")
                            || (mma_wait && is_mma(&insn.opcode) && !insn.hand_sched);
                        if carries_war {
                            insn.ctrl.wait_mask |= 1 << WAR_RB;
                        }
                    }
                }
            }

            // Post-scheduling: insert UIADD3 URZ drain before backward BRA.
            // BRA has CtrlClass::CtrlFlow → encoder uses static upper32 (ignores scheduling).
            // So we can't put wait_mask on BRA itself. Instead, insert a drain instruction.
            {
                // (idx, wait_mask, is_pad). is_pad=true entries are HW-timing pads for
                // uniform backward branches; is_pad=false are barrier drains.
                let mut inserts: Vec<(usize, u8, bool)> = Vec::new();
                for (i, insn) in insns_with_ctrl.iter_mut().enumerate() {
                    if insn.opcode == "BRA" {
                        if let Some(target) = insn.operands.iter().find_map(|o| match o {
                            cubit::ir::Operand::Imm32(v) => Some(*v as u32),
                            cubit::ir::Operand::BranchTarget(a) => Some(*a),
                            _ => None,
                        }) {
                            if target < insn.addr {
                                let wm = insn.ctrl.wait_mask;
                                // Uniform conditional branch = carries a real UPred operand.
                                let is_uniform_cond = insn.operands.iter().any(|o| {
                                    matches!(o,
                                cubit::ir::Operand::UPred { num, .. } if *num != 7)
                                });
                                if wm != 0 {
                                    inserts.push((i, wm, false));
                                    insn.ctrl.wait_mask = 0;
                                } else if is_uniform_cond {
                                    // SM120 HW quirk: a uniform conditional backward branch
                                    // (BRA.U UPx) needs >=1 instruction of loop-body latency
                                    // before it, else the loop over-runs (the per-lane @P BRA
                                    // form does not). The @sched is identical with/without —
                                    // only the instruction count matters. Insert a benign pad.
                                    inserts.push((i, 0, true));
                                }
                            }
                        }
                    }
                }
                let pad_count: usize = std::env::var("CUBIT_UNIFORM_PAD")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                for (idx, _wm, is_pad) in inserts.iter().rev() {
                    let urz = || cubit::ir::Operand::UReg {
                        num: 63,
                        neg: false,
                        abs: false,
                        inv: false,
                        reuse: false,
                        is_zero: true,
                    };
                    let upt = || cubit::ir::Operand::UPred { num: 7, neg: false };
                    let mk = |stall: u8, wm: u8, txt: &str| cubit::ir::Instruction {
                        opcode: "UIADD3".into(),
                        opcode_full: "UIADD3".into(),
                        key: "UIADD3_UR_UP_UP_UR_UR_UR".into(),
                        addr: 0,
                        guard: None,
                        operands: vec![urz(), upt(), upt(), urz(), urz(), urz()],
                        modifiers: vec![],
                        ctrl: cubit::ir::ControlCode {
                            stall,
                            wait_mask: wm,
                            ..Default::default()
                        },
                        hand_sched: false,
                        rsd: None,
                        raw_text: txt.into(),
                    };
                    if *is_pad {
                        // pad: latency only, no barrier wait. SM120 uniform backward branch
                        // needs loop-body padding; 4 warps/SMSP may need >1 instruction.
                        let n = pad_count.max(1);
                        for _ in 0..n {
                            insns_with_ctrl.insert(
                                *idx,
                                mk(2, 0, "/* uniform backward-branch pad (drain) */"),
                            );
                        }
                    } else {
                        insns_with_ctrl
                            .insert(*idx, mk(12, 0x3F, "/* loop back-edge barrier drain */"));
                    }
                }
                if !inserts.is_empty() {
                    for (i, insn) in insns_with_ctrl.iter_mut().enumerate() {
                        insn.addr = (i * 16) as u32;
                    }
                }
            }

            // Fixup BRA targets after all insertions.
            // When a drain UIADD3 was inserted before instruction X, BRA targets
            // that pointed to X should now point to the drain (so the drain executes
            // before X). We map each original address to the FIRST instruction at
            // that logical position — which is the drain if one was inserted.
            {
                use std::collections::HashMap;
                let mut addr_map: HashMap<u32, u32> = HashMap::new();
                let mut old_addr: u32 = 0;
                for insn in insns_with_ctrl.iter() {
                    if insn.raw_text.contains("drain") {
                        // Drain was inserted before the next original instruction.
                        // Map the next original instruction's old address to this drain's
                        // new address (so BRAs land on the drain first).
                        // Don't advance old_addr — the drain doesn't consume an original slot.
                        addr_map.entry(old_addr).or_insert(insn.addr);
                    } else {
                        // Original instruction. Map old_addr → current addr,
                        // but only if no drain already claimed this slot.
                        addr_map.entry(old_addr).or_insert(insn.addr);
                        old_addr += 16;
                    }
                }
                for insn in insns_with_ctrl.iter_mut() {
                    for op in insn.operands.iter_mut() {
                        if let cubit::ir::Operand::BranchTarget(ref mut target) = op {
                            if let Some(&new_addr) = addr_map.get(target) {
                                *target = new_addr;
                            }
                        }
                        if let cubit::ir::Operand::Imm32(ref mut v) = op {
                            if insn.opcode == "BRA" || insn.opcode == "BSSY" {
                                if let Some(&new_addr) = addr_map.get(&(*v as u32)) {
                                    *v = new_addr as i64;
                                }
                            }
                        }
                    }
                }
            }
        } // end `if !fully_frozen` — preserve mode keeps a [CC]-frozen kernel byte-exact

        // DEFAULT correct allocator: re-derive the entire scoreboard (RAW write-barriers +
        // WAR read-barriers) by liveness, AFTER all instruction insertions above so indices
        // are final. The MMA writeback drains remain (their stalls give the cooperative-MMA
        // distance); reallocate just fixes the load/store barriers. Legacy path keeps its own.
        if !fully_frozen {
            cubit::scheduling_pass::reallocate_barriers(&mut insns_with_ctrl, Some(table));
        } else if std::env::var("CUBIT_VERIFY").is_ok() {
            // Preserve mode skips the allocator, but the read-only scoreboard verifier
            // still runs so hand-scheduled kernels report a CUBIT_VERIFY line.
            cubit::scheduling_pass::verify_scoreboard_public(&insns_with_ctrl, Some(table));
        }

        // Encode instructions (use insns_with_ctrl.len() which may be larger after stall gap insertion)
        if std::env::var("CUBIT_HAZ").is_ok() {
            for h in cubit::scheduling_pass::report_hazards(&insns_with_ctrl) {
                eprintln!("  HAZ [{}] {}", def.name, h);
            }
        }

        let mut code_bytes = vec![0u8; insns_with_ctrl.len() * 16];
        let (mut enc, mut fail) = (0u64, 0u64);

        for (i, insn) in insns_with_ctrl.iter().enumerate() {
            // Raw verbatim instruction (`__raw__0x...`): emit the 128-bit code unchanged.
            if insn.opcode == "__raw__" {
                if let Some(code) = insn
                    .raw_text
                    .strip_prefix("__raw__0x")
                    .and_then(|h| u128::from_str_radix(h.trim(), 16).ok())
                {
                    let off = i * 16;
                    code_bytes[off..off + 8].copy_from_slice(&(code as u64).to_le_bytes());
                    code_bytes[off + 8..off + 16]
                        .copy_from_slice(&((code >> 64) as u64).to_le_bytes());
                    enc += 1;
                } else {
                    fail += 1;
                    eprintln!(
                        "  WARN [{}]: malformed __raw__: {:?}",
                        def.name, insn.raw_text
                    );
                }
                continue;
            }
            match cubit::encoder::encode_instruction(insn, table) {
                Ok(mut code128) => {
                    // CUBIT_SCHED2 (RULE 3): control-flow instructions (BRA/EXIT/BSYNC/…)
                    // are "fully static" — the encoder leaves their scheduling at the ISA
                    // table default (so cubit branches come out S01). ptxas encodes a real
                    // settle stall there (forward/back-edge=5, MMA back-edge=11/15). Re-
                    // inject the scheduler's [stall|yield] into the standard sched field so
                    // the learned branch stalls actually land in the bytes. Gated → default
                    // (env unset) byte-identical; NOP already honours its sched in the encoder.
                    // Frozen branches (hand_sched) must keep their authored stall/yield too —
                    // the encoder otherwise emits control-flow at the ISA default (S01),
                    // silently dropping a frozen back-edge/settle stall. Reinject for any
                    // hand_sched control-flow insn, and (as before) under CUBIT_SCHED2.
                    // Reinject for: (a) hand_sched/frozen branches (byte-faithful round-trip),
                    // (b) the DEFAULT auto-scheduler path (!fully_frozen && !legacy) — a fresh
                    // schedule where schedule() computed the real settle stall (LATENCY_CTRL=5,
                    // BAR=6, MMA back-edge=11/15); without this the encoder drops control-flow to
                    // the ISA default S01, which under-stalls every BRA/BAR/BSYNC/BSSY and
                    // corrupts results even at 1 CTA/SM. A fresh asm is never hand_sched, so this
                    // never affects a disasm→reencode round-trip. (c) CUBIT_SCHED2 (legacy gate).
                    let reinject = cubit::scheduling_pass::is_static_sched_reinject(&insn.opcode)
                        && (insn.hand_sched || !fully_frozen);
                    if reinject {
                        let sched = cubit::scheduling::encode_control_code(&insn.ctrl);
                        code128 = cubit::scheduling::inject_sched_into_code128(code128, sched);
                    }
                    let off = i * 16;
                    code_bytes[off..off + 8].copy_from_slice(&(code128 as u64).to_le_bytes());
                    code_bytes[off + 8..off + 16]
                        .copy_from_slice(&((code128 >> 64) as u64).to_le_bytes());
                    enc += 1;
                }
                Err(e) => {
                    fail += 1;
                    if fail <= 5 {
                        eprintln!(
                            "  WARN 0x{:04x} [{}]: {e}  |  src: {:?}",
                            insn.addr, def.name, insn.raw_text
                        );
                    }
                }
            }
        }

        // Post-encoding: set BRA convergence barrier IDs from BSSY regions.
        // SKIP for fully-frozen kernels: their branch byte-3 barrier IDs are the
        // author's own (a re-analysis would renumber and break byte fidelity).
        if !fully_frozen {
            cubit::scheduling_pass::apply_convergence_barriers(&mut code_bytes, &insns_with_ctrl);
        }

        total_enc += enc;
        total_fail += fail;
        let n = def.instructions.len() as u64;
        println!("  {}: {enc}/{n} encoded ({fail} failed)", def.name);

        let meta = kernel_def_to_meta(def, &code_bytes);
        println!(
            "  {}: regcount={}, params={}, barriers={}",
            def.name,
            meta.regcount,
            meta.params.len(),
            meta.num_barriers
        );
        if std::env::var("CUBIT_DEBUG_META").is_ok() {
            eprintln!(
                "  DBG meta: loads={:?} load_flags={:?} atom_pool_hits={:?} s2r_dest={:?} stg_desc_pos={:?}",
                meta.merc_param_loads, meta.merc_load_flags, meta.merc_atom_pool_hits,
                meta.merc_s2r_dest, meta.merc_stg_desc_pos
            );
        }

        // mk13a: PELNE mnemoniczki (opcode_full) — bitmap/scany i tak biora
        // baze split('.'), a stg_wide/u8 + modele mk12/13 potrzebuja
        // modyfikatorow (.64/.128/.CONSTANT). Spojne z ops[] manifestu gold.
        let kops: Vec<String> =
            def.instructions.iter().map(|i| i.opcode_full.clone()).collect();
        entries.push(KernelEntry {
            name: def.name.clone(),
            code: code_bytes,
            meta,
            mercury_stub: mercury_stub.map(|s| s.to_vec()),
            opcodes: Some(kops),
        });
    }

    if entries.is_empty() {
        anyhow::bail!("no kernels assembled (check --kernel filter)");
    }

    merge_syncwarp_from_reference(&mut entries, eiattr_path);
    // Build cubin
    let cubin_bytes = if let Some(tmpl) = template_path {
        use cubit::elf_builder::rebuild_cubin;
        let tmpl_bytes = std::fs::read(tmpl)?;
        let patches: Vec<cubit::elf_builder::CubinPatch> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.code.clone(), e.mercury_stub.clone()))
            .collect();
        rebuild_cubin(&tmpl_bytes, &patches)?
    } else if let Some(ref_path) = eiattr_path {
        use cubit::elf_builder::rebuild_cubin;
        let ref_bytes = std::fs::read(ref_path)?;
        let patches: Vec<cubit::elf_builder::CubinPatch> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.code.clone(), e.mercury_stub.clone()))
            .collect();
        rebuild_cubin(&ref_bytes, &patches)?
    } else {
        use cubit::elf_builder::{build_cubin_for_arch, build_cubin_mercury_for_arch};
        if tensor_class_kernels {
            eprintln!(
                "note: tcgen05/TMA-class instructions present and no explicit \
                       --mercury-stub — emitting a Mercury-free cubin (driver .text \
                       fallback); the static stub does not describe these resources."
            );
            build_cubin_for_arch(&entries, table.ef_flags)?
        } else {
            build_cubin_mercury_for_arch(&entries, table.ef_flags)?
        }
    };

    std::fs::write(output_path, &cubin_bytes)
        .with_context(|| format!("cannot write {}", output_path.display()))?;
    println!("Written: {}", output_path.display());
    println!("Total:   {total_enc} encoded ({total_fail} failed)");
    Ok(())
}

fn cmd_info(table_path: &Path) -> Result<()> {
    let table = IsaTable::load(table_path)?;
    println!("ISA table: {}", table_path.display());
    println!("InsKeys:        {}", table.num_keys());
    println!("Mod groups:     {}", table.num_groups());
    let total_fields: usize = table
        .entries
        .values()
        .flat_map(|e| e.mod_groups.values())
        .map(|mg| mg.fields.len())
        .sum();
    println!("Total fields:   {total_fields}");
    println!(
        "Avg fields/grp: {:.1}",
        total_fields as f64 / table.num_groups() as f64
    );
    Ok(())
}

/// Minimal ELF64 section-header walker for capmerc blobs whose program
/// header table is absent/stripped (JIT-cache extracts); the `elf` crate
/// validates phdrs eagerly and rejects those.
fn elf64_sections(bytes: &[u8]) -> Result<Vec<(String, u64, u64)>> {
    if bytes.len() < 0x40 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 {
        bail!("not an ELF64 file");
    }
    let rd16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
    let rd64 = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    let shoff = rd64(0x28) as usize;
    let shentsize = rd16(0x3a) as usize;
    let shnum = rd16(0x3c) as usize;
    let shstrndx = rd16(0x3e) as usize;
    if shnum == 0 || shoff == 0 || shoff + (shnum + 1) * shentsize > bytes.len() + shentsize {
        bail!("section header table out of range");
    }
    let shdr = |i: usize| -> (u32, u64, u64) {
        let o = shoff + i * shentsize;
        (
            u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()),
            rd64(o + 0x18), // sh_offset
            rd64(o + 0x20), // sh_size
        )
    };
    let str_off = shdr(shstrndx).1 as usize;
    let mut out = Vec::new();
    for i in 0..shnum {
        let (name_off, off, size) = shdr(i);
        let start = str_off + name_off as usize;
        let end = bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(start);
        let name = String::from_utf8_lossy(&bytes[start..end]).to_string();
        out.push((name, off, size));
    }
    Ok(out)
}

fn cmd_merc_dump(input: &Path, kernel: Option<&str>, strict: bool) -> Result<()> {
    use cubit::mercury::CapMerc;
    let bytes =
        std::fs::read(input).with_context(|| format!("failed to read {}", input.display()))?;
    let mut manual: Option<Vec<(String, u64, u64)>> = None;
    let elf_res: Result<ElfFile<'_, elf::FileHeader64<Endianness>>, _> =
        ElfFile::parse(bytes.as_slice());
    let elf = match elf_res {
        Ok(e) => Some(e),
        Err(_) => {
            manual = Some(elf64_sections(&bytes)?);
            None
        }
    };
    let (endian, sections);
    let parsed_sections;
    match &elf {
        Some(e) => {
            endian = e.endian();
            sections = e.elf_header().sections(e.endian(), bytes.as_slice())?;
            parsed_sections = sections
                .iter()
                .filter_map(|section| {
                    let name = sections
                        .section_name(endian, section)
                        .ok()
                        .map(|n| String::from_utf8_lossy(n).to_string())?;
                    Some((name, section.sh_offset(endian), section.sh_size(endian)))
                })
                .collect::<Vec<_>>();
        }
        None => {
            parsed_sections = manual.take().unwrap();
        }
    }
    let mut shown = 0usize;
    for (name, sec_off, sec_size) in &parsed_sections {
        let name = name.clone();
        let Some(ksuffix) = name.strip_prefix(".nv.capmerc.text.") else {
            continue;
        };
        if let Some(k) = kernel {
            if !ksuffix.starts_with(k) {
                continue;
            }
        }
        let off = *sec_off as usize;
        let size = *sec_size as usize;
        if off + size > bytes.len() {
            println!("{ksuffix}: section extends past EOF");
            continue;
        }
        let blob = &bytes[off..off + size];
        match CapMerc::parse(blob, strict) {
            Ok(cm) => {
                shown += 1;
                println!(
                    "{ksuffix}: ord={} B={} records={} tail={:#06x}{} bitmap_bits={}",
                    cm.ordinal,
                    cm.n_nonnop,
                    cm.records.len(),
                    cm.tail,
                    if cm.tail_consistent() {
                        " (tail=f(B))"
                    } else {
                        " (tail!=f(B): normalne dla klas wag-0/tcgen05 — regula to f(trim))"
                    },
                    cm.set_bits().len(),
                );
                for (t, c) in cm.tag_histogram() {
                    println!("    tag {} x{}", t, c);
                }
                if cm.trailing_slop != 0 {
                    println!("    WARN trailing slop: {} bytes", cm.trailing_slop);
                }
            }
            Err(e) => {
                shown += 1;
                println!("{ksuffix}: PARSE-ERROR: {e}");
            }
        }
    }
    if shown == 0 {
        println!("no .nv.capmerc.text.* sections found");
    }
    Ok(())
}
