//! Fail-closed semantic round-trip audit of extracted CUDA ELF code sections.
//!
//! Only the original scheduling ControlCode crosses the binary/text boundary.
//! Instruction selection, operands and every other bit must come from the
//! editable mnemonic stream. No raw words, residue overlays or decoded keys
//! are used as encoder inputs. Failure records are streamed, not accumulated.

use crate::decoder::DecodeIndex;
use crate::ir::Instruction;
use crate::table::IsaTable;
use anyhow::{bail, Context, Result};
use object::read::elf::{ElfFile, FileHeader, SectionHeader as _};
use object::{elf, Endianness};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Debug, Clone, Default, Serialize)]
pub struct KernelReport {
    pub section: String,
    /// Legacy diagnostic index: raw ELF section position in `audit_cubin`,
    /// or the caller-supplied index in `audit_kernel`. Never use for patching.
    pub section_index: usize,
    /// Position in `CubinFile::text_sections`, authoritative for
    /// `patch_semantic_section_at`. Standalone `audit_kernel` has no ELF map.
    pub text_index: Option<usize>,
    pub source_name: String,
    pub source_sha256: String,
    pub bytes: usize,
    pub instructions: usize,
    pub matched: usize,
    pub decode_errors: usize,
    pub parse_errors: usize,
    pub encode_errors: usize,
    pub mismatches: usize,
    pub forbidden: usize,
    pub stream_errors: usize,
    pub partial_tail_bytes: usize,
    pub stream_verified: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditReport {
    pub sm: u32,
    pub table_sm: u32,
    pub kernels: Vec<KernelReport>,
    pub instructions: usize,
    pub matched: usize,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub section: String,
    pub section_index: usize,
    pub addr: Option<u32>,
    pub stage: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub xor: Option<String>,
    pub sass: Option<String>,
    /// Decoder selection is diagnostic only; never supplied to the encoder.
    pub decoded_key: Option<String>,
    pub decoded_mod_group: Option<String>,
    pub error: String,
}

fn failure(report: &KernelReport, addr: Option<u32>, stage: &str, error: String) -> Failure {
    Failure {
        section: report.section.clone(),
        section_index: report.section_index,
        addr,
        stage: stage.into(),
        expected: None,
        actual: None,
        xor: None,
        sass: None,
        decoded_key: None,
        decoded_mod_group: None,
        error,
    }
}

/// Reject fidelity escape hatches before parsing, and check the parsed IR too.
/// This is public so a corpus runner can apply the exact same policy to text.
pub fn check_semantic_source(text: &str) -> Result<()> {
    if text.contains("__raw__") || text.contains("!rsd") {
        bail!("raw instructions and residue overlays are forbidden in a semantic round-trip");
    }
    if text.lines().any(|line| line.split("//").next().unwrap_or("").split('#').next().unwrap_or("").contains('?')) {
        bail!("opaque modifiers and unknown operand glyphs require semantic RE before a strict round-trip");
    }
    if text.lines().any(|line| line.split("//").next().unwrap_or("").split('#').next().unwrap_or("").contains('&')) {
        bail!("opaque & annotations are forbidden in a semantic round-trip");
    }
    Ok(())
}

/// A strict audit must not inherit the encoder's RE-only bypass switches.
pub fn check_strict_environment() -> Result<()> {
    if std::env::var_os("CUBIT_DISABLE_ERRATA").is_some() {
        bail!("strict audit refuses CUBIT_DISABLE_ERRATA; unset the encoder bypass");
    }
    if matches!(
        std::env::var("CUBIT_FIT_LINT").as_deref(),
        Ok("allow" | "warn")
    ) {
        bail!("strict audit refuses permissive CUBIT_FIT_LINT; unset it or select hard mode");
    }
    if !crate::encoder::strict_fit_lint_active() {
        bail!("strict audit refuses the encoder's cached permissive fit policy; start a fresh process with CUBIT_FIT_LINT unset or hard");
    }
    Ok(())
}

/// Validate the binary's architecture and executable-code format before
/// interpreting `.text` as fixed-width native instructions.
pub fn validate_cubin_header(bytes: &[u8], table: &IsaTable) -> Result<u32> {
    let file: ElfFile<'_, elf::FileHeader64<Endianness>> =
        ElfFile::parse(bytes).context("expected extracted CUDA cubin ELF64")?;
    let endian = file.endian();
    let header = file.elf_header();
    if endian != Endianness::Little {
        bail!("CUDA instruction audit requires a little-endian ELF");
    }
    if header.e_machine.get(endian) != 0xbe {
        bail!("expected extracted CUDA cubin (ELF e_machine must be EM_CUDA)");
    }
    let flags = header.e_flags.get(endian);
    let sm = crate::elf::sm_from_ef_flags(flags);
    if sm != table.target_sm() {
        bail!(
            "architecture mismatch: cubin SM{sm}, table SM{}",
            table.target_sm()
        );
    }
    // Blackwell ABI encodes a code-layout ID in the low byte. Native SASS
    // witnesses use ID 2. ID 1 encountered in a runtime-resident compiler
    // object is rejected by NVIDIA nvdisasm and must not be decoded as SASS.
    let layout = flags & 0xff;
    if sm >= 100 && layout < 10 && layout != 2 {
        bail!("unsupported CUDA code layout {layout} for SM{sm}; obtain the finalized native SASS module");
    }
    Ok(sm)
}

fn check_instruction(insn: &Instruction) -> Result<()> {
    check_semantic_source(&insn.raw_text)?;
    crate::sass_file::validate_strict_instruction_surface(insn)?;
    if insn.opcode == "__raw__" || insn.rsd.is_some() {
        bail!("raw instructions and residue overlays are forbidden");
    }
    if !insn.hand_sched {
        bail!("instruction is missing an explicit frozen ControlCode");
    }
    Ok(())
}

/// Assemble an editable frozen section without consulting its original words.
/// Exactly one nonempty entry and explicit scheduling on every instruction are
/// required. Labels are resolved by the normal strict source parser.
/// Live guards must use the selected instruction form's P or UP bank. PT and
/// UPT (including their negations) may normalize: each denotes the same
/// constant boolean value and has no bank-dependent register read.
pub fn encode_semantic_source(source: &str, table: &IsaTable) -> Result<Vec<u8>> {
    check_strict_environment()?;
    check_semantic_source(source)?;
    for line in source.lines() {
        let code = line.split("//").next().unwrap_or("").split('#').next().unwrap_or("");
        // This legacy compiler marker is consumed before body parsing and
        // does not necessarily set the current entry's resources. Reject it
        // lexically, including spacing variants, wherever it appears.
        let trimmed = code.trim_start();
        if trimmed.starts_with(';') {
            let marker = trimmed.trim_start_matches(|c: char| c == ';' || c.is_whitespace());
            if marker.strip_prefix("era").is_some_and(|rest| rest.trim_start().starts_with('=')) {
                bail!("code-only semantic assembly cannot discard a compiler era marker");
            }
        }
        let keyword = code.split_whitespace().next().unwrap_or("");
        if matches!(keyword, ".version" | ".target" | ".address_size" | ".reg" |
            ".maxreg" | ".pred" | ".bar" | ".param" | ".shared" |
            ".merc_syncwarp" | ".merc_cgsites") {
            bail!("code-only semantic assembly cannot apply metadata directive {keyword}; use an explicit metadata-aware cubin build");
        }
    }
    let file = crate::sass_file::parse_sass_file_str_strict(source)?;
    if file.kernels.len() != 1 || file.kernels[0].instructions.is_empty() {
        bail!("semantic section source must contain exactly one nonempty entry");
    }
    let resources = &file.kernels[0].resources;
    if resources.max_reg.is_some() || resources.max_pred.is_some()
        || resources.num_barriers != 0 || !resources.params.is_empty()
        || !resources.shared.is_empty() || !resources.merc_syncwarp.is_empty()
        || !resources.merc_cgsites.is_empty() || resources.era100 {
        bail!("code-only semantic assembly cannot discard resource or compiler metadata");
    }
    let instructions = &file.kernels[0].instructions;
    let index = instructions
        .iter()
        .any(|insn| insn.guard.as_ref().is_some_and(|guard| guard.pred != 7))
        .then(|| table.decode_index());
    let mut code = Vec::with_capacity(instructions.len() * 16);
    for insn in instructions {
        check_instruction(insn)?;
        let word = crate::encoder::encode_instruction(insn, table)?;
        if let Some(guard) = insn.guard.as_ref().filter(|guard| guard.pred != 7) {
            // Inspect only the newly assembled word. Guard.uniform has no
            // independent encoding bit; the selected form determines its bank.
            let decoded = index.as_ref().unwrap().decode(word, insn.addr, table)
                .with_context(|| format!("cannot establish predicate bank at 0x{:x}", insn.addr))?;
            let uniform = crate::printer::guard_is_uniform_family(&decoded.key);
            if guard.uniform != uniform {
                bail!(
                    "predicate bank mismatch at 0x{:x}: authored @{}{}P{}, but {} uses {} predicates",
                    insn.addr,
                    if guard.negated { "!" } else { "" },
                    if guard.uniform { "U" } else { "" },
                    guard.pred,
                    decoded.key,
                    if uniform { "UP" } else { "P" },
                );
            }
        }
        code.extend_from_slice(&word.to_le_bytes());
    }
    Ok(code)
}

/// Replace one complete section with independently assembled source. The ELF
/// container (relocations, resources and other metadata) remains unchanged.
/// Length changes need an explicit metadata rebuild and are refused here.
pub fn patch_semantic_section(
    cubin: &mut crate::elf::CubinFile,
    section: &str,
    source: &str,
    table: &IsaTable,
) -> Result<()> {
    validate_cubin_header(&cubin.bytes, table)?;
    let matches: Vec<_> = cubin
        .text_sections
        .iter()
        .enumerate()
        .filter(|(_, (name, _, _))| name == section)
        .map(|(i, _)| i)
        .collect();
    if matches.len() != 1 {
        bail!("{section}: expected exactly one target code section");
    }
    patch_semantic_section_at(cubin, matches[0], source, table)
}

/// Index-based form for ELF modules containing multiple local sections with
/// the same name. The index is in `CubinFile::text_sections`, never inferred
/// from a symbol's spelling. An ELF audit supplies it as `KernelReport.text_index`;
/// `KernelReport.section_index` is a different, diagnostic index space.
pub fn patch_semantic_section_at(
    cubin: &mut crate::elf::CubinFile,
    index: usize,
    source: &str,
    table: &IsaTable,
) -> Result<()> {
    validate_cubin_header(&cubin.bytes, table)?;
    let code = encode_semantic_source(source, table)?;
    if code.len() != cubin.text_bytes(index)?.len() {
        bail!("section {index}: semantic rebuild must replace every instruction without changing section size");
    }
    cubin.patch_text(index, &code)
}

// Label only absolute, in-section code targets. Register-relative branches
// retain their signed numeric offsets. The printer's entire remaining text
// stays verbatim; rebuilding exotic operands from their IR can lose spelling.
fn label_target(text: &str, opcode: &str, byte_len: usize) -> String {
    let opcode = opcode.split('.').next().unwrap_or(opcode);
    if !matches!(
        opcode,
        "BRA" | "BSSY" | "CALL" | "JMP" | "RET" | "WARPSYNC" | "LEPC"
    ) {
        return text.into();
    }
    static HEX: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)(-?)0x([0-9a-f]+)").unwrap());
    let Some(caps) = HEX.captures_iter(text).last() else {
        return text.into();
    };
    if !caps[1].is_empty() {
        return text.into();
    }
    let Ok(target) = u32::from_str_radix(&caps[2], 16) else {
        return text.into();
    };
    if target as usize > byte_len || target % 16 != 0 {
        return text.into();
    }
    let m = caps.get(0).unwrap();
    let mut out = text.to_string();
    out.replace_range(m.range(), &format!("L_{target:x}"));
    out
}

/// Audit one complete code section and return its actual editable SASS source.
/// The second pass parses this emitted source independently and resolves labels.
/// Failed source is still returned for RE, with explicit ERROR comments for
/// undecodable slots; it can never receive a passing report.
pub fn audit_kernel<F>(
    section: &str,
    section_index: usize,
    bytes: &[u8],
    table: &IsaTable,
    index: &DecodeIndex,
    on_failure: &mut F,
) -> Result<(KernelReport, String)>
where
    F: FnMut(&Failure) -> Result<()>,
{
    check_strict_environment()?;
    if bytes.len() > u32::MAX as usize {
        bail!("{section}: section exceeds 32-bit SASS address space");
    }
    let original_name = section.strip_prefix(".text.").unwrap_or("");
    let name = if !original_name.is_empty()
        && original_name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.$".contains(&c))
    {
        original_name.to_string()
    } else {
        format!("audit_section_{section_index}")
    };
    let mut r = KernelReport {
        section: section.into(),
        section_index,
        source_name: name.clone(),
        bytes: bytes.len(),
        instructions: bytes.len() / 16,
        partial_tail_bytes: bytes.len() % 16,
        ..Default::default()
    };
    let mut body = String::with_capacity(bytes.len().saturating_mul(5));
    // Retain the original function name whenever it is a legal single token.
    // Anonymous/exotic section names get an explicit source_name report mapping.
    if bytes.is_empty() {
        r.stream_errors += 1;
        on_failure(&failure(
            &r,
            None,
            "empty",
            "code section has no instructions".into(),
        ))?;
    }
    if r.partial_tail_bytes != 0 {
        on_failure(&failure(
            &r,
            Some((r.instructions * 16) as u32),
            "partial_tail",
            format!(
                "{} bytes do not form a 128-bit instruction",
                r.partial_tail_bytes
            ),
        ))?;
    }
    for (i, chunk) in bytes.chunks_exact(16).enumerate() {
        let addr = (i * 16) as u32;
        let expected = u128::from_le_bytes(chunk.try_into().unwrap());
        let decoded = match index.decode(expected, addr, table) {
            Ok(d) => d,
            Err(e) => {
                r.decode_errors += 1;
                let mut f = failure(&r, Some(addr), "decode", format!("{e:#}"));
                f.expected = Some(format!("0x{expected:032x}"));
                on_failure(&f)?;
                writeln!(
                    body,
                    "L_{addr:x}: // ERROR: undecodable instruction at 0x{addr:x}"
                )?;
                continue;
            }
        };
        let mnemonic = crate::printer::to_sass_lossless(&decoded);
        let ctrl = crate::scheduling::decode_sched_upper32((expected >> 96) as u32);
        let prefix = crate::scheduling::format_control_code(&ctrl);
        let line = format!("[{prefix}] {mnemonic} ;");
        let mut context = failure(&r, Some(addr), "", String::new());
        context.expected = Some(format!("0x{expected:032x}"));
        context.sass = Some(line.clone());
        context.decoded_key = Some(decoded.key.clone());
        context.decoded_mod_group = Some(decoded.mod_group.clone());
        if let Err(e) = check_semantic_source(&line) {
            r.forbidden += 1;
            context.stage = "forbidden".into();
            context.error = format!("{e:#}");
            on_failure(&context)?;
            writeln!(
                body,
                "L_{addr:x}: // ERROR: forbidden fidelity escape at 0x{addr:x}"
            )?;
            continue;
        }
        let labeled = label_target(&mnemonic, &decoded.opcode, bytes.len());
        writeln!(body, "L_{addr:x}: [{prefix}] {labeled} ;")?;
        // The decoder's key, modifier group and original code are deliberately
        // absent from this parse/encode path. Only source text is supplied.
        let parsed = match crate::parse_cuasm_line(&line, addr).and_then(|p| {
            check_instruction(&p)?;
            Ok(p)
        }) {
            Ok(p) => p,
            Err(e) => {
                r.parse_errors += 1;
                context.stage = "parse".into();
                context.error = format!("{e:#}");
                on_failure(&context)?;
                continue;
            }
        };
        match crate::encoder::encode_instruction(&parsed, table) {
            Ok(actual) if actual == expected => r.matched += 1,
            Ok(actual) => {
                r.mismatches += 1;
                context.stage = "mismatch".into();
                context.error = "complete 128-bit word differs (scheduling included)".into();
                context.actual = Some(format!("0x{actual:032x}"));
                context.xor = Some(format!("0x{:032x}", actual ^ expected));
                on_failure(&context)?;
            }
            Err(e) => {
                r.encode_errors += 1;
                context.stage = "encode".into();
                context.error = format!("{e:#}");
                on_failure(&context)?;
            }
        }
    }
    // Define the end label too: control flow can legally target the section end.
    writeln!(body, "L_{:x}:", r.instructions * 16)?;
    let source = format!(
        "// Strict semantic audit of section {section_index}\n.entry {name}\n{body}.endentry\n"
    );
    r.source_sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
    let stream = crate::sass_file::parse_sass_file_str_strict(&source);
    match stream {
        Err(e) => {
            r.stream_errors += 1;
            on_failure(&failure(&r, None, "stream_parse", format!("{e:#}")))?;
        }
        Ok(file) => {
            if file.kernels.len() != 1 || file.kernels[0].instructions.len() != r.instructions {
                r.stream_errors += 1;
                on_failure(&failure(&r, None, "stream_count", format!(
                    "expected one kernel and {} instructions; parsed {} kernels and {} instructions",
                    r.instructions, file.kernels.len(),
                    file.kernels.iter().map(|k| k.instructions.len()).sum::<usize>())))?;
            } else {
                for (i, parsed) in file.kernels[0].instructions.iter().enumerate() {
                    let addr = (i * 16) as u32;
                    let expected =
                        u128::from_le_bytes(bytes[i * 16..i * 16 + 16].try_into().unwrap());
                    let result = check_instruction(parsed)
                        .and_then(|_| crate::encoder::encode_instruction(parsed, table));
                    match result {
                        Ok(actual) if actual == expected => {}
                        result => {
                            r.stream_errors += 1;
                            let mut f = failure(&r, Some(addr), "stream_encode", match &result {
                                Ok(_) => "emitted source does not reproduce the complete 128-bit word".into(),
                                Err(e) => format!("{e:#}"),
                            });
                            f.expected = Some(format!("0x{expected:032x}"));
                            f.sass = Some(parsed.raw_text.clone());
                            if let Ok(actual) = result {
                                f.actual = Some(format!("0x{actual:032x}"));
                                f.xor = Some(format!("0x{:032x}", actual ^ expected));
                            }
                            on_failure(&f)?;
                        }
                    }
                }
                r.stream_verified = r.stream_errors == 0;
            }
        }
    }
    r.passed = r.instructions > 0
        && r.matched == r.instructions
        && r.stream_verified
        && r.partial_tail_bytes == 0
        && r.forbidden == 0;
    Ok((r, source))
}

/// Audit every `.text` / `.text.*` section, including local device functions.
/// Host ELF, wrong architecture, malformed sections and no code are errors.
/// Decode/parse/encode/mismatch failures remain in the report so all sections
/// can be examined in one run. Callers must require `report.passed`.
pub fn audit_cubin<F, S>(
    bytes: &[u8],
    table: &IsaTable,
    on_failure: &mut F,
    on_sass: &mut S,
) -> Result<AuditReport>
where
    F: FnMut(&Failure) -> Result<()>,
    S: FnMut(&KernelReport, &str) -> Result<()>,
{
    check_strict_environment()?;
    let sm = validate_cubin_header(bytes, table)?;
    let file: ElfFile<'_, elf::FileHeader64<Endianness>> =
        ElfFile::parse(bytes).context("expected extracted CUDA cubin ELF64")?;
    let endian = file.endian();
    let header = file.elf_header();
    let sections = header.sections(endian, bytes)?;
    let index = table.decode_index();
    let mut report = AuditReport {
        sm,
        table_sm: table.target_sm(),
        ..Default::default()
    };
    // Match CubinFile's physical, nonempty PROGBITS text-section ordering.
    // Names need not be unique and raw ELF section indices include metadata.
    let mut text_index = 0usize;
    for (section_index, section) in sections.iter().enumerate() {
        let name = std::str::from_utf8(sections.section_name(endian, section)?)
            .context("non-UTF8 section name")?;
        if !(name == ".text" || name.starts_with(".text.")) {
            continue;
        }
        if section.sh_type(endian) != elf::SHT_PROGBITS {
            bail!("{name}: text section is not PROGBITS");
        }
        let start = usize::try_from(section.sh_offset(endian))?;
        let len = usize::try_from(section.sh_size(endian))?;
        if len == 0 {
            bail!("{name}: no instructions in empty text section");
        }
        let end = start
            .checked_add(len)
            .context("code section offset overflow")?;
        let code = bytes
            .get(start..end)
            .with_context(|| format!("{name}: code section extends past ELF"))?;
        let (mut kernel, source) = audit_kernel(name, section_index, code, table, &index, on_failure)?;
        kernel.text_index = Some(text_index);
        text_index += 1;
        on_sass(&kernel, &source)?;
        report.instructions += kernel.instructions;
        report.matched += kernel.matched;
        report.kernels.push(kernel);
    }
    if report.kernels.is_empty() {
        bail!("no .text / .text.* code sections in extracted cubin");
    }
    if report.instructions == 0 {
        bail!("no instructions in extracted cubin");
    }
    report.passed = report.kernels.iter().all(|r| r.passed);
    Ok(report)
}
