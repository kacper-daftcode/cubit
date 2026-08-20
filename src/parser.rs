//! SASS instruction parser — text → IR with typed operands.
//!
//! Fresh implementation. No encoding-specific transforms.
//! The parser's job: structural decomposition of SASS text.
//! The encoder's job: mapping values to bit positions.

use crate::ir::{ControlCode, Guard, Instruction, Operand};
use crate::scheduling::parse_control_code;
use anyhow::{Context, Result};
use regex::Regex;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Compiled regexes
// ---------------------------------------------------------------------------

static RE_INS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<Pred>@!?U?P\w+\s+)?\s*(?P<Op>[\w.\?]+)(?P<Operands>.*)$").unwrap()
});

static RE_TEXT_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\[(?P<CC>[^\]]+)\]\s*(?P<Asm>.+)$").unwrap()
});

static RE_CMEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^c\[(?P<Bank>0x[0-9a-fA-F]+)\]\[(?P<Inner>[^\]]+)\]$").unwrap()
});

static RE_DESC: LazyLock<Regex> = LazyLock::new(|| {
    // Accept URZ (the zero uniform register, = UR63) as a descriptor index so that
    // `desc[URZ][Ra]` round-trips: the decoder renders a 63-valued descriptor field
    // as URZ, and without this the parser would reject it and fall through to the
    // immediate (II) form -> wrong InsKey -> encode failure.
    Regex::new(r"^desc\[(?P<UR>UR\d+|URZ)\]\[(?P<Inner>[^\]]+)\]$").unwrap()
});

// ---------------------------------------------------------------------------
// Operand parsing
// ---------------------------------------------------------------------------

fn parse_guard(s: &str) -> (Option<Guard>, String) {
    let s = s.trim();
    if s.is_empty() {
        return (None, String::new());
    }
    let s = s.trim_start_matches('@').trim();
    let negated = s.starts_with('!');
    let s = s.trim_start_matches('!');
    let uniform = s.starts_with('U') && s.len() > 1 && s.chars().nth(1) == Some('P');

    // Parse register number
    let num_str = if uniform { &s[2..] } else { &s[1..] };
    let pred = if num_str == "T" { 7 } else { num_str.parse::<u8>().unwrap_or(7) };

    (Some(Guard { pred, negated, uniform }), String::new())
}

fn parse_register(s: &str) -> Option<Operand> {
    let s = s.trim();
    let neg = s.starts_with('-');
    let s = s.trim_start_matches('-');
    let inv = s.starts_with('~');
    let s = s.trim_start_matches('~');

    // Strip .reuse wherever it sits in the modifier chain (R5.reuse,
    // |R18|.reuse, R132.reuse.ROW)
    let (owned, reuse) = if s.contains(".reuse") {
        (s.replace(".reuse", ""), true)
    } else {
        (s.to_string(), false)
    };
    let s = owned.as_str();

    let abs = s.starts_with('|') && s.ends_with('|');
    let s = s.trim_matches('|');

    // Strip other suffixes like .64, .X8, .H1 for classification
    let base = s.split('.').next().unwrap_or(s);

    if base == "RZ" {
        return Some(Operand::Reg { num: 255, neg, abs, inv, reuse });
    }
    if let Some(num_str) = base.strip_prefix('R') {
        if let Ok(num) = num_str.parse::<u8>() {
            return Some(Operand::Reg { num, neg, abs, inv, reuse });
        }
    }
    if base == "URZ" {
        return Some(Operand::UReg { num: 63, neg, abs, inv, reuse, is_zero: true });
    }
    if let Some(num_str) = base.strip_prefix("UR") {
        if let Ok(num) = num_str.parse::<u8>() {
            return Some(Operand::UReg { num, neg, abs, inv, reuse, is_zero: false });
        }
    }
    None
}

fn parse_predicate(s: &str) -> Option<Operand> {
    let s = s.trim();
    let neg = s.starts_with('!');
    let s = s.trim_start_matches('!');

    if s == "PT" {
        return Some(Operand::Pred { num: 7, neg });
    }
    if s == "UPT" {
        return Some(Operand::UPred { num: 7, neg });
    }
    if let Some(num_str) = s.strip_prefix("UP") {
        if let Ok(num) = num_str.parse::<u8>() {
            return Some(Operand::UPred { num, neg });
        }
    }
    if let Some(num_str) = s.strip_prefix('P') {
        if let Ok(num) = num_str.parse::<u8>() {
            return Some(Operand::Pred { num, neg });
        }
    }
    None
}

fn parse_immediate(s: &str, is_float_context: bool) -> Option<Operand> {
    let s = s.trim();

    // Float special values: INF, NAN
    if s.eq_ignore_ascii_case("INF") || s.eq_ignore_ascii_case("+INF") {
        return Some(Operand::FloatImm(f64::INFINITY.to_bits()));
    }
    if s.eq_ignore_ascii_case("-INF") {
        return Some(Operand::FloatImm(f64::NEG_INFINITY.to_bits()));
    }
    if s.eq_ignore_ascii_case("NAN") || s.eq_ignore_ascii_case("+NAN") || s.eq_ignore_ascii_case("-NAN") {
        return Some(Operand::FloatImm(f64::NAN.to_bits()));
    }
    // QNAN intentionally NOT special-cased: corpus shows per-instruction,
    // bimodal QNAN bit lanes (FSEL +QNAN=0x7FC00000/0x7FF80000, MUFU
    // -QNAN=0xFFC00000) with no text-visible discriminator — park as quirk.

    // Hex float: 0x<exactly 8 hex digits>F (trailing 'F' marks f32 raw bits).
    // Only treat as float when EXACTLY 8 hex digits precede the marker — a full
    // f32 bit pattern, which a 32-bit hex *integer* can never have (it would
    // exceed 32 bits). This disambiguates from hex integers that merely end in
    // the digit 'F' (e.g. 0x7F7F7F7F), which were previously stripped of their
    // trailing 'F' and misparsed as floats.
    if (s.starts_with("0x") || s.starts_with("-0x")) && s.ends_with('F') {
        let neg = s.starts_with('-');
        let body = s.trim_start_matches('-').trim_start_matches("0x");
        let hex_part = &body[..body.len() - 1]; // strip exactly one trailing 'F'
        if hex_part.len() == 8 && hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(val) = u32::from_str_radix(hex_part, 16) {
                let f = f32::from_bits(val);
                let f64_val = if neg { -(f as f64) } else { f as f64 };
                return Some(Operand::FloatImm(f64_val.to_bits()));
            }
        }
    }
    // Hex integer: 0x..., -0x...
    if s.starts_with("0x") || s.starts_with("0X") || s.starts_with("-0x") || s.starts_with("-0X") {
        let neg = s.starts_with('-');
        let hex_part = s.trim_start_matches('-').trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(val) = u64::from_str_radix(hex_part, 16) {
            let ival = if neg { -(val as i64) } else { val as i64 };
            return Some(Operand::Imm32(ival));
        }
    }

    // Decimal with dot or scientific notation → always float
    if s.contains('.') || s.contains('e') || s.contains('E') {
        if let Ok(f) = s.parse::<f64>() {
            return Some(Operand::FloatImm(f.to_bits()));
        }
    }

    // In float context (DADD, DFMA, FADD, FMUL, HFMA2 etc.), plain integers are float
    if is_float_context {
        if let Ok(val) = s.parse::<i64>() {
            let f = val as f64;
            return Some(Operand::FloatImm(f.to_bits()));
        }
    }

    // Decimal integer
    if let Ok(val) = s.parse::<i64>() {
        return Some(Operand::Imm32(val));
    }

    None
}

fn parse_address(s: &str) -> Option<Operand> {
    let inner = s.trim().trim_start_matches('[').trim_end_matches(']');

    let inner = inner.replace("-0x", "+-0x");
    let inner = inner.replace("++", "+");
    let parts: Vec<&str> = inner.split('+').filter(|p| !p.trim().is_empty()).collect();

    let mut base_reg = None;
    let mut base_reg_suffix = None;
    let mut ur_reg = None;
    let mut offset = 0i64;

    for part in parts {
        let part = part.trim();
        // Check for register with suffix like R4.64, R2.X8
        let base = part.split('.').next().unwrap_or(part);

        if base == "RZ" || base.starts_with('R') {
            if let Some(num_str) = base.strip_prefix('R') {
                if base == "RZ" {
                    base_reg = Some(255u8);
                } else if let Ok(n) = num_str.parse::<u8>() {
                    base_reg = Some(n);
                }
                // Check for suffix
                if part.contains('.') {
                    base_reg_suffix = Some(part.split('.').skip(1).collect::<Vec<_>>().join("."));
                }
            }
        } else if part.starts_with("UR") {
            let num_part = part.strip_prefix("UR").unwrap_or("0");
            let num_str = num_part.split('.').next().unwrap_or(num_part);
            ur_reg = num_str.parse::<u8>().ok();
        } else if part.starts_with("0x") || part.starts_with("0X")
            || part.starts_with("-0x") || part.starts_with("-0X")
        {
            let neg = part.starts_with('-');
            let hex = part.trim_start_matches('-').trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                offset = if neg { -(v as i64) } else { v as i64 };
            }
        } else if let Ok(v) = part.parse::<i64>() {
            offset = v;
        }
    }

    Some(Operand::Addr { base_reg, base_reg_suffix, ur_reg, offset })
}

/// Opcodes whose immediate operands are float values.
const FLOAT_OPCODES: &[&str] = &[
    "FADD", "FMUL", "FFMA", "FSEL", "FMNMX", "FSET", "FSETP",
    // UFSETP is the uniform-datapath FSETP: its immediate compare value is an
    // f32 (corpus bakes 1.0 as 0x3f800000 at bits[63:32]; nvdisasm prints "1").
    // Without float context the textual `1` parsed to Imm32(1) and silently
    // encoded 0x00000001 (BUG-034, UFSETP.II-form).
    "DADD", "DMUL", "DFMA", "DSET", "DSETP", "UFSETP",
    "HADD2", "HMUL2", "HFMA2", "HSET2", "HSETP2",
];

fn parse_single_operand(s: &str, is_float_context: bool) -> Operand {
    let s = s.trim();

    // Address: [R0+0x8]
    if s.starts_with('[') {
        return parse_address(s).unwrap_or(Operand::Label(s.to_string()));
    }

    // Constant memory: c[0x0][0x37c]
    if let Some(caps) = RE_CMEM.captures(s) {
        let bank = u16::from_str_radix(
            caps.name("Bank").unwrap().as_str().trim_start_matches("0x"),
            16,
        ).unwrap_or(0);
        let inner = caps.name("Inner").unwrap().as_str();
        if let Some(Operand::Addr { base_reg, ur_reg, offset, .. }) =
            parse_address(&format!("[{inner}]"))
        {
            return Operand::ConstMem { bank, base_reg, ur_reg, offset };
        }
    }

    // Descriptor: desc[UR4][R2+0x8]
    if let Some(caps) = RE_DESC.captures(s) {
        let ur_str = caps.name("UR").unwrap().as_str();
        // URZ is the zero uniform register (UR63), analogous to RZ=R255.
        let ur_idx = if ur_str == "URZ" {
            63
        } else {
            ur_str.strip_prefix("UR").and_then(|n| n.parse::<u8>().ok()).unwrap_or(0)
        };
        let inner = caps.name("Inner").unwrap().as_str();
        if let Some(Operand::Addr { base_reg, base_reg_suffix, offset, .. }) =
            parse_address(&format!("[{inner}]"))
        {
            return Operand::Desc { ur_idx, base_reg, base_reg_suffix, offset };
        }
    }

    // Register: R5, -R5, ~R5, |R5|, R5.reuse, UR4, RZ
    if let Some(op) = parse_register(s) {
        return op;
    }

    // Predicate: P0, !P1, PT, UP3
    if let Some(op) = parse_predicate(s) {
        return op;
    }

    // Barrier: B0-B15 (sm_103a BSSY uses B8-B15)
    if let Some(num_str) = s.strip_prefix('B') {
        if let Ok(n) = num_str.parse::<u8>() {
            if n <= 15 {
                return Operand::Barrier(n);
            }
        }
    }

    // Scoreboard barrier: SB0-SB7 (DEPBAR.LE SB<n>, imm). Encoded as a small
    // barrier-number field; treating it as an immediate keeps the II key.
    if let Some(num_str) = s.strip_prefix("SB") {
        if let Ok(n) = num_str.parse::<u8>() {
            if n <= 7 {
                return Operand::Imm32(n as i64);
            }
        }
    }

    // System register: SR_TID.X, SR_CTAID.X, SRZ (zero; encodes as 0xff)
    if s.starts_with("SR_") || s == "SRZ" {
        return Operand::SysReg(s.to_string());
    }

    // Immediate: 0x100, -1, 3.14, INF
    if let Some(op) = parse_immediate(s, is_float_context) {
        return op;
    }

    // Fallback: label or unknown
    Operand::Label(s.to_string())
}

// ---------------------------------------------------------------------------
// Operand type for InsKey derivation
// ---------------------------------------------------------------------------

pub fn operand_type_label_pub(op: &Operand) -> &'static str {
    operand_type_label(op)
}

fn operand_type_label(op: &Operand) -> &'static str {
    match op {
        Operand::Reg { .. } => "R",
        Operand::UReg { .. } => "UR",
        Operand::Pred { .. } => "P",
        Operand::UPred { .. } => "UP",
        Operand::Imm32(_) => "II",
        Operand::Imm64(_) => "II",
        Operand::FloatImm(_) => "FI",  // float immediate — uses f32 raw bits encoding
        Operand::Addr { base_reg, ur_reg, .. } => {
            // Distinguish addresses with/without uniform register: the key differs.
            match (base_reg.is_some(), ur_reg.is_some()) {
                (true,  true)  => "ARURI",
                (true,  false) => "ARI",
                (false, true)  => "AURI",
                (false, false) => "AI",
            }
        }
        Operand::ConstMem { base_reg, .. } => {
            if base_reg.is_some() { "cARI" } else { "cAI" }
        }
        Operand::Desc { base_reg, .. } => {
            if base_reg.is_some() { "dARI" } else { "dAI" }
        }
        Operand::BranchTarget(_) => "II",
        Operand::Barrier(_) => "B",
        Operand::SysReg(_) => "L",
        Operand::Label(_) => "II",  // unresolved label → treated as immediate (branch target)
    }
}

// ---------------------------------------------------------------------------
// Top-level parsing
// ---------------------------------------------------------------------------

/// Parse bare SASS text (no control code prefix).

/// Parse `!rsd[b:v, b:v, [hi:lo]=0x..]` — explicit bit-level residue annotations.
/// Forms: single bits `75:1` / `84:0`, or ranges `[31:24]=0x05`.
pub fn parse_rsd_annotations(s: &str) -> Vec<(u8, u8)> {
    let mut out = Vec::new();
    for item in s.split(',') {
        let item = item.trim();
        if item.is_empty() { continue; }
        if let Some(rest) = item.strip_prefix('[') {
            // [hi:lo]=0xVAL
            if let Some((rng, val)) = rest.split_once("]=") {
                if let Some((hi, lo)) = rng.split_once(':') {
                    if let (Ok(hi), Ok(lo), Ok(v)) = (hi.parse::<u8>(),
                                                     lo.parse::<u8>(),
                                                     u64::from_str_radix(val.trim_start_matches("0x"), 16)) {
                        for b in lo..=hi {
                            out.push((b, ((v >> (b - lo)) & 1) as u8));
                        }
                    }
                }
            }
        } else if let Some((b, v)) = item.split_once(':') {
            if let (Ok(b), Ok(v)) = (b.parse::<u8>(), v.parse::<u8>()) {
                out.push((b, v & 1));
            }
        }
    }
    out
}

pub fn parse_sass(text: &str, addr: u32) -> Result<Instruction> {
    // Raw verbatim instruction: `__raw__0x<128-bit hex>` — emitted unchanged by the
    // encoder (no re-encode, no rescheduling). Used by `disassemble --frozen` for any
    // instruction whose decoded text would not re-encode byte-faithfully.
    let trimmed = text.trim().trim_end_matches(';').trim();
    if let Some(hex) = trimmed.strip_prefix("__raw__0x") {
        return Ok(Instruction {
            addr,
            opcode: "__raw__".to_string(),
            opcode_full: "__raw__".to_string(),
            key: String::new(),
            guard: None,
            operands: Vec::new(),
            modifiers: Vec::new(),
            ctrl: ControlCode::default(),
            hand_sched: true,
            rsd: None,
            raw_text: format!("__raw__0x{}", hex.trim()),
        });
    }

    // Clean annotations
    let text_clean = text.trim().trim_end_matches(';').trim();
    let text_clean = regex::Regex::new(r"\s*[?&]\S+")
        .unwrap()
        .replace_all(text_clean, "")
        .to_string();
    // Bit-residue annotations from `disassemble` (fidelity markers): !rsd[...]
    // carries bits the nvdisasm-compatible text cannot express. Extracted here,
    // applied verbatim by the encoder overlay at the very end of encoding.
    let mut rsd: Option<Vec<(u8, u8)>> = None;
    let text_clean = if let Some(pos) = text_clean.find("!rsd[") {
        if let Some(end) = text_clean[pos..].find(']') {
            let body = &text_clean[pos + 5..pos + end];
            let v = parse_rsd_annotations(body);
            if !v.is_empty() { rsd = Some(v); }
            let mut t2 = String::new();
            t2.push_str(&text_clean[..pos]);
            t2.push_str(&text_clean[pos + end + 1..]);
            t2.trim().to_string()
        } else { text_clean }
    } else { text_clean };

    let caps = RE_INS
        .captures(&text_clean)
        .with_context(|| format!("unrecognized SASS: {text:?}"))?;

    let pred_str = caps.name("Pred").map_or("", |m| m.as_str()).trim().to_string();
    let op_full = caps.name("Op").unwrap().as_str().to_string();
    let operands_str = caps.name("Operands").map_or("", |m| m.as_str()).to_string();

    // Parse predicate guard
    let guard = if !pred_str.is_empty() {
        parse_guard(&pred_str).0
    } else {
        None
    };

    // Split opcode into base + modifiers
    let op_parts: Vec<&str> = op_full.split('.').collect();
    let base_op = op_parts[0].to_string();
    let modifiers: Vec<String> = op_parts[1..].iter().map(|s| format!(".{s}")).collect();

    // Determine if this is a float-context opcode
    let is_float = FLOAT_OPCODES.iter().any(|f| base_op == *f);

    // Branch opcodes: space-separated register+target → comma-separated
    const BRANCH_OPS: &[&str] = &[
        "BRA", "BRX", "BRXU", "CALL", "JMP", "JMX", "JMXU", "RET",
        "BSSY", "SSY", "CAL", "PRET", "PBK",
    ];
    let mut operands_str = operands_str.trim().to_string();
    if BRANCH_OPS.contains(&base_op.as_str()) {
        // "R20 0x60" → "R20, 0x60"  (space between reg and target)
        // Also handles: "UR8 -0x144b0" and negative offsets
        static RE_BRANCH_SPACE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(U?R\d+)\s+(-?0x[0-9a-fA-F]+|-?\d+)").unwrap()
        });
        operands_str = RE_BRANCH_SPACE.replace(&operands_str, "$1, $2").to_string();
    }

    // Parse operands
    let operands_str = operands_str.trim();
    let mut operands = Vec::new();
    if !operands_str.is_empty() {
        // Split by comma, respecting brackets
        let mut depth = 0;
        let mut current = String::new();
        let mut tokens = Vec::new();
        for ch in operands_str.chars() {
            match ch {
                '[' | '(' => { depth += 1; current.push(ch); }
                ']' | ')' => { depth -= 1; current.push(ch); }
                ',' if depth == 0 => {
                    tokens.push(current.trim().to_string());
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
        if !current.trim().is_empty() {
            tokens.push(current.trim().to_string());
        }

        for tok in &tokens {
            operands.push(parse_single_operand(tok, is_float));
        }
    }

    // Build InsKey
    let mut key = base_op.clone();
    for op in &operands {
        key.push('_');
        key.push_str(operand_type_label(op));
    }

    Ok(Instruction {
        addr,
        opcode: base_op,
        opcode_full: op_full,
        key,
        guard,
        operands,
        modifiers,
        ctrl: ControlCode::default(),
        hand_sched: false,
        rsd,
        raw_text: text.to_string(),
    })
}

// ── Multi-instruction assembly with label resolution ──────────────────────────

/// A statement in a multi-instruction assembly block.
#[derive(Debug, Clone)]
pub enum Statement {
    Instruction(Instruction),
    Label(String),
    Comment,
}

/// Parse a multi-instruction SASS string into a list of statements.
/// Handles labels (`name:`), comments (`//`, `#`), and instruction lines.
/// Instructions can be separated by `;` or newlines.
pub fn parse_multi_sass(text: &str, base_addr: u32) -> Vec<Statement> {
    let mut stmts: Vec<Statement> = Vec::new();
    let mut addr = base_addr;

    // Iterate line-by-line and strip `//` / `#` comments BEFORE splitting on ';'.
    // A ';' inside a comment (e.g. "// rows 2t,2t+1 ; col d") must NOT split off a
    // bogus statement. Instructions are separated by either ';' or newlines, and a
    // line may hold several `INSTR ;` statements.
    for raw_line in text.lines() {
        let nocomment = if let Some(pos) = raw_line.find("//") { &raw_line[..pos] }
                        else if let Some(pos) = raw_line.find('#') { &raw_line[..pos] }
                        else { raw_line };
        for seg in nocomment.split(';') {
            // Strip /*addr*/ prefix (sasskit disassemble format)
            static RE_ADDR: std::sync::LazyLock<regex::Regex> =
                std::sync::LazyLock::new(|| regex::Regex::new(r"^\s*/\*[0-9a-f]+\*/\s*").unwrap());
            let line = RE_ADDR.replace(seg.trim(), "");
            let line = line.trim();
            if line.is_empty() { continue; }

            // Check for label definition: "name:" or "name: INSTR"
            // A label is an identifier ending with ':' at the start of the line
            let (label_part, rest_part) = if let Some(pos) = line.find(':') {
                let potential_label = &line[..pos];
                // Valid label: identifier chars only, no spaces
                let is_label = !potential_label.is_empty()
                    && potential_label.chars().all(|c| c.is_alphanumeric() || c == '_');
                if is_label {
                    (Some(potential_label.to_string()), line[pos+1..].trim().to_string())
                } else {
                    (None, line.to_string())
                }
            } else {
                (None, line.to_string())
            };

            if let Some(label) = label_part {
                stmts.push(Statement::Label(label));
                if rest_part.is_empty() { continue; }
                // Fall through to parse the instruction part after the label
                let line = &rest_part;
                if !line.is_empty() {
                    if let Ok(mut insn) = parse_cuasm_line(line, addr) {
                        insn.addr = addr;
                        addr = addr.wrapping_add(16);
                        stmts.push(Statement::Instruction(insn));
                    }
                }
                continue;
            }
            let line = &rest_part;

            // Parse as instruction
            match parse_cuasm_line(line, addr) {
                Ok(mut insn) => {
                    insn.addr = addr;
                    addr = addr.wrapping_add(16);
                    stmts.push(Statement::Instruction(insn));
                }
                Err(_) => {
                    // Skip lines that can't be parsed (directives, etc.)
                }
            }
        }
    }
    stmts
}

/// Resolve labels in a list of statements: replace Operand::Label(name) with
/// Operand::BranchTarget(addr) in branch instructions.
/// Returns only the instruction statements (labels filtered out).
pub fn resolve_labels(stmts: Vec<Statement>, base_addr: u32) -> Vec<Instruction> {
    use std::collections::HashMap;

    // First pass: build label → addr mapping
    let mut label_map: HashMap<String, u32> = HashMap::new();
    let mut addr = base_addr;
    for stmt in &stmts {
        match stmt {
            Statement::Instruction(_) => { addr = addr.wrapping_add(16); }
            Statement::Label(name) => { label_map.insert(name.clone(), addr); }
            Statement::Comment => {}
        }
    }

    // Second pass: resolve and collect instructions
    let branch_ops = ["BRA", "BSSY", "CALL", "JMP", "RET", "BRX", "BRXU"];
    let mut result = Vec::new();
    for stmt in stmts {
        if let Statement::Instruction(mut insn) = stmt {
            if branch_ops.contains(&insn.opcode.as_str()) {
                for op in &mut insn.operands {
                    if let Operand::Label(name) = op {
                        if let Some(&target) = label_map.get(name.as_str()) {
                            *op = Operand::BranchTarget(target);
                        }
                    }
                }
            }
            result.push(insn);
        }
    }
    result
}

/// Parse a cuasm line: `[B------:R-:W-:-:S01] SASS ;`
pub fn parse_cuasm_line(line: &str, addr: u32) -> Result<Instruction> {
    let line = line.trim();
    if let Some(caps) = RE_TEXT_LINE.captures(line) {
        let cc_str = caps.name("CC").unwrap().as_str();
        let asm_str = caps.name("Asm").unwrap().as_str();
        let ctrl = parse_control_code(cc_str)?;
        let mut insn = parse_sass(asm_str, addr)?;
        insn.ctrl = ctrl;
        insn.hand_sched = true; // freeze: scheduler + drain pass must not touch this
        Ok(insn)
    } else {
        parse_sass(line, addr)
    }
}
