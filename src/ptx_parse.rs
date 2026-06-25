//! PTX parser — text → structured kernel IR.
//!
//! PTX has a regular grammar:
//!   - Directives: `.version`, `.target`, `.entry`, `.reg`, `.param`
//!   - Instructions: `[@pred] opcode.mod.type operand, operand, ...;`
//!   - Registers: `%r0`, `%rd0`, `%f0`, `%p0` or named (`r_sum`, `count`)
//!   - Memory: `[%rd0]`, `[%rd0+16]`, `[param_name]`
//!   - Register groups: `{%r0, %r1, %r2, %r3}`

use anyhow::Result;
use std::collections::HashMap;

// ── PTX kernel representation ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PtxParam {
    pub name: String,
    pub ty: String,       // "u64", "u32", "f32", ...
    pub size: usize,      // bytes
    pub offset: usize,    // constant bank offset (assigned during lowering)
}

#[derive(Debug, Clone)]
pub struct PtxKernel {
    pub name: String,
    pub params: Vec<PtxParam>,
    /// Named register declarations: name → (type, count).
    /// type is "b32", "b64", "f32", "pred", etc.
    pub reg_decls: HashMap<String, String>,
    pub body: Vec<PtxStmt>,
    pub shared_bytes: usize,
}

#[derive(Debug, Clone)]
pub enum PtxStmt {
    Label(String),
    Insn(PtxInsn),
}

#[derive(Debug, Clone)]
pub struct PtxInsn {
    pub guard_pred: Option<String>,  // "%p0" or "p0"
    pub guard_neg: bool,             // @!pred
    pub opcode: String,              // "add.s32", "ld.global.v4.b32", etc.
    pub operands: Vec<PtxOperand>,
}

#[derive(Debug, Clone)]
pub enum PtxOperand {
    /// Register: `%r0`, `%rd0`, `%f0`, `r_sum`, etc.
    Reg(String),
    /// Predicate register: `%p0`, `p0`.
    Pred(String),
    /// Special register: `%tid.x`, `%ctaid.y`, etc.
    SReg(String),
    /// Integer immediate.
    IntImm(i64),
    /// Float immediate.
    FloatImm(f64),
    /// Memory address: `[base]` or `[base+offset]`.
    Addr { base: String, offset: i64 },
    /// Param memory reference: `[param_name]`.
    ParamRef(String),
    /// Register group: `{%r0, %r1, %r2, %r3}`.
    RegGroup(Vec<String>),
    /// Label (branch target).
    Label(String),
}

// ── Type size lookup ─────────────────────────────────────────────────────────

pub fn ptx_type_size(ty: &str) -> usize {
    match ty {
        "u8" | "s8" | "b8" => 1,
        "u16" | "s16" | "b16" | "f16" => 2,
        "u32" | "s32" | "b32" | "f32" => 4,
        "u64" | "s64" | "b64" | "f64" => 8,
        _ => 8, // default to pointer size
    }
}

// ── Special register detection ───────────────────────────────────────────────

fn is_special_reg(s: &str) -> bool {
    matches!(s,
        "%tid.x" | "%tid.y" | "%tid.z" |
        "%ctaid.x" | "%ctaid.y" | "%ctaid.z" |
        "%ntid.x" | "%ntid.y" | "%ntid.z" |
        "%nctaid.x" | "%nctaid.y" | "%nctaid.z" |
        "%laneid" | "%warpid" | "%smid" |
        "%clock" | "%clock64"
    )
}

// ── Strip inline comments ────────────────────────────────────────────────────

fn strip_comment(s: &str) -> &str {
    // Find "//" that isn't part of "::"
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'/' {
            if i > 0 && bytes[i - 1] == b':' {
                i += 2;
                continue;
            }
            return s[..i].trim_end();
        }
        i += 1;
    }
    s
}

// ── Join continuation lines ──────────────────────────────────────────────────

fn join_continuations(lines: &[&str]) -> Vec<String> {
    let mut result = Vec::new();
    let mut accum = String::new();

    for (i, line) in lines.iter().enumerate() {
        let s = strip_comment(line.trim());
        if s.is_empty() || s.starts_with("//") || s.starts_with('#') {
            if !accum.is_empty() {
                result.push(std::mem::take(&mut accum));
            }
            continue;
        }
        if !accum.is_empty() {
            accum.push(' ');
            accum.push_str(s);
            if s.ends_with(';') || !s.ends_with(',') {
                result.push(std::mem::take(&mut accum));
            }
        } else if s.ends_with(',') {
            accum = s.to_string();
        } else if !s.ends_with(';') && !s.contains(':') || s.contains("::") {
            // Possible opcode-only line; check if next starts with '{'
            let next = lines.get(i + 1).map(|l| l.trim());
            if next.map_or(false, |n| n.starts_with('{') || n.starts_with('%')) {
                accum = s.to_string();
            } else {
                result.push(s.to_string());
            }
        } else {
            result.push(s.to_string());
        }
    }
    if !accum.is_empty() {
        result.push(accum);
    }
    result
}

// ── Parse a single operand ───────────────────────────────────────────────────

fn parse_operand(s: &str, reg_decls: &HashMap<String, String>, params: &[PtxParam]) -> PtxOperand {
    let s = s.trim();

    // Register group: {%r0, %r1, ...}
    if s.starts_with('{') && s.ends_with('}') {
        let inner = &s[1..s.len()-1];
        let regs: Vec<String> = inner.split(',').map(|r| r.trim().to_string()).collect();
        return PtxOperand::RegGroup(regs);
    }

    // Memory address: [expr]
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len()-1].trim();
        // Check if it's a param reference
        if let Some(p) = params.iter().find(|p| inner.contains(&p.name)) {
            return PtxOperand::ParamRef(p.name.clone());
        }
        // [base+offset]
        if let Some(plus) = inner.rfind('+') {
            let base = inner[..plus].trim().to_string();
            let off_str = inner[plus+1..].trim();
            let offset = parse_int_literal(off_str).unwrap_or(0);
            return PtxOperand::Addr { base, offset };
        }
        // [base]
        return PtxOperand::Addr { base: inner.to_string(), offset: 0 };
    }

    // Special registers
    if is_special_reg(s) {
        return PtxOperand::SReg(s.to_string());
    }

    // Predicates
    if s.starts_with("%p") || (reg_decls.get(s.trim_start_matches('%')).map_or(false, |t| t == "pred")) {
        return PtxOperand::Pred(s.to_string());
    }

    // Hex immediate
    if s.starts_with("0x") || s.starts_with("0X") || s.starts_with("-0x") || s.starts_with("-0X") {
        if let Some(v) = parse_int_literal(s) {
            return PtxOperand::IntImm(v);
        }
    }

    // Decimal integer
    if let Ok(v) = s.parse::<i64>() {
        return PtxOperand::IntImm(v);
    }

    // Float
    if s.contains('.') || s.ends_with('f') {
        if let Ok(v) = s.trim_end_matches('f').parse::<f64>() {
            return PtxOperand::FloatImm(v);
        }
    }

    // Named or numbered register
    if s.starts_with('%') || reg_decls.contains_key(s) {
        return PtxOperand::Reg(s.to_string());
    }

    // Could be a label
    if s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return PtxOperand::Label(s.to_string());
    }

    PtxOperand::Reg(s.to_string())
}

fn parse_int_literal(s: &str) -> Option<i64> {
    let neg = s.starts_with('-');
    let s = s.trim_start_matches('-');
    let val = if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).ok()?
    } else {
        s.parse::<i64>().ok()?
    };
    Some(if neg { -val } else { val })
}

// ── Split operands respecting braces ─────────────────────────────────────────

fn split_operands(s: &str) -> Vec<String> {
    let mut ops = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();

    for ch in s.chars() {
        match ch {
            '{' | '[' | '(' => { depth += 1; current.push(ch); }
            '}' | ']' | ')' => { depth -= 1; current.push(ch); }
            ',' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    ops.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        ops.push(trimmed);
    }
    ops
}

// ── Parse a single instruction line ──────────────────────────────────────────

fn parse_insn_line(line: &str, reg_decls: &HashMap<String, String>, params: &[PtxParam]) -> Option<PtxInsn> {
    let s = line.trim().trim_end_matches(';').trim();
    if s.is_empty() { return None; }

    let (guard_pred, guard_neg, rest) = if s.starts_with('@') {
        let after_at = &s[1..];
        let neg = after_at.starts_with('!');
        let after_neg = if neg { &after_at[1..] } else { after_at };
        if let Some(space_idx) = after_neg.find(char::is_whitespace) {
            let pred = after_neg[..space_idx].to_string();
            let rest = after_neg[space_idx..].trim();
            (Some(pred), neg, rest)
        } else {
            return None;
        }
    } else {
        (None, false, s)
    };

    let (opcode, operands_str) = match rest.find(char::is_whitespace) {
        Some(idx) => (rest[..idx].to_string(), rest[idx..].trim()),
        None => (rest.to_string(), ""),
    };

    let operand_strs = split_operands(operands_str);
    let operands: Vec<PtxOperand> = operand_strs.iter()
        .map(|o| parse_operand(o, reg_decls, params))
        .collect();

    Some(PtxInsn { guard_pred, guard_neg, opcode, operands })
}

// ── Top-level parser ─────────────────────────────────────────────────────────

pub fn parse_ptx(text: &str) -> Result<Vec<PtxKernel>> {
    let mut kernels = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // .visible .entry kernel_name
        if line.contains(".visible") && line.contains(".entry") {
            let name = extract_entry_name(line)
                .ok_or_else(|| anyhow::anyhow!("cannot parse .entry name: {}", line))?;

            let mut params = Vec::new();
            // Params on same line or subsequent lines until ')'
            collect_params(line, &mut params);
            let mut paren_depth = line.chars().filter(|&c| c == '(').count() as i32
                                - line.chars().filter(|&c| c == ')').count() as i32;
            i += 1;
            while i < lines.len() && paren_depth > 0 {
                let pline = lines[i].trim();
                paren_depth += pline.chars().filter(|&c| c == '(').count() as i32;
                paren_depth -= pline.chars().filter(|&c| c == ')').count() as i32;
                collect_params(pline, &mut params);
                i += 1;
            }

            // Parse body until '}'
            let mut reg_decls = HashMap::new();
            let mut body_lines = Vec::new();
            let mut shared_bytes = 0;

            while i < lines.len() {
                let bline = lines[i].trim();
                if bline == "}" { i += 1; break; }
                if bline.is_empty() || bline == "{" || bline == ")" || bline.starts_with("//") {
                    i += 1; continue;
                }

                // .reg declarations
                if bline.starts_with(".reg") {
                    parse_reg_decl(bline, &mut reg_decls);
                    i += 1; continue;
                }

                // .shared
                if bline.starts_with(".shared") {
                    shared_bytes = parse_shared_decl(bline).unwrap_or(0);
                    i += 1; continue;
                }

                // Skip other directives
                if bline.starts_with('.') {
                    i += 1; continue;
                }

                body_lines.push(lines[i]);
                i += 1;
            }

            // Join multi-line instructions
            let joined = join_continuations(&body_lines);

            // Parse statements
            let mut body = Vec::new();
            for jline in &joined {
                let s = jline.trim();
                // Label?
                if let Some(colon) = s.find(':') {
                    let label = s[..colon].trim();
                    if !label.is_empty() && label.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        body.push(PtxStmt::Label(label.to_string()));
                        let rest = s[colon+1..].trim();
                        if !rest.is_empty() {
                            if let Some(insn) = parse_insn_line(rest, &reg_decls, &params) {
                                body.push(PtxStmt::Insn(insn));
                            }
                        }
                        continue;
                    }
                }
                if let Some(insn) = parse_insn_line(s, &reg_decls, &params) {
                    body.push(PtxStmt::Insn(insn));
                }
            }

            // SM120: params at c[0x0][0x380] (matches cubit ELF builder PARAM_CBANK)
            let mut offset = 0x380usize;
            for p in &mut params {
                offset = (offset + 7) & !7; // 8-byte align
                p.offset = offset;
                offset += 8; // all params occupy 8 bytes in cbank (u32 promoted to u64 slot)
            }

            kernels.push(PtxKernel { name, params, reg_decls, body, shared_bytes });
        } else {
            i += 1;
        }
    }
    Ok(kernels)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn extract_entry_name(line: &str) -> Option<String> {
    let idx = line.find(".entry")?;
    let after = line[idx + 6..].trim();
    let end = after.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(after.len());
    let name = &after[..end];
    if name.is_empty() { None } else { Some(name.to_string()) }
}

fn collect_params(line: &str, params: &mut Vec<PtxParam>) {
    let re = regex::Regex::new(r"\.param\s+\.(\w+)\s+(\w+)").unwrap();
    for cap in re.captures_iter(line) {
        let ty = cap[1].to_string();
        let name = cap[2].to_string();
        let size = ptx_type_size(&ty);
        params.push(PtxParam { name, ty, size, offset: 0 });
    }
}

fn parse_reg_decl(line: &str, decls: &mut HashMap<String, String>) {
    // .reg .b32 %r<16>;
    let re_range = regex::Regex::new(r"\.reg\s+\.(\w+)\s+(%\w+)<(\d+)>").unwrap();
    if let Some(cap) = re_range.captures(line) {
        let ty = cap[1].to_string();
        let prefix = &cap[2];
        let count: usize = cap[3].parse().unwrap_or(0);
        for i in 0..count {
            decls.insert(format!("{}{}", prefix, i), ty.clone());
        }
        return;
    }
    // .reg .u32 r_i, r_sum, r_n;
    let re_named = regex::Regex::new(r"\.reg\s+\.(\w+)\s+(.+?)\s*;").unwrap();
    if let Some(cap) = re_named.captures(line) {
        let ty = cap[1].to_string();
        for name in cap[2].split(',') {
            let name = name.trim().to_string();
            if !name.is_empty() {
                decls.insert(name, ty.clone());
            }
        }
    }
}

fn parse_shared_decl(line: &str) -> Option<usize> {
    let re = regex::Regex::new(r"\.shared\s+(?:\.align\s+\d+\s+)?\.(\w+)\s+\w+\[(\d+)\]").unwrap();
    let cap = re.captures(line)?;
    let elem_size = ptx_type_size(&cap[1]);
    let count: usize = cap[2].parse().ok()?;
    Some(elem_size * count)
}
