//! M4.3a (BARRACUDA b1): standalone IR -> SASS text renderer.
//!
//! All M4 passes so far emit text by SPLICING original source lines
//! (ra::emit_spliced, sched verbatim windows): they never print an
//! instruction from its structured form. `render` closes that gap:
//! [`SassFile`] / [`Instruction`] -> nvdisasm-compatible source text.
//!
//! Byte-exact contract (gate G14a on the certified R0b corpus):
//!   render_file(parse_sass_file_str_strict(X)) == X           (byte-identical)
//!
//! Rendering rules are CANONICAL, learned from the corpus census (M4.3a
//! pre-scan): immediates lowercase hex (`0x..`, `-0x..`), labels `L_<addr:x>`,
//! register modifier order `-`/`~` prefix then `|.|` then `.reuse`, wait mask
//! as six slots (`B------`), stall two digits. Constructs the corpus never
//! exercises (`.pred/.bar/.shared`, float literals, multi-label stacks) render
//! canonically but are covered by binary-level gates, not the text gate.
//!
//! The parser resolves branch labels to absolute targets
//! ([`Operand::BranchTarget`]); label PRESENCE is stored per kernel in
//! [`crate::sass_file::KernelDef::labels`] (addr -> names). The renderer is
//! fail-closed: every stored label must be emitted exactly once, and operands
//! it cannot print are a hard error, never a guess.

use crate::directives::ParamType;
use crate::ir::{Instruction, Operand};
use crate::sass_file::{KernelDef, SassFile};
use crate::scheduling::format_control_code;
use anyhow::{bail, Context, Result};

const IND: &str = "    ";

fn param_type_str(t: &ParamType) -> &'static str {
    match t {
        ParamType::U8 => "u8",
        ParamType::U16 => "u16",
        ParamType::U32 => "u32",
        ParamType::U64 => "u64",
        ParamType::S8 => "s8",
        ParamType::S16 => "s16",
        ParamType::S32 => "s32",
        ParamType::S64 => "s64",
        ParamType::F16 => "f16",
        ParamType::F32 => "f32",
        ParamType::F64 => "f64",
        ParamType::Ptr => "ptr",
    }
}

fn reg_name(num: u8) -> String {
    if num == 255 {
        "RZ".to_string()
    } else {
        format!("R{num}")
    }
}

fn ureg_name(num: u8, is_zero: bool) -> String {
    if is_zero {
        "URZ".to_string()
    } else {
        format!("UR{num}")
    }
}

/// Modifier wrap order matches the parser strip order and the corpus:
/// `-` / `~` prefix, then `|name|` bars, then `.reuse` suffix.
fn wrap_regish(name: String, neg: bool, abs: bool, inv: bool, reuse: bool) -> String {
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if inv {
        s.push('~');
    }
    if abs {
        s.push('|');
        s.push_str(&name);
        s.push('|');
    } else {
        s.push_str(&name);
    }
    if reuse {
        s.push_str(".reuse");
    }
    s
}

/// Canonical immediate: lowercase hex, `-0x..` for negatives (R0b corpus
/// carries zero decimal operand literals).
fn fmt_imm(v: i64) -> String {
    if v < 0 {
        // i64::MIN cannot be negated; corpus immediates are 32-bit-class.
        format!("-0x{:x}", (v as i128).unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

/// Canonical float literal: shortest round-trip decimal that always contains
/// a '.' or exponent marker, so a re-parse classifies it as float again.
/// (Absent from the R0b corpus; exercised by sond corpora at binary level.)
fn fmt_float(bits: u64) -> String {
    let f = f64::from_bits(bits);
    if f.is_nan() {
        return "NAN".to_string();
    }
    if f.is_infinite() {
        return if f.is_sign_negative() { "-INF".into() } else { "INF".into() };
    }
    let s = format!("{f}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

/// `[R4.64+0x10]`, `[UR8]`, `[R2.X8+UR4]`, `[RZ.64]`.
fn fmt_addr(
    base_reg: Option<u8>,
    base_reg_suffix: &Option<String>,
    ur_reg: Option<u8>,
    offset: i64,
) -> Result<String> {
    let mut inner = String::new();
    let mut have_base = false;
    if let Some(b) = base_reg {
        inner.push_str(&reg_name(b));
        if let Some(sfx) = base_reg_suffix {
            inner.push('.');
            inner.push_str(sfx);
        }
        have_base = true;
    }
    if let Some(u) = ur_reg {
        if have_base {
            inner.push('+');
        }
        inner.push_str(&format!("UR{u}"));
        have_base = true;
    }
    if offset != 0 {
        if have_base {
            inner.push('+');
        }
        inner.push_str(&fmt_imm(offset));
    }
    if !have_base && offset == 0 {
        bail!("render: empty address operand");
    }
    Ok(format!("[{inner}]"))
}

pub fn render_operand(op: &Operand) -> Result<String> {
    Ok(match op {
        Operand::Reg { num, neg, abs, inv, reuse } => {
            wrap_regish(reg_name(*num), *neg, *abs, *inv, *reuse)
        }
        Operand::UReg { num, neg, abs, inv, reuse, is_zero } => {
            wrap_regish(ureg_name(*num, *is_zero), *neg, *abs, *inv, *reuse)
        }
        Operand::Pred { num, neg } => {
            let name = if *num == 7 { "PT".to_string() } else { format!("P{num}") };
            if *neg {
                format!("!{name}")
            } else {
                name
            }
        }
        Operand::UPred { num, neg } => {
            let name = if *num == 7 { "UPT".to_string() } else { format!("UP{num}") };
            if *neg {
                format!("!{name}")
            } else {
                name
            }
        }
        Operand::Imm32(v) => fmt_imm(*v),
        Operand::Imm64(v) => {
            if (*v as i64) < 0 {
                format!("-0x{:x}", (*v as i128).unsigned_abs())
            } else {
                format!("0x{v:x}")
            }
        }
        Operand::FloatImm(bits) => fmt_float(*bits),
        Operand::Addr { base_reg, base_reg_suffix, ur_reg, offset } => {
            fmt_addr(*base_reg, base_reg_suffix, *ur_reg, *offset)?
        }
        Operand::ConstMem { bank, base_reg, ur_reg, offset } => {
            let inner = fmt_addr(*base_reg, &None, *ur_reg, *offset)?;
            format!("c[0x{bank:x}]{}", &inner[..])
        }
        Operand::Desc { ur_idx, base_reg, base_reg_suffix, offset } => {
            let ur = if *ur_idx == 63 {
                "URZ".to_string()
            } else {
                format!("UR{ur_idx}")
            };
            let inner = fmt_addr(*base_reg, base_reg_suffix, None, *offset)?;
            format!("desc[{ur}]{inner}")
        }
        Operand::BranchTarget(t) => format!("L_{t:x}"),
        Operand::Barrier(n) => format!("B{n}"),
        Operand::SysReg(s) => s.clone(),
        // Label operands are the parser's lossless fallback for exotic forms
        // (c[URx][..], tmem/gdesc/idesc, unresolved labels) -- print verbatim.
        Operand::Label(s) => s.clone(),
    })
}

fn render_payload(ins: &Instruction) -> Result<String> {
    // Raw verbatim words carry no structure; raw_text holds the canonical
    // `__raw__0x<hex>` token (parser contract).
    if ins.opcode == "__raw__" {
        return Ok(ins.raw_text.clone());
    }
    let mut s = String::new();
    if let Some(g) = &ins.guard {
        // Bare PT/UPT guards are dropped exactly like nvdisasm emits; the
        // negated true-guard prints as @!PT / @!UPT (QMMA drain pattern).
        if !(g.pred == 7 && !g.negated) {
            s.push('@');
            if g.negated {
                s.push('!');
            }
            if g.uniform {
                s.push('U');
            }
            s.push('P');
            if g.pred == 7 {
                s.push('T');
            } else {
                s.push_str(&g.pred.to_string());
            }
            s.push(' ');
        }
    }
    s.push_str(&ins.opcode_full);
    if !ins.operands.is_empty() {
        s.push(' ');
        let mut parts = Vec::with_capacity(ins.operands.len());
        for op in &ins.operands {
            parts.push(render_operand(op)?);
        }
        s.push_str(&parts.join(", "));
    }
    Ok(s)
}

/// One instruction line, WITHOUT label prefix / indent decision.
fn render_insn_body(ins: &Instruction) -> Result<String> {
    let payload = render_payload(ins)?;
    let mut line = if ins.hand_sched && ins.opcode != "__raw__" {
        format!("[{}] {}", format_control_code(&ins.ctrl), payload)
    } else {
        payload
    };
    if let Some(rsd) = &ins.rsd {
        if !rsd.is_empty() {
            line.push_str(" !rsd[");
            let mut first = true;
            for (b, v) in rsd {
                if !first {
                    line.push(',');
                }
                first = false;
                line.push_str(&format!("{b}:{v}"));
            }
            line.push(']');
        }
    }
    line.push_str(" ;");
    Ok(line)
}

/// Render one kernel: `.entry` scaffold + canonical directives + body.
///
/// Label policy: all anchors stored for an instruction's addr come out as
/// `name:` label-only lines, except the LAST one which rides on the
/// instruction line (`L_x:  <ins> ;`) -- the corpus shape. Every stored label
/// must be emitted exactly once (fail-closed on trailing orphans).
fn render_kernel(k: &KernelDef) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    lines.push(format!(".entry {}", k.name));
    let res = &k.resources;
    if let Some(hi) = res.max_reg {
        lines.push(format!("{IND}.reg R0-R{hi}"));
    }
    if let Some(hi) = res.max_pred {
        lines.push(format!("{IND}.pred P0-P{hi}"));
    }
    if res.num_barriers > 0 {
        lines.push(format!("{IND}.bar B0-B{}", res.num_barriers - 1));
    }
    for p in &res.params {
        lines.push(format!("{IND}.param {} {}", param_type_str(&p.ty), p.name));
    }
    for s in &res.shared {
        lines.push(format!(
            "{IND}.shared .align {} .b8 {}[{}]",
            s.align, s.name, s.size
        ));
    }
    if !res.merc_cgsites.is_empty() {
        let toks: Vec<String> = res
            .merc_cgsites
            .iter()
            .map(|(site, mask)| {
                if *mask == 0xffff_ffff {
                    format!("0x{site:x}")
                } else {
                    format!("0x{site:x}:{mask:08x}")
                }
            })
            .collect();
        lines.push(format!("{IND}.merc_cgsites {}", toks.join(" ")));
    }
    if !res.merc_syncwarp.is_empty() {
        let toks: Vec<String> =
            res.merc_syncwarp.iter().map(|s| format!("0x{s:x}")).collect();
        lines.push(format!("{IND}.merc_syncwarp {}", toks.join(" ")));
    }

    let mut emitted: usize = 0;
    for ins in &k.instructions {
        let body = render_insn_body(ins)?;
        let anchored = k.labels.get(&ins.addr);
        match anchored {
            None => lines.push(format!("{IND}{body}")),
            Some(names) => {
                emitted += names.len();
                let (last, rest) = names.split_last().unwrap();
                for name in rest {
                    lines.push(format!("{name}:"));
                }
                lines.push(format!("{last}:  {body}"));
            }
        }
        if body.is_empty() {
            bail!("render: empty instruction body at addr 0x{:x}", ins.addr);
        }
    }
    let total: usize = k.labels.values().map(Vec::len).sum();
    if emitted != total {
        bail!(
            "render: kernel {} has {} label(s) not anchored at any instruction \
             (trailing label at kernel end?) -- refusing to drop it",
            k.name,
            total - emitted
        );
    }
    lines.push(".endentry".to_string());
    Ok(lines)
}

/// Render a whole file: kernels separated by exactly one blank line, file
/// ends with a single newline (frozen emitter contract, `barracuda.emit`).
pub fn render_file(sf: &SassFile) -> Result<String> {
    let mut out: Vec<String> = Vec::new();
    let mut first = true;
    for k in &sf.kernels {
        if !first {
            out.push(String::new());
        }
        first = false;
        out.extend(render_kernel(k).with_context(|| format!("render kernel {}", k.name))?);
    }
    Ok(format!("{}\n", out.join("\n")))
}

/// Whole-pass entry: strict parse -> render -> optional structural self-check.
/// Returns the rendered text. With `verify`, the rendered text is re-parsed
/// (strict) and must be structurally identical to the input parse
/// ([`structural_eq`]) before it is returned -- the caller never sees unproven
/// text, mirroring the ra/sched splice-proof discipline.
pub fn run_file(text: &str, verify: bool) -> Result<String> {
    let sf = crate::sass_file::parse_sass_file_str_strict(text)
        .context("render: strict parse failed")?;
    let out = render_file(&sf)?;
    if verify {
        let sf2 = crate::sass_file::parse_sass_file_str_strict(&out)
            .context("render verify: rendered text failed strict re-parse")?;
        structural_eq(&sf, &sf2)?;
    }
    Ok(out)
}

/// Instruction-count + operand-level structural equality between two parsed
/// files (the render self-check: parse(render(X)) must equal parse(X)).
/// Compares everything the ENCODER consumes: opcode/guard/operands/ctrl/rsd
/// plus the label-anchor map. raw_text is excluded by design.
pub fn structural_eq(a: &SassFile, b: &SassFile) -> Result<()> {
    if a.kernels.len() != b.kernels.len() {
        bail!("render verify: kernel count {} != {}", a.kernels.len(), b.kernels.len());
    }
    for (ka, kb) in a.kernels.iter().zip(b.kernels.iter()) {
        if ka.name != kb.name {
            bail!("render verify: kernel name {:?} != {:?}", ka.name, kb.name);
        }
        if ka.instructions.len() != kb.instructions.len() {
            bail!(
                "render verify: kernel {} insn count {} != {}",
                ka.name,
                ka.instructions.len(),
                kb.instructions.len()
            );
        }
        if ka.labels != kb.labels {
            bail!("render verify: kernel {} label anchors differ", ka.name);
        }
        for (i, (ia, ib)) in ka.instructions.iter().zip(kb.instructions.iter()).enumerate() {
            let same = ia.addr == ib.addr
                && ia.opcode_full == ib.opcode_full
                && ia.guard == ib.guard
                && ia.operands == ib.operands
                && ia.ctrl == ib.ctrl
                && ia.rsdd_eq(ib);
            if !same {
                bail!(
                    "render verify: kernel {} insn {i} ({}) drifted: {:?} vs {:?}",
                    ka.name,
                    ia.opcode_full,
                    ia,
                    ib
                );
            }
        }
    }
    Ok(())
}

trait RsdEq {
    fn rsdd_eq(&self, other: &Instruction) -> bool;
}

impl RsdEq for Instruction {
    fn rsdd_eq(&self, other: &Instruction) -> bool {
        fn norm(r: &Option<Vec<(u8, u8)>>) -> Vec<(u8, u8)> {
            r.clone().unwrap_or_default()
        }
        norm(&self.rsd) == norm(&other.rsd)
    }
}
