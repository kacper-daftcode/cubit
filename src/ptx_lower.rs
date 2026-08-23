//! PTX → SASS lowering engine.
//!
//! Takes parsed PTX kernels and produces cubit `Instruction` vectors using the
//! table-driven mapping from `ptx_map`.  Simple 1:1 rules are applied
//! generically; complex patterns (MMA, 64-bit ops, param loads) have dedicated
//! expansion functions.

use std::collections::HashMap;
use anyhow::Result;

use crate::ir::{ControlCode, Guard, Instruction, Operand};
use crate::ptx_map::{self, OpSlot, SassTemplate, find_rule};
use crate::ptx_parse::{PtxKernel, PtxStmt, PtxInsn, PtxOperand};

// ── Register allocator ───────────────────────────────────────────────────────

struct RegAlloc {
    gpr_map: HashMap<String, u8>,
    pred_map: HashMap<String, u8>,
    next_gpr: u8,
    next_pred: u8,
    reg_decls: HashMap<String, String>,
    /// Freed registers available for reuse (sorted ascending).
    free_gprs: Vec<u8>,
    free_pairs: Vec<u8>,   // even-aligned pairs
    free_quads: Vec<u8>,   // 4-aligned quads
    free_preds: Vec<u8>,   // b9 phase-1: dead-predicate reuse pool
    /// b9 phase-2: set when an unmapped PTX special register was used.
    unknown_sreg: Option<String>,
    /// b9 phase-2 P3: set when the P0..P6 predicate pool is exhausted;
    /// lower_kernel bails fail-closed with this instead of panicking.
    pred_hit_cap: Option<String>,
    /// b9 phase-3 #4: kernel shared-window symbols (static layout, see
    /// ptx_parse) for `mov reg, sym` and `[sym+off]` address resolution.
    shared_syms: std::collections::HashMap<String, i64>,
    /// b9 phase-3 #4: set on an unresolved bare-symbol operand; lower_kernel
    /// bails fail-closed. Previously such symbols silently encoded as a
    /// fresh UNINITIALIZED register ([sym] addressing) or 0x0 (mov sym).
    unknown_sym: Option<String>,
}

impl RegAlloc {
    fn new(reg_decls: &HashMap<String, String>, shared_syms: std::collections::HashMap<String, i64>) -> Self {
        Self {
            gpr_map: HashMap::new(),
            pred_map: HashMap::new(),
            next_gpr: 2,
            next_pred: 0,
            reg_decls: reg_decls.clone(),
            free_gprs: Vec::new(),
            free_pairs: Vec::new(),
            free_quads: Vec::new(),
            free_preds: Vec::new(),
            pred_hit_cap: None,
            unknown_sreg: None,
            shared_syms,
            unknown_sym: None,
        }
    }

    /// b9 phase-3 #4: EXCH-rebase carry predicate (self-contained two-insn
    /// chain; a distinct name from CarryChain32's "%cc" so neither clobbers
    /// the other's live range).

    /// b9 phase-3 #4: shared-window static offset of a bare PTX symbol.
    fn shared_sym(&self, name: &str) -> Option<i64> {
        self.shared_syms.get(name).copied()
    }

    fn gpr(&mut self, name: &str) -> u8 {
        if let Some(&r) = self.gpr_map.get(name) { return r; }
        let r = if let Some(pos) = self.free_gprs.pop() { pos } else {
            let r = self.next_gpr; self.next_gpr += 1; r
        };
        self.gpr_map.insert(name.to_string(), r);
        r
    }

    fn gpr_pair(&mut self, name: &str) -> (u8, u8) {
        if let Some(&r) = self.gpr_map.get(name) { return (r, r + 1); }
        let lo = if let Some(pos) = self.free_pairs.pop() { pos } else {
            if self.next_gpr % 2 != 0 { self.next_gpr += 1; }
            let lo = self.next_gpr; self.next_gpr += 2; lo
        };
        self.gpr_map.insert(name.to_string(), lo);
        (lo, lo + 1)
    }

    fn gpr_quad(&mut self, name: &str) -> u8 {
        if let Some(&r) = self.gpr_map.get(name) { return r; }
        let base = if let Some(pos) = self.free_quads.pop() { pos } else {
            while self.next_gpr % 4 != 0 { self.next_gpr += 1; }
            let b = self.next_gpr; self.next_gpr += 4; b
        };
        self.gpr_map.insert(name.to_string(), base);
        base
    }

    fn pred(&mut self, name: &str) -> u8 {
        if let Some(&p) = self.pred_map.get(name) { return p; }
        // b9 phase-1: SASS has P0..P6. Reuse slots whose PTX pred is dead
        // (last-use sweep in lower_kernel); fail-closed when truly exhausted
        // instead of emitting P8+ (the asm layer rejects them per BUG-004).
        if let Some(p) = self.free_preds.pop() {
            self.pred_map.insert(name.to_string(), p);
            return p;
        }
        if self.next_pred >= 7 {
            // b9 phase-2 P3: no panic — record and let lower_kernel bail
            // fail-closed with kernel name + offending predicate.
            self.pred_hit_cap = Some(name.to_string());
            return 0;
        }
        let p = self.next_pred;
        self.next_pred += 1;
        self.pred_map.insert(name.to_string(), p);
        p
    }

    fn free_pred(&mut self, name: &str) {
        if let Some(p) = self.pred_map.remove(name) {
            self.free_preds.push(p);
        }
    }

    fn is_64bit(&self, name: &str) -> bool {
        let bare = name.trim_start_matches('%');
        if bare.starts_with("rd") { return true; }
        self.reg_decls.get(bare).map_or(false, |t|
            matches!(t.as_str(), "u64" | "s64" | "b64" | "f64"))
    }

    fn resolve(&mut self, name: &str) -> u8 {
        if self.is_64bit(name) { self.gpr_pair(name).0 }
        else { self.gpr(name) }
    }

    /// Free a register pair (available for reuse).
    fn free_pair(&mut self, name: &str) {
        if let Some(r) = self.gpr_map.remove(name) {
            if r % 2 == 0 { self.free_pairs.push(r); }
        }
    }

    /// Free a quad of registers (4 consecutive, for .128 reuse).
    fn free_quad(&mut self, name: &str) {
        if let Some(r) = self.gpr_map.remove(name) {
            if r % 4 == 0 { self.free_quads.push(r); }
            else if r % 2 == 0 { self.free_pairs.push(r); }
        }
    }

    fn max_gpr(&self) -> u8 { self.next_gpr }
}

// ── Special register names ───────────────────────────────────────────────────

fn sreg_sass_name(ptx_name: &str) -> Option<&'static str> {
    match ptx_name {
        "%tid.x"    => "SR_TID.X",    "%tid.y"    => "SR_TID.Y",    "%tid.z"    => "SR_TID.Z",
        "%ctaid.x"  => "SR_CTAID.X",  "%ctaid.y"  => "SR_CTAID.Y",  "%ctaid.z"  => "SR_CTAID.Z",
        "%ntid.x"   => "SR_NTID.X",   "%ntid.y"   => "SR_NTID.Y",   "%ntid.z"   => "SR_NTID.Z",
        "%nctaid.x" => "SR_NCTAID.X", "%nctaid.y" => "SR_NCTAID.Y", "%nctaid.z" => "SR_NCTAID.Z",
        "%laneid"   => "SR_LANEID",    "%warpid"   => "SR_WARPID",   "%smid"     => "SR_SMID",
        "%clock"    => "SR_CLOCKLO",   "%clock64"  => "SR_CLOCKLO",
        // b9 phase-2: unknown special registers must NOT silently become
        // SR_TID.X (phase-1 fallback corrupted semantics invisibly).
        _ => return None,
    }
    .into()
}

// ── Label sanitization ───────────────────────────────────────────────────

/// cubit's SASS parser accepts `[A-Za-z0-9_]` in label names only. nvcc emits
/// `$L__BB0_2` style labels. Map deterministically: `$` -> `D` (dollar),
/// every other accepted char passes through. Injective for nvcc output
/// (plain `D`-prefixed BB labels are not emitted by nvcc); collisions are
/// detected fail-closed at label-table construction.
pub fn sass_label(name: &str) -> String {
    name.chars().map(|c| if c == '$' { 'D' } else { c }).collect()
}

// ── Operand conversion ───────────────────────────────────────────────────

fn ptx_op_to_sass(op: &PtxOperand, alloc: &mut RegAlloc, neg: bool) -> Operand {
    match op {
        PtxOperand::Reg(name) => {
            let num = alloc.resolve(name);
            Operand::Reg { num, neg, abs: false, inv: false, reuse: false }
        }
        PtxOperand::Pred(name) => {
            let num = alloc.pred(name);
            Operand::Pred { num, neg: false }
        }
        PtxOperand::SReg(name) => match sreg_sass_name(name) {
            Some(s) => Operand::SysReg(s.to_string()),
            None => {
                alloc.unknown_sreg = Some(name.clone());
                Operand::SysReg("SR_ILLEGAL_UNSUPPORTED".to_string())
            }
        }
        PtxOperand::IntImm(v) => Operand::Imm32(*v),
        PtxOperand::FloatImm(v) => Operand::FloatImm(v.to_bits()),
        PtxOperand::Addr { base, offset } => {
            if !base.starts_with('%') {
                // b9 phase-3 #4: bare-symbol address base. Shared-window
                // symbols have static layout offsets (RZ = 0 base renders the
                // pure immediate form `[RZ+0x..]`, printed `[0x..]`); anything
                // else (module .global etc.) has no static address -> bail
                // channel. Was previously allocated a fresh UNINITIALIZED
                // register (silent garbage reads).
                if let Some(off) = alloc.shared_sym(base) {
                    return Operand::Addr { base_reg: Some(255), base_reg_suffix: None, ur_reg: None, offset: off + *offset };
                }
                if alloc.unknown_sym.is_none() { alloc.unknown_sym = Some(base.clone()); }
                return Operand::Addr { base_reg: Some(255), base_reg_suffix: None, ur_reg: None, offset: 0 };
            }
            let base_reg = alloc.resolve(base);
            Operand::Addr { base_reg: Some(base_reg), base_reg_suffix: None, ur_reg: None, offset: *offset }
        }
        PtxOperand::Label(s) => Operand::Label(sass_label(s)),
        PtxOperand::RegGroup(regs) => {
            let first = if regs.len() == 4 {
                let base = alloc.gpr_quad(&regs[0]);
                for (i, r) in regs[1..].iter().enumerate() {
                    alloc.gpr_map.insert(r.to_string(), base + (i as u8) + 1);
                }
                base
            } else if regs.len() == 2 {
                let (lo, _) = alloc.gpr_pair(&regs[0]);
                alloc.gpr_map.insert(regs[1].to_string(), lo + 1);
                lo
            } else {
                let first = alloc.resolve(&regs[0]);
                for r in &regs[1..] { alloc.resolve(r); }
                first
            };
            Operand::Reg { num: first, neg: false, abs: false, inv: false, reuse: false }
        }
        PtxOperand::ParamRef(_) => Operand::Imm32(0), // handled separately
    }
}

/// Role of a hardware register group at its USING instruction.
#[derive(Clone, Copy, PartialEq)]
enum GroupRole { Src, Dst }

/// b9 phase-2 P4c: materialize a PTX `{a,b[,c,d]}` group into an aligned
/// consecutive chunk sized by arity (2 -> pair, 4 -> quad; encoder laws).
///
/// PTX virtual registers are NOT SSA: names may be redefined, may appear in
/// several groups, may be immediates ({-1,..}) or repeated ({%r30 x4}), and
/// pack/unpack idioms (`mov.b64 %rd, {%r1,%r2}`) are PER-ELEMENT copies, not
/// hardware groups. Per-occurrence materialization: Src gathers (MOVs when a
/// member's current slot differs from its chunk lane), Dst allocates the
/// chunk and re-points member names at its lanes. Bump-allocated fresh lanes
/// make Src/Dst value races impossible; repeated members chain-copy (values
/// stay equal).
fn prepare_group(
    regs: &[String], role: GroupRole, addr: u32,
    alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<(Operand, Vec<Instruction>)> {
    let n = regs.len();
    if !(n == 2 || n == 4) {
        anyhow::bail!("register group of {} members ({:?}) not a pair/quad", n, regs);
    }
    let base = if n == 4 {
        if let Some(b) = alloc.free_quads.pop() { b } else {
            while alloc.next_gpr % 4 != 0 { alloc.next_gpr += 1; }
            let b = alloc.next_gpr; alloc.next_gpr += 4; b
        }
    } else {
        if let Some(b) = alloc.free_pairs.pop() { b } else {
            while alloc.next_gpr % 2 != 0 { alloc.next_gpr += 1; }
            let b = alloc.next_gpr; alloc.next_gpr += 2; b
        }
    };
    let mut pre: Vec<Instruction> = Vec::new();
    for (i, name) in regs.iter().enumerate() {
        let lane = base + i as u8;
        // immediate member in a group element (e.g. mov.b64 %rd, {-1, %r9})
        if let Ok(v) = name.parse::<i64>() {
            if role == GroupRole::Dst {
                anyhow::bail!("immediate {:?} as vector-group destination", name);
            }
            pre.push(make_insn(addr + 16 * pre.len() as u32, "IMAD.MOV.U32",
                vec![op_reg(lane), op_rz(), op_rz(), Operand::Imm32(v)], guard.clone()));
            continue;
        }
        if alloc.is_64bit(name) {
            anyhow::bail!("64-bit name {:?} inside a vector group (unsupported)", name);
        }
        if role == GroupRole::Src {
            let cur = alloc.gpr(name);
            if cur != lane {
                pre.push(make_insn(addr + 16 * pre.len() as u32,
                    "MOV", vec![op_reg(lane), op_reg(cur)], guard.clone()));
            }
        }
        alloc.gpr_map.insert(name.to_string(), lane);
    }
    Ok((op_reg(base), pre))
}

fn op_pt() -> Operand { Operand::Pred { num: 7, neg: false } }
fn op_not_pt() -> Operand { Operand::Pred { num: 7, neg: true } }
fn op_rz() -> Operand { Operand::Reg { num: 255, neg: false, abs: false, inv: false, reuse: false } }
fn op_reg(num: u8) -> Operand { Operand::Reg { num, neg: false, abs: false, inv: false, reuse: false } }
fn op_neg_reg(num: u8) -> Operand { Operand::Reg { num, neg: true, abs: false, inv: false, reuse: false } }
fn op_imm(v: i64) -> Operand { Operand::Imm32(v) }

// ── Build SASS Instruction ───────────────────────────────────────────────────

fn operand_to_sass(op: &Operand) -> String {
    match op {
        Operand::Reg { num, neg, abs, inv, .. } => {
            let name = if *num == 255 { "RZ".to_string() } else { format!("R{}", num) };
            // b9 phase-3 #3: inv (bitwise-not `~R`) must survive printing -
            // subc carry forms use it in the IADD3.X slot A (vendor anchor).
            let s = if *inv { format!("~{}", name) } else { name };
            let s = if *abs { format!("|{}|", s) } else { s };
            if *neg { format!("-{}", s) } else { s }
        }
        Operand::Pred { num, neg } => {
            let name = if *num == 7 { "PT".to_string() } else { format!("P{}", num) };
            if *neg { format!("!{}", name) } else { name }
        }
        Operand::UReg { num, neg, inv, is_zero, .. } => {
            let name = if *is_zero { "URZ".to_string() } else { format!("UR{}", num) };
            let name = if *inv { format!("~{}", name) } else { name };
            if *neg { format!("-{}", name) } else { name }
        }
        Operand::Imm32(v) => {
            if *v < 0 { format!("-0x{:x}", -v) }
            else { format!("0x{:x}", v) }
        }
        Operand::FloatImm(bits) => {
            // b9 phase-1: cubit's parser accepts f32 raw bits as `0x%08xF`.
            // Use that form whenever the value is exactly f32-representable
            // (bit-exact doctrine); otherwise emit a roundtrip decimal
            // (f64 Display is shortest-roundtrip; ensure a float-typed token).
            let v = f64::from_bits(*bits);
            let f = v as f32;
            if f as f64 == v {
                format!("0x{:08x}F", f.to_bits())
            } else {
                let d = format!("{}", v);
                if d.contains('.') || d.contains('e') || d.contains("inf") || d.contains("NaN") { d }
                else { format!("{}.0", d) }
            }
        }
        Operand::Addr { base_reg, offset, .. } => {
            let base = base_reg.map_or("RZ".to_string(), |r| format!("R{}", r));
            if *offset != 0 { format!("[{}+0x{:x}]", base, offset) }
            else { format!("[{}]", base) }
        }
        Operand::ConstMem { bank, offset, .. } => {
            format!("c[0x{:x}][0x{:x}]", bank, offset)
        }
        Operand::Desc { ur_idx, base_reg, base_reg_suffix, offset } => {
            let base = base_reg.map_or("RZ".to_string(), |r| format!("R{}", r));
            let suffix = base_reg_suffix.as_deref().unwrap_or("");
            if *offset != 0 {
                format!("desc[UR{}][{}{}+0x{:x}]", ur_idx, base, suffix, offset)
            } else {
                format!("desc[UR{}][{}{}]", ur_idx, base, suffix)
            }
        }
        Operand::SysReg(name) => name.clone(),
        Operand::Label(s) => s.clone(),
        Operand::Barrier(b) => format!("B{}", b),
        _ => "??".to_string(),
    }
}

fn make_insn(addr: u32, opcode_full: &str, operands: Vec<Operand>, guard: Option<Guard>) -> Instruction {
    let base_opcode = opcode_full.split('.').next().unwrap_or(opcode_full).to_string();
    let modifiers: Vec<String> = opcode_full.split('.')
        .skip(1)
        .map(|s| format!(".{}", s))
        .collect();

    // Generate readable SASS text (fed to cubit's parser for encoding)
    let guard_str = match &guard {
        Some(g) => {
            let pred = if g.pred == 7 { "PT".to_string() } else { format!("P{}", g.pred) };
            if g.negated { format!("@!{} ", pred) } else { format!("@{} ", pred) }
        }
        None => String::new(),
    };
    let ops_str = operands.iter().map(|o| operand_to_sass(o)).collect::<Vec<_>>().join(", ");
    let raw_text = format!("{}{} {} ;", guard_str, opcode_full, ops_str);

    Instruction {
        addr, opcode: base_opcode, opcode_full: opcode_full.to_string(),
        key: String::new(), // cubit's parser will regenerate this
        guard, operands, modifiers,
        ctrl: ControlCode::default(), hand_sched: false, rsd: None, raw_text,
    }
}

// ── Main lowering entry point ────────────────────────────────────────────────

#[derive(Debug)]
pub struct LoweredKernel {
    pub name: String,
    pub instructions: Vec<Instruction>,
    pub max_regs: u8,
    pub params: Vec<crate::ptx_parse::PtxParam>,
    pub shared_bytes: usize,
}

impl LoweredKernel {
    /// Emit SASS text in cubit's .entry/.endentry directive format.
    pub fn to_sass_text(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(".entry {}", self.name));
        lines.push(format!("    .reg R0-R{}", self.max_regs.max(7) - 1));
        for p in &self.params {
            // SM120 ABI: all kernel params are 8-byte aligned in cbank.
            // cubit ELF builder sets KPARAM_INFO.Size from .param type.
            // Using u64 for all params ensures Size=8 matches CBANK_PARAM_SIZE.
            lines.push(format!("    .param u64 {}", p.name));
        }
        if self.shared_bytes > 0 {
            lines.push(format!("    .shared .align 16 smem[{}]", self.shared_bytes));
        }
        lines.push(String::new());

        for insn in &self.instructions {
            lines.push(format!("    {}", insn.raw_text));
        }
        lines.push(".endentry".to_string());
        lines.join("\n")
    }
}

pub fn lower_kernel(kernel: &PtxKernel) -> Result<LoweredKernel> {
    let mut alloc = RegAlloc::new(&kernel.reg_decls, kernel.shared_syms.clone());
    let mut insns: Vec<Instruction> = Vec::new();
    let mut addr: u32 = 0;

    // Label → address mapping (two-pass for forward branches)
    let mut label_addrs: HashMap<String, u32> = HashMap::new();
    // sanitized -> original, fail-closed on collisions (b9 phase-1 doctrine)
    let mut label_names: HashMap<String, String> = HashMap::new();

    // First pass: estimate addresses for labels
    let mut est_addr: u32 = 0;
    for stmt in &kernel.body {
        match stmt {
            PtxStmt::Label(name) => {
                let san = sass_label(name);
                if let Some(prev) = label_names.get(&san) {
                    if prev != name {
                        anyhow::bail!("ptx label sanitization collision: {:?} and {:?} both -> {:?}", prev, name, san);
                    }
                }
                label_names.insert(san, name.clone());
                label_addrs.insert(name.clone(), est_addr);
            }
            PtxStmt::Insn(insn) => {
                let mut expansion_count = estimate_expansion_size(&insn.opcode);
                // b9 phase-3 #4: EXCH / min.s32 / max.s32 with an offset
                // rebase through an extra IADD3/IADD3.X pair (vendor law,
                // see lower_atomic; max.s32 is listed defensively -- it
                // encodes desc-imm natively since the at10 anchor, so this
                // branch is inert for it).
                if insn.opcode.starts_with("atom.")
                    && (insn.opcode.contains(".exch.")
                        || insn.opcode.contains(".min.s32")
                        || insn.opcode.contains(".max.s32"))
                {
                    if let Some(PtxOperand::Addr { offset, .. }) = insn.operands.get(1) {
                        if *offset != 0 { expansion_count += 2; }
                    }
                }
                est_addr += expansion_count * 16;
            }
        }
    }

    // Unsupported opcodes collected across the whole body, reported as ONE
    // hard error with the complete list (census-grade output, zero silent skips).
    let mut unsupported: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // b9 phase-1: predicate last-use sweep (SSA-style nvcc output makes this
    // exact; textual last use is also sound under later redefinition, since a
    // redefining setp simply allocates a fresh slot afterwards).
    let mut pred_last_use: HashMap<String, usize> = HashMap::new();
    for (si, stmt) in kernel.body.iter().enumerate() {
        if let PtxStmt::Insn(insn) = stmt {
            if let Some(g) = &insn.guard_pred { pred_last_use.insert(g.clone(), si); }
            for op in &insn.operands {
                if let PtxOperand::Pred(name) = op { pred_last_use.insert(name.clone(), si); }
            }
        }
    }
    // b9 phase-3 #3: PTX CC.CF carry register -> one physical predicate.
    // Every carry-chain op (writer or consumer) extends the lifetime; the
    // synthetic name keeps it out of the PTX pred namespace.
    for (si, stmt) in kernel.body.iter().enumerate() {
        if let PtxStmt::Insn(insn) = stmt {
            if is_cc_op(&insn.opcode) { pred_last_use.insert("%cc".to_string(), si); }
        }
    }
    let mut dead_preds: Vec<String> = Vec::new();

    // Convert guard
    fn lower_guard(insn: &PtxInsn, alloc: &mut RegAlloc) -> Option<Guard> {
        insn.guard_pred.as_ref().map(|pred| {
            let num = alloc.pred(pred);
            Guard { pred: num, negated: insn.guard_neg, uniform: false }
        })
    }

    // ── Identify store-only params (deferred allocation like ptxas) ─────
    // A param is "store-only" if its ld.param target register is never used
    // as an address for ld.global — only for st.global.
    let mut store_only_params: std::collections::HashSet<String> = std::collections::HashSet::new();
    {
        // Collect which %rd registers are used as ld.global addresses vs st.global addresses
        let mut load_addr_regs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut store_addr_regs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut param_to_reg: HashMap<String, String> = HashMap::new();

        for stmt in &kernel.body {
            if let PtxStmt::Insn(insn) = stmt {
                if insn.opcode.starts_with("ld.param.") {
                    if let (PtxOperand::Reg(dst), PtxOperand::ParamRef(pname)) =
                        (&insn.operands[0], &insn.operands[1]) {
                        param_to_reg.insert(pname.clone(), dst.clone());
                    }
                    if let (PtxOperand::Reg(dst), PtxOperand::Addr { base, .. }) =
                        (&insn.operands[0], &insn.operands[1]) {
                        for p in &kernel.params {
                            if base.contains(&p.name) {
                                param_to_reg.insert(p.name.clone(), dst.clone());
                            }
                        }
                    }
                }
                if insn.opcode.starts_with("ld.global.") {
                    if let Some(PtxOperand::Addr { base, .. }) = insn.operands.get(1) {
                        load_addr_regs.insert(base.clone());
                    }
                }
                if insn.opcode.starts_with("st.global.") {
                    if let Some(PtxOperand::Addr { base, .. }) = insn.operands.get(0) {
                        store_addr_regs.insert(base.clone());
                    }
                }
            }
        }
        for (pname, reg) in &param_to_reg {
            if store_addr_regs.contains(reg) && !load_addr_regs.contains(reg) {
                store_only_params.insert(pname.clone());
            }
        }
    }

    // ── Kernel prologue ────────────────────────────────────────────────
    // LDCU.64 UR4 = global memory descriptor (c[0x0][0x358])
    // Required for desc[UR4] addressing on SM120
    insns.push(make_insn(addr, "LDCU.64",
        vec![Operand::UReg { num: 4, neg: false, abs: false, inv: false, reuse: false, is_zero: false },
             Operand::ConstMem { bank: 0, base_reg: None, ur_reg: None, offset: 0x358 }],
        None));
    addr += 16;

    let has_global_mem = kernel.body.iter().any(|s| match s {
        PtxStmt::Insn(i) => i.opcode.contains("ld.global") || i.opcode.contains("st.global"),
        _ => false,
    });

    // Second pass: emit instructions
    for (si, stmt) in kernel.body.iter().enumerate() {
        match stmt {
            PtxStmt::Label(name) => {
                // Emit label for cubit's label resolution
                insns.push(Instruction {
                    addr, opcode: String::new(), opcode_full: String::new(),
                    key: String::new(), guard: None, operands: vec![],
                    modifiers: vec![], ctrl: crate::ir::ControlCode::default(),
                    hand_sched: false, rsd: None,
                    raw_text: format!("{}:", sass_label(name)),
                });
                // Labels don't consume address space
            }
            PtxStmt::Insn(insn) => {
                let guard = lower_guard(insn, &mut alloc);

                if let Some(rule) = find_rule(&insn.opcode) {
                    match &rule.template {
                        SassTemplate::Single { opcode, slots } => {
                            let operands = resolve_slots(slots, &insn.operands, &mut alloc);
                            insns.push(make_insn(addr, opcode, operands, guard));
                            addr += 16;
                        }

                        SassTemplate::Add64 => {
                            let (insns64, n) = lower_add64(addr, insn, &mut alloc, guard);
                            insns.extend(insns64);
                            addr += n * 16;
                        }

                        SassTemplate::Mov64 => {
                            let (insns_mv, n) = lower_mov64(addr, insn, &mut alloc, guard)?;
                            insns.extend(insns_mv);
                            addr += n * 16;
                        }

                        SassTemplate::LoadParam => {
                            // Skip store-only params — they'll be loaded lazily after QMMA
                            let param_name = match insn.operands.get(1) {
                                Some(PtxOperand::ParamRef(name)) => Some(name.clone()),
                                Some(PtxOperand::Addr { base, .. }) =>
                                    kernel.params.iter().find(|p| base.contains(&p.name)).map(|p| p.name.clone()),
                                _ => None,
                            };
                            if param_name.as_ref().map_or(false, |n| store_only_params.contains(n)) {
                                // Deferred — don't allocate register yet
                                continue;
                            }
                            let i = lower_ld_param(addr, insn, &kernel.params, &mut alloc, guard);
                            let n = i.len() as u32;
                            insns.extend(i);
                            addr += n * 16;
                        }

                        SassTemplate::SpecialRegMov => {
                            let i = lower_mov_or_sreg(addr, insn, &mut alloc, guard)?;
                            let n = i.len() as u32;
                            insns.extend(i);
                            addr += n * 16;
                        }

                        SassTemplate::ISetp | SassTemplate::FSetp => {
                            let i = lower_setp(addr, insn, &mut alloc, guard);
                            insns.push(i);
                            addr += 16;
                        }

                        SassTemplate::Cvt => {
                            match lower_cvt(addr, insn, &mut alloc, guard) {
                                Some(Ok(iv)) => { addr += 16 * iv.len() as u32; insns.extend(iv); }
                                Some(Err(e)) => { unsupported.insert(format!("{} ({})", insn.opcode, e)); }
                                // b9 phase-2 doctrine: unattested cvt must
                                // NOT vanish silently (phase-1 skipped it).
                                None => { unsupported.insert(insn.opcode.clone()); }
                            }
                        }

                        SassTemplate::LdGlobal => {
                            let iv = lower_ld_global(addr, insn, &mut alloc, guard)?;
                            addr += 16 * iv.len() as u32;
                            insns.extend(iv);
                        }

                        SassTemplate::StGlobal => {
                            let iv = lower_st_global(addr, insn, &mut alloc, guard)?;
                            addr += 16 * iv.len() as u32;
                            insns.extend(iv);
                        }

                        SassTemplate::Atom | SassTemplate::Red => {
                            // b9 phase-3 #4: anchored cases lower; every
                            // unanchored op/type/sem/scope/shape joins the
                            // unsupported list, never vanishes silently.
                            let is_red = matches!(&rule.template, SassTemplate::Red);
                            match lower_atomic(addr, insn, &mut alloc, guard, is_red)? {
                                Some(v) => {
                                    addr += 16 * v.len() as u32;
                                    insns.extend(v);
                                }
                                None => { unsupported.insert(insn.opcode.clone()); }
                            }
                        }

                        SassTemplate::Mma => {
                            // b9 phase-2 doctrine: unshapeable MMA joins the
                            // unsupported list, never vanishes silently.
                            if let Some(iv) = lower_mma(addr, insn, &mut alloc, guard) {
                                addr += 16 * iv.len() as u32;
                                insns.extend(iv);
                            } else {
                                unsupported.insert(insn.opcode.clone());
                            }
                        }

                        SassTemplate::Shfl => {
                            let mode = ptx_map::shfl_mode(&insn.opcode);
                            let d = ptx_op_to_sass(&insn.operands[0], &mut alloc, false);
                            let src = ptx_op_to_sass(&insn.operands[1], &mut alloc, false);
                            let off = ptx_op_to_sass(&insn.operands[2], &mut alloc, false);
                            let clamp = if insn.operands.len() > 3 {
                                ptx_op_to_sass(&insn.operands[3], &mut alloc, false)
                            } else { op_imm(0x1f) };
                            let opf = format!("SHFL.{}", mode);
                            insns.push(make_insn(addr, &opf, vec![op_pt(), d, src, off, clamp], guard));
                            addr += 16;
                        }

                        SassTemplate::PredLogic { lut_a, lut_b } => {
                            // b9 phase-3 P1': PTX pred logic -> PLOP3.LUT
                            // (vendor-anchored form/LUTs, see ptx_map.rs).
                            // Binary ops: d, a, b; unary (not/mov): d, a with
                            // the b input tied PT. Negated pred operands
                            // (`!%p1`, zero corpus occurrences) and immediate
                            // sources are NOT attested -> fail-closed.
                            let d_op = insn.operands.get(0)
                                .ok_or_else(|| anyhow::anyhow!("{}: missing dst", insn.opcode))?;
                            let d = match d_op {
                                PtxOperand::Pred(name) if !name.contains('!') => alloc.pred(name),
                                other => anyhow::bail!("{}: dst must be a plain predicate, got {:?}", insn.opcode, other),
                            };
                            let mut pred_src = |i: usize| -> Result<u8> {
                                match insn.operands.get(i) {
                                    Some(PtxOperand::Pred(name)) if !name.contains('!') => Ok(alloc.pred(name)),
                                    other => anyhow::bail!("{}: operand {} must be a plain predicate, got {:?}", insn.opcode, i, other),
                                }
                            };
                            let a = pred_src(1)?;
                            let unary = insn.opcode.starts_with("not.pred")
                                || insn.opcode.starts_with("mov.pred");
                            let b_opnd = if unary { op_pt() } else {
                                let b = pred_src(2)?;
                                Operand::Pred { num: b, neg: false }
                            };
                            insns.push(make_insn(addr, "PLOP3.LUT", vec![
                                Operand::Pred { num: d, neg: false },
                                op_pt(),
                                Operand::Pred { num: a, neg: false },
                                b_opnd,
                                op_pt(),
                                op_imm(*lut_a as i64),
                                op_imm(*lut_b as i64),
                            ], guard));
                            addr += 16;
                        }

                        SassTemplate::B64Logic { lut } => {
                            // b9 phase-3 #2: PTX 64-bit bitwise logic ->
                            // lo/hi pair of 32-bit LOP3.LUT (vendor-anchored
                            // forms/LUTs, see ptx_map.rs). Binary ops: d, a,
                            // b with b either a 64-bit register or a 64-bit
                            // immediate (split into halves, zero half -> RZ
                            // vendor normalization); unary not.b64: d, a with
                            // the input in slot b and slot a tied RZ.
                            // Immediate srcA / immediate unary src / any
                            // other shape is NOT vendor-attested (zero
                            // corpus occurrences) -> fail-closed bail.
                            let d_op = insn.operands.get(0)
                                .ok_or_else(|| anyhow::anyhow!("{}: missing dst", insn.opcode))?;
                            let (d_lo, d_hi) = match d_op {
                                PtxOperand::Reg(name) => alloc.gpr_pair(name),
                                other => anyhow::bail!("{}: dst must be a 64-bit register, got {:?}", insn.opcode, other),
                            };
                            let a_op = insn.operands.get(1)
                                .ok_or_else(|| anyhow::anyhow!("{}: missing srcA", insn.opcode))?;
                            let (a_lo, a_hi) = match a_op {
                                PtxOperand::Reg(name) if alloc.is_64bit(name) => alloc.gpr_pair(name),
                                other => anyhow::bail!("{}: srcA must be a 64-bit register, got {:?}", insn.opcode, other),
                            };
                            if insn.opcode.starts_with("not.b64") {
                                insns.push(make_insn(addr, "LOP3.LUT", vec![
                                    op_reg(d_lo), op_rz(), op_reg(a_lo), op_rz(),
                                    op_imm(*lut as i64), op_not_pt()], guard.clone()));
                                insns.push(make_insn(addr + 16, "LOP3.LUT", vec![
                                    op_reg(d_hi), op_rz(), op_reg(a_hi), op_rz(),
                                    op_imm(*lut as i64), op_not_pt()], guard));
                            } else {
                                let b_op = insn.operands.get(2)
                                    .ok_or_else(|| anyhow::anyhow!("{}: missing srcB", insn.opcode))?;
                                let (b_lo, b_hi): (Operand, Operand) = match b_op {
                                    PtxOperand::Reg(name) if alloc.is_64bit(name) => {
                                        let (lo, hi) = alloc.gpr_pair(name);
                                        (op_reg(lo), op_reg(hi))
                                    }
                                    PtxOperand::IntImm(v) => {
                                        let lo = (*v as u64) & 0xFFFF_FFFF;
                                        let hi = ((*v as u64) >> 32) & 0xFFFF_FFFF;
                                        (
                                            if lo == 0 { op_rz() } else { op_imm(lo as i64) },
                                            if hi == 0 { op_rz() } else { op_imm(hi as i64) },
                                        )
                                    }
                                    other => anyhow::bail!("{}: srcB must be a 64-bit register or immediate, got {:?}", insn.opcode, other),
                                };
                                insns.push(make_insn(addr, "LOP3.LUT", vec![
                                    op_reg(d_lo), op_reg(a_lo), b_lo, op_rz(),
                                    op_imm(*lut as i64), op_not_pt()], guard.clone()));
                                insns.push(make_insn(addr + 16, "LOP3.LUT", vec![
                                    op_reg(d_hi), op_reg(a_hi), b_hi, op_rz(),
                                    op_imm(*lut as i64), op_not_pt()], guard));
                            }
                            addr += 32;
                        }

                        SassTemplate::CarryChain32 { cin, cout, sub } => {
                            // b9 phase-3 #3: forms verbatim from vendor anchors
                            // (see ptx_map.rs). cc = physical carry predicate.
                            if guard.is_some() {
                                anyhow::bail!("{}: guarded carry-chain ops are unattested (0/93,826 corpus sites)", insn.opcode);
                            }
                            let sub = *sub; let cin = *cin; let cout = *cout;
                            let n_ext = lower_carry32(addr, insn, &mut alloc, sub, cin, cout)?;
                            insns.extend(n_ext.0);
                            addr += 16 * n_ext.1;
                        }

                        SassTemplate::MadCc { hi } => {
                            if guard.is_some() {
                                anyhow::bail!("{}: guarded carry-chain ops are unattested", insn.opcode);
                            }
                            let n_ext = lower_madcc(addr, insn, &mut alloc, *hi)?;
                            insns.extend(n_ext.0);
                            addr += 16 * n_ext.1;
                        }

                        SassTemplate::Shift64 { dir_left, signed } => {
                            // vendor-anchored SHF pair; order (hi first) is
                            // load-bearing for in-place dst==src shifts.
                            let d_name = match insn.operands.get(0) {
                                Some(PtxOperand::Reg(n)) => n.clone(),
                                other => anyhow::bail!("{}: dst must be a b64 register pair, got {:?}", insn.opcode, other),
                            };
                            let a_name = match insn.operands.get(1) {
                                Some(PtxOperand::Reg(n)) => n.clone(),
                                other => anyhow::bail!("{}: srcA must be a b64 register pair, got {:?}", insn.opcode, other),
                            };
                            let (d_lo, d_hi) = alloc.gpr_pair(&d_name);
                            let (a_lo, a_hi) = alloc.gpr_pair(&a_name);
                            let sh = match insn.operands.get(2) {
                                Some(o) => ptx_op_to_sass(o, &mut alloc, false),
                                None => anyhow::bail!("{}: missing shift amount", insn.opcode),
                            };
                            // (funnel_op, plain_op): funnel mixes the 64-bit
                            // concatenation, plain does the 32-bit half
                            let (funnel_op, plain_op) = if *dir_left {
                                ("SHF.L.U64.HI", "SHF.L.U32")
                            } else if *signed {
                                ("SHF.R.S64", "SHF.R.S32.HI")
                            } else {
                                ("SHF.R.U64", "SHF.R.U32.HI")
                            };
                            // vendor emission order: shl -> hi,lo; shr -> lo,hi
                            let (first, second) = if *dir_left {
                                (make_insn(addr, funnel_op, vec![op_reg(d_hi), op_reg(a_lo), sh.clone(), op_reg(a_hi)], guard.clone()),
                                 make_insn(addr + 16, plain_op, vec![op_reg(d_lo), op_reg(a_lo), sh, op_rz()], guard))
                            } else {
                                (make_insn(addr, funnel_op, vec![op_reg(d_lo), op_reg(a_lo), sh.clone(), op_reg(a_hi)], guard.clone()),
                                 make_insn(addr + 16, plain_op, vec![op_reg(d_hi), op_rz(), sh, op_reg(a_hi)], guard))
                            };
                            insns.push(first);
                            insns.push(second);
                            addr += 32;
                        }

                        SassTemplate::MulWide { unsigned } => {
                            // mul.wide.s32/u32 %rd, %rA, B -> IMAD.WIDE[.U32] Rdp, Ra, B, RZ
                            let d = insn.operands.get(0).ok_or_else(|| anyhow::anyhow!("mul.wide: missing dst"))?;
                            let a = insn.operands.get(1).ok_or_else(|| anyhow::anyhow!("mul.wide: missing srcA"))?;
                            let b_op = insn.operands.get(2).ok_or_else(|| anyhow::anyhow!("mul.wide: missing srcB"))?;
                            let (d_lo, _) = match d {
                                PtxOperand::Reg(name) => alloc.gpr_pair(name),
                                _ => anyhow::bail!("mul.wide: dst must be a register, got {:?}", d),
                            };
                            let sa = match a {
                                PtxOperand::Reg(name) if !alloc.is_64bit(name) =>
                                    Operand::Reg { num: alloc.resolve(name), neg: false, abs: false, inv: false, reuse: false },
                                PtxOperand::IntImm(v) => Operand::Imm32(*v),
                                _ => anyhow::bail!("mul.wide: srcA must be a 32-bit register or imm, got {:?}", a),
                            };
                            let sb = match b_op {
                                PtxOperand::Reg(name) if !alloc.is_64bit(name) =>
                                    Operand::Reg { num: alloc.resolve(name), neg: false, abs: false, inv: false, reuse: false },
                                PtxOperand::IntImm(v) => Operand::Imm32(*v),
                                _ => anyhow::bail!("mul.wide: srcB must be a 32-bit register or imm, got {:?}", b_op),
                            };
                            let opf = if *unsigned { "IMAD.WIDE.U32" } else { "IMAD.WIDE" };
                            insns.push(make_insn(addr, opf, vec![op_reg(d_lo), sa, sb, op_rz()], guard));
                            addr += 16;
                        }

                        SassTemplate::AliasPair => {
                            // cvta.to.global.u64 %rdD, %rdS: same VA on SM103a/120 —
                            // unify the dst pair with the src pair, emit no code.
                            match (insn.operands.get(0), insn.operands.get(1)) {
                                (Some(PtxOperand::Reg(d)), Some(PtxOperand::Reg(src)))
                                    if alloc.is_64bit(d) && alloc.is_64bit(src) =>
                                {
                                    let (lo, _) = alloc.gpr_pair(src);
                                    alloc.gpr_map.insert(d.clone(), lo);
                                }
                                other => anyhow::bail!("cvta.to.global: expected (reg64, reg64), got {:?}", other),
                            }
                        }

                        SassTemplate::Nop => {
                            // generic no-op lowering (kept for legacy rules)
                        }
                    }
                } else {
                    // b9 phase-1 (doctrine fail-closed): never skip silently.
                    unsupported.insert(insn.opcode.clone());
                }
            }
        }

        // free predicates whose last use is this statement (phase-1 sweep)
        for (name, &lu) in pred_last_use.iter() {
            if lu == si { dead_preds.push(name.clone()); }
        }
        for name in dead_preds.drain(..) { alloc.free_pred(&name); }
    }

    // b9 phase-1: immediate legalization. ISA arith forms carry at most ONE
    // immediate slot; nvcc folds constants into PTX arith (mad.lo with two
    // literals etc.). Policy mirrors ptxas (anchor: k2 probe): keep the LAST
    // immediate in place, materialize every earlier one with a MOV. Applied
    // to the contained arith set only -- LOP3.LUT legitimately carries a data
    // imm + LUT immediate, so blanket imm-counting is unsound.
    const IMM_LEGALIZE_OPS: &[&str] = &["IMAD", "IMAD.HI", "FFMA", "FMUL", "FADD", "SEL"];
    {
        let mut hoisted: Vec<(usize, Instruction)> = Vec::new();
        let mut fixn = 0usize;
        for (idx, insn) in insns.iter_mut().enumerate() {
            if !IMM_LEGALIZE_OPS.contains(&insn.opcode.as_str()) { continue; }
            if insn.guard.is_some() && insn.opcode.starts_with("LDC") { continue; }
            let imm_pos: Vec<usize> = insn.operands.iter().enumerate()
                .filter(|(_, o)| matches!(o, Operand::Imm32(_) | Operand::FloatImm(_)))
                .map(|(i, _)| i).collect();
            if imm_pos.len() <= 1 { continue; }
            let keep = *imm_pos.last().unwrap();
            for &pos in imm_pos.iter().take_while(|&&p| p != keep) {
                let tmp = alloc.gpr(&format!("__immfix_{}", fixn));
                fixn += 1;
                let imm_op = insn.operands[pos].clone();
                insn.operands[pos] = Operand::Reg { num: tmp, neg: false, abs: false, inv: false, reuse: false };
                // Float constants materialize the ptxas way: raw f32 bits as an
                // integer immediate via IMAD.MOV.U32 (anchor: k2 vendor probe).
                // No MOV_R_FI form exists in the tables (observed fail-closed).
                let mat = match &imm_op {
                    Operand::FloatImm(bits) => {
                        let v = f64::from_bits(*bits);
                        let f = v as f32;
                        if f as f64 != v {
                            anyhow::bail!(
                                "imm legalization: f64 literal {} needs 64-bit materialization (unsupported in phase-1)", v);
                        }
                        make_insn(0, "IMAD.MOV.U32",
                            vec![op_reg(tmp), op_rz(), op_rz(), Operand::Imm32(f.to_bits() as i64)], None)
                    }
                    Operand::Imm32(_) => make_insn(0, "MOV", vec![op_reg(tmp), imm_op.clone()], None),
                    _ => unreachable!(),
                };
                hoisted.push((idx, mat));
            }
            insn.raw_text = format!("{}{} {} ;",
                insn.guard.as_ref().map(|g| if g.negated { format!("@!P{} ", g.pred) } else { format!("@P{} ", g.pred) }).unwrap_or_default(),
                insn.opcode_full,
                insn.operands.iter().map(|o| operand_to_sass(o)).collect::<Vec<_>>().join(", "));
        }
        for (off, (idx, mov)) in hoisted.into_iter().enumerate() {
            insns.insert(idx + off, mov);
        }
    }

    let mut fixn_g = 0usize;
    let mut hoist_movs: Vec<(usize, Instruction)> = Vec::new();
    let mut mv_ins_index = 0usize;
    // b9 phase-2: SASS-form normalization for shapes the sm_103a encoder
    // provably lacks ("attempted keys" census of the iter31 corpus):
    //  * IADD3[.X]: imm in source slot-3 -> swap to slot-4 (a/b symmetric in
    //    a 3-input add; cin/cout operands untouched). Vendor keeps imm LAST.
    //  * SEL: imm in slot-1 with reg slot-2 -> swap slots and INVERT the
    //    selecting predicate (selp algebra), otherwise R_II form missing.
    //  * STS: immediate data materializes via IMAD.MOV.U32 (same law as STG).
    //  * BAR.SYNC.DEFER_BLOCKING: RZ placeholders -> imm 0 (vendor corpus
    //    prints "0x0, 0x0"; the II_R mixed form is absent from the table).
    for insn in insns.iter_mut() {
        let op = insn.opcode.as_str();
        let mut touched = false;
        let mut hoist_mov: Option<Instruction> = None;
        if (op == "IADD3" || op == "IADD3.X") && insn.operands.len() >= 6 {
            if matches!(insn.operands[3], Operand::Imm32(_))
                && matches!(insn.operands[4], Operand::Reg { .. }) {
                insn.operands.swap(3, 4);
                touched = true;
            }
        } else if op == "SEL" && insn.operands.len() == 4 {
            let imm_a = matches!(insn.operands[1], Operand::Imm32(_) | Operand::FloatImm(_));
            let reg_b = matches!(insn.operands[2], Operand::Reg { .. });
            if imm_a && reg_b {
                insn.operands.swap(1, 2);
                if let Operand::Pred { neg, .. } = &mut insn.operands[3] {
                    *neg = !*neg;
                    touched = true;
                }
            }
        } else if op == "STS" && insn.operands.len() == 2 {
            if let Operand::Imm32(v) = insn.operands[1].clone() {
                let tmp = alloc.gpr(&format!("__stsimm_{}", fixn_g));
                insn.operands[1] = op_reg(tmp);
                hoist_mov = Some(make_insn(0, "IMAD.MOV.U32",
                    vec![op_reg(tmp), op_rz(), op_rz(), Operand::Imm32(v)], None));
                touched = true;
            }
        } else if op == "BAR" {
            for o in insn.operands.iter_mut() {
                if matches!(o, Operand::Reg { num: 255, .. }) {
                    *o = op_imm(0);
                    touched = true;
                }
            }
        }
        if touched {
            insn.raw_text = format!("{}{} {} ;",
                insn.guard.as_ref().map(|g| if g.negated { format!("@!P{} ", g.pred) } else { format!("@P{} ", g.pred) }).unwrap_or_default(),
                insn.opcode_full,
                insn.operands.iter().map(|o| operand_to_sass(o)).collect::<Vec<_>>().join(", "));
            if let Some(mv) = hoist_mov {
                hoist_movs.push((mv_ins_index, mv));
            }
        }
        mv_ins_index += 1;
    }
    for (off, (idx, mov)) in hoist_movs.into_iter().enumerate() {
        insns.insert(idx + off, mov);
    }

    if let Some(hit) = &alloc.unknown_sreg {
        anyhow::bail!("ptx_lower: unsupported special register {:?} in kernel {} (no sm_103a mapping)", hit, kernel.name);
    }
    if let Some(hit) = &alloc.unknown_sym {
        anyhow::bail!(
            "ptx_lower: unresolved symbol address {:?} in kernel {} (only kernel .shared statics/externs have static offsets; .global needs relocation support)",
            hit, kernel.name);
    }
    if let Some(hit) = &alloc.pred_hit_cap {
        anyhow::bail!(
            "ptx_lower: predicate space exhausted (P0..P6) in kernel {} at predicate {:?}; kernel needs live-range-aware allocation",
            kernel.name, hit);
    }
    if !unsupported.is_empty() {
        anyhow::bail!(
            "unsupported PTX in kernel {}: {} op(s): {}",
            kernel.name,
            unsupported.len(),
            unsupported.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }

    // Scheduling fence before final STG (matches ptxas behavior)
    // @!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ — NOP that forces write barrier drain
    let last_is_stg = insns.last().map_or(false, |i| i.opcode == "STG");
    // Find first STG and insert before it: deferred LDC → UIADD3 fences
    let has_ldg = insns.iter().any(|i| i.opcode == "LDG");

    // Emit deferred (store-only) param loads BEFORE fences/STG
    if let Some(stg_idx) = insns.iter().position(|i| i.opcode == "STG") {
        let mut deferred_insns = Vec::new();
        for stmt in &kernel.body {
            if let PtxStmt::Insn(insn) = stmt {
                if insn.opcode.starts_with("ld.param.") {
                    let param_name = match insn.operands.get(1) {
                        Some(PtxOperand::ParamRef(name)) => Some(name.clone()),
                        Some(PtxOperand::Addr { base, .. }) =>
                            kernel.params.iter().find(|p| base.contains(&p.name)).map(|p| p.name.clone()),
                        _ => None,
                    };
                    if param_name.as_ref().map_or(false, |n| store_only_params.contains(n)) {
                        let guard = lower_guard(insn, &mut alloc);
                        deferred_insns.extend(lower_ld_param(0, insn, &kernel.params, &mut alloc, guard));
                    }
                }
            }
        }
        for (j, di) in deferred_insns.into_iter().enumerate() {
            insns.insert(stg_idx + j, di);
        }
    }

    // Reassign addresses after insertions
    for (i, insn) in insns.iter_mut().enumerate() {
        insn.addr = (i as u32) * 16;
    }
    addr = (insns.len() as u32) * 16;

    if has_ldg {
        let fence_text = "@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ ;".to_string();
        // Find first STG and insert fences before it
        if let Some(stg_idx) = insns.iter().position(|i| i.opcode == "STG") {
            let fence = Instruction {
                addr: 0, opcode: "UIADD3".to_string(), opcode_full: "UIADD3".to_string(),
                key: String::new(),
                guard: Some(Guard { pred: 7, negated: true, uniform: true }),
                operands: vec![], modifiers: vec![],
                ctrl: crate::ir::ControlCode::default(),
                hand_sched: false, rsd: None,
                raw_text: fence_text,
            };
            insns.insert(stg_idx, fence.clone());
            insns.insert(stg_idx, fence);
        }
        // Reassign addresses
        for (i, insn) in insns.iter_mut().enumerate() {
            insn.addr = (i as u32) * 16;
        }
        addr = (insns.len() as u32) * 16;
    }

    // Ensure EXIT at end
    let has_exit = insns.last().map_or(false, |i| i.opcode == "EXIT");
    if !has_exit {
        insns.push(make_insn(addr, "EXIT", vec![], None));
    }

    Ok(LoweredKernel {
        name: kernel.name.clone(),
        instructions: insns,
        max_regs: alloc.max_gpr(),
        params: kernel.params.clone(),
        shared_bytes: kernel.shared_bytes,
    })
}

// ── Slot resolution (the generic "Single" path) ─────────────────────────────

fn resolve_slots(slots: &[OpSlot], ptx_ops: &[PtxOperand], alloc: &mut RegAlloc) -> Vec<Operand> {
    slots.iter().map(|slot| {
        match slot {
            OpSlot::Src(i) => {
                if let Some(op) = ptx_ops.get(*i) {
                    ptx_op_to_sass(op, alloc, false)
                } else { op_rz() }
            }
            OpSlot::NegSrc(i) => {
                if let Some(op) = ptx_ops.get(*i) {
                    ptx_op_to_sass(op, alloc, true)
                } else { op_rz() }
            }
            OpSlot::AbsSrc(i) => {
                if let Some(PtxOperand::Reg(name)) = ptx_ops.get(*i) {
                    let num = alloc.resolve(name);
                    Operand::Reg { num, neg: false, abs: true, inv: false, reuse: false }
                } else { op_rz() }
            }
            OpSlot::Imm(v) => op_imm(*v as i64),
            OpSlot::PT => op_pt(),
            OpSlot::RZ => op_rz(),
            OpSlot::NotPT => op_not_pt(),
        }
    }).collect()
}

/// b9 phase-3 #3: does this opcode touch PTX CC (carry-chain class)?
fn is_cc_op(opcode: &str) -> bool {
    opcode.starts_with("add.cc.") || opcode.starts_with("addc.")
        || opcode.starts_with("sub.cc.") || opcode.starts_with("subc.")
        || opcode.starts_with("mad.lo.cc.") || opcode.starts_with("madc.")
}

fn estimate_expansion_size(opcode: &str) -> u32 {
    // b9 phase-3 #4: acq_rel atoms wrap the core op in 4 glue instructions
    // (vendor anchor at5_sem: MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR; core;
    // CCTL.IVALL). Label-address estimation must match the real expansion
    // or branch targets shift silently.
    if opcode.starts_with("atom.") && opcode.contains(".acq_rel.") { return 5; }
    // b9 phase-3 #3 template sizes (instruction counts)
    if opcode.starts_with("mad.lo.cc.") { return 3; }
    if opcode.starts_with("madc.") { return 2; }
    if opcode == "shl.b64" || opcode == "shr.u64" || opcode == "shr.s64" { return 2; }
    if opcode.contains(".u64") || opcode.contains(".s64") || opcode.contains(".b64") {
        if opcode.starts_with("add.") || opcode.starts_with("sub.") { return 2; }
        if opcode.starts_with("mov.") { return 2; }
    }
    1
}

// ── Specialized lowering functions ───────────────────────────────────────────

/// b9 phase-3 #3: 32-bit add/sub with CC carry in/out. Operand layout and
/// immediate handling are vendor anchors (see ptx_map.rs doc); one physical
/// predicate ("%cc") models PTX CC.CF for the whole chain.
/// b9 phase-3 #4: PTX atom./red. -> SASS atomic class (anchors + suffix map
/// in ptx_map.rs). Returns Ok(None) => op joins the unsupported list
/// (unanchored variant); Err => structural violation (bail whole kernel).
///
/// Legal space x (op,type) x (sem,scope) matrix (census-attested + anchored):
///   global|generic atom: add{u32,f32,f64,u64}, and/or/xor.b32, exch.b32,
///     min/max{u32,s32}, inc/dec.u32, cas.b32; sem/scope: default(.gpu) |
///     relaxed.sys (cas only) | acq_rel.gpu (add only, glue sequence).
///   shared atom (level .cta stripped; sem {,relaxed} + scope
///     {"",cta,gpu,sys} all strip -- vendor emits plain ATOMS, anchor at6):
///     add.u32, max.u32, cas.b32.
///   red.global: add{u32,f32} (no dest). Everything else: unsupported.
fn lower_atomic(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>, is_red: bool,
) -> Result<Option<Vec<Instruction>>> {
    // BUG-080: guarded atomic-class ops are silently dropped by sm_103a
    // silicon (cubit encoder hard-fails them); fail closed by policy.
    if guard.is_some() { return Ok(None); }

    // opcode token decomposition: atom{.sem}{.scope}{.space}.op{.level}.type
    // (qualifiers may follow the op too; ptxas accepts both orders, corpus
    // attests "atom.global.add.acq_rel.gpu.u32").
    let toks: Vec<&str> = insn.opcode.split('.').collect();
    let mut space = "";
    let mut sem = "";
    let mut scope = "";
    let mut op = "";
    let mut ty = "";
    let mut level = "";
    for t in toks.iter().skip(1) {
        match *t {
            "global" | "shared" | "local" => {
                if !space.is_empty() { return Ok(None); }
                space = t;
            }
            "relaxed" | "acquire" | "release" | "acq_rel" => {
                if !sem.is_empty() { return Ok(None); }
                sem = t;
            }
            "gpu" | "sys" | "cluster" => {
                if !scope.is_empty() { return Ok(None); }
                scope = t;
            }
            "cta" => {
                if space == "shared" && level.is_empty() { level = t; }
                else if scope.is_empty() { scope = t; }
                else { return Ok(None); }
            }
            _ if op.is_empty() && matches!(*t,
                "add" | "and" | "or" | "xor" | "exch" | "min" | "max" | "inc" | "dec" | "cas") => { op = t; }
            _ if ty.is_empty() && matches!(*t,
                "u16" | "s16" | "u32" | "s32" | "u64" | "s64" | "b16" | "b32" | "b64" |
                "f16" | "f16x2" | "bf16" | "bf16x2" | "f32" | "f64" | "u128") => { ty = t; }
            _ => return Ok(None),
        }
    }
    if op.is_empty() || ty.is_empty() { return Ok(None); }

    let shared = space == "shared";
    let is64 = matches!(ty, "u64" | "s64" | "b64" | "f64");

    // SASS op suffix per anchored (space, op, type)
    let sfx: &str = if shared {
        if is_red { return Ok(None); }
        match (op, ty) {
            ("add", "u32") => "ADD",
            ("max", "u32") => "MAX",
            ("cas", "b32") => "CAS",
            _ => return Ok(None),
        }
    } else if is_red {
        if !sem.is_empty() || !scope.is_empty() { return Ok(None); }
        match (op, ty) {
            ("add", "u32") => "ADD",
            ("add", "f32") => "ADD.F32.FTZ.RN",
            _ => return Ok(None),
        }
    } else {
        // NOTE: add.s32 has no vendor anchor on sm_103a (only u32/f32/f64/
        // u64); it lands in the unsupported arm below.
        match (op, ty) {
            ("add", "u32") => "ADD",
            ("add", "f32") => "ADD.F32.FTZ.RN",
            ("add", "f64") => "ADD.F64.RN",
            ("add", "u64") => "ADD.64",
            ("and", "b32") => "AND",
            ("or", "b32") => "OR",
            ("xor", "b32") => "XOR",
            ("exch", "b32") => "EXCH",
            ("min", "u32") => "MIN",
            ("max", "u32") => "MAX",
            ("min", "s32") => "MIN.S32",
            ("max", "s32") => "MAX.S32",
            ("inc", "u32") => "INC",
            ("dec", "u32") => "DEC",
            ("cas", "b32") => "CAS",
            _ => return Ok(None),
        }
    };

    // sem/scope -> SASS scope suffix (+ glue for acq_rel)
    let (scope_suffix, glue) = if shared {
        // vendor strips sem/scope on ATOMS entirely (anchor at6)
        let sem_ok = sem.is_empty() || sem == "relaxed";
        let scope_ok = scope.is_empty() || matches!(scope, "cta" | "gpu" | "sys");
        if !sem_ok || !scope_ok { return Ok(None); }
        ("", false)
    } else {
        match (sem, scope) {
            ("", "") => ("GPU", false),
            ("relaxed", "sys") if op == "cas" => ("SYS", false),
            ("acq_rel", "gpu") if op == "add" => ("GPU", true),
            _ => return Ok(None),
        }
    };

    // operand positions: atom d,[a],b[,c]; red [a],b[,c]
    let ops_base = if is_red { 0 } else { 1 };
    let addr_ptx = insn.operands.get(ops_base);
    let val_ptx = insn.operands.get(ops_base + 1);
    let cmp_ptx = if op == "cas" { insn.operands.get(ops_base + 2) } else { None };
    if addr_ptx.is_none() || val_ptx.is_none() || (op == "cas" && cmp_ptx.is_none()) {
        return Ok(None);
    }

    // destination (atom only)
    let dst_num: Option<u8> = if is_red {
        None
    } else {
        match insn.operands.first() {
            Some(PtxOperand::Reg(n)) => Some(alloc.resolve(n)),
            _ => return Ok(None),
        }
    };

    // address: register base (64-bit global/generic, 32-bit shared), or a
    // shared-window symbol (static RZ+imm), eponymous range checks
    let (base_num, off) = match addr_ptx {
        Some(PtxOperand::Addr { base, offset }) => {
            if base.starts_with('%') {
                if shared {
                    if alloc.is_64bit(base) { return Ok(None); } // unattested
                    (alloc.resolve(base), *offset)
                } else {
                    if !alloc.is_64bit(base) { return Ok(None); }
                    (alloc.resolve(base), *offset)
                }
            } else if shared && alloc.shared_sym(base).is_some() {
                (255u8, alloc.shared_sym(base).unwrap() + *offset)
            } else {
                return Ok(None); // named module symbols = reloc territory
            }
        }
        _ => return Ok(None),
    };
    // ARI/desc immediate widths: shared/glue-CAS = 24-bit signed; desc = 23-bit
    let (lo, hi) = if shared || op == "cas" { (-0x800000i64, 0x7fffffi64) } else { (-0x400000i64, 0x3fffffi64) };
    if !(lo..=hi).contains(&off) {
        anyhow::bail!("{}: address offset {} exceeds the ARI/desc immediate range", insn.opcode, off);
    }

    let mut out: Vec<Instruction> = Vec::new();
    // b9 phase-3 #4: ops WITHOUT a canonical desc-immediate field rebase
    // the offset into the address register pair, exactly as ptxas does
    // (-O0: every atomic; -O3: only these ops -- anchors p03/at9, at10):
    //   EXCH     -- 'E,EXCH,GPU,STRONG' carries no sub_imm2 at all
    //   min.s32  -- its field is non-canonical 38/24 (BUG-093 queue; no
    //               +imm vendor word exists anywhere to re-derive against)
    // The pair is IADD3 lo + IADD3.X hi (iter34 carry-form; %atomcc is the
    // self-contained scratch predicate, distinct from CarryChain32's %cc).
    const REBASE_OPS: &[&str] = &["exch", "min"];
    let needs_rebase = !shared && op == "exch"
        || (!shared && REBASE_OPS.contains(&op) && ty == "s32");
    let (base_num, off) = if needs_rebase && off != 0 {
        let t_pair = alloc.gpr_pair(&format!("__atomoff_{}", addr));
        let pcc = alloc.pred("%atomcc");
        out.push(make_insn(addr + 16 * out.len() as u32, "IADD3",
            vec![op_reg(t_pair.0), Operand::Pred { num: pcc, neg: false }, Operand::Pred { num: 7, neg: false },
                 op_reg(base_num), Operand::Imm32(off), op_rz()], None));
        out.push(make_insn(addr + 16 * out.len() as u32, "IADD3.X",
            vec![op_reg(t_pair.1), Operand::Pred { num: 7, neg: false }, Operand::Pred { num: 7, neg: false },
                 op_reg(base_num + 1), op_rz(), op_rz(),
                 Operand::Pred { num: pcc, neg: false }, op_not_pt()], None));
        (t_pair.0, 0i64)
    } else { (base_num, off) };
    let mut mat = |ptx_op: &PtxOperand, alloc: &mut RegAlloc, out: &mut Vec<Instruction>, addr: u32| -> Result<Option<Operand>> {
        match ptx_op {
            PtxOperand::Reg(n) => Ok(Some(op_reg(alloc.resolve(n)))),
            PtxOperand::IntImm(v) if !is64 => {
                let t = alloc.gpr(&format!("__atomimm_{}", addr + 16 * out.len() as u32));
                out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                    vec![op_reg(t), op_rz(), op_rz(), Operand::Imm32(*v)], None));
                Ok(Some(op_reg(t)))
            }
            PtxOperand::FloatImm(v) if ty == "f32" => {
                let f = *v as f32;
                if f as f64 != *v { return Ok(None); }
                let t = alloc.gpr(&format!("__atomimm_{}", addr + 16 * out.len() as u32));
                out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                    vec![op_reg(t), op_rz(), op_rz(), Operand::Imm32(f.to_bits() as i64)], None));
                Ok(Some(op_reg(t)))
            }
            _ => Ok(None),
        }
    };
    let val_op = match mat(val_ptx.unwrap(), alloc, &mut out, addr)? { Some(o) => o, None => return Ok(None) };
    let cmp_op: Option<Operand> = match cmp_ptx {
        Some(cp) => match mat(cp, alloc, &mut out, addr)? { Some(o) => Some(o), None => return Ok(None) },
        None => None,
    };

    // glue prefix (acq_rel anchor): MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR
    let mut seq: Vec<Instruction> = Vec::new();
    if glue {
        for g in ["MEMBAR.ALL.GPU", "ERRBAR", "CGAERRBAR"] {
            seq.push(make_insn(addr + 16 * seq.len() as u32, g, vec![], None));
        }
    }
    seq.append(&mut out);

    let core_addr = addr + 16 * seq.len() as u32;
    if shared {
        let a_op = Operand::Addr { base_reg: Some(base_num), base_reg_suffix: None, ur_reg: None, offset: off };
        let ops = if op == "cas" {
            vec![op_reg(dst_num.unwrap()), a_op, cmp_op.unwrap(), val_op]
        } else {
            vec![op_reg(dst_num.unwrap()), a_op, val_op]
        };
        seq.push(make_insn(core_addr, &format!("ATOMS.{}", sfx), ops, guard));
    } else if op == "cas" {
        // vendor CAS uses the plain ARI form (no desc) -- anchor at4/at6
        let a_op = Operand::Addr { base_reg: Some(base_num), base_reg_suffix: None, ur_reg: None, offset: off };
        let base_op = if space == "global" { "ATOMG" } else { "ATOM" };
        seq.push(make_insn(core_addr,
            &format!("{}.E.CAS.STRONG.{}", base_op, scope_suffix),
            vec![op_pt(), op_reg(dst_num.unwrap()), a_op, cmp_op.unwrap(), val_op], guard));
    } else {
        let desc = Operand::Desc {
            ur_idx: 4, base_reg: Some(base_num),
            base_reg_suffix: Some(".64".to_string()), offset: off,
        };
        if is_red {
            seq.push(make_insn(core_addr, &format!("REDG.E.{}.STRONG.GPU", sfx), vec![desc, val_op], guard));
        } else {
            let base_op = if space == "global" { "ATOMG" } else { "ATOM" };
            seq.push(make_insn(core_addr,
                &format!("{}.E.{}.STRONG.{}", base_op, sfx, scope_suffix),
                vec![op_pt(), op_reg(dst_num.unwrap()), desc, val_op], guard));
        }
    }
    if glue {
        seq.push(make_insn(addr + 16 * seq.len() as u32, "CCTL.IVALL", vec![], None));
    }
    Ok(Some(seq))
}

fn lower_carry32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc,
    sub: bool, cin: bool, cout: bool,
) -> Result<(Vec<Instruction>, u32)> {
    let d = match insn.operands.get(0) {
        Some(o) => ptx_op_to_sass(o, alloc, false),
        None => anyhow::bail!("{}: missing dst", insn.opcode),
    };
    let a = match insn.operands.get(1) {
        Some(PtxOperand::Reg(name)) => op_reg(alloc.resolve(name)),
        other => anyhow::bail!("{}: srcA must be a register (imm unattested), got {:?}", insn.opcode, other),
    };
    let b_op = insn.operands.get(2)
        .ok_or_else(|| anyhow::anyhow!("{}: missing srcB", insn.opcode))?;
    let cout_pred = if cout {
        Operand::Pred { num: alloc.pred("%atomcc"), neg: false }
    } else { op_pt() };
    if !cin {
        // add.cc / sub.cc (IADD3 with carry-out; sub negates srcB)
        let b = match b_op {
            PtxOperand::Reg(name) => {
                let num = alloc.resolve(name);
                Operand::Reg { num, neg: sub, abs: false, inv: false, reuse: false }
            }
            other => anyhow::bail!("{}: imm srcB on a carry-out writer is unattested, got {:?}", insn.opcode, other),
        };
        let ins = make_insn(addr, "IADD3",
            vec![d, cout_pred, op_pt(), a, b, op_rz()], None);
        return Ok((vec![ins], 1));
    }
    let cin_pred = Operand::Pred { num: alloc.pred("%atomcc"), neg: false };
    if !sub {
        // addc / addc.cc
        let b = match b_op {
            PtxOperand::Reg(name) => op_reg(alloc.resolve(name)),
            PtxOperand::IntImm(0) => op_rz(),   // vendor normalization (cr1/cr4)
            other => anyhow::bail!("{}: non-zero imm srcB on addc is unattested, got {:?}", insn.opcode, other),
        };
        let ins = make_insn(addr, "IADD3.X",
            vec![d, cout_pred, op_pt(), a, b, op_rz(), cin_pred, op_not_pt()], None);
        return Ok((vec![ins], 1));
    }
    // subc / subc.cc: ~subtrahend in slot A, minuend in slot B
    let b_inv = match b_op {
        PtxOperand::Reg(name) => {
            let num = alloc.resolve(name);
            Operand::Reg { num, neg: false, abs: false, inv: true, reuse: false }
        }
        PtxOperand::IntImm(v) => {
            // arithmetic bitwise-not: ~v == -v - 1 (proven -0x1 for v==0)
            op_imm(v.checked_neg().and_then(|n| n.checked_sub(1))
                .ok_or_else(|| anyhow::anyhow!("{}: imm srcB overflow", insn.opcode))?)
        }
        other => anyhow::bail!("{}: srcB shape unattested, got {:?}", insn.opcode, other),
    };
    let ins = make_insn(addr, "IADD3.X",
        vec![d, cout_pred, op_pt(), b_inv, a, op_rz(), cin_pred, op_not_pt()], None);
    Ok((vec![ins], 1))
}

/// b9 phase-3 #3: mad.lo.cc / madc.hi decomposition (see ptx_map.rs doc).
fn lower_madcc(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, hi: bool,
) -> Result<(Vec<Instruction>, u32)> {
    let d = match insn.operands.get(0) {
        Some(o) => ptx_op_to_sass(o, alloc, false),
        None => anyhow::bail!("{}: missing dst", insn.opcode),
    };
    macro_rules! reg_src {
        ($i:expr) => {
            match insn.operands.get($i) {
                Some(PtxOperand::Reg(name)) => Ok::<u8, anyhow::Error>(alloc.resolve(name)),
                other => anyhow::bail!("{}: operand {} must be a register (imm unattested), got {:?}", insn.opcode, $i, other),
            }
        };
    }
    let a: u8 = reg_src!(1)?;
    let b: u8 = reg_src!(2)?;
    let cc = Operand::Pred { num: alloc.pred("%atomcc"), neg: false };
    let tmp = alloc.gpr("$madcc_carry_tmp");
    if !hi {
        // mad.lo.cc.u32 d, a, b, c (anchor cr3): IMAD.U32 d ; IMAD t ; IADD3 cc
        let c: u8 = reg_src!(3)?;
        let i1 = make_insn(addr, "IMAD.U32",
            vec![d, op_reg(a), op_reg(b), op_reg(c)], None);
        let i2 = make_insn(addr + 16, "IMAD",
            vec![op_reg(tmp), op_reg(a), op_reg(b), op_rz()], None);
        let i3 = make_insn(addr + 32, "IADD3",
            vec![op_rz(), cc, op_pt(), op_reg(tmp), op_reg(c), op_rz()], None);
        return Ok((vec![i1, i2, i3], 3));
    }
    // madc.hi.u32 d, a, b, c: IMAD.HI.U32 t, a, b, RZ ; IADD3.X d, t, c, cin
    let c_op = match insn.operands.get(3) {
        Some(PtxOperand::Reg(name)) => op_reg(alloc.resolve(name)),
        Some(PtxOperand::IntImm(0)) => op_rz(),  // vendor normalization (cr3)
        other => anyhow::bail!("{}: non-zero imm addend on madc.hi is unattested, got {:?}", insn.opcode, other),
    };
    let i1 = make_insn(addr, "IMAD.HI.U32",
        vec![op_reg(tmp), op_reg(a), op_reg(b), op_rz()], None);
    let i2 = make_insn(addr + 16, "IADD3.X",
        vec![d, op_pt(), op_pt(), op_reg(tmp), c_op, op_rz(), cc, op_not_pt()], None);
    Ok((vec![i1, i2], 2))
}

fn lower_add64(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> (Vec<Instruction>, u32) {
    let d = &insn.operands[0];
    let a = &insn.operands[1];
    let b = &insn.operands[2];

    let (rd_lo, rd_hi) = if let PtxOperand::Reg(name) = d { alloc.gpr_pair(name) } else { (4, 5) };
    let (ra_lo, ra_hi) = if let PtxOperand::Reg(name) = a { alloc.gpr_pair(name) } else { (4, 5) };

    let mut out = Vec::new();
    match b {
        PtxOperand::Reg(name) if alloc.is_64bit(name) => {
            let (rb_lo, rb_hi) = alloc.gpr_pair(name);
            out.push(make_insn(addr, "IADD3",
                vec![op_reg(rd_lo), Operand::Pred{num:0,neg:false}, op_pt(), op_reg(ra_lo), op_reg(rb_lo), op_rz()],
                guard.clone()));
            out.push(make_insn(addr+16, "IADD3.X",
                vec![op_reg(rd_hi), op_pt(), op_pt(), op_rz(), op_reg(ra_hi), op_reg(rb_hi),
                     Operand::Pred{num:0,neg:false}, op_not_pt()],
                guard));
        }
        PtxOperand::IntImm(v) => {
            out.push(make_insn(addr, "IADD3",
                vec![op_reg(rd_lo), Operand::Pred{num:0,neg:false}, op_pt(), op_reg(ra_lo), op_imm(*v), op_rz()],
                guard.clone()));
            out.push(make_insn(addr+16, "IADD3.X",
                vec![op_reg(rd_hi), op_pt(), op_pt(), op_rz(), op_reg(ra_hi), op_rz(),
                     Operand::Pred{num:0,neg:false}, op_not_pt()],
                guard));
        }
        _ => {
            let rb = ptx_op_to_sass(b, alloc, false);
            out.push(make_insn(addr, "IADD3",
                vec![op_reg(rd_lo), Operand::Pred{num:0,neg:false}, op_pt(), op_reg(ra_lo), rb, op_rz()],
                guard.clone()));
            out.push(make_insn(addr+16, "IADD3.X",
                vec![op_reg(rd_hi), op_pt(), op_pt(), op_rz(), op_reg(ra_hi), op_rz(),
                     Operand::Pred{num:0,neg:false}, op_not_pt()],
                guard));
        }
    }
    let n = out.len() as u32;
    (out, n)
}

fn lower_mov64(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<(Vec<Instruction>, u32)> {
    let d = &insn.operands[0];
    let src = &insn.operands[1];

    let mut out = Vec::new();
    // b9 phase-2 P4c: mov64 pseudo-groups are per-element copies.
    match (d, src) {
        (PtxOperand::Reg(name), PtxOperand::Reg(sname)) => {
            let (rd_lo, rd_hi) = alloc.gpr_pair(name);
            let (rs_lo, rs_hi) = alloc.gpr_pair(sname);
            out.push(make_insn(addr, "MOV", vec![op_reg(rd_lo), op_reg(rs_lo)], guard.clone()));
            out.push(make_insn(addr+16, "MOV", vec![op_reg(rd_hi), op_reg(rs_hi)], guard));
        }
        (PtxOperand::Reg(name), PtxOperand::IntImm(v)) => {
            let (rd_lo, rd_hi) = alloc.gpr_pair(name);
            let lo = (*v as u64) & 0xFFFFFFFF;
            let hi = ((*v as u64) >> 32) & 0xFFFFFFFF;
            out.push(make_insn(addr, "IMAD.MOV.U32", vec![op_reg(rd_lo), op_rz(), op_rz(), op_imm(lo as i64)], guard.clone()));
            out.push(make_insn(addr+16, "IMAD.MOV.U32", vec![op_reg(rd_hi), op_rz(), op_rz(), op_imm(hi as i64)], guard));
        }
        (PtxOperand::Reg(name), PtxOperand::FloatImm(v)) => {
            let (rd_lo, rd_hi) = alloc.gpr_pair(name);
            let bits = v.to_bits();
            out.push(make_insn(addr, "IMAD.MOV.U32", vec![op_reg(rd_lo), op_rz(), op_rz(), op_imm((bits & 0xffffffff) as i64)], guard.clone()));
            out.push(make_insn(addr+16, "IMAD.MOV.U32", vec![op_reg(rd_hi), op_rz(), op_rz(), op_imm(((bits>>32) & 0xffffffff) as i64)], guard));
        }
        (PtxOperand::Reg(name), PtxOperand::SReg(srn)) if srn == "%clock64" => {
            let (lo, hi) = alloc.gpr_pair(name);
            out.push(make_insn(addr, "S2R", vec![op_reg(lo), Operand::SysReg("SR_CLOCKLO".into())], guard.clone()));
            out.push(make_insn(addr+16, "S2R", vec![op_reg(hi), Operand::SysReg("SR_CLOCKHI".into())], guard));
        }
        // pack: mov.b64 %rd, {%r1, %r2}
        (PtxOperand::Reg(name), PtxOperand::RegGroup(regs)) => {
            let (rd_lo, rd_hi) = alloc.gpr_pair(name);
            let (op, pfx) = prepare_group(regs, GroupRole::Src, addr, alloc, &guard)?;
            out.extend(pfx);
            let base = match op { Operand::Reg { num, .. } => num, _ => unreachable!() };
            out.push(make_insn(addr + 16 * out.len() as u32, "MOV", vec![op_reg(rd_lo), op_reg(base)], guard.clone()));
            out.push(make_insn(addr + 16 * out.len() as u32, "MOV", vec![op_reg(rd_hi), op_reg(base + 1)], guard));
        }
        // unpack: mov.b32 {%r1, %r2}, %rd   (cvt.b32 {...}, %rd handled via Cvt path)
        (PtxOperand::RegGroup(regs), PtxOperand::Reg(sname)) => {
            let (rs_lo, rs_hi) = alloc.gpr_pair(sname);
            let (op, pfx) = prepare_group(regs, GroupRole::Dst, addr, alloc, &guard)?;
            out.extend(pfx);
            let base = match op { Operand::Reg { num, .. } => num, _ => unreachable!() };
            out.push(make_insn(addr + 16 * out.len() as u32, "MOV", vec![op_reg(base), op_reg(rs_lo)], guard.clone()));
            out.push(make_insn(addr + 16 * out.len() as u32, "MOV", vec![op_reg(base + 1), op_reg(rs_hi)], guard));
        }
        _ => {
            anyhow::bail!("mov64 shape unsupported: {:?} <- {:?}", d, src);
        }
    }
    let n = out.len() as u32;
    Ok((out, n))
}

fn lower_ld_param(addr: u32, insn: &PtxInsn, params: &[crate::ptx_parse::PtxParam],
                  alloc: &mut RegAlloc, guard: Option<Guard>) -> Vec<Instruction> {
    let d = &insn.operands[0];
    let param_ref = &insn.operands[1];

    let param_name = match param_ref {
        PtxOperand::ParamRef(name) => name.clone(),
        PtxOperand::Addr { base, .. } => {
            params.iter().find(|p| base.contains(&p.name)).map(|p| p.name.clone()).unwrap_or_default()
        }
        _ => String::new(),
    };

    let param = params.iter().find(|p| p.name == param_name);
    let offset = param.map(|p| p.offset).unwrap_or(0x160);

    let is_64 = insn.opcode.contains("u64") || insn.opcode.contains("b64") || insn.opcode.contains("s64");

    if is_64 {
        let (rd_lo, _rd_hi) = if let PtxOperand::Reg(name) = d { alloc.gpr_pair(name) } else { (4, 5) };
        let cmem = Operand::ConstMem { bank: 0, base_reg: None, ur_reg: None, offset: offset as i64 };
        vec![make_insn(addr, "LDC.64", vec![op_reg(rd_lo), cmem], guard)]
    } else {
        let rd = if let PtxOperand::Reg(name) = d { alloc.resolve(name) } else { 4 };
        let cmem = Operand::ConstMem { bank: 0, base_reg: None, ur_reg: None, offset: offset as i64 };
        vec![make_insn(addr, "LDC", vec![op_reg(rd), cmem], guard)]
    }
}

fn lower_mov_or_sreg(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<Vec<Instruction>> {
    let d = &insn.operands[0];
    let src = &insn.operands[1];

    // Special register → S2R. b9 phase-2: 64-bit sregs split into LO/HI;
    // unmapped sregs are fail-closed (never SR_TID.X by accident).
    if let PtxOperand::SReg(name) = src {
        let srname = sreg_sass_name(name)
            .ok_or_else(|| anyhow::anyhow!("unsupported special register {:?} (no sm_103a mapping)", name))?;
        let rd = ptx_op_to_sass(d, alloc, false);
        return Ok(vec![make_insn(addr, "S2R", vec![rd, Operand::SysReg(srname.to_string())], guard)]);
    }

    // b9 phase-2 P4c: dst brace group = 64-bit unpack (mov.b32 {lo,hi}, %rd)
    if let PtxOperand::RegGroup(regs) = d {
        let (op, pfx) = prepare_group(regs, GroupRole::Dst, addr, alloc, &guard)?;
        let mut out = pfx;
        let base = match op { Operand::Reg { num, .. } => num, _ => unreachable!() };
        match src {
            PtxOperand::Reg(name) if alloc.is_64bit(name) => {
                let (lo, hi) = alloc.gpr_pair(name);
                out.push(make_insn(addr + 16 * out.len() as u32, "MOV",
                    vec![op_reg(base), op_reg(lo)], guard.clone()));
                out.push(make_insn(addr + 16 * out.len() as u32, "MOV",
                    vec![op_reg(base + 1), op_reg(hi)], guard));
                return Ok(out);
            }
            // mov.b32 {lo16,hi16}, imm / mov.b64 {lo,hi}, imm: lane-wise materialize
            PtxOperand::IntImm(v) => {
                let n = regs.len();
                for (i, _) in regs.iter().enumerate() {
                    let lane = base + i as u8;
                    let bits = if n == 2 && insn.opcode == "mov.b32" {
                        if i == 0 { *v & 0xffff } else { (*v >> 16) & 0xffff }
                    } else {
                        if i == 0 { *v & 0xffffffff } else { (*v >> 32) & 0xffffffff }
                    };
                    out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                        vec![op_reg(lane), op_rz(), op_rz(), Operand::Imm32(bits)], guard.clone()));
                }
                return Ok(out);
            }
            PtxOperand::Reg(other32) if !alloc.is_64bit(other32) => {
                // mov.b32 {lo16,hi16}, %r  — sub-word split needs .H0/.H1 lane
                // selects at use sites (no standalone SASS form on sm_103a).
                anyhow::bail!(
                    "mov {} into a b16 pair {} = sub-word unpack; needs H0/H1 lane-select lowering (b9 phase-3)",
                    insn.opcode, regs.join(","));
            }
            other => anyhow::bail!("mov into brace group: unsupported source {:?}", other),
        }
    }

    // b9 phase-3 #4: `mov.{u32,b32} %r, <bare symbol>`. The PTX parser
    // represents a bare identifier as PtxOperand::Label; previously this fell
    // through to ptx_op_to_sass -> Operand::Label -> encoded SILENTLY as
    // `MOV Rn, 0x0` (repro work/b9p6: `mov.b32 %r1, sh` -> "MOV R2, 0x0").
    // Shared-window symbols materialize their static offset (ptxas law:
    // 0x400-based + decl order + align-up; generic-window CgaCtaId<<24 tag
    // is deliberately NOT emitted -- gateway shared addressing is plain
    // 32-bit window offsets, consistent with our LDS/STS lowering).
    if let PtxOperand::Label(sym) = src {
        let rn = match d {
            PtxOperand::Reg(name) if !alloc.is_64bit(name) => alloc.resolve(name),
            other => anyhow::bail!(
                "{}: mov of symbol {:?} to {:?}: only 32-bit register dst is attested",
                insn.opcode, sym, other),
        };
        match alloc.shared_sym(sym) {
            Some(off) => return Ok(vec![make_insn(addr, "IMAD.MOV.U32",
                vec![op_reg(rn), op_rz(), op_rz(), Operand::Imm32(off)], guard)]),
            None => anyhow::bail!(
                "{}: mov of unresolved symbol {:?} (.global symbols need relocation support; b9 out of scope)",
                insn.opcode, sym),
        }
    }

    // Regular move
    let rd = ptx_op_to_sass(d, alloc, false);
    // b9 phase-1: tables have no MOV_R_FI row (asm fail-closed). Float immediates
    // materialize the ptxas way: raw f32 bits as int immediate via IMAD.MOV.U32.
    if let PtxOperand::FloatImm(v) = src {
        let f = *v as f32;
        if f as f64 != *v {
            anyhow::bail!("mov.f64 literal {}: 64-bit immediate materialization unsupported in phase-1", v);
        }
        let rn = match d { PtxOperand::Reg(name) => alloc.resolve(name), _ =>
            return Err(anyhow::anyhow!("mov: dst must be a register")) };
        return Ok(vec![make_insn(addr, "IMAD.MOV.U32",
            vec![op_reg(rn), op_rz(), op_rz(), Operand::Imm32(f.to_bits() as i64)], guard)]);
    }
    let rs = ptx_op_to_sass(src, alloc, false);
    // b9 phase-2: int mov with immediate rides THE canonical imm form
    // (IMAD.MOV.U32 raw-bits) so both asm front-ends accept it; plain
    // "MOV R,imm" exists only in the directive parser's alias path.
    if let Operand::Imm32(v) = &rs {
        if let PtxOperand::Reg(name) = d {
            if !alloc.is_64bit(name) {
                let rn = alloc.resolve(name);
                return Ok(vec![make_insn(addr, "IMAD.MOV.U32",
                    vec![op_reg(rn), op_rz(), op_rz(), Operand::Imm32(*v)], guard)]);
            }
        }
    }
    Ok(vec![make_insn(addr, "MOV", vec![rd, rs], guard)])
}

fn lower_setp(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Instruction {
    let cmp = ptx_map::setp_cmp_suffix(&insn.opcode);
    let is_float = ptx_map::setp_is_float(&insn.opcode);
    let prefix = if is_float { "FSETP" } else { "ISETP" };
    // PTX type qualifier: setp.ne.u32 → ISETP.NE.U32.AND, setp.lt.s32 → ISETP.LT.AND
    let type_qual = if is_float { String::new() }
        else if insn.opcode.contains(".u32") || insn.opcode.contains(".u16") { ".U32".to_string() }
        else { String::new() }; // signed is default (no qualifier)
    let opf = format!("{}.{}{}.AND", prefix, cmp, type_qual);

    let pd = ptx_op_to_sass(&insn.operands[0], alloc, false);
    let a = ptx_op_to_sass(&insn.operands[1], alloc, false);
    let b = ptx_op_to_sass(&insn.operands[2], alloc, false);

    make_insn(addr, &opf, vec![pd, op_pt(), a, b, op_pt()], guard)
}

/// b9 phase-2 P5: cvt lowered ONLY to vendor-attested sm_103a forms
/// (ptxas 13.3 byte-anchors, census probes cvtprobe/cvt2/cvt3):
///   int->f32:  I2FP.F32.{S32,U32}        int->f64: I2F.F64 (no src suffix)
///   f32<->f64: F2F.{D}.{S}               f32->int: F2I.{TRUNC|FLOOR}.NTZ
///   s32->s64:  MOV lo + SHF.R.S32.HI hi,RZ,0x1f,lo   (I2I absent on sm103a)
///   u32->u64:  MOV lo + MOV hi,RZ        64->32: MOV lo
/// Everything else (F2FP.*.PACK_AB + PRMT f16 chains, f64<->int64, sub-word)
/// => Err(unattested) => lands in the aggregated unsupported list.
fn lower_cvt(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Option<Result<Vec<Instruction>>> {
    let parts: Vec<&str> = insn.opcode.split('.').collect();
    let rounding: Option<&str> = parts[1..].iter().copied()
        .find(|p| matches!(*p, "rn"|"rz"|"rzi"|"rmi"|"rmp"|"rni"|"trunc"));
    let type_parts: Vec<&str> = parts[1..].iter()
        .filter(|p| matches!(**p, "u8"|"s8"|"u16"|"s16"|"u32"|"s32"|"u64"|"s64"|"f16"|"f32"|"f64"|"b8"|"b16"|"b32"|"b64"))
        .copied().collect();

    if type_parts.len() < 2 { return None; }
    let dst = type_parts[0];
    let srct = type_parts[1];

    macro_rules! one { ($opf:expr, $d:expr, $a:expr) => {
        Some(Ok(vec![make_insn(addr, &$opf, vec![$d, $a], guard.clone())]))
    } }
    let unattested = || Some(Err(anyhow::anyhow!(
        "cvt {}->{}: no vendor-attested sm_103a lowering (b9 phase-3)", dst, srct)));

    let d = ptx_op_to_sass(&insn.operands[0], alloc, false);
    let a = ptx_op_to_sass(&insn.operands[1], alloc, false);
    let regnum = |o: &Operand| -> Option<u8> {
        match o { Operand::Reg { num, .. } => Some(*num), _ => None }
    };

    match (dst, srct) {
        ("f32", "s32" | "u32") => one!(format!("I2FP.F32.{}", srct.to_uppercase()), d, a),
        ("f64", "s32" | "u32") => one!("I2F.F64".to_string(), d, a),
        ("f32", "f64") => one!("F2F.F32.F64".to_string(), d, a),
        ("f64", "f32") => one!("F2F.F64.F32".to_string(), d, a),
        ("s32" | "u32", "f32") => match rounding {
            Some("rmi") => one!("F2I.FLOOR.NTZ".to_string(), d, a),
            _ => one!("F2I.TRUNC.NTZ".to_string(), d, a),
        },
        // s32 -> s64: MOV lo + SHF.R.S32.HI hi,RZ,0x1f,lo  (vendor anchor)
        ("s64", "s32") => {
            let (dlo, dhi) = match &insn.operands[0] {
                PtxOperand::Reg(name) => alloc.gpr_pair(name),
                _ => return unattested(),
            };
            let alo = regnum(&a);
            match alo {
                Some(alo) => Some(Ok(vec![
                    make_insn(addr, "MOV", vec![op_reg(dlo), op_reg(alo)], guard.clone()),
                    make_insn(addr + 16, "SHF.R.S32.HI",
                        vec![op_reg(dhi), op_rz(), Operand::Imm32(0x1f), op_reg(alo)], guard),
                ])),
                None => unattested(),
            }
        }
        // u32 -> u64: MOV lo + MOV hi,RZ
        ("u64", "u32") => {
            let (dlo, dhi) = match &insn.operands[0] {
                PtxOperand::Reg(name) => alloc.gpr_pair(name),
                _ => return unattested(),
            };
            match regnum(&a) {
                Some(alo) => Some(Ok(vec![
                    make_insn(addr, "MOV", vec![op_reg(dlo), op_reg(alo)], guard.clone()),
                    make_insn(addr + 16, "MOV", vec![op_reg(dhi), op_rz()], guard),
                ])),
                None => unattested(),
            }
        }
        (dst, srct) if matches!(dst, "s32"|"u32") && matches!(srct, "s64"|"u64") => {
            match regnum(&a) { Some(alo) => one!("MOV".to_string(), d, op_reg(alo)), None => unattested() }
        }
        (dst, srct) if dst == srct && matches!(dst, "s32"|"u32"|"b32") => {
            one!("MOV".to_string(), d, a)
        }
        _ => unattested(),
    }
}

fn lower_ld_global(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<Vec<Instruction>> {
    let is_v4 = insn.opcode.contains(".v4.");
    let is_v2 = insn.opcode.contains(".v2.");
    let is_64 = insn.opcode.contains("u64") || insn.opcode.contains("b64") || insn.opcode.contains("f64");

    let suffix = if is_v4 { ".E.128" } else if is_v2 || is_64 { ".E.64" } else { ".E" };

    // Resolve address register FIRST (before allocating dst which may reuse it)
    let base_addr = &insn.operands[1];
    let (addr_reg_name, base_reg_num, offset) = match base_addr {
        PtxOperand::Addr { base, offset } => (base.clone(), alloc.resolve(base), *offset),
        PtxOperand::Reg(name) => (name.clone(), alloc.resolve(name), 0i64),
        _ => (String::new(), 0, 0),
    };

    if !addr_reg_name.is_empty() && alloc.is_64bit(&addr_reg_name) {
        alloc.free_pair(&addr_reg_name);
    }

    // b9 phase-2 P4c: vector ld dst {r0..r3} = aligned chunk, Dst scatter.
    let mut pre: Vec<Instruction> = Vec::new();
    let d = match &insn.operands[0] {
        PtxOperand::RegGroup(regs) => {
            let (op, pfx) = prepare_group(regs, GroupRole::Dst, addr, alloc, &guard)
                .map_err(|e| e.context(format!("ld dst group in {}", insn.opcode)))?;
            pre.extend(pfx);
            op
        }
        other => ptx_op_to_sass(other, alloc, false),
    };

    let desc_op = Operand::Desc {
        ur_idx: 4,
        base_reg: Some(base_reg_num),
        base_reg_suffix: Some(".64".to_string()),
        offset,
    };
    pre.push(make_insn(addr + 16 * pre.len() as u32, &format!("LDG{}", suffix), vec![d, desc_op], guard));
    Ok(pre)
}

fn lower_st_global(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<Vec<Instruction>> {
    let is_v4 = insn.opcode.contains(".v4.");
    let is_v2 = insn.opcode.contains(".v2.");
    let is_64 = insn.opcode.contains("u64") || insn.opcode.contains("b64") || insn.opcode.contains("f64");

    let suffix = if is_v4 { ".E.128" } else if is_v2 || is_64 { ".E.64" } else { ".E" };

    let addr_ptx = &insn.operands[0];
    let (base_reg_num, offset) = match addr_ptx {
        PtxOperand::Addr { base, offset } => (alloc.resolve(base), *offset),
        PtxOperand::Reg(name) => (alloc.resolve(name), 0i64),
        _ => (0, 0),
    };
    let desc_op = Operand::Desc {
        ur_idx: 4,
        base_reg: Some(base_reg_num),
        base_reg_suffix: Some(".64".to_string()),
        offset,
    };
    // b9 phase-2 P2: a store with immediate data has no sm_103a encoding
    // form; materialize via IMAD.MOV.U32 (the imm form BOTH asm front-ends
    // canonicalize; vendor anchors plain "MOV Rn, imm" — directive parser
    // legacy only).
    // b9 phase-2 P4c: vector st data {r0..} gathers into an aligned chunk.
    let mut out: Vec<Instruction> = Vec::new();
    let mut src = match &insn.operands[1] {
        PtxOperand::RegGroup(regs) => {
            let (op, pfx) = prepare_group(regs, GroupRole::Src, addr, alloc, &guard)?;
            out.extend(pfx);
            op
        }
        other => ptx_op_to_sass(other, alloc, false),
    };
    if let Operand::Imm32(v) = src {
        if is_64 || is_v2 || is_v4 {
            anyhow::bail!(
                "st.global immediate data only legalized for 32-bit stores ({}); wide immediate materialization is phase-3",
                insn.opcode);
        }
        let rn = alloc.gpr(&format!("__stimm_{}", addr));
        out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
            vec![op_reg(rn), op_rz(), op_rz(), Operand::Imm32(v)], guard.clone()));
        src = op_reg(rn);
    }
    out.push(make_insn(addr + 16 * out.len() as u32, &format!("STG{}", suffix), vec![desc_op, src], guard));
    Ok(out)
}

fn lower_mma(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Option<Vec<Instruction>> {
    // Gathered/scattered prefix ops (b9 phase-2 P4c) plus the MMA itself.
    let mut seq: Vec<Instruction> = Vec::new();
    let op = &insn.opcode;

    let shape = regex::Regex::new(r"m(\d+)n(\d+)k(\d+)").ok()
        .and_then(|re| re.captures(op))
        .map(|c| format!("{}{}{}", &c[1], &c[2], &c[3]))
        .unwrap_or_else(|| "16832".to_string());

    let types: Vec<&str> = op.split('.').filter(|p|
        matches!(*p, "f16"|"bf16"|"tf32"|"f32"|"f64"|"e4m3"|"e5m2"|"e2m3"|"e2m1"|
                      "s8"|"u8"|"s4"|"u4"|"ue8m0"|"ue4m3")
    ).collect();

    let is_block_scaled = op.contains("block_scale");
    let is_fp4 = types.contains(&"e2m1");
    let is_fp16 = types.contains(&"f16") || types.contains(&"bf16");

    // Detect scale factor type from PTX opcode
    let scale_type = if op.contains("ue4m3") || op.contains("nvf4") { "UE4M3.4X" }
        else if op.contains("ue8m0") || op.contains("mxf8f6f4") { "E8" }
        else { "E8" };

    let acc_type = if types.contains(&"f32") { "F32" } else { "F16" };

    let elem_types: Vec<&str> = types.iter()
        .filter(|t| matches!(**t, "e4m3"|"e5m2"|"e2m3"|"e2m1"|"s8"|"u8"))
        .copied()
        .collect();
    let a_type = elem_types.first().map(|t| t.to_uppercase()).unwrap_or("E4M3".to_string());
    let b_type = elem_types.get(1).map(|t| t.to_uppercase()).unwrap_or(a_type.clone());

    // Build opcode: QMMA.SF.16832.F32.E4M3.E4M3.E8 (table key format)
    let opf = if is_block_scaled && is_fp4 {
        format!("OMMA.SF.{}.{}.{}.{}.{}", shape, acc_type, a_type, b_type, scale_type)
    } else if is_block_scaled {
        format!("QMMA.SF.{}.{}.{}.{}.{}", shape, acc_type, a_type, b_type, scale_type)
    } else if is_fp16 {
        // b9 phase-2 P4: f16/bf16 MMA on sm_103a has NO element-type suffix
        // (nvdisasm corpus anchor: HMMA.16816.F32). The E4M3 default above is
        // fp8-domain only; never leak it into HMMA.
        format!("HMMA.{}.{}", shape, acc_type)
    } else {
        format!("QMMA.{}.{}.{}.{}", shape, acc_type, a_type, b_type)
    };

    if insn.operands.len() < 4 { return None; }

    // b9 phase-2 P4c: every fragment operand must be a RegGroup; scalar mma
    // forms are unsupported here (they surface in the unsupported list).
    let grp = |i: usize, role: GroupRole, alloc: &mut RegAlloc, seq_len: u32|
        -> Option<(Operand, Vec<Instruction>)> {
        match &insn.operands[i] {
            PtxOperand::RegGroup(regs) =>
                prepare_group(regs, role, addr + 16 * seq_len, alloc, &guard).ok(),
            _ => None,
        }
    };
    let (a, pafx) = grp(1, GroupRole::Src, alloc, seq.len() as u32)?;  seq.extend(pafx);
    let (b, pbfx) = grp(2, GroupRole::Src, alloc, seq.len() as u32)?;  seq.extend(pbfx);
    let (c, pcfx) = grp(3, GroupRole::Src, alloc, seq.len() as u32)?;  seq.extend(pcfx);
    let (d, pdfx) = grp(0, GroupRole::Dst, alloc, seq.len() as u32)?;  seq.extend(pdfx);

    let mut operands = vec![d, a, b, c];

    if is_block_scaled && insn.operands.len() >= 6 {
        // Block-scaled MMA: D, A, B, C, SFA, SFB, UR_selector
        operands.push(ptx_op_to_sass(&insn.operands[4], alloc, false));
        operands.push(ptx_op_to_sass(&insn.operands[5], alloc, false));
        // 7th operand: UR selector (uniform register, always URZ for now)
        operands.push(Operand::UReg { num: 63, neg: false, abs: false, inv: false, reuse: false, is_zero: true });
    }

    seq.push(make_insn(addr + 16 * seq.len() as u32, &opf, operands, guard));
    Some(seq)
}
