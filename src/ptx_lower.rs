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
}

impl RegAlloc {
    fn new(reg_decls: &HashMap<String, String>) -> Self {
        Self {
            gpr_map: HashMap::new(),
            pred_map: HashMap::new(),
            next_gpr: 2,
            next_pred: 0,
            reg_decls: reg_decls.clone(),
            free_gprs: Vec::new(),
            free_pairs: Vec::new(),
            free_quads: Vec::new(),
        }
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
        let p = self.next_pred;
        self.next_pred += 1;
        self.pred_map.insert(name.to_string(), p);
        p
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

fn sreg_sass_name(ptx_name: &str) -> &'static str {
    match ptx_name {
        "%tid.x"    => "SR_TID.X",    "%tid.y"    => "SR_TID.Y",    "%tid.z"    => "SR_TID.Z",
        "%ctaid.x"  => "SR_CTAID.X",  "%ctaid.y"  => "SR_CTAID.Y",  "%ctaid.z"  => "SR_CTAID.Z",
        "%ntid.x"   => "SR_NTID.X",   "%ntid.y"   => "SR_NTID.Y",   "%ntid.z"   => "SR_NTID.Z",
        "%nctaid.x" => "SR_NCTAID.X", "%nctaid.y" => "SR_NCTAID.Y", "%nctaid.z" => "SR_NCTAID.Z",
        "%laneid"   => "SR_LANEID",    "%warpid"   => "SR_WARPID",   "%smid"     => "SR_SMID",
        "%clock"    => "SR_CLOCKLO",   "%clock64"  => "SR_CLOCKLO",
        _ => "SR_TID.X",
    }
}

// ── Operand conversion ───────────────────────────────────────────────────────

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
        PtxOperand::SReg(name) => {
            Operand::SysReg(sreg_sass_name(name).to_string())
        }
        PtxOperand::IntImm(v) => Operand::Imm32(*v),
        PtxOperand::FloatImm(v) => Operand::FloatImm(v.to_bits()),
        PtxOperand::Addr { base, offset } => {
            let base_reg = alloc.resolve(base);
            Operand::Addr { base_reg: Some(base_reg), base_reg_suffix: None, ur_reg: None, offset: *offset }
        }
        PtxOperand::Label(s) => Operand::Label(s.clone()),
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

fn op_pt() -> Operand { Operand::Pred { num: 7, neg: false } }
fn op_not_pt() -> Operand { Operand::Pred { num: 7, neg: true } }
fn op_rz() -> Operand { Operand::Reg { num: 255, neg: false, abs: false, inv: false, reuse: false } }
fn op_reg(num: u8) -> Operand { Operand::Reg { num, neg: false, abs: false, inv: false, reuse: false } }
fn op_neg_reg(num: u8) -> Operand { Operand::Reg { num, neg: true, abs: false, inv: false, reuse: false } }
fn op_imm(v: i64) -> Operand { Operand::Imm32(v) }

// ── Build SASS Instruction ───────────────────────────────────────────────────

fn operand_to_sass(op: &Operand) -> String {
    match op {
        Operand::Reg { num, neg, abs, .. } => {
            let name = if *num == 255 { "RZ".to_string() } else { format!("R{}", num) };
            let s = if *abs { format!("|{}|", name) } else { name };
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
        ctrl: ControlCode::default(), hand_sched: false, raw_text,
    }
}

// ── Main lowering entry point ────────────────────────────────────────────────

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
    let mut alloc = RegAlloc::new(&kernel.reg_decls);
    let mut insns: Vec<Instruction> = Vec::new();
    let mut addr: u32 = 0;

    // Label → address mapping (two-pass for forward branches)
    let mut label_addrs: HashMap<String, u32> = HashMap::new();

    // First pass: estimate addresses for labels
    let mut est_addr: u32 = 0;
    for stmt in &kernel.body {
        match stmt {
            PtxStmt::Label(name) => { label_addrs.insert(name.clone(), est_addr); }
            PtxStmt::Insn(insn) => {
                let expansion_count = estimate_expansion_size(&insn.opcode);
                est_addr += expansion_count * 16;
            }
        }
    }

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
    for stmt in &kernel.body {
        match stmt {
            PtxStmt::Label(name) => {
                // Emit label for cubit's label resolution
                insns.push(Instruction {
                    addr, opcode: String::new(), opcode_full: String::new(),
                    key: String::new(), guard: None, operands: vec![],
                    modifiers: vec![], ctrl: crate::ir::ControlCode::default(),
                    hand_sched: false,
                    raw_text: format!("{}:", name),
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
                            let (insns_mv, n) = lower_mov64(addr, insn, &mut alloc, guard);
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
                            let i = lower_mov_or_sreg(addr, insn, &mut alloc, guard);
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
                            if let Some(i) = lower_cvt(addr, insn, &mut alloc, guard) {
                                insns.push(i);
                                addr += 16;
                            }
                        }

                        SassTemplate::LdGlobal => {
                            let i = lower_ld_global(addr, insn, &mut alloc, guard);
                            insns.push(i);
                            addr += 16;
                        }

                        SassTemplate::StGlobal => {
                            let i = lower_st_global(addr, insn, &mut alloc, guard);
                            insns.push(i);
                            addr += 16;
                        }

                        SassTemplate::Mma => {
                            if let Some(i) = lower_mma(addr, insn, &mut alloc, guard) {
                                insns.push(i);
                                addr += 16;
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

                        SassTemplate::Nop => {
                            // cvta.to.global — NOP on SM120
                        }
                    }
                } else {
                    eprintln!("WARNING: unsupported PTX: {}", insn.opcode);
                }
            }
        }
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
                hand_sched: false,
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

fn estimate_expansion_size(opcode: &str) -> u32 {
    if opcode.contains(".u64") || opcode.contains(".s64") || opcode.contains(".b64") {
        if opcode.starts_with("add.") || opcode.starts_with("sub.") { return 2; }
        if opcode.starts_with("mov.") { return 2; }
    }
    1
}

// ── Specialized lowering functions ───────────────────────────────────────────

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

fn lower_mov64(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> (Vec<Instruction>, u32) {
    let d = &insn.operands[0];
    let src = &insn.operands[1];
    let (rd_lo, rd_hi) = if let PtxOperand::Reg(name) = d { alloc.gpr_pair(name) } else { (4, 5) };

    let mut out = Vec::new();
    match src {
        PtxOperand::Reg(name) => {
            let (rs_lo, rs_hi) = alloc.gpr_pair(name);
            out.push(make_insn(addr, "MOV", vec![op_reg(rd_lo), op_reg(rs_lo)], guard.clone()));
            out.push(make_insn(addr+16, "MOV", vec![op_reg(rd_hi), op_reg(rs_hi)], guard));
        }
        PtxOperand::IntImm(v) => {
            let lo = (*v as u64) & 0xFFFFFFFF;
            let hi = ((*v as u64) >> 32) & 0xFFFFFFFF;
            out.push(make_insn(addr, "MOV", vec![op_reg(rd_lo), op_imm(lo as i64)], guard.clone()));
            out.push(make_insn(addr+16, "MOV", vec![op_reg(rd_hi), op_imm(hi as i64)], guard));
        }
        _ => {
            let s = ptx_op_to_sass(src, alloc, false);
            out.push(make_insn(addr, "MOV", vec![op_reg(rd_lo), s], guard));
        }
    }
    let n = out.len() as u32;
    (out, n)
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

fn lower_mov_or_sreg(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Vec<Instruction> {
    let d = &insn.operands[0];
    let src = &insn.operands[1];

    // Special register → S2R
    if let PtxOperand::SReg(name) = src {
        let rd = ptx_op_to_sass(d, alloc, false);
        let sr = Operand::SysReg(sreg_sass_name(name).to_string());
        return vec![make_insn(addr, "S2R", vec![rd, sr], guard)];
    }

    // Regular move
    let rd = ptx_op_to_sass(d, alloc, false);
    let rs = ptx_op_to_sass(src, alloc, false);
    vec![make_insn(addr, "MOV", vec![rd, rs], guard)]
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

fn lower_cvt(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Option<Instruction> {
    let parts: Vec<&str> = insn.opcode.split('.').collect();
    let type_parts: Vec<&str> = parts[1..].iter()
        .filter(|p| matches!(**p, "u8"|"s8"|"u16"|"s16"|"u32"|"s32"|"u64"|"s64"|"f16"|"f32"|"f64"|"b8"|"b16"|"b32"|"b64"))
        .copied().collect();

    if type_parts.len() < 2 { return None; }
    let dst_type = type_parts[0].to_uppercase();
    let src_type = type_parts[1].to_uppercase();
    let dst_float = dst_type.starts_with('F');
    let src_float = src_type.starts_with('F');

    let prefix = match (dst_float, src_float) {
        (true, true)   => "F2F",
        (true, false)  => "I2F",
        (false, true)  => "F2I",
        (false, false) => "I2I",
    };
    let opf = format!("{}.{}.{}", prefix, dst_type, src_type);

    let d = ptx_op_to_sass(&insn.operands[0], alloc, false);
    let a = ptx_op_to_sass(&insn.operands[1], alloc, false);

    Some(make_insn(addr, &opf, vec![d, a], guard))
}

fn lower_ld_global(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Instruction {
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

    let d = ptx_op_to_sass(&insn.operands[0], alloc, false);

    let desc_op = Operand::Desc {
        ur_idx: 4,
        base_reg: Some(base_reg_num),
        base_reg_suffix: Some(".64".to_string()),
        offset,
    };
    make_insn(addr, &format!("LDG{}", suffix), vec![d, desc_op], guard)
}

fn lower_st_global(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Instruction {
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
    let src = ptx_op_to_sass(&insn.operands[1], alloc, false);

    make_insn(addr, &format!("STG{}", suffix), vec![desc_op, src], guard)
}

fn lower_mma(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Option<Instruction> {
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
        format!("HMMA.{}.{}.{}.{}", shape, acc_type, a_type, b_type)
    } else {
        format!("QMMA.{}.{}.{}.{}", shape, acc_type, a_type, b_type)
    };

    if insn.operands.len() < 4 { return None; }

    // Resolve A, B, C first
    let a = ptx_op_to_sass(&insn.operands[1], alloc, false);
    let b = ptx_op_to_sass(&insn.operands[2], alloc, false);
    let c = ptx_op_to_sass(&insn.operands[3], alloc, false);

    // ptxas trick: QMMA Rd reuses Rc (accumulator consumed, D overwrites C slot).
    // Free A, B, C registers so D can reuse them.
    // C is the best candidate (QMMA reads C, writes D to same location).
    if let PtxOperand::RegGroup(ref regs) = insn.operands[3] {
        alloc.free_quad(&regs[0]);
    } else if let PtxOperand::Reg(ref name) = insn.operands[3] {
        alloc.free_quad(name);
    }
    // Also free A and B (consumed by MMA)
    if let PtxOperand::RegGroup(ref regs) = insn.operands[1] {
        alloc.free_quad(&regs[0]);
    }
    if let PtxOperand::RegGroup(ref regs) = insn.operands[2] {
        alloc.free_pair(&regs[0]);
    }

    let d = ptx_op_to_sass(&insn.operands[0], alloc, false);

    let mut operands = vec![d, a, b, c];

    if is_block_scaled && insn.operands.len() >= 6 {
        // Block-scaled MMA: D, A, B, C, SFA, SFB, UR_selector
        operands.push(ptx_op_to_sass(&insn.operands[4], alloc, false));
        operands.push(ptx_op_to_sass(&insn.operands[5], alloc, false));
        // 7th operand: UR selector (uniform register, always URZ for now)
        operands.push(Operand::UReg { num: 63, neg: false, abs: false, inv: false, reuse: false, is_zero: true });
    }

    Some(make_insn(addr, &opf, operands, guard))
}
