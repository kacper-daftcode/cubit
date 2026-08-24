//! PTX → SASS lowering engine.
//!
//! Takes parsed PTX kernels and produces cubit `Instruction` vectors using the
//! table-driven mapping from `ptx_map`.  Simple 1:1 rules are applied
//! generically; complex patterns (MMA, 64-bit ops, param loads) have dedicated
//! expansion functions.

use std::collections::HashMap;
use anyhow::Result;

use crate::ir::{ControlCode, Guard, Instruction, Operand};
use crate::ptx_map::{self, MbarKind, Mul64Kind, OpSlot, SassTemplate, find_rule};
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
    /// b9 phase-3 #9: set when a fresh GPR allocation would cross R254
    /// into RZ (255). Previously the allocator handed out 255 and
    /// operand_to_sass printed it as "RZ" -- silent data corruption,
    /// surfaced by bench_m9's unrolled loop (mad.wide.u32 a-op read RZ).
    gpr_hit_cap: Option<String>,
    /// b9 phase-3 #4: kernel shared-window symbols (static layout, see
    /// ptx_parse) for `mov reg, sym` and `[sym+off]` address resolution.
    shared_syms: std::collections::HashMap<String, i64>,
    /// b9 phase-3 #4: set on an unresolved bare-symbol operand; lower_kernel
    /// bails fail-closed. Previously such symbols silently encoded as a
    /// fresh UNINITIALIZED register ([sym] addressing) or 0x0 (mov sym).
    unknown_sym: Option<String>,
    /// b9 phase-3 #15 (b9p17): BSSY/BSYNC reconvergence-barrier allocator
    /// for lifter-emitted control regions (atom f16/f16x2 CAS/spin lanes).
    /// PTX-level branches never emit BSSY, so ids are lifter-exclusive.
    bar_next: u8,
    /// BUG-118: textual last-use index per PTX GPR name (all operand
    /// kinds), swept in lower_kernel's first pass. The old
    /// free-the-address-pair-at-load optimization assumed that use was the
    /// name's last one WITHOUT checking; any later use then re-bound a
    /// fresh, never-written pair (deterministic ILLEGAL_ADDRESS 700 on
    /// silicon, nvcc side fine). Fail-closed gate at the end of
    /// lower_kernel keeps the class at BUILD-FAIL forever.
    gpr_last_use: HashMap<String, usize>,
    /// Statement index currently being lowered (companion of gpr_last_use).
    cur_si: usize,
    /// BUG-118 gate waiver registry: (reg, selector) of emitter-DECLARED
    /// dead-byte self-reads. Used ONLY by the sub-word unpack lanes whose
    /// vendor-attested in-place PRMT shape (`PRMT Rd, Rsrc, 0x7610, Rd`)
    /// reads Rd's upper 16 bits which are don't-care by lane contract
    /// (b16 vregs live in the low half; vendor -O0 emits the identical
    /// first-touch self-read, anchors readshared2 0x220 / p15 0x280).
    dead_read_ok: std::collections::BTreeSet<(u8, i64)>,
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
            bar_next: 0,
            pred_hit_cap: None,
            gpr_hit_cap: None,
            unknown_sreg: None,
            shared_syms,
            unknown_sym: None,
            gpr_last_use: HashMap::new(),
            cur_si: 0,
            dead_read_ok: std::collections::BTreeSet::new(),
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
        if r > 254 {
            // R255 aliases RZ in print and in hardware: never hand it out.
            if self.gpr_hit_cap.is_none() { self.gpr_hit_cap = Some(name.to_string()); }
            return 254; // dummy in-range slot; lower_kernel bails below
        }
        self.gpr_map.insert(name.to_string(), r);
        r
    }

    fn gpr_pair(&mut self, name: &str) -> (u8, u8) {
        if let Some(&r) = self.gpr_map.get(name) { return (r, r + 1); }
        let lo = if let Some(pos) = self.free_pairs.pop() { pos } else {
            if self.next_gpr % 2 != 0 { self.next_gpr += 1; }
            let lo = self.next_gpr; self.next_gpr += 2; lo
        };
        if lo + 1 > 254 {
            if self.gpr_hit_cap.is_none() { self.gpr_hit_cap = Some(name.to_string()); }
            return (252, 253);
        }
        self.gpr_map.insert(name.to_string(), lo);
        (lo, lo + 1)
    }

    fn gpr_quad(&mut self, name: &str) -> u8 {
        if let Some(&r) = self.gpr_map.get(name) { return r; }
        let base = if let Some(pos) = self.free_quads.pop() { pos } else {
            while self.next_gpr % 4 != 0 { self.next_gpr += 1; }
            let b = self.next_gpr; self.next_gpr += 4; b
        };
        if base + 3 > 254 {
            if self.gpr_hit_cap.is_none() { self.gpr_hit_cap = Some(name.to_string()); }
            return 248;
        }
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

    /// b9 phase-3 #6: is this operand spelling an actual PTX register
    /// (%-prefixed or a declared name), as opposed to a bare symbol/identifier?
    fn is_ptx_reg_name(&self, name: &str) -> bool {
        name.starts_with('%') || self.reg_decls.contains_key(name)
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

    /// BUG-118: free a 64-bit name's pair ONLY at its textual last use, and
    /// only when no OTHER still-live name is bound to the same physical
    /// pair (cvta AliasPair shares bindings). A pair handed back early is
    /// re-issued by gpr_pair while the dropped name's later use silently
    /// binds a fresh, never-written register (b10 PHASE-2c: pd64/pi64/
    /// pr_rw_ldcgs deterministic 700 on silicon).
    /// Conservative corner: a name bound but NEVER used as an operand has
    /// no last-use entry; if it shares the pair we keep the pair (map_or
    /// true = assume live). Freed pairs never affect already-emitted text,
    /// so loop-carried addresses are unaffected (their binding loss would
    /// only matter to a later lowering-time resolve, which the last-use
    /// condition rules out by construction).
    fn free_pair_if_dead(&mut self, name: &str) {
        match self.gpr_last_use.get(name) {
            Some(&lu) if lu <= self.cur_si => {}
            _ => return,
        }
        let lo = match self.gpr_map.get(name) { Some(&r) => r, None => return };
        let shared_live = self.gpr_map.iter().any(|(n, &r)| {
            n != name && r == lo
                && self.gpr_last_use.get(n).map_or(true, |&lu2| lu2 > self.cur_si)
        });
        if shared_live { return; }
        self.free_pair(name);
    }

    /// b9 phase-3 #15: next free reconvergence barrier id (B0.. class).
    /// PTX-level branches never emit BSSY, so the pool is lifter-exclusive;
    /// lanes emit at most 2 ids per atomic expansion.
    fn bar_alloc(&mut self) -> u8 {
        let b = self.bar_next;
        self.bar_next += 1;
        b
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
        // BUG-118 gate landing (b_cluster): ptxas sm_103a cl.ptx probe
        // 2026-08-24 -> S2R Rn, SR_CgaCtaId.
        "%cluster_ctarank" => "SR_CgaCtaId",
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
    // b9 phase-3 #12 (b9p14): a len-2 group of 64-bit members is a PTX
    // .v2.b64 form = a 128-bit hardware QUAD; member i occupies lanes
    // [base+2i, base+2i+1] (lo,hi preserves even-pair alignment: base is
    // 4-aligned). Vendor law: ld/st .v2.b64 -> LDS/LDG/STS/STG .128 ops
    // (probes work/b9p14/probes q3/q4 -O0/-O3; corpus p13/p29 -O0).
    // Immediate members of a 64-bit group, mixed-width groups, and
    // len-4 groups of 64-bit members (v4.b64 = 256-bit) are NOT
    // vendor-attested -> fail-closed.
    let wide64 = regs.iter().any(|r| alloc.is_64bit(r));
    if wide64 {
        if n != 2 {
            anyhow::bail!("64-bit members in a {}-member group ({:?}): only .v2.b64 (128-bit quad) is vendor-attested", n, regs);
        }
        if let Some(m) = regs.iter().find(|r| !alloc.is_64bit(r)) {
            anyhow::bail!("mixed-width vector group member {:?} (64-bit lanes): unattested", m);
        }
    }
    let base = if n == 4 || wide64 {
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
        // b9 phase-3 #12 (b9p14): 0fXXXXXXXX float-literal member (corpus
        // p29 st.shared.v4.b32 {0f3F800000,..}): materialize the raw bits
        // via IMAD.MOV.U32 like the integer lane (vendor: MOV Rn, 0x3f800000
        // ladder before STS.128, -O0/-O3 alike). 0d................ doubles
        // would sit in 64-bit groups -> mixed-width bail below (fail-closed).
        if let Some(bits) = name.strip_prefix("0f").and_then(|h| u32::from_str_radix(h, 16).ok()) {
            if role == GroupRole::Dst {
                anyhow::bail!("float-literal {:?} as vector-group destination", name);
            }
            pre.push(make_insn(addr + 16 * pre.len() as u32, "IMAD.MOV.U32",
                vec![op_reg(lane), op_rz(), op_rz(), Operand::Imm32(bits as i64)], guard.clone()));
            continue;
        }
        if alloc.is_64bit(name) {
            // v2.b64 member i -> quad lanes [base+2i, base+2i+1].
            let lane_lo = base + 2 * i as u8;
            if role == GroupRole::Src {
                let (cur_lo, cur_hi) = alloc.gpr_pair(name);
                if cur_lo != lane_lo {
                    pre.push(make_insn(addr + 16 * pre.len() as u32,
                        "MOV", vec![op_reg(lane_lo), op_reg(cur_lo)], guard.clone()));
                }
                if cur_hi != lane_lo + 1 {
                    pre.push(make_insn(addr + 16 * pre.len() as u32,
                        "MOV", vec![op_reg(lane_lo + 1), op_reg(cur_hi)], guard.clone()));
                }
            }
            alloc.gpr_map.insert(name.to_string(), lane_lo);
            continue;
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
        Operand::Addr { base_reg, base_reg_suffix, ur_reg, offset } => {
            // b9 phase-3 #6: render the UR address component (SYNCS-class
            // mbarrier ops: [Ra+URZ] / UR-only [UR62]); previously ur_reg was
            // silently dropped from the gateway text. Order follows the
            // existing [R+UR+off] convention (printer.rs STS/LDS).
            // b9 phase-3 #8: R255 prints RZ (vendor spelling; `@!PT LDS RZ, [RZ]`
            // anchor). Parse direction already accepts both.
            let mut inner = base_reg.map_or("RZ".to_string(), |r| if r == 255 { "RZ".to_string() } else { format!("R{}", r) });
            if let Some(sfx) = base_reg_suffix { inner = format!("{}.{}", inner, sfx); }
            match ur_reg {
                Some(255) if base_reg.is_some() => inner = format!("{}+URZ", inner),
                Some(u) if base_reg.is_some() => inner = format!("{}+UR{}", inner, u),
                Some(255) => inner = "URZ".to_string(),
                Some(u) => inner = format!("UR{}", u),
                None => {}
            }
            if *offset != 0 { format!("[{}+0x{:x}]", inner, offset) }
            else { format!("[{}]", inner) }
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
    /// BUG-118 gate waivers declared by emitters: (reg, PRMT-selector)
    /// dead-byte self-reads that are legal on first touch (see RegAlloc).
    pub dead_read_ok: std::collections::BTreeSet<(u8, i64)>,
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
    // b9 phase-3 #7: vendor inserts MEMBAR.ALL.CTA into the release path of
    // every barrier.cluster.arrive when the kernel contains ANY mbarrier op
    // (anchors cl4/cl7/cl8: init/expect_tx/try_wait all trigger it, plain
    // STS does not; order-independent kernel-global rule).
    let has_mbarrier = kernel.body.iter().any(|st| match st {
        PtxStmt::Insn(i) => i.opcode.starts_with("mbarrier."),
        _ => false,
    });
    let mut insns: Vec<Instruction> = Vec::new();
    let mut addr: u32 = 0;

    // Label → address mapping (two-pass for forward branches)
    let mut label_addrs: HashMap<String, u32> = HashMap::new();
    // sanitized -> original, fail-closed on collisions (b9 phase-1 doctrine)
    let mut label_names: HashMap<String, String> = HashMap::new();

    // First pass: estimate addresses for labels
    let mut est_addr: u32 = 0;
    // b9 phase-3 #8: LDGSTS trio preamble is a single 3-slot kernel preamble.
    let mut ldgsts_trio_est = false;
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
                let mut expansion_count = b9p8_expansion_count(insn, &mut ldgsts_trio_est)
                    .unwrap_or_else(|| estimate_expansion_size(&insn.opcode));
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

    // BUG-118: GPR last-use sweep (companion to the pred sweep above).
    // Covers every register-name occurrence an instruction can consume:
    // plain regs, address bases (register ones only), and {group} members.
    // Destination-only occurrences matter too: they extend the binding's
    // life (a later use must see THIS write's slot).
    {
        let mut glu: HashMap<String, usize> = HashMap::new();
        for (si, stmt) in kernel.body.iter().enumerate() {
            if let PtxStmt::Insn(insn) = stmt {
                for op in &insn.operands {
                    match op {
                        PtxOperand::Reg(name) => { glu.insert(name.clone(), si); }
                        PtxOperand::Addr { base, .. } => {
                            if base.starts_with('%') { glu.insert(base.clone(), si); }
                        }
                        PtxOperand::RegGroup(regs) => {
                            for r in regs {
                                if r.starts_with('%') { glu.insert(r.clone(), si); }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        alloc.gpr_last_use = glu;
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
        // BUG-118 sweep-up: the deferral above counted ONLY ld/st.global
        // address uses; atom./red. address uses were missed, so a param
        // register feeding both an atom address and a store address was
        // classed "store-only" and its LDC was deferred PAST the atom
        // (atom read a fresh never-written pair -- gate catch 2026-08-24,
        // b9p6_acq_rel_glue). Conservative law: ANY use of the register
        // outside an st.global address slot blocks the deferral.
        for stmt in &kernel.body {
            if let PtxStmt::Insn(insn) = stmt {
                if insn.opcode.starts_with("ld.param.") { continue; } // own dst is a def site
                for (oi, op) in insn.operands.iter().enumerate() {
                    let is_st_addr =
                        insn.opcode.starts_with("st.global.") && oi == 0;
                    let mut mark_live = |name: &String| {
                        if !is_st_addr { load_addr_regs.insert(name.clone()); }
                    };
                    match op {
                        PtxOperand::Reg(name) => mark_live(name),
                        PtxOperand::Addr { base, .. }
                            if base.starts_with('%') => mark_live(base),
                        PtxOperand::RegGroup(regs) => {
                            for r in regs { mark_live(r); }
                        }
                        _ => {}
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

    // b9 phase-3 #8: the three `@!PT LDS RZ, [RZ]` go out ONCE per kernel,
    // immediately before the first LDGSTS (all anchors incl. -O3).
    let mut ldgsts_trio_done = false;

    // Second pass: emit instructions
    for (si, stmt) in kernel.body.iter().enumerate() {
        alloc.cur_si = si; // BUG-118 last-use companion (frees below)
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
                    // b9 phase-3 #5: Fence rules are exact-name. starts_with
                    // would let "fence.proxy.async" swallow ".global" (vendor
                    // mismap: global = FENCE.VIEW.ASYNC.G, not the S chain).
                    let fence_exact_ok = !matches!(rule.template, SassTemplate::Fence { .. })
                        || insn.opcode == rule.pattern;
                    match &rule.template {
                        SassTemplate::Single { opcode, slots } => {
                            let operands = resolve_slots(slots, &insn.operands, &mut alloc);
                            insns.push(make_insn(addr, opcode, operands, guard));
                            addr += 16;
                        }

                        // ── b9p13 (phase-3 #11) sat/mufu lane ────────────
                        // Same exact-opcode re-check discipline as b9p12.
                        SassTemplate::AddSatS32 | SassTemplate::SinCos { .. }
                        | SassTemplate::Ex2Approx | SassTemplate::Lg2Approx
                        | SassTemplate::DivApproxF32 => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            let r = match &rule.template {
                                SassTemplate::AddSatS32 => lower_addsat_s32(addr, insn, &mut alloc, &guard),
                                SassTemplate::SinCos { cos } => lower_sincos_f32(addr, insn, &mut alloc, &guard, *cos),
                                SassTemplate::Ex2Approx => lower_ex2approx_f32(addr, insn, &mut alloc, &guard),
                                SassTemplate::Lg2Approx => lower_lg2approx_f32(addr, insn, &mut alloc, &guard),
                                _ => lower_divapprox_f32(addr, insn, &mut alloc, &guard),
                            }?;
                            match r {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }

                        // ── b9p12 (phase-3 #10) intmisc/bar lane ─────────
                        // Every arm re-checks the exact opcode (find_rule is a
                        // starts_with scan): unattested suffixes -> unsupported.
                        SassTemplate::Popc32 | SassTemplate::Brev32 | SassTemplate::Clz32
                        | SassTemplate::BfeU32 => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            let r = match &rule.template {
                                SassTemplate::Popc32 => lower_popc32(addr, insn, &mut alloc, &guard),
                                SassTemplate::Brev32 => lower_brev32(addr, insn, &mut alloc, &guard),
                                SassTemplate::Clz32 => lower_clz32(addr, insn, &mut alloc, &guard),
                                _ => lower_bfe32(addr, insn, &mut alloc, &guard),
                            }?;
                            match r {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::BarRed { or } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            match lower_barred(addr, insn, &mut alloc, &guard, *or)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::BarSync { aligned } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            match lower_barsync(addr, insn, &mut alloc, &guard, *aligned)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::BarArrive { aligned } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            match lower_bararrive(addr, insn, &mut alloc, &guard, *aligned)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::DiscardL2 => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            match lower_discard_l2(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
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
                            match lower_setp(addr, insn, &mut alloc, guard) {
                                Ok(iv) => { addr += 16 * iv.len() as u32; insns.extend(iv); }
                                Err(e) => { unsupported.insert(format!("{} ({})", insn.opcode, e)); }
                            }
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
                            // b10 F-3: parser splits the dst token `reg|pred`
                            // into two operands ([0]=data dst, [1]=pred out).
                            // The pred half is consumed nowhere in the corpus
                            // before overwrite (2026-08-24 census of 192 sites)
                            // -> emitted pred is PT, matching the pre-fix
                            // template; the data dst now lands on the SAME
                            // physical register the readers use.
                            let mode = ptx_map::shfl_mode(&insn.opcode);
                            let d = ptx_op_to_sass(&insn.operands[0], &mut alloc, false);
                            let src_i = if insn.operands.len() > 1
                                           && matches!(insn.operands[1], PtxOperand::Pred(_))
                                        { 2 } else { 1 };
                            let src = ptx_op_to_sass(&insn.operands[src_i], &mut alloc, false);
                            let off = ptx_op_to_sass(&insn.operands[src_i + 1], &mut alloc, false);
                            let clamp = if insn.operands.len() > src_i + 2 {
                                ptx_op_to_sass(&insn.operands[src_i + 2], &mut alloc, false)
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
                            // b9 phase-3 #12 (b9p14): mov.pred immediate
                            // materializes the constant through an all-PT
                            // PLOP3.LUT (vendor anchors: probes
                            // work/b9p14/probes movpred1/probe2 q1 -O0/-O3,
                            // corpus p09/V1..V4): imm==0 -> LUTs (0x08,0x80)
                            // (same pair as not.pred, bit7=0 -> false);
                            // nonzero {-1,+1 attested} -> (0x80,0x08) (the
                            // and/mov pair with a=PT -> constant true).
                            // ptxas -O3 folds the constant into consumers
                            // (documented O3-fold divergence; O0 anchor is
                            // the form law). Other immediates: fail-closed.
                            if insn.opcode.starts_with("mov.pred") {
                                if let Some(PtxOperand::IntImm(v)) = insn.operands.get(1) {
                                    let (la, lb) = match *v {
                                        0 => (0x08i64, 0x80i64),
                                        -1 | 1 => (0x80, 0x08),
                                        other => anyhow::bail!(
                                            "mov.pred immediate {} not vendor-attested (only 0/-1/+1 anchored)", other),
                                    };
                                    insns.push(make_insn(addr, "PLOP3.LUT", vec![
                                        Operand::Pred { num: d, neg: false },
                                        op_pt(),
                                        op_pt(),
                                        op_pt(),
                                        op_pt(),
                                        op_imm(la),
                                        op_imm(lb),
                                    ], guard));
                                    addr += 16;
                                    continue;
                                }
                            }
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

                        SassTemplate::SharedVec { store } => {
                            // b9 phase-3 #12 (b9p14): vector ld/st.shared
                            // width-join (anchors in ptx_map.rs): v2.b32 ->
                            // .64 (pair), v2.b64/v4.b32 -> .128 (quad),
                            // v4.b64 (256-bit) fail-closed. 16-bit members
                            // fail-closed (no vendor anchor). Group chunk
                            // via prepare_group (64-bit members = lane
                            // pairs); address resolved FIRST (before the
                            // chunk allocation bumps next_gpr).
                            let is64 = insn.opcode.ends_with(".b64")
                                || insn.opcode.ends_with(".u64") || insn.opcode.ends_with(".s64");
                            let v4 = insn.opcode.contains(".v4.");
                            let suffix = if v4 && is64 {
                                anyhow::bail!("{}: v4 of 64-bit = 256-bit shared op unattested (no LDS/STS.256 row)", insn.opcode);
                            } else if v4 || is64 {
                                ".128"
                            } else if insn.opcode.ends_with(".b16")
                                || insn.opcode.ends_with(".u16") || insn.opcode.ends_with(".s16")
                            {
                                anyhow::bail!("{}: vector of 16-bit members unattested (b9 phase-3 #12)", insn.opcode);
                            } else {
                                ".64"
                            };
                            let (a_idx, g_idx, g_role) =
                                if *store { (0usize, 1usize, GroupRole::Src) } else { (1, 0, GroupRole::Dst) };
                            let aop = ptx_op_to_sass(&insn.operands[a_idx], &mut alloc, false);
                            let (op, pfx) = match insn.operands.get(g_idx) {
                                Some(PtxOperand::RegGroup(regs)) =>
                                    prepare_group(regs, g_role, addr, &mut alloc, &guard)
                                        .map_err(|e| e.context(format!("{} group", insn.opcode)))?,
                                other => anyhow::bail!(
                                    "{}: vector operand must be a brace group, got {:?}", insn.opcode, other),
                            };
                            let opf = if *store { format!("STS{}", suffix) } else { format!("LDS{}", suffix) };
                            let mut seq = pfx;
                            let mem = if *store {
                                make_insn(addr + 16 * seq.len() as u32, &opf, vec![aop, op], guard)
                            } else {
                                make_insn(addr + 16 * seq.len() as u32, &opf, vec![op, aop], guard)
                            };
                            seq.push(mem);
                            let n = seq.len() as u32;
                            insns.extend(seq);
                            addr += 16 * n;
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

                        SassTemplate::Fence { lines } => {
                            if !fence_exact_ok {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            // fixed vendor glue, no operands, no guard
                            for op in lines.iter() {
                                insns.push(make_insn(addr, op, vec![], None));
                                addr += 16;
                            }
                        }

                        SassTemplate::Mbar { kind } => {
                            // b9 phase-3 #6: exact-name match like Fence —
                            // unlisted sem/scope suffixes must not slip under
                            // a shared prefix.
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_mbarrier(addr, insn, &mut alloc, *kind, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }

                        SassTemplate::ClusterBarrier { arrive, relaxed, aligned } => {
                            // b9 phase-3 #7: exact-name match like Mbar —
                            // unlisted sem suffixes (e.g. explicit .sc) must
                            // not slip under a shared prefix.
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_cluster_barrier(addr, insn, &mut alloc,
                                    *arrive, *relaxed, *aligned,
                                    kernel.explicit_cluster, has_mbarrier, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }

                        SassTemplate::Mapa => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_mapa(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
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

                        // ── b9 phase-3 #8 (exact-name gate like Mbar) ─────
                        SassTemplate::Vote { ballot, all } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_vote(addr, insn, &mut alloc, &guard, *ballot, *all)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::MatchAny => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_match_any(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::WarpSyncMask => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_bar_warp(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::ElectSync => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_elect(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Redux => {
                            match lower_redux(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Nanosleep => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            if guard.is_some() { unsupported.insert(insn.opcode.clone()); continue; }
                            let ops = match insn.operands.get(0) {
                                Some(PtxOperand::IntImm(v)) => vec![Operand::Imm32(*v)],
                                Some(PtxOperand::Reg(n)) => vec![ptx_op_to_sass(&PtxOperand::Reg(n.clone()), &mut alloc, false)],
                                _ => { unsupported.insert(insn.opcode.clone()); continue; }
                            };
                            insns.push(make_insn(addr, "NANOSLEEP", ops, guard.clone()));
                            addr += 16;
                        }
                        SassTemplate::GridDep { wait } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            if guard.is_some() || !insn.operands.is_empty() {
                                unsupported.insert(insn.opcode.clone()); continue;
                            }
                            // vendor: launch_dependents -> PREEXIT, wait -> ACQBULK
                            // (anchors ns1/griddep_a + corpus p25, -O0 == -O3).
                            insns.push(make_insn(addr, if *wait { "ACQBULK" } else { "PREEXIT" }, vec![], guard.clone()));
                            addr += 16;
                        }
                        SassTemplate::CpAsync { bypass, ltc } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_cp_async(addr, insn, &mut alloc, &guard, *bypass, *ltc, &mut ldgsts_trio_done)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::CpAsyncBar { commit, all } => {
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            if guard.is_some() { unsupported.insert(insn.opcode.clone()); continue; }
                            if *commit {
                                insns.push(make_insn(addr, "LDGDEPBAR", vec![], None));
                                addr += 16;
                            }
                            if !*commit || *all {
                                // wait_group N / wait_all (=0): DEPBAR.LE SB0, N
                                let n = match insn.operands.get(0) {
                                    _ if *all => 0,
                                    Some(PtxOperand::IntImm(v)) => *v,
                                    _ => { unsupported.insert(insn.opcode.clone()); continue; }
                                };
                                // SB0 is a scoreboard id: the SASS parser folds
                                // SB<n> into Imm32(n) (parser.rs, keeps the II key);
                                // vendor text `DEPBAR.LE SB0, 0x1` and our
                                // `DEPBAR.LE 0x0, 0x1` are the same encoding.
                                insns.push(make_insn(addr, "DEPBAR.LE", vec![Operand::Imm32(0), Operand::Imm32(n)], None));
                                addr += 16;
                            }
                        }

                        SassTemplate::Ldsm { store } => {
                            match lower_ldsm(addr, insn, &mut alloc, &guard, *store)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Sub16 => {
                            match lower_sub16(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::HalfAdd => {
                            match lower_half_add(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::SelpU16 => {
                            match lower_selp_u16(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::SharedScalar { store } => {
                            let v = lower_shared_scalar(addr, insn, &mut alloc, guard, *store)?;
                            let n = v.len() as u32;
                            insns.extend(v); addr += 16 * n;
                        }
                        SassTemplate::MulLo16 => {
                            match lower_mullo16(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::MulHiU16 => {
                            match lower_mulhi_u16(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::ShrU16 => {
                            match lower_shr_u16(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Sub64 => {
                            match lower_sub64(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::MinS64 => {
                            match lower_min_s64(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Clz64 => {
                            match lower_clz64(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Popc64 => {
                            match lower_popc64(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::Mul64 { kind } => {
                            match lower_mul64(addr, insn, &mut alloc, &guard, *kind)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::MadWide32 => {
                            match lower_mad_wide32(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
                            }
                        }
                        SassTemplate::CpAsyncBulk => {
                            // exact-name gate like CpAsync/Fence (prefix-trap class)
                            if insn.opcode != rule.pattern {
                                unsupported.insert(insn.opcode.clone());
                                continue;
                            }
                            match lower_cp_async_bulk(addr, insn, &mut alloc, &guard)? {
                                Some((v, n)) => { insns.extend(v); addr += 16 * n; }
                                None => { unsupported.insert(insn.opcode.clone()); continue; }
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
        // BUG-118 sweep-up: HashMap iteration order fed the free_preds LIFO,
        // making predicate slot assignment run-to-run NONDETERMINISTIC (two
        // consecutive ptxlower runs on ucgate-484102 produced different
        // P1/P2 placements, 2026-08-24). Sort: sink order is now canonical.
        {
            let mut dying: Vec<&String> = pred_last_use.iter()
                .filter(|(_, &lu)| lu == si)
                .map(|(n, _)| n)
                .collect();
            dying.sort();
            for name in dying { dead_preds.push(name.clone()); }
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
    if let Some(hit) = &alloc.gpr_hit_cap {
        anyhow::bail!(
            "ptx_lower: GPR space exhausted (R0..R254, R255=RZ alias trap) in kernel {} at variable {:?}; kernel needs live-range-aware allocation (b1)",
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

    let lk = LoweredKernel {
        name: kernel.name.clone(),
        instructions: insns,
        max_regs: alloc.max_gpr(),
        params: kernel.params.clone(),
        shared_bytes: kernel.shared_bytes,
        dead_read_ok: alloc.dead_read_ok.clone(),
    };
    // BUG-118: fail-closed use-before-def gate on the artifact exactly as
    // shipped. The assembler accepts use-without-producer silently; silicon
    // then reads a wild register (deterministic 700 for address pairs).
    // Debug escape: CUBIT_B118_GATE=off prints the report and CONTINUES
    // (diagnosis only; pipelines must never set it).
    let gate_report = check_use_before_def(&lk.to_sass_text(), &lk.dead_read_ok);
    match gate_report {
        Ok(()) => {}
        Err(e) => {
            if std::env::var("CUBIT_B118_GATE").as_deref() == Ok("off") {
                eprintln!("[b118-gate debug] {}", e);
                eprintln!("[b118-gate debug] dead_read_ok = {:?}", lk.dead_read_ok);
                eprintln!("{}", lk.to_sass_text());
            } else {
                return Err(e.context(format!("ptx_lower gateway kernel {}", kernel.name)));
            }
        }
    }
    Ok(lk)
}

/// BUG-118 fail-closed gate: every R/UR register read in the emitted SASS
/// text must have a producer inside the kernel (entry live-in == empty on
/// both domains; RZ/URZ/PT are constants, excluded by the liveness engine).
/// Runs on the rendered .entry text through the same strict parse +
/// CFG-aware dataflow the M3 reg_liveness pass provides, so backward-branch
/// loops are handled by construction. Kernels containing ops WITHOUT
/// operand-role data can't be certified (transfer unknown) and are rejected
/// as well -- a missing role row is a tables gap, not a waiver.
pub fn check_use_before_def(text: &str, dead_read_ok: &std::collections::BTreeSet<(u8, i64)>) -> Result<()> {
    let live = crate::reg_liveness::liveness_file(text)?;
    let mut bad: Vec<String> = Vec::new();
    for k in &live {
        if !k.unknown_ops.is_empty() {
            bad.push(format!(
                "kernel {}: {} op(s) without operand-role data ({}); transfer sets uncertified",
                k.name, k.unknown_ops.len(),
                k.unknown_ops.iter().take(4).cloned().collect::<Vec<_>>().join(", ")));
            continue;
        }
        if let Some(first) = k.ins.first() {
            // Witnesses of an entry-live reg: nodes reachable from entry
            // WITHOUT crossing a def of that reg, where the reg is read.
            // (live_in membership alone also matches later legal uses.)
            let witnesses = |r: u8, live_in: &[std::collections::BTreeSet<u8>],
                             uses: &[std::collections::BTreeSet<u8>],
                             defs: &[std::collections::BTreeSet<u8>]| -> Vec<usize> {
                let _ = live_in;
                let mut seen = vec![false; k.ins.len()];
                let mut stack = vec![0usize];
                let mut wit = Vec::new();
                while let Some(i) = stack.pop() {
                    if seen[i] { continue; }
                    seen[i] = true;
                    // in-place ops read AND write r at the same node: the
                    // self-read is a valid witness (PRMT Rd, .., Rd shape).
                    if uses[i].contains(&r) { wit.push(i); }
                    if defs[i].contains(&r) { continue; }
                    for &s2 in &k.ins[i].succ { stack.push(s2); }
                }
                wit
            };
            let is_declared_dead_prmt = |r: u8, row: &crate::reg_liveness::InsRegLive| -> bool {
                let t = row.raw_text.trim().trim_end_matches(';').trim();
                let t = if t.starts_with('@') {
                    t.splitn(2, ' ').nth(1).unwrap_or("").trim_start()
                } else { t };
                if !t.starts_with("PRMT R") { return false; }
                let toks: Vec<&str> = t[5..].split(',').map(|s| s.trim()).collect();
                if toks.len() != 4 { return false; }
                let want = format!("R{}", r);
                if toks[0] != want || toks[3] != want { return false; }
                let sel = i64::from_str_radix(toks[2].trim_start_matches("0x"), 16).unwrap_or(-1);
                dead_read_ok.contains(&(r, sel))
            };
            // R domain
            {
                let uses: Vec<_> = k.ins.iter().map(|r| r.ruses.clone()).collect();
                let defs: Vec<_> = k.ins.iter().map(|r| r.rdefs.clone()).collect();
                let li: Vec<_> = k.ins.iter().map(|r| r.rlive_in.clone()).collect();
                for &r in first.rlive_in.iter() {
                    if r == 255 { continue; }
                    let wit = witnesses(r, &li, &uses, &defs);
                    if !wit.is_empty()
                        && wit.iter().all(|&i| is_declared_dead_prmt(r, &k.ins[i]))
                    {
                        continue; // emitter-declared dead-byte in-place PRMT
                    }
                    let clue = wit.first().map(|&i| format!(
                        "\n    R{} first unproduced use before 0x{:x}: {}",
                        r, k.ins[i].addr, k.ins[i].raw_text.trim())).unwrap_or_default();
                    bad.push(format!(
                        "kernel {}: entry live-in R{} -- used without producer{}",
                        k.name, r, clue));
                }
            }
            // UR domain
            {
                let uses: Vec<_> = k.ins.iter().map(|r| r.uuses.clone()).collect();
                let defs: Vec<_> = k.ins.iter().map(|r| r.udefs.clone()).collect();
                let li: Vec<_> = k.ins.iter().map(|r| r.ulive_in.clone()).collect();
                for &r in first.ulive_in.iter() {
                    let wit = witnesses(r, &li, &uses, &defs);
                    let clue = wit.first().map(|&i| format!(
                        "\n    UR{} first unproduced use before 0x{:x}: {}",
                        r, k.ins[i].addr, k.ins[i].raw_text.trim())).unwrap_or_default();
                    bad.push(format!(
                        "kernel {}: entry live-in UR{} -- used without producer{}",
                        k.name, r, clue));
                }
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("use-before-def gate (BUG-118):\n  {}", bad.join("\n  "))
    }
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
            OpSlot::NegRZ => op_neg_reg(255),
        }
    }).collect()
}

/// b9 phase-3 #3: does this opcode touch PTX CC (carry-chain class)?
fn is_cc_op(opcode: &str) -> bool {
    opcode.starts_with("add.cc.") || opcode.starts_with("addc.")
        || opcode.starts_with("sub.cc.") || opcode.starts_with("subc.")
        || opcode.starts_with("mad.lo.cc.") || opcode.starts_with("madc.")
}

/// b9 phase-3 #8: shape-exact expansion sizes for vote/match/elect/
/// bar.warp/nanosleep/griddep/cvta.shared/cp.async ops (labels after these
/// must not shift; first pass has the operands available, unlike
/// estimate_expansion_size). Returns None for ops outside the family.
fn b9p8_expansion_count(insn: &PtxInsn, trio_est: &mut bool) -> Option<u32> {
    // b9p12 (phase-3 #10): named-barrier pack (9) vs direct (2); fail-closed
    // shapes emit 1 slot budget anyway (they land on unsupported and bail).
    let op = insn.opcode.as_str();
    if op == "bfe.u32" {
        // MOV pos elided when pos==0 (anchor bfe_probe (0,31)): 7 vs 8 ops.
        return Some(if matches!(insn.operands.get(2), Some(PtxOperand::IntImm(0))) { 7 } else { 8 });
    }
    if op == "barrier.sync" || op == "barrier.arrive" {
        let imm2 = matches!(insn.operands.get(0), Some(PtxOperand::IntImm(_)))
            && matches!(insn.operands.get(1), Some(PtxOperand::IntImm(_)));
        return Some(if insn.operands.len() == 2 && imm2 { 9 } else { 2 });
    }
    // b9p11: mad.lo.s64 with an immediate c materializes a MOV pair (+2).
    if op == "mad.lo.s64" {
        return Some(if matches!(insn.operands.get(3), Some(PtxOperand::IntImm(_))) { 9 } else { 7 });
    }
    // b9p11: b16 muls are 3/4 (imm-b adds the vendor MOV materialization).
    if op == "mul.lo.s16" {
        return Some(if matches!(insn.operands.get(2), Some(PtxOperand::IntImm(_))) { 4 } else { 3 });
    }
    if op == "mul.hi.u16" {
        return Some(if matches!(insn.operands.get(2), Some(PtxOperand::IntImm(_))) { 5 } else { 4 });
    }
    let imm_last = matches!(insn.operands.last(), Some(PtxOperand::IntImm(_)));
    let n = match op {
        "vote.sync.ballot.b32" | "vote.sync.any.pred" | "vote.sync.all.pred"
        | "match.any.sync.b32" => if imm_last { 4 } else { 3 },
        "bar.warp.sync" => if imm_last { 3 } else { 2 },
        "elect.sync" => {
            let real_dst = match insn.operands.get(0) {
                Some(PtxOperand::Reg(n)) => !n.starts_with("%rx|"),
                _ => false,
            };
            3 + imm_last as u32 + real_dst as u32
        }
        "nanosleep.u32" | "griddepcontrol.wait" | "griddepcontrol.launch_dependents" => 1,
        "cp.async.commit_group" | "cp.async.wait_group" => 1,
        "cp.async.wait_all" => 2,
        _ if op.starts_with("cp.async.c") => {
            let dst_off = match insn.operands.get(0) {
                Some(PtxOperand::Addr { offset, .. }) => *offset != 0,
                _ => false,
            };
            let mut c = 1 + dst_off as u32;
            if let Some(sz) = insn.operands.get(3) {
                c += match sz {
                    PtxOperand::IntImm(_) => 4, // ISETP, MOV, IADD3, LOP3
                    _ => 3,                     // ISETP, IADD3, LOP3
                };
                c += 4; // W-copy carry pair + offset-add carry pair
            }
            c
        }
        "cvt.u64.u16" => 2,
        _ => return None,
    };
    // the 3-slot `@!PT LDS RZ, [RZ]` preamble precedes the FIRST LDGSTS only
    if op.starts_with("cp.async.c") && !*trio_est {
        *trio_est = true;
        return Some(n + 3);
    }
    Some(n)
}

fn estimate_expansion_size(opcode: &str) -> u32 {
    // b9 phase-3 #4: acq_rel atoms wrap the core op in 4 glue instructions
    // (vendor anchor at5_sem: MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR; core;
    // CCTL.IVALL). Label-address estimation must match the real expansion
    // or branch targets shift silently.
    if opcode.starts_with("atom.") && opcode.contains(".acq_rel.") { return 5; }
    // b9 phase-3 #7: barrier.cluster glued expansions (anchored counts;
    // names are exact after the gateway's exact-name gate).
    if opcode.starts_with("barrier.cluster.") {
        let aligned = opcode.ends_with(".aligned");
        let arrive = opcode.contains(".arrive");
        let relaxed = opcode.contains(".relaxed");
        return match (arrive, relaxed, aligned) {
            (true, false, false) => 15, // arrive[.release]
            (true, true, false) => 12,  // arrive.relaxed
            (true, false, true) => 10,  // arrive[.release].aligned
            (true, true, true) => 7,    // arrive.relaxed.aligned
            (false, _, false) => 18,    // wait[.acquire]
            (false, _, true) => 9,      // wait[.acquire].aligned
        };
    }
    // mapa: S2R + LEA + PRMT (+MOV for imm ctaid != 0 / bare sym address --
    // operand-dependent, so this 3 is a lower bound; labels accounted per
    // corpus shapes only).
    if opcode == "mapa.shared::cluster.u32" { return 3; }
    // b9 phase-3 #3 template sizes (instruction counts)
    if opcode.starts_with("mad.lo.cc.") { return 3; }
    if opcode.starts_with("madc.") { return 2; }
    if opcode == "shl.b64" || opcode == "shr.u64" || opcode == "shr.s64" { return 2; }
    // b9 phase-3 #9 fixed expansion sizes (label-address contract; each
    // count == the matching lower_* emission, asserted by debug_assert in
    // the lowerer or by the rust pins).
    if opcode == "sub.s16" { return 3; }
    if opcode == "mul.lo.s16" { return 3; }
    if opcode == "mul.hi.u16" { return 4; }
    if opcode == "shr.u16" { return 4; }
    if opcode == "min.s64" { return 4; }
    if opcode == "clz.b64" { return 6; }
    if opcode == "popc.b64" { return 7; }
    // b9p12 (phase-3 #10) exact counts (pack shapes handled in b9p8 expander)
    if opcode == "clz.b32" { return 2; }
    if opcode == "popc.b32" || opcode == "brev.b32" { return 3; }
    if opcode == "bfe.u32" { return 8; } // pos==0 -> 7 handled in b9p8 expander
    if opcode == "bar.red.and.pred" || opcode == "bar.red.or.pred" { return 3; }
    if opcode == "bar.sync" || opcode == "barrier.sync.aligned" { return 2; }
    if opcode == "barrier.sync" || opcode == "barrier.arrive" { return 2; }
    if opcode == "barrier.arrive.aligned" { return 2; }
    if opcode.starts_with("setmaxnreg.") { return 0; }
    if opcode == "mul.lo.s64" || opcode == "mad.lo.s64" || opcode == "mul.hi.u64" { return 7; }
    // b9p13 (phase-3 #11) mufu/sat lane exact counts (anchors sec.3 of the
    // phase-3 #11 report; asserted by the b9p13 rust pins).
    if opcode == "add.sat.s32" { return 5; }
    if opcode == "sin.approx.f32" || opcode == "cos.approx.f32" { return 2; }
    if opcode == "ex2.approx.f32" { return 6; }
    if opcode == "lg2.approx.f32" { return 7; }
    if opcode == "div.approx.f32" { return 8; }
    if opcode == "mad.wide.u32" { return 4; }
    if opcode == "cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes" { return 16; }
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
/// b9 phase-3 #6: mbarrier family (SYNCS-class), vendor-anchored -O0 glue
/// per op (probes work/b9p8/probes mb1..mb4; parity evidence
/// results/b9/mbar_parity/). Returns Ok(None) for shapes outside the
/// anchored/corpus set (lands on the per-kernel unsupported list).
fn lower_mbarrier(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, kind: MbarKind, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    // Guarded mbarrier ops are unattested; fail closed (BUG-080 policy).
    if guard.is_some() { return Ok(None); }

    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;

    // Fixed uniform-register scratch window for the init EXCH.64 operand
    // triple. The gateway never allocates UR elsewhere (UR4 descriptor aside),
    // so high URs are collision-free; R2UR immediately precedes the consumer.
    const MBAR_UR_LO: u8 = 60; // (0x100000-count)<<1
    const MBAR_UR_HI: u8 = 61; // (0x100000-count)<<11
    const MBAR_UR_AD: u8 = 62; // CGA-wide address

    let ur = |num: u8| Operand::UReg { num, neg: false, abs: false, inv: false, reuse: false, is_zero: false };
    let urz = || Operand::UReg { num: 63, neg: false, abs: false, inv: false, reuse: false, is_zero: true };
    let addr_arurz = |rb: u8| Operand::Addr { base_reg: Some(rb), base_reg_suffix: None, ur_reg: Some(255), offset: 0 };

    // [%reg] with zero offset is the only corpus address shape. A bare
    // shared-window symbol materializes to its static offset (iter35 layout)
    // in a scratch reg first.
    let mut base_r = |insn: &PtxInsn, alloc: &mut RegAlloc, i: usize,
                      out: &mut Vec<Instruction>, a: &mut u32| -> Result<Option<u8>> {
        match insn.operands.get(i) {
            Some(PtxOperand::Addr { base, offset }) => {
                if *offset != 0 { return Ok(None); }
                if alloc.is_ptx_reg_name(base) { Ok(Some(alloc.gpr(base))) }
                else if let Some(off) = alloc.shared_sym(base) {
                    let r = alloc.gpr("$mbar_symaddr");
                    out.push(make_insn(*a, "IMAD.MOV.U32",
                        vec![op_reg(r), op_rz(), op_rz(), op_imm(off)], None));
                    *a += 16;
                    Ok(Some(r))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    };

    // vendor per-op CGA-wide address glue: S2R ctaid; LEA addr,ctaid,base,<<24
    macro_rules! addr_glue {
        ($alloc:expr, $rb:expr) => {{
            let rc = $alloc.gpr("$mbar_ctaid");
            let ra = $alloc.gpr("$mbar_addr");
            out.push(make_insn(a, "S2R", vec![op_reg(rc), Operand::SysReg("SR_CgaCtaId".into())], None));
            a += 16;
            out.push(make_insn(a, "LEA", vec![op_reg(ra), op_reg(rc), op_reg($rb), op_imm(0x18)], None));
            a += 16;
            ra
        }};
    }

    match kind {
        MbarKind::Init => {
            let Some(rb) = base_r(insn, alloc, 0, &mut out, &mut a)? else { return Ok(None) };
            // count operand: imm (materialize via IMAD.MOV.U32; MOV R,imm has
            // no table row, iter31) or 32-bit register.
            let rc = match insn.operands.get(1) {
                Some(PtxOperand::IntImm(v)) => {
                    let r = alloc.gpr("$mbar_cnt");
                    out.push(make_insn(a, "IMAD.MOV.U32",
                        vec![op_reg(r), op_rz(), op_rz(), op_imm(*v)], None));
                    a += 16;
                    r
                }
                Some(PtxOperand::Reg(name)) if alloc.is_ptx_reg_name(name) && !alloc.is_64bit(name) => alloc.gpr(name),
                _ => return Ok(None),
            };
            let ra = addr_glue!(alloc, rb);
            let rcc = alloc.gpr("$mbar_cnt2");
            let rh  = alloc.gpr("$mbar_hi");
            let rl  = alloc.gpr("$mbar_lo");
            out.push(make_insn(a, "IADD3", vec![op_reg(rcc), op_pt(), op_pt(), op_neg_reg(rc), op_imm(0x100000), op_rz()], None));
            a += 16;
            out.push(make_insn(a, "SHF.L.U32", vec![op_reg(rh), op_reg(rcc), op_imm(0xb), op_rz()], None));
            a += 16;
            out.push(make_insn(a, "SHF.L.U32", vec![op_reg(rl), op_reg(rcc), op_imm(0x1), op_rz()], None));
            a += 16;
            out.push(make_insn(a, "R2UR", vec![ur(MBAR_UR_LO), op_reg(rl)], None));
            a += 16;
            out.push(make_insn(a, "R2UR", vec![ur(MBAR_UR_HI), op_reg(rh)], None));
            a += 16;
            out.push(make_insn(a, "R2UR", vec![ur(MBAR_UR_AD), op_reg(ra)], None));
            a += 16;
            out.push(make_insn(a, "SYNCS.EXCH.64", vec![urz(), Operand::Addr { base_reg: None, base_reg_suffix: None, ur_reg: Some(MBAR_UR_AD), offset: 0 }, ur(MBAR_UR_LO)], None));
            a += 16;
        }
        MbarKind::TryWaitParity | MbarKind::TryWait => {
            let pd = match insn.operands.get(0) {
                Some(PtxOperand::Pred(name)) if !name.contains('!') => alloc.pred(name),
                _ => return Ok(None),
            };
            let Some(rb) = base_r(insn, alloc, 1, &mut out, &mut a)? else { return Ok(None) };
            let ra = addr_glue!(alloc, rb);
            let phase_op = if kind == MbarKind::TryWaitParity {
                // parity bit -> bit31 of the phase word (SHF.L by 0x1f).
                let rp = alloc.gpr("$mbar_phase");
                match insn.operands.get(2) {
                    Some(PtxOperand::IntImm(v)) => {
                        if *v != 0 {
                            out.push(make_insn(a, "IMAD.MOV.U32",
                                vec![op_reg(rp), op_rz(), op_rz(), op_imm(*v)], None));
                            a += 16;
                        }
                        out.push(make_insn(a, "SHF.L.U32", vec![op_reg(rp), if *v != 0 { op_reg(rp) } else { op_rz() }, op_imm(0x1f), op_rz()], None));
                        a += 16;
                    }
                    Some(PtxOperand::Reg(name)) if alloc.is_ptx_reg_name(name) => {
                        let r = alloc.gpr(name);
                        out.push(make_insn(a, "SHF.L.U32", vec![op_reg(rp), op_reg(r), op_imm(0x1f), op_rz()], None));
                        a += 16;
                    }
                    _ => return Ok(None),
                }
                op_reg(rp)
            } else {
                // suspend-time hint: only the corpus-attested 0 (-> RZ) shape.
                match insn.operands.get(2) {
                    Some(PtxOperand::IntImm(0)) => op_rz(),
                    _ => return Ok(None),
                }
            };
            out.push(make_insn(a, "SYNCS.PHASECHK.TRANS64.TRYWAIT",
                vec![Operand::Pred { num: pd, neg: false }, addr_arurz(ra), phase_op], None));
            a += 16;
        }
        MbarKind::Arrive | MbarKind::ArriveExpectTx => {
            // dst: `_` (PTX discard token parses as Label("_")) -> RZ; a real
            // b64 register -> 64-bit destination pair (nvdisasm prints lo).
            let dst_op = match insn.operands.get(0) {
                Some(PtxOperand::Label(name)) if name == "_" => op_rz(),
                Some(PtxOperand::Reg(name)) if alloc.is_ptx_reg_name(name) && alloc.is_64bit(name) => {
                    let (lo, _hi) = alloc.gpr_pair(name);
                    op_reg(lo)
                }
                _ => return Ok(None),
            };
            let Some(rb) = base_r(insn, alloc, 1, &mut out, &mut a)? else { return Ok(None) };
            let ra = addr_glue!(alloc, rb);
            if kind == MbarKind::Arrive {
                out.push(make_insn(a, "SYNCS.ARRIVE.TRANS64.A1T0", vec![dst_op, addr_arurz(ra), op_rz()], None));
                a += 16;
            } else {
                let tx_op = match insn.operands.get(2) {
                    Some(PtxOperand::IntImm(0)) => op_rz(),
                    Some(PtxOperand::IntImm(v)) => {
                        let rt = alloc.gpr("$mbar_tx");
                        out.push(make_insn(a, "IMAD.MOV.U32", vec![op_reg(rt), op_rz(), op_rz(), op_imm(*v)], None));
                        a += 16;
                        op_reg(rt)
                    }
                    Some(PtxOperand::Reg(name)) if alloc.is_ptx_reg_name(name) => op_reg(alloc.gpr(name)),
                    _ => return Ok(None),
                };
                out.push(make_insn(a, "SYNCS.ARRIVE.TRANS64", vec![dst_op, addr_arurz(ra), tx_op], None));
                a += 16;
            }
        }
        MbarKind::ArriveCluster => {
            // remote arrive: dst is always `_`, and the address is expected to
            // be mapa-shared::cluster-remapped already (vendor anchor mb3:
            // PRMT glue, no ctaid LEA). Corpus has no other shape.
            match insn.operands.get(0) {
                Some(PtxOperand::Label(name)) if name == "_" => {}
                _ => return Ok(None),
            }
            let Some(rb) = base_r(insn, alloc, 1, &mut out, &mut a)? else { return Ok(None) };
            out.push(make_insn(a, "SYNCS.ARRIVE.TRANS64.RED.A1T0", vec![op_rz(), addr_arurz(rb), op_rz()], None));
            a += 16;
        }
    }

    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// b9 phase-3 #7: barrier.cluster family -> guarded UCGABAR protocol with
/// runtime cluster-presence test (gate = LDC c[0x0][0x36c] & 1). Emitted
/// glue replicates the vendor -O0 per-op expansion 1:1 (anchors cl1/cl3;
/// byte-parity 142/142 in results/b9/cluster_parity/). Branch targets are
/// per-expansion gensyms (BCL_<addr>_{ELSE,MID,END}) resolved textually by
/// cubit's assembler; labels follow the same pseudo-instruction convention
/// as PTX-level labels (raw_text "NAME:", zero address cost).
/// Returns Ok(None) => op lands on the unsupported list.
fn lower_cluster_barrier(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc,
    arrive: bool, relaxed: bool, aligned: bool,
    explicit_cluster: bool, has_mbarrier: bool, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    // Guarded barrier.cluster ops are unattested; fail closed (BUG-080
    // policy, same as mbarrier).
    if guard.is_some() { return Ok(None); }
    if !insn.operands.is_empty() { return Ok(None); }

    let l_else = format!("BCL_{:x}_ELSE", addr);
    let l_mid = format!("BCL_{:x}_MID", addr);
    let l_end = format!("BCL_{:x}_END", addr);

    let r0 = alloc.gpr("$clu_r0");
    let pg = alloc.pred("%clu_gate");

    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;

    let mut push = |out: &mut Vec<Instruction>, a: &mut u32, op: &str, ops: Vec<Operand>, g: Option<Guard>| {
        out.push(make_insn(*a, op, ops, g));
        *a += 16;
    };
    let label = |out: &mut Vec<Instruction>, name: &str| {
        out.push(Instruction {
            addr: a_dummy(), opcode: String::new(), opcode_full: String::new(),
            key: String::new(), guard: None, operands: vec![], modifiers: vec![],
            ctrl: ControlCode::default(), hand_sched: false, rsd: None,
            raw_text: format!("{}:", name),
        });
    };

    // Direct mode (anchors cl5/cl6/cl7): `.explicitcluster` proves a real
    // cluster launch at compile time, so ptxas ELIDES the runtime gate --
    // no LDC/ISETP/branch, just the inline protocol. `.reqnctapercluster`
    // alone (any n) keeps the guarded form.
    if explicit_cluster {
        if aligned {
            push(&mut out, &mut a, "WARPSYNC.ALL", vec![], None);
        } else {
            push(&mut out, &mut a, "MOV", vec![op_reg(r0), op_imm(0xffff_ffff)], None);
            push(&mut out, &mut a, "WARPSYNC.COLLECTIVE.ALL", vec![Operand::Label(l_mid.clone())], None);
        }
        if arrive {
            if !relaxed {
                // vendor inserts MEMBAR.ALL.CTA first when ANY mbarrier op
                // exists in the kernel (anchors cl7/cl8: init / expect_tx /
                // try_wait all trigger; plain STS does not; relaxed never).
                if has_mbarrier {
                    push(&mut out, &mut a, "MEMBAR.ALL.CTA", vec![], None);
                }
                push(&mut out, &mut a, "MEMBAR.ALL.GPU", vec![], None);
                push(&mut out, &mut a, "ERRBAR", vec![], None);
                push(&mut out, &mut a, "CGAERRBAR", vec![], None);
            }
            push(&mut out, &mut a, "UCGABAR_ARV", vec![], None);
        } else {
            push(&mut out, &mut a, "UCGABAR_WAIT", vec![], None);
            push(&mut out, &mut a, "CCTL.IVALL", vec![], None);
        }
        if !aligned {
            push(&mut out, &mut a, "ENDCOLLECTIVE", vec![], None);
            label(&mut out, &l_mid);
        }
        let n = ((a - addr) / 16) as u32;
        return Ok(Some((out, n)));
    }

    // shared guard prefix: LDC; ISETP; @!Pg BRA ELSE
    push(&mut out, &mut a, "LDC", vec![op_reg(r0), Operand::ConstMem { bank: 0, base_reg: None, ur_reg: None, offset: 0x36c }], None);
    push(&mut out, &mut a, "ISETP.EQ.U32.AND",
        vec![Operand::Pred { num: pg, neg: false }, Operand::Pred { num: 7, neg: false },
             op_reg(r0), op_imm(0x1), Operand::Pred { num: 7, neg: false }], None);
    push(&mut out, &mut a, "BRA", vec![Operand::Label(l_else.clone())],
        Some(Guard { pred: pg, negated: true, uniform: false }));

    if aligned {
        push(&mut out, &mut a, "WARPSYNC.ALL", vec![], None);
        if arrive {
            if !relaxed {
                if has_mbarrier {
                    push(&mut out, &mut a, "MEMBAR.ALL.CTA", vec![], None);
                }
                push(&mut out, &mut a, "MEMBAR.ALL.GPU", vec![], None);
                push(&mut out, &mut a, "ERRBAR", vec![], None);
                push(&mut out, &mut a, "CGAERRBAR", vec![], None);
            }
            push(&mut out, &mut a, "UCGABAR_ARV", vec![], None);
        } else {
            push(&mut out, &mut a, "UCGABAR_WAIT", vec![], None);
            push(&mut out, &mut a, "CCTL.IVALL", vec![], None);
        }
        push(&mut out, &mut a, "BRA", vec![Operand::Label(l_end.clone())], None);
        label(&mut out, &l_else);
        push(&mut out, &mut a, "WARPSYNC.ALL", vec![], None);
        if !arrive {
            push(&mut out, &mut a, "BAR.SYNC.DEFER_BLOCKING", vec![op_imm(0x0)], None);
        }
        label(&mut out, &l_end);
    } else {
        push(&mut out, &mut a, "MOV", vec![op_reg(r0), op_imm(0xffff_ffff)], None);
        push(&mut out, &mut a, "WARPSYNC.COLLECTIVE.ALL", vec![Operand::Label(l_mid.clone())], None);
        if arrive {
            if !relaxed {
                if has_mbarrier {
                    push(&mut out, &mut a, "MEMBAR.ALL.CTA", vec![], None);
                }
                push(&mut out, &mut a, "MEMBAR.ALL.GPU", vec![], None);
                push(&mut out, &mut a, "ERRBAR", vec![], None);
                push(&mut out, &mut a, "CGAERRBAR", vec![], None);
            }
            push(&mut out, &mut a, "UCGABAR_ARV", vec![], None);
        } else {
            push(&mut out, &mut a, "UCGABAR_WAIT", vec![], None);
            push(&mut out, &mut a, "CCTL.IVALL", vec![], None);
        }
        push(&mut out, &mut a, "ENDCOLLECTIVE", vec![], None);
        label(&mut out, &l_mid);
        push(&mut out, &mut a, "BRA", vec![Operand::Label(l_end.clone())], None);
        label(&mut out, &l_else);
        if arrive {
            push(&mut out, &mut a, "MOV", vec![op_reg(r0), op_imm(0xffff_ffff)], None);
            push(&mut out, &mut a, "WARPSYNC.COLLECTIVE", vec![op_reg(r0), Operand::Label(l_end.clone())], None);
            push(&mut out, &mut a, "NOP", vec![], None);
            push(&mut out, &mut a, "ENDCOLLECTIVE", vec![], None);
        } else {
            let r2 = alloc.gpr("$clu_r2");
            let r3 = alloc.gpr("$clu_r3");
            push(&mut out, &mut a, "MOV", vec![op_reg(r2), op_imm(0x0)], None);
            push(&mut out, &mut a, "MOV", vec![op_reg(r3), op_imm(0x0)], None);
            push(&mut out, &mut a, "MOV", vec![op_reg(r0), op_imm(0xffff_ffff)], None);
            push(&mut out, &mut a, "WARPSYNC.COLLECTIVE", vec![op_reg(r0), Operand::Label(l_end.clone())], None);
            push(&mut out, &mut a, "SHF.L.U32", vec![op_reg(r3), op_reg(r3), op_imm(0x10), op_rz()], None);
            push(&mut out, &mut a, "LOP3.LUT", vec![op_reg(r3), op_reg(r3), op_imm(0xf), op_reg(r2), op_imm(0xf8), op_not_pt()], None);
            push(&mut out, &mut a, "BAR.SYNC.DEFER_BLOCKING", vec![op_reg(r3), op_reg(r3)], None);
            push(&mut out, &mut a, "SHF.R.U32", vec![op_reg(r3), op_reg(r3), op_imm(0x10), op_rz()], None);
            push(&mut out, &mut a, "ENDCOLLECTIVE", vec![], None);
        }
        label(&mut out, &l_end);
    }

    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

// label pseudo-instructions carry no address; the field is never read for
// them (same convention as the PtxStmt::Label path in lower_kernel).
fn a_dummy() -> u32 { 0 }

/// b9 phase-3 #7: mapa.shared::cluster.u32 d, a, ctaid -> per-op CGA-wide
/// address glue + PRMT byte splice (vendor anchors cl2, -O0):
///   S2R rc, SR_CgaCtaId ; LEA ra, rc, rb, 0x18 ; PRMT d, ctsel, 0x654, ra
/// ctsel = RZ for imm 0, plain-MOV materialized reg for imm != 0, or the
/// resolved ctaid register. Fail-closed: non-reg address shapes, imm ctaid
/// outside 0..=255, non-reg/non-imm ctaid, guards.
fn lower_mapa(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }

    let d_name = match insn.operands.get(0) {
        Some(PtxOperand::Reg(n)) => n.clone(),
        _ => return Ok(None),
    };
    // Address: a plain register (corpus shape). A bare shared-window symbol
    // materializes to its static offset in a scratch reg first (iter35
    // layout, same contract as base_r in lower_mbarrier).
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let rb = match insn.operands.get(1) {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => alloc.gpr(n),
        Some(PtxOperand::Reg(n)) | Some(PtxOperand::Label(n)) => {
            match alloc.shared_sym(n) {
                Some(off) => {
                    let r = alloc.gpr("$clu_symaddr");
                    out.push(make_insn(a, "IMAD.MOV.U32",
                        vec![op_reg(r), op_rz(), op_rz(), op_imm(off)], None));
                    a += 16;
                    r
                }
                None => return Ok(None),
            }
        }
        _ => return Ok(None),
    };
    let ctaid_op = match insn.operands.get(2) {
        Some(PtxOperand::IntImm(0)) => op_rz(),
        Some(PtxOperand::IntImm(v)) if *v > 0 && *v <= 0xff => {
            let t = alloc.gpr("$clu_ctimm");
            out.push(make_insn(a, "MOV", vec![op_reg(t), op_imm(*v)], None));
            a += 16;
            op_reg(t)
        }
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => op_reg(alloc.gpr(n)),
        _ => return Ok(None),
    };

    let rc = alloc.gpr("$clu_ctaid");
    let ra = alloc.gpr("$clu_addr");
    out.push(make_insn(a, "S2R", vec![op_reg(rc), Operand::SysReg("SR_CgaCtaId".into())], None));
    a += 16;
    out.push(make_insn(a, "LEA", vec![op_reg(ra), op_reg(rc), op_reg(rb), op_imm(0x18)], None));
    a += 16;
    let d = alloc.gpr(&d_name);
    out.push(make_insn(a, "PRMT", vec![op_reg(d), ctaid_op, op_imm(0x654), op_reg(ra)], None));
    a += 16;

    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

// ── b9 phase-3 #8: vote/match/bar.warp/elect/nanosleep/griddep/cp.async ──

/// Label pseudo-instruction following the PtxStmt::Label convention
/// (same form as lower_cluster_barrier's per-expansion gensyms).
fn push_gensym_label(out: &mut Vec<Instruction>, name: &str) {
    out.push(Instruction {
        addr: a_dummy(), opcode: String::new(), opcode_full: String::new(),
        key: String::new(), guard: None, operands: vec![], modifiers: vec![],
        ctrl: ControlCode::default(), hand_sched: false, rsd: None,
        raw_text: format!("{}:", name),
    });
}

/// WARPSYNC.COLLECTIVE mask protocol open (b9p8 anchors): an imm membermask
/// materializes via MOV into a shared scratch, a reg mask is used directly.
/// Emits [MOV ;] WARPSYNC.COLLECTIVE mask, `(lbl). Returns the mask's reg.
fn b9p8_warpsync_open(
    out: &mut Vec<Instruction>, a: &mut u32, alloc: &mut RegAlloc,
    mask: Option<&PtxOperand>, lbl: &str,
) -> Option<u8> {
    let mreg = match mask {
        Some(PtxOperand::IntImm(v)) => {
            let r = alloc.gpr("$ws_mask");
            out.push(make_insn(*a, "MOV", vec![op_reg(r), op_imm(*v)], None));
            *a += 16;
            r
        }
        Some(PtxOperand::Reg(name)) => alloc.resolve(name),
        _ => return None,
    };
    out.push(make_insn(*a, "WARPSYNC.COLLECTIVE",
        vec![op_reg(mreg), Operand::Label(lbl.to_string())], None));
    *a += 16;
    Some(mreg)
}

/// vote.sync.{ballot.b32, any.pred, all.pred} (anchors vm1 + v_vote1).
/// ballot: VOTE.ANY Rd, PT, Ps -- pred-family: VOTE.{ANY,ALL} Pd, Ps.
fn lower_vote(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
    ballot: bool, all: bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let lbl = format!("VOT_{:x}_END", addr);
    if b9p8_warpsync_open(&mut out, &mut a, alloc, insn.operands.get(2), &lbl).is_none() {
        return Ok(None);
    }
    if ballot {
        let d = match insn.operands.get(0) {
            Some(PtxOperand::Reg(n)) => op_reg(alloc.resolve(n)),
            _ => return Ok(None),
        };
        let p = match insn.operands.get(1) {
            Some(PtxOperand::Pred(n)) => Operand::Pred { num: alloc.pred(n), neg: false },
            _ => return Ok(None),
        };
        out.push(make_insn(a, "VOTE.ANY", vec![d, op_pt(), p], None));
        a += 16;
    } else {
        let d = match insn.operands.get(0) {
            Some(PtxOperand::Pred(n)) => Operand::Pred { num: alloc.pred(n), neg: false },
            _ => return Ok(None),
        };
        let p = match insn.operands.get(1) {
            Some(PtxOperand::Pred(n)) => Operand::Pred { num: alloc.pred(n), neg: false },
            _ => return Ok(None),
        };
        out.push(make_insn(a, if all { "VOTE.ALL" } else { "VOTE.ANY" }, vec![d, p], None));
        a += 16;
    }
    out.push(make_insn(a, "ENDCOLLECTIVE", vec![], None));
    a += 16;
    push_gensym_label(&mut out, &lbl);
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// match.any.sync.b32 (anchors vm1 + p_matchany): MATCH.ANY Rd, Rs.
fn lower_match_any(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let lbl = format!("MAT_{:x}_END", addr);
    if b9p8_warpsync_open(&mut out, &mut a, alloc, insn.operands.get(2), &lbl).is_none() {
        return Ok(None);
    }
    let d = match insn.operands.get(0) {
        Some(PtxOperand::Reg(n)) => op_reg(alloc.resolve(n)),
        _ => return Ok(None),
    };
    let s = match insn.operands.get(1) {
        Some(PtxOperand::Reg(n)) => op_reg(alloc.resolve(n)),
        _ => return Ok(None),
    };
    out.push(make_insn(a, "MATCH.ANY", vec![d, s], None));
    a += 16;
    out.push(make_insn(a, "ENDCOLLECTIVE", vec![], None));
    a += 16;
    push_gensym_label(&mut out, &lbl);
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// bar.warp.sync mask (anchor bw1 + corpus p_ldgsts): bare WARPSYNC pair.
fn lower_bar_warp(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let lbl = format!("BWS_{:x}_END", addr);
    if b9p8_warpsync_open(&mut out, &mut a, alloc, insn.operands.get(0), &lbl).is_none() {
        return Ok(None);
    }
    out.push(make_insn(a, "ENDCOLLECTIVE", vec![], None));
    a += 16;
    push_gensym_label(&mut out, &lbl);
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}


// ── b9 phase-3 #9 lowerings ────────────────────────────────────────────────
// Vendor anchors: work/b9p11/probes/*.ptx (-O0 primary, -O3 control) +
// corpus kernels quoted per fn. All shapes outside the anchored/corpus set
// return Ok(None) -> per-kernel unsupported list (fail-closed), never a
// silent skip.

fn ur(n: u8) -> Operand {
    Operand::UReg { num: n, neg: false, abs: false, inv: false, reuse: false, is_zero: false }
}
fn ur_addr(n: u8) -> Operand {
    Operand::Addr { base_reg: None, base_reg_suffix: None, ur_reg: Some(n), offset: 0 }
}
fn op_inv_reg(n: u8) -> Operand {
    Operand::Reg { num: n, neg: false, abs: false, inv: true, reuse: false }
}
/// 64-bit PTX operand -> (lo, hi) register pair, or None (unsupported shape).
fn pair_of(op: Option<&PtxOperand>, alloc: &mut RegAlloc) -> Option<(u8, u8)> {
    match op {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => Some(alloc.gpr_pair(n)),
        _ => None,
    }
}
/// 32-bit PTX operand -> SASS Reg operand (imm handled by callers), or None.
fn reg_of(op: Option<&PtxOperand>, alloc: &mut RegAlloc) -> Option<u8> {
    match op {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => Some(alloc.resolve(n)),
        _ => None,
    }
}

/// ldmatrix/stmatrix (Ldsm). Corpus: b_ldmatrix x4 [%rd pair], p11 x4 [%r],
/// p_ldsm x1, p12 stmatrix x4; probe ldsm1 (x1/x4/store, [Rn] plain).
fn lower_ldsm(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>, store: bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let op = &insn.opcode;
    let xs: u32 = if op.contains(".x1.") { 1 } else if op.contains(".x4.") { 4 } else { return Ok(None) };
    // exact family shape: ldmatrix.sync.aligned.m8n8.xN.shared.b16 (+st)
    let want_pre = if store { "stmatrix.sync.aligned.m8n8." } else { "ldmatrix.sync.aligned.m8n8." };
    let want_suf = ".shared.b16";
    if !op.starts_with(want_pre) || !op.ends_with(want_suf) { return Ok(None); }
    let (grp_i, adr_i) = if store { (1, 0) } else { (0, 1) };
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    // group: x4 -> aligned quad via prepare_group; x1 -> single register.
    let g = match &insn.operands[grp_i] {
        PtxOperand::RegGroup(regs) if regs.len() == 4 && xs == 4 => {
            let role = if store { GroupRole::Src } else { GroupRole::Dst };
            match prepare_group(regs, role, a, alloc, guard) {
                Ok((oper, pre)) => {
                    let n = pre.len() as u32;
                    out.extend(pre);
                    a += 16 * n;
                    oper
                }
                Err(_) => return Ok(None),
            }
        }
        PtxOperand::RegGroup(regs) if regs.len() == 1 && xs == 1 => {
            // LDSM x1 dst is a plain single register (anchor ldsm1/p_ldsm).
            op_reg(alloc.resolve(&regs[0]))
        }
        _ => return Ok(None),
    };
    let adr = match &insn.operands[adr_i] {
        PtxOperand::Addr { base, offset } => {
            if *offset != 0 || !alloc.is_ptx_reg_name(base) { return Ok(None); }
            Operand::Addr { base_reg: Some(alloc.resolve(base)), base_reg_suffix: None, ur_reg: None, offset: 0 }
        }
        _ => return Ok(None),
    };
    let opf = if store {
        "STSM.16.M88.4"
    } else if xs == 4 {
        "LDSM.16.M88.4"
    } else {
        "LDSM.16.M88"
    };
    let operands = if store { vec![adr, g] } else { vec![g, adr] };
    out.push(make_insn(a, opf, operands, guard.clone()));
    a += 16;
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// sub.s16 (Sub16). Anchors: b16a (imm-a: 1951/7807) + b16b (reg-reg).
fn lower_sub16(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let b = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };
    let t = alloc.gpr("$sub16_t");
    let mut out = vec![
        make_insn(addr, "IADD3", vec![op_reg(t), op_pt(), op_pt(), op_rz(), op_neg_reg(b), op_rz()], guard.clone()),
        make_insn(addr + 16, "PRMT", vec![op_reg(t), op_reg(t), op_imm(0x7710), op_rz()], guard.clone()),
    ];
    let third = match insn.operands.get(1) {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => {
            vec![op_reg(d), op_pt(), op_pt(), op_reg(alloc.resolve(n)), op_reg(t), op_rz()]
        }
        Some(PtxOperand::IntImm(v)) => {
            vec![op_reg(d), op_pt(), op_pt(), op_reg(t), op_imm(*v), op_rz()]
        }
        _ => return Ok(None),
    };
    out.push(make_insn(addr + 32, "IADD3", third, guard.clone()));
    Ok(Some((out, 3)))
}

/// add.f16 (HalfAdd, b9 phase-3 #14 / b9p16): scalar f16 add. Vendor anchor
/// corpus_p15 -O0 /*0320*/ (+ ptxas bit-exact precedent mk67): HADD2 with
/// both sources .H0_H0 half-broadcast:
///   HADD2 Rd, Ra.H0_H0, Rb.H0_H0
/// The lift IR has no half-select operand slot; the modifier lives in the
/// raw operand text (encoder op_hsel reads it off). raw_text is therefore
/// spelled explicitly (precedent: fence/mbar raw_text construction, and the
/// raw_text rewrites at the scheduling fixup sites). IR operands carry the
/// plain registers for introspection.
fn lower_half_add(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if insn.opcode != "add.f16" { return Ok(None); }  // add.f16x2 & friends: no anchor
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let b = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };
    let mut ins = make_insn(addr, "HADD2",
        vec![op_reg(d), op_reg(a), op_reg(b)], guard.clone());
    let g = guard_text(guard);
    ins.raw_text = format!("{}HADD2 R{}, R{}.H0_H0, R{}.H0_H0 ;", g, d, a, b);
    Ok(Some((vec![ins], 1)))
}

/// Guard prefix text identical to make_insn's rendering (for explicit
/// raw_text spelling).
fn guard_text(guard: &Option<Guard>) -> String {
    match guard {
        Some(g) => {
            let pred = if g.pred == 7 { "PT".to_string() } else { format!("P{}", g.pred) };
            if g.negated { format!("@!{} ", pred) } else { format!("@{} ", pred) }
        }
        None => String::new(),
    }
}

/// mul.lo.s16 (MulLo16): sign-extend halves (PRMT 0x9910) + IMAD (anchor b16b).
fn lower_mullo16(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let x = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let at = alloc.gpr("$mlo16_at");
    let bt = alloc.gpr("$mlo16_bt");
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    // b imm (anchor t16i + probe-022920 11): MOV bt, v&0xffff up front,
    // then the same 0x9910 sign-extend as the register path.
    if let Some(PtxOperand::IntImm(v)) = insn.operands.get(2) {
        out.push(make_insn(a, "MOV", vec![op_reg(bt), op_imm(*v & 0xffff)], guard.clone()));
        a += 16;
    }
    let y = match insn.operands.get(2) {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => alloc.resolve(n),
        Some(PtxOperand::IntImm(_)) => bt,
        _ => return Ok(None),
    };
    out.push(make_insn(a, "PRMT", vec![op_reg(at), op_reg(x), op_imm(0x9910), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "PRMT", vec![op_reg(bt), op_reg(y), op_imm(0x9910), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "IMAD", vec![op_reg(d), op_reg(at), op_reg(bt), op_rz()], guard.clone()));
    a += 16;
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// mul.hi.u16 (MulHiU16): zero-extend (0x7710) + IMAD.U32 + >>16 (anchor b16a).
fn lower_mulhi_u16(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let x = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let at = alloc.gpr("$mhi16_at");
    let bt = alloc.gpr("$mhi16_bt");
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    // b imm (anchor t16i + probe-022920 -17873=0xba2f): MOV bt, v&0xffff,
    // then the same 0x7710 zero-extend as the register path.
    if let Some(PtxOperand::IntImm(v)) = insn.operands.get(2) {
        out.push(make_insn(a, "MOV", vec![op_reg(bt), op_imm(*v & 0xffff)], guard.clone()));
        a += 16;
    }
    let y = match insn.operands.get(2) {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => alloc.resolve(n),
        Some(PtxOperand::IntImm(_)) => bt,
        _ => return Ok(None),
    };
    out.push(make_insn(a, "PRMT", vec![op_reg(at), op_reg(x), op_imm(0x7710), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "PRMT", vec![op_reg(bt), op_reg(y), op_imm(0x7710), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "IMAD.U32", vec![op_reg(at), op_reg(at), op_reg(bt), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "SHF.R.U32.HI", vec![op_reg(d), op_rz(), op_imm(0x10), op_reg(at)], guard.clone()));
    a += 16;
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// shr.u16 (ShrU16): clamp/zero-extend the 32-bit shift amount, zero-extend a,
/// SHF.R.U32.HI (anchors b16a imm + b16b reg; d may alias t, vendor does so).
fn lower_shr_u16(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let x = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let t = alloc.gpr("$shr16_t");
    let at = alloc.gpr("$shr16_at");
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    match insn.operands.get(2) {
        Some(PtxOperand::IntImm(v)) => {
            out.push(make_insn(a, "MOV", vec![op_reg(t), op_imm(*v)], guard.clone()));
            a += 16;
        }
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => {
            let s = alloc.resolve(n);
            out.push(make_insn(a, "VIMNMX.U32", vec![op_reg(t), op_pt(), op_pt(), op_reg(s), op_imm(0xffff), op_pt()], guard.clone()));
            a += 16;
        }
        _ => return Ok(None),
    }
    out.push(make_insn(a, "PRMT", vec![op_reg(t), op_reg(t), op_imm(0x7710), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "PRMT", vec![op_reg(at), op_reg(x), op_imm(0x7710), op_rz()], guard.clone()));
    a += 16;
    out.push(make_insn(a, "SHF.R.U32.HI", vec![op_reg(d), op_rz(), op_reg(t), op_reg(at)], guard.clone()));
    a += 16;
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// sub.s64 (Sub64, anchor s64_sub -O0; -O3 identical form).
fn lower_sub64(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let (dlo, dhi) = match pair_of(insn.operands.get(0), alloc) { Some(p) => p, None => return Ok(None) };
    let (alo, ahi) = match pair_of(insn.operands.get(1), alloc) { Some(p) => p, None => return Ok(None) };
    let (blo, bhi) = match pair_of(insn.operands.get(2), alloc) { Some(p) => p, None => return Ok(None) };
    let pc = alloc.pred("$sub64_cc");
    let out = vec![
        make_insn(addr, "IADD3", vec![op_reg(dlo), Operand::Pred { num: pc, neg: false }, op_pt(), op_reg(alo), op_neg_reg(blo), op_rz()], guard.clone()),
        make_insn(addr + 16, "IADD3.X", vec![
            op_reg(dhi), op_pt(), op_pt(), op_reg(ahi), op_inv_reg(bhi), op_rz(),
            Operand::Pred { num: pc, neg: false }, op_not_pt(),
        ], guard.clone()),
    ];
    alloc.free_pred("$sub64_cc");
    Ok(Some((out, 2)))
}

/// min.s64 (MinS64, anchors s64_min reg + s64_mini imm4096). Imm with hi!=0
/// is unattested -> fail-closed.
fn lower_min_s64(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let (dlo, dhi) = match pair_of(insn.operands.get(0), alloc) { Some(p) => p, None => return Ok(None) };
    let (alo, ahi) = match pair_of(insn.operands.get(1), alloc) { Some(p) => p, None => return Ok(None) };
    let pc = alloc.pred("$min64_c");
    let pco = Operand::Pred { num: pc, neg: false };
    // b: reg pair or non-negative imm (hi32==0 -> RZ like the vendor anchor).
    let (blo_op, bhi_op) = match insn.operands.get(2) {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => {
            let (blo, bhi) = alloc.gpr_pair(n);
            (op_reg(blo), op_reg(bhi))
        }
        Some(PtxOperand::IntImm(v)) => {
            if (*v >> 32) != 0 { alloc.free_pred("$min64_c"); return Ok(None); }
            (op_imm(*v & 0xffff_ffff), op_rz())
        }
        _ => { alloc.free_pred("$min64_c"); return Ok(None) }
    };
    let out = vec![
        make_insn(addr, "ISETP.LT.U32.AND",
            vec![pco.clone(), op_pt(), op_reg(alo), blo_op.clone(), op_pt()], guard.clone()),
        make_insn(addr + 16, "ISETP.LT.AND.EX",
            vec![pco.clone(), op_pt(), op_reg(ahi), bhi_op.clone(), op_pt(), pco.clone()], guard.clone()),
        make_insn(addr + 32, "SEL", vec![op_reg(dlo), op_reg(alo), blo_op, pco.clone()], guard.clone()),
        make_insn(addr + 48, "SEL", vec![op_reg(dhi), op_reg(ahi), bhi_op, pco], guard.clone()),
    ];
    alloc.free_pred("$min64_c");
    Ok(Some((out, 4)))
}

/// clz.b64 (Clz64, anchor s64_clz -O0; -O3 uses NE+dual-IADD3, documented).
fn lower_clz64(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let (alo, ahi) = match pair_of(insn.operands.get(1), alloc) { Some(p) => p, None => return Ok(None) };
    let pc = alloc.pred("$clz64_c");
    let pco = Operand::Pred { num: pc, neg: false };
    let bias = alloc.gpr("$clz64_bias");
    let x = alloc.gpr("$clz64_x");
    let out = vec![
        make_insn(addr, "ISETP.EQ.U32.AND", vec![pco.clone(), op_pt(), op_reg(ahi), op_rz(), op_pt()], guard.clone()),
        make_insn(addr + 16, "SEL", vec![op_reg(bias), op_rz(), op_imm(0x20), Operand::Pred { num: pc, neg: true }], guard.clone()),
        make_insn(addr + 32, "SEL", vec![op_reg(x), op_reg(alo), op_reg(ahi), pco.clone()], guard.clone()),
        make_insn(addr + 48, "FLO.U32", vec![op_reg(x), op_reg(x)], guard.clone()),
        make_insn(addr + 64, "IADD3", vec![op_reg(x), op_pt(), op_pt(), op_neg_reg(x), op_imm(0x1f), op_rz()], guard.clone()),
        make_insn(addr + 80, "IADD3", vec![op_reg(d), op_pt(), op_pt(), op_reg(bias), op_reg(x), op_rz()], guard.clone()),
    ];
    alloc.free_pred("$clz64_c");
    Ok(Some((out, 6)))
}

/// popc.b64 (Popc64, anchor s64_popc): vendor keeps the ~0 mask AND idiom
/// per half (semantically identity; emitted verbatim, documented in report).
fn lower_popc64(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let (alo, ahi) = match pair_of(insn.operands.get(1), alloc) { Some(p) => p, None => return Ok(None) };
    let m = alloc.gpr("$popc_m");
    let t = alloc.gpr("$popc_t");
    let u = alloc.gpr("$popc_u");
    let out = vec![
        make_insn(addr, "LOP3.LUT", vec![op_reg(m), op_rz(), op_rz(), op_rz(), op_imm(0x33), op_not_pt()], guard.clone()),
        make_insn(addr + 16, "LOP3.LUT", vec![op_reg(t), op_reg(alo), op_reg(m), op_rz(), op_imm(0xc0), op_not_pt()], guard.clone()),
        make_insn(addr + 32, "POPC", vec![op_reg(t), op_reg(t)], guard.clone()),
        make_insn(addr + 48, "LOP3.LUT", vec![op_reg(m), op_rz(), op_rz(), op_rz(), op_imm(0x33), op_not_pt()], guard.clone()),
        make_insn(addr + 64, "LOP3.LUT", vec![op_reg(u), op_reg(ahi), op_reg(m), op_rz(), op_imm(0xc0), op_not_pt()], guard.clone()),
        make_insn(addr + 80, "POPC", vec![op_reg(u), op_reg(u)], guard.clone()),
        make_insn(addr + 96, "IADD3", vec![op_reg(d), op_pt(), op_pt(), op_reg(t), op_reg(u), op_rz()], guard.clone()),
    ];
    Ok(Some((out, 7)))
}

/// mul64 network (Mul64: Lo/Mad/Hi; anchors s64_mullo/s64_mulloi/s64_madlo/
/// s64_mulhi; -O0 full network kept verbatim incl. the dead t3/t2.hi lanes
/// for mul.lo, since the -O0 text is the parity reference).
fn lower_mul64(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>, kind: Mul64Kind,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    use crate::ptx_map::Mul64Kind::*;
    if guard.is_some() { return Ok(None); }
    let (dlo, dhi) = match pair_of(insn.operands.get(0), alloc) { Some(p) => p, None => return Ok(None) };
    let (alo, ahi) = match pair_of(insn.operands.get(1), alloc) { Some(p) => p, None => return Ok(None) };
    // b: register pair or 64-bit immediate split (anchor s64_mulloi:
    // lo as low-32 literal, hi as signed high-32 literal in slot B).
    let (blo, bhi): (Operand, Operand) = match insn.operands.get(2) {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => {
            let (l, h) = alloc.gpr_pair(n);
            (op_reg(l), op_reg(h))
        }
        Some(PtxOperand::IntImm(v)) => {
            let lo = (*v as u32) as i32 as i64;
            let hi = *v >> 32;
            (Operand::Imm32(lo), Operand::Imm32(hi))
        }
        _ => return Ok(None),
    };
    // mad: c addend pair (reg or imm; imm materializes as a MOV pair,
    // anchor madwi); mul: RZ pair.
    let mut pre: Vec<(u32, Instruction)> = Vec::new();
    let c_pair = if kind == Mad {
        match insn.operands.get(3) {
            Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => alloc.gpr_pair(n),
            Some(PtxOperand::IntImm(v)) => {
                let p = alloc.gpr_pair("$m64_cimm");
                pre.push((0, make_insn(addr, "MOV",
                    vec![op_reg(p.0), op_imm(*v as u32 as i32 as i64)], guard.clone())));
                pre.push((1, make_insn(addr + 16, "MOV",
                    vec![op_reg(p.1), op_imm(*v >> 32)], guard.clone())));
                p
            }
            _ => return Ok(None),
        }
    } else { (255, 255) };
    // scratch: t0 target pair = dst pair for Lo/Mad (d.lo is final t0.lo and
    // t0.hi feeds s1); Hi keeps t0 in its own pair. t1/t2/s2/t3 scratch.
    let (t0l, t0h) = if kind == Hi { alloc.gpr_pair("$m64_t0") } else { (dlo, dhi) };
    let (t1l, _t1h) = alloc.gpr_pair("$m64_t1");
    let (t2l, t2h) = alloc.gpr_pair("$m64_t2");
    let (s2l, s2h) = alloc.gpr_pair("$m64_s2");
    let (t3l, _t3h) = if kind == Hi { (dlo, dhi) } else { alloc.gpr_pair("$m64_t3") };
    let pc0 = alloc.pred("$m64_c0");
    let pc1 = alloc.pred("$m64_c1");
    let pc2 = alloc.pred("$m64_c2");
    let p = |n: u8| Operand::Pred { num: n, neg: false };
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    for (_, ins) in pre.drain(..) {
        out.push(ins);
        a += 16;
    }
    // 1. t0 = alo*blo + addend
    match kind {
        Mad => {
            // anchor: IMAD.WIDE.U32 d, Pc0, a, b, c (carry-out slot second)
            out.push(make_insn(a, "IMAD.WIDE.U32",
                vec![op_reg(t0l), p(pc0), op_reg(alo), blo.clone(), op_reg(c_pair.0)], guard.clone()));
        }
        _ => {
            out.push(make_insn(a, "IMAD.WIDE.U32",
                vec![op_reg(t0l), op_reg(alo), blo.clone(), op_rz()], guard.clone()));
        }
    }
    a += 16;
    // 2. t1 = ahi*blo
    out.push(make_insn(a, "IMAD.WIDE.U32",
        vec![op_reg(t1l), op_reg(ahi), blo, op_rz()], guard.clone()));
    a += 16;
    // 3. t2 = alo*bhi + t1 (carry-out Pc2)
    // anchor: IMAD.WIDE.U32 d, Pc2, a, b, addend (carry-out slot second)
    out.push(make_insn(a, "IMAD.WIDE.U32",
        vec![op_reg(t2l), p(pc2), op_reg(alo), bhi.clone(), op_reg(t1l)], guard.clone()));
    a += 16;
    // 4. s1 = t2.lo + t0.hi (carry-out Pc1). For Lo/Mad s1 lands on d.hi.
    let (s1r,) = if kind == Hi { (alloc.gpr("$m64_s1"),) } else { (dhi,) };
    out.push(make_insn(a, "IADD3",
        vec![op_reg(s1r), p(pc1), op_pt(), op_reg(t2l), op_reg(t0h), op_rz()], guard.clone()));
    a += 16;
    // 5. s2 = t2.hi + carries. mul: IADD3 + IADD3.X(single cin Pc2);
    //    mad: IADD3.X cin+contPc0 then IADD3.X dual cin (Pc2,Pc0').
    match kind {
        Mad => {
            out.push(make_insn(a, "IADD3.X",
                vec![op_reg(s2l), p(pc0), op_pt(), op_rz(), op_reg(t2h), op_rz(), p(pc0), op_not_pt()], guard.clone()));
            a += 16;
            out.push(make_insn(a, "IADD3.X",
                vec![op_reg(s2h), op_pt(), op_pt(), op_rz(), op_rz(), op_rz(), p(pc2), p(pc0)], guard.clone()));
            a += 16;
        }
        _ => {
            out.push(make_insn(a, "IADD3",
                vec![op_reg(s2l), op_pt(), op_pt(), op_rz(), op_reg(t2h), op_rz()], guard.clone()));
            a += 16;
            out.push(make_insn(a, "IADD3.X",
                vec![op_reg(s2h), op_pt(), op_pt(), op_rz(), op_rz(), op_rz(), p(pc2), op_not_pt()], guard.clone()));
            a += 16;
        }
    }
    // 6. t3 = ahi*bhi + s2 + Pc1
    out.push(make_insn(a, "IMAD.WIDE.U32.X",
        vec![op_reg(t3l), op_reg(ahi), bhi, op_reg(s2l), p(pc1)], guard.clone()));
    a += 16;
    alloc.free_pred("$m64_c0");
    alloc.free_pred("$m64_c1");
    alloc.free_pred("$m64_c2");
    let n = ((a - addr) / 16) as u32;
    // sanity: fixed expansion sizes (label-address contract; 7, or 9 when
    // the mad c-immediate materializes its MOV pair).
    debug_assert!(n == 7 || n == 9, "mul64 expansion {n}");
    Ok(Some((out, n)))
}

/// mad.wide.u32 d64, a32, b32, c64 (anchor madwi -O0):
///   IMAD.U32 tlo, a, b, RZ ; IMAD.HI.U32 thi, a, b, RZ ;
///   IADD3 dlo, Pc, PT, tlo, clo, RZ ; IADD3.X dhi, PT, PT, thi, chi, RZ, Pc, !PT
fn lower_mad_wide32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let (dlo, dhi) = match pair_of(insn.operands.get(0), alloc) { Some(p) => p, None => return Ok(None) };
    let a32 = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let b32 = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };
    let (clo, chi) = match pair_of(insn.operands.get(3), alloc) { Some(p) => p, None => return Ok(None) };
    let pc = alloc.pred("$madw32_c");
    let out = vec![
        make_insn(addr, "IMAD.U32", vec![op_reg(dlo), op_reg(a32), op_reg(b32), op_rz()], guard.clone()),
        make_insn(addr + 16, "IMAD.HI.U32", vec![op_reg(dhi), op_reg(a32), op_reg(b32), op_rz()], guard.clone()),
        make_insn(addr + 32, "IADD3", vec![op_reg(dlo), Operand::Pred { num: pc, neg: false }, op_pt(), op_reg(dlo), op_reg(clo), op_rz()], guard.clone()),
        make_insn(addr + 48, "IADD3.X", vec![
            op_reg(dhi), op_pt(), op_pt(), op_reg(dhi), op_reg(chi), op_rz(),
            Operand::Pred { num: pc, neg: false }, op_not_pt(),
        ], guard.clone()),
    ];
    alloc.free_pred("$madw32_c");
    Ok(Some((out, 4)))
}

/// cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes
/// (CpAsyncBulk; anchor corpus b_bulk_cp -O0 0x140..0x430; -O3 uniform-path
/// divergence documented). 16-insn fixed expansion (label contract).
fn lower_cp_async_bulk(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    // [dst(shared cta off)],[src(global 64)],size(reg),[mbar(shared cta off)]
    let addr32 = |i: usize, alloc: &mut RegAlloc| -> Option<u8> {
        match insn.operands.get(i) {
            Some(PtxOperand::Addr { base, offset }) if *offset == 0 && alloc.is_ptx_reg_name(base) =>
                Some(alloc.resolve(base)),
            _ => None,
        }
    };
    let rb_dst = match addr32(0, alloc) { Some(r) => r, None => return Ok(None) };
    let (slo, shi) = match insn.operands.get(1) {
        Some(PtxOperand::Addr { base, offset }) if *offset == 0 && alloc.is_ptx_reg_name(base) =>
            alloc.gpr_pair(base),
        _ => return Ok(None),
    };
    let sz = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };
    let rb_mb = match addr32(3, alloc) { Some(r) => r, None => return Ok(None) };
    // Fixed UR window (gateway-local; UR4 descriptor / UR60..62 mbar free).
    const B_UR_SZ: u8 = 52;
    const B_UR_SL: u8 = 53;
    const B_UR_SH: u8 = 54;
    const B_UR_DS: u8 = 55;
    const B_UR_MB: u8 = 56;
    let ct = alloc.gpr("$bcp_ctaid");
    let ad = alloc.gpr("$bcp_dsta");
    let ct2 = alloc.gpr("$bcp_ctaid2");
    let mb = alloc.gpr("$bcp_mba");
    let t = alloc.gpr("$bcp_sz");
    let pl = alloc.pred("$bcp_loop");
    let pe = alloc.pred("$bcp_elect");
    let lbl = format!("BCP_{:x}_LOOP", addr);
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let mut push = |opf: &str, ops: Vec<Operand>, g: Option<Guard>, out: &mut Vec<Instruction>, a: &mut u32| {
        out.push(make_insn(*a, opf, ops, g));
        *a += 16;
    };
    // dst CGA glue
    push("S2R", vec![op_reg(ct), Operand::SysReg("SR_CgaCtaId".into())], None, &mut out, &mut a);
    push("LEA", vec![op_reg(ad), op_reg(ct), op_reg(rb_dst), op_imm(0x18)], None, &mut out, &mut a);
    // src global pair -> UR
    push("R2UR", vec![ur(B_UR_SL), op_reg(slo)], None, &mut out, &mut a);
    push("R2UR", vec![ur(B_UR_SH), op_reg(shi)], None, &mut out, &mut a);
    // size: bytes>>4 packed to 16 bits
    push("SHF.R.U32.HI", vec![op_reg(t), op_rz(), op_imm(0x4), op_reg(sz)], None, &mut out, &mut a);
    push("PRMT", vec![op_reg(t), op_reg(t), op_imm(0x5410), op_rz()], None, &mut out, &mut a);
    push("R2UR", vec![ur(B_UR_SZ), op_reg(t)], None, &mut out, &mut a);
    // mbar CGA glue
    push("S2R", vec![op_reg(ct2), Operand::SysReg("SR_CgaCtaId".into())], None, &mut out, &mut a);
    push("LEA", vec![op_reg(mb), op_reg(ct2), op_reg(rb_mb), op_imm(0x18)], None, &mut out, &mut a);
    push("R2UR", vec![ur(B_UR_MB), op_reg(mb)], None, &mut out, &mut a);
    push("R2UR", vec![ur(B_UR_DS), op_reg(ad)], None, &mut out, &mut a);
    // elect loop
    push("PLOP3.LUT", vec![Operand::Pred { num: pl, neg: false }, op_pt(), op_pt(), op_pt(), op_pt(), op_imm(0x80), op_imm(0x8)], None, &mut out, &mut a);
    push_gensym_label(&mut out, &lbl);
    push("ELECT", vec![Operand::Pred { num: pe, neg: false },
        Operand::UReg { num: 63, neg: false, abs: false, inv: false, reuse: false, is_zero: true }, op_pt()],
        Some(Guard { pred: pl, negated: false, uniform: false }), &mut out, &mut a);
    push("PLOP3.LUT", vec![Operand::Pred { num: pl, neg: false }, op_pt(), Operand::Pred { num: pe, neg: false }, op_pt(), op_pt(), op_imm(0x8), op_imm(0x80)],
        Some(Guard { pred: pe, negated: false, uniform: false }), &mut out, &mut a);
    push("UBLKCP.S.G", vec![ur_addr(B_UR_DS), ur_addr(B_UR_SL), ur(B_UR_SZ)], None, &mut out, &mut a);
    push("PLOP3.LUT", vec![Operand::Pred { num: pe, neg: false }, op_pt(), op_pt(), op_pt(), op_pt(), op_imm(0x8), op_imm(0x80)], None, &mut out, &mut a);
    push("BRA.U.ANY", vec![Operand::Label(lbl.clone())],
        Some(Guard { pred: pl, negated: false, uniform: false }), &mut out, &mut a);
    alloc.free_pred("$bcp_loop");
    alloc.free_pred("$bcp_elect");
    let n = ((a - addr) / 16) as u32;
    debug_assert_eq!(n, 16);
    Ok(Some((out, n)))
}

/// elect.sync d|p, mask (anchors ns1/elect_a + el2/elect_sink + corpus p26).
/// ELECT Pp, UR79, PT; the %rx sink dst skips the trailing MOV from UR79.
fn lower_elect(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let pipe = match insn.operands.get(0) {
        Some(PtxOperand::Reg(n)) => n.clone(),
        _ => return Ok(None),
    };
    let parts: Vec<&str> = pipe.split('|').collect();
    if parts.len() != 2 { return Ok(None); }
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let lbl = format!("ELC_{:x}_END", addr);
    if b9p8_warpsync_open(&mut out, &mut a, alloc, insn.operands.get(1), &lbl).is_none() {
        return Ok(None);
    }
    let pd = match parts[1] {
        "%px" | "%p" => None,
        n => Some(Operand::Pred { num: alloc.pred(n), neg: false }),
    };
    // ELECT always produces a pred (anchor: P0/P1) and UR79.
    let elect_pd = match &pd {
        Some(p) => p.clone(),
        None => Operand::Pred { num: alloc.pred("%elect_sink"), neg: false },
    };
    out.push(make_insn(a, "ELECT", vec![
        elect_pd,
        Operand::UReg { num: 79, neg: false, abs: false, inv: false, reuse: false, is_zero: false },
        op_pt(),
    ], None));
    a += 16;
    match parts[0] {
        "%rx" => {}
        n => {
            out.push(make_insn(a, "MOV", vec![
                op_reg(alloc.resolve(n)),
                Operand::UReg { num: 79, neg: false, abs: false, inv: false, reuse: false, is_zero: false },
            ], None));
            a += 16;
        }
    }
    out.push(make_insn(a, "ENDCOLLECTIVE", vec![], None));
    a += 16;
    push_gensym_label(&mut out, &lbl);
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// redux.sync.{add,min,max}.{s32,u32} d, a, membermask (b9 phase-3 #13; anchors
/// corpus p08_redux/p_redux/v_redux1 -O0/-O3 + reduxprobes x5 kernels):
///   add.s32 -> REDUX.SUM.S32 UR79, Ra ; add.u32 -> REDUX.SUM UR79, Ra
///   max.u32 -> CREDUX.MAX UR79, Ra   ; min.u32 -> CREDUX.MIN UR79, Ra
/// O0 wraps each in the WARPSYNC.COLLECTIVE mask protocol (mask reg/imm ->
/// [MOV ;] WARPSYNC.COLLECTIVE Rm, `(L)) + MOV Rd, UR79 + ENDCOLLECTIVE + L:.
/// UR79 is the vendor's fixed redux result scratch at -O0 (p08 0x100/0x1d0/0x270
/// x3 in sequence, each read out by MOV before the next wrap). -O3 ELIDES the
/// collective wrap entirely (bare REDUX + IMAD.U32/MOV from low URs; documented
/// O3-elision divergence -- spans claimed -O0 only). and/or/xor, 64-bit, .s32
/// min/max (table groups MIN,S32/MAX,S32 exist era-side but the WORDS for
/// redux.sync.{min,max}.s32 are anchored here: CREDUX.MIN.S32/C32 MAX.S32 via
/// rdx_d; fail-closed pending an explicit corpus need) and pred-guarded forms
/// are fail-closed.
fn lower_redux(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let form = match insn.opcode.as_str() {
        "redux.sync.add.s32" => "REDUX.SUM.S32",
        "redux.sync.add.u32" => "REDUX.SUM",
        "redux.sync.max.u32" => "CREDUX.MAX",
        "redux.sync.min.u32" => "CREDUX.MIN",
        "redux.sync.max.s32" => "CREDUX.MAX.S32",
        "redux.sync.min.s32" => "CREDUX.MIN.S32",
        _ => return Ok(None),
    };
    let dst = match insn.operands.get(0) {
        Some(PtxOperand::Reg(n)) if !alloc.is_64bit(n) => n.clone(),
        _ => return Ok(None),
    };
    let src = match insn.operands.get(1) {
        Some(PtxOperand::Reg(n)) if !alloc.is_64bit(n) => n.clone(),
        _ => return Ok(None),
    };
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let lbl = format!("RDX_{:x}_END", addr);
    if b9p8_warpsync_open(&mut out, &mut a, alloc, insn.operands.get(2), &lbl).is_none() {
        return Ok(None);
    }
    let ur79 = || Operand::UReg { num: 79, neg: false, abs: false, inv: false, reuse: false, is_zero: false };
    out.push(make_insn(a, form, vec![ur79(), op_reg(alloc.resolve(&src))], None));
    a += 16;
    out.push(make_insn(a, "MOV", vec![op_reg(alloc.resolve(&dst)), ur79()], None));
    a += 16;
    out.push(make_insn(a, "ENDCOLLECTIVE", vec![], None));
    a += 16;
    push_gensym_label(&mut out, &lbl);
    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}

/// cp.async.ca/cg.shared.global[.L2::hint] [dst], [src], N {, src_size}.
/// Vendor anchors (cp1/cp2/cp3 -O0 + corpus b_cpasync/p_ldgsts/p13):
/// plain forms are a bare LDGSTS (dst [R..], src desc[UR4][G.64+off]);
/// a src-size operand (imm or reg) switches to the ZFILL form with the
/// size-adjust glue (Pz = sz==0; off = (0x10 - sz) & 0xF; 64-bit src
/// advance through IADD3/IADD3.X carry pairs; trailing !Pz predicate).
/// The PTX dst/src offsets fold into the address math (anchor cp1).
fn lower_cp_async(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
    bypass: bool, ltc: Option<u16>, trio_done: &mut bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let (dst_name, dst_off) = match insn.operands.get(0) {
        Some(PtxOperand::Addr { base, offset }) if base.starts_with('%') => (base.clone(), *offset),
        _ => return Ok(None),
    };
    let (src_name, src_off) = match insn.operands.get(1) {
        Some(PtxOperand::Addr { base, offset }) if base.starts_with('%') => (base.clone(), *offset),
        _ => return Ok(None),
    };
    if !alloc.is_64bit(&src_name) { return Ok(None); }
    let size = match insn.operands.get(2) {
        Some(PtxOperand::IntImm(v)) if *v == 4 || *v == 8 || *v == 16 => *v,
        _ => return Ok(None),
    };
    let sz_op = insn.operands.get(3);
    let zfill = sz_op.is_some();

    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;

    // dst address: +offset folded into a scratch (anchor cp1: IADD3 d, base, imm)
    let dst_reg = alloc.resolve(&dst_name);
    let d_use = if dst_off != 0 {
        let t = alloc.gpr("$cp_dst");
        out.push(make_insn(a, "IADD3", vec![op_reg(t), op_pt(), op_pt(), op_reg(dst_reg), op_imm(dst_off), op_rz()], None));
        a += 16;
        t
    } else { dst_reg };

    // src pair + optional ZFILL glue
    let (glo, ghi) = alloc.gpr_pair(&src_name);
    let (src_use, zpred): (u8, Option<u8>) = if !zfill {
        (glo, None)
    } else {
        let pz = alloc.pred("$cp_zp");
        let pq = alloc.pred("$cp_cq");
        let off = alloc.gpr("$cp_off");
        match sz_op {
            // reg: ISETP.EQ.U32.AND Pz, PT, Rs, RZ, PT  (32-bit only; a 64-bit
            // src-size is unattested -> fail closed)
            Some(PtxOperand::Reg(rn)) if !alloc.is_64bit(rn) => {
                out.push(make_insn(a, "ISETP.EQ.U32.AND",
                    vec![Operand::Pred { num: pz, neg: false }, op_pt(), op_reg(alloc.resolve(rn)), op_rz(), op_pt()], None));
                a += 16;
                out.push(make_insn(a, "IADD3",
                    vec![op_reg(off), op_pt(), op_pt(),
                         Operand::Reg { num: alloc.resolve(rn), neg: true, abs: false, inv: false, reuse: false },
                         op_imm(0x10), op_rz()], None));
                a += 16;
            }
            // imm: ISETP.EQ.U32.AND Pz, PT, RZ, imm, PT ; MOV off, imm ;
            //      IADD3 off, -off, 0x10  (anchor p13/cp3: MOV precedes IADD3)
            Some(PtxOperand::IntImm(v)) if *v >= 0 && *v <= 16 => {
                out.push(make_insn(a, "ISETP.EQ.U32.AND",
                    vec![Operand::Pred { num: pz, neg: false }, op_pt(), op_rz(), op_imm(*v), op_pt()], None));
                a += 16;
                out.push(make_insn(a, "MOV", vec![op_reg(off), op_imm(*v)], None));
                a += 16;
                out.push(make_insn(a, "IADD3",
                    vec![op_reg(off), op_pt(), op_pt(),
                         Operand::Reg { num: off, neg: true, abs: false, inv: false, reuse: false },
                         op_imm(0x10), op_rz()], None));
                a += 16;
            }
            _ => return Ok(None),
        }
        out.push(make_insn(a, "LOP3.LUT", vec![op_reg(off), op_reg(off), op_imm(0xf), op_rz(), op_imm(0xc0), op_not_pt()], None));
        a += 16;
        // 64-bit working copy of the src address (flatten pair, absorbing
        // the PTX src offset first when present; anchor cp1 0x200/0x210).
        let w = alloc.gpr("$cp_wlo");
        let wh = alloc.gpr("$cp_whi");
        if src_off != 0 {
            out.push(make_insn(a, "IADD3", vec![op_reg(w), Operand::Pred { num: pq, neg: false }, op_pt(), op_reg(glo), op_imm(src_off), op_rz()], None));
        } else {
            out.push(make_insn(a, "IADD3", vec![op_reg(w), Operand::Pred { num: pq, neg: false }, op_pt(), op_reg(glo), op_rz(), op_rz()], None));
        }
        a += 16;
        out.push(make_insn(a, "IADD3.X", vec![
            op_reg(wh), op_pt(), op_pt(), op_reg(ghi), op_rz(), op_rz(),
            Operand::Pred { num: pq, neg: false }, op_not_pt()], None));
        a += 16;
        out.push(make_insn(a, "IADD3", vec![
            op_reg(w), Operand::Pred { num: pq, neg: false }, op_pt(), op_reg(w), op_reg(off), op_rz()], None));
        a += 16;
        out.push(make_insn(a, "IADD3.X", vec![
            op_reg(wh), op_pt(), op_pt(), op_reg(wh), op_rz(), op_rz(),
            Operand::Pred { num: pq, neg: false }, op_not_pt()], None));
        a += 16;
        (w, Some(pz))
    };

    // kernel-wide trio preamble before the first LDGSTS
    if !*trio_done {
        for _ in 0..3 {
            out.push(make_insn(a, "LDS", vec![
                op_rz(),
                Operand::Addr { base_reg: Some(255), base_reg_suffix: None, ur_reg: None, offset: 0 },
            ], Some(Guard { pred: 7, negated: true, uniform: false })));
            a += 16;
        }
        *trio_done = true;
    }

    // modifier suffix in vendor print order: E, BYPASS, LTC128B/256B, width, ZFILL
    let mut sfx = String::from("LDGSTS.E");
    if bypass { sfx.push_str(".BYPASS"); }
    match ltc { Some(128) => sfx.push_str(".LTC128B"), Some(256) => sfx.push_str(".LTC256B"), _ => {} }
    if size == 8 { sfx.push_str(".64"); } else if size == 16 { sfx.push_str(".128"); }

    let mut ops = vec![
        Operand::Addr { base_reg: Some(d_use), base_reg_suffix: None, ur_reg: None, offset: 0 },
        Operand::Desc {
            ur_idx: 4,
            base_reg: Some(src_use),
            base_reg_suffix: Some(".64".to_string()),
            offset: if zfill { 0 } else { src_off },
        },
    ];
    if let Some(pz) = zpred {
        sfx.push_str(".ZFILL");
        ops.push(Operand::Pred { num: pz, neg: true });
    }
    if ltc == Some(256) && !zfill && !bypass {
        // mg '64,E,LTC256B' only attested for .ca 8
        if size != 8 { return Ok(None); }
    }
    out.push(make_insn(a, &sfx, ops, None));
    a += 16;

    let n = ((a - addr) / 16) as u32;
    Ok(Some((out, n)))
}



/// b9 phase-3 #15 (b9p17): half-float atomics lane. Only `atom.add.noftz`
/// is anchored; ftz / plain / red / sem+scope / shared / bf16 variants are
/// all fail-closed (the unsupported list exposes them, zero silent drops).
///
/// atom.add.noftz.f16 d, [a], v  -- vendor CAS-emulation loop (corpus p06
/// O0 /*0150-02d0*/; global probe_f16glob same macro with the G-spellings):
///   LOP3.LUT tA, a.lo, 0xfffffffd, RZ, 0xc0, !PT    (addr & ~3 semantics:
///                                                    clear bit1 -> 32b word)
///   LOP3.LUT tA+1, a.hi, 0xffffffff, RZ, 0xc0, !PT  (hi copy)
///   LOP3.LUT tB, a.lo, 0x2, RZ, 0xc0, !PT           (half-select bit)
///   ISETP.EQ.U32.AND P, PT, RZ, tB, PT              (P = aligned-low)
///   MOV tM, 0x3254 ; SEL tM, tM, 0x7610, P          (PRMT mode by half)
///   SHF.L.U32 tB, tB, 0x3, RZ                       (extract shift 0/16)
///   LD[.E|G.E] tO, desc[UR4][tA.64]
///   BSSY.RECONVERGENT Bk, POST
/// LOOP: HADD2 tN, tO, v.H0_H0                       (add into both halves)
///   PRMT tN, tO, tM, tN                             (merge selected half)
///   ATOM[G].E.CAS.STRONG.GPU PT, tN, [tA], tO, tN   (dest <- old word)
///   ISETP.NE.U32.AND P, PT, tN, tO, PT
///   MOV tO, tN
///   @P BRA LOOP ; NOP ; BSYNC.RECONVERGENT Bk
/// POST: SHF.R.U32.HI d, RZ, tB, tN                  (selected old half)
///
/// atom.add.noftz.f16x2 d, [a], v -- GENERIC space only has the 3-way
/// fallback protocol (corpus p06 O0 /*0340-05c0*/, distinct-half probe
/// x2diff): native ATOM.E.ADD.F16x2.RN with the success predicate; on fault
/// QSPC.E.S routes shared-window aliases to an LDS + ATOMS.CAST.SPIN loop
/// (H0/H1 HADD2 + SHF.L 0x10 + LOP3 0xe2 (hi&hi_mask)|(lo&~hi_mask) merge)
/// and anything else to a plain LD/IADD3/ST read-modify-write. Explicit
/// .global is a SINGLE native ATOMG.F16x2 word (probe_f16glob /*0350*/:
/// known space, no fallback, PT predicate).
///
/// Instruction words are all table-covered rows (LD/LDG dARI, ATOM CAS +
/// dARI, ATOMS_P_ARI_R_R CAST, QSPC_P_R_ARI, SEL/PLOP3/LOP3/ISETP/SHF/
/// HADD2 hsel-raw, BSSY_B_II/BSYNC_B/BRA_P_II); the reconvergence barrier
/// ids come from the lifter-owned pool (PTX-level branches emit no BSSY).
fn lower_atom_half(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, is_red: bool,
    op: &str, ty: &str, space: &str, sem: &str, scope: &str, noftz: bool, ftz: bool,
) -> Result<Option<Vec<Instruction>>> {
    if is_red || op != "add" || ftz || !noftz { return Ok(None); }
    if !sem.is_empty() || !scope.is_empty() { return Ok(None); }
    let global = match space { "" => false, "global" => true, _ => return Ok(None) };
    if !matches!(ty, "f16" | "f16x2") { return Ok(None); }
    if insn.operands.len() != 3 { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a64 = match insn.operands.get(1) {
        Some(PtxOperand::Addr { base, offset }) => {
            if !alloc.is_ptx_reg_name(base) || !alloc.is_64bit(base) || *offset != 0 {
                return Ok(None); // imm-offset / 32-bit / symbol bases: no anchor
            }
            alloc.gpr_pair(base)
        }
        _ => return Ok(None),
    };
    let v = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };

    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    macro_rules! p {
        ($op:expr, $ops:expr) => {{ out.push(make_insn(a, $op, $ops, None)); a += 16; }};
    }
    let lbl = |out: &mut Vec<Instruction>, name: &str| {
        out.push(Instruction {
            addr: a_dummy(), opcode: String::new(), opcode_full: String::new(),
            key: String::new(), guard: None, operands: vec![], modifiers: vec![],
            ctrl: ControlCode::default(), hand_sched: false, rsd: None,
            raw_text: format!("{}:", name),
        });
    };
    let hadd2 = |out: &mut Vec<Instruction>, d: u8, x: u8, xs: &str, y: u8, ys: &str, a: &mut u32| {
        let mut ins = make_insn(*a, "HADD2", vec![op_reg(d), op_reg(x), op_reg(y)], None);
        ins.raw_text = format!("HADD2 R{}, R{}{}, R{}{} ;", d, x, xs, y, ys);
        out.push(ins);
        *a += 16;
    };
    let pc = alloc.pred("%atomcc");
    let pred = |neg: bool| Operand::Pred { num: pc, neg };

    if ty == "f16" {
        let b = alloc.bar_alloc();
        let l_loop = format!("AF16CAS_{:x}", addr);
        let l_post = format!("AF16CAS_{:x}_POST", addr);
        let (t_alo, t_ahi) = alloc.gpr_pair("$atom16_addr");
        let t_bit = alloc.gpr("$atom16_bit");
        let t_mode = alloc.gpr("$atom16_mode");
        let t_old = alloc.gpr("$atom16_old");
        let t_new = alloc.gpr("$atom16_new");
        let (ld_op, cas_op) = if global { ("LDG.E", "ATOMG.E.CAS.STRONG.GPU") }
                              else { ("LD.E", "ATOM.E.CAS.STRONG.GPU") };
        p!("LOP3.LUT", vec![op_reg(t_alo), op_reg(a64.0), op_imm(0xffff_fffd), op_rz(), op_imm(0xc0), op_not_pt()]);
        p!("LOP3.LUT", vec![op_reg(t_ahi), op_reg(a64.1), op_imm(0xffff_ffff), op_rz(), op_imm(0xc0), op_not_pt()]);
        p!("LOP3.LUT", vec![op_reg(t_bit), op_reg(a64.0), op_imm(0x2), op_rz(), op_imm(0xc0), op_not_pt()]);
        p!("ISETP.EQ.U32.AND", vec![pred(false), op_pt(), op_rz(), op_reg(t_bit), op_pt()]);
        p!("IMAD.MOV.U32", vec![op_reg(t_mode), op_rz(), op_rz(), op_imm(0x3254)]);
        p!("SEL", vec![op_reg(t_mode), op_reg(t_mode), op_imm(0x7610), pred(false)]);
        p!("SHF.L.U32", vec![op_reg(t_bit), op_reg(t_bit), op_imm(0x3), op_rz()]);
        p!(ld_op, vec![op_reg(t_old), Operand::Desc {
            ur_idx: 4, base_reg: Some(t_alo), base_reg_suffix: Some(".64".to_string()), offset: 0 }]);
        p!("BSSY.RECONVERGENT", vec![Operand::Barrier(b), Operand::Label(l_post.clone())]);
        lbl(&mut out, &l_loop);
        hadd2(&mut out, t_new, t_old, "", v, ".H0_H0", &mut a);
        p!("PRMT", vec![op_reg(t_new), op_reg(t_old), op_reg(t_mode), op_reg(t_new)]);
        p!(cas_op, vec![op_pt(), op_reg(t_new),
            Operand::Addr { base_reg: Some(t_alo), base_reg_suffix: None, ur_reg: None, offset: 0 },
            op_reg(t_old), op_reg(t_new)]);
        p!("ISETP.NE.U32.AND", vec![pred(false), op_pt(), op_reg(t_new), op_reg(t_old), op_pt()]);
        p!("MOV", vec![op_reg(t_old), op_reg(t_new)]);
        out.push(make_insn(a, "BRA", vec![Operand::Label(l_loop.clone())],
            Some(Guard { pred: pc, negated: false, uniform: false })));
        a += 16;
        p!("NOP", vec![]);
        p!("BSYNC.RECONVERGENT", vec![Operand::Barrier(b)]);
        lbl(&mut out, &l_post);
        p!("SHF.R.U32.HI", vec![op_reg(d), op_rz(), op_reg(t_bit), op_reg(t_new)]);
        return Ok(Some(out));
    }

    // f16x2: explicit .global is vendor-anchored (probe_f16glob: single
    // ATOMG.E.ADD.F16x2.RN.STRONG.GPU word) but the ATOMG dARI entry has no
    // F16x2 mod-group; the generic->G bit transform is non-uniform across
    // the five twin rows (junk in variable regions), so n=2 probe words
    // cannot fit it honestly. Fail closed; words published to the b4-queue
    // (b9p17 report sec. F-2).
    if global { return Ok(None); }
    let (t_old, t_lo, t_hi, t_new) = (alloc.gpr("$atomx2_old"), alloc.gpr("$atomx2_lo"),
        alloc.gpr("$atomx2_hi"), alloc.gpr("$atomx2_new"));
    let b0 = alloc.bar_alloc();
    let b1 = alloc.bar_alloc();
    let stem = format!("AX2_{:x}", addr);
    let l_post = format!("{}_POST", stem);
    let l_done = format!("{}_DONE", stem);
    let l_spin = format!("{}_SPIN", stem);
    let l_sdone = format!("{}_SDONE", stem);
    let l_glob = format!("{}_GLOB", stem);
    let a_lo32 = Operand::Addr { base_reg: Some(a64.0), base_reg_suffix: None, ur_reg: None, offset: 0 };
    let desc64 = |base: u8| Operand::Desc {
        ur_idx: 4, base_reg: Some(base), base_reg_suffix: Some(".64".to_string()), offset: 0 };
    p!("ATOM.E.ADD.F16x2.RN.STRONG.GPU", vec![pred(false), op_reg(d), desc64(a64.0), op_reg(v)]);
    p!("PLOP3.LUT", vec![pred(false), op_pt(), pred(false), op_pt(), op_pt(), op_imm(0x80), op_imm(0x8)]);
    p!("BSSY.RECONVERGENT", vec![Operand::Barrier(b0), Operand::Label(l_post.clone())]);
    {
        let brg = Guard { pred: pc, negated: false, uniform: false };
        out.push(make_insn(a, "BRA", vec![Operand::Label(l_done.clone())], Some(brg)));
        a += 16;
    }
    p!("QSPC.E.S", vec![pred(false), op_rz(), a_lo32.clone()]);
    {
        let brg = Guard { pred: pc, negated: true, uniform: false };
        out.push(make_insn(a, "BRA", vec![Operand::Label(l_glob.clone())], Some(brg)));
        a += 16;
    }
    p!("BSSY.RECONVERGENT", vec![Operand::Barrier(b1), Operand::Label(l_sdone.clone())]);
    lbl(&mut out, &l_spin);
    p!("LDS", vec![op_reg(t_old), a_lo32.clone()]);
    hadd2(&mut out, t_lo, t_old, ".H0_H0", v, ".H0_H0", &mut a);
    hadd2(&mut out, t_hi, t_old, ".H1_H1", v, ".H1_H1", &mut a);
    p!("SHF.L.U32", vec![op_reg(t_hi), op_reg(t_hi), op_imm(0x10), op_rz()]);
    p!("LOP3.LUT", vec![op_reg(t_new), op_reg(t_hi), op_imm(0xffff_0000), op_reg(t_lo), op_imm(0xe2), op_not_pt()]);
    p!("ATOMS.CAST.SPIN", vec![pred(false), a_lo32.clone(), op_reg(t_old), op_reg(t_new)]);
    {
        let brg = Guard { pred: pc, negated: true, uniform: false };
        out.push(make_insn(a, "BRA", vec![Operand::Label(l_spin.clone())], Some(brg)));
        a += 16;
    }
    p!("NOP", vec![]);
    p!("BSYNC.RECONVERGENT", vec![Operand::Barrier(b1)]);
    lbl(&mut out, &l_sdone);
    p!("IMAD.MOV.U32", vec![op_reg(d), op_rz(), op_rz(), op_reg(t_old)]);
    p!("BRA", vec![Operand::Label(l_done.clone())]);
    lbl(&mut out, &l_glob);
    p!("LD.E", vec![op_reg(d), desc64(a64.0)]);
    p!("IADD3", vec![op_reg(t_new), op_pt(), op_pt(), op_reg(d), op_reg(v), op_rz()]);
    p!("ST.E", vec![desc64(a64.0), op_reg(t_new)]);
    lbl(&mut out, &l_done);
    p!("NOP", vec![]);
    p!("BSYNC.RECONVERGENT", vec![Operand::Barrier(b0)]);
    lbl(&mut out, &l_post);
    Ok(Some(out))
}

/// selp.u16 (SelpU16, b9 phase-3 #15 / b9p17): SEL positional law -- the
/// imm operand occupies s2 (the imm-capable slot); when a is that imm the
/// select swaps operands and negates the predicate. Always followed by the
/// u16 zero-extend PRMT 0x7710 (same idiom as MulHiU16/ShrU16). Anchors:
/// probe_selu16 -O0 (reg/reg, reg/imm, imm/reg, imm/imm non-zero) + corpus
/// p06 /*5f0-0620*/ (imm 1 / RZ / !P0). Guards, negated pred sources,
/// floats and imm values outside u16: fail-closed.
fn lower_selp_u16(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if insn.opcode != "selp.u16" { return Ok(None); }
    if guard.is_some() { return Ok(None); }
    if insn.operands.len() != 4 { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = insn.operands.get(1);
    let b = insn.operands.get(2);
    let p_num = match insn.operands.get(3) {
        Some(PtxOperand::Pred(n)) if !n.contains('!') => alloc.pred(n),
        _ => return Ok(None),
    };
    let in_u16 = |v: i64| -> Option<i64> { if (0..=0xffff).contains(&v) { Some(v) } else { None } };
    let mut out: Vec<Instruction> = Vec::new();
    let (s1, s2, neg) = match (a, b) {
        (Some(PtxOperand::Reg(ra)), Some(PtxOperand::Reg(rb))) => {
            (op_reg(alloc.resolve(ra)), op_reg(alloc.resolve(rb)), false)
        }
        (Some(PtxOperand::Reg(ra)), Some(PtxOperand::IntImm(ib))) => {
            let i = match in_u16(*ib) { Some(v) => v, None => return Ok(None) };
            (op_reg(alloc.resolve(ra)), op_imm(i), false)
        }
        (Some(PtxOperand::IntImm(ia)), other) => {
            let i = match in_u16(*ia) { Some(v) => v, None => return Ok(None) };
            let s1 = match other {
                Some(PtxOperand::Reg(rb)) => op_reg(alloc.resolve(rb)),
                Some(PtxOperand::IntImm(0)) => op_rz(),
                Some(PtxOperand::IntImm(i2)) => {
                    let v = match in_u16(*i2) { Some(v) => v, None => return Ok(None) };
                    let t = alloc.gpr("$sel16_mat");
                    out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                        vec![op_reg(t), op_rz(), op_rz(), op_imm(v)], None));
                    op_reg(t)
                }
                _ => return Ok(None),
            };
            (s1, op_imm(i), true)
        }
        _ => return Ok(None),
    };
    out.push(make_insn(addr + 16 * out.len() as u32, "SEL",
        vec![op_reg(d), s1, s2, Operand::Pred { num: p_num, neg }], None));
    out.push(make_insn(addr + 16 * out.len() as u32, "PRMT",
        vec![op_reg(d), op_reg(d), op_imm(0x7710), op_rz()], None));
    let n = out.len() as u32;
    Ok(Some((out, n)))
}

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
    // b9 phase-3 #15 (b9p17): ftz/noftz are type-level float modifiers.
    // Anchored only on the f16/f16x2 half-atom lane (noftz; corpus p06 +
    // probes); on every other (op,type) they remain unanchored fail-closed
    // (previously the bare token already fell off the end of the matcher).
    let mut noftz = false;
    let mut ftz = false;
    for t in toks.iter().skip(1) {
        match *t {
            "noftz" => {
                if noftz { return Ok(None); }
                noftz = true;
            }
            "ftz" => {
                if ftz { return Ok(None); }
                ftz = true;
            }
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

    // b9 phase-3 #15: half-float atom lane (f16 CAS loop / f16x2 native +
    // space fallback), fully vendored. Everything else carrying ftz/noftz
    // has no anchor.
    if matches!(ty, "f16" | "f16x2" | "bf16" | "bf16x2") {
        return lower_atom_half(addr, insn, alloc, is_red, op, ty, space, sem, scope, noftz, ftz);
    }
    if noftz || ftz { return Ok(None); }

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
            // b9 phase-3 #14 (b9p16): 64-bit immediates on 64-bit atoms
            // (atom.global.add.u64/f64; corpus p28 -O0 /*02c0-02d0*/ vendor
            // MOV lo; MOV hi ladder into a value pair):
            PtxOperand::IntImm(v) if is64 => {
                let bits = *v as u64;
                let t = alloc.gpr_pair(&format!("__atomimm64_{}", addr + 16 * out.len() as u32));
                out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                    vec![op_reg(t.0), op_rz(), op_rz(), Operand::Imm32((bits & 0xffff_ffff) as i64)], None));
                out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                    vec![op_reg(t.1), op_rz(), op_rz(), Operand::Imm32(((bits >> 32) & 0xffff_ffff) as i64)], None));
                Ok(Some(op_reg(t.0)))
            }
            PtxOperand::FloatImm(v) if ty == "f64" => {
                let bits = v.to_bits();
                let t = alloc.gpr_pair(&format!("__atomimm64_{}", addr + 16 * out.len() as u32));
                out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                    vec![op_reg(t.0), op_rz(), op_rz(), Operand::Imm32((bits & 0xffff_ffff) as i64)], None));
                out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                    vec![op_reg(t.1), op_rz(), op_rz(), Operand::Imm32(((bits >> 32) & 0xffff_ffff) as i64)], None));
                Ok(Some(op_reg(t.0)))
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
        // b10 F-1 (pilot gtprobe catch): 64-bit %globaltimer read lowers to
        // the vendor CS2R form (one instruction, even pair dest); the 32-bit
        // %globaltimer_lo/hi views have no vendor-anchored mapping and stay
        // fail-closed below (sreg_sass_name has no entry for them).
        (PtxOperand::Reg(name), PtxOperand::SReg(srn)) if srn == "%globaltimer" => {
            let (lo, _hi) = alloc.gpr_pair(name);
            out.push(make_insn(addr, "CS2R", vec![op_reg(lo), Operand::SysReg("SR_GLOBALTIMERLO".into())], guard));
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
            // b9 phase-3 #14 (b9p16): mov.b32 {lo16,hi16}, %r32 — sub-word
            // unpack. H0/H1 lane-select lowering (the old bail). Vendor law
            // (anchors corpus_readshared2 -O0 /*0220*/ 0x7610-form, unpack1
            // -O0 /*00e0*/ + corpus_p15 -O0 /*0280*/ 0x7632-form): b16 vregs
            // live in the LOW half of a 32-bit GPR (upper half don't-care);
            // both extracts are in-place PRMTs preserving the dst upper half:
            //   lo <- PRMT Rlo, Rsrc, 0x7610, Rlo   (dst.lo = src.b1b0)
            //   hi <- PRMT Rhi, Rsrc, 0x7632, Rhi   (dst.lo = src.b3b2)
            // (vendor coalesces the lo-extract away when the source reg can
            // feed the consumer directly, e.g. unpack1 -O0 stores R0 as-is;
            // the explicit 0x7610 form is the always-safe attested shape.)
            // `_` discard members get no instruction (vendor likewise).
            PtxOperand::Reg(other32) if !alloc.is_64bit(other32) => {
                if insn.opcode != "mov.b32" || regs.len() != 2 {
                    anyhow::bail!(
                        "mov {} into a {}-member group from 32-bit reg: only mov.b32 {{lo16,hi16}} unpack is vendor-attested (b9 phase-3)",
                        insn.opcode, regs.len());
                }
                let srcn = alloc.resolve(other32);
                if (base..base + 2).contains(&srcn) {
                    anyhow::bail!(
                        "mov.b32 unpack: dst group lane aliases the source reg {} (unattested aliasing)", other32);
                }
                for (i, name) in regs.iter().enumerate() {
                    if name == "_" { continue; }  // discard member: no instruction
                    let lane = base + i as u8;
                    let sel: i64 = if i == 0 { 0x7610 } else { 0x7632 };
                    // lanes are freshly rebound by prepare_group above, so
                    // the in-place 4th operand self-reads an unwritten reg
                    // -- dead upper half by lane contract; declare the
                    // waiver for the BUG-118 gate (docs on the field).
                    alloc.dead_read_ok.insert((lane, sel));
                    out.push(make_insn(addr + 16 * out.len() as u32, "PRMT",
                        vec![op_reg(lane), op_reg(srcn), Operand::Imm32(sel), op_reg(lane)], guard.clone()));
                }
                return Ok(out);
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

    // b9 phase-3 #14 (b9p16): mov.b32 %r, {lo16,hi16} — half pack.
    // Vendor law (anchors packonly -O0 /*00a0*/ {x,x} a==b and /*0130*/
    // {x,y}, corpus_p15 -O0 /*0330*/, corpus_p06 /*02f0*/):
    //   PRMT d, Rlo, 0x5410, Rhi     (d = Rlo.b1b0 | Rhi.b1b0 << 16)
    // Replaces the pre-b9p16 SILENT-WRONG fallthrough: the group was
    // aliased to its lo-member pair base by ptx_op_to_sass and a plain MOV
    // kept only that half (green-lie corpus p15_half2 dropped the hi half;
    // repro packonly.ptx: {rs,rs} -> MOV r,r instead of r = lo|lo<<16).
    // Every OTHER mov.* with a group source is fail-closed (unattested).
    if let PtxOperand::RegGroup(regs) = src {
        let shapes_ok = insn.opcode == "mov.b32" && regs.len() == 2
            && regs.iter().all(|r| alloc.is_ptx_reg_name(r) && !alloc.is_64bit(r) && r != "_");
        if !shapes_ok {
            anyhow::bail!(
                "{}: group source {:?}: only mov.b32 d, {{lo16,hi16}} half-pack of two registers is vendor-attested (b9 phase-3)",
                insn.opcode, regs);
        }
        let rd = match d {
            PtxOperand::Reg(n) if !alloc.is_64bit(n) => alloc.resolve(n),
            other => anyhow::bail!(
                "mov.b32 half-pack dst {:?}: only a 32-bit register dst is vendor-attested", other),
        };
        let lo = alloc.resolve(&regs[0]);
        let hi = alloc.resolve(&regs[1]);
        return Ok(vec![make_insn(addr, "PRMT",
            vec![op_reg(rd), op_reg(lo), Operand::Imm32(0x5410), op_reg(hi)], guard)]);
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

/// b9 phase-3 #16 (b9p18): setp.{cmp}.f16 -> HSETP2 lane (FINDING F-1 iter46:
/// pre-lane these went through generic FSETP f32 = silently wrong semantics),
/// and setp.{eq,ne}.b16 -> PRMT zee-extend + ISETP.U32 lane (pre-lane emitted
/// signed-no-qualifier ISETP with no zero-extension = silently wrong).
/// Vendor law is -O0-anchored (ptxas 13.3 sm_103a, work/b9p18/probes):
///   setp.{lt,le,eq,ne,gt,ge}.f16 p, a, b  ->  HSETP2.{CMP}.AND p, PT, Ra.H0_H0, Rb.H0_H0, PT
///   (cmp code bits76-79 = LT1/EQ2/LE3/GT4/NE5/GE6, +8 = U; table groups
///    AND,{LT,LE,EQ,GT,GE} new + AND,NE reg,reg union-widen; anchors
///    corpus p06 0x5f0/0x300 + probe_setpf16/b/c + probe_imm)
///   setp.{eq,ne}.b16 p, a, b  ->  PRMT ta,a,0x7710,RZ ; PRMT tb,b,0x7710,RZ ;
///                                 ISETP.{EQ|NE}.U32.AND p, PT, ta, tb, PT
///   setp.{eq,ne}.b16 p, a, 0  ->  PRMT ta,a,0x7710,RZ ; ISETP.{EQ|NE}.U32.AND p, PT, ta, RZ, PT
///   (anchors corpus p06 O0 + probe_setpb16 O0/O3)
/// FAIL-CLOSED (no vendor anchor): setp.f16x2 (dual-pred vector form),
/// setp.bf16/.bf16x2 (BF16_V2 cmp groups missing from tables), f16 with
/// immediate operand (not expressible in accepted PTX: ptxas 13.3 rejects
/// both literal spellings), b16 ordered cmps / non-zero imm, guarded forms
/// pass the guard through but stay style-tight (vm guard=7 unguarded only).
fn lower_setp(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<Vec<Instruction>> {
    let op = insn.opcode.as_str();
    let parts: Vec<&str> = op.split('.').collect();
    let cmp_tok = parts.get(1).copied().unwrap_or("");
    let is = |t: &str| parts.iter().any(|p| *p == t);

    if is("f16x2") || is("bf16") || is("bf16x2") {
        anyhow::bail!("{}: vector/bf16 setp has no vendor-anchored sm_103a lowering (b9 phase-3 #16)", op);
    }
    if is("f16") {
        let cmp = match cmp_tok {
            "lt" => "LT", "le" => "LE", "eq" => "EQ",
            "ne" => "NE", "gt" => "GT", "ge" => "GE",
            _ => anyhow::bail!("{}: f16 cmp '{}' unanchored (lane covers lt/le/eq/ne/gt/ge only)", op, cmp_tok),
        };
        let pd = match ptx_op_to_sass(&insn.operands[0], alloc, false) {
            Operand::Pred { num, neg: false } => num,
            other => anyhow::bail!("{}: dst {:?}: only a plain predicate dst is vendor-attested", op, other),
        };
        let mut regs = |i: usize| -> Result<u8> {
            match insn.operands.get(i) {
                Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) && !alloc.is_64bit(n) => Ok(alloc.resolve(n)),
                other => anyhow::bail!("{}: src{} {:?}: only 16-bit register operands are vendor-attested", op, i, other),
            }
        };
        let ra = regs(1)?;
        let rb = regs(2)?;
        let mut ins = make_insn(addr, &format!("HSETP2.{}.AND", cmp),
            vec![Operand::Pred { num: pd, neg: false }, op_pt(), op_reg(ra), op_reg(rb), op_pt()], guard.clone());
        let g = guard_text(&guard);
        ins.raw_text = format!("{}HSETP2.{}.AND P{}, PT, R{}.H0_H0, R{}.H0_H0, PT ;", g, cmp, pd, ra, rb);
        return Ok(vec![ins]);
    }
    if is("b16") {
        let cmp = match cmp_tok {
            "eq" => "EQ", "ne" => "NE",
            _ => anyhow::bail!("{}: b16 cmp '{}' unanchored (lane covers eq/ne only)", op, cmp_tok),
        };
        let pd = match ptx_op_to_sass(&insn.operands[0], alloc, false) {
            Operand::Pred { num, neg: false } => num,
            other => anyhow::bail!("{}: dst {:?}: only a plain predicate dst is vendor-attested", op, other),
        };
        let za = alloc.gpr("%setp_b16_za");
        let ra = match insn.operands.get(1) {
            Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) && !alloc.is_64bit(n) => alloc.resolve(n),
            other => anyhow::bail!("{}: src1 {:?}: only a 16-bit register is vendor-attested", op, other),
        };
        let mut out = Vec::with_capacity(3);
        out.push(make_insn(addr, "PRMT",
            vec![op_reg(za), op_reg(ra), Operand::Imm32(0x7710), op_rz()], guard.clone()));
        let b_op = match insn.operands.get(2) {
            Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) && !alloc.is_64bit(n) => {
                let zb = alloc.gpr("%setp_b16_zb");
                let rb = alloc.resolve(n);
                out.push(make_insn(addr + 16, "PRMT",
                    vec![op_reg(zb), op_reg(rb), Operand::Imm32(0x7710), op_rz()], guard.clone()));
                op_reg(zb)
            }
            Some(PtxOperand::IntImm(0)) => op_rz(),
            other => anyhow::bail!("{}: src2 {:?}: only a 16-bit register or zero immediate is vendor-attested", op, other),
        };
        let n = out.len() as u32;
        out.push(make_insn(addr + n * 16, &format!("ISETP.{}.U32.AND", cmp),
            vec![Operand::Pred { num: pd, neg: false }, op_pt(), op_reg(za), b_op, op_pt()], guard));
        return Ok(out);
    }

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

    Ok(vec![make_insn(addr, &opf, vec![pd, op_pt(), a, b, op_pt()], guard)])
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
    let has_sat = parts[1..].contains(&"sat");
    let type_parts: Vec<&str> = parts[1..].iter()
        .filter(|p| matches!(**p, "u8"|"s8"|"u16"|"s16"|"u32"|"s32"|"u64"|"s64"|"f16"|"f16x2"|"bf16"|"bf16x2"|"f32"|"f64"|"b8"|"b16"|"b32"|"b64"))
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
        // b9 phase-3 #14 (b9p16): cvt.f32.f16 -> HADD2.F32 widening (vendor
        // never uses F2F for f16->f32 on sm_103a in-corpus; anchors
        // corpus_p15 -O0 /*02c0,02f0*/ + ptxas bit-exact pin encoding.rs).
        // The .H0_H0 source suffix is read off raw operand text by the ASM
        // parser (encoder op_hsel); spelled explicitly like HalfAdd.
        ("f32", "f16") => {
            let (dr, ar) = match (regnum(&d), regnum(&a)) {
                (Some(dr), Some(ar)) => (dr, ar),
                _ => return unattested(),
            };
            let mut ins = make_insn(addr, "HADD2.F32",
                vec![op_reg(dr), op_reg(255), op_reg(ar)], guard.clone());
            let g = guard_text(&guard);
            ins.raw_text = format!("{}HADD2.F32 R{}, -RZ, R{}.H0_H0 ;", g, dr, ar);
            Some(Ok(vec![ins]))
        }
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
        // b9 phase-3 #8 sub-word + f16 chain vendor anchors (probes
        // work/b9p10/cv{1,2,3}_O0):
        //   f16<-f32 (rn):        F2F.F16.F32 d, a                 (cv1 0x150)
        //   f16x2<-2*f32 (rn):    F2FP.F16.F32.PACK_AB d, a, b     (cv1 0x1e0)
        //   f32<-s16 (rn):        I2F.S16 d, a                     (cv3 0x150)
        //   u32<-u16:             PRMT d, a, 0x7710, RZ            (cv1 0x150)
        //   s32<-s16:             PRMT d, a, 0x9910, RZ            (cv1 0x150)
        //   u16<-u32:             PRMT d, a, 0x7610, d  (dst self 4th, cv1)
        //   u64<-u16:             PRMT dlo, a, 0x7710, RZ ; MOV dhi, RZ (cv2)
        //   s32<-f64 (rzi):       F2I.F64.TRUNC d, a_pair          (cv1 0x150)
        //   s16<-f32 (rni.sat):   F2I.S16.NTZ d, a                 (cv2)
        ("f16", "f32") if rounding == Some("rn") && !has_sat => {
            Some(Ok(vec![make_insn(addr, "F2F.F16.F32", vec![d, a], guard.clone())]))
        }
        ("f16x2", "f32") if rounding == Some("rn") && !has_sat => {
            let b = match insn.operands.get(2) {
                Some(o) => ptx_op_to_sass(o, alloc, false),
                None => return unattested(),
            };
            Some(Ok(vec![make_insn(addr, "F2FP.F16.F32.PACK_AB", vec![d, a, b], guard.clone())]))
        }
        // b9 phase-3 #9: bf16<-f32 rn -> F2F.BF16.F32 (anchor corpus p16
        // -O0: 0x200/0x220; -O3 fuses pairs into F2FP.BF16.F32.PACK_AB --
        // documented divergence like f16x2).
        ("bf16", "f32") if rounding == Some("rn") && !has_sat => {
            Some(Ok(vec![make_insn(addr, "F2F.BF16.F32", vec![d, a], guard.clone())]))
        }
        ("f32", "s16") if rounding == Some("rn") && !has_sat => {
            Some(Ok(vec![make_insn(addr, "I2F.S16", vec![d, a], guard.clone())]))
        }
        ("u32", "u16") => {
            Some(Ok(vec![make_insn(addr, "PRMT", vec![d, a, Operand::Imm32(0x7710), op_rz()], guard.clone())]))
        }
        ("s32", "s16") => {
            Some(Ok(vec![make_insn(addr, "PRMT", vec![d, a, Operand::Imm32(0x9910), op_rz()], guard.clone())]))
        }
        ("u16", "u32") => {
            // vendor reads the dst back as PRMT's fourth operand (cv1 anchor)
            let dnum = match &d { Operand::Reg { num, .. } => *num, _ => return unattested() };
            // first-touch self-read of the freshly bound u32 dst: dead
            // upper half by contract (cv1); declared to the BUG-118 gate.
            alloc.dead_read_ok.insert((dnum, 0x7610));
            Some(Ok(vec![make_insn(addr, "PRMT", vec![d, a, Operand::Imm32(0x7610), op_reg(dnum)], guard.clone())]))
        }
        ("u64", "u16") => {
            let (dlo, dhi) = match &insn.operands[0] {
                PtxOperand::Reg(name) => alloc.gpr_pair(name),
                _ => return unattested(),
            };
            match regnum(&a) {
                Some(alo) => Some(Ok(vec![
                    make_insn(addr, "PRMT", vec![op_reg(dlo), op_reg(alo), Operand::Imm32(0x7710), op_rz()], guard.clone()),
                    make_insn(addr + 16, "MOV", vec![op_reg(dhi), op_rz()], guard),
                ])),
                None => unattested(),
            }
        }
        ("s32", "f64") if rounding == Some("rzi") && !has_sat =>
            one!("F2I.F64.TRUNC".to_string(), d, a),
        ("s16", "f32") if rounding == Some("rni") && has_sat =>
            one!("F2I.S16.NTZ".to_string(), d, a),
        _ => unattested(),
    }
}

/// Suffix filtered to row-backed forms (see mem_width_suffix callers):
/// (st|S|T) S8 ld OK; S8 st GLOBAL missing, S16 st/ld GLOBAL missing.
fn rowbacked_width(base: &str, w: Option<&'static str>) -> Result<()> {
    match (base, w) {
        ("LDG", Some("S16")) | ("STG", Some("S8")) | ("STG", Some("S16")) =>
            anyhow::bail!("{} no .{} table row on sm_103a (asm fail-closed upstream; unattested in corpus)", base, w.unwrap()),
        _ => Ok(()),
    }
}

/// b9 phase-3 #14 (b9p16): scalar sub-32-bit memory width. Pre-lane these
/// lifted as PLAIN 32-bit ops — st.global.b8 stored 4 bytes, ld.shared.b64
/// loaded only the low half (silent wrong-width in ~14 green corpus files:
/// stg_u8/test34/test39/test8_16/p11/p12/b_mbarrier/ucgate/...). Vendor law
/// (widths.ptx + readshared2/stg_u8 -O0 anchors): unsigned -> U8/U16,
/// signed -> S8/S16. Returns None for 32-bit (or wider, handled elsewhere)
/// opcodes. STG .S8/.S16 and LDG .S16 have no table rows on sm_103a (asm
/// fail-closed upstream); only the row-backed forms are emitted.
fn mem_width_suffix(opcode: &str) -> Option<&'static str> {
    if opcode.ends_with(".b8") || opcode.ends_with(".u8") { Some("U8") }
    else if opcode.ends_with(".s8") { Some("S8") }
    else if opcode.ends_with(".b16") || opcode.ends_with(".u16") { Some("U16") }
    else if opcode.ends_with(".s16") { Some("S16") }
    else { None }
}

/// Scalar ld.shared/st.shared (SharedScalar, b9 phase-3 #14 / b9p16):
/// honest-width single op. `LDS{w} Rd, [Ra+off]` / `STS{w} [Ra+off], Rv`.
/// 64-bit data rides the even pair base (LDS.64/STS.64), 8/16-bit per
/// mem_width_suffix. Everything else (v-forms handled upstream, .f16 etc.)
/// hard-fails: unattested.
fn lower_shared_scalar(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>, store: bool,
) -> Result<Vec<Instruction>> {
    let w = mem_width_suffix(&insn.opcode);
    let wide64 = insn.opcode.ends_with(".b64") || insn.opcode.ends_with(".u64")
        || insn.opcode.ends_with(".s64") || insn.opcode.ends_with(".f64");
    let thirtytwo = insn.opcode.ends_with(".b32") || insn.opcode.ends_with(".u32")
        || insn.opcode.ends_with(".s32") || insn.opcode.ends_with(".f32");
    if w.is_none() && !wide64 && !thirtytwo {
        anyhow::bail!("{}: scalar shared width unattested (b9 phase-3 #14)", insn.opcode);
    }
    let sfx = if wide64 { ".64".to_string() } else { w.map_or(String::new(), |x| format!(".{}", x)) };
    let (ori, dri) = if store { (0usize, 1usize) } else { (1usize, 0usize) };
    let data = ptx_op_to_sass(&insn.operands[dri], alloc, false);
    let addr_op = ptx_op_to_sass(&insn.operands[ori], alloc, false);
    let ops = if store { vec![addr_op, data] } else { vec![data, addr_op] };
    Ok(vec![make_insn(addr, &format!("{}{}", if store { "STS" } else { "LDS" }, sfx), ops, guard)])
}

fn lower_ld_global(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<Vec<Instruction>> {
    let is_v4 = insn.opcode.contains(".v4.");
    let is_v2 = insn.opcode.contains(".v2.");
    let is_64 = insn.opcode.contains("u64") || insn.opcode.contains("b64") || insn.opcode.contains("f64");


    // b9p12 (phase-3 #10): ld.volatile.global.b32 -> LDG.E.EF (anchor corpus
    // p02_cacheops O0 0x530; rows = b4fill4 LD.EF family). Only the 32-bit
    // scalar form is attested; vector/wide volatile -> hard fail (rc=1).
    let is_volatile = insn.opcode.starts_with("ld.volatile.");
    if is_volatile && (is_v4 || is_v2 || is_64) {
        anyhow::bail!(
            "ld.volatile.global wide/vector form has no vendor-anchored lowering ({}); only .b32 attested (b9p12)",
            insn.opcode);
    }

    // b9 phase-3 #12 (b9p14): v2 of 64-bit members = 128-bit op
    // (LDG.E.128; probe q3 + ptx_own p29-class law), same selection law as
    // the ld.shared path and the st.global mirror below.
    let wide128 = is_v4 || (is_v2 && is_64);
    let width = mem_width_suffix(&insn.opcode);
    if is_volatile && width.is_some() {
        // wide/thin-volatile combos are unattested (vol doctrine: hard fail)
        anyhow::bail!("ld.volatile with sub-32-bit width ({}) has no vendor-anchored lowering (b9 phase-3 #14)", insn.opcode);
    }
    let suffix = if is_volatile { ".E.EF".to_string() } else if wide128 { ".E.128".to_string() } else if is_v2 || is_64 { ".E.64".to_string() }
        else if let Some(w) = width { format!(".E.{}", w) } else { ".E".to_string() };

    // Resolve address register FIRST (before allocating dst which may reuse it)
    let base_addr = &insn.operands[1];
    let (addr_reg_name, base_reg_num, offset) = match base_addr {
        PtxOperand::Addr { base, offset } => (base.clone(), alloc.resolve(base), *offset),
        PtxOperand::Reg(name) => (name.clone(), alloc.resolve(name), 0i64),
        _ => (String::new(), 0, 0),
    };

    if !addr_reg_name.is_empty() && alloc.is_64bit(&addr_reg_name) {
        // BUG-118: the pair is reclaimable ONLY at the name's textual last
        // use; an early free is re-issued by gpr_pair while the dropped
        // name's later use silently re-binds a fresh never-written pair
        // (deterministic 700 on silicon, b10 PHASE-2c pd64/pi64/pr_rw).
        alloc.free_pair_if_dead(&addr_reg_name);
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
    rowbacked_width("LDG", width)?;
    pre.push(make_insn(addr + 16 * pre.len() as u32, &format!("LDG{}", suffix), vec![d, desc_op], guard));
    Ok(pre)
}

fn lower_st_global(addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: Option<Guard>) -> Result<Vec<Instruction>> {
    let is_v4 = insn.opcode.contains(".v4.");
    let is_v2 = insn.opcode.contains(".v2.");
    let is_64 = insn.opcode.contains("u64") || insn.opcode.contains("b64") || insn.opcode.contains("f64");

    // b9 phase-3 #12 (b9p14): st.global.v2.b64 -> STG.E.128 (probe q4 +
    // corpus p13/p29 -O0), same member-width law as the ld.global mirror.
    let wide128 = is_v4 || (is_v2 && is_64);
    let width = mem_width_suffix(&insn.opcode);
    let suffix: String = if wide128 { ".E.128".to_string() } else if is_v2 || is_64 { ".E.64".to_string() }
        else if let Some(w) = width { format!(".E.{}", w) } else { ".E".to_string() };

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
        if is_v2 || is_v4 {
            anyhow::bail!(
                "st.global immediate data in vector stores is not vendor-attested ({}); b9 phase-3",
                insn.opcode);
        }
        if is_64 {
            // b9 phase-3 #12 (b9p14): st.global.{b64,u64,s64} imm store:
            // materialize the full 64-bit immediate into an even-aligned
            // pair (lo then hi, two's-complement split; IMAD.MOV.U32 is the
            // canonical imm form -- nvdisasm prints plain MOV) immediately
            // before the STG. Vendor anchors: corpus s_u64/v_p1i64 -O0
            // (42 -> R6=0x2a/R7=0x0) + probes q2 -O0 (-1 -> 0xffffffff/
            // 0xffffffff, 200000 -> 0x30d40/0x0). -O3 diverges via
            // const-materialization fold (HFMA2 classes, recorded).
            let uv = v as u64;
            let (lo_r, hi_r) = alloc.gpr_pair(&format!("__stimm64_{}", addr));
            out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                vec![op_reg(lo_r), op_rz(), op_rz(), Operand::Imm32((uv & 0xffff_ffff) as i64)], guard.clone()));
            out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                vec![op_reg(hi_r), op_rz(), op_rz(), Operand::Imm32((uv >> 32) as i64)], guard.clone()));
            src = op_reg(lo_r);
        } else {
            let rn = alloc.gpr(&format!("__stimm_{}", addr));
            out.push(make_insn(addr + 16 * out.len() as u32, "IMAD.MOV.U32",
                vec![op_reg(rn), op_rz(), op_rz(), Operand::Imm32(v)], guard.clone()));
            src = op_reg(rn);
        }
    }
    rowbacked_width("STG", width)?;
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

// ── b9p12 (phase-3 #10) lowerings: intmisc / bar.red / barrier / trap / misc ──
// Vendor anchors: work/b9p12/probes (corpus p19/p20/v55/p30/p32/p_cctl/p21 O0
// cubins, both opt levels noted), form probes work/b9p12/t/{bar,bar2,bfe_*}.
// All shapes outside the anchored set return Ok(None) -> unsupported list
// (fail-closed, never silent).

/// popc.b32: vendor -O0 idiom keeps the identity AND ladder (anchor p19
/// 0x350..0x370: LOP3 m=maker(~0); LOP3 t=a&m; POPC d,t).
fn lower_popc32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match ptx_op_to_sass_opt(insn.operands.get(1), alloc) { Some(o) => o, None => return Ok(None) };
    let t = alloc.gpr("$popc32_t");
    let out = vec![
        make_insn(addr, "LOP3.LUT", vec![op_reg(t), op_rz(), op_rz(), op_rz(), op_imm(0x33), op_not_pt()], None),
        make_insn(addr + 16, "LOP3.LUT", vec![op_reg(t), a, op_reg(t), op_rz(), op_imm(0xc0), op_not_pt()], None),
        make_insn(addr + 32, "POPC", vec![op_reg(d), op_reg(t)], None),
    ];
    Ok(Some((out, 3)))
}

/// brev.b32: anchor p19 0x380-0x3a0 (BREV; SHF.R.U32.HI by RZ; SGXT.U32 0x20).
fn lower_brev32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let t = alloc.gpr("$brev32_t");
    let out = vec![
        make_insn(addr, "BREV", vec![op_reg(t), op_reg(a)], None),
        make_insn(addr + 16, "SHF.R.U32.HI", vec![op_reg(t), op_rz(), op_rz(), op_reg(t)], None),
        make_insn(addr + 32, "SGXT.U32", vec![op_reg(d), op_reg(t), op_imm(0x20)], None),
    ];
    Ok(Some((out, 3)))
}

/// clz.b32: anchor p19 0x3c0-0x3d0 (FLO.U32; IADD3 31-x). b9p12 NOTE: phase-1
/// mapped clz.b32 to a single FLO.U32, dropping 31-x -- semantic bug fixed
/// here (FLO.U32 returns msb-index, PTX clz = count of leading zeros).
fn lower_clz32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let t = alloc.gpr("$clz32_t");
    let out = vec![
        make_insn(addr, "FLO.U32", vec![op_reg(t), op_reg(a)], None),
        make_insn(addr + 16, "IADD3", vec![op_reg(d), op_pt(), op_pt(), op_neg_reg(t), op_imm(0x1f), op_rz()], None),
    ];
    Ok(Some((out, 2)))
}

// ── b9p13 (phase-3 #11) lowerings: sat / mufu lane ─────────────────────────
// Vendor anchors: corpus p27_sat / p18_fastmath / mufu1 O0 cubins (this
// workdir work/b9p13/probes, regenerated byte-identical from b9census PTX
// with ptxas 13.3) + add.sat word-probes work/b9p13/t/satprobes (O0+O3).
// All shapes outside the anchored set return Ok(None) -> unsupported
// (fail-closed, never silent). Float immediates are emitted in the
// FSETP/FMUL/FADD FI slots (O3-anchored inline-imm forms; the -O0
// const-materialization MOV ladder is vendor alloc noise, see report sec.3).

/// f32 immediate as FloatImm (cubit stores f64 bits in Operand::FloatImm).
fn op_f32(x: f32) -> Operand { Operand::FloatImm((x as f64).to_bits()) }

/// add.sat.s32 d, a, b: IADD3 + 2x PLOP3.LUT with R.SIGN sign-inputs
/// (overflow detectors, LUT 0x2 = !a&!b&r pos-overflow, LUT 0x40 =
/// a&b&!r neg-overflow) + 2x SEL clamps. Anchor: corpus p27 O0 0x290-0x2d0
/// (identical role shape at -O3, modulo IMAD.IADD for the sum and .reuse).
/// New encoder row PLOP3_P_P_R_R_R_II_II (76-anchor exact word fit,
/// work/b9p13/t/plop3sign_samples.json). Reg operands only; imm/guard ->
/// None. Destination is the SIGN-source for both PLOP3s (pre-SEL sum).
fn lower_addsat_s32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let b = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };
    let pp = alloc.pred("$sat_pp");
    let pn = alloc.pred("$sat_pn");
    let pl = |off: u32, pd: u8, lut: i64| make_insn(addr + off, "PLOP3.LUT",
        vec![Operand::Pred { num: pd, neg: false }, op_pt(),
             op_reg(a), op_reg(b), op_reg(d), op_imm(lut), op_imm(0)], None);
    let out = vec![
        make_insn(addr, "IADD3", vec![op_reg(d), op_pt(), op_pt(), op_reg(a), op_reg(b), op_rz()], None),
        pl(16, pp, 0x2),
        pl(32, pn, 0x40),
        make_insn(addr + 48, "SEL", vec![op_reg(d), op_reg(d), op_imm(0x7fffffff), Operand::Pred { num: pp, neg: true }], None),
        make_insn(addr + 64, "SEL", vec![op_reg(d), op_reg(d), op_imm(0x80000000), Operand::Pred { num: pn, neg: true }], None),
    ];
    Ok(Some((out, 5)))
}

/// sin.approx.f32 / cos.approx.f32: FMUL.RZ t, a, 0x1.921fb54442d18p-4 (1/2pi)
/// ; MUFU.SIN/COS d, t (anchors corpus p18 O0 0x4d0-0x4e0 / 0x500-0x510;
/// O0==-O3 form). Phase-1 Singles dropped the 1/2pi scale = wrong-function
/// semantic bug (MUFU.SIN/COS operate on turn units).
fn lower_sincos_f32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>, cos: bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let t = alloc.gpr("$sincos_t");
    let out = vec![
        make_insn(addr, "FMUL.RZ", vec![op_reg(t), op_reg(a), op_f32(0.15915494)], None),
        make_insn(addr + 16, if cos { "MUFU.COS" } else { "MUFU.SIN" }, vec![op_reg(d), op_reg(t)], None),
    ];
    Ok(Some((out, 2)))
}

/// ex2.approx.f32: vendor -O0 6-op range-scaled form (anchor corpus p18 O0
/// 0x2a0-0x320; const -126 materialization MOV folded to the FI slot, O3
/// anchor 0xb0/0x360): if a < -126: EX2(a*0.5)^2 else EX2(a).
fn lower_ex2approx_f32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let p = alloc.pred("$ex2_p");
    let t = alloc.gpr("$ex2_t");
    let t2 = alloc.gpr("$ex2_t2");
    let out = vec![
        make_insn(addr, "FSETP.LT.AND", vec![Operand::Pred { num: p, neg: false }, op_pt(), op_reg(a), op_f32(-126.0), op_pt()], None),
        make_insn(addr + 16, "FMUL", vec![op_reg(t), op_reg(a), op_f32(0.5)], None),
        make_insn(addr + 32, "FSEL", vec![op_reg(t), op_reg(t), op_reg(a), Operand::Pred { num: p, neg: false }], None),
        make_insn(addr + 48, "MUFU.EX2", vec![op_reg(t), op_reg(t)], None),
        make_insn(addr + 64, "FMUL", vec![op_reg(t2), op_reg(t), op_reg(t)], None),
        make_insn(addr + 80, "FSEL", vec![op_reg(d), op_reg(t2), op_reg(t), Operand::Pred { num: p, neg: false }], None),
    ];
    Ok(Some((out, 6)))
}

/// lg2.approx.f32: vendor -O0 7-op denormal-guard form (anchor corpus p18 O0
/// 0x3e0-0x4a0; consts 2^-126 / 2^24 / -24 folded to FI slots, O3 anchor
/// 0xc0 shows the plain MUFU.LG2 elision when ptxas proves the range -- we
/// always emit the safe form, documented divergence).
fn lower_lg2approx_f32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let p = alloc.pred("$lg2_p");
    let t1 = alloc.gpr("$lg2_t1");
    let t2 = alloc.gpr("$lg2_t2");
    let t3 = alloc.gpr("$lg2_t3");
    let out = vec![
        make_insn(addr, "FADD", vec![op_reg(t1), op_neg_reg(255), Operand::Reg { num: a, neg: false, abs: true, inv: false, reuse: false }], None),
        make_insn(addr + 16, "FSETP.LT.AND", vec![Operand::Pred { num: p, neg: false }, op_pt(), op_reg(t1), op_f32(f32::from_bits(0x00800000)), op_pt()], None),
        make_insn(addr + 32, "FMUL", vec![op_reg(t2), op_reg(a), op_f32(f32::from_bits(0x4b800000))], None),
        make_insn(addr + 48, "FSEL", vec![op_reg(t2), op_reg(t2), op_reg(a), Operand::Pred { num: p, neg: false }], None),
        make_insn(addr + 64, "MUFU.LG2", vec![op_reg(t2), op_reg(t2)], None),
        make_insn(addr + 80, "FADD", vec![op_reg(t3), op_reg(t2), op_f32(-24.0)], None),
        make_insn(addr + 96, "FSEL", vec![op_reg(d), op_reg(t3), op_reg(t2), Operand::Pred { num: p, neg: false }], None),
    ];
    Ok(Some((out, 7)))
}

/// div.approx.f32 d, a, b: vendor -O0 8-op form (anchors corpus mufu1 O0
/// 0x1c0-0x280 + p18 O0 0xaa0..; consts folded to FI slots): scale both
/// operands by 2^24 when |b| < 2^-126, then rcp(b)*a. -O3 folds constant
/// divisors to reciprocal-multiply (documented divergence; reg-divisor
/// keeps this exact shape).
fn lower_divapprox_f32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let b = match reg_of(insn.operands.get(2), alloc) { Some(r) => r, None => return Ok(None) };
    let p = alloc.pred("$div_p");
    let tab = alloc.gpr("$div_ab");
    let tb = alloc.gpr("$div_tb");
    let ta = alloc.gpr("$div_ta");
    let out = vec![
        make_insn(addr, "FADD", vec![op_reg(tab), op_neg_reg(255), Operand::Reg { num: b, neg: false, abs: true, inv: false, reuse: false }], None),
        make_insn(addr + 16, "FSETP.LT.AND", vec![Operand::Pred { num: p, neg: false }, op_pt(), op_reg(tab), op_f32(f32::from_bits(0x00800000)), op_pt()], None),
        make_insn(addr + 32, "FMUL", vec![op_reg(tb), op_reg(b), op_f32(f32::from_bits(0x4b800000))], None),
        make_insn(addr + 48, "FSEL", vec![op_reg(tb), op_reg(tb), op_reg(b), Operand::Pred { num: p, neg: false }], None),
        make_insn(addr + 64, "MUFU.RCP", vec![op_reg(tb), op_reg(tb)], None),
        make_insn(addr + 80, "FMUL", vec![op_reg(ta), op_reg(a), op_f32(f32::from_bits(0x4b800000))], None),
        make_insn(addr + 96, "FSEL", vec![op_reg(ta), op_reg(ta), op_reg(a), Operand::Pred { num: p, neg: false }], None),
        make_insn(addr + 112, "FMUL", vec![op_reg(d), op_reg(ta), op_reg(tb)], None),
    ];
    Ok(Some((out, 8)))
}

/// helper: 32-bit PTX operand -> SASS Reg or Imm32 (fail -> None).
fn ptx_op_to_sass_opt(op: Option<&PtxOperand>, alloc: &mut RegAlloc) -> Option<Operand> {
    match op {
        Some(PtxOperand::Reg(n)) if alloc.is_ptx_reg_name(n) => Some(op_reg(alloc.resolve(n))),
        Some(PtxOperand::IntImm(v)) => Some(Operand::Imm32(*v)),
        _ => None,
    }
}

/// bfe.u32, IMMEDIATE pos/len only: anchor corpus p20 O0 0x350-0x3c0
/// (pos|len<<8 const-materialization dance kept verbatim, +PRMT byte-split +
/// SHF.R.U32.HI + SGXT.U32). Reg pos/len, bfe.s32, guarded -> None.
fn lower_bfe32(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let d = match reg_of(insn.operands.get(0), alloc) { Some(r) => r, None => return Ok(None) };
    let a = match reg_of(insn.operands.get(1), alloc) { Some(r) => r, None => return Ok(None) };
    let pos = match insn.operands.get(2) {
        Some(PtxOperand::IntImm(v)) if (0..=255).contains(v) => *v,
        _ => return Ok(None),
    };
    let len = match insn.operands.get(3) {
        Some(PtxOperand::IntImm(v)) if (1..=255).contains(v) => *v,
        _ => return Ok(None),
    };
    let tl = alloc.gpr("$bfe_len");
    let tp2 = alloc.gpr("$bfe_pos2");
    let tl2 = alloc.gpr("$bfe_len2");
    let t3 = alloc.gpr("$bfe_sh");
    // pos==0 folds to RZ inline (no MOV, LOP3 c-slot = RZ): 7-op form, anchor
    // bfe_probe.cubin (0,31) 0x210-0x270; pos!=0: 8-op form (corpus p20 4,12).
    let mut out: Vec<Instruction> = vec![
        make_insn(addr, "MOV", vec![op_reg(tl), op_imm(len)], None),
        make_insn(addr + 16, "SHF.L.U32", vec![op_reg(tl), op_reg(tl), op_imm(0x8), op_rz()], None),
    ];
    let mut a2 = 32u32;
    if pos != 0 {
        let tp = alloc.gpr("$bfe_pos");
        out.push(make_insn(addr + a2, "MOV", vec![op_reg(tp), op_imm(pos)], None));
        a2 += 16;
        out.push(make_insn(addr + a2, "LOP3.LUT", vec![op_reg(tl), op_reg(tl), op_imm(0xff00), op_reg(tp), op_imm(0xe2), op_not_pt()], None));
    } else {
        out.push(make_insn(addr + a2, "LOP3.LUT", vec![op_reg(tl), op_reg(tl), op_imm(0xff00), op_rz(), op_imm(0xe2), op_not_pt()], None));
    }
    a2 += 16;
    out.push(make_insn(addr + a2, "PRMT", vec![op_reg(tp2), op_rz(), op_imm(0x4), op_reg(tl)], None));
    out.push(make_insn(addr + a2 + 16, "PRMT", vec![op_reg(tl2), op_rz(), op_imm(0x5), op_reg(tl)], None));
    out.push(make_insn(addr + a2 + 32, "SHF.R.U32.HI", vec![op_reg(t3), op_rz(), op_reg(tp2), op_reg(a)], None));
    out.push(make_insn(addr + a2 + 48, "SGXT.U32", vec![op_reg(d), op_reg(t3), op_reg(tl2)], None));
    let n = out.len() as u32;
    Ok(Some((out, n)))
}

/// bar.red.{and,or}.pred d, b, s: anchor corpus v55 (0x2b0-0x2d0 AND,
/// 0x4f0-0x510 OR) + probe bar.ptx (imm bar id=1). WARPSYNC.ALL prefix;
/// barrier operand: immediate only (encoding is BAR_II_P); register barrier
/// forms unanchored -> fail-closed.
fn lower_barred(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>, or: bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let pd = match insn.operands.get(0) {
        Some(PtxOperand::Pred(n)) => alloc.pred(n),
        _ => return Ok(None),
    };
    let bar = match insn.operands.get(1) {
        Some(PtxOperand::IntImm(v)) if (0..=15).contains(v) => *v,
        _ => return Ok(None),
    };
    let ps = match insn.operands.get(2) {
        Some(PtxOperand::Pred(n)) => alloc.pred(n),
        _ => return Ok(None),
    };
    let op = if or { "BAR.RED.OR.DEFER_BLOCKING" } else { "BAR.RED.AND.DEFER_BLOCKING" };
    let out = vec![
        make_insn(addr, "WARPSYNC.ALL", vec![], None),
        make_insn(addr + 16, op, vec![op_imm(bar), Operand::Pred { num: ps, neg: false }], None),
        make_insn(addr + 32, "B2R.RESULT", vec![op_rz(), Operand::Pred { num: pd, neg: false }], None),
    ];
    Ok(Some((out, 3)))
}

/// Named-barrier collective pack shared by barrier.sync (non-aligned, with
/// count) and barrier.arrive (non-aligned, with count). Anchor corpus p21
/// O0 (0xe0-0x160 sync, 0x1c0-0x240 arrive): MOV id; MOV cnt; MOV -1;
/// WARPSYNC.COLLECTIVE.ALL `(L); SHF.L.U32 cnt<<0x10; LOP3 0xf8 pack
/// (cnt<<16 | 0xf | id); BAR.x R,R; SHF.R.U32; ENDCOLLECTIVE; L:.
fn lower_bar_pack(
    addr: u32, alloc: &mut RegAlloc, id: i64, cnt: i64, arrive: bool,
) -> Vec<Instruction> {
    let rid = alloc.gpr("$bar_id");
    let rcnt = alloc.gpr("$bar_cnt");
    let rmask = alloc.gpr("$bar_mask");
    let lbl = format!("BARS_{:x}_END", addr);
    let mut out: Vec<Instruction> = Vec::new();
    let mut a = addr;
    let mut push = |op: &str, ops: Vec<Operand>| {
        out.push(make_insn(a, op, ops, None));
        a += 16;
    };
    push("MOV", vec![op_reg(rid), op_imm(id)]);
    push("MOV", vec![op_reg(rcnt), op_imm(cnt)]);
    push("MOV", vec![op_reg(rmask), op_imm(-1)]);
    push("WARPSYNC.COLLECTIVE.ALL", vec![Operand::Label(lbl.clone())]);
    push("SHF.L.U32", vec![op_reg(rcnt), op_reg(rcnt), op_imm(0x10), op_rz()]);
    push("LOP3.LUT", vec![op_reg(rcnt), op_reg(rcnt), op_imm(0xf), op_reg(rid), op_imm(0xf8), op_not_pt()]);
    if arrive {
        push("BAR.ARV", vec![op_reg(rcnt), op_reg(rcnt)]);
    } else {
        push("BAR.SYNC.DEFER_BLOCKING", vec![op_reg(rcnt), op_reg(rcnt)]);
    }
    push("SHF.R.U32", vec![op_reg(rcnt), op_reg(rcnt), op_imm(0x10), op_rz()]);
    push("ENDCOLLECTIVE", vec![]);
    push_gensym_label(&mut out, &lbl);
    out
}

/// bar.sync / barrier.sync[.aligned] (anchors: probe bar.ptx + bar2.ptx +
/// corpus p21). direct forms ALWAYS carry the WARPSYNC.ALL prefix (vendor
/// law, both opt levels); the non-aligned barrier.sync with a count is the
/// pack protocol. Everything else (reg barrier, guard) -> None.
fn lower_barsync(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>, aligned: bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let is_barrier_spell = insn.opcode.starts_with("barrier.");
    let imm_at = |i: usize| match insn.operands.get(i) {
        Some(PtxOperand::IntImm(v)) => Some(*v),
        _ => None,
    };
    let nops = insn.operands.len();
    // single-operand: WARPSYNC.ALL; BAR.SYNC.DEFER_BLOCKING imm
    if nops == 1 {
        let bar = match imm_at(0) { Some(v) => v, None => return Ok(None) };
        let out = vec![
            make_insn(addr, "WARPSYNC.ALL", vec![], None),
            make_insn(addr + 16, "BAR.SYNC.DEFER_BLOCKING", vec![op_imm(bar)], None),
        ];
        return Ok(Some((out, 2)));
    }
    if nops == 2 {
        let (Some(bar), Some(cnt)) = (imm_at(0), imm_at(1)) else { return Ok(None) };
        if is_barrier_spell && !aligned {
            // pack protocol (anchor p21 0xe0-0x160)
            let out = lower_bar_pack(addr, alloc, bar, cnt, false);
            return Ok(Some((out, 9)));
        }
        // bar.sync I,N / barrier.sync.aligned I,N -> direct II_II (probe bar.ptx/bar2)
        let out = vec![
            make_insn(addr, "WARPSYNC.ALL", vec![], None),
            make_insn(addr + 16, "BAR.SYNC.DEFER_BLOCKING", vec![op_imm(bar), op_imm(cnt)], None),
        ];
        return Ok(Some((out, 2)));
    }
    Ok(None)
}

/// barrier.arrive[.aligned] (anchors: corpus p21 pack; probe bar2: aligned =
/// WARPSYNC.ALL + BAR.ARV immI,immN direct; non-aligned = pack + BAR.ARV R,R).
fn lower_bararrive(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>, aligned: bool,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    let (Some(bar), Some(cnt)) = (
        match insn.operands.get(0) { Some(PtxOperand::IntImm(v)) => Some(*v), _ => None },
        match insn.operands.get(1) { Some(PtxOperand::IntImm(v)) => Some(*v), _ => None },
    ) else { return Ok(None) };
    if insn.operands.len() != 2 { return Ok(None); }
    if aligned {
        let out = vec![
            make_insn(addr, "WARPSYNC.ALL", vec![], None),
            make_insn(addr + 16, "BAR.ARV", vec![op_imm(bar), op_imm(cnt)], None),
        ];
        return Ok(Some((out, 2)));
    }
    let out = lower_bar_pack(addr, alloc, bar, cnt, true);
    Ok(Some((out, 9)))
}

/// discard.global.L2 [a], 128 = CCTL.E.RML2 [pair] (anchor corpus p_cctl O0
/// 0x200). Other extents/addresses/guards -> None.
fn lower_discard_l2(
    addr: u32, insn: &PtxInsn, alloc: &mut RegAlloc, guard: &Option<Guard>,
) -> Result<Option<(Vec<Instruction>, u32)>> {
    if guard.is_some() { return Ok(None); }
    if insn.operands.len() != 2 { return Ok(None); }
    match insn.operands.get(1) {
        Some(PtxOperand::IntImm(128)) => {}
        _ => return Ok(None),
    }
    let addr_op = match insn.operands.get(0) {
        Some(PtxOperand::Addr { base, offset }) if alloc.is_ptx_reg_name(base) && *offset == 0 => {
            Operand::Addr { base_reg: Some(alloc.resolve(base)), base_reg_suffix: None, ur_reg: None, offset: 0 }
        }
        _ => return Ok(None),
    };
    let out = vec![make_insn(addr, "CCTL.E.RML2", vec![addr_op], None)];
    Ok(Some((out, 1)))
}
