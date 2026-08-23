//! Table-driven PTX → SASS instruction mapping.
//!
//! Each PTX opcode pattern maps to a SASS template describing:
//! - The SASS opcode + modifiers
//! - How PTX operands map to SASS operand slots
//! - Any implicit operands (PT, RZ, etc.)
//!
//! ~70% of PTX instructions are "simple" 1:1 mappings handled by a single
//! table entry.  The remaining ~30% (64-bit ops, ld.param, MMA, cvt) use
//! special-case expansion variants.

/// How a SASS operand slot is filled from the PTX instruction.
#[derive(Debug, Clone, Copy)]
pub enum OpSlot {
    /// PTX operand at index `i`, as a register.
    Src(usize),
    /// PTX operand at index `i`, negated register.
    NegSrc(usize),
    /// PTX operand at index `i`, absolute value.
    AbsSrc(usize),
    /// PTX operand at index `i`, as immediate (pass through).
    Imm(usize),
    /// Implicit predicate PT (always-true, P7).
    PT,
    /// Implicit register RZ (zero, R255).
    RZ,
    /// Implicit negated-PT (!PT).
    NotPT,
}

/// What kind of SASS output a PTX rule produces.
#[derive(Debug, Clone)]
pub enum SassTemplate {
    /// One PTX instruction → one SASS instruction.
    Single {
        opcode: &'static str,
        slots: &'static [OpSlot],
    },

    /// 64-bit integer add (2 instructions: IADD3 + IADD3.X carry chain).
    Add64,
    /// 64-bit move (2 MOVs for lo/hi halves).
    Mov64,
    /// Load kernel parameter from constant bank.
    LoadParam,
    /// mov from special register (%tid.x etc.) → S2R.
    SpecialRegMov,
    /// Type conversion (cvt.*).
    Cvt,
    /// MMA instruction (complex opcode/type/shape extraction).
    Mma,
    /// Integer comparison → ISETP.
    ISetp,
    /// Float comparison → FSETP.
    FSetp,
    /// Shuffle → SHFL.
    Shfl,
    /// Global load (scalar or vector).
    LdGlobal,
    /// Global store (scalar or vector).
    StGlobal,
    /// Address space conversion (NOP on SM120).
    Nop,
    /// mul.wide.s32/u32 -> IMAD.WIDE / IMAD.WIDE.U32 (64-bit product pair,
    /// zero addend). Vendor form anchored in b9 phase-1 (nvdisasm byte-parity
    /// payload: IMAD.WIDE R2, R9, 0x4, R2 probe).
    MulWide { unsigned: bool },
    /// cvta.to.global.u64: register-pair alias (generic==global VA on
    /// SM103a/120); emits NO code, unifies the dst pair with the src pair.
    AliasPair,
    /// b9 phase-3 P1': PTX predicate logic (and/or/xor/not.pred, mov.pred)
    /// -> PLOP3.LUT predicate-domain. Form + LUT bytes are vendor anchors
    /// (ptxas 13.3 -O0 sm_103a, full 16-byte word parity IDENT x5 over
    /// probes work/b9p3/plp{1,2}): `PLOP3.LUT Pd, PT, Pa, Pb, PT, immA,
    /// immB`; immA is the op as f(a, b) with the third input tied PT
    /// (c=0 rows are don't-care, ptxas choices preserved verbatim:
    /// and/mov = 0x80, or = 0xf8, xor = 0x28, not = 0x08), immB is the
    /// inert second-destination table (Pd1 == PT, writes discarded), kept
    /// verbatim for byte-parity (and/mov = 0x08, or = 0x8f, xor = 0x82,
    /// not = 0x80).
    PredLogic { lut_a: u8, lut_b: u8 },
}

/// A single PTX→SASS mapping rule.
pub struct PtxRule {
    /// PTX opcode prefix to match (e.g. "add.s32", "add.u32", "fma.rn.f32").
    pub pattern: &'static str,
    pub template: SassTemplate,
}

use OpSlot::*;
use SassTemplate::*;

/// Master mapping table.  Searched linearly — longest/most-specific match first.
pub static RULES: &[PtxRule] = &[
    // ── Integer arithmetic ───────────────────────────────────────────────
    // 64-bit (must come before 32-bit patterns)
    PtxRule { pattern: "add.u64",       template: Add64 },
    PtxRule { pattern: "add.s64",       template: Add64 },
    // 32-bit
    // Use IADD (2-source) instead of IADD3 (3-source with RZ) to avoid Rc2=RZ ctrl word issue
    // b9 phase-1: plain "IADD" does not exist in the sm_103a/120 tables;
    // vendor shape is the carry-form IADD3 with PT ties (anchor: k2/k3 ptxas
    // probes, e.g. `IADD3 R7, PT, PT, R0, R7, R5`).
    PtxRule { pattern: "add.s32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), Src(2), RZ] } },
    PtxRule { pattern: "add.u32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), Src(2), RZ] } },
    PtxRule { pattern: "sub.s32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), NegSrc(2), RZ] } },
    PtxRule { pattern: "sub.u32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), NegSrc(2), RZ] } },
    PtxRule { pattern: "mul.lo.s32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mul.lo.u32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mul.hi.s32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mul.hi.u32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mad.lo.s32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.lo.u32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.hi.s32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.hi.u32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "min.s32",       template: Single { opcode: "IMNMX", slots: &[Src(0), Src(1), Src(2), PT] } },
    PtxRule { pattern: "min.u32",       template: Single { opcode: "IMNMX", slots: &[Src(0), Src(1), Src(2), PT] } },
    PtxRule { pattern: "max.s32",       template: Single { opcode: "IMNMX", slots: &[Src(0), Src(1), Src(2), NotPT] } },
    PtxRule { pattern: "max.u32",       template: Single { opcode: "IMNMX", slots: &[Src(0), Src(1), Src(2), NotPT] } },
    PtxRule { pattern: "neg.s32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, NegSrc(1), RZ, RZ] } },
    PtxRule { pattern: "abs.s32",       template: Single { opcode: "IABS",  slots: &[Src(0), Src(1)] } },

    // ── Bitwise / shift ──────────────────────────────────────────────────
    PtxRule { pattern: "and.b32",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0xc0), NotPT] } },
    PtxRule { pattern: "or.b32",        template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0xfc), NotPT] } },
    PtxRule { pattern: "xor.b32",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0x3c), NotPT] } },
    PtxRule { pattern: "not.b32",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), RZ, RZ, Imm(0x0f), NotPT] } },
    // b9 phase-1 (vendor-anchored byte-parity, probes in results/b9):
    // SHF.L.U32 d, a, shift, RZ  /  SHF.R.[US]32.HI d, RZ, shift, a
    PtxRule { pattern: "shl.b32",       template: Single { opcode: "SHF.L.U32", slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "shr.b32",       template: Single { opcode: "SHF.R.U32.HI", slots: &[Src(0), RZ, Src(2), Src(1)] } },
    PtxRule { pattern: "shr.u32",       template: Single { opcode: "SHF.R.U32.HI", slots: &[Src(0), RZ, Src(2), Src(1)] } },
    PtxRule { pattern: "shr.s32",       template: Single { opcode: "SHF.R.S32.HI", slots: &[Src(0), RZ, Src(2), Src(1)] } },
    PtxRule { pattern: "popc.b32",      template: Single { opcode: "POPC",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "brev.b32",      template: Single { opcode: "BREV",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "clz.b32",       template: Single { opcode: "FLO.U32", slots: &[Src(0), Src(1)] } },

    // ── FP32 arithmetic ──────────────────────────────────────────────────
    PtxRule { pattern: "add.f32",       template: Single { opcode: "FADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "add.rn.f32",    template: Single { opcode: "FADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "add.ftz.f32",   template: Single { opcode: "FADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "sub.f32",       template: Single { opcode: "FADD", slots: &[Src(0), Src(1), NegSrc(2)] } },
    PtxRule { pattern: "sub.rn.f32",    template: Single { opcode: "FADD", slots: &[Src(0), Src(1), NegSrc(2)] } },
    PtxRule { pattern: "mul.f32",       template: Single { opcode: "FMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.rn.f32",    template: Single { opcode: "FMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.ftz.f32",   template: Single { opcode: "FMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "fma.rn.f32",    template: Single { opcode: "FFMA", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "fma.rn.ftz.f32",template: Single { opcode: "FFMA", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "min.f32",       template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), PT] } },
    PtxRule { pattern: "min.ftz.f32",   template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), PT] } },
    PtxRule { pattern: "max.f32",       template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), NotPT] } },
    PtxRule { pattern: "max.ftz.f32",   template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), NotPT] } },

    // ── FP64 arithmetic ──────────────────────────────────────────────────
    PtxRule { pattern: "add.f64",       template: Single { opcode: "DADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "add.rn.f64",    template: Single { opcode: "DADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.f64",       template: Single { opcode: "DMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.rn.f64",    template: Single { opcode: "DMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "fma.rn.f64",    template: Single { opcode: "DFMA", slots: &[Src(0), Src(1), Src(2), Src(3)] } },

    // ── Math functions (MUFU) ────────────────────────────────────────────
    PtxRule { pattern: "rcp.approx",    template: Single { opcode: "MUFU.RCP",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "rcp.rn.f32",    template: Single { opcode: "MUFU.RCP",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "rsqrt.approx",  template: Single { opcode: "MUFU.RSQ",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "sqrt.approx",   template: Single { opcode: "MUFU.SQRT", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "sqrt.rn.f32",   template: Single { opcode: "MUFU.SQRT", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "lg2.approx",    template: Single { opcode: "MUFU.LG2",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "ex2.approx",    template: Single { opcode: "MUFU.EX2",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "sin.approx",    template: Single { opcode: "MUFU.SIN",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "cos.approx",    template: Single { opcode: "MUFU.COS",  slots: &[Src(0), Src(1)] } },

    // ── Moves ────────────────────────────────────────────────────────────
    PtxRule { pattern: "mov.u32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.b32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.s32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.f32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.u64",       template: Mov64 },
    PtxRule { pattern: "mov.b64",       template: Mov64 },

    // ── Comparison ───────────────────────────────────────────────────────
    PtxRule { pattern: "setp.lt.s32",   template: ISetp },
    PtxRule { pattern: "setp.le.s32",   template: ISetp },
    PtxRule { pattern: "setp.eq.s32",   template: ISetp },
    PtxRule { pattern: "setp.ne.s32",   template: ISetp },
    PtxRule { pattern: "setp.gt.s32",   template: ISetp },
    PtxRule { pattern: "setp.ge.s32",   template: ISetp },
    PtxRule { pattern: "setp.lt.u32",   template: ISetp },
    PtxRule { pattern: "setp.le.u32",   template: ISetp },
    PtxRule { pattern: "setp.eq.u32",   template: ISetp },
    PtxRule { pattern: "setp.ne.u32",   template: ISetp },
    PtxRule { pattern: "setp.gt.u32",   template: ISetp },
    PtxRule { pattern: "setp.ge.u32",   template: ISetp },
    PtxRule { pattern: "setp.lo.u32",   template: ISetp },
    PtxRule { pattern: "setp.ls.u32",   template: ISetp },
    PtxRule { pattern: "setp.hi.u32",   template: ISetp },
    PtxRule { pattern: "setp.hs.u32",   template: ISetp },
    PtxRule { pattern: "setp.",          template: ISetp },  // catch-all for setp variants

    // ── Predicate logic (b9 phase-3 P1': census family "pred-logic", 127
    // files / 2,443 ops; forms vendor-anchored, see PredLogic variant docs).
    PtxRule { pattern: "and.pred",      template: PredLogic { lut_a: 0x80, lut_b: 0x08 } },
    PtxRule { pattern: "or.pred",       template: PredLogic { lut_a: 0xf8, lut_b: 0x8f } },
    PtxRule { pattern: "xor.pred",      template: PredLogic { lut_a: 0x28, lut_b: 0x82 } },
    PtxRule { pattern: "not.pred",      template: PredLogic { lut_a: 0x08, lut_b: 0x80 } },
    PtxRule { pattern: "mov.pred",      template: PredLogic { lut_a: 0x80, lut_b: 0x08 } },

    PtxRule { pattern: "selp.s32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "selp.b32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mul.wide.s32",  template: MulWide { unsigned: false } },
    PtxRule { pattern: "mul.wide.u32",  template: MulWide { unsigned: true } },
    PtxRule { pattern: "selp.u32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "selp.f32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },

    // ── Memory ───────────────────────────────────────────────────────────
    PtxRule { pattern: "ld.param.",     template: LoadParam },
    PtxRule { pattern: "ld.global.",    template: LdGlobal },
    PtxRule { pattern: "st.global.",    template: StGlobal },
    PtxRule { pattern: "ld.shared.",    template: Single { opcode: "LDS", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "st.shared.",    template: Single { opcode: "STS", slots: &[Src(0), Src(1)] } },

    // ── Control flow ─────────────────────────────────────────────────────
    PtxRule { pattern: "bra.uni",       template: Single { opcode: "BRA", slots: &[Src(0)] } },
    PtxRule { pattern: "bra",           template: Single { opcode: "BRA", slots: &[Src(0)] } },
    PtxRule { pattern: "ret",           template: Single { opcode: "EXIT", slots: &[] } },
    PtxRule { pattern: "exit",          template: Single { opcode: "EXIT", slots: &[] } },

    // ── Synchronization ──────────────────────────────────────────────────
    // b9 phase-1: vendor canonical for __syncthreads is DEFER_BLOCKING
    // (anchor: k3 ptxas probe).
    // b9 phase-2: vendor keeps id AND thread-count (corpus anchor:
    // "BAR.SYNC.DEFER_BLOCKING 0x2, 0x1a0"); missing args resolve to RZ.
    PtxRule { pattern: "bar.sync",      template: Single { opcode: "BAR.SYNC.DEFER_BLOCKING", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "membar.gl",     template: Single { opcode: "MEMBAR.SC.GL", slots: &[] } },
    PtxRule { pattern: "membar.cta",    template: Single { opcode: "MEMBAR.SC.CTA", slots: &[] } },

    // ── Warp ops ─────────────────────────────────────────────────────────
    PtxRule { pattern: "shfl.sync.",    template: Shfl },
    // b9 phase-2 P6: removed "redux.sync." -> REDUX.ADD single-op rule. It
    // collapsed MIN/MAX/AND/OR into ADD (wrong op) AND emitted an R-dest form
    // the sm_103a encoder does not have (vendor: REDUX[.op][.type] URd, Ra;
    // REDUX_UR_R table key). The gateway has no UR-domain allocation, so the
    // honest behavior is PTX-level rejection ("unsupported PTX: redux.sync..")
    // until a phase-3 UR path exists.

    // ── Conversions ──────────────────────────────────────────────────────
    PtxRule { pattern: "cvt.",          template: Cvt },
    PtxRule { pattern: "cvta.to.global.u64", template: AliasPair },

    // ── MMA ──────────────────────────────────────────────────────────────
    PtxRule { pattern: "mma.sync.",     template: Mma },
];

/// Find the first matching rule for a PTX opcode.
pub fn find_rule(ptx_opcode: &str) -> Option<&'static PtxRule> {
    RULES.iter().find(|r| ptx_opcode.starts_with(r.pattern))
}

/// Comparison operator mapping: PTX name → SASS suffix.
pub fn setp_cmp_suffix(ptx_opcode: &str) -> &'static str {
    let parts: Vec<&str> = ptx_opcode.split('.').collect();
    if parts.len() < 2 { return "EQ"; }
    let cmp = parts[1];
    if cmp.eq_ignore_ascii_case("lt") || cmp.eq_ignore_ascii_case("lo") { "LT" }
    else if cmp.eq_ignore_ascii_case("le") || cmp.eq_ignore_ascii_case("ls") { "LE" }
    else if cmp.eq_ignore_ascii_case("eq") || cmp.eq_ignore_ascii_case("equ") { "EQ" }
    else if cmp.eq_ignore_ascii_case("ne") || cmp.eq_ignore_ascii_case("neu") { "NE" }
    else if cmp.eq_ignore_ascii_case("gt") || cmp.eq_ignore_ascii_case("hi") { "GT" }
    else if cmp.eq_ignore_ascii_case("ge") || cmp.eq_ignore_ascii_case("hs") { "GE" }
    else if cmp.eq_ignore_ascii_case("ltu") { "LT" }
    else if cmp.eq_ignore_ascii_case("leu") { "LE" }
    else if cmp.eq_ignore_ascii_case("gtu") { "GT" }
    else if cmp.eq_ignore_ascii_case("geu") { "GE" }
    else { "EQ" }
}

/// Is this a float setp?
pub fn setp_is_float(ptx_opcode: &str) -> bool {
    ptx_opcode.contains(".f32") || ptx_opcode.contains(".f64") || ptx_opcode.contains(".f16")
}

/// Extract shuffle mode from PTX opcode.
pub fn shfl_mode(ptx_opcode: &str) -> &'static str {
    if ptx_opcode.contains(".up") { "UP" }
    else if ptx_opcode.contains(".down") { "DOWN" }
    else if ptx_opcode.contains(".bfly") { "BFLY" }
    else if ptx_opcode.contains(".idx") { "IDX" }
    else { "BFLY" }
}
