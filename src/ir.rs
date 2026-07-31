//! Instruction intermediate representation.
//!
//! Clean types that carry ALL information needed for encoding.
//! The encoder never needs to re-parse raw ASM text.

/// Predicate guard: `@P0`, `@!P1`, `@UP2`, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guard {
    pub pred: u8,
    pub negated: bool,
    pub uniform: bool,
}

/// Scheduling / dependency control code.
///
/// Format: `B------:R-:W-:-:S01`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlCode {
    pub stall: u8,
    pub yield_flag: bool,
    pub write_bar: u8,
    pub read_bar: u8,
    pub wait_mask: u8,
}

impl Default for ControlCode {
    fn default() -> Self {
        Self {
            stall: 1,
            yield_flag: false,
            write_bar: 7,
            read_bar: 7,
            wait_mask: 0,
        }
    }
}

/// A typed operand — the parser produces these, the encoder consumes them.
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    /// General register R0-R255 (RZ = 255).
    Reg { num: u8, neg: bool, abs: bool, inv: bool, reuse: bool },
    /// Uniform register UR0-UR63. `is_zero` distinguishes "URZ" (architectural
    /// zero, encodes as 0xFF in 8-bit slots on sm_103a) from "UR63" (a real
    /// register, encodes as 63).
    UReg { num: u8, neg: bool, abs: bool, inv: bool, reuse: bool, is_zero: bool },
    /// Predicate P0-P6, PT=7.
    Pred { num: u8, neg: bool },
    /// Uniform predicate UP0-UP6, UPT=7.
    UPred { num: u8, neg: bool },
    /// 32-bit integer immediate.
    Imm32(i64),
    /// 64-bit integer immediate (for MOV.64, etc.).
    Imm64(u64),
    /// Float immediate (stored as raw bits).
    FloatImm(u64),
    /// Address expression [R + offset] or [R + UR + offset].
    Addr {
        base_reg: Option<u8>,
        base_reg_suffix: Option<String>,  // e.g. ".64", ".X8"
        ur_reg: Option<u8>,
        offset: i64,
    },
    /// Constant memory c[bank][offset] or c[bank][R+offset].
    ConstMem {
        bank: u16,
        base_reg: Option<u8>,
        ur_reg: Option<u8>,
        offset: i64,
    },
    /// Descriptor desc[UR][R+offset].
    Desc {
        ur_idx: u8,
        base_reg: Option<u8>,
        base_reg_suffix: Option<String>,
        offset: i64,
    },
    /// Branch target (absolute byte offset).
    BranchTarget(u32),
    /// Barrier index B0-B5.
    Barrier(u8),
    /// System register (SR_TID.X, etc.) — stored as raw name.
    SysReg(String),
    /// Label / unknown token.
    Label(String),
}

/// A parsed SASS instruction, ready for encoding.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Byte offset within `.text` section.
    pub addr: u32,
    /// Base opcode: `"IADD3"`, `"LDG"`, `"BRA"`.
    pub opcode: String,
    /// Full opcode with modifiers: `"IADD3.X"`, `"LDG.E.128"`.
    pub opcode_full: String,
    /// Instruction key for table lookup: `"IADD3_R_P_P_R_R_R"`.
    pub key: String,
    /// Predicate guard, if any.
    pub guard: Option<Guard>,
    /// Parsed operands in order.
    pub operands: Vec<Operand>,
    /// Opcode-level modifiers: `[".X", ".E", ".128", ".WIDE"]`.
    pub modifiers: Vec<String>,
    /// Control / scheduling code.
    pub ctrl: ControlCode,
    /// True when `ctrl` was hand-specified in the source via a `[B..:R..:W..:Y:S..]`
    /// prefix. Such instructions are FROZEN: the scheduler leaves their control code
    /// untouched and the MMA writeback-drain post-pass skips them (the author owns the
    /// schedule, e.g. an nvcc-mirrored PV loop). Defaults to false.
    pub hand_sched: bool,
    /// Raw SASS text (for diagnostics only — encoder does NOT use this).
    pub raw_text: String,
}
