//! Instruction scheduling class — documents ctrl word constraints per instruction family.
//!
//! Each SM120 instruction belongs to a `CtrlClass` that describes:
//! - Which hi_lower32 bits are fixed instruction discriminators (never touch)
//! - Which hi_lower32 bits the scheduler may freely set
//! - Constraints on wait_mask / write_bar / stall assignment
//!
//! All constraints are hardware-verified on RTX 5090 (SM120, driver 570.211.01).

/// Scheduling class for an SM120 instruction.
///
/// The class is stored per-InsKey in sm120.json and loaded by `IsaTable`.
/// The scheduler uses it to avoid writing scheduling bits into fixed
/// instruction-discriminator positions in the ctrl word.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CtrlClass {
    /// 3-source ALU (IADD3, IMAD, FFMA, HFMA2) — Rc2 at hi[7:0].
    /// When Rc2=RZ (255): hi[7:0]=0xFF forced; no independent wait_mask or write_bar.
    AluIadd3,
    /// 2-source ALU (MOV, SEL, IADD, FADD, FMUL, comparisons, conversions).
    AluSimple,
    /// IMAD.WIDE — upper32 must be 0x000fc000 (not 0x000fe200 epoch).
    ImadWide,
    /// System register read — hi[15:8] = SR code (opcode extension).
    S2r,
    /// MUFU transcendentals — hi[15:8] = function code (TABLES_opex_0).
    /// wait_mask FORBIDDEN: setting it corrupts opex_0 table decode.
    Mufu,
    /// 32-bit constant bank load — hi[11:8]=0x8 is type discriminator.
    Ldc,
    /// 64-bit constant bank load — hi[11:8]=0xa is type discriminator.
    Ldc64,
    /// 32-bit uniform constant bank load.
    Ldcu,
    /// 64-bit uniform constant bank load — bit43=1 required in and_base.
    Ldcu64,
    /// Global memory load (descriptor form) — lower32 all fixed discriminators.
    /// Producer of long-latency result via scoreboard. NOP gap required before
    /// IADD3 consumer (≥1) and MUFU consumer (≥8).
    Ldg,
    /// Global memory store (descriptor form) — lower32 all fixed.
    Stg,
    /// Generic global load (non-descriptor form).
    LdGeneric,
    /// Generic global store (non-descriptor form).
    StGeneric,
    /// Shared memory load — hi[11:8]=0x8 type discriminator.
    Lds,
    /// Shared memory store — hi[11:8]=0x8 type discriminator.
    Sts,
    /// Local memory load.
    Ldl,
    /// Local memory store.
    Stl,
    /// Async global→shared copy (LDGSTS, LDGDEPBAR).
    Ldgsts,
    /// Global atomic / reduction (ATOMG, REDG).
    Atomg,
    /// Shared memory atomic (ATOMS).
    Atoms,
    /// Half-precision tensor core MMA (HMMA).
    Hmma,
    /// Integer tensor core MMA (IMMA).
    Imma,
    /// Double-precision tensor core MMA (DMMA).
    Dmma,
    /// FP8 / quantized tensor core MMA — Blackwell (QMMA).
    Qmma,
    /// Texture / surface load.
    Tex,
    /// Barrier / sync / membar instructions — no scheduling bits.
    Barrier,
    /// Control flow (BRA, CALL, RET, BSSY, BSYNC, etc.) — no standard scheduling.
    CtrlFlow,
    /// EXIT — fully static ctrl word, bit43 required.
    ExitStatic,
    /// NOP — fully static, no write/wait mask.
    Nop,
    /// Unknown class — not yet in CTRL_CLASS_MAP (should log a warning).
    Unknown,
}

impl CtrlClass {
    /// Parse from the string stored in sm120.json.
    pub fn parse(s: &str) -> Self {
        match s {
            "alu_iadd3"   => Self::AluIadd3,
            "alu_simple"  => Self::AluSimple,
            "imad_wide"   => Self::ImadWide,
            "s2r"         => Self::S2r,
            "mufu"        => Self::Mufu,
            "ldc"         => Self::Ldc,
            "ldc64"       => Self::Ldc64,
            "ldcu"        => Self::Ldcu,
            "ldcu64"      => Self::Ldcu64,
            "ldg"         => Self::Ldg,
            "stg"         => Self::Stg,
            "ld_generic"  => Self::LdGeneric,
            "st_generic"  => Self::StGeneric,
            "lds"         => Self::Lds,
            "sts"         => Self::Sts,
            "ldl"         => Self::Ldl,
            "stl"         => Self::Stl,
            "ldgsts"      => Self::Ldgsts,
            "atomg"       => Self::Atomg,
            "atoms"       => Self::Atoms,
            "hmma"        => Self::Hmma,
            "imma"        => Self::Imma,
            "dmma"        => Self::Dmma,
            "qmma"        => Self::Qmma,
            "tex"         => Self::Tex,
            "barrier"     => Self::Barrier,
            "ctrl_flow"   => Self::CtrlFlow,
            "exit_static" => Self::ExitStatic,
            "nop"         => Self::Nop,
            _             => Self::Unknown,
        }
    }

    /// Returns true for instructions that produce a long-latency result
    /// requiring a hardware scoreboard (write_bar assignment).
    ///
    /// NOTE: ALL warp-cooperative tensor MMAs (QMMA, HMMA, IMMA, DMMA) are
    /// excluded. On SM120 (consumer Blackwell) the MMA writeback is NOT tracked
    /// by the scoreboard — a write_bar on the MMA is ignored by hardware and the
    /// cooperative writeback is not visible to consumers. nvcc uses stall=11 +
    /// `@!UPT UIADD3 URZ` writeback drains instead (see main.rs / scheduling_pass).
    /// Assigning write_bar also lets downstream wait_mask bits interfere with
    /// warp-cooperative K-accumulation (each wait_mask bit halves output).
    pub fn needs_write_bar(&self) -> bool {
        matches!(self,
            Self::Ldg | Self::LdGeneric |
            Self::Ldc | Self::Ldc64 | Self::Ldcu | Self::Ldcu64 |
            Self::Lds | Self::Ldl | Self::Ldgsts |
            Self::ImadWide |
            Self::Mufu |
            Self::Atomg | Self::Atoms |
            Self::Tex |
            Self::S2r
        )
    }

    /// Returns true for store-class instructions — they fire and forget,
    /// don't produce a result, but may need a stall for ordering.
    pub fn is_store(&self) -> bool {
        matches!(self, Self::Stg | Self::StGeneric | Self::Sts | Self::Stl)
    }

    /// Returns true for control flow or barrier instructions that use
    /// static scheduling (no dynamic write_bar/wait_mask).
    pub fn is_static_ctrl(&self) -> bool {
        matches!(self,
            Self::Barrier | Self::CtrlFlow | Self::ExitStatic | Self::Nop
        )
    }

    /// Returns true if the scheduler may set `wait_mask` bits for this class.
    ///
    /// Only classes whose scheduling is encoded at standard upper32[16:0]
    /// positions can use wait_mask.  Classes with non-standard scheduling
    /// layout (LDC, LDG, STG, IMAD.WIDE, etc.) or fully-static encoding
    /// cannot — the scheduler falls back to stall-based dependency.
    ///
    /// NOTE: QMMA is NOT excluded here because the scheduling pass needs
    /// to compute wait_mask for dependency tracking. The main.rs drain pass
    /// then moves QMMA's wait_mask to a preceding UIADD3 URZ instruction,
    /// keeping the QMMA itself clean (wait_mask=0).
    pub fn can_set_wait_mask(&self) -> bool {
        self.has_standard_upper32_sched()
            && !matches!(self, Self::Mufu)
    }

    /// Returns true if the scheduler may set a `write_bar` for this class.
    ///
    /// Only assign write_bar to long-latency producers whose consumers
    /// can encode wait_mask in the standard upper32[16:0] layout.
    /// For IADD3+RZ, the caller must additionally check `iadd3_rc2_is_rz`.
    pub fn can_set_write_bar(&self) -> bool {
        self.has_standard_upper32_sched()
    }

    /// Returns true if upper32[16:0] uses the standard 17-bit scheduling
    /// layout (wait_mask|read_bar|write_bar|yield|stall).
    ///
    /// Classes where hi_lower32_sched_mask != 0 have scheduling in lower32
    /// at documented positions; their upper32 also follows the standard layout.
    /// Classes with sched_mask == 0 either have scheduling at non-standard
    /// upper32 positions or are fully static.
    pub fn has_standard_upper32_sched(&self) -> bool {
        // SM120: ALL non-static instructions use the same scheduling layout
        // (17-bit packed word at upper32[25:9]). Derived from tungsten LLVM backend
        // where buildSchedUpper32 applies universally.
        !self.is_static_ctrl()
    }

    /// Minimum NOP gap required AFTER an LDG result is consumed by this class.
    ///
    /// - `mufu`: 8 NOPs — opex field in MUFU conflicts with wait_mask encoding.
    /// - `alu_iadd3`: 1 NOP — IADD3+RZ can't encode wait_mask.
    /// - others: 0 (use scoreboard wait_mask normally).
    pub fn min_nop_gap_after_ldg(&self) -> u8 {
        match self {
            Self::Mufu    => 8,
            Self::AluIadd3 => 1,
            _ => 0,
        }
    }

    /// Returns true if this is a tensor-core MMA instruction.
    pub fn is_mma(&self) -> bool {
        matches!(self, Self::Hmma | Self::Imma | Self::Dmma | Self::Qmma)
    }
}

/// Check whether an IADD3 instruction has Rc2=RZ as its last register operand.
///
/// When Rc2=RZ, hi[7:0]=0xFF is forced by hardware (stall forced to 15,
/// no independent wait_mask or write_bar possible).
pub fn iadd3_rc2_is_rz(insn: &crate::ir::Instruction) -> bool {
    if insn.opcode != "IADD3" && insn.opcode != "UIADD3" {
        return false;
    }
    // Rc2 is the last register operand. In IADD3_R_P_P_R_R_R,
    // it's operand index 5 (0-based). Look for the last Reg in operands.
    insn.operands.iter().rev().find_map(|op| {
        if let crate::ir::Operand::Reg { num, .. } = op {
            Some(*num == 255)
        } else {
            None
        }
    }).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// BUG-103 / BUG-105 (mk300, 2026-08-23, iter 497): tcgen05 c1 UTC*MMA family —
// vendor-CONSTANT ctrl word per (class, guard-presence), independent of dataflow.
//
// Evidence (750/750 split 1:1, sm_100a + sm_103a cubins, and the mk296 corpus
// nvdisasm -hex matrix of 43 vendor UTC*MMA words decoded by ctrl d3):
//   direct  (guard == PT):    d3 = 0x0011d800 -> stall=12 yield=0 rbar=0 wbar=7 wait=0x01
//   guarded (uniform guard):  d3 = 0x0001f200 -> stall=9  yield=1 rbar=0 wbar=7 wait=0x00
// The guarded stamp applies ONLY to the 7/8-op 1CTA key
//   <BASE>_II_II_II_II_II_UR_UP[_II]   (mod group '', no .2CTA/.WS)
// of UTCHMMA / UTCIMMA / UTCQMMA. Everything else in the family rides direct:
//   - 6-op `_II_II_II_II_II_UP` (+.WS/2CTA) — even @!UP2-guarded (mvF* evidence);
//   - `.2CTA` — always direct, guarded or not (UTCQMMA.2CTA @!UP1 -> 0x11d800);
//   - UTCOMMA[.4X/.BLOCK16] — always direct even guarded;
//   - UTCQMMA block-scale sibling (`..._II_II` sig, tok6 tmem) — direct even guarded.
// sm120 UR-form keys (UTCHMMA.1CTA_UR_UR_...) are excluded by the descriptor-sig
// requirement `_II_II_II_II_` (sm120 = separate concern, no vendor ctrl data).
//
// The law fixes the encode-side wrong-ctrl of finding 103 (encode stamped the
// generic default 0x000fc200 / sched-pass 0x000fca00; rt-audit e4 class) and the
// 105-kand c3-stamp on the 6-op `_UP` class. It is a candidate input row for the
// b1 physics table (vendor ctrl is deterministic per family).
// ---------------------------------------------------------------------------

/// Vendor ctrl word for an unguarded (PT) descriptor-form UTC*MMA:
/// stall=12, yield=0, rbar=0, wbar=7, wait=0x01.
pub const UTC_MMA_DIRECT_CTRL: crate::ir::ControlCode = crate::ir::ControlCode {
    stall: 12,
    yield_flag: false,
    write_bar: 7,
    read_bar: 0,
    wait_mask: 0x01,
};

/// Vendor ctrl word for a uniform-guarded 1CTA 7/8-op `_UR_UP[_II]` UTC*MMA:
/// stall=9, yield=1, rbar=0, wbar=7, wait=0x00.
pub const UTC_MMA_GUARDED_CTRL: crate::ir::ControlCode = crate::ir::ControlCode {
    stall: 9,
    yield_flag: true,
    write_bar: 7,
    read_bar: 0,
    wait_mask: 0x00,
};

/// Returns the vendor-constant ctrl word for tcgen05 c1 UTC*MMA instructions
/// (descriptor-form operand signature), or None outside the family.
///
/// `hand_sched` instructions are NOT exempted here — the caller (encoder)
/// decides; author-owned ctrl prefixes always win over this law.
pub fn utc_mma_vendor_ctrl(insn: &crate::ir::Instruction) -> Option<crate::ir::ControlCode> {
    let key = insn.key.as_str();
    // Descriptor-form family on sm_100a/103a taxonomy: base op + `_II_II_II_II_` sig
    // (gdesc/tmem/idesc operands parse as II-typed labels). The sm120 UR-form keys
    // (UTCHMMA.1CTA_UR_UR_UR_UR_UR_UP) carry no II descriptors -> excluded.
    let family = key.starts_with("UTCHMMA_")
        || key.starts_with("UTCIMMA_")
        || key.starts_with("UTCQMMA_")
        || key.starts_with("UTCOMMA_");
    if !family || !key.contains("_II_II_II_II_") {
        return None;
    }
    // Guarded class: 7/8-op 1CTA `<BASE>_II_II_II_II_II_UR_UP[_II]` carrying a real
    // uniform guard. UTCOMMA never matches (its sig is `_II_II_II_II_II_II_II_UP`).
    let ur_up_c1 = key == format!("{}_II_II_II_II_II_UR_UP", insn.opcode)
        || key == format!("{}_II_II_II_II_II_UR_UP_II", insn.opcode);
    let multi = insn.opcode_full.contains("2CTA") || insn.opcode_full.contains("WS");
    // Evidence-exact guard test: the guarded stamp was observed ONLY with the
    // uniform negated guards @!UP0/@!UP1 (vendor guard field 8/9). Any other
    // guard variant (positive, non-uniform, wider pred number) rides direct —
    // fail-closed toward the majority stamp, encode stays legal.
    let guarded = ur_up_c1
        && !multi
        && matches!(&insn.guard, Some(g) if g.uniform && g.negated && matches!(g.pred, 0 | 1));
    Some(if guarded { UTC_MMA_GUARDED_CTRL } else { UTC_MMA_DIRECT_CTRL })
}
