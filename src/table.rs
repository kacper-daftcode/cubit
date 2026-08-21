//! ISA table loader for per-modifier-group sm120.json.
//!
//! Table format:
//! ```json
//! { "IADD3_R_P_P_R_R_R": { "mod_groups": {
//!     "": { "and_base": "0x...", "fields": [...], "count": 26820 },
//!     "X": { "and_base": "0x...", "fields": [...], "count": 5623 }
//! }}}
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// JSON schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JsonTable(HashMap<String, JsonInsKey>);

#[derive(Deserialize)]
struct JsonInsKey {
    pub mod_groups: HashMap<String, JsonModGroup>,
}

#[derive(Deserialize)]
struct JsonModGroup {
    pub and_base: String,
    pub variable_mask: Option<String>,
    pub fields: Vec<JsonField>,
    #[allow(dead_code)]
    pub count: Option<usize>,
}

#[derive(Deserialize)]
struct JsonField {
    pub shift: u32,
    pub bits: u32,
    pub token_idx: i32,
    pub extraction: String,
}

// ---------------------------------------------------------------------------
// Runtime types
// ---------------------------------------------------------------------------

/// Extraction type: how to derive a field value from an operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extraction {
    // Guard
    Guard, GuardLo3, GuardNeg,
    // Register
    Reg, UReg, URegFf, RegFf, Pred, Barrier,
    /// MMA accumulate-gate UP (QMMA/HMMA trailing UP operand @87 + inv@90).
    /// BUG-032: ONLY this slot uses nvdisasm's INVERTED naming (sel = 7-n,
    /// UPT = sel 0); every other upred field on sm_120 is straight (sel = n,
    /// UPT = sel 7) per the i93 field census (206775 UP records).
    UPredGate,
    // Immediate shifts (unmasked — field mask handles truncation)
    Imm, ImmShr(u8), // imm >> N
    ImmDec, ImmDecU32,
    // Float
    F32, F16, F16d, F64hi,
    // Flags
    Neg, NegShl1, Reuse, Inv, Abs, NegAbs,
    /// KAND-058 (SPARK/UFADD): sign mirror for float/immediate tokens -
    /// FloatImm sign bit, int-looking tokens sign. HW: UFADD imm bit2.
    NegF32,
    /// KAND-058: value-cast to f32 (int-looking imm -> f32 of value);
    /// FloatImm behaves like F32.
    F32Cast,
    ByteSel,
    // Half-register pair selector parsed from raw text (.H0_H0/.H0_H1/.H1_H1):
    // sm_103a fp16x2-class ops encode it as 2 bits (none=0, H0_H1=1, H0_H0=2,
    // H1_H1=3), empirically pure over the corpus.
    HalfSel,
    // System register
    SysReg, SysRegLo7, SysRegLo4, SysRegHi4, SysRegHi1,
    // Register bit-shifted (for double-precision, S64, etc.)
    RegShr(u8), URegShr(u8),
    // Address sub-parts
    SubR(u8), SubUR(u8), SubImm(u8), SubImmS24(u8),
    // Address sub-parts, bit-shifted (for .64 addresses storing reg/2)
    SubRShr(u8, u8), SubURShr(u8, u8), SubImmShr(u8, u8),
    /// BUG-070: unsigned scaled sub-offset ("sub_imm{i}_shr{n}u"). Same window
    /// placement as SubImmShr but no sign extension (STG.256 desc offset is an
    /// unsigned 16-bit window per nvdisasm-13.3 probes). Encoder is strict:
    /// negative / sub-granule / overflowing offsets fail closed.
    SubImmShrU(u8, u8),
    // Constant memory combined
    Cm16Off, Cm17Off,
    // Opaque modifier: decoded as raw value, printed as .modifier text,
    // re-encoded from the modifier text. Used for comparison modes (EQ/NE/LT/LE/GT/GE),
    // reduction functions (AND/OR/XOR/SUM/MIN/MAX), signed flags, combine modes (AND/OR/XOR).
    OpaqueModifier,
    // Operand-attached modifier flag: 1 if the raw SASS text of the operand
    // carries ".NAME" (e.g. opmod:HI_LO for "R106.F32x2.HI_LO"). sm_103a
    // paired-FFMA2 class encodings are partly controlled by these.
    OpModFlag(String),
    // Instruction mnemonic mod at ordered position: "mnemod1:F32" is 1 when
    // the first suffix of the instruction name is F32 (distinguishes
    // F2F.F32.F64 from F2F.F64.F32 within the same sorted mod group).
    MnemMod(u8, String),
    // Bfloat16 immediate (f64 -> f32 -> bf16 round-to-nearest-even)
    BF16,
    // Number scraped from a Label operand's raw text: the parser keeps
    // tcgen05 tmem[UR4+0x10] / gdesc[UR24] / idesc[UR23] / desc[UR6] forms
    // as labels; the pattern name selects which number to read.
    // "tdesc_*" patterns accept any of the four descriptor kinds (mixed-kind
    // operand positions), "dsel2" reads the 2-bit kind tag.
    LblPat(String),
    // Explicit "+URZ" addressing-mode flag read from the operand's raw text
    // (STS.64 [R3+URZ+...]); UrExplInv is the inverse-polarity twin.
    UrExpl,
    UrExplInv,
    // Address sub-UR number minus one: sibling-pair convention where the
    // second [URx] operand shares the first's slot (UGETNEXTWORKID.BROADCAST
    // corpus records: URb == URa + 1 in one 8-bit window).
    SubURm1(u8),
    // Derived from the scheduling yield flag (inverted): 1 when yield is false.
    // Used by barrier/sync instructions where yield=0 triggers additional
    // hi-dword bits (122/124 in DEPBAR on sm_103a) that the SCHED mask doesn't cover.
    YieldInv,
    // Address scale from the base-register suffix ([R9.X8]/[R9.X16]):
    // 0 none, 1=X4, 2=X8, 3=X16 (i108 golden attribution, BUG-038).
    AddrScale,
    // Unknown (no extraction, use 0)
    None,
}

fn parse_extraction(s: &str) -> Extraction {
    match s {
        "guard" => Extraction::Guard,
        "guard_lo3" => Extraction::GuardLo3,
        "guard_neg" => Extraction::GuardNeg,
        "reg" => Extraction::Reg,
        "ureg" => Extraction::UReg,
        "ureg_ff" => Extraction::URegFf,
        "reg_ff" => Extraction::RegFf,
        "pred" | "upred" => Extraction::Pred,
        "upred_gate" => Extraction::UPredGate,
        "barrier" => Extraction::Barrier,
        "imm" => Extraction::Imm,
        "imm_dec" => Extraction::ImmDec,
        "imm_dec_u32" => Extraction::ImmDecU32,
        "f32" => Extraction::F32,
        "f16" => Extraction::F16,
        "f16_d" => Extraction::F16d,
        "f64hi" => Extraction::F64hi,
        "neg" => Extraction::Neg,
        "neg_f32" => Extraction::NegF32,
        "f32cast" => Extraction::F32Cast,
        "neg_shl1" => Extraction::NegShl1,
        "reuse" => Extraction::Reuse,
        "inv" => Extraction::Inv,
        "abs" => Extraction::Abs,
        "neg_abs" => Extraction::NegAbs,
        "byte_sel" => Extraction::ByteSel,
        "hsel" => Extraction::HalfSel,
        "addr_scale" => Extraction::AddrScale,
        "sysreg" => Extraction::SysReg,
        "sysreg_lo7" => Extraction::SysRegLo7,
        "sysreg_lo4" => Extraction::SysRegLo4,
        "sysreg_hi4" => Extraction::SysRegHi4,
        "sysreg_hi1" => Extraction::SysRegHi1,
        "sub_r0" => Extraction::SubR(0),
        "sub_r1" => Extraction::SubR(1),
        "sub_r2" => Extraction::SubR(2),
        "sub_ur0" => Extraction::SubUR(0),
        "sub_ur1" => Extraction::SubUR(1),
        "sub_imm0" => Extraction::SubImm(0),
        "sub_imm1" => Extraction::SubImm(1),
        "sub_imm2" => Extraction::SubImm(2),
        "sub_imm0_s24" => Extraction::SubImmS24(0),
        "sub_imm1_s24" => Extraction::SubImmS24(1),
        "sub_imm2_s24" => Extraction::SubImmS24(2),
        "sub_r0_shr1" => Extraction::SubRShr(0, 1),
        "sub_r1_shr1" => Extraction::SubRShr(1, 1),
        "sub_ur0_shr1" => Extraction::SubURShr(0, 1),
        "sub_ur1_shr1" => Extraction::SubURShr(1, 1),
        "sub_imm1_shr1" => Extraction::SubImmShr(1, 1),
        "sub_imm2_shr1" => Extraction::SubImmShr(2, 1),
        s if s.starts_with("sub_imm") && s.contains("_shr") && s.ends_with('u') => {
            // unsigned variant "sub_imm{i}_shr{n}u" (BUG-070; STG.256 desc off)
            let body = &s[7..s.len() - 1];
            if let Some((i, n)) = body.split_once("_shr") {
                Extraction::SubImmShrU(i.parse().unwrap_or(0), n.parse().unwrap_or(1))
            } else {
                Extraction::None
            }
        }
        s if s.starts_with("sub_imm") && s.contains("_shr") => {
            // generic "sub_imm{i}_shr{n}" (sm_103a wide-desc offsets scale the
            // immediate; e.g. ENL2.256 desc stores off>>5)
            let body = &s[7..];
            if let Some((i, n)) = body.split_once("_shr") {
                Extraction::SubImmShr(i.parse().unwrap_or(0), n.parse().unwrap_or(1))
            } else {
                Extraction::None
            }
        }
        "cm16_off" => Extraction::Cm16Off,
        "cm17_off" => Extraction::Cm17Off,
        "opaque_mod" => Extraction::OpaqueModifier,
        "bf16" => Extraction::BF16,
        "" => Extraction::None,
        s if matches!(s, "tmem_ur" | "tmem_off" | "gdesc_ur" | "gdesc_off"
                        | "idesc_ur" | "desc_ur"
                        | "tdesc_ur" | "tdesc_off" | "dsel2") => {
            Extraction::LblPat(s.to_string())
        }
        "urz_expl" => Extraction::UrExpl,
        "urz_expl_inv" => Extraction::UrExplInv,
        s if s.starts_with("sub_ur") && s.ends_with("_m1") => {
            let i: u8 = s[6..s.len() - 3].parse().unwrap_or(0);
            Extraction::SubURm1(i)
        }
        s if s.starts_with("opmod:") => {
            Extraction::OpModFlag(s[6..].to_string())
        }
        s if s.starts_with("mnemod") => {
            let rest = &s[6..];
            let (i, name) = rest.split_once(':')
                .unwrap_or(("1", rest));
            Extraction::MnemMod(i.parse::<u8>().unwrap_or(1), name.to_string())
        }
        s if s.starts_with("reg_shr") => {
            let n: u8 = s[7..].parse().unwrap_or(0);
            Extraction::RegShr(n)
        }
        s if s.starts_with("ureg_shr") => {
            let n: u8 = s[8..].parse().unwrap_or(0);
            Extraction::URegShr(n)
        }
        s if s.starts_with("imm_shr") => {
            let n: u8 = s[7..].parse().unwrap_or(0);
            Extraction::ImmShr(n)
        }
        s if s.starts_with("sub_r") && s.contains("_shr") => {
            // e.g. "sub_r0_shr1", "sub_r1_shr2"
            let parts: Vec<&str> = s.split('_').collect();
            let idx: u8 = parts.get(1).and_then(|p| p.strip_prefix('r')).and_then(|n| n.parse().ok()).unwrap_or(0);
            let shr: u8 = parts.get(2).and_then(|p| p.strip_prefix("shr")).and_then(|n| n.parse().ok()).unwrap_or(0);
            Extraction::SubRShr(idx, shr)
        }
        s if s.starts_with("sub_ur") && s.contains("_shr") => {
            let parts: Vec<&str> = s.split('_').collect();
            let idx: u8 = parts.get(1).and_then(|p| p.strip_prefix("ur")).and_then(|n| n.parse().ok()).unwrap_or(0);
            let shr: u8 = parts.get(2).and_then(|p| p.strip_prefix("shr")).and_then(|n| n.parse().ok()).unwrap_or(0);
            Extraction::SubURShr(idx, shr)
        }
        s if s.starts_with("sub_imm") && s.contains("_shr") => {
            let parts: Vec<&str> = s.split('_').collect();
            let idx: u8 = parts.get(1).and_then(|p| p.strip_prefix("imm")).and_then(|n| n.parse().ok()).unwrap_or(0);
            let shr: u8 = parts.get(2).and_then(|p| p.strip_prefix("shr")).and_then(|n| n.parse().ok()).unwrap_or(0);
            Extraction::SubImmShr(idx, shr)
        }
        "yield_inv" => Extraction::YieldInv,
        _ => {
            eprintln!("warning: unknown extraction '{s}', using None");
            Extraction::None
        }
    }
}

/// A single bitfield within an instruction encoding.
#[derive(Debug, Clone)]
pub struct Field {
    /// Bit position (0 = LSB of 128-bit instruction).
    pub shift: u32,
    /// Number of bits.
    pub bits: u32,
    /// Bitmask: `(1 << bits) - 1` (capped at 64 bits).
    pub mask: u64,
    /// Which token in the SASS this field corresponds to (0 = guard, 1+ = operands).
    pub token_idx: i32,
    /// How to extract the value from the operand.
    pub extraction: Extraction,
}

/// Encoding spec for one (instruction_key, modifier_group) pair.
#[derive(Debug, Clone)]
pub struct ModGroupEntry {
    /// Constant bits (AND of all codes in this group, excluding variable bits).
    pub and_base: u128,
    /// Mask of all variable bits (for decode matching).
    pub variable_mask: u128,
    /// Variable fields with extraction rules.
    pub fields: Vec<Field>,
}

/// All modifier groups for one instruction key.
#[derive(Debug, Clone)]
pub struct InsKeyEntry {
    /// Map from modifier group string ("", "X", "64,E", etc.) to encoding.
    pub mod_groups: HashMap<String, ModGroupEntry>,
    /// Scheduling class — None if not available (old table format).
    pub ctrl_class: Option<crate::ctrl_class::CtrlClass>,
    /// Resolved hi_upper32 value from ctrl_class → ctrl_epoch chain.
    /// Contains mode bits [31:17] and default scheduling bits [16:0].
    pub epoch_upper32: Option<u32>,
}

/// The complete ISA table.
#[derive(Debug, Clone)]
pub struct IsaTable {
    /// Map from InsKey to modifier groups.
    pub entries: HashMap<String, InsKeyEntry>,
    /// ELF e_flags for the target architecture (from _meta.architecture).
    pub ef_flags: u32,
}

impl Default for IsaTable {
    fn default() -> Self {
        Self { entries: HashMap::new(), ef_flags: crate::elf_builder::EF_CUDA_SM120 }
    }
}

/// Map _meta.architecture (e.g. "SM103a") to CUDA ELF e_flags.
fn arch_ef_flags(arch: &str) -> Option<u32> {
    let a = arch.to_ascii_lowercase();
    // Order matters: "121" contains "12" but not "120"/"103"; check the
    // longer prefixes first and use exact 3-digit matches to stay unambiguous.
    if a.contains("121") { Some(0x0600_7902) }      // sm_121 / sm_121a (GB10, BUG-049)
    else if a.contains("103") { Some(0x0600_6702) } // sm_103 / sm_103a (B300)
    else if a.contains("120") { Some(0x0600_7802) } // sm_120
    else { None }
}

fn parse_hex_u128(s: &str) -> Result<u128> {
    let s = s.trim();
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u128::from_str_radix(digits, 16).with_context(|| format!("invalid hex: {s}"))
}

impl IsaTable {
    /// Numeric SM arch this table targets (from _meta.architecture e_flags).
    pub fn target_sm(&self) -> u32 {
        crate::elf::sm_from_ef_flags(self.ef_flags)
    }

    /// Load from a per-modifier-group JSON file.
    /// Load from default location: CUBIT_TABLE env var, then tables/sm120.json.
    pub fn load_default() -> Result<Self> {
        if let Ok(p) = std::env::var("CUBIT_TABLE") {
            return Self::load(Path::new(&p));
        }
        for p in &["tables/sm120.json", "sm120.json"] {
            let path = Path::new(p);
            if path.exists() { return Self::load(path); }
        }
        anyhow::bail!("Cannot find sm120.json. Set CUBIT_TABLE env var or run from the repo root.")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Detect format: unified ISA DB (has "_meta") or flat encoding
        if data.contains("\"_meta\"") && data.contains("\"instructions\"") {
            Self::from_json_unified(&data)
        } else {
            Self::from_json_flat(&data)
        }
    }

    /// Parse the unified ISA-DB format, extracting mod_groups and ctrl_class per InsKey.
    fn from_json_unified(json: &str) -> Result<Self> {
        use crate::ctrl_class::CtrlClass;

        let raw: serde_json::Value = serde_json::from_str(json).context("invalid JSON")?;

        // Build ctrl_class → epoch_upper32 resolver from _meta
        let epoch_map = Self::build_epoch_map(&raw);

        let instructions = raw.get("instructions").and_then(|v| v.as_object())
            .ok_or_else(|| anyhow::anyhow!("missing 'instructions' key"))?;

        let mut entries = HashMap::with_capacity(instructions.len());

        for (key, val) in instructions {
            let mg_val = match val.get("mod_groups") {
                Some(v) => v,
                None => continue,
            };

            let ctrl_class_str = val.get("ctrl_class").and_then(|v| v.as_str());
            let ctrl_class = ctrl_class_str.map(CtrlClass::parse);
            let epoch_upper32 = ctrl_class_str.and_then(|cc| epoch_map.get(cc).copied());

            // Re-serialize just mod_groups to reuse the flat parser logic
            let mut flat_entry = serde_json::Map::new();
            flat_entry.insert("mod_groups".to_string(), mg_val.clone());
            let flat_json = serde_json::to_string(&serde_json::Value::Object({
                let mut m = serde_json::Map::new();
                m.insert(key.clone(), serde_json::Value::Object(flat_entry));
                m
            }))?;

            let mut partial = Self::from_json_flat(&flat_json)?;
            if let Some(mut ike) = partial.entries.remove(key.as_str()) {
                ike.ctrl_class = ctrl_class;
                ike.epoch_upper32 = epoch_upper32;
                entries.insert(key.clone(), ike);
            }
        }

        let ef_flags = raw.get("_meta")
            .and_then(|m| m.get("architecture"))
            .and_then(|v| v.as_str())
            .and_then(arch_ef_flags)
            .unwrap_or(crate::elf_builder::EF_CUDA_SM120);
        Ok(IsaTable { entries, ef_flags })
    }

    /// Resolve _meta.ctrl_classes + _meta.ctrl_epochs into a map from
    /// ctrl_class name → resolved upper32 value.
    fn build_epoch_map(raw: &serde_json::Value) -> HashMap<String, u32> {
        let mut result = HashMap::new();
        let meta = match raw.get("_meta") {
            Some(m) => m,
            None => return result,
        };

        // Parse ctrl_epochs: epoch_name → upper32 hex value
        let mut epochs: HashMap<&str, u32> = HashMap::new();
        if let Some(ce) = meta.get("ctrl_epochs").and_then(|v| v.as_object()) {
            for (epoch_name, epoch_val) in ce {
                if let Some(hex) = epoch_val.get("upper32").and_then(|v| v.as_str()) {
                    if let Ok(v) = parse_hex_u128(hex) {
                        epochs.insert(epoch_name.as_str(), v as u32);
                    }
                }
            }
        }

        // Parse ctrl_classes: class_name → hi_upper32 (epoch reference) → resolve
        if let Some(cc) = meta.get("ctrl_classes").and_then(|v| v.as_object()) {
            for (class_name, class_val) in cc {
                if let Some(epoch_name) = class_val.get("hi_upper32").and_then(|v| v.as_str()) {
                    if let Some(&upper32) = epochs.get(epoch_name) {
                        result.insert(class_name.clone(), upper32);
                    }
                }
            }
        }

        result
    }

    /// Parse flat encoding format (cubit's sm120_encoding.json).
    fn from_json_flat(json: &str) -> Result<Self> {
        let jt: JsonTable = serde_json::from_str(json).context("failed to parse table JSON")?;
        let mut entries = HashMap::with_capacity(jt.0.len());

        for (key, jik) in jt.0 {
            let mut mod_groups = HashMap::with_capacity(jik.mod_groups.len());

            for (mods, jmg) in jik.mod_groups {
                let and_base = parse_hex_u128(&jmg.and_base)
                    .with_context(|| format!("bad and_base for {key}::{mods}"))?;

                let fields: Vec<Field> = jmg.fields.iter().map(|jf| {
                    let bits = jf.bits;
                    Field {
                        shift: jf.shift,
                        bits,
                        mask: if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 },
                        token_idx: jf.token_idx,
                        extraction: parse_extraction(&jf.extraction),
                    }
                }).collect();

                // Variable mask: from JSON if available, else from fields
                let variable_mask = jmg.variable_mask.as_ref()
                    .and_then(|s| parse_hex_u128(s).ok())
                    .unwrap_or_else(|| {
                        let mut vm: u128 = 0;
                        for f in &fields {
                            let fm = if f.bits >= 128 { u128::MAX } else { ((1u128 << f.bits) - 1) << f.shift };
                            vm |= fm;
                        }
                        vm
                    });

                mod_groups.insert(mods, ModGroupEntry { and_base, variable_mask, fields });
            }

            entries.insert(key, InsKeyEntry { mod_groups, ctrl_class: None, epoch_upper32: None });
        }

        Ok(IsaTable { entries, ef_flags: crate::elf_builder::EF_CUDA_SM120 })
    }

    /// Look up encoding for (InsKey, modifier_group).
    pub fn get(&self, key: &str, mod_group: &str) -> Option<&ModGroupEntry> {
        self.entries.get(key)?.mod_groups.get(mod_group)
    }

    /// Get the InsKey entry (all modifier groups).
    pub fn get_key(&self, key: &str) -> Option<&InsKeyEntry> {
        self.entries.get(key)
    }

    /// Look up the ctrl_class for an InsKey. Returns None if the key is
    /// unknown or the table was loaded from a format without ctrl_class data.
    pub fn ctrl_class(&self, key: &str) -> Option<&crate::ctrl_class::CtrlClass> {
        self.entries.get(key)?.ctrl_class.as_ref()
    }

    /// Look up the resolved epoch upper32 for an InsKey.
    /// Returns None if the key is unknown or the table lacks epoch data.
    pub fn epoch_upper32(&self, key: &str) -> Option<u32> {
        self.entries.get(key)?.epoch_upper32
    }

    pub fn num_keys(&self) -> usize {
        self.entries.len()
    }

    pub fn num_groups(&self) -> usize {
        self.entries.values().map(|e| e.mod_groups.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Backward-compatible Record type (for validation)
// ---------------------------------------------------------------------------

/// A validation record: (addr, code128, asm, key, mod_group).
#[derive(Debug, Clone)]
pub struct Record {
    pub addr: u32,
    pub code: u128,
    pub asm: String,
    pub key: String,
    pub mod_group: String,
}

/// Load records from JSONL, computing modifier group for each.
pub fn load_records(path: &Path) -> Result<Vec<Record>> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let sched_mask: u128 = 0x1FFFF_u128 << (64 + 41);
    let mut records = Vec::new();

    for line in data.lines() {
        if line.trim().is_empty() { continue; }
        let v: serde_json::Value = serde_json::from_str(line)?;
        let key = v["key"].as_str().unwrap_or("").to_string();
        let addr = v["addr"].as_u64().unwrap_or(0) as u32;
        let code_str = v["code"].as_str().unwrap_or("0x0");
        let code = parse_hex_u128(code_str)? & !sched_mask;
        let asm = v["asm"].as_str().unwrap_or("").to_string();

        // Derive modifier group from ASM
        let mod_group = extract_mod_group(&asm);

        records.push(Record { addr, code, asm, key, mod_group });
    }
    Ok(records)
}

/// Extract modifier group from ASM text.
/// E.g., "@P0 IADD3.X R5, ..." → "X"
/// E.g., "LDG.E.128 R12, ..." → "128,E"
pub fn extract_mod_group(asm: &str) -> String {
    let t = asm.trim();
    // Remove scheduling annotations
    let t = if let Some(pos) = t.find("&") { &t[..pos] } else { t };
    let t = t.trim().trim_end_matches(';').trim();
    // Remove guard
    let t = if t.starts_with('@') {
        t.split_whitespace().nth(1).map(|rest| {
            let idx = t.find(rest).unwrap_or(0);
            &t[idx..]
        }).unwrap_or(t)
    } else { t };
    // Get mnemonic (first token)
    let mnemonic = t.split_whitespace().next().unwrap_or("");
    let parts: Vec<&str> = mnemonic.split('.').collect();
    if parts.len() <= 1 {
        String::new()
    } else {
        let mut mods: Vec<&str> = parts[1..].iter()
            .filter(|s| !s.is_empty() && !s.starts_with('?'))
            .copied()
            .collect();
        mods.sort();
        mods.join(",")
    }
}
