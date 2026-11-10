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

/// The SM120 table compiled into the binary (used when no `tables/` directory
/// is reachable and for the compile-time aux sections). Vendored gzip-compressed
/// (2026-11-04: `tables/<arch>.json.gz` are the files in git; the plain JSON is
/// a generated, git-ignored convenience written by `tools/sync_table.py --unpack`).
const BUNDLED_SM120_GZ: &[u8] = include_bytes!("../tables/sm120.json.gz");

/// The bundled SM120 table as JSON text, decompressed once per process.
fn bundled_sm120_json() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| {
        let bytes = gunzip(BUNDLED_SM120_GZ).expect("the bundled SM120 table is a valid gzip stream");
        String::from_utf8(bytes).expect("the bundled SM120 table is UTF-8 JSON")
    })
}

/// Decompress one gzip member (the vendored tables are written by Python's
/// `gzip.compress(..., mtime=0)`: a single member, ISIZE trailer = plain length).
fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let hint = if data.len() >= 4 {
        u32::from_le_bytes([data[data.len() - 4], data[data.len() - 3], data[data.len() - 2], data[data.len() - 1]]) as usize
    } else { 0 };
    let mut out = Vec::with_capacity(hint);
    flate2::read::MultiGzDecoder::new(data).read_to_end(&mut out).context("gzip stream is corrupt")?;
    Ok(out)
}

/// `true` when `path` can be opened by [`read_table_bytes`]: the file itself
/// or its gzip-compressed twin `<path>.gz` exists.
pub fn table_file_available(path: &Path) -> bool {
    path.is_file() || gz_twin(path).is_some_and(|gz| gz.is_file())
}

fn gz_twin(path: &Path) -> Option<std::path::PathBuf> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".gz") { return None; }
    Some(path.with_file_name(format!("{name}.gz")))
}

/// Read a table file transparently: `tables/sm120.json` is served from the
/// plain file when it exists, else from `tables/sm120.json.gz` (decompressed);
/// a path ending in `.gz` is always decompressed. The bytes returned are the
/// canonical JSON bytes that `tables/SOURCE.json` pins (SHA-256 of the plain
/// text), whichever file they came from. Decompressed bytes are cached per
/// process (keyed by path, length and mtime of the `.gz` file), so the test
/// suite's repeated loads of one table decompress it once.
pub fn read_table_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    let is_gz = path.extension().is_some_and(|e| e == "gz");
    if !is_gz && path.is_file() {
        return std::fs::read(path).with_context(|| format!("failed to read {}", path.display()));
    }
    let gz_path = if is_gz { path.to_path_buf() } else {
        match gz_twin(path) {
            Some(gz) if gz.is_file() => gz,
            _ => anyhow::bail!(
                "table file not found: {} (neither the plain JSON nor its gzip twin {}.gz exists; \
                 the vendored tables are `tables/<arch>.json.gz`, run from the repository root or \
                 pass --table / CUBIT_TABLE)", path.display(), path.display()),
        }
    };
    use std::sync::{Arc, Mutex, OnceLock};
    type Key = (std::path::PathBuf, u64, Option<std::time::SystemTime>);
    static CACHE: OnceLock<Mutex<HashMap<Key, Arc<Vec<u8>>>>> = OnceLock::new();
    let meta = std::fs::metadata(&gz_path).with_context(|| format!("failed to stat {}", gz_path.display()))?;
    let key: Key = (gz_path.canonicalize().unwrap_or_else(|_| gz_path.clone()), meta.len(), meta.modified().ok());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
        return Ok((*hit).clone());
    }
    let raw = std::fs::read(&gz_path).with_context(|| format!("failed to read {}", gz_path.display()))?;
    let plain = gunzip(&raw).with_context(|| format!("failed to decompress {}", gz_path.display()))?;
    if let Ok(mut c) = cache.lock() { c.insert(key, Arc::new(plain.clone())); }
    Ok(plain)
}

/// [`read_table_bytes`] as UTF-8 text.
pub fn read_table_text(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    String::from_utf8(read_table_bytes(path)?)
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

/// Identity of the file [`read_table_bytes`] serves `path` from (the plain
/// file, or its gzip twin): canonical path, size, modification time.
type TableFileKey = (std::path::PathBuf, u64, Option<std::time::SystemTime>);

fn table_file_identity(path: &Path) -> Option<TableFileKey> {
    let file = if path.is_file() { path.to_path_buf() } else { gz_twin(path).filter(|gz| gz.is_file())? };
    let meta = std::fs::metadata(&file).ok()?;
    Some((file.canonicalize().unwrap_or(file), meta.len(), meta.modified().ok()))
}

/// The per-process cache of parsed tables behind [`IsaTable::load`].
fn parsed_table_cache() -> &'static std::sync::Mutex<HashMap<TableFileKey, std::sync::Arc<IsaTable>>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<TableFileKey, std::sync::Arc<IsaTable>>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// `false` the first time a key is seen in this process, `true` from then on.
fn seen_once(key: &TableFileKey) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<TableFileKey>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    match seen.lock() {
        Ok(mut s) => !s.insert(key.clone()),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// JSON schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JsonTable(HashMap<String, JsonInsKey>);

#[derive(Deserialize)]
struct JsonInsKey {
    pub mod_groups: HashMap<String, JsonModGroup>,
    /// BUG-090: rows visible to the ENCODER only (decoder skips them).
    /// For frozen-era text compatibility rows whose decode surface must not
    /// shadow canonical rows (legacy harvest-junk names kept load-bearing
    /// for pinned publish text).
    #[serde(default)]
    pub encode_only: bool,
    /// The key's provenance tag (2026-11-08, `tools/tablefmt.py`): set when every row of the key
    /// carries the same `_src`; a row without its own `_src` inherits it.
    #[serde(default, rename = "_src")]
    pub src: Option<String>,
}

/// BUG-452: claim-forbid value exclusions on a mod group (donor-first claim
/// narrowing). Each entry forbids the listed values at bits
/// [shift, shift+bits): the decoder drops the candidate and the encoder
/// refuses to mint (fail-closed), so shapes the vendor rejects (rc=1) or
/// prints with an invalid-operand glyph (`???255.64`) are never claimed nor
/// emitted. Rows without the attr keep legacy cube-claim behavior (same
/// doctrine as BUG-099 addr_width).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonClaimForbid {
    pub shift: u32,
    pub bits: u32,
    pub values: Vec<u64>,
}

#[derive(Deserialize)]
struct JsonModGroup {
    pub and_base: String,
    pub variable_mask: Option<String>,
    pub fields: Vec<JsonField>,
    #[allow(dead_code)]
    pub count: Option<usize>,
    /// BUG-092: mod-group-level encode-only retention (decoder skips this
    /// group, encoder sees it). Key-level `encode_only` hides a whole InsKey;
    /// some frozen-era legacy renders ('?'-mod glyph soup) resolve to
    /// (base_key, "") which must coexist with canonical groups on the same key.
    #[serde(default)]
    pub encode_only: bool,
    /// BUG-099: uniform-indexed GLOBAL address rows (LDG/STG `R_ARURI` /
    /// `ARURI_R` keys) encode a real width mode in bits [92:90] that nvdisasm
    /// prints as `[Rn.U32+URm]` vs `[Rn.64+URm]`. Two rows for the same
    /// textual key+mg exist (".U32" harvest-native and repaired ".64"), so the
    /// textual bracket suffix is the only encoder discriminator. Rows may pin
    /// `"U32"` or `"64"`; a mismatched textual suffix is a hard miss
    /// (pre-fix it silently encoded the wrong mode). Rows without the attr
    /// keep legacy suffix-blind behavior.
    #[serde(default)]
    pub addr_width: Option<String>,
    /// BUG-452: optional claim-forbid value exclusions (parsed into
    /// ModGroupEntry::claim_forbid); absent = legacy cube-claim behavior.
    #[serde(default)]
    pub claim_forbid: Vec<JsonClaimForbid>,
    /// The row's provenance tag (`_meta.provenance.sources`); `rows-<family>-2026-11-07` marks a row verified
    /// field by field over the whole word by `tools/probes/re_sm120_rows.py` (session G run 5) -- such a row has a
    /// field on every live slot and fails closed on the rest, so the decoder keeps it off the broad match.
    #[serde(default, rename = "_src")]
    pub src: Option<String>,
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
    /// BUG-169: uniform predicate (UP slot) split from Pred at parse time.
    /// Bit semantics are identical to Pred (3-bit sel, 7 = UPT sentinel);
    /// the variant exists so the decoder tiebreak
    /// (key_field_consistency_score) and the printer can SEE UP-domain fields
    /// — the pre-fix "pred" | "upred" collapse made is_upred unreachable and
    /// let P-domain junk rows out-score correct UP rows on sm120.
    UPred,
    /// MMA accumulate-gate UP (QMMA/HMMA trailing UP operand @87 + inv@90).
    /// BUG-032: ONLY this slot uses nvdisasm's INVERTED naming (sel = 7-n,
    /// UPT = sel 0); every other upred field on sm_120 is straight (sel = n,
    /// UPT = sel 7) per the i93 field census (206775 UP records).
    UPredGate,
    /// Trailing guard-pred inverted 4-bit map (sm_121a convention; LDG
    /// \[67:64\] / .256 \[90:87\] windows): PT/none -> 0, Pn -> 7-n, !PT -> 8,
    /// !Pn -> 15-n. Ported 1:1 from the SM121a fleet implementation (q2
    /// iter38) — same window as `pred` on sm_103a, different value mapping.
    PredInv4,
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
    F2fpScaleSel,
    F2fpRaByteSel,
    // Half-register pair selector parsed from raw text (.H0_H0/.H0_H1/.H1_H1):
    // sm_103a fp16x2-class ops encode it as 2 bits (none=0, H0_H1=1, H0_H0=2,
    // H1_H1=3), empirically pure over the corpus.
    HalfSel,
    /// BUG-271: single-bit operand suffix '.H0_NH1' — the third bit of the
    /// tok3 3-bit hsel-suffix window on the HFMA2 packed-f16 imm family
    /// (window (b86,b82,b81)) and the sm121a BF16_V2 host rows (window
    /// (b86,b61,b60)). arb271/arb264/arb279 (nvdisasm 13.3.73 raw -b, x4
    /// models agree): value 4 = '.H0_NH1' composing signs; values 5..7 =
    /// vendor '.INVALID{5,6,7}' (decode hole + fail-closed encode).
    H0NH1,
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

fn parse_extraction(s: &str) -> Result<Extraction> {
    Ok(match s {
        "guard" => Extraction::Guard,
        "guard_lo3" => Extraction::GuardLo3,
        "guard_neg" => Extraction::GuardNeg,
        "reg" => Extraction::Reg,
        "ureg" => Extraction::UReg,
        "ureg_ff" => Extraction::URegFf,
        "reg_ff" => Extraction::RegFf,
        "pred" => Extraction::Pred,
        "upred" => Extraction::UPred,
        "upred_gate" => Extraction::UPredGate,
        "pred_inv4" => Extraction::PredInv4,
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
        "f2fp_scale_sel" => Extraction::F2fpScaleSel,
        "f2fp_ra_b1" | "f2fp_ra_b2" => Extraction::F2fpRaByteSel,
        "hsel" => Extraction::HalfSel,
        "h0nh1" => Extraction::H0NH1,
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
            let n: u8 = s[7..].parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            Extraction::RegShr(n)
        }
        s if s.starts_with("ureg_shr") => {
            let n: u8 = s[8..].parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            Extraction::URegShr(n)
        }
        s if s.starts_with("imm_shr") => {
            let n: u8 = s[7..].parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            Extraction::ImmShr(n)
        }
        s if s.starts_with("sub_r") && s.contains("_shr") => {
            // e.g. "sub_r0_shr1", "sub_r1_shr2"
            let parts: Vec<&str> = s.split('_').collect();
            let idx: u8 = parts.get(1).and_then(|p| p.strip_prefix('r'))
                .ok_or_else(|| anyhow::anyhow!("invalid extraction '{s}'"))?.parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            let shr: u8 = parts.get(2).and_then(|p| p.strip_prefix("shr"))
                .ok_or_else(|| anyhow::anyhow!("invalid extraction '{s}'"))?.parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            Extraction::SubRShr(idx, shr)
        }
        s if s.starts_with("sub_ur") && s.contains("_shr") => {
            let parts: Vec<&str> = s.split('_').collect();
            let idx: u8 = parts.get(1).and_then(|p| p.strip_prefix("ur"))
                .ok_or_else(|| anyhow::anyhow!("invalid extraction '{s}'"))?.parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            let shr: u8 = parts.get(2).and_then(|p| p.strip_prefix("shr"))
                .ok_or_else(|| anyhow::anyhow!("invalid extraction '{s}'"))?.parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            Extraction::SubURShr(idx, shr)
        }
        s if s.starts_with("sub_imm") && s.contains("_shr") => {
            let parts: Vec<&str> = s.split('_').collect();
            let idx: u8 = parts.get(1).and_then(|p| p.strip_prefix("imm"))
                .ok_or_else(|| anyhow::anyhow!("invalid extraction '{s}'"))?.parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            let shr: u8 = parts.get(2).and_then(|p| p.strip_prefix("shr"))
                .ok_or_else(|| anyhow::anyhow!("invalid extraction '{s}'"))?.parse()
                .with_context(|| format!("invalid extraction '{s}'"))?;
            Extraction::SubImmShr(idx, shr)
        }
        "yield_inv" => Extraction::YieldInv,
        _ => anyhow::bail!("unknown extraction '{s}'"),
    })
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
/// BUG-452: parsed form of JsonClaimForbid.
#[derive(Debug, Clone)]
pub struct ClaimForbid {
    pub shift: u32,
    pub bits: u32,
    pub values: Vec<u64>,
}

impl ClaimForbid {
    /// True when `code` carries a forbidden value at this guard's window.
    pub fn rejects(&self, code: u128) -> bool {
        let m: u128 = if self.bits >= 128 { u128::MAX } else { (1u128 << self.bits) - 1 };
        let v = (code >> self.shift) & m;
        self.values.iter().any(|&fv| fv as u128 == v)
    }
}

#[derive(Debug, Clone)]
pub struct ModGroupEntry {
    /// Constant bits (AND of all codes in this group, excluding variable bits).
    pub and_base: u128,
    /// BUG-452: value exclusions of the claim cube (see JsonClaimForbid).
    /// The cube model (and_base/variable_mask) cannot express "any value but
    /// 255"; guards live here as plain (shift, bits, values) triples.
    pub claim_forbid: Vec<ClaimForbid>,
    /// Mask of all variable bits (for decode matching).
    pub variable_mask: u128,
    /// Variable fields with extraction rules.
    pub fields: Vec<Field>,
    /// BUG-092: encoder-visible, decoder-invisible mod group (legacy frozen
    /// text compatibility at (base_key, "") granularity; canonical groups on
    /// the same key still own the decode surface).
    pub encode_only: bool,
    /// BUG-099: optional pinned address width for uniform-indexed global
    /// address rows ("U32"/"64"); see JsonModGroup::addr_width.
    pub addr_width: Option<String>,
    /// Verified field by field over the whole word by the per-row probe (session G run 5, `_src` =
    /// `rows-<family>-2026-11-07`): the decoder's broad match (standard register slots freed for memory keys) is
    /// off for the row -- its mask is exactly its fields, fail closed on the text-inert slots.
    pub row_probe: bool,
}

/// The modifier groups of one instruction key, shared between the key and its
/// `_meta.key_aliases` clones.
///
/// 2026-11-07 (session T-16, BUG-487): the alias clones used to deep-copy the target's
/// whole group map (`InsKeyEntry::clone`), which is quadratic in the measured
/// lattices -- `REDG_ARURI_R` has 6 144 groups and 3 072 aliases, so the sm120
/// table at blackwell-isa `3a94df3` materialised 36.7 million `ModGroupEntry`
/// copies for its 39 203 rows: `cubit decode` of one word took 21 GB of RAM and
/// 8.5 s (3.9 GB / 1.9 s at `5cb10e5`), every test binary 40-55 GB, and sixteen
/// of them in parallel drove the build host out of memory. An alias now shares
/// the target's groups through an `Arc` (the clone is one pointer); the entry
/// keeps its own `encode_only` flag, so the alias stays encoder-visible and
/// decoder-invisible as before. Reads are unchanged: the wrapper derefs to the
/// map and `&mod_groups` iterates it.
#[derive(Debug, Clone, Default)]
pub struct ModGroups(std::sync::Arc<HashMap<String, ModGroupEntry>>);

impl ModGroups {
    /// Shared ownership of the same group map (the alias clone).
    pub fn shares_with(&self, other: &ModGroups) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }

    /// Mutable access, copy-on-write: a map shared with an alias is copied first, so
    /// editing a key's rows (the tests' row poisoning) never edits its aliases' view.
    pub fn make_mut(&mut self) -> &mut HashMap<String, ModGroupEntry> {
        std::sync::Arc::make_mut(&mut self.0)
    }
}

impl From<HashMap<String, ModGroupEntry>> for ModGroups {
    fn from(m: HashMap<String, ModGroupEntry>) -> Self {
        ModGroups(std::sync::Arc::new(m))
    }
}

impl std::ops::Deref for ModGroups {
    type Target = HashMap<String, ModGroupEntry>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> IntoIterator for &'a ModGroups {
    type Item = (&'a String, &'a ModGroupEntry);
    type IntoIter = std::collections::hash_map::Iter<'a, String, ModGroupEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut ModGroups {
    type Item = (&'a String, &'a mut ModGroupEntry);
    type IntoIter = std::collections::hash_map::IterMut<'a, String, ModGroupEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.make_mut().iter_mut()
    }
}

/// All modifier groups for one instruction key.
#[derive(Debug, Clone)]
pub struct InsKeyEntry {
    /// Map from modifier group string ("", "X", "64,E", etc.) to encoding
    /// (shared with the key's `_meta.key_aliases` clones, see [`ModGroups`]).
    pub mod_groups: ModGroups,
    /// Scheduling class — None if not available (old table format).
    pub ctrl_class: Option<crate::ctrl_class::CtrlClass>,
    /// Resolved hi_upper32 value from ctrl_class → ctrl_epoch chain.
    /// Contains mode bits \[31:17\] and default scheduling bits \[16:0\].
    pub epoch_upper32: Option<u32>,
    /// BUG-090: encoder-visible, decoder-invisible row (frozen-era text
    /// compatibility). DecodeIndex::build skips these keys.
    pub encode_only: bool,
}

/// The complete ISA table.
#[derive(Debug, Clone)]
pub struct IsaTable {
    /// Map from InsKey to modifier groups.
    pub entries: HashMap<String, InsKeyEntry>,
    /// ELF e_flags for the target architecture (from _meta.architecture).
    pub ef_flags: u32,
    /// Aux sections carried inside the canonical table (O2 layout: one table
    /// per arch from blackwell-isa holds cost_model / stallfix / operand_roles
    /// next to the encoding rows; cubit owns no sidecar files anymore).
    pub aux: HashMap<String, serde_json::Value>,
    /// Lazily-built shared decode index (BUG-132: encoder decode-back checks).
    #[doc(hidden)]
    pub decode_index_cache: DecodeIndexCache,
}

impl Default for IsaTable {
    fn default() -> Self {
        Self { entries: HashMap::new(), ef_flags: crate::elf_builder::EF_CUDA_SM120,
               aux: HashMap::new(),
               decode_index_cache: DecodeIndexCache::default() }
    }
}

/// Lazily-built [`crate::decoder::DecodeIndex`] cache hanging off an
/// [`IsaTable`]. Building the index costs one pass over the table (the
/// `cubit decode` path did it per invocation); the encoder's BUG-132
/// decode-back check needs it inside tight batch loops, so it is built at
/// most once per table and Arc-shared. Never printed (index dumps are huge).
pub struct DecodeIndexCache(std::sync::OnceLock<std::sync::Arc<crate::decoder::DecodeIndex>>);

impl Clone for DecodeIndexCache {
    fn clone(&self) -> Self {
        Self(match self.0.get() {
            Some(v) => std::sync::OnceLock::from(v.clone()),
            None => std::sync::OnceLock::new(),
        })
    }
}

impl Default for DecodeIndexCache {
    fn default() -> Self { Self(std::sync::OnceLock::new()) }
}

impl std::fmt::Debug for DecodeIndexCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.get().is_some() {
            "DecodeIndexCache(cached)"
        } else {
            "DecodeIndexCache(empty)"
        })
    }
}

/// Map _meta.architecture (e.g. "SM103a") to CUDA ELF e_flags.
fn arch_ef_flags(arch: &str) -> Option<u32> {
    let a = arch.to_ascii_lowercase();
    // Order matters: "121" contains "12" but not "120"/"103"; check the
    // longer prefixes first and use exact 3-digit matches to stay unambiguous.
    if a.contains("121") { Some(0x0600_7902) }      // sm_121 / sm_121a (GB10, BUG-049)
    else if a.contains("103") { Some(0x0600_6702) } // sm_103 / sm_103a (B300)
    else if a.contains("100") { Some(0x0600_640a) } // sm_100 / sm_100a (B200)
    else if a.contains("120") { Some(0x0600_7802) } // sm_120
    else { None }
}

/// Encoding-layer family predicate: the sm_100a/sm_103a encoding layer is
/// byte-identical (119/119 tcgen05 probe-pair parity; O2 sm100a derivative),
/// so every arch-gated encoding decision made for sm_103a applies verbatim
/// to the sm_100 family (both generic 0x02 and 'a' 0x0a e_flags variants).
pub fn is_sm103a_encoding_family(ef_flags: u32) -> bool {
    matches!((ef_flags >> 8) & 0xFFF, 100 | 103)
}

/// Encoding-layer family predicate for the consumer-Blackwell line: sm_120
/// (RTX 5090, 0x78) and sm_121a (GB10, 0x79) share the SM120 encoding space
/// (the sm121a table is delta-driven vs sm120; GB10 census 2026-11-04: 0 decode
/// differences over 91 927 words). Printer decisions gated on sm_120 therefore
/// apply verbatim to sm_121a (e.g. the ATOMS/ARRIVES `[Rm+URn(+off)]` glyph).
///
/// Wave 11 note: the same predicate is what the lane's BUG-496 arm reads for
/// WARPSYNC.COLLECTIVE -- sm_120/sm_121 use the 496-era 8-bit target law
/// (target = addr + 0x10 + (byte2 << 2), arb496 x4) instead of the sm_100/103
/// REL16 layout of BUG-116. Nothing outside WARPSYNC keys on it.
pub fn is_sm120_encoding_family(ef_flags: u32) -> bool {
    matches!((ef_flags >> 8) & 0xFFF, 120 | 121)
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

    /// Shared decode index (built at most once per table). Used by the
    /// encoder's BUG-132 decode-back verification; CLI/py decode paths keep
    /// their own long-lived indexes.
    pub fn decode_index(&self) -> std::sync::Arc<crate::decoder::DecodeIndex> {
        self.decode_index_cache.0
            .get_or_init(|| std::sync::Arc::new(crate::decoder::DecodeIndex::build(self)))
            .clone()
    }

    /// Load from a per-modifier-group JSON file.
    /// Load from default location: CUBIT_TABLE env var, then tables/sm120.json.
    pub fn load_default() -> Result<Self> {
        if let Ok(p) = std::env::var("CUBIT_TABLE") {
            return Self::load(Path::new(&p));
        }
        for p in &["tables/sm120.json", "sm120.json"] {
            let path = Path::new(p);
            if table_file_available(path) { return Self::load(path); }
        }
        Self::from_json_unified(bundled_sm120_json())
            .context("failed to load the bundled SM120 table")
    }

    /// Load a table file; `tables/<arch>.json` is read from the plain file or,
    /// when only the vendored `tables/<arch>.json.gz` exists, decompressed on
    /// the fly ([`read_table_text`]). `@bundled` selects the compiled-in SM120 table.
    ///
    /// Parsed tables are cached per process from the second load of the same
    /// file on (keyed by the file's path, size and modification time, so a
    /// rewritten table is parsed again): parsing the 56 MB SM120 JSON costs
    /// ~0.4 s in release, a clone of the parsed table ~10 ms, and a test
    /// binary loads the same four tables once per test. A process that loads
    /// a table once (the CLI) pays nothing — no master copy is kept until a
    /// second load shows the table is reused. `CUBIT_TABLE_CACHE=0` disables it.
    pub fn load(path: &Path) -> Result<Self> {
        if path == Path::new("@bundled") {
            return Self::from_json_unified(bundled_sm120_json())
                .context("failed to load the bundled SM120 table");
        }
        let key = if std::env::var("CUBIT_TABLE_CACHE").is_ok_and(|v| v == "0") {
            None
        } else {
            table_file_identity(path)
        };
        if let Some(k) = &key {
            if let Some(hit) = parsed_table_cache().lock().ok().and_then(|c| c.get(k).cloned()) {
                return Ok((*hit).clone());
            }
        }
        let data = read_table_text(path)?;
        let table = Self::from_json(&data)?;
        if let Some(k) = key {
            if let Ok(mut c) = parsed_table_cache().lock() {
                // a parallel loader may have filled it meanwhile (keep theirs); the first
                // load of a file records the key only, the second stores the master copy
                if let std::collections::hash_map::Entry::Vacant(slot) = c.entry(k.clone()) {
                    if seen_once(&k) {
                        slot.insert(std::sync::Arc::new(table.clone()));
                    }
                }
            }
        }
        Ok(table)
    }

    /// Load exactly the JSON bytes a caller has already hashed or snapshotted.
    pub fn from_json(data: &str) -> Result<Self> {
        // Detect format: unified ISA DB (has "_meta") or flat encoding
        if data.contains("\"_meta\"") && data.contains("\"instructions\"") {
            Self::from_json_unified(data)
        } else {
            Self::from_json_flat(data)
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
            let encode_only = val.get("encode_only").and_then(|v| v.as_bool()).unwrap_or(false);
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
                ike.encode_only = encode_only;
                entries.insert(key.clone(), ike);
            }
        }

        // `_meta.key_aliases` (blackwell-isa, 2026-11-04): retired key names that
        // still resolve. The target entry is cloned under the old name as an
        // encoder-visible, decoder-invisible entry: `table.entries[old]` and text
        // written with the old mnemonic keep working, the decoder never prints the
        // retired name (the 20 era keys with a glued predicate token in the
        // mnemonic, `QMMA.16816.F16.E4M3.E4M3_P0_R_R_R_R` -> `..._R_R_R_R`, are the
        // first use; docs/KNOWN_ISSUES.md T1, blackwell-isa README "Data Model").
        // The clone shares the target's group map (`ModGroups`, an Arc): with the
        // measured lattices of 2026-11-07 (14 613 aliases, targets of up to 6 144
        // groups) a deep copy was 36.7 million rows and 21 GB per process.
        if let Some(aliases) = raw.get("_meta").and_then(|m| m.get("key_aliases")).and_then(|v| v.as_object()) {
            for (old, new) in aliases {
                let Some(target) = new.as_str() else { continue };
                if entries.contains_key(old.as_str()) {
                    anyhow::bail!("_meta.key_aliases: alias {old} collides with an instruction key");
                }
                let Some(src) = entries.get(target) else {
                    anyhow::bail!("_meta.key_aliases: alias {old} -> {target}: target is not in the table");
                };
                let mut ike = src.clone();
                ike.encode_only = true;
                entries.insert(old.clone(), ike);
            }
        }

        let ef_flags = raw.get("_meta")
            .and_then(|m| m.get("architecture"))
            .and_then(|v| v.as_str())
            .and_then(arch_ef_flags)
            .unwrap_or(crate::elf_builder::EF_CUDA_SM120);
        let aux = ["cost_model", "stallfix", "operand_roles"]
            .iter()
            .filter_map(|k| raw.get(*k).map(|v| (k.to_string(), v.clone())))
            .collect();
        Ok(IsaTable { entries, ef_flags, aux, decode_index_cache: DecodeIndexCache::default() })
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

                let fields: Vec<Field> = jmg.fields.iter().map(|jf| -> Result<Field> {
                    let bits = jf.bits;
                    let end = jf.shift.checked_add(bits)
                        .ok_or_else(|| anyhow::anyhow!(
                            "field range overflow for {key}::{mods}: shift={}, bits={bits}",
                            jf.shift
                        ))?;
                    if bits == 0 || end > 128 {
                        anyhow::bail!(
                            "field outside 128-bit instruction for {key}::{mods}: \
                             shift={}, bits={bits}",
                            jf.shift
                        );
                    }
                    Ok(Field {
                        shift: jf.shift,
                        bits,
                        mask: if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 },
                        token_idx: jf.token_idx,
                        extraction: parse_extraction(&jf.extraction)
                            .with_context(|| format!(
                                "bad extraction for {key}::{mods} at shift {}", jf.shift
                            ))?,
                    })
                }).collect::<Result<Vec<_>>>()?;

                // Variable mask: from JSON if available, else from fields
                let variable_mask = if let Some(mask) = jmg.variable_mask.as_ref() {
                    parse_hex_u128(mask)
                        .with_context(|| format!("bad variable_mask for {key}::{mods}"))?
                } else {
                        let mut vm: u128 = 0;
                        for f in &fields {
                            let fm = if f.bits >= 128 { u128::MAX } else { ((1u128 << f.bits) - 1) << f.shift };
                            vm |= fm;
                        }
                        vm
                };

                let row_probe = jmg.src.as_deref().or(jik.src.as_deref()).is_some_and(|s| s.starts_with("rows-"));
                mod_groups.insert(mods, ModGroupEntry { and_base, claim_forbid: jmg.claim_forbid.iter().map(|cf| ClaimForbid { shift: cf.shift, bits: cf.bits, values: cf.values.clone() }).collect(), variable_mask, fields, encode_only: jmg.encode_only, addr_width: jmg.addr_width.clone(), row_probe });
            }

            entries.insert(key, InsKeyEntry { mod_groups: mod_groups.into(), ctrl_class: None, epoch_upper32: None, encode_only: jik.encode_only });
        }

        Ok(IsaTable { entries, ef_flags: crate::elf_builder::EF_CUDA_SM120, aux: HashMap::new(),
                      decode_index_cache: DecodeIndexCache::default() })
    }

    /// Look up encoding for (InsKey, modifier_group).
    pub fn get(&self, key: &str, mod_group: &str) -> Option<&ModGroupEntry> {
        self.entries.get(key)?.mod_groups.get(mod_group)
    }

    /// Get the InsKey entry (all modifier groups).
    pub fn get_key(&self, key: &str) -> Option<&InsKeyEntry> {
        self.entries.get(key)
    }

    /// Top-level aux section shipped inside the canonical table
    /// (`cost_model` / `stallfix` / `operand_roles`; O2 single-table layout).
    pub fn aux_section(&self, name: &str) -> Option<&serde_json::Value> {
        self.aux.get(name)
    }

    /// Aux section of the BUNDLED sm120 table, parsed once. Backs data tables
    /// that historically lived as separate files under tables/ and are
    /// compile-time assets (operand roles for the liveness/RA passes).
    /// The canonical tables carry identical operand_roles per arch, so the
    /// bundled copy is authoritative regardless of the active arch.
    pub fn bundled_aux(name: &str) -> Option<serde_json::Value> {
        use std::sync::OnceLock;
        static RAW: OnceLock<Option<serde_json::Value>> = OnceLock::new();
        let raw = RAW.get_or_init(|| serde_json::from_str(bundled_sm120_json()).ok());
        raw.as_ref()?.get(name).cloned()
    }

    /// If `text` is a full canonical ISA table carrying the aux section
    /// `key`, return that section re-serialized; otherwise `None` and the
    /// caller parses `text` as the aux payload directly. Lets --cost/--rules
    /// accept either the standalone data file (legacy) or the single
    /// per-arch table (O2 layout).
    pub fn embedded_section(text: &str, key: &str) -> Option<String> {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        if v.get("instructions").is_none() && v.get("_meta").is_none() {
            return None;
        }
        let sec = v.get(key)?;
        serde_json::to_string(sec).ok()
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

    /// The number of encoding rows: every group map counted once (an alias entry shares its
    /// target's map, see [`ModGroups`] — before 2026-11-07 the aliases' copies were summed too).
    pub fn num_groups(&self) -> usize {
        let mut seen: std::collections::HashSet<*const HashMap<String, ModGroupEntry>> = std::collections::HashSet::new();
        self.entries
            .values()
            .filter(|e| seen.insert(std::sync::Arc::as_ptr(&e.mod_groups.0)))
            .map(|e| e.mod_groups.len())
            .sum()
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

/// BUG-279: true when a table/instruction key belongs to the HFMA2 packed-f16
/// immediate family grafted in BUG-279 (parents HFMA2_R_R_R_{II_FI,FI_FI,II_II},
/// their RELU _P dotted keys and the new FTZ/OOB dotted keys). Used by the
/// printer/encoder arms for the tok3 hsel window \[82:81\] (vendor value 1 =
/// the ".F32" operand modifier on this family, arb279/arb279b x4 models).
pub fn hfma2_immfam_key(key: &str) -> bool {
    if !key.starts_with("HFMA2") {
        return false;
    }
    let toks: Vec<&str> = key.split('_').collect();
    let t: &[&str] = if toks.last() == Some(&"P") {
        &toks[..toks.len() - 1]
    } else {
        &toks[..]
    };
    if t.len() < 4 || t[1..4] != ["R", "R", "R"] {
        return false;
    }
    matches!(
        (t[t.len() - 2], t[t.len() - 1]),
        ("II", "FI") | ("FI", "FI") | ("II", "II")
    )
}

/// BUG-297: hsel value-validity law on the UR half-select tokens of the
/// packed-f16 pair families. arb273 (A1/A5/C4) + arb297/arb297b (nvdisasm
/// 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a agree on every
/// probe): on these rows a UR token hsel value 1 is vendor-ILLEGAL and
/// nvdisasm prints the operand as `URn.INVALID1`; values 2/3 stay the
/// legal `.H0_H0`/`.H1_H1`. Scope = exactly the table keys whose rows
/// carry a UR token with an hsel field (iter151 tables census, all four
/// legs): HFMA2_R_R_R_UR (UR tok4), HMUL2_R_R_UR ''+'BF16_V2' (tok3),
/// HSETP2_P_P_R_UR_P (tok4, all mod-groups). The HFMA2_R_R_UR_R UR token
/// reads value 1 as the vendor `.F32` modifier instead (G1/I1/G41 x4) --
/// that sibling law is 305-kand, NOT armed here. The R-domain tokens of
/// the same families have their own per-window value law
/// (arb297 K1/K2c/K3: win@81 v1 = '.F32' under BUG-279; win@74 v1 and the
/// HADD2 win@60 v1 = '.INVALID1') = 306-kand, also not armed here.
/// Corpus exposure ZERO on the 2,406-cubin battery (routex297, both
/// bundle legs: no hsel==1 word on any scoped row).
pub fn ur_hsel_invalid1_key(key: &str) -> bool {
    key.starts_with("HFMA2_R_R_R_UR")
        || key.starts_with("HMUL2_R_R_UR")
        || key.starts_with("HSETP2_P_P_R_UR_P")
        || key == "HMNMX2_R_R_UR_P"
}

/// BUG-305: sibling value-validity law, armed F2-iter152. On the
/// `HFMA2_R_R_UR_R` rows (UR tok3, hsel window \[61:60\]) value 1 reads as
/// the vendor `.F32` operand modifier -- arb297 G1/I1 + arb297b G41
/// (nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a agree
/// on every probe): 0='' 1='.F32' 2='.H0_H0' 3='.H1_H1; signs compose
/// inside the pipes ('|UR4.F32|', '-UR4.F32'; sm121a BF16_V2 lattice I2/I3)
/// exactly like the BUG-297 INVALID1 marker. This is the UR-slot mirror of
/// the BUG-279 imm-family law (win@81 v1='.F32'). Scope = the exact-modern
/// key only (both mod-groups '' and 'BF16_V2'; the era key
/// `HFMA2.BF16_V2_R_R_UR_R` carries NO hsel field -- iter152 census -- and
/// stays out). The R-domain tokens of this key (win@74/win@81) keep their
/// own laws (306/279 classes; untouched). Corpus exposure ZERO (routex297
/// x2 bundle legs: no hsel==1 word on any HFMA2_R_R_UR_R row).
pub fn ur_hsel_f32_key(key: &str) -> bool {
    key == "HFMA2_R_R_UR_R"
}

/// BUG-306: R-domain half-select value-validity laws, armed F2-iter154.
/// Full per-window census arb306 (nvdisasm 13.3.73 raw -b, x4 models
/// SM100a/SM103a/SM120/SM121a agree on ALL 171 decodable lattice groups of
/// the slot inventory -- every table row x4 legs carrying an hsel field on
/// an R-class token; 12 slot-classes, zero mixed):
/// - value 1 = vendor `.INVALID1` on every R-class hsel slot of
///   HADD2 / HMUL2 / HMNMX2 / HSETP2 (all slots) and on HFMA2 tok2
///   (win@74, arb297 K3) + HFMA2 tok4 (win@81, e.g. G8/G13), i.e.
///   everywhere in the R domain EXCEPT the HFMA2 tok3 slots;
/// - value 1 = vendor `.F32` on the HFMA2 tok3 R-class hsel slots
///   (win@60 on the HFMA2_R_R_R_R rows, win@81 on the other R-carrying
///   HFMA2 rows; arb297 K1 + arb306 G7/G9/G57 set) -- the R-side mirror
///   of the BUG-305 UR-slot law, subsuming the BUG-279 imm-family
///   (2,81,3) arm on its R-class tokens.
///
/// Values 2/3 keep the shared `.H0_H0`/`.H1_H1` mapping on every slot.
/// UR tokens keep the BUG-297/305 laws (format_ureg_raw), imm/FI tokens
/// keep the BUG-279 imm-family lanes; these two functions are consulted
/// only on R-class operand paths (format_reg / encoder Reg arms).
/// Corpus exposure ZERO (routex306, 2,406-cubin battery x4 legs: no
/// hsel==1 word on any R-class hsel slot; the single weak-print sm121a
/// row's fingerprint collisions decode as LEA/ULEA, verify_fifi 117,894
/// words, H-family claims 0).
/// BUG-419: the HADD2 `.F32` 3-token dotted keys on the FI FI two-imm frame
/// (0x430; `HADD2.F32[.SAT/.FTZ]_R_R_FI`). arb419 (x4 models AGREE EVERY):
/// under the F32 route the Ra abs bit b73 is vendor-INERT
/// (`HADD2.F32 R0, R0, ...`, never `|R0|`) -- the generic FP abs recovery
/// fallback (Ra@24 -> raw b73) must NOT fire on these keys.
/// BUG-458b helper: vendor x4 (arb458bf AGREE EVERY, carriers x all
/// F2FP-family mg rows x guards {@P0,@!PT}) treats the generic abs/neg
/// bits as INERT across the whole F2FP family: b62/b63 inert everywhere,
/// b73 vendor-REFUSE (or baked as the real E4M3/E5M2 type selector on
/// the UNPACK_B rows, never ghost-printed), b72 inert too -- EXCEPT on
/// MERGE_C-semantic forms (era `*MERGE_C*` keys and the x3 generic
/// `*MERGE_C*` mg rows) where b72 is the real `.H1` selector of the last
/// operand (vendor prints 'Rz.H1'; the legacy ghost glyph there stays
/// until D-h1, a separate ledger item). Returns true when the generic
/// ghost-sign synth must be suppressed for the given bit.
/// BUG-505b FLIP-B (GHOST62-505A; osobny commit chaina po FLIP505B-A
/// tables): vendor NIGDY nie drukuje abs-bar `|..|` na rodzinie VIADD --
/// arb505b_law 171 sond x4 AGREE (nvdisasm 13.3.73), w tym 16 sond ghost
/// {62,63,72} x fmt{0,3} x2 nogi era: b62 = ghost bars '|R|'/'|UR|' na
/// operandach R/UR (hot-rec pre-arm; PRESTUDY505b sec. GHOST-ABS
/// iter0596). b63 '-UR' oraz b72 neg = REALNE znaki vendora na erze
/// (law 505a) -- zostaja uzbrojone; b73 = selektor fmt pieczony w
/// and_base dokladnych kluczy 505b (nigdy wolny na slowie claimnietym),
/// wiec nie wymaga armu. Arm tlumi b62 zaabs-synteze dla base_op VIADD
/// (klucze *_R_R_UR tabeli 505b + mg rodziny 505a). Pack t505b_3 byl
/// PACK-RED 16/32 pre-arm by design (bramka chainscriptu).
pub fn viadd_sign_arm(key: &str, bit: u32) -> bool {
    let base = key
        .split('_')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    if base != "VIADD" {
        return false;
    }
    bit == 62
}

pub fn f2fp_sign_arm(key: &str, _mod_group: &str, bit: u32) -> bool {
    let base = key.split('_').next().unwrap_or("").split('.').next().unwrap_or("");
    if base != "F2FP" {
        return false;
    }
    match bit {
        62 | 63 | 73 => true,
        // D1 (458b-D-h1, iter370 probe; re-pin base cafd97a0 iter0843): b72 ghost-neg
        // znika WSZEDZIE na F2FP; na MERGE_C-semantyce b72 to prawdziwy
        // selektor '.H1' ostatniego operandu -- druk w printer.rs (blok
        // BUG-458b-D1), x4 AGREE arb458bf law (128 sond: 44+44
        // PACK_AB_MERGE_C, 12+12 MERGE_C, 8+8 ZOMBIE).
        72 => true,
        _ => false,
    }
}

/// BUG-458b F5: era P-dest F2FP keys (`*PACK_AB_P_R_R_R` on sm120/sm121a)
/// carry NO pred field in any row, so the generic P-slot print emits an
/// explicit `PT,` dest. Vendor (arb458bf fresh law x2 legs x 2 guards x the
/// full ghost-variant sweep) ELIDES a PT dest on exactly these five keys.
/// Listed explicitly (fail-closed, measured set only).
pub fn f2fp_p_dest_pt_elide_key(key: &str) -> bool {
    matches!(
        key,
        "F2FP.BF16.F32.PACK_AB_P_R_R_R"
            | "F2FP.RELU.BF16.F32.PACK_AB_P_R_R_R"
            | "F2FP.SATFINITE.BF16.F32.PACK_AB_P_R_R_R"
            | "F2FP.SATFINITE.F16.F32.PACK_AB_P_R_R_R"
            | "F2FP.SATFINITE.RELU.F16.F32.PACK_AB_P_R_R_R"
    )
}

pub fn hadd2_f32_abs_inert_key(key: &str) -> bool {
    matches!(
        key,
        "HADD2.F32_R_R_FI" | "HADD2.F32.SAT_R_R_FI" | "HADD2.F32.FTZ_R_R_FI"
    )
}

/// BUG-484 (2026-11-06): the same law on the register form `HADD2_R_R_R`, whose `.F32` groups
/// are selected by bit 78 of the word (`tools/probes/re_sm120_hadd2_sel.py`: nvdisasm 13.1
/// prints no `|Ra|` for bit 73 under `.F32`; the rebuilt `F32*` groups carry no `abs` field
/// on Ra). `raw` is the instruction word.
pub fn hadd2_f32_abs_inert(key: &str, raw: u128) -> bool {
    hadd2_f32_abs_inert_key(key) || (key == "HADD2_R_R_R" && (raw >> 78) & 1 == 1)
}

/// BUG-419: trailing predicate elision law of the HFMA2 two-imm R-final
/// `.RELU` dotted keys (frames 0x7831; keys `HFMA2*RELU_R_R_{FI_FI,II_II}_R_P`):
/// arb419 x4 models AGREE EVERY -- vendor ELIDES the trailing slot when the
/// predicate reads PT (pred@87 == 7, inv@90 == 0); anything else prints
/// `, [!]Pn`.
pub fn relu_pt_elide_key(key: &str) -> bool {
    let head = key.split("_R_R_").next().unwrap_or("");
    head.starts_with("HFMA2")
        && head.contains("RELU")
        && (key.ends_with("_R_FI_FI_R_P") || key.ends_with("_R_II_II_R_P"))
}

/// BUG-495 (wave 11, from the lane): ENDCOLLECTIVE trailing-P -- the vendor ELIDES
/// the token at PT. arb495/arb495b x4 AGREE EVERY, nvdisasm 13.3.73 raw -b:
/// v=7 & neg=0 prints the bare `ENDCOLLECTIVE`; P0..P6 and !Pv print. The bare form
/// is the only native one observed (redux/vote/match cubins, x3 carriers,
/// sm120 + sm121a). Silicon confirmation of the surrounding encoding:
/// the shipped deep_gemm kernels execute WARPSYNC.COLLECTIVE -> ELECT -> ENDCOLLECTIVE
/// with this exact payload (census 56248/56248, see wave11 REPORT 10e).
pub fn endc_pt_elide_key(key: &str) -> bool {
    key.starts_with("ENDCOLLECTIVE_P")
}

pub fn r_hsel_invalid1_slot(ins_key: &str, tok: i32) -> bool {
    // (HSET2 joined 2026-11-08: the measured `HSET2_R_R_FI_FI_P` row -- tools/probes/re_sm120_rows.py, nvdisasm 13.1 --
    // prints `R48.INVALID1` for hsel value 1 on its register source like the other packed-half compares)
    if ins_key.starts_with("HADD2")
        || ins_key.starts_with("HMUL2")
        || ins_key.starts_with("HMNMX2")
        || ins_key.starts_with("HSETP2")
        || ins_key.starts_with("HSET2")
    {
        return true;
    }
    // BUG-419 (arb419/arb417 x4 models): the two-imm R-final HFMA2 frames
    // (0x7831 class; keys HFMA2_R_R_{FI_FI,II_II}_R + their dotted rows)
    // ALSO arm the value-1 INVALID1 law on the tok5 R operand marker window
    // [81:83) -- b81 -> '.INVALID1', b82 -> '.H0_H0', 81+82 -> '.H1_H1',
    // composed independently with the tok2 law (c74+81 probe).
    ins_key.starts_with("HFMA2") && (tok == 2 || tok == 4 || tok == 5)
}

/// BUG-306 sibling law: the HFMA2 tok3 R-class hsel slots read value 1 as
/// the vendor `.F32` operand modifier (arb297 K1 + arb306 census x4).
pub fn r_hsel_f32_slot(ins_key: &str, tok: i32) -> bool {
    ins_key.starts_with("HFMA2") && tok == 3
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
        // BUG-383: split components on ',' as well so comma-authored
        // multi-mods (`X.F32,FMZ`) canonicalize exactly like dot-authored
        // ones (`X.F32.FMZ`) — and any order spells the same mod-group name.
        let mut mods: Vec<&str> = parts[1..].iter()
            .flat_map(|s| s.split(','))
            .filter(|s| !s.is_empty() && !s.starts_with('?'))
            .collect();
        mods.sort();
        mods.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::IsaTable;

    fn table_with(group: &str) -> String {
        ["{\"TEST_R\":{\"mod_groups\":{\"\":", group, "}}}}"].concat()
    }

    #[test]
    fn rejects_supplied_mask_wider_than_u128() {
        let json = table_with(
            r#"{"and_base":"0x1","variable_mask":"0x100000000000000000000000000000000","fields":[]}"#
        );
        assert!(IsaTable::from_json_flat(&json).is_err());
    }

    #[test]
    fn rejects_field_outside_instruction() {
        let json = table_with(
            r#"{"and_base":"0x1","fields":[{"shift":122,"bits":8,"token_idx":1,"extraction":"reg"}]}"#
        );
        assert!(IsaTable::from_json_flat(&json).is_err());
    }

    #[test]
    fn rejects_unknown_extraction() {
        let json = table_with(
            r#"{"and_base":"0x1","fields":[{"shift":16,"bits":8,"token_idx":1,"extraction":"mystery"}]}"#
        );
        assert!(IsaTable::from_json_flat(&json).is_err());
    }

    #[test]
    fn bundled_table_is_self_contained() {
        let table = IsaTable::from_json_unified(super::bundled_sm120_json()).unwrap();
        // 2_481 keys (1_541 InsKeys x mod-groups); the >=2_000 bar came from the
        // old canonical-derived export which counted raw variants differently.
        // 2026-08-28 BUG-226d: era phantom cleanup (canonical b2e5227) takes
        // sm120 InsKeys 1507 -> 1471 on purpose; bar lowered 1_500 -> 1_400.
        assert!(table.num_keys() >= 1_400, "bundled table shrank unexpectedly");
    }

    /// R3: the parsed-table cache hands out clones of one parse from the second
    /// load on, keyed by the file's identity — the same table whichever way it is
    /// named (plain path or the `.gz` twin), re-parsed when the file changes.
    #[test]
    fn parsed_table_cache_serves_clones_of_the_same_file() {
        let dir = std::env::temp_dir().join(format!("cubit_table_cache_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gz = dir.join("t.json.gz");
        let json = r#"{"TEST_R":{"mod_groups":{"":{"and_base":"0x1","fields":[]}}}}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, json.as_bytes()).unwrap();
        std::fs::write(&gz, enc.finish().unwrap()).unwrap();
        let plain = dir.join("t.json");
        // the plain name resolves to the gz twin: one identity
        let id_plain = super::table_file_identity(&plain).expect("twin found");
        let id_gz = super::table_file_identity(&gz).expect("gz found");
        assert_eq!(id_plain, id_gz);
        assert!(super::table_file_identity(&dir.join("missing.json")).is_none());
        // three loads: the first parses, the second parses and fills the cache, the third is a clone
        for _ in 0..3 {
            let t = IsaTable::load(&plain).unwrap();
            assert_eq!(t.num_keys(), 1);
        }
        assert!(super::parsed_table_cache().lock().unwrap().contains_key(&id_plain), "cached from the second load on");
        // a rewritten file (new size) is a new identity: parsed afresh, the old entry is not served
        let json2 = r#"{"TEST_R":{"mod_groups":{"":{"and_base":"0x1","fields":[]}}},"OTHER_R":{"mod_groups":{"":{"and_base":"0x2","fields":[]}}}}"#;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, json2.as_bytes()).unwrap();
        std::fs::write(&gz, enc.finish().unwrap()).unwrap();
        assert_ne!(super::table_file_identity(&plain).unwrap(), id_plain);
        assert_eq!(IsaTable::load(&plain).unwrap().num_keys(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
