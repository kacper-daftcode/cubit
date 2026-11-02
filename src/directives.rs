//! Parser for .sass file directives: .entry, .reg, .param, .shared, etc.

/// Parameter type in a kernel entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamType {
    U8, U16, U32, U64,
    S8, S16, S32, S64,
    F16, F32, F64,
    Ptr,  // 64-bit pointer
    /// An aggregate passed by value (`b8[N]`): a struct of N bytes.
    Bytes(u32),
}

impl ParamType {
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        if let Some(n) = lower.strip_prefix("b8[").and_then(|r| r.strip_suffix(']')) {
            return n.parse::<u32>().ok().filter(|&n| n > 0).map(Self::Bytes);
        }
        match lower.as_str() {
            "u8"  => Some(Self::U8),  "u16" => Some(Self::U16),
            "u32" => Some(Self::U32), "u64" => Some(Self::U64),
            "s8"  => Some(Self::S8),  "s16" => Some(Self::S16),
            "s32" => Some(Self::S32), "s64" => Some(Self::S64),
            "f16" => Some(Self::F16), "f32" => Some(Self::F32),
            "f64" => Some(Self::F64), "ptr" | "b64" | "u64*" => Some(Self::Ptr),
            _ => None,
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> u32 {
        match self {
            Self::U8  | Self::S8            => 1,
            Self::U16 | Self::S16 | Self::F16 => 2,
            Self::U32 | Self::S32 | Self::F32 => 4,
            Self::U64 | Self::S64 | Self::F64 | Self::Ptr => 8,
            Self::Bytes(n) => *n,
        }
    }

    /// Alignment of the parameter inside the constant-bank parameter block
    /// when no explicit `offset=` is declared. Scalars align to their size.
    /// A by-value aggregate aligns to the largest power of two (<= 8) that
    /// divides its size: the CUDA ABI aligns a struct to its most aligned
    /// member, which the byte count alone cannot tell (nvcc places 16-byte
    /// structs at both 8- and 16-byte offsets); `disassemble --frozen`
    /// therefore always writes the exact offset.
    pub fn natural_align(&self) -> u32 {
        match self {
            Self::Bytes(n) => [8u32, 4, 2].into_iter().find(|a| n % a == 0).unwrap_or(1),
            other => other.size(),
        }
    }

    /// EIATTR_KPARAM_INFO address space field: nvcc records 5 for pointer
    /// parameters and 0 for scalars and by-value aggregates.
    pub fn default_space(&self) -> u8 {
        if *self == Self::Ptr { 5 } else { 0 }
    }

    /// The spelling `disassemble --frozen` / `render` use for the type.
    pub fn spelling(&self) -> String {
        match self {
            Self::U8 => "u8".into(), Self::U16 => "u16".into(),
            Self::U32 => "u32".into(), Self::U64 => "u64".into(),
            Self::S8 => "s8".into(), Self::S16 => "s16".into(),
            Self::S32 => "s32".into(), Self::S64 => "s64".into(),
            Self::F16 => "f16".into(), Self::F32 => "f32".into(),
            Self::F64 => "f64".into(), Self::Ptr => "ptr".into(),
            Self::Bytes(n) => format!("b8[{n}]"),
        }
    }
}

/// A kernel parameter (.param directive).
///
/// `.param <type> <name> [offset=<bytes>] [space=<n>] [logalign=<n>]`
///
/// The optional attributes pin the EIATTR_KPARAM_INFO record exactly: the
/// offset inside the parameter block (otherwise the natural layout rule of
/// [`KernelResources::param_layout`] applies), the address-space nibble and
/// the pointee log2 alignment byte (otherwise the type's defaults).
#[derive(Debug, Clone)]
pub struct KernelParam {
    pub ty: ParamType,
    pub name: String,
    /// Explicit byte offset inside the parameter block (`offset=`).
    pub offset: Option<u32>,
    /// Explicit KPARAM_INFO address space (`space=`).
    pub space: Option<u8>,
    /// Explicit KPARAM_INFO pointee log2 alignment (`logalign=`).
    pub log_align: Option<u8>,
}

/// One parameter of the resolved constant-bank layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamSlot {
    pub offset: u32,
    pub size: u32,
    pub space: u8,
    pub log_align: u8,
}

/// A shared memory allocation (.shared directive).
#[derive(Debug, Clone)]
pub struct SharedMemDecl {
    pub align: u32,
    pub name: String,
    pub size: u32,
}

/// Resource declarations for a kernel.
#[derive(Debug, Clone, Default)]
pub struct KernelResources {
    /// Max register index used (inclusive). None = auto-detect from instructions.
    pub max_reg: Option<u32>,
    /// Max predicate index used (inclusive). None = default 7.
    pub max_pred: Option<u32>,
    /// Number of barriers declared.
    pub num_barriers: u32,
    /// mk19: lane'y duchow __syncwarp z dyrektywy `.merc_syncwarp`
    /// (EIATTR 0x28/0x29 nie ma odpowiednika w SASS; `disassemble --frozen`
    /// emituje, `asm` konsumuje).
    pub merc_syncwarp: Vec<u32>,
    /// mk28: SUROWE site'y __syncwarp z oryginalu (EIATTR 0x28) + maski
    /// (0x29): `.merc_cgsites 0x20[:ffffffff] ...` — journal EIATTR 28/29
    /// w .nv.info.K; edykcyjny podzbior (duchy) = `.merc_syncwarp`.
    pub merc_cgsites: Vec<(u32, u32)>,
    /// Kernel parameters in declaration order.
    pub params: Vec<KernelParam>,
    /// Exact EIATTR_REGCOUNT declared with `.regcount N` (the value ptxas
    /// recorded); None = derive from the `.reg` range ([`Self::reg_count`]).
    pub regcount: Option<u32>,
    /// Shared memory declarations.
    pub shared: Vec<SharedMemDecl>,
    /// mk41: marker ery zrodla z `;; era=sm100` (disasm --frozen):
    /// era-100 ptxas-pipeline rozni sie od 103a w niektorych klasach mini.
    pub era100: bool,
}

impl KernelResources {
    /// Constant-bank layout of the declared parameters, in declaration order.
    /// An explicit `offset=` wins; otherwise each parameter is placed at the
    /// next offset aligned to its [`ParamType::natural_align`] (nvcc's rule for
    /// scalars and pointers). The parameter block itself starts at
    /// c\[0x0\]\[0x380\] on SM120 (the offsets here are relative to it).
    pub fn param_layout(&self) -> Vec<ParamSlot> {
        let mut next = 0u32;
        self.params
            .iter()
            .map(|p| {
                let size = p.ty.size();
                let align = p.ty.natural_align();
                let offset = p.offset.unwrap_or((next + align - 1) & !(align - 1));
                next = next.max(offset + size);
                ParamSlot {
                    offset,
                    size,
                    space: p.space.unwrap_or_else(|| p.ty.default_space()),
                    log_align: p.log_align.unwrap_or(0),
                }
            })
            .collect()
    }

    /// Total size of the parameter block in bytes: the end of the last
    /// parameter, unrounded (EIATTR_CBANK_PARAM_SIZE as ptxas records it —
    /// 768/768 census kernels, 131 of them not a multiple of 8).
    pub fn param_space_size(&self) -> u32 {
        self.param_layout().iter().map(|s| s.offset + s.size).max().unwrap_or(0)
    }

    /// Register count for REGCOUNT EIATTR.
    ///
    /// With `.regcount N` the declared value is used verbatim (ptxas records
    /// `highest register touched + 3`, unrounded: 55, 114, 128 in the v6
    /// MoE kernels). Without it the count is derived from the `.reg` range:
    /// SM120 (Blackwell) allocates registers in blocks of 32.
    /// Using smaller granularity causes ILLEGAL_INSTRUCTION on any register
    /// whose index falls outside the allocated block.
    pub fn reg_count(&self) -> u32 {
        if let Some(n) = self.regcount {
            return n.clamp(2, 255);
        }
        let raw = self.max_reg.map(|r| r + 1).unwrap_or(32).max(2);
        // BUG-011: hardware caps REGCOUNT at 255 (R255 is the RZ alias — a
        // `.reg R0-R255` kernel is exactly 255 regs). The block-rounding used
        // to produce 256 there, an invalid driver value.
        // BUG-075: usable regs under a declared N are R0..R(N-3) (granule
        // shadow; silicon sm_120 i115 + sm_103a band sweep 2026-08-22), so
        // N must clear max_reg by 3. Granule 8 is driver-accepted (nvcc uses
        // granule-8 values like 168; 136 silicon-verified in the sweep).
        ((raw + 2 + 7) & !7).clamp(32, 255)
    }

    /// Total shared memory in bytes (sum of all shared declarations).
    pub fn shared_size(&self) -> u32 {
        self.shared.iter().map(|s| s.size).sum()
    }
}

/// Parse resource directives from lines within a `.entry` block.
/// Modifies `res` in-place. Returns true if the line was a directive.
pub fn parse_directive(line: &str, res: &mut KernelResources) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with("//") { return true; }

    if let Some(rest) = line.strip_prefix(".maxreg") {
        // .maxreg <N> — declare maximum register count (e.g. .maxreg 64)
        if let Ok(n) = rest.trim().parse::<u32>() {
            let hi = if n > 0 { n - 1 } else { 0 };
            let cur = res.max_reg.unwrap_or(0);
            res.max_reg = Some(cur.max(hi));
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".regcount") {
        // .regcount <N> — the exact EIATTR_REGCOUNT (disassemble --frozen
        // writes the value ptxas recorded; asm checks the granule-shadow law
        // against the registers the code touches).
        if let Ok(n) = rest.trim().parse::<u32>() {
            if (2..=255).contains(&n) {
                res.regcount = Some(n);
            }
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".reg") {
        // .reg R<lo>-R<hi>  or  .reg .u32 R<lo>-R<hi>
        let rest = rest.trim().trim_start_matches(".u32").trim()
                        .trim_start_matches(".u64").trim();
        if let Some(hi) = parse_reg_range(rest) {
            let cur = res.max_reg.unwrap_or(0);
            res.max_reg = Some(cur.max(hi));
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".pred") {
        // .pred P0-P<hi>
        let rest = rest.trim();
        if let Some(hi) = parse_pred_range(rest) {
            let cur = res.max_pred.unwrap_or(0);
            res.max_pred = Some(cur.max(hi));
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".bar") {
        // .bar B0-B<n>
        let rest = rest.trim();
        if let Some(n) = parse_bar_count(rest) {
            res.num_barriers = res.num_barriers.max(n);
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".merc_cgsites") {
        // .merc_cgsites 0x20 0x1a0 .. LUB 0x20:ffffffff .. (site[:maska])
        for tok in rest.trim().trim_end_matches(';').split([' ', ',', '\t']) {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let (sv, mv) = match tok.split_once(':') {
                Some((s, m)) => (s, m),
                None => (tok, "0xffffffff"),
            };
            let parse = |t: &str| -> Option<u32> {
                if let Some(h) = t.strip_prefix("0x") {
                    u32::from_str_radix(h, 16).ok()
                } else {
                    t.parse::<u32>().ok()
                }
            };
            if let (Some(s), Some(m)) = (parse(sv), parse(mv)) {
                res.merc_cgsites.push((s, m));
            }
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".merc_syncwarp") {
        // .merc_syncwarp 0x<off>|<off-dzies> — lane = offset bajtowy / 16
        let t = rest.trim().trim_end_matches(';');
        let v = if let Some(h) = t.strip_prefix("0x") {
            u32::from_str_radix(h, 16).ok()
        } else {
            t.parse::<u32>().ok()
        };
        if let Some(v) = v {
            res.merc_syncwarp.push(v / 16);
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".param") {
        // .param <type> <name> [offset=<n>] [space=<n>] [logalign=<n>]
        let mut parts = rest.split_whitespace();
        if let (Some(ty), Some(name)) = (parts.next().and_then(ParamType::parse), parts.next()) {
            let mut param = KernelParam {
                ty,
                name: name.to_string(),
                offset: None,
                space: None,
                log_align: None,
            };
            for attr in parts {
                let Some((key, value)) = attr.split_once('=') else { continue };
                let value = value.trim();
                let parsed = value
                    .strip_prefix("0x")
                    .map(|h| u32::from_str_radix(h, 16))
                    .unwrap_or_else(|| value.parse::<u32>());
                let Ok(v) = parsed else { continue };
                match key {
                    "offset" => param.offset = Some(v),
                    "space" => param.space = u8::try_from(v).ok().filter(|s| *s < 16),
                    "logalign" => param.log_align = u8::try_from(v).ok(),
                    _ => {}
                }
            }
            res.params.push(param);
        }
        return true;
    }

    if let Some(rest) = line.strip_prefix(".shared") {
        // .shared [.align N] <name>[<size>]
        let (align, rest2) = if let Some(r) = rest.trim().strip_prefix(".align") {
            let mut parts = r.trim().splitn(2, char::is_whitespace);
            let align_str = parts.next().unwrap_or("1");
            let align = align_str.parse::<u32>().unwrap_or(1);
            (align, parts.next().unwrap_or("").trim())
        } else {
            (1u32, rest.trim())
        };

        // Parse name[size]
        if let Some((name, size)) = parse_array_decl(rest2) {
            res.shared.push(SharedMemDecl { align, name, size });
        }
        return true;
    }

    false
}

fn parse_reg_range(s: &str) -> Option<u32> {
    // "R0-R47" or "R47" → returns 47
    let s = s.trim();
    if let Some(idx) = s.rfind('-') {
        let hi = s[idx+1..].trim().trim_start_matches('R');
        hi.parse::<u32>().ok()
    } else if let Some(rest) = s.strip_prefix('R') {
        rest.parse::<u32>().ok()
    } else {
        None
    }
}

fn parse_pred_range(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(idx) = s.rfind('-') {
        let hi = s[idx+1..].trim().trim_start_matches('P');
        hi.parse::<u32>().ok()
    } else {
        None
    }
}

fn parse_bar_count(s: &str) -> Option<u32> {
    // "B0-B5" → 6 barriers
    let s = s.trim();
    if let Some(idx) = s.rfind('-') {
        let hi = s[idx+1..].trim().trim_start_matches('B');
        hi.parse::<u32>().ok().map(|n| n + 1)
    } else {
        Some(1)
    }
}

fn parse_array_decl(s: &str) -> Option<(String, u32)> {
    // "smem[4096]" → ("smem", 4096)
    if let Some(bracket) = s.find('[') {
        let name = s[..bracket].trim().to_string();
        let rest = s[bracket+1..].trim_end_matches(']').trim();
        let size = rest.parse::<u32>().ok()?;
        Some((name, size))
    } else {
        None
    }
}
