//! Parser for .sass file directives: .entry, .reg, .param, .shared, etc.

/// Parameter type in a kernel entry.
#[derive(Debug, Clone)]
pub enum ParamType {
    U8, U16, U32, U64,
    S8, S16, S32, S64,
    F16, F32, F64,
    Ptr,  // 64-bit pointer
}

impl ParamType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
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
        }
    }
}

/// A kernel parameter (.param directive).
#[derive(Debug, Clone)]
pub struct KernelParam {
    pub ty: ParamType,
    pub name: String,
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
    /// Kernel parameters in declaration order.
    pub params: Vec<KernelParam>,
    /// Shared memory declarations.
    pub shared: Vec<SharedMemDecl>,
}

impl KernelResources {
    /// Total size of .param space in bytes (sum of all param sizes, 4-byte aligned each).
    pub fn param_space_size(&self) -> u32 {
        self.params.iter().map(|p| (p.ty.size() + 3) & !3).sum()
    }

    /// Register count for REGCOUNT EIATTR.
    /// SM120 (Blackwell) allocates registers in blocks of 32.
    /// Using smaller granularity causes ILLEGAL_INSTRUCTION on any register
    /// whose index falls outside the allocated block.
    pub fn reg_count(&self) -> u32 {
        let raw = self.max_reg.map(|r| r + 1).unwrap_or(32).max(2);
        ((raw + 31) & !31).max(32)
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

    if let Some(rest) = line.strip_prefix(".param") {
        // .param <type> <name>
        let parts: Vec<&str> = rest.trim().splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 {
            if let Some(ty) = ParamType::parse(parts[0]) {
                res.params.push(KernelParam {
                    ty,
                    name: parts[1].trim().to_string(),
                });
            }
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
