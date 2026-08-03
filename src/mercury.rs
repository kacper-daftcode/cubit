//! Mercury (capmerc) section parser for SM100+/SM103a cubins.
//!
//! Wire format (empirically derived 2026-08 from the 27,790-section corpus
//! plus B300 driver oracles; see blackwell-isa-internal MERCURY_UPLIFT_SM103A):
//!
//! ```text
//! [0:4]    u32 ordinal      kernel ordinal within the cubin
//! [4:8]    u32 magic        always 0xC0000001
//! [8:12]   u32 n_nonnop     number of non-NOP instructions in .text.K
//! [12:..]  u8 bitmap        ceil(n_nonnop/32)*4 bytes; bit i (LSB-first) set
//!                           iff non-NOP instruction i produces a scoreboard
//!                           tracked result (loads, ALU writes, NANOSLEEP, EXIT)
//! [..]     TLV records      tag(4B)+payload; length by class (record_len),
//!                           interleaved with 2B separator atoms (`d0 00`,
//!                           `00 00`)
//! [len-2:] u16 tail         deterministic f(n_nonnop), see tail_for_instr_count
//! ```
//!
//! Grammar v3 (2026-08-03): 17,612/17,612 corpus sections (4.2M records) and
//! 6,134/6,134 oracle-harvested sections parse with zero unknown classes and
//! zero slop, including tcgen05/FA4 families.

use std::fmt;

pub const CAPMERC_MAGIC: u32 = 0xC0000001;

/// High nibble of the tail word by B % 16 (empirical: 100% deterministic
/// over 6,134 harvested kernel pairs).
const TAIL_X: [u16; 16] = [4, 8, 7, 7, 6, 6, 5, 5, 4, 8, 7, 7, 6, 6, 5, 5];

/// The u16 tail is a pure function of the non-NOP instruction count.
pub fn tail_for_instr_count(n_nonnop: u32) -> u16 {
    let x = TAIL_X[(n_nonnop % 16) as usize];
    let y: u16 = if n_nonnop % 2 == 1 { 0x50 } else { 0xd0 };
    (x << 8) | y
}

/// Record byte length implied by the tag. Grammar v3 (2026-08-03):
///
/// | class     | bytes | meaning (empirical)                                 |
/// |-----------|-------|----------------------------------------------------|
/// | 0x01..*   |  16   | leaf record (params/const/exit descriptors)        |
/// | 0x02..*   |  32   | wide record (global desc, load/store, MMA, STS..)  |
/// | 0x03..*   |  16   | leaf variant                                       |
/// | 0x31xx    |  16   | tcgen05-family record (FA4-class)                  |
/// | 0x41xx    |   4   | scalar mini-record (`41 vv vv kk`)                 |
/// | 0x42xx    |   4   | scalar mini-record                                 |
/// | 0x32xx    |   4   | scalar mini-record (cutlass tensorop kernels)      |
/// | 0x11xx    |   8   | mini record (imma_dgemm family)                    |
/// | 0x51xx    | 18/34 | pinned (u16-list) record: tag[2]==01 -> 18B,       |
/// |           |       | tag[2]==02 -> 34B                                  |
/// | 0xd101xx  |  18   | extended record (mbarrier/older-toolkit style)     |
/// | 0xd102xx  |  34   | extended record                                    |
/// | `d0 00`   |   2   | separator atom (runs between record groups)        |
/// | `00 00`   |   2   | padding atom (trailing/alignment regions)          |
///
/// Per-class length histograms over the full corpus are singletons (no
/// length ambiguity observed).
pub fn record_len(tag: &[u8; 4]) -> Option<usize> {
    match tag[0] {
        0x01 | 0x03 | 0x31 => Some(16),
        0x02 => Some(32),
        0x41 | 0x42 | 0x32 => Some(4),
        0x11 => Some(8),
        0x51 | 0xd1 => match tag[2] {
            0x01 => Some(18),
            0x02 => Some(34),
            _ => None,
        },
        0xd0 if tag[1] == 0x00 => Some(2),
        0x00 if tag[1] == 0x00 => Some(2),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub offset: usize,
    pub tag: [u8; 4],
    pub payload: Vec<u8>,
    /// Total record length on the wire (tag + payload). 2 for separator
    /// atoms (`d0 00` / `00 00`); those carry no payload and only
    /// tag[0..2] is meaningful.
    pub len: usize,
}

impl Record {
    pub fn is_atom(&self) -> bool {
        self.len == 2
    }
}

#[derive(Debug)]
pub struct CapMerc {
    pub ordinal: u32,
    pub magic: u32,
    pub n_nonnop: u32,
    pub bitmap: Vec<u8>,
    pub records: Vec<Record>,
    pub tail: u16,
    /// Bytes between last record end and tail (normally 0).
    pub trailing_slop: usize,
}

#[derive(Debug)]
pub enum MercError {
    Truncated,
    BadMagic(u32),
    MalformedRecord { offset: usize, tag: [u8; 4] },
}

impl fmt::Display for MercError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MercError::Truncated => write!(f, "capmerc section truncated"),
            MercError::BadMagic(m) => write!(f, "bad capmerc magic {:#010x}", m),
            MercError::MalformedRecord { offset, tag } => {
                write!(f, "unknown record tag {:02x?} at byte {}", tag, offset)
            }
        }
    }
}

impl std::error::Error for MercError {}

impl CapMerc {
    /// Parse a `.nv.capmerc.text.<K>` section body. `strict` rejects unknown
    /// record tags; lenient mode captures the remainder as one opaque record.
    pub fn parse(blob: &[u8], strict: bool) -> Result<CapMerc, MercError> {
        if blob.len() < 14 {
            return Err(MercError::Truncated);
        }
        let rd = |o: usize| u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());
        let ordinal = rd(0);
        let magic = rd(4);
        if magic != CAPMERC_MAGIC {
            return Err(MercError::BadMagic(magic));
        }
        let n_nonnop = rd(8);
        let bmp_len = ((n_nonnop as usize + 31) / 32) * 4;
        if blob.len() < 12 + bmp_len + 2 {
            return Err(MercError::Truncated);
        }
        let bitmap = blob[12..12 + bmp_len].to_vec();
        let tail = u16::from_le_bytes([blob[blob.len() - 2], blob[blob.len() - 1]]);
        let mut records = Vec::new();
        let mut off = 12 + bmp_len;
        let end = blob.len() - 2;
        while off + 2 <= end {
            if off + 4 > end {
                // Trailing 2B atom directly before the tail (no room for a
                // full tag lookahead).
                let t2 = &blob[off..end];
                if t2 == [0xd0, 0x00] || t2 == [0x00, 0x00] {
                    records.push(Record {
                        offset: off,
                        tag: [t2[0], t2[1], 0, 0],
                        payload: Vec::new(),
                        len: 2,
                    });
                    off = end;
                    break;
                }
                let tag = [t2[0], t2[1], 0, 0];
                if strict {
                    return Err(MercError::MalformedRecord { offset: off, tag });
                }
                records.push(Record {
                    offset: off,
                    tag,
                    payload: Vec::new(),
                    len: end - off,
                });
                off = end;
                break;
            }
            let tag: [u8; 4] = blob[off..off + 4].try_into().unwrap();
            match record_len(&tag) {
                Some(2) => {
                    records.push(Record {
                        offset: off,
                        tag: [tag[0], tag[1], 0, 0],
                        payload: Vec::new(),
                        len: 2,
                    });
                    off += 2;
                }
                Some(l) if off + l <= end => {
                    records.push(Record {
                        offset: off,
                        tag,
                        payload: blob[off + 4..off + l].to_vec(),
                        len: l,
                    });
                    off += l;
                }
                _ => {
                    if strict {
                        return Err(MercError::MalformedRecord { offset: off, tag });
                    }
                    // lenient: resync do najblizszego znanego tagu
                    let mut nxt = None;
                    let mut p = off + 2;
                    while p + 4 <= end && p < off + 96 {
                        if record_len(blob[p..p + 4].try_into().unwrap_or(&[0; 4])).is_some() {
                            nxt = Some(p);
                            break;
                        }
                        p += 2;
                    }
                    let mut stop = nxt.unwrap_or(end);
                    if stop < off + 4 {
                        stop = (off + 4).min(end);
                    }
                    records.push(Record {
                        offset: off,
                        tag,
                        payload: blob[off + 4..stop].to_vec(),
                        len: stop - off,
                    });
                    off = stop;
                }
            }
        }
        let trailing_slop = end - off;
        Ok(CapMerc {
            ordinal,
            magic,
            n_nonnop,
            bitmap,
            records,
            tail,
            trailing_slop,
        })
    }

    /// Set bitmap bits as indices into the non-NOP instruction stream.
    pub fn set_bits(&self) -> Vec<u32> {
        (0..self.n_nonnop)
            .filter(|&i| (self.bitmap[(i / 8) as usize] >> (i % 8)) & 1 == 1)
            .collect()
    }

    pub fn tail_consistent(&self) -> bool {
        self.tail == tail_for_instr_count(self.n_nonnop)
    }

    /// Frequency table of record tags (key = tag bytes hex string).
    pub fn tag_histogram(&self) -> Vec<(String, usize)> {
        let mut m: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for r in &self.records {
            let key = if r.is_atom() {
                format!("{:02x}{:02x}(atom)", r.tag[0], r.tag[1])
            } else {
                r.tag.iter().map(|b| format!("{:02x}", b)).collect()
            };
            *m.entry(key).or_insert(0) += 1;
        }
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

/// Reporting-only heuristic for the bitmap's semantics: returns true if an
/// opcode class typically produces a scoreboard-tracked register result.
/// (The bitmap in data is authoritative; this is for dumps/estimates.)
pub fn opcode_tracked_hint(op: &str) -> bool {
    let base = op.split('.').next().unwrap_or(op);
    !matches!(
        base,
        "LDC"
            | "LDCU"
            | "S2R"
            | "S2UR"
            | "STG"
            | "REDG"
            | "RED"
            | "ATOMG"
            | "BRA"
            | "BRX"
            | "JMP"
            | "JMPX"
            | "CALL"
            | "BAR"
            | "BSSY"
            | "BSYNC"
            | "NOP"
            | "HMMA"
            | "UTCHMMA"
            | "UTCQMMA"
            | "UTCIMMA"
            | "UTCMXQMMA"
            | "OMMA"
            | "QMMA"
            | "IMMA"
            | "DMMA"
            | "UTMALDG"
            | "UTMASTG"
            | "BREAK"
            | "PREEXIT"
    )
}
