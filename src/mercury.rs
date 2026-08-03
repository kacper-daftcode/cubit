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
//! [..]     TLV records      tag(4B)+payload; length by tag[0]:
//!                           0x01 -> 16B, 0x02 -> 32B, 0x03 -> 16B
//! [len-2:] u16 tail         deterministic f(n_nonnop), see tail_for_instr_count
//! ```

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

/// Record byte length implied by the tag. Grammar v1 (2026-08):
///
/// | class   | bytes | meaning (empirical)                                |
/// |---------|-------|----------------------------------------------------|
/// | 0x01..* |  16   | leaf record (params/const/exit descriptors)        |
/// | 0x02..* |  32   | wide record (global desc, store/load, STS/LDS...)  |
/// | 0x03..* |  16   | leaf variant                                       |
/// | 0x41xx  |   4   | scalar mini-record (4B, `41 vv vv kk`)             |
/// | 0x42xx  |   4   | scalar mini-record                                 |
/// | 0x51xx  |  18   | pinned record (`51 01 01 09 <2B> f8 00 ...`)         |
/// | 0x31xx  |  16   | tcgen05-family record (FA4-class; phase metadata)   |
/// | d10102* |  34   | extended record (rare, older-toolkit style)        |
///
/// Streams ending in `d0 00`-chains or zero padding are tolerated by the
/// lenient parser (they precede the 2B tail). Unknown classes (`d1 01 00`,
/// `d0 *` nie-dopasowane) sa resync-owane do najblizszego znanego tagu —
/// FA4-class (tcgen05) parsuje sie w ~99.6% bajtow (1622+/1664 rekordow).
pub fn record_len(tag: &[u8; 4]) -> Option<usize> {
    match tag[0] {
        0x01 => Some(16),
        0x02 => Some(32),
        0x03 => Some(16),
        // tag-klasy potwierdzone na tcgen05-kernelach (FA4/mkvmem):
        // 0x31 = 16B (FA4 prolog records), patrz MERCURY_UPLIFT_SM103A.md
        0x31 => Some(16),
        0x41 | 0x42 => Some(4),
        0x51 => Some(18),
        0xd1 if tag[1] == 0x01 && tag[2] == 0x02 => Some(34),
        0xd0 if tag[1] == 0x00 && tag[2] == 0x00 && tag[3] == 0x00 => None,
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub offset: usize,
    pub tag: [u8; 4],
    pub payload: Vec<u8>,
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
        while off + 4 <= end {
            let tag: [u8; 4] = blob[off..off + 4].try_into().unwrap();
            match record_len(&tag) {
                Some(l) if off + l <= end => {
                    records.push(Record {
                        offset: off,
                        tag,
                        payload: blob[off + 4..off + l].to_vec(),
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
            *m.entry(r.tag.iter().map(|b| format!("{:02x}", b)).collect())
                .or_insert(0) += 1;
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
