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
            // ELECT: config/sync klasa — bez bitu t4-flag1; dostaje wlasny
            // mini-rekord 41 64 00 0a w lane (mk7 p_elect, fs-lab 2026-08-05).
            | "ELECT"
            // ACQBULK: lane-rekord 01 62 00 0a (gold w_depsync; mk10c).
            | "ACQBULK"
            // CCTL (IVALL itd.): marker 51 02 + rekord 01 49 10 0a w lane,
            // bez bitu (gold p_fence, fs8/9-grid 2026-08-05).
            | "CCTL"
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

/// NOP detection heuristic for raw words (first two bytes of the sm_100/103
/// NOP encoding; used when no opcode list is provided).
pub fn word_is_nop_hint(w: &[u8]) -> bool {
    w[0] == 0x18 && w[1] == 0x79
}

/// Classes that consume NO bitmap slot (weight-0 in the B model
/// `B = trim_count - n_w0`, verified on lab + corpus: MEMBAR/ERRBAR/CGAERRBAR
/// (fence probes), DEPBAR/LDGDEPBAR/LDGSTS (cp.async probes), B2R
/// (voting/divergence kernels)).
pub fn opcode_bitmap_zero_weight(op: &str) -> bool {
    let base = op.split('.').next().unwrap_or(op);
    matches!(
        base,
        "MEMBAR" | "ERRBAR" | "CGAERRBAR" | "DEPBAR" | "LDGDEPBAR" | "LDGSTS" | "B2R"
    )
}


/// ===== Rekordy 025a (MMA) / 020f,020c (DMUL/DADD z f64-imm) =====
/// Model zweryfikowany byte-exact na calej probce korpusu (mma_harvest2/
/// mma_model/f64imm_harvest, 2026-08-05): 15,104 rekordow 025a + 512 mini
/// + 221 rekordow f64-imm, zero niedopasowan.
///
/// Klasyfikator mnemonika SASS -> id klasy 025a.
pub fn merc_mma_class(mnem: &str) -> Option<u8> {
    Some(match mnem {
        "HMMA.16816.F32" => 0,
        "HMMA.16816.F32.BF16" => 1,
        "HMMA.1688.F32.TF32" => 2,
        "HMMA.16816.F16" => 3,
        "DMMA.8x8x4" => 4,
        "IMMA.16832.S8.S8" => 5,
        "IMMA.16816.S8.S8.SAT" => 6,
        "IMMA.16832.S8.S8.SAT" => 7,
        _ => return None,
    })
}

/// Histogram korpusowy wykazal klase mini (4B) tylko dla IMMA.16832.*.SAT.
pub fn merc_mma_is_mini(cls: u8) -> bool {
    cls == 7
}

/// Zbuduj rekord 025a dla instrukcji MMA.
/// (b2,b6,b7,b8base) per (klasa/dtype); bajty [12..=20]: bity-operandow:
/// b12 = base | (D&2)<<6 | w F16: base=03 (brak bitu D&2 observacji? nie,
/// tam tez D&2 -> 0x80); b13 = D>>2; b14 = base | (A&2)<<6; b15 = A>>2;
/// b17 = base | (B&3)<<6; b18 = B>>2; C: b19 = base | (C&3)<<6, b20 = C>>2;
/// C=RZ -> (c0, ff). b8 |= 0x80 gdy bit 63 slowa instrukcji, |= 0x20 gdy 72.
pub fn build_mma_rec(cls: u8, d: u8, a: u8, b: u8, c: u8, b8flags: u8) -> [u8; 32] {
    const T: [(u8, u8, u8, u8, u8, u8, u8, u8); 8] = [
        // b2    b6    b7    b8    b12base b14base b17base b19base
        (0x00, 0x81, 0x80, 0x02, 0x07, 0x06, 0x02, 0x06), // HMMA.16816.F32
        (0x00, 0x81, 0x92, 0x02, 0x07, 0x06, 0x02, 0x06), // HMMA.16816.F32.BF16
        (0x00, 0x80, 0xa4, 0x02, 0x07, 0x06, 0x02, 0x06), // HMMA.1688.F32.TF32
        (0x00, 0x01, 0x00, 0x02, 0x03, 0x06, 0x02, 0x02), // HMMA.16816.F16
        (0x04, 0x00, 0x00, 0x08, 0x07, 0x02, 0x02, 0x06), // DMMA.8x8x4
        (0x08, 0x05, 0x44, 0x40, 0x07, 0x06, 0x02, 0x06), // IMMA.16832.S8.S8
        (0x08, 0x04, 0x44, 0x50, 0x07, 0x02, 0x00, 0x06), // IMMA.16816.S8.S8.SAT
        (0x08, 0x05, 0x44, 0x40, 0x07, 0x06, 0x02, 0x06), // (mini nie uzywa)
    ];
    let (b2, b6, b7, b8, c12, c14, c17, c19) = T[cls as usize];
    let mut r = [0u8; 32];
    r[0] = 0x02;
    r[1] = 0x5a;
    r[2] = b2;
    r[3] = 0x26;
    r[4] = 0xf8;
    r[6] = b6;
    r[7] = b7;
    r[8] = b8 | b8flags;
    r[12] = c12 | ((d & 2) << 6);
    r[13] = (d >> 2) & 0x3f;
    r[14] = c14 | ((a & 2) << 6);
    r[15] = a >> 2;
    r[17] = c17 | ((b & 3) << 6);
    r[18] = b >> 2;
    if c == 255 {
        r[19] = 0xc0;
        r[20] = 0xff;
    } else {
        r[19] = c19 | ((c & 3) << 6);
        r[20] = (c >> 2) & 0x3f;
    }
    r[22] = 0xf8;
    r
}

/// Mini-rekord dla IMMA.16832.*.SAT.
pub const MERC_MMA_MINI_SAT: [u8; 4] = [0x42, 0x5a, 0x08, 0x26];

/// Rekord 020f (DMUL z imm) / 020c (DADD z imm): imm = gorne 32 bity stalej
/// f64 na [28:32]; bajty-operandy: b10 = 03|(D&2)<<6, b11 = D>>2,
/// b12 = 02|(A&2)<<6, b13 = A>>2, b14 = 0x13 const. Wariant: 0=DMUL, 1=DADD.
pub fn build_f64imm_rec(variant: u8, d: u8, a: u8, imm_top: u32) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0x02;
    let (t1, t2) = if variant == 0 { (0x0f, 0x12) } else { (0x0c, 0x1e) };
    r[1] = t1;
    r[2] = t2;
    r[3] = 0x0e;
    r[4] = 0xf8;
    r[6] = 0x08;
    r[10] = 0x03 | ((d & 2) << 6);
    r[11] = (d >> 2) & 0x3f;
    r[12] = 0x02 | ((a & 2) << 6);
    r[13] = a >> 2;
    r[14] = 0x13;
    r[28..32].copy_from_slice(&imm_top.to_le_bytes());
    r
}

/// Atom wypelniajacy lane dla UIADD3-killpad. UWAGA korpus (uiadd3_bitmap2):
/// killpad = _dokladna_ forma `UIADD3 URZ, UPT, UPT, URZ, URZ, URZ` — tylko
/// wtedy brak bitu bitmapy + atom w lane. LIVE UIADD3 (dest URn) ma bit
/// (32,490 vs 18 pomiarowow). Dlatego lane-pady sa explicite w meta.
pub const MERC_LANE_PAD: [u8; 2] = [0xd0, 0x00];

/// True gdy tekst SASS to killpad uniform-datapath (atom d0 00 w lane).
/// Guard-tokeny (@Pn/@!UPT) sa tolerowane (mk11: drukarka dopisuje @!UPT).
pub fn is_uiadd3_killpad(text: &str) -> bool {
    let mut t = text.trim_end_matches(';').trim();
    while let Some(rest) = t.strip_prefix('@') {
        t = rest.split_whitespace().next().map(|_| {
            let sp = rest.find(char::is_whitespace).map(|i| i + 1).unwrap_or(rest.len());
            rest[sp..].trim_start()
        }).unwrap_or("");
    }
    t == "UIADD3 URZ, UPT, UPT, URZ, URZ, URZ"
}
