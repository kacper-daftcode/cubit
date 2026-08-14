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
            // mk40: store-matrix — ST.E/STL dostaja rekordy 0238 (b2=2a/20),
            // zastepuja wezel t4: lane bez bitu (korpus mk40 stg-fields).
            | "ST"
            | "STL"
            | "REDG"
            | "RED"
            | "ATOMG"
            // mk49: sm_100 ATOM.E.* (desc-rodzina) — jak wszystkie atomowe.
            | "ATOM"
            // mk14: AShared ATOMS tez bez bitu (gold p_atoms slot15 bit=0;
            // wszystkie klasy atomowe bez bitu — mk14/atombits.py).
            | "ATOMS"
            // mk14.3: LDSM bez bitu (gold p_ldsm slot31 bit=0).
            | "LDSM"
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


/// mk28: klasyfikator operacji warp-wide dla EIATTR 0x31
/// (INT_WARP_WIDE_INSTR_OFFSETS — nvcc listuje bajtowe offsety tych opow,
/// gdy kernel zawiera VOTEU). Korpus labu: VOTEU, SHFL, REDUX, MATCHANY.
/// Zwrotka: Some(b'v') dla VOTEU (bramka emisji), Some(inna litera) dla
/// reszty klasikow, None poza tym.
pub fn wwide_class(opcode_full: &str, base: &str) -> Option<u8> {
    let b = if base.is_empty() {
        opcode_full.split('.').next().unwrap_or(opcode_full)
    } else {
        base
    };
    match b {
        "VOTEU" => Some(b'v'),
        "SHFL" => Some(b's'),
        "REDUX" => Some(b'r'),
        "MATCH" | "MATCHANY" => Some(b'm'),
        _ => None,
    }
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

/// mk13: bajt b12 rekordu anchor 010b040a = enum rejestru SR czytanego przez
/// S2R, ktoremu anchor odpowiada (b13=0x02 stale; boot-anchor = 0x0400).
/// Zmierzone na gold: SR_LANEID=0, SR_TID.X=1, SR_CTAID.X=4, SR_LTMASK=8
/// (p_atomg/p_atoms/c_ld_dyn2/k_mma/k_atom — po 2+ probki; zastepuje stary
/// hack "cf[12]=0 dla atom/mma", kAtom/kMma czytaja wlasnie LANEID).
/// Fallback 1 (TID.X = dominanta korpusowa).
pub fn merc_s2r_sr_enum(sr: &str) -> u8 {
    match sr {
        "SR_LANEID" => 0,
        "SR_TID.X" => 1,
        "SR_TID.Y" => 2,
        "SR_TID.Z" => 3,
        "SR_CTAID.X" => 4,
        "SR_CTAID.Y" => 5,
        "SR_CTAID.Z" => 6,
        "SR_LTMASK" => 8,
        // mk56: korpus 1:1 (merclab/mk56 c10): LE=09, GT=0a.
        "SR_LEMASK" => 9,
        "SR_GTMASK" => 10,
        // mk57: korpus 1:1 (merclab/mk57 c4/c5/c6): GEMASK=0b; zamyka
        // 92 kernele residuum M02/E02 (cub thrust; 581/607 domknietych
        // rekordow b12=11; reszta = dup-def pierwszego dopasowania).
        "SR_GEMASK" => 11,
        // mk28: SR_CgaCtaId -> 0x2c (E2E b_cluster/b_mbarrier/b_tcgen05;
        // b12 rekordu anchor 010b040a = enum SR czytanego przez S2R).
        "SR_CgaCtaId" => 0x2c,
        "SR_SWINHI" => 0x2d,
        // mk41: korpus sm_100 010b040a b12: SWINHI=0x2d (2751/6071 exact-par)
        _ => 1,
    }
}

/// mk13: wyciaga nazwe SR_ z linii S2R (`S2R R5, SR_LANEID ;` -> "SR_LANEID";
/// guard @Pn tolerowany).
pub fn s2r_sr_name(text: &str) -> String {
    match text.split("SR_").nth(1) {
        Some(t) => {
            let e = t
                .find(|c: char| !(c.is_alphanumeric() || c == '.'))
                .unwrap_or(t.len());
            format!("SR_{}", &t[..e])
        }
        None => String::new(),
    }
}

/// mk17a (2026-08-07): numer rejestru docelowego S2R -> payload f4 rekordu
/// anchor 010b040a: bajty [10:11] = (dest<<6)|1. Empirycznie 90/90 anchorow
/// mk20-datasetu (oraculum gdb na ptxas): f4 == numer R dest S2R, na ktorym
/// stoi anchor; boot-anchor (REC_PROLOG) ma f4=1 const. Potwierdzone tez
/// RE pisarza: FUN_00ad93f0 zapisuje node+0x44 = pozycja skanu first-fit
/// alokatora rejestrow, a reader anchorowy (FUN_00bd2fb0) czyta wlasnie te
/// pozycje dla wiersza S2R. RZ -> 0x3f (konwencja 6-bit jak URZ; brak
/// probek korpusowych). None gdy tekst nieparsowalny.
pub fn merc_s2r_dest_reg(text: &str) -> Option<u32> {
    let mut toks = text.split_whitespace();
    for t in &mut toks {
        if t.starts_with('@') {
            continue;
        }
        if t.split('.').next() == Some("S2R") {
            break;
        }
    }
    let dest = toks.next()?.trim_end_matches(',');
    if dest == "RZ" {
        return Some(0x3f);
    }
    let n = dest.strip_prefix('R')?;
    n.parse::<u32>().ok()
}

/// mk56: rekord geo-anchor LDC `01 0b 04 0a` z b13=0x04. Nosnik: KAZDY lane
/// `LDC Rn, c[0x0][0x3XX]` z okna geometrii launcha drivera (per-lane —
/// dup-def desta nosi rekord per instrukcja; merclab/mk56 c6/c7:
/// 17951/18932 kerneli multiset+byte EXACT reguly boot+S2R+LDC-geo).
/// Mapa stalego okna c[0x0]: 0x360->1, 0x364->2, 0x368->3, 0x370->4,
/// 0x374->5, 0x378->6 (ta sama numeracja geometrii co enum SR mk13;
/// empirycznie ~98-100% tych offsetow; reszta offsetow ma b12 z
/// value-analysis ptxas -> poza zakresem, fail-closed zwraca None).
/// mk57: 0x2f8->0x44 (merclab/mk57 c5: 12 rekordow/9 kerneli cusparse,
/// bijekcja lane<->rekord 1:1, zero FP; domyka 18932/18932 EXACT).
/// Tylko golony opcode "LDC" (NIE LDC.64/LDC.U8/LDCU). Zwraca
/// (dest=R-numer, b12). None dla RZ/UR/parse-fail — fail-closed.
pub fn merc_ldc_geo(text: &str) -> Option<(u32, u8)> {
    let mut toks = text.split_whitespace();
    let mut opc = "";
    for t in &mut toks {
        if t.starts_with('@') {
            continue;
        }
        opc = t.trim_end_matches(';');
        break;
    }
    if opc != "LDC" {
        return None;
    }
    let dest = toks.next()?.trim_end_matches(',');
    if dest == "RZ" || !dest.starts_with('R') {
        return None;
    }
    let d: u32 = dest[1..].parse().ok()?;
    let marker = "c[0x0][0x";
    let pos = text.find(marker)?;
    let hexstart = pos + marker.len();
    let hexdigits: String = text[hexstart..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    let off = u32::from_str_radix(&hexdigits, 16).ok()?;
    let b12 = match off {
        0x360 => 1,
        0x364 => 2,
        0x368 => 3,
        0x370 => 4,
        0x374 => 5,
        0x378 => 6,
        0x2f8 => 0x44,
        _ => return None,
    };
    Some((d, b12))
}

/// Mini-rekord dla LOP3 z destem predykatowym (`LOP3.LUT Pn, ..`): lane NIE
/// dostaje bitu bitmapy (w przeciwienstwie do LOP3 z destem Rn), zamiast
/// tego 4-bajtowy atom w lane (gold d_sw4_store slot6, mk13 2026-08-06).
pub const MERC_LOP3_PWRITE_MINI: [u8; 4] = [0x42, 0x2a, 0x02, 0x06];

/// Rekord 020f120e (DMUL z imm) / 020c1e0e (DADD z imm): imm = gorne 32 bity
/// stalej f64 na [28:32] (rownowazne minimalnemu ogonowi mk51 — LSB stalej
/// sa w praktyce zerowe); siatka rejestrowa (d<<6)|3 / (a<<6)|2, ZRODLO RZ
/// bez flagi |2 (0xffc0, jak mk49/store2). mk51: b4 = pelny kod predykatu
/// mk41 (korpus 020c1e0e: 106 predkowanych), b7 = 2*negA + 4*absA
/// (korpus: 1828x 00 / 1203x 02). Wariant: 0=DMUL, 1=DADD.
pub fn build_f64imm_rec(
    variant: u8,
    d: u16,
    a: u16,
    imm_top: u32,
    pred: u8,
    b7: u8,
) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0x02;
    let (t1, t2) = if variant == 0 { (0x0f, 0x12) } else { (0x0c, 0x1e) };
    r[1] = t1;
    r[2] = t2;
    r[3] = 0x0e;
    r[4] = pred;
    r[6] = 0x08;
    r[7] = b7;
    r[10..12].copy_from_slice(&(((d.min(0x3ff)) << 6) | 3).to_le_bytes());
    let aflag: u16 = if a == 0x3ff { 0 } else { 2 }; // zrodlo RZ bez |2
    r[12..14].copy_from_slice(&(((a.min(0x3ff)) << 6) | aflag).to_le_bytes());
    r[14] = 0x13;
    r[28..32].copy_from_slice(&imm_top.to_le_bytes());
    r
}

/// mk51: rekordy DFMA z natychmiastowym f64 (emulator korpusowy
/// merclab/mk51 c10: 18932/18932 kerneli byte-exact, obustronnie):
///   020d1c0e = DFMA Rd, sA, sB, imm   (imm LAST;   72255 rekordow korpusu)
///   020d1a0e = DFMA Rd, sA, imm, sB   (imm MIDDLE;  4256 rekordow)
/// Layout: b4=pred (mk41), b6=0x08, b7=2*negA+8*negB+4*absA+16*absB;
/// b10/11=(dst<<6)|3, b12/13=(A<<6)|2, B w [14:16] + marker 0x13 na b17
/// (wariant last) albo marker b14=0x13 i B w [17:19] (wariant mid).
/// Zrodlo RZ bez flagi |2 (0xffc0). Ogon imm: MINIMALNE gorne bajty stalej
/// f64 wyrownane do b31 (co najmniej 2): 1.0 -> [30:32]=f0 3f;
/// stala z bitem w dolnym slowie wypelnia wiecej (0x40c81c80.. -> [28:32]).
pub fn build_dfmaimm_rec(
    mid: bool,
    pred: u8,
    b7: u8,
    d: u16,
    a: u16,
    b: u16,
    imm: u64,
) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0x02;
    r[1] = 0x0d;
    r[2] = if mid { 0x1a } else { 0x1c };
    r[3] = 0x0e;
    r[4] = pred;
    r[6] = 0x08;
    r[7] = b7;
    r[10..12].copy_from_slice(&(((d.min(0x3ff)) << 6) | 3).to_le_bytes());
    let sf = |x: u16| -> u16 { if x == 0x3ff { 0 } else { 2 } };
    r[12..14].copy_from_slice(&(((a.min(0x3ff)) << 6) | sf(a)).to_le_bytes());
    if mid {
        r[14] = 0x13;
        r[17..19].copy_from_slice(&(((b.min(0x3ff)) << 6) | sf(b)).to_le_bytes());
    } else {
        r[14..16].copy_from_slice(&(((b.min(0x3ff)) << 6) | sf(b)).to_le_bytes());
        r[17] = 0x13;
    }
    let mut v = imm;
    let mut m = 0u32;
    while m < 6 && v & 0xff == 0 {
        v >>= 8;
        m += 1;
    }
    let nb = (8 - m) as usize;
    r[32 - nb..32].copy_from_slice(&v.to_le_bytes()[..nb]);
    r
}

/// True gdy tekst LOP3 to wariant DUAL-WRITE (R-dest != RZ + zapis
/// predykatu): nvdisasm drukuje go `LOP3.LUT Pn, ...` (gubi jawny R-dest —
/// rozroznienie mozliwe tylko po slowie kodu), cubit drukuje
/// `LOP3.LUT R0, R0, 0x3, RZ, 0xc0, !P1`. Gold d_sw4_store slot6: taki lane
/// NIE dostaje bitu bitmapy; zamiast niego mini-rekord 42 2a 02 06. Wariant
/// pred-only (dest RZ, np. `LOP3.LUT RZ, R0, 0x1, RZ, 0xc0, !P0`) dostaje
/// bit normalnie (c_sel/d_ifelse2/sw2 exact; mk13 2026-08-06).
pub fn lop3_writes_pred(text: &str) -> bool {
    let mut t = text.trim_end_matches([';', ' ']).trim();
    while let Some(rest) = t.strip_prefix('@') {
        t = rest
            .split_once(char::is_whitespace)
            .map(|(_, r)| r.trim_start())
            .unwrap_or("");
    }
    // odetnij mnemonik
    let body = match t.split_once(char::is_whitespace) {
        Some((_, r)) => r,
        None => return false,
    };
    let toks: Vec<&str> = body
        .split(',')
        .map(|x| x.trim().trim_end_matches([';', ',']).trim_start_matches('!'))
        .collect();
    let is_p = |tok: &str| {
        tok.len() >= 2 && tok.starts_with('P') && tok[1..].chars().all(|c| c.is_ascii_digit())
    };
    let is_rdest = |tok: &str| {
        tok.len() >= 2 && tok != "RZ" && tok.starts_with('R')
            && tok[1..].chars().all(|c| c.is_ascii_digit())
    };
    match (toks.first(), toks.last()) {
        (Some(d), Some(p)) => is_rdest(d) && is_p(p),
        _ => false,
    }
}

/// Atom wypelniajacy lane dla UIADD3-killpad. UWAGA korpus (uiadd3_bitmap2):
/// killpad = _dokladna_ forma `UIADD3 URZ, UPT, UPT, URZ, URZ, URZ` — tylko
/// wtedy brak bitu bitmapy + atom w lane. LIVE UIADD3 (dest URn) ma bit
/// (32,490 vs 18 pomiarowow). Dlatego lane-pady sa explicite w meta.
pub const MERC_LANE_PAD: [u8; 2] = [0xd0, 0x00];

/// mk14: rekord-event ducha `__syncwarp()` (ptxas eliduje bezwarunkowy
/// syncwarp do NOP; site'y z EIATTR 0x28 z maska 0xffffffff). Lane bez
/// bitu bitmapy spoza spanow BSSY; payload stale (gold: p_warpsync/p_lds/
/// p_sts2/p_ldsm/p_ldgsts/q_bsync_pair x2 — wszystkie identyczne).
pub const MERC_SYNCWARP_GHOST: [u8; 16] = [
    0x01, 0x47, 0x6c, 0x0a, 0xf8, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// mk14.3: blob 32B rekordu pinned `51 02` + 0223 3034 (LDGSTS/cp.async).
/// Pola (3 probki m15-lab): dst(smem R)@[12..14)=(r<<6), addr-src(global
/// R lancucha desc)@[17..19)=(a<<6)|2; blob[9]=01, [19]=09 stale; blob[16]
/// niezdekodowane (modal 0x00; wariant noldg 0x01 — do mk16).
pub fn build_ldgsts_blob(dst: u8, addr_src: u8) -> [u8; 34] {
    let mut b = [0u8; 34];
    b[0] = 0x51;
    b[1] = 0x02;
    // blob 32B
    b[2] = 0x02;
    b[3] = 0x23;
    b[4] = 0x30;
    b[5] = 0x34;
    b[6] = 0xf8;
    b[8] = 0x24;
    b[9] = 0x10;
    b[11] = 0x01;
    if dst != 255 {
        let v = (dst as u16) << 6;
        b[14] = (v & 0xff) as u8;
        b[15] = (v >> 8) as u8;
    }
    b[16] = 0x0a;
    b[17] = 0x01;
    if addr_src != 255 {
        let v = ((addr_src as u16) << 6) | 2;
        b[19] = (v & 0xff) as u8;
        b[20] = (v >> 8) as u8;
    }
    b[21] = 0x09;
    b[23] = 0x82;
    b[24] = 0x01;
    b[26] = 0xf8;
    b
}

/// mk14.3: event 0123-400a (16B) — host = ostatnia instrukcja ze slotem
/// przed DEPBAR(.LE) zamykajacym grupe cp.async; gryzie bit bitmapy hosta.
pub const MERC_LDGSTS_WAIT: [u8; 16] = [
    0x01, 0x23, 0x40, 0x0a, 0xf8, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// mk14.3: mini-rekord LDSM (4B) w lane (gold p_ldsm: 42 5b 02 06 przed
/// rekordem 0129 xor-rega; rekord zastepuje wezel t4 — bit LDSM = 0).
pub const MERC_LDSM_MINI: [u8; 4] = [0x42, 0x5b, 0x02, 0x06];

// ==== mk30: tekstowa wersja skanu mc (lustro dla main.rs asm-path) ====
pub struct McScanText {
    pub lane: u32,
    pub base: String,
    pub full: String,
    pub text: String,
    pub guarded: bool,
    /// mk44: kod guarda jak merc_guard_code (0xf8 = brak; (n<<3)|neg|u*2).
    pub guard_code: u8,
}

pub struct McScanOut {
    pub exch: Vec<(u32, bool, u8, u8)>,
    pub arrive: Vec<(u32, u8)>,
    pub phase: Vec<u32>,
    pub uiadd3_1m: Vec<(u32, bool)>,
    pub ushf_fin: Vec<u32>,
    pub voteu_all: Vec<u32>,
    pub mov400: Vec<u32>,
    pub lea18: Vec<u32>,
    /// mk41: ULEA ..., 0x18 (era-100 tylko; wybor przy budowie meta).
    pub ulea18: Vec<u32>,
    pub ws: Vec<(u32, u8)>,
    pub uvcount: Vec<u32>,
    pub umov_rr: Vec<u32>,
    pub ublkcp: Vec<u32>,
    pub plop3_tx: Vec<(u32, u8)>,
    /// mk44: generalne rekordy 0110060a — (lane, 16B gotowych bajtow),
    /// z bramka dual-output (nibswap-LUT) i bez operandow UP.
    pub plop3_rec: Vec<(u32, [u8; 16])>,
    /// mk54: rekordy 02100214 (PLOP3.LUT z uniform Pc) — (lane, 32B).
    pub plop3u_rec: Vec<(u32, [u8; 32])>,
    /// mk54: rekordy 02100414 (UPLOP3.LUT) — (lane, 32B).
    pub uplop3_rec: Vec<(u32, [u8; 32])>,
    /// mk54: rekordy 0210160e/02100a0e (DSETP z imm f64) — (lane, 32B).
    pub dsetpimm_rec: Vec<(u32, [u8; 32])>,
    /// mk45: rekordy 010b0c0a (CS2R Rd, SRZ) — (lane, 16B gotowych bajtow).
    pub cs2r_rec: Vec<(u32, [u8; 16])>,
    /// mk46: rekordy 010b060a geo-anchor (S2UR-geo + LDCU okno drivera).
    pub geo_rec: Vec<(u32, [u8; 16])>,
    /// mk47: rekordy 012b{00|04}0a (LOP3.LUT NOT-MOV LUT=0x33) — (lane, 16B).
    pub lop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk58: rekordy 012b080a (ULOP3.LUT NOT-MOV LUT=0x33) — (lane, 16B).
    pub ulop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk71: rekordy 01291004 (ULOP3.LUT xor LUT=0x3c, 3xUR) — (lane, 16B).
    pub ulop3xor_rec: Vec<(u32, [u8; 16])>,
    /// mk72: rekordy 01290804 (LOP3.LUT xor LUT=0x3c, Rd=R,Ra=R,srcB=UR) — (lane, 16B).
    pub lop3xorur_rec: Vec<(u32, [u8; 16])>,
    /// mk48: rekordy 024d*32 (REDG desc/non-desc) — (lane, 32B).
    pub redg2_rec: Vec<(u32, [u8; 32])>,
    /// mk49: rekordy 024e*32 (ATOM.E/ATOMG/ATOMS) — (lane, 32B).
    pub atomg2_rec: Vec<(u32, [u8; 32])>,
    pub fence_async: Vec<u32>,
    pub ldgsts_b128: bool,
    /// mk41: (lane, guarded, dst-UR) — payload smem-anchora z dst.
    pub s2ur_cga: Vec<(u32, bool, u8)>,
    pub bsync_close: Vec<u32>,
    pub hfma2_const: Vec<u32>,
    pub ulea_x: Vec<u32>,
    pub bra_np_loop: Vec<u32>,
    /// mk59: rekord d1-34B wariant 47 per WARPSYNC.COLLECTIVE (nie-.ALL)
    /// z regionem same NOP-y -> (lane WC, reg maski). Patrz merc_d1wc47_record.
    pub d1wc47: Vec<(u32, u8)>,
    /// mk62: regiony BSSY.RECONVERGENT -> rekord 51010109 na lane zamkniecia
    /// BSYNC; (close_lane, barrier_id). Payload: stale + dw[12:16]=2*barrier.
    pub region09: Vec<(u32, u8)>,
    /// mk62: False gdy para BSSY/BSYNC niespojna -> elf_builder bierze legacy.
    pub region09_ok: bool,
    /// mk60: rekordy 0132100a (REDUX.SUM.S32/CREDUX) — (lane, 16B).
    pub redux2: Vec<(u32, [u8; 16])>,
    /// mk34 (node-model g5b): lane'y bez wezla w liscie capmerc — NIE zajmuja
    /// slotu bitmapy (b_mbarrier: para USHF licznika mbarrier po d1-UIADD3;
    /// b_bulk_cp: te + FENCE.ASYNC). Tylko m-family (SYNCS.*).
    pub nodeless: Vec<u32>,
}

/// mk62: id bariery z tekstu operandow BSSY/BSYNC ("B0, `(.L_x_7)" -> 0).
pub fn merc_barrier_id(text: &str) -> Option<u8> {
    let t = text.trim().trim_end_matches(';');
    // skanuj tokeny (opcode/guard/operandy): pierwszy "B<n>" wygrywa.
    for tok in t.split(|c: char| c == ' ' || c == ',') {
        let tok = tok.trim();
        if let Some(n) = tok.strip_prefix('B') {
            if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) {
                if let Ok(v) = n.parse::<u8>() {
                    if v < 8 {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// mk62: rekord 51010109 (18B): staly szkielet + dw[12:16] = 2*barrier_id.
/// Dowod korpusowy (mk62 c9/c21): multiset(dw/2) == multiset(barier) zawsze
/// gdy count sie zgadza (3267/3267 kerneli, byte-exactness pelna).
pub fn merc_region09_record(barrier: u8) -> [u8; 18] {
    let mut r: [u8; 18] = [
        0x51, 0x01, 0x01, 0x09, 0x02, 0x0a, 0xf8, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    r[12..16].copy_from_slice(&(2u32 * barrier as u32).to_le_bytes());
    r
}

pub fn mc_scan_lines(items: &[McScanText]) -> McScanOut {
    let mut o = McScanOut {
        exch: Vec::new(),
        arrive: Vec::new(),
        phase: Vec::new(),
        uiadd3_1m: Vec::new(),
        ushf_fin: Vec::new(),
        voteu_all: Vec::new(),
        mov400: Vec::new(),
        lea18: Vec::new(),
        ulea18: Vec::new(),
        ws: Vec::new(),
        uvcount: Vec::new(),
        umov_rr: Vec::new(),
        ublkcp: Vec::new(),
        plop3_tx: Vec::new(),
        plop3_rec: Vec::new(),
        plop3u_rec: Vec::new(),
        uplop3_rec: Vec::new(),
        dsetpimm_rec: Vec::new(),
        cs2r_rec: Vec::new(),
        geo_rec: Vec::new(),
        lop3not_rec: Vec::new(),
        ulop3not_rec: Vec::new(),
        ulop3xor_rec: Vec::new(),
        lop3xorur_rec: Vec::new(),
        redg2_rec: Vec::new(),
        atomg2_rec: Vec::new(),
        fence_async: Vec::new(),
        ldgsts_b128: false,
        s2ur_cga: Vec::new(),
        bsync_close: Vec::new(),
        hfma2_const: Vec::new(),
        ulea_x: Vec::new(),
        bra_np_loop: Vec::new(),
        nodeless: Vec::new(),
        d1wc47: Vec::new(),
        region09: Vec::new(),
        region09_ok: false,
        redux2: Vec::new(),
    };
    // mk62: regiony BSSY/BSYNC (stack per barrier-id) — rekord 51010109
    // per zamkniecie regionu o flavorze RECONVERGENT.
    {
        let mut ok = true;
        let mut stacks: [Vec<(u32, bool)>; 8] = Default::default();
        for it in items.iter() {
            match it.base.as_str() {
                "BSSY" => match merc_barrier_id(&it.text) {
                    Some(b) => stacks[b as usize]
                        .push((it.lane, it.full.contains("RECONVERGENT"))),
                    None => {
                        ok = false;
                        break;
                    }
                },
                "BSYNC" => match merc_barrier_id(&it.text) {
                    Some(b) => match stacks[b as usize].pop() {
                        Some((_, rec)) => {
                            if rec {
                                o.region09.push((it.lane, b));
                            }
                        }
                        None => {
                            ok = false;
                            break;
                        }
                    },
                    None => {
                        ok = false;
                        break;
                    }
                },
                _ => {}
            }
        }
        if ok && stacks.iter().all(|s| s.is_empty()) {
            o.region09_ok = true;
        }
    }
    let bar_lanes: Vec<u32> = items
        .iter()
        .filter(|i| i.base == "BAR")
        .map(|i| i.lane)
        .collect();
    let ws_lanes: Vec<u32> = items
        .iter()
        .filter(|i| i.base == "WARPSYNC" && i.full.contains(".ALL") && !i.full.contains(".COLLECTIVE"))
        .map(|i| i.lane)
        .collect();
    // mk59: d1-47 per WC-site (region (WC..ENDCOLLECTIVE) = same NOP-y).
    // Fail-closed: guard, .ALL, maska spoza R<n>, region pusty/nie-NOP.
    for (i, it) in items.iter().enumerate() {
        if it.base != "WARPSYNC" || !it.full.contains(".COLLECTIVE") || it.full.contains(".ALL") {
            continue;
        }
        if it.guarded {
            continue;
        }
        let mask = match merc_d1wc_mask_reg(&it.text) {
            Some(m) => m,
            None => continue,
        };
        let mut j = i + 1;
        let mut ok = false;
        let mut nnop = 0usize;
        while j < items.len() {
            let b2 = items[j].base.as_str();
            if b2 == "ENDCOLLECTIVE" {
                ok = nnop >= 1;
                break;
            } else if b2 == "NOP" {
                nnop += 1;
                j += 1;
            } else {
                break;
            }
        }
        if ok {
            o.d1wc47.push((it.lane, mask));
        }
    }
    let mut saw_ushf_0b: Option<u32> = None;
    for it in items {
        let lane = it.lane;
        let t = it.text.as_str();
        match it.base.as_str() {
            "REDUX" | "CREDUX" => {
                // mk60: rekord 0132100a (klasyfikator pelny, fail-closed).
                if !it.guarded {
                    if let Some(r) = merc_redux2_record(&it.text) {
                        o.redux2.push((lane, r));
                    }
                }
            }
            "SYNCS" => {
                if t.contains("EXCH") {
                    let mut urs = t
                        .split(|c: char| c == '[' || c == ']' || c == ',' || c == ' ')
                        .filter_map(|tok| {
                            let tk = tok.trim().trim_end_matches(';');
                            tk.strip_prefix("UR").and_then(|n| n.parse::<u8>().ok())
                        });
                    let addr = urs.next().unwrap_or(6);
                    let val = urs.next().unwrap_or(4);
                    o.exch.push((lane, it.guarded, addr, val));
                } else if t.contains("ARRIVE") {
                    let b4: u8 = if !it.guarded { 0xf8 } else { 0x01 };
                    o.arrive.push((lane, b4));
                } else if t.contains("PHASECHK") {
                    o.phase.push(lane);
                }
            }
            "UIADD3" if t.contains("0x100000") => o.uiadd3_1m.push((lane, it.guarded)),
            "VOTEU" if it.full.contains(".ALL") => o.voteu_all.push(lane),
            "MOV" if t.contains(", 0x400") => o.mov400.push(lane),
            x if (x == "LEA" || x == "ULEA") && t.contains(", 0x18") && !it.full.contains("HI") => { if x == "ULEA" { o.ulea18.push(lane) } else { o.lea18.push(lane) } },
            "UMOV" => {
                let body = t.trim();
                let rest = body.trim_start_matches("UMOV").trim_start();
                let mut it2 = rest.split(',');
                let d = it2.next().unwrap_or("").trim();
                let s = it2.next().unwrap_or("").trim().trim_end_matches(';');
                if d.starts_with("UR") && s.starts_with("UR") {
                    o.umov_rr.push(lane);
                }
            }
            "UVIRTCOUNT" if it.full.contains("DEALLOC") => o.uvcount.push(lane),
            "FENCE" if t.contains("ASYNC") => o.fence_async.push(lane),
            "PLOP3" => {
                if !it.guarded && t.contains("P0, PT, PT, PT, PT, 0x80, 0x8") {
                    o.plop3_tx.push((lane, 0));
                } else if t.contains("P0, PT, P1, PT, PT, 0x8, 0x80") {
                    o.plop3_tx.push((lane, 1));
                } else if !it.guarded && t.contains("P1, PT, PT, PT, PT, 0x8, 0x80") {
                    o.plop3_tx.push((lane, 2));
                }
                // mk44: generyczny rekord 0110060a (dual-output, bez UP).
                if let Some(r) = merc_plop3_record(t, it.guard_code) {
                    o.plop3_rec.push((lane, r));
                }
                // mk54: rekord 02100214 (PLOP3.LUT z uniform Pc).
                if let Some(r) = merc_plop3u_record(t, it.guard_code) {
                    o.plop3u_rec.push((lane, r));
                }
            }
            "UPLOP3" => {
                // mk54: rekord 02100414.
                if let Some(r) = merc_uplop3_record(t, it.guard_code) {
                    o.uplop3_rec.push((lane, r));
                }
            }
            "DSETP" => {
                // mk54: rekordy 0210160e/02100a0e (DSETP z imm f64).
                if let Some(r) = merc_dsetpimm_record(t, it.guard_code) {
                    o.dsetpimm_rec.push((lane, r));
                }
            }
            "CS2R" => {
                // mk45: generyczny rekord 010b0c0a (CS2R R<d>, SRZ).
                if let Some(r) = merc_cs2r_srz_record(t, it.guard_code) {
                    o.cs2r_rec.push((lane, r));
                }
            }
            "LOP3" => {
                // mk47: rekord 012b{00|04}0a (LOP3.LUT NOT-MOV, LUT=0x33).
                if let Some(r) = merc_lop3_not_record(t, it.guard_code) {
                    o.lop3not_rec.push((lane, r));
                }
                // mk72: rekord 01290804 (LOP3.LUT xor LUT=0x3c, R,R,UR).
                if let Some(r) = merc_lop3_xor_ur_record(t, it.guard_code) {
                    o.lop3xorur_rec.push((lane, r));
                }
            }
            "ULOP3" => {
                // mk58: rekord 012b080a (ULOP3.LUT NOT-MOV, LUT=0x33).
                if let Some(r) = merc_ulop3_not_record(t, it.guard_code) {
                    o.ulop3not_rec.push((lane, r));
                }
                // mk71: rekord 01291004 (ULOP3.LUT xor LUT=0x3c, 3xUR).
                if let Some(r) = merc_ulop3_xor_record(t, it.guard_code) {
                    o.ulop3xor_rec.push((lane, r));
                }
            }
            "REDG" => {
                // mk48: rekordy 024d{0e|24|2e}32 (REDG desc/non-desc).
                if let Some(r) = merc_redg_record(t, it.guard_code) {
                    o.redg2_rec.push((lane, r));
                }
            }
            "ATOM" | "ATOMG" | "ATOMS" => {
                // mk49: rekordy 024e*32 (ATOM.E desc, ATOMG float/int/CAS,
                // ATOMS shared POPC/ADD/MINMAX). CAST.SPIN/ATOM.E.CAS bez rekordu.
                if let Some(r) = merc_atomg2_record(t, it.guard_code) {
                    o.atomg2_rec.push((lane, r));
                }
            }
            "LDGSTS" if it.full.contains(".128") => o.ldgsts_b128 = true,
            "S2UR" => {
                // mk46: geo-anchor 010b060a (CTAID.* / CgaCtaId / SWINHI).
                if let Some((d, role, cls)) = merc_geo_anchor(t, "S2UR", &it.full) {
                    o.geo_rec.push((lane, merc_geo_record(d, role, cls, it.guard_code)));
                    if t.contains("SR_CgaCtaId") {
                        // mk41: dst UR z tekstu — payload smem-anchora (dstUR<<6)|1.
                        o.s2ur_cga.push((lane, it.guarded, d.min(255) as u8));
                    }
                }
            }
            "LDCU" => {
                // mk46: LDCU z okna stalych drivera -> geo-anchor 010b060a.
                if let Some((d, role, cls)) = merc_geo_anchor(t, "LDCU", &it.full) {
                    o.geo_rec.push((lane, merc_geo_record(d, role, cls, it.guard_code)));
                }
            }
            "BSYNC" => o.bsync_close.push(lane),
            "HFMA2" if t.matches("RZ").count() >= 2 => o.hfma2_const.push(lane),
            _ => {}
        }
        if it.base == "USHF" {
            let parts: Vec<&str> = t.split(',').collect();
            let imm = parts.get(2).map(|s| s.trim());
            if imm == Some("0xb") {
                saw_ushf_0b = Some(lane);
            } else if imm == Some("0x1") && saw_ushf_0b.is_some() {
                o.ushf_fin.push(lane);
                // mk34: prolog licznika mbarrier ("USHF ..,0xb" + "USHF ..,0x1"
                // po d1-UIADD3) nie ma zadnych wezlow (g5b: b_mbarrier l9/10,
                // b_bulk_cp l12/13) — lane'e wypadaja z przestrzeni bitmapy.
                o.nodeless.push(saw_ushf_0b.unwrap());
                o.nodeless.push(lane);
            }
        }
        if it.base.starts_with("__raw__") || it.full.starts_with("__raw__") {
            let tx = t.trim().trim_end_matches(';');
            if tx.ends_with("0073ba") || it.full.trim_end_matches(';').ends_with("0073ba") {
                o.ublkcp.push(lane);
            }
        }
    }
    if o.exch.is_empty() && o.arrive.is_empty() && o.phase.is_empty() {
        o.mov400.clear();
        o.nodeless.clear(); // para ushf poza m-family nie obowiazuje
        o.nodeless.shrink_to_fit();
    } else if o.exch.is_empty() {
        o.mov400.clear();
    }
    // mk34 ODSLOWIENIE (node-model g5b): ulea_x i bra_np_loop pozostaja puste.
    // Wczesniejsze fitowano lane-space na zamienionych indeksach bitmapy; we
    // wlasciwej przestrzeni NODE nvcc ULEA prologu EXCH i braided-BRA maja
    // wezly t4 z flaga=1 (b_mbarrier n09/lane11, n19/n21, n32/n34, n33/n35;
    // b_bulk_cp n14/n16, n15/n17, n25/lane28).
    for (k, &wl) in ws_lanes.iter().enumerate() {
        let end = ws_lanes.get(k + 1).copied().unwrap_or(u32::MAX);
        let has_bar = bar_lanes.iter().any(|&b| b > wl && b < end);
        o.ws.push((wl, if has_bar { 0x6e_u8 } else { 0x76_u8 }));
    }
    // mk34: FENCE.ASYNC tez bez wezla (b_bulk_cp lane18; g5b: brak nodu
    // miedzy ULEA#2 a EXCH).
    let m_fam2 = !(o.exch.is_empty() && o.arrive.is_empty() && o.phase.is_empty());
    if m_fam2 {
        let fl = o.fence_async.clone();
        for l in fl {
            if !o.nodeless.contains(&l) {
                o.nodeless.push(l);
            }
        }
        o.nodeless.sort_unstable();
        o.nodeless.dedup();
    }
    o
}


// ==== mk30: rodziny rekordow b_* (SYNCS/mbarrier/TMA/minis) ====
// Rodowod: mk26-capture (oraculum kandydata->final) + mikrolab mk30
// (m_init/m_arr/m_wait/bulk1/uvc/m_min — nvcc 13.3.73, sm_103a).

/// mini 4B: VOTEU.ALL (klasa 014c -> 41 4c 02 0a; mk26 CLS 0x11d).
pub const MERC_MINI_VOTEU: [u8; 4] = [0x41, 0x4c, 0x02, 0x0a];
/// mini 4B: LEA R,R,R,0x18 w prologu mbarrier-register-path
/// (kand. 01 00 00 0a; m_arr/m_wait/b_mbarrier).
pub const MERC_MINI_LEA18: [u8; 4] = [0x41, 0x00, 0x00, 0x0a];
/// mini 4B: UMOV URx, URy (reg-reg) — b_ldmatrix lane3 (bit kasowany).
pub const MERC_MINI_UMOV_RR: [u8; 4] = [0x41, 0x00, 0x10, 0x0a];
/// mini 4B: UVIRTCOUNT.DEALLOC.SMPOOL (b_tcgen05 @lane35; bit ZOSTAJE).
pub const MERC_MINI_UVIRT: [u8; 4] = [0x41, 0x44, 0x00, 0x3c];
/// mini 4B: WARPSYNC.ALL — b2 = 0x6e gdy w regionie az do kolejnego
/// WARPSYNC/konca jest BAR.SYNC; inaczej 0x76. (mk26 CLS: kand. 0147xx0a;
/// potwierdzone na b_mbarrier(6e), b_tcgen05(76/76/6e), uvc(76/76/6e),
/// mkvmem(76).) Zgodne bajtowo z REC_MINI_GHOST76 (mk27).
pub const MERC_MINI_WS6E: [u8; 4] = [0x41, 0x47, 0x6e, 0x0a];
pub const MERC_MINI_WS76: [u8; 4] = [0x41, 0x47, 0x76, 0x0a];

/// mini 4B: WARPSYNC reg-form / WARPSYNC.EXCLUSIVE (maska w R<n>) —
/// mk65 (merclab/mk65 c9: korpus EXACT obustronnie 18932/18932):
/// b2 = 0x78 iff lane jest site'em EIATTR-0x28, inaczej 0x70.
pub const MERC_MINI_WS78: [u8; 4] = [0x41, 0x47, 0x78, 0x0a];
pub const MERC_MINI_WS70: [u8; 4] = [0x41, 0x47, 0x70, 0x0a];

/// d1-marker + blob 01 1b 36 0a (16B): mbarrier-init count-prolog
/// (UIADD3 UR?, UPT, UPT, +/-UR?, 0x100000, URZ). b4: 0x03 gdy prolog jest
/// predykowany (@!UPx i @!Px rowno — m_init/b_mbarrier), 0xfa gdy nie.
/// uklad kabla: [d1 01] marker (2B) + 16B rekord.
pub fn merc_mbar_d1_blob(guarded: bool) -> [u8; 18] {
    // marker d1 01, potem 16B rekord 01 1b 36 0a + payload
    let body = [
        0x01, 0x1b, 0x36, 0x0a,
        if guarded { 0x03 } else { 0xfa }, 0x00, 0x53, 0x00,
        0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0xc0, 0xff,
    ];
    let mut r = [0u8; 18];
    r[0] = 0xd1;
    r[1] = 0x01;
    r[2..18].copy_from_slice(&body);
    r
}

/// mk59: rekord 34B `d1 01 02 47` (wariant 47 = "pusty region kolektywny")
/// per site `WARPSYNC.COLLECTIVE R<mask>, L` (nie-.ALL), ktorego region
/// (WC..ENDCOLLECTIVE) zawiera wylacznie NOP-y. Dekod korpusowy merclab/mk59
/// (c1..c10; l2 676 plikow, 18932 kerneli):
/// - licznik: rekord per WC-site (4412/4464 kerneli #rekordow == #WC-sitow;
///   wyjatki = strony 4c/23, fail-closed);
/// - 47-body: b8=0x10, b12=0x00, b13=0xf8, (b14,b15)=LE16(mask<<6)
///   [19935/19935 rekordow: F0 == mask<<6; 47-only kerneli b30=0 zawsze
///   (15711/15711)]; maska zawsze klasa R<n> (0xUR/RZ bez wystapien).
/// - warianty wykryte i zaparkowane (region-tree mk29): 4b = region z
///   pojedynczym SHFL (F=[(dst<<6)|1, srcA<<6, srcB<<6, srcC<<6, mask<<6],
///   b8=0x20|kind{IDX,UP,DOWN,BFLY}; b13/b30 = koordynaty drzewa regionow);
///   4c = region z VOTE.ANY/ALL; 23 = kernele bez WC-sitow.
pub fn merc_d1wc47_record(mask: u8) -> [u8; 34] {
    let mut r = [0u8; 34];
    r[0] = 0xd1;
    r[1] = 0x01;
    r[2] = 0x02;
    r[3] = 0x47;
    r[4] = 0x7c;
    r[5] = 0x06;
    r[6] = 0xf8;
    r[8] = 0x10;
    r[13] = 0xf8;
    let v = (mask as u16) << 6;
    r[14] = (v & 0xff) as u8;
    r[15] = (v >> 8) as u8;
    r[16] = 0x02;
    r
}

/// mk60: rekord 0132100a (16B) per lane REDUX/CREDUX — pelny dekod
/// korpusowy (merclab/mk60; l2 676 plikow, 18932 kerneli):
/// nosza: CREDUX.MAX.S32 -> b6=55, CREDUX.MIN.S32 -> b6=51,
///        CREDUX.MIN -> b6=50, REDUX.SUM.S32 -> b6=4d (ale NIE gd
///        dst==UR79: 88/88 bez rekordu — rejestr zarezerwowany ptxas);
/// NIE nosza: REDUX.OR (3376 lane'ow), goly REDUX, guardy (brak w
/// korpusie -> fail-closed). Pola: (b10,b11)=LE16((URd<<6)|1),
/// (b12,b13)=LE16(src<<6) (RZ -> 0x3ff<<6 = ffc0); (b14,b15)=0.
/// Wymagane dokladnie 2 operandy: UR-dst + R/RZ-src.
/// Uwaga: druk cubit pisze REDUX.S32.SUM (kolejnosc legacy) — akceptujemy
/// obie formy.
pub fn merc_redux2_record(text: &str) -> Option<[u8; 16]> {
    let t = text.trim();
    if t.starts_with('@') {
        return None; // guard: brak korpusowy
    }
    let (op, ops) = t.split_once(char::is_whitespace)?;
    let op = op.trim();
    let b6: u8 = match op {
        "CREDUX.MAX.S32" => 0x55,
        "CREDUX.MIN.S32" => 0x51,
        "CREDUX.MIN" => 0x50,
        "REDUX.SUM.S32" | "REDUX.S32.SUM" => 0x4d,
        _ => return None, // REDUX.OR, goly REDUX, inne: fail-closed
    };
    let mut parts = ops.splitn(3, ',');
    let dst = parts.next().unwrap_or("").trim();
    let src = parts.next().unwrap_or("").trim();
    if parts.next().is_some() {
        return None; // >2 operandow: fail-closed
    }
    let dst = dst.trim_end_matches(';').trim();
    let src = src.trim_end_matches(';').trim();
    let dn: u16 = dst.strip_prefix("UR")?.parse().ok()?;
    if op.contains("REDUX") && dn == 79 {
        return None; // UR79 = rezerwa ptxas (korpus: 88/88 bez rekordu)
    }
    let f1: u16 = (dn << 6) | 1;
    let f2: u16 = if src == "RZ" {
        0x3ff << 6
    } else {
        let sn: u16 = src.strip_prefix('R')?.parse().ok()?;
        sn << 6
    };
    let mut r = [0u8; 16];
    r[0..4].copy_from_slice(&[0x01, 0x32, 0x10, 0x0a]);
    r[4] = 0xf8;
    r[6] = b6;
    r[10..12].copy_from_slice(&f1.to_le_bytes());
    r[12..14].copy_from_slice(&f2.to_le_bytes());
    Some(r)
}

/// Skan pomocniczy mk59 (wspoldzielony przez mc_scan_lines z main.rs):
/// tekst maski `WARPSYNC.COLLECTIVE R<n>, ...` -> n (brak -> None).
pub fn merc_d1wc_mask_reg(text: &str) -> Option<u8> {
    // text = tresc instrukcji bez guarda; pierwszy token po mnemonicu.
    let t = text.trim();
    // pomijaj formy .ALL (bez operandu maski)
    if t.contains("WARPSYNC.COLLECTIVE.ALL") {
        return None;
    }
    let body = t.split_once("WARPSYNC.COLLECTIVE")?.1;
    let first = body.trim_start().split(',').next()?.trim();
    let n = first.strip_prefix('R')?.parse::<u8>().ok()?;
    Some(n)
}

/// 02 1b 5e 06 (32B, marker 51 01 gdy kernel ma BSSY): SYNCS.EXCH.64.
/// b4: guard EXCH (0x03 predykat / 0xfa brak); [10..12) = u16 addrUR<<6;
/// [12] = 0x0a; [14..16) = u16 (valUR<<6)|2.
pub fn merc_exch_rec(guarded: bool, bssy: bool, addr_ur: u8, val_ur: u8) -> Vec<u8> {
    let mut r = [0u8; 32];
    r[0] = 0x02;
    r[1] = 0x1b;
    r[2] = 0x5e;
    r[3] = 0x06;
    r[4] = if guarded { 0x03 } else { 0xfa };
    r[6] = 0x41;
    r[7] = 0x05;
    r[10..12].copy_from_slice(&((addr_ur as u16) << 6).to_le_bytes());
    r[12] = 0x0a;
    r[14..16].copy_from_slice(&(((val_ur as u16) << 6) | 2).to_le_bytes());
    let mut v = Vec::with_capacity(34);
    if bssy {
        v.extend_from_slice(&[0x51, 0x01]);
    }
    v.extend_from_slice(&r);
    v
}

/// 02 1b 2c 32 (32B): SYNCS.ARRIVE.TRANS64.A1T0  (tran64, dst RZ).
/// b4 = guard (f8 brak / 01 @!Pn / 00 @Pn); reszta stala z probek.
pub fn merc_arrive_rec(b4: u8) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0x02;
    r[1] = 0x1b;
    r[2] = 0x2c;
    r[3] = 0x32;
    r[4] = b4;
    r[6] = 0x40;
    r[7] = 0x28;
    r[8] = 0x01;
    r[12] = 0xc1;
    r[13] = 0xff;
    r[17] = 0xc0;
    r[18] = 0xff;
    r[19] = 0x0a;
    r
}

/// 02 1b 4c 32 (32B): SYNCS.PHASECHK.TRANS64.TRYWAIT — forma [R0]/[R0+URZ]
/// z kerneli z ramka if(tid==0) (b_mbarrier/m_wait x2: stala).
/// UWAGA (otwarte): m_min (bez ramki) ma inny uklad b14..17 (grid RZ wczesniej).
pub fn merc_phasechk_rec() -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = 0x02;
    r[1] = 0x1b;
    r[2] = 0x4c;
    r[3] = 0x32;
    r[4] = 0xf8;
    r[6] = 0x51;
    r[7] = 0x4a;
    r[12] = 0x01;
    r[17] = 0xc0;
    r[18] = 0xff;
    r[19] = 0x0a;
    r[21] = 0xc0;
    r[22] = 0xff;
    r
}

/// 01 10 06 0a (16B): elementy sekwencji cp.async.bulk (mbarrier::complete_tx).
/// Trzy stale warianty po podpisie PLOP3 (b_bulk_cp/bulk1/bulk2):
/// A: `PLOP3.LUT P0, PT, PT, PT, PT, 0x80, 0x8` (bez guarda)
/// B: `@P1 PLOP3.LUT P0, PT, P1, PT, PT, 0x8, 0x80`
/// C: `PLOP3.LUT P1, PT, PT, PT, PT, 0x8, 0x80` (bez guarda)
pub const MERC_TMA_A: [u8; 16] = [
    0x01, 0x10, 0x06, 0x0a, 0xf8, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0xf8, 0x00, 0xf8,
];
pub const MERC_TMA_B: [u8; 16] = [
    0x01, 0x10, 0x06, 0x0a, 0x08, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0xf8,
];
pub const MERC_TMA_C: [u8; 16] = [
    0x01, 0x10, 0x06, 0x0a, 0xf8, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x08, 0x00, 0xf8, 0x00, 0xf8,
];

/// mk44: generalizacja 0110060a (korpus sm_100: EQ 5902/5902 kerneli).
/// Rekord dla KAZDEGO lane'a PLOP3.LUT dwu-wyjsciowego "dual-output"
/// (l1,l2 para nibswap: l2 == rot4(l1)) BEZ operandow UP (UPLOP3/i UPn
/// w Pd/Ps/Pa/Pb/Pc/... zawsze bez rekordu; lane'y z l2 != nibswap(l1)
/// — np. (0xe0,0x00) z trsv — tez zawsze bez; 527 kerneli-czyste dowod).
/// Era-inwariantne (sondy nvcc: sm_100a == sm_103a; mk44/probe).
/// Bajty: [4]=kod guarda (jak merc_guard_code); [6],[7]=klasa lut pary;
/// [10]=0x01; [11]=Pd; [13]=Pa; [15]=Pb; PT -> 0xf8 (Pa/Pb); '!' -> |1.
/// Mapa (l1,l2)->(b6,b7) eksperymentalna (8 kluczy korpus + (0x28,0x82) lab).
pub fn merc_plop3_lut_flags(l1: u8, l2: u8) -> Option<(u8, u8)> {
    // nibswap guard: l2 musi byc rotacja nibli l1 (dual-output form)
    if l2 != ((l1 & 0x0f) << 4) | (l1 >> 4) {
        return None;
    }
    Some(match (l1, l2) {
        (0x08, 0x80) => (0x00, 0x01),
        (0x80, 0x08) => (0x00, 0x00),
        (0x02, 0x20) => (0x00, 0x03),
        (0x20, 0x02) => (0x00, 0x02),
        (0x8f, 0xf8) => (0x20, 0x01),
        (0xf8, 0x8f) => (0x20, 0x00),
        (0xf2, 0x2f) => (0x20, 0x02),
        (0x2f, 0xf2) => (0x20, 0x03),
        (0x28, 0x82) => (0x40, 0x00),
        _ => return None,
    })
}

/// parse pred-token 'P3'/'PT'/'!P2'/'UP1' -> kod jak merc_guard_code;
/// None gdy token nie jest predem.
fn merc_plop3_pred_code(tok: &str) -> Option<u8> {
    let t = tok.trim().trim_end_matches(';');
    let (neg, t2) = match t.strip_prefix('!') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let (uni, t3) = match t2.strip_prefix('U') {
        Some(r) => (true, r),
        None => (false, t2),
    };
    let t4 = t3.strip_prefix('P')?;
    if t4 == "T" {
        return Some(0xf8);
    }
    let n: u8 = t4.parse().ok()?;
    if n > 6 {
        return None;
    }
    Some((n << 3) | (if uni { 2 } else { 0 }) | (if neg { 1 } else { 0 }))
}

/// mk44: z tekstu lane'a PLOP3.LUT buduj 16B rekord 0110060a (albo None
/// gdy lane nie podpada — UP-operandy albo nietypowa para LUT).
/// `text` = surowy tekst lane (z ewentualnym prowadzacym guardem '@.. ').
pub fn merc_plop3_record(text: &str, guard_code: u8) -> Option<[u8; 16]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r.split_once(char::is_whitespace).map(|(_, x)| x.trim_start()).unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("PLOP3.LUT") {
        return None;
    }
    let rest = body["PLOP3.LUT".len()..].trim();
    let toks: Vec<&str> = rest.split(',').collect();
    if toks.len() < 7 {
        return None;
    }
    let pd = merc_plop3_pred_code(toks[0])?;
    let ps = merc_plop3_pred_code(toks[1])?;
    let pa = merc_plop3_pred_code(toks[2])?;
    let pb = merc_plop3_pred_code(toks[3])?;
    let pc = merc_plop3_pred_code(toks[4])?;
    // UP-operandy gdziekolwiek (0x2 w kodzie) => lane NIE kwalifikuje sie.
    // Pd == PT (0xf8 w slocie dst) nie wystepuje w korpusie; tez odrzucamy.
    for c in [pd, ps, pa, pb, pc] {
        if c & 0x02 != 0 {
            return None;
        }
    }
    if pd == 0xf8 {
        return None;
    }
    let lut_tok = |t: &str| -> Option<u8> {
        let t2 = t.trim().trim_end_matches(';').trim();
        u8::from_str_radix(t2.strip_prefix("0x").unwrap_or(t2), 16).ok()
    };
    let l1 = lut_tok(toks[5])?;
    let l2 = lut_tok(toks[6])?;
    let (b6, b7) = merc_plop3_lut_flags(l1, l2)?;
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x10;
    r[2] = 0x06;
    r[3] = 0x0a;
    r[4] = guard_code;
    r[6] = b6;
    r[7] = b7;
    r[10] = 0x01;
    r[11] = pd;
    r[13] = pa;
    r[15] = pb;
    Some(r)
}

// ================= mk54: rodzina 02 10 (rekordy klasy SETP) =================
// Dekod korpusowy merclab/mk54 (c1..c23): 4347/4347 kerneli multiset+sekwencja
// EXACT, dwustronnie vs korpus (emulator c20; bitmapa rozwarstwiona — nietknieta,
// jak mk52).

/// mk54: pred-pole rekordow 02 10: 'P3'/'PT'/'!P1'/'UP2'/'UPT'
/// -> (kod slotu: n<<3 albo 0xf8 dla *T, uniform-space?, zanegowany?).
fn merc_pred10(tok: &str) -> Option<(u8, bool, bool)> {
    let t = tok.trim().trim_end_matches(';').trim();
    let (neg, t) = match t.strip_prefix('!') { Some(r) => (true, r), None => (false, t) };
    let (uni, t) = match t.strip_prefix('U') { Some(r) => (true, r), None => (false, t) };
    let rest = t.strip_prefix('P')?;
    if rest == "T" {
        return Some((0xf8, uni, neg));
    }
    let n: u8 = rest.parse().ok()?;
    if n > 6 {
        return None;
    }
    Some((n << 3, uni, neg))
}

/// mk54: rozbicie tekstu lane (z opcjonalnym guardem) na (opcode-full, operandy).
fn merc0210_body(text: &str) -> Option<(&str, &str)> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    body.split_once(char::is_whitespace)
}

fn merc_lut_tok(t: &str) -> Option<u8> {
    let t2 = t.trim().trim_end_matches(';').trim();
    u8::from_str_radix(t2.strip_prefix("0x").unwrap_or(t2), 16).ok()
}

/// mk54: rekord 02 10 02 14 (32B) — lane `PLOP3.LUT Pd, PT, Pa, Pb, UPc, l1, l2`
/// (Pc w przestrzeni UNIFORM; rodzenstwo mk44 = Pc zwykle/PT).
/// Bramka: nibswap LUT (l2==rot4(l1)) + tabela b7 po parze (l1,l2)
/// {80/08->00, 40/04->20, ea/ae->01, d5/5d->21, 5d/d5->29}; Pd=Pn n<=6 (b11),
/// Pt==PT (b13=f8), Pa=PT|Pn (b15), Pb==PT (b18=f8), Pc=UPn (b20=n<<3);
/// guard: korpus zawsze bez guarda (b4=f8). Kolejnosc tier20 lane-asc.
pub fn merc_plop3u_record(text: &str, guard_code: u8) -> Option<[u8; 32]> {
    let (op, ops0) = merc0210_body(text)?;
    if op != "PLOP3.LUT" {
        return None;
    }
    if guard_code != 0xf8 {
        return None;
    }
    let toks: Vec<&str> = ops0.trim().trim_end_matches(';').split(',').collect();
    if toks.len() != 7 {
        return None;
    }
    let (pd, du, dn) = merc_pred10(toks[0])?;
    if du || dn || pd == 0xf8 {
        return None;
    }
    let (pt, tu, tn) = merc_pred10(toks[1])?;
    if tu || tn || pt != 0xf8 {
        return None;
    }
    let (pa, au, an) = merc_pred10(toks[2])?;
    if au || an {
        return None;
    }
    let (pb, bu, bn) = merc_pred10(toks[3])?;
    if bu || bn || pb != 0xf8 {
        return None;
    }
    let (pc, cu, cn) = merc_pred10(toks[4])?;
    if !cu || cn || pc == 0xf8 {
        return None;
    }
    let l1 = merc_lut_tok(toks[5])?;
    let l2 = merc_lut_tok(toks[6])?;
    if ((l1 & 0x0f) << 4) | (l1 >> 4) != l2 {
        return None;
    }
    let b7 = match (l1, l2) {
        (0x80, 0x08) => 0x00,
        (0x40, 0x04) => 0x20,
        (0xea, 0xae) => 0x01,
        (0xd5, 0x5d) => 0x21,
        (0x5d, 0xd5) => 0x29,
        _ => return None,
    };
    let mut r = [0u8; 32];
    r[0] = 0x02; r[1] = 0x10; r[2] = 0x02; r[3] = 0x14;
    r[4] = 0xf8;
    r[7] = b7;
    r[10] = 0x01; r[11] = pd;
    r[12] = 0x01; r[13] = 0xf8;
    r[15] = pa;
    r[18] = 0xf8;
    r[20] = pc;
    Some(r)
}

/// mk54: rekord 02 10 04 14 (32B) — lane `UPLOP3.LUT UPd, UPT, UPT, UPT, UPc,
/// l1, l2` (wszystkie predy w przestrzeni uniform; Pt/Pa/Pb == UPT w korpusie,
/// nibswap LUT, pary (80,08)->b7=00 / (40,04)->b7=20). b4 = kod guarda w
/// wersji UNIFORM: brak guarda -> 0xfa (nie f8!), '@UPn'/'@!UPn' -> mk41
/// (n<<3)|2|neg; guard P-space -> fail-closed (korpus: brak).
pub fn merc_uplop3_record(text: &str, guard_code: u8) -> Option<[u8; 32]> {
    let (op, ops0) = merc0210_body(text)?;
    if op != "UPLOP3.LUT" {
        return None;
    }
    let toks: Vec<&str> = ops0.trim().trim_end_matches(';').split(',').collect();
    if toks.len() != 7 {
        return None;
    }
    let (pd, du, dn) = merc_pred10(toks[0])?;
    if !du || dn || pd == 0xf8 {
        return None;
    }
    for i in 1..=3 {
        let (p, u, n) = merc_pred10(toks[i])?;
        if !u || n || p != 0xf8 {
            return None;
        }
    }
    let (pc, cu, cn) = merc_pred10(toks[4])?;
    if !cu || cn {
        return None;
    }
    let l1 = merc_lut_tok(toks[5])?;
    let l2 = merc_lut_tok(toks[6])?;
    if ((l1 & 0x0f) << 4) | (l1 >> 4) != l2 {
        return None;
    }
    let b7 = match (l1, l2) {
        (0x80, 0x08) => 0x00,
        (0x40, 0x04) => 0x20,
        _ => return None,
    };
    let b4 = if guard_code == 0xf8 {
        0xfa
    } else if guard_code & 0x02 != 0 {
        guard_code
    } else {
        return None;
    };
    let mut r = [0u8; 32];
    r[0] = 0x02; r[1] = 0x10; r[2] = 0x04; r[3] = 0x14;
    r[4] = b4;
    r[7] = b7;
    r[10] = 0x01; r[11] = pd;
    r[12] = 0x01; r[13] = 0xf8;
    r[15] = 0xf8;
    r[18] = 0xf8;
    r[20] = pc;
    Some(r)
}

/// mk54: rekordy 02 10 16 0e / 02 10 0a 0e (32B) — lane DSETP z literalem f64
/// w 4. slocie: `DSETP.<cmp>.<bool> Pd, Pt, [neg?]Ra[.reuse], imm, [!]Pc`.
/// Selektor klasy (korpus merclab/mk54): Pt==PT i Pc==PT -> 16-forma
/// (marker 0x13@b14); inaczej 0a-forma (marker 0x13@b17 + pola Pt@b13 i
/// Pc@b20). b6 = 0x08 | C<<5, C: LT1 EQ2 LE3 GT4 NE5 GE6 MAX7 (sufiks -U
/// tej samej klasy). b7 = 8*absA | 1*(U lub MAX) | 4*(bool==OR, tylko 0a)
/// | 0x80*!Pc (tylko 0a). b4 = mk41 kod guarda (f8/(@!P0)=01/@!P1=09 ...).
/// Ogon imm: minimalne gorne bajty f64 (>=2B), wyrownane do b31 (jak mk51;
/// 1.0 -> f0 3f, +INF -> f0 7f, MAX_DENORM -> 00 10 00; b16 b(o29)=ga gdy
/// bajt5 mantysy != 0). Fail-closed: Ra slot RZ/UR/neg, imm-first/NAN,
/// 16-forma tylko dla {EQ,GT,NE,GE}[U].AND (innych klas w korpusie brak).
pub fn merc_dsetpimm_record(text: &str, guard_code: u8) -> Option<[u8; 32]> {
    let (op, ops0) = merc0210_body(text)?;
    let mm = op.strip_prefix("DSETP.")?;
    let mut jit = mm.split('.');
    let cmp_full = jit.next()?;
    let boolop = jit.next()?;
    if jit.next().is_some() {
        return None;
    }
    if boolop != "AND" && boolop != "OR" {
        return None;
    }
    let uu = cmp_full.ends_with('U');
    let cbase = cmp_full.strip_suffix('U').unwrap_or(cmp_full);
    let cnum: u8 = match cbase {
        "LT" => 1,
        "EQ" => 2,
        "LE" => 3,
        "GT" => 4,
        "NE" => 5,
        "GE" => 6,
        "MAX" => 7,
        _ => return None,
    };
    let toks: Vec<&str> = ops0.trim().trim_end_matches(';').split(',').collect();
    if toks.len() != 5 {
        return None;
    }
    let (pd, du, dn) = merc_pred10(toks[0])?;
    if du || dn || pd == 0xf8 {
        return None;
    }
    let (pt, tu, tn) = merc_pred10(toks[1])?;
    if tu || tn {
        return None;
    }
    let (pc, cu, cn) = merc_pred10(toks[4])?;
    if cu {
        return None;
    }
    let t = toks[2].trim().trim_end_matches(';').trim();
    let t0 = t.strip_suffix(".reuse").unwrap_or(t);
    let (abs, t1) = if t0.len() > 1 && t0.starts_with('|') && t0.ends_with('|') {
        (true, &t0[1..t0.len() - 1])
    } else {
        (false, t0)
    };
    if t1.starts_with('-') {
        return None;
    }
    let rn: u16 = t1.strip_prefix('R')?.trim().parse().ok()?;
    if rn > 0x3ff {
        return None;
    }
    let immf = crate::sass_file::merc_f64_lit(toks[3])?;
    if immf.is_nan() {
        return None;
    }
    let bits = immf.to_bits().to_le_bytes();
    let mut k = 2usize;
    while 8 - k > 0 && bits[8 - k - 1] != 0 {
        k += 1;
    }
    let b6 = 0x08 | (cnum << 5);
    let mut r = [0u8; 32];
    r[0] = 0x02;
    r[1] = 0x10;
    r[4] = guard_code;
    r[6] = b6;
    let u16a = (rn << 6) | 2;
    if pt == 0xf8 && pc == 0xf8 && !cn {
        // 16-forma: tylko klasy obserwowane (korpus: EQ/GT/NE/GE [+U], .AND).
        if boolop != "AND" || matches!(cbase, "LT" | "LE" | "MAX") {
            return None;
        }
        r[2] = 0x16;
        r[3] = 0x0e;
        r[7] = (if abs { 8 } else { 0 }) | (if uu { 1 } else { 0 });
        r[10] = 0x01;
        r[11] = pd;
        r[12] = (u16a & 0xff) as u8;
        r[13] = (u16a >> 8) as u8;
        r[14] = 0x13;
    } else {
        r[2] = 0x0a;
        r[3] = 0x0e;
        r[7] = (if abs { 8 } else { 0 })
            | (if uu || cbase == "MAX" { 1 } else { 0 })
            | (if boolop == "OR" { 4 } else { 0 })
            | (if cn { 0x80 } else { 0 });
        r[10] = 0x01;
        r[11] = pd;
        r[12] = 0x01;
        r[13] = pt;
        r[14] = (u16a & 0xff) as u8;
        r[15] = (u16a >> 8) as u8;
        r[17] = 0x13;
        r[20] = pc;
    }
    r[32 - k..].copy_from_slice(&bits[8 - k..]);
    Some(r)
}

/// mk45: rekordy 01 0b 0c 0a (16B): lane CS2R Rd, SRZ (korpus sm_100:
/// 10951/10989 kerneli count-exact, payload 184252/184361 par EXACT +
/// 109 RZ-special). Bramka: TYLKO SR == SRZ (SR_GLOBALTIMERLO: 240 rekordow
/// w symv_tma_ws — kernel-level gate nieznany, PARKED; SR_CgaSize i inne
/// SR: zawsze bez rekordu — 8 kerneli czystych dowodem).
/// Payload: b4=kod guarda (jak merc_guard_code); b6=0x05; b10 =
/// 0x03 | ((dst&3)<<6), b11 = dst>>2; dst==RZ -> b10=0xc1, b11=0xff;
/// b12=0xff, b13=0x0f; reszta zer.
pub fn merc_cs2r_srz_record(text: &str, guard_code: u8) -> Option<[u8; 16]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    let rest = body.strip_prefix("CS2R")?;
    let rest = rest
        .trim_start_matches(|c: char| matches!(c, '.' | 'Z' | '3' | '2' | '6' | '4'))
        .trim_start();
    let mut it = rest.split(',');
    let dst = it.next()?.trim().trim_end_matches(';').trim_end();
    let sr = it.next().unwrap_or("").trim().trim_end_matches(';').trim_end();
    if sr != "SRZ" {
        return None;
    }
    let (b10, b11) = if dst == "RZ" {
        (0xc1u8, 0xffu8)
    } else if let Some(dig) = dst.strip_prefix('R') {
        let d: u32 = dig.parse().ok()?;
        if d > 255 {
            return None;
        }
        (0x03 | (((d as u8) & 3) << 6), (d >> 2) as u8)
    } else {
        return None;
    };
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x0b;
    r[2] = 0x0c;
    r[3] = 0x0a;
    r[4] = guard_code;
    r[6] = 0x05;
    r[10] = b10;
    r[11] = b11;
    r[12] = 0xff;
    r[13] = 0x0f;
    Some(r)
}

/// mk47: rekordy 01 2b {00|04} 0a (16B). Host = lane
/// `LOP3.LUT Rd, RZ, Rs, RZ, 0x33, !PT` (kanoniczny NOT-MOV; LUT 0x33 = !B
/// przy pozostalych wejsciach martwych). Rd zawsze R<n>; klasa (bajt 2 tagu):
/// 0x00 gdy Rs = R<n>, 0x04 gdy Rs = UR<n>. Bramka korpusowa (sm_100, 676
/// plikow): multiset (guard,Rd,Rs,cls) EXACT 7305/7305 kerneli z rekordami;
/// reverse 0 kerneli z lane-wzorcem bez rekordu (17684 rekordy ogolem:
/// 16478 klasy R + 1206 klasy UR). Payload: b4=kod guarda (merc_guard_code);
/// b6=0x04; b10=0x01; b11=0xf8; (b12,b13)=LE16((Rd<<6)|1);
/// (b14,b15)=LE16(Rs<<6); reszta zer. Lane rekordu bez bitu bitmapy
/// (lanebits: 3922 bit=0 / 549 bit=1 — ogony = misalign big-kerneli jak mk44;
/// doktryna 'rekord zastepuje wezel t4').
pub fn merc_lop3_not_record(text: &str, guard_code: u8) -> Option<[u8; 16]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("LOP3.LUT") {
        return None;
    }
    let rest = body["LOP3.LUT".len()..].trim();
    let toks: Vec<&str> = rest.split(',').collect();
    if toks.len() < 6 {
        return None;
    }
    fn clean(s: &str) -> &str {
        let t = s.trim();
        let t = t.strip_suffix(';').map(str::trim_end).unwrap_or(t);
        t.strip_suffix(".reuse").unwrap_or(t)
    }
    let rd_tok = clean(toks[0]);
    if clean(toks[1]) != "RZ" || clean(toks[3]) != "RZ" {
        return None;
    }
    if clean(toks[4]) != "0x33" || clean(toks[5]) != "!PT" {
        return None;
    }
    let rd: u32 = rd_tok.strip_prefix('R')?.parse().ok()?;
    if rd > 0x3ff {
        return None;
    }
    let rs_tok = clean(toks[2]);
    let (rs, cls): (u32, u8) = if let Some(d) = rs_tok.strip_prefix("UR") {
        (d.parse().ok()?, 0x04)
    } else if let Some(d) = rs_tok.strip_prefix('R') {
        (d.parse().ok()?, 0x00)
    } else {
        return None;
    };
    if rs > 0x3ff {
        return None;
    }
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x2b;
    r[2] = cls;
    r[3] = 0x0a;
    r[4] = guard_code;
    r[6] = 0x04;
    r[10] = 0x01;
    r[11] = 0xf8;
    let dv = (rd << 6) | 1;
    r[12] = (dv & 0xff) as u8;
    r[13] = (dv >> 8) as u8;
    let sv = rs << 6;
    r[14] = (sv & 0xff) as u8;
    r[15] = (sv >> 8) as u8;
    Some(r)
}

/// mk71: rozpoznanie lane'a xor-U (`ULOP3.LUT URd, URa, URb, URZ, 0x3c, !UPT`)
/// -> rekord 01 29 10 04 (16B, layout jak 0129-R / rec_xor_reg: marker
/// 01 f8 @[8..10], dst@[10..12]=(d<<6)|1, srcA@[12..14]=a<<6,
/// srcB@[14..16]=b<<6). Korpus l2: 491/491 EXACT (licznik per kernel),
/// parkowanie payloadu potwierdzone na wszystkich 491 parach
/// (merclab/mk71 c7: b4=0xfa zawsze, wszystkie lane'y niegarded,
/// naglowek staly 01 29 10 04 fa 00 04 00 01 f8). imm-forma 0x3c (348)
/// bez rekordu; formy z innym LUT/pin/tokenami poza klasa.
pub fn merc_ulop3_xor_record(text: &str, guard_code: u8) -> Option<[u8; 16]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("ULOP3.LUT") {
        return None;
    }
    let rest = body["ULOP3.LUT".len()..].trim();
    let toks: Vec<&str> = rest.split(',').collect();
    if toks.len() == 6 {
        // jedyna forma korpusowa: 6 tok = dst,a,b,URZ,0x3c,!UPT.
    } else {
        return None;
    }
    fn clean(s: &str) -> &str {
        let t = s.trim();
        let t = t.strip_suffix(';').map(str::trim_end).unwrap_or(t);
        t.strip_suffix(".reuse").unwrap_or(t)
    }
    // guard jak mk58 (012b080a): brak -> 0xfa; korpusowo @!UPn = (n<<3)|3
    // (nieobserwowane dla 0x3c; symetria rodziny 012x), pozytywny -> brak.
    let g4: u8 = if guard_code == 0xf8 {
        0xfa
    } else if (guard_code & 0x07) == 0x03 {
        guard_code
    } else {
        return None;
    };
    if clean(toks[3]) != "URZ" || clean(toks[4]) != "0x3c" || clean(toks[5]) != "!UPT" {
        return None;
    }
    // imm-formy poza klasa (348 w l2): a/b musza byc czystymi UR<n>.
    let rd: u32 = clean(toks[0]).strip_prefix("UR")?.parse().ok()?;
    let ra: u32 = clean(toks[1]).strip_prefix("UR")?.parse().ok()?;
    let rb: u32 = clean(toks[2]).strip_prefix("UR")?.parse().ok()?;
    if rd > 0x3ff || ra > 0x3ff || rb > 0x3ff {
        return None;
    }
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x29;
    r[2] = 0x10;
    r[3] = 0x04;
    r[4] = g4;
    r[6] = 0x04;
    r[8] = 0x01;
    r[9] = 0xf8;
    r[10..12].copy_from_slice(&(((rd << 6) | 1) as u16).to_le_bytes());
    r[12..14].copy_from_slice(&((ra << 6) as u16).to_le_bytes());
    r[14..16].copy_from_slice(&((rb << 6) as u16).to_le_bytes());
    Some(r)
}

/// mk72: rozpoznanie lane'a xor-mieszanego R/R/UR (`LOP3.LUT Rd, Ra, URb, RZ,
/// 0x3c, !PT`) -> rekord 01 29 08 04 (16B, layout jak 0129-R / rec_xor_reg
/// z b2=0x08; b4=0xf8 stale — wszystkie 271 lane'ow korpusowych niegarded,
/// formy guarded nieobserwowane -> fail-closed). dst@[10..12]=(d<<6)|1,
/// srcA@[12..14]=a<<6, srcB@[14..16]=b<<6. Korpus l2: 271/271 EXACT
/// licznikowo (liczba rekordow == liczba kandydatow per kernel, zero
/// wyjatkow) i payloadowo (k-ty rekord <-> k-ty kandydat, naglowek staly
/// 01 29 08 04 f8 00 04 00 01 f8 — merclab/mk72 c11/c12). Pozostale formy
/// xor poza klasa: (R,R,R)->01290004 mk13, (R,R,imm)->kanal imm mk13,
/// (UR,UR,UR)->01291004 mk71, guarded/brak pina/inne litery -> brak.
pub fn merc_lop3_xor_ur_record(text: &str, guard_code: u8) -> Option<[u8; 16]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("LOP3.LUT") {
        return None;
    }
    let rest = body["LOP3.LUT".len()..].trim();
    let toks: Vec<&str> = rest.split(',').collect();
    // jedyna forma korpusowa: 6 tok = Rd,Ra,URb,RZ,0x3c,!PT.
    if toks.len() != 6 {
        return None;
    }
    fn clean(s: &str) -> &str {
        let t = s.trim();
        let t = t.strip_suffix(';').map(str::trim_end).unwrap_or(t);
        t.strip_suffix(".reuse").unwrap_or(t)
    }
    // korpusowo wylacznie brak guarda (b4=0xf8); pozostale kody -> fail-closed.
    if guard_code != 0xf8 {
        return None;
    }
    if clean(toks[3]) != "RZ" || clean(toks[4]) != "0x3c" || clean(toks[5]) != "!PT" {
        return None;
    }
    let rd: u32 = clean(toks[0]).strip_prefix('R')?.parse().ok()?;
    let ra: u32 = clean(toks[1]).strip_prefix('R')?.parse().ok()?;
    let rb: u32 = clean(toks[2]).strip_prefix("UR")?.parse().ok()?;
    if rd > 0x3ff || ra > 0x3ff || rb > 0x3ff {
        return None;
    }
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x29;
    r[2] = 0x08;
    r[3] = 0x04;
    r[4] = 0xf8;
    r[6] = 0x04;
    r[8] = 0x01;
    r[9] = 0xf8;
    r[10..12].copy_from_slice(&(((rd << 6) | 1) as u16).to_le_bytes());
    r[12..14].copy_from_slice(&((ra << 6) as u16).to_le_bytes());
    r[14..16].copy_from_slice(&((rb << 6) as u16).to_le_bytes());
    Some(r)
}

/// mk58: rekord 01 2b 08 0a (16B) = per-lane "ULOP3 NOT-MOV" — uniformna
/// siostra mk47. Host = lane `ULOP3.LUT URd, URZ, URs, URZ, 0x33, !UPT`
/// (+opc. guard @!UPn). Korpus sm_100 (676 plikow, 18932 kerneli): multiset
/// (guard,URd,URs) EXACT 975/975 kerneli z rekordami (1630 rekordow) +
/// bramka odwrotna 0 kerneli z lane-wzorcem bez rekordu (merclab/mk58 c3/c4).
/// Payload: [4]=guard (0xfa brak — bit |2 wzgledem mk47; @!UPn -> (n<<3)|3;
/// pozytywny @UPn nie wystepuje korpusowo -> fail-closed), [6]=04,
/// [10]=01, [11]=f8, (b12,b13)=LE16((URd<<6)|1), (b14,b15)=LE16(URs<<6).
/// Lane hosta bez bitu bitmapy (675 bit=0 / 134 bit=1, ogony = misalign
/// big-kerneli jak mk44/47; doktryna 'rekord zastepuje wezel t4').
pub fn merc_ulop3_not_record(text: &str, guard_code: u8) -> Option<[u8; 16]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("ULOP3.LUT") {
        return None;
    }
    let rest = body["ULOP3.LUT".len()..].trim();
    let toks: Vec<&str> = rest.split(',').collect();
    if toks.len() < 6 {
        return None;
    }
    fn clean(s: &str) -> &str {
        let t = s.trim();
        let t = t.strip_suffix(';').map(str::trim_end).unwrap_or(t);
        t.strip_suffix(".reuse").unwrap_or(t)
    }
    // guard: brak/@UPT -> 0xfa (uniformna wersja 0xf8); korpusowo tylko
    // zanegowane @!UPn ((n<<3)|3). Pozytywny @UPn / P-space -> brak rekordu.
    let g4: u8 = if guard_code == 0xf8 {
        0xfa
    } else if (guard_code & 0x07) == 0x03 {
        guard_code
    } else {
        return None;
    };
    let rd_tok = clean(toks[0]);
    if clean(toks[1]) != "URZ" || clean(toks[3]) != "URZ" {
        return None;
    }
    if clean(toks[4]) != "0x33" || clean(toks[5]) != "!UPT" {
        return None;
    }
    let rd: u32 = rd_tok.strip_prefix("UR")?.parse().ok()?;
    if rd > 0x3ff {
        return None;
    }
    let rs: u32 = clean(toks[2]).strip_prefix("UR")?.parse().ok()?;
    if rs > 0x3ff {
        return None;
    }
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x2b;
    r[2] = 0x08;
    r[3] = 0x0a;
    r[4] = g4;
    r[6] = 0x04;
    r[10] = 0x01;
    r[11] = 0xf8;
    let dv = (rd << 6) | 1;
    r[12] = (dv & 0xff) as u8;
    r[13] = (dv >> 8) as u8;
    let sv = rs << 6;
    r[14] = (sv & 0xff) as u8;
    r[15] = (sv >> 8) as u8;
    Some(r)
}

/// mk46: rozpoznanie lane'a-geometrycznego (rodzina rekordow 01 0b 06 0a,
/// 16B). Host = lane S2UR ze specjalnym SR geometrii (rola == id sysreg:
/// SR_CTAID.X/Y/Z -> 4/5/6, SR_CgaCtaId -> 0x2c, SR_SWINHI -> 0x2d; klasa
/// b13=2) ALBO lane LDCU .32 ladowania stalej drivera z okna c[0x0][off]
/// (0x360->1, 0x364->2, 0x368->3, 0x370->4, 0x374->5, 0x378->6; rzadkie
/// 0x2f8->68 / 0x2fc->69; klasa b13=4). Korpus sm_100 (676 plikow,
/// 18932 kerneli): multiset (klasa,rola,dst) EXACT 17674/17674 kerneli
/// z rekordami, porzadek strumienia == porzadek lane (17674/17674).
/// Zwraca (dstUR, rola-b12, klasa-b13) albo None.
pub fn merc_geo_anchor(text: &str, base: &str, full: &str) -> Option<(u32, u8, u8)> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    let parse_ur = |s: &str| -> Option<u32> {
        let d = s.trim().trim_end_matches(';').trim();
        d.strip_prefix("UR")?.parse::<u32>().ok()
    };
    if base == "S2UR" {
        let rest = body.strip_prefix("S2UR")?.trim_start();
        let mut it = rest.split(',');
        let dst = parse_ur(it.next()?)?;
        let sr = it.next().unwrap_or("").trim().trim_end_matches(';').trim();
        let role = match sr {
            "SR_CTAID.X" => 4u8,
            "SR_CTAID.Y" => 5,
            "SR_CTAID.Z" => 6,
            "SR_CgaCtaId" => 0x2c,
            "SR_SWINHI" => 0x2d,
            _ => return None,
        };
        return Some((dst.min(1023), role, 2));
    }
    if base == "LDCU" {
        if full.contains(".64") {
            return None;
        }
        let rest = body.strip_prefix("LDCU")?.trim_start();
        let mut it = rest.split(',');
        let dst = parse_ur(it.next()?)?;
        let src = it.next().unwrap_or("");
        let off = (|| {
            let mut k = src.find("c[0x0][")? + 7;
            if src[k..].starts_with("0x") {
                k += 2;
            }
            let h: String = src[k..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            u32::from_str_radix(&h, 16).ok()
        })()?;
        let role = match off {
            0x360 => 1u8,
            0x364 => 2,
            0x368 => 3,
            0x370 => 4,
            0x374 => 5,
            0x378 => 6,
            0x2f8 => 68,
            0x2fc => 69,
            _ => return None,
        };
        return Some((dst.min(1023), role, 4));
    }
    None
}

/// mk46: payload rekordu 01 0b 06 0a: b4 = guard_code|0x02 (0xf8->0xfa PT;
/// korpus: 89391/89401 fa, guarded np. @!P0 -> 0x03, @UP2 -> 0x12), b6 = 4,
/// (b10,b11) = LE16((dstUR<<6)|1), b12 = rola, b13 = klasa; reszta zer.
pub fn merc_geo_record(dst: u32, role: u8, cls: u8, guard_code: u8) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x0b;
    r[2] = 0x06;
    r[3] = 0x0a;
    r[4] = guard_code | 0x02;
    r[6] = 0x04;
    let v = (dst.min(1023) << 6) | 1;
    r[10] = (v & 0xff) as u8;
    r[11] = (v >> 8) as u8;
    r[12] = role;
    r[13] = cls;
    r
}

/// 02 23 28 26 (32B): rekord UBLKCP.S.G. Pola zaleza od puli deskryptorow /
/// rejestrow; ZMEASURED const dla ukladu b_bulk_cp/bulk1 (src-pool UR-desc z
/// LDCU.64 parametru, dst UR pair, size UR). bulk2 pokazuje odmienne pola —
/// pelny dekod: OTWARTE (mk30b-next).
pub const MERC_UBLKCP: [u8; 32] = [
    0x02, 0x23, 0x28, 0x26, 0xfa, 0x00, 0x40, 0x01,
    0x02, 0x01, 0x00, 0x00, 0x80, 0x01, 0xc0, 0x01,
    0x00, 0x82, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// mk14.3: skan LDGSTS/cp.async po tekscie SASS: zwraca
/// (pin=(lane,dst,src) rekordu pinned 5102+02233034, wait=lane 0123400a).
/// - pin host = pierwszy killpad `@!PT LDS RZ, [RZ]` (iadla LDGSTS; 3/3 m15).
/// - wait host = ostatnia instrukcja ze slotem przed pierwszym DEPBAR(.LE)
///   po ostatnim LDGSTS (pomijamy klasy bez slotu: W0-lista).
/// Brak LDGSTS albo brak killpada => None (nie emitujemy blobu).
pub fn merc_ldgsts_scan(lines: &[(u32, String)]) -> (Option<(u32, u8, u8)>, Option<(u32, u8)>) {
    let reg_of = |t: &str| -> u8 {
        let t = t.trim().trim_end_matches([';', ')', ']']);
        if t == "RZ" || t == "URZ" {
            return 255;
        }
        let d = t.trim_start_matches(['R', 'U']);
        if !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()) {
            d.parse::<u32>().ok().map(|v| v.min(255) as u8).unwrap_or(255)
        } else {
            255
        }
    };
    let norm = |t: &str| -> String {
        let mut x = t.trim().to_string();
        while x.starts_with('@') {
            x = match x.split_once(' ') {
                Some((_, r)) => r.trim().to_string(),
                None => return x,
            };
        }
        x
    };
    let base_of = |t: &str| -> String {
        norm(t).split_whitespace().next().unwrap_or("").to_string()
    };
    let mut ldgsts: Option<(u32, u8, u8)> = None;
    let mut killpads: Vec<u32> = Vec::new();
    let mut dep_bar: Option<(u32, u8)> = None; // (lane, imm)
    let mut last_ldgsts_lane = 0u32;
    for (lane, text) in lines {
        let b = base_of(text);
        let bb = b.split('.').next().unwrap_or("");
        if bb == "LDGSTS" {
            // LDGSTS.E [R7], desc[UR6][R4.64]
            let tx = text.replace(';', "");
            let parts: Vec<&str> = tx.split(',').map(|x| x.trim()).collect();
            let mut dst = 255u8;
            let mut src = 255u8;
            if let Some(first) = parts.first() {
                if let Some(o) = first.rfind('[') {
                    let inner = &first[o + 1..];
                    let end = inner.find(']').unwrap_or(inner.len());
                    dst = reg_of(inner[..end].split('.').next().unwrap_or(""));
                }
                if parts.len() >= 2 {
                    let ap = parts[1];
                    if let Some(o) = ap.rfind('[') {
                        let inner = &ap[o + 1..];
                        let end = inner.find(']').unwrap_or(inner.len());
                        src = reg_of(inner[..end].split('.').next().unwrap_or(""));
                    }
                }
            }
            ldgsts = Some((*lane, dst, src));
            last_ldgsts_lane = *lane;
        } else if bb == "LDS" {
            let n = norm(text);
            if n == "LDS RZ, [RZ]" {
                killpads.push(*lane);
            }
        } else if bb == "DEPBAR" && ldgsts.is_some() && *lane > last_ldgsts_lane && dep_bar.is_none() {
            // mk55: legacy wait wybiera pierwszy DEPBAR klasy SB0 po ostatnim
            // LDGSTS (SB5 rekordu nie nosi; korpus mk55 c5: no-blob kernele
            // to dokladnie (1 wait, 1 SB0-DEPBAR)); imm w b11 rekordu.
            let n2 = norm(text);
            let imm_sb0 = n2.split_once(char::is_whitespace).and_then(|(_, rest)| {
                let mut o = rest.trim().trim_end_matches(';').split(',').map(|s| s.trim());
                if o.next()? != "SB0" {
                    return None;
                }
                let im = o.next()?;
                im.strip_prefix("0x")
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| im.parse::<u32>().ok())
                    .map(|v| v.min(255) as u8)
            });
            if let Some(imm) = imm_sb0 {
                dep_bar = Some((*lane, imm));
            }
        }
    }
    let pin = match (ldgsts, killpads.first()) {
        (Some((_, d, s)), Some(&kpl)) => Some((kpl, d, s)),
        _ => None,
    };
    let wait = dep_bar.and_then(|(dl, dimm)| {
        lines
            .iter()
            .rev()
            .filter(|(l, _)| *l < dl)
            .find(|(_, t)| {
                let b = base_of(t);
                !opcode_bitmap_zero_weight(&b)
            })
            .map(|(l, _)| (*l, dimm))
    });
    (pin.filter(|_| ldgsts.is_some()), wait)
}

/// mk14: klasa rekordu atomowego 02 4d/02 4e.
pub const MERC_ATOM_CLS_RED: u8 = 0;   // REDG/RED (fire-and-forget) -> 024d (legacy)
pub const MERC_ATOM_CLS_G4: u8 = 1;    // ATOMG.E.<op> 4B global -> 024e5232
pub const MERC_ATOM_CLS_CAS: u8 = 2;   // ATOMG.E.CAS.* -> 024e2432 (2 data regs)
pub const MERC_ATOM_CLS_SHARED: u8 = 3;// ATOMS.<op> -> 024e8432
pub const MERC_ATOM_CLS_REDG_D: u8 = 4; // REDG.E.<op>.STRONG.<sc> desc[UR][R.64] -> 024d2432

fn merc_put16(b: &mut [u8; 32], off: usize, v: u16) {
    b[off] = (v & 0xff) as u8;
    b[off + 1] = (v >> 8) as u8;
}

/// Siatka rejestru jak w 0229/02 38: (r<<6)|flagi; RZ formy specjalne.
fn merc_grid1(r: u8) -> u16 { if r == 255 { 0xffc1 } else { ((r as u16) << 6) | 1 } }

/// === mk53: pelny silnik rekordow 02 23 {b2} 34 (LDGSTS pinned blobs) ===
/// Korpus (merclab/mk53 c1..c37, 677/744 kerneli byte-exact "clean"):
/// - jeden blob 32B na kazdy lane `LDGSTS... [R..(+imm)], desc[URm][Rs.64..]`
///   (forma z deskryptorem; [UR]-dst i non-desc bez rekordow);
/// - rekord bajtowo: 02 23 30 34 | b4=guard (PT->f8, @Pn->n<<3, @!Pn->n<<3|1)
///   b6=0x20 gdy BYPASS inaczej 0x24; b7=0x10; b8=widthE(.64=0x08,.128=0x10)
///   |0x02 gdy LTC128B; b9=01; b12/13=LE16(dstbase<<6); b14/15=0a 01; b16=00;
///   b17/18=LE16((srcreg<<6)|2); b19=09; b20=00; b21/b22=const per kernel
///   (domkniete tylko dla 1-blob kerneli: 0x82/0x01; mk54 sweep); b23=00;
///   b24 = notify-pred<<3 (3. operand P#; brak -> 0xf8; zanegowany: bez neg);
///   b25..27=00 (u16@26 parked: wartosci 04/08/... czesciowo; mk54);
///   u32@28 = imm smem-dst RAW.
/// - marker 51 02 (2B) przed blobem k-tego lane'a gdy miedzy poprzednim
///   blob-lane'em a tym stoi run killpadow `@!PT LDS RZ,[RZ]` (host pinu =
///   pierwszy killpad runu; mk14.3 domknieto to dla 1-grupowych kerneli).
/// - era cutlass_80 (libcublas sm_100 v1070/Lt-548): tag 02 23 34 34 dla
///   form z LTC128B (zamiast 30 34); 02 23 3a 34 pozostaje parked (mk54).
#[derive(Debug, Clone)]
pub struct Ldgsts2Blob {
    pub lane: u32,
    pub pin: bool,
    pub pin_host: Option<u32>,
    /// imm strony src (desc[URm][Rs.64+0ximm]) — u16@26-27 RAW (K1: 0x40).
    pub simm: u32,
    pub guard: u8,
    pub b6: u8,
    pub b8: u8,
    pub tag3434: bool,
    pub dreg: u32,
    pub dimm: u32,
    pub sreg: Option<u32>,
    pub npred: Option<u8>,
}

/// Parsuje lane SASS LDGSTS -> Some(blob) gdy forma z desc[UR..] i R-dst.
/// Skadnia: [@!Pn] LDGSTS.<warianty> [Rd(+0ximm)(..)], desc[URm][Rs.64(+..)](, Pn)?
pub fn ldgsts2_parse_mode(
    text: &str,
    nodesc: bool,
) -> Option<(u8, u8, u8, u32, u32, Option<u32>, Option<u8>, u32)> {
    let mut t = text.trim_end_matches(';').trim();
    let mut guard = 0xf8u8;
    if let Some(rest) = t.strip_prefix('@') {
        let mut sp = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let g = &rest[..sp];
        sp = sp.min(rest.len());
        let p = g.trim_start_matches('!');
        let neg = g.starts_with('!') as u8;
        if let Some(num) = p.strip_prefix('P').and_then(|d| d.parse::<u8>().ok()) {
            guard = (num << 3) | neg;
        } else if p != "PT" {
            return None; // @UPn / inne: fail-closed
        }
        t = rest[sp..].trim_start();
    }
    if !t.starts_with("LDGSTS") {
        return None;
    }
    let opend = t.find(char::is_whitespace).unwrap_or(t.len());
    let opfull = &t[..opend];
    if !t.contains("desc[UR") && !nodesc {
        return None;
    }
    // dst: pierwszy nawias kwadratowy z R (nie UR).
    let b0 = t.find('[')?;
    let b1 = t[b0..].find(']').map(|i| b0 + i)?;
    let dst_inner = &t[b0 + 1..b1];
    if !dst_inner.starts_with('R') {
        return None; // [UR..]/inne: brak rekordu (korpus mk53)
    }
    let dreg_str = dst_inner.strip_prefix('R')?;
    let dreg_digits: String = dreg_str.chars().take_while(|c| c.is_ascii_digit()).collect();
    let dreg: u32 = dreg_digits.parse().ok()?;
    let dimm: u32 = (|| {
        let plus = dst_inner.find("+0x")?;
        let raw: String = dst_inner[plus + 3..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        u32::from_str_radix(&raw, 16).ok()
    })()
    .unwrap_or(0);
    // src: po desc[URm] albo (nodesc) od razu drugi nawias [Rs.64..].
    let b2s = if let Some(desc_pos) = t.find("desc[UR") {
        t[desc_pos + 6..].find('[').map(|i| desc_pos + 6 + i)?
    } else {
        t[b1 + 1..].find('[').map(|i| b1 + 1 + i)?
    };
    let b2e = t[b2s..].find(']').map(|i| b2s + i)?;
    let src_inner = &t[b2s + 1..b2e];
    let s_digits: String = src_inner
        .strip_prefix('R')?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let sreg: Option<u32> = s_digits.parse().ok();
    let simm: u32 = (|| {
        let plus = src_inner.find("+0x")?;
        let raw: String = src_inner[plus + 3..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        u32::from_str_radix(&raw, 16).ok()
    })()
    .unwrap_or(0);
    // notify-pred: ostatni token po przecinku to (!)P<cyfra>.
    let npred = t.rsplit(',').find_map(|tk| {
        let tk = tk.trim();
        let tk = tk.strip_prefix('!').unwrap_or(tk);
        let d = tk.strip_prefix('P')?;
        d.parse::<u8>().ok()
    });
    let b6: u8 = if opfull.contains("BYPASS") { 0x20 } else { 0x24 };
    let mut b8: u8 = 0;
    if opfull.contains("LTC128B") {
        b8 |= 0x02;
    }
    if opfull.contains(".64") {
        b8 |= 0x08;
    }
    if opfull.contains(".128") {
        b8 |= 0x10;
    }
    Some((guard, b6, b8, dreg, dimm, sreg, npred, simm))
}

/// Kompat dla testow: tryb desc.
#[allow(dead_code)]
pub fn ldgsts2_parse(text: &str) -> Option<(u8, u8, u8, u32, u32, Option<u32>, Option<u8>, u32)> {
    ldgsts2_parse_mode(text, false)
}

/// Czy tekst to killpad `@!PT LDS RZ, [RZ]` (dowolny guard tolerate).
pub fn is_ldgsts_killpad(text: &str) -> bool {
    let mut t = text.trim_end_matches(';').trim();
    while let Some(rest) = t.strip_prefix('@') {
        let sp = rest.find(char::is_whitespace).map(|i| i + 1).unwrap_or(rest.len());
        t = rest[sp..].trim_start();
    }
    t.replace(' ', "") == "LDSRZ,[RZ]"
}

/// Pelny skan: blob per lane + pin wg runu killpadow od poprzedniego blobu.
pub fn merc_ldgsts2_scan(lines: &[(u32, String)], kern_name: &str) -> Vec<Ldgsts2Blob> {
    let mut out: Vec<Ldgsts2Blob> = Vec::new();
    let mut kill_run: Vec<u32> = Vec::new();
    let era74 = kern_name.contains("cutlass_80");
    for (lane, text) in lines {
        if is_ldgsts_killpad(text) {
            kill_run.push(*lane);
            continue;
        }
        let base = text
            .trim_end_matches(';')
            .trim()
            .strip_prefix('@')
            .map(|r| {
                let sp = r.find(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
                r[sp..].trim_start()
            })
            .unwrap_or_else(|| text.trim());
        if !base.starts_with("LDGSTS") {
            if !kill_run.is_empty() && !base.starts_with("LDS ") {
                kill_run.clear();
            }
            continue;
        }
        let Some((guard, b6, b8, dreg, dimm, sreg, npred, simm)) = ldgsts2_parse_mode(
            text,
            era74 && text.contains("LTC128B"),
        ) else {
            kill_run.clear();
            continue;
        };
        let pin = !kill_run.is_empty();
        out.push(Ldgsts2Blob {
            lane: *lane,
            pin,
            pin_host: if pin { Some(kill_run[0]) } else { None },
            simm,
            guard,
            b6,
            b8,
            tag3434: era74 && b8 & 0x02 != 0,
            dreg,
            dimm,
            sreg,
            npred,
        });
        kill_run.clear();
    }
    out
}

/// mk55: wait-event 01 23 40 0a (16B) per `DEPBAR.* SB0, 0xN` (b11 = imm N).
/// Regula korpusowa mk55 c2/c3 (2619/2619 rekordow, 1250/1250 kerneli EXACT
/// multiset+porzadek, 0 FP/FN): rekord dostaje WYLACZNIE klasa SB0 (DEPBAR
/// SB5 go nie ma — stad "przepiekla" proba per-DEPBAR z mk53 robila +208
/// new-only), guardowany DEPBAR: fail-closed (korpus: brak; b4=f8 zawsze).
/// host = ostatnia instrukcja ze slotem przed DEPBARem (DEPBAR jest
/// zero-weight; mk14.3); bity bitmapy waity NIE gryza (mk55 c8/c9: mix
/// bit=0/1 na hostach, decyduje zwykly model bitmapy — feat_host_zero
/// zostawiony na legacy-host jak mk53/54).
pub fn merc_ldgsts2_waits(lines: &[(u32, String)]) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    // norm: bez guarda i bez ';'; base_of: sam mnemonic bez guarda.
    let norm = |t: &str| -> String {
        let mut x = t.trim().to_string();
        while x.starts_with('@') {
            x = match x.split_once(' ') {
                Some((_, r)) => r.trim().to_string(),
                None => return x,
            };
        }
        x.trim().trim_end_matches(';').trim().to_string()
    };
    let base_of = |t: &str| -> String {
        norm(t).split_whitespace().next().unwrap_or("").to_string()
    };
    // (op0=="SB0", imm) z "DEPBAR.LE SB0, 0xN"; None gdy forma niestandardowa.
    let sb0_imm = |t: &str| -> Option<u8> {
        let n = norm(t);
        let (_op, rest) = n.split_once(char::is_whitespace)?;
        let mut ops = rest.split(',').map(|s| s.trim());
        if ops.next()? != "SB0" {
            return None;
        }
        let im = ops.next()?;
        let v = im
            .strip_prefix("0x")
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .or_else(|| im.parse::<u32>().ok())?;
        Some(v.min(255) as u8)
    };
    for (lane, text) in lines {
        let b = base_of(text);
        let bb = b.split('.').next().unwrap_or("");
        if bb != "DEPBAR" {
            continue;
        }
        if text.trim_start().starts_with('@') {
            continue; // fail-closed: guardowany DEPBAR (brak w korpusie)
        }
        // 1. operand musi byc SB0 (SB5 wait-rekordu nie nosi — mk55 c2).
        let imm = match sb0_imm(text) {
            Some(v) => v,
            None => continue, // fail-closed: SB5 / forma niestandardowa
        };
        let host = lines
            .iter()
            .rev()
            .filter(|(l, _)| *l < *lane)
            .find(|(_, t)| {
                let b2 = base_of(t);
                !opcode_bitmap_zero_weight(&b2)
            })
            .map(|(l, _)| *l);
        if let Some(h) = host {
            out.push((h, imm));
        }
    }
    out
}

/// 16B wait: b4=f8, b6=08, b11=imm.
pub fn build_ldgsts2_wait(imm: u8) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[0] = 0x01;
    r[1] = 0x23;
    r[2] = 0x40;
    r[3] = 0x0a;
    r[4] = 0xf8;
    r[6] = 0x08;
    r[11] = imm;
    r
}

/// Blob 32B (bez markera). single = kernel ma dokladnie 1 blob (gold m15:
/// b21=0x82, b22=0x01; multi-blob domknije mk54 sweep, na razie modal).
pub fn build_ldgsts2_blob(x: &Ldgsts2Blob, single: bool) -> [u8; 32] {
    let mut r = [0u8; 32];
    let tag: [u8; 4] = if x.tag3434 {
        [0x02, 0x23, 0x34, 0x34]
    } else {
        [0x02, 0x23, 0x30, 0x34]
    };
    r[..4].copy_from_slice(&tag);
    r[4] = x.guard;
    r[6] = x.b6;
    r[7] = 0x10;
    r[8] = x.b8;
    r[9] = 0x01;
    let v = (x.dreg.min(0x3ff) as u16) << 6;
    r[12] = (v & 0xff) as u8;
    r[13] = (v >> 8) as u8;
    r[14] = 0x0a;
    r[15] = 0x01;
    if let Some(s) = x.sreg {
        let s16 = ((s.min(0x3ff) as u16) << 6) | 2;
        r[17] = (s16 & 0xff) as u8;
        r[18] = (s16 >> 8) as u8;
    }
    r[19] = 0x09;
    r[21] = if single { 0x82 } else { 0x02 };
    r[26] = (x.simm & 0xff) as u8;
    r[27] = (x.simm >> 8) as u8;
    r[22] = if single { 0x01 } else { 0x03 };
    r[24] = x.npred.map(|p| p << 3).unwrap_or(0xf8);
    r[28..32].copy_from_slice(&x.dimm.to_le_bytes());
    r
}

fn merc_grid0(r: u8) -> u16 { if r == 255 { 0xffc0 } else { (r as u16) << 6 } }

/// mk14: rekordy atomowe z rejestrami (dekod mk14/atommodel.py)
/// istotnych zgodnych): guard_b4 = 0xf8 brak / 0x00 @Pn / 0x01 @!Pn.
/// G4: [6]=subop (EXCH=0x80), dst@[14..16) grid1, addr@[17..19)=(a<<6)|2,
/// value@[23..25) grid0. CAS: cmp@[21], swp@[23]. SHARED: dst@[12..14),
/// [14..16)=0xffc0 stale, value@[21..23).
/// mk48: rekordy REDG 02 4d {b2} 32 (32B) — DOMKNIECIE swapu 024d0e32<->024d2432.
///
/// Hosty (korpus sm_100, 676 plikow; parowanie po (addr,descUR,data,imm)
/// multiset==lane-set; pelna zgodnosc bajtowa 22342/22342 rekordow,
/// 1322/1335 kerneli, reszta = forma non-desc S32 tez obsluzona):
///
///   REDG.E.<OP>[.<typ>][.FTZ][.RN].STRONG.<scope> desc[URn][Rm.64(+0xIMM)], Rv
///   REDG.E.<OP>.<typ>.STRONG.<scope> [Rn], Rv            (forma non-desc)
///
/// Tabela bajtow klasy:
///   float ADD:   b2=0x0e b6=0x80; F32 -> b7=0x44, F64 -> b7=0x47; b8=0x03
///   int desc:    b2=0x24 b8=0x01;  b6 = drabina op (ADD 00, MIN 10, MAX 20,
///                AND 50, OR 60);   b7 = 0xa0 | kod-typu (.S32 -> 2, .64 -> 3)
///   int non-desc: b2=0x2e (korpus: wylacznie ADD.S32 w cublasLt.548)
/// Sloty: [12:14)=(areg<<6)|2; b14=0x0a;
///   desc:     [17:19)=(descUR<<6)|2, [19:21)=(data<<6)|dflag
///   non-desc: [17:19)=(data<<6)|dflag, [19:21)=0
///   dflag=1<<1 gdy dane 64-bit (F64 / .64), inaczej 0.
///   [28:32) = imm adresu (i32 LE, np. "-0x8" -> f8ffffff); reszta bajtow 0.
/// b4 = guard_code (drabina mk41: idx<<3|neg / UPn<<3|2 / 0xf8).
/// Bitmapa bez zmian (lane atomowy nigdy nie tracil bitu — doktryna mk14).
pub fn merc_redg_record(text: &str, guard_code: u8) -> Option<[u8; 32]> {
    let body0 = text.trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("REDG.") {
        return None;
    }
    let (opstr, ops0) = body.split_once(char::is_whitespace)?;
    let ops = ops0.trim().trim_end_matches(';');
    let f32v = opstr.contains(".F32");
    let f64v = opstr.contains(".F64");
    let (b2_int, b6, b7, b8) = if f32v {
        (0x0e_u8, 0x80_u8, 0x44_u8, 0x03_u8)
    } else if f64v {
        (0x0e_u8, 0x80_u8, 0x47_u8, 0x03_u8)
    } else {
        let sub: u8 = if opstr.contains(".MIN") {
            0x10
        } else if opstr.contains(".MAX") {
            0x20
        } else if opstr.contains(".AND") {
            0x50
        } else if opstr.contains(".OR") {
            0x60
        } else {
            0x00
        };
        let tcode: u8 = if opstr.contains(".64") {
            3
        } else if opstr.contains(".S32") {
            2
        } else {
            0
        };
        (0x24_u8, sub, 0xa0_u8 | tcode, 0x01_u8)
    };
    let dflag: u16 = if f64v || opstr.contains(".64") { 2 } else { 0 };
    let regnum = |tok: &str| -> Option<u32> {
        tok.strip_prefix('R')?.parse::<u32>().ok().filter(|v| *v < 0x4000)
    };
    // adres: desc[URn][Rm.64(+/-0ximm)] albo [Rn] (non-desc)
    let (areg, descur, data, imm, is_desc): (u32, Option<u32>, u32, i32, bool) =
        if let Some(dp) = ops.find("desc[UR") {
            let rest = &ops[dp + 7..];
            let end = rest.find(']')?;
            let d: u32 = rest[..end].parse().ok()?;
            let bp = rest[end..].find('[').map(|p| p + end)?;
            let bend = rest[bp..].find(']').map(|e| e + bp)?;
            let inner = &rest[bp + 1..bend]; // "R18.64+0x4" / "R10.64+-0x8"
            let a: u32 = regnum(inner.split('.').next()?)?;
            let imm: i32 = match inner.find("0x") {
                Some(h) => {
                    let hexs: String = inner[h + 2..]
                        .chars()
                        .take_while(|c| c.is_ascii_hexdigit())
                        .collect();
                    let v = i32::from_str_radix(&hexs, 16).ok()?;
                    if inner[..h].contains('-') { -v } else { v }
                }
                None => 0,
            };
            // data = ostatni operand po przecinku top-level
            let dtok = ops.rsplit(',').next()?.trim();
            let dv = regnum(dtok)?;
            (a, Some(d), dv, imm, true)
        } else if ops.starts_with('[') {
            let bend = ops.find(']')?;
            let inner = &ops[1..bend];
            if !inner.is_empty() && inner.starts_with('R')
                && inner[1..].chars().all(|c| c.is_ascii_digit())
            {
                let a = regnum(inner)?;
                let dtok = ops[bend + 1..].trim_start_matches(',').trim();
                let dv = regnum(dtok)?;
                (a, None, dv, 0, false)
            } else {
                return None;
            }
        } else {
            return None;
        };
    if f32v || f64v {
        if !is_desc {
            return None; // float non-desc: forma nieobserwowana
        }
    }
    let b2: u8 = if f32v || f64v {
        0x0e
    } else if is_desc {
        b2_int
    } else {
        0x2e
    };
    let mut b = [0u8; 32];
    b[0] = 0x02;
    b[1] = 0x4d;
    b[2] = b2;
    b[3] = 0x32;
    b[4] = guard_code;
    b[6] = b6;
    b[7] = b7;
    b[8] = b8;
    let put = |b: &mut [u8; 32], off: usize, v: u16| {
        b[off] = (v & 0xff) as u8;
        b[off + 1] = (v >> 8) as u8;
    };
    put(&mut b, 12, ((areg as u16) << 6) | 2);
    b[14] = 0x0a;
    match descur {
        Some(d) => {
            put(&mut b, 17, ((d as u16) << 6) | 2);
            put(&mut b, 19, ((data as u16) << 6) | dflag);
        }
        None => {
            put(&mut b, 17, ((data as u16) << 6) | dflag);
        }
    }
    b[28..32].copy_from_slice(&imm.to_le_bytes());
    Some(b)
}

/// mk49: rekordy 02 4e {b2} 32 (32B) — rodzina ATOM.E/ATOMG/ATOMS (korpus
/// sm_100, 2929 kerneli; byte-exact 11898/11898, porzadek strumienia lane-asc
/// 2929/2929; lab merclab/mk49). Zastepuje mk14-tuple dla nowych klas.
///
/// Wspolne: b0=02 b1=4e b3=32 b4=guard_code (drabina mk41); siatka rejestrow
/// (r<<6)|flag LE16; grid1 = |1, grid0 = |0; RZ/URZ = 255 -> 0xffc1/0xffc0.
/// imm adresu = i32 LE w [28:32). Bitmapa: lane atomowy bez bitu (doktryna
/// mk14/mk30b). CAST.SPIN / ATOM.E.CAS.* sa bezrekordowe (patrz
/// merc_atomg2_recordless).
///
/// Klasy (b2):
///   20  ATOM.E desc float: F16x2->b6=00, BF16x2->18, F32->48, F64->78; b7=34.
///   68  ATOM.E desc int:   ADD -> b6=00; ADD.64 -> 60; MAX.S32 -> 42;
///       MAX.S64 -> a2 (wzor: op<<4 | tmod; tmod S32=2, dane .64 => +0x60|2).
///   30  ATOMG float [Rn(+imm)]: b6=80; b7 F32=44 / F64=47; b8=03.
///   24  ATOMG.E.CAS: b6=00; b7: GPU=68 / SYS=88 / .64 SYS=89; b8=00.
///   52  ATOMG int [Rn]/desc: b6: ADD=00 MIN=10 MAX=20 INC=30 EXCH=80;
///       b7 = 40 | (04 gdy .S32); b8=03. (Ladder mk14 b21/b22: descUR albo
///       powtorzony addr gdy brak desc; wczesniej stal sie to przez gold R4.)
///   82  ATOMS [Rn(+imm)]: tylko ADD w korpusie — b6=04 b7=60 b8=03.
///   84  ATOMS [URn(+imm)]: b6: MIN=14 MAX=24 AND=54 OR=64; b7=.S32?64:60;
///       b8=03. Wariant OR/AND z imm!=0 zostaje przy mk27 AtomSmem (tu None).
///   8a  ATOMS.POPC.INC.32 [Rn+URZ(+imm)]: b6=b4 b7=62 b8=03.
///   (b8=01 zamiast 03 w 82/8a = libcusparse.so.782 sub-driver — parked jak
///    mk41 STL b7-variant.)
///
/// Sloty:
///   20/68: b12=01, b13 = predykat-dst (PT=f8 / Pn=n<<3), [14:16)=grid1(dst)
///          (68 non-RZ: |1|df), [17:19)=(addr<<6)|2, b19=0a,
///          [21:23)=(descUR<<6)|2, [23:25)=(data<<6)|df, [28:32)=imm.
///          df=2 dla 64-bit danych (F64 / int .64|S64); RZ nie dostaje df.
///   30:    jak 20 lecz [21:23)=(data<<6)|df, brak desc.
///   24:    [14:16)=(dst<<6)|(1, lub 3 gdy .64); [17:19)=(addr<<6)|2; b19=0a;
///          [21:23)=(cmp<<6)|(2 gdy .64); [23:25)=(swp<<6)|(2 gdy .64).
///   52:    [12]=01, b13=pred-dst; [14:16)=grid1(dst); [17:19)=(addr<<6)|2;
///          b19=0a; [21:23)=(descUR|addr)<<6|2; [23:25)=grid0(data); imm.
///   82:    [12:14)=grid1(dst); [14:16)=grid0(addr); b17=0a; [19:21)=grid0(val);
///          imm.
///   84:    [12:14)=grid1(dst); [14:16)=ffc0; [17:19)=grid0(UR); b19=0a;
///          [21:23)=grid0(val); imm.
///   8a:    [12:14)=grid1(dst); [14:16)=grid0(addrR); [17:19)=grid0(UR);
///          b19=0a; imm.
pub fn merc_atomg2_record(text: &str, guard_code: u8) -> Option<[u8; 32]> {
    let body0 = text.trim().trim_end_matches(';').trim();
    let body = match body0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(body0),
        None => body0,
    };
    if !body.starts_with("ATOM") || merc_atomg2_recordless(body) {
        return None;
    }
    let pc = |tok: &str| -> Option<u8> {
        let t = tok.trim();
        if t == "PT" {
            return Some(0xf8);
        }
        let d = t.strip_prefix('P')?;
        d.parse::<u8>().ok().filter(|v| *v < 8).map(|v| v << 3)
    };
    // u16 LE do siatki
    let put = |b: &mut [u8; 32], off: usize, v: u16| {
        b[off] = (v & 0xff) as u8;
        b[off + 1] = (v >> 8) as u8;
    };
    let mut b = [0u8; 32];
    b[0] = 0x02;
    b[1] = 0x4e;
    b[3] = 0x32;
    b[4] = guard_code;

    // ---- parser operandow: rozdziel po przecinkach top-level ----
    // (mnemonik F16/BF16 ma spacje: "ATOM.E.ADD.F16 x2.RN... P4, ...")
    let parts: Vec<&str> = body.split(',').map(|x| x.trim()).collect();
    fn last_word(t: &str) -> &str { t.split_whitespace().last().unwrap_or(t) }
    let reg = |tok: &str| -> Option<u32> {
        match last_word(tok) {
            "RZ" | "URZ" => Some(255),
            w => {
                let d = w.strip_prefix('R')?;
                if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                d.parse::<u32>().ok().filter(|v| *v < 0x4000)
            }
        }
    };
    let uregr = |tok: &str| -> Option<u32> {
        match last_word(tok) {
            "URZ" => Some(255),
            w => {
                let d = w.strip_prefix("UR")?;
                if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                d.parse::<u32>().ok().filter(|v| *v < 0x4000)
            }
        }
    };
    // imm w opisie nawiasu: "+0x400" / "+-0xc" / "+-0x8"
    let imm_of = |inner: &str| -> i32 {
        match inner.find("0x") {
            Some(h) => {
                let hexs: String = inner[h + 2..]
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                let v = i32::from_str_radix(&hexs, 16).unwrap_or(0);
                if inner[..h].contains('-') {
                    -v
                } else {
                    v
                }
            }
            None => 0,
        }
    };

    if body.starts_with("ATOM.E.") {
        // desc[URn][Rm.64(+imm)]
        let dp = body.find("desc[UR")?;
        let rest = &body[dp + 7..];
        let end = rest.find(']')?;
        let descur: u32 = rest[..end].parse().ok()?;
        let bp = rest[end..].find('[').map(|p| p + end)?;
        let bend = rest[bp..].find(']').map(|e| e + bp)?;
        let inner = &rest[bp + 1..bend]; // "R10.64+0x4"
        let addr = reg(inner.split('.').next()?)?;
        let imm = imm_of(inner);
        // dst = ostatni token przed desc[ ; data = token po zamknieciu ']'
        let head = &body[..dp];
        let hparts: Vec<&str> = head.split(',').map(|x| x.trim()).collect();
        if hparts.len() < 2 {
            return None;
        }
        let pdc = pc(last_word(hparts[0]))?;
        let dst = reg(hparts[1])?;
        let data = reg(&rest[bend + 1..].trim_start_matches(',').trim())?;
        // klasa: float vs int
        let (tag2, b6, df): (u8, u8, u16) = if body.contains(".F64") {
            (0x20, 0x78, 2)
        } else if body.contains(".F32") {
            (0x20, 0x48, 0)
        } else if body.contains(".BF16") {
            (0x20, 0x18, 0)
        } else if body.contains(".F16") {
            (0x20, 0x00, 0)
        } else if body.contains(".ADD.64") {
            (0x68, 0x60, 2)
        } else if body.contains(".MAX.S64") {
            (0x68, 0xa2, 2)
        } else if body.contains(".MAX.S32") {
            (0x68, 0x42, 0)
        } else if body.contains(".ADD") {
            (0x68, 0x00, 0)
        } else {
            return None; // MIN/AND/OR/... nieobserwowane w korpusie
        };
        b[2] = tag2;
        b[6] = b6;
        b[7] = 0x34;
        b[12] = 0x01;
        b[13] = pdc;
        let dg = if tag2 == 0x68 && dst != 255 {
            ((dst as u16) << 6) | 1 | df
        } else {
            merc_grid1(dst as u8)
        };
        put(&mut b, 14, dg);
        put(&mut b, 17, ((addr as u16) << 6) | 2);
        b[19] = 0x0a;
        put(&mut b, 21, ((descur as u16) << 6) | 2);
        put(&mut b, 23, ((data as u16) << 6) | df);
        b[28..32].copy_from_slice(&imm.to_le_bytes());
        return Some(b);
    }

    if body.starts_with("ATOMG.") {
        // shift: pierwszy token (po mnemoniku) moze byc predykatem Pn|PT
        let pdw = last_word(parts.get(0)?);
        let (pdc, sh) = match pc(pdw) {
            Some(c) => (c, 1usize),
            None => (0xf8, 0usize),
        };
        if body.contains(".CAS") {
            // [PT,] Rd, [Rn], Rcmp, Rswp
            if parts.len() < sh + 4 {
                return None;
            }
            let w64 = body.contains(".CAS.64");
            let sys = body.contains(".SYS");
            let dst = reg(parts[sh])?;
            let bp = parts[sh + 1].find('[')?;
            let bend = parts[sh + 1].find(']')?;
            let addr = reg(&parts[sh + 1][bp + 1..bend])?;
            let cmp = reg(parts[sh + 2])?;
            let swp = reg(parts[sh + 3])?;
            let wf: u16 = if w64 { 3 } else { 1 };
            b[2] = 0x24;
            b[6] = 0;
            b[7] = if w64 {
                0x89
            } else if sys {
                0x88
            } else {
                0x68
            };
            b[12] = 0x01;
            b[13] = pdc;
            // RZ nie dostaje flagi szerokosci (jak mk49 0x68 / mk40 store2).
            let dg = if dst == 255 {
                merc_grid1(255)
            } else {
                ((dst as u16) << 6) | wf
            };
            put(&mut b, 14, dg);
            put(&mut b, 17, ((addr as u16) << 6) | 2);
            b[19] = 0x0a;
            put(&mut b, 21, ((cmp as u16) << 6) | if w64 { 2 } else { 0 });
            put(&mut b, 23, ((swp as u16) << 6) | if w64 { 2 } else { 0 });
            return Some(b);
        }
        if parts.len() < sh + 3 {
            return None;
        }
        let dst = reg(parts[sh])?;
        let addr_tok = parts[sh + 1];
        let (addr, desc, imm) = if addr_tok.contains("desc[UR") {
            let dp = addr_tok.find("desc[UR")?;
            let rest = &addr_tok[dp + 7..];
            let end = rest.find(']')?;
            let d32: u32 = rest[..end].parse().ok()?;
            let bp2 = rest[end..].find('[').map(|p| p + end)?;
            let bend = rest[bp2..].find(']').map(|e| e + bp2)?;
            let inner = &rest[bp2 + 1..bend];
            (
                reg(inner.split('.').next()?)?,
                Some(d32),
                imm_of(inner),
            )
        } else {
            let bo = addr_tok.find('[')?;
            let bc = addr_tok.find(']')?;
            let inner = &addr_tok[bo + 1..bc];
            (reg(inner.split('+').next()?)?, None, imm_of(inner))
        };
        let data = reg(parts[sh + 2])?;
        if body.contains(".F64") || body.contains(".F32") {
            let f64v = body.contains(".F64");
            b[2] = 0x30;
            b[6] = 0x80;
            b[7] = if f64v { 0x47 } else { 0x44 };
            b[8] = 0x03;
            b[12] = 0x01;
            b[13] = pdc;
            put(&mut b, 14, merc_grid1(dst as u8));
            put(&mut b, 17, ((addr as u16) << 6) | 2);
            b[19] = 0x0a;
            put(&mut b, 21, ((data as u16) << 6) | if f64v { 2 } else { 0 });
            b[28..32].copy_from_slice(&imm.to_le_bytes());
            return Some(b);
        }
        // g52: int
        let mut sub = 0u8;
        for (s, v) in [
            (".MIN", 0x10u8),
            (".MAX", 0x20u8),
            (".INC", 0x30u8),
            (".EXCH", 0x80u8),
        ] {
            if body.contains(s) {
                sub = v;
            }
        }
        b[2] = 0x52;
        b[6] = sub;
        b[7] = 0x40 | if body.contains(".S32") { 4 } else { 0 };
        b[8] = 0x03;
        b[12] = 0x01;
        b[13] = pdc;
        put(&mut b, 14, merc_grid1(dst as u8));
        put(&mut b, 17, ((addr as u16) << 6) | 2);
        b[19] = 0x0a;
        put(&mut b, 21, ((desc.unwrap_or(addr) as u16) << 6) | 2);
        put(&mut b, 23, (data as u16) << 6);
        b[28..32].copy_from_slice(&imm.to_le_bytes());
        return Some(b);
    }

    if body.starts_with("ATOMS.") {
        let ob = body.find('[')?;
        let cb = body.find(']')?;
        let inner = &body[ob + 1..cb];
        let dst = reg(parts.get(0)?)?;
        let val = {
            let after = body[cb + 1..].trim_start_matches(',').trim();
            if after.is_empty() {
                None
            } else {
                reg(after)
            }
        };
        if inner.contains("+URZ") || (inner.contains("+UR") && !inner.starts_with("UR")) {
            // [Rn+URZ(+imm)] -> POPC 8a
            if !body.contains(".POPC") {
                return None;
            }
            let addr = reg(inner.split('+').next()?)?;
            let imm = imm_of(inner);
            b[2] = 0x8a;
            b[6] = 0xb4;
            b[7] = 0x62;
            b[8] = 0x03;
            put(&mut b, 12, merc_grid1(dst as u8));
            put(&mut b, 14, (addr as u16) << 6);
            put(&mut b, 17, merc_grid0(255));
            b[19] = 0x0a;
            b[28..32].copy_from_slice(&imm.to_le_bytes());
            return Some(b);
        }
        if inner.starts_with("UR") {
            // [URn(+imm)]
            let ur = uregr(inner.split('+').next()?)?;
            let imm = imm_of(inner);
            let val = val?;
            let sub: u8 = if body.contains(".MIN") {
                0x14
            } else if body.contains(".MAX") {
                0x24
            } else if body.contains(".AND") {
                0x54
            } else if body.contains(".OR") {
                0x64
            } else {
                return None;
            };
            if imm != 0 && (body.contains(".AND") || body.contains(".OR")) {
                return None; // mk27 AtomSmem (tier 5) trzyma OR/AND+imm
            }
            b[2] = 0x84;
            b[6] = sub;
            b[7] = if body.contains(".S32") { 0x64 } else { 0x60 };
            b[8] = 0x03;
            put(&mut b, 12, merc_grid1(dst as u8));
            put(&mut b, 14, 0xffc0);
            put(&mut b, 17, (ur as u16) << 6);
            b[19] = 0x0a;
            put(&mut b, 21, (val as u16) << 6);
            b[28..32].copy_from_slice(&imm.to_le_bytes());
            return Some(b);
        }
        // [Rn(+imm)] — korpus: wylacznie ADD
        if !body.contains(".ADD") {
            return None;
        }
        let addr = reg(inner.split('+').next()?)?;
        let imm = imm_of(inner);
        let val = val?;
        b[2] = 0x82;
        b[6] = 0x04;
        b[7] = 0x60;
        b[8] = 0x03;
        put(&mut b, 12, merc_grid1(dst as u8));
        put(&mut b, 14, (addr as u16) << 6);
        b[17] = 0x0a;
        put(&mut b, 19, (val as u16) << 6);
        b[28..32].copy_from_slice(&imm.to_le_bytes());
        return Some(b);
    }
    None
}

/// mk49: lane ATOM-rodziny ktory NIE dostaje rekordu capmerc (spin-loop CAS):
/// ATOMS.CAST.SPIN(,.64), ATOM.E.CAST.SPIN(,.64), ATOM.E.CAS.* (1536+7041
/// lane'ow korpusu — zadne nie ma rekordu 024e; dowod c8: po ich pomieciu
/// parowanie rekordow jest 1:1 w 2929/2929 kernelach).
pub fn merc_atomg2_recordless(text: &str) -> bool {
    let t0 = text.trim();
    let t = match t0.strip_prefix('@') {
        Some(r) => r
            .split_once(char::is_whitespace)
            .map(|(_, x)| x.trim_start())
            .unwrap_or(t0),
        None => t0,
    };
    t.contains(".CAST.SPIN") || t.starts_with("ATOM.E.CAS.")
}

pub fn build_atom_rec(
    cls: u8, guard_b4: u8, subop6: u8, dst: u8, addr: u8, v1: u8, v2: u8,
) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 0x02; b[1] = 0x4e; b[3] = 0x32;
    b[4] = guard_b4;
    match cls {
        MERC_ATOM_CLS_G4 => {
            b[2] = 0x52; b[6] = subop6; b[7] = 0x40; b[8] = 0x03;
            b[12] = 0x01; b[13] = 0xf8;
            merc_put16(&mut b, 14, merc_grid1(dst));
            if addr != 255 { merc_put16(&mut b, 17, ((addr as u16) << 6) | 2); }
            b[19] = 0x0a; b[21] = 0x02; b[22] = 0x01;
            merc_put16(&mut b, 23, merc_grid0(v1));
        }
        MERC_ATOM_CLS_CAS => {
            b[2] = 0x24; b[7] = 0x88;
            b[12] = 0x01; b[13] = 0xf8;
            merc_put16(&mut b, 14, merc_grid1(dst));
            if addr != 255 { merc_put16(&mut b, 17, ((addr as u16) << 6) | 2); }
            b[19] = 0x0a;
            merc_put16(&mut b, 21, merc_grid0(v1));
            merc_put16(&mut b, 23, merc_grid0(v2));
        }
        MERC_ATOM_CLS_SHARED => {
            b[2] = 0x84; b[6] = 0x04; b[7] = 0x60; b[8] = 0x01;
            merc_put16(&mut b, 12, merc_grid1(dst));
            merc_put16(&mut b, 14, 0xffc0);
            b[18] = 0x01; b[19] = 0x0a;
            merc_put16(&mut b, 21, merc_grid0(v1));
        }
        // mk35 (probki k_atom REDG.ADD / at_and REDG.AND / at_min REDG.MIN.S32,
        // wszystkie desc[URx][Ry.64], Rv):
        //   b1=4d b2=24; b6 = subop (ADD=00, MIN=10, AND=50 — inne: do domkniecia
        //   gdy probka sie pojawi); b7 = a0 (+0x02 gdy wariant .S32);
        //   [12:14] = (areg<<6)|2; [14]=0x0a; [17:19] = (desc_ur<<6)|2;
        //   [19:21] = dataR<<6 (bez flagi). b8=01 jest czescia szablonu.
        MERC_ATOM_CLS_REDG_D => {
            b[1] = 0x4d; b[2] = 0x24;
            b[6] = subop6;
            b[7] = 0xa0 | (if v2 & 0x80 != 0 { 0x02 } else { 0x00 });
            b[8] = 0x01;
            if addr != 255 { merc_put16(&mut b, 12, ((addr as u16) << 6) | 2); }
            b[14] = 0x0a;
            let dur = v2 & 0x7f;
            if dur != 0x7f { merc_put16(&mut b, 17, ((dur as u16) << 6) | 2); }
            merc_put16(&mut b, 19, (v1 as u16) << 6);
        }
        _ => {}
    }
    b
}
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

// ==== mk64: rodzina duchow __syncwarp 01476c0a (pelna regula tekstowa) ====
/// Dekompozycja site'ow EIATTR-0x28 na kandydatow pelnego rekordu-ducha
/// 01476c0a i mini (mk64, merclab/mk64 c4/c5 — korpus l2 EXACT obustronnie:
/// 3513 kern z rekordami + 3311 z site'ami bez rekordow, 30554/30554):
/// - pelny rekord dla site'a z instr NOP w .text (maska 0x29 bez znaczenia —
///   maski 0x050000xx tez daja rekordy, np. symv cublas.255),
/// - mini (realna instrukcja na lane) zachowana osobno (mk14 ghost_mini76),
/// - srodek triple'a [WARPSYNC*;NOP;ENDCOLLECTIVE] NIE dostaje niczego
///   (pokryty przez rekordy kolektywu d10102-47, mk59).
/// `op(lane)` -> bazowy opcode (bez kropki) lane'a lub None poza kodem.
pub fn merc_ghost64_split<F: Fn(u32) -> Option<String>>(
    cgsites: &[u32],
    op: F,
) -> (Vec<u32>, Vec<u32>) {
    let is = |l: u32, want: &str| op(l).as_deref() == Some(want);
    let wcmid = |ln: u32| {
        ln.checked_sub(1).map(|p| is(p, "WARPSYNC")).unwrap_or(false)
            && is(ln + 1, "ENDCOLLECTIVE")
    };
    let mut full = Vec::new();
    let mut mini = Vec::new();
    for &s in cgsites {
        let ln = s / 16;
        if wcmid(ln) {
            continue;
        }
        if is(ln, "NOP") {
            full.push(ln);
        } else {
            mini.push(ln);
        }
    }
    full.sort_unstable();
    full.dedup();
    mini.sort_unstable();
    mini.dedup();
    (full, mini)
}

/// mk64: finalna lista lane'ow do dyrektywy .merc_syncwarp.
/// Dowod: n_ghost_recs = liczba rekordow 01476c0a w oryginalnym capmerc
/// (None gdy cubin bez capmerc — wtedy keep-all na legacy jak mk19b).
/// utca_ret = dialekt zero-param (kernel z UTCATOMSWS i wewnetrznym RET):
/// ostatni lone-NOP site pokrywa tail-special (mk27/mk28, mkvmem), a site'y
/// z realna instrukcja dostaja mini 4147760a — sklejone w jednej liscie
/// (elf_builder rozpoznaje pelny-vs-mini po opcode lane'a: feat.ghost_mini76).
pub fn merc_ghost64_lanes(
    cgsites: &[u32],
    op: &dyn Fn(u32) -> Option<String>,
    n_ghost_recs: Option<usize>,
    utca_ret: bool,
    legacy: &[u32],
) -> Vec<u32> {
    if cgsites.is_empty() {
        return Vec::new();
    }
    let (mut full, mini) = merc_ghost64_split(cgsites, op);
    match n_ghost_recs {
        Some(n) if n == full.len() => {
            if utca_ret {
                full.pop();
                full.extend_from_slice(&mini);
                full.sort_unstable();
            }
            full
        }
        Some(n) => legacy.iter().copied().take(n).collect(),
        None => legacy.to_vec(),
    }
}
