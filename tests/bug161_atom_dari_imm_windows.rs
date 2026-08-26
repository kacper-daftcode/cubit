//! BUG-161 (iter75, loop5/blind front-main; queue item "ATOM-family window
//! audit @35/37/38/39 vs s24@40" from notes 155/156/158 sec.5): sub_imm2
//! immediate windows of ATOM/ATOMG/REDG dARI rows sat off the vendor window,
//! overlapping the data-reg field [32:40) (decode fabricates offsets from
//! register numerals; encode OR-pollutes the data reg) and, for ATOMG,
//! cutting the locked bit63 into the field. Nvdisasm 13.3.73 V13.3.73
//! bit-walk arbitration on corpus anchors (work/i75/arb*, census161.json):
//!   REDG dARI family (anchored AND x6 / OR x33 / MIN.S32 x305 anchors;
//!   healthy MIN/ADD controls; 64-bit MAX/MIN synthesized from and_base
//!   skeletons, zero anchors): imm = s24@[40:64), sign = bit63.
//!   ATOMG dARI family (anchored MIN.S32 x680 + healthy ADD x6475): imm =
//!   s23@[40:63); bit63 is match-space, locked 1 (clr63 -> ILLEGAL).
//!   [32:40) = data reg, [24:32) = base reg, [64:72) = desc UR everywhere.
//! Pre-fix geometry per row (shift): REDG_dARI_R/REDG_P_dARI_R 64MAX/64MIN
//! @35, AND/OR @37, MIN.S32 @38; ATOMG_P_R_dARI_R MIN.S32 @38 with 24 bits
//! (bit63 swallowed). Fix = data-only window moves (11 rows, sm103a.json);
//! sm120 table was already clean; REDG_ARI_R ADD,S32 @35 (plain ARI) is the
//! parked patch156 row - excluded here by design; ATOM/ATOMG CAS @39/@36 =
//! parked patch155. Match invariant: freed bits [35/37/38:40) stay
//! field-excluded via the data-reg field @[32:40); newly covered upper bits
//! relax from matched-0 to field-variable, which is the vendor truth.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn imm_s24(w: u128) -> i64 {
    let v = ((w >> 40) & 0xFF_FFFF) as i64;
    if v & 0x80_0000 != 0 { v - 0x100_0000 } else { v }
}

fn imm_s23(w: u128) -> i64 {
    let v = ((w >> 40) & 0x7F_FFFF) as i64;
    if v & 0x40_0000 != 0 { v - 0x80_0000 } else { v }
}

/// t161_1 (invariant): all eleven patched rows park their sub_imm2 window
/// exactly on the vendor geometry; nothing else overlaps it; the freed
/// low bits stay under the data-reg field.
#[test]
fn t161_1_window_polygon() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm103a.json").unwrap()).unwrap();
    let mut seen = 0;
    for (key, mg, bits, tok) in [
        ("ATOMG_P_R_dARI_R", "E,GPU,MIN,S32,STRONG", 23u64, 3u64),
        ("REDG_dARI_R", "64,E,GPU,MAX,STRONG", 24, 1),
        ("REDG_dARI_R", "64,E,GPU,MIN,STRONG", 24, 1),
        ("REDG_dARI_R", "AND,E,GPU,STRONG", 24, 1),
        ("REDG_dARI_R", "E,GPU,MIN,S32,STRONG", 24, 1),
        ("REDG_dARI_R", "E,GPU,OR,STRONG", 24, 1),
        ("REDG_P_dARI_R", "64,E,GPU,MAX,STRONG", 24, 2),
        ("REDG_P_dARI_R", "64,E,GPU,MIN,STRONG", 24, 2),
        ("REDG_P_dARI_R", "AND,E,GPU,STRONG", 24, 2),
        ("REDG_P_dARI_R", "E,GPU,MIN,S32,STRONG", 24, 2),
        ("REDG_P_dARI_R", "E,GPU,OR,STRONG", 24, 2),
    ] {
        seen += 1;
        let row = j
            .pointer(&format!("/instructions/{key}/mod_groups/{mg}"))
            .unwrap_or_else(|| panic!("{key}[{mg}] missing"));
        let fields = row["fields"].as_array().unwrap();
        let imm: Vec<_> = fields.iter().filter(|f| f["extraction"] == "sub_imm2").collect();
        assert_eq!(imm.len(), 1, "{key}[{mg}] exactly one sub_imm2");
        assert_eq!(imm[0]["shift"].as_u64().unwrap(), 40, "{key}[{mg}] shift");
        assert_eq!(imm[0]["bits"].as_u64().unwrap(), bits, "{key}[{mg}] bits");
        assert_eq!(imm[0]["token_idx"].as_u64().unwrap(), tok, "{key}[{mg}] token_idx");
        for f in fields {
            let (s, b) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
            if f["extraction"] == "sub_imm2" { continue; }
            assert!(
                s + b <= 40 || s >= 64,
                "{key}[{mg}] field {:?} overlaps imm window [40:64)",
                f
            );
        }
    }
    assert_eq!(seen, 11);
}

/// t161_2: authored REDG immediates (incl. pred form and 64-bit forms)
/// land in the s24@[40:64) window, keep the data reg intact, round-trip.
#[test]
fn t161_2_redg_authored_roundtrip() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let cases: &[(&str, i64, u32)] = &[
        ("REDG.E.OR.STRONG.GPU desc[UR6][R4.64+0x10], R9", 0x10, 9),
        ("REDG.E.OR.STRONG.GPU desc[UR6][R4.64+-0x10], R9", -0x10, 9),
        ("REDG.E.AND.STRONG.GPU desc[UR6][R2.64+0x7fffff], R5", 0x7fffff, 5),
        ("REDG.E.AND.STRONG.GPU desc[UR6][R2.64+-0x800000], R5", -0x800000, 5),
        ("REDG.E.MIN.S32.STRONG.GPU desc[UR8][R4.64+0x100], R130", 0x100, 130),
        ("REDG.E.MAX.64.STRONG.GPU desc[UR8][R4.64+0x40], R12", 0x40, 12),
        ("REDG.E.MIN.64.STRONG.GPU desc[UR8][R4.64+-0x1], R2", -0x1, 2),
        ("REDG.E.MIN.STRONG.GPU desc[UR6][R2.64+0x10], R5", 0x10, 5), // healthy control
    ];
    for (text, imm, dat) in cases {
        let w = enc(&t, text);
        assert_eq!(imm_s24(w), *imm, "{text}: imm window");
        assert_eq!(((w >> 32) & 0xFF) as u32, *dat, "{text}: data-reg window");
        let d = dec(&idx, w, &t);
        let re = enc(&t, &d);
        assert_eq!(re, w, "{text}: decode->re-encode fixed point");
    }
}

/// t161_3: authored ATOMG immediates use the s23@[40:63) window with
/// bit63 locked high; 23-bit edges round-trip.
#[test]
fn t161_3_atomg_authored_roundtrip() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, imm) in [
        ("ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR8][R2.64+0x10], R5", 0x10i64),
        ("ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR8][R2.64+-0x10], R5", -0x10),
        ("ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR8][R2.64+0x3fffff], R5", 0x3fffff),
        ("ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR8][R2.64+-0x400000], R5", -0x400000),
        ("ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR8][R2.64+0x11], R35", 0x11),
    ] {
        let w = enc(&t, text);
        assert_eq!(imm_s23(w), imm, "{text}: imm window");
        assert_eq!((w >> 63) & 1, 1, "{text}: bit63 must stay locked high");
        let d = dec(&idx, w, &t);
        let re = enc(&t, &d);
        assert_eq!(re, w, "{text}: decode->re-encode fixed point");
    }
}

/// t161_4: real vendor corpus anchors decode through the patched rows
/// with imm == 0 (the pre==post invariant point of the corpus) and
/// re-encode byte-exact in the low 96 bits. Words from census161
/// (bug142 hexdb): MIN.S32 ATOMG/REDG, OR, AND (sm_103-arch entries).
#[test]
fn t161_4_corpus_anchors_zero_imm_fixedpoint() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let anchors: &[u128] = &[
        // @P0 ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR8][R2.64], R5 (sm_103)
        u128::from_str_radix("001fe200089ef3088000000502ff09a8", 16).unwrap(),
        // REDG.E.MIN.S32.STRONG.GPU desc[UR8][R4.64], R11
        u128::from_str_radix("0087e4000c92e3080000000b0400798e", 16).unwrap(),
        // @P0 REDG.E.OR.STRONG.GPU desc[UR8][R4.64], R7
        u128::from_str_radix("0001e4000f12e108000000070400098e", 16).unwrap(),
        // @P0 REDG.E.AND.STRONG.GPU desc[UR6][R2.64], R5 (sm_103a)
        u128::from_str_radix("00c7a4000e92e106000000050200098e", 16).unwrap(),
    ];
    for (i, &w) in anchors.iter().enumerate() {
        let w = w & !SCHED;
        let imm = if i == 0 { imm_s23(w) } else { imm_s24(w) };
        assert_eq!(imm, 0, "anchor carries imm 0");
        let d = dec(&idx, w, &t);
        assert!(!d.starts_with('?'), "decode must not be raw: {w:x}");
        // BUG-080 keeps guarded atomics encode-closed; the guarded anchors
        // (pred-set words) are decode-pins, the unguarded one round-trips.
        if !d.starts_with('@') {
            let re = enc(&t, &d);
            assert_eq!(re, w, "anchor roundtrip: {w:x}");
        }
    }
    // Window-position decode pins on anchored words: flipping vendor-window
    // bits must move exactly the printed immediate (arbitration replay).
    // C2 MIN.S32: set40 -> +0x1, set63 -> +-0x800000 (s24)
    let c2 = anchors[1];
    assert!(dec(&idx, c2 | (1 << 40), &t).contains("[R4.64+0x1]"));
    assert!(dec(&idx, c2 | (1 << 63), &t).contains("[R4.64+-0x800000]"));
    // C3 OR (guarded anchor): set40 -> +0x1
    assert!(dec(&idx, anchors[2] | (1 << 40), &t).contains("[R4.64+0x1]"));
    // C4 AND: set40 -> +0x1
    assert!(dec(&idx, anchors[3] | (1 << 40), &t).contains("[R2.64+0x1]"));
    // C1 ATOMG (s23): set40 -> +0x1, set62 -> +-0x400000 (23-bit sign)
    let c1 = anchors[0];
    assert!(dec(&idx, c1 | (1 << 40), &t).contains("[R2.64+0x1]"));
    assert!(dec(&idx, c1 | (1 << 62), &t).contains("[R2.64+-0x400000]"));
}

/// t161_5 (fail-closed): guarded non-EL REDG encode stays BUG-080
/// fail-closed (the P_ rows patched here are decode-side citizens; their
/// authored encode must keep ringing the bell, not mis-emit).
#[test]
fn t161_5_failclosed_encode_lanes() {
    let t = t103a();
    let guarded = parse_sass("@P0 REDG.E.OR.STRONG.GPU desc[UR4][R6.64+0x20], R11", 0).expect("parse");
    assert!(
        encode_instruction(&guarded, &t).is_err(),
        "guarded atomics encode must remain BUG-080 fail-closed"
    );
}
