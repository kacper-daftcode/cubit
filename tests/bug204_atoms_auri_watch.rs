//! BUG-204 (F2-iter100, 2026-08-27): sm120 ATOMS AURI (64,9) watch closure +
//! witness-first ATOMS-family ARI coverage. patch204.py (data-only):
//! PART A: ATOMS_R_AURI_R {AND,OR,XOR,MIN,S32,MAX,S32} sub_ur0 (64,9)->(64,8)
//! on sm120 (mirror BUG-143-E2; b72 vendor-inert, arb204).
//! PART B: ATOMS_R_ARI_R rebuild sm120 'MAX,S32' (phantom (64,8,'reg') tok4
//! hijacking 19 live AURI anchors) + 'EXCH' (junk held bits, no imm field),
//! plus witness-backed rows MIN/MIN,S32/MAX,S32/INC/EXCH per table from
//! probe204a x3 arch (payload arch-eq). Law: UR=[64:72); MIN=^b87, MAX=^b88,
//! INC=^b87^b88, EXCH=^b90 vs ADD; .S32=^b73; b74=.64/INVALID3.
//! ctl asymmetry pinned: sm103a refuses guarded ATOMS encode (BUG-080 policy).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const T103: &str = "tables/sm103a.json";
const T120: &str = "tables/sm120.json";
const T100: &str = "tables/sm100a.json";
const TABS: &[&str] = &[T120, T103, T100];
fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| cubit::printer::to_sass(&d))
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
const M96: u128 = (1u128 << 96) - 1;
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).ok()
}

/// Live corpus anchors: AURI-form words that ctl sm120 rendered as `[RZ]`
/// (19/19 junk pre-fix; UR slot fabricated as R by the phantom row).
const AURI_ANCHORS: &[(&str, u64, u64)] = &[
    ("@P6 ATOMS.MAX.S32 RZ, [UR6], R0",     0x00000000ffff698c, 0x0001e40009000206),
    ("@P5 ATOMS.MAX.S32 RZ, [UR7], R3",     0x00000003ffff598c, 0x0005e40009000207),
    ("@P0 ATOMS.MIN.S32 RZ, [UR7+0x4008], R4", 0x00400804ffff098c, 0x0001e80008800207),
    ("ATOMS.MIN.S32 RZ, [UR5+0x2100], R9",  0x00210009ffff798c, 0x0001e40008800205),
    ("@P0 ATOMS.AND RZ, [UR5+0x18], R0",    0x00001800ffff098c, 0x0009e2000a800005),
    ("ATOMS.OR RZ, [UR65+0x14], R7",        0x00001407ffff798c, 0x0003e8000b000041),
    ("ATOMS.OR RZ, [UR70+0x18], R7",        0x00001807ffff798c, 0x0003e8000b000046),
    ("ATOMS.XOR RZ, [UR5+0x10], R8",        0x00001008ffff798c, 0x0007e4000b800005),
    ("@P0 ATOMS.OR RZ, [UR4], R2",          0x00000002ffff098c, 0x0001e4000b000004),
];

/// probe204a witnesses (nvcc/ptxas+nvdisasm 13.3.73 x3 arch, payload arch-eq).
const ARI_PROBES: &[(&str, u64, u64)] = &[
    ("ATOMS.ADD R7, [R0+0x20], R3",         0x000020030007738c, 0x004e280000000000),
    ("ATOMS.AND R7, [R0+0x80], R3",         0x000080030007738c, 0x004e280002800000),
    ("ATOMS.OR R7, [R0+0x40], R3",          0x000040030007738c, 0x004e280003000000),
    ("ATOMS.XOR R7, [R0+0x100], R3",        0x000100030007738c, 0x004e280003800000),
    ("ATOMS.EXCH R7, [R0+0x200], R3",       0x000200030007738c, 0x004e280004000000),
    ("ATOMS.INC R7, [R0+0x1000], R3",       0x001000030007738c, 0x004e280001800000),
    ("ATOMS.MAX R7, [R0], R3",              0x000000030007738c, 0x004e280001000000),
    ("ATOMS.MAX.S32 R7, [R0], R3",          0x000000030007738c, 0x004e280001000200),
    ("ATOMS.MIN R7, [R0+0x800], R3",        0x000800030007738c, 0x004e280000800000),
    ("ATOMS.MIN.S32 R7, [R0+0x10], R3",     0x000010030007738c, 0x004e280000800200),
    ("ATOMS.MIN.S32 R9, [R0+0x8], R5",      0x000008050009738c, 0x008e280000800200),
    ("ATOMS.CAS R7, [R0+0x400], R6, R7",    0x000400060007738d, 0x004e280000000007),
];

#[test]
fn t204_1_auri_corpus_anchors_decode_vendor_exact() {
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        for (glyph, lo, hi) in AURI_ANCHORS {
            let got = dec(&t, &idx, word(*lo, *hi)).expect("decode hole");
            assert_eq!(&got, glyph, "{p} AURI anchor");
        }
    }
}

#[test]
fn t204_2_ari_probe_witnesses_decode_vendor_exact() {
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        for (glyph, lo, hi) in ARI_PROBES {
            let got = dec(&t, &idx, word(*lo, *hi)).expect("decode hole");
            assert_eq!(&got, glyph, "{p} ARI probe");
        }
    }
}

#[test]
fn t204_3_ari_encode_byte_exact() {
    for p in TABS {
        let t = tab(p);
        for (glyph, lo, hi) in ARI_PROBES {
            let w = enc(&t, glyph).unwrap_or_else(|| panic!("{p} encode HOLE: {glyph}"));
            let want = word(*lo, *hi);
            // payload bits [0:96): sched/control top dword is harness-owned
            assert_eq!(w & M96, want & M96, "{p} encode != witness: {glyph}");
        }
    }
}

#[test]
fn t204_4_b72_vendor_inert_decode_parity() {
    // arb204: nvdisasm ignores b72 on AURI/ARURI/ARI words (glyph unchanged);
    // the UR read stays 8-bit. Pin: our decode of the b72-flipped word equals
    // the vendor glyph of the unflipped word on every table.
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        let w = word(0x00000000ffff698c, 0x0001e40009000206 | (1u64 << 8)); // +b72
        let got = dec(&t, &idx, w).expect("b72 word decode hole");
        assert_eq!(got, "@P6 ATOMS.MAX.S32 RZ, [UR6], R0", "{p} b72 inert parity");
        let w2 = word(0x000000030007738c, 0x004e280001000200 | (1u64 << 8)); // ARI +b72
        let got2 = dec(&t, &idx, w2).expect("b72 ARI word decode hole");
        assert_eq!(got2, "ATOMS.MAX.S32 R7, [R0], R3", "{p} b72 ARI inert parity");
    }
}

#[test]
fn t204_5_auri_urz_gen_and_encode_byte_exact_sm120() {
    // 0xff = URZ elision retention on the pure-UR form + guarded AURI encode
    // byte-exact vs the corpus anchor words (sm120 + sm100a; sm103a refuses
    // guarded ATOMS by BUG-080 policy — pinned separately).
    for p in [T120, T100] {
        let t = tab(p);
        for (glyph, lo, hi) in &AURI_ANCHORS[..8] {
            let w = enc(&t, glyph).unwrap_or_else(|| panic!("{p} encode HOLE: {glyph}"));
            assert_eq!(w & M96, word(*lo, *hi) & M96, "{p} AURI encode != anchor");
        }
    }
}

#[test]
fn t204_6_guarded_atoms_refusal_stays_closed_on_sm103a() {
    // BUG-080 policy: guarded non-EL ATOMS on sm103a = silicon-broken; encode
    // was refusing before this fix and must keep refusing (ata: both ctl and
    // fix refuse; encode-only behavior, decode untouched).
    let t = tab(T103);
    assert!(enc(&t, "@P6 ATOMS.MAX.S32 RZ, [UR6], R0").is_none(), "103a guarded ATOMS must refuse");
    assert!(enc(&t, "@P0 ATOMS.OR RZ, [UR4], R2").is_none(), "103a guarded ATOMS must refuse");
}

#[test]
fn t204_7_cross_table_parity_ari_stems() {
    // every ARI probe word decodes to the same glyph on all three tables
    // (payload arch-eq proven by nvdisasm; our tables must not diverge).
    for (glyph, lo, hi) in ARI_PROBES {
        let mut renders = vec![];
        for p in TABS {
            let t = tab(p); let idx = DecodeIndex::build(&t);
            renders.push(dec(&t, &idx, word(*lo, *hi)));
        }
        assert!(renders.windows(2).all(|w| w[0] == w[1] && w[0].as_deref() == Some(*glyph)),
                "cross-table divergence: {glyph} -> {renders:?}");
    }
}
