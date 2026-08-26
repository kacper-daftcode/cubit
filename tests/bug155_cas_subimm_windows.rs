//! BUG-155 (iter73, front-main; adoption of spark LATENT-WATCH note
//! 153_cas_subimm1 = fleet 155-kand): the sub_imm1 immediate window of the
//! CAS-class ARI rows lived at shift 36/39 instead of the vendor window
//! [40:63] (24-bit signed), overlapping the CAS data-reg field reg@32/8
//! (bits [36:40) of the word / bit39). Consequences of the pre-fix geometry:
//!   encode: semantic imm T was written T<<36 (C1/C3) / T<<39 (C2), so
//!     nvdisasm renders T>>4 / T>>1 (e.g. authored [R6+0x10] came out as
//!     vendor-visible [R6+0x1] / [R6+0x8]); T&0xF (C1/C3) / T&1 (C2) also
//!     clobber the CAS data-reg numeral; C2 (shift 39, 24 bits) cut the
//!     sign bit 63 out of the window so negative offsets printed positive.
//!   decode: extraction = imm*16 + reg-nibble (C1/C3) / 2*imm + reg.bit7
//!     (C2) - silently wrong for any vendor word with imm != 0.
//! Latency proof (census work/i73/census155.json, bug142 hexdb):
//!   C1 ATOMG "64,CAS,E,STRONG,SYS": 10 uniq / 55 lines, bits[36:64) all 0
//!   C2 ATOM  "CAS,E,GPU,STRONG":   666 uniq / 7434 lines, bits[40:64)=0,
//!                                    bit39=0 (max data-reg R121)
//!   C3 SYNCS "ARRIVE,RED,TRANS64":  6 uniq / 8 lines, bits[36:64) all 0
//!   => shifting the window is both decode-invariant and match-invariant
//!      on the corpus (fail-closed tightening, zero loss).
//! nvdisasm-13.3 arbitration after the fix (work/i73): authored
//!   +0x10/+0x20/-0x10/+0x7fffff/-0x800000 round-trip byte-exact; R130
//!   data-reg with odd imm no longer corrupts (pre-fix bit39 clobber).
//! C3 row identity: real vendor anchors (6) decode through the row and the
//!   family has a healthy @40 sibling; row genuine. Residual render-parity
//!   (cubit "SYNCS.ARRIVE.RED.TRANS64" + "[R3]" vs vendor
//!   "SYNCS.ARRIVE.TRANS64.RED" + "[R3+URZ]") is reported separately and
//!   NOT part of this fix.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn imm_ari(w: u128) -> i64 {
    // vendor window [40:63], 24-bit signed
    let v = ((w >> 40) & 0xFF_FFFF) as i64;
    if v & 0x80_0000 != 0 { v - 0x100_0000 } else { v }
}

/// t155_1 (invariant): table polygons of all four patched rows put
/// sub_imm1 at [40:63] with no overlap against the CAS data-reg window
/// reg@32..40; both tables agree on the sm120-shared row.
#[test]
fn t155_1_window_at_40_no_overlap() {
    for path in ["tables/sm103a.json", "tables/sm120.json"] {
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for (key, mg) in [
            ("ATOMG_P_R_ARI_R_R", "64,CAS,E,STRONG,SYS"),
            ("ATOM_P_R_ARI_R_R", "CAS,E,GPU,STRONG"),
            ("SYNCS_R_ARI_R", "ARRIVE,RED,TRANS64"),
        ] {
            let Some(row) = j.pointer(&format!(
                "/instructions/{key}/mod_groups/{mg}"
            )) else {
                continue; // ATOM/SYNCS rows live in sm103a only
            };
            let fields = row["fields"].as_array().unwrap();
            let imm: Vec<_> = fields
                .iter()
                .filter(|f| f["extraction"] == "sub_imm1")
                .collect();
            assert_eq!(imm.len(), 1, "{key}[{mg}] must have exactly one sub_imm1");
            assert_eq!(imm[0]["shift"].as_u64().unwrap(), 40, "{key}[{mg}] shift");
            assert_eq!(imm[0]["bits"].as_u64().unwrap(), 24, "{key}[{mg}] bits");
            for f in fields {
                let (s, b) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
                if f["extraction"] == "sub_imm1" { continue; }
                assert!(
                    s + b <= 40 || s >= 64,
                    "{key}[{mg}] field {:?} overlaps imm window [40:63]",
                    f
                );
            }
        }
    }
}

/// t155_2: authored CAS immediates land in the vendor window, keep the
/// data-reg window [32:40) untouched, and round-trip.
#[test]
fn t155_2_authored_imm_window_and_roundtrip() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let cases: &[(&str, i64, u32)] = &[
        ("ATOM.E.CAS.STRONG.GPU PT, R5, [R6+0x10], R7, R8", 0x10, 7),
        ("ATOM.E.CAS.STRONG.GPU PT, R5, [R6+-0x10], R7, R8", -0x10, 7),
        ("ATOM.E.CAS.STRONG.GPU PT, R5, [R6+0x7fffff], R7, R8", 0x7fffff, 7),
        ("ATOM.E.CAS.STRONG.GPU PT, R5, [R6+-0x800000], R7, R8", -0x800000, 7),
        ("ATOM.E.CAS.STRONG.GPU PT, R130, [R6+0x11], R121, R8", 0x11, 121),
        ("ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R12+0x10], R8, R10", 0x10, 8),
        ("SYNCS.ARRIVE.RED.TRANS64 RZ, [R3+0x20], R9", 0x20, 9),
    ];
    for (text, imm, dat) in cases {
        let w = enc(&t, text);
        assert_eq!(imm_ari(w), *imm, "{text}: imm window");
        assert_eq!(((w >> 32) & 0xFF) as u32, *dat, "{text}: data-reg window");
        let d = dec(&idx, w, &t);
        let re = enc(&t, &d);
        assert_eq!(re, w, "{text}: decode->re-encode must be a fixed point");
    }
}

/// t155_3: sm120 embedded table encodes the shared C1 row identically.
#[test]
fn t155_3_sm120_same_window() {
    let t = t120();
    let w = enc(&t, "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R12+0x10], R8, R10");
    assert_eq!(imm_ari(w), 0x10);
    assert_eq!((w >> 32) & 0xFF, 8);
}

/// t155_4: real vendor corpus anchors (census155) decode to the intended
/// groups with imm == 0 (the pre-fix == post-fix invariant point) and
/// re-encode byte-exact in the low 96 bits.
#[test]
fn t155_4_corpus_anchors_zero_imm_fixedpoint() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let anchors: &[u128] = &[
        // C1: ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R12], R8, R10
        u128::from_str_radix("000ea400001f450a000000080c0a73a9", 16).unwrap(),
        // C2: ATOM.E.CAS.STRONG.GPU PT, R4, [R2], R9, R5
        u128::from_str_radix("000ea400001ee105000000090204738b", 16).unwrap(),
        // C3: SYNCS.ARRIVE.TRANS64.RED RZ, [R3+URZ], R9 (guard PT form)
        u128::from_str_radix("0003e200080004ff0000000903ff79a7", 16).unwrap(),
    ];
    for &w in anchors {
        assert_eq!(imm_ari(w & !SCHED), 0);
        let d = dec(&idx, w & !SCHED, &t);
        assert!(!d.starts_with('?'), "decode must not be raw: {w:x}");
        let re = enc(&t, &d);
        assert_eq!(re, w & !SCHED, "anchor roundtrip");
    }
}
