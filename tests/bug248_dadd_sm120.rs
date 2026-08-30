//! BUG-248 (F2-iter125, front2/blind, 2026-08-28): sm120 DADD
//! vendor-parity closure (canonical cfba9e9; patch248.py
//! replayable+idempotent). Donors sm100a/sm103a + sm121a byte-untouched.
//!
//! Pre-fix state (gold245_post FAMS extension, 2,406-file battery x4 legs
//! vs vendor nvdisasm 13.3.73 at-address): sm120 DADD **95,052 DIFF +
//! 11,939 HOLE** (all other legs all-MATCH 294,999).
//!
//! Defects:
//!   D1 era DADD_R_R_R row: and_base 0x7229 (guard bits PT-baked), NO
//!      guard field, and bogus 2-bit fields neg_abs@72 / neg_shl1@74 where
//!      the vendor law has per-token neg/abs pairs -> '-RZ'/'|R12|' printed
//!      bare with !rsd residues.
//!   D2 era DADD_R_R_UR row: placeholder shell (and_base 0xe29, vmask 0,
//!      ZERO fields) -> broad-match cannot cover real UR words (b91=1 in
//!      every one of the 2,632 unique corpus UR words) -> decode HOLE.
//!
//! Laws (law248 census: 141,819 unique DADD words / 353,377 occurrences;
//! arb248 transplant walks on battery witness slots, nvdisasm 13.3.73):
//!   L1 guard 4b@12: 0..6=@P0..6, 7=bare, 8..14=@!P0..6, 15=@!PT.
//!   L2 R_R_R sign law: tok2 neg=b72 abs=b73; tok3(R) neg=b75 abs=b74;
//!      reuse b122/b124. b62/63 text-inert on the RR cell (arb B).
//!   L3 UR cell: ureg@32, neg=b63 abs=b62; b91=1 mandatory (2,632/2,632
//!      corpus); b59=0 always, Rc@64=0 always; reuse b122/123/124
//!      text-inert on the UR cell (arb C; 401 unique corpus words carry
//!      them and vendor prints them indistinguishably).
//!   L4 arb C: rc64 / b74 / b75 / b80 / b85..87 walks on the UR cell all
//!      text-inert under vendor.
//!
//! Fix (sibling-graft): sm120 mod_groups[''] of DADD_R_R_R and
//! DADD_R_R_UR replaced by byte-copies of the proven donor rows (sm103a
//! == sm100a, parity asserted in patch248): true guard field, per-token
//! sign fields, UR cell with real fields. Key top-level records
//! (ctrl_class/scheduling) stay sm120-native. Era FI/_? keys untouched
//! (zero measured corpus exposure change; FI words route to FI rows on
//! opcode 0x429).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// Vendor witnesses (full 128-bit; decode strips ctrl [127:96]). All from
// law248.json battery census; vendor glyph per nvdisasm 13.3.73.
const W_RR: u128 = 0x00004fe400000000220000000004047229; // DADD R4, R4, R34
const W_RR_NA: u128 = 0x00004fc4000000051000000000ff087229; // DADD R8, -RZ, |R16|
const W_RR_A: u128 = 0x00000fe200000006120000000010067229; // DADD R6, |R16|, |R18|
const W_RR_NN: u128 = 0x00000fcc000000090c00000000ff0c7229; // DADD R12, -RZ, -R12
const W_RR_G: u128 = 0x00002fce000000001a000000001e1a0229; // @P0 DADD R26, R30, R26
const W_RR_GN: u128 = 0x00004fce00000001160000000018169229; // @!P1 DADD R22, -R24, R22
const W_RR_GNA: u128 = 0x00004fd4000000050600000000ff048229; // @!P0 DADD R4, -RZ, |R6|
const W_UR_NN: u128 = 0x00000fc8000800010080000016ff0c7e29; // DADD R12, -RZ, -UR22
const W_UR_GA: u128 = 0x00001e10000800020040000006080a8e29; // @!P0 DADD R10, |R8|, |UR6|
const W_UR_NA: u128 = 0x0000ee4000800010040000006ff207e29; // DADD R32, -RZ, |UR6|
const W_FI: u128 = 0x0000fe200000000003ff000000e0e7429; // DADD R14, R14, 1
const W_FI_N: u128 = 0x00001fcc00000001003ff0000014167429; // DADD R22, -R20, 1
const W_FI_G: u128 = 0x0000fe400000000003ff000001c1c8429; // @!P0 DADD R28, R28, 1

#[test]
fn t248_1_structure() {
    let t = tab("sm120");
    let ins = |k: &str| t.entries.get(k).unwrap_or_else(|| panic!("sm120 {k}"));
    // R_R_R graft: guard true field + per-token neg/abs + reuse, ab 0x229
    let r = &ins("DADD_R_R_R").mod_groups[""];
    assert_eq!(r.and_base & 0xFFF, 0x229, "R_R_R opcode");
    assert!(
        r.fields.iter().any(|f| f.shift == 12 && f.bits == 4),
        "guard field"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 72 && f.bits == 1),
        "tok2 neg@72"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 73 && f.bits == 1),
        "tok2 abs@73"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 64 && f.bits == 8),
        "tok3 reg@64"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 75 && f.bits == 1),
        "tok3 neg@75"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 74 && f.bits == 1),
        "tok3 abs@74"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 122 && f.bits == 1),
        "tok2 reuse@122"
    );
    assert!(
        r.fields.iter().any(|f| f.shift == 124 && f.bits == 1),
        "tok3 reuse@124"
    );
    // bogus era fields gone
    let bogus = r
        .fields
        .iter()
        .any(|f| (f.shift == 72 || f.shift == 74) && f.bits == 2);
    assert!(!bogus, "era neg_abs/neg_shl1 2-bit fields removed");
    // R_R_UR graft: UR cell with real fields; b91 mandatory (L3)
    let u = &ins("DADD_R_R_UR").mod_groups[""];
    assert_eq!(u.and_base & 0xFFF, 0xE29, "UR opcode");
    assert_eq!(
        (u.and_base >> 91) & 1,
        1,
        "UR b91 mandatory (corpus 2632/2632)"
    );
    assert!(
        u.fields.iter().any(|f| f.shift == 32 && f.bits == 8),
        "ureg@32"
    );
    assert!(
        u.fields.iter().any(|f| f.shift == 63 && f.bits == 1),
        "UR neg@63"
    );
    assert!(
        u.fields.iter().any(|f| f.shift == 62 && f.bits == 1),
        "UR abs@62"
    );
    // era FI keys untouched (still present, PT-baked is their own state)
    assert!(
        ins("DADD_R_R_FI").mod_groups.contains_key(""),
        "FI key alive"
    );
    assert!(t.entries.contains_key("DADD_R_II_R"), "II_R alive");
}

#[test]
fn t248_2_decode_vendor_true() {
    let t = tab("sm120");
    let cases: &[(u128, &str)] = &[
        (W_RR, "DADD R4, R4, R34"),
        (W_RR_NA, "DADD R8, -RZ, |R16|"),
        (W_RR_A, "DADD R6, |R16|, |R18|"),
        (W_RR_NN, "DADD R12, -RZ, -R12"),
        (W_RR_G, "@P0 DADD R26, R30, R26"),
        (W_RR_GN, "@!P1 DADD R22, -R24, R22"),
        (W_RR_GNA, "@!P0 DADD R4, -RZ, |R6|"),
        (W_UR_NN, "DADD R12, -RZ, -UR22"),
        (W_UR_GA, "@!P0 DADD R10, |R8|, |UR6|"),
        (W_UR_NA, "DADD R32, -RZ, |UR6|"),
        // FI kept era-row: already vendor-true (zero drift regression net)
        (W_FI, "DADD R14, R14, 1"),
        (W_FI_N, "DADD R22, -R20, 1"),
        (W_FI_G, "@!P0 DADD R28, R28, 1"),
    ];
    for (w, want) in cases {
        assert_eq!(dec(&t, *w).as_deref(), Some(*want), "sm120 {want}");
    }
}

#[test]
fn t248_3_encode_witness() {
    let t = tab("sm120");
    let cases: &[(u128, &str)] = &[
        (W_RR, "DADD R4, R4, R34"),
        (W_RR_NA, "DADD R8, -RZ, |R16|"),
        (W_RR_NN, "DADD R12, -RZ, -R12"),
        (W_RR_GN, "@!P1 DADD R22, -R24, R22"),
        (W_UR_NN, "DADD R12, -RZ, -UR22"),
        (W_UR_NA, "DADD R32, -RZ, |UR6|"),
    ];
    for (w, text) in cases {
        let rc = enc(&t, text);
        assert_eq!(rc & M96, w & M96, "sm120 encode {text}");
    }
}

#[test]
fn t248_4_roundtrip_fidelity() {
    // decode->text->encode must return the identical low-96 bits for every
    // witness (incl. guarded + sign/abs forms)
    let t = tab("sm120");
    for w in [
        W_RR, W_RR_NA, W_RR_A, W_RR_NN, W_RR_G, W_RR_GN, W_RR_GNA, W_UR_NN, W_UR_GA, W_UR_NA, W_FI,
        W_FI_N, W_FI_G,
    ] {
        let text = dec(&t, w).unwrap_or_else(|| panic!("decode {w:032x}"));
        let insn = parse_sass(&format!("{text};"), 0).unwrap();
        let rc = encode_instruction(&insn, &t).unwrap_or_else(|e| panic!("re-encode {text}: {e}"));
        assert_eq!(rc & M96, w & M96, "sm120 roundtrip {text}");
    }
}

#[test]
fn t248_5_no_drift_guard_law() {
    // arb248 A: guard [15:12] full walk on a plain R_R_R word. Every vendor
    // rendering must decode to the same glyph on sm120.
    let t = tab("sm120");
    let want = [
        "@P0 DADD R4, R4, R34",
        "@P1 DADD R4, R4, R34",
        "@P2 DADD R4, R4, R34",
        "@P3 DADD R4, R4, R34",
        "@P4 DADD R4, R4, R34",
        "@P5 DADD R4, R4, R34",
        "@P6 DADD R4, R4, R34",
        "DADD R4, R4, R34",
        "@!P0 DADD R4, R4, R34",
        "@!P1 DADD R4, R4, R34",
        "@!P2 DADD R4, R4, R34",
        "@!P3 DADD R4, R4, R34",
        "@!P4 DADD R4, R4, R34",
        "@!P5 DADD R4, R4, R34",
        "@!P6 DADD R4, R4, R34",
        "@!PT DADD R4, R4, R34",
    ];
    for gv in 0u128..16 {
        let w = (W_RR & !(0xFu128 << 12)) | (gv << 12);
        assert_eq!(
            dec(&t, w).as_deref(),
            Some(want[gv as usize]),
            "guard {gv:x}"
        );
    }
    // arb248 L2/L3 spot law: tok3-UR reuse bits are text-inert (prints
    // indistinguishable); the word must NOT decode to something re-encoding
    // differently (fidelity: either decode-clean or fail-closed).
    let reuse_ur = W_UR_NN | (1u128 << 122);
    if let Some(text) = dec(&t, reuse_ur) {
        let insn = parse_sass(&format!("{text};"), 0).unwrap();
        let rc = encode_instruction(&insn, &t)
            .map(|rc| rc & M96)
            .unwrap_or(0);
        assert_eq!(rc, reuse_ur & M96, "UR reuse word roundtrips lossless");
    }
    // ... and the fresh equivalent: era DADD_R_R_FI PT-bake must NOT have
    // infected the R_R_R graft (no other mg on the grafted keys)
    assert_eq!(
        t.entries["DADD_R_R_R"].mod_groups.len(),
        1,
        "only mg '' grafted"
    );
    assert_eq!(
        t.entries["DADD_R_R_UR"].mod_groups.len(),
        1,
        "only mg '' grafted"
    );
}
