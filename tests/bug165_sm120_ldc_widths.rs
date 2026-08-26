//! BUG-165 (F2-iter79, front2/blind; queue item = fleet note 163 sec.7(b),
//! "165-kand: audit of dead sm120 LDC-family rows, 150-style").
//!
//! Census-first (work/bug165/census165.json, vendor_test*.py): the five
//! kand-named rows and siblings are ZERO-anchor on the sm120 corpus (392
//! cubins), era rc4/rt98 and sm_120a gold. Machine arbitration
//! (nvdisasm-13.3.73; probe words always taken programmatically from hexdb
//! -- a first hand-typed probe set was misaligned, re-driven and recorded in
//! work/bug165/decode2/legality.json): ALL vendor LDC/LDCU width forms are
//! LEGAL on sm120. Vendor law (sig_classes.py + BUG-162/163):
//!   LDC width = 3 bits @[73:76)  (U8=0 S8=1 U16=2 plain=4 64=5),
//!   LDCU  = same + bit91; LDCU.128 = width 6 exists and is legal too;
//!   off s16@[38:54) / LDCU s17@[37:54), bank u5@[54:59), idx [24:32).
//! Measured pre-fix on the base binary (work/bug165/decode2/prefix_winners.json):
//!   FABR  every `LDC.U8` word decoded as `LDC R3, 0x5ec` via junk key
//!         LDC_R_II (const addressing + width dropped from the text);
//!   FABR  `@P5 LDC.U16 R15, c[0x0][0x3f0]` printed as
//!         `@P1 LDC.U16 R15, c[0x0][0x0], 0x0` via junk LDC.U16_R_cAI_II;
//!   HOLE  LDC.U16 / LDC.S8 / LDCU.U16 / LDCU.S8 fail-closed;
//!   OK    LDC/LDC.64, LDCU plain/U8/128/64 via canonical keys.
//! Fix = data-only (work/bug165/patch165.py): delete 14 junk keys
//! (fabricators + geometrically-dead shells), add 5 canonical width groups
//! cloned field-for-field from the live '64' donor of each key with the
//! width bits swapped in and_base: LDC_R_cAI + U8/U16/S8,
//! LDCU_UR_cAI + U16/S8. Kept with evidence (encode byte-exact vs vendor):
//! LDCU_UR_cAI/cARI '128','U8'. cAURI groups untouched (owner = parked 152).
//! Compose: disjoint with parked patch151/152/163 ('' groups) and
//! 142/148/155/156/158/161.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const L96: u128 = (1u128 << 96) - 1;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    s.split("/* @sched").next().unwrap().trim().to_string()
}
fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

/// t165_1 (polygon/compose): junk keys gone; canonical width groups present
/// with the donor geometry and width-tagged and_base; compose sentinels:
/// '' groups still pre-163/pre-152 on this base (sub_imm1 or, once they
/// land, cm*off -- tolerant either way).
#[test]
fn t165_1_polygon() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    for k in [
        "LDC.64_R_cAI", "LDC.64_P_R_cAI", "LDC.64_R_II", "LDC_R_II",
        "LDC.U8_R_cAI", "LDC.U8_R_cAI_?", "LDC.U16_R_cAI", "LDC.U16_R_cAI_II",
        "LDCU.64_UR_cAI", "LDCU.64_UR_II", "LDCU.U16_UR_cAI", "LDCU.U8_UR_cAI",
        "LDCU.128_UR_cAI", "LDCU_P_UR_II",
    ] {
        assert!(j.pointer(&format!("/instructions/{k}")).is_none(), "junk key {k} survived");
    }
    let ldc = j.pointer("/instructions/LDC_R_cAI/mod_groups").unwrap();
    for (g, wbits) in [("U8", 0u128), ("S8", 1u128), ("U16", 2u128)] {
        let row = &ldc[g];
        assert_eq!(row["_src"].as_str().unwrap(), "bug165-2026-08-25");
        let ab = u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!((ab >> 73) & 0x7, wbits, "LDC_R_cAI[{g}] width bits");
        assert_eq!((ab >> 91) & 0x1, 0, "LDC (not LDCU) discriminator");
        let f: Vec<_> = row["fields"].as_array().unwrap().iter().map(|f| f["extraction"].as_str().unwrap()).collect();
        assert_eq!(f, ["guard", "reg", "sub_r1", "cm16_off", "reuse"], "clone of '64': {f:?}");
        assert_eq!(row["variable_mask"], ldc["64"]["variable_mask"], "vm must equal live donor");
    }
    let ldcu = j.pointer("/instructions/LDCU_UR_cAI/mod_groups").unwrap();
    for (g, wbits) in [("U16", 2u128), ("S8", 1u128)] {
        let row = &ldcu[g];
        assert_eq!(row["_src"].as_str().unwrap(), "bug165-2026-08-25");
        let ab = u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!((ab >> 73) & 0x7, wbits);
        assert_eq!((ab >> 91) & 0x1, 1, "LDCU discriminator");
        let f: Vec<_> = row["fields"].as_array().unwrap().iter().map(|f| f["extraction"].as_str().unwrap()).collect();
        assert_eq!(f, ["ureg", "cm17_off"], "clone of '64': {f:?}");
    }
    // kept-with-evidence: canonical LDCU width groups stay (encode byte-exact)
    for g in ["128", "U8"] {
        assert!(ldcu.get(g).is_some(), "kept LDCU_UR_cAI[{g}] wrongly removed");
    }
    // compose sentinels (parked 151/152/163 own the '' groups)
    let e = ldc[""]["fields"][1]["extraction"].as_str().unwrap();
    assert!(e == "sub_imm1" || e == "cm16_off", "163 compose: {e}");
    let e2 = ldcu[""]["fields"][1]["extraction"].as_str().unwrap();
    assert!(e2 == "sub_imm1" || e2 == "cm17_off" || e2 == "sub_ur1", "152 compose: {e2}");
}

/// t165_2 (decode vendor-exact, anchors straight from hexdb): every width
/// class prints the vendor text, including the two measured FABR cases.
#[test]
fn t165_2_decode_anchors() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let cases: [(&str, &str); 10] = [
        ("00000000000000000000017b00ff037b82", "LDC.U8 R3, c[0x0][0x5ec]"),
        ("0000000000000000000002c000ffcb7b82", "LDC.U8 R203, c[0x0][0xb00]"),
        ("000004000000fc00ff0f5b82", "@P5 LDC.U16 R15, c[0x0][0x3f0]"), // was FABR @P1 ... 0x0, 0x0
        ("000004000000e500ff067b82", "LDC.U16 R6, c[0x0][0x394]"),
        ("0000020000010b80ff037b82", "LDC.S8 R3, c[0x0][0x42e]"),
        ("0800040000007180ff0577ac", "LDCU.U16 UR5, c[0x0][0x38c]"),
        ("0800020000007c40ff0977ac", "LDCU.S8 UR9, c[0x0][0x3e2]"),
        ("080000000000bc80ff0477ac", "LDCU.U8 UR4, c[0x0][0x5e4]"),     // kept-class control
        ("08000c0000007000ff0877ac", "LDCU.128 UR8, c[0x0][0x380]"),    // kept-class control
        ("00000a000000e000ff027b82", "LDC.64 R2, c[0x0][0x380]"),       // kept control
    ];
    for (h, want) in cases {
        assert_eq!(dec(&idx, w(h), &t), want, "anchor {h}");
    }
}

/// t165_3 (encode byte-exact [0:96) vs the same vendor anchors; roundtrip
/// identity disasm->asm).
#[test]
fn t165_3_encode_roundtrip() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let cases: [(&str, &str); 10] = [
        ("00000000000000000000017b00ff037b82", "LDC.U8 R3, c[0x0][0x5ec]"),
        ("0000000000000000000002c000ffcb7b82", "LDC.U8 R203, c[0x0][0xb00]"),
        ("000004000000fc00ff0f5b82", "@P5 LDC.U16 R15, c[0x0][0x3f0]"),
        ("000004000000e500ff067b82", "LDC.U16 R6, c[0x0][0x394]"),
        ("0000020000010b80ff037b82", "LDC.S8 R3, c[0x0][0x42e]"),
        ("0800040000007180ff0577ac", "LDCU.U16 UR5, c[0x0][0x38c]"),
        ("0800020000007c40ff0977ac", "LDCU.S8 UR9, c[0x0][0x3e2]"),
        ("080000000000bc80ff0477ac", "LDCU.U8 UR4, c[0x0][0x5e4]"),
        ("08000c0000007000ff0877ac", "LDCU.128 UR8, c[0x0][0x380]"),
        ("00000a000000e000ff027b82", "LDC.64 R2, c[0x0][0x380]"),
    ];
    for (h, text) in cases {
        assert_eq!(enc(&t, text) & L96, w(h) & L96, "encode byte-exact {text}");
        let s = dec(&idx, w(h), &t);
        assert_eq!(enc(&t, &s) & L96, w(h) & L96, "roundtrip {h}");
    }
}

/// t165_4 (fabrication killed + fail-closed): the measured FABR word can no
/// longer render the junk text; garbage width bits [73:76) fail-closed;
/// junk-signage text forms fail-closed on encode.
#[test]
fn t165_4_no_fabrication() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let u8w = w("00000000000000000000017b00ff037b82");
    let s = dec(&idx, u8w, &t);
    assert_ne!(s, "LDC R3, 0x5ec", "pre-fix fabrication resurrected?");
    assert!(s.starts_with("LDC.U8"));
    let base = u8w & !(0x7u128 << 73);
    for width in [3u128, 6, 7] {
        assert!(idx.decode(base | (width << 73), 0, &t).is_err(),
                "garbage LDC width {width} must fail-closed");
    }
    // junk-signage encodes die (keys deleted)
    let bad = parse_sass("LDC R3, 0x5ec", 0).unwrap();
    assert!(encode_instruction(&bad, &t).is_err());
    let bad = parse_sass("LDC.U8 R3, 0x5ec", 0).unwrap();
    assert!(encode_instruction(&bad, &t).is_err());
}

/// t165_5 (indexed width forms: nvdisasm-arbitrated legal on sm120,
/// zero corpus anchors -- decode renders the index; encode STAYS
/// fail-closed because no cARI width group exists yet = documented hole,
/// see report sec.7).
#[test]
fn t165_5_indexed_width_shapes() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let u8idx = w("00000000000000000000017b00ff037b82") & !(0xffu128 << 24) | (5u128 << 24);
    assert_eq!(dec(&idx, u8idx, &t), "LDC.U8 R3, c[0x0][R5+0x5ec]");
    let insn = parse_sass("LDC.U8 R3, c[0x0][R5+0x5ec]", 0).unwrap();
    assert!(encode_instruction(&insn, &t).is_err(),
            "indexed width encode: fail-closed hole (no LDC_R_cARI width groups)");
}
