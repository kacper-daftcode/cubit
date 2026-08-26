//! BUG-167 (F2, front2/blind; queue item = fleet note 165 sec.7(b) "167-kand",
//! lane F2/b4): sm120 LDC indexed (cARI) width encode-hole.
//!
//! Census-first (work/bug167): indexed+width forms have ZERO anchors in
//! hexdb 32.2M gold (sm_100/100a/103/103a/120a) and the sm120 392-cubin
//! corpus; only LDC.64-idx (107 uniq words) and LDC-plain-idx exist.
//! Arbitration (nvdisasm 13.3 [cuda_13.3.38244171], words programmatic
//! from hexdb donors, work/bug167/arb/*.json): width = 3b @[73:76);
//! 0..5 legal for LDC-idx (U8,S8,U16,S16,plain,64), 6/7 = LDC.INVALID;
//! windows live: idx [24:32) (255=RZ), off+bank = cm16_off@[38:59)
//! (`u8_off5ec` -> `LDC.U8 R24, c[0x3][R24+0x5ec]`, `u8_bank5` -> c[0x5]).
//! Pre-fix measured on base binary: encode `LDC.U8 R3, c[0x0][R5+0x5ec]`
//! = FAIL (hole), decode of the vendor word = `?` fail-closed.
//! Fix = data-only (work/bug167/patch167.py): clone LDC_R_cARI '64' donor
//! (reg@16/8, sub_r1@24/8, cm16_off@38/21, reuse@122, guard@12/4) with
//! width bits swapped: U8=w0, S8=w1, U16=w2.
//! Out of scope (documented, not touched): S16=w3 (legal, 0 anchors ->
//! b4-fill candidate), LDCU_UR_cARI R-index (vendor-ILLEGAL per arb round2,
//! bit91 flip on LDC-idx donor = unrecognized uC op), LDCU UR-index widths
//! (cAURI territory = parked-152 domain). Compose: key LDC_R_cARI disjoint
//! from every parked patch 138..165 (machine-checked).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn enc_res(t: &IsaTable, text: &str) -> bool {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).is_ok()
}
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    cubit::printer::to_sass(&d).split("/* @sched").next().unwrap().trim().to_string()
}
fn dec_res(idx: &DecodeIndex, w: u128, t: &IsaTable) -> bool { idx.decode(w, 0, t).is_ok() }
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }

/// t167_1: decode parity vs nvdisasm-13.3 renders (arb round1/2 anchors).
#[test]
fn t167_1_decode_parity() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    let cases = [
        ("000e24000000000000c0000018187b82", "LDC.U8 R24, c[0x3][R24]"),
        ("000e24000000020000c0000018187b82", "LDC.S8 R24, c[0x3][R24]"),
        ("000e24000000040000c0000018187b82", "LDC.U16 R24, c[0x3][R24]"),
        ("000e24000000000000c17b0018187b82", "LDC.U8 R24, c[0x3][R24+0x5ec]"),
    ];
    for (hw, want) in cases {
        assert_eq!(dec(&idx, w(hw), &t), want, "decode {hw}");
    }
}

/// t167_2: encode byte-exact on the payload [0:96) vs the arbitrated window
/// law (donor payload bits exact; sched [96:128) masked out).
#[test]
fn t167_2_encode_payload_exact() {
    let t = t120();
    // LDC.U8 R24, c[0x3][R24] must reproduce the vendor donor payload.
    assert_eq!((enc(&t, "LDC.U8 R24, c[0x3][R24]") & ((1u128<<96)-1)),
               (w("000e24000000000000c0000018187b82") & ((1u128<<96)-1)), "hi+lo payload");
    assert_eq!(enc(&t, "LDC.U8 R3, c[0x0][R5+0x5ec]") & ((1u128<<96)-1),
               ((0x0000u128) | (0xb82) | (3<<16) | (5<<24) | (0x7<<12) | (0x5ecu128<<38)), "R3/R5/0x5ec");
    assert_eq!(enc(&t, "LDC.U16 R3, c[0x0][R5+0x5ec]") & ((1u128<<96)-1),
               ((0x0400u128<<64) | 0xb82 | (3<<16) | (5<<24) | (0x7<<12) | (0x5ecu128<<38)), "U16 width bit");
    assert_eq!(enc(&t, "LDC.S8 R3, c[0x0][R5+0x5ec]") & ((1u128<<96)-1),
               ((0x0200u128<<64) | 0xb82 | (3<<16) | (5<<24) | (0x7<<12) | (0x5ecu128<<38)), "S8 width bit");
}

/// t167_3: roundtrip encode->decode->encode is a fixed point (payload).
#[test]
fn t167_3_roundtrip_fixed_point() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    for text in ["LDC.U8 R3, c[0x0][R5+0x5ec]", "LDC.S8 R10, c[0x2][R0]",
                 "LDC.U16 R8, c[0x1][R17+0x10]", "@P0 LDC.U8 R2, c[0x0][R5]",
                 "LDC.64 R24, c[0x3][R24]", "LDC R2, c[0x2][R6+0x10]"] {
        let a = enc(&t, text);
        let s = dec(&idx, a, &t);
        let b = enc(&t, &s);
        assert_eq!(a, b, "fixed point for {text} (via {s})");
        assert_eq!(s, text, "canonical text for {text} (via {s})");
    }
}

/// t167_4: fail-closed preserved -- vendor-illegal/absent forms stay holes.
#[test]
fn t167_4_fail_closed_preserved() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    // 2026-08-26 compose: S16 flips to LIVE coverage (BUG-172, arb172
    // vendor width-walk); LDC.128-cARI stays vendor-INVALID.
    assert!(!enc_res(&t, "LDC.128 R4, c[0x0][R5]"), "LDC.128-cARI must stay fail-closed");
    let s16w = enc(&t, "LDC.S16 R3, c[0x0][R5+0x5ec]");
    assert_eq!(s16w, 0x60000017b0005037b82u128,
               "S16 encode byte pin");
    // decode: w6/w7 (INVALID) stay fail-closed; w3 is S16 (legal post-172).
    assert!(!dec_res(&idx, w("000e240000000c0000c0000018187b82"), &t), "INVALID6 decode");
    assert!(!dec_res(&idx, w("000e240000000e0000c0000018187b82"), &t), "INVALID7 decode");
    let s16d = idx.decode(w("000e24000000060000c0000018187b82"), 0, &t)
        .map(|d| cubit::printer::to_sass(&d));
    assert_eq!(s16d.as_deref().ok(), Some("LDC.S16 R24, c[0x3][R24]"), "S16 decode");
    // LDCU R-index (vendor-ILLEGAL per arb round2) stays fail-closed.
    assert!(!dec_res(&idx, w("000e24000800000000c0000018187b82"), &t), "LDCU.R-idx decode");
}

/// t167_5 (polygon): table state -- clone provenance, width bits, vm/fields
/// == donor '64', pre-existing groups untouched.
#[test]
fn t167_5_polygon() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    let cari = j.pointer("/instructions/LDC_R_cARI/mod_groups").unwrap();
    let donor_ab = cari["64"]["and_base"].as_str().unwrap();
    assert_eq!(donor_ab, "0x0000000000000a000000000000000b82", "donor drift");
    for (g, wbits) in [("U8", 0u128), ("S8", 1u128), ("U16", 2u128)] {
        let row = &cari[g];
        assert_eq!(row["_src"].as_str().unwrap(), "bug167-2026-08-26");
        let ab = u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!((ab >> 73) & 0x7, wbits, "{g} width bits");
        assert_eq!((ab >> 91) & 0x1, 0, "LDC (not LDCU) discriminator");
        let f: Vec<_> = row["fields"].as_array().unwrap().iter().map(|f| f["extraction"].as_str().unwrap()).collect();
        assert_eq!(f, ["guard", "reg", "sub_r1", "cm16_off", "reuse"], "clone of '64': {f:?}");
        assert_eq!(row["variable_mask"], cari["64"]["variable_mask"], "vm == live donor");
    }
    // 2026-08-26 compose: S16 l anded via BUG-172 (its own header told this
    // suite's negatives to flip). Clone-shape guard, S16 included:
    let s16 = &cari["S16"];
    assert_eq!(u128::from_str_radix(s16["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap() >> 73 & 0x7, 3, "S16 width bits");
    assert_eq!(s16["variable_mask"], cari["64"]["variable_mask"], "S16 vm == live donor");
    let s16f: Vec<_> = s16["fields"].as_array().unwrap().iter().map(|f| f["extraction"].as_str().unwrap()).collect();
    assert_eq!(s16f, ["guard", "reg", "sub_r1", "cm16_off", "reuse"], "S16 clone of '64': {s16f:?}");
}
