//! BUG-172 (iter80, loop5/blind front-MAIN; queue item = fleet note 167
//! sec.7(b) "172-kand b4-fill"): LDC/LDCU S16 (width=3 @[73:76)) family hole.
//!
//! Census-first (work/i80/census172.json): S16 has ZERO anchors in the 32.2M
//! hexdb (sm_100/100a/103/103a) and the sm120 nv-harvest; siblings exist
//! (LDC.U8/S8/U16 = 1507/18/567, LDCU.U8/S8/U16 = 4966/302/494).
//! Arbitration (nvdisasm 13.3.73, work/i80/arb/arb172_widthwalk.json, real
//! vendor anchors with width walk w0..w7): S16 legal on BOTH arches for
//! plain cAI, indexed cARI and LDCU-cAI shapes; operand render preserved;
//! R-forms keep INVALID6/INVALID7; LDCU plain w6 = LDCU.128 (legal).
//! Pre-fix measured on ctl 8e02983 (work/i80/prefix172.txt): encode of all
//! three S16 shapes = hard fail-closed (BUG-132 mod-drop guard), decode of
//! w3 words = "no instruction matches" fail-closed, ZERO fabrication.
//! Fix = data-only (work/i80/patch172.py): clone donor rows with ONLY the
//! width bits swapped to 3 (sm120: '64' donors x3 keys; sm103a: S8-width
//! sibling for the cAI keys, '64' for cARI), fields/vmask verbatim.
//! Out of scope (owned by parked work): LDCU_UR_cAURI (parked-152 domain),
//! LDCU_UR_cARI R-index (173-kand, vendor-ILLEGAL), sm103a cARI U8/S8/U16
//! family (new 17x-kand), LDC.128-cARI (w6 idx = vendor INVALID).
//! Compose note: additions are GROUP-level (`S16`), disjoint from parked
//! 152..171 (their LDC patches add U8/S8/U16 groups only); after ff of
//! 167+172 the parked test bug167 t167_4 S16 fail-closed assertions must
//! flip (re-pin with attribution, see report 172.md sec.7).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const PAYLOAD: u128 = (1u128 << 96) - 1;
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
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

/// t172_1: decode parity vs nvdisasm-13.3 renders on sm120 (arb172 anchors).
#[test]
fn t172_1_decode_parity_sm120() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    let cases = [
        ("000e22000000060000010b80ff037b82", "LDC.S16 R3, c[0x0][0x42e]"),
        ("000e24000000060000c0000018187b82", "LDC.S16 R24, c[0x3][R24]"),
        ("000e2200080006000000bc80ff0477ac", "LDCU.S16 UR4, c[0x0][0x5e4]"),
        ("000e22000800060000006b00ff0877ac", "LDCU.S16 UR8, c[0x0][0x358]"),
        // sibling-width controls (unchanged rows, unchanged renders):
        ("000e220000000a0000010b80ff037b82", "LDC.64 R3, c[0x0][0x42e]"),
        ("000e240000000a0000c0000018187b82", "LDC.64 R24, c[0x3][R24]"),
    ];
    for (hw, want) in cases {
        assert_eq!(dec(&idx, w(hw), &t), want, "decode sm120 {hw}");
    }
}

/// t172_2: same vendor words under the sm103a table -> identical renders.
#[test]
fn t172_2_decode_parity_sm103a() {
    let t = t103(); let idx = DecodeIndex::build(&t);
    let cases = [
        ("000e22000000060000010b80ff037b82", "LDC.S16 R3, c[0x0][0x42e]"),
        ("000e24000000060000c0000018187b82", "LDC.S16 R24, c[0x3][R24]"),
        ("000e2200080006000000bc80ff0477ac", "LDCU.S16 UR4, c[0x0][0x5e4]"),
    ];
    for (hw, want) in cases {
        assert_eq!(dec(&idx, w(hw), &t), want, "decode sm103a {hw}");
    }
}

/// t172_3: encode payload-exact [0:96) vs the arbitrated flipped anchors.
#[test]
fn t172_3_encode_payload_exact() {
    let t = t120();
    assert_eq!(enc(&t, "LDC.S16 R3, c[0x0][0x42e]") & PAYLOAD,
               w("000e22000000060000010b80ff037b82") & PAYLOAD, "plain payload");
    assert_eq!(enc(&t, "LDC.S16 R24, c[0x3][R24]") & PAYLOAD,
               w("000e24000000060000c0000018187b82") & PAYLOAD, "idx payload");
    assert_eq!(enc(&t, "LDCU.S16 UR4, c[0x0][0x5e4]") & PAYLOAD,
               w("000e2200080006000000bc80ff0477ac") & PAYLOAD, "ldcu payload");
    let t3 = t103();
    assert_eq!(enc(&t3, "LDC.S16 R3, c[0x0][0x42e]") & PAYLOAD,
               w("000e22000000060000010b80ff037b82") & PAYLOAD, "sm103a plain payload");
}

/// t172_4: roundtrip encode->decode->encode fixed point (payload), both arches.
#[test]
fn t172_4_roundtrip_fixed_point() {
    for t in [t120(), t103()] {
        let idx = DecodeIndex::build(&t);
        for text in ["LDC.S16 R3, c[0x0][0x42e]", "LDC.S16 R24, c[0x3][R24]",
                     "LDC.S16 R2, c[0x2][R6]", "LDCU.S16 UR4, c[0x0][0x5e4]",
                     "@P0 LDC.S16 R8, c[0x0][0x110]", "LDCU.S16 UR9, c[0x0][0x3e2]",
                     "LDC.64 R24, c[0x3][R24]"] {
            let a = enc(&t, text);
            let s = dec(&idx, a, &t);
            let b = enc(&t, &s);
            assert_eq!(a, b, "fixed point for {text} (via {s})");
        }
    }
}

/// t172_5: fail-closed preserved -- vendor-INVALID / out-of-scope forms stay holes.
#[test]
fn t172_5_fail_closed_preserved() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    // idx w6/w7 = LDC.INVALID6/INVALID7 (arbitrated): no such table rows.
    assert!(!dec_res(&idx, w("000e240000000c0000c0000018187b82"), &t), "INVALID6 idx");
    assert!(!dec_res(&idx, w("000e240000000e0000c0000018187b82"), &t), "INVALID7 idx");
    // LDCU R-index (vendor-ILLEGAL per arb167 round2 / 173-kand) stays closed, incl. w3:
    assert!(!dec_res(&idx, w("000e24000800060000c0000018187b82"), &t), "LDCU.R-idx S16");
    // LDCU UR-indexed cAURI = parked-152 domain: S16 variant not modelled, stays closed.
    assert!(!dec_res(&idx, w("000f22000800060000004b00050577ac"), &t), "LDCU cAURI S16 (UR-idx)");
    // encode-side: LDCU with R index has no row regardless of width.
    assert!(!enc_res(&t, "LDCU.S16 UR4, c[0x0][R5]"), "LDCU R-idx encode");
    // 128-indexed LDC = vendor INVALID6: encode stays closed.
    assert!(!enc_res(&t, "LDC.128 R4, c[0x0][R5]"), "LDC.128-idx encode");
    let t3 = t103(); let idx3 = DecodeIndex::build(&t3);
    assert!(!dec_res(&idx3, w("000e240000000c0000c0000018187b82"), &t3), "INVALID6 idx sm103a");
    assert!(!dec_res(&idx3, w("000e24000800060000c0000018187b82"), &t3), "LDCU.R-idx S16 sm103a");
}

/// t172_6 (polygon): table state -- donors anchored, S16 = width-swap clone,
/// vm/fields == donor, provenance tags set, all six (arch,key) spots present.
#[test]
fn t172_6_polygon() {
    for (path, key, donor, donor_ab) in [
        ("tables/sm120.json", "LDC_R_cAI",   "64", "0x0000000000000a000000000000000b82"),
        ("tables/sm120.json", "LDC_R_cARI",  "64", "0x0000000000000a000000000000000b82"),
        ("tables/sm120.json", "LDCU_UR_cAI", "64", "0x0000000008000a0000000000ff0077ac"),
        ("tables/sm103a.json", "LDC_R_cAI",   "S8", "0x000e20000000020000000880ff000b82"),
        ("tables/sm103a.json", "LDCU_UR_cAI", "S8", "0x000e22000800020000000000ff0077ac"),
        ("tables/sm103a.json", "LDC_R_cARI",  "64", "0x0000200000000a000000000000007b82"),
    ] {
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mg = j.pointer(&format!("/instructions/{key}/mod_groups")).unwrap();
        let don = &mg[donor];
        assert_eq!(don["and_base"].as_str().unwrap(), donor_ab, "{path} {key}/{donor} drift");
        let row = &mg["S16"];
        assert_eq!(row["_src"].as_str().unwrap(), "bug172-2026-08-26", "{path} {key} src");
        let ab = u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let dab = u128::from_str_radix(donor_ab.trim_start_matches("0x"), 16).unwrap();
        assert_eq!((ab >> 73) & 0x7, 3, "{path} {key}/S16 width bits");
        assert_eq!(ab ^ dab, 3u128 << 73 ^ ((dab >> 73) & 0x7) << 73, "{path} {key}/S16 width-only delta");
        assert_eq!(row["variable_mask"], don["variable_mask"], "{path} {key}/S16 vm == donor");
        assert_eq!(row["fields"].as_array().unwrap().len(), don["fields"].as_array().unwrap().len(),
                   "{path} {key}/S16 fields == donor");
    }
}
