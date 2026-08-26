//! BUG-175 (iter81, loop5/blind front-MAIN; queue item = fleet note 172
//! sec.7(b) "175-kand b4-fill"): sm103a LDC_R_cARI width-mirror U8/S8/U16.
//!
//! Census-first (work/i81/census175.json, regex-fixed full family census,
//! 971,180 rows): indexed LDC forms live ONLY at w4 (126) / w5 (2,964);
//! w0/w1/w2 (U8/S8/U16) idx = ZERO anchors, text grep none => LATENT.
//! Pre-fix on ctl 8e02983 (work/i81/prefix175.txt): encode of all indexed
//! U8/S8/U16 forms = hard fail-closed (BUG-132 guard), decode of vendor
//! w0/w1/w2 words = '?' fail-closed, zero fabrication.
//! Arbitration nvdisasm-13.3.73 on sm_103a (work/i81/arb/arb175_offsetlaw.json
//! + arb175_bankwalk.json, REAL offset anchor flips): U8/S8/U16 indexed LEGAL;
//! idx law = off s16@[38:54), bank u5@[54:59) (bank31 -> 0x1f, bits [59:64)+
//! inert), idx u8@[24:32) with 0xff sentinel (vendor elides to non-idx form).
//! Fix = data-only ADD of 3 groups (work/i81/patch175.py): and_base/vm =
//! width-swap of the '64' donor, fields = canonical carrier cm16_off@38/21
//! (identical to the post-ff target of parked-147/162; existing rows ''/'64'
//! NOT touched -> compose-disjoint with 147/162/172 by construction).
//! Out of scope: cARI ''/'64' carrier repair = parked-162 domain; S16 idx =
//! parked-172 domain; LDCU R-idx = vendor-ILLEGAL (173); cAURI = parked-152.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const PAYLOAD: u128 = (1u128 << 96) - 1;
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

/// t175_1: decode parity vs nvdisasm-13.3 sm_103a renders (arb175 probe words,
/// real-anchor width flips with non-zero offset + bank walk + sentinel).
#[test]
fn t175_1_decode_parity_sm103a() {
    let t = t103(); let idx = DecodeIndex::build(&t);
    let cases = [
        // offset-bearing w0/w1/w2 (arb175 offanch flips):
        ("000e22000000000000009f0003037b82", "LDC.U8 R3, c[0x0][R3+0x27c]"),
        ("000e22000000020000009f0003037b82", "LDC.S8 R3, c[0x0][R3+0x27c]"),
        ("000e22000000040000009f0003037b82", "LDC.U16 R3, c[0x0][R3+0x27c]"),
        // offset-0 w0/w1/w2 (arb172 sm103a:LDC_64_idx flips):
        ("000e24000000000000c0000018187b82", "LDC.U8 R24, c[0x3][R24]"),
        ("000e24000000020000c0000018187b82", "LDC.S8 R24, c[0x3][R24]"),
        ("000e24000000040000c0000018187b82", "LDC.U16 R24, c[0x3][R24]"),
        // bank walk (arb175_bankwalk): bank 2 and the u5 ceiling 31:
        ("000e22000000000000809f0003037b82", "LDC.U8 R3, c[0x2][R3+0x27c]"),
        ("000e22000000000007c09f0003037b82", "LDC.U8 R3, c[0x1f][R3+0x27c]"),
        // sentinel idx=0xff: vendor elides to the non-indexed form:
        ("000e22000000000000009f00ff037b82", "LDC.U8 R3, c[0x0][0x27c]"),
        // unchanged controls (existing ''/'64' rows, renders must NOT move):
        ("000e22000000080000009f0003037b82", "LDC R3, c[0x0][R3+0x27c]"),
        ("000e240000000a0000c0000018187b82", "LDC.64 R24, c[0x3][R24]"),
    ];
    for (hw, want) in cases {
        assert_eq!(dec(&idx, w(hw), &t), want, "decode sm103a {hw}");
    }
}

/// t175_2: encode payload-exact [0:96) vs the arbitrated vendor words.
#[test]
fn t175_2_encode_payload_exact() {
    let t = t103();
    let cases = [
        ("LDC.U8 R3, c[0x0][R3+0x27c]", "000e22000000000000009f0003037b82"),
        ("LDC.S8 R3, c[0x0][R3+0x27c]", "000e22000000020000009f0003037b82"),
        ("LDC.U16 R3, c[0x0][R3+0x27c]", "000e22000000040000009f0003037b82"),
        ("LDC.U8 R24, c[0x3][R24]", "000e24000000000000c0000018187b82"),
        ("LDC.U16 R24, c[0x3][R24]", "000e24000000040000c0000018187b82"),
        ("LDC.U8 R3, c[0x1f][R3+0x27c]", "000e22000000000007c09f0003037b82"),
        ("LDC.U8 R15, c[0x4][R8+0x2a4]", "000e2400000000000100a900080f7b82"),
        // negative offset (vendor s16 carrier): payload-exact vs nvdisasm render
        ("LDC.U8 R3, c[0x0][R3+-0x40]", "000e220000000000003ff00003037b82"),
    ];
    for (text, hw) in cases {
        assert_eq!(enc(&t, text) & PAYLOAD, w(hw) & PAYLOAD,
                   "encode payload {text}");
    }
}

/// t175_3: roundtrip encode->decode->encode fixed point on the new groups.
#[test]
fn t175_3_roundtrip_fixed_point() {
    let t = t103(); let idx = DecodeIndex::build(&t);
    for text in ["LDC.U8 R3, c[0x0][R3+0x27c]", "LDC.S8 R24, c[0x3][R24]",
                 "LDC.U16 R2, c[0x2][R6]", "LDC.U8 R3, c[0x1f][R3+0x27c]",
                 // zero-offset controls through the existing rows:
                 "LDC R24, c[0x3][R24]", "LDC.64 R24, c[0x3][R24]"] {
        let a = enc(&t, text);
        let s = dec(&idx, a, &t);
        let b = enc(&t, &s);
        assert_eq!(a, b, "fixed point for {text} (via {s})");
    }
}

/// t175_4: fail-closed preserved -- vendor-INVALID / out-of-scope stay holes.
/// (invariant class: PASSes on ctl and fix alike)
#[test]
fn t175_4_fail_closed_preserved() {
    let t = t103(); let idx = DecodeIndex::build(&t);
    // idx w6/w7 = LDC.INVALID6/INVALID7 (arbitrated): no table rows.
    assert!(!dec_res(&idx, w("000e220000000c0000009f0003037b82"), &t), "INVALID6 idx");
    assert!(!dec_res(&idx, w("000e220000000e0000009f0003037b82"), &t), "INVALID7 idx");
    // S16-idx (w3) = parked-172 domain: must stay a hole until ff.
    assert!(!dec_res(&idx, w("000e22000000060000009f0003037b82"), &t), "S16 idx pre-172");
    // junk above the vendor bank window [59:64): vendor-inert, we stay closed.
    assert!(!dec_res(&idx, w("000e22000000000000809f0003037b82".replace("0080","4080").as_str()), &t),
            "bit62 junk (vendor-inert) stays fail-closed");
    // LDCU R-index = vendor-ILLEGAL (arb167 r2 / 173): closed regardless of width.
    assert!(!dec_res(&idx, w("000e24000800000000c0000018187b82"), &t), "LDCU.R-idx U8");
    // encode-side: 128-idx vendor-INVALID; LDCU R-idx has no row.
    assert!(!enc_res(&t, "LDC.128 R4, c[0x0][R5]"), "LDC.128-idx encode");
    assert!(!enc_res(&t, "LDCU.U8 UR4, c[0x0][R5]"), "LDCU R-idx encode");
}

/// t175_5 (polygon): table state -- donor intact, U8/S8/U16 = '64' width-swap
/// and_base + verbatim vm + canonical fields, provenance tags on every field.
#[test]
fn t175_5_polygon() {
    let path = "tables/sm103a.json";
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mg = j.pointer("/instructions/LDC_R_cARI/mod_groups").unwrap();
    let don = &mg["64"];
    let donor_ab: u128 = 0x0000200000000a000000000000007b82;
    assert_eq!(don["and_base"].as_str().unwrap(),
               format!("0x{donor_ab:032x}"), "donor '64' and_base drift");
    // existing groups preserved with their pre-patch fields (162/147 domain):
    for g in ["", "64"] { assert!(mg.get(g).is_some(), "group {g} preserved"); }
    for (grp, wd) in [("U8", 0u128), ("S8", 1), ("U16", 2)] {
        let row = &mg[grp];
        assert_eq!(row["_src"].as_str().unwrap(), "bug175-2026-08-26", "{grp} src");
        let ab = u128::from_str_radix(
            row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!((ab >> 73) & 0x7, wd, "{grp} width bits");
        assert_eq!(ab ^ donor_ab, (wd << 73) ^ (5u128 << 73), "{grp} width-only delta");
        assert_eq!(row["variable_mask"], don["variable_mask"], "{grp} vm == donor");
        let fs = row["fields"].as_array().unwrap();
        let sig: Vec<(u64, u64, &str)> = fs.iter().map(|f| {
            (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap(),
             f["extraction"].as_str().unwrap())
        }).collect();
        assert_eq!(sig, vec![(16, 8, "reg"), (24, 8, "sub_r1"), (38, 21, "cm16_off")],
                   "{grp} canonical carrier fields");
        for f in fs { assert_eq!(f["_src"].as_str().unwrap(), "bug175-2026-08-26"); }
    }
}
