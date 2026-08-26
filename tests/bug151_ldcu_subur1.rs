//! BUG-151 (iter71, follow-up of BUG-147 section 5 "LDCU_UR_cAI['']
//! sub_ur1@24/9, 8,108 anchors" / BUG-149 section 5): the no-width LDCU row
//! on sm103a carried a 9-bit sub_ur1 window [24:33) whose 9th bit (bit32)
//! belongs to the neighbour fixed-0 space, and the printer dropped the UR
//! index of c[bank][UR+off] const-addr forms entirely.
//!
//! Census-first (work/i71/census151.json, ur_indexed101.json; vendor hexdb
//! ~30.4M lines, F2-iter67 build): 214,590 bare-LDCU corpus anchors:
//!   (a) 214,489 plain  `LDCU URn, c[0x0][0xOFF]`   -- window value 255
//!       (URZ sentinel) on ALL, bit32 == 0 on ALL;
//!   (b) 101 UR-indexed `LDCU URn, c[0x0][URn+0xOFF]` (6 cubins, arch mix
//!       sm_100/100a/103/103a; CUTLASS blackwell + cublasLt + cusparse) --
//!       window value == vendor UR numeral on ALL (hist 4..77, always
//!       < 256, so 8 bits suffice and UR77 proves >63 reach), bit32 == 0 on
//!       ALL, vendor offset == cm16_off on ALL.
//! bits [24:32) are the true UR numeral with URZ=255 sentinel; bit32 is
//! never carried by any witness. Narrowing to 8 bits turns bit32 into a
//! match-fixed-0 position (no field cover, vmask-0, and_base-0): post-fix
//! bit32=1 words leave the row and fail closed with zero corpus match-loss.
//!
//! Printer companion (same commit): format_const_addr ignored SubUR token
//! fields, so class (b) rendered UR-dropped as `c[0x0][0x258]` plus an
//! !rsd[25:0,27:0,...] roundtrip-residue trailer (pre-fix empirical probe
//! work/i71/p1: CLI render and libcublasLt.so.539 corpusab lines). Vendor
//! arbitration: nvdisasm-13.3 on our re-encoded words prints the identical
//! UR-indexed forms (work/i71/p2: 6/6 author forms byte-exact vs hexdb
//! anchors).
//!
//! Encode was correct all along: op_sub_ureg defaults the missing UR to the
//! 255 sentinel, so the 214k plain class round-trips byte-exact across the
//! narrowing (battery invariant pre==fix, work/i71/battery*).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::{Extraction, IsaTable};

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn parts(lo: u64, hi32: u32) -> u128 { (lo as u128) | ((hi32 as u128) << 64) }

// Live vendor witnesses of the UR-indexed form (hexdb corpus anchors;
// libcusparse.319 / cublasLt.539 / CUTLASS 70/74/77 cubins).
const WITNESS_UR: &[(u64, u32, &str)] = &[
    (0x00004b00050577ac, 0x08000800, "LDCU UR5, c[0x0][UR5+0x258]"),
    (0x00004a80080877ac, 0x08000800, "LDCU UR8, c[0x0][UR8+0x254]"),
    (0x00004a800e0e77ac, 0x08000800, "LDCU UR14, c[0x0][UR14+0x254]"),
    // UR77: the UR numeral exceeds 63 -- guards the full 8-bit width and
    // refutes any 63-saturated URZ-corner model.
    (0x000054804d4d77ac, 0x08000800, "LDCU UR77, c[0x0][UR77+0x2a4]"),
];

// Plain-form anchors: URZ sentinel (255) in the window, never UR-printed.
const WITNESS_PLAIN: &[(u64, u32, &str)] = &[
    (0x0000ae00ff0477ac, 0x08000800, "LDCU UR4, c[0x0][0x570]"),
    (0x0000b180ff0477ac, 0x08000800, "LDCU UR4, c[0x0][0x58c]"),
    // .64 sibling row has no sub_ur field at all -- invariant by construction.
    (0x00006b00ff0677ac, 0x08000a00, "LDCU.64 UR6, c[0x0][0x358]"),
];

#[test]
fn t151_1_witness_decode_vendor_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in WITNESS_UR {
        let got = dec(&t, &idx, parts(*lo, *hi32));
        assert_eq!(&got, want, "UR-indexed decode must match vendor");
    }
}

#[test]
fn t151_2_witness_encode_byte_exact() {
    let t = t103a();
    for (lo, hi32, text) in WITNESS_UR {
        assert_eq!(enc(&t, text), parts(*lo, *hi32), "encode parity: {text}");
    }
    // text -> word -> text fixed point on the author forms
    let idx = DecodeIndex::build(&t);
    for (_, _, text) in WITNESS_UR {
        assert_eq!(&dec(&t, &idx, enc(&t, text)), text);
    }
}

#[test]
fn t151_3_plain_sentinel_invariant() {
    // The 214k-line plain class: URZ sentinel 255 must decode without a UR
    // bracket and re-encode byte-exactly (roundtrip through the no-UR text).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in WITNESS_PLAIN {
        let got = dec(&t, &idx, parts(*lo, *hi32));
        assert_eq!(&got, want, "plain-form decode drifted (URZ sentinel)");
        if !want.starts_with("LDCU.64") {
            assert_eq!(enc(&t, want), parts(*lo, *hi32), "encode parity: {want}");
        }
    }
}

#[test]
fn t151_4_table_class_narrowed() {
    // LDCU_UR_cAI[""] sub_ur1@24 is 8 bits wide (was 9). On this baseline
    // (c9ef102 + patch151) it is the ONLY sub_ur*@24 field left in the
    // sm103a table; the assertion is scope-tight to the LDCU row so parked
    // siblings (patch143/149 row sets) cannot collide at ff replay.
    let t = t103a();
    let g = &t.entries["LDCU_UR_cAI"].mod_groups[""];
    let mut n = 0usize;
    for f in &g.fields {
        if matches!(f.extraction, Extraction::SubUR(1)) && f.shift == 24 {
            n += 1;
            assert_eq!(f.bits, 8, "sub_ur1@24 must be narrowed to 8 bits");
        }
    }
    assert_eq!(n, 1, "exactly one sub_ur1@24 field in LDCU_UR_cAI[\"\"]");
    // class sweep: no 9-bit sub_ur* window at shift 24 anywhere in sm103a
    for (key, ins) in &t.entries {
        for (gname, g) in &ins.mod_groups {
            for f in &g.fields {
                let is_subur = matches!(f.extraction,
                    Extraction::SubUR(_) | Extraction::SubURShr(..));
                if is_subur && f.shift == 24 && f.bits == 9 {
                    panic!("9-bit sub_ur*@24 remains: {key}[{gname}]");
                }
            }
        }
    }
}

#[test]
fn t151_5_bit32_fail_closed() {
    // Crafted (synthetic): plain witness with bit32 forced. Post-fix bit32
    // is match-fixed-0 (no field cover), so the word must leave the row --
    // fail closed (no match), never silently decode as the plain LDCU form.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let (lo, hi32, _) = WITNESS_PLAIN[0];
    let mut w = parts(lo, hi32);
    w |= 1u128 << 32;
    match idx.decode(w, 0, &t) {
        Err(_) => {} // canonical fail-closed surface
        Ok(d) => {
            let got = cubit::printer::to_sass(&d);
            assert!(!got.starts_with("LDCU UR4, c[0x0][0x570]"),
                    "bit32=1 silently matched the plain row: {got}");
        }
    }
}

#[test]
fn t151_6_ur63_wide_corner() {
    // Crafted (synthetic, rule-arbitrated): with the 8-bit-wide field a
    // window value of 63 is the real UR63 (mirrors format_auri_uronly's
    // wide rule), while 255 stays the URZ sentinel (no UR bracket).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let (lo, hi32, _) = WITNESS_UR[0]; // sub_ur1 window value 5
    let w63 = (parts(lo, hi32) & !(0xffu128 << 24)) | (63u128 << 24);
    assert_eq!(dec(&t, &idx, w63), "LDCU UR5, c[0x0][UR63+0x258]");
    let w255 = (parts(lo, hi32) & !(0xffu128 << 24)) | (255u128 << 24);
    assert_eq!(dec(&t, &idx, w255), "LDCU UR5, c[0x0][0x258]");
}
