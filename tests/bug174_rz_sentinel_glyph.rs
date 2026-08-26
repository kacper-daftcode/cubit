//! BUG-174 (F2-iter83, front2/blind; queue = fleet note 173 sec.7(b)
//! "174-kand LDC-idx + idx=0xff RZ-sentinel", note 175 sec.6(d)/8(d)
//! "174-kand = lane F2"): LDC-family zero-offset const address prints the
//! RZ sentinel glyph (render-parity, printer-only).
//!
//! Triage note (duplicate-split): the ORIGINAL 174-kand fabrication
//! (`LDC.U8 R24, c[0x3][RZ]` -> `LDC R24, 0x30000` via the width-blind
//! flat-II junk cluster LDC_R_II / LDC.64_R_cAI / LDC.64_R_II /
//! LDC.64_P_R_cAI / LDCU.*_UR_* era masks) is ALREADY fixed by parked
//! BUG-165 (patch165.py deletes those 14 junk keys on sm120 and adds
//! canonical width groups; machine-verified in work/bug174: patched table
//! decodes W1 as `LDC.U8 R24, c[0x3][0x0]`).  What REMAINED open is the
//! render glyph at offset == 0: cubit printed `c[0x4][0x0]`.
//!
//! Vendor law (hexdb 32.2M words, work/bug174/census174.json): the LDC/LDCU
//! const slot NEVER prints `[0x0]` (0 anchors); every off==0 const address
//! renders as `[RZ]` (12/12 anchors: `LDC.64 Rn, c[0x4][RZ]`, sm_100/103/
//! 103a cutlass/curand).  nvdisasm-13.3.73 arbitration of the U8 sentinel
//! probe (work/bug167/arb/arb167_round2.json, u8_idx255) confirms
//! `LDC.U8 R24, c[0x3][RZ]`.  The idx byte [24:32)==0xff is structurally
//! the RZ sink on every row reaching this printer fallthrough, so the glyph
//! is lawful independent of which row (cAI split-fields / cm16_off / cARI
//! with base_reg==255) won the decode.
//!
//! Fix = printer-only (src/printer.rs format_const_addr): on the R-side
//! const path (`cAI`/`cARI`, key LDC* but not LDCU*), offset==0 prints
//! `c[bank][RZ]` instead of `c[0x0]`.  Tables/parser/encoder untouched;
//! the `[RZ]` glyph re-encodes byte-exact (cARI/cAI envelope both accept
//! it, verified t174_3).  LDCU keeps the `[URZ]` cm17 convention; non-LDC
//! const users keep `[0x0]` (zero anchors, out of law's scope).
//! Compose: 174 then parked-165 yields vendor-exact `LDC.U8 R24, c[0x3][RZ]`
//! on sm120 (compose preview in work/bug174), and the 10 live corpus lines
//! (sm103 cutlass) flip to the vendor text at once on this fix alone.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    cubit::printer::to_sass(&d).split("/* @sched").next().unwrap().trim().to_string()
}
fn enc_word(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).map(|w| w & !SCHED).expect("encode")
}
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }

/// Vendor corpus anchors (work/bug174/census174.json; hexdb):
/// `LDC.64 Rn, c[0x4][RZ]` on 3 archs (12 raw lines, 3 uniq words).
const ANCHORS: &[(&str, &str)] = &[
    ("000e220000000a0001000000ff1e7b82", "LDC.64 R30, c[0x4][RZ]"),
    ("000e220000000a0001000000ff087b82", "LDC.64 R8, c[0x4][RZ]"),
    ("000e220000000a0001000000ff0c7b82", "LDC.64 R12, c[0x4][RZ]"),
];

/// t174_1: zero-offset anchors render vendor-exact `[RZ]`.
#[test]
fn t174_1_anchor_set_vendor_exact() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in ANCHORS {
        assert_eq!(dec(&idx, w(hx), &t), *want, "anchor {hx}");
    }
}

/// t174_2: non-zero offsets are unchanged on both tables.
#[test]
fn t174_2_nonzero_offset_unchanged() {
    let t1 = t103();
    let idx1 = DecodeIndex::build(&t1);
    // sm103 corpus LDC: `LDC R1, c[0x0][0x37c]`
    assert_eq!(dec(&idx1, w("000fe200000008000000df00ff017b82"), &t1),
               "LDC R1, c[0x0][0x37c]");
    let t2 = t120();
    let idx2 = DecodeIndex::build(&t2);
    // LDCU non-zero (173 battery control): `LDCU.64 UR8, c[0x0][0x358]`
    assert_eq!(dec(&idx2, w("000ea20008000a0000006b00ff0877ac"), &t2),
               "LDCU.64 UR8, c[0x0][0x358]");
}

/// t174_3: both glyphs encode byte-exact to the anchor word (`[RZ]` roundtrip
/// is safe: the encoder routes it to the cARI envelope with the same bits).
#[test]
fn t174_3_encode_glyph_byte_exact() {
    let t = t103();
    let want = enc_word(&t, "LDC.64 R30, c[0x4][0x0] ;");
    assert_eq!(enc_word(&t, "LDC.64 R30, c[0x4][RZ] ;"), want);
    // and equals the raw anchor insn bits (sans sched):
    assert_eq!(want, w("0000000000000a0001000000ff1e7b82"));
}

/// t174_4: decode->render is a fixed point for the new glyph.
#[test]
fn t174_4_render_fixed_point() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in ANCHORS {
        let again = enc_word(&t, &format!("{want} ;"));
        assert_eq!(dec(&idx, again, &t), *want, "fixed point {hx}");
    }
}

/// t174_5: the W1 sentinel-U8 fabrication on the sm120 MAIN table is the
/// parked-165 domain and MUST stay pre==post here (no scope creep).
#[test]
fn t174_5_parked165_domain_unchanged() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    // work/bug167/arb/arb167_round2.json u8_idx255:
    assert_eq!(dec(&idx, w("000e24000000000000c00000ff187b82"), &t),
               "LDC R24, 0x30000");
}

/// t174_6: LDCU (UR-dest) off==0 keeps its legacy/correct URZ-domain print;
/// the flip is scoped to the R-dest LDC family.  (The 152-domain cAURI
/// fabrication on this synth word is parked, pinned pre==post by t173_5.)
#[test]
fn t174_6_ldcu_scoped_out() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&idx, w("000f220008000a0000004b00050577ac"), &t),
               "LDCU.64 UR0, c[0x0][0x0], 0x0, 0x0, UR0");
}
