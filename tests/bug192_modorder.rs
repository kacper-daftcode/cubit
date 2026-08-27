//! BUG-192 / b11 RP-2 render-parity: modifier PRINT order vs nvdisasm.
//!
//! Two glyph classes where the stable alphabetical table-key order leaked
//! into the render while vendor (nvdisasm-13.3.73) prints a semantic order:
//!   * REDUX/CREDUX: reduction function BEFORE data type — vendor census
//!     9,190 words (bug142 hexdb all.tsv): REDUX.SUM.S32 x426, MAX.S32 x567,
//!     MIN.S32 x843, MIN x226, OR x7194, XOR x1; zero .S32-first.  The old
//!     render was `REDUX.S32.SUM` (key "S32,SUM").
//!   * UTCCP: direction pair T.S BEFORE 2CTA and the shape — BUG-190
//!     witness corpus (ptxas 13.3 tcgen05.cp 12/12 forms, arb190a.json):
//!     "UTCCP.T.S.2CTA.128dp128bit tmem[UR0], gdesc[UR4]".
//!     The old render was `UTCCP.128dp128bit.S.T`.
//! Encoding is unchanged (printer-only); the assembler mod lookup is
//! order-independent (extract_mod_group sorts), so both spellings assemble.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0x1FFFFu128 << (64 + 41);

fn table(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}

fn render(t: &IsaTable, idx: &DecodeIndex, word: u128, addr: u32) -> String {
    idx.decode(word, addr, t)
        .map(|d| cubit::printer::to_sass(&d))
        .expect("decode")
}

fn enc(t: &IsaTable, text: &str, addr: u32) -> u128 {
    let insn = parse_sass(text, addr).expect("parse");
    encode_instruction(&insn, t).expect("encode")
}

/// Vendor corpus words (bug142 hexdb; sm_103 rows decode on the sm103a table).
/// `(lo64, hi64, expected-text-prefix)`.
const REDUX_ANCHORS: &[(u64, u64, &str)] = &[
    (0x000000000a0473c4, 0x000e24000000c200, "REDUX.SUM.S32 UR4, R10"),
    (0x00000000100473c4, 0x000e24000000c200, "REDUX.SUM.S32 UR4, R16"),
];
const CREDUX_ANCHORS: &[(u64, u64, &str)] = &[
    (0x00000000040572cc, 0x000fe20000000200, "CREDUX.MAX.S32 UR5, R4"),
    (0x00000000040572cc, 0x000fe20000008000, "CREDUX.MIN UR5, R4"),
];

#[test]
fn t192_1_redux_sum_s32_order() {
    let t = table("sm103a");
    let idx = DecodeIndex::build(&t);
    for &(lo, hi, want) in REDUX_ANCHORS {
        let got = render(&t, &idx, ((hi as u128) << 64) | (lo as u128), 0);
        assert!(got.starts_with(want),
            "REDUX render must print op before type: want [{want}], got [{got}]");
        assert!(!got.starts_with("REDUX.S32."), "old order must be gone: {got}");
    }
}

#[test]
fn t192_2_credux_order() {
    let t = table("sm103a");
    let idx = DecodeIndex::build(&t);
    for &(lo, hi, want) in CREDUX_ANCHORS {
        let got = render(&t, &idx, ((hi as u128) << 64) | (lo as u128), 0);
        assert!(got.starts_with(want),
            "CREDUX render must print op before type: want [{want}], got [{got}]");
    }
}

#[test]
fn t192_3_redux_roundtrip_byte_exact() {
    let t = table("sm103a");
    let idx = DecodeIndex::build(&t);
    for &(lo, hi, _) in REDUX_ANCHORS.iter().chain(CREDUX_ANCHORS.iter()) {
        let word = ((hi as u128) << 64) | (lo as u128);
        let text = render(&t, &idx, word, 0);
        let back = enc(&t, &text, 0);
        assert_eq!(back & !SCHED, word & !SCHED,
            "roundtrip payload must be byte-exact: {text}");
    }
}

/// BUG-190 witness words (ptxas 13.3 tcgen05.cp), nvdisasm text in order T.S.
/// Compose note: operand glyphs are parked-190's domain (main pre-190
/// renders the UR0-authored sentinel as `tmem[URZ]`; 190's pins own the
/// operand spelling). 192 pins the MOD ORDER only, so the test passes both
/// pre- and post-190-landing.
const UTCCP_ANCHORS: &[(u64, u64, u32, &str)] = &[
    (0x00000004ff0079e7, 0x0033d80008000000, 80,  "UTCCP.T.S "),
    (0x00000004ff0079e7, 0x0011d80009100000, 560, "UTCCP.T.S.4x32dp128bit "),
    (0x00000004ff0079e7, 0x0011d80009300000, 560, "UTCCP.T.S.2CTA.4x32dp128bit "),
    (0x00000004ff0079e7, 0x0011d80008380000, 176, "UTCCP.T.S.2CTA.128dp128bit "),
];

#[test]
fn t192_4_utccp_ts_order() {
    let t = table("sm103a");
    let idx = DecodeIndex::build(&t);
    for &(lo, hi, addr, want) in UTCCP_ANCHORS {
        let got = render(&t, &idx, ((hi as u128) << 64) | (lo as u128), addr);
        assert!(got.starts_with(want),
            "UTCCP render must match nvdisasm mod order: want prefix [{want}], got [{got}]");
        assert!(!got.starts_with("UTCCP.S") && !got.contains(".S.T"),
            "old S.T order must be gone: {got}");
    }
}

#[test]
fn t192_5_both_spellings_assemble_identically() {
    // The lookup is order-independent (extract_mod_group sorts); authoring the
    // old key order must keep producing the same payload as the vendor order.
    let t = table("sm103a");
    for (a, b) in [
        ("REDUX.S32.SUM UR4, R10 ;", "REDUX.SUM.S32 UR4, R10 ;"),
        ("UTCCP.S.T.4x32dp128bit tmem[UR0], gdesc[UR4] ;",
         "UTCCP.T.S.4x32dp128bit tmem[UR0], gdesc[UR4] ;"),
    ] {
        let wa = enc(&t, a, 0) & !SCHED;
        let wb = enc(&t, b, 0) & !SCHED;
        assert_eq!(wa, wb, "spellings must encode identically: {a} vs {b}");
    }
}

#[test]
fn t192_6_neg_control_sibling_orders_untouched() {
    // Neighbouring arm families keep their established prints.
    let t = table("sm103a");
    let idx = DecodeIndex::build(&t);
    // LOP3.LUT.PAND stays PAND-after-LUT (BUG-?? b11 RP-1 arm, key "LUT,PAND").
    // REDUX.OR alone has no second mod to reorder; must still print OR.
    let word = (0x000e24000000c200u128 << 64) | 0x000000000a0473c4;
    let text = render(&t, &idx, word, 0);
    assert!(text.starts_with("REDUX.SUM.S32"), "sanity: {text}");
    // The REDUX/CREDUX arm must not touch unrelated families: IMAD.WIDE.U32
    // type-order must stay (WIDE(3) < U32(5)).
    let t2 = "IMAD.WIDE.U32 R4, R5, R6, RZ ;";
    let back = enc(&t, t2, 0);
    let re = render(&t, &idx, back, 0);
    assert!(re.starts_with("IMAD.WIDE.U32"), "IMAD order untouched: {re}");
}
