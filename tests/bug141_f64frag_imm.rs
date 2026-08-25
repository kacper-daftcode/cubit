//! BUG-141 (b4/b11 lane, follow-up of BUG-140 section 7): the
//! MUFU_R_II::RCP64H and FCHK_P_R_II table rows carried a harvest-era
//! scatter of the immediate window (imm_shr1/3/4/5 pieces with holes at
//! imm bits 0,2,20..25). The immediate of these f64-fragment forms is in
//! fact a full 32-bit float fragment at word bits [32,64): MUFU.RCP64H
//! holds the HIGH half of an f64 (extraction f64hi), FCHK holds an f32
//! (extraction f32cast for the value-semantic integer spelling). nvdisasm
//! renders integral fragments as plain integers ("MUFU.RCP64H R5, 6890496"
//! == f64 6890496.0's high half 0x415a4900; "FCHK P1, R0, 6890499" ==
//! f32 6890499.0 bits 0x4ad24806) and non-integral ones as %.20g floats.
//!
//! Pre-fix consequences (BUG-140 census, corpus anchors x15+x15):
//!   decode side: only the !rsd overlay kept render-parity
//!     ("6890496 !rsd[51:1,52:1,54:1,56:1]");
//!   encode side: the author text "6890496" exceeded the scatter union
//!     0xffffa, silently re-issued as 0x92400 (ctl legacy) - the word had
//!     imm bits 21/22 DROPPED.
//!
//! Post-fix: full-window f64hi/f32cast fields; and_base window-region
//! residue cleared so arbitrary authored integers are not polluted
//! (encode of "1" must produce f64hi(1.0)=0x3ff00000, not bit30-or-INF);
//! !rsd passthrough spelling of the same value keeps encoding byte-exact.
//!
//! Evidence (corpus census 2026-08-25, /root/blindlab/work/bug141):
//!   MUFU.RCP64H int-imm words  0x415a4900 / 0x415a593c / 0x40240000 (x24/x6/x60)
//!   FCHK int-imm words         0x4ad24806 / 0x4ad2c9e2 / 0x41200000 (x24/x6/x52)
//!   float-form words           0x422fffef(f64hi) / 0x517fff80(f32) etc.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

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

// (text, low64, high64 low32 bits) — vendor witnesses, sm_103 corpus.
const CASES: &[(&str, u64, u32)] = &[
    ("MUFU.RCP64H R5, 6890496",  0x415a490000057908, 0x00001800),
    ("MUFU.RCP64H R23, 6907120", 0x415a593c00177908, 0x00001800),
    ("MUFU.RCP64H R15, 10",      0x40240000000f7908, 0x00001800),
    ("MUFU.RCP64H R25, 6.87189196800000000000e+10", 0x422fffef00197908, 0x00001800),
    ("MUFU.RCP64H R3, 2.23463412221201359600e+153", 0x5fc5555500037908, 0x00001800),
    ("MUFU.RCP64H R15, 4.29496524800000000000e+09", 0x41efffff000f7908, 0x00001800),
    ("MUFU.RCP64H R15, 4.29494272000000000000e+09", 0x41effff4000f7908, 0x00001800),
    ("FCHK P1, R0, 6890499",     0x4ad2480600007902, 0x00020000),
    ("FCHK P1, R11, 6907121",    0x4ad2c9e20b007902, 0x00020000),
    ("FCHK P0, R0, 10",          0x4120000000007902, 0x00000000),
    ("FCHK P1, R25, 6.87189524480000000000e+10", 0x517fff8019007902, 0x00020000),
    ("FCHK P0, R0, 3.07445743724422758400e+18",  0x5e2aaaab00007902, 0x00000000),
];

#[test]
fn bug141_encode_byte_exact_vendor() {
    let t = t103a();
    for (text, lo, hi32) in CASES {
        let got = enc(&t, text);
        let want = (*lo as u128) | ((*hi32 as u128) << 64);
        assert_eq!(got, want, "encode byte-exact: {text}");
    }
}

#[test]
fn bug141_decode_parity_no_rsd_roundtrip() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi32) in CASES {
        let w = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = dec(&t, &idx, w);
        assert!(!got.contains("rsd"), "no rsd residue after fix: {got}");
        // re-encode of the decoded spelling is byte-exact
        let re = enc(&t, &got);
        assert_eq!(re, w, "roundtrip byte-exact for decoded '{got}'");
        // integer spellings match nvdisasm exactly (floats print %.20g-trimmed;
        // their byte round-trip above is the hard gate)
        if !text.contains('e') {
            assert_eq!(got, *text, "decode spelling == nvdisasm");
        }
    }
}

#[test]
fn bug141_and_base_no_window_pollution() {
    let t = t103a();
    // f64hi(1.0) = 0x3ff00000: pre-fix and_base would have OR'd word bit 62
    // (0x40000000 in the top half, f64 INF territory). The repaired row keeps
    // the window pure.
    let w = enc(&t, "MUFU.RCP64H R5, 1");
    assert_eq!((w >> 32) as u32, 0x3ff00000, "MUFU f64hi window unpolluted");
    // f32(3.0) = 0x40400000 through the value-cast int path of FCHK.
    let w = enc(&t, "FCHK P0, R0, 3");
    assert_eq!((w >> 32) as u32, 0x40400000, "FCHK f32cast window unpolluted");
}

#[test]
fn bug141_rsd_legacy_spelling_still_byte_exact() {
    let t = t103a();
    // Legacy (pre-fix) disasm spelling carries the residual overlay; it must
    // keep encoding to the same vendor word (compat with old dumps).
    let full = enc(&t, "MUFU.RCP64H R5, 6890496 !rsd[51:1,52:1,54:1,56:1]");
    assert_eq!(full, (0x415a490000057908u64 as u128) | (0x00001800u128 << 64),
        "rsd overlay idempotent over the full f64hi window");
    let full = enc(&t, "FCHK P1, R0, 6890499 !rsd[34:1,54:1,55:1,57:1,59:1]");
    assert_eq!(full, (0x4ad2480600007902u64 as u128) | (0x00020000u128 << 64),
        "rsd overlay idempotent over the full f32cast window");
}

#[test]
fn bug141_fchk_abs_form_generic_path() {
    // FCHK P0, |R31|, 10: abs on tok2 lives at word bit 73 via the generic
    // ALU abs/neg path (the II row itself intentionally carries no abs
    // fields; witness: cusolver 2051 /*105e0*/).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w = 0x412000001f007902u128 | (0x00000200u128 << 64);
    let got = dec(&t, &idx, w);
    assert_eq!(got, "FCHK P0, |R31|, 10", "abs spelling via generic path");
    assert_eq!(enc(&t, &got), w, "abs form re-encode byte-exact");
}
