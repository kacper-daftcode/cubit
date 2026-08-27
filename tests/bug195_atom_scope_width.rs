//! BUG-195 — ATOM/ATOMG/REDG scope+width closure; 142-sec.5 residuum
//! (owner: front2/blind F2-iter94). All rows data-only via patch195.py,
//! each backed by an nvcc/ptxas 13.3.73 witness (probe195{a..e}, arch-eq
//! sm_120a==sm_103a==sm_100a) or a graft-sonda rendered legal by nvdisasm
//! (arb195 g1 = ATOM-generic {1,5} flip).
//!
//! Vendor law (arb195/arb195b.json, nvdisasm 13.3.73):
//!   - scope = 4-bit field [77:81): 0x5=SM, 0x7=GPU, 0xA=SYS (16-state sweep
//!     g3; only witnessed scopes get rows).
//!   - width = [74:73]: 00=U32(bare glyph), 01=.S32, 10=.64, 11=.S64.
//!   - generic ATOM = ATOMG ^ {1,5} (single-bit flips = uC-INVALID/QSPC).
//!
//! printer.rs: "SM" joins the ATOM-family scope bucket (last position) —
//! fixes the pre-existing render-parity divergence on the 142-era row
//! AND,E,SM,STRONG (`ATOM.E.AND.SM.STRONG` -> vendor `ATOM.E.AND.STRONG.SM`).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// (vendor text, lo64, hi64) — probe195{a..e} cubins + hexdb (REDG/CAS.SM).
const CASES_120: &[(&str, u64, u64)] = &[
    ("@P0 REDG.E.ADD.STRONG.SM desc[UR6][R2.64], R5",        0x000000050200098e, 0x004fe2000c12a106),
    ("@P0 REDG.E.ADD.STRONG.SYS desc[UR6][R2.64], R5",       0x000000050200098e, 0x004fe2000c134106),
    ("ATOMG.E.CAS.STRONG.SM PT, R5, [R4], R6, R7",           0x00000006040573a9, 0x002ea200001ea107),
    ("ATOMG.E.EXCH.STRONG.SM PT, R3, desc[UR4][R2.64], R7",  0x80000007020379a8, 0x001eac000c1eb104),
    ("ATOMG.E.EXCH.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8, 0x001eac000c1f5104),
    ("ATOMG.E.MAX.STRONG.GPU PT, R3, desc[UR4][R2.64], R7",  0x80000007020379a8, 0x001eac00091ef104),
    ("ATOMG.E.MAX.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091ef504),
    ("ATOMG.E.MAX.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091ef704),
    ("ATOMG.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091eb704),
    ("ATOMG.E.MAX.S64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091f5704),
    ("ATOMG.E.MIN.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00089ef704),
    ("ATOMG.E.MIN.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00089ef504),
    ("ATOM.E.MAX.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x800000060202798a, 0x001eac00091ef704),
    ("ATOM.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x800000060202798a, 0x001eac00091eb704),
    ("ATOMG.E.ADD.F64.RN.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1eff04),
    ("ATOMG.E.ADD.F64.RN.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1ebf04),
    ("ATOMG.E.ADD.F64.RN.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1f5f04),
    // 142-era row: render-parity fix via the SM scope bucket.
    ("@P0 ATOM.E.AND.STRONG.SM PT, RZ, desc[UR10][R10.64+0x4], R9", 0x800004090aff098a, 0x0011e4000a9eb10a),
];

// sm103a: the same vendor words (arch-eq) — pre-fix these decoded to junk
// (`MAX.S32` mislabel, `P10,|R2|` hallucinations) or failed closed.
const CASES_103: &[(&str, u64, u64)] = &[
    ("@P0 REDG.E.ADD.STRONG.SM desc[UR6][R2.64], R5",        0x000000050200098e, 0x004fe2000c12a106),
    ("@P0 REDG.E.ADD.STRONG.SYS desc[UR6][R2.64], R5",       0x000000050200098e, 0x004fe2000c134106),
    ("ATOMG.E.CAS.STRONG.SM PT, R5, [R4], R6, R7",           0x00000006040573a9, 0x002ea200001ea107),
    ("ATOMG.E.EXCH.STRONG.SM PT, R3, desc[UR4][R2.64], R7",  0x80000007020379a8, 0x001eac000c1eb104),
    ("ATOMG.E.EXCH.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8, 0x001eac000c1f5104),
    ("ATOMG.E.MAX.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091ef504),
    ("ATOMG.E.MAX.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091ef704),
    ("ATOMG.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091eb704),
    ("ATOMG.E.MAX.S64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091f5704),
    ("ATOMG.E.MIN.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00089ef704),
    ("ATOMG.E.MIN.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00089ef504),
    ("ATOMG.E.ADD.F64.RN.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1ebf04),
    ("ATOMG.E.ADD.F64.RN.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1f5f04),
];

fn run_tab(p: &str, cases: &[(&str, u64, u64)]) {
    let t = tab(p);
    let idx = DecodeIndex::build(&t);
    for (v, lo, hi) in cases {
        let w = ((*hi as u128) << 64) | (*lo as u128);
        let text = dec(&t, &idx, w);
        assert_eq!(&text, v, "{p}: decode must reproduce vendor text");
        assert_eq!(enc(&t, v), w & !SCHED, "{p}: encode payload must equal anchor");
        let w2 = enc(&t, &text);
        assert_eq!(w2, w & !SCHED, "{p}: decode->encode fixed point");
    }
}

#[test]
fn t195_1_sm120_vendor_exact() { run_tab("tables/sm120.json", CASES_120); }

#[test]
fn t195_2_sm103a_vendor_exact() {
    // sm103a: the guarded @P0 REDG forms are decode-exact but encode is
    // fail-closed by the BUG-080 silicon policy (guarded non-EL atomics =
    // silent corruption on sm_103a); pin BOTH directions explicitly.
    run_tab("tables/sm103a.json", &CASES_103[2..]);
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    for (v, lo, hi) in &CASES_103[..2] {
        let w = ((*hi as u128) << 64) | (*lo as u128);
        assert_eq!(&dec(&t, &idx, w), v, "guarded REDG decode-exact");
        let insn = parse_sass(v, 0).expect("parse");
        assert!(
            encode_instruction(&insn, &t).is_err(),
            "encode of guarded non-EL atomic must fail on sm103a (BUG-080)"
        );
    }
}

#[test]
fn t195_3_no_junk_glyph_remnants() {
    // pre-fix sm103a decode hallucinated `P10, |R2|` on the S64 scope words
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    for (_, lo, hi) in CASES_103 {
        let w = ((*hi as u128) << 64) | (*lo as u128);
        let text = dec(&t, &idx, w);
        assert!(!text.contains('|'), "abs-junk remnant: {text}");
        assert!(!text.contains(" P10,"), "pred hallucination remnant: {text}");
        assert!(!text.contains("!rsd"), "rsd-junk remnant: {text}");
    }
}

#[test]
fn t195_4_unwitnessed_scope_fails_closed() {
    // graft: EXCH donor with scope=0x3 (CONSTANT.CTA.PRIVATE) — vendor-legal
    // glyph but zero rows by doctrine (no witness): decode must NOT fabricate
    // an ATOMG.E.EXCH.* rendering.
    for p in ["tables/sm120.json", "tables/sm103a.json"] {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        let hi: u64 = (0x001eac000c1ef104u64 & !(0xf << (77 - 64))) | (0x3u64 << (77 - 64));
        let w = ((hi as u128) << 64) | 0x80000007020379a8u128;
        match idx.decode(w, 0, &t) {
            Ok(d) => {
                let s = cubit::printer::to_sass(&d);
                assert!(!s.starts_with("ATOMG.E.EXCH"), "{p}: fabricated EXCH: {s}");
            }
            Err(_) => {}
        }
    }
}

#[test]
fn t195_5_retention_181_forms() {
    // 181-era forms stay exact (ATOMS.CAS.64 / ATOMS.EXCH AURI / UTCATOMSWS
    // no-ALIGN / ATOMG F64 plain) — regression fence around the family.
    let t = tab("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    for (v, lo, hi) in [
        ("ATOMS.CAS.64 R2, [R7+0x10], R8, R10", 0x000010080702738d_u64, 0x000e22000000040a_u64),
        ("ATOMS.EXCH R0, [UR4+0x1c], R0", 0x00001c00ff00798c_u64, 0x000e24000c000004_u64),
    ] {
        let w = ((hi as u128) << 64) | (lo as u128);
        assert_eq!(&dec(&t, &idx, w), v);
        assert_eq!(enc(&t, v), w & !SCHED);
    }
    let t103 = tab("tables/sm103a.json");
    let idx103 = DecodeIndex::build(&t103);
    let w = 0x000e6400080e0000u128 << 64 | 0x00000005000485e3u128;
    assert_eq!(&dec(&t103, &idx103, w), "@!UP0 UTCATOMSWS.FIND_AND_SET UPT, UR4, UR5");
    assert_eq!(
        enc(&t103, "ATOMG.E.ADD.F64.RN.STRONG.GPU PT, RZ, [R132+0x1000], R32"),
        (((0x00052800001eff00u128) << 64) | 0x0010002084ff73a3u128) & !SCHED
    );
}

#[test]
fn t195_6_sm120_max_widths_not_s32() {
    // the four width states must not collapse to the .S32 glyph (pre-fix
    // bare/U64/S64 all rendered `MAX.S32`).
    let t = tab("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    for (_, lo, hi) in CASES_120.iter().filter(|(v, _, _)| v.starts_with("ATOMG.E.MAX")) {
        let w = ((*hi as u128) << 64) | (*lo as u128);
        assert!(!dec(&t, &idx, w).contains("MAX.S32"), "S32-absorption remnant");
    }
}
