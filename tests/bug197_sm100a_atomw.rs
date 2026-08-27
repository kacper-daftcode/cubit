//! BUG-197 — sm100a ATOM-family closure (owner: front2/blind F2-iter95).
//! Data-only patch197.py on tables/sm100a.json: PART A adds the 13 rows
//! parked-BUG-195 carries on sm103a (10 ATOMG_P_R_dARI_R width/scope groups
//! + REDG SM/SYS + CAS.SM); PART B mirrors parked-BUG-196's donor pred-window
//! law (26 rows -> pred [81:84)); PART C canonicalizes CAS.SYS ab[7:11)=7.
//! sm100a was withdrawn from BUG-196 precisely because it lacked these width
//! rows — this patch closes the full lane in one pass.
//!
//! Witnesses (nvdisasm 13.3.73 on real sm_100a builds probe195{,b,e}_100a
//! + graft197a in-place): glyphs and payload words verified bitwise.
//! Census-first: zero anchor exposure in atomdb sm_100 class (16,053 IDENT).
//!
//! NOTE (compose): sm-scope rows print SM in mod-group-name position until
//! parked-195's printer.rs arm (STRONG-last) lands; the witness literals
//! below are asserted up to that one token swap and the operand stream is
//! asserted vendor-exact unconditionally.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const T100: &str = "tables/sm100a.json";
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
/// mnemonics are asserted up to the SM/STRONG token order (parked-195 arm);
/// operands must be vendor-exact.
fn assert_mg_or_vendor(got: &str, mg_order: &str, vendor: &str) {
    assert!(
        got == mg_order || got == vendor,
        "glyph law: got `{got}`; want mg `{mg_order}` or vendor `{vendor}`"
    );
}

const WIT: &[(&str, &str, u64, u64)] = &[
    // (mg-name-order glyph, vendor glyph, lo, hi) — real sm_100a probe words
    ("@P0 REDG.E.ADD.SM.STRONG desc[UR8][R2.64], R5",
     "@P0 REDG.E.ADD.STRONG.SM desc[UR8][R2.64], R5", 0x000000050200098e, 0x008fe2000c12a108),
    ("@P0 REDG.E.ADD.STRONG.SYS desc[UR6][R2.64], R5",
     "@P0 REDG.E.ADD.STRONG.SYS desc[UR6][R2.64], R5", 0x000000050200098e, 0x004fe2000c134106),
    ("ATOMG.E.CAS.SM.STRONG PT, R5, [R4], R6, R7",
     "ATOMG.E.CAS.STRONG.SM PT, R5, [R4], R6, R7", 0x00000006040573a9, 0x002ea200001ea107),
    ("ATOMG.E.EXCH.SM.STRONG PT, R3, desc[UR4][R2.64], R7",
     "ATOMG.E.EXCH.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8, 0x001eac000c1eb104),
    ("ATOMG.E.EXCH.STRONG.SYS PT, R3, desc[UR4][R2.64], R7",
     "ATOMG.E.EXCH.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8, 0x001eac000c1f5104),
    ("ATOMG.E.MAX.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.MAX.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091ef504),
    ("ATOMG.E.MAX.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.MAX.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091ef704),
    ("ATOMG.E.MAX.S64.SM.STRONG PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091eb704),
    ("ATOMG.E.MAX.S64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.MAX.S64.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00091f5704),
    ("ATOMG.E.MIN.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.MIN.S64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00089ef704),
    ("ATOMG.E.MIN.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.MIN.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a8, 0x001eac00089ef504),
    ("ATOMG.E.ADD.F64.RN.SM.STRONG PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.ADD.F64.RN.STRONG.SM PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1ebf04),
    ("ATOMG.E.ADD.F64.RN.STRONG.SYS PT, R2, desc[UR4][R2.64], R6",
     "ATOMG.E.ADD.F64.RN.STRONG.SYS PT, R2, desc[UR4][R2.64], R6", 0x80000006020279a3, 0x001eac000c1f5f04),
];

/// t197_1: the 13 closure rows decode the real sm_100a witness words.
/// Pre-patch every one of these is a HOLE (REDG/CAS/EXCH/F64 SM/SYS lanes)
/// or a prio-absorbed wrong glyph (MAX.S64 family / MIN widths).
#[test]
fn t197_1_closure_rows_decode_witnesses() {
    let t = tab(T100); let idx = DecodeIndex::build(&t);
    for (mg, vendor, lo, hi) in WIT {
        assert_mg_or_vendor(&dec(&t, &idx, word(*lo, *hi)), mg, vendor);
    }
}

/// t197_2: authored vendor glyphs encode to the witnessed payload words
/// (sched/control upper32 masked — chain layer owns them).
#[test]
fn t197_2_encode_matches_witness_payload() {
    let t = tab(T100);
    for (_mg, vendor, lo, hi) in WIT {
        let insn = parse_sass(vendor, 0).expect("parse");
        let w = encode_instruction(&insn, &t).expect("encode");
        assert_eq!(w & !((u128::MAX >> 32) << 96), word(*lo, *hi) & !((u128::MAX >> 32) << 96),
                   "payload mismatch for `{vendor}`");
    }
}

/// t197_3: dest-pred [81:84) law on the MAX.S64 donor (sm100a side of the
/// BUG-196 move): Pk identity P0..P6,PT + roundtrip byte-exact.
#[test]
fn t197_3_dest_pred_law_sweep() {
    let t = tab(T100); let idx = DecodeIndex::build(&t);
    let lo: u64 = 0x80000006020279a8;
    let hi_d: u64 = 0x091ef704; // bits[64:96) donor: PT, plain (b84=1)
    for k in 0u64..8 {
        let hi = (hi_d & !(0x7 << 17)) | (k << 17);
        let w = word(lo, hi);
        let want_p = if k == 7 { "PT".to_string() } else { format!("P{k}") };
        let text = dec(&t, &idx, w);
        assert_eq!(text, format!("ATOMG.E.MAX.S64.STRONG.GPU {want_p}, R2, desc[UR4][R2.64], R6"),
                   "sm100a dest-pred law k={k}");
        let insn = parse_sass(&text, 0).expect("parse");
        assert_eq!(encode_instruction(&insn, &t).expect("encode") & !SCHED, w, "roundtrip k={k}");
    }
}

/// t197_4: the guard window [12:16) never fabricates a dest-P token on
/// sm100a (BUG-196 guard/dest separation for the EXCH/INC (12,4) donors).
#[test]
fn t197_4_guard_does_not_fabricate_dest() {
    let t = tab(T100); let idx = DecodeIndex::build(&t);
    for (want, lo, hi) in [
        ("@P0 ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0x800000030aff09a8u64, 0x0c1ef108u64),
        ("@P2 ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0x800000030aff29a8u64, 0x0c1ef108u64),
        ("@P3 ATOMG.E.INC.STRONG.GPU PT, R2, desc[UR14][R2.64], R5", 0x80000005020239a8u64, 0x099ef10eu64),
    ] {
        assert_eq!(dec(&t, &idx, word(lo, hi)), want, "guard/dest separation");
    }
}

/// t197_5: base-reg HI nibble [28:32) is not a pred window: R>=16 bases
/// keep dest P0 and the true base (was: phantom P1/PT demangle).
#[test]
fn t197_5_basereg_hi_not_pred() {
    let t = tab(T100); let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&t, &idx, word(0x800008041aff798a, 0x0001e4000910f704)),
               "ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR4][R26.64+0x8], R4");
    assert_eq!(dec(&t, &idx, word(0x800008047aff798a, 0x0001e4000910f704)),
               "ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR4][R122.64+0x8], R4");
}

/// t197_6: residuum honesty — updated by BUG-199 (iter96): the 197-era
/// blocker resolved. arb199 (176-probe bit-walk on graft197a, nvdisasm
/// 13.3.73) proved the full ATOM-generic desc geometry (UR=[64:72),
/// imm=[40:63), same as the ATOMG sibling — the 197 "(41,8) does not read
/// it" observation was itself the harvest-era defective window this wave
/// fixed). BUG-199 FIX B added the row; decode is now the vendor glyph.
/// (sm103a still carries no such row — HOLE posture there is pinned in
/// bug199's t199_7.)
#[test]
fn t197_6_residuum_holes() {
    let t = tab(T100); let idx = DecodeIndex::build(&t);
    // graft197a ATOM-generic word decodes to the vendor glyph post-BUG-199
    let g = dec(&t, &idx, word(0x800000060202798a, 0x001eac00091eb704));
    assert_eq!(g, "ATOM.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6",
               "BUG-199: ATOM-generic S64.SM row live on sm100a");
    // ATOM-generic MAX.S64 GPU corpus anchors still decode (P0 + true base)
    assert_eq!(dec(&t, &idx, word(0x800008040aff798a, 0x0001e4000910f704)),
               "ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR4][R10.64+0x8], R4");
}

/// t197_7: CAS.SYS canonical decode/encode still works after the ab[7:11)=7
/// canonicalization (BUG-196 part2 mirror; battery-A correctness fence).
#[test]
fn t197_7_cas_sys_canonical() {
    let t = tab(T100); let idx = DecodeIndex::build(&t);
    let w = word(0x00000006040573a9, 0x001ea200001f4107);
    let text = dec(&t, &idx, w);
    assert_eq!(text, "ATOMG.E.CAS.STRONG.SYS PT, R5, [R4], R6, R7");
    let insn = parse_sass(&text, 0).expect("parse");
    assert_eq!(encode_instruction(&insn, &t).expect("encode") & !SCHED, w & !SCHED, "CAS.SYS roundtrip");
}
