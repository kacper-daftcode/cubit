//! BUG-170 (front-main iter88, 2026-08-26, loop5/blind; candidate 170 from report
//! 168 sec. 8 = "control emission of UPLOP3", lane front-M/asm): cubins assembled
//! from TEXT with UPLOP3.LUT received a control word from the scheduler on which
//! nvdisasm -c aborts ("Opclass 'uplop3_lut_2out_', undefined value 0x1e for table
//! 'TABLES_opex_1'") -- pre-existing on main, reproduced in work/i88.
//!
//! Law (report results/cubitfix/170.md):
//!   the control bits of the word [105:110) = stall[0:4) | yield<<4 are, for the
//!   opclasses uplop3_lut_2out_ / plop3_lut_2out_, an index into TABLES_opex_1.
//!   Defined = 0x00..=0x0F and 0x11..=0x1B; undefined = 0x10 (yield with stall 0)
//!   and 0x1C..=0x1F (yield with stall 12..=15).
//!   Evidence: a bit scan 32/32 on corpus payloads (work/i88/arb) + the vendor hexdb
//!   census of 32.2M words: 5,970 UPLOP3 rows + 144,796 PLOP3, none outside the legal
//!   set. Stage-3 RULE-2 (ptxas-derived: clear Y at stall == 0 and stall >= 12) = exactly
//!   the same law -- an independent convergence.
//! Root cause: the legacy path set yield unconditionally on UPLOP3 (scheduling_pass
//!   "uniform datapath writers keep the yield") and added stall 14 = LATENCY_PRED(13)+1
//!   => 0x1e on EVERY textual UPLOP3.
//! Fix: scheduling_pass::opex1_lop3_legalize -- a final sweep of schedule() + a sweep
//!   after main.rs's post-passes (settle MMA / back-edge): stall 0 -> 1 with yield (the
//!   shape 0x11 dominant at the vendor), stall >= 12 loses the yield and keeps the stall
//!   (the shapes 0x0C / 0x0F are in the corpus). hand_sched frozen: the author's bits
//!   untouched.
//! sm120: the sm120 tables have no carrying UPLOP3 row (168 sec. 8); the lane is
//!   defended by the same shared code.
//!
//! Pins: t170_1 repro core 0x1e -> stall kept, yield removed; t170_2 the 53 uniq
//! corpus UPLOP3 (hexdb, from t168) all legal; t170_3 the PLOP3 form legal; t170_4
//! hand_sched frozen untouched; t170_5 byte level: the encoded words have [105:110)
//! in the legal set. Negative control (main 2bd2a82): t170_1 / t170_2 / t170_5 FAIL
//! (0x1e), t170_3 / t170_4 PASS.

use cubit::encoder::encode_instruction;
use cubit::ir::{ControlCode, Instruction};
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn scheduled(lines: &[&str], t: &IsaTable) -> Vec<Instruction> {
    let mut v: Vec<Instruction> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| parse_sass(l, (i * 16) as u32).expect("parse"))
        .collect();
    cubit::scheduling_pass::schedule(&mut v, Some(t));
    v
}

/// Indeks opex_1 pola ctrl slowa (bity [105:110) = stall[0:4) | yield<<4).
fn opex1_index(c: &ControlCode) -> u8 {
    (c.stall & 0xF) | ((c.yield_flag as u8) << 4)
}

fn opex1_legal(c: &ControlCode) -> bool {
    matches!(opex1_index(c), 0x00..=0x0F | 0x11..=0x1B)
}

static EXIT: &str = "    EXIT ;";

#[test]
fn t170_1_repro_core() {
    // Bit-exact repro z noty 168: tekstowa UPLOP3 w 2-instr kernelu.
    // Main 2bd2a82: stall=14 + yield (0x1e) z prefixu ostatniej reguly
    // (pred-latency 13+1) i bezwarunkowego yield na pathie uniform-pred.
    let t = t103a();
    let v = scheduled(
        &["    UPLOP3.LUT UP1, UPT, UP1, UP2, UPT, 0xf8, 0x8f ;", EXIT],
        &t,
    );
    let c = &v[0].ctrl;
    assert!(
        opex1_legal(c),
        "UPLOP3 ctrl must land in TABLES_opex_1 defined set, got index 0x{:02x} (stall {}, yield {})",
        opex1_index(c), c.stall, c.yield_flag
    );
    // Naprawa zachowuje zamierzony delay: stall NIE jest obcinany do 11 ani
    // kasowany — tracony jest tylko yield (zbyt wysoki stall + yield = indeks
    // poza tabela vendora). Yield-free S12..S15 istnieja w korpusie (0x0C/0x0F).
    assert!(c.stall >= 12, "wanted delay must be preserved, got stall {}", c.stall);
    assert!(!c.yield_flag, "yield must be dropped beside stall>=12");
    // Bity barier/masek nie ruszane.
    assert_eq!((c.write_bar, c.read_bar, c.wait_mask), (7, 7, 0));
}

/// 53 uniq teksty UPLOP3 z hexdb (jak w tests/bug168_uplop3_lattice.rs),
/// w tym formy z guardem @UPx/@!UPx.
const CORPUS_UPLOP3: &[&str] = &[
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "UPLOP3.LUT UP1, UPT, UP1, UP0, UPT, 0xf8, 0x8f",
    "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8",
    "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8",
    "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f",
    "UPLOP3.LUT UP0, UPT, UP0, UP2, UPT, 0xf8, 0x8f",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UP0, 0x40, 0x4",
    "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP1, UPT, UP0, UP1, UPT, 0xf8, 0x8f",
    "UPLOP3.LUT UP1, UPT, UP1, UP2, UPT, 0xf8, 0x8f",
    "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "@UP5 UPLOP3.LUT UP0, UPT, UP0, UP2, UPT, 0xf8, 0x8f",
    "@UP5 UPLOP3.LUT UP3, UPT, UPT, UPT, UP0, 0x40, 0x4",
    "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "UPLOP3.LUT UP2, UPT, UP0, UP1, UPT, 0xf8, 0x8f",
    "@UP0 UPLOP3.LUT UP1, UPT, UPT, UPT, UP2, 0x40, 0x4",
    "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "@!UP0 UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "@!UP0 UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "@!UP0 UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "@!UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x40, 0x4",
    "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x80, 0x8",
    "UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8",
    "UPLOP3.LUT UP2, UPT, UPT, UPT, UP1, 0x80, 0x8",
    "@!UP1 UPLOP3.LUT UP0, UPT, UPT, UPT, UP2, 0x80, 0x8",
    "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP3, 0x80, 0x8",
    "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP4, 0x80, 0x8",
    "UPLOP3.LUT UP2, UPT, UP1, UP0, UPT, 0x2, 0x20",
    "@UP3 UPLOP3.LUT UP2, UPT, UPT, UPT, UP4, 0x40, 0x4",
    "UPLOP3.LUT UP4, UPT, UPT, UPT, UP5, 0x80, 0x8",
    "@!UP1 UPLOP3.LUT UP3, UPT, UPT, UPT, UP0, 0x80, 0x8",
    "@!UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UP4, 0x40, 0x4",
    "@UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UP1, 0x80, 0x8",
    "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8",
    "UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x40, 0x4",
    "@UP0 UPLOP3.LUT UP1, UPT, UPT, UPT, UP2, 0x80, 0x8",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0xf8, 0x8f",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0xf8, 0xf",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x42, 0x4",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x44, 0x4",
    "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x78, 0x8",
];

#[test]
fn t170_2_corpus_forms_all_legal() {
    let t = t103a();
    let mut bad = Vec::new();
    for text in CORPUS_UPLOP3 {
        let line = format!("    {} ;", text);
        let v = scheduled(&[&line, EXIT], &t);
        let c = &v[0].ctrl;
        if !opex1_legal(c) {
            bad.push((text, opex1_index(c)));
        }
    }
    assert!(bad.is_empty(), "corpus UPLOP3 forms outside TABLES_opex_1: {bad:?}");
}

#[test]
fn t170_3_plop3_stays_legal() {
    let t = t103a();
    for text in [
        "    PLOP3.LUT P1, PT, P1, P0, PT, 0xf8, 0x8f ;",
        "    PLOP3.LUT P4, PT, P4, P0, PT, 0x80, 0x8 ;",
    ] {
        let v = scheduled(&[text, EXIT], &t);
        let c = &v[0].ctrl;
        assert!(
            opex1_legal(c),
            "PLOP3 ctrl must stay in TABLES_opex_1 defined set, got 0x{:02x}",
            opex1_index(c)
        );
    }
}

#[test]
fn t170_4_hand_sched_frozen_untouched() {
    // Autoryzowane bity ctrl sa wlasnoscia autora (doktryna M4): legalizer
    // nie wolno-doprowadza frozen ctrl, nawet gdy jest poza zbiorem legalnym.
    let t = t103a();
    let mut v: Vec<Instruction> = ["    UPLOP3.LUT UP2, UPT, UP1, UP0, UPT, 0x2, 0x20 ;", EXIT]
        .iter()
        .enumerate()
        .map(|(i, l)| parse_sass(l, (i * 16) as u32).expect("parse"))
        .collect();
    v[0].hand_sched = true;
    v[0].ctrl = ControlCode { stall: 14, yield_flag: true, write_bar: 2, read_bar: 6, wait_mask: 0x3f };
    cubit::scheduling_pass::schedule(&mut v, Some(&t));
    assert_eq!(
        (v[0].ctrl.stall, v[0].ctrl.yield_flag, v[0].ctrl.write_bar, v[0].ctrl.read_bar, v[0].ctrl.wait_mask),
        (14, true, 2, 6, 0x3f),
        "hand_sched ctrl bits are author-owned and frozen"
    );
}

#[test]
fn t170_5_byte_level_emission_legal() {
    // Dowod poziomem BAJTOWYM, nie tylko struktury: zakodowane slowo 128-bit
    // ma bity [105:110) w zbiorze legalnym (stall|yield<<4).
    let t = t103a();
    for text in CORPUS_UPLOP3 {
        let line = format!("    {} ;", text);
        let v = scheduled(&[&line, EXIT], &t);
        let word = encode_instruction(&v[0], &t).expect("encode");
        let idx = ((word >> 105) as u8) & 0x1F;
        assert!(
            matches!(idx, 0x00..=0x0F | 0x11..=0x1B),
            "encoded ctrl bits [105:110) outside TABLES_opex_1: 0x{idx:02x} for {text}"
        );
    }
}
