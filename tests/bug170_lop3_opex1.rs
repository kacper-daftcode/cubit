//! BUG-170 (front-main iter88, 2026-08-26, loop5/blind; kandydat 170 z raportu
//! 168 sec.8 = "control-emission UPLOP3", lane front-M/asm): kubiny skladane
//! z TEKSTU z UPLOP3.LUT dostawaly od schedulera control word, na ktorym
//! nvdisasm -c abort ("Opclass 'uplop3_lut_2out_', undefined value 0x1e for
//! table 'TABLES_opex_1'") — pre-existing na main, odtworzone work/i88.
//!
//! Prawo (raport results/cubitfix/170.md):
//!   ctrl bity slowa [105:110) = stall[0:4) | yield<<4 sa dla opclass
//!   uplop3_lut_2out_ / plop3_lut_2out_ indeksem TABLES_opex_1.
//!   Defined = 0x00..=0x0F i 0x11..=0x1B; undefined = 0x10 (yield przy
//!   stall 0) i 0x1C..=0x1F (yield przy stall 12..=15).
//!   Dowody: bit-scan 32/32 na payloadach korpusowych (work/i88/arb) +
//!   census vendor hexdb 32.2M: 5,970 wierszy UPLOP3 + 144,796 PLOP3, zero
//!   poza zbiorem legalnym. Stage-3 RULE-2 (ptxas-derived: clear Y przy
//!   stall==0 i stall>=12) = dokladnie to samo prawo — zbieznosc niezalezna.
//! Root cause: legacy path ustawial yield bezwarunkowo na UPLOP3
//!   (scheduling_pass "uniform datapath writers keep the yield") i dokladal
//!   stall 14 = LATENCY_PRED(13)+1 => 0x1e na KAZDEJ tekstowej UPLOP3.
//! Fix: scheduling_pass::opex1_lop3_legalize — sweep koncowy schedule() +
//!   sweep po post-passach main.rs (settle MMA / back-edge): stall 0 -> 1
//!   przy yield (ksztalt 0x11 dominujacy u vendora), stall >= 12 traci yield
//!   i zachowuje stall (ksztalty 0x0C/0x0F sa w korpusie). hand_sched frozen:
//!   bity autorskie nietkniete.
//! sm120: tabele sm120 nie maja nosnego wiersza UPLOP3 (168 sec.8), lane
//!   defensywny przez ten sam kod wspoldzielony.
//!
//! Piny: t170_1 repro-core 0x1e -> stall zachowany, yield zdjety;
//! t170_2 53 uniq korpusowe UPLOP3 (hexdb, z t168) wszystkie legalne;
//! t170_3 PLOP3 forma legalna; t170_4 hand_sched frozen nietkniete;
//! t170_5 byte-level: zakodowane slowa maja [105:110) w zbiorze legalnym.
//! Neg-ctl (main 2bd2a82): t170_1/t170_2/t170_5 FAIL (0x1e), t170_3/t170_4 PASS.

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
