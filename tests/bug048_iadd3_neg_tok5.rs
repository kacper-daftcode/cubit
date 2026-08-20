//! BUG-048 (rejestr sm120: 045_failed_encode_ghost.md, gnome-ghost class sink):
//! `IADD3.X Rd, Pc, PT, Ra, -Rb, Rc, P, P` — prawdziwa negacja (`-Rn`) na
//! drugim ORDYNARNYM argumencie rejestrowym (tok5) byla CICHO GUBIONA przez
//! grupe mod "X" wiersza `IADD3_R_P_P_R_R_R_P_P` (pole `inv@63` bylo, `neg@63`
//! brak; wiersz-zdublowany `IADD3.X_R_P_P_R_R_R_P_P` je ma, ale matcher
//! wybiera IADD3_R_P_P...). Efekt: `R26 - R25` enkodowalo sie jako `R26 + R25`
//! (bbf7412: encode-fail + ghost w .text; po mk74 carry-minis: pelny zly kod,
//! 0 failed). Dowodze zlota:
//!  * nvcc 12.8 sm_120 (sub.cc/subc.cc probe, /tmp/p048 na sm120):
//!    `IADD3 R11, P0, PT, R0, -R7, RZ`            lo = 0x80000007000b7210
//!    `IADD3.X R13, P0, PT, R6, ~R9, RZ, P0, !PT` lo = 0x80000009060d7210
//!    => bit63 = invert wejscia tok5 (jedno miejsce dla ~ i -; semantyka
//!    `-b` = `~b` + cin, przy cin==PT (1): a + ~b + 1 = a - b — dokladnie).
//!  * rt98_pub.cubin /*d430*/ = 0x8000000d3b0d3210: `@P3 IADD3.X R13, P0, P1,
//!    R59, ~R13, -R92, P0, PT` (inv tok5 @63 + neg tok6 @75) — pelny
//!    frozen-RT opiera sie na tym slowie bajtowo.
//!  * nvdisasm 13.0 (sm103a) i 13.3 (sm120) DRUKUJA `~Rn` dla bit63 w formie
//!    .X niezaleznie od slotu cin — glyph `-Rn` w tym slocie pochodzi z rek
//!    autora (s6 i122), nie z nvdisasm; enkoder odwzorowuje `-` na kanoniczny
//!    bit inwersji (printer po roundtrip pokazuje `~`, jak nvdisasm).
//! Fix (data-level, symetria z wierszem IADD3.X_): + `neg@63` tok5 w grupie
//! "X" wiersza `IADD3_R_P_P_R_R_R_P_P` — tables/sm120.json + sm103a.json.
//! Extraction::Neg juz pada wstecznie na inv, wiec dotychczasowe zlote
//! enkodowania tok5 (~R) sa bitowo niezmienione (frozen-RT rt98 == 3d15ab6a,
//! stale).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

fn lo(text: &str) -> u64 {
    (enc(text) & ((1u128 << 64) - 1)) as u64
}

#[test]
fn bug048_neg_tok5_encoded_not_dropped() {
    let neg = lo("IADD3.X R26, P2, PT, R26, -R25, RZ, !PT, !PT");
    let inv = lo("IADD3.X R26, P2, PT, R26, ~R25, RZ, !PT, !PT");
    let plain = lo("IADD3.X R26, P2, PT, R26, R25, RZ, !PT, !PT");
    assert_eq!(plain, 0x00000019_1a1a7210, "base form regressed: {plain:#018x}");
    assert_eq!(neg, inv, "`-` must land on the same invert bit as `~` (cin=PT arithmetic)");
    assert_ne!(neg, plain, "neg silently dropped again");
    assert!(neg & (1 << 63) != 0 && plain & (1 << 63) == 0);
}

#[test]
fn bug048_nvcc_golden_subcc_byte_exact() {
    // nvcc 12.8 sm_120, sub.cc.u32: lo64 dokladnie jak z nvcc (bity sched
    // powyzej 96 zdjeta przez probe sa maskowane — porownujemy pelne lo64).
    assert_eq!(lo("IADD3 R11, P0, PT, R0, -R7, RZ"), 0x80000007_000b7210);
    assert_eq!(lo("IADD3.X R13, P0, PT, R6, ~R9, RZ, P0, !PT"), 0x80000009_060d7210);
}

#[test]
fn bug048_rt98_golden_inv_tok5_neg_tok6() {
    // rt98_pub.cubin .text.KernelB /*d430*/ — frozen bajt w bajt.
    assert_eq!(
        lo("@P3 IADD3.X R13, P0, P1, R59, ~R13, -R92, P0, PT"),
        0x8000000d_3b0d3210
    );
    // tok4 neg (ra) i tok6 neg (rc) — pre-existing pokrycie, pin regresyjny:
    // -R59 -> bit 72; -R92 -> bit 75.
    let w4 = enc("@P3 IADD3.X R13, P0, P1, -R59, R13, R92, P0, PT");
    let w6 = enc("@P3 IADD3.X R13, P0, P1, R59, R13, -R92, P0, PT");
    assert!((w4 >> 72) & 1 == 1, "tok4 neg@72 lost");
    assert!((w6 >> 75) & 1 == 1, "tok6 neg@75 lost");
}

#[test]
fn bug048_render_canonical_inv_glyph() {
    // Golden slowo rt98 /*d430*/ renderuje sie do kanonicznej formy nvdisasm.
    let idx = DecodeIndex::build(&t120());
    let word: u128 = 0x000fe800_0010ec5c_8000000d_3b0d3210;
    let d = idx.decode(word, 0, &t120()).expect("decode golden failed");
    let text = format!("{d}");
    assert!(
        text.contains("IADD3.X R13, P0, P1, R59, ~R13, -R92"),
        "golden render drifted: {text}"
    );
    // Nowo encodowalna forma `-R25` renderuje z powrotem jako `~R25`
    // (kanon nvdisasm-13.x dla bit63 w formie .X).
    let w = enc("IADD3.X R26, P2, PT, R26, -R25, RZ, !PT, !PT");
    let d2 = idx.decode(w, 0, &t120()).expect("decode new word failed");
    let text2 = format!("{d2}");
    assert!(
        text2.contains("IADD3.X R26, P2, PT, R26, ~R25, RZ"),
        "roundtrip glyph not canonical: {text2}"
    );
}

#[test]
fn bug048_sm103a_table_parity() {
    let t103 = IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    // Uwaga: sm103a.x-group nie ma pola neg@90 dla tok7 (trailing `!PT`) —
    // BUG-006 check fail-closed odrzuca te koncowki od dawna (poza zakresem
    // 048). Paritetyczny pin dotyczy WYLACZNIE tok5 (neg@63).
    let insn = parse_sass("IADD3.X R26, P2, PT, R26, -R25, RZ, PT, PT", 0).unwrap();
    let w = encode_instruction(&insn, &t103).expect("encode sm103a failed");
    assert!(w & (1u128 << 63) != 0, "sm103a table still drops tok5 neg");
}
