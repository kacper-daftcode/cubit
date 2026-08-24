//! BUG-131: FADD cluster in tables/sm120.json (a stale junk field behind a
//! decoder hole + toolchain load block). Three layers:
//! (a) FLEET-BLOCKER [zamkniety merge'em 823f5d4; t131_3 = pin-invariant]:
//!     FADD_R_L_R::{RZ,SAT} niosly junk-pole {shift:122, bits:8,
//!     token_idx:3, extraction:"reg"} -> 122+8=130 > 128 -> post-hardening
//!     walidacja tabeli odrzucala CALA tabele przy load (flota: asm
//!     championa + korpus ts2 fail). Pole = zdegenerowany import tok3-reg
//!     (prawdziwa geometria tok3 = 8b@[39:32], jak we wszystkich R_R_R).
//! (b) DZIURA DEKODERA pre-existing (nie skutek merge'a): forma FADD.FTZ.RZ
//!     (FTZ = bit80, RZ = bits[79:78]=0b11, baza 0x221) nie miala grupy w
//!     sm120.json -> sloty korpusu dekodowaly sie jako `/* ? */`. Fix:
//!     kanoniczna mod-grupa "FTZ,RZ" w FADD_R_R_R (and_base
//!     0x000000000001c0000000000000000221, te same 9 pol i maska co
//!     siostrzane RZ/FTZ), evidence = 2 cubiny korpusu (cutlass
//!     70_blackwell_fp16_gemm.1 + 77_blackwell_mla_2sm_fp8, 4 slowa vendor).
//! (c) RESIDUUM po (a): po wycieciu junk-pola wiersze FADD_R_L_R::{RZ,SAT}
//!     zostaly Z ZUPELNIE brakujacym polem tok3 (decode = cichy drop
//!     operandu) ORAZ z bake 0x04/0x05 w oknie tok3 (count=1, harvest-junk,
//!     sig R_L_R sprzeczny z polami reg; zero form *L w korpusie 2051
//!     cubinow vendor). Fix: USUNIECIE obu junk-grup; ich slowa kanoniczne
//!     dekoduja sie przez prawidlowe FADD_R_R_R::{RZ,SAT} z pelnym tok3
//!     (t131_4). Dowód A/B korpusu: the internal fix archive
//! Obserwacja pre-fix (raport 131.md; oddzielny kandydat BUG-132): encode
//! '@P1 FADD.FTZ.RZ ...' przed fixa "przechodzil" z bitami 78..80
//! WYZEROWANYMI (cichy mod-drop przez fallback lookup-chain do grupy "";
//! klasa enkoder/wrong-code). Kontrola pre-fix (HEAD 4d661bb): t131_1/2
//! FAIL (dziura), t131_3 PASS (inwariant), t131_4 PASS (FADD_R_R_R i tak
//! wygrywal; po usunieciu junk-grup zachowanie wzmocnione).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

/// Rzeczywiste slowa vendor z korpusu cutlass (sm120 table).
const GOLD: &[(u128, &str)] = &[
    (0x000fe2000000c0000000000a0d151221u128, "@P1 FADD.RZ R21, R13, R10"),
    (0x000fe2000000c0000000000a13121221u128, "@P1 FADD.RZ R18, R19, R10"),
    (0x000fe4000001c0000000001a1b221221u128, "@P1 FADD.FTZ.RZ R34, R27, R26"),
    (0x000fe2000001c0000000000a13161221u128, "@P1 FADD.FTZ.RZ R22, R19, R10"),
];

#[test]
fn t131_1_decode_render_reencode_vendor_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let mut fails = Vec::new();
    for &(word, golden) in GOLD {
        let d = match idx.decode(word, 0, &t) {
            Ok(d) => d,
            Err(e) => { fails.push(format!("word {word:032x}: decode fail: {e}")); continue; }
        };
        let text = cubit::printer::to_sass(&d);
        if text != golden {
            fails.push(format!("word {word:032x}: render {text:?} != golden {golden:?}"));
            continue;
        }
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        let e = t.get(&d.key, &d.mod_group).unwrap();
        let mut fm: u128 = 0;
        for f in &e.fields {
            if f.extraction == cubit::table::Extraction::None { continue; }
            fm |= ((1u128 << f.bits) - 1) << f.shift;
        }
        let keep = (!e.variable_mask | fm) & !SCHED;
        if (w2 & keep) != (word & keep) {
            fails.push(format!("re-encode diff {w2:032x} vs {word:032x} (keep {keep:032x})"));
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn t131_2_ftzrz_routes_to_canonical_group() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(GOLD[2].0, 0, &t).expect("decode FTZRZ3");
    assert_eq!(d.key, "FADD_R_R_R");
    assert_eq!(d.mod_group, "FTZ,RZ");
}

/// Inwariant (a): kazda tabela musi sie ladowac (walidacja fail-closed
/// klasy "field outside 128-bit" pokrywa wszystkie wiersze przy load).
#[test]
fn t131_3_all_tables_load_no_field_outside_128() {
    for tab in ["tables/sm120.json", "tables/sm103a.json"] {
        IsaTable::load(std::path::Path::new(tab))
            .unwrap_or_else(|e| panic!("{tab} must load: {e}"));
    }
}

/// Inwariant (c): po usunieciu junk-grup ich slowa kanoniczne dekoduja sie
/// przez prawidlowe wiersze z PELNYM tok3 (zero dropu operandu).
#[test]
fn t131_4_junk_canonical_words_full_render() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(word, want) in &[
        (0x000fe2000000c0000000000400000221u128, "@P0 FADD.RZ R0, R0, R4"),
        (0x000fe200000020000000000500000221u128, "@P0 FADD.SAT R0, R0, R5"),
    ] {
        let d = idx.decode(word, 0, &t)
            .unwrap_or_else(|e| panic!("decode junk-canon 0x{word:032x}: {e}"));
        assert_eq!(cubit::printer::to_sass(&d), want);
        assert_eq!(d.key, "FADD_R_R_R");
    }
}
