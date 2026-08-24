//! BUG-076 (from the B12 A/B O3 wrapper; guard
//! + probe matrix executed F2 2026-08-22): STG desc-form with a 64-bit
//! address pair `desc[URm][Rn.64]` requires an EVEN pair base Rn on sm_103a
//! silicon -- OPPOSITE polarity to BUG-060 (LDG.E.NA.EFL2.256 needs ODD).
//!
//! Silicon (B300, krunp harness, GPU idle-windows 2026-08-22; records in
//! the internal fix archive + krun_stats2.txt):
//!   deterministic trap (odd -> CUDA_ERROR_ILLEGAL_INSTRUCTION before the
//!     memory stage): STG.E (9/9), STG.E.64 (9/9), STG.E.128 (~16/17),
//!     STG.E.STRONG.GPU (9/9), STG.E.ENL2.256 (12/17)
//!   flaky trap (epoch-sensitive; II/IA mixes): STG.E.EF (4/6 II),
//!     STG.E.EL.ENL2.256.STRONG.GPU (3/4 II) -- guarded per the F2Q-066
//!     flaky=poison policy (must-not-emit)
//!   never trapped (0/20+ II across epochs): EL.ELL2.256 / NA.ELL2.256 /
//!     NA.EFL2.256 (STRONG.GPU) -- vendor render [Rn.U32+URm] = different
//!     desc addressing mode; transactions default-desc-rejected at the
//!     memory stage on sm_103a anyway (B12 silicon-facts)
//! Even base executes in every probed class (companion cells, n>=4 each).
//! First seen: work/o3/y_ur4_r59.sass (R59.64 ILLEGAL) vs y_e58.sass
//! (R58.64 EXACT). Era corpus (rt98_ref.s103) carries 3 odd-base STG words,
//! all EL.ELL2 (exempt class) -> expected encoder-census delta = 0.
//!
//! Fix: encoder fails closed on the trap/flaky classes for target sm_103a
//! (silicon-scoped, like BUG-059/060/070); ELL2/EFL2 mods exempt; decode
//! untouched (era words keep rendering for RE). LDG non-EFL2 desc pairs and
//! REDG/ATOMG desc pairs deliberately NOT covered -- no silicon verdict
//! either way (ENL2-load odd = F2Q-066-kand flaky, parked).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

// Words frozen at the pinning date (payload bits; ctrl/sched bits zero).
const W_E_EVEN: u128 = 0x000fc2000c1019040000000a3a007986u128;
const W_E64_EVEN: u128 = 0x000fc2000c101b040000000a04007986u128;
const W_ENL2_EVEN: u128 = 0x000fc2000f121804f8000008040c797fu128;
const W_EL_ELL2_ODD: u128 = 0x000fc2000f24e004f8000008050c797fu128;
const W_PRED_EVEN: u128 = 0x000fc2000c1019140000100016005986u128;

// (1) trap classes, odd base: fail closed with the silicon citation.
#[test]
fn t1_sm103a_trap_classes_odd_base_rejected() {
    for text in [
        "STG.E desc[UR4][R59.64], R10",
        "STG.E.64 desc[UR4][R3.64], R10",
        "STG.E.128 desc[UR4][R3.64], R8",
        "STG.E.STRONG.GPU desc[UR4][R5.64], R10",
        "STG.E.ENL2.256 desc[UR4][R5.64], R8, R12",
        "STG.E.EF desc[UR4][R5.64], R10",
        "STG.E.EL.ENL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12",
        "@P5 STG.E desc[UR20][R23.64+0x10], R0",
    ] {
        let e = enc(text, &t103a()).expect_err(&format!("odd-base desc STG must not encode for sm_103a: {text}"));
        let m = format!("{e}");
        assert!(m.contains("BUG-076") && m.contains("SILICON-ILLEGAL"), "{text}: got: {m}");
    }
}

// (2) same classes, even base: encode, byte-fixed at the pinned words.
#[test]
fn t2_sm103a_trap_classes_even_base_encode_fixed_point() {
    assert_eq!(enc("STG.E desc[UR4][R58.64], R10", &t103a()).unwrap(), W_E_EVEN);
    assert_eq!(enc("STG.E.64 desc[UR4][R4.64], R10", &t103a()).unwrap(), W_E64_EVEN);
    assert_eq!(enc("STG.E.ENL2.256 desc[UR4][R4.64], R8, R12", &t103a()).unwrap(), W_ENL2_EVEN);
    assert_eq!(enc("@P5 STG.E desc[UR20][R22.64+0x10], R0", &t103a()).unwrap(), W_PRED_EVEN);
}

// (3) exempt classes (silicon-proven non-trapping; desc addressing mode
// bit84=0): odd base stays encodable.
#[test]
fn t3_sm103a_exempt_classes_odd_base_encode() {
    assert_eq!(enc("STG.E.EL.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12", &t103a()).unwrap(), W_EL_ELL2_ODD);
    enc("STG.E.NA.EFL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12", &t103a())
        .expect("NA.EFL2 class exempt (silicon: 0/8 II across epochs)");
    enc("STG.E.NA.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12", &t103a())
        .expect("NA.ELL2 class exempt (silicon)");
}

// (4) arch scoping: sm120 has no silicon verdict for this erratum, so the
// odd-base trap form stays encodable there (era lineage runs on sm120).
#[test]
fn t4_sm120_odd_base_still_encodes() {
    enc("STG.E desc[UR4][R59.64], R10", &t120())
        .expect("sm120 must keep encoding odd-base desc STG (no silicon evidence)");
}

// (5) decode retention: the exact era odd-base EL.ELL2 word (rt98 KernelA
// +0x4530 class) still decodes+renders under sm103a.json -- RE unaffected.
#[test]
fn t5_sm103a_decode_of_era_odd_word_retained() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let d = idx
        .decode(W_EL_ELL2_ODD, 0, &t)
        .expect("era odd-base EL.ELL2 word must stay decodable under sm103a.json");
    assert_eq!(
        cubit::printer::to_sass(&d),
        "STG.E.EL.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12"
    );
}

// (6) guard precision: unrelated ops and non-desc STG forms must not see
// the BUG-076 path; a 32-bit-suffix desc address likewise passes (pair
// parity does not apply).
#[test]
fn t6_guard_precision() {
    enc("IMAD R10, R2, R3, RZ", &t103a()).expect("plain IMAD unaffected");
    enc("STG.E [R58.64], R10", &t103a()).expect("plain (non-desc) STG unaffected");
    enc("STG.E desc[UR4][R58], R10", &t103a())
        .expect("32-bit desc address unaffected (no pair)");
}
