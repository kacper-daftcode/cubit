//! BUG-077 (F2Q; znalezione przy matrycy BUG-076, zamkniete F2 2026-08-22):
//! LDG desc-form with a 64-bit address pair `desc[URm][Rn.64]` requires an
//! EVEN pair base Rn on sm_103a for every true-pair desc class.
//!
//! Silicon (B300, krunp, GPU idle-windows 2026-08-22; records in
//! results/cubitfix/077/krun_stats.txt; odd -> CUDA_ERROR_ILLEGAL_INSTRUCTION
//! pre-memory, even -> executes):
//!   traps:   LDG.E 4/8 II, LDG.E.64 7/8 II, LDG.E.128 7/8 II,
//!            LDG.E.STRONG.GPU 5/6 II, LDG.E.EF 5/6 II, LDG.E.U16 5/6 II,
//!            LDG.E.256.ENL2 8/8 II this window (+ F2Q-066: ENL2-load odd
//!            flaky ~50/80 across epochs -> flaky=poison policy)
//!   exempt:  LTC128B (0/7 II; era corpus carries 69 such odd words),
//!            ELL2.256 (066: 20/20 both parities), EFL2.256 (BUG-060:
//!            odd REQUIRED; even already fails closed there)
//! Untested sub-classes (CONSTANT/SM/SYS/S8/U8/EL.ENL2-load) ride the
//! default rule; era corpus (rt98_ref.s103) holds NO trap-class odd desc-LDG
//! (odd = 69 LTC128B + 3 ELL2 only) -> encoder census delta = 0.
//! Complementary to BUG-076 (STG): same direction for true-pair classes,
//! opposite to BUG-060 (EFL2-load). Decode untouched.

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

const W_E_EVEN: u128 = 0x000fc2000c1e190000000004040a7981u128;
const W_E128_EVEN: u128 = 0x000fc2000c1e1d000000000404087981u128;
const W_EFL2_ODD: u128 = 0x000fc2000850e108fe000004050c797eu128;

// (1) trap classes, odd base: fail closed with the silicon citation.
#[test]
fn t1_sm103a_trap_classes_odd_base_rejected() {
    for text in [
        "LDG.E R10, desc[UR4][R3.64]",
        "LDG.E.64 R10, desc[UR4][R3.64]",
        "LDG.E.128 R8, desc[UR4][R3.64]",
        "LDG.E.STRONG.GPU R10, desc[UR4][R3.64]",
        "LDG.E.EF R10, desc[UR4][R3.64]",
        "LDG.E.U16 R10, desc[UR4][R3.64]",
        "LDG.E.256.ENL2 R8, R12, desc[UR4][R3.64]",
        "@P0 LDG.E R10, desc[UR4][R5.64]",
    ] {
        let e = enc(text, &t103a()).expect_err(&format!("odd-base desc LDG must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-077"), "{text}: got: {e}");
    }
}

// (2) same classes, even base: encode, byte-fixed at the pinned words.
#[test]
fn t2_sm103a_even_base_encode_fixed_point() {
    assert_eq!(enc("LDG.E R10, desc[UR4][R4.64]", &t103a()).unwrap(), W_E_EVEN);
    assert_eq!(enc("LDG.E.128 R8, desc[UR4][R4.64]", &t103a()).unwrap(), W_E128_EVEN);
    enc("LDG.E.256.ENL2 R8, R12, desc[UR4][R4.64]", &t103a()).expect("even ENL2 256 OK");
}

// (3) exempt classes per silicon: LTC128B / ELL2 decode+encode unaffected
// by the guard; EFL2 odd REQUIRED (BUG-060 polarity preserved) and EFL2
// even still fails closed by the 060 guard.
#[test]
fn t3_exemptions_and_060_polarity() {
    enc("LDG.E.LTC128B.128 R8, desc[UR8][R7.64]", &t103a())
        .expect("LTC128B class: guard must not fire (silicon 0/7 II)");
    enc("LDG.E.256.ELL2.STRONG.GPU.NA R8, R12, desc[UR4][R3.64]", &t103a())
        .expect("ELL2 class: guard must not fire (silicon 20/20)");
    assert_eq!(
        enc("LDG.E.NA.EFL2.256.STRONG.GPU R8, R12, desc[UR4][R5.64]", &t103a()).unwrap(),
        W_EFL2_ODD,
        "EFL2 odd base REQUIRED on sm_103a (BUG-060)"
    );
    let e = enc("LDG.E.NA.EFL2.256.STRONG.GPU R8, R12, desc[UR4][R4.64]", &t103a())
        .expect_err("EFL2 even base must stay fail-closed (BUG-060)");
    assert!(format!("{e}").contains("BUG-060"), "got: {e}");
}

// (4) arch scoping: sm120 has no verdict -> odd trap form stays encodable.
#[test]
fn t4_sm120_odd_base_still_encodes() {
    enc("LDG.E R10, desc[UR4][R3.64]", &t120())
        .expect("sm120 must keep encoding odd-base desc LDG (no silicon evidence)");
}

// (5) decode retention + guard precision.
#[test]
fn t5_decode_and_precision() {
    let t = t103a();
    enc("IMAD R10, R2, R3, RZ", &t).expect("plain IMAD unaffected");
    enc("LDG.E R10, [R4.64]", &t).expect("plain non-desc LDG unaffected");
    enc("LDG.E R10, desc[UR4][R4]", &t)
        .expect("32-bit desc address unaffected (no pair)");
}
