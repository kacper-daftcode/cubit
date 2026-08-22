//! BUG-078 (F2Q-078-kand; follow-up BUG-076/077, zamkniete F2 2026-08-22):
//! ATOMG/REDG desc-form with a 64-bit address pair `desc[URm][Rn.64]`
//! (non-EL classes -- the true register-pair desc addressing mode, vendor
//! render `desc[URm][Rn.64]`) requires an EVEN pair base Rn on sm_103a.
//!
//! Silicon (B300, krunp, GPU idle windows 2026-08-22; records
//! results/cubitfix/078/krun_record.txt; krunp harness from 060k):
//!   decisive A/B (valid VA composed into the pair):
//!     ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R5.64], R40
//!       -> CUDA_ERROR_ILLEGAL_INSTRUCTION 10/10 across spaced epochs
//!     same with [R2.64] -> OK 10/10, 32-lane ADD sum in memory exact
//!   fault-priority caveat: garbage-address odd probes report
//!     ILLEGAL_ADDRESS (the memory fault precedes the parity check on the
//!     atom path), unlike STG/LDG where odd traps pre-memory. ATOM parity
//!     probing therefore REQUIRES a working transaction.
//!   .EL classes exempt: ATOMG/REDG *.EL.STRONG.GPU encode in the
//!     single-32-bit-offset desc mode (vendor render `[Rn.U32+URm]`, same
//!     mode family as ELL2/EFL2 in BUG-076/077) -- no pair, no parity rule;
//!     their transactions are default-desc-rejected at the memory stage
//!     (B12 silicon facts) -- descriptor-campaign question (b12-full-2),
//!     not an encoder-legality one. Era corpus (rt98_ref.s103): 44 odd
//!     desc-atom words, ALL .EL -> encoder census delta = 0.
//! Decode untouched. sm120: no evidence -> guard scoped to target_sm()==103.

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

// Fixed points: words produced by the pre-guard encoder (cubit-0d14959),
// cross-rendered by nvdisasm 13.3 (results/cubitfix/078/probes/*.cubin).
// NOTE: constants are ENCODER fixed points (encode_instruction returns the
// payload with the default ctrl pattern 0x000fc200..; the scheduled cubins
// carry the same payload -- nvdisasm hex differs only in the ctrl field).
const W_ATOMG_EVEN: u128 = 0x000fc200081ef10480000028023a79a8u128;
const W_ATOMG_EL_ODD: u128 = 0x000fc200082ee10400000028053a79a8u128;
const W_REDG_EL_ODD: u128 = 0x000fc2000820e104000000280500798eu128;
const W_REDG_EL_RZ: u128 = 0x000fc2000820e10400000028ff00798eu128;

// (1) non-EL trap class, odd base: fail closed with the silicon citation.
#[test]
fn t1_sm103a_atomg_odd_base_rejected() {
    for text in [
        "ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R5.64], R40",
        "@P0 ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R3.64], R40",
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("odd-base desc ATOMG (non-EL) must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-078"), "{text}: got: {e}");
    }
}

// (2) non-EL, even base: encode, byte-fixed at the pinned word.
#[test]
fn t2_sm103a_atomg_even_base_fixed_point() {
    assert_eq!(
        enc("ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R2.64], R40", &t103a()).unwrap(),
        W_ATOMG_EVEN
    );
}

// (3) .EL classes exempt (single-offset desc mode, no register pair):
// odd base encodes at the pinned words; RZ base too (era idiom).
#[test]
fn t3_sm103a_el_classes_exempt_fixed_point() {
    assert_eq!(
        enc("ATOMG.E.ADD.EL.STRONG.GPU PT, R58, desc[UR4][R5.64], R40", &t103a()).unwrap(),
        W_ATOMG_EL_ODD
    );
    assert_eq!(
        enc("REDG.E.ADD.EL.STRONG.GPU PT, desc[UR4][R5.64], R40", &t103a()).unwrap(),
        W_REDG_EL_ODD
    );
    assert_eq!(
        enc("REDG.E.ADD.EL.STRONG.GPU PT, desc[UR4][RZ.64], R40", &t103a()).unwrap(),
        W_REDG_EL_RZ
    );
}

// (4) arch scoping: sm120 has no verdict -> odd trap form stays encodable.
#[test]
fn t4_sm120_odd_base_still_encodes() {
    enc("ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R5.64], R40", &t120())
        .expect("sm120 must keep encoding odd-base desc ATOMG (no silicon evidence)");
    enc("REDG.E.ADD.STRONG.GPU desc[UR4][R5.64], R40", &t120())
        .expect("sm120 must keep encoding odd-base desc REDG (no silicon evidence)");
}

// (5) guard precision: plain/pair forms outside the desc-pair class and
// non-atom opcodes stay unaffected; LDCU descriptor producer unaffected.
#[test]
fn t5_precision() {
    let t = t103a();
    enc("IMAD R10, R2, R3, RZ", &t).expect("plain IMAD unaffected");
    enc("LDCU.64 UR4, c[0x0][0x358]", &t).expect("LDCU unaffected");
    enc("ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R5], R40", &t)
        .expect("32-bit desc address unaffected (no pair)");
    // The neighboring guards keep their scope (no cross-relaxation):
    let e = enc("STG.E.64 desc[UR4][R5.64], R10", &t)
        .expect_err("BUG-076 STG guard untouched");
    assert!(format!("{e}").contains("BUG-076"), "got: {e}");
    let e = enc("LDG.E.64 R10, desc[UR4][R5.64]", &t)
        .expect_err("BUG-077 LDG guard untouched");
    assert!(format!("{e}").contains("BUG-077"), "got: {e}");
}
