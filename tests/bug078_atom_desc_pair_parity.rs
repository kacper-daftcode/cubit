//! BUG-078 (candidate F2Q-078; a follow-up of BUG-076/077, closed F2 2026-08-22):
//! ATOMG/REDG desc-form with a 64-bit address pair `desc[URm][Rn.64]`
//! (non-EL classes -- the true register-pair desc addressing mode, vendor
//! render `desc[URm][Rn.64]`) requires an EVEN pair base Rn on sm_103a.
//!
//! Silicon (B300, krunp, GPU idle windows 2026-08-22; records
//! the internal fix archive krunp harness from 060k):
//!   decisive A/B (valid VA composed into the pair):
//!     ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R5.64], R40
//!       -> CUDA_ERROR_ILLEGAL_INSTRUCTION 10/10 across spaced epochs
//!     same with [R2.64] -> OK 10/10, 32-lane ADD sum in memory exact
//!   fault-priority caveat: garbage-address odd probes report
//!     ILLEGAL_ADDRESS (the memory fault precedes the parity check on the
//!     atom path), unlike STG/LDG where odd traps pre-memory. ATOM parity
//!     probing therefore REQUIRES a working transaction.
//!   The plain .EL form (ATOMG/REDG *.EL.STRONG.GPU, vendor render
//!     `[Rn.U32+URm(+off)]`, same mode family as ELL2/EFL2 in BUG-076/077)
//!     has no pair and no parity rule; its transactions are default-desc-
//!     rejected at the memory stage (B12 silicon facts) -- descriptor-campaign
//!     question (b12-full-2), not an encoder-legality one. Era corpus
//!     (rt98_ref.s103): 44 odd desc-atom words, ALL .EL -> encoder census
//!     delta = 0. 2026-11-05: the era text `desc[URm][Rn.64]` + `.EL` no
//!     longer mints that plain word (it was the BUG-041 downcast) -- it mints
//!     the real pair word (measured on silicon the same day: executes through
//!     the 64-bit address; the owner lifted the hard-error doctrine) and
//!     rides this rule (t3b). The plain form is written as the vendor prints
//!     it, `[Rn.U32+URm(+off)]`.
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
// cross-rendered by nvdisasm 13.3 (the internal fix archive
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

// (3) The plain .EL form (single 32-bit offset, no register pair) is outside
// the rule: it encodes at the pinned words from the vendor's own text
// `[Rn.U32+URm]` (nvdisasm 13.1 -b SM103 on W_ATOMG_EL_ODD / W_REDG_EL_ODD /
// W_REDG_EL_RZ; measured rows 2026-11-05, tests/sm120_atomg_el_aruri.rs).
// Until 2026-11-05 the same words were minted from the era text
// `desc[UR4][R5.64]` through a mis-keyed `_P_R_dARI_R` row -- the BUG-041
// downcast (64-bit text, 32-bit word). With the wave-11 tables that text would
// mint the real descriptor-pair word (silicon-legal, 2026-11-05; the BUG-041
// hard error is gone, t3b pins the pair word and the parity rule on it).
// REDG keeps the BUG-454 era-glyph fallback (`PT, desc[..]` -> plain word).
#[test]
fn t3_sm103a_el_plain_form_fixed_points() {
    assert_eq!(
        enc("ATOMG.E.ADD.EL.STRONG.GPU PT, R58, [R5.U32+UR4], R40", &t103a()).unwrap(),
        W_ATOMG_EL_ODD
    );
    assert_eq!(
        enc("REDG.E.ADD.EL.STRONG.GPU [R5.U32+UR4], R40", &t103a()).unwrap(),
        W_REDG_EL_ODD
    );
    assert_eq!(
        enc("REDG.E.ADD.EL.STRONG.GPU [RZ.U32+UR4], R40", &t103a()).unwrap(),
        W_REDG_EL_RZ
    );
    // the BUG-454 era glyph for REDG still maps onto the plain words
    assert_eq!(
        enc("REDG.E.ADD.EL.STRONG.GPU PT, desc[UR4][R5.64], R40", &t103a()).unwrap(),
        W_REDG_EL_ODD
    );
    assert_eq!(
        enc("REDG.E.ADD.EL.STRONG.GPU PT, desc[UR4][RZ.64], R40", &t103a()).unwrap(),
        W_REDG_EL_RZ
    );
}

#[test]
fn t3b_sm103a_el_desc_pair_rides_the_parity_rule() {
    // BUG-041 doctrine lifted 2026-11-05 (owner, after the silicon probe): the `.EL` descriptor-pair
    // text mints the real pair word -- never the plain U32 word again -- and so rides this rule:
    // the odd base R5 is refused on sm_103a like every pair, the even base R2 mints bits 76 + 63.
    let t = t103a();
    let e = enc("ATOMG.E.ADD.EL.STRONG.GPU PT, R58, desc[UR4][R5.64], R40", &t)
        .expect_err("odd-base .EL descriptor pair must not encode for sm_103a");
    assert!(format!("{e}").contains("BUG-078"), "got: {e}");
    let w = enc("ATOMG.E.ADD.EL.STRONG.GPU PT, R58, desc[UR4][R2.64], R40", &t).unwrap();
    assert_eq!((w >> 76) & 1, 1, "descriptor form bit");
    assert_eq!((w >> 63) & 1, 1, "64-bit address pair bit (not the U32 downcast)");
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
