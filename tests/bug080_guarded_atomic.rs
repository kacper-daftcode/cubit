//! BUG-080 (F2Q-080-kand from the F-SS4 census-hi, 2026-08-22): on sm_103a a
//! guard-predicated NON-EL memory atomic (`@Pn`/`@!Pn`/`@UPn` on
//! ATOM/ATOMS/ATOMG/RED/REDG) is SILENTLY BROKEN: the instruction writes
//! NONDET garbage to memory with no trap, at every producer stall tested
//! (S04/S11/S13 variants) and even at the 1x32 occupancy geometry; crucially
//! with an ALWAYS-TRUE guard (`ISETP.EQ P2, PT, RZ, RZ` right before), so the
//! guarded-atom issue path itself is broken, not the dataflow around it.
//! Unguarded instances of the same words perform the service exactly
//! (count-analytic PASS); guarded .EL forms trap loudly (ILLEGAL_ADDRESS on
//! the default descriptor).
//! Raw logs: results/stallsuf/fss4/raw/{x_atomt_d1h,x_atomte,p_atomv}.txt ;
//! probes: work/stallsuf/fss4/x_atomt_d1h.sass.
//! Encoder fails closed (sm_103a-scoped); .EL classes and explicit `@PT`
//! (bit-identical to unguarded) exempt; REDUX is register-space, not a
//! memory atomic, and stays outside.
//! Era corpus (rt98_ref.s103): all 22 guarded-atom sites are .EL (F-SS4
//! guard census) -> zero forced migration, encoder census delta = 0.

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

// Encoder fixed points captured pre-guard (cubit-1952927 lib path); the
// guard rejects or passes through, it never changes payload bits.
const W_ATOMG_PLAIN: u128 = 0x000fc200081ef1148000002c221679a8u128; // unguarded non-EL
const W_ATOMG_EL_GUARDED: u128 = 0x000fc200082ee1260000004d52d639a8u128; // era .EL guarded
const W_REDG_EL_GUARDED: u128 = 0x000fc2000820e10000000051d100498eu128; // era .EL guarded

// (1) the silicon-proven trap class: guarded non-EL ATOMG, all guard shapes.
#[test]
fn t1_sm103a_guarded_nonel_atomg_rejected() {
    for text in [
        "@P2 ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44", // exact x_atomt_d1h shape
        "@!P2 ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44",
        "@UP2 ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44",
        "@!PT ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44", // never-executing: unprobed encoding, fail-closed
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("guarded non-EL ATOMG must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-080"), "{text}: got: {e}");
    }
}

// (2) family coverage by prevention: guarded non-EL REDG / ATOMS / ATOM.
#[test]
fn t2_sm103a_guarded_nonel_family_rejected() {
    for text in [
        "@P4 REDG.E.64.ADD.STRONG.GPU desc[UR20][R34.64], R44",
        "@P0 ATOMS.ADD R10, [R12], R14",
        "@P2 ATOM.E.ADD.STRONG.GPU PT, R10, desc[UR20][R34.64], R44",
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("guarded non-EL family member must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-080"), "{text}: got: {e}");
    }
}

// (3) unguarded non-EL stays encodable at the pinned word (service OK on
// silicon per p_atomv); explicit @PT is bit-identical to unguarded.
#[test]
fn t3_sm103a_unguarded_nonel_fixed_points() {
    assert_eq!(
        enc("ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44", &t103a()).unwrap(),
        W_ATOMG_PLAIN
    );
    assert_eq!(
        enc("@PT ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44", &t103a()).unwrap(),
        W_ATOMG_PLAIN
    );
    enc("REDG.E.64.ADD.STRONG.GPU desc[UR20][R34.64], R44", &t103a())
        .expect("unguarded REDG non-EL unaffected");
    enc("ATOMS.ADD R10, [R12], R14", &t103a()).expect("unguarded ATOMS unaffected");
}

// (4) .EL era forms exempt (loud IA at default-desc; descriptor port is the
// O1-road question): guarded .EL ATOMG/REDG encode at the pinned era words.
#[test]
fn t4_sm103a_el_guarded_exempt_fixed_points() {
    assert_eq!(
        enc("@P3 ATOMG.E.ADD.EL.STRONG.GPU PT, R214, desc[UR38][R82.64], R77", &t103a()).unwrap(),
        W_ATOMG_EL_GUARDED
    );
    assert_eq!(
        enc("@P4 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R209.64], R81", &t103a()).unwrap(),
        W_REDG_EL_GUARDED
    );
}

// (5) precision + arch scope: REDUX (register reduction) unaffected;
// non-atomic guarded ops unaffected; sm120 has no silicon verdict and keeps
// encoding the guarded non-EL form; the BUG-078 parity guard still bites
// (no cross-relaxation).
#[test]
fn t5_precision_and_scope() {
    let t = t103a();
    enc("@P0 REDUX.ADD.U32 UR4, R10", &t).expect("REDUX is register-space, not covered");
    enc("@P0 IMAD R10, R2, R3, RZ", &t).expect("guarded ALU unaffected");
    enc("@P0 STG.E desc[UR20][R34.64], R40", &t).expect("guarded STG unaffected");
    enc("@P0 LDG.E.64 R10, desc[UR20][R34.64]", &t).expect("guarded LDG unaffected");
    enc("@P2 ATOMG.E.ADD.STRONG.GPU PT, R22, desc[UR20][R34.64], R44", &t120())
        .expect("sm120 keeps encoding guarded non-EL ATOMG (no silicon evidence)");
    let e = enc("ATOMG.E.ADD.STRONG.GPU PT, R58, desc[UR4][R5.64], R40", &t)
        .expect_err("BUG-078 odd-base guard untouched");
    assert!(format!("{e}").contains("BUG-078"), "got: {e}");
}
