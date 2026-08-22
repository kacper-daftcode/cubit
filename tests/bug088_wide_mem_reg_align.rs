//! BUG-088 (F2Q-088-kand; b12-full-2 preflight + dedicated B300 krunp probe
//! matrix 2026-08-22, work/f2-088/probes + results/cubitfix/088/): wide
//! const/shared-memory accesses enforce destination/data register alignment
//! laws that the encoder used to accept silently; the word then traps
//! CUDA_ERROR_ILLEGAL_INSTRUCTION at execution:
//!   * LDC.64 dest R odd -> II (cAI + cARI; even OK, RZ exempt)
//!   * LDCU.64 dest UR odd -> II (UR5/UR61/REAL UR63; even OK, URZ exempt)
//!   * LDS.64 dest / STS.64 data odd -> II (even OK, RZ exempt)
//!   * LDS.128 dest / STS.128 data: legal iff RZ | Rn%8==0 | (Rn<44 & %4==0)
//!     (%4!=0 traps everywhere tested; odd-quad >=11 traps)
//!   * LDC.128 deliberately unguarded (no silicon constraint observed)
//! Pins both trap classes (fail-closed, BUG-088 message) and the legal-form
//! byte-exact fixed points (guard is reject/pass-through, never rewrites).
//! Scope: sm_103a table only; encoder side; decode untouched.

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
/// The env-unlock pin flips process-wide CUBIT_DISABLE_ERRATA; serialize all
/// tests in this binary so no reject-case runs while the guard is off.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

// Legal-form fixed points captured pre-guard (cubit-9e3ff80); the guard is
// pure reject/pass-through and must never perturb payload bits.
const W_LDC64_R54: u128 = 0x000fc20000000a000000e000ff367b82;
const W_LDC64_RZ: u128 = 0x000fc20000000a000000e000ffff7b82;
const W_LDC128_R53: u128 = 0x000fc200000008000000e000ff357b82;
const W_LDCU64_UR4: u128 = 0x000fc20008000a0000006b00ff0477ac;
const W_LDCU64_UR62: u128 = 0x000fc20008000a0000006b00ff3e77ac;
const W_LDCU64_URZ: u128 = 0x000fc20008000a0000006b00ffff77ac;
const W_LDS64_R6: u128 = 0x000fc20000000a000000000008067984;
const W_STS64_R6: u128 = 0x000fc20000000a000000000608007388;
const W_STS64_RZ: u128 = 0x000fc20000000a00000000ff08007388;
const W_STS128_R200: u128 = 0x000fc2000000cc00000000c805007388;
const W_STS128_R28: u128 = 0x000fc2000000cc000000001c05007388;
const W_STS128_R32_IMM: u128 = 0x000fc2000000cc000000102005007388;
const W_LDS128_R48: u128 = 0x000fc20000000c000000000005307984;
const W_LDS128_R4: u128 = 0x000fc20000000c000000000005047984;
const W_LDC32_R53: u128 = 0x000fc200000008000000e200ff357b82;
const W_LDC64_R53_120: u128 = 0x000fc20000000a000000e000ff357b82;

// (1) the headline trap class (b12-full-2 preflight find): LDC.64 odd dest.
#[test]
fn t1_sm103a_ldc64_odd_dest_rejected() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    for text in [
        "LDC.64 R53, c[0x0][0x380]",  // exact m9a preflight kill
        "LDC.64 R201, c[0x0][0x380]", // odd high
        "LDC.64 R53, c[0x0][R4]",     // cARI register-offset form, same law
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("LDC.64 odd dest must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-088"), "{text}: got: {e}");
    }
}

// (2) LDCU.64 uniform-domain parity: odd (incl. REAL UR63) rejected,
// even + URZ fixed points legal.
#[test]
fn t2_sm103a_ldcu64_odd_dest_rejected() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    for text in [
        "LDCU.64 UR5, c[0x0][0x358]",
        "LDCU.64 UR61, c[0x0][0x358]",
        "LDCU.64 UR63, c[0x0][0x358]", // real UR63 traps; only URZ exempt
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("LDCU.64 odd dest must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-088"), "{text}: got: {e}");
    }
    assert_eq!(enc("LDCU.64 UR4, c[0x0][0x358]", &t103a()).unwrap(), W_LDCU64_UR4);
    assert_eq!(enc("LDCU.64 UR62, c[0x0][0x358]", &t103a()).unwrap(), W_LDCU64_UR62);
    assert_eq!(enc("LDCU.64 URZ, c[0x0][0x358]", &t103a()).unwrap(), W_LDCU64_URZ);
}

// (3) LDS.64/STS.64 even-odd law + RZ exemption fixed points.
#[test]
fn t3_sm103a_lds_sts_64_parity() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    for text in [
        "LDS.64 R5, [R8]",
        "LDS.64 R201, [R8]",
        "STS.64 [R8], R5",
        "STS.64 [R8], R201",
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("64-bit LDS/STS odd register must not encode for sm_103a: {text}"));
        assert!(format!("{e}").contains("BUG-088"), "{text}: got: {e}");
    }
    assert_eq!(enc("LDS.64 R6, [R8]", &t103a()).unwrap(), W_LDS64_R6);
    assert_eq!(enc("STS.64 [R8], R6", &t103a()).unwrap(), W_STS64_R6);
    assert_eq!(enc("STS.64 [R8], RZ", &t103a()).unwrap(), W_STS64_RZ);
}

// (4) the .128 law: %4!=0 rejected everywhere; odd-quad >=11 rejected; the
// legal window (RZ, Rn%8==0, Rn<44 aligned) fixed points byte-exact.
#[test]
fn t4_sm103a_lds_sts_128_alignment_law() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    for text in [
        "STS.128 [R5.X16], R44",        // quad 11 (first illegal odd quad)
        "STS.128 [R5.X16+0x10], R204",  // verbatim era word (quad 51; dead path at runtime)
        "STS.128 [R5.X16], R45",        // %4=1
        "STS.128 [R5.X16], R46",        // %4=2
        "STS.128 [R5.X16], R49",        // even quad but %4!=0
        "STS.128 [R5.X16], R13",        // low window does NOT exempt %4!=0
        "LDS.128 R52, [R5]",            // LDS dest same law (quad 13)
        "LDS.128 R13, [R5]",
    ] {
        let e = enc(text, &t103a())
            .expect_err(&format!("128-bit LDS/STS illegal alignment must not encode: {text}"));
        assert!(format!("{e}").contains("BUG-088"), "{text}: got: {e}");
    }
    assert_eq!(enc("STS.128 [R5.X16], R200", &t103a()).unwrap(), W_STS128_R200);
    assert_eq!(enc("STS.128 [R5.X16], R28", &t103a()).unwrap(), W_STS128_R28);
    assert_eq!(enc("STS.128 [R5.X16+0x10], R32", &t103a()).unwrap(), W_STS128_R32_IMM);
    assert_eq!(enc("LDS.128 R48, [R5]", &t103a()).unwrap(), W_LDS128_R48);
    assert_eq!(enc("LDS.128 R4, [R5]", &t103a()).unwrap(), W_LDS128_R4);
}

// (5) deliberately unguarded: LDC.128 (silicon shows NO constraint: R53/R54/
// R201 all execute), plain 32-bit LDC, LDC.64 even + RZ fixed points.
#[test]
fn t5_sm103a_unconstrained_forms_fixed_points() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    assert_eq!(enc("LDC.64 R54, c[0x0][0x380]", &t103a()).unwrap(), W_LDC64_R54);
    assert_eq!(enc("LDC.64 RZ, c[0x0][0x380]", &t103a()).unwrap(), W_LDC64_RZ);
    assert_eq!(enc("LDC.128 R53, c[0x0][0x380]", &t103a()).unwrap(), W_LDC128_R53);
    assert_eq!(enc("LDC R53, c[0x0][0x388]", &t103a()).unwrap(), W_LDC32_R53);
}

// (6) scope + env unlock: sm120 table passes the era-illegal shapes through
// (no sm120 silicon evidence), and CUBIT_DISABLE_ERRATA unlocks the guard on
// the 103a table for analysis.
#[test]
fn t6_scope_and_env_unlock() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    assert_eq!(
        enc("LDC.64 R53, c[0x0][0x380]", &t120()).unwrap(),
        W_LDC64_R53_120,
        "guard must stay sm_103a-scoped (no sm120 silicon evidence)"
    );
    // era word encodes fine on the sm120 table as well (frozen-chain safety)
    enc("STS.128 [R5.X16+0x10], R204", &t120())
        .expect("sm120 table must stay unguarded");
    unsafe { std::env::set_var("CUBIT_DISABLE_ERRATA", "1") };
    let w = enc("LDC.64 R53, c[0x0][0x380]", &t103a());
    unsafe { std::env::remove_var("CUBIT_DISABLE_ERRATA") };
    assert_eq!(w.unwrap(), 0x000fc20000000a000000e000ff357b82, "env unlock must pass through byte-identically");
    // guard active again after env removal
    enc("LDC.64 R53, c[0x0][0x380]", &t103a())
        .expect_err("guard must re-engage once CUBIT_DISABLE_ERRATA is unset");
}
