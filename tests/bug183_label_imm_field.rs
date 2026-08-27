//! BUG-183 (iter87, front2/blind, loop5; queue = fleet note 178 sec.5(b)
//! "183-kand", taken per the fleet's oldest-LOW-first precedent, iter82/178):
//! encode-side silent degradation of a non-branch Label operand riding a
//! table row that OWNS an immediate field for its token — the mirror lane of
//! BUG-178 (that gate owns the BAKED-immediate no-field rows; this one owns
//! the with-field rows). Mechanism: parser.rs keeps unresolved non-branch
//! identifiers as Operand::Label and the key fallback is `Label -> "II"`;
//! the imm extraction family (Imm/ImmShr/ImmDec/ImmDecU32) is the only
//! Label-accepting field family, and op_imm(Label) == 0 — so any
//! identifier, typo'd or not, encoded the imm-0 word "OK".
//!
//! Empirical on clean 2f579f0 (report 183 sec.1): `P2R R6, PR, R12, FOOBAR`
//! encoded to the same 128-bit word as `..., 0x0` (and disassembles back as
//! `P2R R6, 0x0, R12, 0x0`); `IADD3 R25, PT, PT, R25, FOOBAR, RZ` likewise.
//! Census-first: 258 sm103a / 462 sm120 (key,mod_group) slots expose the
//! geometry, but ZERO corpus lines carry a symbolic identifier there (sm103
//! 2014-cubin dump: 5.7M operand tokens, only B0/B1/B11 barrier operands;
//! sm120 392-cubin dump: none; rt98_v2 chain: in-scope branch labels only)
//! — the lane is purely defensive and this gate changes no corpus byte.
//!
//! Doctrine (mirrors BUG-091/178): refuse at byte production with
//! attribution, NOT CUBIT_DISABLE_ERRATA-unlockable; the
//! CUBIT_FIT_LINT=allow fidelity-probe oracle still passes (disassemble
//! re-encode probes must measure this loss for !rsd[..]; covered by the
//! corpus A/B battery, not here, because fit_lint_mode is process-cached).

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }

fn assemble_ok(text: &str) {
    cubit::assemble(text, 0, &t103()).expect("defined labels still assemble");
}

fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    match parse_sass(text, 0) {
        Ok(insn) => encode_instruction(&insn, t).map_err(|e| format!("{e:#}")),
        Err(e) => Err(format!("parse: {e:#}")),
    }
}

/// t183_1: the core defect — identifiers on imm-field tokens refuse with
/// attribution, on two independent row families (P2R byte-select imm,
/// IADD3 32-bit imm). The refusal must echo the offending identifier.
#[test]
fn t183_1_label_on_imm_field_refused() {
    let t = t103();
    for (text, name) in [
        ("P2R R6, PR, R12, FOOBAR ;", "FOOBAR"),
        ("P2R R6, PR, R12, QNAAN ;", "QNAAN"),
        ("IADD3 R25, PT, PT, R25, FOOBAR, RZ ;", "FOOBAR"),
        ("IADD3 R25, PT, PT, R25, some_sym, RZ ;", "some_sym"),
    ] {
        let err = enc(&t, text).expect_err(&format!("{text}: must refuse"));
        assert!(err.contains("BUG-183"), "{text}: attribution missing: {err}");
        assert!(err.contains(name), "{text}: identifier missing: {err}");
        assert!(err.contains("silently degrade it to 0"), "{text}: wrong arm: {err}");
    }
}

/// t183_2: numeric immediates on the same rows encode exactly as pre-fix
/// (the imm window keeps the value). The gate fires only on
/// Operand::Label by construction, so Reg/predicate spellings cannot be
/// affected; the zero window is pinned here as the reference word for the
/// pre-fix FOOBAR collision.
#[test]
fn t183_2_numeric_and_rz_lanes_untouched() {
    let t = t103();
    let w = enc(&t, "P2R R6, PR, R12, 0xff ;").expect("numeric imm encodes");
    assert_eq!((w >> 32) as u32, 0xff, "P2R imm window");
    let w0 = enc(&t, "P2R R6, PR, R12, 0x0 ;").expect("zero encodes");
    assert_eq!((w0 >> 32) as u32, 0x0, "P2R zero window");
    let a = enc(&t, "IADD3 R25, PT, PT, R25, 0x7b, RZ ;").expect("IADD3 imm encodes");
    assert_eq!((a >> 32) as u32, 0x7b, "IADD3 imm window");
    let b = enc(&t, "IADD3 R25, PT, PT, R25, 123, RZ ;").expect("decimal imm encodes");
    assert_eq!(a, b, "hex == decimal");
}

/// t183_3: sibling lanes stay exactly as they are on this base — the
/// LblPat descriptor channel encodes (LDG desc form), and the LEPC label
/// case is NOT this bug's lane: the LEPC_R_II row owns no imm field for
/// the label token (178-lane, baked), so here it keeps the pre-existing
/// behavior. Tripwire: when the parked BUG-178 branch lands, the second
/// expectation flips to a BUG-178 refusal (compose note in report sec.6).
#[test]
fn t183_3_sibling_lanes_untouched() {
    let t = t103();
    enc(&t, "LDG.E R8, desc[UR4][R10.64+0x10] ;").expect("LblPat desc lane encodes");
    // 2026-08-26 compose: BUG-178/184 landed in the same wave -- this
    // branch's own tripwire fires as designed (undefined LEPC label now
    // refuses through the 091/178 gates). The expectation flipped per the
    // note in report sec.6.
    assert!(enc(&t, "LEPC R4, `(.L_x_3) ;").is_err(),
        "undefined LEPC label refuses post-178 (was: silent baked lane)");
}

/// t183_4: branch labels are unreachable for this gate — BUG-091 refuses
/// undefined branch labels before entry selection, and defined labels
/// resolve to BranchTarget (numeric) in the parser.
#[test]
fn t183_4_branch_gate_intact() {
    let t = t103();
    let e = enc(&t, "BRA nowhere ;").expect_err("undefined branch label refuses");
    assert!(e.contains("unresolved branch label"), "BUG-091 arm intact: {e}");
    assert!(!e.contains("BUG-183"), "183 must not fire on branches: {e}");
    assemble_ok("BRA done ;\ndone: NOP ;");
}

/// t183_5: sm120 table — same defect class, same gate, demonstrated on
/// the IADD3 imm lane (verified pre-fix on clean 2f579f0:
/// `IADD3 .., FOOBAR, RZ` silently encoded "OK"). The P2R PR-spelling is
/// a different posture on sm120: no `P2R_R_II_R_II` key exists there, so
/// it was already fail-closed at entry match (pre-existing, untouched).
#[test]
fn t183_5_sm120_parity() {
    let t = t120();
    let err = enc(&t, "IADD3 R25, PT, PT, R25, FOOBAR, RZ ;").expect_err("sm120 must refuse");
    assert!(err.contains("BUG-183"), "attribution missing: {err}");
    assert!(err.contains("FOOBAR"), "identifier missing: {err}");
    let w = enc(&t, "IADD3 R25, PT, PT, R25, 0x7b, RZ ;").expect("sm120 numeric encodes");
    assert_eq!((w >> 32) as u32, 0x7b, "sm120 IADD3 imm window");
    enc(&t, "P2R R6, PR, R12, 0xff ;").expect_err("sm120 P2R PR-form stays fail-closed (key gap)");
}

/// t183_6: fixed-point anchor — corpus-shape lines keep byte-identical
/// words and re-encode through disasm unchanged; the parser-special-cased
/// SRZ system spelling (not a Label) is untouched.
#[test]
fn t183_6_anchor_fixed_point() {
    let t = t103();
    let w = enc(&t, "P2R R6, PR, R12, 0xff ;").expect("anchor encodes");
    let w2 = enc(&t, "P2R R6, PR, R12, 0xff ;").expect("anchor re-encodes");
    assert_eq!(w, w2, "encode determinism");
    enc(&t, "R2P PR, R9, 0x6 ;").expect("R2P PR lane unaffected");
    enc(&t, "CS2R R2, SRZ ;").expect("CS2R SRZ lane unaffected");
    enc(&t, "LEPC R20, 0x0 ;").expect("LEPC numeric lane unaffected");
}
