//! BUG-178 (iter85, front MAIN, loop5/blind; queue = fleet note 177 sec.5(b)
//! "178-kand [decyzja]", taken per the fleet's oldest-LOW-first precedent):
//! encode-side silent fabrication through the `Label -> "II"` fallback onto
//! BAKED-immediate table rows (winning entry owns NO field for the operand
//! token; the constant lives in and_base). Concrete lane: `FSEL_R_R_II_P`
//! bakes +QNAN (0x7FC00000 on [32:64)); before this fix `+QNAN`, `-QNAN`,
//! and `FOOBAR` all emitted the SAME +QNAN word — sign and typos vanished
//! at byte production (sm120 has no such row and was already fail-closed;
//! verified identical on clean 2f579f0, see report sec.3).
//!
//! Census-first (hexdb 32.2M): 6,380 vendor NaN-imm lines — FSEL +QNAN
//! 4,132 / FSEL -QNAN 412 / FMUL +QNAN 256 / MUFU.RSQ -QNAN 1,580; SNAN 0.
//! Table audit (audit's own script work/bug178/audit178.py): sm103a has 25
//! II-baked (key, mod_group) rows — branch ops excluded (BUG-091 gate),
//! float lane = FSEL/FMUL (+QNAN), MUFU.RSQ (-QNAN); sm120 II-baked rows
//! are branch-only. Baked constants measured on [32:64): FSEL 0x7FC00000,
//! FMUL 0x7FC00000 (both asserted below), MUFU.RSQ 0xFFC00000.
//!
//! Decision (the "decyzja" of the candidate): TIGHTEN, scoped to the
//! Label-on-baked-row lane. Admitted symbolically: QNAN/+QNAN/-QNAN/
//! SNAN/+SNAN/-SNAN, and only when the symbol equals the row's baked f32
//! constant on [32:64); everything else fails closed with attribution.
//! Numeric immediates are untouched (FI row / 0x<8-hex>F; labels own the
//! "II" key family only). Desc-label (LblPat) tokens are legitimate and
//! skipped. Label-on-imm-FIELD degradation (Label -> 0) is a separate
//! legacy lane: filed as the 183-kand, out of scope.

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

/// t178_1: symbols equal to the row's baked constant keep working, same word
/// as pre-fix (admission with exact bit match). Case-insensitive like the
/// parser's NAN/INF acceptance.
#[test]
fn t178_1_matching_symbols_admitted() {
    let t = t103();
    let w = enc(&t, "FSEL R7, RZ, +QNAN , !P1 ;").expect("+QNAN on FSEL admitted");
    assert_eq!((w >> 32) as u32, 0x7FC0_0000, "FSEL +QNAN imm lane");
    for text in [
        "FSEL R7, RZ, QNAN , !P1 ;",
        "FSEL R7, RZ, qnan , !P1 ;",
        "FSEL R7, RZ, +qNaN , !P1 ;",
    ] {
        assert_eq!(enc(&t, text).ok(), Some(w), "{text}: word drift");
    }
    let fm = enc(&t, "FMUL R2, R3, +QNAN ;").expect("+QNAN on FMUL admitted");
    assert_eq!((fm >> 32) as u32, 0x7FC0_0000, "FMUL +QNAN imm lane");
    let mu = enc(&t, "MUFU.RSQ R1, -QNAN ;").expect("-QNAN on MUFU.RSQ admitted");
    assert_eq!((mu >> 32) as u32, 0xFFC0_0000, "MUFU.RSQ -QNAN imm lane");
}

/// t178_2: symbol != baked constant refuses with attribution (the sign-loss
/// lane) — FSEL/FMUL bake +QNAN so -QNAN/SNAN must fail; MUFU.RSQ bakes
/// -QNAN so +QNAN must fail. Message must name BUG-178 and the baked value.
#[test]
fn t178_2_mismatched_symbols_refused() {
    let t = t103();
    for (text, want_baked) in [
        ("FSEL R7, RZ, -QNAN , !P1 ;", "0x7fc00000"),
        ("FSEL R7, RZ, +SNAN , !P1 ;", "0x7fc00000"),
        ("FSEL R7, RZ, -SNAN , !P1 ;", "0x7fc00000"),
        ("FMUL R2, R3, -QNAN ;", "0x7fc00000"),
        ("MUFU.RSQ R1, +QNAN ;", "0xffc00000"),
        ("MUFU.RSQ R1, +SNAN ;", "0xffc00000"),
    ] {
        let err = enc(&t, text).expect_err(&format!("{text}: must refuse"));
        assert!(err.contains("BUG-178"), "{text}: attribution missing: {err}");
        assert!(err.contains(want_baked), "{text}: baked value missing: {err}");
    }
}

/// t178_3: unknown identifiers on a baked-imm row refuse (the typo lane),
/// on more than one row family.
#[test]
fn t178_3_unknown_identifiers_refused() {
    let t = t103();
    for text in [
        "FSEL R7, RZ, FOOBAR , !P1 ;",
        "FSEL R7, RZ, QNAAN , !P1 ;",
        "FMUL R2, R3, NaNish ;",
        "MUFU.RSQ R1, INFINITY ;",
    ] {
        let err = enc(&t, text).expect_err(&format!("{text}: must refuse"));
        assert!(err.contains("unresolved identifier"), "{text}: wrong arm: {err}");
        assert!(err.contains("BUG-178"), "{text}: attribution missing: {err}");
    }
}

/// t178_4: invariants — numeric immediates (FI row and hex-float escape
/// path), the sm120 fail-closed posture, small-int baked rows, and the
/// branch-label gate all behave exactly as pre-fix.
#[test]
fn t178_4_invariants_unchanged() {
    let t = t103();
    // numeric "5" is a float-context plain int -> FI row, f32 5.0
    let w5 = enc(&t, "FSEL R7, RZ, 5 , !P1 ;").expect("numeric imm encodes");
    assert_eq!((w5 >> 32) as u32, 5.0f32.to_bits(), "FI numeric lane");
    // hex-float escape path 0x<8 hexdigits>F -> FI row raw bits
    let wh = enc(&t, "FSEL R7, RZ, 0xFFC00000F , !P1 ;").expect("hex-float -QNAN encodes");
    assert_eq!((wh >> 32) as u32, 0xFFC0_0000, "hex-float escape path");
    // vendor-legit system symbols on baked rows stay admitted, op-scoped
    // (hexdb census: PR 3,651+63 on P2R / 2,882+ on R2P; UPR on UP2UR;
    // Rpc.LO on RPCMOV.32). The baked constant IS the symbol there.
    enc(&t, "P2R R6, PR, R12, 0xff ;").expect("P2R PR unaffected");
    enc(&t, "R2P PR, R9, 0x6 ;").expect("R2P PR unaffected");
    enc(&t, "UP2UR UR2, UPR, URZ, 0x1 ;").expect("UP2UR UPR unaffected");
    enc(&t, "RPCMOV.32 R4, Rpc.LO ;").expect("RPCMOV Rpc.LO unaffected");
    // cross-op pollution must NOT be admitted by the system-symbol arm
    let e = enc(&t, "FSEL R7, RZ, PR , !P1 ;").expect_err("PR off-family refuses");
    assert!(e.contains("BUG-178"), "{e}");
    // LEPC's backtick label: pre-fix it silently encoded a fixed constant
    // losing the address entirely; now refuses. Compose 2026-08-26: BUG-184
    // landed in the same wave and gives the refusal first through its
    // BUG-091-style unresolved-label gate (the 178 note named 184 the parked
    // owner of LEPC label semantics).
    let e = enc(&t, "LEPC R4, `(.L_x_3) ;").expect_err("LEPC label refuses");
    assert!(e.contains("BUG-178") || e.contains("unresolved branch label"), "{e}");
    // sm120: no II-baked FSEL row -> still fail-closed (pre-existing posture)
    enc(&t120(), "FSEL R7, RZ, QNAN , !P1 ;").expect_err("sm120 stays fail-closed");
    // branch labels: undefined -> BUG-091 refuse; defined -> resolves & encodes
    let e = enc(&t, "BRA nowhere ;").expect_err("undefined branch label refuses");
    assert!(e.contains("unresolved branch label"), "BUG-091 arm intact: {e}");
    assemble_ok("BRA done ;\ndone: NOP ;");
}

/// t178_5: anchor fixed-point discipline (the fleet-style byte-exact
/// proof): admitted +QNAN anchors re-encode to the word that decodes back
/// to the same text (render -> asm -> render fixed point, canonical payload
/// lane byte-exact vs the vendor anchor). Payload-variant lanes need the
/// hex-float form; the -QNAN symbolic form is refused (it never round-
/// tripped pre-fix either — it silently emitted the +QNAN word).
#[test]
fn t178_5_anchor_fixed_point() {
    use cubit::decoder::DecodeIndex;
    let t = t103();
    let idx = DecodeIndex::build(&t);
    // canonical +QNAN anchor: full byte-exact round-trip of the text lane.
    let want = u128::from_str_radix("000fe200048000007fc00000ff077808", 16).unwrap();
    let w = enc(&t, "FSEL R7, RZ, +QNAN , !P1 ;").expect("+QNAN admitted");
    assert_eq!((w >> 32) as u32, 0x7FC0_0000, "imm lane");
    let d = idx.decode(w, 0, &t).expect("decode own word");
    let s = cubit::printer::to_sass(&d);
    let s = s.split("/* @sched").next().unwrap().split(" !rsd[").next().unwrap();
    let w2 = enc(&t, s.trim()).expect("render re-encodes");
    assert_eq!(w, w2, "fixed point on the admitted lane; render was: {s}");
    // payload-variant anchor (0x7FF80000): encode the anchor text the vendor
    // way (hex-float) and require the exact imm lane back.
    let wv = enc(&t, "FSEL R13, RZ, 0x7FF80000F , !P2 ;").expect("hex-float");
    assert_eq!((wv >> 32) as u32, 0x7FF8_0000, "payload lane via hex-float");
    // -QNAN anchor (0xFFF00000): symbolic refuses with attribution; the
    // hex-float form reproduces the exact lane; and pre-fix the symbolic
    // form degraded to the +QNAN word (proven by neg-ctl on t178_2).
    let err = enc(&t, "FSEL R11, R9, -QNAN , P0 ;").expect_err("-QNAN symbolic refuses");
    assert!(err.contains("BUG-178"), "{err}");
    let wn = enc(&t, "FSEL R11, R9, 0xFFF00000F , P0 ;").expect("hex-float encodes");
    assert_eq!((wn >> 32) as u32, 0xFFF0_0000, "-QNAN via hex-float, exact lane");
}

/// t178_6: the check is exhaustive over the float lane — every baked-imm
/// (key, mod_group) row with a float constant from the table audit admits
/// its own symbol and refuses the complement. (Data-asserted law:
/// FSEL 0x7FC00000 / FMUL 0x7FC00000 / MUFU.RSQ 0xFFC00000 on [32:64).)
#[test]
fn t178_6_float_lane_exhaustive() {
    let t = t103();
    for (good, bads) in [
        ("FSEL R7, RZ, +QNAN , !P1 ;", vec!["FSEL R7, RZ, -QNAN , !P1 ;"]),
        ("FMUL R2, R3, +QNAN ;", vec!["FMUL R2, R3, -QNAN ;"]),
        ("MUFU.RSQ R1, -QNAN ;", vec!["MUFU.RSQ R1, +QNAN ;", "MUFU.RSQ R1, QNAN ;"]),
    ] {
        enc(&t, good).unwrap_or_else(|e| panic!("{good}: admitted lane broke: {e}"));
        for b in bads {
            enc(&t, b).expect_err(&format!("{b}: refused lane opened"));
        }
    }
}
