//! BUG-118 pins: ptx_lower must never emit SASS that reads a register
//! without a producer (b10 PHASE-2c: pd64/pi64/pr_rw_ldcgs faulted
//! deterministically with ILLEGAL_ADDRESS 700 on silicon while ptxas was
//! fine). Two layers pinned here:
//!   A) last-use-aware pair freeing (cvta AliasPair no longer drops a
//!      still-live binding),
//!   B) the fail-closed use-before-def GATE at the end of lower_kernel
//!      (entry liveness on the rendered text, R+UR domains),
//! plus the run-to-run determinism of the emitted text (dead-pred sink
//! order). Report: results/cubitfix/118.md.
use cubit::ptx_lower::{check_use_before_def, lower_kernel};
use cubit::ptx_parse::parse_ptx;
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn lower_text(ptx: &str) -> String {
    let kernels = parse_ptx(ptx).unwrap();
    lower_kernel(&kernels[0]).unwrap().to_sass_text()
}

/// Strip directives and feed the body through the bare assembler, proving
/// the emitted stream is encodable (same helper shape as tests/b9_ptx_lower).
fn assemble_body(text: &str) -> Vec<u8> {
    let body: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('.'))
        .collect::<Vec<_>>()
        .join("\n");
    cubit::assemble(&body, 0, &table()).unwrap().0
}

const PROLOG: &str = ".version 9.3\n.target sm_103a\n.address_size 64\n\n";

/// A: cvta alias pair freed at first (non-last) use pre-fix -> STG address
/// rebound to never-written pair. Post-fix the STG address pair MUST be the
/// LDC-written pair (R2:R3) and the LDG dst must NOT collide with it.
#[test]
fn t118_1_cvta_alias_pair_survives_store() {
    let ptx = format!(r"{} .visible .entry _Z1kPd(
    .param .u64 .ptr .align 1 _Z1kPd_param_0
)
{{
    .reg .b64  %rd<5>;
    ld.param.b64      %rd1, [_Z1kPd_param_0];
    cvta.to.global.u64 %rd2, %rd1;
    ld.global.b64     %rd3, [%rd2];
    add.f64           %rd4, %rd3, 0d3FF0000000000000;
    st.global.b64     [%rd2], %rd4;
    ret;
}}", PROLOG);
    let text = lower_text(&ptx); // pre-fix: the GATE itself rejects this
    assert!(text.contains("LDC.64 R2, c[0x0][0x380]"), "param load must own R2:R3:\n{}", text);
    assert!(text.contains("LDG.E.64 R4, desc[UR4][R2.64]"),
        "ld dst must not collide with the live address pair:\n{}", text);
    assert!(text.contains("STG.E.64 desc[UR4][R2.64], R6"),
        "store must reuse the ALIVE bound pair R2:R3:\n{}", text);
    assemble_body(&text);
}

/// A: the same free-at-first-use hole through the add.s64 carry expansion.
#[test]
fn t118_2_add64_src_pair_has_producer() {
    let ptx = format!(r"{} .visible .entry _Z1kPx(
    .param .u64 .ptr .align 1 _Z1kPx_param_0
)
{{
    .reg .b64  %rd<5>;
    ld.param.b64      %rd1, [_Z1kPx_param_0];
    cvta.to.global.u64 %rd2, %rd1;
    ld.global.b64     %rd3, [%rd2];
    add.s64           %rd4, %rd3, 1;
    st.global.b64     [%rd2], %rd4;
    ret;
}}", PROLOG);
    let text = lower_text(&ptx);
    assert!(text.contains("IADD3 R6, P0, PT, R4, 0x1, RZ"), "add64 lo reads the loaded value:\n{}", text);
    assert!(text.contains("STG.E.64 desc[UR4][R2.64], R6"), "store address pair alive:\n{}", text);
    assemble_body(&text);
}

/// A: pair-bound address used by TWO loads with an add64 in between
/// (pr_rw_ldcgs-962761): the second use must still see the LDC pair.
#[test]
fn t118_3_pair_reuse_across_loads() {
    let ptx = format!(r"{} .visible .entry _Z1kPKiPi(
    .param .u64 .ptr .align 1 _Z1kPKiPi_param_0,
    .param .u64 .ptr .align 1 _Z1kPKiPi_param_1
)
{{
    .reg .b32  %r<4>;
    .reg .b64  %rd<5>;
    ld.param.b64  %rd1, [_Z1kPKiPi_param_0];
    ld.param.b64  %rd3, [_Z1kPKiPi_param_1];
    cvta.to.global.u64 %rd4, %rd3;
    ld.global.cg.s32 %r1, [%rd1];
    add.s64       %rd2, %rd1, 4;
    ld.global.cs.s32 %r2, [%rd2];
    add.s32       %r3, %r2, %r1;
    st.global.b32 [%rd4], %r3;
    ret;
}}", PROLOG);
    let text = lower_text(&ptx);
    assert!(text.contains("IADD3 R8, P0, PT, R2, 0x4, RZ"),
        "the +4 address math must read the LDC-written pair R2:R3:\n{}", text);
    assert!(text.contains("LDG.E R10, desc[UR4][R8.64]"), "second load reads the derived pair:\n{}", text);
    assemble_body(&text);
}

/// B: the gate is fail-closed on a use-bez-def artifact (pre-fix pd64
/// emission shape), and reports the register + first-use line.
#[test]
fn t118_4_gate_rejects_use_before_def_text() {
    let bad = ".entry k\n    .reg R0-R7\n\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    STG.E.64 desc[UR4][R6.64], R4 ;\n    EXIT  ;\n.endentry";
    let none: std::collections::BTreeSet<(u8, i64)> = Default::default();
    let err = check_use_before_def(bad, &none).unwrap_err().to_string();
    assert!(err.contains("entry live-in"), "gate error names the class: {}", err);
    assert!(err.contains('6') || err.contains("R{4"), "error names the dead register(s): {}", err);
}

/// B: a sane artifact passes the gate.
#[test]
fn t118_5_gate_accepts_produced_uses() {
    let ok = lower_text(&format!(r"{} .visible .entry k(
    .param .u32 k_param_0
)
{{
    .reg .b32  %r<3>;
    ld.param.b32 %r1, [k_param_0];
    add.s32      %r2, %r1, 1;
    ret;
}}", PROLOG));
    let none: std::collections::BTreeSet<(u8, i64)> = Default::default();
    check_use_before_def(&ok, &none).unwrap();
}

/// Determinism pin: two consecutive lowerings of the same kernel must emit
/// byte-identical text (pre-fix the dead-pred sink order fed by HashMap
/// iteration made predicate placements run-to-run random).
#[test]
fn t118_6_emission_deterministic() {
    let ptx = format!(r"{} .visible .entry k(
    .param .u32 k_param_0
)
{{
    .reg .pred %p<4>;
    .reg .b32  %r<6>;
    ld.param.b32 %r1, [k_param_0];
    setp.gt.s32  %p1, %r1, 0;
    setp.lt.s32  %p2, %r1, 9;
    setp.eq.s32  %p3, %r1, 4;
    mov.b32      %r2, 7;
    @%p1 add.s32 %r2, %r1, 1;
    @%p2 add.s32 %r2, %r1, 2;
    @%p3 add.s32 %r2, %r1, 3;
    add.s32      %r5, %r2, 1;
    ret;
}}", PROLOG);
    let a = lower_text(&ptx);
    let b = lower_text(&ptx);
    assert_eq!(a, b, "two runs over the same kernel must be byte-identical");
}
