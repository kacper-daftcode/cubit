//! b9 phase-1 pins for the PTX gateway (ptx_parse/ptx_map/ptx_opt/ptx_lower).
//! Doctrine: every behavior here was first observed fail-closed or against a
//! vendor (ptxas 13.3 sm_103a) anchor — see results/b9/B9-PHASE1.md.
use cubit::ptx_lower::{lower_kernel, sass_label};
use cubit::ptx_parse::parse_ptx;
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// cubit::assemble consumes a bare instruction stream — feed the lowered text
/// minus the .entry/.param/.shared directive lines (labels and instructions
/// carry the full semantics for encode purposes).
fn assemble_body(text: &str) -> (Vec<u8>, usize) {
    let body: String = text.lines()
        .filter(|l| !l.trim_start().starts_with('.'))
        .collect::<Vec<_>>().join("
");
    cubit::assemble(&body, 0, &table()).unwrap()
}

const PROLOG: &str = ".version 9.3\n.target sm_103a\n.address_size 64\n\n";

/// 1. nvcc `$L__BB0_2` labels parse and sanitize injectively; the branch
///    references the same sanitized name; re-assembles through the strict
///    multi-sass parser.
#[test]
fn b9_label_sanitized_branch() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u32 k_param_0
)
{{
    .reg .pred  %p<2>;
    .reg .b32   %r<3>;
    ld.param.b32 %r1, [k_param_0];
    setp.gt.s32  %p1, %r1, 0;
    @%p1 bra     $L__BB0_2;
    mov.b32      %r2, 1;
$L__BB0_2:
    st.global.b32 [%rd-not-applicable], %r2;
    ret;
}}"#, PROLOG);
    // st.global with a bogus address reg would drag in Addr plumbing; keep the
    // kernel store-free instead -- rewrite: drop the st line entirely.
    let ptx = ptx.replace("    st.global.b32 [%rd-not-applicable], %r2;\n", "");
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(text.contains("DL__BB0_2:"), "sanitized label must be emitted:\n{}", text);
    assert!(text.contains("BRA DL__BB0_2"), "branch must reference the sanitized label:\n{}", text);
    // strict roundtrip through cubit's own parser + encoder
    let (bytes, n) = assemble_body(&text);
    assert!(n >= 6 && bytes.len() == n * 16);
}

/// 2. Unsupported PTX is a hard error with the complete op list (doctrine:
///    zero silent skips; phase-0 used to warn-and-drop, corrupting control
///    flow when the skipped op was a label-carrier).
#[test]
fn b9_unknown_op_fail_closed() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u32 k_param_0
)
{{
    .reg .b32 %r<2>;
    .reg .f32 %f<2>;
    mov.b32      %r1, 7;
    tanh.approx.f32 %f1, %f2;
    griddepcontrol.launch_dependents;
    mov.b32      %r2, %r1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(msg.contains("tanh.approx.f32"), "error must name the op: {}", msg);
    assert!(msg.contains("griddepcontrol.launch_dependents"), "error must aggregate ALL unsupported ops: {}", msg);
}

/// 3. mul.wide.s32/u32 lower to IMAD.WIDE[.U32] with an even pair destination
///    and encode (vendor payload anchor: results/b9 probe_wide byte-parity).
#[test]
fn b9_mul_wide_encodes() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u64 k_param_1
)
{{
    .reg .b32 %r<4>;
    .reg .b64 %rd<6>;
    ld.param.b64 %rd1, [k_param_0];
    ld.param.b32 %r1, [k_param_1];
    mul.wide.s32 %rd3, %r1, 24;
    mul.wide.u32 %rd4, %r1, %r1;
    add.s64 %rd5, %rd3, %rd4;
    st.global.b64 [%rd1], %rd5;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(text.contains("IMAD.WIDE R"), "wide s32 form:\n{}", text);
    assert!(text.contains("IMAD.WIDE.U32 R"), "wide u32 form:\n{}", text);
    let (_bytes, _n) = assemble_body(&text);
}

/// 4. cvta.to.global.u64 aliases the destination pair onto the source pair
///    (generic == global VA on SM103a/120): no code, one LDC.64 for the param.
#[test]
fn b9_cvta_aliases_pair() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<3>;
    .reg .b64 %rd<5>;
    ld.param.b64 %rd1, [k_param_0];
    cvta.to.global.u64 %rd2, %rd1;
    ld.global.b32 %r1, [%rd2];
    st.global.b32 [%rd2], %r1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert_eq!(text.matches("LDC.64").count(), 1, "cvta must not reload the param:\n{}", text);
    assert!(!text.contains("cvta"), "no residue");
    // the load and the store must use the SAME address pair
    let ld = text.lines().find(|l| l.contains("LDG")).unwrap();
    let st = text.lines().find(|l| l.contains("STG")).unwrap();
    let addr = |l: &str| { let a = l.split('[').nth(2).unwrap(); a.split(']').next().unwrap().to_string() };
    assert_eq!(addr(ld), addr(st), "ldg/stg address pair must agree:\n{}\n{}", ld, st);
    let (_b, _n) = assemble_body(&text);
}

/// 5. Predicate pressure beyond P0..P6 reuses dead PTX preds (last-use
///    sweep); emitted text never contains P7+/P8+ literals.
#[test]
fn b9_pred_reuse_caps_at_p6() {
    let mut body = String::new();
    body.push_str(".reg .pred %p<12>;\n.reg .b32 %r<3>;\nmov.b32 %r1, 1;\n");
    for i in 1..11 {
        body.push_str(&format!("setp.gt.s32 %p{}, %r1, {};\n", i, i));
        body.push_str(&format!("@%p1 mov.b32 %r2, %r1;\n").replace("%p1", &format!("%p{}", i)));
    }
    body.push_str("ret;\n");
    let ptx = format!(r#"{} .visible .entry k(
    .param .u32 k_param_0
)
{{
{}
}}"#, PROLOG, body);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    for bad in ["P7", "P8", "P9", "P10"] {
        assert!(!text.contains(bad), "pred space must stay within P0..P6:\n{}", text);
    }
    let (_b, _n) = assemble_body(&text);
}

/// 6. Folded float constants: at most ONE immediate survives per arith op;
///    earlier ones materialize via IMAD.MOV.U32 (ptxas policy anchor), and the
///    remaining immediate is the LAST one (addend), f32-bit-exact.
#[test]
fn b9_float_imm_legalization() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .f32 %f<4>;
    .reg .b64 %rd<3>;
    ld.param.b64 %rd1, [k_param_0];
    ld.global.b32 %f1, [%rd1];
    fma.rn.f32 %f2, %f1, 0f3FD9999A, 0f3E99999A;
    st.global.b32 [%rd1], %f2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(text.contains("IMAD.MOV.U32"), "earlier float imm must hoist:\n{}", text);
    assert!(text.contains("0x3e99999aF"), "last imm (addend 0.3f) stays, f32-exact:\n{}", text);
    let ffma = text.lines().find(|l| l.contains("FFMA")).unwrap();
    assert_eq!(ffma.matches("0x").count(), 1, "FFMA must carry exactly one immediate:\n{}", ffma);
    let (_b, _n) = assemble_body(&text);
}
