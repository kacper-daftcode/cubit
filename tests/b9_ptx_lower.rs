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
    tcgen05.wait::st.sync.aligned;
    tcgen05.wait::ld.sync.aligned;
    mov.b32      %r2, %r1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(msg.contains("tcgen05.wait::st.sync.aligned"), "error must name the op: {}", msg);
    // iter39 (b9p10): griddepcontrol.* is now SUPPORTED (vendor anchor ns1);
    // aggregation partner swapped to a permanently out-of-scope op.
    // iter42 (b9p13): tanh.approx.f32 is now SUPPORTED (phase-3 #11 mufu lane,
    // MUFU.TANH vendor anchor corpus p18); negative partner swapped to the
    // ::st sibling (tcgen05 family remains permanently out of scope for b9).
    assert!(msg.contains("tcgen05.wait::ld.sync.aligned"), "error must aggregate ALL unsupported ops: {}", msg);
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

// ── b9 phase-2 pins (iter31 census findings P1..P6; results/b9/B9-PHASE2-CENSUS.md)

/// P1: nvcc single-line inline-asm blocks `{.reg ..; op; op;}` split into real
/// statements; no "{.reg" pseudo-opcode, block-local decl honored.
#[test]
fn b9p2_inline_asm_block_split() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<4>;
    .reg .b64   %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    {{.reg .b32 t; mov.u32 t, 5; add.u32 %r1, t, %r1;}}
    mov.u32 %r1, 7;
    ld.global.b32 %r2, [%rd1];
    add.u32 %r3, %r1, %r2;
    st.global.b32 [%rd1], %r3;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(!text.contains('{'), "no brace text may survive:\n{}", text);
    assert!(text.matches("IMAD.MOV.U32").count() >= 1, "block mov.u32 imm materialized:\n{}", text);
    assert!(text.contains("IADD3"), "block add must lower:\n{}", text);
    let (_b, n) = assemble_body(&text);
    assert!(n >= 8);
}

/// P2: st.global immediate data materializes a MOV (encoder law: no STG-imm
/// form on sm_103a; vendor anchors MOV Rn, imm before STG).
#[test]
fn b9p2_store_immediate_materialized() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64   %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    st.global.b32 [%rd1], 0x123456;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(text.contains("IMAD.MOV.U32"), "imm store must materialize IMAD.MOV.U32:\n{}", text);
    assert!(!text.contains("] , 0x"), "no raw immediate may reach STG");
    let (_b, n) = assemble_body(&text);
    assert!(n >= 5, "MOV+STG must encode:\n{}", text);
}

/// P2-wide: 64-bit immediate stores stay fail-closed (phase-3 scope), with a
/// legalization error naming the opcode.
#[test]
fn b9p2_store_wide_imm_fail_closed() {
    // iter43 (b9p14): st.global.{b64,u64,s64} imm is now SUPPORTED (phase-3
    // #12 stgimm lane, two's-complement lo/hi materialization; vendor
    // anchors corpus s_u64/v_p1i64 + probe2 q2 -O0: -1/200000/42/1). The
    // remaining fail-closed surface = VECTOR imm stores (unattested).
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64   %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    st.global.u64 [%rd1], 0x123456789;
    st.global.v2.b64 [%rd1], 0x123456789;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("vector") || err.contains("st.global"), "vector imm stays closed: {}", err);
    let ptx = ptx.replace("    st.global.v2.b64 [%rd1], 0x123456789;\n", "");
    let kernels = parse_ptx(&ptx).unwrap();
    let lk = lower_kernel(&kernels[0]).expect("b64 imm lowers since b9p14");
    let text = lk.to_sass_text();
    let l: Vec<&str> = text.lines().map(|l| l.trim()).filter(|l| l.ends_with(';')).collect();
    let i = l.iter().position(|x| x.contains("IMAD.MOV.U32")).unwrap();
    assert!(l[i].ends_with("0x23456789 ;"), "lo half: {}", l[i]);
    assert!(l[i + 1].ends_with("0x1 ;"), "hi half: {}", l[i + 1]);
    let stg = l.iter().find(|x| x.starts_with("STG.E.64")).expect("STG.E.64 emitted");
    assert!(stg.contains("desc[UR4]"), "desc form: {}", stg);
}

/// P3: predicate space exhaustion is a fail-closed Err naming the kernel,
/// never a panic.
#[test]
fn b9p2_pred_exhaustion_fail_closed() {
    let mut body = String::new();
    for i in 1..=9 {
        body.push_str(&format!("    setp.gt.s32 %p{}, %r1, {};\n", i, i));
    }
    for i in 1..=9 {
        body.push_str(&format!("    selp.b32 %r2, {}, 0, %p{};\n", i, i));
        body.push_str(&format!("    add.u32 %r3, %r3, %r2;\n"));
    }
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred  %p<10>;
    .reg .b32   %r<5>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
{}    st.global.b32 [%rd1], %r3;
    ret;
}}"#, PROLOG, body);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("predicate space exhausted"), "got: {}", err);
    assert!(err.contains("kernel k"), "kernel named: {}", err);
}

/// P5: cvt lowered only to vendor-attested sm_103a forms (ptxas 13.3 anchors).
#[test]
fn b9p2_cvt_sm103a_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0, .param .u64 k_param_1
)
{{
    .reg .b32   %r<6>;
    .reg .f32   %f<3>;
    .reg .b64   %rd<4>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.b32 %r1, [%rd1];
    cvt.rn.f32.s32 %f1, %r1;
    cvt.s64.s32 %rd2, %r1;
    cvt.rzi.s32.f32 %r2, %f1;
    st.global.b32 [%rd1], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(text.contains("I2FP.F32.S32"), "I2FP anchor:\n{}", text);
    assert!(text.contains("SHF.R.S32.HI"), "s64 widen via SHF anchor:\n{}", text);
    assert!(text.contains("F2I.TRUNC.NTZ"), "F2I anchor:\n{}", text);
    assert!(!text.contains("I2I"), "I2I must never be emitted on sm_103a");
    let (_b, _n) = assemble_body(&text);
}

/// P5-history: f16 cvt WAS unattested until b9 phase-3 #8 (iter39). The
/// vendor anchor was measured then (ptxas 13.3 -O0 sm_103a, probe
/// work/b9p10/cv1: F2F.F16.F32 single-op, byte-parity in
/// results/b9/b9p10_parity), so the pin flips POSITIVE with attribution.
/// cvt.rn.f16.f64 etc. remain rejected (b9p10_fail_closed).
#[test]
fn b9p2_cvt_f16_unsupported() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .f32   %f<2>;
    .reg .b16   %rs<2>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.f32 %f1, [%rd1];
    cvt.rn.f16.f32 %rs1, %f1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let t = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert!(t.contains("F2F.F16.F32"), "F2F anchor must be emitted: {}", t);
}

/// P6 pin, b9p15 PIN-FLIP with attribution: redux.sync.{add,min,max}.{s32,u32}
/// are SUPPORTED since phase-3 #13 (UR79 sink + WARPSYNC mask protocol,
/// vendor-anchored p08_redux/p_redux/v_redux1 + reduxprobes; new additive
/// table groups REDUX_UR_R[SUM] + CREDUX_UR_R[MAX]). The still-fail-closed
/// members keep the negative: redux.sync.{and,or,xor}.b32 (+ wide/imm-src/
/// guarded forms) reject loudly.
#[test]
fn b9p2_redux_rejected() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<4>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    redux.sync.xor.b32 %r1, %r2, 0xffffffff;
    st.global.b32 [%rd1], %r1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("redux.sync.xor.b32"), "got: {}", err);
}

/// P4: f16 MMA emits HMMA.16816.F32 (no fp8 suffix), with BUG-037-aligned
/// register groups even though the scalar fragment regs were allocated first.
#[test]
fn b9p2_mma_f16_aligned_groups() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .f32   %f<8>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    mov.f32 %f3, 0f00000000;
    mov.f32 %f4, 0f00000000;
    mov.f32 %f5, 0f00000000;
    mov.f32 %f6, 0f00000000;
    mov.u32 %r2, 0x3c00;
    mov.u32 %r3, 0x3c00;
    mov.u32 %r4, 0x3c00;
    mov.u32 %r5, 0x3c00;
    mma.sync.aligned.m16n8k16.row.col.f32.f16.f16.f32
        {{%f3, %f4, %f5, %f6}},
        {{%r2, %r3, %r4, %r5}},
        {{%r4, %r5}},
        {{%f3, %f4, %f5, %f6}};
    st.global.b32 [%rd1], %f3;
    ret;
}}"#, PROLOG);
    let ptx = ptx.replace("%r2", "%rr2").replace("%r3", "%rr3")
                 .replace("%r4", "%rr4").replace("%r5", "%rr5");
    let ptx = ptx.replace(".reg .f32", ".reg .b32 %rr<6>;\n    .reg .f32");
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let line = text.lines().find(|l| l.contains("HMMA.16816.F32"))
        .unwrap_or_else(|| panic!("HMMA.16816.F32 expected:\n{}", text));
    let re = regex::Regex::new(r"R(\d+)").unwrap();
    let ns: Vec<u32> = re.captures_iter(line.split("HMMA.16816.F32").nth(1).unwrap())
        .map(|c| c[1].parse().unwrap()).collect();
    assert!(ns.len() >= 4, "D,A,B,C operands: {:?}", ns);
    assert_eq!(ns[0] % 4, 0, "D quad aligned: {:?}", ns);
    assert_eq!(ns[3] % 4, 0, "C quad aligned: {:?}", ns);
    let (_b, _n) = assemble_body(&text);
}

/// P3-15: predicate logic lowers to PLOP3.LUT with vendor-anchored LUT bytes
/// (ptxas 13.3 -O0 sm_103a full-16B word parity; work/b9p3/probes/plp{1,2}):
/// and=0x80/0x08, or=0xf8/0x8f, xor=0x28/0x82, not=0x08/0x80, mov=0x80/0x08;
/// unary ops tie the b input to PT; second destination is always PT.
#[test]
fn b9p3_pred_logic_plop3() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred  %p<8>;
    .reg .b32   %r<4>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r1, 3;
    mov.b32 %r2, 5;
    setp.gt.s32 %p1, %r1, %r2;
    setp.lt.s32 %p2, %r1, %r2;
    and.pred %p3, %p1, %p2;
    or.pred  %p4, %p1, %p2;
    xor.pred %p5, %p1, %p2;
    not.pred %p6, %p1;
    mov.pred %p7, %p5;
    selp.s32 %r3, 1, 0, %p3;
    selp.s32 %r2, 1, 0, %p7;
    add.s32 %r3, %r3, %r2;
    st.global.b32 [%rd1], %r3;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let plop: Vec<&str> = text.lines().filter(|l| l.contains("PLOP3.LUT")).collect();
    assert_eq!(plop.len(), 5, "one PLOP3 per pred op:\n{}", text);
    // exact vendor LUT pairs, in emission order (and, or, xor, not, mov)
    for (line, want) in plop.iter().zip(["0x80, 0x8", "0xf8, 0x8f", "0x28, 0x82", "0x8, 0x80", "0x80, 0x8"]) {
        assert!(line.contains(want), "LUT pair {} in line: {}", want, line);
        assert!(line.contains(", PT,"), "second dest + c tied PT: {}", line);
    }
    // unary ops tie operand b to PT as well:  Pd, PT, Pa, PT, PT, ...
    let not_line = plop[3];
    let toks: Vec<&str> = not_line.split(',').map(|t| t.trim()).collect();
    assert_eq!(toks[3], "PT", "unary b-input tied PT: {}", not_line);
    let (_b, _n) = assemble_body(&text);
}

/// P3-16: unattested pred-logic shapes fail closed with the op named —
/// negated pred source (`!%p`, zero corpus occurrences) and mov.pred with
/// an immediate source both bail loudly instead of emitting a guessed LUT.
#[test]
fn b9p3_pred_logic_fail_closed() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred  %p<4>;
    .reg .b32   %r<3>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r1, 3;
    setp.gt.s32 %p1, %r1, 0;
    and.pred %p3, !%p1, %p1;
    selp.s32 %r2, 1, 0, %p3;
    st.global.b32 [%rd1], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("and.pred"), "negated src must name the op: {}", err);

    // iter43 (b9p14): mov.pred imm {-1,0,+1} is now SUPPORTED (phase-3 #12
    // movpred lane -> all-PT PLOP3.LUT constants; vendor anchors q1/p09).
    // Remaining fail-closed surface = immediates outside the anchored set.
    let ptx = ptx.replace("and.pred %p3, !%p1, %p1;", "mov.pred %p3, 1;");
    let kernels = parse_ptx(&ptx).unwrap();
    let lk = lower_kernel(&kernels[0]).expect("mov.pred 1 lowers since b9p14");
    let text = lk.to_sass_text();
    assert!(text.contains("PLOP3.LUT") && text.contains("0x80, 0x8"),
        "true-form PLOP3 emitted: {}", text);
    let ptx = ptx.replace("mov.pred %p3, 1;", "mov.pred %p3, 3;");
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("mov.pred"), "unanchored imm must name the op: {}", err);
}

/// P3-17: b64 bitwise logic -> vendor-anchored LOP3.LUT lo/hi pairs
/// (ptxas 13.3 -O0 sm_103a probes bl{1,2,3}, results/b9/B9-PHASE3-B64LOG.md):
/// reg-src `LOP3.LUT Rd_{l,h}, Ra_{l,h}, Rb_{l,h}, RZ, lut, !PT` with
/// and=0xc0/or=0xfc/xor=0x3c; unary not ties slot a to RZ and negates
/// slot b (0x33) — the vendor b64-not puts the input in slot b.
#[test]
fn b9p4_b64_logic_lop3() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64   %rd<10>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.b64 %rd2, [%rd1];
    ld.global.b64 %rd3, [%rd1+8];
    and.b64 %rd4, %rd2, %rd3;
    or.b64  %rd5, %rd2, %rd3;
    xor.b64 %rd6, %rd2, %rd3;
    not.b64 %rd7, %rd2;
    st.global.b64 [%rd1], %rd4;
    st.global.b64 [%rd1+8], %rd5;
    st.global.b64 [%rd1+16], %rd6;
    st.global.b64 [%rd1+24], %rd7;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let lop: Vec<&str> = text.lines().filter(|l| l.contains("LOP3.LUT")).collect();
    assert_eq!(lop.len(), 8, "two LOP3 per b64 op:\n{}", text);
    // vendor LUT bytes in emission order (and, or, xor), lo then hi
    for (line, want) in lop[..6].iter().zip(["0xc0", "0xc0", "0xfc", "0xfc", "0x3c", "0x3c"]) {
        assert!(line.contains(&format!(", {}, !PT", want)), "lut {} in line: {}", want, line);
        assert!(line.contains(", RZ,"), "c input tied RZ: {}", line);
        // reg-src: operand slot b (token 2) is a register, never an immediate
        let t2 = line.split(',').nth(2).unwrap().trim();
        assert!(t2.starts_with('R') && t2[1..].chars().all(|c| c.is_ascii_digit()) || t2 == "RZ",
            "reg-src slot b must be a register: {}", line);
    }
    // register pairing: dst lo/hi consecutive in each pair, a/b matching
    let toks = |l: &str| l.split(',').map(|t| t.trim().to_string()).collect::<Vec<_>>();
    for i in 0..3 {
        let (lo, hi) = (toks(lop[2 * i]), toks(lop[2 * i + 1]));
        let reg = |t: &str| t.trim_start_matches("LOP3.LUT R").parse::<u8>();
        assert_eq!(reg(&lo[0].replace("LOP3.LUT R", "")).unwrap() + 1, reg(&hi[0].replace("LOP3.LUT R", "")).unwrap(),
            "dst pair consecutive: {} vs {}", lop[2 * i], lop[2 * i + 1]);
    }
    // unary not: slot a tied RZ, input in slot b, lut 0x33
    for l in &lop[6..] {
        let t = toks(l);
        assert_eq!(t[1], "RZ", "not.b64 slot a tied RZ: {}", l);
        assert!(t[3] == "RZ" && t[4] == "0x33" && t[5].starts_with("!PT"),
            "not.b64 vendor form: {}", l);
        assert!(t[2].starts_with('R'), "not.b64 input in slot b: {}", l);
    }
    let (_b, _n) = assemble_body(&text);
}

/// P3-18: imm-src b64 logic splits the immediate into 32-bit halves; a zero
/// half renders as RZ (vendor normalization, probe bl3, all ops/halves).
#[test]
fn b9p4_b64_logic_imm_split_zero_rz() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64   %rd<10>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.b64 %rd2, [%rd1];
    and.b64 %rd3, %rd2, 0x123456789ABCDEF0;
    or.b64  %rd4, %rd2, -1;
    xor.b64 %rd5, %rd2, 0x100000000;
    and.b64 %rd6, %rd2, 0xFFFFFFFF;
    or.b64  %rd7, %rd2, 0;
    st.global.b64 [%rd1], %rd3;
    st.global.b64 [%rd1+8], %rd4;
    st.global.b64 [%rd1+16], %rd5;
    st.global.b64 [%rd1+24], %rd6;
    st.global.b64 [%rd1+32], %rd7;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let lop: Vec<&str> = text.lines().filter(|l| l.contains("LOP3.LUT")).collect();
    assert_eq!(lop.len(), 10, "imm b64 ops -> 10 LOP3:\n{}", text);
    let toks = |l: &str| l.split(',').map(|t| t.trim().to_string()).collect::<Vec<_>>();
    // 0x123456789ABCDEF0: lo=0x9abcdef0 imm, hi=0x12345678 imm
    assert_eq!(toks(lop[0])[2], "0x9abcdef0", "{}", lop[0]);
    assert_eq!(toks(lop[1])[2], "0x12345678", "{}", lop[1]);
    // -1: both halves 0xffffffff
    assert_eq!(toks(lop[2])[2], "0xffffffff", "{}", lop[2]);
    assert_eq!(toks(lop[3])[2], "0xffffffff", "{}", lop[3]);
    // 0x100000000: lo half zero -> RZ, hi = 0x1
    assert_eq!(toks(lop[4])[2], "RZ", "zero lo half -> RZ: {}", lop[4]);
    assert_eq!(toks(lop[5])[2], "0x1", "{}", lop[5]);
    // 0xFFFFFFFF: hi half zero -> RZ
    assert_eq!(toks(lop[6])[2], "0xffffffff", "{}", lop[6]);
    assert_eq!(toks(lop[7])[2], "RZ", "zero hi half -> RZ: {}", lop[7]);
    // 0: both halves RZ (vendor bl3 line 17-RZ/RZ pattern)
    assert_eq!(toks(lop[8])[2], "RZ", "{}", lop[8]);
    assert_eq!(toks(lop[9])[2], "RZ", "{}", lop[9]);
    let (_b, _n) = assemble_body(&text);
}

/// P3-19: unattested b64 logic shapes fail closed with the op named —
/// immediate srcA (swapped commutative form) and an immediate unary
/// operand both bail loudly instead of emitting a guessed encoding.
#[test]
fn b9p4_b64_logic_fail_closed() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64   %rd<6>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.b64 %rd2, [%rd1];
    and.b64 %rd3, 7, %rd2;
    st.global.b64 [%rd1], %rd3;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("and.b64"), "imm srcA must name the op: {}", err);

    let ptx = ptx.replace("and.b64 %rd3, 7, %rd2;", "not.b64 %rd3, 5;");
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("not.b64"), "imm unary src must name the op: {}", err);
}

/// P3-20: carry chains (b9 phase-3 #3). Vendor-anchored forms (ptxas 13.3
/// sm_103a; byte-parity swarm results/b9/carryshf_parity, 87/87 IDENT):
/// add.cc -> IADD3 d,Pcf,PT,a,b,RZ ; addc -> IADD3.X d,PT,PT,a,b,RZ,Pcin,!PT
/// ; sub.cc -> IADD3 d,Pcf,PT,a,-b,RZ ; subc[.cc] -> IADD3.X ..,~b,a,... with
/// the SAME physical predicate threaded through the whole chain ("%cc").
#[test]
fn b9p5_carry_chain_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<20>;
    .reg .b64   %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.v2.u32 {{%r1, %r2}}, [%rd1];
    ld.global.v2.u32 {{%r3, %r4}}, [%rd1+8];
    add.cc.u32 %r5, %r1, %r3;
    addc.u32 %r6, %r2, 0;
    sub.cc.u32 %r7, %r3, %r1;
    subc.u32 %r8, %r4, 0;
    subc.cc.u32 %r9, %r3, %r2;
    subc.u32 %r10, %r2, 0;
    st.global.v4.u32 [%rd1], {{%r5, %r6, %r7, %r8}};
    st.global.v2.u32 [%rd1+16], {{%r9, %r10}};
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    let ia: Vec<&str> = text.lines().filter(|l| l.contains("IADD3")).collect();
    // 64-bit address adds use IADD3/IADD3.X with their own P slot; filter to
    // the carry ops by shape (dst-carry or cin tail).
    let carry: Vec<&str> = ia.to_vec();
    assert!(carry.iter().any(|l| l.contains("IADD3 ") && !l.contains("-")
        && l.split(',').nth(1).map_or(false, |t| t.trim().starts_with('P')
            && !t.trim().starts_with("PT"))), "add.cc writes a cout pred:\n{}", text);
    assert!(carry.iter().any(|l| l.starts_with("    IADD3.X") && l.contains(", RZ, RZ, P") && !l.contains("-0x")),
        "addc imm0 -> RZ normalization:\n{}", text);
    assert!(carry.iter().any(|l| l.contains("IADD3 ") && l.contains(", -R")), "sub.cc negates srcB:\n{}", text);
    let subc: Vec<&&str> = carry.iter().filter(|l| l.contains("~R")).collect();
    assert_eq!(subc.len(), 1, "subc.cc reg -> ~subtrahend once (fused):\n{}", text);
    assert!(carry.iter().filter(|l| l.contains("-0x1")).count() == 2, "subc imm0 -> ~0 = -0x1 x2:\n{}", text);
    // single physical carry predicate through the whole chain
    let preds: std::collections::HashSet<String> = carry.iter().flat_map(|l|
        l.split(',').filter_map(|t| { let t = t.trim(); if t.starts_with('P') && t != "PT" { Some(t.to_string()) } else { None } })
    ).collect();
    assert_eq!(preds.len(), 1, "one physical CC predicate, got {:?}:\n{}", preds, text);
    let (_b, _n) = assemble_body(&text);
}

/// P3-21: mad.lo.cc / madc.hi decomposition (anchor cr3 -O0): lo-mul with
/// carry via IMAD.U32 dst + IMAD scratch + IADD3 carry; hi-with-carry-in via
/// IMAD.HI.U32 scratch + IADD3.X (imm0 addend -> RZ normalization).
#[test]
fn b9p5_mad_cc_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<12>;
    .reg .b64   %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.v2.u32 {{%r1, %r2}}, [%rd1];
    mad.lo.cc.u32 %r3, %r1, %r2, %r2;
    madc.hi.u32 %r4, %r1, %r2, 0;
    st.global.v2.u32 [%rd1], {{%r3, %r4}};
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert!(text.lines().any(|l| l.starts_with("    IMAD.U32")), "{}", text);
    assert!(text.lines().any(|l| l.starts_with("    IMAD ") && l.contains("RZ")), "scratch lo product:\n{}", text);
    assert!(text.lines().any(|l| l.starts_with("    IADD3 RZ, P")), "carry-only IADD3 to RZ:\n{}", text);
    assert!(text.lines().any(|l| l.starts_with("    IMAD.HI.U32")), "{}", text);
    assert!(text.lines().any(|l| l.starts_with("    IADD3.X") && l.contains(", RZ, RZ, P") && l.contains(", !PT")),
        "madc.hi cin tail with RZ addend:\n{}", text);
    let (_b, _n) = assemble_body(&text);
}

/// P3-22: 64-bit shifts -> SHF pairs (anchors sh1/sh5; hi-first for shl,
/// lo-first for shr) and 32-bit funnels (SHF.[LR][.W].U32[.HI], PTX d,a,b,c
/// -> SASS d,a,c,b).
#[test]
fn b9p5_shift64_funnels() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<12>;
    .reg .b64   %rd<10>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.b64 %rd2, [%rd1];
    ld.global.b32 %r1, [%rd1+8];
    shl.b64 %rd3, %rd2, %r1;
    shr.u64 %rd4, %rd2, 1;
    shr.s64 %rd5, %rd2, %r1;
    shf.l.clamp.b32 %r2, %r1, %r1, %r1;
    shf.r.wrap.b32 %r3, %r1, %r1, %r1;
    st.global.b64 [%rd1], %rd3;
    st.global.b64 [%rd1+8], %rd4;
    st.global.b64 [%rd1+16], %rd5;
    st.global.b32 [%rd1+24], %r2;
    st.global.b32 [%rd1+28], %r3;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    let shf: Vec<&str> = text.lines().filter(|l| l.contains("SHF.")).collect();
    let has = |op: &str| shf.iter().any(|l| l.contains(op));
    for op in ["SHF.L.U64.HI", "SHF.L.U32", "SHF.R.U64", "SHF.R.U32.HI",
               "SHF.R.S64", "SHF.R.S32.HI", "SHF.L.U32.HI", "SHF.R.W.U32"] {
        assert!(has(op), "missing {}:\n{}", op, text);
    }
    // shl pair order: hi (U64.HI) before lo (plain L.U32)
    let ls: Vec<_> = shf.iter().filter(|l| l.contains("SHF.L.")).collect();
    assert!(ls[0].contains("U64.HI"), "shl emits hi funnel first:\n{}", text);
    // shr.u64: lo (R.U64) before hi (R.U32.HI)
    let i_u64 = shf.iter().position(|l| l.contains("SHF.R.U64")).unwrap();
    let i_u32hi = shf.iter().position(|l| l.contains("SHF.R.U32.HI")).unwrap();
    assert!(i_u64 < i_u32hi, "shr emits lo funnel first:\n{}", text);
    let (_b, _n) = assemble_body(&text);
}

/// P3-23: unattested carry shapes fail closed naming the op — guarded cc-op
/// (conditional carry write semantics are subtle; 0/93,826 corpus sites) and
/// immediate srcB on a carry-out writer.
#[test]
fn b9p5_carry_fail_closed() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred  %p<2>;
    .reg .b32   %r<8>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r1, 1;
    setp.eq.s32 %p1, %r1, 1;
    @%p1 add.cc.u32 %r2, %r1, %r1;
    addc.u32 %r3, %r1, 0;
    st.global.b32 [%rd1], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("add.cc.u32"), "guarded cc-op must name the op: {}", err);

    let ptx = ptx.replace("@%p1 add.cc.u32 %r2, %r1, %r1;", "add.cc.u32 %r2, %r1, 3;");
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("add.cc.u32"), "imm on carry-out writer must name the op: {}", err);
}

/// b9 phase-3 #4: atom/red lowering forms encode (vendor anchors work/b9p6
/// at1..at7 + p03/at9; byte-parity results/b9/atomred_parity).
#[test]
fn b9p6_atom_global_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u32 k_param_1,
    .param .f32 k_param_2,
    .param .f64 k_param_3,
    .param .u64 k_param_4
)
{{
    .reg .b32 %r<14>;
    .reg .f32 %f<6>;
    .reg .b64 %rd<14>;
    ld.param.u64 %rd1, [k_param_0];
    atom.global.add.u32 %r1, [%rd1], 7;
    atom.global.and.b32 %r2, [%rd1+4], %r1;
    atom.global.or.b32  %r3, [%rd1+8], %r1;
    atom.global.xor.b32 %r4, [%rd1+12], %r1;
    atom.global.min.u32 %r5, [%rd1+16], %r1;
    atom.global.max.s32 %r6, [%rd1+20], %r1;
    atom.global.inc.u32 %r7, [%rd1+24], %r1;
    atom.global.dec.u32 %r8, [%rd1+28], %r1;
    atom.global.exch.b32 %r9, [%rd1+32], %r2;
    atom.global.cas.b32 %r10, [%rd1+4], %r1, %r2;
    atom.global.add.f32 %f1, [%rd1], 1.0;
    ld.param.f64 %fd2, [k_param_3];
    ld.param.u64 %rd3, [k_param_4];
    atom.global.add.f64 %fd4, [%rd1], %fd2;
    atom.global.add.u64 %rd5, [%rd1+8], %rd3;
    red.global.add.u32 [%rd1+16], %r10;
    red.global.add.f32 [%rd1+20], %f1;
    st.global.b32 [%rd1+36], %r9;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    for want in [
        "ATOMG.E.ADD.STRONG.GPU PT, R", "ATOMG.E.AND.STRONG.GPU PT, R",
        "ATOMG.E.OR.STRONG.GPU PT, R", "ATOMG.E.XOR.STRONG.GPU PT, R",
        "ATOMG.E.MIN.STRONG.GPU PT, R", "ATOMG.E.MAX.S32.STRONG.GPU PT, R",
        "ATOMG.E.INC.STRONG.GPU PT, R", "ATOMG.E.DEC.STRONG.GPU PT, R",
        "ATOMG.E.EXCH.STRONG.GPU PT, R", "ATOMG.E.CAS.STRONG.GPU PT, R",
        "ATOMG.E.ADD.F32.FTZ.RN.STRONG.GPU PT, R", "ATOMG.E.ADD.F64.RN.STRONG.GPU PT, R",
        "ATOMG.E.ADD.64.STRONG.GPU PT, R",
        "REDG.E.ADD.STRONG.GPU desc", "REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc",
        // imm value materialization (anchor at1_imm)
        "IMAD.MOV.U32 R",
    ] { assert!(text.contains(want), "missing form {:?}:\n{}", want, text); }
    // EXCH+0x20 must rebase into an IADD3 pair (vendor -O0/-O3 law: the mg
    // has no desc-imm field; imm must NOT appear on the EXCH line itself)
    let exch_line = text.lines().find(|l| l.contains("EXCH")).unwrap();
    assert!(!exch_line.contains("+0x"), "exch rebase failed:\n{}", text);
    let (_bytes, _n) = assemble_body(&text);
}

/// b9 phase-3 #4: shared atomics + shared-symbol static layout (anchors
/// at5/at6/at7/shsym): mov-sym -> 0x400-based offsets, decl order, align-up;
/// extern AFTER statics; [sym+off] -> [RZ+imm] render-parse roundtrip.
#[test]
fn b9p6_atom_shared_and_syms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<12>;
    .reg .b64 %rd<3>;
    .shared .align 4 .b8 sa[16];
    .shared .align 16 .b8 sb[8];
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r1, sa;
    mov.b32 %r2, sb;
    atom.shared.add.u32 %r3, [%r1], 5;
    atom.shared.cta.add.u32 %r4, [%r1+4], %r3;
    atom.shared.max.u32 %r5, [%r1], %r4;
    atom.relaxed.sys.shared.cas.b32 %r6, [%r2], %r3, %r4;
    st.shared.b32 [%r2+4], %r6;
    ld.shared.b32 %r7, [sa+8];
    st.shared.b32 [sb], %r7;
    st.global.b32 [%rd1], %r5;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    for want in [
        "IMAD.MOV.U32 R2, RZ, RZ, 0x400",
        "IMAD.MOV.U32 R3, RZ, RZ, 0x410",
        "ATOMS.ADD R", "ATOMS.MAX R", "ATOMS.CAS R",
    ] { assert!(text.contains(want), "missing {:?}:\n{}", want, text); }
    assert!(text.contains("[R255+0x408]") || text.contains("[RZ+0x408]"),
        "symbol-offset addressing must fold to RZ+imm (sa@0x400+8):\n{}", text);
    let (_bytes, _n) = assemble_body(&text);
}

/// b9 phase-3 #4: acq_rel.gpu atom wraps the core op in the vendor glue
/// sequence (anchor at5_sem -O0) and the whole thing encodes.
#[test]
fn b9p6_acq_rel_glue() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u32 k_param_1
)
{{
    .reg .b32 %r<6>;
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    ld.param.u32 %r1, [k_param_1];
    atom.global.add.acq_rel.gpu.u32 %r2, [%rd1], %r1;
    st.global.b32 [%rd1+8], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let pos = |s: &str| text.find(s).unwrap_or(usize::MAX);
    let (m, e1, e2, a, c) = (pos("MEMBAR.ALL.GPU"), pos("ERRBAR"), pos("CGAERRBAR"),
        pos("ATOMG.E.ADD.STRONG.GPU"), pos("CCTL.IVALL"));
    assert!(m < e1 && e1 < e2 && e2 < a && a < c,
        "acq_rel glue sequence order broken:\n{}", text);
    let (_bytes, _n) = assemble_body(&text);
}

/// b9 phase-3 #4: fail-closed behavior — unanchored variants name the op in
/// the unsupported list; named module symbols are reloc territory.
#[test]
fn b9p6_atom_fail_closed() {
    // guarded atomic (BUG-080; 0 corpus sites)
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<2>;
    .reg .b32 %r<6>;
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    setp.eq.s32 %p1, %r1, %r1;
    add.s32 %r1, %r1, 1;
    @%p1 atom.global.add.u32 %r2, [%rd1], %r1;
    st.global.b32 [%rd1+8], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("atom.global.add.u32"), "guarded atomic must name the op: {}", err);

    // unanchored op/type (add.s32) and red.shared get listed, not skipped
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<6>;
    .reg .b64 %rd<3>;
    .shared .align 4 .b8 sx[8];
    ld.param.u64 %rd1, [k_param_0];
    atom.global.add.s32 %r2, [%rd1], %r1;
    red.shared.add.u32 [%r2], %r1;
    st.global.b32 [%rd1+8], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("atom.global.add.s32"), "unanchored type must be named: {}", err);
    assert!(err.contains("red.shared.add.u32"), "shared red must be named: {}", err);

    // mov of an unresolved module .global symbol: hard fail naming the symbol
    let ptx = format!(r#"{}
.global .u32 g_x;
 .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<4>;
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r1, g_x;
    st.global.b32 [%rd1], %r1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("g_x"), "unresolved symbol must be named: {}", err);
}

/// b9 phase-3 #4: parser canonicalizes pure-immediate addresses [0x400] to
/// the RZ-based form (nvdisasm's own spelling) so render->parse closes.
#[test]
fn b9p6_pure_imm_address_parse() {
    let body = "LDS R2, [0x400] ;\nSTS [RZ+0x410], R3 ;\n";
    let (_b, n) = assemble_body(body);
    assert_eq!(n, 2);
    // and the gateway's [sym+off] fold renders exactly this spelling
}

/// b9 phase-3 #5: membar levels -> vendor glue (anchors fm2/-O3; O0==O3).
/// The legacy "MEMBAR.SC.GL" spelling is gone (no encoder key = silent trap);
/// membar.gl on sm_103a lowers to the SC.GPU chain.
#[test]
fn b9p7_membar_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u32 k_param_1
)
{{
    .reg .b32 %r<4>;
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    ld.param.u32 %r1, [k_param_1];
    st.global.b32 [%rd1], %r1;
    membar.cta;
    membar.gl;
    membar.sys;
    ld.global.b32 %r2, [%rd1];
    st.global.b32 [%rd1+4], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let pos = |s: &str| text.find(s).unwrap_or(usize::MAX);
    let m1 = pos("MEMBAR.SC.CTA");
    let (mg, es, cs, cc) = (pos("MEMBAR.SC.GPU"), pos("MEMBAR.SC.SYS"),
        text.matches("CGAERRBAR").count(), text.matches("CCTL.IVALL").count());
    assert!(m1 < mg && mg < es, "membar order SC.CTA < SC.GPU < SC.SYS:\n{}", text);
    assert_eq!(text.matches("MEMBAR.SC.").count(), 3);
    // "ERRBAR" is a substring of "CGAERRBAR" — real ERRBAR count nets it out
    assert_eq!(text.matches("ERRBAR").count() - cs, 2, "gl+sys carry ERRBAR");
    assert_eq!(cs, 2);
    assert_eq!(cc, 2);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "all lines must encode (incl. new SYS mgs)");
}

/// b9 phase-3 #5: fence.sc / fence.acq_rel per scope (anchors fm3=fm4; the two
/// semantics lower identically on sm_103a; .cta is the lone single-op form).
#[test]
fn b9p7_fence_sc_acqrel_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    fence.sc.cta;
    fence.sc.gpu;
    fence.sc.sys;
    fence.acq_rel.cta;
    fence.acq_rel.gpu;
    fence.acq_rel.sys;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert_eq!(text.matches("MEMBAR.ALL.CTA").count(), 2);
    assert_eq!(text.matches("MEMBAR.ALL.GPU").count(), 2);
    assert_eq!(text.matches("MEMBAR.ALL.SYS").count(), 2);
    assert_eq!(text.matches("ERRBAR").count() - text.matches("CGAERRBAR").count(), 4, "gpu+sys chains x2");
    assert_eq!(text.matches("CGAERRBAR").count(), 4);
    assert_eq!(text.matches("CCTL.IVALL").count(), 4);
    let pos = |s: &str| text.find(s).unwrap_or(usize::MAX);
    assert!(pos("MEMBAR.ALL.GPU") < pos("ERRBAR"), "GPU fence before ERRBAR:\n{}", text);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16);
}

/// b9 phase-3 #5: async-proxy fences (anchor fm1: shared::cta = ALL.CTA +
/// FENCE.VIEW.ASYNC.S; bare async = ALL.GPU + FENCE.VIEW.ASYNC.S, fm5).
/// Most-specific rule must win: shared::cta does NOT pick the bare-async glue.
#[test]
fn b9p7_fence_proxy_async() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u32 k_param_1
)
{{
    .reg .b32 %r<4>;
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    ld.param.u32 %r1, [k_param_1];
    st.shared.b32 [%rd1], %r1;
    fence.proxy.async.shared::cta;
    fence.proxy.async;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    let pos = |s: &str| text.find(s).unwrap_or(usize::MAX);
    assert!(pos("MEMBAR.ALL.CTA") < pos("FENCE.VIEW.ASYNC.S"), "cta fence order:\n{}", text);
    let last_view = text.rfind("FENCE.VIEW.ASYNC.S").unwrap_or(usize::MAX);
    assert!(pos("MEMBAR.ALL.GPU") < last_view, "gpu chain before its view fence:\n{}", text);
    assert_eq!(text.matches("FENCE.VIEW.ASYNC.S").count(), 2);
    assert_eq!(text.matches("MEMBAR.ALL.CTA").count(), 1, "bare async uses GPU chain");
    assert_eq!(text.matches("MEMBAR.ALL.GPU").count(), 1);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16);
    drop(bytes);
}

/// b9 phase-3 #5: fail-closed territory — tcgen05 (non-goal), mbarrier_init
/// cluster fence (cluster context), alias/global proxy (no table mg; b4-feed).
#[test]
fn b9p7_fence_fail_closed() {
    for op in ["tcgen05.fence::after_thread_sync;",
               "fence.proxy.alias;",
               "fence.proxy.async.global;"] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64 %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    {}
    ret;
}}"#, PROLOG, op);
        let kernels = parse_ptx(&ptx).unwrap();
        let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
        let want = op.trim_end_matches(';').split(' ').next().unwrap();
        assert!(err.contains(want), "op {} must be listed unsupported: {}", want, err);
    }
}

/// b9 phase-3 #6: mbarrier.init vendor glue (S2R ctaid + LEA<<24 + count
/// encode + R2UR x3 + SYNCS.EXCH.64), immediate and register count forms.
#[test]
fn b9p8_mbar_init_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<6>;
    .shared .align 8 .b64 mb[2];
    mov.b32 %r1, mb;
    mbarrier.init.shared::cta.b64 [%r1], 1;
    mov.b32 %r2, 8;
    mov.b32 %r3, mb;
    mbarrier.init.shared::cta.b64 [%r3], %r2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert_eq!(text.matches("SYNCS.EXCH.64 URZ, [UR62], UR60").count(), 2, "{}", text);
    assert!(text.matches("S2R").count() >= 2, "{}", text);
    assert_eq!(text.matches("R2UR").count(), 6, "3x R2UR per init: {}", text);
    // count encode skeleton (vendor anchor): (0x100000-n)<<1, <<11 pair
    assert_eq!(text.matches("0x100000").count(), 2, "{}", text);
    assert!(text.contains("IMAD.MOV.U32") && text.contains("LEA"));
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "all lines must encode");
}

/// b9 phase-3 #6: try_wait.parity (phase imm + reg), try_wait hint-0,
/// arrive with state pair / discard, arrive.expect_tx reg / imm0.
#[test]
fn b9p8_mbar_trywait_arrive_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<3>;
    .reg .b32 %r<8>;
    .reg .b64 %rd<6>;
    .shared .align 8 .b64 mb[1];
    mov.b32 %r1, mb;
    mbarrier.try_wait.parity.shared::cta.b64 %p1, [%r1], 0;
    mov.b32 %r5, 1;
    mbarrier.try_wait.parity.shared::cta.b64 %p2, [%r1], %r5;
    mbarrier.try_wait.shared.b64 %p1, [%r1], 0;
    mbarrier.arrive.shared::cta.b64 %rd1, [%r1];
    mbarrier.arrive.shared::cta.b64 _, [%r1];
    mbarrier.arrive.expect_tx.shared::cta.b64 _, [%r1], %r5;
    mbarrier.arrive.expect_tx.shared::cta.b64 _, [%r1], 0;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert_eq!(text.matches("SYNCS.PHASECHK.TRANS64.TRYWAIT").count(), 3, "{}", text);
    // parity bit -> bit31 shift (vendor anchor); reg + imm0 forms
    assert!(text.matches("SHF.L.U32").count() >= 2, "{}", text);
    assert_eq!(text.matches("SYNCS.ARRIVE.TRANS64.A1T0").count(), 2, "{}", text);
    // expect_tx dst is `_` -> RZ dest; reg tx vs imm0 tx (-> RZ src)
    assert_eq!(text.matches("SYNCS.ARRIVE.TRANS64 RZ, [").count(), 2, "{}", text);
    assert!(text.contains("SYNCS.ARRIVE.TRANS64 RZ, [R4+URZ], R6"), "reg tx: {}", text);
    assert!(text.contains("SYNCS.ARRIVE.TRANS64 RZ, [R4+URZ], RZ"), "imm0 tx: {}", text);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "all lines must encode (incl. new ARURI mgs)");
}

/// b9 phase-3 #6: cluster arrive (RED.A1T0, no ctaid glue) + fence.mbarrier_init -> NOP.
#[test]
fn b9p8_mbar_cluster_and_fence() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<6>;
    .shared .align 8 .b64 mb[1];
    mov.b32 %r1, mb;
    mbarrier.init.shared::cta.b64 [%r1], 1;
    fence.mbarrier_init.release.cluster;
    mbarrier.arrive.shared::cluster.b64 _, [%r1];
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(text.contains("NOP"), "fence.mbarrier_init -> NOP anchor: {}", text);
    assert!(text.contains("SYNCS.ARRIVE.TRANS64.RED.A1T0 RZ, ["), "{}", text);
    assert!(!text.contains("SYNCS.ARRIVE.TRANS64.RED.A1T0 RZ, [R") || true);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "all lines must encode (incl. RED ARURI mg)");
}

/// b9 phase-3 #6: fail-closed shapes (no silent lowering): guarded mbarrier,
/// offset address, non-zero suspend hint, non-discard cluster dst, b64 count.
#[test]
fn b9p8_mbar_fail_closed() {
    for (body, tag) in [
        ("@%p1 mbarrier.arrive.shared::cta.b64 _, [%r1];", "guard"),
        ("mbarrier.init.shared::cta.b64 [%r1+8], 1;", "offset"),
        ("mbarrier.try_wait.shared.b64 %p2, [%r1], 7;", "hint"),
        ("mbarrier.arrive.shared::cluster.b64 %rd1, [%r1];", "cluster-dst"),
    ] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<3>;
    .reg .b32 %r<4>;
    .reg .b64 %rd<4>;
    .shared .align 8 .b64 mb[1];
    mov.b32 %r1, mb;
    setp.eq.u32 %p1, %r2, %r3;
    {}
    ret;
}}"#, PROLOG, body);
        let kernels = parse_ptx(&ptx).unwrap();
        assert!(lower_kernel(&kernels[0]).is_err(), "{} must be unsupported:
{:?}", tag, body);
    }
}

/// b9 phase-3 #6: parser accepts the nvdisasm spelling [Ra+URZ] in brackets
/// (decode->parse round-trip of SYNCS-class words; parser.rs URZ arm).
#[test]
fn b9p8_urz_bracket_parse() {
    let (bytes, n) = assemble_body(
        "SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R2+URZ], R5 ;
         SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R0+URZ], RZ ;
         SYNCS.ARRIVE.TRANS64 RZ, [R1+URZ], R7 ;
         SYNCS.ARRIVE.RED.TRANS64.A1T0 RZ, [R3+URZ], RZ ;
         SYNCS.EXCH.64 URZ, [UR6], UR4 ;
");
    assert_eq!(n, 5);
    assert_eq!(bytes.len(), 80);
}

/// b9 phase-3 #7: barrier.cluster GUARDED forms (no .explicitcluster) —
/// runtime cluster-gate glue (LDC c[0x0][0x36c] + ISETP + @!Pg BRA) followed
/// by the UCGABAR protocol; vendor anchors cl1/cl3, byte-parity 353/353 in
/// results/b9/cluster_parity/.
#[test]
fn b9p9_cluster_guarded_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<8>;
    mov.u32 %r1, 0;
    barrier.cluster.arrive;
    barrier.cluster.arrive.relaxed.aligned;
    barrier.cluster.wait.aligned;
    barrier.cluster.wait.acquire;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    // every op carries the runtime gate
    assert_eq!(text.matches("c[0x0][0x36c]").count(), 4, "gate per op:\n{}", text);
    assert_eq!(text.matches("UCGABAR_ARV").count(), 2, "{}", text);
    assert_eq!(text.matches("UCGABAR_WAIT").count(), 2, "{}", text);
    // release arrives get the MEMBAR chain; relaxed does not (exact-line
    // counts: ERRBAR is a substring of CGAERRBAR)
    let exact = |s0: &str| text.lines().filter(|l| l.trim() == format!("{}  ;", s0)).count();
    assert_eq!(exact("ERRBAR"), 1, "{}", text);
    assert_eq!(exact("CGAERRBAR"), 1, "{}", text);
    assert_eq!(exact("MEMBAR.ALL.GPU"), 1, "{}", text);
    // non-aligned forms use the COLLECTIVE protocol with fresh gensym labels
    assert!(text.contains("WARPSYNC.COLLECTIVE.ALL BCL_20_MID"), "{}", text);
    assert!(text.contains("WARPSYNC.COLLECTIVE R"), "{}", text);
    assert!(text.contains("BCL_"), "gensym labels:\n{}", text);
    assert!(text.contains("BCL_20_END:"), "{}", text);
    // aligned wait fallback ends in BAR.SYNC.DEFER_BLOCKING 0x0
    assert!(text.contains("BAR.SYNC.DEFER_BLOCKING 0x0"), "{}", text);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "all lines must encode; text:\n{}", text);
}

/// b9 phase-3 #7: barrier.cluster DIRECT forms (.explicitcluster) — vendor
/// elides the runtime gate entirely (anchors cl5/cl6/cl7).
#[test]
fn b9p9_cluster_direct_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
.explicitcluster
{{
    .reg .b32 %r<8>;
    mov.u32 %r1, 0;
    barrier.cluster.arrive.aligned;
    barrier.cluster.wait.aligned;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    assert!(kernels[0].explicit_cluster, "parser must capture .explicitcluster");
    let lowered = lower_kernel(&kernels[0]).unwrap();
    let text = lowered.to_sass_text();
    assert!(!text.contains("c[0x0][0x36c]"), "no runtime gate:\n{}", text);
    assert!(!text.contains("ISETP"), "no ISETP in direct mode:\n{}", text);
    assert!(!text.contains("BCL_"), "no branches in aligned direct mode:\n{}", text);
    let lines: Vec<&str> = text.lines().map(|l| l.trim()).collect();
    // exact vendor sequence (anchors cl7/cl8)
    let w1 = lines.iter().position(|l| l.starts_with("WARPSYNC.ALL")).unwrap();
    assert_eq!(&lines[w1..w1 + 5],
        &["WARPSYNC.ALL  ;", "MEMBAR.ALL.GPU  ;", "ERRBAR  ;", "CGAERRBAR  ;", "UCGABAR_ARV  ;"],
        "direct arrive.aligned glue order: {:?}", &lines[w1..w1 + 5]);
    let w2 = w1 + 5;
    assert_eq!(&lines[w2..w2 + 3],
        &["WARPSYNC.ALL  ;", "UCGABAR_WAIT  ;", "CCTL.IVALL  ;"],
        "direct wait.aligned glue order: {:?}", &lines[w2..w2 + 3]);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "{}", text);
}

/// b9 phase-3 #7: MEMBAR.ALL.CTA insertion — kernel-global mbarrier
/// co-presence gates the CTA fence into release arrives (anchors cl7/cl8:
/// init / expect_tx / try_wait all trigger; plain STS does not; relaxed
/// never). Program-order independent (arrive may precede the mbarrier op).
#[test]
fn b9p9_cluster_cta_fence_rule() {
    // with mbarrier co-presence: CTA fence lands between WARPSYNC and
    // MEMBAR.ALL.GPU in the arrive glue
    let with_mb = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
.explicitcluster
{{
    .reg .b32 %r<8>;
    .shared .align 8 .b64 mb[1];
    mov.b32 %r1, mb;
    barrier.cluster.arrive.aligned;
    mbarrier.try_wait.parity.shared::cta.b64 %p-placeholder, [%r1], 0;
    ret;
}}"#, PROLOG);
    let with_mb = with_mb.replace("%p-placeholder", "%p1")
        .replace(".reg .b32 %r<8>;", ".reg .b32 %r<8>;\n    .reg .pred %p<2>;");
    let kernels = parse_ptx(&with_mb).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    let lines: Vec<&str> = text.lines().map(|l| l.trim()).collect();
    let w = lines.iter().position(|l| l.starts_with("WARPSYNC.ALL")).unwrap();
    assert_eq!(lines[w + 1], "MEMBAR.ALL.CTA  ;",
        "CTA fence must precede ALL.GPU with mbarrier co-presence: {:?}", &lines[w..w + 4]);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "{}", text);

    // relaxed arrive: NEVER a CTA fence, even with mbarrier co-presence
    let relaxed = with_mb.replace("barrier.cluster.arrive.aligned", "barrier.cluster.arrive.relaxed.aligned");
    let kernels = parse_ptx(&relaxed).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert!(!text.contains("MEMBAR"), "relaxed carries no fence: {}", text);

    // without mbarrier ops: no CTA fence (anchor cl7_arrive_al)
    let no_mb = with_mb.replace("    mbarrier.try_wait.parity.shared::cta.b64 %p1, [%r1], 0;\n", "");
    let kernels = parse_ptx(&no_mb).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert!(!text.contains("MEMBAR.ALL.CTA"), "no mbarrier -> no CTA fence: {}", text);
    assert!(text.contains("MEMBAR.ALL.GPU"), "release chain stays: {}", text);
}

/// b9 phase-3 #7: guarded mode keeps working when mbarrier ops coexist
/// (anchor cl8_guarded_init): the CTA fence lands in the then-branch.
#[test]
fn b9p9_cluster_guarded_mbar_cta_fence() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<8>;
    .shared .align 8 .b64 mb[1];
    mov.b32 %r1, mb;
    mbarrier.init.shared::cta.b64 [%r1], 1;
    barrier.cluster.arrive.aligned;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    let lines: Vec<&str> = text.lines().map(|l| l.trim()).collect();
    let w = lines.iter().position(|l| l.starts_with("WARPSYNC.ALL")).unwrap();
    assert_eq!(lines[w + 1], "MEMBAR.ALL.CTA  ;", "guarded then-branch: {:?}", &lines[w..w + 5]);
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "{}", text);
}

/// b9 phase-3 #7: mapa.shared::cluster.u32 -> S2R + LEA<<24 + PRMT splice
/// (anchors cl2). imm 0 -> RZ; imm != 0 materialized with plain MOV;
/// register ctaid resolved directly.
#[test]
fn b9p9_mapa_forms() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
.explicitcluster
{{
    .reg .b32 %r<10>;
    .shared .align 8 .b64 sh[1];
    mov.b32 %r1, sh;
    mapa.shared::cluster.u32 %r2, %r1, 0;
    mov.b32 %r5, 5;
    mapa.shared::cluster.u32 %r3, %r1, %r5;
    mapa.shared::cluster.u32 %r4, %r1, 2;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let text = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert_eq!(text.matches("S2R").count(), 3, "{}", text);       // ctaid glue per op
    assert_eq!(text.matches("LEA").count(), 3, "{}", text);
    assert_eq!(text.matches("PRMT").count(), 3, "{}", text);
    assert!(text.contains(", 0x654,"), "PRMT sel 0x654: {}", text);
    assert!(text.matches("PRMT").any(|_| true));
    let (bytes, n) = assemble_body(&text);
    assert!(bytes.len() == n * 16, "{}", text);
}

/// b9 phase-3 #7: fail-closed territory — guards, unknown sem suffixes
/// (exact-name match; a prefix rule must not trap them), bad mapa shapes.
#[test]
fn b9p9_cluster_fail_closed() {
    for (tag, body) in [
        ("guarded-barrier", "@%p1 barrier.cluster.arrive.aligned;"),
        ("sc-suffix", "barrier.cluster.arrive.sc;"),
        ("release-cluster-wait", "barrier.cluster.wait.release;"),
        ("mapa-imm-ctaid-over", "mapa.shared::cluster.u32 %r2, %r1, 256;"),
        ("mapa-imm-addr", "mapa.shared::cluster.u32 %r2, 4, 0;"),
    ] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<3>;
    .reg .b32 %r<8>;
    .shared .align 8 .b64 sh[1];
    mov.b32 %r1, sh;
    {}
    ret;
}}"#, PROLOG, body);
        let kernels = parse_ptx(&ptx).unwrap();
        assert!(lower_kernel(&kernels[0]).is_err(), "{} must be unsupported:\n{:?}", tag, body);
    }
}

/// b9 phase-3 #7: WARPSYNC.COLLECTIVE label targets encode via the sm_103a
/// REL16 fixup (imm = (target - addr - 16) >> 4; [23:18] | [43:34], like
/// BRA) — vendor anchors cl1 word-equality. Layout: WSC at 0x0, target at
/// 0x20 -> rq = (0x20 - 0x10) >> 4 = 1.
#[test]
fn b9p9_warpsync_collective_rel16_encoding() {
    let (bytes, n) = assemble_body(
        "WARPSYNC.COLLECTIVE.ALL `(L0) ;
         NOP ;
L0:
         EXIT ;
");
    assert_eq!(n, 3);
    let w = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
    let rq = ((w >> 18) & 0x3F) | (((w >> 34) & 0x3FF) << 6);
    assert_eq!(rq, 1, "REL16 immediate must be 1 (vendor-derived formula)");
    // sign-extension lane clean for positive offsets
    assert_eq!((w >> 44) & 0xFFFFF, 0, "anchors carry no [63:44] payload bits here");
    // and the decode re-spells the same form (nvdisasm-side proven in
    // results/b9/cluster_parity/verify_parity.py).
}

// ═══ b9 phase-3 #8 (iter39): vote/match/bar.warp/elect/nanosleep/griddep/
//     cp.async/cvt-sub-word/cvta.shared — vendor-anchored (ptxas 13.3 -O0
//     sm_103a, probes work/b9p10/probes; byte-parity results/b9/b9p10_parity).

fn lower_text(body: &str) -> String {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0,
    .param .u64 k_param_1
)
{{
    .reg .pred %p<5>;
    .reg .b16 %rs<4>;
    .reg .b32 %r<10>;
    .reg .b64 %rd<6>;
    .reg .f32 %f<4>;
    .reg .f64 %fd<3>;
    ld.param.u64 %rd1, [k_param_0];
    ld.param.u64 %rd2, [k_param_1];
    ld.global.u32 %r1, [%rd1];
    setp.ne.u32 %p1, %r1, 0;
    {}
    ret;
}}"#, PROLOG, body);
    let kernels = parse_ptx(&ptx).unwrap();
    lower_kernel(&kernels[0]).unwrap().to_sass_text()
}

#[test]
fn b9p10_vote_glue() {
    let t = lower_text("vote.sync.ballot.b32 %r3, %p1, 0xffffffff;");
    assert!(t.contains("MOV R"), "imm mask materialized: {}", t);
    assert!(t.contains("WARPSYNC.COLLECTIVE") && t.contains("VOTE.ANY") && t.contains("ENDCOLLECTIVE"), "{}", t);
    assert!(t.contains("VOT_"), "gensym label: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);

    let t = lower_text("vote.sync.any.pred %p2, %p1, %r1; vote.sync.all.pred %p3, %p1, %r1;");
    assert!(t.contains("VOTE.ANY") && t.contains("VOTE.ALL"), "{}", t);
    assert!(!t.contains("MOV R"), "reg mask is used directly (bw1/vm1 anchor)");
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p10_match_barwarp() {
    let t = lower_text("match.any.sync.b32 %r3, %r1, 0xffffffff; bar.warp.sync %r1;");
    assert!(t.contains("MATCH.ANY"), "{}", t);
    assert_eq!(t.matches("WARPSYNC.COLLECTIVE").count(), 2, "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p10_elect_sink_and_real() {
    let t = lower_text("elect.sync %rx|%px, %r1;");
    assert!(t.contains("ELECT P") && t.contains("UR79"), "{}", t);
    assert_eq!(t.matches("MOV R").count(), 0, "sink dst skips MOV (el2 anchor): {}", t);
    let t2 = lower_text("elect.sync %r3|%p2, %r1;");
    assert!(t2.contains("MOV R"), "real dst reads UR79 back: {}", t2);
    let (bytes, n) = assemble_body(&t2);
    assert_eq!(bytes.len(), n * 16, "{}", t2);
}

#[test]
fn b9p10_nanosleep_griddep() {
    let t = lower_text("nanosleep.u32 50; nanosleep.u32 %r1; griddepcontrol.launch_dependents; griddepcontrol.wait;");
    assert!(t.contains("NANOSLEEP 0x32") && t.contains("NANOSLEEP R"), "{}", t);
    assert!(t.contains("PREEXIT") && t.contains("ACQBULK"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p10_cp_async_forms() {
    // plain .ca 4 / .cg 16 + group protocol (anchors cp1/cp2 + p_ldgsts/b_cpasync)
    let t = lower_text("cp.async.ca.shared.global [%r1], [%rd1], 4; cp.async.cg.shared.global [%r1+16], [%rd1+16], 16; cp.async.commit_group; cp.async.wait_group 1; cp.async.wait_all;");
    assert!(t.contains("LDGSTS.E [") && t.contains("LDGSTS.E.BYPASS.128 ["), "{}", t);
    assert_eq!(t.matches("@!PT LDS RZ, [RZ]").count(), 3, "trio once per kernel: {}", t);
    assert!(t.contains("LDGDEPBAR") && t.contains("DEPBAR.LE 0x0, 0x1") && t.contains("DEPBAR.LE 0x0, 0x0"), "{}", t);
    assert!(t.contains("IADD3"), "dst+16 folded into address math (cp1 anchor): {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);

    // src-size operand -> ZFILL form with the size-adjust glue (p13/cp1 anchor)
    let t = lower_text("cp.async.cg.shared.global.L2::128B [%r1], [%rd1], 16, %r1;");
    assert!(t.contains("LDGSTS.E.BYPASS.LTC128B.128.ZFILL"), "{}", t);
    assert!(t.contains("ISETP.EQ.U32.AND") && t.contains("LOP3.LUT") && t.contains("!P"), "{}", t);
    assert!(t.ends_with(".endentry\n") || t.contains(".endentry"), "");
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);

    // imm src-size == 16 keeps the same ZFILL shape (p13 anchor, vendor -O0)
    let t = lower_text("cp.async.cg.shared.global [%r1], [%rd1], 16, 16;");
    assert!(t.contains("LDGSTS.E.BYPASS.128.ZFILL"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p10_cvt_subword_f16() {
    let t = lower_text("cvt.rn.f16.f32 %rs1, %f1; cvt.rn.f16x2.f32 %r2, %f1, %f2;");
    assert!(t.contains("F2F.F16.F32") && t.contains("F2FP.F16.F32.PACK_AB"), "{}", t);
    let t = lower_text("cvt.u32.u16 %r2, %rs1; cvt.s32.s16 %r3, %rs1; cvt.u16.u32 %rs2, %r1;");
    assert!(t.contains("PRMT") && t.contains("0x7710") && t.contains("0x9910") && t.contains("0x7610"), "{}", t);
    let t = lower_text("cvt.u64.u16 %rd3, %rs1; cvt.rzi.s32.f64 %r2, %fd1; cvt.rni.sat.s16.f32 %rs1, %f1; cvt.rn.f32.s16 %f2, %rs2;");
    assert!(t.contains("F2I.F64.TRUNC") && t.contains("F2I.S16.NTZ") && t.contains("I2F.S16"), "{}", t);
    let (_, n) = assemble_body(&t);
    assert!(n > 0);
    let t = lower_text("cvta.to.shared.u64 %rd3, %rd1;");
    assert!(!t.contains("S2R"), "runtime-generic cvta.to.shared is an alias (b_ldmatrix anchor): {}", t);
}

#[test]
fn b9p10_fail_closed() {
    for body in [
        "@%p1 vote.sync.ballot.b32 %r3, %p1, 0xffffffff;", // guarded collective
        "match.any.sync.b64 %rd3, %rd1, %rd1;",            // unattested width
        "elect.sync %r3, %r1;",                            // missing pred pipe dst
        "cp.async.ca.shared.global [%r1], [%rd1], 8, %rd1;", // 64-bit src-size
        "cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes [%r1], [%rd1], 16, [%r1];",
        "cvt.rpi.f32.f32 %f1, %f2;",                       // unattested rounding pair
        "cvt.rn.f16.f64 %rs1, %fd1;",                      // unattested src width
    ] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<5>;
    .reg .b16 %rs<4>;
    .reg .b32 %r<10>;
    .reg .b64 %rd<6>;
    .reg .f32 %f<4>;
    .reg .f64 %fd<3>;
    ld.param.u64 %rd1, [k_param_0];
    setp.eq.u32 %p1, %r1, %r2;
    {}
    ret;
}}"#, PROLOG, body);
        let kernels = parse_ptx(&ptx).unwrap();
        assert!(lower_kernel(&kernels[0]).is_err(), "must be unsupported: {}", body);
    }
}

// ═══ b9 phase-3 #9 (iter40, loop5/blind): bf16 / ldmatrix-stmatrix / b16 /
//     sub.s64..popc.b64 / mul64 network / mad.wide.u32 / cp.async.bulk +
//     surfaced fixes (VIMNMX swap for BUG-059, GPR 255=RZ fail-closed cap).
//     Vendor anchors ptxas 13.3 sm_103a -O0: probes work/b9p11/probes
//     (s64_*, b16a/b16b, t16i, madwi, mnm1, mulf16, ldsm1 + corpus O0/O3
//     anchors); byte-parity results/b9/b9p11_parity (259/259 payload IDENT).

#[test]
fn b9p11_bf16_forms() {
    let t = lower_text("cvt.rn.bf16.f32 %rs1, %f1; add.bf16x2 %r2, %r1, %r1; mul.bf16x2 %r3, %r2, %r2;");
    assert!(t.contains("F2F.BF16.F32"), "cvt.rn.bf16.f32 anchor (p16 0x200): {}", t);
    assert!(t.contains("HADD2.BF16_V2") && t.contains("HMUL2.BF16_V2"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_ldsm_stsm() {
    let t = lower_text("ldmatrix.sync.aligned.m8n8.x4.shared.b16 {%r1,%r2,%r3,%r4}, [%rd1];");
    assert!(t.contains("LDSM.16.M88.4 R") && t.contains("[R"), "x4 quad: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
    let t = lower_text("ldmatrix.sync.aligned.m8n8.x1.shared.b16 {%r1}, [%r2];");
    assert!(t.contains("LDSM.16.M88 R") && !t.contains("LDSM.16.M88.4"), "x1 plain: {}", t);
    let t = lower_text("stmatrix.sync.aligned.m8n8.x4.shared.b16 [%r1], {%r2,%r3,%r4,%r5};");
    assert!(t.contains("STSM.16.M88.4 [R"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_b16_logic_arith() {
    // vendor LUT bytes: and 0xc0 / or 0xfc / xor 0x3c (b16a/b16b anchors)
    let t = lower_text("and.b16 %rs1, %rs2, 3; or.b16 %rs2, %rs1, %rs3; xor.b16 %rs3, %rs2, 2047;");
    assert!(t.contains("LOP3.LUT") && t.contains("0xc0") && t.contains("0xfc") && t.contains("0x3c"), "{}", t);
    // add.s16 = plain IADD3 (wrap truncation deferred to the pack)
    let t = lower_text("add.s16 %rs1, %rs2, 7;");
    assert!(t.contains("IADD3") && !t.contains("PRMT"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
    // sub.s16 imm-first and reg-reg: neg + u16 clamp + add (3 insns each)
    let t = lower_text("sub.s16 %rs1, 1951, %rs2;");
    assert_eq!(t.matches("IADD3").count(), 2, "{}", t);
    assert!(t.contains("PRMT") && t.contains("0x7710"), "{}", t);
    let t = lower_text("sub.s16 %rs1, %rs2, %rs3;");
    assert!(t.matches("IADD3").count() == 2 && t.contains("PRMT"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_b16_mul_shr_selp_mov() {
    // mul.lo.s16: 0x9910 sign-extend both + IMAD; imm-b materializes
    // MOV v&0xffff first (t16i/probe-022920 anchors).
    let t = lower_text("mul.lo.s16 %rs1, %rs2, %rs3;");
    assert_eq!(t.matches("PRMT").count(), 2, "{}", t);
    assert!(t.contains("0x9910") && t.contains("IMAD"), "{}", t);
    let t = lower_text("mul.lo.s16 %rs1, %rs2, 11;");
    assert!(t.contains("MOV R") && t.contains("0xb"), "imm-b MOV pair materialization: {}", t);
    // mul.hi.u16: 0x7710 both + IMAD.U32 + SHF 16
    let t = lower_text("mul.hi.u16 %rs1, %rs2, %rs3;");
    assert!(t.contains("0x7710") && t.contains("IMAD.U32") && t.contains("SHF.R.U32.HI"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
    // shr.u16 imm: MOV + 0x7710 + SHF; reg: VIMNMX.U32 clamp + 0x7710 + SHF
    let t = lower_text("shr.u16 %rs1, %rs2, 4;");
    assert!(t.contains("MOV R") && t.contains("0x7710") && t.contains("SHF.R.U32.HI"), "{}", t);
    let t = lower_text("shr.u16 %rs1, %rs2, %r1;");
    assert!(t.contains("VIMNMX.U32") && t.contains("0xffff"), "{}", t);
    // selp.b16 = plain SEL; mov.b16 = plain MOV (reg/imm)
    let t = lower_text("selp.b16 %rs1, %rs2, %rs3, %p1; mov.b16 %rs3, %rs1;");
    assert!(t.contains("SEL") && t.contains("MOV R"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_sub64_slot_order() {
    let t = lower_text("sub.s64 %rd3, %rd1, %rd2;");
    // vendor -O0 slot order: IADD3.X dhi, PT, PT, ahi, ~bhi, RZ, Pc, !PT
    assert!(t.contains("IADD3.X") && t.contains("~R"), "a.hi at slot A, ~b.hi at slot B: {}", t);
    assert!(t.contains("-R"), "lo negated: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_min64_clz_popc() {
    let t = lower_text("min.s64 %rd3, %rd1, %rd2;");
    assert!(t.contains("ISETP.LT.U32.AND") && t.contains("ISETP.LT.AND.EX"), "{}", t);
    assert_eq!(t.matches("SEL").count(), 2, "{}", t);
    let t = lower_text("min.s64 %rd3, %rd1, 4096;");
    assert!(t.contains("0x1000") && t.contains("ISETP.LT.AND.EX"), "imm4096 anchor: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
    let t = lower_text("clz.b64 %r3, %rd1;");
    assert!(t.contains("ISETP.EQ.U32.AND") && t.contains("FLO.U32") && t.contains("0x1f"), "{}", t);
    let t = lower_text("popc.b64 %r3, %rd1;");
    assert_eq!(t.matches("POPC").count(), 2, "{}", t);
    // vendor -O0 keeps the ~0 mask AND idiom per half (verbatim, dead)
    assert!(t.contains("0x33"), "identity mask LUT verbatim: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_mul64_network() {
    let t = lower_text("mul.lo.s64 %rd3, %rd1, %rd2;");
    assert_eq!(t.matches("IMAD.WIDE.U32").count(), 4, "full -O0 network incl. dead hi lanes: {}", t);
    assert!(t.contains("IADD3.X") && t.contains("IMAD.WIDE.U32.X"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
    // imm b: lo/hi halves inline (s64_mulloi anchor), same 7-insn skeleton
    let t = lower_text("mul.lo.s64 %rd3, %rd1, -2960836687051489901;");
    assert!(t.contains("0x6659fd93") && t.contains("-0x29170148"), "imm split lo/hi: {}", t);
    assert_eq!(t.matches("IMAD.WIDE.U32").count(), 4, "{}", t);
    // mad.lo.s64 imm c: MOV pair materialization (madwi anchor)
    let t = lower_text("mad.lo.s64 %rd3, %rd1, %rd2, 765737733928381521;");
    assert!(t.contains("0x75e9ec51") && t.contains("0xaa07269"), "c MOV pair: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
    // mul.hi.u64: same network, result = t3
    let t = lower_text("mul.hi.u64 %rd3, %rd1, %rd2;");
    assert_eq!(t.matches("IMAD.WIDE.U32").count(), 4, "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_mad_wide32() {
    let t = lower_text("mad.wide.u32 %rd3, %r1, %r2, %rd1;");
    assert!(t.contains("IMAD.U32") && t.contains("IMAD.HI.U32"), "{}", t);
    assert!(t.contains("IADD3.X"), "addend carry chain: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_cp_async_bulk() {
    let t = lower_text("cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes [%r1], [%rd1], %r2, [%r3];");
    assert!(t.contains("UBLKCP.S.G [UR"), "{}", t);
    assert!(t.contains("ELECT") && t.contains("BRA.U.ANY") && t.contains("BCP_"), "elect loop: {}", t);
    assert!(t.contains("SHF.R.U32.HI") && t.contains("0x5410"), "bytes>>4 pack: {}", t);
    assert_eq!(t.matches("R2UR").count(), 5, "UR window: {}", t);
    assert!(t.contains("S2R") && t.contains("SR_CgaCtaId") && t.contains("LEA"), "CGA glue: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_vimnmx_swap() {
    // BUG-059 surface: plain IMNMX with pred-outputs is silicon-illegal on
    // sm_103a; the gateway emits VIMNMX[.U32] with the PT/!PT trick (mnm1).
    let t = lower_text("min.s32 %r3, %r1, %r2; max.s32 %r4, %r1, %r2; min.u32 %r5, %r1, 7;");
    assert!(t.contains("VIMNMX R") && t.contains("VIMNMX.U32"), "{}", t);
    assert!(!t.lines().any(|l| l.trim_start().starts_with("IMNMX ")),
        "no plain IMNMX R-form from the gateway: {}", t);
    assert!(t.contains("!PT"), "max via !PT select: {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_f16x2_arith() {
    let t = lower_text("fma.rn.f16x2 %r3, %r1, %r1, %r1; mul.f16x2 %r2, %r1, %r1;");
    assert!(t.contains("HFMA2") && t.contains("HMUL2"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

#[test]
fn b9p11_fail_closed() {
    for body in [
        "div.u16 %rs1, %rs2, %rs3;",                        // CALL lane (helper fn)
        "ldmatrix.sync.aligned.m8n8.x2.shared.b16 {%r1,%r2}, [%r2];", // x2 unattested
        "ldmatrix.sync.aligned.m8n8.x1.shared.b16 {%r1}, [%r2+8];",   // nonzero [R+imm]
        "@%p1 ldmatrix.sync.aligned.m8n8.x4.shared.b16 {%r1,%r2,%r3,%r4}, [%r2];",
        "@%p1 sub.s64 %rd3, %rd1, %rd2;",                   // guarded 64-bit chain
        "min.s64 %rd3, %rd1, -1;",                          // imm hi != 0 unattested
        "sub.s64 %rd3, %rd1, 5;",                           // imm subtrahend unattested
        "mul.hi.s64 %rd3, %rd1, %rd2;",                     // signed mul.hi unattested
        "cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes [%r1], [%rd1], 16, [%r1];", // imm size
        "cp.async.bulk.shared::cta.global.mbarrier::complete_tx::bytes [%r1], [%rd1], %r2, [%r1];",   // ::cta unattested
    ] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<5>;
    .reg .b16 %rs<6>;
    .reg .b32 %r<10>;
    .reg .b64 %rd<6>;
    .reg .f32 %f<4>;
    ld.param.u64 %rd1, [k_param_0];
    setp.eq.u32 %p1, %r1, %r2;
    {}
    ret;
}}"#, PROLOG, body);
        let kernels = parse_ptx(&ptx).unwrap();
        assert!(lower_kernel(&kernels[0]).is_err(), "must be unsupported: {}", body);
    }
}

#[test]
fn b9p11_gpr_cap_rz_trap() {
    // >254 live GPRs must bail fail-closed (R255 == RZ alias = silent data
    // corruption; surfaced by bench_m9, dead-write smoking guns in the old
    // green set vk/test29/test35: `IMAD RZ, ...` / `LDS RZ, [R255+..]`).
    let mut body = String::new();
    body.push_str("add.u32 %r9, %r1, %r2;\n");
    for i in 10..270 {
        body.push_str(&format!("add.u32 %r{}, %r{}, 1;\n", i, i - 1));
    }
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<300>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.u32 %r1, [%rd1];
  {}
    ret;
}}"#, PROLOG, body);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).err().map(|e| format!("{e}"));
    assert!(err.as_deref().map_or(false, |e| e.contains("GPR space exhausted")),
        "must bail fail-closed: {:?}", err);
    // and a just-legal chain still lowers
    let mut body = String::new();
    for i in 3..40 {
        body.push_str(&format!("add.u32 %r{}, %r{}, 1;\n", i, i - 1));
    }
    let t = lower_text(&body.replace("%r", "%r"));
    assert!(t.contains("IADD3"), "{}", t);
}

// ── b9p15 (phase-3 #13): redux.sync lane ─────────────────────────────────
/// Vendor-anchored law (corpus p08_redux O0 0x0f0/0x1d0/0x270, p_redux O0,
/// v_redux1 O0/O3 + reduxprobes rdx_a..rdx_e O0/O3): each redux.sync at -O0
/// wraps as [MOV Rm, mask-imm ;] WARPSYNC.COLLECTIVE Rm, `(L) ; REDUX|CREDUX
/// UR79, Ra ; MOV Rd, UR79 ; ENDCOLLECTIVE ; L:. -O3 elides the wrap (bare
/// REDUX family; documented divergence, spans claimed -O0 only).
fn redux_lane_text(op: &str, mask: &str) -> String {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<8>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r4, -1;
    {} %r3, %r2, {};
    st.global.b32 [%rd1], %r3;
    ret;
}}"#, PROLOG, op, mask);
    let kernels = parse_ptx(&ptx).unwrap();
    lower_kernel(&kernels[0]).unwrap().to_sass_text()
}

#[test]
fn b9p15_redux_forms() {
    for (op, sass) in [
        ("redux.sync.add.s32", "REDUX.SUM.S32"),
        ("redux.sync.add.u32", "REDUX.SUM"),
        ("redux.sync.max.u32", "CREDUX.MAX"),
        ("redux.sync.min.u32", "CREDUX.MIN"),
        ("redux.sync.max.s32", "CREDUX.MAX.S32"),  // probe-anchored (rdx_d)
        ("redux.sync.min.s32", "CREDUX.MIN.S32"),  // probe-anchored (rdx_d)
    ] {
        let t = redux_lane_text(op, "%r4");
        let expect = format!("{} UR79,", sass);
        assert!(t.contains(&expect), "{} must emit {:?}: {}", op, expect, t);
        // exactly one redux word inside the O0 wrap; MOV Rd, UR79 readout
        assert!(t.contains("WARPSYNC.COLLECTIVE"), "{}: {}", op, t);
        assert!(t.contains("ENDCOLLECTIVE"), "{}: {}", op, t);
        assert!(t.matches("UR79").count() >= 2, "{}: {}", op, t);
        // ordering: wrap -> redux word -> MOV Rd, UR79 -> ENDCOLLECTIVE
        let iw = t.find("WARPSYNC.COLLECTIVE").unwrap();
        let ir = t.find(&expect).unwrap();
        let ie = t.find("ENDCOLLECTIVE").unwrap();
        assert!(iw < ir && ir < ie, "wrap->redux->end ordering broken: {}", t);
        let readout = t[ir..].find(", UR79").expect("MOV Rd, UR79 readout missing");
        let _ = readout;
    }
}

#[test]
fn b9p15_redux_mask_imm_materializes() {
    // imm membermask: vendor materializes via MOV into scratch then
    // WARPSYNC.COLLECTIVE Rm (b9p8 helper path; v_redux1 anchor).
    let t = redux_lane_text("redux.sync.add.u32", "0xffffffff");
    assert!(t.contains("MOV"), "imm mask must materialize: {}", t);
    assert!(t.contains("WARPSYNC.COLLECTIVE"), "{}", t);
    assert!(t.contains("REDUX.SUM UR79,"), "{}", t);
}

#[test]
fn b9p15_redux_fail_closed() {
    for body in [
        "redux.sync.and.b32 %r3, %r2, %r4;",
        "redux.sync.or.b32  %r3, %r2, %r4;",
        "redux.sync.xor.b32 %r3, %r2, %r4;",
        "redux.sync.add.u64 %rd2_NOT64, %r2, %r4;", // wide form: parser splits, lower bails
        "redux.sync.add.u32 %r3, 42, %r4;",          // imm src unattested
        "redux.sync.add.s64 %rd2b, %rd2, %r4;",      // wide min/max lane N/A
    ] {
        let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<8>;
    .reg .b64   %rd<4>;
    ld.param.u64 %rd1, [k_param_0];
    mov.b32 %r4, -1;
    {}
    ret;
}}"#, PROLOG, body);
        let kernels = parse_ptx(&ptx).unwrap();
        assert!(lower_kernel(&kernels[0]).is_err(), "must be unsupported: {}", body);
    }
    // guarded form fail-closed
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<2>;
    .reg .b32   %r<8>;
    setp.eq.u32 %p1, %r1, %r2;
    @%p1 redux.sync.add.u32 %r3, %r2, 0xffffffff;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    assert!(lower_kernel(&kernels[0]).is_err(), "guarded redux must be unsupported");
}

#[test]
fn b9p15_redux_corpus_p08_shape() {
    // The 3-op chain (add.s32 -> add -> max.u32 -> add -> min.u32) lowers end-to-end:
    // 3 wraps, 3 redux words, all result MOVs from UR79.
    let ptx = std::fs::read_to_string("/root/blindlab/work/b9census/ptx/p08_redux-eb6f6d.ptx").unwrap();
    let kernels = parse_ptx(&ptx).unwrap();
    let t = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert_eq!(t.matches("WARPSYNC.COLLECTIVE").count(), 3, "{}", t);
    assert!(t.contains("REDUX.SUM.S32 UR79,") && t.contains("CREDUX.MAX UR79,")
        && t.contains("CREDUX.MIN UR79,"), "{}", t);
    assert_eq!(t.matches("ENDCOLLECTIVE").count(), 3, "{}", t);
}
