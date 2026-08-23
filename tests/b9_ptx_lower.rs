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
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b64   %rd<3>;
    ld.param.u64 %rd1, [k_param_0];
    st.global.u64 [%rd1], 0x123456789;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("wide immediate") || err.contains("32-bit stores"), "got: {}", err);
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

/// P5-negative: f16 cvt has no attested lowering (F2FP.PACK_AB + PRMT chain is
/// phase-3) and must hit the aggregated unsupported list.
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
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("cvt.rn.f16.f32"), "got: {}", err);
}

/// P6: redux.* rejected at the PTX layer (UR-dest op; the old REDUX.ADD/R-dest
/// rule was withdrawn — wrong op + unencodable form).
#[test]
fn b9p2_redux_rejected() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32   %r<4>;
    .reg .b64   %rd<2>;
    ld.param.u64 %rd1, [k_param_0];
    redux.sync.add.u32 %r1, %r2, 0xffffffff;
    st.global.b32 [%rd1], %r1;
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("redux.sync.add.u32"), "got: {}", err);
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

    let ptx = ptx.replace("and.pred %p3, !%p1, %p1;", "mov.pred %p3, 1;");
    let kernels = parse_ptx(&ptx).unwrap();
    let err = lower_kernel(&kernels[0]).unwrap_err().to_string();
    assert!(err.contains("mov.pred"), "imm src must name the op: {}", err);
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
