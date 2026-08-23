//! b9p14 (phase-3 #12) pins: mov/store/vector idiom residu lane
//!   * mov.pred imm {-1,0,+1} -> PLOP3.LUT all-PT constant forms
//!     (vendor anchors probes q1/movpred1 -O0, corpus p09/V1..V4)
//!   * activemask.b32 -> VOTE.ANY Rd, PT, PT (corpus p09 -O0 0x370)
//!   * st.global.{b64,u64,s64} imm -> IMAD.MOV.U32 lo,hi pair + STG.E.64
//!     (anchors corpus s_u64/v_p1i64 -O0, probe2 q2 -O0: -1/200000/42/1)
//!   * vector shared ld/st width-join: v2.b32 -> .64 pair, v2.b64/v4.b32
//!     -> .128 quad, imm/float members materialized (corpus p13/p29,
//!     probe2 q3/q4; p29 exposure fixed the pre-b9p14 silent bare-STS
//!     flattening of shared vector groups)
//!   * ld.global.v2.b64 -> LDG.E.128 / st.global.v2.b64 -> STG.E.128
//!     (q3/q4 + corpus p13/p29 -O0 law)
//! Doctrine: fail-closed on unanchored shapes.
use cubit::ptx_lower::lower_kernel;
use cubit::ptx_parse::parse_ptx;
use cubit::table::IsaTable;

fn hx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn assemble_body(text: &str) -> (Vec<u8>, usize) {
    let body: String = text.lines()
        .filter(|l| !l.trim_start().starts_with('.'))
        .collect::<Vec<_>>().join("\n");
    cubit::assemble(&body, 0, &table()).unwrap()
}
const PROLOG: &str = ".version 9.3\n.target sm_103a\n.address_size 64\n\n";
fn kern(body: &str) -> String {
    format!(r#"{} .visible .entry k(
    .param .u64 .ptr .align 1 k_param_0
)
{{
    .reg .pred %p<8>;
    .reg .b32  %r<40>;
    .reg .b64  %rd<12>;
    ld.param.b64 %rd1, [k_param_0];
    cvta.to.global.u64 %rd2, %rd1;
{}
    ret;
}}"#, PROLOG, body)
}
fn kern_shm(body: &str) -> String {
    format!(r#"{} .visible .entry k(
    .param .u64 .ptr .align 1 k_param_0
)
{{
    .shared .align 16 .b8 shm[128];
    .reg .pred %p<8>;
    .reg .b32  %r<40>;
    .reg .b64  %rd<12>;
    ld.param.b64 %rd1, [k_param_0];
    cvta.to.global.u64 %rd2, %rd1;
    mov.b32 %r30, shm;
{}
    ret;
}}"#, PROLOG, body)
}
fn lower(body: &str) -> String {
    let k = parse_ptx(&kern(body)).unwrap();
    lower_kernel(&k[0]).unwrap().to_sass_text()
}
fn lower_shm(body: &str) -> String {
    let k = parse_ptx(&kern_shm(body)).unwrap();
    lower_kernel(&k[0]).unwrap().to_sass_text()
}
fn lower_shm_err(body: &str) -> String {
    let k = parse_ptx(&kern_shm(body)).unwrap();
    match lower_kernel(&k[0]) { Ok(_) => String::new(), Err(e) => format!("{:#}", e) }
}
fn lower_err(body: &str) -> String {
    let k = parse_ptx(&kern(body)).unwrap();
    match lower_kernel(&k[0]) { Ok(_) => String::new(), Err(e) => format!("{:#}", e) }
}
fn lines_of(text: &str) -> Vec<String> {
    text.lines().map(|l| l.trim()).filter(|l| l.ends_with(';')).map(|l| l.to_string()).collect()
}
fn shape(l: &[String]) -> Vec<String> {
    let re = regex::Regex::new(r"\b(?:R|UR|P)(\d+)(\.64)?\b").unwrap();
    let mut out = Vec::new();
    let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for ll in l {
        let s = re.replace_all(ll, |c: &regex::Captures| {
            let t = format!("{}{}", &c[1], c.get(2).map(|m| m.as_str()).unwrap_or(""));
            if t == "255" || t == "255.64" { return "255".to_string(); }
            let k = t.clone();
            let n = map.len();
            let v = map.entry(k).or_insert(n);
            format!("@{v}{}", c.get(2).map(|m| m.as_str()).unwrap_or(""))
        });
        out.push(s.to_string());
    }
    out
}
fn shape_from(text: &str, marker_substr: &str) -> Vec<String> {
    let mut l = lines_of(text);
    let i = l.iter().position(|x| x.contains(marker_substr)).expect(marker_substr);
    l.drain(..i);
    shape(&l)
}

// ── 1. mov.pred imm shapes (anchors q1 0x80/0xb0/0xe0) ─────────────────
#[test]
fn b9p14_movpred_imm_shapes() {
    let t = lower("    mov.pred %p1, -1;");
    let s = shape_from(&t, "PLOP3.LUT");
    assert_eq!(s[0], "PLOP3.LUT @0, PT, PT, PT, PT, 0x80, 0x8 ;", "{s:?}");
    let t = lower("    mov.pred %p1, 0;");
    let s = shape_from(&t, "PLOP3.LUT");
    assert_eq!(s[0], "PLOP3.LUT @0, PT, PT, PT, PT, 0x8, 0x80 ;", "{s:?}");
    let t = lower("    mov.pred %p1, 1;");
    let s = shape_from(&t, "PLOP3.LUT");
    assert_eq!(s[0], "PLOP3.LUT @0, PT, PT, PT, PT, 0x80, 0x8 ;", "{s:?}");
    // reg form unchanged (P1' lane law)
    let t = lower("    setp.lt.s32 %p1, %r1, 0;\n    mov.pred %p2, %p1;");
    let s = shape_from(&t, "PLOP3.LUT");
    assert_eq!(s[0], "PLOP3.LUT @0, PT, @1, PT, PT, 0x80, 0x8 ;", "{s:?}");
}

// ── 2. mov.pred imm ENCODE byte-parity (probe2 q1 -O0 words) ───────────
#[test]
fn b9p14_movpred_encode_parity() {
    let (b, n) = assemble_body(
        "PLOP3.LUT P0, PT, PT, PT, PT, 0x80, 0x8 ;
         PLOP3.LUT P0, PT, PT, PT, PT, 0x8, 0x80 ;");
    assert_eq!(n, 2);
    assert_eq!(&b[0..12], &hx("1c7808000000000070f0f003")[..], "-1/+1 form");
    assert_eq!(&b[16..28], &hx("1c7880000000000070e1f003")[..], "0 form");
}

// ── 3. activemask.b32 -> VOTE.ANY d, PT, PT (p09 -O0 0x370) ────────────
#[test]
fn b9p14_activemask_shape_and_parity() {
    let t = lower("    activemask.b32 %r7;");
    let s = shape_from(&t, "VOTE.ANY");
    assert_eq!(s[0], "VOTE.ANY @0, PT, PT ;", "{s:?}");
    let (b, n) = assemble_body("VOTE.ANY R7, PT, PT ;");
    assert_eq!(n, 1);
    assert_eq!(&b[0..12], &hx("067807000000000000018e03")[..]);
}

// ── 4. st.global.b64 imm: lo/hi materialization + STG.E.64 ─────────────
#[test]
fn b9p14_stimm64_shapes() {
    // 42 (corpus s_u64): lo=0x2a hi=0x0 (anchor 0xe0/0xf0/0x120)
    let t = lower("    st.global.b64 [%rd2], 42;");
    let s = shape_from(&t, "IMAD.MOV.U32");
    assert_eq!(s[0], "IMAD.MOV.U32 @0, RZ, RZ, 0x2a ;", "{s:?}");
    assert_eq!(s[1], "IMAD.MOV.U32 @1, RZ, RZ, 0x0 ;", "{s:?}");
    assert_eq!(s[2], "STG.E.64 desc[@0][@2.64], @0 ;", "{s:?}");
    // -1 (probe q2): lo=0xffffffff hi=0xffffffff (anchor 0xc0/0xd0/0x100)
    let t = lower("    st.global.b64 [%rd2], -1;");
    let s = shape_from(&t, "IMAD.MOV.U32");
    assert_eq!(s[0], "IMAD.MOV.U32 @0, RZ, RZ, 0xffffffff ;", "{s:?}");
    assert_eq!(s[1], "IMAD.MOV.U32 @1, RZ, RZ, 0xffffffff ;", "{s:?}");
    assert_eq!(s[2], "STG.E.64 desc[@0][@2.64], @0 ;", "{s:?}");
    // 200000 (probe q2): lo=0x30d40 hi=0x0
    let t = lower("    st.global.u64 [%rd2], 200000;");
    let s = shape_from(&t, "IMAD.MOV.U32");
    assert_eq!(s[0], "IMAD.MOV.U32 @0, RZ, RZ, 0x30d40 ;", "{s:?}");
    assert_eq!(s[1], "IMAD.MOV.U32 @1, RZ, RZ, 0x0 ;", "{s:?}");
    // 32-bit path unchanged (I): single IMAD.MOV.U32 + STG.E
    let t = lower("    st.global.b32 [%rd2], 42;");
    let s = shape_from(&t, "IMAD.MOV.U32");
    assert_eq!(s[0], "IMAD.MOV.U32 @0, RZ, RZ, 0x2a ;", "{s:?}");
    assert_eq!(s[1], "STG.E desc[@0][@1.64], @0 ;", "{s:?}");
}

// ── 5. st.global.b64 imm ENCODE parity (s_u64/q2 vendor words) ─────────
#[test]
fn b9p14_stimm64_encode_parity() {
    let (b, n) = assemble_body(
        "MOV R6, 0x2a ;
         MOV R7, 0x0 ;
         STG.E.64 desc[UR4][R2.64], R6 ;");
    assert_eq!(n, 3);
    assert_eq!(&b[0..12], &hx("027806002a000000000f0000")[..]);
    assert_eq!(&b[16..28], &hx("0278070000000000000f0000")[..]);
    assert_eq!(&b[32..44], &hx("8679000206000000041b100c")[..]);
    let (b, n) = assemble_body(
        "MOV R8, 0xffffffff ;
         MOV R9, 0xffffffff ;
         STG.E.64 desc[UR4][R2.64], R8 ;");
    assert_eq!(n, 3);
    assert_eq!(&b[0..12], &hx("02780800ffffffff000f0000")[..]);
    assert_eq!(&b[16..28], &hx("02780900ffffffff000f0000")[..]);
    assert_eq!(&b[32..44], &hx("8679000208000000041b100c")[..]);
}

// ── 6. vector shared/global .128/.64 law shapes ────────────────────────
#[test]
fn b9p14_vecshapes() {
    // ld.shared.v2.b64 -> LDS.128 (quad dst; pair lanes lo,hi)
    let t = lower_shm("    ld.shared.v2.b64 {%rd3, %rd4}, [%r30];");
    let s = shape_from(&t, "LDS.128");
    assert_eq!(s[0], "LDS.128 @0, [@1] ;", "{s:?}");
    // st.shared.v2.b64 -> STS.128 (quad src; pre-MOVs when lanes differ)
    let t = lower_shm("    ld.global.v2.b64 {%rd3, %rd4}, [%rd2];\n    st.shared.v2.b64 [%r30], {%rd3, %rd4};");
    let s = shape_from(&t, "STS.128");
    assert_eq!(s[0], "STS.128 [@0], @1 ;", "{s:?}");
    // ld.global.v2.b64 -> LDG.E.128 (q3 law)
    let t = lower("    ld.global.v2.b64 {%rd3, %rd4}, [%rd2];");
    let s = shape_from(&t, "LDG.E.128");
    assert_eq!(s[0], "LDG.E.128 @0, desc[@0][@1.64] ;", "{s:?}");
    // st.global.v2.b64 -> STG.E.128
    let t = lower("    ld.global.v2.b64 {%rd3, %rd4}, [%rd2];\n    st.global.v2.b64 [%rd2+16], {%rd3, %rd4};");
    let s = shape_from(&t, "STG.E.128");
    assert_eq!(s[0], "STG.E.128 desc[@0][@1.64+0x10], @2 ;", "{s:?}");
    // ld.shared.v2.b32 -> LDS.64 (pair)
    let t = lower_shm("    ld.shared.v2.b32 {%r3, %r4}, [%r30];");
    let s = shape_from(&t, "LDS.64");
    assert_eq!(s[0], "LDS.64 @0, [@1] ;", "{s:?}");
    // st.shared.v2.b32 -> STS.64
    let t = lower_shm("    ld.global.b32 %r1, [%rd2];\n    st.shared.v2.b32 [%r30], {%r1, %r1};");
    let s = shape_from(&t, "STS.64");
    assert_eq!(s[0], "STS.64 [@0], @1 ;", "{s:?}");
    // st.shared.v4.b32 float-imms: 4x IMAD.MOV.U32 + STS.128 (p29 0x140-0x180)
    let t = lower_shm("    st.shared.v4.b32 [%r30], {0f3F800000, 0f40000000, 0f40400000, 0f40800000};");
    let s = shape_from(&t, "IMAD.MOV.U32");
    assert_eq!(s[1], "IMAD.MOV.U32 @1, RZ, RZ, 0x3f800000 ;", "{s:?}");
    assert_eq!(s[4], "IMAD.MOV.U32 @4, RZ, RZ, 0x40800000 ;", "{s:?}");
    assert_eq!(s[5], "STS.128 [@0], @1 ;", "{s:?}");
    // ld.shared.v4.b32 -> LDS.128 quad dst
    let t = lower_shm("    ld.shared.v4.b32 {%r3, %r4, %r5, %r6}, [%r30];");
    let s = shape_from(&t, "LDS.128");
    assert_eq!(s[0], "LDS.128 @0, [@1] ;", "{s:?}");
}

// ── 7. vector .128/.64 ENCODE parity (p29/q3/q4 vendor words) ──────────
#[test]
fn b9p14_vec_encode_parity() {
    let (b, n) = assemble_body(
        "STS.128 [R0], R12 ;
         LDS.128 R4, [R4] ;
         STG.E.128 desc[UR4][R2.64], R4 ;
         LDG.E.128 R4, desc[UR4][R2.64] ;");
    assert_eq!(n, 4);
    assert_eq!(&b[0..12], &hx("887300000c000000000c0000")[..], "STS.128");
    assert_eq!(&b[16..28], &hx("8479040400000000000c0000")[..], "LDS.128");
    assert_eq!(&b[32..44], &hx("8679000204000000041d100c")[..], "STG.E.128");
    assert_eq!(&b[48..60], &hx("8179040204000000001d1e0c")[..], "LDG.E.128");
}

// ── 8. fail-closed on unanchored shapes ────────────────────────────────
#[test]
fn b9p14_fail_closed() {
    let e = lower_err("    mov.pred %p1, 3;");
    assert!(e.contains("mov.pred"), "{e}");
    // vector imm store: no vendor anchor
    let e = lower_err("    st.global.v2.b64 [%rd2], 42;");
    assert!(e.contains("st.global"), "{e}");
    // 16-bit member vector: unattested
    let e = lower_shm_err("    ld.shared.v2.b16 {%r3, %r4}, [%r30];");
    assert!(e.contains("16-bit") || e.contains("unattested") || e.contains("ld.shared.v2"), "{e}");
    // v4.b64 = 256-bit: fail-closed
    let e = lower_shm_err("    st.shared.v4.b64 [%r30], {%rd3, %rd4, %rd5, %rd6};");
    assert!(e.contains("256") || e.contains("v4"), "{e}");
    // imm member inside a 64-bit group: mixed-width fail-closed
    let e = lower_shm_err("    st.shared.v2.b64 [%r30], {%rd3, 5};");
    assert!(e.contains("mixed") || e.contains("64-bit"), "{e}");
}

// ── 9. quad alignment law: v2.b64 dst lands 4-aligned (encoder LDS.128
//       quad convention), members keep even-pair alignment ──────────────
#[test]
fn b9p14_quad_alignment() {
    // burn one reg so a naive pair alloc would start misaligned; the v2.b64
    // dst must still be 4-aligned and its members at +0/+2 (even).
    let t = lower_shm(
        "    ld.global.b32 %r1, [%rd2];\n    ld.global.b32 %r2, [%rd2+4];\n    ld.global.b32 %r3, [%rd2+8];\n    ld.shared.v2.b64 {%rd3, %rd4}, [%r30];\n    mov.b64 {%r8, %r9}, %rd3;\n    st.global.b32 [%rd2], %r8;");
    assert!(t.contains("LDS.128"), "{t}");
    // the quad base in the LDS.128 line is 4-aligned
    let l = lines_of(&t).into_iter().find(|l| l.starts_with("LDS.128")).unwrap();
    let re = regex::Regex::new(r"LDS.128 R(\d+)").unwrap();
    let c = re.captures(&l).unwrap();
    let q: u32 = c[1].parse().unwrap();
    assert_eq!(q % 4, 0, "quad base 4-aligned: {l}");
}
