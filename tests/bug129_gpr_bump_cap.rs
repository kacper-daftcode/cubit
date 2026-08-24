//! BUG-129: GPR bump-pointer cap
//! arithmetic in ptx_lower. Pre-fix (b6a254d..15ee924):
//!   (a) gpr()/gpr_pair()/gpr_quad()/prepare_group bumped a u8 `next_gpr`
//!       with plain `+=`; at the cap edge the arithmetic itself overflowed
//!       -> panic in debug builds *before* the intended fail-closed bail
//!       (surfaced as b9p11_gpr_cap_rz_trap), wrap-around in release.
//!   (b) the pair/gQuad/group bumps past next_gpr==255 could silently
//!       re-issue R0-class slots with NO cap record (release corner).
//!   (c) prepare_group had no cap check at all.
//!   (d) cp.async.bulk lane debug_assert said 16 while the lane emits 17
//!       (stale from introduction a5369db; fired as b9p11_cp_async_bulk).
//! Post-fix: saturating bump_gpr() + overflow-free bounds + group cap bail;
//! every over-cap path ends in fail-closed Err, no panic, in both profiles.
use cubit::ptx_lower::lower_kernel;
use cubit::ptx_parse::parse_ptx;
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// cubit::assemble consumes a bare instruction stream (same helper as
/// tests/b9_ptx_lower.rs).
fn assemble_body(text: &str) -> (Vec<u8>, usize) {
    let body: String = text.lines()
        .filter(|l| !l.trim_start().starts_with('.'))
        .collect::<Vec<_>>().join("\n");
    cubit::assemble(&body, 0, &table()).unwrap()
}

const PROLOG: &str = ".version 9.3\n.target sm_103a\n.address_size 64\n\n";

/// Kernel with K singles kept live across one trailing .b64 pair load.
/// Register budget: %rd1 pair = (2,3); K singles %r1..%rk = 4..(4+K-1).
fn build_k_singles_then_pair(k: usize) -> String {
    let mut body = String::new();
    body.push_str("    ld.param.u64 %rd1, [k_param_0];\n");
    for i in 1..=k {
        body.push_str(&format!("    ld.global.u32 %r{}, [%rd1];\n", i));
    }
    body.push_str("    ld.global.b64 %rd2, [%rd1];\n"); // the corner pair alloc
    // keep every single live past the pair allocation, then drain
    body.push_str("    add.u32 %r1, %r1, %r2;\n");
    for i in 2..=k {
        // fold each single into %r1 exactly once (last use of %r{i})
        body.push_str(&format!("    add.u32 %r1, %r1, %r{};\n", i));
    }
    body.push_str("    st.global.b32 [%rd1+8], %r1;\n");
    body.push_str("    st.global.b64 [%rd1+16], %rd2;\n");
    body.push_str("    ret;");
    format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<{}>;
    .reg .b64 %rd<4>;
{}
}}"#, PROLOG, k + 2, body)
}

fn lower_result(ptx: &str) -> Result<String, anyhow::Error> {
    let kernels = parse_ptx(ptx).unwrap();
    lower_kernel(&kernels[0]).map(|l| l.to_sass_text())
}

/// t129_1: pair allocation AT the odd 255 bump-pointer corner (pre-fix:
/// u8 overflow on the alignment pad -> debug panic; release wrapped to 0
/// and silently re-issued R0/R1 with no cap record).
/// Post-fix: fail-closed Err, no panic.
#[test]
fn t129_1_pair_at_255_corner_fail_closed() {
    let ptx = build_k_singles_then_pair(251); // singles land 4..=254, next == 255
    let r = lower_result(&ptx);
    match &r {
        Err(e) => assert!(format!("{e:?}").contains("GPR space exhausted"),
            "fail-closed bail expected, got: {e:?}"),
        Ok(t) => panic!("over-cap kernel must not lower (silent-wrap corner):\n{}", &t[..t.len().min(400)]),
    }
}

/// t129_2: vector-group materialization at the same corner — the
/// prepare_group bump had NO cap check at all pre-fix (debug panic /
/// release-wrap into RZ-aliased lanes in emitted code). Stimulus uses the
/// vendor-attested st.shared.v2.b32 source-group lane (global v2 loads are
/// fail-closed Dst groups by design, so they never reach the bump).
#[test]
fn t129_2_group_at_255_corner_fail_closed() {
    let k = 251;
    let mut body = String::new();
    body.push_str("    ld.param.u64 %rd1, [k_param_0];\n");
    for i in 1..=k {
        body.push_str(&format!("    ld.global.u32 %r{}, [%rd1];\n", i));
    }
    body.push_str("    st.shared.v2.b32 [buf], {%r1, %r2};\n");
    for i in 2..=k {
        body.push_str(&format!("    add.u32 %r1, %r1, %r{};\n", i));
    }
    body.push_str("    st.global.b32 [%rd1+8], %r1;\n    ret;");
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .shared .align 16 .b8 buf[64];
    .reg .b32 %r<254>;
    .reg .b64 %rd<4>;
{}
}}"#, PROLOG, body);
    let r = lower_result(&ptx);
    match &r {
        // the group lane wraps the bail in opcode context; match the cause chain
        Err(e) => assert!(format!("{e:?}").contains("GPR space exhausted"),
            "fail-closed bail expected, got: {e:?}"),
        Ok(t) => panic!("over-cap vector group must not lower:\n{}", &t[..t.len().min(400)]),
    }
}

/// t129_3: the cp.async.bulk lane emits exactly 17 instructions and the
/// emitted body assembles through tables/sm103a.json (pre-fix the lane-size
/// debug_assert was a stale 16 and panicked in debug builds first).
#[test]
fn t129_3_cp_async_bulk_lane_shape_17() {
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .shared .align 16 .b8 buf[64];
    .reg .b32 %r<10>;
    .reg .b64 %rd<6>;
    ld.param.u64 %rd1, [k_param_0];
    ld.global.u32 %r1, [%rd1];
    mov.b32 %r2, 1024;
    mov.b32 %r3, 8;
    cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes [%r1], [%rd1], %r2, [%r3];
    ret;
}}"#, PROLOG);
    let kernels = parse_ptx(&ptx).unwrap();
    let t = lower_kernel(&kernels[0]).unwrap().to_sass_text();
    assert!(t.contains("UBLKCP.S.G [UR"), "{}", t);
    assert!(t.contains("ELECT") && t.contains("BRA.U.ANY") && t.contains("BCP_"),
        "elect loop: {}", t);
    // lane span: first S2R (CGA glue) .. BRA.U.ANY inclusive; the label
    // carrier line is not an instruction
    let insns: Vec<&str> = t.lines().map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('.') && !l.ends_with(':')).collect();
    let start = insns.iter().position(|l| l.starts_with("S2R")).expect("lane start");
    let end = insns.iter().position(|l| l.contains("BRA.U.ANY")).expect("lane end");
    assert_eq!(end - start + 1, 17, "lane shape pin (bump deliberately with the lane): {}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

/// t129_4 (invariant): a kernel that exactly fits the legal budget still
/// lowers — 248 singles (4..=251) + one trailing pair at lo=252 == the last
/// legal pair. Guards against over-eager cap after the saturating rewrite.
#[test]
fn t129_4_exact_fit_pair_still_lowers() {
    let ptx = build_k_singles_then_pair(248);
    let t = lower_result(&ptx).expect("exact-fit kernel must lower");
    assert!(t.contains("IADD3"), "{}", t);
    assert!(t.contains("STG"), "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}
