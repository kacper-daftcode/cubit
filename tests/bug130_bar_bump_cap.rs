//! BUG-130 (follow-up of BUG-129): bar_alloc BSSY/BSYNC
//! reconvergence-barrier bump pointer in ptx_lower.
//! Pre-fix (..efff676):
//!   (a) bar_alloc() bumped a u8 `bar_next` with plain `+=`; at the 255 edge
//!       the arithmetic itself overflowed -> panic in debug builds, wrap to
//!       B0 in release (exact BUG-129 shape, no cap record).
//!   (b) ids 16..254 were handed to the encoder, whose barrier field is 4
//!       bits wide (tables/sm103a.json BSSY_B_II RECONVERGENT/"", shift 16
//!       bits 4); field application masks the value
//!       (encoder.rs: code = (code & !mask) | ((value & mask) << shift)),
//!       so B16.. silently re-issued B0.. — two live reconvergence regions
//!       sharing one barrier id with zero diagnostic.
//! Post-fix: fail-closed cap at 16 recorded in bar_hit_cap; lower_kernel
//! bails Err with kernel + ordinal context (mirrors pred_hit_cap /
//! gpr_hit_cap). No free-list exists (regions are never recycled), so
//! exhaustion is a hard error, not a silent alias.
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

/// Kernel with N generic f16x2 atomicAdd lanes. Each lane allocates TWO
/// reconvergence barrier ids (outer BSSY + ATOMS.CAST.SPIN inner BSSY).
/// N lanes => 2N ids from the lifter-owned B0.. pool (no reuse).
fn build_n_f16x2_lanes(n: usize) -> String {
    let mut body = String::new();
    body.push_str("    ld.param.u64 %rd1, [k_param_0];\n");
    body.push_str("    mov.b32 %r2, 0x3f803f80;\n");
    for _ in 0..n {
        body.push_str("    atom.add.noftz.f16x2 %r3,[%rd1],%r2;\n");
    }
    body.push_str("    ret;");
    format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .b32 %r<8>;
    .reg .b64 %rd<4>;
{}
}}"#, PROLOG, body)
}

fn lower_result(ptx: &str) -> Result<String, anyhow::Error> {
    let kernels = parse_ptx(ptx).unwrap();
    lower_kernel(&kernels[0]).map(|l| l.to_sass_text())
}

/// t130_1: 9 f16x2 lanes = 18 barrier ids -> the 17th request crosses the
/// 4-bit encoding domain. Pre-fix: lowered fine, text carried "B16"/"B17"
/// which the encoder silently masked back to B0/B1 (evidence captured in
/// the internal fix archive the BSSY words of region pair (B0,B16) differ
/// ONLY in the branch target, the barrier nibble is identical). Post-fix:
/// fail-closed Err naming the kernel, no truncation ever assembled.
#[test]
fn t130_1_pool_exhaustion_fail_closed() {
    let ptx = build_n_f16x2_lanes(9); // 18 ids, cap is 16
    let r = lower_result(&ptx);
    match &r {
        Err(e) => assert!(format!("{e:?}").contains("reconvergence barrier space exhausted"),
            "fail-closed bail expected, got: {e:?}"),
        Ok(t) => panic!("over-cap kernel must not lower (silent B16->B0 alias corner):\n{}",
            &t[..t.len().min(400)]),
    }
}

/// t130_2: the u8 overflow corner — 128 lanes = 256 allocation requests.
/// Pre-fix the 256th bump of the raw u8 `bar_next` panicked in debug builds
/// / wrapped to B0 in release, long after ids had already started aliasing
/// at 16. Post-fix the cap at 16 makes u8 overflow unreachable: same
/// graceful Err, no panic in either profile.
#[test]
fn t130_2_u8_overflow_corner_no_panic() {
    let ptx = build_n_f16x2_lanes(128);
    let r = lower_result(&ptx);
    match &r {
        Err(e) => assert!(format!("{e:?}").contains("reconvergence barrier space exhausted"),
            "fail-closed bail expected, got: {e:?}"),
        Ok(t) => panic!("255-corner kernel must not lower (wrap corner):\n{}",
            &t[..t.len().min(400)]),
    }
}

/// t130_3 (invariant): 8 f16x2 lanes = exactly 16 ids = full legal pool.
/// Must still lower, and the emitted ids must cover B0..B15 with every BSSY
/// paired to its BSYNC by id (the b9p17 pairing law at pool scale).
#[test]
fn t130_3_exact_fit_full_pool_still_lowers() {
    let ptx = build_n_f16x2_lanes(8);
    let t = lower_result(&ptx).expect("exact-fit pool (16 ids) must lower");
    assert!(t.contains("BSSY.RECONVERGENT B15,"), "id 15 reachable: {}", t);
    assert!(!t.contains(" B16"), "no id past B15: {}", t);
    assert_eq!(t.matches("BSSY.RECONVERGENT B").count(), 16, "{}", t);
    assert_eq!(t.matches("BSYNC.RECONVERGENT B").count(), 16, "{}", t);
    let (bytes, n) = assemble_body(&t);
    assert_eq!(bytes.len(), n * 16, "{}", t);
}

/// t130_4: both bar-alloc lanes share ONE pool — 8 f16x2 lanes (16 ids)
/// plus a single f16 CAS lane (1 more id) trips the same cap with the same
/// message. Spelling of the f16 stimulus mirrors the vendor-anchored
/// b9p17_atom_f16_cas_loop lane.
#[test]
fn t130_4_lanes_share_one_pool() {
    let mut body = String::new();
    body.push_str("    ld.param.u64 %rd1, [k_param_0];\n");
    body.push_str("    mov.b32 %r2, 0x3f803f80;\n");
    for _ in 0..8 {
        body.push_str("    atom.add.noftz.f16x2 %r3,[%rd1],%r2;\n");
    }
    body.push_str("    mov.b32 %f1, 0x3f800000;\n");  // BUG-118 gate: producer for cvt
    body.push_str("    cvt.rn.f16.f32 %rs1, %f1;\n");
    body.push_str("    atom.add.noftz.f16 %rs2,[%rd1],%rs1;\n");
    body.push_str("    ret;");
    let ptx = format!(r#"{} .visible .entry k(
    .param .u64 k_param_0
)
{{
    .reg .pred %p<2>;
    .reg .b16 %rs<4>;
    .reg .f32 %f<4>;
    .reg .b32 %r<8>;
    .reg .b64 %rd<4>;
{}
}}"#, PROLOG, body);
    let r = lower_result(&ptx);
    match &r {
        Err(e) => assert!(format!("{e:?}").contains("reconvergence barrier space exhausted"),
            "fail-closed bail expected, got: {e:?}"),
        Ok(t) => panic!("17th barrier id from the second lane must bail:\n{}",
            &t[..t.len().min(400)]),
    }
}
