//! mk73: closing the 01290004 residuals (keep-400 oo 92->0): (a) .reuse on
//! operands (trsv/sphpr/sphpmv — nvdis l2 drops the suffix, frozen-sass
//! prints it; the simplified R<num> parse rejected them), (b) the full guard code b4 =
//! merc_guard_code (pred<<3|uni<<1|neg; none/@P7 -> 0xf8) instead of the tri-state
//! 0/1/2 mapowanego w from_parts. Korpus l2 EXACT: liczniki 18932/18932,
//! payload+b4 19374/19374 (merclab/mk73 c1/c3).
use cubit::sass_file::{kernel_def_to_meta, merc_guard_code, parse_sass_file_str};

fn scan_xor(sass: &str) -> Vec<(u32, u32, u32, u32, u8)> {
    let file = parse_sass_file_str(sass).unwrap();
    let n = file.kernels[0].instructions.len();
    let meta = kernel_def_to_meta(&file.kernels[0], &vec![0u8; 16 * (n + 1)]);
    meta.merc_xor_reg
}

#[test]
fn xor_reuse_accepted() {
    // libcublas.so.315 sphpr (cubit's frozen view): dst czysty, src'e .reuse
    let x = scan_xor(
        ".entry t\n    .reg R0-R79\n    LOP3.LUT R17, R14.reuse, R21.reuse, RZ, 0x3c, !PT ;\n",
    );
    assert_eq!(x, vec![(0, 17, 14, 21, 0xf8)], "rez: {x:?}");
}

#[test]
fn xor_guard_full_code() {
    // sphpmv cublas.279: @!P4 -> b4=0x21; trsv cublas.225: @P0 -> 0x00,
    // @!P0 -> 0x01; the original records in mk73 c1 are exactly like that.
    let x = scan_xor(
        ".entry t\n    .reg R0-R79\n    @!P4 LOP3.LUT R41, R4.reuse, R31.reuse, RZ, 0x3c, !PT ;\n    @P0 LOP3.LUT R75, R75, R74, RZ, 0x3c, !PT ;\n    @!P0 LOP3.LUT R47, R47, R46, RZ, 0x3c, !PT ;\n",
    );
    assert!(x.contains(&(0, 41, 4, 31, 0x21)), "present: {x:?}");
    assert!(x.contains(&(1, 75, 75, 74, 0x00)), "present: {x:?}");
    assert!(x.contains(&(2, 47, 47, 46, 0x01)), "present: {x:?}");
}

#[test]
fn guard_code_edge() {
    use cubit::ir::Guard;
    let g = |p, n, u| Some(Guard { pred: p, negated: n, uniform: u });
    assert_eq!(merc_guard_code(None), 0xf8);
    assert_eq!(merc_guard_code(g(7, false, false).as_ref()), 0xf8); // @P7 like none
    assert_eq!(merc_guard_code(g(7, true, false).as_ref()), 0x39); // @!P7
    assert_eq!(merc_guard_code(g(2, false, true).as_ref()), 0x12); // @UP2
}
