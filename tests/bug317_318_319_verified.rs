//! BUG-317/318/319 VERIFIED-CLOSED (F2-iter166, loop5/blind front2,
//! 2026-08-31): regression pins for three LOW registrations closed as
//! side-effects of earlier grafts; no table change in this iteration.
//!
//!  - 317 (closed via BUG-288 bf16-constant closure, canonical c359172):
//!    HFMA2.BF16_V2 (b85) tok4 payload prints BF16 semantics '1' (vendor),
//!    not the fp16-era '1.875'. Witness arb286 A_32.
//!  - 318 (closed via BUG-286 sm121a FI_FI repair 16210e9 + BUG-312 tok2
//!    basis repair ed4c840/88697c2): era row no longer double-prints
//!    tok2's neg@72/abs@73 as a ghost '-RZ' on tok3. Witnesses arb286
//!    B_02/B_03/B_15. Residual on sparse legs (no hsel@74 print/mint on
//!    sm100a/sm103a FI_FI) is BUG-329-tracked and fail-closed, not the
//!    318 ghost.
//!  - 319 (closed via BUG-312 tok2 basis shift 64->24): FI_FI real-reg
//!    tok2 decodes/mints at [31:24] (vendor law), not the latent era
//!    reg@64 window. Witnesses arb286 F_r5r7 / F_r5r7neg.
//!
//! VERBATIM SOURCE (pub pyo3-e8426d9 + tables @ canonical 88697c2):
//! decode of every witness == vendor nvdisasm 13.3.73 -b text on the dense
//! legs (x4 for B_02/B_03/F_*), and encode of the vendor text re-mints the
//! witness byte-exact on 96 bits (fail-closed holes on the sparse legs for
//! A_32 / B_15 hsel, as registered under 329).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}

/// 317: BF16_V2 (b85) tok4 imm prints bf16 value '1', never the fp16
/// ghost '1.875'; dense legs roundtrip byte-exact; sparse legs are a
/// fail-closed hole both directions (BUG-329-class, not 317).
#[test]
fn t317_bf16_tok4_print_semantics() {
    const W: u128 = 0x2000ff3f800000ff000431;
    const V: &str = "@P0 HFMA2.BF16_V2 R0, RZ, RZ, 1, 0";
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let got = dec(&t, W).expect("dense legs decode A_32");
        assert_eq!(got, V, "{arch} 317 vendor-exact");
        assert!(!got.contains("1.875"), "{arch} 317 no fp16 ghost imm");
        let mint = enc(&t, V).unwrap_or_else(|e| panic!("{arch} encode: {e}"));
        assert_eq!(mint & M96, W & M96, "{arch} 317 encode byte-exact");
    }
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        assert!(dec(&t, W).is_none(), "{arch} 317 sparse decode hole (loud)");
        assert!(enc(&t, V).is_err(), "{arch} 317 sparse encode hole (loud)");
    }
}

/// 318: tok2 neg/abs witness words print exactly once on tok2, and tok3
/// stays a plain 'RZ' -- the era-row ghost duplicate '-RZ' on tok3 is gone
/// (BUG-286 + BUG-312). Byte-exact re-encode on all four legs.
#[test]
fn t318_tok2_sign_no_tok3_ghost() {
    let cases: [(u128, &str); 2] = [
        (0x2ff3f800000ff000431, "@P0 HFMA2 R0, |RZ|, RZ, 1.875, 0"),
        (0x3ff3f800000ff000431, "@P0 HFMA2 R0, -|RZ|, RZ, 1.875, 0"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (w, vend) in cases {
            let got = dec(&t, w).expect("all legs decode B_02/B_03");
            assert_eq!(got, vend, "{arch} 318 vendor-exact");
            // ghost-print signature pre-BUG-286/312: tok2 sign duplicated
            // on tok3 as '-RZ'
            assert!(!got.contains("-RZ, 1.875"), "{arch} no tok3 ghost '-RZ'");
            let mint = enc(&t, vend).unwrap_or_else(|e| panic!("{arch} encode: {e}"));
            assert_eq!(mint & M96, w & M96, "{arch} 318 encode byte-exact");
        }
    }
}

/// 318 residual (329-class) CLOSED by BUG-329 (iter176, canonical
/// 65a6aab): B_15 hsel@74 v3 = '.H1_H1' now prints AND mints on all four
/// legs (sparse tok2 arm grafted; vendor law arb312 L5 + arb329 x4).
/// Dense references kept; sparse section = closure proof.
#[test]
fn t318_hsel_residual_sparse_failclosed() {
    const W: u128 = 0xfff3f800000ff000431;
    const V: &str = "@P0 HFMA2 R0, -|RZ|.H1_H1, RZ, 1.875, 0";
    for arch in ["sm120", "sm121a", "sm100a", "sm103a"] {
        let t = tab(arch);
        assert_eq!(dec(&t, W).expect("decode B_15"), V, "{arch}");
        let mint = enc(&t, V).unwrap_or_else(|e| panic!("{arch} encode: {e}"));
        assert_eq!(mint & M96, W & M96, "{arch} 318 B_15 encode byte-exact");
    }
}

/// 319: FI_FI tok2 real-reg lives at [31:24] (BUG-312); vendor texts
/// decode + re-encode byte-exact on all four legs.
#[test]
fn t319_fifi_tok2_realreg_roundtrip() {
    let cases: [(u128, &str); 2] = [
        (0x73f800000ff050431, "@P0 HFMA2 R5, RZ, R7, 1.875, 0"),
        (0x1073f800000ff050431, "@P0 HFMA2 R5, -RZ, R7, 1.875, 0"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (w, vend) in cases {
            assert_eq!(dec(&t, w).expect("all legs decode F_r5r7*"), vend, "{arch}");
            let mint = enc(&t, vend).unwrap_or_else(|e| panic!("{arch} encode: {e}"));
            assert_eq!(mint & M96, w & M96, "{arch} 319 encode byte-exact");
        }
    }
}
