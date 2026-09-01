//! BUG-313 render-parity batch (F2-iter167, loop5/blind front=main,
//! 2026-08-31): four era-era render classes closed, all proven by
//! arbitraz arb313 (nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/
//! SM120/SM121a agree on every probe) + canonical table graft patch313.py
//! (95e190b + 720d240) + one printer arm (P2R "PR" literal, mirror of R2P).
//!
//! (A) 313A sm121a HADD2_R_R_R mnemod routes: plain mg '' over-claimed
//!     (vm covered b85+b78) -> silent '.BF16_V2'/'.F32' drop on decode
//!     (witnesses from verify306 v2: G2/G4/G5 families, 14 probes).
//!     Law: b85 = BF16_V2, b78 = F32, (b85,b78)=(1,1) vendor-ILLEGAL.
//! (B) 313C sm100a/sm103a HSETP2_P_P_R_(R|UR)_P: second-pred window was
//!     read as 4b@87 DUP of tok5 (engine 'P0,' vs vendor ' PT,');
//!     law: tok2 pred = 3b@84, tok5 = 3b@87 + inv@90.
//! (C) 309 sm121a SHFL.BFLY era/junk rows: dest field off-by-one 8b@17
//!     (leaked tok3 bit24; encode minted 'R12' read back 'R140', vendor
//!     'R24'); law = donor geometry dest 8b@[23:16], pred 3b@[83:81],
//!     tok3@24 / tok4@32 / tok5@64 on BOTH claim surfaces (b82=0 era key
//!     + b82=1 SHFL_P_R_R_R_R['BFLY'] -- junk fields repaired render-only,
//!     claim surface unchanged).
//! (D) 310 P2R: era phantom P2R_R_R_R_II on sm121a dup-rendered tok2
//!     ('R6,R12,R12,0x0'); vendor prints the literal 'PR' for the baked
//!     imm slot on 6 probed imm values x4 models -- key deleted
//!     (mint-neutral), printer arm prints "PR" on the II_R_II rows.
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

#[test]
fn t313_1_shfl_bfly_sm121a_donor_geometry() {
    let t121 = tab("sm121a");
    // Legacy era-mint word (dest written at @17 pre-fix): vendor reads the
    // [23:16] window -> 'R24'; post-fix engine prints the same (was 'R140').
    let legacy: u128 = 0x00000b0c00000a15187389;
    assert_eq!(
        dec(&t121, legacy).as_deref(),
        Some("SHFL.BFLY P0, R24, R21, R10, R11"),
        "309: legacy @17 word now reads vendor-exact"
    );
    // Canonical (vendor) word decodes and round-trips.
    let good: u128 = 0x00000b0c00000a150c7389;
    assert_eq!(
        dec(&t121, good).as_deref(),
        Some("SHFL.BFLY P0, R12, R21, R10, R11")
    );
    // Encode mints the canonical word (byte-pin == donor sm120/sm103a mint),
    // pred coverage incl. PT (3 bits @81, junk-BFLY claim surface b82=1).
    for (text, pred_bits) in [
        ("SHFL.BFLY P0, R12, R21, R10, R11", 0u128),
        ("SHFL.BFLY P6, R1, R2, R3, R4", 6u128),
        ("SHFL.BFLY PT, R12, R21, R10, R11", 7u128),
    ] {
        let w = enc(&t121, text).unwrap();
        assert_eq!((w >> 81) & 0x7, pred_bits, "pred window @81");
        assert_eq!(dec(&t121, w).as_deref(), Some(text), "121a roundtrip");
    }
    let w = enc(&t121, "SHFL.BFLY P0, R12, R21, R10, R11").unwrap();
    assert_eq!(
        w & M96,
        0x00000b0c00000a150c7389,
        "309 mint byte-pin (donor-equal)"
    );
}

#[test]
fn t313_2_p2r_pr_literal_x3_legs() {
    for arch in ["sm100a", "sm103a", "sm121a"] {
        let t = tab(arch);
        // Witness word (303 block E): all imm values print the PR literal.
        for (imm, want_tail) in [(0x80000000u64, "0x80000000"), (0x0, "0x0"), (0x7f, "0x7f")] {
            let text = format!("P2R R6, PR, R12, {want_tail}");
            let w = enc(&t, &text).unwrap();
            assert_eq!(
                dec(&t, w).as_deref(),
                Some(text.as_str()),
                "{arch} PR roundtrip imm={imm:#x}"
            );
        }
        // Authored numeric '0x0' mints the same word as 'PR'.
        let a = enc(&t, "P2R R6, 0x0, R12, 0x0").unwrap();
        let b = enc(&t, "P2R R6, PR, R12, 0x0").unwrap();
        assert_eq!(a, b, "{arch}: '0x0' and 'PR' alias the same word");
        assert_eq!(dec(&t, a).as_deref(), Some("P2R R6, PR, R12, 0x0"));
    }
    // sm121a phantom era key is gone (dup-render closure 310-D).
    let t121 = tab("sm121a");
    assert!(
        t121.get_key("P2R_R_R_R_II").is_none(),
        "phantom key deleted"
    );
}

#[test]
fn t313_3_hadd2_mnemod_routes_sm121a() {
    let t121 = tab("sm121a");
    // Discriminant witnesses (arb313 A; verify306 v2 G2/G4 families).
    let bf16: u128 = 0x002000000000000403020230; // b85=1
    let f32w: u128 = 0x0000410090000004ff020230; // b78=1
    let plain: u128 = bf16 & !(1u128 << 85); // discriminant cleared -> plain lattice
    assert_eq!(
        dec(&t121, bf16).as_deref(),
        Some("@P0 HADD2.BF16_V2 R2, R3, R4")
    );
    assert_eq!(
        dec(&t121, f32w).as_deref(),
        Some("@P0 HADD2.F32 R2, -RZ, -R4.INVALID1")
    );
    assert_eq!(dec(&t121, plain).as_deref(), Some("@P0 HADD2 R2, R3, R4"));
    // (b85|b78) = vendor-ILLEGAL combo: the plain row must NOT claim it
    // (pre-fix it printed plain = silent mnemod drop; era label-carrier
    // claim documented, not closed here).
    let combo = bf16 | (1u128 << 78);
    assert_ne!(dec(&t121, combo).as_deref(), Some("@P0 HADD2 R2, R3, R4"));
    // Encode: mints carry the discriminant bits, roundtrip == vendor text.
    let w = enc(&t121, "HADD2.BF16_V2 R1, R2, R3").unwrap();
    assert_eq!((w >> 85) & 1, 1);
    assert_eq!((w >> 78) & 1, 0);
    assert_eq!(dec(&t121, w).as_deref(), Some("HADD2.BF16_V2 R1, R2, R3"));
    let w = enc(&t121, "@P0 HADD2.BF16_V2 R2, R3, R4").unwrap();
    assert_eq!(
        dec(&t121, w).as_deref(),
        Some("@P0 HADD2.BF16_V2 R2, R3, R4")
    );
    // '.INVALID1' authored on the F32 route stays fail-closed (272-class;
    // same doctrine as BF16).
    assert!(enc(&t121, "HADD2.F32 R2, -RZ, -R4.INVALID1").is_err());
}

#[test]
fn t313_4_hsetp2_second_pred_window_100a_103a() {
    let w0: u128 = 0x7020002000000504000234; // [86:84]=7 -> PT
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        assert_eq!(
            dec(&t, w0).as_deref(),
            Some("@P0 HSETP2.EQ.AND P0, PT, R4, R5.H0_H0, P0"),
            "{arch}: witness W0 vendor-exact (was 'P0,')"
        );
        assert_eq!(
            dec(&t, w0 ^ (1u128 << 84)).as_deref(),
            Some("@P0 HSETP2.EQ.AND P0, P6, R4, R5.H0_H0, P0"),
            "{arch}: tok2 = 3b@84 (b84 flips PT->P6)"
        );
        assert_eq!(
            dec(&t, w0 | (1u128 << 90)).as_deref(),
            Some("@P0 HSETP2.EQ.AND P0, PT, R4, R5.H0_H0, !P0"),
            "{arch}: tok5 = 3b@87 + inv@90"
        );
    }
}

#[test]
fn t313_5_donor_legs_untouched_and_era_holds() {
    // Donor sm120/sm103a paths that were already vendor-correct must not move.
    let t120 = tab("sm120");
    let t103 = tab("sm103a");
    let w = enc(&t120, "SHFL.BFLY P0, R12, R21, R10, R11").unwrap();
    assert_eq!(
        dec(&t120, w).as_deref(),
        Some("SHFL.BFLY P0, R12, R21, R10, R11")
    );
    let w = enc(&t103, "HADD2 R2, R3, R4").unwrap();
    assert_eq!(dec(&t103, w).as_deref(), Some("HADD2 R2, R3, R4"));
}
