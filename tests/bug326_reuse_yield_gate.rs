//! BUG-326 (F2-iter174, loop5/blind front2, 2026-09-01): DECODE print of
//! `.reuse` is gated by the control-word YIELD bit (global bit 109 =
//! upper32 bit 13 = packed sched bit 4). Vendor print law measured
//! (arb325: nvdisasm 13.3.73 raw -b, 264 probes x4 models SM120/121a/100a/
//! 103a -- AGREE on every probe, zero divergent; work/bug325/
//! arb325_verdicts.json): `.reuse` prints IFF [bit 122/123/124 set on an
//! R-domain slot] AND [yield=1]. With yield=0 the reuse bits are
//! PRINT-INERT: word decodes rc=0, text is PLAIN. census325 (full
//! 2,406-cubin battery; 2,545,138 reuse-bit words): every vendor-printed
//! `.reuse` sits in a yield=1 word; ALL 1,309 yield=0 reuse-bit words
//! print PLAIN -- pre-fix cubit printed `.reuse` on 1,288 of them
//! (IMAD.WIDE.U32 family in rt98_pub/rt83_final/r055_* ...), vendor-
//! divergent. The suppressed bits keep byte authority: fidelity flows
//! surface them via `!rsd[...]` (rsd_annotation measures the drop).
//! FIX (engine, src/printer.rs reuse_print_visible): format_reg's explicit
//! reuse-field print + the raw-bit sideband are gated on yield. The
//! UR-domain formatter is NOT gated (vendor never prints UR.reuse per
//! BUG-226d; table-taught explicit UR fields keep their authored spelling
//! per tests/bug144 t144_4; zero corpus exposure either direction).
//! 325-kand CLOSED AS NEGATYW by arb325 measurement (see t326_5): the
//! registered "HFMA2 R-form vendor personality hole" does NOT exist --
//! the very same rows print `.reuse` whenever yield=1 (e.g. corpus
//! 0x0c0fe4.. word `@P0 HFMA2 R5, R3.reuse.H0_H0, R2.reuse.H0_H0, ...`,
//! 21,779/21,779 HFMA2 corpus prints yield=1). The encode-side mint
//! (bits carried in the word independent of the control trivially) is
//! t291-pinned byte authority and stays.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

const B109: u128 = 1 << 109;
/// IMAD.WIDE.U32.X corpus anchor (r055_raw_355c98a9.cubin .text.KernelA
/// @4256): reuse rb=1 (b122 tok3 R30), yield=0 -- vendor prints PLAIN.
const W_WIDE_Y0: u128 = 0x040fc80002080442000000781e427225;
/// HFMA2 corpus anchor (libcublas.so.375 sm_100, batch_gemm @17280):
/// rb=3 (b122 tok2 + b123 tok3), yield=1 -- vendor prints .reuse x2.
const W_HFMA2_Y1: u128 = 0x0c0fe400000408052000000203050231;

#[test]
fn t326_1_yield_gated_decode_law_x4_legs() {
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        // yield=0: vendor-exact PLAIN (pre-fix printed `.reuse` here)
        let d0 = dec(&t, W_WIDE_Y0).expect("decode wide y0");
        assert_eq!(
            d0, "IMAD.WIDE.U32.X R66, P4, R30, R120, R66, P4",
            "{leg}: yield=0 reuse word must print plain (vendor law)"
        );
        // same word with yield=1: .reuse lands on tok3 (R30)
        let d1 = dec(&t, W_WIDE_Y0 | B109).expect("decode wide y1");
        assert_eq!(
            d1, "IMAD.WIDE.U32.X R66, P4, R30.reuse, R120, R66, P4",
            "{leg}: yield=1 must re-enable the print"
        );
        // corpus y1 anchor unchanged on both reuse tokens
        let d2 = dec(&t, W_HFMA2_Y1).expect("decode hfma2 y1");
        assert_eq!(
            d2, "@P0 HFMA2 R5, R3.reuse.H0_H0, R2.reuse.H0_H0, R5.H0_H0",
            "{leg}: y1 corpus print regressed"
        );
    }
}

#[test]
fn t326_2_rsd_overlay_restores_suppressed_bits() {
    // byte-authority backstop: plain text loses b122 on re-encode, and the
    // explicit !rsd overlay (what rsd_annotation emits in fidelity flows)
    // restores the payload bits. (The control window [121:105] is owned by
    // the printed control prefix in fidelity flows, not by !rsd, so the
    // bare-text encode here carries the default stall -- mask it.)
    let sched: u128 = 0x1ffff << 105;
    let payload = |w: u128| w & !sched;
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        let plain = dec(&t, W_WIDE_Y0).expect("decode wide y0");
        let w_plain = enc(&t, &plain);
        assert_eq!(
            payload(w_plain | (1 << 122)),
            payload(W_WIDE_Y0),
            "{leg}: plain-text re-encode must differ ONLY in b122 (mod sched)"
        );
        let w_rsd = enc(
            &t,
            "IMAD.WIDE.U32.X R66, P4, R30, R120, R66, P4 !rsd[122:1]",
        );
        assert_eq!((w_rsd >> 122) & 1, 1, "{leg}: !rsd must set b122");
        assert_eq!(
            payload(w_rsd),
            payload(W_WIDE_Y0),
            "{leg}: !rsd[122:1] overlay must restore the original payload"
        );
    }
}

#[test]
fn t326_3_full_rb_matrix_yield_gate() {
    let t = tab("sm120");
    let base = W_WIDE_Y0 & !(7u128 << 122);
    for rb in 1u128..8 {
        let w0 = base | (rb << 122);
        let d0 = dec(&t, w0).expect("decode rb");
        assert!(
            !d0.contains(".reuse"),
            "yield=0 rb={rb:03b}: no .reuse may print (vendor plain law): {d0}"
        );
        let d1 = dec(&t, w0 | B109).expect("decode rb y1");
        let want: Vec<&str> = [
            (rb & 1 != 0).then_some("R30.reuse"),
            (rb & 2 != 0).then_some("R120.reuse"),
            (rb & 4 != 0).then_some("R66.reuse"), // slot@64 maps to tok5 here
        ]
        .into_iter()
        .flatten()
        .collect();
        for tok in &want {
            assert!(
                d1.contains(tok),
                "yield=1 rb={rb:03b}: missing {tok} in {d1}"
            );
        }
        assert_eq!(
            d1.matches(".reuse").count(),
            want.len(),
            "yield=1 rb={rb:03b}: unexpected reuse print count in {d1}"
        );
    }
}

#[test]
fn t326_4_keep_lanes_y1_byte_anchors() {
    // pre-existing y1 decode anchors must stay byte-exact (t291-era pins
    // re-anchored under the law: they carry yield=1 already)
    let t = tab("sm120");
    assert_eq!(
        dec(&t, 0x040fe2000780a009000000ff0c087212),
        Some("LOP3.LUT P0, R8, R12.reuse, RZ, R9, 0xa0, !PT".into())
    );
    assert_eq!(
        dec(&t, 0x140fe200000102070000000406197819),
        Some("SHF.L.U64.HI R25, R6.reuse, 0x4, R7.reuse".into())
    );
}

#[test]
fn t326_5_encode_mint_unchanged_325_negatyw() {
    // 325-kand NEGATYW pins: (a) the authored mint bytes are unchanged on
    // every leg (t291 keep-law); (b) the SAME rows are vendor-print-real
    // once yield=1 -- no row personality hole exists.
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        let base = enc(&t, "HFMA2 R1, R2, R3, R4");
        assert_eq!(base, 0x000fc200000000040000000302017231, "{leg} base");
        assert_eq!(
            enc(&t, "HFMA2 R1, R2.reuse, R3, R4"),
            base | (1 << 122),
            "{leg} tok2 mint unchanged"
        );
        assert_eq!(
            enc(&t, "HFMA2 R1, R2, R3.reuse, R4"),
            base | (1 << 123),
            "{leg} tok3 mint unchanged"
        );
        assert_eq!(
            enc(&t, "HFMA2 R1, R2, R3, R4.reuse"),
            base | (1 << 124),
            "{leg} tok4 mint unchanged"
        );
        // the minted word with yield=1 decodes text-exact (vendor parity):
        let d = dec(&t, base | (1 << 122) | B109).expect("decode hfma2 y1");
        assert_eq!(d, "HFMA2 R1, R2.reuse, R3, R4", "{leg}: y1 print law");
    }
}

#[test]
fn t326_6_ur_domain_not_gated_bug144_pin_stays() {
    // UR-domain explicit-field print keeps the authored spelling (t144_4
    // hosts this): base+124 has yield=0 and STILL prints UR7.reuse. Vendor
    // never prints UR.reuse in any legal word; this table-taught lane is
    // authored-spelling-only, zero corpus exposure (census325).
    let t = tab("sm120");
    let base = enc(&t, "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7");
    assert_eq!((base >> 109) & 1, 0, "default control must be yield=0");
    let d = dec(&t, base | (1u128 << 124)).expect("decode ur reuse");
    assert!(d.contains("UR7.reuse"), "UR print lane not gated: {d}");
}
