//! BUG-307 (F2-iter164, loop5/blind front2, 2026-08-31): sm121a BF16_V2
//! discriminant closure on HMUL2_R_R_UR / HFMA2_R_R_UR_R (both bit85,
//! donor-equal).
//!
//! Law (arb307/307c/307d/307e/307f: nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/103a/120/121a agree on EVERY probe):
//!   BOTH keys:  b85 = single-bit '.BF16_V2' discriminant (arb307e singles+
//!               pairs, arb307f full (b85,b89)x(hsel@74,hsel@81) x16 matrix:
//!               b89 fully INERT, b85 = THE discriminant; donors pin b85
//!               identically since harvest).
//!   HMUL2_R_R_UR:  orthogonal tok3(UR) hsel[61:60] (0='' 1='.INVALID1'
//!                  2/3=H0_H0/H1_H1; abs@62/neg@63 compose) and tok2(R)
//!                  hsel[75:74]+neg@72; b86 TEXT-INERT under both mg
//!                  (arb271-D + arb307d); reuse122/123 = vendor word-
//!                  illegal on this form (rc=1) = registration 328-kand.
//!   HFMA2_R_R_UR_R: the h0nh1 window (b86,b61,b60: 4='.H0_NH1',
//!                  b86&hs!=0='.INVALID5/6/7') is legal EQUALLY under plain
//!                  and BF16 => the '' row clone carries h0nh1@86 (arb307d).
//! Pre-fix (pub pyo3-1c01ce3): the sm121a BF16_V2 era rows carried NO
//! discriminant in and_base (0x...c32 vs donor 0x820...27c32) and the plain
//! '' mod-groups were MISSING. Encode of '.BF16_V2' text minted a word the
//! vendor reads as plain (silent mnemonic-mod drop); every plain corpus
//! word decode-misprinted as BF16_V2 (routex307: 16 HMUL2 + 35 HFMA2 words
//! on the 2,406 battery, incl. witnesses W_HML261/W_HML_RX/W_HFA_RX2/W_HMA/
//! W_HMB), and the plain text was not encodable at all (272 path).
//! Graft = canonical patch307.py (replayable+idempotent), sm121a only;
//! donors byte-untouched. Pin flips 261/264/266/270/271/273/305 carry the
//! per-site attribution.
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
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).unwrap()
}

#[test]
fn t307_1_structure() {
    let t = tab("sm121a");
    for key in ["HMUL2_R_R_UR", "HFMA2_R_R_UR_R"] {
        let b = 85u32;
        let mgs = &t.entries[key].mod_groups;
        let bf = &mgs["BF16_V2"];
        let pl = mgs
            .get("")
            .unwrap_or_else(|| panic!("{key}: '' row missing"));
        assert_eq!((u128::from(bf.and_base) >> b) & 1, 1, "{key}: BF16 pin");
        assert_eq!((u128::from(pl.and_base) >> b) & 1, 0, "{key}: '' clear");
        // discriminant must be match-owned: not vm/field covered
        assert_eq!((u128::from(bf.variable_mask) >> b) & 1, 0);
        for f in &bf.fields {
            assert!(
                f.shift > b || f.shift + f.bits <= b,
                "{key}: field covers b{b}"
            );
        }
        // '' clone = BF16 shape minus the pin (arb307d: same window laws)
        let shp = |f: &cubit::table::Field| (f.token_idx, f.bits, f.shift, f.extraction.clone());
        assert_eq!(
            bf.fields.iter().map(shp).collect::<Vec<_>>(),
            pl.fields.iter().map(shp).collect::<Vec<_>>(),
            "{key}: '' field clone"
        );
        assert_eq!(bf.variable_mask, pl.variable_mask, "{key}: '' vm clone");
    }
    // h0nh1@86 present on BOTH HFMA2 mg (arb307d: legal under plain too)
    for mg in ["", "BF16_V2"] {
        assert!(
            t.entries["HFMA2_R_R_UR_R"].mod_groups[mg]
                .fields
                .iter()
                .any(|f| f.extraction == cubit::table::Extraction::H0NH1
                    && f.shift == 86
                    && f.token_idx == 3),
            "HFMA2_R_R_UR_R[{mg}] h0nh1@86"
        );
    }
    // donors untouched: BF16 discriminant pinned there since harvest
    for leg in ["sm100a", "sm103a", "sm120"] {
        let d = tab(leg);
        for key in ["HMUL2_R_R_UR", "HFMA2_R_R_UR_R"] {
            let b = 85u32;
            let m = &d.entries[key].mod_groups;
            assert_eq!(
                (u128::from(m["BF16_V2"].and_base) >> b) & 1,
                1,
                "{leg} {key}"
            );
            assert_eq!((u128::from(m[""].and_base) >> b) & 1, 0, "{leg} {key} ''");
        }
    }
}

#[test]
fn t307_2_decode_vendor_law() {
    let t = tab("sm121a");
    // Era witnesses are vendor PLAIN (arb307c x4).
    for (w, want) in [
        (0x8000000300000080c0b7c32u128, "HMUL2 R11, R12, UR8.H1_H1"),
        (0x8000000300000080c037c32u128, "HMUL2 R3, R12, UR8.H1_H1"),
        (
            0x80408052000000602057c31u128,
            "HFMA2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0",
        ),
        (
            0x80408052000000402057c31u128,
            "HFMA2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0",
        ),
        (
            0x816080b200000080c097c31u128,
            "HFMA2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
        ),
    ] {
        assert_eq!(dec(&t, w).as_deref(), Some(want), "w={w:#x}");
    }
    // b85-set siblings of the same shapes print BF16_V2 (arb307 A x4; the
    // HFMA2 b85-set corpus words are byte-shapes from cublasLt/cusparse);
    // the two cublas words previously routed through the dotted era row now
    // land on the canonical row with vendor-exact operands.
    for (w, want) in [
        (
            0x82008002000000404037c32u128,
            "HMUL2.BF16_V2 R3, R4.H0_H0, UR4.H0_H0",
        ),
        (
            0x82008002000000902037c32u128,
            "HMUL2.BF16_V2 R3, R2.H0_H0, UR9.H0_H0",
        ),
        (
            0x8200000300000080c0b7c32u128,
            "HMUL2.BF16_V2 R11, R12, UR8.H1_H1",
        ),
        (
            0x82408052000000602057c31u128,
            "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0",
        ),
    ] {
        assert_eq!(dec(&t, w).as_deref(), Some(want), "w={w:#x}");
    }
}

#[test]
fn t307_3_encode_mints_discriminant() {
    let t = tab("sm121a");
    // Every minted word cross-reads vendor-exact (nvdisasm 13.3.73 raw -b,
    // SM103a/SM121a; arb307-family verdicts in work/bug307/).
    for (want, txt) in [
        (
            0x0000000008000000300000080c037c32u128,
            "HMUL2 R3, R12, UR8.H1_H1",
        ),
        (
            0x0000000008200000300000080c037c32u128,
            "HMUL2.BF16_V2 R3, R12, UR8.H1_H1",
        ),
        (
            0x0000000008000000600000080c037c32u128,
            "HMUL2 R3, R12, |UR8.H0_H0|",
        ),
        (
            0x0000000008200000600000080c037c32u128,
            "HMUL2.BF16_V2 R3, R12, |UR8.H0_H0|",
        ),
        (
            0x0000000008200100000000080c037c32u128,
            "HMUL2.BF16_V2 R3, -R12, UR8",
        ),
        (
            0x00000000080408052000000602057c31u128,
            "HFMA2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0",
        ),
        (
            0x00000000082408052000000602057c31u128,
            "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0",
        ),
        (
            0x00000000084408050000000602057c31u128,
            "HFMA2 R5, R2.H0_H0, UR6.H0_NH1, R5.H0_H0",
        ),
        (
            0x00000000080408051000000602057c31u128,
            "HFMA2 R5, R2.H0_H0, UR6.F32, R5.H0_H0",
        ),
    ] {
        let w = enc(&t, txt) & M96;
        assert_eq!(w, want, "{txt}");
        assert_eq!(dec(&t, w).as_deref(), Some(txt), "rt {txt}");
    }
}

#[test]
fn t307_4_fail_closed_surface() {
    let t = tab("sm121a");
    // '.INVALID1' text refused upstream (272-gate; BUG-297/306 doctrine).
    let insn = parse_sass("HMUL2 R3, R12, UR8.INVALID1;", 0).unwrap();
    assert!(encode_instruction(&insn, &t)
        .expect_err("INVALID1 closed")
        .to_string()
        .contains("unknown operand suffix"));
    // era claims: INVALID combos on the h0nh1 window = decode hole on BOTH
    // mg (arb307d: b86&hs!=0 vendor INVALID5/6/7 under plain AND BF16).
    let hfa = 0x80408052000000602057c31u128 & !(0xFu128 << 60);
    for v in 5u128..=7 {
        assert!(
            dec(&t, hfa | ((v & 3) << 60) | ((v >> 2) << 86)).is_none(),
            "plain INVALID{v}"
        );
        assert!(
            dec(&t, hfa | (1 << 85) | ((v & 3) << 60) | ((v >> 2) << 86)).is_none(),
            "bf16 INVALID{v}"
        );
    }
    // encode-side: the INVALID-combo prints refuse to mint (271-arm).
    for bad in [
        "HFMA2 R5, R2.H0_H0, UR6.H0_H0.H0_NH1, R5.H0_H0",
        "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H1_H1.H0_NH1, R5.H0_H0",
    ] {
        let insn = parse_sass(&format!("{bad};"), 0).unwrap();
        assert!(
            encode_instruction(&insn, &t).is_err(),
            "{bad}: must fail closed"
        );
    }
}
