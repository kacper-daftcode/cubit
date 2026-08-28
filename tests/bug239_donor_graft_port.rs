//! BUG-239 (F2-iter120, front2/blind, 2026-08-28): donor-table (sm100a,
//! sm103a) graft-port of the corpus-witnessed BUG-226d fields that had
//! landed sm120-only in b2e5227 (canonical 807d0e9; patch239.py
//! replayable+idempotent; donor sm100a == sm103a per affected row).
//!
//! Defect (gold239 census: 2,014-cubin ab103 battery decoded with donor
//! tables; 1,136,243 DFMA/HMUL2 lines vs local nvdisasm 13.3.73 gold
//! at-address): 1,483 omission-ghost DIFFs, zero other classes:
//! * 1,467 x DFMA.RP prints drop the tok2 neg sign (`DFMA.RP R12, R8, ..`
//!   where vendor prints `DFMA.RP R12, -R8, ..`): 1,411 R-form
//!   (DFMA_R_R_R_R["RP"]) + 56 UR-form (DFMA_R_R_R_UR["RP"]) -- donor rows
//!   lacked the neg@72 tok2 field (sm120 grafted in 226d, 630 RP + 41 hole
//!   witnesses there). RM row ported for parity (zero corpus exposure, same
//!   era shape; keeps the donor lattice identical RM/RP).
//! * 16 x HMUL2 R-form-UR prints drop the hsel suffix (`HMUL2 R15, R22,
//!   UR8` where vendor prints `HMUL2 R15, R22, UR8.H1_H1`; hsel@60 = 3):
//!   donor HMUL2_R_R_UR[""] lacked hsel2b@74 tok2 / hsel2b@60 tok3 (sm120
//!   grafted in 226d, 7 corpus witnesses there).
//!
//! Zero reuse/order ghosts: the BUG-226d printer arm (UR-domain sideband
//! skip) is global and holds on both donor streams (55,768 DFMA*UR lines
//! carry zero `URn.reuse`).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T103: &str = "tables/sm103a.json";
const T100: &str = "tables/sm100a.json";
const M96: u128 = (1u128 << 96) - 1;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new(T103)).unwrap()
}
fn t100() -> IsaTable {
    IsaTable::load(std::path::Path::new(T100)).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(w, 0, t).expect("decode");
    to_sass(&d)
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}
fn has_field(t: &IsaTable, key: &str, mg: &str, ext: &str, shift: u32, tok: i32) -> bool {
    let r = t
        .get(key, mg)
        .unwrap_or_else(|| panic!("{key}[{mg:?}] missing"));
    r.fields
        .iter()
        .any(|f| format!("{:?}", f.extraction) == ext && f.shift == shift && f.token_idx == tok)
}

#[test]
fn t239_1_structure_and_donor_parity() {
    let a = t103();
    let b = t100();
    for (key, mg, ext, shift, tok) in [
        ("DFMA_R_R_R_R", "RM", "Neg", 72, 2),
        ("DFMA_R_R_R_R", "RP", "Neg", 72, 2),
        ("DFMA_R_R_R_UR", "RP", "Neg", 72, 2),
        ("HMUL2_R_R_UR", "", "HalfSel", 74, 2),
        ("HMUL2_R_R_UR", "", "HalfSel", 60, 3),
    ] {
        assert!(
            has_field(&a, key, mg, ext, shift, tok),
            "sm103a {key}[{mg}] {ext}@{shift}"
        );
        assert!(
            has_field(&b, key, mg, ext, shift, tok),
            "sm100a {key}[{mg}] {ext}@{shift}"
        );
        let ra = a.get(key, mg).unwrap();
        let rb = b.get(key, mg).unwrap();
        assert_eq!(
            format!("{:?}", ra.fields),
            format!("{:?}", rb.fields),
            "donor parity {key}[{mg:?}]"
        );
        assert_eq!(
            ra.and_base, rb.and_base,
            "donor and_base parity {key}[{mg:?}]"
        );
    }
}

#[test]
fn t239_2_decode_anchors_donor() {
    // Corpus witness words (gold239, nvdisasm-13.3.73-verified at-address).
    for t in [t103(), t100()] {
        // DFMA.RP R-form: matinv_kernelWarp @4b80
        assert!(dec(&t, 0x8122000000141622722b).starts_with("DFMA.RP R34, -R22, R20, R34"));
        // DFMA.RP UR-form: curand qrng @3d00
        assert!(dec(&t, 0x800810a00000006080c7e2b).starts_with("DFMA.RP R12, -R8, R10, UR6"));
        // DFMA.RP R-form: rotg_complex_kernel_ref @27a0
        assert!(dec(&t, 0x811a0000000c0a1a722b).starts_with("DFMA.RP R26, -R10, R12, R26"));
        // HMUL2 hsel@60=3: cusparse binary_search_lb_offset @2a10 / @2db0
        assert!(dec(&t, 0x8000000300000080c0b7c32).starts_with("HMUL2 R11, R12, UR8.H1_H1"));
        assert!(dec(&t, 0x800000030000008160f7c32).starts_with("HMUL2 R15, R22, UR8.H1_H1"));
    }
}

#[test]
fn t239_3_encode_anchors_donor() {
    // Spelled vendor text now carries b72 / hsel@60 through encode.
    for t in [t103(), t100()] {
        assert_eq!(
            enc(&t, "DFMA.RP R34, -R22, R20, R34 ;") & M96,
            0x8122000000141622722b,
            "neg@72 tok2 on DFMA.RP R-form"
        );
        assert_eq!(
            enc(&t, "HMUL2 R15, R22, UR8.H1_H1 ;") & M96,
            0x800000030000008160f7c32,
            "hsel@60 tok3 on HMUL2_R_R_UR"
        );
        // decode(encode(x)) roundtrips on the cured forms
        for (text, body) in [
            (
                "DFMA.RP R34, -R22, R20, R34 ;",
                "DFMA.RP R34, -R22, R20, R34",
            ),
            ("DFMA.RP R12, -R8, R10, UR6 ;", "DFMA.RP R12, -R8, R10, UR6"),
            (
                "DFMA.RM R34, -R22, R20, R34 ;",
                "DFMA.RM R34, -R22, R20, R34",
            ),
            ("HMUL2 R15, R22, UR8.H1_H1 ;", "HMUL2 R15, R22, UR8.H1_H1"),
        ] {
            let w = enc(&t, text);
            assert!(
                dec(&t, w & M96).starts_with(body),
                "roundtrip {text}: got {}",
                dec(&t, w & M96)
            );
        }
    }
}

#[test]
fn t239_4_no_reuse_ghost_and_plain_forms() {
    // The omission fix must not resurrect the reuse ghost class: words with
    // b123/b124 set on UR-form rows print vendor-plain (arm226d global).
    let t = t103();
    // DFMA_R_R_UR_R word with b124 set prints Rc.reuse (legal, sideband slot64
    // = R window) and never UR.reuse; decode of a b123 UR-window word must
    // not stamp `.reuse` onto the UR token.
    let d = dec(&t, 0x8122000000141622722b);
    assert!(
        !d.contains("UR") || !d.contains("UR.reuse"),
        "ghost class guard: {d}"
    );
    // Plain non-neg DFMA.RP encodes with b72 clear and roundtrips verbatim.
    let w = enc(&t, "DFMA.RP R34, R22, R20, R34 ;") & M96;
    assert_eq!((w >> 72) & 1, 0, "b72 clear without neg");
    assert!(dec(&t, w).starts_with("DFMA.RP R34, R22, R20, R34"));
}
