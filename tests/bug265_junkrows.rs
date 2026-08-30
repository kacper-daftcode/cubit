//! BUG-265 (F2-iter138, loop5/blind front2, 2026-08-29): junk-rows b3-line
//! closure, legs sm120+sm121a (canonical pending-commit, ride-after 9984a9e).
//! Measurement-first (work/bug265): census265 base verdicts + routex265 FULL
//! 2,406-cubin battery routing + arb265 nvdisasm 13.3.73 raw -b (x4 models
//! SM100a/103a/120/121a all agree).
//!
//! DELETED keys (routing==0 battery-wide except FMNMX-'?' = 10 all-zero
//! padding words/leg out of t2.cubin, vendor rc=1 on w=0 too):
//!   FMNMX_R_R_II_II_II_II_?    ab=0, vendor 'Illegal instruction' x4 models;
//!                              poison row (won its own base = zero word)
//!   I2I.S16.S32.SAT_P0_R_R   base vendor-decodes '@P0 I2IP.U8.S32'
//!                            (head-mismatch); shadowed by I2IP.U8.S32_R_R_R_R
//!   I2I.U16.S32.SAT_P0_R_R   same base+bit104; poison (won own base)
//!   I2IP.U8.S32_{P0,P2,P5}_R_R_R_R  phantom predicate specializations
//!                            (ab/vm identical to the '' row), shadowed
//!   HFMA2_R_R_R_R_?          ab=0x11, vendor 'Unrecognized operation' x4
//!   FRND.F16.{CEIL,FLOOR,TRUNC}_R_R  identical-quadruplet phantom variants
//!                            (arb270c: no vendor rounding discrimination);
//!                            encode was already fail-closed (BUG-132 guard)
//! DELETED mgs (vendor rc=1 x4, zero routing; BUG-270 register):
//!   HFMA2_R_R_R_FI_FI|BF16_V2 (sm121a), HFMA2_R_R_R_II_II|BF16_V2 (both)
//! RENAMED (cmp-name mislabels; arb265 B/C + base self-decode, x4 models):
//!   FSET.BF.GT.AND_R_R_R_P -> FSET.BF.F.AND_R_R_R_P (both legs): vendor
//!     base decode 'FSET.BF.F.AND'; bits 43..46 print-invariant. Pre-fix
//!     encode of 'FSET.BF.GT.AND ...' silently produced the vendor-F word
//!     (SILENT WRONG-CODE); post-fix '.F.AND' encodes vendor-correct,
//!     '.GT.AND' fails closed.
//!   sm120 HSETP2_P_P_R_UR_P mg 'GEU.AND' -> 'AND,F': cmp field [79:76],
//!     base value 0 = F (arb265 B: F=0..T=15 lattice == sm121a mg set +
//!     grammar parity). routex265: 0 anchors sm120.
//! RETYPE: I2IP.U8.S32_R_R_R_R '' era 'neg' 2b@72 tok4 -> opmod:H1 1b@72
//!   (arb265 A: v1='.H1' on tok4 vendor-exact; v2/v3 vendor-undefined
//!   '.???2'/'.???3' => bit73 payload-gap = 275-kand; generic sign overlay
//!   prints '|R0|' on tok2 for v2, corpus-zero, cosmetic note).
//! KEEP (measurement flip vs the 266 queue note): HADD2_R_R_II_II_II_II_?
//!   is the ONLY mask covering 112 vendor-decodable words ('HFMA2 4R+reuse'
//!   variant, fixed bits {0,4,5,43,50,75} outside every proper HFMA2 row);
//!   removal converts vendor-decodable words into decode holes => kept;
//!   content repair = new-row synthesis, 278-kand (owner scope).
//! DONORS sm100a/sm103a BYTE-UNTOUCHED (asserted in patch265.py).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}
fn and_base(t: &IsaTable, key: &str, mg: &str) -> u128 {
    let g = t.entries[key].mod_groups.get(mg).expect("mg");
    u128::from(g.and_base)
}

const W_I2IP_V0: u128 = 0x7239;
#[test]
fn t265_1_structure_deletions_and_renames() {
    let del_keys = [
        "FMNMX_R_R_II_II_II_II_?",
        "I2I.S16.S32.SAT_P0_R_R",
        "I2I.U16.S32.SAT_P0_R_R",
        "I2IP.U8.S32_P0_R_R_R_R",
        "I2IP.U8.S32_P2_R_R_R_R",
        "I2IP.U8.S32_P5_R_R_R_R",
        "HFMA2_R_R_R_R_?",
        "FRND.F16.CEIL_R_R",
        "FRND.F16.FLOOR_R_R",
        "FRND.F16.TRUNC_R_R",
        "FSET.BF.GT.AND_R_R_R_P",
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for k in del_keys {
            assert!(!t.entries.contains_key(k), "{leg}: {k} survived deletion");
        }
        assert!(
            t.entries.contains_key("FSET.BF.F.AND_R_R_R_P"),
            "{leg}: FSET.BF.F rename missing"
        );
        assert!(
            t.entries.contains_key("FRND.F16_R_R"),
            "{leg}: plain FRND.F16 lost"
        );
        // junk mgs deleted, authentic '' mg kept
        assert!(
            !t.entries["HFMA2_R_R_R_II_II"]
                .mod_groups
                .contains_key("BF16_V2"),
            "{leg}: HFMA2_R_R_R_II_II BF16_V2 junk mg survived"
        );
        assert!(t.entries["HFMA2_R_R_R_II_II"].mod_groups.contains_key(""));
        // retype: era neg 2b@72 gone, opmod:H1 1b@72 present
        let g = &t.entries["I2IP.U8.S32_R_R_R_R"].mod_groups[""];
        assert!(
            !g.fields
                .iter()
                .any(|f| f.token_idx == 4 && f.shift == 72 && f.extraction == Extraction::Neg),
            "{leg}: I2IP era neg@72 survived"
        );
        assert!(
            g.fields.iter().any(|f| f.token_idx == 4
                && f.shift == 72
                && f.bits == 1
                && f.extraction == Extraction::OpModFlag("H1".into())),
            "{leg}: I2IP opmod:H1 missing"
        );
        // and_base/variable_mask of the retyped row unchanged
        let ab: u128 = g.and_base.into();
        let vm: u128 = g.variable_mask.into();
        assert_eq!(ab, 0x7239, "{leg}: I2IP '' and_base drift");
        // BUG-276 flip: (80,81) armed into the vmask (vendor text-inert,
        // arb276 D x4 models; decode-hole reclaim of vendor-legal words)
        // BUG-282 flip: (62,63) Rb-sign-slot armed text-inert too (arb282 E2
        // x4 models; ghost '-Rb'/'|Rb|' of the generic is_alu post-pass was
        // vendor-WRONG; paired with the decoder.rs is_alu/prio-3 I2IP arms)
        // BUG-275 flip: b73 vendor-undefined '.???n' payload-gap CLOSED by
        // vmask narrowing (arb275 116 probes x4 models: [73:72] enum
        // ''/.H1/.???2/.???3 on tok4; v2/v3 get NO row = decode hole, 125/274/
        // 276/282 doctrine). Prio-3 re-absorption already fail-closed (282).
        // BUG-284 flip: payload window [95:82] \ b91 armed text-inert
        // (arb284 560 probes x4 models: every bit/sub-window/composition
        // prints the base text rc=0; b91 = vendor kill-bit rc=1 x4, stays
        // care = hole preserved). 276 (80,81) / 282 (62,63) doctrine.
        assert_eq!(
            vm,
            0x1c000000000301ffc00000fffffff000u128 | (0x3DFFu128 << 82),
            "{leg}: I2IP '' vmask drift"
        );
    }
    // sm121a-only junk mg
    let t121 = tab("sm121a");
    assert!(
        !t121.entries["HFMA2_R_R_R_FI_FI"]
            .mod_groups
            .contains_key("BF16_V2"),
        "sm121a: HFMA2_R_R_R_FI_FI BF16_V2 junk mg survived"
    );
    assert!(t121.entries["HFMA2_R_R_R_FI_FI"]
        .mod_groups
        .contains_key(""));
    // sm120 mg rename + sm121a parity name
    let t120 = tab("sm120");
    let mgs = &t120.entries["HSETP2_P_P_R_UR_P"].mod_groups;
    assert!(
        mgs.contains_key("AND,F") && !mgs.contains_key("GEU.AND"),
        "sm120 mg rename missing"
    );
    assert!(t121.entries["HSETP2_P_P_R_UR_P"]
        .mod_groups
        .contains_key("AND,F"));
    // donor sentinels: junk rows STILL present on donors (owner scope, untouched)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            !t.entries.contains_key("FMNMX_R_R_II_II_II_II_?"),
            "{leg}: donor drift"
        );
        assert!(
            !t.entries.contains_key("I2I.S16.S32.SAT_P0_R_R"),
            "{leg}: donor drift"
        );
        assert!(
            !t.entries.contains_key("FSET.BF.GT.AND_R_R_R_P"),
            "{leg}: donor drift"
        );
        assert!(
            !t.entries.contains_key("FSET.BF.F.AND_R_R_R_P"),
            "{leg}: donor rename leak"
        );
    }
    // post-265 2-bit 'neg' census = ZERO on graft legs (261 registry closure)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let n = t
            .entries
            .values()
            .flat_map(|e| e.mod_groups.values())
            .flat_map(|g| g.fields.iter())
            .filter(|f| f.extraction == Extraction::Neg && f.bits == 2)
            .count();
        assert_eq!(
            n, 0,
            "{leg}: 2b-neg residuum post-265 (261 registry closed)"
        );
    }
}

#[test]
fn t265_2_poison_rows_closed_and_hole_parity() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // zero word: pre-265 decoded as FMNMX junk; now a vendor-conform hole
        assert!(dec(&t, 0).is_none(), "{leg}: zero word still decodes");
        // I2I.S16 poison base routes to the authentic I2IP row
        assert_eq!(
            dec(&t, 0x239 & M96).as_deref(),
            Some("@P0 I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: 0x239 base misrouted"
        );
        // BUG-276 flip (the 276-kand reclaim promised below pre-276): the
        // vendor-legal (80,81)-set words decode via the widened I2IP '' row
        // (arb276b B1 x4 models: '@P0 I2IP.U8.S32 R0, R0, R0, R0').
        assert_eq!(
            dec(&t, (0x239u128 | (3 << 80)) & M96).as_deref(),
            Some("@P0 I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: 276 (80,81) reclaim missing"
        );
    }
}

#[test]
fn t265_3_rename_witness_laws_vendor_equal() {
    // arb265 B: sm120 cmp-F base + hsel=2@74 prints '.F.AND' (x4 models)
    let t = tab("sm120");
    let h0 = and_base(&t, "HSETP2_P_P_R_UR_P", "AND,F");
    assert_eq!(
        dec(&t, (h0 | (2 << 74)) & M96).as_deref(),
        Some("@P0 HSETP2.F.AND P0, P0, R0.H0_H0, UR0, P0")
    );
    // arb265 C + base decode: FSET.BF base prints '.F.AND' both legs
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let f = and_base(&t, "FSET.BF.F.AND_R_R_R_P", "");
        assert_eq!(
            dec(&t, f & M96).as_deref(),
            Some("@P0 FSET.BF.F.AND R0, R0, R0, P0"),
            "{leg}"
        );
        assert_eq!(
            dec(&t, (f | (1 << 72)) & M96).as_deref(),
            Some("@P0 FSET.BF.F.AND R0, -R0, R0, P0"),
            "{leg}: neg@72 tok1 law drift"
        );
        assert_eq!(
            dec(&t, (f | (1 << 63)) & M96).as_deref(),
            Some("@P0 FSET.BF.F.AND R0, R0, -R0, P0"),
            "{leg}: neg@63 tok3 law drift"
        );
    }
}

#[test]
fn t265_4_i2ip_retype_decode_encode_and_fail_closed() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, W_I2IP_V0 & M96).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}"
        );
        assert_eq!(
            dec(&t, (W_I2IP_V0 | (1 << 72)) & M96).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0.H1"),
            "{leg}: arb265 A v1 law"
        );
        // encode: '.H1' text now sets bit 72 (pre-fix: silently dropped)
        let w0 = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2").expect("plain encode");
        let w1 = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.H1").expect("h1 encode");
        assert_ne!(w0, w1, "{leg}: .H1 still silently dropped");
        assert_eq!(
            (w1 ^ w0) & M96,
            1u128 << 72,
            "{leg}: .H1 sets exactly bit 72"
        );
        assert_eq!(
            dec(&t, w1 & M96).as_deref(),
            Some("I2IP.U8.S32 R5, R4, R3, R2.H1")
        );
        // fail-closed: phantom variants and the retired wrong name
        assert!(
            enc_res(&t, "FRND.F16.CEIL R0, R0").is_err(),
            "{leg}: FRND.F16.CEIL still encodes"
        );
        assert!(
            enc_res(&t, "FRND.F16.FLOOR R0, R0").is_err(),
            "{leg}: FRND.F16.FLOOR still encodes"
        );
        assert!(
            enc_res(&t, "FSET.BF.GT.AND R0, R0, R0, P0").is_err(),
            "{leg}: retired GT.AND encodes"
        );
    }
    // rename makes the vendor spelling encodable; word == pre-fix silent word
    let f120 = enc_res(&tab("sm120"), "FSET.BF.F.AND R0, R0, R0, P0").expect("F enc sm120");
    let f121 = enc_res(&tab("sm121a"), "FSET.BF.F.AND R0, R0, R0, P0").expect("F enc sm121a");
    assert_eq!(f120 & M96, f121 & M96, "legs diverge on FSET.BF.F.AND word");
    assert_eq!(
        f120 & M96,
        0x720a,
        "FSET.BF.F.AND word != pre-fix silent-GT word"
    );
    // sm120: HSETP2.F.AND text encodable post-rename (pre-fix: no entry)
    let h = enc_res(&tab("sm120"), "HSETP2.F.AND P0, P0, R0, UR0, P0").expect("sm120 F enc");
    assert_eq!(h & M96, 0x80000000000000000007e34u128, "sm120 F word drift");
    // sm121a lattice reference: GEU variant still encodable there (16 mgs)
    assert!(enc_res(&tab("sm121a"), "HSETP2.GEU.AND P0, P0, R0, UR0, P0").is_ok());
    // sm120 has no cmp-GEU R_UR_P mg -> fail closed (was: fail too, latent mislabel)
    assert!(enc_res(&tab("sm120"), "HSETP2.GEU.AND P0, P0, R0, UR0, P0").is_err());
}

#[test]
fn t265_5_keepers_and_registrations() {
    // 278-kand: HADD2-'?' bucket kept (112 vendor-decodable 'HFMA2 4R+reuse'
    // words; removal => holes). Witness still decodes, never a hole.
    let w2: u128 = 0x0000000000ff13007231u128 | (0x40fe400000000000u128 << 64);
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert!(
            t.entries.contains_key("HADD2_R_R_II_II_II_II_?"),
            "{leg}: keeper row removed"
        );
        assert!(
            dec(&t, w2 & M96).is_some(),
            "{leg}: 278 witness became a hole"
        );
    }
    // 276-kand CLOSED (F2-iter140): the registered head-drift rows were
    // deleted (routex276 FULL battery routing 0; census276/arb276 x4 models).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for k in [
            "I2I.U16.S32.SAT_P_R_R",
            "I2IP.U8.S32_P_R_R_R_R",
            "I2IP.S8.S32_P_R_R_R_R",
            "I2IP.U16.S32_P_R_R_R_R",
            "I2IP.U8.S32.SAT_P_R_R_R_R",
            "I2IP.U8.S32.SATRELU_P_R_R_R_R",
        ] {
            assert!(
                !t.entries.contains_key(k),
                "{leg}: 276-closed row {k} resurrected"
            );
        }
    }
    // 274-kand sentinel: HFMA2_R_R_R_II_FI bits 76..79 stay unextracted
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let g = &t.entries["HFMA2_R_R_R_II_FI"].mod_groups[""];
        assert!(
            !g.fields.iter().any(|f| f.shift >= 76 && f.shift <= 79),
            "{leg}: 274 payload-gap silently armed"
        );
        // operand law @72 from BUG-270 untouched by 265
        assert!(g.fields.iter().any(|f| f.token_idx == 2
            && f.shift == 72
            && f.bits == 1
            && f.extraction == Extraction::Neg));
    }
    // 261-era anchors stay green (chain discipline): FFMA & HADD2 FI witnesses
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, 0xfc60000000900bf80bf80ff0b2430u128 & M96).as_deref(),
        Some("@P2 HADD2 R11, -RZ.H0_H0, -1.875, -1.875")
    );
}
