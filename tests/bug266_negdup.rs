//! BUG-266 (F2-iter135, loop5/blind front2, 2026-08-29): era 1-bit 'neg'
//! mislabels on ctl/reuse bits 122/123/124 (canonical b205e68).
//!
//! Class: harvest type-error — bits 122/123/124 are the Ra/Rb/Rc reuse flags
//! (encoder REUSE_SLOTS doctrine; arb249b; BUG-252). arb266 (nvdisasm
//! 13.3.73 raw -b, routex266 FULL 2,406-cubin battery witnesses, x4 models
//! all agree): the vendor NEVER prints '-' from them — '.reuse' or decode-
//! ILLEGAL. Engine damage pre-fix:
//!   ghost '-' on reuse-set words (printer reads the era field):
//!     HMMA.16816.F32.BF16 / HMMA.1688.F32.TF32 tok3 (128+144 w),
//!     IDP.4A.S8.S8 tok2/tok3 sm121a (2,240+8,745 w), LEA_P0 tok2 (13 w),
//!     HFMA2 BF16_V2 tok2/tok4 (16+16 w), HADD2_'?' phantom (50 w);
//!   shadow '-' drop (era field listed AFTER the true window; printer
//!   last-assignment zeroes it): LEA_P0 tok3 x301 / tok2 x25 (true windows
//!   @63/@72), FSET.BF.GT.AND hosts, HFMA2 BF16_V2 tok4 (true neg@84),
//!   DFMA/FFMA-class rows (corpus-zero per routex266);
//!   HADD2_R_R_FI_FI tok2: era neg@73 mislabel + neg@122 dup — b72-set
//!   corpus words lose '-' (7 w; vendor '-RZ.H0_H0'), b73 ghost-neg.
//! Encode-side: bits 122-124 are authoritatively RMW'd by
//! apply_reuse_encoding / explicit Reuse fields (probes: no text-level
//! fabrication reaches the era fields; static escape-set 22 sm120 + 20
//! sm121a fields survived the shields as dead payload — now deleted).
//! Graft (patch266.py, canonical b205e68, replayable+idempotent): DELETE
//! every (neg,1b,{122,123,124}) field sm120 (409) + sm121a (403) = uniform
//! KASA (decision over reorder: the fields have no arb-able meaning);
//! HADD2 FI sibling pair graft neg@72 + abs@73 per arb261 law.
//! and_base/variable_mask unchanged; donors sm100a/sm103a byte-untouched
//! (their IMNMX neg@122 x4+4 = 268-kand, donor-scope decision).
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
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}
fn and_base(t: &IsaTable, key: &str, mg: &str) -> u128 {
    let g = t.entries[key].mod_groups.get(mg).expect("mg");
    u128::from(g.and_base)
}

// routex266 corpus witnesses (full 128-bit; the rust harness masks ctl).
const W_HMMA16816: u128 = 0x80fea0000041820000000564420723c; // ghost tok3
const W_HMMA1688: u128 = 0x80fe20000081020000000968420723c; // ghost tok3
const W_LEA_A: u128 = 0xfe400078e08ff8000001312167211; // shadow drop t3
const W_LEA_B: u128 = 0x40fe200078e18ff8000001c1c0d2211; // ghost t2 + shadow drop t3
const W_LEA_C: u128 = 0x2fe400078e31ff000000ff93937211; // shadow drop t2
const W_IDP_A: u128 = 0x40fe400000006ff0000000c13087226; // ghost tok2
const W_IDP_B: u128 = 0x81fe400000006390000002940397226; // ghost tok3
const W_HFMA2B: u128 = 0x140fe40008160803200000080c027c31; // tok4 neg@84 kept
const W_HDF: u128 = 0xfc60000000900bf80bf80ff0b2430; // HADD2 FI b72 neg
const W_HML: u128 = 0x10fc80008000000300000080c0b7c32; // 264 sentinel

#[test]
fn t266_1_structure() {
    // Class closure: zero (neg,1,{122,123,124}) fields on the grafted legs.
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (k, row) in &t.entries {
            for (mg, g) in &row.mod_groups {
                for f in &g.fields {
                    assert!(
                        !(f.extraction == Extraction::Neg
                            && f.bits == 1
                            && (f.shift == 122 || f.shift == 123 || f.shift == 124)),
                        "{leg} {k}|{mg}: era ctl-neg tok{}@{} survived BUG-266",
                        f.token_idx,
                        f.shift
                    );
                }
            }
        }
    }
    // HADD2 FI sibling: pair neg@72/abs@73 grafted, era neg@73 gone.
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let g = &t.entries["HADD2_R_R_FI_FI"].mod_groups[""];
        let mut tok2: Vec<(u32, &str)> = g
            .fields
            .iter()
            .filter(|f| f.token_idx == 2 && (f.shift == 72 || f.shift == 73))
            .map(|f| {
                (
                    f.shift,
                    match f.extraction {
                        Extraction::Neg => "neg",
                        Extraction::Abs => "abs",
                        _ => "other",
                    },
                )
            })
            .collect();
        tok2.sort();
        assert_eq!(
            tok2,
            vec![(72u32, "neg"), (73u32, "abs")],
            "{leg} HADD2 FI tok2 pair drift"
        );
        assert!(g.fields.iter().any(|f| f.extraction == Extraction::HalfSel
            && f.bits == 2
            && f.shift == 74
            && f.token_idx == 2));
    }
    // 268-kand sentinel: donor tables still carry their era IMNMX neg@122
    // (byte-untouched this iteration; flip when the donor-side graft lands).
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let g = &t.entries["IMNMX_P_P_R_R_II_P_P"].mod_groups;
        let mut n = 0;
        for (_m, e) in g {
            n += e
                .fields
                .iter()
                .filter(|f| f.extraction == Extraction::Neg && f.bits == 1 && f.shift == 122)
                .count();
        }
        assert_eq!(n, 4, "{leg} donor IMNMX ctl-neg count drift (268-kand)");
    }
}

#[test]
fn t266_2_decode_ghost_free() {
    // arb266 witness laws: no '-' glyph may originate from bits 122-124
    // (harness ctl-zeroes, so '.reuse' does not print here; smoke266 pins
    // the ctl-carrying pyo3 text with vendor-equal '.reuse').
    let t = tab("sm120");
    assert_eq!(
        dec(&t, W_HMMA16816 & M96).as_deref(),
        Some("HMMA.16816.F32.BF16 R32, R68, R86, R32")
    );
    assert_eq!(
        dec(&t, W_HMMA1688 & M96).as_deref(),
        Some("HMMA.1688.F32.TF32 R32, R132, R150, R32")
    );
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_IDP_A & M96).as_deref(),
        Some("IDP.4A.S8.S8 R8, R19, R12, RZ")
    );
    assert_eq!(
        dec(&t, W_IDP_B & M96).as_deref(),
        Some("IDP.4A.S8.S8 R57, R64, R41, R57")
    );
    // and_base host law (arb266): reuse bits vendor-ILLEGAL here, never '-'.
    // Name FLIPPED 2026-08-29 (BUG-265): key/mnemod 'GT.AND' -> 'F.AND'
    // (arb265 C: base decodes vendor '.F.AND', bits 43..46 print-invariant;
    // closes the encode-side silent GT->F wrong-code).
    let f = and_base(&t, "FSET.BF.F.AND_R_R_R_P", "");
    assert_eq!(
        dec(&t, (f | (1 << 122)) & M96).as_deref(),
        Some("@P0 FSET.BF.F.AND R0, R0, R0, P0")
    );
    assert_eq!(
        dec(&t, (f | (1 << 123)) & M96).as_deref(),
        Some("@P0 FSET.BF.F.AND R0, R0, R0, P0")
    );
}

#[test]
fn t266_3_shadow_restored() {
    // True windows print again (arb266 vendor-equal witnesses).
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_LEA_A & M96).as_deref(),
        Some("LEA_P0 R22, R18, -R19, 0x1")
    );
    assert_eq!(
        dec(&t, W_LEA_C & M96).as_deref(),
        Some("LEA_P0 R147, -R147, RZ, 0x6")
    );
    // W_LEA_B carries both symptoms: tok2 ghost '-' gone AND tok3 '-'
    // restored (vendor ctl-carrying: '@P2 LEA R13, R28.reuse, -R28, 0x3').
    assert_eq!(
        dec(&t, W_LEA_B & M96).as_deref(),
        Some("@P2 LEA_P0 R13, R28, -R28, 0x3")
    );
    // HFMA2 BF16_V2 tok4: era dup neg@124 gone, true neg@84 prints through.
    // tok3 suffix FLIPPED 2026-08-29 (BUG-264/267): '.H0_H0' vendor-equal.
    assert_eq!(
        dec(&t, W_HFMA2B & M96).as_deref(),
        Some("HFMA2.BF16_V2 R2, R12.H0_H0, UR8.H0_H0, -R3.H1_H1")
    );
    // True-window laws on hosts (arb266: b72/b63 vendor '-').
    let f = and_base(&t, "FSET.BF.F.AND_R_R_R_P", "");
    assert_eq!(
        dec(&t, (f | (1 << 72)) & M96).as_deref(),
        Some("@P0 FSET.BF.F.AND R0, -R0, R0, P0")
    );
    assert_eq!(
        dec(&t, (f | (1 << 63)) & M96).as_deref(),
        Some("@P0 FSET.BF.F.AND R0, R0, -R0, P0")
    );
}

#[test]
fn t266_4_hadd2_fi_pair() {
    // 266 sibling fix: arb261 pair law (b72=neg, b73=abs) on the FI row.
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, W_HDF & M96).as_deref(),
            Some("@P2 HADD2 R11, -RZ.H0_H0, -1.875, -1.875"),
            "{leg} HADD2 FI witness law"
        );
        let h = and_base(&t, "HADD2_R_R_FI_FI", "");
        assert_eq!(
            dec(&t, (h | (1 << 72)) & M96).as_deref(),
            Some("@P0 HADD2 R0, -R0, 0, 0"),
            "{leg} b72 neg law"
        );
        assert_eq!(
            dec(&t, (h | (1 << 73)) & M96).as_deref(),
            Some("@P0 HADD2 R0, |R0|, 0, 0"),
            "{leg} b73 abs law"
        );
    }
    // Encode inverse on the pair (text -> exact window bits -> decode-back).
    let t = tab("sm121a");
    for (text, bits) in [
        ("HADD2 R8, -R4, 0, 0", 1u128),
        ("HADD2 R8, |R4|, 0, 0", 2u128),
        ("HADD2 R8, -|R4|, 0, 0", 3u128),
    ] {
        let w = enc(&t, text);
        assert_eq!((w >> 72) & 3, bits, "{text}: pair window bits");
        assert_eq!(
            dec(&t, w & M96).as_deref(),
            Some(text),
            "{text}: decode-back"
        );
    }
}

#[test]
fn t266_5_encode_no_fabrication() {
    // Negated operands now land on true windows only; bits 122-124 stay
    // owned by .reuse authoring (explicit fields + apply_reuse_encoding).
    let t = tab("sm121a");
    for text in [
        "LEA_P0 R22, R18, -R19, 0x1",
        "FSET.BF.F.AND R8, -R4, R7, P2",
        "HADD2 R8, -R4, 0, 0",
    ] {
        let w = enc(&t, text);
        assert_eq!((w >> 122) & 7, 0, "{text}: ctl bits fabricated");
        assert_eq!(
            dec(&t, w & M96).as_deref(),
            Some(text),
            "{text}: decode-back"
        );
    }
    // .reuse authority survives the deletion (slot bits from operand flag);
    // byte-stable roundtrip of reuse-carrying corpus witnesses.
    let w = enc(&t, "LEA_P0 R22, R18, R19.reuse, 0x1");
    assert_eq!((w >> 122) & 7, 2, "LEA_P0 .reuse slot bit lost");
    for (t2, witness) in [
        (tab("sm120"), W_HMMA16816),
        (tab("sm120"), W_HMMA1688),
        (tab("sm121a"), W_LEA_A),
        (tab("sm121a"), W_LEA_B),
        (tab("sm121a"), W_LEA_C),
        (tab("sm121a"), W_IDP_A),
        (tab("sm121a"), W_IDP_B),
    ] {
        let txt = dec(&t2, witness & M96).expect("decode witness");
        assert_eq!(
            enc(&t2, &txt) & M96,
            witness & M96,
            "payload drift on {txt}"
        );
    }
    // 264-kand sentinel FLIPPED 2026-08-29 (BUG-264 landed): era 4-bit
    // 'neg'@60 -> hsel 2b@60 + abs@62 + neg@63; ghost '-UR8' -> vendor
    // 'UR8.H1_H1' (arb264 A-set, x4 models).
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_HML & M96).as_deref(),
        Some("HMUL2.BF16_V2 R11, R12, UR8.H1_H1")
    );
    // 267-kand sentinel FLIPPED 2026-08-29 (closed by 264): HFMA2 BF16_V2
    // tok3-UR hsel suffix restored ('UR8.H0_H0', vendor-equal).
    assert!(dec(&t, W_HFMA2B & M96)
        .expect("decode")
        .contains(", UR8.H0_H0,"));
    // 265-kand anchor: phantom head row still registered (removal queued).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert!(t.entries.contains_key("HADD2_R_R_II_II_II_II_?"));
    }
}
