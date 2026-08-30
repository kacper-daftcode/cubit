//! BUG-271 (F2-iter143, loop5/blind front2, 2026-08-29): b86 '.H0_NH1' —
//! third bit of the tok3 3-bit hsel-suffix window — closure on the HFMA2
//! packed-f16 imm family (both legs, canonical efa714a) + sm121a BF16_V2
//! hosts. Engine: new Extraction::H0NH1 ("h0nh1") + printer opmod arm +
//! encoder scrape arm (fail-closed on hsel/'.F32' combos) + decoder gate
//! (b86 with nonzero same-token hsel = vendor INVALID{5,6,7} = hole;
//! era opmod:H0_NH1 rows share the gate).
//!
//! Laws (arb271/arb271b FULL window sweeps, nvdisasm 13.3.73 raw -b; x4
//! models SM100a/103a/120/121a agree byte-for-byte on all 212 probes):
//!   imm family window (b86,b82,b81): v0 '' v1 '.F32' v2 '.H0_H0' v3 '.H1_H1'
//!   v4 '.H0_NH1' v5/6/7 '.INVALID{5,6,7}'; v4 composes abs@83
//!   ('|RZ|.H0_NH1' — suffix OUTSIDE the pipes), neg@84, both, the whole
//!   mnemonic suffix lattice (F32/FMZ/FTZ/OOB/SAT/RELU+PT), tok2 hsel, regs;
//!   SAT+RELU rc=1; b86+b85 -> BF16_V2 cross-key (285-kand, stays hole).
//!   BF16 host HFMA2_R_R_UR_R|BF16_V2 (sm121a): window (b86,b61,b60) same
//!   map, signs compose ('|UR6.H0_NH1|' INSIDE pipes = 273-class print note).
//!   BF16 host HMUL2_R_R_UR|BF16_V2 (sm121a): b86 vendor TEXT-INERT
//!   (v4==v0, v5/6/7==v1/2/3) => reclaim without field (282 (62,63) /
//!   276 (80,81) precedent).
//! routex271 FULL 2,406-cubin battery (published cubit_py-af95e54, canonical
//! e819129): exposure ZERO on every graft surface (imm 97,337w x2 legs,
//! bf16 hosts 51w == routex264 35+16; R4 43,933+7,947 w with 32 b86 words on
//! sm120 ALL on the era-armed opmod:H0_NH1 row with hsel=0 => the decode-gate
//! extension to era rows is corpus-neutral) => graft corpus-neutral by
//! construction.
//! Registered: 285-kand (BF16_V2 cross-key family), 287-kand (HFMA2_R_R_R_R
//! era opmod:H0_NH1 row asymmetries: sm121a leg lacks the field; INVALID
//! combos now gated), 288-kand (rows wider than the 279 graft —
//! HFMA2_R_R_R_II_II_II both legs: same b86 law measured (vendor probe
//! 'RZ.H0_NH1' x4) but tok3 has no 279 arm; stays hole), tok3-UR '.F32'
//! v1 spelling pre-existing divergence (261/264 owner-scope).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
// II_FI host payloads (arb271 base; b72 neg cleared on IIB):
const FIB: u128 = 0x000001ff00000000ff037431; // 'HFMA2 R3, -RZ, RZ, 0, 0'
const IIB: u128 = 0x000fc600000000ff00000000ff037431 & M96; // b72=0 plain
                                                            // sm121a BF16_V2 hosts (routex264/arb264 witnesses):
const W_HML: u128 = 0x4fe20008000000300000080c037c32 & M96; // 'HMUL2 ... UR8.H0_H0'
const W_HFA: u128 = 0x4fca00080408052000000602057c31 & M96; // 'HFMA2 ... UR6.H0_H0 ...'
                                                            // era opmod:H0_NH1 R4-row witnesses (routex271 sm120): vendor-legal corpus word
const W_R4_LEGAL: u128 = 0xfca0000400c0c0000000f000d0231 & M96;
// R4 INVALID6 shape (arb271b): tok3 hsel=2 + b86
const W_R4_INV: u128 = (0xfc6000004080e200000121b1b7231u128 | (1u128 << 86)) & M96;
const W_R4_BASE: u128 = 0xfc6000004080e200000121b1b7231 & M96;

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

#[test]
fn t271_1_structure_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let mut armed = 0usize;
        for (k, e) in &t.entries {
            if !super_family(k) {
                continue;
            }
            for g in e.mod_groups.values() {
                let has_hsel = g.fields.iter().any(|f| {
                    f.extraction == Extraction::HalfSel && f.shift == 81 && f.token_idx == 3
                });
                let has_nh1 = g.fields.iter().any(|f| {
                    f.extraction == Extraction::H0NH1
                        && f.shift == 86
                        && f.bits == 1
                        && f.token_idx == 3
                });
                if has_hsel {
                    assert!(has_nh1, "{leg}|{k}: 279-armed row missing h0nh1");
                    let vm: u128 = g.variable_mask.into();
                    assert_ne!(vm & (1 << 86), 0, "{leg}|{k}: b86 not variable");
                    armed += 1;
                } else {
                    // rows wider than the 279 graft (II_II_II): no arm, b86
                    // stays outside vm (hole) = 288-kand status quo
                    assert!(!has_nh1, "{leg}|{k}: h0nh1 without the 279 arm?");
                }
            }
        }
        assert_eq!(armed, 96, "{leg}: armed family row count drift");
        // skipped registered: II_II_II keeps b86 outside vm (hole)
        let g = &t.entries["HFMA2_R_R_R_II_II_II"].mod_groups[""];
        assert_eq!(
            g.fields
                .iter()
                .filter(|f| f.extraction == Extraction::H0NH1)
                .count(),
            0
        );
        let vm: u128 = g.variable_mask.into();
        assert_eq!(vm & (1 << 86), 0, "{leg}: II_II_II widened?");
    }
    // sm121a BF16 hosts:
    let t = tab("sm121a");
    let g = &t.entries["HFMA2_R_R_UR_R"].mod_groups["BF16_V2"];
    assert!(g.fields.iter().any(|f| f.extraction == Extraction::H0NH1
        && f.shift == 86
        && f.bits == 1
        && f.token_idx == 3));
    let g = &t.entries["HMUL2_R_R_UR"].mod_groups["BF16_V2"];
    let vmh: u128 = g.variable_mask.into();
    assert_ne!(vmh & (1 << 86), 0, "HMUL2 reclaim lost");
    assert!(
        !g.fields.iter().any(|f| f.extraction == Extraction::H0NH1),
        "HMUL2: b86 is vendor text-inert — reclaim must NOT carry a field"
    );
    // donors byte-untouched: NO h0nh1 extraction anywhere (era opmod:H0_NH1
    // pre-exists and is untouched by definition)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (k, e) in &t.entries {
            for g in e.mod_groups.values() {
                assert!(
                    !g.fields.iter().any(|f| f.extraction == Extraction::H0NH1),
                    "{leg}|{k}: donor touched"
                );
            }
        }
    }
}

#[test]
fn t271_2_decode_laws_vendor_exact() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let law = |bits: u128, want: &str| {
            assert_eq!(
                dec(&t, (IIB | bits) & M96).as_deref(),
                Some(want),
                "{leg} bits={bits:#x}"
            );
        };
        // anchors: v0..v3 unchanged (279 armed)
        law(0, "HFMA2 R3, RZ, RZ, 0, 0");
        law(1 << 81, "HFMA2 R3, RZ, RZ.F32, 0, 0");
        law(2 << 81, "HFMA2 R3, RZ, RZ.H0_H0, 0, 0");
        law(3 << 81, "HFMA2 R3, RZ, RZ.H1_H1, 0, 0");
        // v4 = the 271 arm; sign composition = vendor print (arb271 A2)
        law(1 << 86, "HFMA2 R3, RZ, RZ.H0_NH1, 0, 0");
        law((1 << 86) | (1 << 84), "HFMA2 R3, RZ, -RZ.H0_NH1, 0, 0");
        law((1 << 86) | (1 << 83), "HFMA2 R3, RZ, |RZ|.H0_NH1, 0, 0");
        law((1 << 86) | (3 << 83), "HFMA2 R3, RZ, -|RZ|.H0_NH1, 0, 0");
        // tok2 hsel independence (arb271 E)
        law((1 << 86) | (2 << 74), "HFMA2 R3, RZ.H0_H0, RZ.H0_NH1, 0, 0");
        // mnemonic suffix lattice composition (arb271 B; PT-elided RELU)
        law((1 << 86) | (1 << 78), "HFMA2.F32 R3, RZ, RZ.H0_NH1, 0, 0");
        law((1 << 86) | (1 << 76), "HFMA2.FMZ R3, RZ, RZ.H0_NH1, 0, 0");
        law((1 << 86) | (1 << 80), "HFMA2.FTZ R3, RZ, RZ.H0_NH1, 0, 0");
        law(
            (1 << 86) | (1 << 80) | (1 << 76),
            "HFMA2.OOB R3, RZ, RZ.H0_NH1, 0, 0",
        );
        law((1 << 86) | (1 << 77), "HFMA2.SAT R3, RZ, RZ.H0_NH1, 0, 0");
        law(
            (1 << 86) | (1 << 79) | (7 << 87),
            "HFMA2.RELU R3, RZ, RZ.H0_NH1, 0, 0",
        );
        // neg tok2 witness anchor with b86 (arb279 E shape)
        assert_eq!(
            dec(&t, (FIB | (1 << 86)) & M96).as_deref(),
            Some("HFMA2 R3, -RZ, RZ.H0_NH1, 0, 0"),
            "{leg}: FIB+b86"
        );
    }
    // BF16 host HFMA2 (sm121a; window (b86,b61,b60), ab v2 baked => clear)
    let t = tab("sm121a");
    let b = W_HFA & !(0xFu128 << 60);
    let law = |w: u128, want: &str| assert_eq!(dec(&t, w & M96).as_deref(), Some(want), "w={w:#x}");
    law(b, "HFMA2.BF16_V2 R5, R2.H0_H0, UR6, R5.H0_H0");
    law(
        b | 2 << 60,
        "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0",
    );
    law(
        b | 1 << 86,
        "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_NH1, R5.H0_H0",
    );
    law(
        b | (1 << 86) | (1 << 63),
        "HFMA2.BF16_V2 R5, R2.H0_H0, -UR6.H0_NH1, R5.H0_H0",
    );
    // abs+b86: vendor prints '|UR6.H0_NH1|' (inside pipes) — engine compositor
    // put operand mods outside the pipes pre-BUG-273 (273-class cosmetics).
    // FLIPPED by BUG-273 (arb273 x4 models): engine now composes the suffix
    // inside the pipes == vendor text. Bit-law unchanged (encode-inverse
    // below/nvdisasm).
    law(
        b | (1 << 86) | (1 << 62),
        "HFMA2.BF16_V2 R5, R2.H0_H0, |UR6.H0_NH1|, R5.H0_H0",
    );
    // HMUL2 reclaim: b86 vendor TEXT-INERT (arb271 D) — text-equal, no ghost
    let hb = W_HML & !(0xFu128 << 60);
    assert_eq!(
        dec(&t, hb | (1 << 86)).as_deref(),
        Some("HMUL2.BF16_V2 R3, R12, UR8")
    );
    assert_eq!(
        dec(&t, hb | (1 << 86) | (2 << 60)).as_deref(),
        Some("HMUL2.BF16_V2 R3, R12, UR8.H0_H0")
    );
    assert_eq!(
        dec(&t, hb | (1 << 86) | (1 << 60)).as_deref(),
        // FLIPPED F2-iter151 (BUG-297 landed): hsel v1 on the HMUL2 UR slot
        // is the vendor '.INVALID1' (arb273 C4 + arb297b Hc1 x4 models);
        // b86 stays text-inert on this host (arb271 D).
        Some("HMUL2.BF16_V2 R3, R12, UR8.INVALID1")
    );
}

#[test]
fn t271_3_invalid_combos_decode_hole() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // imm family v5/v6/v7 = vendor INVALID{5,6,7} => decode hole
        for v in 5u128..=7 {
            assert!(
                dec(&t, (IIB | ((v & 3) << 81) | ((v >> 2) << 86)) & M96).is_none(),
                "{leg}: imm INVALID{v} must hole"
            );
        }
    }
    let t = tab("sm121a");
    let b = W_HFA & !(0xFu128 << 60);
    for v in 5u128..=7 {
        assert!(
            dec(&t, (b | ((v & 3) << 60) | ((v >> 2) << 86)) & M96).is_none(),
            "bf16 INVALID{v} must hole"
        );
    }
    // era opmod:H0_NH1 R4 row (sm120): INVALID6 shape gated (arb271b x4);
    // legal corpus witness (hsel=0) still decodes vendor-equal
    let t120 = tab("sm120");
    assert_eq!(
        dec(&t120, W_R4_LEGAL).as_deref(),
        Some("@P0 HFMA2 R13, R0.H1_H1, R15.H0_NH1, R12"),
        "era R4 legal word"
    );
    assert!(dec(&t120, W_R4_BASE).is_some(), "R4 base must decode");
    assert!(
        dec(&t120, W_R4_INV).is_none(),
        "R4 b86+hsel=2 INVALID6 must hole"
    );
}

#[test]
fn t271_4_encode_inverse_and_fail_closed() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // text -> word -> text roundtrips on the armed forms
        for (txt, bits) in [
            ("HFMA2 R3, RZ, RZ.H0_NH1, 0, 0", 1u128 << 86),
            ("HFMA2 R3, RZ, -RZ.H0_NH1, 0, 0", (1 << 86) | (1 << 84)),
            ("HFMA2 R3, RZ, |RZ|.H0_NH1, 0, 0", (1 << 86) | (1 << 83)),
            ("HFMA2 R3, RZ, -|RZ|.H0_NH1, 0, 0", (1 << 86) | (3 << 83)),
            ("HFMA2.F32 R3, RZ, RZ.H0_NH1, 0, 0", (1 << 86) | (1 << 78)),
            ("HFMA2.FTZ R3, RZ, RZ.H0_NH1, 0, 0", (1 << 86) | (1 << 80)),
            (
                "HFMA2.OOB R3, RZ, RZ.H0_NH1, 0, 0",
                (1 << 86) | (1 << 80) | (1 << 76),
            ),
            ("HFMA2.SAT R3, RZ, RZ.H0_NH1, 0, 0", (1 << 86) | (1 << 77)),
            (
                "HFMA2.RELU R3, RZ, RZ.H0_NH1, 0, 0, P2",
                (1 << 86) | (1 << 79) | (2 << 87),
            ),
        ] {
            // sm121a era FI_FI/II_FI rows bake neg@72=1 ('-RZ' tok2 sink
            // convention; routex279: 94,630+2,707 corpus words all b72=1) —
            // a plain 'RZ' text coerces to the era word there (pre-existing
            // 270/286-class FI-region shadowing, registered, NOT 271). The
            // 271 payload/roundtrip pins therefore run bit-exact on sm120
            // (b72-variable) and text-exact on sm121a via the '-RZ' baseline.
            let w = enc_res(&t, txt).unwrap_or_else(|e| panic!("{leg} enc {txt}: {e}"));
            assert_ne!(w & (1 << 86), 0, "{leg}: b86 not encoded for {txt}");
            if leg == "sm120" {
                assert_eq!(w & M96, (IIB | bits) & M96, "{leg} payload {txt}");
                assert_eq!(dec(&t, w & M96).as_deref(), Some(txt), "{leg} rt {txt}");
            } else {
                let txt121 = txt.replacen("R3, RZ,", "R3, -RZ,", 1);
                // sm121a RELU _P winner prints the FI imm as '0x0' (pre-existing
                // FI-region print cosmetics, registered at BUG-274/279; tripwire)
                let txt121 = if txt.contains(".RELU") {
                    txt121.replacen(", 0, 0,", ", 0x0, 0,", 1)
                } else {
                    txt121
                };
                assert_eq!(
                    dec(&t, w & M96).as_deref(),
                    Some(txt121.as_str()),
                    "{leg} rt {txt} (era -RZ baseline)"
                );
            }
        }
        // fail-closed: INVALID compositions on the same token
        for bad in [
            "HFMA2 R3, RZ, RZ.H0_H0.H0_NH1, 0, 0",
            "HFMA2 R3, RZ, RZ.H1_H1.H0_NH1, 0, 0",
            "HFMA2 R3, RZ, RZ.F32.H0_NH1, 0, 0",
            "HFMA2 R3, RZ, RZ.H0_H1.H0_NH1, 0, 0",
            "HFMA2.SAT.RELU R3, RZ, RZ.H0_NH1, 0, 0",
        ] {
            assert!(enc_res(&t, bad).is_err(), "{leg}|{bad}: must fail closed");
        }
    }
    // BF16 host encode-inverse (sm121a)
    let t = tab("sm121a");
    let hb = W_HFA & !(0xFu128 << 60);
    // hb = W_HFA with tok3 window [63:60] CLEARED: the input texts carry
    // '.H0_NH1' (hsel 0 + b86), not '.H0_H0' — tok2/tok4 bits stay W's
    for (txt, bits) in [
        (
            "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_NH1, R5.H0_H0",
            1u128 << 86,
        ),
        (
            "HFMA2.BF16_V2 R5, R2.H0_H0, -UR6.H0_NH1, R5.H0_H0",
            (1 << 86) | (1 << 63),
        ),
        (
            // FLIPPED by BUG-273 to the vendor in-pipes spelling; the legacy
            // tail form stays encode-equivalent (pinned in t273_4).
            "HFMA2.BF16_V2 R5, R2.H0_H0, |UR6.H0_NH1|, R5.H0_H0",
            (1 << 86) | (1 << 62),
        ),
    ] {
        let w = enc_res(&t, txt).unwrap_or_else(|e| panic!("enc {txt}: {e}"));
        assert_eq!(w & M96, (hb | bits) & M96, "payload {txt}");
        assert_eq!(dec(&t, w & M96).as_deref(), Some(txt), "rt {txt}");
    }
    for bad in [
        "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_H0.H0_NH1, R5.H0_H0",
        "HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H1_H1.H0_NH1, R5.H0_H0",
    ] {
        assert!(enc_res(&t, bad).is_err(), "{bad}: must fail closed");
    }
}

#[test]
fn t271_5_registrations_and_anchors() {
    // 285-kand: b85 BF16_V2 cross-key stays a hole on the imm family
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert!(
            dec(&t, (IIB | (1 << 85)) & M96).is_none(),
            "{leg}: b85 hole lost"
        );
        assert!(
            enc_res(&t, "HFMA2.BF16_V2 R3, RZ, RZ.H0_NH1, 0, 0").is_err(),
            "{leg}: b85 cross-key encode"
        );
        // SAT+RELU stays vendor-ILLEGAL fail-closed
        assert!(enc_res(&t, "HFMA2.SAT.RELU R3, RZ, RZ.H0_NH1, 0, 0").is_err());
    }
    // 288-kand: rows wider than the 279 graft (II_II_II) carry NO h0nh1
    // field and keep b86 outside vm (structure pinned in t271_1). The vendor
    // '.H0_NH1' law IS measured on that shape (x4, arb271 registration);
    // today the '.H0_NH1' text on a 6-operand form hits the registered
    // 272-class parser drop => encoded word MUST keep b86 clear (tripwire).
    // (encode probe removed: the text encoder maps bare '0' operands to FI
    // and never selects the II_II_II key — the 272-class parser drop on
    // non-armed rows stays registered; structure pin = t271_1)
    // the earlier prober 'witness' 0xfe400000001ff00000000ff1d7431 decodes via
    // the FI_FI/II_FI armed rows (not II_II_II): with b86 it now prints the
    // armed 271 law text = routing anchor
    assert_eq!(
        dec(
            &tab("sm120"),
            (0xfe400000001ff00000000ff1d7431u128 | (1 << 86)) & M96
        )
        .as_deref(),
        Some("HFMA2 R29, -RZ, RZ.H0_NH1, 0, 0"),
        "armed-law routing anchor"
    );
    let t = tab("sm120");
    // era R4 row: opmod:H0_NH1 field untouched (byte-equal era), 32 corpus
    // words anchor — decode of the witness unchanged post-271
    let g = &t.entries["HFMA2_R_R_R_R"].mod_groups[""];
    assert!(g
        .fields
        .iter()
        .any(|f| f.extraction == Extraction::OpModFlag("H0_NH1".into())));
    assert_eq!(
        dec(&t, W_R4_LEGAL).as_deref(),
        Some("@P0 HFMA2 R13, R0.H1_H1, R15.H0_NH1, R12")
    );
    // 279 anchors: D0 decode unchanged; the tok2 v1 slot is FLIPPED
    // F2-iter154 (BUG-306 armed) -- vendor law '.INVALID1' (arb279 C
    // lattice inside the arb306 win@74 census, x4 models).
    let t = tab("sm120");
    assert_eq!(
        dec(&t, FIB & M96).as_deref(),
        Some("HFMA2 R3, -RZ, RZ, 0, 0")
    );
    assert_eq!(
        dec(&t, (FIB | (1 << 74)) & M96).as_deref(),
        Some("HFMA2 R3, -RZ.INVALID1, RZ, 0, 0")
    );
}

fn super_family(k: &str) -> bool {
    // mirror of table::hfma2_immfam_key
    if !k.starts_with("HFMA2") {
        return false;
    }
    let toks: Vec<&str> = k.split('_').collect();
    let t: &[&str] = if toks.last() == Some(&"P") {
        &toks[..toks.len() - 1]
    } else {
        &toks
    };
    if t.len() < 4 || t[1..4] != ["R", "R", "R"] {
        return false;
    }
    matches!(
        (t[t.len() - 2], t[t.len() - 1]),
        ("II", "FI") | ("FI", "FI") | ("II", "II")
    )
}
