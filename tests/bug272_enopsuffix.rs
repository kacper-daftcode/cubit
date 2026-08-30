//! BUG-272 (F2-iter146, loop5/blind front2, 2026-08-30): encoder-side
//! unknown-operand-suffix SILENT DROP closure (bare R/UR/RZ/URZ tokens).
//! Class registered as residual of 264-class triage (270); first pinned as
//! encode-side residue by 271/275/284 (tripwires t271_5 note / t275_5 /
//! t284_5 + smoke284; all flipped by THIS fix).
//! PRE-FIX (measured on pub pyo3-f8360bb, work/bug272/measure_pre272.json):
//!   `MOV R1, RZ.INVALID5` (x4 legs), `UMOV UR4, UR6.GARBAGE` (x4 legs),
//!   `I2IP.U8.S32 R5, R4, R3, R2.{???2,GARBAGE,INVALID1,H0_NH1}` (x2 legs)
//!   all encoded the EXACT plain word = silent wrong-code the moment the
//!   suffix was meant to carry bits.
//! GATE (engine, src/encoder.rs check_operand_suffixes, post-selection
//! always-on, NOT CUBIT_DISABLE_ERRATA-unlockable; CUBIT_FIT_LINT=allow
//! skips it for the disassemble probe oracle): every suffix segment of a
//! bare-register token must be (a) consumed by a winning-row field on that
//! token (opmod:*/hsel incl. the 279-armed '.F32'/h0nh1/reuse) or (b) a
//! vendor-default notation (HSETP* .H0_H0 / FFMA2* lane set / PLOP3 R-form
//! row-carried .SIGN). '.reuse' is owned by the generic slot path (R) and
//! the BUG-252 guard (UR); .INVALID3 is deliberately refused.
//! CENSUS (work/bug272/census272.json): FULL 2,406-cubin battery decode +
//! rt98_v2 chain text + the rt cuobjdump feed inventory over the delta
//! files (reuse/F32x2/F32/HI_LO/LO_HI/NP/H0_H0/H1_H1/H0_NH1/B0..B3/ROW/COL/
//! ???0..1): every observed bare-reg suffix segment is covered by (a)/(b)
//! => the gate changes no honest corpus byte.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const FIB: u128 = 0x000001ff00000000ff037431; // 'HFMA2 R3, -RZ, RZ, 0, 0'
const I2IP_PLAIN: u128 = 0xfc200000000020000000304057239; // 'I2IP.U8.S32 R5, R4, R3, R2'
const UMOV_PLAIN: u128 = 0xfc200080000000000000600047c82; // 'UMOV UR4, UR6'
const MOV_PLAIN: u128 = 0xfc20000000f00000000ff00017202; // 'MOV R1, RZ'

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
fn enc(t: &IsaTable, text: &str) -> u128 {
    enc_res(t, text).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

#[test]
fn t272_1_unknown_suffix_failclosed_all_legs() {
    // the measured pre-fix silent-drop class, now fail-closed with
    // attribution, on every table leg
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for text in [
            "MOV R1, RZ.INVALID5",
            "MOV R1, RZ.GARBAGE",
            "UMOV UR4, UR6.GARBAGE",
            "UMOV UR4, URZ.???3",
        ] {
            let e = enc_res(&t, text).expect_err("{leg}|{text}: must fail closed");
            assert!(e.contains("BUG-272"), "{leg}|{text}: gate attribution: {e}");
        }
        // plain forms unchanged (byte pins from measure_pre272)
        assert_eq!(enc(&t, "MOV R1, RZ"), MOV_PLAIN, "{leg}: MOV plain drift");
        assert_eq!(
            enc(&t, "UMOV UR4, UR6"),
            UMOV_PLAIN,
            "{leg}: UMOV plain drift"
        );
    }
    // I2IP family (sm120/sm121a legs): the registered 275/284 tripwire set
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for text in [
            "I2IP.U8.S32 R5, R4, R3, R2.???2",
            "I2IP.U8.S32 R5, R4, R3, R2.GARBAGE",
            "I2IP.U8.S32 R5, R4.INVALID1, R3, R2",
            // '.H0_NH1' is a KNOWN suffix but the I2IP row owns no h0nh1
            // field for tok4 -- unknown on this row => fail closed (the
            // pre-fix silent drop was measured exactly here in 264-triage)
            "I2IP.U8.S32 R5, R4, R3, R2.H0_NH1",
        ] {
            let e = enc_res(&t, text).expect_err("{leg}|{text}: must fail closed");
            assert!(e.contains("BUG-272"), "{leg}|{text}: gate attribution: {e}");
        }
        assert_eq!(
            enc(&t, "I2IP.U8.S32 R5, R4, R3, R2"),
            I2IP_PLAIN,
            "{leg}: I2IP plain drift"
        );
    }
    // FFMA2 print-law '.INVALID3' (b82&b81, zero corpus exposure per
    // ana234): pre-fix encoded the both-bits-clear default word = silent
    // wrong-code; the gate now refuses it (donor legs)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            enc_res(&t, "FFMA2 R4, R5.INVALID3, R6, R7").is_err(),
            "{leg}: .INVALID3 must fail closed"
        );
        assert!(
            enc_res(&t, "FFMA2 R4, |R5|.F32x2.???7, R6, R7").is_err(),
            "{leg}: abs-tail unknown segment must fail closed"
        );
    }
}

#[test]
fn t272_2_consumed_suffixes_vendor_exact() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // opmod:H1@72 tok4 (BUG-265 retype anchor, both legs)
        let w = enc(&t, "I2IP.U8.S32 R5, R4, R3, R2.H1");
        assert_eq!(w, I2IP_PLAIN | (1 << 72), "{leg}: .H1 encode");
        assert_eq!(
            dec(&t, w & M96).as_deref(),
            Some("I2IP.U8.S32 R5, R4, R3, R2.H1"),
            "{leg}: .H1 roundtrip"
        );
        // HFMA2 imm-family tok3 hsel window (BUG-279 arming) + 271 h0nh1:
        // every vendor-legal suffix on the armed slot still encodes exact
        let cases: &[(&str, u128)] = &[
            ("HFMA2 R3, -RZ, RZ.F32, 0, 0", FIB | (1 << 81)),
            ("HFMA2 R3, -RZ, RZ.H0_H0, 0, 0", FIB | (2 << 81)),
            ("HFMA2 R3, -RZ, RZ.H1_H1, 0, 0", FIB | (3 << 81)),
            ("HFMA2 R3, -RZ, |RZ|.F32, 0, 0", FIB | (1 << 81) | (1 << 83)),
            ("HFMA2 R3, -RZ, RZ.H0_NH1, 0, 0", FIB | (1 << 86)),
            (
                "HFMA2 R3, -RZ, -|RZ|.H0_NH1, 0, 0",
                FIB | (1 << 86) | (3 << 83),
            ),
        ];
        for (text, want) in cases {
            let got = enc(&t, text) & M96;
            assert_eq!(got, want & M96, "{leg}|{text}: word");
            let back = dec(&t, got).unwrap_or_else(|| panic!("{leg}|{text}: decode hole"));
            let re = enc(&t, &back) & M96;
            assert_eq!(re, want & M96, "{leg}|{text}: roundtrip via '{back}'");
        }
        // the armed-INVALID combos stay fail-closed through 271/279 arms
        // (gate must not re-open them via the hsel consumed-set)
        assert!(
            enc_res(&t, "HFMA2 R3, -RZ, RZ.H0_H1, 0, 0").is_err(),
            "{leg}: '.H0_H1' INVALID form aliased"
        );
        assert!(
            enc_res(&t, "HFMA2 R3, -RZ, RZ.H0_H0.H0_NH1, 0, 0").is_err(),
            "{leg}: hsel+h0nh1 INVALID combo aliased"
        );
    }
    // ByteSel scrape consumers (.B0..B3 on the R2P source, byte_sel@76):
    // census272 shows real corpus lines `R2P 0x0, R6.B1, 0xf` -- the (a)
    // lane must admit them on both row shapes (L/II imm-first keys).
    for leg in ["sm100a", "sm103a", "sm121a"] {
        let t = tab(leg);
        let b0 = enc(&t, "R2P 0x0, R6, 0xf");
        assert_eq!(enc(&t, "R2P 0x0, R6.B1, 0xf"), b0 | (1 << 76), "{leg}: .B1");
        assert_eq!(enc(&t, "R2P 0x0, R6.B3, 0xf"), b0 | (3 << 76), "{leg}: .B3");
    }
    // the I2F.S8 byte_sel@60 shape covers the sm120 leg too
    for leg in ["sm103a", "sm120"] {
        let t = tab(leg);
        let b0 = enc(&t, "I2F.S8 R4, R8");
        assert_eq!(enc(&t, "I2F.S8 R4, R8.B2"), b0 | (2 << 60), "{leg}: .B2");
    }
    // R-domain .reuse through the generic slot path (t266_5 sibling pin):
    // tok2 Rb@32 -> bit 122, tok4 Rc@64 -> bit 124, unchanged post-272
    let t = tab("sm120");
    let base = enc(&t, "IMAD R1, R2, R3, R4");
    assert_eq!(
        enc(&t, "IMAD R1, R2.reuse, R3, R4"),
        base | (1 << 122),
        "Rb.reuse"
    );
    assert_eq!(
        enc(&t, "IMAD R1, R2, R3, R4.reuse"),
        base | (1 << 124),
        "Rc.reuse"
    );
    assert_eq!(
        dec(&t, base | (1 << 122)),
        Some("IMAD R1, R2.reuse, R3, R4".into())
    );
}

#[test]
fn t272_3_default_notations_stay() {
    // HSETP* vendor default '.H0_H0' (printer law; corpus 100% of HSETP2
    // records). Two row shapes, both must keep working:
    let t = tab("sm103a");
    //  (i) rows WITHOUT an hsel field (e.g. GEU mg) -- pure notation, word
    //      equals the bare spelling (this is the (b)-class surface)
    let p_geu = enc(&t, "HSETP2.GEU.AND P1, PT, R9, R24, PT");
    assert_eq!(
        enc(&t, "HSETP2.GEU.AND P1, PT, R9.H0_H0, R24.H0_H0, PT"),
        p_geu,
        "HSETP2/GEU .H0_H0 default changed"
    );
    //  (ii) rows WITH an hsel field (e.g. GT mg, v1@61 on the source slot)
    //      -- consumed by the field (candidate (a)); exact-word pin
    let p_gt = enc(&t, "HSETP2.GT.AND P1, PT, R9, R24, PT");
    assert_eq!(
        enc(&t, "HSETP2.GT.AND P1, PT, R9.H0_H0, R24.H0_H0, PT"),
        p_gt | (1 << 61),
        "HSETP2/GT .H0_H0 field value changed"
    );
    // FFMA2 lane decorations (BUG-234 print law: row fields only carry
    // t2's non-default mods; t3/t4 defaults + t2 .HI_LO are pure vendor
    // notation). The canonical corpus spellings from the 234 parity suite
    // must STILL encode post-272 (gate admits the full lane set); byte
    // pins themselves stay owned by tests/bug234_ffma2_parity.rs.
    let canonical_ffma2 = [
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, R56.F32x2.HI_LO",
        "FFMA2 R66, R40.F32x2.HI_LO.NP, R48.reuse.F32, R66.F32x2.HI_LO",
        "FFMA2 R84, R20.F32, R24.reuse.F32x2.HI_LO, R64.F32x2.HI_LO",
        "FFMA2 R68, R36.F32x2.LO_HI, R51.F32, R68.F32x2.HI_LO",
        "FFMA2 R70, -R64.reuse.F32x2.LO_HI.NP, R39.reuse.F32, R58.F32x2.HI_LO",
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, |R56|.F32x2.HI_LO",
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32x2.HI_LO, R56.F32x2.HI_LO",
    ];
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for text in canonical_ffma2 {
            // gate admission: the suffix audits must not refuse the
            // canonical lane spellings; payload byte-pins + text roundtrip
            // identity stay owned by t234_2/t234_4 (byte-delta scope).
            enc(&t, text);
        }
    }
    // FFMA2 UR-form encode stays fail-closed on sm120 regardless of the
    // (b) lane breadth (arb234x/z: vendor-illegal cells; t234_3 pin). The
    // donor legs' baked UR row (b88=1, no opmod fields) encodes the
    // '.F32' notation through the same (b) lane it is printed by.
    let t120 = tab("sm120");
    assert!(
        enc_res(&t120, "FFMA2 R30, R27, UR9.F32, R17").is_err(),
        "sm120: FFMA2 UR-form reopened"
    );
    // IMMA vendor sparse-selector notations '.ROW'/'.COL'/'.???n' (the
    // rt272 2,406-cubin roundtrip attribution: every 272-gate delta was an
    // IMMA selector line). Text forms from the cuobjdump feed (s4/imma
    // v_75 + s4a selector-marker shapes):
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let plain = enc(&t, "IMMA.16832.S8.S8 R8, R40, R44, R8");
        for text in [
            "IMMA.16832.S8.S8 R8, R40.ROW, R44, R8",
            "IMMA.16832.S8.S8 R8, R40.ROW, R44.COL, R8",
            "IMMA.16832.S8.S8 R8, R40.???1, R44.COL, R8",
            "IMMA.16832.S8.S8 R8, R40.ROW, R44.???0, R8",
        ] {
            assert_eq!(
                enc(&t, text),
                plain,
                "{leg}|{text}: selector admission changed"
            );
        }
        // the IMMA lane does NOT swallow arbitrary unknown suffixes
        let e = enc_res(&t, "IMMA.16832.S8.S8 R8, R40.ROW, R44.GARBAGE, R8")
            .expect_err("{leg}: non-selector suffix must fail closed");
        assert!(e.contains("BUG-272"), "{leg}: {e}");
    }
    // PLOP3 R-form row-carried '.SIGN' (b9p13 phase-3 #11 authored surface;
    // word identity with the bare spelling = row carries the semantics)
    for leg in ["sm100a", "sm103a", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            enc(
                &t,
                "@P0 PLOP3.LUT P1, PT, R4.SIGN, R5.SIGN, R10.SIGN, 0x2, 0x0"
            ),
            enc(&t, "@P0 PLOP3.LUT P1, PT, R4, R5, R10, 0x2, 0x0"),
            "{leg}: PLOP3 .SIGN changed"
        );
    }
}

#[test]
fn t272_4_era_anchors_and_lanes() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // 265/274/276/284 anchors unchanged (gate must not re-open holes)
        assert!(t.entries.contains_key("I2I.U8.S32.SAT_R_R"), "{leg}");
        assert!(
            t.entries["HFMA2_R_R_R_II_FI"]
                .mod_groups
                .contains_key("SAT"),
            "{leg}"
        );
        assert_eq!(
            dec(&t, 0x70000023a).as_deref(),
            Some("@P0 MOVM.16.MT88_P5 R0, R128"),
            "{leg}: 276 MOVM anchor"
        );
        assert_eq!(
            dec(&t, 0x30000000000000000007239u128).as_deref(),
            Some("I2IP.U8.S32 R0, R0, R0, R0"),
            "{leg}: 284 window anchor"
        );
        assert!(
            dec(&t, 0x2000000000000007239u128).is_none(),
            "{leg}: 275 hole anchor"
        );
        // bracket lanes out of 272 scope: desc/addr suffix channel untouched
        // (BUG-160 canonical frozen-era line still encodes)
        assert!(
            enc_res(&t, "LDG.E.LTC128B.128 R0, desc[URZ][R60.64+0x2400]").is_ok(),
            "{leg}: desc channel regression"
        );
    }
    // zero word never decodes; predicate-suffix lane was already fail-closed
    // at key lookup (parse never produces a Pred out of 'P0.BAR') -- pin
    // the documented sibling closure
    for leg in ["sm120"] {
        let t = tab(leg);
        assert!(dec(&t, 0).is_none(), "{leg}: zero word decodes");
        assert!(
            enc_res(&t, "SEL R1, R2, R3, P0.BAR").is_err(),
            "{leg}: predicate suffix lane reopened"
        );
    }
}

#[test]
fn t272_5_registrations_and_residual_trips() {
    // 291-kand (registered residual, out of 272 scope): R-domain '.reuse'
    // on an operand whose slot the generic reuse path does NOT own (dest @
    // bits[23:16] vs reuse slots @24/@32/@64) is STILL silently dropped --
    // pin current behavior so the 291 fix flips this.
    let t = tab("sm120");
    let base = enc(&t, "IMAD R1, R2, R3, R4");
    assert_eq!(
        enc(&t, "IMAD R1.reuse, R2, R3, R4"),
        base,
        "291-kand: unmapped-slot R.reuse drop changed -- flip with its fix"
    );
    // 293-kand (registered residual): an AUTHORED '.H0_NH1' on a
    // HFMA2.BF16_V2-text WITHOUT the era tok2 '.H1_H1' still rides the era
    // redundancy lane and loses b86 (word == plain). Vendor never prints
    // the unpaired shape (arb271 law), so the lane is corpus-neutral, but
    // authored text can hit it -- pin current behavior for the flip.
    let p_plain = enc(&t, "HFMA2.BF16_V2 R13, R14, R15, R12");
    assert_eq!(
        enc(&t, "HFMA2.BF16_V2 R13, R14, R15.H0_NH1, R12"),
        p_plain,
        "293-kand: unpaired BF16_V2 .H0_NH1 drop changed -- flip with its fix"
    );
    // doctrine notes standing: t275_5/t284_5 twins flipped by THIS fix
    // (encode of '.???2' now fails closed, asserted there); the FFMA2
    // '.INVALID3' refusal is pinned in t272_1; the bracket-side suffix
    // channel ([R.QQ+..]) is untouched and registered for the follow-up
    // lane (out of the registered UR/R bare-token class).
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let e = enc_res(&t, "I2IP.U8.S32 R5, R4, R3, R2.???2")
            .expect_err("272 twin: unknown suffix fails closed");
        assert!(e.contains("BUG-272"), "{leg}: {e}");
    }
}
