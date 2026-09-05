//! BUG-383 + BUG-384 (F2-iter205, loop5/blind front2, 2026-09-05).
//!
//! BUG-383 (ENGINE, parser.rs + table.rs, canonical UNCHANGED): authored
//! comma-joined multi-mod texts (`HFMA2.F32,FMZ R1, R2, UR4, R5;`) failed
//! RE_INS at the first comma, leaking `,FMZ R1` into the operand stream as
//! Label operands -> InsKey HFMA2_II_II_R_UR_R -> loud rc=1
//! `no operand-compatible table entry` on EVERY leg (measure_pre383). The
//! tables name multi-mod groups with commas (`F32,FMZ`), so the authored
//! form is the natural spelling; zero corruption (loud hole), LOW severity
//! registration F2-iter196 (383-kand, triggered for ANY op with comma
//! mod-groups: HFMA2/F2I/ISETP/ATOM/...). Fix: RE_INS Op class accepts ','
//! (operands always follow whitespace — no real operand token can be
//! swallowed) and both parser.rs modifiers and table::extract_mod_group
//! split components on ',' so dot- and comma-spellings canonicalize to the
//! SAME mod-group name (sort+join was already canonical for dot order).
//!
//! BUG-384 (canonical graft patch384.py, dbe5e91 -> 9713fd6; ENGINE ZERO):
//! delete harvest-junk dense era keys HFMA2.BF16_V2_R_R_R_R +
//! HFMA2_R_R_R_R_R (sm120 + sm121a only; sparse legs never shipped them --
//! the sparse 5-reg hole is the open 394-kand). Junk-baked claims
//! (H0_H0 hsel bakes b61/b75/b82; odd shifted 5-reg windows guard 1b@13,
//! reg @18/@33/@66) with field sets that do not match the vendor geometry;
//! arb384 lattice (168 probes = 2 era bases x 84 flips x2 legs, nvdisasm
//! 13.3.73 raw -b) found the 5-reg row WINNING inert-window words and
//! printing garbage regs (flip40: engine printed `@P0 HFMA2 R0, R28, R128,
//! R0, R2` where vendor renders the base text unchanged) = live silent
//! decode corruption pre-fix. arb384b window law: both shapes carry exactly
//! the HFMA2_R_R_R_R window geometry, already owned by the main rows
//! (guard 4b@[15:12], Rd@[23:16], Ra@[31:24], Rb@[39:32], Rc@[71:64];
//! hsel [75:74]/[61:60]/[82:81]; neg 72/63/84; abs 73/62/83; h0nh1@86;
//! b91 kill). census384 on the 2,406-cubin battery (34,087,886 words):
//! the era claims cover 420 real cublasLt sm_100 words; every hit renders
//! VENDOR-EXACT pre==post (census384x / arb384_post). Encode unchanged:
//! era keys never minted; the 5-token `HFMA2 R_,R_,R_,R_,R_` stays loud.
//! Precedent: BUG-165/173 dead-shell removal.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const DENSE: [&str; 2] = ["sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    DecodeIndex::build(t)
        .decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

/// BUG-383: comma-authored multi-mods mint byte-identical words to the
/// dot-authored spelling, on every leg — including reversed mod order (the
/// mod-group name is the sorted join in both spellings).
#[test]
fn t383_1_comma_dot_byte_parity_x4() {
    const PAIRS: [(&str, &str); 7] = [
        (
            "HFMA2.F32,FMZ R1, R2, UR4, R5",
            "HFMA2.F32.FMZ R1, R2, UR4, R5",
        ),
        (
            "HFMA2.BF16_V2,FMZ R1, R2, UR4, R5",
            "HFMA2.BF16_V2.FMZ R1, R2, UR4, R5",
        ),
        (
            "HFMA2.BF16_V2,FMZ,RELU R1, R2, UR4, R5",
            "HFMA2.BF16_V2.FMZ.RELU R1, R2, UR4, R5",
        ),
        (
            "HFMA2.FMZ,F32 R1, R2, UR4, R5",
            "HFMA2.F32.FMZ R1, R2, UR4, R5",
        ),
        (
            "HFMA2.F32,FMZ R1, R2, R3, R5",
            "HFMA2.F32.FMZ R1, R2, R3, R5",
        ),
        (
            "HFMA2.BF16_V2,FMZ R1, R2, R3, R5",
            "HFMA2.BF16_V2.FMZ R1, R2, R3, R5",
        ),
        (
            "@P3 HFMA2.F32,FTZ R1, R2, UR4, R5",
            "@P3 HFMA2.F32.FTZ R1, R2, UR4, R5",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (comma, dot) in PAIRS {
            let wc = enc(&t, comma)
                .unwrap_or_else(|e| panic!("{leg}: comma form rejected: {comma} — {e}"));
            let wd =
                enc(&t, dot).unwrap_or_else(|e| panic!("{leg}: dot form rejected: {dot} — {e}"));
            assert_eq!(
                wc & M96,
                wd & M96,
                "{leg}: comma/dot word drift: {comma} vs {dot}"
            );
        }
    }
}

/// BUG-383: exact minted words (regression lock on the mod bits b76/b78/
/// b79/b85 encoding): comma == dot == these exact payloads x4 legs.
#[test]
fn t383_2_comma_words_locked() {
    const W_F32_FMZ: u128 = 0x08005005_0000000402017c31u128;
    const W_BF16_FMZ_RELU: u128 = 0x0ba09005_0000000402017c31u128;
    for leg in LEGS {
        let t = tab(leg);
        assert_eq!(
            enc(&t, "HFMA2.F32,FMZ R1, R2, UR4, R5").unwrap() & M96,
            W_F32_FMZ,
            "{leg}: F32+FMZ word drift"
        );
        assert_eq!(
            enc(&t, "HFMA2.BF16_V2,FMZ,RELU R1, R2, UR4, R5").unwrap() & M96,
            W_BF16_FMZ_RELU,
            "{leg}: BF16_V2+FMZ+RELU word drift"
        );
    }
}

/// BUG-383: the pre-fix failure mode (Label-operand II_II routing) is gone;
/// unknown mods and empty comma segments stay fail-closed.
#[test]
fn t383_3_fail_closed_edges() {
    for leg in LEGS {
        let t = tab(leg);
        // no more II_II Label routing — the error (if any) must never be
        // the phantom-key one; this exact text mints:
        assert!(enc(&t, "HFMA2.F32,FMZ R1, R2, UR4, R5").is_ok(), "{leg}");
        // unknown mod stays loud:
        let e = enc(&t, "HFMA2.F32,NOTAMOD R1, R2, UR4, R5");
        assert!(e.is_err(), "{leg}: unknown comma mod must not mint");
        let msg = e.unwrap_err();
        assert!(
            !msg.contains("II_II"),
            "{leg}: failure must not route through phantom Label keys: {msg}"
        );
    }
}

/// BUG-384: the junk era keys are deleted on both dense legs; the sparse
/// legs never shipped them (394-kand stays the sparse-5-reg followup).
#[test]
fn t384_1_era_keys_deleted_dense() {
    for leg in DENSE {
        let t = tab(leg);
        assert!(!t.entries.contains_key("HFMA2.BF16_V2_R_R_R_R"), "{leg}");
        assert!(!t.entries.contains_key("HFMA2_R_R_R_R_R"), "{leg}");
    }
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(!t.entries.contains_key("HFMA2.BF16_V2_R_R_R_R"), "{leg}");
        assert!(!t.entries.contains_key("HFMA2_R_R_R_R_R"), "{leg}");
    }
}

/// BUG-384: era-shape words (H0_H0-baked family, corpus-witnessed) decode
/// vendor-exact on both dense legs post-delete, and roundtrip byte-exact.
/// CORP*: real cublasLt sm_100 battery words (census384 hits).
#[test]
fn t384_2_era_shapes_vendor_exact_roundtrip() {
    const WITNESS: [(u128, &str); 5] = [
        (
            0x0024080f_200000120e0e2231u128,
            "@P2 HFMA2.BF16_V2 R14, R14.H0_H0, R18.H0_H0, R15.H0_H0",
        ),
        (
            0x00240810_2000000c030c5231u128,
            "@P5 HFMA2.BF16_V2 R12, R3.H0_H0, R12.H0_H0, R16.H0_H0",
        ),
        (
            0x0004080a_200000111f0a4231u128,
            "@P4 HFMA2 R10, R31.H0_H0, R17.H0_H0, R10.H0_H0",
        ),
        (
            0x0000000000240800_2000000000000231u128 >> 0,
            "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0",
        ),
        (
            0x0000000000040802_200000011c024231u128 >> 0,
            "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0",
        ),
    ];
    for leg in DENSE {
        let t = tab(leg);
        for (w, want) in WITNESS {
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg}: HOLE on witness {w:#x}"));
            assert_eq!(&got, want, "{leg}: witness text drift {w:#x}");
            let back = enc(&t, &format!("@{got}")[1..]).unwrap();
            assert_eq!(back & M96, w, "{leg}: witness roundtrip drift {w:#x}");
        }
        // the pre-fix live WRONG cell: 5-reg row won this word and printed
        // garbage regs; post-delete the main row renders the vendor text
        // (inert b40, arb384 flip40 x2 legs):
        let base5: u128 = 0x0000000000040802_200000011c024231u128 >> 0;
        let got =
            dec(&t, base5 ^ (1 << 40)).unwrap_or_else(|| panic!("{leg}: HOLE on flip40 witness"));
        assert_eq!(&got, "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0");
    }
}

/// BUG-384: encode parity around the deletion — plain and dotted-authored
/// dense HFMA2 texts mint their main-row words unchanged; the 5-token
/// authored OVERCOUNT form stays loud (394-kand).
#[test]
fn t384_3_encode_parity_and_5tok_loud() {
    for leg in LEGS {
        let t = tab(leg);
        // main-row mint paths ride HFMA2_R_R_R_R / mg rows, untouched by
        // the era-key deletion:
        assert!(enc(&t, "HFMA2.BF16_V2 R1, R2, R3, R4").is_ok(), "{leg}");
        assert!(
            enc(&t, "HFMA2.BF16_V2.FMZ R1, R2, UR4, R5").is_ok(),
            "{leg}"
        );
        // 5-token over-count text must stay fail-closed on every leg:
        let e = enc(&t, "HFMA2 R1, R2, R3, R4, R5");
        assert!(e.is_err(), "{leg}: 5-token HFMA2 must not mint (394-kand)");
    }
}
