//! BUG-382 (F2-iter200, loop5/blind front2, 2026-09-04): SHFL stray-window
//! relax -- b63 + [90:88] write-inert na WSZYSTKICH graftowanych rodzinach
//! SHFL (RR x4 tryby, R_II x4, II_II x4, II_R x2) x4 nogi. Rejestracja
//! 382-kand LOW (368_369.md sec.6, F2-iter194; arb368 E w reku). Canonical
//! graft patch382.py (6742fdf -> 47e4ce4, tabele-only, ENGINE ZERO).
//!
//! LAW: arb382 98 sond (nvdisasm 13.3.73 raw -b, x4 modele
//! SM100a/SM103a/SM120/SM121a AGREE na KAZDEJ sondzie, DIVERGENT=0):
//! b63/b88/b89/b90 write-inert (junk word -> identyczny czysty tekst) na
//! kazdej rodzinie x trybie; ball-probe {63,88,89,90} inert; b91 = KILL
//! x4 na kazdej klasie (pin ZOSTAJE).
//! Pre-fix (publish cubit_py-f1f3dd78 caef5dea..; canonical 6742fdf;
//! measure_pre382.json): 224 ogniwa junk-bit LOUD HOLE x4 nogi, 0 cichego
//! misprintu; II_R IDX/BFLY mint REFUSE x4 = residuum no-claim (368 sec.6,
//! poza zakresem -- zostaje).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const RELAX: u128 = (1u128 << 63) | (0x7u128 << 88);

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

/// (key, mg, clean text, junk word templates share one mint)
#[test]
fn t382_1_structure_relax_rows_x4_legs() {
    let era: &[(&str, &[&str])] = &[
        ("SHFL_P_R_R_II_II", &["BFLY", "DOWN", "IDX", "UP"]),
        ("SHFL_P_R_R_II_R", &["DOWN", "UP"]),
        ("SHFL_P_R_R_R_II", &["BFLY", "DOWN", "IDX", "UP"]),
        ("SHFL_P_R_R_R_R", &["BFLY", "DOWN", "IDX", "UP"]),
    ];
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let mut n = 0;
        for (k, mgs) in era {
            for mg in *mgs {
                let g = &t.entries[*k].mod_groups[*mg];
                let vm = g.variable_mask;
                let mut fmask = 0u128;
                for f in &g.fields {
                    fmask |= ((1u128 << f.bits) - 1) << f.shift;
                }
                let care = M96 & !(vm | fmask);
                assert_eq!(care & RELAX, 0, "{leg} {k}[{mg}] relax bits still pinned");
                assert_eq!((care >> 91) & 1, 1, "{leg} {k}[{mg}] b91 kill-pin lost");
                n += 1;
            }
        }
        assert_eq!(n, 14, "{leg} era relax row count");
    }
    let t = tab("sm121a");
    let ka: &[(&str, &str)] = &[
        ("SHFL.BFLY_P_R_R_II_II", ""),
        ("SHFL_P_R_R_II_II", "DOWN"),
        ("SHFL_P_R_R_II_II", "IDX"),
        ("SHFL_P_R_R_II_II", "UP"),
        ("SHFL_P_R_R_II_R", "DOWN"),
        ("SHFL_P_R_R_II_R", "UP"),
        ("SHFL_P_R_R_R_II", "BFLY"),
        ("SHFL_P_R_R_R_II", "DOWN"),
        ("SHFL_P_R_R_R_II", "UP"),
        ("SHFL.IDX_P_R_R_R_II", ""),
        ("SHFL.BFLY_P_R_R_R_R", ""),
        ("SHFL_P_R_R_R_R", "BFLY"),
        ("SHFL_P_R_R_R_R", "DOWN"),
        ("SHFL_P_R_R_R_R", "IDX"),
        ("SHFL_P_R_R_R_R", "UP"),
    ];
    for (k, mg) in ka {
        let g = &t.entries[*k].mod_groups[*mg];
        let vm = g.variable_mask;
        let mut fmask = 0u128;
        for f in &g.fields {
            fmask |= ((1u128 << f.bits) - 1) << f.shift;
        }
        let care = M96 & !(vm | fmask);
        assert_eq!(care & RELAX, 0, "sm121a {k}[{mg}] relax bits still pinned");
        assert_eq!((care >> 91) & 1, 1, "sm121a {k}[{mg}] b91 kill-pin lost");
    }
    // '_?' residuum rows stay pinned (celowo nietkniete przez graft)
    for k in ["SHFL.BFLY_P_R_R_II_II_?", "SHFL.IDX_P_R_R_R_II_?"] {
        let g = &t.entries[k].mod_groups[""];
        let vm = g.variable_mask;
        assert_eq!(vm & RELAX, 0, "sm121a {k}[\'\'] residuum relaxed?!");
    }
}

#[test]
fn t382_2_vendor_junk_words_decode_clean_x4() {
    // Anchor words = mints on publish-era tables (arb382 clean anchors);
    // expected text = nvdisasm x4 unanimous canonical render.
    let cases: &[(u128, &str)] = &[
        (
            0x000fc200000000108c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200010000100c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200020000100c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200040000100c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200070000108c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200000000108000000b0a127389,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200040000100800000b0a127389,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ),
        (
            0x000fc200070000108400000b0a127389,
            "SHFL.UP P0, R18, R10, R11, R16",
        ),
        (
            0x000fc2000002000080001f0a170b7589,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ),
        (
            0x000fc2000702000084001f0a170b7589,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ),
        (
            0x000fc200000200008c001f0a170b7589,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ),
        (
            0x000fc200000000008fe00c0012097f89,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ),
        (
            0x000fc200070000008be00c0012097f89,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ),
        (
            0x000fc2000100000003e00c0012097f89,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ),
        (
            0x000fc2000200000007e00c0012097f89,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ),
        (
            0x000fc2000000001087e0000012097989,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ),
        (
            0x000fc200070000108be0000012097989,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ),
    ];
    for (w, text) in cases {
        for leg in LEGS {
            let t = tab(leg);
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg} HOLE on {w:#034x}"));
            assert_eq!(&got, *text, "{leg} wrong-text {w:#034x}");
        }
    }
}

#[test]
fn t382_3_mint_unchanged_and_roundtrip_clean() {
    for leg in LEGS {
        let t = tab(leg);
        for text in [
            "SHFL.BFLY P0, R18, R10, R11, R16",
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ] {
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg} REFUSE {text}: {e}"));
            assert_eq!(w & RELAX, 0, "{leg} mint leaks junk bits: {text}");
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg} redec HOLE {text}"));
            assert_eq!(&got, text, "{leg} roundtrip {text}");
        }
    }
}

#[test]
fn t382_4_b91_kill_stays_x4() {
    // jeden reprezentant na kazda rodzine (czyste minty publish-era);
    // b91 = KILL x4 modele na KAZDEJ klasie (arb382).
    let anchors: &[u128] = &[
        0x000fc200000000100c00000b0a127389, // RR BFLY
        0x000fc2000000000080001f0a170b7589, // R_II IDX
        0x000fc2000000000087e00c0012097f89, // II_II BFLY
        0x000fc2000000000087e0000012097989, // II_R UP
    ];
    for w0 in anchors {
        let w = w0 | (1u128 << 91);
        for leg in LEGS {
            let t = tab(leg);
            assert!(dec(&t, w).is_none(), "{leg} b91 kill claimed on {w:#034x}");
        }
    }
    // II_R IDX/BFLY absent x4 = residuum no-claim 358/368 sec.6: mint
    // musi zostac LOUD REFUSE (poza zakresem 382)
    for leg in LEGS {
        let t = tab(leg);
        for text in [
            "SHFL.IDX P0, R9, R18, 0x1f, R16",
            "SHFL.BFLY P0, R9, R18, 0x1f, R16",
        ] {
            assert!(enc(&t, text).is_err(), "{leg} II_R {text} minted?!");
        }
    }
}

#[test]
fn t382_5_flips_with_attribution_era_class() {
    // t303_5-class word (R_II b63 ghost, sm120-era encode class): pre-fix
    // loud HOLE; post-382 decodes to the clean vendor text (arb382
    // R_II-IDX-b63 x4 AGREE).
    let wghost = 0x000e000080001f0a170b7589u128;
    for leg in LEGS {
        let t = tab(leg);
        let got = dec(&t, wghost).unwrap_or_else(|| panic!("{leg} b63 R_II HOLE"));
        assert_eq!(
            &got, "SHFL.IDX PT, R11, R23, R10, 0x1f",
            "{leg} b63 wrong-text"
        );
    }
    // 368_369 era anchors stay byte-identical (no mint/text drift)
    let t = tab("sm103a");
    let w = enc(&t, "SHFL.BFLY P0, R18, R10, R11, R16").unwrap();
    assert_eq!(
        w & M96,
        0x000fc200000000100c00000b0a127389 & M96,
        "era BFLY mint drift"
    );
}
