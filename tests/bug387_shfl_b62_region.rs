//! BUG-387 (F2-iter206, loop5/blind front2, 2026-09-05): SHFL b62-region
//! stray-window relax -- [62:61] write-inert na WSZYSTKICH graftowanych
//! rodzinach SHFL (RR x4 tryby, R_II x4, II_II x4, II_R x2) x4 nogi (b63
//! nosi BUG-382). Rejestracja 387-kand LOW (382.md sec.7, F2-iter200).
//! Canonical graft patch387.py (9713fd6 -> 93bc221, tabele-only, ENGINE ZERO).
//!
//! LAW: arb387 280 sond (28 ksztaltow = 14 rodzin x 2 warianty wartosci,
//! nvdisasm 13.3.73 raw -b, x4 modele SM100a/SM103a/SM120/SM121a AGREE na
//! KAZDEJ sondzie, DIVERGENT=0) + arb387b (okno [95:92], t225 exact-words):
//! b62 + b61 write-inert na kazdej rodzinie x trybie x wariancie; combo
//! b62|b63 + b62|ball(63,[90:88]) inert; b64/b65 = LIVE reg-c field [71:64]
//! na RR/II_R (render zmienia, granica dolna okna); b91 = KILL x4 na kazdej
//! klasie (pin ZOSTAJE); b92..b95 inert = okno [95:92] POZA zakresem 387
//! (pin ZOSTAJE) -> 396-kand.
//! Pre-fix (publish cubit_py-042ffa91 6748f0c8..; canonical 9713fd6;
//! measure_pre387.json): 56 ogniw b62 + 56 ogniw b61 LOUD HOLE x4 nogi,
//! 0 cichego misprintu; II_R IDX/BFLY mint REFUSE x4 = residuum no-claim
//! 358/368 sec.6 (poza zakresem -- zostaje).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const RELAX: u128 = (1u128 << 61) | (1u128 << 62);
const RELAXW: u128 = RELAX | (1u128 << 63);

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

#[test]
fn t387_1_structure_relax_rows_x4_legs() {
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
                assert_eq!(
                    care & RELAXW,
                    0,
                    "{leg} {k}[{mg}] window [63:61] still pinned"
                );
                assert_eq!((care >> 91) & 1, 1, "{leg} {k}[{mg}] b91 kill-pin lost");
                // po BUG-396 (graft c155d00, iter207): deferral 396-kand
                // WYKONANY -- okno [95:92] zrelaksowane na tych samych 57
                // wierszach -> care & (0xf<<92) == 0.
                assert_eq!(
                    care & (0xfu128 << 92),
                    0,
                    "{leg} {k}[{mg}] [95:92] relax (BUG-396) lost"
                );
                assert_eq!(RELAX & fmask, 0, "{leg} {k}[{mg}] relax overlaps fields");
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
        assert_eq!(
            care & RELAXW,
            0,
            "sm121a {k}[{mg}] window [63:61] still pinned"
        );
        assert_eq!((care >> 91) & 1, 1, "sm121a {k}[{mg}] b91 kill-pin lost");
        // po BUG-396 (graft c155d00): [95:92] zrelaksowane -> care==0.
        assert_eq!(
            care & (0xfu128 << 92),
            0,
            "sm121a {k}[{mg}] [95:92] relax (BUG-396) lost"
        );
    }
    // '_?' residuum rows stay pinned w.r.t. [62:61] (celowo nietkniete)
    for k in ["SHFL.BFLY_P_R_R_II_II_?", "SHFL.IDX_P_R_R_R_II_?"] {
        let g = &t.entries[k].mod_groups[""];
        let vm = g.variable_mask;
        assert_eq!(vm & RELAX, 0, "sm121a {k} residuum relaxed?!");
    }
}

#[test]
fn t387_2_vendor_junk_words_decode_clean_x4() {
    // Machine-generated arb-verbatim pins (work/bug387/pin_words387.json;
    // cross-checked vs arb387_verdicts.json): b62/b61/b62+b63 junk words
    // per rodzina x tryb; expected text = nvdisasm x4 unanimous canonical
    // render == clean anchor text.
    let cases: &[(u128, &str)] = &[
        (
            0xfc200000000004fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // II_II-BFLY-b62
        (
            0xfc200000000002fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // II_II-BFLY-b61
        (
            0xfc200000000006fe00c0012097f89u128,
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
        ), // II_II-BFLY-b6263
        (
            0xfc200000000004be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // II_II-DOWN-b62
        (
            0xfc200000000002be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // II_II-DOWN-b61
        (
            0xfc200000000006be00c0012097f89u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
        ), // II_II-DOWN-b6263
        (
            0xfc2000000000043e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // II_II-IDX-b62
        (
            0xfc2000000000023e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // II_II-IDX-b61
        (
            0xfc2000000000063e00c0012097f89u128,
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
        ), // II_II-IDX-b6263
        (
            0xfc2000000000047e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // II_II-UP-b62
        (
            0xfc2000000000027e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // II_II-UP-b61
        (
            0xfc2000000000067e00c0012097f89u128,
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
        ), // II_II-UP-b6263
        (
            0xfc200000000104be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // II_R-DOWN-b62
        (
            0xfc200000000102be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // II_R-DOWN-b61
        (
            0xfc200000000106be0000012097989u128,
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
        ), // II_R-DOWN-b6263
        (
            0xfc2000000001047e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // II_R-UP-b62
        (
            0xfc2000000001027e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // II_R-UP-b61
        (
            0xfc2000000001067e0000012097989u128,
            "SHFL.UP P0, R9, R18, 0x1f, R16",
        ), // II_R-UP-b6263
        (
            0xfc200000000104c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // RR-BFLY-b62
        (
            0xfc200000000102c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // RR-BFLY-b61
        (
            0xfc200000000106c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // RR-BFLY-b6263
        (
            0xfc200000000104800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // RR-DOWN-b62
        (
            0xfc200000000102800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // RR-DOWN-b61
        (
            0xfc200000000106800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // RR-DOWN-b6263
        (
            0xfc200000000104000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // RR-IDX-b62
        (
            0xfc200000000102000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // RR-IDX-b61
        (
            0xfc200000000106000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // RR-IDX-b6263
        (
            0xfc200000000104400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // RR-UP-b62
        (
            0xfc200000000102400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // RR-UP-b61
        (
            0xfc200000000106400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // RR-UP-b6263
        (
            0xfc200000200004c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // R_II-BFLY-b62
        (
            0xfc200000200002c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // R_II-BFLY-b61
        (
            0xfc200000200006c001f0a170b7589u128,
            "SHFL.BFLY P1, R11, R23, R10, 0x1f",
        ), // R_II-BFLY-b6263
        (
            0xfc2000002000048001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // R_II-DOWN-b62
        (
            0xfc2000002000028001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // R_II-DOWN-b61
        (
            0xfc2000002000068001f0a170b7589u128,
            "SHFL.DOWN P1, R11, R23, R10, 0x1f",
        ), // R_II-DOWN-b6263
        (
            0xfc2000002000040001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // R_II-IDX-b62
        (
            0xfc2000002000020001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // R_II-IDX-b61
        (
            0xfc2000002000060001f0a170b7589u128,
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
        ), // R_II-IDX-b6263
        (
            0xfc2000002000044001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // R_II-UP-b62
        (
            0xfc2000002000024001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // R_II-UP-b61
        (
            0xfc2000002000064001f0a170b7589u128,
            "SHFL.UP P1, R11, R23, R10, 0x1f",
        ), // R_II-UP-b6263
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
fn t387_3_mint_unchanged_and_roundtrip_clean() {
    let anchors: &[(&str, u128)] = &[
        (
            "SHFL.BFLY P0, R18, R10, R11, R16",
            0x000fc200000000100c00000b0a127389,
        ),
        (
            "SHFL.IDX P0, R18, R10, R11, R16",
            0x000fc200000000100000000b0a127389,
        ),
        (
            "SHFL.DOWN P0, R18, R10, R11, R16",
            0x000fc200000000100800000b0a127389,
        ),
        (
            "SHFL.UP P0, R18, R10, R11, R16",
            0x000fc200000000100400000b0a127389,
        ),
        (
            "SHFL.IDX P1, R11, R23, R10, 0x1f",
            0x000fc2000002000000001f0a170b7589,
        ),
        (
            "SHFL.DOWN P0, R9, R18, 0x1f, 0xc",
            0x000fc200000000000be00c0012097f89,
        ),
        (
            "SHFL.UP P0, R9, R18, 0x1f, 0xc",
            0x000fc2000000000007e00c0012097f89,
        ),
        (
            "SHFL.BFLY P0, R9, R18, 0x1f, 0xc",
            0x000fc200000000000fe00c0012097f89,
        ),
        (
            "SHFL.IDX P0, R9, R18, 0x1f, 0xc",
            0x000fc2000000000003e00c0012097f89,
        ),
        (
            "SHFL.DOWN P0, R9, R18, 0x1f, R16",
            0x000fc200000000100be0000012097989,
        ),
        (
            "SHFL.UP P0, R9, R18, 0x1f, R16",
            0x000fc2000000001007e0000012097989,
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (text, want) in anchors {
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg} REFUSE {text}: {e}"));
            assert_eq!(w & M96, want & M96, "{leg} mint drift: {text}");
            assert_eq!(
                w & (0x7u128 << 61),
                0,
                "{leg} mint leaks [63:61] junk: {text}"
            );
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg} redec HOLE {text}"));
            assert_eq!(&got, *text, "{leg} roundtrip {text}");
        }
    }
}

#[test]
fn t387_4_kill_deferral_and_field_boundary_x4() {
    // b91 = KILL x4 na kazdej klasie (arb387 28/28 rc!=0 x4).
    let anchors: &[u128] = &[
        0x000fc200000000100c00000b0a127389, // RR BFLY
        0x000fc2000002000000001f0a170b7589, // R_II IDX
        0x000fc200000000000fe00c0012097f89, // II_II BFLY
        0x000fc2000000001007e0000012097989, // II_R UP
    ];
    for w0 in anchors {
        let w = w0 | (1u128 << 91);
        for leg in LEGS {
            let t = tab(leg);
            assert!(dec(&t, w).is_none(), "{leg} b91 kill claimed on {w:#034x}");
        }
    }
    // okno [95:92] (dawny deferral 396-kand) -- po BUG-396 (graft
    // c155d00, iter207; prawo arb387/arb387b + kompozycja arb396):
    // single b92..b95 dekoduja do czystego tekstu kotwicy x4.
    for b in [92u32, 93, 94, 95] {
        let w = 0x000fc200000000100c00000b0a127389u128 | (1u128 << b);
        for leg in LEGS {
            let t = tab(leg);
            let got =
                dec(&t, w).unwrap_or_else(|| panic!("{leg} b{b} [95:92] HOLE post-396 {w:#034x}"));
            assert_eq!(
                &got, "SHFL.BFLY P0, R18, R10, R11, R16",
                "{leg} b{b} [95:92] wrong-text {w:#034x}"
            );
        }
    }
    // granica dolna okna: b64/b65 = LIVE reg-c field [71:64] na RR/II_R;
    // pole musi renderowac rejestr (nie byc skonsumowane relaxem).
    let rr_down = 0x000fc200000000100800000b0a127389u128;
    for leg in LEGS {
        let t = tab(leg);
        let got = dec(&t, rr_down | (1u128 << 64)).unwrap();
        assert_eq!(
            &got, "SHFL.DOWN P0, R18, R10, R11, R17",
            "{leg} b64 field lost"
        );
        let got = dec(&t, rr_down | (1u128 << 65)).unwrap();
        assert_eq!(
            &got, "SHFL.DOWN P0, R18, R10, R11, R18",
            "{leg} b65 field lost"
        );
    }
}

#[test]
fn t387_5_flips_with_attribution_era_class() {
    // t225_3-class: dawny NEG wpis SHFL b62 przechodzi na vendor-parity
    // (pelny zestaw w t225_3c); tu: combo window [63:61] na tej bazie.
    let w0 = 0x000000000800000000007f89u128 ^ (7u128 << 61);
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let got = dec(&t, w0).unwrap_or_else(|| panic!("{leg} t225-window HOLE"));
        assert_eq!(&got, "SHFL.DOWN P0, R0, R0, 0x0, 0x0", "{leg} wrong-text");
    }
    // II_R IDX/BFLY absent x4 = residuum no-claim 358/368 sec.6: mint musi
    // zostac LOUD REFUSE (poza zakresem 387)
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
