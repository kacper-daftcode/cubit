//! BUG-368 (F2-iter194, loop5/blind front2, 2026-09-04): SHFL R-form
//! (b1 0x73) closure -- [57:40]=0 window pin -> vm-relax x4 nogi +
//! sm121a UP mg pred repair (4,12)->(3,81) + sm121a DOWN/IDX mg
//! completion (klony z UP-patched, mode pinned). Rejestracja 368-kand
//! LOW (358.md sec.6, F2-iter185; arb358 A-b173). Canonical graft
//! patch368_369.py (0933cf6 -> c913faa), ride-after d31adfa7/BUG-367.
//!
//! LAW: arb368 40 sond + arb358 73 sondy (nvdisasm 13.3.73 raw -b, x4
//! modele SM100a/SM103a/SM120/SM121a AGREE on EVERY probe, DIVERGENT=0):
//! [57:40] write-inert na R-form x4 modes x junk {0xc0c0,0x201f,0x3ffff};
//! pred[83:81] legalne na R-form x4; guard niezalezny od pred/junk;
//! R-form DOWN/IDX vendor-legal x4 takze z max junk (arb368 G).
//! Pre-fix (publish cubit_py-d31adfa7 0aac6654..; canonical 0933cf6;
//! work/bug368_369/measure_pre368_369.json): RR-junk HOLE x4 nogi;
//! sm121a RR-clean UP pred<PT HOLE + IDX/DOWN HOLE (brak mg); era
//! RR-clean OK. NOT grafted: era+121a [63] pin = 382-kand LOW (E-b63
//! vendor-inert, loud HOLE stoi), II_R IDX/BFLY residuum (358, pin w
//! t368_4).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

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
fn has_pred81(t: &IsaTable, key: &str, mg: &str) -> bool {
    t.entries[key].mod_groups[mg].fields.iter().any(|f| {
        f.extraction == Extraction::Pred && f.shift == 81 && f.bits == 3 && f.token_idx == 1
    })
}
fn care(t: &IsaTable, key: &str, mg: &str) -> u128 {
    let m = &t.entries[key].mod_groups[mg];
    let mut fmask = 0u128;
    for f in &m.fields {
        fmask |= ((1u128 << f.bits) - 1) << f.shift;
    }
    M96 & !(m.variable_mask | fmask)
}

#[test]
fn t368_1_structure_vm_relax_and_121a_completion() {
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        for (mg, mode) in [("BFLY", 3u128), ("DOWN", 2), ("IDX", 0), ("UP", 1)] {
            let c = care(&t, "SHFL_P_R_R_R_R", mg);
            assert_eq!((c >> 40) & 0x3ffff, 0, "{leg} R-form[{mg}] [57:40] pinned");
            assert_eq!((c >> 58) & 3, 3, "{leg} R-form[{mg}] mode not pinned");
            let ab = t.entries["SHFL_P_R_R_R_R"].mod_groups[mg].and_base;
            assert_eq!((ab >> 58) & 3, mode, "{leg} R-form[{mg}] mode value");
            assert!(
                has_pred81(&t, "SHFL_P_R_R_R_R", mg),
                "{leg} R-form[{mg}] pred81 missing"
            );
        }
    }
    let t = tab("sm121a");
    for (key, mg, mode) in [
        ("SHFL.BFLY_P_R_R_R_R", "", 3u128),
        ("SHFL_P_R_R_R_R", "BFLY", 3),
        ("SHFL_P_R_R_R_R", "UP", 1),
        ("SHFL_P_R_R_R_R", "DOWN", 2),
        ("SHFL_P_R_R_R_R", "IDX", 0),
    ] {
        let c = care(&t, key, mg);
        assert_eq!((c >> 40) & 0x3ffff, 0, "121a {key}[{mg}] [57:40] pinned");
        assert_eq!((c >> 58) & 3, 3, "121a {key}[{mg}] mode not pinned");
        let ab = t.entries[key].mod_groups[mg].and_base;
        assert_eq!((ab >> 58) & 3, mode, "121a {key}[{mg}] mode value");
        assert!(has_pred81(&t, key, mg), "121a {key}[{mg}] pred81 missing");
        assert!(
            !t.entries[key].mod_groups[mg]
                .fields
                .iter()
                .any(|f| f.extraction == Extraction::Pred && f.shift == 12),
            "121a {key}[{mg}] bad pred (4,12) still present"
        );
    }
    // 121a II-form nietkniete przez 368 (stan 358): UP II_II pred81 stoi
    assert!(
        has_pred81(&t, "SHFL_P_R_R_II_II", "UP"),
        "121a II_II[UP] pred81 drifted"
    );
}

#[test]
fn t368_2_decode_vendor_law_rr_battery() {
    let cases: &[(u128, &str)] = &[
        (
            0x6400000000100000000b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // RR-IDX-p0-j0
        (
            0x64000000001000201f0b0a127389u128,
            "SHFL.IDX P0, R18, R10, R11, R16",
        ), // RR-IDX-p0-j201f
        (
            0x6400000c00100000000b0a127389u128,
            "SHFL.IDX P6, R18, R10, R11, R16",
        ), // RR-IDX-p6-j0
        (
            0x6400000c001000201f0b0a127389u128,
            "SHFL.IDX P6, R18, R10, R11, R16",
        ), // RR-IDX-p6-j201f
        (
            0x6400000e00100000000b0a127389u128,
            "SHFL.IDX PT, R18, R10, R11, R16",
        ), // RR-IDX-p7-j0
        (
            0x6400000e001000201f0b0a127389u128,
            "SHFL.IDX PT, R18, R10, R11, R16",
        ), // RR-IDX-p7-j201f
        (
            0x6400000000100400000b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // RR-UP-p0-j0
        (
            0x64000000001004201f0b0a127389u128,
            "SHFL.UP P0, R18, R10, R11, R16",
        ), // RR-UP-p0-j201f
        (
            0x6400000c00100400000b0a127389u128,
            "SHFL.UP P6, R18, R10, R11, R16",
        ), // RR-UP-p6-j0
        (
            0x6400000c001004201f0b0a127389u128,
            "SHFL.UP P6, R18, R10, R11, R16",
        ), // RR-UP-p6-j201f
        (
            0x6400000e00100400000b0a127389u128,
            "SHFL.UP PT, R18, R10, R11, R16",
        ), // RR-UP-p7-j0
        (
            0x6400000e001004201f0b0a127389u128,
            "SHFL.UP PT, R18, R10, R11, R16",
        ), // RR-UP-p7-j201f
        (
            0x6400000000100800000b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // RR-DOWN-p0-j0
        (
            0x64000000001008201f0b0a127389u128,
            "SHFL.DOWN P0, R18, R10, R11, R16",
        ), // RR-DOWN-p0-j201f
        (
            0x6400000c00100800000b0a127389u128,
            "SHFL.DOWN P6, R18, R10, R11, R16",
        ), // RR-DOWN-p6-j0
        (
            0x6400000c001008201f0b0a127389u128,
            "SHFL.DOWN P6, R18, R10, R11, R16",
        ), // RR-DOWN-p6-j201f
        (
            0x6400000e00100800000b0a127389u128,
            "SHFL.DOWN PT, R18, R10, R11, R16",
        ), // RR-DOWN-p7-j0
        (
            0x6400000e001008201f0b0a127389u128,
            "SHFL.DOWN PT, R18, R10, R11, R16",
        ), // RR-DOWN-p7-j201f
        (
            0x6400000000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // RR-BFLY-p0-j0
        (
            0x6400000000100c201f0b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // RR-BFLY-p0-j201f
        (
            0x6400000c00100c00000b0a127389u128,
            "SHFL.BFLY P6, R18, R10, R11, R16",
        ), // RR-BFLY-p6-j0
        (
            0x6400000c00100c201f0b0a127389u128,
            "SHFL.BFLY P6, R18, R10, R11, R16",
        ), // RR-BFLY-p6-j201f
        (
            0x6400000e00100c00000b0a127389u128,
            "SHFL.BFLY PT, R18, R10, R11, R16",
        ), // RR-BFLY-p7-j0
        (
            0x6400000e00100c201f0b0a127389u128,
            "SHFL.BFLY PT, R18, R10, R11, R16",
        ), // RR-BFLY-p7-j201f
        (
            0x6400000200100c201f0b0a129389u128,
            "@!P1 SHFL.BFLY P1, R18, R10, R11, R16",
        ), // RR-BFLY-guardN1-p1-j
    ];
    for leg in LEGS {
        let t = tab(leg);
        for &(w, want) in cases {
            let got = dec(&t, w);
            assert_eq!(got.as_deref(), Some(want), "{leg} word {w:#034x}");
        }
    }
}

#[test]
fn t368_3_mints_word_exact_cross_leg() {
    let texts: &[&str] = &[
        "SHFL.BFLY P0, R18, R10, R11, R16",
        "SHFL.UP P1, R18, R10, R11, R16",
        "SHFL.DOWN P2, R18, R10, R11, R16",
        "SHFL.IDX P3, R18, R10, R11, R16",
        "SHFL.BFLY PT, R18, R10, R11, R16",
        "SHFL.IDX PT, R18, R10, R11, R16",
        "@P1 SHFL.UP P1, R18, R10, R11, R16",
        "@!P2 SHFL.DOWN PT, R18, R10, R11, R16",
    ];
    for text in texts {
        let mut ws = Vec::new();
        for leg in LEGS {
            let t = tab(leg);
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg} REFUSE {text}: {e}"));
            let got = dec(&t, w).unwrap_or_else(|| panic!("{leg} redec HOLE {text}"));
            assert_eq!(&got, text, "{leg} roundtrip {text}");
            ws.push(w);
        }
        assert!(
            ws.windows(2).all(|p| p[0] == p[1]),
            "cross-leg word drift {text}: {ws:#x?}"
        );
    }
}

#[test]
fn t368_4_fail_closed_stays() {
    for leg in LEGS {
        let t = tab(leg);
        // b91 = vendor kill (arb368 E-b91 rc=1 x4 modele): HOLE musi stac
        let w = 0x00006400000000100c00000b0a127389u128 | (1u128 << 91);
        assert!(dec(&t, w).is_none(), "{leg} b91 kill claimed");
        // 382-kand: era+121a [63] pin stoi (E-b63 vendor-inert): tylko
        // loud HOLE albo poprawny IDX claim -- NIGDY wrong-text
        let mut w2 = 0x00006400000000100c00000b0a127389u128 & !(0x3u128 << 58);
        w2 |= 1u128 << 63;
        let got = dec(&t, w2);
        assert!(
            got.is_none() || got.clone().unwrap().starts_with("SHFL.IDX"),
            "{leg} b63 word misclaimed: {got:?}"
        );
    }
    // II_R IDX/BFLY absent x4 = residuum 358 (vendor-legal, brak donora)
    let t = tab("sm121a");
    let wbfly_ii = 0x000e6400000e00000c201f0009127f89u128;
    for mode in [0u128, 3] {
        let w = (wbfly_ii & !(0xffu128 << 8) & !(0x3u128 << 58)) | (0x79u128 << 8) | (mode << 58);
        let got = dec(&t, w & !((0x3fffu128) << 40) & !((0xffu128) << 64));
        assert!(
            got.is_none() || !got.unwrap().contains(", R0"),
            "II_R absent-mode word must not surface as II_R (mode {mode})"
        );
    }
}

#[test]
fn t368_5_corpus_anchors_no_drift_x4() {
    // SHFL R-form corpus anchors (bug333 census, battery ab240) x4 nogi
    let anchors: &[(u128, &str)] = &[
        (
            0x00006400000000100c00000b0a127389u128,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x00006400000000140c000013121a7389u128,
            "SHFL.BFLY P0, R26, R18, R19, R20",
        ),
        (
            0x0002a400000000140c0000131c167389u128,
            "SHFL.BFLY P0, R22, R28, R19, R20",
        ),
        (
            0x0002a400000000140c00001312177389u128,
            "SHFL.BFLY P0, R23, R18, R19, R20",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for &(w, want) in anchors {
            let got = dec(&t, w);
            assert_eq!(got.as_deref(), Some(want), "{leg} anchor drift {w:#034x}");
        }
    }
}
