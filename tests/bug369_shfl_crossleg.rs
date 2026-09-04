//! BUG-369 (F2-iter194, loop5/blind front2, 2026-09-04): cross-leg
//! SHFL II-form over-strict + mode-junk SILENT MISPRINT closure na
//! sm100a/sm103a/sm120 = lustro graftu 358 (sm121a). Rejestracja
//! 369-kand LOW (358.md sec.6, F2-iter185). Canonical patch368_369.py
//! (0933cf6 -> c913faa), ride-after d31adfa7/BUG-367. sm121a II-form
//! byte-invariant (asserted in patch).
//!
//! LAW: arb358 73 sondy + arb368 40 sond (nvdisasm 13.3.73 raw -b, x4
//! modele AGREE EVERY probe, DIVERGENT=0): pred[83:81] legal x4 na
//! II-form; [71:64] write-inert na tok5-imm (jug64); [52:40] inert na
//! II_R; lane5@[57:53] inert na R_II; mode@[59:58]=IDX/UP/DOWN/BFLY.
//! Pre-fix (publish cubit_py-d31adfa7; canonical 0933cf6;
//! work/bug368_369/measure_pre368_369.json): decode HOLE pred<PT IIII
//! {IDX,UP,BFLY} + R_II x4 na 100a/103a (+RII+IIR HOLE na sm120);
//! SILENT MISPRINT mode-junk x3 nogi ('0x21'/'0x4001f'/'0x1400001f' --
//! era II_II[IDX] imm28@53 + DOWN imm6@53 (b58 pod polem) + R_II[IDX]
//! imm32@40 claim-empire); encode intent-drop pred->PT + cicha
//! BFLY->DOWN x2 nogi era; REFUSE R_II UP/DOWN/BFLY x3 nogi.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const LEGS3: [&str; 3] = ["sm100a", "sm103a", "sm120"];
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

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
fn care(t: &IsaTable, key: &str, mg: &str) -> u128 {
    let m = &t.entries[key].mod_groups[mg];
    let mut fmask = 0u128;
    for f in &m.fields {
        fmask |= ((1u128 << f.bits) - 1) << f.shift;
    }
    M96 & !(m.variable_mask | fmask)
}
fn has_pred81(t: &IsaTable, key: &str, mg: &str) -> bool {
    t.entries[key].mod_groups[mg].fields.iter().any(|f| {
        f.extraction == Extraction::Pred && f.shift == 81 && f.bits == 3 && f.token_idx == 1
    })
}
fn has_imm(t: &IsaTable, key: &str, mg: &str, bits: u32, shift: u32, tok: i32) -> bool {
    t.entries[key].mod_groups[mg].fields.iter().any(|f| {
        f.extraction == Extraction::Imm && f.bits == bits && f.shift == shift && f.token_idx == tok
    })
}

#[test]
fn t369_1_structure_post_shape_x3() {
    for leg in LEGS3 {
        let t = tab(leg);
        for (mg, mode) in [("BFLY", 3u128), ("IDX", 0), ("UP", 1), ("DOWN", 2)] {
            let c = care(&t, "SHFL_P_R_R_II_II", mg);
            assert!(
                has_pred81(&t, "SHFL_P_R_R_II_II", mg),
                "{leg} II_II[{mg}] pred81"
            );
            assert_eq!((c >> 81) & 7, 0, "{leg} II_II[{mg}] pred pinned");
            assert_eq!((c >> 58) & 3, 3, "{leg} II_II[{mg}] mode not pinned");
            let ab = t.entries["SHFL_P_R_R_II_II"].mod_groups[mg].and_base;
            assert_eq!((ab >> 58) & 3, mode, "{leg} II_II[{mg}] mode value");
            assert_eq!((c >> 64) & 0xff, 0, "{leg} II_II[{mg}] [71:64] pinned");
            assert!(
                has_imm(&t, "SHFL_P_R_R_II_II", mg, 5, 53, 4),
                "{leg} II_II[{mg}] imm5 tok4"
            );
            assert!(
                has_imm(&t, "SHFL_P_R_R_II_II", mg, 13, 40, 5),
                "{leg} II_II[{mg}] imm13 tok5"
            );
            assert!(
                !has_imm(&t, "SHFL_P_R_R_II_II", mg, 28, 53, 4)
                    && !has_imm(&t, "SHFL_P_R_R_II_II", mg, 6, 53, 4),
                "{leg} II_II[{mg}] junk imm width still there"
            );
        }
        for (mg, mode) in [("IDX", 0u128), ("UP", 1), ("DOWN", 2), ("BFLY", 3)] {
            let c = care(&t, "SHFL_P_R_R_R_II", mg);
            assert!(
                has_pred81(&t, "SHFL_P_R_R_R_II", mg),
                "{leg} R_II[{mg}] pred81"
            );
            assert_eq!((c >> 58) & 3, 3, "{leg} R_II[{mg}] mode not pinned");
            let ab = t.entries["SHFL_P_R_R_R_II"].mod_groups[mg].and_base;
            assert_eq!((ab >> 58) & 3, mode, "{leg} R_II[{mg}] mode value");
            assert_eq!((c >> 64) & 0xff, 0, "{leg} R_II[{mg}] [71:64] pinned");
            assert_eq!((c >> 53) & 0x1f, 0, "{leg} R_II[{mg}] lane5 pinned");
            assert!(
                has_imm(&t, "SHFL_P_R_R_R_II", mg, 13, 40, 5),
                "{leg} R_II[{mg}] imm13 tok5"
            );
            assert!(
                !has_imm(&t, "SHFL_P_R_R_R_II", mg, 32, 40, 5),
                "{leg} R_II[{mg}] imm32 still there"
            );
        }
        for (mg, mode) in [("UP", 1u128), ("DOWN", 2)] {
            let c = care(&t, "SHFL_P_R_R_II_R", mg);
            assert_eq!((c >> 40) & 0x1fff, 0, "{leg} II_R[{mg}] [52:40] pinned");
            assert!(
                has_imm(&t, "SHFL_P_R_R_II_R", mg, 5, 53, 4),
                "{leg} II_R[{mg}] imm5 tok4"
            );
            assert!(
                !has_imm(&t, "SHFL_P_R_R_II_R", mg, 6, 53, 4),
                "{leg} II_R[{mg}] imm6 still there"
            );
            let ab = t.entries["SHFL_P_R_R_II_R"].mod_groups[mg].and_base;
            assert_eq!((ab >> 58) & 3, mode, "{leg} II_R[{mg}] mode value");
        }
    }
}

#[test]
fn t369_2_decode_vendor_law_ii_battery_x3() {
    let cases: &[(u128, &str)] = &[
        (
            0xe64000000000000201f0009127f89u128,
            "SHFL.IDX P0, R18, R9, 0x1, 0x1f",
        ), // IIII-IDX-p0
        (
            0xe6400000c000000201f0009127f89u128,
            "SHFL.IDX P6, R18, R9, 0x1, 0x1f",
        ), // IIII-IDX-p6
        (
            0xe6400000e000000201f0009127f89u128,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // IIII-IDX-p7
        (
            0xe6400000e001400201f0009127f89u128,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // IIII-IDX-jug64
        (
            0x4e24000000000000001f0c09057589u128,
            "SHFL.IDX P0, R5, R9, R12, 0x1f",
        ), // RII-IDX-p0
        (
            0x4e2400000c000000001f0c09057589u128,
            "SHFL.IDX P6, R5, R9, R12, 0x1f",
        ), // RII-IDX-p6
        (
            0x4e2400000e000000001f0c09057589u128,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // RII-IDX-p7
        (
            0x4e2400000e001400001f0c09057589u128,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // RII-IDX-jug64
        (
            0xe64000000000004201f0009127f89u128,
            "SHFL.UP P0, R18, R9, 0x1, 0x1f",
        ), // IIII-UP-p0
        (
            0xe6400000c000004201f0009127f89u128,
            "SHFL.UP P6, R18, R9, 0x1, 0x1f",
        ), // IIII-UP-p6
        (
            0xe6400000e000004201f0009127f89u128,
            "SHFL.UP PT, R18, R9, 0x1, 0x1f",
        ), // IIII-UP-p7
        (
            0xe6400000e001404201f0009127f89u128,
            "SHFL.UP PT, R18, R9, 0x1, 0x1f",
        ), // IIII-UP-jug64
        (
            0x4e24000000000004001f0c09057589u128,
            "SHFL.UP P0, R5, R9, R12, 0x1f",
        ), // RII-UP-p0
        (
            0x4e2400000c000004001f0c09057589u128,
            "SHFL.UP P6, R5, R9, R12, 0x1f",
        ), // RII-UP-p6
        (
            0x4e2400000e000004001f0c09057589u128,
            "SHFL.UP PT, R5, R9, R12, 0x1f",
        ), // RII-UP-p7
        (
            0x4e2400000e001404001f0c09057589u128,
            "SHFL.UP PT, R5, R9, R12, 0x1f",
        ), // RII-UP-jug64
        (
            0xe64000000000008201f0009127f89u128,
            "SHFL.DOWN P0, R18, R9, 0x1, 0x1f",
        ), // IIII-DOWN-p0
        (
            0xe6400000c000008201f0009127f89u128,
            "SHFL.DOWN P6, R18, R9, 0x1, 0x1f",
        ), // IIII-DOWN-p6
        (
            0xe6400000e000008201f0009127f89u128,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // IIII-DOWN-p7
        (
            0xe6400000e001408201f0009127f89u128,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // IIII-DOWN-jug64
        (
            0x4e24000000000008001f0c09057589u128,
            "SHFL.DOWN P0, R5, R9, R12, 0x1f",
        ), // RII-DOWN-p0
        (
            0x4e2400000c000008001f0c09057589u128,
            "SHFL.DOWN P6, R5, R9, R12, 0x1f",
        ), // RII-DOWN-p6
        (
            0x4e2400000e000008001f0c09057589u128,
            "SHFL.DOWN PT, R5, R9, R12, 0x1f",
        ), // RII-DOWN-p7
        (
            0x4e2400000e001408001f0c09057589u128,
            "SHFL.DOWN PT, R5, R9, R12, 0x1f",
        ), // RII-DOWN-jug64
        (
            0xe6400000000000c201f0009127f89u128,
            "SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
        ), // IIII-BFLY-p0
        (
            0xe6400000c00000c201f0009127f89u128,
            "SHFL.BFLY P6, R18, R9, 0x1, 0x1f",
        ), // IIII-BFLY-p6
        (
            0xe6400000e00000c201f0009127f89u128,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // IIII-BFLY-p7
        (
            0xe6400000e00140c201f0009127f89u128,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // IIII-BFLY-jug64
        (
            0x4e2400000000000c001f0c09057589u128,
            "SHFL.BFLY P0, R5, R9, R12, 0x1f",
        ), // RII-BFLY-p0
        (
            0x4e2400000c00000c001f0c09057589u128,
            "SHFL.BFLY P6, R5, R9, R12, 0x1f",
        ), // RII-BFLY-p6
        (
            0x4e2400000e00000c001f0c09057589u128,
            "SHFL.BFLY PT, R5, R9, R12, 0x1f",
        ), // RII-BFLY-p7
        (
            0x4e2400000e00140c001f0c09057589u128,
            "SHFL.BFLY PT, R5, R9, R12, 0x1f",
        ), // RII-BFLY-jug64
        (
            0xe64000000000004201f0009127989u128,
            "SHFL.UP P0, R18, R9, 0x1, R0",
        ), // IIR-UP-p0
        (
            0xe6400000c000004201f0009127989u128,
            "SHFL.UP P6, R18, R9, 0x1, R0",
        ), // IIR-UP-p6
        (
            0xe6400000e000004201f0009127989u128,
            "SHFL.UP PT, R18, R9, 0x1, R0",
        ), // IIR-UP-p7
        (
            0xe6400000e001404201f0009127989u128,
            "SHFL.UP PT, R18, R9, 0x1, R20",
        ), // IIR-UP-jug64
        (
            0xe64000000000008201f0009127989u128,
            "SHFL.DOWN P0, R18, R9, 0x1, R0",
        ), // IIR-DOWN-p0
        (
            0xe6400000c000008201f0009127989u128,
            "SHFL.DOWN P6, R18, R9, 0x1, R0",
        ), // IIR-DOWN-p6
        (
            0xe6400000e000008201f0009127989u128,
            "SHFL.DOWN PT, R18, R9, 0x1, R0",
        ), // IIR-DOWN-p7
        (
            0xe6400000e001408201f0009127989u128,
            "SHFL.DOWN PT, R18, R9, 0x1, R20",
        ), // IIR-DOWN-jug64
        (
            0xe6400000200000c201f0009121f89u128,
            "@P1 SHFL.BFLY P1, R18, R9, 0x1, 0x1f",
        ), // IIII-BFLY-guard1-p1
    ];
    for leg in LEGS3 {
        let t = tab(leg);
        for &(w, want) in cases {
            let got = dec(&t, w);
            assert_eq!(got.as_deref(), Some(want), "{leg} word {w:#034x}");
        }
    }
}

#[test]
fn t369_3_mints_word_exact_cross_leg() {
    let texts: &[&str] = &[
        "SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
        "SHFL.BFLY P6, R18, R9, 0x1, 0x1f",
        "SHFL.IDX P1, R18, R9, 0x1, 0x1f",
        "SHFL.UP P2, R18, R9, 0x1, 0x1f",
        "SHFL.DOWN P3, R18, R9, 0x1, 0x1f",
        "SHFL.IDX P0, R5, R9, R12, 0x1f",
        "SHFL.UP P1, R5, R9, R12, 0x1f",
        "SHFL.DOWN P2, R5, R9, R12, 0x1f",
        "SHFL.BFLY P3, R5, R9, R12, 0x1f",
        "SHFL.UP P4, R18, R9, 0x1, R20",
        "SHFL.DOWN P5, R18, R9, 0x1, R21",
        "@P1 SHFL.BFLY P1, R18, R9, 0x1, 0x1f",
        "@!P1 SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        "SHFL.IDX PT, R5, R9, R12, 0x1f",
    ];
    for text in texts {
        let mut ws = Vec::new();
        for leg in LEGS4 {
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
fn t369_4_fail_closed_and_antimisprint_pins() {
    // II_R IDX/BFLY absent x3 nogi = residuum 358 (vendor-legal, brak
    // donora na zadnej nodze): crafted word nie moze wyjsc jako II_R.
    let wbfly_ii = 0x000e6400000e00000c201f0009127f89u128;
    for leg in LEGS3 {
        let t = tab(leg);
        for mode in [0u128, 3] {
            let w =
                (wbfly_ii & !(0xffu128 << 8) & !(0x3u128 << 58)) | (0x79u128 << 8) | (mode << 58);
            let got = dec(&t, w & !((0x3fffu128) << 40) & !((0xffu128) << 64));
            assert!(
                got.is_none() || !got.unwrap().contains(", R0"),
                "{leg} II_R absent-mode word must not surface as II_R (mode {mode})"
            );
        }
        // anti-misprint: R_II UP/DOWN/BFLY ze junk [71:64] MUSI trafic
        // na wlasciwy mg (nigdy IDX '0x1404001f'-klasa)
        let wup = (0x004e2400000e000000001f0c09057589u128 & !(0x3u128 << 58) & !(0xffu128 << 64))
            | (1u128 << 58)
            | (20u128 << 64);
        assert_eq!(
            dec(&t, wup).as_deref(),
            Some("SHFL.UP PT, R5, R9, R12, 0x1f"),
            "{leg} R_II UP jug64 misclaimed"
        );
        // era II_II[UP] misprint class: 'SHFL.UP PT, R18, R9, 0x1, 0x1f'
        // word nie moze wyjsc jako IDX z junk imm
        let wup2 = 0x000e6400000e000004201f0009127f89u128;
        let got2 = dec(&t, wup2);
        assert!(
            got2.is_none() || !got2.unwrap().starts_with("SHFL.IDX"),
            "{leg} II_II UP word claimed by IDX empire"
        );
    }
}

#[test]
fn t369_5_corpus_anchors_no_drift_x3() {
    // 70 II-form corpus anchors (bug333 census battery ab240) x3 nogi
    let anchors: &[(u128, &str)] = &[
        (
            0x000e6400000e00000c201f0009127f89u128,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0013127f89u128,
            "SHFL.BFLY PT, R18, R19, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0016127f89u128,
            "SHFL.BFLY PT, R18, R22, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0013127f89u128,
            "SHFL.BFLY PT, R18, R19, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f000a127f89u128,
            "SHFL.BFLY PT, R18, R10, 0x2, 0x1f",
        ),
        (
            0x0000a400000e00000c801f0009127f89u128,
            "SHFL.BFLY PT, R18, R9, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0005127f89u128,
            "SHFL.BFLY PT, R18, R5, 0x1, 0x1f",
        ),
        (
            0x0000a400000e00000c801f0006127f89u128,
            "SHFL.BFLY PT, R18, R6, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0007127f89u128,
            "SHFL.BFLY PT, R18, R7, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0008127f89u128,
            "SHFL.BFLY PT, R18, R8, 0x4, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0007127f89u128,
            "SHFL.BFLY PT, R18, R7, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c401f001a127f89u128,
            "SHFL.BFLY PT, R18, R26, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f001b127f89u128,
            "SHFL.BFLY PT, R18, R27, 0x4, 0x1f",
        ),
        (
            0x00006400000e00000c801f001a127f89u128,
            "SHFL.BFLY PT, R18, R26, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0004127f89u128,
            "SHFL.BFLY PT, R18, R4, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c201f00181a7f89u128,
            "SHFL.BFLY PT, R26, R24, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f00061a7f89u128,
            "SHFL.BFLY PT, R26, R6, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f00071a7f89u128,
            "SHFL.BFLY PT, R26, R7, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f000b1a7f89u128,
            "SHFL.BFLY PT, R26, R11, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f00121a7f89u128,
            "SHFL.BFLY PT, R26, R18, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f00061a7f89u128,
            "SHFL.BFLY PT, R26, R6, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f00191a7f89u128,
            "SHFL.BFLY PT, R26, R25, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c201f00121a7f89u128,
            "SHFL.BFLY PT, R26, R18, 0x1, 0x1f",
        ),
        (
            0x0002a400000e00000c801f00001a7f89u128,
            "SHFL.BFLY PT, R26, R0, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f00051a7f89u128,
            "SHFL.BFLY PT, R26, R5, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f00051a7f89u128,
            "SHFL.BFLY PT, R26, R5, 0x4, 0x1f",
        ),
        (
            0x001e2400000e00000c201f00091a7f89u128,
            "SHFL.BFLY PT, R26, R9, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f001b1a7f89u128,
            "SHFL.BFLY PT, R26, R27, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f001c1a7f89u128,
            "SHFL.BFLY PT, R26, R28, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f001b1a7f89u128,
            "SHFL.BFLY PT, R26, R27, 0x1, 0x1f",
        ),
        (
            0x00006400000e00000c801f00181a7f89u128,
            "SHFL.BFLY PT, R26, R24, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c401f00021a7f89u128,
            "SHFL.BFLY PT, R26, R2, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f00091a7f89u128,
            "SHFL.BFLY PT, R26, R9, 0x4, 0x1f",
        ),
        (
            0x0004e400000e00000c801f00021a7f89u128,
            "SHFL.BFLY PT, R26, R2, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0012167f89u128,
            "SHFL.BFLY PT, R22, R18, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0006167f89u128,
            "SHFL.BFLY PT, R22, R6, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0007167f89u128,
            "SHFL.BFLY PT, R22, R7, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0009167f89u128,
            "SHFL.BFLY PT, R22, R9, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0004167f89u128,
            "SHFL.BFLY PT, R22, R4, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0000167f89u128,
            "SHFL.BFLY PT, R22, R0, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0006167f89u128,
            "SHFL.BFLY PT, R22, R6, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0017167f89u128,
            "SHFL.BFLY PT, R22, R23, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0012167f89u128,
            "SHFL.BFLY PT, R22, R18, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f001c167f89u128,
            "SHFL.BFLY PT, R22, R28, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f001c167f89u128,
            "SHFL.BFLY PT, R22, R28, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0012167f89u128,
            "SHFL.BFLY PT, R22, R18, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0000167f89u128,
            "SHFL.BFLY PT, R22, R0, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0002167f89u128,
            "SHFL.BFLY PT, R22, R2, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0004167f89u128,
            "SHFL.BFLY PT, R22, R4, 0x4, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0002167f89u128,
            "SHFL.BFLY PT, R22, R2, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0012177f89u128,
            "SHFL.BFLY PT, R23, R18, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0008177f89u128,
            "SHFL.BFLY PT, R23, R8, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0009177f89u128,
            "SHFL.BFLY PT, R23, R9, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0012177f89u128,
            "SHFL.BFLY PT, R23, R18, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0008177f89u128,
            "SHFL.BFLY PT, R23, R8, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0018177f89u128,
            "SHFL.BFLY PT, R23, R24, 0x1, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0000177f89u128,
            "SHFL.BFLY PT, R23, R0, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0005177f89u128,
            "SHFL.BFLY PT, R23, R5, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0005177f89u128,
            "SHFL.BFLY PT, R23, R5, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0016177f89u128,
            "SHFL.BFLY PT, R23, R22, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0018177f89u128,
            "SHFL.BFLY PT, R23, R24, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0019177f89u128,
            "SHFL.BFLY PT, R23, R25, 0x4, 0x1f",
        ),
        (
            0x00006400000e00000c801f0010177f89u128,
            "SHFL.BFLY PT, R23, R16, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0002177f89u128,
            "SHFL.BFLY PT, R23, R2, 0x2, 0x1f",
        ),
        (
            0x0004e400000e00000c801f0002177f89u128,
            "SHFL.BFLY PT, R23, R2, 0x4, 0x1f",
        ),
        (
            0x004e2400000e000000001f0c09057589u128,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ),
        (
            0x004e2400000e000000001f0605037589u128,
            "SHFL.IDX PT, R3, R5, R6, 0x1f",
        ),
        (
            0x004e2400000e000000001f0805067589u128,
            "SHFL.IDX PT, R6, R5, R8, 0x1f",
        ),
        (
            0x004e2400000e000000001f0a07047589u128,
            "SHFL.IDX PT, R4, R7, R10, 0x1f",
        ),
        (
            0x004e6400000e000000001f0807047589u128,
            "SHFL.IDX PT, R4, R7, R8, 0x1f",
        ),
    ];
    for leg in LEGS3 {
        let t = tab(leg);
        for &(w, want) in anchors {
            let got = dec(&t, w);
            assert_eq!(got.as_deref(), Some(want), "{leg} anchor drift {w:#034x}");
        }
    }
}
