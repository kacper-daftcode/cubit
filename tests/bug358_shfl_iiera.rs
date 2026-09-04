//! BUG-358 (F2-iter185, loop5/blind front2, 2026-09-02): sm121a SHFL
//! II-form era over-strict closure -- pred field (3,81) era zamiast
//! mylnego (4,12) [guard slot] na 8 wierszach + vm-relax [71:64]
//! (write-inert na tok5-imm) + vm-relax [52:40] na II_R + clone II_R
//! DOWN mg. Leg sm121a ONLY (registration 358-kand LOW at 333.md sec
//! Rejestracje, F2-iter178). Canonical graft patch358.py (b17a33b),
//! ride-after aa5a610/BUG-354.
//!
//! MEASUREMENT (pre-fix publish cubit_py-aa5a610.so 9dce9a44.., canonical
//! 5c12995; work/bug358/measure_pre358.json):
//!  (a) decode HOLE pred<PT on IIII {IDX,UP,BFLY} + R_II x4 + IIR-UP
//!      (16 zmierzonych); HOLE IIR p7 ([52:40] pin); HOLE [71:64]!=0
//!      IIII x4; SILENT MISDECODE R_II jug64 x4 ('...0x0, UR20' junk);
//!      II_R DOWN brak => HOLE + mint REFUSE.
//!  (b) authored mints pred<PT cicho do PT (intent-drop via (4,12) field
//!      piszacy w guard slot; '@!P1 ... PT' redec 'P9').
//! LAW: arb358 73 sondy nvdisasm 13.3.73 raw -b, x4 modele AGREE on
//! EVERY probe: mode2b@[59:58]=IDX/UP/DOWN/BFLY; b1 0x7f=II_II,
//! 0x75=R_II, 0x79=II_R, 0x73=R_R; pred[83:81] legalne na kazdej II-form
//! rodzinie x4, niezalezne od guard[15:12]; [71:64] inert na tok5-imm;
//! [52:40] inert na II_R. Corpus exposure ZERO (74 kotwice SHFL battery
//! ab240: II-form pred!=PT / [71:64]!=0 / II_R = 0).
//! NOT grafted: _? junk rows (iter211 ERR-213). CLOSED since: R-form UP
//! pinned pred + cross-leg II-form = BUG-368/369 (F2-iter194, canonical
//! c913faa): kontrast-piny w t358_4 odwrocone do prawa vendor z atrybucja.
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
fn t358_1_structure_pred81_fields_and_vm_relax() {
    let t = tab("sm121a");
    // 8 rows with the grafted era pred field (3b@81 tok1)
    let rows: &[(String, String, u128)] = &[
        (
            "SHFL.BFLY_P_R_R_II_II".into(),
            "".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
        (
            "SHFL.IDX_P_R_R_R_II".into(),
            "".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
        ("SHFL_P_R_R_II_II".into(), "DOWN".into(), 0xffu128 << 64), // pred field pre-existed
        (
            "SHFL_P_R_R_II_II".into(),
            "IDX".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
        (
            "SHFL_P_R_R_II_II".into(),
            "UP".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
        (
            "SHFL_P_R_R_II_R".into(),
            "UP".into(),
            (0x7u128 << 81) | (0x1fffu128 << 40),
        ),
        (
            "SHFL_P_R_R_R_II".into(),
            "DOWN".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
        (
            "SHFL_P_R_R_R_II".into(),
            "UP".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
        (
            "SHFL_P_R_R_R_II".into(),
            "BFLY".into(),
            (0x7u128 << 81) | (0xffu128 << 64),
        ),
    ];
    for (key, mgn, vmwin) in rows {
        let mg = &t.entries[key].mod_groups[mgn];
        let pred81 = mg
            .fields
            .iter()
            .filter(|f| {
                f.extraction == Extraction::Pred && f.shift == 81 && f.bits == 3 && f.token_idx == 1
            })
            .count();
        assert_eq!(pred81, 1, "{key}[{mgn}]: pred(3,81) tok1 field missing");
        let bad12 = mg
            .fields
            .iter()
            .filter(|f| f.extraction == Extraction::Pred && f.shift == 12)
            .count();
        assert_eq!(bad12, 0, "{key}[{mgn}]: stale guard-slot pred(4,12) field");
        assert_eq!(
            mg.variable_mask & *vmwin,
            *vmwin,
            "{key}[{mgn}]: vm window not relaxed"
        );
    }
    // II_R DOWN clone: delta law vs UP (mode bits [59:58] 1->2), mirror fields/vm
    let e = &t.entries["SHFL_P_R_R_II_R"];
    let up = &e.mod_groups["UP"];
    let dn = &e.mod_groups["DOWN"];
    assert_eq!((up.and_base >> 58) & 3, 1, "II_R UP mode drift");
    assert_eq!((dn.and_base >> 58) & 3, 2, "II_R DOWN mode drift");
    assert_eq!(up.and_base ^ dn.and_base, 0x3u128 << 58);
    assert_eq!(up.variable_mask, dn.variable_mask);
    let tf = |mg: &cubit::table::ModGroupEntry| {
        let mut v: Vec<(u32, String, u32, u32)> = mg
            .fields
            .iter()
            .map(|f| {
                (
                    f.bits,
                    format!("{:?}", f.extraction),
                    f.shift,
                    f.token_idx as u32,
                )
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(tf(up), tf(dn), "II_R DOWN field mirror drift");
}

#[test]
fn t358_2_decode_law_vendor_text_x_probe_battery() {
    let t = tab("sm121a");
    // (word, vendor text) from arb358 B/C/D/E sets, unanimous x4 models
    let cases: &[(u128, &str)] = &[
        (
            0x000e6400000000000c201f0009127f89,
            "SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
        ), // B-BFLY-IIII-p0
        (
            0x000e6400000200000c201f0009127f89,
            "SHFL.BFLY P1, R18, R9, 0x1, 0x1f",
        ), // B-BFLY-IIII-p1
        (
            0x000e6400000c00000c201f0009127f89,
            "SHFL.BFLY P6, R18, R9, 0x1, 0x1f",
        ), // B-BFLY-IIII-p6
        (
            0x000e6400000e00000c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // B-BFLY-IIII-p7
        (
            0x004e2400000000000c001f0c09057589,
            "SHFL.BFLY P0, R5, R9, R12, 0x1f",
        ), // B-BFLY-RII-p0
        (
            0x004e2400000200000c001f0c09057589,
            "SHFL.BFLY P1, R5, R9, R12, 0x1f",
        ), // B-BFLY-RII-p1
        (
            0x004e2400000c00000c001f0c09057589,
            "SHFL.BFLY P6, R5, R9, R12, 0x1f",
        ), // B-BFLY-RII-p6
        (
            0x004e2400000e00000c001f0c09057589,
            "SHFL.BFLY PT, R5, R9, R12, 0x1f",
        ), // B-BFLY-RII-p7
        (
            0x000e64000000000000201f0009127f89,
            "SHFL.IDX P0, R18, R9, 0x1, 0x1f",
        ), // B-DOWN-IIII-p0
        (
            0x000e64000002000000201f0009127f89,
            "SHFL.IDX P1, R18, R9, 0x1, 0x1f",
        ), // B-DOWN-IIII-p1
        (
            0x000e6400000c000000201f0009127f89,
            "SHFL.IDX P6, R18, R9, 0x1, 0x1f",
        ), // B-DOWN-IIII-p6
        (
            0x000e6400000e000000201f0009127f89,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // B-DOWN-IIII-p7
        (
            0x004e24000000000000001f0c09057589,
            "SHFL.IDX P0, R5, R9, R12, 0x1f",
        ), // B-DOWN-RII-p0
        (
            0x004e24000002000000001f0c09057589,
            "SHFL.IDX P1, R5, R9, R12, 0x1f",
        ), // B-DOWN-RII-p1
        (
            0x004e2400000c000000001f0c09057589,
            "SHFL.IDX P6, R5, R9, R12, 0x1f",
        ), // B-DOWN-RII-p6
        (
            0x004e2400000e000000001f0c09057589,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // B-DOWN-RII-p7
        (
            0x004e24000000000000001f0c09057589,
            "SHFL.IDX P0, R5, R9, R12, 0x1f",
        ), // B-IDX-RII-p0
        (
            0x004e24000002000000001f0c09057589,
            "SHFL.IDX P1, R5, R9, R12, 0x1f",
        ), // B-IDX-RII-p1
        (
            0x004e2400000c000000001f0c09057589,
            "SHFL.IDX P6, R5, R9, R12, 0x1f",
        ), // B-IDX-RII-p6
        (
            0x004e2400000e000000001f0c09057589,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // B-IDX-RII-p7
        (
            0x000e64000000000008201f0009127989,
            "SHFL.DOWN P0, R18, R9, 0x1, R0",
        ), // B-UP-II-R-p0
        (
            0x000e64000002000008201f0009127989,
            "SHFL.DOWN P1, R18, R9, 0x1, R0",
        ), // B-UP-II-R-p1
        (
            0x000e6400000c000008201f0009127989,
            "SHFL.DOWN P6, R18, R9, 0x1, R0",
        ), // B-UP-II-R-p6
        (
            0x000e6400000e000008201f0009127989,
            "SHFL.DOWN PT, R18, R9, 0x1, R0",
        ), // B-UP-II-R-p7
        (
            0x000e64000000000008201f0009127f89,
            "SHFL.DOWN P0, R18, R9, 0x1, 0x1f",
        ), // B-UP-IIII-p0
        (
            0x000e64000002000008201f0009127f89,
            "SHFL.DOWN P1, R18, R9, 0x1, 0x1f",
        ), // B-UP-IIII-p1
        (
            0x000e6400000c000008201f0009127f89,
            "SHFL.DOWN P6, R18, R9, 0x1, 0x1f",
        ), // B-UP-IIII-p6
        (
            0x000e6400000e000008201f0009127f89,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // B-UP-IIII-p7
        (
            0x004e24000000000008001f0c09057589,
            "SHFL.DOWN P0, R5, R9, R12, 0x1f",
        ), // B-UP-RII-p0
        (
            0x004e24000002000008001f0c09057589,
            "SHFL.DOWN P1, R5, R9, R12, 0x1f",
        ), // B-UP-RII-p1
        (
            0x004e2400000c000008001f0c09057589,
            "SHFL.DOWN P6, R5, R9, R12, 0x1f",
        ), // B-UP-RII-p6
        (
            0x004e2400000e000008001f0c09057589,
            "SHFL.DOWN PT, R5, R9, R12, 0x1f",
        ), // B-UP-RII-p7
        (
            0x000e6400000e00000c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // C-BFLY-IIII-r0
        (
            0x000e6400000e00140c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // C-BFLY-IIII-r20
        (
            0x000e6400000e00ff0c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // C-BFLY-IIII-r255
        (
            0x004e2400000e00000c001f0c09057589,
            "SHFL.BFLY PT, R5, R9, R12, 0x1f",
        ), // C-BFLY-RII-r0
        (
            0x004e2400000e00140c001f0c09057589,
            "SHFL.BFLY PT, R5, R9, R12, 0x1f",
        ), // C-BFLY-RII-r20
        (
            0x004e2400000e00ff0c001f0c09057589,
            "SHFL.BFLY PT, R5, R9, R12, 0x1f",
        ), // C-BFLY-RII-r255
        (
            0x000e6400000e000000201f0009127f89,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // C-DOWN-IIII-r0
        (
            0x000e6400000e001400201f0009127f89,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // C-DOWN-IIII-r20
        (
            0x000e6400000e00ff00201f0009127f89,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // C-DOWN-IIII-r255
        (
            0x004e2400000e000000001f0c09057589,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // C-IDX-RII-r0
        (
            0x004e2400000e001400001f0c09057589,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // C-IDX-RII-r20
        (
            0x004e2400000e00ff00001f0c09057589,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ), // C-IDX-RII-r255
        (
            0x000e6400000e000008201f0009127f89,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // C-UP-IIII-r0
        (
            0x000e6400000e001408201f0009127f89,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // C-UP-IIII-r20
        (
            0x000e6400000e00ff08201f0009127f89,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // C-UP-IIII-r255
        (
            0x000e6400000000000c201f0009121f89,
            "@P1 SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
        ), // D-g1-p0
        (
            0x000e6400000e00000c201f0009121f89,
            "@P1 SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // D-g1-p7
        (
            0x000e6400000000000c201f0009127f89,
            "SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
        ), // D-g7-p0
        (
            0x000e6400000e00000c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // D-g7-p7
        (
            0x000e6400000000000c201f0009129f89,
            "@!P1 SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
        ), // D-g9-p0
        (
            0x000e6400000e00000c201f0009129f89,
            "@!P1 SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // D-g9-p7
        (
            0x00006400000000100c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ), // E-RR-p0
        (
            0x000e6400000e000000201f0009127589,
            "SHFL.IDX PT, R18, R9, R0, 0x1f",
        ), // A-b175-m0
        (
            0x000e6400000e000004201f0009127589,
            "SHFL.UP PT, R18, R9, R0, 0x1f",
        ), // A-b175-m1
        (
            0x000e6400000e000008201f0009127589,
            "SHFL.DOWN PT, R18, R9, R0, 0x1f",
        ), // A-b175-m2
        (
            0x000e6400000e00000c201f0009127589,
            "SHFL.BFLY PT, R18, R9, R0, 0x1f",
        ), // A-b175-m3
        (
            0x000e6400000e000004201f0009127989,
            "SHFL.UP PT, R18, R9, 0x1, R0",
        ), // A-b179-m1
        (
            0x000e6400000e000008201f0009127989,
            "SHFL.DOWN PT, R18, R9, 0x1, R0",
        ), // A-b179-m2
        (
            0x000e6400000e000000201f0009127f89,
            "SHFL.IDX PT, R18, R9, 0x1, 0x1f",
        ), // A-b17f-m0
        (
            0x000e6400000e000004201f0009127f89,
            "SHFL.UP PT, R18, R9, 0x1, 0x1f",
        ), // A-b17f-m1
        (
            0x000e6400000e000008201f0009127f89,
            "SHFL.DOWN PT, R18, R9, 0x1, 0x1f",
        ), // A-b17f-m2
        (
            0x000e6400000e00000c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ), // A-b17f-m3
        (
            0x00006400000200100c00000b0a127389,
            "SHFL.BFLY P1, R18, R10, R11, R16",
        ), // E-RR-p1
        (
            0x00006400000c00100c00000b0a127389,
            "SHFL.BFLY P6, R18, R10, R11, R16",
        ), // E-RR-p6
        (
            0x00006400000e00100c00000b0a127389,
            "SHFL.BFLY PT, R18, R10, R11, R16",
        ), // E-RR-p7
    ];
    for (w, want) in cases {
        let got = dec(&t, *w).unwrap_or_else(|| format!("<HOLE {w:#x}>"));
        assert_eq!(got, *want, "decode drift {w:#034x}");
    }
}

#[test]
fn t358_3_mint_word_exact_and_roundtrip() {
    let t = tab("sm121a");
    // (authored text, post-fix word hex) -- word-decoded by nvdisasm ==
    // authored text (work/bug358/mintpost358_quick.json)
    let cases: &[(&str, u128)] = &[
        (
            "SHFL.BFLY P0, R18, R9, 0x1, 0x1f",
            0xfc200000000000c201f0009127f89,
        ),
        (
            "SHFL.BFLY P6, R18, R9, 0x1, 0x1f",
            0xfc200000c00000c201f0009127f89,
        ),
        (
            "SHFL.IDX P1, R18, R9, 0x1, 0x1f",
            0xfc2000002000000201f0009127f89,
        ),
        (
            "SHFL.UP P2, R18, R9, 0x1, 0x1f",
            0xfc2000004000004201f0009127f89,
        ),
        (
            "SHFL.DOWN P3, R18, R9, 0x1, 0x1f",
            0xfc2000006000008201f0009127f89,
        ),
        (
            "SHFL.IDX P0, R5, R9, R12, 0x1f",
            0xfc2000000000000001f0c09057589,
        ),
        (
            "SHFL.UP P1, R5, R9, R12, 0x1f",
            0xfc2000002000004001f0c09057589,
        ),
        (
            "SHFL.DOWN P2, R5, R9, R12, 0x1f",
            0xfc2000004000008001f0c09057589,
        ),
        (
            "SHFL.BFLY P3, R5, R9, R12, 0x1f",
            0xfc200000600000c001f0c09057589,
        ),
        (
            "SHFL.UP P4, R18, R9, 0x1, R20",
            0xfc200000800140420000009127989,
        ),
        (
            "SHFL.DOWN P5, R18, R9, 0x1, R21",
            0xfc200000a00150820000009127989,
        ),
        (
            "@P1 SHFL.BFLY P1, R18, R9, 0x1, 0x1f",
            0xfc200000200000c201f0009121f89,
        ),
        (
            "@!P1 SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
            0xfc200000e00000c201f0009129f89,
        ),
        (
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
            0xfc200000e00000c201f0009127f89,
        ),
        (
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
            0xfc200000e000000001f0c09057589,
        ),
    ];
    for (text, want) in cases {
        let got = enc(&t, text).unwrap_or_else(|e| panic!("mint drift {text:?}: {e}"));
        assert_eq!(got & M96, want & M96, "word drift for {text:?}");
        let back = dec(&t, got).unwrap_or_else(|| "<HOLE>".to_string());
        assert_eq!(&back, text, "roundtrip drift for {text:?}");
    }
}

#[test]
fn t358_4_fail_closed_residua_stay_hole() {
    let t = tab("sm121a");
    // II_R IDX/BFLY mgs absent on ALL legs (arb358 A-set legal but no
    // donor): crafted words must NOT be claimed by the II_R rows
    // (mode bits are in care). b1=0x79, mode 0 (IDX) / 3 (BFLY).
    let wbfly_ii = 0x000e6400000e00000c201f0009127f89u128;
    for mode in [0u128, 3] {
        let w = (wbfly_ii & !(0xffu128 << 8) & !(0x3u128 << 58)) | (0x79u128 << 8) | (mode << 58);
        let got = dec(&t, w & !((0x3fffu128) << 40) & !((0xffu128) << 64));
        assert!(
            got.is_none() || !got.unwrap().contains(", R0"),
            "II_R absent-mode word must not surface as II_R (mode {mode})"
        );
    }
    // FLIP z atrybucja BUG-368 (F2-iter194, canonical 0933cf6->c913faa):
    // kontrast-piny 368-residuum ODWROCONE do pozytywnego prawa vendor.
    // R-form UP pred<PT teraz claim+poprawny text (arb368 C: x4 ZGODNE)
    let wr = 0x00006400000000100c00000b0a127389u128; // BFLY R_R P0 corpus
    let wup = (wr & !(0x3u128 << 58)) | (1u128 << 58) | (0u128 << 81);
    let got = dec(&t, wup);
    let want = "SHFL.UP P0, R18, R10, R11, R16";
    assert_eq!(
        got.as_deref(),
        Some(want),
        "368-flip: R-form UP pred81 law (arb368 C-set)"
    );
    // A-b173 + arb368 A/B: R-form slowa z junk [57:40] = vendor-inert,
    // teraz poprawnie claimuja R-form (teksty wg arb358 A-b173 x4)
    let wii4 = 0x000e6400000e00000c201f0009127f89u128;
    let want_by_mode = ["SHFL.IDX", "SHFL.UP", "SHFL.DOWN", "SHFL.BFLY"];
    for mode in [0u128, 1, 2, 3] {
        let w = (wii4 & !(0xffu128 << 8) & !(0x3u128 << 58)) | (0x73u128 << 8) | (mode << 58);
        let got = dec(&t, w).expect("368-flip: R-form junk[57:40] word HOLEs");
        assert!(
            got.starts_with(want_by_mode[mode as usize]) && got.ends_with("R0, R0"),
            "368-flip: R-form junk-window law (mode {mode}): {got}"
        );
    }
}

#[test]
fn t358_5_corpus_anchors_no_drift() {
    let t = tab("sm121a");
    // 74 SHFL corpus anchors (bug333 census, battery ab240) must decode
    // byte-identical pre/post (graft corpus-invisible on II-form window).
    let anchors: &[(u128, &str)] = &[
        (
            0x004e2400000e000000001f0c09057589,
            "SHFL.IDX PT, R5, R9, R12, 0x1f",
        ),
        (
            0x004e2400000e000000001f0605037589,
            "SHFL.IDX PT, R3, R5, R6, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0013127f89,
            "SHFL.BFLY PT, R18, R19, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0016127f89,
            "SHFL.BFLY PT, R18, R22, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0013127f89,
            "SHFL.BFLY PT, R18, R19, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f000a127f89,
            "SHFL.BFLY PT, R18, R10, 0x2, 0x1f",
        ),
        (
            0x0000a400000e00000c801f0009127f89,
            "SHFL.BFLY PT, R18, R9, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0005127f89,
            "SHFL.BFLY PT, R18, R5, 0x1, 0x1f",
        ),
        (
            0x0000a400000e00000c801f0006127f89,
            "SHFL.BFLY PT, R18, R6, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0007127f89,
            "SHFL.BFLY PT, R18, R7, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0008127f89,
            "SHFL.BFLY PT, R18, R8, 0x4, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0007127f89,
            "SHFL.BFLY PT, R18, R7, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c401f001a127f89,
            "SHFL.BFLY PT, R18, R26, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f001b127f89,
            "SHFL.BFLY PT, R18, R27, 0x4, 0x1f",
        ),
        (
            0x00006400000e00000c801f001a127f89,
            "SHFL.BFLY PT, R18, R26, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0004127f89,
            "SHFL.BFLY PT, R18, R4, 0x1, 0x1f",
        ),
        (
            0x00006400000000100c00000b0a127389,
            "SHFL.BFLY P0, R18, R10, R11, R16",
        ),
        (
            0x004e2400000e000000001f0805067589,
            "SHFL.IDX PT, R6, R5, R8, 0x1f",
        ),
        (
            0x000e2400000e00000c201f00181a7f89,
            "SHFL.BFLY PT, R26, R24, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f00061a7f89,
            "SHFL.BFLY PT, R26, R6, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f00071a7f89,
            "SHFL.BFLY PT, R26, R7, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f000b1a7f89,
            "SHFL.BFLY PT, R26, R11, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f00121a7f89,
            "SHFL.BFLY PT, R26, R18, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f00061a7f89,
            "SHFL.BFLY PT, R26, R6, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f00191a7f89,
            "SHFL.BFLY PT, R26, R25, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c201f00121a7f89,
            "SHFL.BFLY PT, R26, R18, 0x1, 0x1f",
        ),
        (
            0x0002a400000e00000c801f00001a7f89,
            "SHFL.BFLY PT, R26, R0, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f00051a7f89,
            "SHFL.BFLY PT, R26, R5, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f00051a7f89,
            "SHFL.BFLY PT, R26, R5, 0x4, 0x1f",
        ),
        (
            0x001e2400000e00000c201f00091a7f89,
            "SHFL.BFLY PT, R26, R9, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f001b1a7f89,
            "SHFL.BFLY PT, R26, R27, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f001c1a7f89,
            "SHFL.BFLY PT, R26, R28, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f001b1a7f89,
            "SHFL.BFLY PT, R26, R27, 0x1, 0x1f",
        ),
        (
            0x00006400000e00000c801f00181a7f89,
            "SHFL.BFLY PT, R26, R24, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c401f00021a7f89,
            "SHFL.BFLY PT, R26, R2, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f00091a7f89,
            "SHFL.BFLY PT, R26, R9, 0x4, 0x1f",
        ),
        (
            0x0004e400000e00000c801f00021a7f89,
            "SHFL.BFLY PT, R26, R2, 0x4, 0x1f",
        ),
        (
            0x00006400000000140c000013121a7389,
            "SHFL.BFLY P0, R26, R18, R19, R20",
        ),
        (
            0x004e2400000e000000001f0a07047589,
            "SHFL.IDX PT, R4, R7, R10, 0x1f",
        ),
        (
            0x004e6400000e000000001f0807047589,
            "SHFL.IDX PT, R4, R7, R8, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0012167f89,
            "SHFL.BFLY PT, R22, R18, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0006167f89,
            "SHFL.BFLY PT, R22, R6, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0007167f89,
            "SHFL.BFLY PT, R22, R7, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0009167f89,
            "SHFL.BFLY PT, R22, R9, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0004167f89,
            "SHFL.BFLY PT, R22, R4, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0000167f89,
            "SHFL.BFLY PT, R22, R0, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0006167f89,
            "SHFL.BFLY PT, R22, R6, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c201f0017167f89,
            "SHFL.BFLY PT, R22, R23, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0012167f89,
            "SHFL.BFLY PT, R22, R18, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f001c167f89,
            "SHFL.BFLY PT, R22, R28, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f001c167f89,
            "SHFL.BFLY PT, R22, R28, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0012167f89,
            "SHFL.BFLY PT, R22, R18, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0000167f89,
            "SHFL.BFLY PT, R22, R0, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0002167f89,
            "SHFL.BFLY PT, R22, R2, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0004167f89,
            "SHFL.BFLY PT, R22, R4, 0x4, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0002167f89,
            "SHFL.BFLY PT, R22, R2, 0x4, 0x1f",
        ),
        (
            0x0002a400000000140c0000131c167389,
            "SHFL.BFLY P0, R22, R28, R19, R20",
        ),
        (
            0x000e2400000e00000c201f0012177f89,
            "SHFL.BFLY PT, R23, R18, 0x1, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0008177f89,
            "SHFL.BFLY PT, R23, R8, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0009177f89,
            "SHFL.BFLY PT, R23, R9, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0012177f89,
            "SHFL.BFLY PT, R23, R18, 0x2, 0x1f",
        ),
        (
            0x00006400000e00000c801f0008177f89,
            "SHFL.BFLY PT, R23, R8, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0018177f89,
            "SHFL.BFLY PT, R23, R24, 0x1, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0000177f89,
            "SHFL.BFLY PT, R23, R0, 0x4, 0x1f",
        ),
        (
            0x000e2400000e00000c401f0005177f89,
            "SHFL.BFLY PT, R23, R5, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0005177f89,
            "SHFL.BFLY PT, R23, R5, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c201f0016177f89,
            "SHFL.BFLY PT, R23, R22, 0x1, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0018177f89,
            "SHFL.BFLY PT, R23, R24, 0x2, 0x1f",
        ),
        (
            0x0002a400000e00000c801f0019177f89,
            "SHFL.BFLY PT, R23, R25, 0x4, 0x1f",
        ),
        (
            0x00006400000e00000c801f0010177f89,
            "SHFL.BFLY PT, R23, R16, 0x4, 0x1f",
        ),
        (
            0x000e6400000e00000c401f0002177f89,
            "SHFL.BFLY PT, R23, R2, 0x2, 0x1f",
        ),
        (
            0x0004e400000e00000c801f0002177f89,
            "SHFL.BFLY PT, R23, R2, 0x4, 0x1f",
        ),
        (
            0x0002a400000000140c00001312177389,
            "SHFL.BFLY P0, R23, R18, R19, R20",
        ),
    ];
    for (w, want) in anchors {
        let got = dec(&t, *w).unwrap_or_else(|| format!("<HOLE {w:#x}>"));
        assert_eq!(got, *want, "anchor drift {w:#034x}");
    }
}
