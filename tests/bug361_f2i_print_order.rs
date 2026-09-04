//! BUG-361 (F2-iter191, loop5/blind front2, 2026-09-03): F2I print-order
//! vendor law on the generic mod-group rows (render-parity b11 lane) --
//! dst-type < src-type < rounding < NTZ. canonical cfcd697 tables; ENGINE
//! arm: src/printer.rs mod_priority_for base=="F2I".
//!
//! PRE (publish cubit-ef75c5c fa12e0d7.. + canonical 32cde7a;
//!   work/bug361_362/measure_pre361_362.json + census362 over the ab240
//!   2,406-cubin battery): generic-prio tie at 5 kept the mg's alphabetical
//!   order, printing e.g. 'F2I.TRUNC.U64' / 'F2I.F64.TRUNC.U64' /
//!   'F2I.FTZ.NTZ.TRUNC.U32' where the vendor prints 'F2I.U64.TRUNC' /
//!   'F2I.U64.F64.TRUNC' / 'F2I.FTZ.U32.TRUNC.NTZ'. Corpus exposure:
//!   14,232 disassembly slots / 1,318 uniq words on 4 arch legs drifted
//!   (census362_printdiff.json: F2I.FTZ.* x10,576 / TRUNC.U64 x1,346 /
//!   F64.TRUNC.U32 x1,178 / NTZ.TRUNC x672 / F64.S64 x192 / ...), every
//!   class engine-claimed but vendor-text-WRONG (LOW severity, b11 lane).
//! LAW (arb339 A1/A7era0 + arb362 U-mints + census vendor cross,
//!   nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a AGREE):
//!   FTZ < dst-type(U8..S64) < src-type(F32/F64) < rounding(FLOOR/CEIL/RN/
//!   TRUNC) < NTZ. The key-scoped BUG-125 F2I_R_FI arm resolves FIRST and
//!   carries the identical law, so the FI form is invariant (t361_3).
//!   F2IP (base 'F2IP') is untouched (era mgs print their own shapes).
//! FIX scope: decode/print-side only; claim windows untouched.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

#[test]
fn t361_1_decode_battery_vendor_exact_x4() {
    // classes measured drifting pre-361 (arb339/arb362 + corpus witnesses)
    let words: &[(u128, &str)] = &[
        (
            0x000000000020d9004000001500161311u128,
            "@P1 F2I.S64.TRUNC R22, |R21|",
        ),
        (
            0x000000000020d9008000001500161311u128,
            "@P1 F2I.S64.TRUNC R22, -R21",
        ),
        (
            0x000000000020d900c000001500161311u128,
            "@P1 F2I.S64.TRUNC R22, -|R21|",
        ),
        (
            0x000000000020d8004000001500161311u128,
            "@P1 F2I.U64.TRUNC R22, |R21|",
        ),
        (
            0x000000000020d8008000001500161311u128,
            "@P1 F2I.U64.TRUNC R22, -R21",
        ),
        (
            0x000000000020d800c000001500161311u128,
            "@P1 F2I.U64.TRUNC R22, -|R21|",
        ),
        (
            0x000000000020d9004000001a00167311u128,
            "F2I.S64.TRUNC R22, |R26|",
        ),
        (
            0x000000000020d9008000001a00167311u128,
            "F2I.S64.TRUNC R22, -R26",
        ),
        (
            0x000000000020d900c000001a00167311u128,
            "F2I.S64.TRUNC R22, -|R26|",
        ),
        (
            0x000000000020d8004000001a00167311u128,
            "F2I.U64.TRUNC R22, |R26|",
        ),
        (
            0x000000000020d8008000001a00167311u128,
            "F2I.U64.TRUNC R22, -R26",
        ),
        (
            0x000000000020d800c000001a00167311u128,
            "F2I.U64.TRUNC R22, -|R26|",
        ),
        (
            0x000000000030d80040000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, |R6|",
        ),
        (
            0x000000000030d80080000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, -R6",
        ),
        (
            0x000000000030d800c0000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, -|R6|",
        ),
        (
            0x000000000030d00040000006001a7311u128,
            "F2I.U32.F64.TRUNC R26, |R6|",
        ),
        (
            0x000000000030d00080000006001a7311u128,
            "F2I.U32.F64.TRUNC R26, -R6",
        ),
        (
            0x000000000030d000c0000006001a7311u128,
            "F2I.U32.F64.TRUNC R26, -|R6|",
        ),
        (
            0x000000000030d10040000006001a7311u128,
            "F2I.F64.TRUNC R26, |R6|",
        ),
        (
            0x000000000030d10080000006001a7311u128,
            "F2I.F64.TRUNC R26, -R6",
        ),
        (
            0x000000000030d100c0000006001a7311u128,
            "F2I.F64.TRUNC R26, -|R6|",
        ),
        (
            0x000000000030d90040000006001a7311u128,
            "F2I.S64.F64.TRUNC R26, |R6|",
        ),
        (
            0x000000000030d90080000006001a7311u128,
            "F2I.S64.F64.TRUNC R26, -R6",
        ),
        (
            0x000000000030d900c0000006001a7311u128,
            "F2I.S64.F64.TRUNC R26, -|R6|",
        ),
        (
            0x000000000030510040000006001a7311u128,
            "F2I.F64.FLOOR R26, |R6|",
        ),
        (
            0x000000000030510080000006001a7311u128,
            "F2I.F64.FLOOR R26, -R6",
        ),
        (
            0x0000000000305100c0000006001a7311u128,
            "F2I.F64.FLOOR R26, -|R6|",
        ),
        (
            0x000000000030510000000006001a7311u128,
            "F2I.F64.FLOOR R26, R6",
        ),
        (
            0x000000000030da0000000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030dc0000000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030de0000000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, R6",
        ),
        (
            0x000000000020df000000001a00167311u128,
            "F2I.S64.TRUNC R22, R26",
        ),
        (
            0x000000000020da000000001a00167311u128,
            "F2I.U64.TRUNC R22, R26",
        ),
        (
            0x000000000020dc000000001a00167311u128,
            "F2I.U64.TRUNC R22, R26",
        ),
        (
            0x000000000020de000000001a00167311u128,
            "F2I.U64.TRUNC R22, R26",
        ),
        (
            0x000000000030d40000000006001a7311u128,
            "F2I.U32.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030d60000000006001a7311u128,
            "F2I.U32.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030d50000000006001a7311u128,
            "F2I.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030d70000000006001a7311u128,
            "F2I.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030db0000000006001a7311u128,
            "F2I.S64.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030dd0000000006001a7311u128,
            "F2I.S64.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030df0000000006001a7311u128,
            "F2I.S64.F64.TRUNC R26, R6",
        ),
        (
            0x000000000030530000000006001a7311u128,
            "F2I.F64.FLOOR R26, R6",
        ),
    ];
    for leg in LEGS4 {
        let t = tab(leg);
        for (w, want) in words {
            let got = dec(&t, *w);
            assert_eq!(got.as_deref(), Some(*want), "{leg} {want} (0x{w:024x})");
        }
    }
}

#[test]
fn t361_2_corpus_witness_classes_native_leg() {
    // one real corpus witness per drift class (census362_printdiff.json,
    // battery ab240; vendor text cross-checked on the native model)
    let wits: &[(&str, u128, &str)] = &[
        (
            "sm103a",
            0x002070000000000000007305u128,
            "F2I.U32.FLOOR.NTZ R0, R0",
        ),
        (
            "sm100a",
            0x0020d8000000000000027311u128,
            "F2I.U64.TRUNC R2, R0",
        ),
        (
            "sm100a",
            0x0020f0000000000000007305u128,
            "F2I.U32.TRUNC.NTZ R0, R0",
        ),
        (
            "sm100a",
            0x0020f1000000000000037305u128,
            "F2I.TRUNC.NTZ R3, R0",
        ),
        (
            "sm100a",
            0x0021f0000000000000007305u128,
            "F2I.FTZ.U32.TRUNC.NTZ R0, R0",
        ),
        (
            "sm100a",
            0x003019000000000200027311u128,
            "F2I.S64.F64 R2, R2",
        ),
        (
            "sm103a",
            0x0030d0000000000200027311u128,
            "F2I.U32.F64.TRUNC R2, R2",
        ),
        (
            "sm100a",
            0x0030d80000000006001a7311u128,
            "F2I.U64.F64.TRUNC R26, R6",
        ),
        (
            "sm100a",
            0x0030d9000000000200027311u128,
            "F2I.S64.F64.TRUNC R2, R2",
        ),
    ];
    for (leg, w, want) in wits {
        let t = tab(leg);
        assert_eq!(dec(&t, *w).as_deref(), Some(*want), "{leg} corpus");
    }
}

#[test]
fn t361_3_mints_and_roundtrips() {
    for leg in LEGS4 {
        let t = tab(leg);
        // authored vendor-form text mints the proven cell words (M2-era
        // measurements; payload-exact incl. the BUG-125-key governance)
        let w = enc(&t, "F2I.U64.TRUNC R22, R26").unwrap();
        assert_eq!(w & M96, 0x0020d8000000001a00167311u128, "{leg}");
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("F2I.U64.TRUNC R22, R26"),
            "{leg} rt"
        );
        let w = enc(&t, "@P1 F2I.U64.TRUNC R22, R21").unwrap();
        assert_eq!(w & M96, 0x0020d8000000001500161311u128, "{leg}");
        // the unified priority class mints + decodes vendor-form
        let w = enc(&t, "F2I.FTZ.U32.TRUNC.NTZ R5, R9").unwrap();
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("F2I.FTZ.U32.TRUNC.NTZ R5, R9"),
            "{leg}"
        );
        let w = enc(&t, "F2I.U32.NTZ R2, R5").unwrap();
        assert_eq!(dec(&t, w).as_deref(), Some("F2I.U32.NTZ R2, R5"), "{leg}");
        let w = enc(&t, "F2I.U64.F64.TRUNC R26, R6").unwrap();
        assert_eq!(w & M96, 0x0030d80000000006001a7311u128, "{leg}");
        assert_eq!(
            dec(&t, w).as_deref(),
            Some("F2I.U64.F64.TRUNC R26, R6"),
            "{leg}"
        );
    }
}

#[test]
fn t361_4_bug125_fi_form_invariant() {
    // the key-scoped F2I_R_FI arm (BUG-125) resolves before the base arm;
    // its texts are byte-stable (arb125-era vendor law == 361 law anyway).
    // The gold battery is pinned on the sm103a native leg (mirrors t125_1).
    let words: &[(u128, &str)] = &[
        (0x000e2200002020004180000000007905u128, "F2I.U8.NTZ R0, 16"),
        (
            0x000e2200002120004180000000007905u128,
            "F2I.FTZ.U8.NTZ R0, 16",
        ),
        (
            0x000e22000020e0004180000000007905u128,
            "F2I.U8.TRUNC.NTZ R0, 16",
        ),
        (
            0x000e22000021a0004180000000007905u128,
            "F2I.FTZ.U8.CEIL.NTZ R0, 16",
        ),
        (0x000e2200002131004180000000007905u128, "F2I.FTZ.NTZ R0, 16"),
    ];
    let t = tab("sm103a");
    let idx = DecodeIndex::build(&t);
    for (w, want) in words {
        let got = idx.decode(*w, 0, &t).map(|d| to_sass(&d)).ok();
        let got = got.map(|g| {
            g.split("/*")
                .next()
                .unwrap()
                .trim()
                .trim_end_matches(';')
                .trim()
                .to_string()
        });
        assert_eq!(got.as_deref(), Some(*want), "FI invariance");
    }
}

#[test]
fn t361_5_scope_guard_other_bases_untouched() {
    // F2IP rows print their own era shape (base 'F2IP' not covered by the
    // arm; word == t340_2 base word, text byte-pinned there)
    let t = tab("sm120");
    let w: u128 = (0x7243) | (4u128 << 16) | (6u128 << 24) | (8u128 << 32) | (10u128 << 64);
    assert_eq!(dec(&t, w).as_deref(), Some("F2IP.U8.F32 R4, R6, R8, R10"));
    // generic prio arms for other bases stand: HMUL2 lattice text
    let t2 = tab("sm121a");
    let h = enc(&t2, "HMUL2.BF16_V2.FTZ.SAT R12, R22.H0_H0, R32.H0_H0")
        .ok()
        .map(|x| x & M96);
    if let Some(h) = h {
        assert_eq!(
            dec(&t2, h).as_deref(),
            Some("HMUL2.BF16_V2.FTZ.SAT R12, R22.H0_H0, R32.H0_H0")
        );
    }
}
