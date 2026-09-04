//! BUG-341 (F2-iter181, loop5/blind front2, 2026-09-02): F2I small-int
//! R_R lattice (op 0x0305) normalisation + closure, 4 legs (canonical
//! 337e21e; ENGINE untouched; work/bug341).
//!
//! LAW (arb341 379 + arb341b 192 probes, nvdisasm raw -b, x4 models
//!   SM100a/SM103a/SM120/SM121a AGREE on EVERY probe):
//!   byte9 = round[79:75] x type[75:72]; type: 0x00 U8 / 0x01 S8 /
//!   0x08 U16 / 0x09 S16 / 0x10 U32 / 0x11 S32-elided; bits 73/72 text-inert
//!   aliases; round: -/NTZ/FLOOR/FLOOR.NTZ/CEIL/CEIL.NTZ/TRUNC/TRUNC.NTZ;
//!   byte10=0x20 required (0x00 rows rc=1 x4); b80=.FTZ prefix + b86=.BF16
//!   (registered 363, NOT grafted); signs neg@63/abs@62 tok2 vendor-legal
//!   on ALL 48 canonical lanes x4.
//! PRE (publish f218216 = measured bugs): D1 era F2I.S16.NTZ_R_R owned
//!   byte9=0x00: authored 'F2I.S16.NTZ R4, R6' minted the vendor-U8 word
//!   (silent wrong-code); D2 era trio/squatters overclaim misprints (zlom
//!   C0 0020310040.. -> 'F2I.FLOOR.NTZ R1, |R15|', vendor 'F2I.NTZ R1,
//!   |R15|'); D3 sign-window HOLE 100a/103a + mint REFUSE x4; D4 mg
//!   'NTZ,U32' sm120/121a carried abs@62 BAKED in and_base -> authored
//!   'F2I.U32.NTZ R4, R6' minted the '|R6|' word (silent); G: ~40/48 plain
//!   lanes HOLE per leg. Corpus exposure ZERO beyond owned lanes (attr341:
//!   11,751 slots / 747 uniq battery x4: only lanes {31,70,71,f0,f1}x{20,21};
//!   DIFF class = mg print-order drift = 361-kand, untouched by design).
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
fn word(lane: u32, guard: u32, dst: u32, src: u32, sign: u32) -> u128 {
    0x0305u128
        | ((guard as u128) << 12)
        | ((dst as u128) << 16)
        | ((src as u128) << 32)
        | ((lane as u128) << 72)
        | (0x20u128 << 80)
        | ((sign as u128) << 62)
}

#[test]
fn t341_1_structure_owner_geometry() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let ins = &t.entries;
        if arch == "sm120" || arch == "sm121a" {
            for (key, lane) in [
                ("F2I.S16.NTZ_R_R", 0x29u128),
                ("F2I.FLOOR.NTZ_R_R", 0x71u128),
                ("F2I.TRUNC.NTZ_R_R", 0xf1u128),
                ("F2I.U32.TRUNC.NTZ_R_R", 0xf0u128),
                ("F2I.U32.NTZ_R_R", 0x30u128),
                ("F2I.CEIL.NTZ_R_R", 0xb1u128),
            ] {
                let r = &ins[key].mod_groups[""];
                assert_eq!((r.and_base >> 72) & 0xff, lane, "{arch} {key} lane");
                assert_eq!((r.and_base >> 80) & 0xff, 0x20, "{arch} {key} byte10 pin");
                assert_eq!(
                    (r.variable_mask >> 72) & 0xff,
                    0x06,
                    "{arch} {key} alias tolerance"
                );
                assert!(
                    r.fields.iter().any(|f| f.shift == 63),
                    "{arch} {key} neg field"
                );
                assert!(
                    r.fields.iter().any(|f| f.shift == 62),
                    "{arch} {key} abs field"
                );
            }
            let r = &ins["F2I.FTZ.U32.TRUNC.NTZ_R_R"].mod_groups[""];
            assert_eq!((r.and_base >> 72) & 0xff, 0xf0);
            assert_eq!((r.and_base >> 80) & 0xff, 0x21);
            // BUG-363 flip (canonical fbcef1c): signs were measured legal on
            // ALL 48 FTZ lanes (arb363 S-group 288 probes x4 AGREE) so the
            // pre-363 "no signs (unprobed)" posture is closed IN PLACE; the
            // unprobed reuse field was dropped (arb363 R-group: reuse bits
            // on FTZ lanes are vendor rc=1, fail-closed via decoder arm).
            assert!(
                r.fields.iter().any(|f| f.shift == 63),
                "{arch} FTZ era neg post-363"
            );
            assert!(
                r.fields.iter().any(|f| f.shift == 62),
                "{arch} FTZ era abs post-363"
            );
            assert!(
                !r.fields.iter().any(|f| f.shift >= 96),
                "{arch} FTZ era no-reuse post-363"
            );
            let g = &ins["F2I_R_R"].mod_groups["NTZ,U32"];
            assert_eq!((g.and_base >> 62) & 1, 0, "{arch} NTZ,U32 b62 bake gone");
        }
        let g = &ins["F2I_R_R"].mod_groups[""];
        assert_eq!((g.and_base >> 72) & 0xff, 0x11, "{arch} mg '' plain lane");
        if arch == "sm100a" || arch == "sm103a" {
            for mg in [
                "NTZ",
                "NTZ,S16",
                "FLOOR,NTZ",
                "FLOOR,NTZ,U32",
                "NTZ,TRUNC",
                "NTZ,TRUNC,U32",
            ] {
                let g = &ins["F2I_R_R"].mod_groups[mg];
                assert!(g.fields.iter().any(|f| f.shift == 63), "{arch} {mg} neg");
                assert!(g.fields.iter().any(|f| f.shift == 62), "{arch} {mg} abs");
            }
        }
    }
}

#[test]
fn t341_2_decode_matrix_law_minus_registered_drift() {
    // 48 canonical lanes x {plain, abs@62, negabs, +0x02 alias} x 4 legs.
    // Expectations measured post-graft and cross-checked against arb341 x4:
    // non-drift cells == vendor law; cells marked with drift order come from
    // pre-existing mg owners = 361-kand, deliberate (corpus-stable).
    let expect: &[(&str, u32, [&str; 4])] = &[
        (
            "sm100a",
            0x00,
            [
                "F2I.U8 R4, R6",
                "F2I.U8 R4, |R6|",
                "F2I.U8 R4, -|R6|",
                "F2I.U8 R4, R6",
            ],
        ),
        (
            "sm100a",
            0x01,
            [
                "F2I.S8 R4, R6",
                "F2I.S8 R4, |R6|",
                "F2I.S8 R4, -|R6|",
                "F2I.S8 R4, R6",
            ],
        ),
        (
            "sm100a",
            0x08,
            [
                "F2I.U16 R4, R6",
                "F2I.U16 R4, |R6|",
                "F2I.U16 R4, -|R6|",
                "F2I.U16 R4, R6",
            ],
        ),
        (
            "sm100a",
            0x09,
            [
                "F2I.S16 R4, R6",
                "F2I.S16 R4, |R6|",
                "F2I.S16 R4, -|R6|",
                "F2I.S16 R4, R6",
            ],
        ),
        (
            "sm100a",
            0x10,
            [
                "F2I.U32 R4, R6",
                "F2I.U32 R4, |R6|",
                "F2I.U32 R4, -|R6|",
                "F2I.U32 R4, R6",
            ],
        ),
        (
            "sm100a",
            0x11,
            ["F2I R4, R6", "F2I R4, |R6|", "F2I R4, -|R6|", "F2I R4, R6"],
        ),
        (
            "sm100a",
            0x20,
            [
                "F2I.U8.NTZ R4, R6",
                "F2I.U8.NTZ R4, |R6|",
                "F2I.U8.NTZ R4, -|R6|",
                "F2I.U8.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x21,
            [
                "F2I.S8.NTZ R4, R6",
                "F2I.S8.NTZ R4, |R6|",
                "F2I.S8.NTZ R4, -|R6|",
                "F2I.S8.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x28,
            [
                "F2I.U16.NTZ R4, R6",
                "F2I.U16.NTZ R4, |R6|",
                "F2I.U16.NTZ R4, -|R6|",
                "F2I.U16.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x29,
            [
                "F2I.S16.NTZ R4, R6",
                "F2I.S16.NTZ R4, |R6|",
                "F2I.S16.NTZ R4, -|R6|",
                "F2I.S16.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x30,
            [
                "F2I.U32.NTZ R4, R6",
                "F2I.U32.NTZ R4, |R6|",
                "F2I.U32.NTZ R4, -|R6|",
                "F2I.U32.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x31,
            [
                "F2I.NTZ R4, R6",
                "F2I.NTZ R4, |R6|",
                "F2I.NTZ R4, -|R6|",
                "F2I.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x40,
            [
                "F2I.U8.FLOOR R4, R6",
                "F2I.U8.FLOOR R4, |R6|",
                "F2I.U8.FLOOR R4, -|R6|",
                "F2I.U8.FLOOR R4, R6",
            ],
        ),
        (
            "sm100a",
            0x41,
            [
                "F2I.S8.FLOOR R4, R6",
                "F2I.S8.FLOOR R4, |R6|",
                "F2I.S8.FLOOR R4, -|R6|",
                "F2I.S8.FLOOR R4, R6",
            ],
        ),
        (
            "sm100a",
            0x48,
            [
                "F2I.U16.FLOOR R4, R6",
                "F2I.U16.FLOOR R4, |R6|",
                "F2I.U16.FLOOR R4, -|R6|",
                "F2I.U16.FLOOR R4, R6",
            ],
        ),
        (
            "sm100a",
            0x49,
            [
                "F2I.S16.FLOOR R4, R6",
                "F2I.S16.FLOOR R4, |R6|",
                "F2I.S16.FLOOR R4, -|R6|",
                "F2I.S16.FLOOR R4, R6",
            ],
        ),
        (
            "sm100a",
            0x50,
            [
                "F2I.U32.FLOOR R4, R6",
                "F2I.U32.FLOOR R4, |R6|",
                "F2I.U32.FLOOR R4, -|R6|",
                "F2I.U32.FLOOR R4, R6",
            ],
        ),
        (
            "sm100a",
            0x51,
            [
                "F2I.FLOOR R4, R6",
                "F2I.FLOOR R4, |R6|",
                "F2I.FLOOR R4, -|R6|",
                "F2I.FLOOR R4, R6",
            ],
        ),
        (
            "sm100a",
            0x60,
            [
                "F2I.U8.FLOOR.NTZ R4, R6",
                "F2I.U8.FLOOR.NTZ R4, |R6|",
                "F2I.U8.FLOOR.NTZ R4, -|R6|",
                "F2I.U8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x61,
            [
                "F2I.S8.FLOOR.NTZ R4, R6",
                "F2I.S8.FLOOR.NTZ R4, |R6|",
                "F2I.S8.FLOOR.NTZ R4, -|R6|",
                "F2I.S8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x68,
            [
                "F2I.U16.FLOOR.NTZ R4, R6",
                "F2I.U16.FLOOR.NTZ R4, |R6|",
                "F2I.U16.FLOOR.NTZ R4, -|R6|",
                "F2I.U16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x69,
            [
                "F2I.S16.FLOOR.NTZ R4, R6",
                "F2I.S16.FLOOR.NTZ R4, |R6|",
                "F2I.S16.FLOOR.NTZ R4, -|R6|",
                "F2I.S16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x70,
            [
                "F2I.U32.FLOOR.NTZ R4, R6",
                "F2I.U32.FLOOR.NTZ R4, |R6|",
                "F2I.U32.FLOOR.NTZ R4, -|R6|",
                "F2I.U32.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x71,
            [
                "F2I.FLOOR.NTZ R4, R6",
                "F2I.FLOOR.NTZ R4, |R6|",
                "F2I.FLOOR.NTZ R4, -|R6|",
                "F2I.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0x80,
            [
                "F2I.U8.CEIL R4, R6",
                "F2I.U8.CEIL R4, |R6|",
                "F2I.U8.CEIL R4, -|R6|",
                "F2I.U8.CEIL R4, R6",
            ],
        ),
        (
            "sm100a",
            0x81,
            [
                "F2I.S8.CEIL R4, R6",
                "F2I.S8.CEIL R4, |R6|",
                "F2I.S8.CEIL R4, -|R6|",
                "F2I.S8.CEIL R4, R6",
            ],
        ),
        (
            "sm100a",
            0x88,
            [
                "F2I.U16.CEIL R4, R6",
                "F2I.U16.CEIL R4, |R6|",
                "F2I.U16.CEIL R4, -|R6|",
                "F2I.U16.CEIL R4, R6",
            ],
        ),
        (
            "sm100a",
            0x89,
            [
                "F2I.S16.CEIL R4, R6",
                "F2I.S16.CEIL R4, |R6|",
                "F2I.S16.CEIL R4, -|R6|",
                "F2I.S16.CEIL R4, R6",
            ],
        ),
        (
            "sm100a",
            0x90,
            [
                "F2I.U32.CEIL R4, R6",
                "F2I.U32.CEIL R4, |R6|",
                "F2I.U32.CEIL R4, -|R6|",
                "F2I.U32.CEIL R4, R6",
            ],
        ),
        (
            "sm100a",
            0x91,
            [
                "F2I.CEIL R4, R6",
                "F2I.CEIL R4, |R6|",
                "F2I.CEIL R4, -|R6|",
                "F2I.CEIL R4, R6",
            ],
        ),
        (
            "sm100a",
            0xa0,
            [
                "F2I.U8.CEIL.NTZ R4, R6",
                "F2I.U8.CEIL.NTZ R4, |R6|",
                "F2I.U8.CEIL.NTZ R4, -|R6|",
                "F2I.U8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xa1,
            [
                "F2I.S8.CEIL.NTZ R4, R6",
                "F2I.S8.CEIL.NTZ R4, |R6|",
                "F2I.S8.CEIL.NTZ R4, -|R6|",
                "F2I.S8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xa8,
            [
                "F2I.U16.CEIL.NTZ R4, R6",
                "F2I.U16.CEIL.NTZ R4, |R6|",
                "F2I.U16.CEIL.NTZ R4, -|R6|",
                "F2I.U16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xa9,
            [
                "F2I.S16.CEIL.NTZ R4, R6",
                "F2I.S16.CEIL.NTZ R4, |R6|",
                "F2I.S16.CEIL.NTZ R4, -|R6|",
                "F2I.S16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xb0,
            [
                "F2I.U32.CEIL.NTZ R4, R6",
                "F2I.U32.CEIL.NTZ R4, |R6|",
                "F2I.U32.CEIL.NTZ R4, -|R6|",
                "F2I.U32.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xb1,
            [
                "F2I.CEIL.NTZ R4, R6",
                "F2I.CEIL.NTZ R4, |R6|",
                "F2I.CEIL.NTZ R4, -|R6|",
                "F2I.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xc0,
            [
                "F2I.U8.TRUNC R4, R6",
                "F2I.U8.TRUNC R4, |R6|",
                "F2I.U8.TRUNC R4, -|R6|",
                "F2I.U8.TRUNC R4, R6",
            ],
        ),
        (
            "sm100a",
            0xc1,
            [
                "F2I.S8.TRUNC R4, R6",
                "F2I.S8.TRUNC R4, |R6|",
                "F2I.S8.TRUNC R4, -|R6|",
                "F2I.S8.TRUNC R4, R6",
            ],
        ),
        (
            "sm100a",
            0xc8,
            [
                "F2I.U16.TRUNC R4, R6",
                "F2I.U16.TRUNC R4, |R6|",
                "F2I.U16.TRUNC R4, -|R6|",
                "F2I.U16.TRUNC R4, R6",
            ],
        ),
        (
            "sm100a",
            0xc9,
            [
                "F2I.S16.TRUNC R4, R6",
                "F2I.S16.TRUNC R4, |R6|",
                "F2I.S16.TRUNC R4, -|R6|",
                "F2I.S16.TRUNC R4, R6",
            ],
        ),
        (
            "sm100a",
            0xd0,
            [
                "F2I.U32.TRUNC R4, R6",
                "F2I.U32.TRUNC R4, |R6|",
                "F2I.U32.TRUNC R4, -|R6|",
                "F2I.U32.TRUNC R4, R6",
            ],
        ),
        (
            "sm100a",
            0xd1,
            [
                "F2I.TRUNC R4, R6",
                "F2I.TRUNC R4, |R6|",
                "F2I.TRUNC R4, -|R6|",
                "F2I.TRUNC R4, R6",
            ],
        ),
        (
            "sm100a",
            0xe0,
            [
                "F2I.U8.TRUNC.NTZ R4, R6",
                "F2I.U8.TRUNC.NTZ R4, |R6|",
                "F2I.U8.TRUNC.NTZ R4, -|R6|",
                "F2I.U8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xe1,
            [
                "F2I.S8.TRUNC.NTZ R4, R6",
                "F2I.S8.TRUNC.NTZ R4, |R6|",
                "F2I.S8.TRUNC.NTZ R4, -|R6|",
                "F2I.S8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xe8,
            [
                "F2I.U16.TRUNC.NTZ R4, R6",
                "F2I.U16.TRUNC.NTZ R4, |R6|",
                "F2I.U16.TRUNC.NTZ R4, -|R6|",
                "F2I.U16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xe9,
            [
                "F2I.S16.TRUNC.NTZ R4, R6",
                "F2I.S16.TRUNC.NTZ R4, |R6|",
                "F2I.S16.TRUNC.NTZ R4, -|R6|",
                "F2I.S16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xf0,
            [
                "F2I.U32.TRUNC.NTZ R4, R6",
                "F2I.U32.TRUNC.NTZ R4, |R6|",
                "F2I.U32.TRUNC.NTZ R4, -|R6|",
                "F2I.U32.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm100a",
            0xf1,
            [
                "F2I.TRUNC.NTZ R4, R6",
                "F2I.TRUNC.NTZ R4, |R6|",
                "F2I.TRUNC.NTZ R4, -|R6|",
                "F2I.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x00,
            [
                "F2I.U8 R4, R6",
                "F2I.U8 R4, |R6|",
                "F2I.U8 R4, -|R6|",
                "F2I.U8 R4, R6",
            ],
        ),
        (
            "sm103a",
            0x01,
            [
                "F2I.S8 R4, R6",
                "F2I.S8 R4, |R6|",
                "F2I.S8 R4, -|R6|",
                "F2I.S8 R4, R6",
            ],
        ),
        (
            "sm103a",
            0x08,
            [
                "F2I.U16 R4, R6",
                "F2I.U16 R4, |R6|",
                "F2I.U16 R4, -|R6|",
                "F2I.U16 R4, R6",
            ],
        ),
        (
            "sm103a",
            0x09,
            [
                "F2I.S16 R4, R6",
                "F2I.S16 R4, |R6|",
                "F2I.S16 R4, -|R6|",
                "F2I.S16 R4, R6",
            ],
        ),
        (
            "sm103a",
            0x10,
            [
                "F2I.U32 R4, R6",
                "F2I.U32 R4, |R6|",
                "F2I.U32 R4, -|R6|",
                "F2I.U32 R4, R6",
            ],
        ),
        (
            "sm103a",
            0x11,
            ["F2I R4, R6", "F2I R4, |R6|", "F2I R4, -|R6|", "F2I R4, R6"],
        ),
        (
            "sm103a",
            0x20,
            [
                "F2I.U8.NTZ R4, R6",
                "F2I.U8.NTZ R4, |R6|",
                "F2I.U8.NTZ R4, -|R6|",
                "F2I.U8.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x21,
            [
                "F2I.S8.NTZ R4, R6",
                "F2I.S8.NTZ R4, |R6|",
                "F2I.S8.NTZ R4, -|R6|",
                "F2I.S8.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x28,
            [
                "F2I.U16.NTZ R4, R6",
                "F2I.U16.NTZ R4, |R6|",
                "F2I.U16.NTZ R4, -|R6|",
                "F2I.U16.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x29,
            [
                "F2I.S16.NTZ R4, R6",
                "F2I.S16.NTZ R4, |R6|",
                "F2I.S16.NTZ R4, -|R6|",
                "F2I.S16.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x30,
            [
                "F2I.U32.NTZ R4, R6",
                "F2I.U32.NTZ R4, |R6|",
                "F2I.U32.NTZ R4, -|R6|",
                "F2I.U32.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x31,
            [
                "F2I.NTZ R4, R6",
                "F2I.NTZ R4, |R6|",
                "F2I.NTZ R4, -|R6|",
                "F2I.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x40,
            [
                "F2I.U8.FLOOR R4, R6",
                "F2I.U8.FLOOR R4, |R6|",
                "F2I.U8.FLOOR R4, -|R6|",
                "F2I.U8.FLOOR R4, R6",
            ],
        ),
        (
            "sm103a",
            0x41,
            [
                "F2I.S8.FLOOR R4, R6",
                "F2I.S8.FLOOR R4, |R6|",
                "F2I.S8.FLOOR R4, -|R6|",
                "F2I.S8.FLOOR R4, R6",
            ],
        ),
        (
            "sm103a",
            0x48,
            [
                "F2I.U16.FLOOR R4, R6",
                "F2I.U16.FLOOR R4, |R6|",
                "F2I.U16.FLOOR R4, -|R6|",
                "F2I.U16.FLOOR R4, R6",
            ],
        ),
        (
            "sm103a",
            0x49,
            [
                "F2I.S16.FLOOR R4, R6",
                "F2I.S16.FLOOR R4, |R6|",
                "F2I.S16.FLOOR R4, -|R6|",
                "F2I.S16.FLOOR R4, R6",
            ],
        ),
        (
            "sm103a",
            0x50,
            [
                "F2I.U32.FLOOR R4, R6",
                "F2I.U32.FLOOR R4, |R6|",
                "F2I.U32.FLOOR R4, -|R6|",
                "F2I.U32.FLOOR R4, R6",
            ],
        ),
        (
            "sm103a",
            0x51,
            [
                "F2I.FLOOR R4, R6",
                "F2I.FLOOR R4, |R6|",
                "F2I.FLOOR R4, -|R6|",
                "F2I.FLOOR R4, R6",
            ],
        ),
        (
            "sm103a",
            0x60,
            [
                "F2I.U8.FLOOR.NTZ R4, R6",
                "F2I.U8.FLOOR.NTZ R4, |R6|",
                "F2I.U8.FLOOR.NTZ R4, -|R6|",
                "F2I.U8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x61,
            [
                "F2I.S8.FLOOR.NTZ R4, R6",
                "F2I.S8.FLOOR.NTZ R4, |R6|",
                "F2I.S8.FLOOR.NTZ R4, -|R6|",
                "F2I.S8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x68,
            [
                "F2I.U16.FLOOR.NTZ R4, R6",
                "F2I.U16.FLOOR.NTZ R4, |R6|",
                "F2I.U16.FLOOR.NTZ R4, -|R6|",
                "F2I.U16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x69,
            [
                "F2I.S16.FLOOR.NTZ R4, R6",
                "F2I.S16.FLOOR.NTZ R4, |R6|",
                "F2I.S16.FLOOR.NTZ R4, -|R6|",
                "F2I.S16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x70,
            [
                "F2I.U32.FLOOR.NTZ R4, R6",
                "F2I.U32.FLOOR.NTZ R4, |R6|",
                "F2I.U32.FLOOR.NTZ R4, -|R6|",
                "F2I.U32.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x71,
            [
                "F2I.FLOOR.NTZ R4, R6",
                "F2I.FLOOR.NTZ R4, |R6|",
                "F2I.FLOOR.NTZ R4, -|R6|",
                "F2I.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0x80,
            [
                "F2I.U8.CEIL R4, R6",
                "F2I.U8.CEIL R4, |R6|",
                "F2I.U8.CEIL R4, -|R6|",
                "F2I.U8.CEIL R4, R6",
            ],
        ),
        (
            "sm103a",
            0x81,
            [
                "F2I.S8.CEIL R4, R6",
                "F2I.S8.CEIL R4, |R6|",
                "F2I.S8.CEIL R4, -|R6|",
                "F2I.S8.CEIL R4, R6",
            ],
        ),
        (
            "sm103a",
            0x88,
            [
                "F2I.U16.CEIL R4, R6",
                "F2I.U16.CEIL R4, |R6|",
                "F2I.U16.CEIL R4, -|R6|",
                "F2I.U16.CEIL R4, R6",
            ],
        ),
        (
            "sm103a",
            0x89,
            [
                "F2I.S16.CEIL R4, R6",
                "F2I.S16.CEIL R4, |R6|",
                "F2I.S16.CEIL R4, -|R6|",
                "F2I.S16.CEIL R4, R6",
            ],
        ),
        (
            "sm103a",
            0x90,
            [
                "F2I.U32.CEIL R4, R6",
                "F2I.U32.CEIL R4, |R6|",
                "F2I.U32.CEIL R4, -|R6|",
                "F2I.U32.CEIL R4, R6",
            ],
        ),
        (
            "sm103a",
            0x91,
            [
                "F2I.CEIL R4, R6",
                "F2I.CEIL R4, |R6|",
                "F2I.CEIL R4, -|R6|",
                "F2I.CEIL R4, R6",
            ],
        ),
        (
            "sm103a",
            0xa0,
            [
                "F2I.U8.CEIL.NTZ R4, R6",
                "F2I.U8.CEIL.NTZ R4, |R6|",
                "F2I.U8.CEIL.NTZ R4, -|R6|",
                "F2I.U8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xa1,
            [
                "F2I.S8.CEIL.NTZ R4, R6",
                "F2I.S8.CEIL.NTZ R4, |R6|",
                "F2I.S8.CEIL.NTZ R4, -|R6|",
                "F2I.S8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xa8,
            [
                "F2I.U16.CEIL.NTZ R4, R6",
                "F2I.U16.CEIL.NTZ R4, |R6|",
                "F2I.U16.CEIL.NTZ R4, -|R6|",
                "F2I.U16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xa9,
            [
                "F2I.S16.CEIL.NTZ R4, R6",
                "F2I.S16.CEIL.NTZ R4, |R6|",
                "F2I.S16.CEIL.NTZ R4, -|R6|",
                "F2I.S16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xb0,
            [
                "F2I.U32.CEIL.NTZ R4, R6",
                "F2I.U32.CEIL.NTZ R4, |R6|",
                "F2I.U32.CEIL.NTZ R4, -|R6|",
                "F2I.U32.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xb1,
            [
                "F2I.CEIL.NTZ R4, R6",
                "F2I.CEIL.NTZ R4, |R6|",
                "F2I.CEIL.NTZ R4, -|R6|",
                "F2I.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xc0,
            [
                "F2I.U8.TRUNC R4, R6",
                "F2I.U8.TRUNC R4, |R6|",
                "F2I.U8.TRUNC R4, -|R6|",
                "F2I.U8.TRUNC R4, R6",
            ],
        ),
        (
            "sm103a",
            0xc1,
            [
                "F2I.S8.TRUNC R4, R6",
                "F2I.S8.TRUNC R4, |R6|",
                "F2I.S8.TRUNC R4, -|R6|",
                "F2I.S8.TRUNC R4, R6",
            ],
        ),
        (
            "sm103a",
            0xc8,
            [
                "F2I.U16.TRUNC R4, R6",
                "F2I.U16.TRUNC R4, |R6|",
                "F2I.U16.TRUNC R4, -|R6|",
                "F2I.U16.TRUNC R4, R6",
            ],
        ),
        (
            "sm103a",
            0xc9,
            [
                "F2I.S16.TRUNC R4, R6",
                "F2I.S16.TRUNC R4, |R6|",
                "F2I.S16.TRUNC R4, -|R6|",
                "F2I.S16.TRUNC R4, R6",
            ],
        ),
        (
            "sm103a",
            0xd0,
            [
                "F2I.U32.TRUNC R4, R6",
                "F2I.U32.TRUNC R4, |R6|",
                "F2I.U32.TRUNC R4, -|R6|",
                "F2I.U32.TRUNC R4, R6",
            ],
        ),
        (
            "sm103a",
            0xd1,
            [
                "F2I.TRUNC R4, R6",
                "F2I.TRUNC R4, |R6|",
                "F2I.TRUNC R4, -|R6|",
                "F2I.TRUNC R4, R6",
            ],
        ),
        (
            "sm103a",
            0xe0,
            [
                "F2I.U8.TRUNC.NTZ R4, R6",
                "F2I.U8.TRUNC.NTZ R4, |R6|",
                "F2I.U8.TRUNC.NTZ R4, -|R6|",
                "F2I.U8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xe1,
            [
                "F2I.S8.TRUNC.NTZ R4, R6",
                "F2I.S8.TRUNC.NTZ R4, |R6|",
                "F2I.S8.TRUNC.NTZ R4, -|R6|",
                "F2I.S8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xe8,
            [
                "F2I.U16.TRUNC.NTZ R4, R6",
                "F2I.U16.TRUNC.NTZ R4, |R6|",
                "F2I.U16.TRUNC.NTZ R4, -|R6|",
                "F2I.U16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xe9,
            [
                "F2I.S16.TRUNC.NTZ R4, R6",
                "F2I.S16.TRUNC.NTZ R4, |R6|",
                "F2I.S16.TRUNC.NTZ R4, -|R6|",
                "F2I.S16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xf0,
            [
                "F2I.U32.TRUNC.NTZ R4, R6",
                "F2I.U32.TRUNC.NTZ R4, |R6|",
                "F2I.U32.TRUNC.NTZ R4, -|R6|",
                "F2I.U32.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm103a",
            0xf1,
            [
                "F2I.TRUNC.NTZ R4, R6",
                "F2I.TRUNC.NTZ R4, |R6|",
                "F2I.TRUNC.NTZ R4, -|R6|",
                "F2I.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x00,
            [
                "F2I.U8 R4, R6",
                "F2I.U8 R4, |R6|",
                "F2I.U8 R4, -|R6|",
                "F2I.U8 R4, R6",
            ],
        ),
        (
            "sm120",
            0x01,
            [
                "F2I.S8 R4, R6",
                "F2I.S8 R4, |R6|",
                "F2I.S8 R4, -|R6|",
                "F2I.S8 R4, R6",
            ],
        ),
        (
            "sm120",
            0x08,
            [
                "F2I.U16 R4, R6",
                "F2I.U16 R4, |R6|",
                "F2I.U16 R4, -|R6|",
                "F2I.U16 R4, R6",
            ],
        ),
        (
            "sm120",
            0x09,
            [
                "F2I.S16 R4, R6",
                "F2I.S16 R4, |R6|",
                "F2I.S16 R4, -|R6|",
                "F2I.S16 R4, R6",
            ],
        ),
        (
            "sm120",
            0x10,
            [
                "F2I.U32 R4, R6",
                "F2I.U32 R4, |R6|",
                "F2I.U32 R4, -|R6|",
                "F2I.U32 R4, R6",
            ],
        ),
        (
            "sm120",
            0x11,
            ["F2I R4, R6", "F2I R4, |R6|", "F2I R4, -|R6|", "F2I R4, R6"],
        ),
        (
            "sm120",
            0x20,
            [
                "F2I.U8.NTZ R4, R6",
                "F2I.U8.NTZ R4, |R6|",
                "F2I.U8.NTZ R4, -|R6|",
                "F2I.U8.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x21,
            [
                "F2I.S8.NTZ R4, R6",
                "F2I.S8.NTZ R4, |R6|",
                "F2I.S8.NTZ R4, -|R6|",
                "F2I.S8.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x28,
            [
                "F2I.U16.NTZ R4, R6",
                "F2I.U16.NTZ R4, |R6|",
                "F2I.U16.NTZ R4, -|R6|",
                "F2I.U16.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x29,
            [
                "F2I.S16.NTZ R4, R6",
                "F2I.S16.NTZ R4, |R6|",
                "F2I.S16.NTZ R4, -|R6|",
                "F2I.S16.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x30,
            [
                "F2I.U32.NTZ R4, R6",
                "F2I.U32.NTZ R4, |R6|",
                "F2I.U32.NTZ R4, -|R6|",
                "F2I.U32.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x31,
            [
                "F2I.NTZ R4, R6",
                "F2I.NTZ R4, |R6|",
                "F2I.NTZ R4, -|R6|",
                "F2I.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x40,
            [
                "F2I.U8.FLOOR R4, R6",
                "F2I.U8.FLOOR R4, |R6|",
                "F2I.U8.FLOOR R4, -|R6|",
                "F2I.U8.FLOOR R4, R6",
            ],
        ),
        (
            "sm120",
            0x41,
            [
                "F2I.S8.FLOOR R4, R6",
                "F2I.S8.FLOOR R4, |R6|",
                "F2I.S8.FLOOR R4, -|R6|",
                "F2I.S8.FLOOR R4, R6",
            ],
        ),
        (
            "sm120",
            0x48,
            [
                "F2I.U16.FLOOR R4, R6",
                "F2I.U16.FLOOR R4, |R6|",
                "F2I.U16.FLOOR R4, -|R6|",
                "F2I.U16.FLOOR R4, R6",
            ],
        ),
        (
            "sm120",
            0x49,
            [
                "F2I.S16.FLOOR R4, R6",
                "F2I.S16.FLOOR R4, |R6|",
                "F2I.S16.FLOOR R4, -|R6|",
                "F2I.S16.FLOOR R4, R6",
            ],
        ),
        (
            "sm120",
            0x50,
            [
                "F2I.U32.FLOOR R4, R6",
                "F2I.U32.FLOOR R4, |R6|",
                "F2I.U32.FLOOR R4, -|R6|",
                "F2I.U32.FLOOR R4, R6",
            ],
        ),
        (
            "sm120",
            0x51,
            [
                "F2I.FLOOR R4, R6",
                "F2I.FLOOR R4, |R6|",
                "F2I.FLOOR R4, -|R6|",
                "F2I.FLOOR R4, R6",
            ],
        ),
        (
            "sm120",
            0x60,
            [
                "F2I.U8.FLOOR.NTZ R4, R6",
                "F2I.U8.FLOOR.NTZ R4, |R6|",
                "F2I.U8.FLOOR.NTZ R4, -|R6|",
                "F2I.U8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x61,
            [
                "F2I.S8.FLOOR.NTZ R4, R6",
                "F2I.S8.FLOOR.NTZ R4, |R6|",
                "F2I.S8.FLOOR.NTZ R4, -|R6|",
                "F2I.S8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x68,
            [
                "F2I.U16.FLOOR.NTZ R4, R6",
                "F2I.U16.FLOOR.NTZ R4, |R6|",
                "F2I.U16.FLOOR.NTZ R4, -|R6|",
                "F2I.U16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x69,
            [
                "F2I.S16.FLOOR.NTZ R4, R6",
                "F2I.S16.FLOOR.NTZ R4, |R6|",
                "F2I.S16.FLOOR.NTZ R4, -|R6|",
                "F2I.S16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x70,
            [
                "F2I.U32.FLOOR.NTZ R4, R6",
                "F2I.U32.FLOOR.NTZ R4, |R6|",
                "F2I.U32.FLOOR.NTZ R4, -|R6|",
                "F2I.U32.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x71,
            [
                "F2I.FLOOR.NTZ R4, R6",
                "F2I.FLOOR.NTZ R4, |R6|",
                "F2I.FLOOR.NTZ R4, -|R6|",
                "F2I.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0x80,
            [
                "F2I.U8.CEIL R4, R6",
                "F2I.U8.CEIL R4, |R6|",
                "F2I.U8.CEIL R4, -|R6|",
                "F2I.U8.CEIL R4, R6",
            ],
        ),
        (
            "sm120",
            0x81,
            [
                "F2I.S8.CEIL R4, R6",
                "F2I.S8.CEIL R4, |R6|",
                "F2I.S8.CEIL R4, -|R6|",
                "F2I.S8.CEIL R4, R6",
            ],
        ),
        (
            "sm120",
            0x88,
            [
                "F2I.U16.CEIL R4, R6",
                "F2I.U16.CEIL R4, |R6|",
                "F2I.U16.CEIL R4, -|R6|",
                "F2I.U16.CEIL R4, R6",
            ],
        ),
        (
            "sm120",
            0x89,
            [
                "F2I.S16.CEIL R4, R6",
                "F2I.S16.CEIL R4, |R6|",
                "F2I.S16.CEIL R4, -|R6|",
                "F2I.S16.CEIL R4, R6",
            ],
        ),
        (
            "sm120",
            0x90,
            [
                "F2I.U32.CEIL R4, R6",
                "F2I.U32.CEIL R4, |R6|",
                "F2I.U32.CEIL R4, -|R6|",
                "F2I.U32.CEIL R4, R6",
            ],
        ),
        (
            "sm120",
            0x91,
            [
                "F2I.CEIL R4, R6",
                "F2I.CEIL R4, |R6|",
                "F2I.CEIL R4, -|R6|",
                "F2I.CEIL R4, R6",
            ],
        ),
        (
            "sm120",
            0xa0,
            [
                "F2I.U8.CEIL.NTZ R4, R6",
                "F2I.U8.CEIL.NTZ R4, |R6|",
                "F2I.U8.CEIL.NTZ R4, -|R6|",
                "F2I.U8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xa1,
            [
                "F2I.S8.CEIL.NTZ R4, R6",
                "F2I.S8.CEIL.NTZ R4, |R6|",
                "F2I.S8.CEIL.NTZ R4, -|R6|",
                "F2I.S8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xa8,
            [
                "F2I.U16.CEIL.NTZ R4, R6",
                "F2I.U16.CEIL.NTZ R4, |R6|",
                "F2I.U16.CEIL.NTZ R4, -|R6|",
                "F2I.U16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xa9,
            [
                "F2I.S16.CEIL.NTZ R4, R6",
                "F2I.S16.CEIL.NTZ R4, |R6|",
                "F2I.S16.CEIL.NTZ R4, -|R6|",
                "F2I.S16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xb0,
            [
                "F2I.U32.CEIL.NTZ R4, R6",
                "F2I.U32.CEIL.NTZ R4, |R6|",
                "F2I.U32.CEIL.NTZ R4, -|R6|",
                "F2I.U32.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xb1,
            [
                "F2I.CEIL.NTZ R4, R6",
                "F2I.CEIL.NTZ R4, |R6|",
                "F2I.CEIL.NTZ R4, -|R6|",
                "F2I.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xc0,
            [
                "F2I.U8.TRUNC R4, R6",
                "F2I.U8.TRUNC R4, |R6|",
                "F2I.U8.TRUNC R4, -|R6|",
                "F2I.U8.TRUNC R4, R6",
            ],
        ),
        (
            "sm120",
            0xc1,
            [
                "F2I.S8.TRUNC R4, R6",
                "F2I.S8.TRUNC R4, |R6|",
                "F2I.S8.TRUNC R4, -|R6|",
                "F2I.S8.TRUNC R4, R6",
            ],
        ),
        (
            "sm120",
            0xc8,
            [
                "F2I.U16.TRUNC R4, R6",
                "F2I.U16.TRUNC R4, |R6|",
                "F2I.U16.TRUNC R4, -|R6|",
                "F2I.U16.TRUNC R4, R6",
            ],
        ),
        (
            "sm120",
            0xc9,
            [
                "F2I.S16.TRUNC R4, R6",
                "F2I.S16.TRUNC R4, |R6|",
                "F2I.S16.TRUNC R4, -|R6|",
                "F2I.S16.TRUNC R4, R6",
            ],
        ),
        (
            "sm120",
            0xd0,
            [
                "F2I.U32.TRUNC R4, R6",
                "F2I.U32.TRUNC R4, |R6|",
                "F2I.U32.TRUNC R4, -|R6|",
                "F2I.U32.TRUNC R4, R6",
            ],
        ),
        (
            "sm120",
            0xd1,
            [
                "F2I.TRUNC R4, R6",
                "F2I.TRUNC R4, |R6|",
                "F2I.TRUNC R4, -|R6|",
                "F2I.TRUNC R4, R6",
            ],
        ),
        (
            "sm120",
            0xe0,
            [
                "F2I.U8.TRUNC.NTZ R4, R6",
                "F2I.U8.TRUNC.NTZ R4, |R6|",
                "F2I.U8.TRUNC.NTZ R4, -|R6|",
                "F2I.U8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xe1,
            [
                "F2I.S8.TRUNC.NTZ R4, R6",
                "F2I.S8.TRUNC.NTZ R4, |R6|",
                "F2I.S8.TRUNC.NTZ R4, -|R6|",
                "F2I.S8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xe8,
            [
                "F2I.U16.TRUNC.NTZ R4, R6",
                "F2I.U16.TRUNC.NTZ R4, |R6|",
                "F2I.U16.TRUNC.NTZ R4, -|R6|",
                "F2I.U16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xe9,
            [
                "F2I.S16.TRUNC.NTZ R4, R6",
                "F2I.S16.TRUNC.NTZ R4, |R6|",
                "F2I.S16.TRUNC.NTZ R4, -|R6|",
                "F2I.S16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xf0,
            [
                "F2I.U32.TRUNC.NTZ R4, R6",
                "F2I.U32.TRUNC.NTZ R4, |R6|",
                "F2I.U32.TRUNC.NTZ R4, -|R6|",
                "F2I.U32.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm120",
            0xf1,
            [
                "F2I.TRUNC.NTZ R4, R6",
                "F2I.TRUNC.NTZ R4, |R6|",
                "F2I.TRUNC.NTZ R4, -|R6|",
                "F2I.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x00,
            [
                "F2I.U8 R4, R6",
                "F2I.U8 R4, |R6|",
                "F2I.U8 R4, -|R6|",
                "F2I.U8 R4, R6",
            ],
        ),
        (
            "sm121a",
            0x01,
            [
                "F2I.S8 R4, R6",
                "F2I.S8 R4, |R6|",
                "F2I.S8 R4, -|R6|",
                "F2I.S8 R4, R6",
            ],
        ),
        (
            "sm121a",
            0x08,
            [
                "F2I.U16 R4, R6",
                "F2I.U16 R4, |R6|",
                "F2I.U16 R4, -|R6|",
                "F2I.U16 R4, R6",
            ],
        ),
        (
            "sm121a",
            0x09,
            [
                "F2I.S16 R4, R6",
                "F2I.S16 R4, |R6|",
                "F2I.S16 R4, -|R6|",
                "F2I.S16 R4, R6",
            ],
        ),
        (
            "sm121a",
            0x10,
            [
                "F2I.U32 R4, R6",
                "F2I.U32 R4, |R6|",
                "F2I.U32 R4, -|R6|",
                "F2I.U32 R4, R6",
            ],
        ),
        (
            "sm121a",
            0x11,
            ["F2I R4, R6", "F2I R4, |R6|", "F2I R4, -|R6|", "F2I R4, R6"],
        ),
        (
            "sm121a",
            0x20,
            [
                "F2I.U8.NTZ R4, R6",
                "F2I.U8.NTZ R4, |R6|",
                "F2I.U8.NTZ R4, -|R6|",
                "F2I.U8.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x21,
            [
                "F2I.S8.NTZ R4, R6",
                "F2I.S8.NTZ R4, |R6|",
                "F2I.S8.NTZ R4, -|R6|",
                "F2I.S8.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x28,
            [
                "F2I.U16.NTZ R4, R6",
                "F2I.U16.NTZ R4, |R6|",
                "F2I.U16.NTZ R4, -|R6|",
                "F2I.U16.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x29,
            [
                "F2I.S16.NTZ R4, R6",
                "F2I.S16.NTZ R4, |R6|",
                "F2I.S16.NTZ R4, -|R6|",
                "F2I.S16.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x30,
            [
                "F2I.U32.NTZ R4, R6",
                "F2I.U32.NTZ R4, |R6|",
                "F2I.U32.NTZ R4, -|R6|",
                "F2I.U32.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x31,
            [
                "F2I.NTZ R4, R6",
                "F2I.NTZ R4, |R6|",
                "F2I.NTZ R4, -|R6|",
                "F2I.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x40,
            [
                "F2I.U8.FLOOR R4, R6",
                "F2I.U8.FLOOR R4, |R6|",
                "F2I.U8.FLOOR R4, -|R6|",
                "F2I.U8.FLOOR R4, R6",
            ],
        ),
        (
            "sm121a",
            0x41,
            [
                "F2I.S8.FLOOR R4, R6",
                "F2I.S8.FLOOR R4, |R6|",
                "F2I.S8.FLOOR R4, -|R6|",
                "F2I.S8.FLOOR R4, R6",
            ],
        ),
        (
            "sm121a",
            0x48,
            [
                "F2I.U16.FLOOR R4, R6",
                "F2I.U16.FLOOR R4, |R6|",
                "F2I.U16.FLOOR R4, -|R6|",
                "F2I.U16.FLOOR R4, R6",
            ],
        ),
        (
            "sm121a",
            0x49,
            [
                "F2I.S16.FLOOR R4, R6",
                "F2I.S16.FLOOR R4, |R6|",
                "F2I.S16.FLOOR R4, -|R6|",
                "F2I.S16.FLOOR R4, R6",
            ],
        ),
        (
            "sm121a",
            0x50,
            [
                "F2I.U32.FLOOR R4, R6",
                "F2I.U32.FLOOR R4, |R6|",
                "F2I.U32.FLOOR R4, -|R6|",
                "F2I.U32.FLOOR R4, R6",
            ],
        ),
        (
            "sm121a",
            0x51,
            [
                "F2I.FLOOR R4, R6",
                "F2I.FLOOR R4, |R6|",
                "F2I.FLOOR R4, -|R6|",
                "F2I.FLOOR R4, R6",
            ],
        ),
        (
            "sm121a",
            0x60,
            [
                "F2I.U8.FLOOR.NTZ R4, R6",
                "F2I.U8.FLOOR.NTZ R4, |R6|",
                "F2I.U8.FLOOR.NTZ R4, -|R6|",
                "F2I.U8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x61,
            [
                "F2I.S8.FLOOR.NTZ R4, R6",
                "F2I.S8.FLOOR.NTZ R4, |R6|",
                "F2I.S8.FLOOR.NTZ R4, -|R6|",
                "F2I.S8.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x68,
            [
                "F2I.U16.FLOOR.NTZ R4, R6",
                "F2I.U16.FLOOR.NTZ R4, |R6|",
                "F2I.U16.FLOOR.NTZ R4, -|R6|",
                "F2I.U16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x69,
            [
                "F2I.S16.FLOOR.NTZ R4, R6",
                "F2I.S16.FLOOR.NTZ R4, |R6|",
                "F2I.S16.FLOOR.NTZ R4, -|R6|",
                "F2I.S16.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x70,
            [
                "F2I.U32.FLOOR.NTZ R4, R6",
                "F2I.U32.FLOOR.NTZ R4, |R6|",
                "F2I.U32.FLOOR.NTZ R4, -|R6|",
                "F2I.U32.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x71,
            [
                "F2I.FLOOR.NTZ R4, R6",
                "F2I.FLOOR.NTZ R4, |R6|",
                "F2I.FLOOR.NTZ R4, -|R6|",
                "F2I.FLOOR.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0x80,
            [
                "F2I.U8.CEIL R4, R6",
                "F2I.U8.CEIL R4, |R6|",
                "F2I.U8.CEIL R4, -|R6|",
                "F2I.U8.CEIL R4, R6",
            ],
        ),
        (
            "sm121a",
            0x81,
            [
                "F2I.S8.CEIL R4, R6",
                "F2I.S8.CEIL R4, |R6|",
                "F2I.S8.CEIL R4, -|R6|",
                "F2I.S8.CEIL R4, R6",
            ],
        ),
        (
            "sm121a",
            0x88,
            [
                "F2I.U16.CEIL R4, R6",
                "F2I.U16.CEIL R4, |R6|",
                "F2I.U16.CEIL R4, -|R6|",
                "F2I.U16.CEIL R4, R6",
            ],
        ),
        (
            "sm121a",
            0x89,
            [
                "F2I.S16.CEIL R4, R6",
                "F2I.S16.CEIL R4, |R6|",
                "F2I.S16.CEIL R4, -|R6|",
                "F2I.S16.CEIL R4, R6",
            ],
        ),
        (
            "sm121a",
            0x90,
            [
                "F2I.U32.CEIL R4, R6",
                "F2I.U32.CEIL R4, |R6|",
                "F2I.U32.CEIL R4, -|R6|",
                "F2I.U32.CEIL R4, R6",
            ],
        ),
        (
            "sm121a",
            0x91,
            [
                "F2I.CEIL R4, R6",
                "F2I.CEIL R4, |R6|",
                "F2I.CEIL R4, -|R6|",
                "F2I.CEIL R4, R6",
            ],
        ),
        (
            "sm121a",
            0xa0,
            [
                "F2I.U8.CEIL.NTZ R4, R6",
                "F2I.U8.CEIL.NTZ R4, |R6|",
                "F2I.U8.CEIL.NTZ R4, -|R6|",
                "F2I.U8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xa1,
            [
                "F2I.S8.CEIL.NTZ R4, R6",
                "F2I.S8.CEIL.NTZ R4, |R6|",
                "F2I.S8.CEIL.NTZ R4, -|R6|",
                "F2I.S8.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xa8,
            [
                "F2I.U16.CEIL.NTZ R4, R6",
                "F2I.U16.CEIL.NTZ R4, |R6|",
                "F2I.U16.CEIL.NTZ R4, -|R6|",
                "F2I.U16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xa9,
            [
                "F2I.S16.CEIL.NTZ R4, R6",
                "F2I.S16.CEIL.NTZ R4, |R6|",
                "F2I.S16.CEIL.NTZ R4, -|R6|",
                "F2I.S16.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xb0,
            [
                "F2I.U32.CEIL.NTZ R4, R6",
                "F2I.U32.CEIL.NTZ R4, |R6|",
                "F2I.U32.CEIL.NTZ R4, -|R6|",
                "F2I.U32.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xb1,
            [
                "F2I.CEIL.NTZ R4, R6",
                "F2I.CEIL.NTZ R4, |R6|",
                "F2I.CEIL.NTZ R4, -|R6|",
                "F2I.CEIL.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xc0,
            [
                "F2I.U8.TRUNC R4, R6",
                "F2I.U8.TRUNC R4, |R6|",
                "F2I.U8.TRUNC R4, -|R6|",
                "F2I.U8.TRUNC R4, R6",
            ],
        ),
        (
            "sm121a",
            0xc1,
            [
                "F2I.S8.TRUNC R4, R6",
                "F2I.S8.TRUNC R4, |R6|",
                "F2I.S8.TRUNC R4, -|R6|",
                "F2I.S8.TRUNC R4, R6",
            ],
        ),
        (
            "sm121a",
            0xc8,
            [
                "F2I.U16.TRUNC R4, R6",
                "F2I.U16.TRUNC R4, |R6|",
                "F2I.U16.TRUNC R4, -|R6|",
                "F2I.U16.TRUNC R4, R6",
            ],
        ),
        (
            "sm121a",
            0xc9,
            [
                "F2I.S16.TRUNC R4, R6",
                "F2I.S16.TRUNC R4, |R6|",
                "F2I.S16.TRUNC R4, -|R6|",
                "F2I.S16.TRUNC R4, R6",
            ],
        ),
        (
            "sm121a",
            0xd0,
            [
                "F2I.U32.TRUNC R4, R6",
                "F2I.U32.TRUNC R4, |R6|",
                "F2I.U32.TRUNC R4, -|R6|",
                "F2I.U32.TRUNC R4, R6",
            ],
        ),
        (
            "sm121a",
            0xd1,
            [
                "F2I.TRUNC R4, R6",
                "F2I.TRUNC R4, |R6|",
                "F2I.TRUNC R4, -|R6|",
                "F2I.TRUNC R4, R6",
            ],
        ),
        (
            "sm121a",
            0xe0,
            [
                "F2I.U8.TRUNC.NTZ R4, R6",
                "F2I.U8.TRUNC.NTZ R4, |R6|",
                "F2I.U8.TRUNC.NTZ R4, -|R6|",
                "F2I.U8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xe1,
            [
                "F2I.S8.TRUNC.NTZ R4, R6",
                "F2I.S8.TRUNC.NTZ R4, |R6|",
                "F2I.S8.TRUNC.NTZ R4, -|R6|",
                "F2I.S8.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xe8,
            [
                "F2I.U16.TRUNC.NTZ R4, R6",
                "F2I.U16.TRUNC.NTZ R4, |R6|",
                "F2I.U16.TRUNC.NTZ R4, -|R6|",
                "F2I.U16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xe9,
            [
                "F2I.S16.TRUNC.NTZ R4, R6",
                "F2I.S16.TRUNC.NTZ R4, |R6|",
                "F2I.S16.TRUNC.NTZ R4, -|R6|",
                "F2I.S16.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xf0,
            [
                "F2I.U32.TRUNC.NTZ R4, R6",
                "F2I.U32.TRUNC.NTZ R4, |R6|",
                "F2I.U32.TRUNC.NTZ R4, -|R6|",
                "F2I.U32.TRUNC.NTZ R4, R6",
            ],
        ),
        (
            "sm121a",
            0xf1,
            [
                "F2I.TRUNC.NTZ R4, R6",
                "F2I.TRUNC.NTZ R4, |R6|",
                "F2I.TRUNC.NTZ R4, -|R6|",
                "F2I.TRUNC.NTZ R4, R6",
            ],
        ),
    ];
    for (arch, lane, cells) in expect {
        let t = tab(arch);
        let base = word(*lane, 7, 4, 6, 0);
        let got = [
            dec(&t, base),
            dec(&t, base | (1u128 << 62)),
            dec(&t, base | (3u128 << 62)),
            dec(&t, base | (2u128 << 72)),
        ];
        for (i, want) in cells.iter().enumerate() {
            assert_eq!(
                got[i].as_deref().unwrap_or("HOLE"),
                *want,
                "{arch} lane {lane:#04x} cell{i} got {:?}",
                got[i]
            );
        }
    }
}

#[test]
fn t341_3_authored_mints_byte_exact_and_roundtrips() {
    let cases: &[(&str, &str, u128)] = &[
        ("sm100a", "F2I R4, R6", 0x002011000000000600047305),
        ("sm120", "F2I R4, R6", 0x002011000000000600047305),
        ("sm100a", "F2I.U8 R4, R6", 0x002000000000000600047305),
        ("sm120", "F2I.U8 R4, R6", 0x002000000000000600047305),
        ("sm100a", "F2I.S16.NTZ R4, R6", 0x002029000000000600047305),
        ("sm103a", "F2I.S16.NTZ R4, R6", 0x002029000000000600047305),
        ("sm120", "F2I.S16.NTZ R4, R6", 0x002029000000000600047305),
        ("sm121a", "F2I.S16.NTZ R4, R6", 0x002029000000000600047305),
        ("sm100a", "F2I.NTZ R1, |R15|", 0x002031004000000f00017305),
        ("sm103a", "F2I.NTZ R1, |R15|", 0x002031004000000f00017305),
        ("sm100a", "F2I.S8.NTZ R4, -R6", 0x002021008000000600047305),
        ("sm100a", "F2I.U32.NTZ R4, |R6|", 0x002030004000000600047305),
        (
            "sm100a",
            "F2I.CEIL.NTZ R4, -|R6|",
            0x0020b100c000000600047305,
        ),
        (
            "sm100a",
            "F2I.U8.FLOOR.NTZ R4, R6",
            0x002060000000000600047305,
        ),
        ("sm120", "F2I.S8.NTZ R4, -R6", 0x002021008000000600047305),
        ("sm121a", "F2I.S8.NTZ R4, -R6", 0x002021008000000600047305),
        (
            "sm120",
            "F2I.U8.FLOOR.NTZ R4, R6",
            0x002060000000000600047305,
        ),
        ("sm120", "F2I.U32.NTZ R4, R6", 0x002030000000000600047305),
    ];
    for (arch, text, want) in cases {
        let t = tab(arch);
        let w = enc(&t, text).unwrap() & M96;
        assert_eq!(w, want & M96, "{arch} mint {text}");
        let back = dec(&t, w).unwrap();
        let w2 = enc(&t, &back).unwrap() & M96;
        assert_eq!(w2, w, "{arch} roundtrip {text} via {back}");
    }
}

#[test]
fn t341_4_fail_closed_residua() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for lane in [0x18u32, 0x19u32, 0x78u32, 0xd9u32] {
            assert!(
                dec(&t, word(lane, 7, 4, 6, 0)).is_none(),
                "{arch} ??? lane {lane:#x}"
            );
        }
        assert!(
            dec(
                &t,
                0x0305u128 | (4u128 << 16) | (6u128 << 32) | (0x31u128 << 72)
            )
            .is_none(),
            "{arch} byte10=0 stays hole"
        );
    }
    let t = tab("sm103a");
    assert!(enc(&t, "@P0 F2I -R4, 1.5").is_err(), "F2I_R_FI sign refuse");
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        assert!(
            enc(&t, "F2I.NTZ R1, |R15|").is_err(),
            "{arch} mg-lane signed mint refuse (364)"
        );
        assert!(
            enc(&t, "F2I.U32.NTZ R4, |R6|").is_err(),
            "{arch} mg-lane signed mint refuse (364)"
        );
    }
}

#[test]
fn t341_5_corpus_lane_prints_byte_stable() {
    // corpus lanes {31,70,71,f0,f1} x4: publish prints pinned verbatim
    let words: &[(&str, u128, &str)] = &[
        // attr341 corpus witnesses (publish print pinned; DRIFT = 361-kand, mg owners)
        ("sm100a", 0x002031000000000000007305, "F2I.NTZ R0, R0"),
        ("sm103a", 0x002031000000000000007305, "F2I.NTZ R0, R0"),
        ("sm100a", 0x002071000000000000007305, "F2I.FLOOR.NTZ R0, R0"),
        ("sm103a", 0x002071000000000000007305, "F2I.FLOOR.NTZ R0, R0"),
        (
            "sm100a",
            0x002070000000000000097305,
            "F2I.U32.FLOOR.NTZ R9, R0",
        ),
        (
            "sm103a",
            0x0020f0000000000700077305,
            "F2I.U32.TRUNC.NTZ R7, R7",
        ),
        ("sm100a", 0x0020f1000000000000037305, "F2I.TRUNC.NTZ R3, R0"),
    ];
    for (arch, w, want) in words {
        let t = tab(arch);
        let got = dec(&t, *w).unwrap();
        assert_eq!(&got, want, "{arch} corpus-lane {w:#x} print stability");
    }
}
