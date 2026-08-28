//! BUG-243 (F2-iter122, front2/blind, 2026-08-28): HFMA2 wave closure
//! (canonical 0b6a753; patch243.py replayable+idempotent).
//!
//! Pre-fix state (gold241 post-census, 2,406-file battery x 4 legs vs vendor
//! nvdisasm 13.3.73 at-address): donors HFMA2 114,316 DIFF (tok2 `-RZ` neg
//! drop on the 5-token FI_FI form; b72 era-baked in and_base) + BF16_V2 35
//! (hsel on UR token dropped); sm120 HFMA2 15,980 DIFF + 40,884 HOLE +
//! BF16_V2 2,628+446 (era rows: guard 2b@13 -> `@P3 .. !rsd[14:1]` ghost,
//! missing hsel/reuse/neg fields -> HOLE storm on reuse+hsel words,
//! BF16 imm printed `0, 0` instead of `1, 1`, typed BF16 rows narrow).
//!
//! Laws (hfma2law.json: 158,311-line census / 33,972 uniq vendor words):
//!   L1 src1 '-' <-> b72 (9,438/9,438 uniq FI_FI words; zero counterexample)
//!   L2 hsel 2b: src1 @74-75, src2 @60-61, src3 @81-82; 2=.H0_H0 3=.H1_H1
//!      (0=unprinted; 1 never observed)
//!   L3 reuse: src1 b122, src2 b123, src3 b124 (uniq witnesses in thousands)
//!   L4 src3 neg @84 (82 uniq RRRR + 12 UR-form)
//!   L5 guard 4b@12, PT=7 (b12..15 = 1,1,1,0); era sm120 carried 2b@13
//!   L6 BF16_V2 pivot = b85 baked (all three table legs)
//!   L7 UR token prints .H0_H0/.H1_H1 but never .reuse/- (26/26 uniq words
//!      + 226d printer law); rebuilt UR row carries no field@123/- on tok3.
//! Engine arm (printer.rs, BUG-243): raw-bits abs recovery for the @64 slot
//! is skipped on HFMA2 rows -- b74 there is the src1 hsel low bit (L2), and
//! printing `|R|` beside `.H1_H1` was a ghost (zero HFMA2 abs in census).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96G: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(w, 0, t).expect("decode");
    to_sass(&d)
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}
fn rustext(e: &str) -> &'static str {
    match e {
        "guard" => "Guard",
        "neg" => "Neg",
        "hsel" => "HalfSel",
        "abs" => "Abs",
        "ureg" => "UReg",
        "reg" => "Reg",
        "re-use" => "reuse",
        _ => "?",
    }
}
fn has(r: &cubit::table::ModGroupEntry, e: &str, bits: u32, shift: u32, tok: i32) -> bool {
    let want = rustext(e);
    r.fields.iter().any(|f| {
        format!("{:?}", f.extraction) == want
            && f.bits == bits
            && f.shift == shift
            && f.token_idx == tok
    })
}

#[test]
fn t243_1_structure_law() {
    for arch in ["sm120", "sm100a", "sm103a"] {
        let t = tab(arch);
        // L1: true neg field on the 5-token FI_FI key; b72 unbaked.
        let r = &t.entries["HFMA2_R_R_R_FI_FI"].mod_groups[""];
        assert!(has(r, "neg", 1, 72, 2), "{arch}: FI_FI missing neg@72 tok2");
        assert_eq!(
            (r.and_base >> 72) & 1,
            0,
            "{arch}: b72 still era-baked in FI_FI and_base"
        );
        // L7: UR row clean rebuild.
        let u = &t.entries["HFMA2_R_R_UR_R"].mod_groups[""];
        assert!(
            has(u, "ureg", 8, 32, 3),
            "{arch}: UR row missing ureg@32 tok3"
        );
        assert!(
            has(u, "hsel", 2, 60, 3),
            "{arch}: UR row missing hsel@60 tok3"
        );
        assert!(
            has(u, "hsel", 2, 81, 4),
            "{arch}: UR row missing hsel@81 tok4"
        );
        assert!(
            has(u, "neg", 1, 84, 4),
            "{arch}: UR row missing neg@84 tok4"
        );
        assert!(
            has(u, "hsel", 2, 74, 2),
            "{arch}: UR row missing hsel@74 tok2"
        );
        assert!(
            u.fields.iter().all(|f| f.shift != 106 && f.shift != 109),
            "{arch}: UR row era garbage reuse@106/109 survived"
        );
        // L5+L2: sm120 RRRR row post-wholesale.
        let rr = &t.entries["HFMA2_R_R_R_R"].mod_groups[""];
        assert!(
            has(rr, "guard", 4, 12, 0),
            "{arch}: RRRR guard 4b@12 missing"
        );
        assert!(has(rr, "hsel", 2, 74, 2), "{arch}: RRRR hsel@74 missing");
        assert!(has(rr, "neg", 1, 84, 4), "{arch}: RRRR neg@84 missing");
    }
}

#[test]
fn t243_2_decode_anchors_vendor_true() {
    // All words are vendor cubin corpus words (hfma2law census); expectations
    // are the native nvdisasm 13.3.73 prints.
    let a: &[(u128, &str)] = &[
        (
            0x000fe200000001ff00000000ff1d7431,
            "HFMA2 R29, -RZ, RZ, 0, 0",
        ),
        (
            0x001fc600000408112000000f0e0e7231,
            "HFMA2 R14, R14.H0_H0, R15.H0_H0, R17.H0_H0",
        ),
        (
            0x004fca00002000273f803f802a27a831,
            "@!P2 HFMA2.BF16_V2 R39, R42, 1, 1, R39",
        ),
        (
            0x008fce00002000133f803f8008081831,
            "@P1 HFMA2.BF16_V2 R8, R8, 1, 1, R19",
        ),
        (
            0x0c0fe400000408052000000203050231,
            "@P0 HFMA2 R5, R3.reuse.H0_H0, R2.reuse.H0_H0, R5.H0_H0",
        ),
        (
            0x000fca00002000080000000903037231,
            "HFMA2.BF16_V2 R3, R3, R9, R8",
        ),
        (
            0x002fca00082408052000000402057c31,
            "HFMA2.BF16_V2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0",
        ),
        (
            0x002fca00080408052000000402057c31,
            "HFMA2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0",
        ),
        (
            0x140fe4000816080b200000080c097c31,
            "HFMA2 R9, R12.reuse.H0_H0, UR8.H0_H0, -R11.reuse.H1_H1",
        ),
        (
            0x000fca0008040c0b200000080c0b7c31,
            "HFMA2 R11, R12.H1_H1, UR8.H0_H0, R11.H0_H0",
        ),
        (
            0x00fc40000000c250000001816257231,
            "HFMA2 R37, R22.H1_H1, R24, R37",
        ),
    ];
    for arch in ["sm120", "sm100a", "sm103a"] {
        let t = tab(arch);
        for (w, want) in a {
            let got = dec(&t, *w);
            assert_eq!(&got, want, "{arch} decode {w:032x}");
        }
    }
}

#[test]
fn t243_3_encode_anchors() {
    // Data-96 equality (guard+sched/ctl live above bit95; reuse sideband is
    // ctrl-word payload handled by sched passes, out of scope here).
    let t = tab("sm120");
    let cases: &[(&str, u128)] = &[
        (
            "HFMA2 R29, -RZ, RZ, 0, 0",
            0x000fc200000001ff00000000ff1d7431,
        ),
        (
            "HFMA2 R29, RZ, RZ, 0, 0",
            0x000fc200000000ff00000000ff1d7431,
        ),
        (
            "HFMA2.BF16_V2 R39, R42, 1, 1, R39",
            0x000fc200002000273f803f802a277831,
        ),
        (
            "HFMA2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0",
            0x000fc200080408052000000402057c31,
        ),
        (
            "HFMA2.BF16_V2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0",
            0x000fc200082408052000000402057c31,
        ),
        (
            "HFMA2 R11, R12.H1_H1, UR8.H0_H0, R11.H0_H0",
            0x000fc20008040c0b200000080c0b7c31,
        ),
        (
            "HFMA2.BF16_V2 R3, R3, R9, R8",
            0x000fc200002000080000000903037231,
        ),
    ];
    for (text, want) in cases {
        let got = enc(&t, text);
        assert_eq!(got & M96G, want & M96G, "encode {text}");
    }
    // The era silent-negation regression: era R_R_R_FI_FI baked b72=1, so the
    // text `RZ` encoded `-RZ`. Both spellings are now true-field driven.
    let neg = enc(&t, "HFMA2 R29, -RZ, RZ, 0, 0") & M96G;
    let pos = enc(&t, "HFMA2 R29, RZ, RZ, 0, 0") & M96G;
    assert_eq!((neg >> 72) & 1, 1, "-RZ must set b72");
    assert_eq!((pos >> 72) & 1, 0, "RZ must clear b72 (era bake removed)");
}

#[test]
fn t243_4_donor_parity_and_no_ghost_guard() {
    let j = |a: &str, k: &str| {
        let t = tab(a);
        let m = &t.entries[k];
        let mut v: Vec<String> = m
            .mod_groups
            .iter()
            .map(|(mg, r)| {
                let mut fs: Vec<String> = r
                    .fields
                    .iter()
                    .map(|f| format!("{:?}{}@{}t{}", f.extraction, f.bits, f.shift, f.token_idx))
                    .collect();
                fs.sort();
                format!("{mg}|{}", fs.join(","))
            })
            .collect();
        v.sort();
        v.join(" ;; ")
    };
    for k in [
        "HFMA2_R_R_R_FI_FI",
        "HFMA2_R_R_UR_R",
        "HFMA2_R_R_FI_FI_R",
        "HFMA2_R_R_R_R",
    ] {
        assert_eq!(j("sm100a", k), j("sm103a", k), "donor field parity {k}");
    }
    // Era @P3 ghost: guard now decodes to PT, never to @P3+rsd on PT words.
    let t = tab("sm120");
    let got = dec(&t, 0x001fc600000408112000000f0e0e7231);
    assert!(!got.contains('@'), "guard ghost survived: {got}");
    assert!(!got.contains("rsd"), "rsd residue on hsel word: {got}");
}
