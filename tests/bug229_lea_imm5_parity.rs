//! BUG-229 patch 3 (F2-iter112, front2/blind, 2026-08-27): sm120 vendor-parity
//! LEA .HI 5-token imm-window [79:75] closure (canonical 68c352b; patch229.py
//! replayable+idempotent).
//!
//! Defect (measured, work/bug229): every `LEA.HI` 5-token word (b80=.HI pivot
//! set) was hijacked by era impostor rows and printed 4-token, losing the
//! trailing imm5: mg LEA_R_R_II_II["HI"] (5-field list under a 4-token sig,
//! engine drops tok4/tok5) for the off-0x1e words (rsd-flagged), key
//! LEA_R_R_II_R (imm5==0x1e baked as an and_base CONSTANT, no imm5 field) for
//! the 0x1e era majority (fully silent text loss), and LEA_R_R_UR_R_II["HI"]
//! with ureg 5b@32 (b36 dropped, encode-lossy) + imm 2b@75 (prints imm5&3).
//! popdiff229.jsonl: 13,254 occurrence-paired DIFF lines (ii_imm 6,773 /
//! ur_imm 5,541 / Xreuse 506 / neg 234 / ptform 200; 4 truncated-name
//! dup-section mis-pairs excluded, classes covered by the remaining
//! thousands). Law (arb229.json bit-walks x{100a,103a,120a}, print-identical):
//! b80=.HI pivot (1 -> 5-token `LEA.HI Rd,Ra,imm32,Rc,imm5`, 0 -> 4-token
//! `LEA Rd,Ra,imm32,imm5`), tok5=imm5@[79:75], b74=.X (trailing pred slot),
//! b81/b82=output-pred slot, b36=ureg bit4 on the UR form.
//!
//! Repairs: DELETE mg LEA_R_R_II_II["HI"] (donor sm100a has no such mg),
//! DELETE key LEA_R_R_II_R (donor lacks it), REPLACE LEA_R_R_UR_R_II["HI"]
//! with the donor row (ureg 8b@32, imm5@75). The lawful sm120 row
//! LEA_R_R_II_R_II["HI"] needed no change; every target occurrence now strict-
//! routes to it (patch asserts, true ctrl). Donor is NOT a clone source for
//! the II class: its II_II[""] reads imm6 incl b80 and prints a wrong glyph on
//! its own arch (231-kand).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const M96: u128 = (1u128 << 96) - 1;
fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}
fn decode(t: &IsaTable, w128: u128) -> Result<String, String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w128, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn mk(w96: u128, ctrl: u64) -> u128 {
    (w96 & ((1 << 96) - 1)) | ((ctrl as u128) << 96)
}

/// Cured anchors: (vendor glyph, word96, ctrl) — every triple is an
/// occurrence-paired corpus hit (popdiff229.jsonl) spanning all 13 rsd shapes.
const CURED: &[(&str, u128, u64)] = &[
    (
        "LEA.HI R55, R57, 0x1, RZ, 0x17",
        0x078fb8ff0000000139377811,
        0x000fe400,
    ), // witness
    (
        "LEA.HI R2, R2, 0x1, RZ, 0x1f",
        0x078ff8ff0000000102027811,
        0x000fc800,
    ),
    (
        "LEA.HI R2, R2, 0x1, RZ, 0x1d",
        0x078fe8ff0000000102027811,
        0x000fc800,
    ),
    (
        "LEA.HI R13, R7, 0x1, RZ, 0x19",
        0x078fc8ff00000001070d7811,
        0x000fe200,
    ),
    (
        "LEA.HI R8, R10.reuse, 0xffffff81, RZ, 0x9",
        0x078f48ffffffff810a087811,
        0x040fe400,
    ),
    (
        "LEA.HI R34, R34, 0x1, RZ, 0x15",
        0x078fa8ff0000000122227811,
        0x000fe200,
    ),
    (
        "LEA.HI R39, R16, 0x1, RZ, 0x1b",
        0x078fd8ff0000000110277811,
        0x000fc600,
    ),
    (
        "LEA.HI R39, R16, 0x1, RZ, 0x1c",
        0x078fe0ff0000000110277811,
        0x000fc600,
    ),
    (
        "LEA.HI R105, R22, 0x1, RZ, 0x18",
        0x078fc0ff0000000116697811,
        0x000fc600,
    ),
    (
        "LEA.HI R2, R5, 0x1, RZ, 0x14",
        0x078fa0ff0000000105027811,
        0x000fe200,
    ),
    (
        "LEA.HI R24, R2, 0x1, RZ, 0x1a",
        0x078fd0ff0000000102187811,
        0x000fe200,
    ),
    (
        "LEA.HI R42, R20, 0x1, RZ, 0x16",
        0x078fb0ff00000001142a7811,
        0x000fc600,
    ),
    // silent 0x1e era-baked class (key LEA_R_R_II_R captured these, no rsd!)
    (
        "LEA.HI R4, R37, 0x1, RZ, 0x1e",
        0x078ff0ff0000000125047811,
        0x000fc800,
    ),
    // UR form: b36 (ureg bit4) + full imm5 window restored
    (
        "LEA.HI R54, R2, UR17, RZ, 0x1a",
        0x0f8fd0ff0000001102367c11,
        0x002fe200,
    ),
];

#[test]
fn t229_1_cured_anchors_decode_exact_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in CURED {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "sm120 drift @{ctl:#x}");
    }
}

#[test]
fn t229_2_structure_and_stability_sm120() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(T120).unwrap()).unwrap();
    let ins = &j["instructions"];
    // impostors gone
    assert!(ins["LEA_R_R_II_R"].is_null(), "era key must be deleted");
    let s = ins["LEA_R_R_II_II"]["mod_groups"].as_object().unwrap();
    assert!(!s.contains_key("HI"), "era shadow mg must be deleted");
    for kept in ["", "HI,SX32", "HI,SX32,X", "HI,X"] {
        assert!(s.contains_key(kept), "sibling mg {kept} must be kept");
    }
    // UR row carries the donor field law
    let fs = ins["LEA_R_R_UR_R_II"]["mod_groups"]["HI"]["fields"]
        .as_array()
        .unwrap();
    assert!(fs
        .iter()
        .any(|f| f["extraction"] == "ureg" && f["shift"] == 32 && f["bits"] == 8));
    assert!(fs
        .iter()
        .any(|f| f["extraction"] == "imm" && f["shift"] == 75 && f["bits"] == 5));
    // lawful row unchanged (imm5@75 tok5, imm32@32 tok3, Rc@64 tok4)
    let fs = ins["LEA_R_R_II_R_II"]["mod_groups"]["HI"]["fields"]
        .as_array()
        .unwrap();
    assert!(fs
        .iter()
        .any(|f| f["extraction"] == "imm" && f["shift"] == 75 && f["bits"] == 5));
    let t = tab(T120);
    // cross-key stability: BUG-226 anchors must not drift
    for (glyph, w96, ctl) in [
        (
            "FSETP.EQ.OR P0, PT, R7, RZ, P0",
            0x00702400000000ff0700720bu128,
            0x000fda00u64,
        ),
        (
            "IADD3 R10, P1, P0, R5, UR4, R128",
            0x0f83e08000000004050a7c10,
            0x002fe200,
        ),
        (
            "LEA.HI.X.SX32 R5, R2, R5, 0x2, P0",
            0x000f16ff0000000502057211,
            0x000fea00,
        ),
    ] {
        let got = decode(&t, mk(w96, ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "stability broke @{ctl:#x}");
    }
}

#[test]
fn t229_3_law_pivots_and_fail_closed_sm120() {
    let t = tab(T120);
    // law pins on the witness word: b80=0 -> 4-token plain LEA (imm5 kept);
    // b74=1 -> .X with trailing !PT; imm5 walk shifts the printed imm.
    let base = 0x078fb8ff0000000139377811u128;
    let got = decode(&t, mk(base ^ (1 << 80), 0x000fe400)).unwrap();
    assert_eq!(got, "LEA R55, R57, 0x1, 0x17");
    // b74 flip (.X pivot per graft on vendor): this crafted word is absorbed
    // by II_II["HI,SX32"] (226b donor-clone) printing .SX32 4-token while
    // nvdisasm renders .X 6-token — a latent parity gap with ZERO corpus
    // exposure (all witnessed .X forms match the _P rows today). Parked as
    // 232-kand LOW; pinned here so the boundary is machine-visible.
    let got = decode(&t, mk(base ^ (1 << 74), 0x000fe400)).unwrap();
    assert_eq!(got, "LEA.HI.SX32 R55, R57, 0x1, 0x17");
    let got = decode(&t, mk(base ^ (1 << 75), 0x000fe400)).unwrap();
    assert_eq!(got, "LEA.HI R55, R57, 0x1, RZ, 0x16");
    // fail-closed: b91-cleared witness must not round-trip through any
    // relaxed tier into the crafted word (bug089-class contract).
    let w = base ^ (1u128 << 91);
    if let Ok(got) = decode(&t, mk(w, 0x000fe400)) {
        let insn = parse_sass(&got, 0).unwrap();
        let re = encode_instruction(&insn, &t).map(|x| x & M96).ok();
        assert_ne!(
            re,
            Some(w & M96),
            "crafted word must not survive round-trip"
        );
    }
}

#[test]
fn t229_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        (
            "LEA.HI R55, R57, 0x1, RZ, 0x17 ;",
            0x078fb8ff0000000139377811u128,
        ),
        (
            "LEA.HI R4, R37, 0x1, RZ, 0x1e ;",
            0x078ff0ff0000000125047811,
        ),
        (
            "LEA.HI R54, R2, UR17, RZ, 0x1a ;",
            0x0f8fd0ff0000001102367c11,
        ),
        ("LEA R55, R57, 0x1, 0x17 ;", 0x078eb8ff0000000139377811u128),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
}
