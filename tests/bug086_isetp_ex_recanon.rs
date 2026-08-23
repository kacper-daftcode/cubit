//! BUG-086 (F2Q-086-kand, residuum klasy z 074; fixed F2 2026-08-23):
//! The ISETP/UISETP family in tables/sm120.json was legacy-harvest junk:
//! (a) EX (dual-pred, 6-token) family missing entirely -- EX words were
//!     absorbed by 5-token rows, scrambling operands (`-|R23|`, imm `0xff, 0x0`
//!     phantoms, dropped .EX/U32 mods, dropped second predicate);
//! (b) dotted junk keys (`ISETP.NE.AND_P_P_R_R_II`, ...) hijacked EX words;
//! (c) canon-shaped sm120 rows misrouted U32/bool mods (vendor
//!     `ISETP.GE.U32.AND` rendered `ISETP.GE.AND` etc.);
//! (d) 6,304 corpus words had NO row at all (decode-FAIL, e.g.
//!     `UISETP.NE.U32.AND UP0, UPT, UR14, 0xa, UPT`).
//! Canon-side (tables/sm103a.json) surgical fixes with vendor anchors:
//!  E1 +mg `AND,LE,U32` on UISETP II key (bool op bit74=0; 6 anchors);
//!  E2 UISETP II tok5 pred 4b@87 -> 3b@87 + neg@90 (2 negated-source anchors);
//!  E3 UISETP EX-UR `EX,NE,OR,U32` de-fossil fields (2 anchors);
//!     + `EQ,OR,U32` de-fossil on UR key (2 anchors, encode was impossible);
//!  E4 +mg `AND,EX,GE` on ISETP II-EX key (imm32 EX form, 1 anchor);
//!  E5 UISETP II `GT,OR` de-fossil fields (1 anchor).
//! Fix sm120: whole family rebuilt to the fixed sm103a geometry (174 legacy
//! keys -> 10 canon keys, mod_groups ported 1:1). Anchors: 221,092 uniq /
//! 710,764 records from the 2049-cubin vendor census (cuobjdump 13.3).
//! Post: parity 221,091/221,092 both tables; RT EXACT96 221,091 both tables.
//! Two "imm-small subform" anchors (initially parked single-anchor) closed
//! during the same iteration after the 2nd anchor landed: the trigger was the
//! missing tok5 pred window (3b@87) — words with a real bool-source pred lost
//! strict-match to PLOP3. Predicate-field template normalized across all 10
//! canon keys (probe truth from 057: dst@81 3b / dst2@84 3b / tok5@87 3b +
//! neg@90 / EX-cin@68 4b).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

fn dec_render(word: u128, t: &IsaTable) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(word, 0, t).expect("decode");
    cubit::printer::to_sass(&d)
}

const PAYLOAD: u128 = (1u128 << 96) - 1;

fn norm(t: &str) -> String {
    t.trim().trim_end_matches(';').replace(".reuse", "").split(',')
        .map(|c| c.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>().join(",")
}

// (word & [95:0], vendor text) -- one per fix class + coverage spread
const ANCHORS: &[(u128, &str)] = &[
    (0x03f06300ffffffff0900780c, "ISETP.GE.AND.EX P0, PT, R9, -0x1, PT, P0"),      // E4
    (0x03f05100000000ffff00720c, "ISETP.NE.U32.AND.EX P0, PT, RZ, RZ, PT, P0"),    // EX-II
    (0x03f86140000000030900720c, "ISETP.GE.U32.AND.EX P4, PT, R9, R3, PT, P4"),    // EX-R
    (0x0bf0430000000005ff007c0c, "ISETP.GT.AND.EX P0, PT, RZ, UR5, PT, P0"),       // EX-UR
    (0x08f45500000000ff1200728c, "UISETP.NE.U32.OR.EX UP2, UPT, UR18, URZ, UP1, UP0"), // E3
    (0x08703070000000031200788c, "UISETP.LE.U32.AND UP0, UPT, UR18, 0x3, UP0"),    // E1
    (0x0d745070000000021200788c, "UISETP.NE.U32.AND UP2, UPT, UR18, 0x2, !UP2"),   // E2
    (0x0c784670000000011600788c, "UISETP.GT.OR UP4, UPT, UR22, 0x1, !UP0"),        // E5
    (0x08702470000000ff0e00728c, "UISETP.EQ.U32.OR UP0, UPT, UR14, URZ, UP0"),     // EQ,OR,U32
    (0x03f06270000000030900720c, "ISETP.GE.AND P0, PT, R9, R3, PT"),               // regression-ctrl
    (0x0bf26070000000ff0500728c, "UISETP.GE.U32.AND UP1, UPT, UR5, URZ, UPT"),     // regression-ctrl
    (0x0bf050700000000a0e00788c, "UISETP.NE.U32.AND UP0, UPT, UR14, 0xa, UPT"),    // pre-decode-FAIL
    (0x04702670000000ff1000720c, "ISETP.EQ.OR P0, PT, R16, RZ, !P0"),              // neg pred src
    (0x00704670000000880700720c, "ISETP.GT.OR P0, PT, R7, R136, P0"),              // R136 wide reg
];

#[test]
fn t086_decode_vendor_exact_both_tables() {
    let a = t103(); let b = t120();
    let ia = DecodeIndex::build(&a); let ib = DecodeIndex::build(&b);
    for (w, want) in ANCHORS {
        for (name, idx, t) in [("sm103a", &ia, &a), ("sm120", &ib, &b)] {
            let d = idx.decode(w & PAYLOAD, 0, t).unwrap_or_else(|e| panic!("{name} decode FAIL {want}: {e}"));
            let got = cubit::printer::to_sass(&d);
            assert_eq!(norm(&got), norm(want), "{name} render mismatch for {want:#x?}");
        }
    }
}

#[test]
fn t086_encode_roundtrip_payload_both_tables() {
    let a = t103(); let b = t120();
    for (w, text) in ANCHORS {
        for (name, t) in [("sm103a", &a), ("sm120", &b)] {
            let got = enc(text, t).unwrap_or_else(|e| panic!("{name} encode FAIL {text}: {e}")) & PAYLOAD;
            assert_eq!(got, w & PAYLOAD, "{name} RT payload mismatch for {text}");
        }
    }
}

#[test]
fn t086_ex_family_keys_present_sm120() {
    let b = t120();
    for key in ["ISETP_P_P_R_II_P_P", "ISETP_P_P_R_R_P_P", "ISETP_P_P_R_UR_P_P",
                "UISETP_UP_UP_UR_II_UP_UP", "UISETP_UP_UP_UR_UR_UP_UP"] {
        assert!(b.get_key(key).is_some(), "EX key {key} missing in sm120");
    }
    // legacy dotted junk must be gone
    for key in ["ISETP.NE.AND_P_P_R_R_II", "ISETP.GE.AND_P_P_R_R_R", "ISETP.GT.U32.AND_P_P_R_R_R"] {
        assert!(b.get_key(key).is_none(), "junk key {key} still present");
    }
}

#[test]
fn t086_smallimm_subform_closed() {
    // Era pierwotnie parkowane jako single-anchor residuum (imm8@40 subform);
    // domkniete po 2. kotwicy (R2 = GE.U32.AND.EX 0x100): TRIGGEREM byl brak
    // schematu pol predykatow (tok5 3b@87) -> slowa z realnym predykatem
    // zrodla bool nie strict-matchowaly i przegrywaly z PLOP3. Normalizacja
    // szablonu (157 mg) + 2 nowe mg (AND,EX,GE[,U32] na II-EX).
    let a = t103(); let b = t120();
    for t in [&a, &b] {
        let idx = DecodeIndex::build(t);
        for (w, want) in [
            (0x01743070000000070500780cu128, "ISETP.LE.U32.AND P2, PT, R5, 0x7, P2"),
            (0x03f06100000001000300780cu128, "ISETP.GE.U32.AND.EX P0, PT, R3, 0x100, PT, P0"),
        ] {
            let d = idx.decode(w, 0, t).unwrap();
            assert_eq!(norm(&cubit::printer::to_sass(&d)), norm(want));
            let got = enc(want, t).unwrap() & PAYLOAD;
            assert_eq!(got, w, "RT {want}");
        }
    }
}
