//! BUG-363 (F2-iter192, loop5/blind front2, 2026-09-03): F2I R_R FTZ
//! (b80 => byte10=0x21) + BF16 (b86 => byte10=0x40) lattice closure x4 legs
//! + sev-A dst-field repair. canonical fbcef1c; ENGINE arm: decoder.rs
//! BUG-363 reuse fail-closed extension (name-scoped era keys).
//!
//! PRE (publish cubit_py-6d34fe3 1b20d31b.. + canonical cfcd697;
//!   work/bug363/measure_pre363.json):
//!   - 94/96 G/H lanes HOLE x4 legs (loud).
//!   - **sev-A**: sm100a/sm103a mg F2I_R_R::FTZ,NTZ (lane 0x31@0x21) carried
//!     dst 8b@15 (vendor @16): authored 'F2I.FTZ.NTZ R5, R9' minted
//!     0x002131000000000900027305 = vendor 'F2I.FTZ.NTZ R2, R9' (silent dst
//!     corruption, encoder-side) + probe word dst R4 decoded as 'R8' x2
//!     legs. lane 0xf0 mg carried dst@16 but pinned guard=7 + no signs;
//!     era key on 120/121a carried an unprobed reuse field (vendor-ILLEGAL).
//! LAW (arb341b G/H 48+48 lanes + arb363 326 probes incl S-signs x288 /
//!   G-pred / R-reuse-illegal x16 / X-0x61-illegal x3 / A-aliases; nvdisasm
//!   13.3.73 raw -b, x4 models AGREE on every legal probe): full 48-lane
//!   closure per class; signs tok2 legal in all 3 armed combos; guard field
//!   carries pred forms; ANY reuse bit => rc=1; byte10=0x61 => rc=1;
//!   byte9 aliases 73/74 inert; byte10 aliases [83:81] stay pinned (HOLE).
//! FIX: D delete legacy mgs; N1/N2 keyed era rows x96/leg (era geometry,
//!   signs IN, reuse field OUT); era key F2I.FTZ.U32.TRUNC.NTZ_R_R on
//!   120/121a normalized in place. Expected overlap: keyed lane-0x31 FTZ x
//!   retained R_UR sister (mirrors pre-existing lane-0xf0 pattern).
//! CORPUS (census362/ab240 2,406): lane 0xf0 slots 10,576 claim-carrying on
//!   the 4 legs (text unchanged: same fields dst@16), lane 0x31: 2 slots
//!   sm_103a (text repair x2 = the abtext attribution); every other
//!   FTZ/BF16 lane corpus-ZERO => the graft is corpus-invisible apart from
//!   those 2 repaired slots and newly-claimed HOLEs being loud->text on
//!   lanes with zero occupancy.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn dec128(t: &IsaTable, raw: u128) -> Result<String, String> {
    let idx = DecodeIndex::build(t);
    idx.decode(raw, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}

const TYPES: [(u8, &str); 6] = [
    (0x00, "U8"),
    (0x01, "S8"),
    (0x08, "U16"),
    (0x09, "S16"),
    (0x10, "U32"),
    (0x11, ""),
];
const ROUNDS: [(u8, &str); 8] = [
    (0x00, ""),
    (0x20, "NTZ"),
    (0x40, "FLOOR"),
    (0x60, "FLOOR.NTZ"),
    (0x80, "CEIL"),
    (0xa0, "CEIL.NTZ"),
    (0xc0, "TRUNC"),
    (0xe0, "TRUNC.NTZ"),
];
fn lanes() -> Vec<u8> {
    let mut v = Vec::new();
    for (r, _) in ROUNDS {
        for (t, _) in TYPES {
            v.push(r | t);
        }
    }
    v.sort();
    v
}
fn ftz_text(lane: u8) -> String {
    let mut n = "F2I.FTZ".to_string();
    let t = TYPES.iter().find(|(b, _)| *b == lane & 0x1f).unwrap().1;
    let r = ROUNDS.iter().find(|(b, _)| *b == lane & 0xe0).unwrap().1;
    if !t.is_empty() {
        n.push('.');
        n.push_str(t);
    }
    if !r.is_empty() {
        n.push('.');
        n.push_str(r);
    }
    n
}
fn bf16_text(lane: u8) -> String {
    let mut n = "F2I".to_string();
    let t = TYPES.iter().find(|(b, _)| *b == lane & 0x1f).unwrap().1;
    let r = ROUNDS.iter().find(|(b, _)| *b == lane & 0xe0).unwrap().1;
    if !t.is_empty() {
        n.push('.');
        n.push_str(t);
    }
    n.push_str(".BF16");
    if !r.is_empty() {
        n.push('.');
        n.push_str(r);
    }
    n
}
fn mk(lane: u8, b10: u8, guard: u8, dst: u8, src: u8) -> u128 {
    let mut v: u128 = 0x0305;
    v |= (guard as u128) << 12;
    v |= (dst as u128) << 16;
    v |= (src as u128) << 32;
    v |= (lane as u128) << 72;
    v |= (b10 as u128) << 80;
    v
}

#[test]
fn t363_1_structure_keyed_rows_and_legacy_deleted() {
    for leg in LEGS4 {
        let t = tab(leg);
        let _ = &t;
        // legacy mgs deleted on all legs
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let mgs = j["instructions"]["F2I_R_R"]["mod_groups"]
            .as_object()
            .unwrap();
        assert!(
            !mgs.contains_key("FTZ,NTZ"),
            "{leg}: FTZ,NTZ mg still present"
        );
        assert!(
            !mgs.contains_key("FTZ,NTZ,TRUNC,U32"),
            "{leg}: FTZ,NTZ,TRUNC,U32 mg still present"
        );
        // 96 keyed rows with exact era shape, signs in, NO reuse field
        for lane in lanes() {
            for (b10, nm) in [(0x21u8, ftz_text(lane)), (0x40u8, bf16_text(lane))] {
                let key = format!("{nm}_R_R");
                let row = &j["instructions"][&key]["mod_groups"][""];
                assert!(row.is_object(), "{leg}: missing row {key}");
                let ab = u128::from_str_radix(
                    row["and_base"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(ab & 0xfff, 0x305, "{leg} {key} op");
                assert_eq!(((ab >> 72) & 0xff) as u8, lane, "{leg} {key} lane");
                assert_eq!(((ab >> 80) & 0xff) as u8, b10, "{leg} {key} byte10");
                let vm = u128::from_str_radix(
                    row["variable_mask"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(vm & (0xff << 72), 0x06u128 << 72, "{leg} {key} vm byte9");
                let flds: Vec<(u64, u64, &str)> = row["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| {
                        (
                            f["shift"].as_u64().unwrap(),
                            f["bits"].as_u64().unwrap(),
                            f["extraction"].as_str().unwrap(),
                        )
                    })
                    .collect();
                assert!(
                    flds.contains(&(16, 8, "reg")),
                    "{leg} {key}: dst field @16 missing (sev-A class)"
                );
                assert!(
                    flds.contains(&(63, 1, "neg")),
                    "{leg} {key}: neg@63 missing"
                );
                assert!(
                    flds.contains(&(62, 1, "abs")),
                    "{leg} {key}: abs@62 missing"
                );
                assert!(
                    !flds.iter().any(|(s, _, e)| *s >= 96 && *e == "reuse"),
                    "{leg} {key}: reuse field must NOT be present (vendor-ILLEGAL)"
                );
            }
        }
    }
}

#[test]
fn t363_2_decode_battery_96_lanes_x4_legs() {
    for leg in LEGS4 {
        let t = tab(leg);
        for lane in lanes() {
            let w = mk(lane, 0x21, 7, 4, 6);
            let want = format!("{} R4, R6", ftz_text(lane));
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(want.as_str()),
                "{leg} FTZ {lane:#04x}"
            );
            let w = mk(lane, 0x40, 7, 4, 6);
            let want = format!("{} R4, R6", bf16_text(lane));
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(want.as_str()),
                "{leg} BF16 {lane:#04x}"
            );
        }
    }
}

#[test]
fn t363_3_signs_pred_and_alias_decode() {
    // arb363 S/A/G group witnesses (x4 models AGREE): signs in all combos,
    // pred guard field, byte9 aliases 73/74 inert.
    for leg in LEGS4 {
        let t = tab(leg);
        for (lane, base) in [
            (0x00u8, "F2I.FTZ.U8"),
            (0x31, "F2I.FTZ.NTZ"),
            (0xf1, "F2I.FTZ.TRUNC.NTZ"),
        ] {
            let w = mk(lane, 0x21, 7, 4, 6) | (1u128 << 62);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(format!("{base} R4, |R6|").as_str()),
                "{leg}"
            );
            let w = mk(lane, 0x21, 7, 4, 6) | (1u128 << 63);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(format!("{base} R4, -R6").as_str()),
                "{leg}"
            );
            let w = mk(lane, 0x21, 7, 4, 6) | (3u128 << 62);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(format!("{base} R4, -|R6|").as_str()),
                "{leg}"
            );
        }
        for (lane, base) in [(0x11u8, "F2I.BF16"), (0xc0, "F2I.U8.BF16.TRUNC")] {
            let w = mk(lane, 0x40, 7, 4, 6) | (3u128 << 62);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(format!("{base} R4, -|R6|").as_str()),
                "{leg}"
            );
        }
        // pred form (arb363 G-group)
        let w = mk(0x31, 0x21, 3, 4, 6);
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("@P3 F2I.FTZ.NTZ R4, R6"),
            "{leg}"
        );
        let w = mk(0x11, 0x40, 3, 4, 6);
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("@P3 F2I.BF16 R4, R6"),
            "{leg}"
        );
        // byte9 alias bits 73/74 text-inert (arb363 A-group)
        let w = mk(0x33, 0x21, 7, 4, 6);
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.FTZ.NTZ R4, R6"),
            "{leg} alias"
        );
        let w = mk(0x13, 0x40, 7, 4, 6);
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.BF16 R4, R6"),
            "{leg} alias"
        );
    }
}

#[test]
fn t363_4_mints_incl_sevA_repair_and_pred() {
    for leg in LEGS4 {
        let t = tab(leg);
        // sev-A repair: dst@16 everywhere == vendor mint (0x...057305 family)
        let w = enc(&t, "F2I.FTZ.NTZ R5, R9").unwrap();
        assert_eq!(w & M96, mk(0x31, 0x21, 7, 5, 9) & M96, "{leg} sev-A mint");
        let rt = dec96(&t, w);
        assert_eq!(rt.as_deref(), Some("F2I.FTZ.NTZ R5, R9"), "{leg} rt");
        // pred mint (new capability; pre-fix loud-refuse on mg rows)
        let w = enc(&t, "@P3 F2I.FTZ.U32.TRUNC.NTZ R5, R9").unwrap();
        let rt = dec96(&t, w);
        assert_eq!(
            rt.as_deref(),
            Some("@P3 F2I.FTZ.U32.TRUNC.NTZ R5, R9"),
            "{leg}"
        );
        // closure mints x4 lanes signed
        let w = enc(&t, "F2I.BF16 R4, -|R6|").unwrap();
        assert_eq!(dec96(&t, w).as_deref(), Some("F2I.BF16 R4, -|R6|"), "{leg}");
        let w = enc(&t, "F2I.S8.BF16.TRUNC.NTZ R4, R6").unwrap();
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.S8.BF16.TRUNC.NTZ R4, R6"),
            "{leg}"
        );
        let w = enc(&t, "F2I.FTZ.U8.CEIL.NTZ R4, R6").unwrap();
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.FTZ.U8.CEIL.NTZ R4, R6"),
            "{leg}"
        );
        let w = enc(&t, "F2I.U16.BF16.FLOOR R4, R6").unwrap();
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.U16.BF16.FLOOR R4, R6"),
            "{leg}"
        );
    }
}

#[test]
fn t363_5_fail_closed_and_guards() {
    for leg in LEGS4 {
        let t = tab(leg);
        // reuse => vendor rc=1 (arb363 R-group) => engine HOLE with BUG-363
        for (lane, b10) in [(0x31u8, 0x21u8), (0xf0, 0x21), (0x11, 0x40), (0xc0, 0x40)] {
            for rbits in [1u128, 2, 4, 7] {
                let w = mk(lane, b10, 7, 4, 6) | (rbits << 122);
                let e = dec128(&t, w).unwrap_err();
                assert!(
                    e.contains("BUG-363"),
                    "{leg} {lane:#04x} reuse {rbits}: {e}"
                );
            }
        }
        // byte10=0x61 (FTZ+BF16) vendor rc=1 => claim HOLE
        for lane in [0x00u8, 0x11, 0x31] {
            assert!(
                dec96(&t, mk(lane, 0x61, 7, 4, 6)).is_none(),
                "{leg} 0x61 {lane:#04x}"
            );
        }
        // byte10 aliases [83:81] stay pinned (341 doctrine)
        assert!(dec96(&t, mk(0x11, 0x23, 7, 4, 6)).is_none(), "{leg} b23");
        assert!(dec96(&t, mk(0x11, 0x46, 7, 4, 6)).is_none(), "{leg} b46");
        // plain/R_FI/F2IP/regression guards intact
        let w = enc(&t, "F2I.U8.CEIL R4, R6").unwrap();
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.U8.CEIL R4, R6"),
            "{leg} plain"
        );
        let w = enc(&t, "IMAD.WIDE.U32 R4, R5, R6, R7").unwrap();
        assert!(
            dec128(&t, w | (1u128 << 122)).is_ok(),
            "{leg} IMAD reuse intact"
        );
        if leg == "sm103a" {
            let w = enc(&t, "F2IP.F32.NTZ.S8 R4, R6, R8, R10").unwrap();
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some("F2IP.F32.NTZ.S8 R4, R6, R8, R10"),
                "F2IP print intact"
            );
        }
        if leg == "sm120" {
            // retained R_UR sister: UR-src text stays ENCODABLE through the
            // shared window; decode renders the vendor-canonical R form (law
            // anchored pre-fix: both texts mint the same word and nvdisasm
            // prints the R form -- work/bug363 raport).
            let w = enc(&t, "F2I.FTZ.U32.TRUNC.NTZ R4, UR6").unwrap();
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some("F2I.FTZ.U32.TRUNC.NTZ R4, R6"),
                "{leg} R_UR canonical-display law"
            );
        }
    }
}
