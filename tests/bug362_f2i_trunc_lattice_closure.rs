//! BUG-362 (F2-iter191, loop5/blind front2, 2026-09-03): F2I TRUNC/F64/FLOOR
//! lattice (byte10 = 0x20 wide-dst + 0x30 F64-src anchors) era-row closure.
//! canonical cfcd697; ENGINE arms: decoder.rs BUG-362a reuse fail-closed (the
//! stripped-upper32 claim zone cannot see bits [124:122]), printer.rs BUG-361
//! (own pin file).
//!
//! PRE (publish cubit_py-ef75c5c 9a6f956c.. + canonical 32cde7a;
//!   work/bug361_362/measure_pre361_362.json):
//!   - sign window: b62/b63-armed words HOLE x4 legs on all 9 classes while
//!     the vendor prints tok2 abs/neg in every combination (arb362 S-group
//!     27 probes + arb339 A5b62/63/B4b62/63, x4 models AGREE on every probe).
//!   - reuse window: ANY of bits [124:122] set on a lattice word = vendor
//!     rc=1 (arb362 R-group 24 + arb362b 6 probes incl yield=1 variants),
//!     while the donor-parity rows claimed them x4 legs (plain print, or a
//!     ghost '.reuse' under yield=1 -- 362-nota overclaim).
//!   - dst-selector [75:72] aliases: b73/b74-armed cells HOLE x4 although
//!     they are the vendor's alias cells of every class (arb339 B1n2/B1nf +
//!     arb362c 12 probes: the alias lattice is fully measured below).
//! FIX parts:
//!   S table graft: {abs 1b@62, neg 1b@63} tok2 fields on 34 rows
//!     (7 generic F2I_R_R mgs on 100a/103a; 3 generic + 7 era *_R_R keys on
//!     120/121a) -- field-carried, claim-invariant on [62:63].
//!   I table graft: vm |= 3<<73 on the same rows = the alias-bit closure.
//!     Vendor law for the byte9-low-nibble [75:72] dst selector on the
//!     byte10=0x30 anchor: {0,2,4,6}->U32, {1,3,5,7}->F64-def,
//!     {8,a,c,e}->U64, {9,b,d,f}->S64 (nvdisasm x4 agree; engine decodes
//!     each class through its own row). On the byte10=0x20 A-anchor the
//!     same alias pairs hold for the S64/U64 rows (arb339 A2b73/74).
//!   a ENGINE decoder arm: matched lattice row + any reuse bit set = HOLE.
//! CORPUS (census362 over ab240 2,406): sign-armed slots = 0, reuse-armed
//!   claimed slots = 0, pre-fix HOLE slots on these ops = 0 -- the graft is
//!   corpus-invisible; the only corpus-visible change of the iteration is
//!   the BUG-361 print law (own pin file).
//! NOT-DONE registrations: 'F2I.F64.FLOOR.NTZ' cell (b77-armed FLOOR anchor)
//!   = vendor-legal un-rowed class HOLE x4 (380-kand); the era keys carry
//!   the pre-existing 2aE-era shifted fields.

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
    // full-128 decode: the upper32 (sched/reuse) travels with `code`
    idx.decode(raw, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}

#[test]
fn t362_1_structure_rows_carry_sign_and_alias_window() {
    let gen_low = [
        "S64,TRUNC",
        "TRUNC,U64",
        "F64,TRUNC",
        "F64,TRUNC,U32",
        "F64,TRUNC,U64",
        "F64,S64,TRUNC",
        "F64,FLOOR",
    ];
    let gen_era = ["S64,TRUNC", "TRUNC,U64", "F64,TRUNC"];
    let era = [
        "F2I.S64.TRUNC_R_R",
        "F2I.U64.TRUNC_R_R",
        "F2I.F64.TRUNC_R_R",
        "F2I.U32.F64.TRUNC_R_R",
        "F2I.U64.F64.TRUNC_R_R",
        "F2I.S64.F64.TRUNC_R_R",
        "F2I.F64.FLOOR_R_R",
    ];
    for leg in LEGS4 {
        let t = tab(leg);
        let mut rows: Vec<(&str, &str)> = Vec::new();
        let general = if leg.starts_with("sm10") {
            &gen_low[..]
        } else {
            &gen_era[..]
        };
        for mg in general {
            rows.push(("F2I_R_R", mg));
        }
        if !leg.starts_with("sm10") {
            for k in era {
                rows.push((k, ""));
            }
        }
        let expect = if leg.starts_with("sm10") { 7 } else { 10 };
        assert_eq!(rows.len(), expect, "{leg} row census");
        for (key, mg) in rows {
            let g = &t.entries[key].mod_groups[mg];
            let has = |bit: u32| g.fields.iter().any(|f| f.shift == bit && f.token_idx == 2);
            assert!(has(62) && has(63), "{leg} {key}::{mg} sign window");
            assert_eq!((g.variable_mask >> 73) & 3, 3, "{leg} {key}::{mg} alias vm");
        }
    }
    // era-key S64/U64 parity preserved (b72 flip only in ab, not in fields/vm)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let s = &t.entries["F2I.S64.TRUNC_R_R"].mod_groups[""];
        let u = &t.entries["F2I.U64.TRUNC_R_R"].mod_groups[""];
        assert_eq!(s.variable_mask, u.variable_mask, "{leg} vm parity");
        let sh = |e: &cubit::table::ModGroupEntry| {
            e.fields
                .iter()
                .map(|f| (f.shift, f.bits, f.token_idx))
                .collect::<Vec<_>>()
        };
        assert_eq!(sh(s), sh(u), "{leg} fields parity");
    }
}

#[test]
fn t362_2_decode_law_battery_vendor_exact_x4() {
    // sign-window x9 classes + alias cells (arb362 S/I + arb339 A5/B4 +
    // arb362c; x4 models unanimous, engine pre-fix HOLE)
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
            assert_eq!(dec96(&t, *w).as_deref(), Some(*want), "{leg} {want}");
        }
    }
}

#[test]
fn t362_3_sign_mints_word_exact_and_negative_controls() {
    for leg in LEGS4 {
        let t = tab(leg);
        let w = enc(&t, "@P1 F2I.S64.TRUNC R22, -R21").unwrap();
        assert_eq!(w & M96, 0x0020d9008000001500161311u128, "{leg} neg mint");
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("@P1 F2I.S64.TRUNC R22, -R21"),
            "{leg} rt"
        );
        let w = enc(&t, "F2I.U64.F64.TRUNC R26, |R6|").unwrap();
        assert_eq!(w & M96, 0x0030d80040000006001a7311u128, "{leg} abs mint");
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.U64.F64.TRUNC R26, |R6|"),
            "{leg} rt"
        );
        let w = enc(&t, "F2I.F64.FLOOR R26, -|R6|").unwrap();
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("F2I.F64.FLOOR R26, -|R6|"),
            "{leg} rt2"
        );
        // negative control: an ungrafted F2I subclass still fails closed with
        // the BUG-308 attribution (no sign window on 'F64,S64')
        let e = enc(&t, "F2I.S64.F64 R26, -R6").err().unwrap_or_default();
        assert!(e.contains("BUG-308"), "{leg} negative control: {e}");
    }
}

#[test]
fn t362_4_reuse_window_fail_closed() {
    // arb362 R-group + arb362b battery: (word || reuse-bit/yield) decoded
    // full-128 must HOLE with the BUG-362 attribution on every leg
    let battery: &[u128] = &[
        0x040000000020d9000000001a00167311u128,
        0x040020000020d9000000001a00167311u128,
        0x080000000020d9000000001a00167311u128,
        0x080020000020d9000000001a00167311u128,
        0x100000000020d9000000001a00167311u128,
        0x100020000020d9000000001a00167311u128,
        0x040000000020d8000000001a00167311u128,
        0x040020000020d8000000001a00167311u128,
        0x080000000020d8000000001a00167311u128,
        0x080020000020d8000000001a00167311u128,
        0x100000000020d8000000001a00167311u128,
        0x100020000020d8000000001a00167311u128,
        0x040000000030d80000000006001a7311u128,
        0x040020000030d80000000006001a7311u128,
        0x080000000030d80000000006001a7311u128,
        0x080020000030d80000000006001a7311u128,
        0x100000000030d80000000006001a7311u128,
        0x100020000030d80000000006001a7311u128,
        0x040000000030d90000000006001a7311u128,
        0x040020000030d90000000006001a7311u128,
        0x080000000030d90000000006001a7311u128,
        0x080020000030d90000000006001a7311u128,
        0x100000000030d90000000006001a7311u128,
        0x100020000030d90000000006001a7311u128,
        0x080000000020d9000000001500161311u128,
        0x080020000020d9000000001500161311u128,
        0x080000000030d00000000006001a7311u128,
        0x080000000030d10000000006001a7311u128,
        0x080020000030d10000000006001a7311u128,
        0x080000000030510000000006001a7311u128,
    ];
    for leg in LEGS4 {
        let t = tab(leg);
        for w in battery {
            let e = dec128(&t, *w);
            let msg = e.err().unwrap_or_default();
            assert!(
                msg.contains("BUG-362"),
                "{leg} reuse-armed 0x{w:032x} decoded: {msg}"
            );
        }
    }
    // scope guard: a reuse-armed word of a non-lattice class is untouched by
    // the arm (IMAD.WIDE.U32: yield=0 plain print per the 325/326 law)
    for leg in LEGS4 {
        let t = tab(leg);
        let w = enc(&t, "IMAD.WIDE.U32 R4, R5, R6, R7").unwrap();
        assert!(dec128(&t, w | (1u128 << 122)).is_ok(), "{leg} IMAD gated");
    }
}

#[test]
fn t362_5_alias_lattice_full_sweep_and_borders() {
    // the full [75:72]-nibble sweep on the byte10=0x30 anchor word
    let base: u128 = 0x0030d80000000006001a7311;
    let law = |n: u128| -> &'static str {
        match n {
            0 | 2 | 4 | 6 => "F2I.U32.F64.TRUNC R26, R6",
            1 | 3 | 5 | 7 => "F2I.F64.TRUNC R26, R6",
            8 | 10 | 12 | 14 => "F2I.U64.F64.TRUNC R26, R6",
            _ => "F2I.S64.F64.TRUNC R26, R6",
        }
    };
    for leg in LEGS4 {
        let t = tab(leg);
        for n in 0..16u128 {
            let w = (base & !(0xFu128 << 72)) | (n << 72);
            assert_eq!(dec96(&t, w).as_deref(), Some(law(n)), "{leg} nibble {n}");
        }
    }
    // border: the b77-armed FLOOR anchor is a vendor-legal UN-ROWED class
    // ('F2I.F64.FLOOR.NTZ', arb362c control) -> stays HOLE-pinned (380-kand)
    let fnz: u128 = 0x0030710000000006001a7311;
    for leg in LEGS4 {
        let t = tab(leg);
        assert!(dec96(&t, fnz).is_none(), "{leg} 380-kand posture");
    }
    // border: b75=0 on the A-anchor stays vendor-illegal HOLE (arb339 A2b75)
    let bad: u128 = 0x0020d9000000001500161311u128 ^ (1u128 << 75);
    for leg in LEGS4 {
        let t = tab(leg);
        assert!(dec96(&t, bad).is_none(), "{leg} b75 doctrine");
    }
}
