//! BUG-339 (F2-iter180, loop5/blind front2, 2026-09-02): F2I era closure on
//! sm120/sm121a (canonical 02c147d; ENGINE untouched).
//!
//! PRE (publish f1e894a, canonical bfc8480; work/bug339/measure_pre339):
//!   D1: '@P1 F2I.S64.TRUNC Rd, Rs' class (8 corpus words, cutlass sm_103a)
//!       decode HOLE on sm120 AND sm121a; donors 100a/103a decode EXACT.
//!   D2: whole F64-src era family HOLE on sm120 (F2I.{F64.FLOOR, F64.TRUNC,
//!       S64.F64, S64.F64.TRUNC, U32.F64.TRUNC} classes; sm121a dlt=0-vendor
//!       era keys existed but were never cloned across); sm121a additionally
//!       HOLEs 'F2I.U64.F64.TRUNC Rd, Rs' (28 corpus words, cusolver sm_100).
//!   D3: era-shaped S64 space (b72=1 sibling of F2I.U64.TRUNC_R_R) HOLE on
//!       both era legs (arb339 A7: vendor-legal x4).
//! LAW (arb339 61 probes + mint-space extras, nvdisasm 13.3.73 raw -b, x4
//!   models SM100a/SM103a/SM120/SM121a AGREE on EVERY probe;
//!   work/bug339/arb339_verdicts.json):
//!   byte10=0x20 family: b72 = dst U64(0)/S64(1) select; b73/b74 text-INERT;
//!     b75 pinned 1 (b75=0 -> nvdisasm rc=1); guard nibble [15:12] fully
//!     legal (P0..P7, !, PT, !PT); b62/b63 era abs/neg on tok2 (vendor
//!     prints; 4-leg engine gap left registered); dst/src any reg.
//!   byte10=0x30 family: nibble [75:72] = dst lattice 0/2=U32 1=S32?
//!     8=U64 9=S64; b73/b74 text-INERT inside a lane.
//! GRAFT (table-only mirrors; verify339post FAILS 0: 64/64 graft-space +
//!   18/18 corpus witnesses NEW==vendor x4; no-shadow OLD==NEW):
//!   sm120: +era keys {F64.FLOOR,F64.TRUNC,S64.F64,S64.F64.TRUNC,
//!     U32.F64.TRUNC} cloned from sm121a; +F2I.U64.F64.TRUNC_R_R (new, ab
//!     b72^=1 of the S64 sibling); +F2I.S64.TRUNC_R_R (era clone of the
//!     same-leg U64 row ab|b72); F2I_R_R += mg 'F64,TRUNC' (121a guard-field
//!     clone) + mg 'S64,TRUNC' (byte-exact sm103a donor clone).
//!   sm121a: +F2I.U64.F64.TRUNC_R_R; +mg 'S64,TRUNC'; +F2I.S64.TRUNC_R_R.
//! NOT GRAFTED (registered): NTZ_P = HMMA.1688 dead-shadow; donor-parity
//!   reuse overclaim (b122/b123, vendor rc=1, engine==donor); era-sign 62/63
//!   on TRUNC/F64 classes (4-leg pre-existing); byte9-lane siblings (b73/b74
//!   inert words stay pinned-hole per sibling posture).

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
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}

#[test]
fn t339_1_structure_clones_and_disjointness() {
    let d = tab("sm103a");
    let l121 = tab("sm121a");
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // generic donor clone S64,TRUNC == donor shape (ab/vm/fields)
        let g = &t.entries["F2I_R_R"].mod_groups["S64,TRUNC"];
        let gd = &d.entries["F2I_R_R"].mod_groups["S64,TRUNC"];
        assert_eq!(g.and_base ^ gd.and_base, 0, "{leg} S64 clone ab");
        assert_eq!(g.variable_mask, gd.variable_mask, "{leg} S64 clone vm");
        let shape = |e: &cubit::table::ModGroupEntry| {
            e.fields
                .iter()
                .map(|f| (f.shift, f.bits, f.token_idx))
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(g), shape(gd), "{leg} S64 clone fields");
        // era S64 key == sibling U64 key with exactly b72 flipped
        let s = &t.entries["F2I.S64.TRUNC_R_R"].mod_groups[""];
        let u = &t.entries["F2I.U64.TRUNC_R_R"].mod_groups[""];
        assert_eq!(
            (s.and_base ^ u.and_base) & M96,
            1u128 << 72,
            "{leg} era b72"
        );
        assert_eq!(s.variable_mask, u.variable_mask, "{leg} era vm parity");
        assert_eq!(shape(s), shape(u), "{leg} era fields parity");
        // U64.F64.TRUNC era key == S64.F64.TRUNC sibling with b72 cleared
        let n = &t.entries["F2I.U64.F64.TRUNC_R_R"].mod_groups[""];
        let s64 = &t.entries["F2I.S64.F64.TRUNC_R_R"].mod_groups[""];
        assert_eq!(
            (n.and_base ^ s64.and_base) & M96,
            1u128 << 72,
            "{leg} F64 b72"
        );
        // BUG-362 flip: era-sign fields ARE armed now (abs@62/neg@63 tok2
        // grafted, arb362 S-group x4 agree; was the registered gap):
        assert!(
            s.fields.iter().any(|f| matches!(f.extraction, cubit::table::Extraction::Neg))
                && s.fields.iter().any(|f| matches!(f.extraction, cubit::table::Extraction::Abs)),
            "{leg}: era S64 row carries neg/abs (BUG-362 graft)"
        );
    }
    // sm120-era clones byte-parity with the 121a donors
    for k in [
        "F2I.F64.FLOOR_R_R",
        "F2I.F64.TRUNC_R_R",
        "F2I.S64.F64_R_R",
        "F2I.S64.F64.TRUNC_R_R",
        "F2I.U32.F64.TRUNC_R_R",
    ] {
        let a = &tab("sm120").entries[k].mod_groups[""];
        let b = &l121.entries[k].mod_groups[""];
        assert_eq!(a.and_base ^ b.and_base, 0, "{k} cross-leg ab");
        assert_eq!(a.variable_mask, b.variable_mask, "{k} cross-leg vm");
    }
    // donors untouched by the graft
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(!t.entries.contains_key("F2I.U64.F64.TRUNC_R_R"), "{leg}");
        assert!(!t.entries.contains_key("F2I.S64.TRUNC_R_R"), "{leg}");
    }
}

#[test]
fn t339_2_decode_witnesses_vendor_exact() {
    // D1 corpus witnesses (x4-vendor-verified texts; arb339 B2354-style)
    let w1: u128 = 0x0020d9000000001500161311; // '@P1 F2I.S64.TRUNC R22, R21'
    let w2: u128 = 0x0030d80000000006001a7311; // 'F2I.U64.F64.TRUNC R26, R6'
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(dec(&t, w1).unwrap(), "@P1 F2I.S64.TRUNC R22, R21", "{leg}");
        // BUG-361 flip: the generic-mg print order is the vendor law now
        // (dst-type < src-type < rounding), donors print vendor text too.
        assert_eq!(dec(&t, w2).unwrap(), "F2I.U64.F64.TRUNC R26, R6", "{leg}");
    }
    // D2 era family on both era legs (vendor texts from arb339 F64fam set)
    let fam: &[(u128, &str)] = &[
        (0x0030d00000000006001a7311, "F2I.U32.F64.TRUNC R26, R6"),
        (0x0030d10000000006001a7311, "F2I.F64.TRUNC R26, R6"),
        (0x0030d90000000006001a7311, "F2I.S64.F64.TRUNC R26, R6"),
        (0x003051000000000000007311, "F2I.F64.FLOOR R0, R0"),
        (0x003019000000000000007311, "F2I.S64.F64 R0, R0"),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (w, want) in fam {
            assert_eq!(dec(&t, *w).as_deref(), Some(*want), "{leg} {want}");
        }
    }
    // era-shaped S64 (arb339 A7): PT lane, fields @17/@33
    let e: u128 = 0x0020d9000000001a00167311;
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(dec(&t, e).unwrap(), "F2I.S64.TRUNC R22, R26", "{leg}");
    }
}

#[test]
fn t339_3_authored_mints_and_roundtrips() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // generic-clone lane: guard==1 word is byte-exact vs corpus witness
        let w = enc(&t, "@P1 F2I.S64.TRUNC R22, R21").unwrap();
        assert_eq!(w & M96, 0x0020d9000000001500161311u128, "{leg}");
        // era lane: PT shape byte-pin (== arb339 A7 pattern, x4 vendor text)
        let w = enc(&t, "F2I.S64.TRUNC R22, R26").unwrap();
        assert_eq!(w & M96, 0x0020d9000000001a00167311u128, "{leg}");
        let w = enc(&t, "F2I.U64.F64.TRUNC R26, R6").unwrap();
        assert_eq!(w & M96, 0x0030d80000000006001a7311u128, "{leg}");
        for (w, want) in [
            (w, "F2I.U64.F64.TRUNC R26, R6"),
            (
                enc(&t, "F2I.F64.FLOOR R0, R0").unwrap(),
                "F2I.F64.FLOOR R0, R0",
            ),
        ] {
            assert_eq!(dec(&t, w).as_deref(), Some(want), "{leg} roundtrip");
        }
        // authored U64 sibling unchanged (era U64 lane byte-stable)
        let w = enc(&t, "F2I.U64.TRUNC R22, R26").unwrap();
        assert_eq!((w >> 72) & 1, 0, "{leg}: U64 stays b72=0");
    }
}

#[test]
fn t339_4_fail_closed_residua() {
    // b75=0 in the S64 lane is vendor-ILLEGAL (arb339 A2b75): stays HOLE on
    // every leg (byte9 pinned d9; donors agree).
    let bad: u128 = 0x0020d9000000001500161311 ^ (1u128 << 75);
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert!(dec(&t, bad).is_none(), "{leg}: b75 junk claims");
    }
    // byte9 [75:72]-nibble alias window: this word is the arb339 B1n2
    // probe (nibble value 2 on the U64 anchor byte9=0xd8 -> 0xd2).
    // BUG-362 flip: b73/b74 are the ALIAS bits of the dst-selector lattice
    // nibble (vendor aliases {0,2,4,6}->U32.F64.TRUNC, {8,a,c,e}->U64,
    // {9,b,d,f}->S64, {1,3,5,7}->F64; arb339 A2/B1 + arb362 I + arb362b +
    // arb362c 12 probes, x4 models): nibble 2 decodes vendor-EXACT as the
    // U32 class on every leg. Pre-362 the era rows pinned b73/b74 = 0, so
    // this word was HOLE ("lane-2 posture"); the grafted vm relax closes
    // the whole alias zone (supersedes the 362c pin-posture -- see also
    // tests/bug362 pin t362_5 for the full lattice + fail-closed borders).
    let lane2: u128 = (0x0030d80000000006001a7311 & !(0xFu128 << 72)) | (2u128 << 72);
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, lane2).as_deref(),
            Some("F2I.U32.F64.TRUNC R26, R6"),
            "{leg}: B1n2 alias decode (BUG-362)"
        );
    }
    let t = tab("sm120");
    // Post-341 attributed flip (arb341 C-sweep law, x4 vendor AGREE): the
    // era pin S16.NTZ leaves the U8 vendor lane -- pre-341 byte9=0x00 was the
    // D1 silent wrong-code pin (authored 'F2I.S16.NTZ' minted a vendor-U8
    // word); BUG-341 lattice geometry type[0x09]|round[0x20] -> era lane
    // 0x29; lane 0x00 is owned by the U8 plain row (bug341 pin file).
    let s16 = &tab("sm120").entries["F2I.S16.NTZ_R_R"].mod_groups[""];
    assert_eq!(
        (s16.and_base >> 72) & 0xff,
        0x29,
        "341 flip: S16.NTZ era lane = 0x29"
    );
}

#[test]
fn t339_5_corpus_samples_byte_stable() {
    // all 8 B2354-class + 2 U64.F64 corpus witnesses byte-decode on all legs
    let words: [u128; 6] = [
        0x0020d9000000001500161311,
        0x0020d9000000001200141311,
        0x0020d9000000002200201311,
        0x0020d9000000001600141311,
        0x0030d80000000006001a7311,
        0x0030d80000000010001e7311,
    ];
    let want: [&str; 6] = [
        "@P1 F2I.S64.TRUNC R22, R21",
        "@P1 F2I.S64.TRUNC R20, R18",
        "@P1 F2I.S64.TRUNC R32, R34",
        "@P1 F2I.S64.TRUNC R20, R22",
        "F2I.U64.F64.TRUNC R26, R6",
        "F2I.U64.F64.TRUNC R30, R16",
    ];
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        // BUG-361 flip: donors print vendor text (own-spelling map removed).
        for (w, txt) in words.iter().zip(want) {
            assert_eq!(dec(&t, *w).as_deref(), Some(txt), "{leg} {txt}");
        }
    }
}
