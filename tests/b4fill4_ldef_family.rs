//! b4fill4 (loop5 F2-iter38, 2026-08-23): LD generic-family ARI coverage —
//! the BUG-094 junk-sink word's vendor-true class (LD.EF.U8, zero corpus
//! anchors anywhere — pure word-probe RE on cuobjdump-13.3 one-word cubins,
//! geometry grounded on the LDG_R_dARI sibling family deltas + LD_R_ARI donor).
//! 25 additive mod groups on LD_R_ARI, both tables: full size enum
//! U8/S8/U16/S16/U32/64/128 x {.E present, absent} x {.EF, non-EF},
//! guard@[12:16), dest reg@[16:24), addr reg@[24:32), signed imm32@[32:64).
//! Existing rows (E/64,E/128,E) untouched; INVALID7 enum values stay
//! fail-closed. Provenance: /root/blindlab/work/f2i38/ldef/ (probe scripts +
//! anchors_ldef.json; per-row _evidence in the tables).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

static GOLD: &[(u128, &str)] = &[
    (0x000fe200000000000000000000000980u128, "@P0 LD.EF.U8 R0, [R0]"),
    (0x000fe200001000000000000000000980u128, "@P0 LD.U8 R0, [R0]"),
    (0x000fe200000001000000000000000980u128, "@P0 LD.E.EF.U8 R0, [R0]"),
    (0x000fe200001001000000000000000980u128, "@P0 LD.E.U8 R0, [R0]"),
    (0x000fe200000002000000000000000980u128, "@P0 LD.EF.S8 R0, [R0]"),
    (0x000fe200001002000000000000000980u128, "@P0 LD.S8 R0, [R0]"),
    (0x000fe200000003000000000000000980u128, "@P0 LD.E.EF.S8 R0, [R0]"),
    (0x000fe200001003000000000000000980u128, "@P0 LD.E.S8 R0, [R0]"),
    (0x000fe200000004000000000000000980u128, "@P0 LD.EF.U16 R0, [R0]"),
    (0x000fe200001004000000000000000980u128, "@P0 LD.U16 R0, [R0]"),
    (0x000fe200000005000000000000000980u128, "@P0 LD.E.EF.U16 R0, [R0]"),
    (0x000fe200001005000000000000000980u128, "@P0 LD.E.U16 R0, [R0]"),
    (0x000fe200000006000000000000000980u128, "@P0 LD.EF.S16 R0, [R0]"),
    (0x000fe200001006000000000000000980u128, "@P0 LD.S16 R0, [R0]"),
    (0x000fe200000007000000000000000980u128, "@P0 LD.E.EF.S16 R0, [R0]"),
    (0x000fe200001007000000000000000980u128, "@P0 LD.E.S16 R0, [R0]"),
    (0x000fe200000008000000000000000980u128, "@P0 LD.EF R0, [R0]"),
    (0x000fe200001008000000000000000980u128, "@P0 LD R0, [R0]"),
    (0x000fe200000009000000000000000980u128, "@P0 LD.E.EF R0, [R0]"),
    (0x000fe20000000a000000000000000980u128, "@P0 LD.EF.64 R0, [R0]"),
    (0x000fe20000100a000000000000000980u128, "@P0 LD.64 R0, [R0]"),
    (0x000fe20000000b000000000000000980u128, "@P0 LD.E.EF.64 R0, [R0]"),
    (0x000fe20000000c000000000000000980u128, "@P0 LD.EF.128 R0, [R0]"),
    (0x000fe20000100c000000000000000980u128, "@P0 LD.128 R0, [R0]"),
    (0x000fe20000000d000000000000000980u128, "@P0 LD.E.EF.128 R0, [R0]"),
];

fn check(table: &IsaTable) {
    let idx = DecodeIndex::build(table);
    for (word, want) in GOLD {
        let d = idx
            .decode(*word, 0, table)
            .unwrap_or_else(|e| panic!("decode failed for {word:032x} (want {want:?}): {e}"));
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, *want, "decode text mismatch for {word:032x}");
        let parsed = parse_sass(&format!("{text} ;"), 0).expect("pin text must re-parse");
        let enc = encode_instruction(&parsed, table).expect("pin text must re-encode");
        assert_eq!(
            enc & !SCHED,
            word & !SCHED,
            "encode payload mismatch for {want:?} (word {word:032x})"
        );
    }
}

#[test]
fn b4fill4_ldef_family_103a() { check(&t103a()); }

#[test]
fn b4fill4_ldef_family_120() { check(&t120()); }

#[test]
fn b4fill4_ldef_sink_is_vendor_true() {
    // BUG-094 junk sink (ex LDG_R_dARI::128,E,LTC128B and_base self-word) —
    // re-pinned per the pin's own note ("re-pin to the LD.EF truth when
    // coverage lands"): now decodes to the vendor-true LD.EF.U8 on both tables.
    for t in [t103a(), t120()] {
        let idx = DecodeIndex::build(&t);
        let sink: u128 = 0x000f_e200_0000_0000_0000_0000_0000_0980;
        let d = idx.decode(sink, 0, &t).expect("sink word must decode now");
        assert_eq!(cubit::printer::to_sass(&d), "@P0 LD.EF.U8 R0, [R0]", "sink identity");
    }
}

#[test]
fn b4fill4_ldef_invalid7_stays_closed() {
    // enum values 0xe/0xf (INVALID7) must remain fail-closed on both tables.
    for t in [t103a(), t120()] {
        let idx = DecodeIndex::build(&t);
        for v in [0xeu128, 0xf] {
            let w = 0x980u128 | (v << 72) | (0x000fe200u128 << 96);
            assert!(idx.decode(w, 0, &t).is_err(), "INVALID7 v={v:x} must fail closed");
        }
    }
}
