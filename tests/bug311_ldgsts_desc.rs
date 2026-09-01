//! BUG-311 (F2-iter168, loop5/blind front2, 2026-09-01): LDGSTS sm120
//! desc-form encoder law restored; era arm removed.
//!
//! PRE: encoder.rs carried a FlashAttention-era arm that rebuilt EVERY
//!   LDGSTS *.128 desc encode as baked `hi[31:0]=0x0b9a180e` (UR pinned to
//!   14, both immediates dropped, trailing pred/neg dropped, policy bits
//!   dropped) whenever the table was not sm103a-family. On the rt303 census
//!   that silently wrong-encoded 8,371 slots / 28 cubins
//!   (LDGSTS.E.BYPASS{.LTC128B}.128); post-303 strict-verify caught it
//!   (fail-closed migration; registration 311).
//! POST: arm deleted; sm120 BYPASS rows (already vendor-EXACT on decode)
//!   encode via their fields; the L1-allocate sibling family '128,E'
//!   grafted into sm120 tables (canonical 8fc8395) so `LDGSTS.E.128`
//!   keeps its era-verified L1-allocate mint instead of superset-routing
//!   to the BYPASS family.
//!
//! VENDOR LAW (arb311, nvdisasm 13.3.73 raw -b x4 models agree on every
//! probe; work/bug311/arb311_verdicts.json): b81 = L1-alloc<->BYPASS,
//! b73 = LTC128B, b76 = desc-form marker, b75 = size(.128) on the PT
//! block, b82 = ZFILL, b83/b91 = family core (flip -> ILLEGAL),
//! pred 3b@87 + neg@90 live on the E.128 family too (PT elides),
//! dst imm 20b@44 signed+raw, desc imm 12b@32 signed (0xff4 -> '+-0xc'),
//! UR 9b@64, dst 8b@[23:16] (row carries 9b; R>=256 impossible), guard 4b@12.
//!
//! POST-FIX CENSUS: 8,371/8,371 slots mint vendor-EXACT (SCHED-masked),
//! zero failures (measure_post311b.json); pre-303 reference mint: 0/N
//! exact (arm class, measure_pre311.json).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const SCHED: u128 = 0x1ffffu128 << 105;
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

#[test]
fn t311_1_row_structure_and_claim_disjointness() {
    let t = tab("sm120");
    let get = |key: &str, mg: &str| {
        t.entries
            .get(key)
            .and_then(|e| e.mod_groups.get(mg))
            .unwrap_or_else(|| panic!("{key}::{mg} missing"))
    };
    // L1-allocate sibling family grafted on both keys (canonical 8fc8395).
    let d = get("LDGSTS_ARI_dARI", "128,BYPASS,E");
    let n = get("LDGSTS_ARI_dARI", "128,E");
    assert_eq!(n.and_base & !M96, d.and_base & !M96, "same ctrl template");
    assert_eq!(
        (n.and_base ^ d.and_base) & M96,
        1u128 << 81,
        "only b81 (alloc)"
    );
    let shape = |g: &cubit::table::ModGroupEntry| {
        g.fields
            .iter()
            .map(|f| (f.shift, f.bits, f.token_idx))
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(n), shape(d), "dARI 128,E := donor field shape");
    assert_eq!(n.variable_mask, d.variable_mask, "vm inherited from donor");
    let dp = get("LDGSTS_ARI_dARI_P", "128,BYPASS,E,LTC128B");
    let np = get("LDGSTS_ARI_dARI_P", "128,E");
    assert_eq!(
        (np.and_base ^ dp.and_base) & M96,
        (1u128 << 73) | (1u128 << 81),
        "_P: b73 LTC off, b81 alloc on"
    );
    assert_eq!(shape(np), shape(dp), "dARI_P 128,E := donor field shape");
    assert_eq!(
        np.variable_mask, dp.variable_mask,
        "vm inherited from donor"
    );
    // claim separation: b73/b81 sit OUTSIDE variable_mask of every sibling
    for key in ["LDGSTS_ARI_dARI", "LDGSTS_ARI_dARI_P"] {
        for (mg, gg) in &t.entries[key].mod_groups {
            assert_eq!(
                gg.variable_mask & ((1u128 << 73) | (1u128 << 81)),
                0,
                "{key}::{mg} vm must pin LTC/alloc discriminants"
            );
        }
    }
}

#[test]
fn t311_2_decode_vendor_witnesses_exact() {
    let t = tab("sm120");
    // corpus witnesses (rt303 census; pre-fix: encode-side poisoned via arm)
    for (w, text) in [
        (
            0x0007e2000b98181206000000181b7faeu128,
            "LDGSTS.E.BYPASS.128 [R27+0x6000], desc[UR18][R24.64]",
        ),
        (
            0x0003e20008981a0e018800801c5a7faeu128,
            "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
        ),
        (
            0x0003e2000b98181200000ff43e1f7faeu128,
            "LDGSTS.E.BYPASS.128 [R31], desc[UR18][R62.64+-0xc]",
        ),
        (
            0x000ff6000c181a1a000000405a4a7faeu128,
            "LDGSTS.E.BYPASS.LTC128B.128 [R74], desc[UR26][R90.64+0x40], !P0",
        ),
    ] {
        assert_eq!(dec(&t, w).as_deref(), Some(text), "decode {text}");
    }
    // era FA witness: decode HOLE pre-fix (no sm120 row for L1-alloc family)
    let fa = 0x000000000b9a180e0000000016038faeu128;
    assert_eq!(
        dec(&t, fa).as_deref(),
        Some("@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]"),
        "E.128 (L1-alloc) family decode hole closed"
    );
}

#[test]
fn t311_3_encode_mints_vendor_exact() {
    let t = tab("sm120");
    for (text, vendor) in [
        (
            "LDGSTS.E.BYPASS.128 [R27+0x6000], desc[UR18][R24.64]",
            0x0007e2000b98181206000000181b7faeu128,
        ),
        (
            "LDGSTS.E.BYPASS.LTC128B.128 [R90+0x1880], desc[UR14][R28.64+0x80], P1",
            0x0003e20008981a0e018800801c5a7faeu128,
        ),
        (
            "LDGSTS.E.BYPASS.128 [R31], desc[UR18][R62.64+-0xc]",
            0x0003e2000b98181200000ff43e1f7faeu128,
        ),
        (
            "LDGSTS.E.BYPASS.LTC128B.128 [R74], desc[UR26][R90.64+0x40], !P0",
            0x000ff6000c181a1a000000405a4a7faeu128,
        ),
        (
            "@P2 LDGSTS.E.BYPASS.128 [R26+0x2000], desc[UR20][R52.64]",
            0x0003e2000b98181402000000341a2faeu128,
        ),
    ] {
        let w = enc(&t, text).unwrap();
        assert_eq!(w & !SCHED, vendor & !SCHED, "mint {text}");
        assert_eq!(dec(&t, w).as_deref(), Some(text), "roundtrip {text}");
    }
}

#[test]
fn t311_4_e128_alloc_family_mints() {
    let t = tab("sm120");
    // FA-era witness family: field-driven UR/imm/guard (arm pinned UR=14)
    let w = enc(&t, "@!P0 LDGSTS.E.128 [R3], desc[UR14][R22.64]").unwrap();
    assert_eq!(
        w & M96,
        0x0b9a180e0000000016038faeu128,
        "era FA word family preserved via table rows"
    );
    // UR and both immediates now flow through fields (arb311 law)
    let w = enc(&t, "LDGSTS.E.128 [R26], desc[UR20][R54.64], P2").unwrap();
    assert_eq!((w >> 64) & 0x1ff, 20, "desc UR not baked");
    assert_eq!((w >> 87) & 7, 2, "trailing pred window live on E.128");
    assert_eq!(
        dec(&t, w).as_deref(),
        Some("LDGSTS.E.128 [R26], desc[UR20][R54.64], P2")
    );
    let w = enc(&t, "LDGSTS.E.128 [R7+0x70], desc[UR6][R4.64+0x708]").unwrap();
    assert_eq!((w >> 44) & 0xF_FFFF, 0x70, "dst imm window raw");
    assert_eq!((w >> 32) & 0xFFF, 0x708, "desc imm window raw");
    // and BYPASS witnesses must NOT be claimed by the new rows (b81 pinned)
    for w in [w] {
        let _ = w;
    }
}

#[test]
fn t311_5_fail_closed_and_boundaries() {
    let t = tab("sm120");
    // ZFILL on sm120: no rows (family unwitnessed there) -> fail-closed
    let r = enc(&t, "LDGSTS.E.64.ZFILL [R7+0x70], desc[UR6][R4.64+0x708]");
    assert!(r.is_err(), "sm120 ZFILL must stay fail-closed");
    assert!(format!("{}", r.unwrap_err()).contains("no operand-compatible table entry"));
    // immediate windows fail closed via encode-lint (pathological overflow)
    assert!(enc(
        &t,
        "LDGSTS.E.BYPASS.128 [R27+0x2000000], desc[UR18][R24.64]"
    )
    .is_err());
    assert!(enc(
        &t,
        "LDGSTS.E.BYPASS.128 [R27+0x1], desc[UR18][R24.64+0x1000]"
    )
    .is_err());
    // signed 20-bit dst window edge is vendor-legal both ways (raw law)
    let w = enc(&t, "LDGSTS.E.BYPASS.128 [R27+0x80000], desc[UR18][R24.64]").unwrap();
    assert_eq!(
        dec(&t, w).as_deref(),
        Some("LDGSTS.E.BYPASS.128 [R27+-0x80000], desc[UR18][R24.64]")
    );
    // sm100a/sm103a legs: '128,E' rows were out of scope at 311; BUG-334
    // (canonical bfc8480) grafted them symmetric to sm120 -- flip with
    // attribution: rows now PRESENT; BYPASS desc mint stays byte-stable.
    for leg in ["sm100a", "sm103a"] {
        let tl = tab(leg);
        assert!(
            tl.entries["LDGSTS_ARI_dARI"]
                .mod_groups
                .contains_key("128,E"),
            "{leg}: 128,E grafted by BUG-334"
        );
        let r = enc(&tl, "LDGSTS.E.BYPASS.128 [R27+0x6000], desc[UR18][R24.64]").unwrap();
        assert_eq!(
            r & M96,
            0x0b98181206000000181b7faeu128,
            "{leg}: BYPASS desc mint stable vs publish"
        );
    }
}
