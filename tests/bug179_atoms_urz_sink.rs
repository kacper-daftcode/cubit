//! BUG-179 — ATOMS baked-URZ-sink ARI rows: render + encode parity (owner:
//! loop5/blind iter83). Found by the `_ARI_`-bez-UR row audit (note 157 b):
//! SYNCS-class rows outside SYNCS.
//!
//! Root (census-first; 9,130 ATOMS vendor words in the 32.2M-line hexdb):
//!   - ATOMS_R_ARI::"32,INC,POPC" bakes the uniform window 0xff @[64:72) with
//!     no UR field; the printer dropped `+URZ` and the ATOMS arm lacked POPC,
//!     so the class rendered `ATOMS.INC.POPC.32 RZ, [R0+0x3c]` — vendor:
//!     `ATOMS.POPC.INC.32 RZ, [R0+URZ+0x3c]` (478/478 cohort anchors, ALL
//!     `RZ, [Rn+URZ(+0x..)]`, bit72=0, window=0xff; 0 `ATOMS.INC.POPC.*`
//!     occurrences anywhere in the hexdb).
//!   - encode side failed closed on the vendor text (ARURI-shaped keys absent).
//!
//! Sibling evidence (same audit, NOT this bug): LDGSTS_ARI_ARI{,_P} and
//! STAS_ARI_R rows bake the same window but vendor ELIDES the sink there
//! (2,183 LDGSTS + 5 STAS machine anchors, zero vendor `+URZ`; nvdisasm
//! 13.3.73 arb179 D/E) — the splice must stay SYNCS|ATOMS-scoped.
//!
//! Vendor law pins (nvdisasm 13.3.73, work/i83/arb/arb179.json):
//!   - window 0xff renders `+URZ`, 0x3f renders `+UR63` (BUG-160 8-bit law),
//!     0x06 renders `+UR6` (real UR legal on INC.POPC — decode hole today is
//!     LATENT: 0 real-UR anchors; parked as follow-up candidate).
//!
//! Fix:
//!   - printer.rs: sink-splice arm extended SYNCS -> {SYNCS, ATOMS}
//!     (superset of parked-BUG-157's arm); ATOMS mod priority POPC < op.
//!   - encoder.rs: ARI-shaped alias candidates for `+URZ` addresses +
//!     urz_sink_baked() structural guard (window fully pinned to 0xff, not
//!     variable, not field-carried) relaxing the `addr UR` completeness
//!     reject ONLY for ur_reg==Some(255).
//!
//! Anchors below = vendor witnesses from the 32.2M-line hexdb.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// (vendor text, lo64, hi32 = bits[64:96))
const ATOMS_CASES: &[(&str, u64, u32)] = &[
    // Cohort shape: no-offset and offset forms (hexdb).
    ("ATOMS.POPC.INC.32 RZ, [R0+URZ+0x3c]", 0x00003c0000ff7f8c, 0x0d8000ff),
    ("ATOMS.POPC.INC.32 RZ, [R0+URZ]", 0x0000000000ff7f8c, 0x0d8000ff),
    ("ATOMS.POPC.INC.32 RZ, [R2+URZ+0x40]", 0x0000400002ff7f8c, 0x0d8000ff),
];

#[test]
fn t179_1_decode_vendor_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (v, lo, hi) in ATOMS_CASES {
        let got = dec(&t, &idx, ((*hi as u128) << 64) | *lo as u128);
        assert_eq!(&got, v, "decode must reproduce the vendor text");
    }
}

#[test]
fn t179_2_encode_payload_exact() {
    let t = t103a();
    for (v, lo, hi) in ATOMS_CASES {
        let w = enc(&t, v);
        assert_eq!(w, ((*hi as u128) << 64) | *lo as u128,
            "encode must land the sink structurally (and_base), payload == anchor");
    }
}

#[test]
fn t179_3_roundtrip_fixed_point() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (_, lo, hi) in ATOMS_CASES {
        let w = ((*hi as u128) << 64) | *lo as u128;
        let text = dec(&t, &idx, w);
        assert_eq!(enc(&t, &text), w, "decode->encode must be a fixed point");
    }
}

#[test]
fn t179_4_real_ur_stays_fail_closed() {
    let t = t103a();
    // UR63 is a REAL register (BUG-160 law), UR6 likewise vendor-legal on the
    // silicon (arb179 B/C) but the table has no AURI row for INC.POPC —
    // and the sink alias must not cover them.
    for bad in ["ATOMS.POPC.INC.32 RZ, [R0+UR63+0x3c]",
                "ATOMS.POPC.INC.32 RZ, [R0+UR6+0x3c]"] {
        let insn = parse_sass(bad, 0).expect("parse");
        assert!(encode_instruction(&insn, &t).is_err(), "must fail closed: {bad}");
    }
}

#[test]
fn t179_5_baked_siblings_still_elide() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // LDGSTS/STAS bake the same 0xff window but vendor never prints the sink.
    // (The LDGSTS `.BYPASS.E` mod order and the `[R28.64]` -> `[R28]` glyph on
    // these rows are the parked 092-domain classes measured in iter83's audit
    // — NOT this bug; only the no-UR invariant is pinned here.)
    let ldgsts = dec(&t, &idx, (0x08180affu128 << 64) | 0x000000001c8c7faeu128);
    assert!(ldgsts.contains("[R140]") && !ldgsts.contains("UR"),
        "LDGSTS must keep eliding URZ: {ldgsts}");
    // STAS shares the baked sink AND shows the same parked 092-domain `.64`
    // glyph drop as LDGSTS (vendor `STAS [R2.64], R9`, 5 anchors) — only the
    // no-UR invariant is in scope here.
    let stas = dec(&t, &idx, (0x0c0008ffu128 << 64) | 0x0000000902007dbdu128);
    assert!(!stas.contains("UR"), "STAS must keep eliding URZ: {stas}");
}

#[test]
fn t179_6_syncs_sink_superset_consistent() {
    // The ARI splice arm is a superset of parked-BUG-157's SYNCS-only variant.
    // On main-side (pre-compose) the SYNCS mod-order law is NOT in this patch
    // (it is 157's), so pin only the sink behavior: +URZ printed, and the
    // P-row phasechk case end-to-end (its mg storage order happens to equal
    // the vendor order already).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let r_side = dec(&t, &idx, (0x081000ffu128 << 64) | 0x000130ff05ff79a7u128);
    assert!(r_side.contains("[R5+URZ+0x130]"), "sink printed: {r_side}");
    let p = "SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R5+URZ+0x140], R4";
    let got = dec(&t, &idx, (0x080011ffu128 << 64) | 0x00014004050075a7u128);
    assert_eq!(got, p);
    assert_eq!(enc(&t, p), (0x080011ffu128 << 64) | 0x00014004050075a7u128);
}
