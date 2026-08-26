//! BUG-157 — SYNCS family render/encode parity (owner: loop5/blind iter82).
//!
//! Root (census-first, 17,651 vendor words; winner-census binary-driven):
//!   1. mod-order: cubit printed group-storage order (`.ARRIVE.RED.TRANS64`,
//!      A1T0/A0TR first), vendor law is ARRIVE < TRANS64 < RED < A1T0/A0TR
//!      (corpus: 17,651 anchors, zero counter-examples).
//!   2. ARI rows (R+P, 6 groups) carry the UR window baked 0xff @[64:72) with
//!      no UR field => render dropped `+URZ` (vendor ALWAYS prints it:
//!      `[R5+URZ+0x130]`, 7,413 ARI-class anchors, zero `[R+off]` bare forms).
//!   3. real UR != URZ in ARI brackets (187 anchors) fell OFF the baked rows
//!      and were stolen by junk rows: R-side dup-reg@24 SYNCS_R_AURI_R rows
//!      (printed `R170, [UR40+0x180e0], R170` — base dropped), P-side
//!      SYNCS_P_dARI_R (printed `desc[UR13][R2.64+0xe0]` — desc fabricated).
//!      103/103 P_dARI wins were fabrications; key deleted.
//! Data fix (patch157.py): dup@24 removed from two R_AURI groups (tok1=reg@16,
//! tok3=reg@32, sibling geometry); SYNCS_P_dARI_R deleted; SYNCS_R_ARURI_R
//! gains anchor-derived group "ARRIVE,RED,TRANS64" (encode fixed-point of the
//! corrected render; the six RED-only anchors).
//! Printer fix (src/printer.rs): SYNCS mod priority arm; ARURI+SYNCS routed to
//! format_addr (plain [R+UR+off], never desc); ARI+SYNCS without UR field and
//! raw @[64:72)==0xff splices "+URZ"; format_addr URZ law is window-width
//! aware (8-bit windows: 255=URZ, 63=UR63 — BUG-160 law; narrower legacy
//! windows keep 63=URZ).
//!
//! Anchors below = vendor witnesses from the 32.2M-line hexdb + nv-harvest
//! (arch tag per row; decode/encode through tables/sm103a.json).

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

// (vendor text, lo64, hi32 = bits[64:96)) — vendor witnesses.
const CASES: &[(&str, u64, u32)] = &[
    // ARI R, no-RED, imm: mod fine but +URZ was dropped pre-fix.
    ("SYNCS.ARRIVE.TRANS64 RZ, [R4+URZ], R7", 0x0000000704ff79a7, 0x080000ff),
    // ARI R, A1T0, imm: A1T0 printed first pre-fix + URZ dropped.
    ("SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R5+URZ+0x130], RZ", 0x000130ff05ff79a7, 0x081000ff),
    // ARI R, real UR != URZ: stolen by dup-reg@24 AURI junk pre-fix.
    ("SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R170+UR40+0x180e0], RZ", 0x0180e0ffaaff79a7, 0x08100028),
    // ARI R, RED only: mod order + URZ.
    ("@!P0 SYNCS.ARRIVE.TRANS64.RED RZ, [R30+URZ], R2", 0x000000021eff89a7, 0x080004ff),
    // AURI R-form [URm(+off)]: mod order only (A1T0/A0TR first pre-fix).
    ("@!P3 SYNCS.ARRIVE.TRANS64.A1T0 RZ, [UR13+0xc8], RZ", 0x0000c8ffffffb9a7, 0x0810000d),
    ("SYNCS.ARRIVE.TRANS64.RED.A1T0 RZ, [UR7], RZ", 0x000000ffffff79a7, 0x08100407),
    ("@!P1 SYNCS.ARRIVE.TRANS64.RED.A0TR RZ, [UR13+0x80], R4", 0x00008004ffff99a7, 0x0830040d),
    ("SYNCS.ARRIVE.TRANS64.RED RZ, [UR4], R5", 0x00000005ffff79a7, 0x08000404),
    // ARI P-side: URZ dropped pre-fix.
    ("SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R5+URZ+0x140], R4", 0x00014004050075a7, 0x080011ff),
    ("@!P0 SYNCS.PHASECHK.TRANS64 P0, [R5+URZ+0x40], R4", 0x00004004050085a7, 0x080010ff),
    // P-side real UR: desc-fabricated pre-fix (SYNCS_P_dARI_R, row deleted).
    ("SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R2+UR13+0xe0], R3", 0x0000e003020075a7, 0x0800110d),
    ("@!P0 SYNCS.PHASECHK.TRANS64 P0, [R3+UR4+0x100], R0", 0x00010000030085a7, 0x08001004),
    // Guard rail: EXCH uniform path untouched.
    ("SYNCS.EXCH.64 URZ, [UR13], UR8", 0x000000080dff75b2, 0x08000100),
];

#[test]
fn bug157_decode_byte_exact_vendor() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi32) in CASES {
        let w = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = dec(&t, &idx, w);
        assert_eq!(&got, text, "decode render parity");
    }
}

#[test]
fn bug157_encode_byte_exact_vendor() {
    let t = t103a();
    for (text, lo, hi32) in CASES {
        let want = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = enc(&t, text);
        assert_eq!(got, want, "encode byte-exact (payload): {text}");
    }
}

#[test]
fn bug157_canonical_fixed_point() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, _, _) in CASES {
        let w = enc(&t, text);
        let got = dec(&t, &idx, w);
        assert_eq!(&got, text, "decode(encode(text)) fixed point");
    }
}

#[test]
fn bug157_no_desc_fabrication_and_fail_closed() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // The old P_dARI fabrication: plain [R+UR+off] must never print desc-form.
    let w = 0x0000e003020075a7u128 | (0x0800110du128 << 64);
    let got = dec(&t, &idx, w);
    assert!(!got.contains("desc["), "no desc fabrication: {got}");
    // The fabricated spelling itself is no longer encodable (key deleted).
    let insn = parse_sass("SYNCS.PHASECHK.TRANS64.TRYWAIT P0, desc[UR13][R2.64+0xe0], R3", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err(), "desc-form SYNCS must fail closed");
}

#[test]
fn bug157_synctable_invariants() {
    let t = t103a();
    // P_dARI key deleted outright.
    assert!(t.get("SYNCS_P_dARI_R", "PHASECHK,TRANS64,TRYWAIT").is_none());
    // Encode-hole closure: R_ARURI gained the anchor-derived RED-only group.
    assert!(t.get("SYNCS_R_ARURI_R", "ARRIVE,RED,TRANS64").is_some());
    // ARI rows still carry no UR field (printer BUG-157 arm owns the +URZ glyph)
    // and still pin the baked window 0xff @[64:72).
    let e = t.get("SYNCS_R_ARI_R", "A1T0,ARRIVE,TRANS64").expect("row");
    assert!(e.fields.iter().all(|f| f.shift != 64));
    assert_eq!(e.and_base & (0xFFu128 << 64), 0xFFu128 << 64);
}
