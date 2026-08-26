//! BUG-142 pins (census waves over the full vendor corpus, 2014 cubins
//! nvdisasm-13.3 anchor DB 30,406 atom-family instructions): encoder
//! coverage of REDG/ATOM/ATOMG/ATOMS desc-offset, return-dest, pred-dest
//! and shared-memory forms on tables/sm120.json and era artifact
//! tb_i82p3.json (identical family constants -- proven by anchor
//! consensus; the era file is pinned indirectly here through the same
//! byte-level rows on the shipped table).
//!
//! Pre-fix (census): tb_i82p3 125 + sm120 125 unique vendor texts failed
//! loudly (fail-closed), incl. the b8-F6b blocker
//! `@P4 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R209.64+0x80], R81`
//! (EL.P row had no imm field while sibling AND.EL/OR.EL did), all REDG
//! imm-offset forms, ATOM-with-return (desc + plain), ATOMS pred-dest
//! and UR+imm forms, ATOMG F64/EXCH/INC/DEC, UTCATOMSWS, UTMAREDG.3D.
//! Pre-fix encode was also SILENTLY wrong for some decode-shadow rows
//! (junk and_base, e.g. ASCII 'A' 0x41 baked at bits[32:40) of
//! REDG.E.ADD.STRONG.GPU_dARI_R; ATOMS_* and_base 0x0912.08 vs vendor
//! 0x00.73) -- encode-only path produced non-vendor bytes.
//!
//! Post-fix state (data-only; geometry cloned from sm103a canon where
//! census-proven, else derived from anchor consensus; and_base/vendor
//! consensus enforced per group; vmask widened only by observed vendor
//! variance): encode battery 14,372/14,378 unique vendor texts OK on
//! BOTH tables, 0 payload mismatches (bits<96, sched window excluded),
//! 0 decode regressions OLD-vs-NEW, +16,392 words newly decoded from
//! __raw__. 6 remaining fail-closed texts = canon-missing scope variants
//! (documented in results/cubitfix/142.md sec.5 parking).
//!
//! All words below are vendor witnesses (nvdisasm 13.3 corpus anchors,
//! rt98-era frozen cubins, or nvcc-13.3 sm_120a goldens); comparison
//! masks the top-32 sched/ctrl window like the surrounding suites.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// (text, low64, high64 low32 bits) — vendor witnesses.
const CASES: &[(&str, u64, u32)] = &[
    ("REDG.E.ADD.STRONG.GPU desc[UR12][R2.64+0x100], R9", 0x000100090200798e, 0x0c12e10c),
    ("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR10][R28.64+0x80], R57", 0x000080391c0079a6, 0x0c12f30a),
    ("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR10][R34.64+-0x4], R15", 0xfffffc0f220079a6, 0x0c12f30a),
    ("REDG.E.ADD.F64.RN.STRONG.GPU desc[UR4][R76.64+0x200], R56", 0x000200384c0079a6, 0x0c12ff04),
    ("@P0 REDG.E.AND.STRONG.GPU desc[UR6][R2.64], R5", 0x000000050200098e, 0x0e92e106),
    ("@P0 REDG.E.XOR.STRONG.GPU desc[UR6][R2.64], R5", 0x000000050200098e, 0x0f92e106),
    ("@P0 REDG.E.MIN.STRONG.GPU desc[UR52][R2.64], R5", 0x000000050200098e, 0x0c92e134),
    ("REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64], R6", 0x000000060800798e, 0x0d12e50a),
    ("REDG.E.ADD.64.STRONG.GPU desc[UR6][R6.64+0x8], R8", 0x000008080600798e, 0x0c12e506),
    ("REDG.E.ADD.S32.STRONG.GPU [R134], R3", 0x000000038600798e, 0x0010e300),
    ("@P0 ATOM.E.ADD.STRONG.GPU PT, R11, desc[UR6][R6.64+0x4], R11", 0x8000040b060b098a, 0x081ef106),
    ("ATOM.E.ADD.F16x2.RN.STRONG.GPU P0, RZ, desc[UR10][R10.64], R100", 0x800000640aff79a2, 0x0c10e10a),
    ("ATOM.E.ADD.BF16x2.RN.STRONG.GPU P4, RZ, desc[UR14][R4.64+0x8], R7", 0x8000080704ff79a2, 0x0c18e70e),
    ("ATOM.E.ADD.F32.FTZ.RN.STRONG.GPU P0, RZ, desc[UR10][R2.64], R11", 0x8000000b02ff79a2, 0x0c10f30a),
    ("ATOM.E.ADD.F64.RN.STRONG.GPU P0, RZ, desc[UR10][R10.64], R12", 0x8000000c0aff79a2, 0x0c10ff0a),
    ("ATOM.E.ADD.64.STRONG.GPU P0, R10, desc[UR10][R8.64+0x8], R10", 0x8000080a080a798a, 0x0810f50a),
    ("@P0 ATOM.E.AND.STRONG.SM PT, RZ, desc[UR10][R10.64+0x4], R9", 0x800004090aff098a, 0x0a9eb10a),
    ("ATOM.E.CAS.STRONG.GPU PT, R26, [R6], R27, R26", 0x0000001b061a738b, 0x001ee11a),
    ("ATOM.E.CAST.SPIN PT, R5, [R2+0x4], R4, R5", 0x000004040205738b, 0x019e0105),
    ("ATOM.E.CAST.SPIN.64 PT, R6, [R10+0x8], R4, R6", 0x000008040a06738b, 0x019e0506),
    ("ATOMS.ADD R23, [R23+0x100], R0", 0x000100001717738c, 0x00000000),
    ("ATOMS.CAS R0, [R0+0x4], R6, R7", 0x000004060000738d, 0x00000007),
    ("ATOMS.CAST.SPIN P1, [R88+0x80], R44, R45", 0x0000802c5800758d, 0x0182002d),
    ("ATOMS.CAST.SPIN.64 P0, [R13+0x8], R8, R10", 0x000008080d00758d, 0x0180040a),
    ("ATOMS.MAX.S32 RZ, [UR4+0x2004], R8", 0x00200408ffff798c, 0x09000204),
    ("ATOMS.MIN.S32 RZ, [UR4+0x2000], R11", 0x0020000bffff798c, 0x08800204),
    ("@P0 ATOMS.AND RZ, [UR4+0x14], R2", 0x00001402ffff098c, 0x0a800004),
    ("ATOMS.POPC.INC.32 RZ, [R0+URZ+0x121c]", 0x00121c0000ff7f8c, 0x0d8000ff),
    ("ATOMS.POPC.INC.32 RZ, [UR4+0xc]", 0x00000c00ffff7f8c, 0x0d800004),
    ("@P0 ATOMG.E.MIN.STRONG.GPU PT, RZ, desc[UR6][R10.64], R5", 0x800000050aff09a8, 0x089ef106),
    ("ATOMG.E.MAX.S32.STRONG.GPU PT, RZ, desc[UR6][R2.64], R0", 0x8000000002ff79a8, 0x091ef306),
    ("ATOMG.E.INC.STRONG.GPU PT, R2, desc[UR14][R2.64], R5", 0x80000005020279a8, 0x099ef10e),
    ("ATOMG.E.DEC.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8, 0x0a1ef104),
    ("ATOMG.E.EXCH.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8, 0x0c1ef104),
    ("ATOMG.E.CAS.STRONG.GPU PT, R11, [R12], R10, R11", 0x0000000a0c0b73a9, 0x001ee10b),
    ("UTCATOMSWS.FIND_AND_SET.ALIGN UP0, UR4, UR4", 0x00000004000475e3, 0x08000800),
    ("UTCATOMSWS.2CTA.FIND_AND_SET.ALIGN UP0, UR4, UR4", 0x00000004000475e3, 0x08200800),
    ("@!UP0 UTCATOMSWS.AND URZ, UR5", 0x0000000500ff89e3, 0x08000000),
    ("UTMAREDG.3D.ADD [UR8], [UR4]", 0x00000008040073b6, 0x08010000),
];

#[test]
fn bug142_encode_byte_exact_vendor() {
    let t = t120();
    for (text, lo, hi32) in CASES {
        let got = enc(&t, text);
        let want = (*lo as u128) | ((*hi32 as u128) << 64);
        assert_eq!(got, want, "encode byte-exact ({text})");
    }
}

#[test]
fn bug142_decode_parity_roundtrip() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi32) in CASES {
        let w = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = dec(&t, &idx, w);
        assert!(!got.contains("!rsd"), "no rsd residue ({text}) got: {got}");
        let re = enc(&t, &got);
        assert_eq!(re, w, "decode->encode roundtrip byte-exact for '{got}'");
    }
}

/// nota-138 follow-up intentionally NOT fixed here (see report sec.5):
/// `@P4 REDG.E.ADD.EL.STRONG.GPU PT, desc[..][..+imm], ..` stays
/// fail-closed everywhere. nvdisasm 13.3 arbitration (SM100/103a/120/120a)
/// proves the vendor reading of these EL words is the `[R84.U32+UR20+imm]`
/// mode (bug038a pins roundtrip that dialect), while the era table's
/// desc-form EL.P render is legacy fiction whose ureg@56 window aliases
/// the true imm window's top byte (imm up to 0xa2400 proven in era words).
/// Remodeling EL rows to U32+UR semantics is a table-epoch decision
/// (frozen era texts ride on the desc fiction), parked for the owner.
#[test]
fn bug142_sm120_el_desc_form_stays_failclosed() {
    let t = t120();
    let insn = parse_sass(
        "@P4 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R209.64+0x80], R81 ;", 0)
        .expect("parse");
    assert!(encode_instruction(&insn, &t).is_err(),
        "desc-form EL.P+imm must stay fail-closed on sm120 (U32+UR is vendor-true)");
    // ...but the era epoch's zero-offset EL.P text still must not exist here
    // either (no regression vs pre-fix sm120 behavior)
    let insn2 = parse_sass("@P4 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R209.64], R81 ;", 0)
        .expect("parse");
    assert!(encode_instruction(&insn2, &t).is_err(),
        "pre-existing sm120 fail-closed state for desc-form EL.P kept");
}

/// ATOM (0x738b) vs ATOMG (0x73a9) CAS: distinct opcodes, pre-fix era/sm120
/// tables had no rows for either plain-address form.
#[test]
fn bug142_atom_vs_atomg_cas_split() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let a = 0x0000001b061a738bu128 | ((0x001ee11au128) << 64); // ATOM.E.CAS
    let g = 0x0000000a0c0b73a9u128 | ((0x001ee10bu128) << 64); // ATOMG.E.CAS
    assert_eq!(dec(&t, &idx, a), "ATOM.E.CAS.STRONG.GPU PT, R26, [R6], R27, R26");
    assert_eq!(dec(&t, &idx, g), "ATOMG.E.CAS.STRONG.GPU PT, R11, [R12], R10, R11");
}

/// CAS.64 SYS (sm120 vendor golden, nvcc-13.3 sm_120a): cross-cloned row.
#[test]
fn bug142_atomg_cas64_sys() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let w = 0x000000080c0a73a9u128 | ((0x001f450au128) << 64);
    let txt = dec(&t, &idx, w);
    assert_eq!(txt, "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R12], R8, R10");
    assert_eq!(enc(&t, &txt), w, "CAS.64 SYS roundtrip");
}

/// POPC three-source address `[R+UR+imm]`: URZ writes the 0xFF sentinel in
/// the 8-bit sub_ur1 window (not 6-bit 0x3F).
#[test]
fn bug142_popc_ur_sentinel() {
    let t = t120();
    let w = enc(&t, "ATOMS.POPC.INC.32 RZ, [R23+URZ+0x683c]");
    assert_eq!((w >> 64) as u8, 0xff, "URZ sentinel 0xFF at sub_ur1 window");
    let idx = DecodeIndex::build(&t);
    let txt = dec(&t, &idx, w);
    assert!(txt.contains("URZ") || txt.contains("UR255"), "URZ sentinel prints back: {txt}");
    assert_eq!(enc(&t, &txt), w, "popc roundtrip");
}
