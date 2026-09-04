//! BUG-245 (F2-iter124, front2/blind, 2026-08-28): f16/bf16 negative-zero
//! immediate glyph law — nvdisasm 13.3.73 prints "-0.0 " WITH a trailing
//! space (same special-token law as ±INF/±QNAN); our printer used to print
//! "-0.0" (no space) -> 23 whitespace-only DIFFs per leg in gold243_post
//! (s100a/s103/s120, identical words: HFMA2 FI_FI pairs in libcusolver).
//!
//! Law (arb245 probes on the corpus witness word, vendor nvdisasm 13.3.73,
//! work/bug245/probe245[bc].py):
//!   L1 f16 tok4=-0.0   -> "-0.0 , 0"      (trailing space)
//!   L2 f16 tok4 in {-1,-2.5,-subnormal,+1,0} -> NO trailing space
//!   L3 f16 tok5=-0.0   -> "1, -0.0  ;"    (space rides the token, any slot)
//!   L4 ±INF/±QNAN      -> trailing space  (already our law, confirmed f16)
//!   L5 bf16 halves obey the identical law (HFMA2.BF16_V2 probes)
//! Encoder side unchanged: parser trims whitespace, both spellings encode
//! to the identical word.
//!
//! Decode legs pinned: sm100a / sm103a / sm120 (ohne sm121a: HFMA2 there is
//! in the registered 121a-parity era class, not this fix's scope).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1; // strip ctrl/sched bits on encode compares

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    to_sass(&idx.decode(w, 0, t).expect("decode"))
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// Witness words (corpus libcusolver.so.1002.sm_100.cubin .text.sytrd4
// @0x3f20 + bit-set variants; low-96, ctrl stripped). HFMA2 R3, -RZ, RZ, <lo>, <hi>
// with tok4=bits[63:48], tok5=bits[47:32].
const W_BASE: u128 = 0x000001ff80000000ff037431; // lo=-0.0, hi=0
const W_LO_POS1: u128 = 0x000001ff3c000000ff037431; // lo=+1.0
const W_LO_NEG1: u128 = 0x000001ffbc000000ff037431; // lo=-1.0
const W_LO_NEG2P5: u128 = 0x000001ffc1000000ff037431; // lo=-2.5
const W_LO_NEGSUB: u128 = 0x000001ff80010000ff037431; // lo=-subnormal
const W_HI_NEG0_LO_POS1: u128 = 0x000001ff3c008000ff037431; // hi=-0.0
const W_HI_NEG1_LO_POS1: u128 = 0x000001ff3c00bc00ff037431; // hi=-1.0
const W_BOTH_NEG0: u128 = 0x000001ff80008000ff037431; // both -0.0
const W_BF16: u128 = 0x002001ff80000000ff037431; // BF16_V2 pivot b85, lo=-0.0
const W_LO_PINF: u128 = 0x000001ff7c000000ff037431; // lo=+INF

#[test]
fn t245_1_decode_neg0_trailing_space() {
    // L1/L5: vendor-true glyphs per leg.
    for arch in ["sm100a", "sm103a", "sm120"] {
        let t = tab(arch);
        assert_eq!(dec(&t, W_BASE), "HFMA2 R3, -RZ, RZ, -0.0 , 0", "{arch} L1");
        assert_eq!(
            dec(&t, W_BOTH_NEG0),
            "HFMA2 R3, -RZ, RZ, -0.0 , -0.0 ",
            "{arch} both -0.0"
        );
        assert_eq!(
            dec(&t, W_LO_PINF),
            "HFMA2 R3, -RZ, RZ, +INF , 0",
            "{arch} L4 INF unchanged"
        );
    }
}

#[test]
fn t245_2_encode_both_spellings_identical() {
    // Parser trims whitespace: "-0.0 , 0" (vendor) and "-0.0, 0" (legacy ours)
    // encode to the SAME witness word on all three fixed legs.
    for arch in ["sm100a", "sm103a", "sm120"] {
        let t = tab(arch);
        let a = enc(&t, "HFMA2 R3, -RZ, RZ, -0.0 , 0");
        let b = enc(&t, "HFMA2 R3, -RZ, RZ, -0.0, 0");
        assert_eq!(a & M96, W_BASE, "{arch} vendor spelling encodes to witness");
        assert_eq!(a, b, "{arch} legacy spelling == witness");
    }
}

#[test]
fn t245_3_roundtrip_fidelity() {
    // decode -> print -> encode == original word (whitespace never re-encodes).
    for arch in ["sm100a", "sm103a", "sm120"] {
        let t = tab(arch);
        for w in [W_BASE, W_BOTH_NEG0, W_LO_PINF, W_LO_NEG1] {
            let text = dec(&t, w);
            assert_eq!(enc(&t, &text) & M96, w, "{arch} rt {text}");
        }
    }
}

#[test]
fn t245_4_no_space_law_holds() {
    // L2/L3: negative (non-zero), subnormal, and positive halves must NOT
    // gain a space; the space rides only -0.0/INF/QNAN tokens (L3: any slot).
    for arch in ["sm100a", "sm103a", "sm120"] {
        let t = tab(arch);
        assert_eq!(dec(&t, W_LO_POS1), "HFMA2 R3, -RZ, RZ, 1, 0", "{arch} +1");
        assert_eq!(dec(&t, W_LO_NEG1), "HFMA2 R3, -RZ, RZ, -1, 0", "{arch} -1");
        assert_eq!(
            dec(&t, W_LO_NEG2P5),
            "HFMA2 R3, -RZ, RZ, -2.5, 0",
            "{arch} -2.5"
        );
        assert_eq!(
            dec(&t, W_LO_NEGSUB),
            "HFMA2 R3, -RZ, RZ, -5.9604644775390625e-08, 0",
            "{arch} -subnormal"
        );
        assert_eq!(
            dec(&t, W_HI_NEG0_LO_POS1),
            "HFMA2 R3, -RZ, RZ, 1, -0.0 ",
            "{arch} L3 last-slot -0.0"
        );
        assert_eq!(
            dec(&t, W_HI_NEG1_LO_POS1),
            "HFMA2 R3, -RZ, RZ, 1, -1",
            "{arch} last-slot -1 no space"
        );
    }
}

#[test]
fn t245_5_bf16_fifi_hole_sentinel() {
    // FLIPPED F2-iter157 (BUG-285 armed, canonical e41a438): the BF16_V2
    // cross-key rows LANDED on the packed-f16 imm parents (arb285 x4), i.e.
    // the graft decision that 246-kand parked is executed for this lane.
    // FLIP2 2026-09-02 (BUG-354, attribution): the sparse (donor) legs are
    // ARMED too -- the 354 graft landed BF16_V2 + the mod-lane family on
    // the sparse FI/II lattice (arb354 108 probes x4; canonical 5c12995);
    // sparse decode is vendor-EXACT byte-identical to dense. Full battery
    // in tests/bug354_hfma2_sparse_modlane.rs.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        let d = idx
            .decode(W_BF16, 0, &t)
            .unwrap_or_else(|e| panic!("{arch}: 285 arm lost: {e}"));
        assert_eq!(
            cubit::printer::to_sass(&d),
            "HFMA2.BF16_V2 R3, -RZ, RZ, -0.0 , 0",
            "{arch}: vendor-exact 285 decode (post-354: all legs)"
        );
        // L5 holds engine-side via the shared float formatter (bf16 halves
        // go through format_float): the *print* law is pinned by t245_1/4.
    }
}
