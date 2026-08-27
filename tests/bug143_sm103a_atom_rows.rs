//! BUG-143 (b4-forward lane, follow-up of BUG-142 note pkt 4): decoder
//! junk-rows in tables/sm103a.json, ATOM/ATOMS/ATOMG/REDG family.
//!
//! Census-first over the 30,406-anchor hexdb (nvdisasm 13.3 -hex, corpus
//! 2014 cubins + nvcc goldens sm_103a/sm_120a; work/bug142/hexdb +
//! work/i67). Pre-fix state (all machine-observed):
//!   (a) ATOMG.E.INC decoded with the address R window 9 bits wide
//!       ([24:33)) reading bit32, which is the DATA-R low bit on
//!       P_R_dARI_R rows: `desc[UR14][R258.64]` hallucination on 2
//!       vendor witnesses (R-value = base + 256).
//!   (b) ATOMS.POPC.INC.32 UR-tied address forms entirely mis-served:
//!       127 URZ-sentinel (0xFF@[64:72)) renders dropped the URZ token
//!       and 1 lone `[UR4+imm]` witness lost UR4 behind `[RZ+imm] !rsd`;
//!       text forms `[R+URZ+off]` / `[UR+off]` were fail-closed on encode.
//!   (c) ATOMS.CAS.64 mis-decoded as ATOMS.CAS with !rsd[74:1]; bit74 is
//!       the family's .64 discriminator (sibling pair proof:
//!       ATOMS_P_ARI_R_R CAST,SPIN vs 64,CAST,SPIN const-delta == 1<<74).
//!   (d) zombie rows REDG_[P_]dARI_R '64,ADD' (sub_ur0@24/8 dual-claiming
//!       the sub_r1 window, and_base junk constants inside field windows)
//!       SILENTLY mis-encoded `desc[UR10][..]` as desc[UR2][..] with
//!       UR6 baked at [64:72). Rebuilt from anchors.
//!
//! Fix (data-only tables/sm103a.json + one additive printer convention):
//!   E1  sub_r@24 9->8 bits on 17 groups (17 anchors have data-R LSB live;
//!       named REDG MIN.64 rows included)
//!   E2  ATOMS_R_AURI_R sub_ur0@64 9->8 on 7 groups (267 anchor lines,
//!       bit72 never set on silicon-witnessed words)
//!   E3  ATOMS_R_ARURI + ATOMS_R_AURI keys for POPC.32 (127+1 anchors),
//!       printer: 0xFF in ARURI UR windows prints URZ for ATOMS
//!   E4  ATOMS_R_ARI_R_R group '64,CAS' (1 anchor + bit74 sibling proof)
//!   E5  zombie rebuild from anchors
//!
//! Graft/twin controls are in t143_5: the exact pre-fix byte pattern of
//! the R258 class only differs in field width, not in match masks (bit32
//! is variable in the row vmask), so post-fix decode must keep routing
//! while printing the true base register.

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

fn w(lo: u64, hi: u64) -> u128 { lo as u128 | ((hi as u128) << 64) }

#[test]
fn t143_1_inc_r258_fixed_and_roundtrips() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // vendor witnesses (pre-fix printed desc[..][R258.64])
    let cases = [
        ("ATOMG.E.INC.STRONG.GPU PT, R2, desc[UR14][R2.64], R5",
         w(0x80000005020279a8, 0x001f2400099ef10e)),
        ("ATOMG.E.INC.STRONG.GPU PT, R3, desc[UR4][R2.64], R7",
         w(0x80000007020379a8, 0x001eac00099ef104)),
    ];
    for (text, word) in cases {
        let d = dec(&t, &idx, word);
        assert_eq!(d, text, "decode render must match nvdisasm spelling");
        assert_eq!(enc(&t, text), word & !SCHED, "encode payload must equal vendor word");
    }
}

#[test]
fn t143_2_popc_urz_sentinel_render_and_encode() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // URZ sentinel is 0xFF in this family (127 unique vendor words).
    let cases = [
        ("ATOMS.POPC.INC.32 RZ, [R0+URZ+0x121c]",
         w(0x00121c0000ff7f8c, 0x0001e4000d8000ff)),
        ("ATOMS.POPC.INC.32 RZ, [R11+URZ]",
         w(0x000000000bff7f8c, 0x0003e2000d8000ff)),
        ("ATOMS.POPC.INC.32 RZ, [R2+URZ+0x1a3c]",
         w(0x001a3c0002ff7f8c, 0x0005e4000d8000ff)),
    ];
    // nvdisasm prints "ATOMS.POPC.INC.32", cubit sorts mods ("ATOMS.INC.POPC.32")
    // — known mod-order print dialect (same class as 142's FTZ-first); compare
    // as modifier sets, keep vendor spelling as the documented reference.
    fn semantic(t: &str) -> (String, Vec<String>, String) {
        let (op, rest) = t.split_once(' ').unwrap();
        let mut it = op.split('.');
        let base = it.next().unwrap().to_string();
        (base, it.map(|m| m.to_string()).collect(), rest.to_string())
    }
    for (text, word) in cases {
        let d = dec(&t, &idx, word);
        let (b1, mut m1, r1) = semantic(&d);
        let (b2, mut m2, r2) = semantic(text);
        m1.sort(); m2.sort();
        assert_eq!((b1, m1, r1), (b2, m2, r2), "semantics must match vendor, got {d}");
        assert_eq!(enc(&t, text), word & !SCHED);
    }
    // the plain 2-term spelling encodes to the identical URZ-sentinel payload
    // (parser maps URZ in an address bracket to ur_reg 0xFF; op_sub_ureg
    // default for an absent UR is also 0xFF)
    let full = enc(&t, "ATOMS.POPC.INC.32 RZ, [R0+URZ+0x44]");
    let short = enc(&t, "ATOMS.POPC.INC.32 RZ, [R0+0x44]");
    assert_eq!(full, short, "both spellings carry 0xFF in the UR window");
    let back = dec(&t, &idx, full);
    assert!(back.contains("+URZ+"), "render must carry the URZ token, got: {back}");
}

#[test]
fn t143_3_popc_auri_lone_witness() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // 1-witness form: nvdisasm prints "[UR4+0xc]"; our render keeps the
    // base sentinel explicit ("[RZ+UR4+0xc]"). Encode is byte-exact.
    let word = w(0x00000c00ffff7f8c, 0x000fe8000d800004);
    let text = "ATOMS.POPC.INC.32 RZ, [UR4+0xc]";
    let d = dec(&t, &idx, word);
    assert!(d.contains("+UR4+"), "UR must survive decode, got: {d}");
    assert!(!d.contains("!rsd"), "residual-marker junk render is gone, got: {d}");
    assert_eq!(enc(&t, text), word & !SCHED, "encode byte-exact (payload)");
}

#[test]
fn t143_4_atoms_cas64() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // 1 vendor witness (sm_120a golden) + structural proof via the
    // CAST,SPIN / 64,CAST,SPIN sibling pair (constant-zone delta == bit74).
    let text = "ATOMS.CAS.64 R2, [R7+0x10], R8, R10";
    let word = w(0x000010080702738d, 0x000e22000000040a);
    let d = dec(&t, &idx, word);
    assert_eq!(d, text, "no more ATOMS.CAS + !rsd[74:1], got: {d}");
    assert_eq!(enc(&t, text), word & !SCHED);
    // the non-64 sibling keeps matching its own witness (regression twin)
    let d0 = dec(&t, &idx, w(0x000004060000738d, 0x000e240000000007));
    assert!(d0.starts_with("ATOMS.CAS "), "plain CAS twin unaffected, got: {d0}");
}

#[test]
fn t143_5_redg64_zombie_encode_and_graft_controls() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // pre-fix silent wrong-code repro: UR10 got dropped, UR6 baked, render UR2.
    let word = w(0x000008040200798e, 0x000fe2000c12e50a);
    let text = "REDG.E.ADD.64.STRONG.GPU desc[UR10][R2.64+0x8], R4";
    assert_eq!(dec(&t, &idx, word), text);
    assert_eq!(enc(&t, text), word & !SCHED);
    // the harvest-era pair (R==UR==6) that taught the zombie row still works
    let w0 = w(0x000008080600798e, 0x000fe2000c12e506);
    assert_eq!(dec(&t, &idx, w0), "REDG.E.ADD.64.STRONG.GPU desc[UR6][R6.64+0x8], R8");
    // graft: take the INC witness and force the address-base 9th bit round-trip
    // at the data-LSB positions: base stays R2 (never R258) while data flips even/odd
    let base = w(0x80000005020279a8, 0x001f2400099ef10e);
    let even = (base & !(0xFFu128 << 32)) | (4u128 << 32);
    let d1 = dec(&t, &idx, even);
    assert!(d1.contains("desc[UR14][R2.64]"), "bit32=0: base R2, got {d1}");
    assert!(d1.ends_with("R4"), "data R4, got {d1}");
    let odd = (base & !(0xFFu128 << 32)) | (7u128 << 32);
    let d2 = dec(&t, &idx, odd);
    assert!(d2.contains("desc[UR14][R2.64]"), "bit32=1 must not hallucinate R258, got {d2}");
    assert!(d2.ends_with("R7"), "data R7, got {d2}");
}

#[test]
fn t143_6_parked_classes_stay_fail_closed() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // BUG-142 parking parity: single-witness no-canon classes must NOT be
    // absorbed (fail-closed decode). Compose-wave 2026-08-26 note: BUG-195
    // and BUG-206 (same stack) un-parked ADD.SM / CAS.SM / EXCH.SYS and
    // XOR.GPU respectively; see below.
    // BUG-206 (F2-iter99): the @P0 REDG.E.XOR.STRONG.GPU word is UN-parked —
    // probe206d (nvcc/ptxas+nvdisasm 13.3.73, x3 arch payload arch-eq) delivered
    // the canon witness verbatim (rx_xor_b32/rg_xor_b32) and arb206 in-place
    // scope flips confirm the GPU/SM/SYS law; exact pins in bug206_redg_scope.rs
    // (t206_1/t206_2). Assert the vendor-exact render:
    let wxor = w(0x000000050200098e, 0x004fe2000f92e106);
    let dx = idx.decode(wxor, 0, &t).expect("un-parked XOR.GPU must decode");
    assert_eq!(cubit::printer::to_sass(&dx),
               "@P0 REDG.E.XOR.STRONG.GPU desc[UR6][R2.64], R5");
    let parked = [
        // BUG-195 (F2-iter94): REDG SM / ATOMG CAS.SM / ATOMG EXCH.SYS are
        // UN-parked with full vendor canon (nvcc 13.3.73 fresh witnesses,
        // arch-eq sm_120a==sm_103a==sm_100a, scope law [77:81) arb195) — exact
        // decode/encode pins live in bug195_atom_scope_width.rs. The classes
        // below stay parked (still no canon):
        w(0x00001c00ff00798c, 0x000e24000c000004), // ATOMS.EXCH [UR4+0x1c]
    ];
    for word in parked {
        assert!(idx.decode(word, 0, &t).is_err(),
                "parked word must stay fail-closed: {word:032x}");
    }
}
