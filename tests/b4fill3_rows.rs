//! b4forward3: closure of the final `/* ? */`
//! passthrough residuum on tables/sm103a.json (23 slots of the certified rt98
//! gold -- M4.8 sm103 A/B hygiene; parked list from B4FILL2 + BUG-060 guard):
//!
//! * BRA-plain era x17 (0x...947): the shared BRA_II "" row fixed bit32=0,
//!   but the dword-split branch-target layout (lo8@[23:16], hi30@[63:32]>>2;
//!   same code path as BUG-027/BRXU) DISCARDS bits [33:32] -- era words carry
//!   them set. Widened variable_mask by [33:32]; all 17 predicted targets
//!   in-range/16-aligned, 5 vendor-known targets reproduced exactly.
//! * LDG.E.NA.EFL2.256[.HINT].STRONG.GPU desc-form x4 (0x...97e): two new mod
//!   groups under LDG_R_R_dARI cloned from the ELL2 sibling geometry
//!   (guard/reg@16/reg@64/r1@24/ur0@32/imm20@37); HINT = bit63=0 + bit72=0 +
//!   hint-val 0x3f@[62:57] baked (n=2; fresh hint values render fall back to
//!   '?' -- fail-closed, no fabricated generality). Trailing era imm token
//!   (", 0x3f"/", 0x0") is not text-carried (render-parity drop, documented in
//!   the report; roundtrip byte-exactness proven by the full-file gate).
//! * Encoder parity guard (BUG-060, krun 7/7): the EFL2.256 desc form needs an
//!   ODD Rn on sm_103a silicon; even Rn traps CUDA_ERROR_ILLEGAL_INSTRUCTION.
//!   Encoder fails closed (scoped target_sm()==103); decode stays full.
//! * BRXU 1-token era x2 (0x...958): BRXU_L ported from tables/sm120.json for
//!   decode (both words -> dispatch target 0xc850, dword-split verified); the
//!   encoder lookup key BRXU_II got an era-grounded and_base (AND of the two
//!   gold words; target regions + sched-hi in variable_mask) so the canonical
//!   one-operand form re-encodes byte-exact natively (BUG-027 fixup shadows
//!   the stale harvest imm field). Silicon legality of this era class on
//!   sm_103a is NOT probed -- krun-audit queue (BUG-060 follow-up list).
//! Provenance: the internal research tree (measurement + gates).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

/// (gold word, addr, canonical render)
static GOLD: &[(u128, u32, &str)] = &[
    // LDG.E.NA.EFL2.256[.HINT] desc-form (vendor renders from BUG-060 report)
    (0x000824000850e1ccfe00000e04c8797eu128, 0x0180, "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, desc[UR14][R4.64]"),
    (0x000824000850e0387e00000c0334797eu128, 0x0570, "LDG.E.NA.EFL2.256.STRONG.GPU.HINT R56, R52, desc[UR12][R3.64]"),
    (0x000824000850e0407e00000c043c797eu128, 0x0590, "LDG.E.NA.EFL2.256.STRONG.GPU.HINT R64, R60, desc[UR12][R4.64]"),
    (0x000824000850e120fe000006181c797eu128, 0x0260, "LDG.E.NA.EFL2.256.STRONG.GPU R32, R28, desc[UR6][R24.64]"),
    // BRA-plain era: targets = dword-split (verified vs sm120-table renders)
    (0x000fc2000383fffffffffffd00e08947u128, 0x01e0, "@!P0 BRA 0x170"),
    (0x000fc2000383ffffffffffd100247947u128, 0x3920, "BRA 0x9c0"),
    (0x000fc2000383ffffffffffbd008c7947u128, 0x5fc0, "BRA 0x1e00"),
    (0x000fe200038000000000008300e80947u128, 0x0210, "@P0 BRA 0x85c0"),
    (0x000fe2000383ffffffffffe900187947u128, 0x7830, "BRA 0x60a0"),
    (0x010fe2000383ffffffffffbd00a07947u128, 0xc750, "BRA 0x85e0"),
    // BRXU 1-token era: both dispatch to 0xc850
    (0x000fe2000b80000000000050ff087958u128, 0x7820, "BRXU 0xc850"),
    (0x000fe2000b80000000000028ffdc7958u128, 0x9cd0, "BRXU 0xc850"),
];

#[test]
fn b4fill3_decode_render() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let mut fails = Vec::new();
    for &(word, addr, golden) in GOLD {
        match idx.decode(word, addr, &t) {
            Ok(d) => {
                let text = cubit::printer::to_sass(&d);
                if text != golden {
                    fails.push(format!("word {word:032x}@{addr:04x}: render {text:?} != {golden:?}"));
                }
            }
            Err(e) => fails.push(format!("word {word:032x}@{addr:04x}: decode fail: {e}")),
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn b4fill3_brxu_reencode_byte_exact() {
    // era-grounded BRXU_II and_base: canonical text -> exact era bytes
    // (modulo sched bits, which the file pipeline regenerates via @sched).
    let t = t103a();
    for &(word, addr, golden) in &GOLD[..] {
        if !golden.starts_with("BRXU ") { continue; }
        let insn = parse_sass(&format!("{golden} ;"), addr).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & !SCHED, word & !SCHED,
            "BRXU encode {w2:032x} != era {word:032x}");
    }
}

#[test]
fn b4fill3_bra_target_region_exact() {
    // encode of the canonical BRA text reproduces the era dword-split target
    // region exactly; bits [33:32] are era-carry (rsd at file level).
    let t = t103a();
    let tgtmask: u128 = ((0xFFu128 << 16) | (0xFFFF_FFFFu128 << 32)) & !(0b11u128 << 32);
    for &(word, addr, golden) in &GOLD[..] {
        if !golden.contains("BRA ") { continue; }
        let insn = parse_sass(&format!("{golden} ;"), addr).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & tgtmask, word & tgtmask,
            "BRA target region {w2:032x} vs era {word:032x} at {addr:04x}");
    }
}

#[test]
fn b4fill3_efl2_parity_guard() {
    let t = t103a();
    // odd Rn (R3): the HINT gold word w2 encodes from canonical text; compare
    // the row-owned region (fields + and_base constants minus sched).
    let w2gold = 0x000824000850e0387e00000c0334797eu128;
    let insn = parse_sass(
        "LDG.E.NA.EFL2.HINT.256.STRONG.GPU R56, R52, desc[UR12][R3.64] ;", 0x570).unwrap();
    let w2 = encode_instruction(&insn, &t).unwrap();
    assert_eq!(w2 & !SCHED, w2gold & !SCHED, "EFL2.256 HINT odd-addr encode");
    // even Rn (R4/R24 era slots): fail closed with the BUG-060 citation
    for bad in [
        "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, desc[UR14][R4.64]",
        "LDG.E.NA.EFL2.256.STRONG.GPU.HINT R64, R60, desc[UR12][R4.64]",
        "LDG.E.NA.EFL2.256.STRONG.GPU R32, R28, desc[UR6][R24.64]",
    ] {
        let insn = parse_sass(&format!("{bad} ;"), 0x180).unwrap();
        let err = encode_instruction(&insn, &t).unwrap_err();
        assert!(format!("{err}").contains("BUG-060"), "missing BUG-060 in: {err}");
    }
    // escape hatch exists for RE tooling (probe assembly)
    std::env::set_var("CUBIT_DISABLE_ERRATA", "1");
    let insn = parse_sass(
        "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, desc[UR14][R4.64] ;", 0x180).unwrap();
    assert!(encode_instruction(&insn, &t).is_ok());
    std::env::remove_var("CUBIT_DISABLE_ERRATA");
}

#[test]
fn b4fill3_efl2_cross_matrix() {
    // membership matrix: no cross-matching inside the ELL2/EFL2 family
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let cases = [
        (0x000824000850e1ccfe00000e04c8797eu128, "256,E,EFL2,GPU,NA,STRONG"),
        (0x000824000850e0387e00000c0334797eu128, "256,E,EFL2,GPU,HINT,NA,STRONG"),
        (0x000824000850e0407e00000c043c797eu128, "256,E,EFL2,GPU,HINT,NA,STRONG"),
        (0x000824000850e120fe000006181c797eu128, "256,E,EFL2,GPU,NA,STRONG"),
    ];
    for (w, mg) in cases {
        let d = idx.decode(w, 0, &t).unwrap();
        assert_eq!(d.key, "LDG_R_R_dARI");
        assert_eq!(d.mod_group, mg, "word {w:032x} routed to {}", d.mod_group);
    }
}
