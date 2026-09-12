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
    (
        0x000824000850e1ccfe00000e04c8797eu128,
        0x0180,
        "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, [R4.U32+UR14]",
    ), // healed 447
    (
        0x000824000850e0387e00000c0334797eu128,
        0x0570,
        "LDG.E.NA.EFL2.256.STRONG.GPU R56, R52, [R3.U32+UR12], 0x3f",
    ), // healed 447
    (
        0x000824000850e0407e00000c043c797eu128,
        0x0590,
        "LDG.E.NA.EFL2.256.STRONG.GPU R64, R60, [R4.U32+UR12], 0x3f",
    ), // healed 447
    (
        0x000824000850e120fe000006181c797eu128,
        0x0260,
        "LDG.E.NA.EFL2.256.STRONG.GPU R32, R28, [R24.U32+UR6]",
    ), // healed 447
    // BRA-plain era: targets = dword-split (verified vs sm120-table renders)
    (
        0x000fc2000383fffffffffffd00e08947u128,
        0x01e0,
        "@!P0 BRA 0x170",
    ),
    (0x000fc2000383ffffffffffd100247947u128, 0x3920, "BRA 0x9c0"),
    (0x000fc2000383ffffffffffbd008c7947u128, 0x5fc0, "BRA 0x1e00"),
    (
        0x000fe200038000000000008300e80947u128,
        0x0210,
        "@P0 BRA 0x85c0",
    ),
    (0x000fe2000383ffffffffffe900187947u128, 0x7830, "BRA 0x60a0"),
    (0x010fe2000383ffffffffffbd00a07947u128, 0xc750, "BRA 0x85e0"),
    // BRXU 1-token era: both dispatch to 0xc850
    (
        0x000fe2000b80000000000050ff087958u128,
        0x7820,
        "BRXU 0xc850",
    ),
    (
        0x000fe2000b80000000000028ffdc7958u128,
        0x9cd0,
        "BRXU 0xc850",
    ),
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
                    fails.push(format!(
                        "word {word:032x}@{addr:04x}: render {text:?} != {golden:?}"
                    ));
                }
            }
            Err(e) => fails.push(format!("word {word:032x}@{addr:04x}: decode fail: {e}")),
        }
    }
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn b4fill3_brxu_reencode_byte_exact() {
    // era-grounded BRXU_II and_base: canonical text -> exact era bytes
    // (modulo sched bits, which the file pipeline regenerates via @sched).
    let t = t103a();
    for &(word, addr, golden) in &GOLD[..] {
        if !golden.starts_with("BRXU ") {
            continue;
        }
        let insn = parse_sass(&format!("{golden} ;"), addr).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(
            w2 & !SCHED,
            word & !SCHED,
            "BRXU encode {w2:032x} != era {word:032x}"
        );
    }
}

#[test]
fn b4fill3_bra_target_region_exact() {
    // encode of the canonical BRA text reproduces the era dword-split target
    // region exactly; bits [33:32] are era-carry (rsd at file level).
    let t = t103a();
    let tgtmask: u128 = ((0xFFu128 << 16) | (0xFFFF_FFFFu128 << 32)) & !(0b11u128 << 32);
    for &(word, addr, golden) in &GOLD[..] {
        if !golden.contains("BRA ") {
            continue;
        }
        let insn = parse_sass(&format!("{golden} ;"), addr).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(
            w2 & tgtmask,
            word & tgtmask,
            "BRA target region {w2:032x} vs era {word:032x} at {addr:04x}"
        );
    }
}

#[test]
fn b4fill3_efl2_parity_guard() {
    let t = t103a();
    // odd Rn (R3): the HINT gold word w2 encodes from canonical text; compare
    // the row-owned region (fields + and_base constants minus sched).
    let w2gold = 0x000824000850e0387e00000c0334797eu128;
    let insn = parse_sass(
        "LDG.E.NA.EFL2.256.STRONG.GPU R56, R52, [R3.U32+UR12], 0x3f ;",
        0x570,
    )
    .unwrap();
    let w2 = encode_instruction(&insn, &t).unwrap();
    // healed 447: plain donor key; era gold ma hint-bake (dead b72) --
    // compare z tolerancja dead-set {72,73,87} (gen447pins DEADNORM).
    let dead: u128 = (1u128 << 72) | (1u128 << 73) | (1u128 << 87);
    assert_eq!(
        (w2 ^ w2gold) & !SCHED & !dead,
        0,
        "EFL2.256 plain odd-addr encode vs era gold"
    );
    // even Rn (R4/R24 era slots): fail closed with the BUG-060 citation
    // healed 447 (F2-iter252): desc spelling ponizej = era-dead (parse/lookup err,
    // osobny assert nizej); guard silicon zostaje na PLAIN formie (keeper arm
    // BUG-060 w encoder.rs; even base R-FAIL z cytatem).
    for bad in [
        "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, [R4.U32+UR14]",
        "LDG.E.NA.EFL2.256.STRONG.GPU R64, R60, [R4.U32+UR12], 0x3f",
        "LDG.E.NA.EFL2.256.STRONG.GPU R32, R28, [R24.U32+UR6]",
    ] {
        let insn = parse_sass(&format!("{bad} ;"), 0x180).unwrap();
        let err = encode_instruction(&insn, &t).unwrap_err();
        assert!(
            format!("{err}").contains("BUG-060"),
            "missing BUG-060 in: {err}"
        );
    }
    for dead in [
        "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, desc[UR14][R4.64]",
        "LDG.E.NA.EFL2.256.STRONG.GPU.HINT R64, R60, desc[UR12][R4.64]",
    ] {
        assert!(
            parse_sass(&format!("{dead} ;"), 0x180)
                .and_then(|i| encode_instruction(&i, &t))
                .is_err(),
            "era desc spelling must be dead post-447: {dead}"
        );
    }
    // escape hatch exists for RE tooling (probe assembly); byte-mapping
    // rownowazna ze zlotem era (0180) modulo dead-set (healed 447).
    std::env::set_var("CUBIT_DISABLE_ERRATA", "1");
    let insn = parse_sass(
        "LDG.E.NA.EFL2.256.STRONG.GPU R204, R200, [R4.U32+UR14] ;",
        0x180,
    )
    .unwrap();
    let w3 = encode_instruction(&insn, &t).expect("hatch encode");
    std::env::remove_var("CUBIT_DISABLE_ERRATA");
    let dead: u128 = (1u128 << 72) | (1u128 << 73) | (1u128 << 87);
    assert_eq!(
        (w3 ^ 0x000824000850e1ccfe00000e04c8797eu128) & !SCHED & !dead,
        0,
        "hatch byte-map vs era gold 0180"
    );
}

#[test]
fn b4fill3_efl2_cross_matrix() {
    // membership matrix: no cross-matching inside the ELL2/EFL2 family
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // healed 447 (graft 099faa0): era LDG_R_R_dARI NA/HINT mgs usuniete;
    // wszystkie 4 slowa routuja do donor-klucza 121a ARURI. HINT-era bake
    // renderowany jako policy-imm ', 0x3f' (teksty pinowane w GOLD wyzej).
    // klucze weryfikowane maszynowo na keep.so post-447 (flip447c):
    let cases = [
        (
            0x000824000850e1ccfe00000e04c8797eu128,
            "LDG.E.NA.EFL2.256.STRONG.GPU_R_R_ARURI",
        ),
        (
            0x000824000850e0387e00000c0334797eu128,
            "LDG.E.NA.EFL2.256.STRONG.GPU_R_R_ARURI_II",
        ),
        (
            0x000824000850e0407e00000c043c797eu128,
            "LDG.E.NA.EFL2.256.STRONG.GPU_R_R_ARURI_II",
        ),
        (
            0x000824000850e120fe000006181c797eu128,
            "LDG.E.NA.EFL2.256.STRONG.GPU_R_R_ARURI",
        ),
    ];
    for (w, key) in cases {
        let d = idx.decode(w, 0, &t).unwrap();
        assert_eq!(d.key, key, "word {w:032x} routed to {}", d.key);
    }
}
