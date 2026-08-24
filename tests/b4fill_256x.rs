//! b4fill: sm_103a table-fill of the M4.7/G16e
//! mulmod-shape lock + adjacent LDG/STG.256-desc family. Rows derived from
//! (a) native ptxas-13.3 sm_103a probes (mulacc/mulcc IMAD.WIDE.U32.X Cout/Cin,
//! ldg256* ENL2.256 EL/NA/STRONG/CONSTANT, stg256 siblings),
//! (b) rt98 (sm_120 hop-kernel mkvar88-class words, silicon-proven on 5090),
//! cross-decoded natively by nvdisasm-13.3 under an sm_103 ELF shell,
//! and (c) sm103 corpus IMAD.WIDE.U32.X II forms. Field windows per-token
//! brute-force multi-sample fit; statics cross-origin compared (payload
//! drift zero on IMAD R_P_R_R_R_P). Gate: decode renders EXACT canonical
//! text; re-encode byte-exact modulo scheduler top dword [127:96].
//! Provenance: the internal research tree (battery + derivation).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

static GOLD: &[(u128, &str)] = &[
    (0x008fca0000000404000000130c047225u128, "IMAD.WIDE.U32.X R4, P0, R12, R19, R4, P0"),
    (0x010fca00000004080000000f0c1a7225u128, "IMAD.WIDE.U32.X R26, P0, R12, R15, R8, P0"),
    (0x020fc800000004080000000d0c087225u128, "IMAD.WIDE.U32.X R8, P0, R12, R13, R8, P0"),
    (0x000fe200000004040000001706047225u128, "IMAD.WIDE.U32.X R4, P0, R6, R23, R4, P0"),
    (0x000fe400020e04ff000000781c407225u128, "IMAD.WIDE.U32.X R64, R28, R120, RZ, P4"),
    (0x000fe400020e04ff0000007a1c427225u128, "IMAD.WIDE.U32.X R66, R28, R122, RZ, P4"),
    (0x000fe400020e04ff0000007b1d607225u128, "IMAD.WIDE.U32.X R96, R29, R123, RZ, P4"),
    (0x080fe20001040462000003d1635a7825u128, "IMAD.WIDE.U32.X R90, P2, R99, 0x3d1, R98, P2"),
    (0x080fe20001040464000003d165587825u128, "IMAD.WIDE.U32.X R88, P2, R101, 0x3d1, R100, P2"),
    (0x080fe20001040466000003d167567825u128, "IMAD.WIDE.U32.X R86, P2, R103, 0x3d1, R102, P2"),
    (0x080fe20007840460000003d161567825u128, "IMAD.WIDE.U32.X.B90 R86, P2, R97, 0x3d1, R96, PT"),
    (0x080fe2000786043c000003d15c3c7825u128, "IMAD.WIDE.U32.X.B90 R60, P3, R92, 0x3d1, R60, PT"),
    (0x080fe40007860400000003d15c007825u128, "IMAD.WIDE.U32.X.B90 R0, P3, R92, 0x3d1, R0, PT"),
    (0x000e24000824e110fe112014410c197eu128, "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, desc[UR20][R65.64+0x22400]"),
    (0x000e26000824e188fe1120141a84797eu128, "LDG.E.EL.ELL2.256.STRONG.GPU R136, R132, desc[UR20][R26.64+0x22400]"),
    (0x000e26000824e190fe1121141a8c797eu128, "LDG.E.EL.ELL2.256.STRONG.GPU R144, R140, desc[UR20][R26.64+0x22420]"),
    (0x000e66000824e198fe1122141a94797eu128, "LDG.E.EL.ELL2.256.STRONG.GPU R152, R148, desc[UR20][R26.64+0x22440]"),
    (0x000824000824e130fe000004182c697eu128, "@P6 LDG.E.EL.ELL2.256.STRONG.GPU R48, R44, desc[UR4][R24.64]"),
    (0x000a64000824e150fe000004184c697eu128, "@P6 LDG.E.EL.ELL2.256.STRONG.GPU R80, R76, desc[UR4][R24.64]"),
    (0x000a62000824e150fe000004184c397eu128, "@P3 LDG.E.EL.ELL2.256.STRONG.GPU R80, R76, desc[UR4][R24.64]"),
    (0x000824000854e198fe0000041894797eu128, "LDG.E.NA.ELL2.256.STRONG.GPU R152, R148, desc[UR4][R24.64]"),
    (0x000824000854e1a0fe000004189c797eu128, "LDG.E.NA.ELL2.256.STRONG.GPU R160, R156, desc[UR4][R24.64]"),
    (0x0009e4000f24e014f81120004104197fu128, "@P1 STG.E.EL.ELL2.256.STRONG.GPU desc[UR20][R65.64+0x22400], R0, R4"),
    (0x0009e4000f24e014f83120bc1ac0797fu128, "STG.E.EL.ELL2.256.STRONG.GPU desc[UR20][R26.64+0x62400], R188, R192"),
    (0x0009e4000f24e014f83121c41ac8797fu128, "STG.E.EL.ELL2.256.STRONG.GPU desc[UR20][R26.64+0x62420], R196, R200"),
    (0x0009e4000f54e004f80000941898797fu128, "STG.E.NA.ELL2.256.STRONG.GPU desc[UR4][R24.64], R148, R152"),
    (0x0009e4000f54e004f800009c18a0797fu128, "STG.E.NA.ELL2.256.STRONG.GPU desc[UR4][R24.64], R156, R160"),
    (0x000be4000f50e026f800002c1c30197fu128, "@P1 STG.E.NA.EFL2.256.STRONG.GPU desc[UR38][R28.64], R44, R48"),
    (0x000be4000f50e026f80000341d38197fu128, "@P1 STG.E.NA.EFL2.256.STRONG.GPU desc[UR38][R29.64], R52, R56"),
    (0x001ea2000812190cfe0000040208797eu128, "LDG.E.ENL2.256 R12, R8, desc[UR4][R2.64]"),
    (0x001ea2000812990cfe0000040208797eu128, "LDG.E.ENL2.256.CONSTANT R12, R8, desc[UR4][R2.64]"),
    (0x001eaa000812f90cfe0000040208797eu128, "LDG.E.ENL2.256.STRONG.GPU R12, R8, desc[UR4][R2.64]"),
    (0x001ea2000852f90cfe0000040208797eu128, "LDG.E.NA.ENL2.256.STRONG.GPU R12, R8, desc[UR4][R2.64]"),
    (0x001ea2000822f90cfe0000040208797eu128, "LDG.E.EL.ENL2.256.STRONG.GPU R12, R8, desc[UR4][R2.64]"),
];

#[test]
fn b4fill_decode_render_reencode_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let mut fails = Vec::new();
    for &(word, golden) in GOLD {
        let d = match idx.decode(word, 0, &t) {
            Ok(d) => d,
            Err(e) => { fails.push(format!("word {word:032x}: decode fail: {e}")); continue; }
        };
        let text = cubit::printer::to_sass(&d);
        if text != golden {
            fails.push(format!("word {word:032x}: render {text:?} != golden {golden:?}"));
            continue;
        }
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        if (w2 & !SCHED) != (word & !SCHED) {
            fails.push(format!("re-encode diff {w2:032x} vs {word:032x}"));
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails[..5].join("\n"));
}

#[test]
fn b4fill_b90_implies_pt_carry_in() {
    // .B90 = hardware marker for Cin==PT on the II carry form (bit90 set);
    // plain .X text with PT Cin must not set bit90, and B90 text must set it.
    let t = t103a();
    let plain = parse_sass("IMAD.WIDE.U32.X R194, P2, R203, 0x3d1, R202, P2 ;", 0).unwrap();
    let w_plain = encode_instruction(&plain, &t).unwrap();
    assert_eq!((w_plain >> 90) & 1, 0);
    let b90 = parse_sass("IMAD.WIDE.U32.X.B90 R190, P2, R201, 0x3d1, R200, PT ;", 0).unwrap();
    let w_b90 = encode_instruction(&b90, &t).unwrap();
    assert_eq!((w_b90 >> 90) & 1, 1);
}

#[test]
fn b4fill_imm_scaled_shr5_and_preserved() {
    // desc offsets on the 256-desc family are stored off>>5 in [55:40].
    let t = t103a();
    let ldg = parse_sass("LDG.E.EL.ELL2.256.STRONG.GPU R136, R132, desc[UR20][R26.64+0x22400] ;", 0).unwrap();
    let w = encode_instruction(&ldg, &t).unwrap();
    assert_eq!((w >> 40) & 0xffff, 0x1120);
    let stg = parse_sass("STG.E.EL.ELL2.256.STRONG.GPU desc[UR20][R26.64+0x62420], R196, R200 ;", 0).unwrap();
    let w2 = encode_instruction(&stg, &t).unwrap();
    assert_eq!((w2 >> 40) & 0xffff, 0x3121);
}
