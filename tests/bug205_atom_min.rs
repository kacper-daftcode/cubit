//! BUG-205 (iter97, front MAIN, 2026-08-27): generic-address ATOM MIN lane.
//! patch205.py (data-only, 12 rows x3 tables) — ATOM_P_R_dARI_R had ZERO MIN
//! rows (flips199 had no donor; probing per 203 methodology). Witnesses:
//! nvcc/ptxas+nvdisasm 13.3.73 probe205a.cu on sm_100a/103a/120a (inline-PTX
//! generic atom.relaxed.{gpu,cta,sys}.min.{u32,s32,u64,s64} + opaque-pointer
//! CUDA intrinsics; payload arch-eq). Law re-derived in-place (arb205.json):
//! OP [87:91) MIN=4 (b87=ADD b88=INC b89=AND b90=INVALID9), SCOPE [77:81),
//! WIDTH [74:73), b76=address-form (desc<->[R.64+UR], NOT width for int).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| cubit::printer::to_sass(&d))
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

const T103: &str = "tables/sm103a.json";
const T120: &str = "tables/sm120.json";
const T100: &str = "tables/sm100a.json";
const TABS: &[&str] = &[T103, T120, T100];

/// The 12 witnessed (glyph, word) pairs — probe205a, all three arches
/// (payload arch-eq; per-kernel sources in work/i97/probe/probe205.tsv).
const WIT_MIN: &[(&str, u64, u64)] = &[
    ("ATOM.E.MIN.S32.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x800000070203798au64, 0x001eac00089f5304u64),
    ("ATOM.E.MIN.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x800000070203798au64, 0x001eac00089eb104u64),
    ("ATOM.E.MIN.S64.STRONG.GPU P0, R4, desc[UR4][R2.64], R4", 0x800000040204798au64, 0x001162000890f704u64),
    ("ATOM.E.MIN.64.STRONG.GPU P0, R4, desc[UR4][R2.64], R4", 0x800000040204798au64, 0x001162000890f504u64),
    ("ATOM.E.MIN.S32.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x800000070203798au64, 0x001eac00089ef304u64),
    ("ATOM.E.MIN.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x800000070203798au64, 0x001eac00089ef104u64),
    ("ATOM.E.MIN.S64.STRONG.SYS P0, R4, desc[UR4][R2.64], R4", 0x800000040204798au64, 0x0011620008915704u64),
    ("ATOM.E.MIN.64.STRONG.SYS P0, R4, desc[UR4][R2.64], R4", 0x800000040204798au64, 0x0011620008915504u64),
    ("ATOM.E.MIN.STRONG.SYS PT, R3, desc[UR4][R2.64], R7", 0x800000070203798au64, 0x001eac00089f5104u64),
    ("ATOM.E.MIN.S64.STRONG.SM P0, R4, desc[UR4][R2.64], R4", 0x800000040204798au64, 0x001162000890b704u64),
    ("ATOM.E.MIN.64.STRONG.SM P0, R4, desc[UR4][R2.64], R4", 0x800000040204798au64, 0x001162000890b504u64),
    ("ATOM.E.MIN.S32.STRONG.SM PT, R3, desc[UR4][R2.64], R7", 0x800000070203798au64, 0x001eac00089eb304u64),
];

/// Retention anchors (corpus, atomdb199): ATOMG/ATOMS MIN lanes untouched.
const RET_MIN: &[(&str, u64, u64)] = &[
    ("@P0 ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR10][R2.64], R5", 0x8000000502ff09a8u64, 0x00156400089ef30au64),
    ("@P0 ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR10][R2.64], R5", 0x8000000502ff09a8u64, 0x001fe200089ef30au64),
    ("@P0 ATOMG.E.MIN.S32.STRONG.GPU PT, RZ, desc[UR10][R2.64], R5", 0x8000000502ff09a8u64, 0x00436400089ef30au64),
];

/// t205_1: every witnessed generic MIN word decodes to its exact vendor glyph
/// on all three tables (pre-fix: 36/36 fail-closed HOLE).
#[test]
fn t205_1_atom_min_decode() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in WIT_MIN {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} MIN {g}");
        }
    }
}

/// t205_2: authored vendor text encodes back to the witnessed payload
/// (upper32 sched masked, per cubit encode contract).
#[test]
fn t205_2_atom_min_encode() {
    for tp in TABS {
        let t = tab(tp);
        for (g, lo, hi) in WIT_MIN {
            assert_eq!(enc(&t, g), word(*lo, *hi) & !SCHED, "{tp} MIN {g}");
        }
    }
}

/// t205_3: retention — corpus ATOMG MIN anchors decode unchanged.
#[test]
fn t205_3_atomg_min_retention() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in RET_MIN {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} RET {g}");
        }
    }
}

/// t205_4: fail-closed negatives — ops/classes with no witness stay rejected.
#[test]
fn t205_4_fail_closed_negatives() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        // SAFEADD = INVALID9 on the ATOM lane (arb205 b90 walk): no glyph, no row
        let safeadd = word(0x800000070203798au64, 0x001eac00089ef104u64 ^ (1u64 << (90 - 64)));
        assert_ne!(dec(&t, &idx, safeadd).as_deref(),
                   Some("ATOM.E.MIN.STRONG.GPU PT, R3, desc[UR4][R2.64], R7"), "{tp} b90");
        // encode-side: INVALID9/SAFEADD family unwitnessed -> refuse
        let insn = parse_sass("ATOM.E.SAFEADD.STRONG.GPU PT, R3, desc[UR4][R2.64], R7 ;", 0);
        let enc_err = insn.map(|i| encode_instruction(&i, &t).is_err()).unwrap_or(true);
        assert!(enc_err, "{tp} SAFEADD encode must fail");
        // no float MIN exists (only F16x2-ADD-class vector forms are legal)
        let insn = parse_sass("ATOM.E.MIN.F32.STRONG.GPU PT, R3, desc[UR4][R2.64], R7 ;", 0);
        let enc_err = insn.map(|i| encode_instruction(&i, &t).is_err()).unwrap_or(true);
        assert!(enc_err, "{tp} MIN.F32 encode must fail");
    }
}
