//! BUG-206 (F2, 2026-08-27): REDG scope SM/SYS lane closure (witness-first).
//! patch206.py (data-only, 153 rows: 48 SM/SYS scope grafts + MIN/MAX S64 GPU
//! x3 tabs, + per-table singletons E,GPU,STRONG,XOR on sm103a/sm100a and
//! E,GPU,MAX,STRONG on sm120). Witnesses: nvcc/ptxas+nvdisasm 13.3.73
//! probe206{a..d} x3 arch (payload arch-eq). Scoped generic-address red lowers
//! to ATOM-to-RZ + REDUX/CREDUX (not RED) — global-space scoped keeps RED.
//! Law (lawaudit206.json + arb206.json 24/24): SM = ^b78, SYS = ^b77,79,80.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
const T103: &str = "tables/sm103a.json";
const T120: &str = "tables/sm120.json";
const T100: &str = "tables/sm100a.json";
const TABS: &[&str] = &[T103, T120, T100];
fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| cubit::printer::to_sass(&d))
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).ok().map(|w| w & !SCHED)
}

const PROBE_NEW: &[(&str, u64, u64)] = &[
    ("@P0 REDG.E.ADD.64.STRONG.SM desc[UR10][R2.64], R4", 17213426062u64, 22485012990567690u64),
    ("@P0 REDG.E.ADD.64.STRONG.SYS desc[UR10][R2.64], R4", 17213426062u64, 22485012990608650u64),
    ("REDG.E.ADD.BF16x2.RN.STRONG.SM desc[UR4][R2.64], R5", 21508422054u64, 8974214108456708u64),
    ("REDG.E.ADD.BF16x2.RN.STRONG.SYS desc[UR4][R2.64], R5", 21508422054u64, 8974214108497668u64),
    ("REDG.E.ADD.F16x2.RN.STRONG.SM desc[UR4][R2.64], R5", 21508422054u64, 8974214108455172u64),
    ("REDG.E.ADD.F16x2.RN.STRONG.SYS desc[UR4][R2.64], R5", 21508422054u64, 8974214108496132u64),
    ("REDG.E.ADD.F32.FTZ.RN.STRONG.SM desc[UR4][R2.64], R5", 21508422054u64, 8974214108459780u64),
    ("REDG.E.ADD.F32.FTZ.RN.STRONG.SYS desc[UR4][R2.64], R5", 21508422054u64, 8974214108500740u64),
    ("REDG.E.ADD.F32x2.FTZ.RN.STRONG.SM desc[UR4][R2.64], R4", 17213454758u64, 8974214108460292u64),
    ("REDG.E.ADD.F32x2.FTZ.RN.STRONG.SYS desc[UR4][R2.64], R4", 17213454758u64, 8974214108501252u64),
    ("REDG.E.ADD.F32x4.FTZ.RN.STRONG.SM desc[UR4][R2.64], R4", 17213454758u64, 8974214108460804u64),
    ("REDG.E.ADD.F32x4.FTZ.RN.STRONG.SYS desc[UR4][R2.64], R4", 17213454758u64, 8974214108501764u64),
    ("REDG.E.ADD.F64.RN.STRONG.SM desc[UR4][R2.64], R4", 17213454758u64, 8974214108462852u64),
    ("REDG.E.ADD.F64.RN.STRONG.SYS desc[UR4][R2.64], R4", 17213454758u64, 8974214108503812u64),
    ("@P0 REDG.E.ADD.S32.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485012990567174u64),
    ("@P0 REDG.E.ADD.S32.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485012990608134u64),
    ("REDG.E.AND.64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214150399236u64),
    ("REDG.E.AND.64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214150440196u64),
    ("@P0 REDG.E.AND.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485013032509702u64),
    ("@P0 REDG.E.AND.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485013032550662u64),
    ("REDG.E.DEC.STRONG.SM desc[UR4][R2.64], R5", 21508422030u64, 8974214142009604u64),
    ("REDG.E.DEC.STRONG.SYS desc[UR4][R2.64], R5", 21508422030u64, 8974214142050564u64),
    ("REDG.E.INC.STRONG.SM desc[UR4][R2.64], R5", 21508422030u64, 8974214133620996u64),
    ("REDG.E.INC.STRONG.SYS desc[UR4][R2.64], R5", 21508422030u64, 8974214133661956u64),
    ("REDG.E.MAX.64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214125233412u64),
    ("REDG.E.MAX.64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214125274372u64),
    ("@P0 REDG.E.MAX.S32.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485013007344390u64),
    ("@P0 REDG.E.MAX.S32.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485013007385350u64),
    ("REDG.E.MAX.S64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214125250308u64),
    ("REDG.E.MAX.S64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214125233924u64),
    ("REDG.E.MAX.S64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214125274884u64),
    ("@P0 REDG.E.MAX.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485013007343878u64),
    ("@P0 REDG.E.MAX.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485013007384838u64),
    ("REDG.E.MIN.64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214116844804u64),
    ("REDG.E.MIN.64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214116885764u64),
    ("@P0 REDG.E.MIN.S32.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485012998955782u64),
    ("@P0 REDG.E.MIN.S32.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485012998996742u64),
    ("REDG.E.MIN.S64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214116861700u64),
    ("REDG.E.MIN.S64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214116845316u64),
    ("REDG.E.MIN.S64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214116886276u64),
    ("@P0 REDG.E.MIN.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485012998955270u64),
    ("@P0 REDG.E.MIN.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485012998996230u64),
    ("REDG.E.OR.64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214158787844u64),
    ("REDG.E.OR.64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214158828804u64),
    ("@P0 REDG.E.OR.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485013040898310u64),
    ("@P0 REDG.E.OR.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485013040939270u64),
    ("REDG.E.XOR.64.STRONG.SM desc[UR4][R2.64], R4", 17213454734u64, 8974214167176452u64),
    ("REDG.E.XOR.64.STRONG.SYS desc[UR4][R2.64], R4", 17213454734u64, 8974214167217412u64),
    ("@P0 REDG.E.XOR.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485013049303302u64),
    ("@P0 REDG.E.XOR.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485013049286918u64),
    ("@P0 REDG.E.XOR.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485013049327878u64),
];

const PROBE_RETENTION: &[(&str, u64, u64)] = &[
    ("@P0 REDG.E.ADD.64.STRONG.GPU desc[UR10][R2.64], R4", 17213426062u64, 22485012990584074u64),
    ("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR4][R2.64], R5", 21508422054u64, 8974214108476164u64),
    ("REDG.E.ADD.F64.RN.STRONG.GPU desc[UR4][R2.64], R4", 17213454758u64, 8974214108479236u64),
    ("@P0 REDG.E.ADD.S32.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485012990583558u64),
    ("@P0 REDG.E.ADD.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485012990583046u64),
    ("@P0 REDG.E.ADD.STRONG.SM desc[UR6][R2.64], R5", 21508393358u64, 22485012990566662u64),
    ("@P0 REDG.E.ADD.STRONG.SYS desc[UR6][R2.64], R5", 21508393358u64, 22485012990607622u64),
    ("REDG.E.AND.64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214150415620u64),
    ("@P0 REDG.E.AND.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485013032526086u64),
    ("REDG.E.DEC.STRONG.GPU desc[UR4][R2.64], R5", 21508422030u64, 8974214142025988u64),
    ("REDG.E.INC.STRONG.GPU desc[UR4][R2.64], R5", 21508422030u64, 8974214133637380u64),
    ("REDG.E.MAX.64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214125249796u64),
    ("@P0 REDG.E.MAX.S32.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485013007360774u64),
    ("@P0 REDG.E.MAX.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485013007360262u64),
    ("REDG.E.MIN.64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214116861188u64),
    ("@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485012998972166u64),
    ("@P0 REDG.E.MIN.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485012998971654u64),
    ("REDG.E.OR.64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214158804228u64),
    ("@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64], R5", 21508393358u64, 22485013040914694u64),
    ("REDG.E.XOR.64.STRONG.GPU desc[UR4][R2.64], R4", 17213454734u64, 8974214167192836u64),
];

/// t206_1: every new witness word decodes to the exact vendor glyph on all
/// three tables (48 scope grafts + 2x S64 GPU + per-table singletons).
#[test]
fn t206_1_redg_scope_decode() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in PROBE_NEW {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} NEW {g}");
        }
    }
}
/// t206_2: new forms encode byte-exact to the witness word. Guard-predicated
/// non-EL REDG on sm_103a is refused by the BUG-080 erratum lane (measured
/// silently-broken on B300) — same posture as ATOMG t203_4.
#[test]
fn t206_2_redg_scope_encode() {
    for tp in TABS {
        let t = tab(tp);
        for (g, lo, hi) in PROBE_NEW {
            if g.starts_with("@P") && tp.ends_with("sm103a.json") {
                assert!(enc(&t, g).is_none(), "{tp} guard-080 {g}");
                continue;
            }
            assert_eq!(enc(&t, g), Some(word(*lo, *hi) & !SCHED), "{tp} enc {g}");
        }
    }
}
/// t206_3: retention — pre-existing REDG dARI anchors (incl. GPU base rows
/// that donated encoding to the new rows) render unchanged.
#[test]
fn t206_3_redg_retention() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        for (g, lo, hi) in PROBE_RETENTION {
            assert_eq!(dec(&t, &idx, word(*lo, *hi)).as_deref(), Some(*g), "{tp} RET {g}");
        }
    }
}
/// t206_4: fail-closed negatives — coveritudes with no witness stay refused:
/// EXCH/SAFEADD scope grafts, widened INC/DEC, vector widths without probes,
/// type/op nonsense on the new scope rows.
#[test]
fn t206_4_fail_closed_negatives() {
    for tp in TABS {
        let t = tab(tp);
        for text in [
            "REDG.E.ADD.F16x4.RN.STRONG.SM desc[UR4][R2.64], R6",
            "REDG.E.ADD.F16x8.RN.STRONG.SYS desc[UR4][R2.64], R4",
            "REDG.E.EXCH.STRONG.SM desc[UR4][R2.64], R5",
            "REDG.E.EXCH.STRONG.SYS desc[UR4][R2.64], R5",
            "REDG.E.INC.S64.STRONG.SM desc[UR4][R2.64], R5",
            "REDG.E.INC.64.STRONG.SYS desc[UR4][R2.64], R5",
            "REDG.E.DEC.64.STRONG.SYS desc[UR4][R2.64], R5",
            "REDG.E.MIN.F32.STRONG.SM desc[UR4][R2.64], R4",
            "REDG.E.ADD.S64.STRONG.SM desc[UR4][R2.64], R4",
            "REDG.E.CAS.64.STRONG.SM desc[UR4][R2.64], R6",
        ] {
            assert!(enc(&t, text).is_none(), "{tp} must refuse {text}");
        }
    }
}
/// t206_5: scope-law spot round-trip — the arb206 in-place mutations are the
/// same words as the compiler witnesses (MIN pair via rcg/rsg donors).
#[test]
fn t206_5_scope_law_roundtrip() {
    for tp in TABS {
        let t = tab(tp); let idx = DecodeIndex::build(&t);
        let g = "REDG.E.MIN.STRONG.GPU desc[UR6][R2.64], R5";
        let w = word(0x000000050200098eu64, 0x004fe2000c92e106u64);
        assert_eq!(dec(&t, &idx, w).as_deref(), Some("@P0 REDG.E.MIN.STRONG.GPU desc[UR6][R2.64], R5"));
        // ^b78 -> SM, ^(77,79,80) -> SYS (arb206.json, nvdisasm-validated)
        let wsm = w ^ (1u128 << 78);
        let wsys = w ^ (1u128 << 77) ^ (1u128 << 79) ^ (1u128 << 80);
        assert_eq!(dec(&t, &idx, wsm).as_deref(), Some("@P0 REDG.E.MIN.STRONG.SM desc[UR6][R2.64], R5"));
        assert_eq!(dec(&t, &idx, wsys).as_deref(), Some("@P0 REDG.E.MIN.STRONG.SYS desc[UR6][R2.64], R5"));
        let _ = g;
    }
}
