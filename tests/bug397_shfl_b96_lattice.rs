//! BUG-397 pins (AUDIT-CLOSED / FALSIFIED registration; pin-pack deferred from
//! F2-iter215, lands with the BUG-402 fix commit per the 379/380/394 practice).
//!
//! Registration (F2-iter207, 396.md sec.7): "SHFL RR-anchor^b96 -> vendor
//! renders R32 where the engine prints R16" -- the claimed witness pair was
//! never found in ANY artifact and the claim does not reproduce on the exact
//! registered anchor (3 independent re-runs). Measured lattice closure
//! (arb397/arb397b/arb397c: 20 corpus anchors x [clean + per-bit b96..b119 +
//! 4 inert masks + 2 control balls] = 620 probes x 4 vendor models
//! (nvdisasm 13.3.73 raw -b) + 4 engine legs, isolated per leg per INC-215):
//! vendor: 560 INERT + 40 KILL + 0 LIVE; the engine is vendor-faithful on
//! every inert cell (600/600 per leg re-verified isolated); the only KILLs
//! are full balls crossing into the control prefix [119:104] (vendor rc=1;
//! engine = documented M96 silent-decode posture, no registration).
//! Report: results/cubitfix/397.md (+ iter215 addendum, verify397_iso_*.json).
//!
//! These pins freeze the measured law as a tripwire: if a future table or
//! decoder change perturbs the SHFL b96+ inert lattice, t397 fires.
//!
//! Witness data: tests/bug397_data.inc (machine-built by
//! work/bug402/gen397inc.py from work/bug397/pin_wit397.json verbatim).

use cubit::decoder::DecodeIndex;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}

include!("bug397_data.inc");

/// 2026-11-09 (T-25; rows-misc-2026-11-07 on -b SM100 / SM103 / SM121, T-23's per-row passes): a SHFL row measured field
/// by field fails closed on the text-inert bits -- [95:92] (396), [63:61] (387), [90:88] (382): nvdisasm prints the clean
/// text for them, the row's mask is its fields and does not claim them --, the sm120 harvest rows keep the relax. Five of
/// the 20 F2-era anchors carry bit 93 (none of the production census' 3 320 SHFL words does): they and their b96+ lattice
/// are HOLEs on the measured legs; the clean word (the inert bits cleared) renders the pinned text on every leg.
const INERT_SHFL: u128 = (0xfu128 << 92) | (0x7u128 << 61) | (0x7u128 << 88);
fn render_or_closed(t: &IsaTable, idx: &DecodeIndex, word: u128, tag: &str) -> String {
    match idx.decode(word & M96, 0, t) {
        Ok(d) => to_sass(&d),
        Err(e) => {
            assert!(word & INERT_SHFL != 0, "[{tag}] {word:032x}: {e}");
            let d = idx
                .decode(word & M96 & !INERT_SHFL, 0, t)
                .unwrap_or_else(|e| panic!("[{tag}] clean word of {word:032x}: {e}"));
            assert!(
                t.entries[&d.key].mod_groups[&d.mod_group].row_probe,
                "[{tag}] a harvest row fails closed on {word:032x} ({}[{}])",
                d.key,
                d.mod_group
            );
            to_sass(&d)
        }
    }
}

/// t397_1: 20 clean anchors decode vendor-verbatim on all four legs.
#[test]
fn t397_1_clean_anchors_vendor_verbatim() {
    for leg in LEGS4 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, want) in W397_ANCHORS {
            let got = render_or_closed(&t, &idx, word, &format!("{leg}] anchor"));
            assert_eq!(got, want, "[{leg}] anchor render drift {word:032x}");
        }
    }
}

/// t397_2: every per-bit flip in [119:96] is inert on all four legs:
/// decode renders exactly the clean anchor text (560 inert cells shrink to
/// the pinned 480 single-bit probes; compositions follow in t397_3).
#[test]
fn t397_2_perbit_inert_lattice() {
    for leg in LEGS4 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, ai) in W397_PERBIT {
            let got = render_or_closed(&t, &idx, word, &format!("{leg}] perbit"));
            assert_eq!(
                got,
                W397_ANCHORS[ai].1,
                "[{leg}] bit not inert vs anchor {}: {word:032x}",
                W397_ANCHORS[ai].1
            );
        }
    }
}

/// t397_3: composition masks inside [103:96] stay inert x4 legs.
#[test]
fn t397_3_composition_inert() {
    for leg in LEGS4 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (word, ai) in W397_COMPO {
            let got = render_or_closed(&t, &idx, word, &format!("{leg}] compo"));
            assert_eq!(got, W397_ANCHORS[ai].1);
        }
    }
}

/// t397_4: full balls crossing into the control prefix [119:104] = vendor
/// KILL (rc=1 x4, doctrina M96 boundary documented in 397.md sec.2); the
/// engine posture is silent decode (project stance, not a registration):
/// the instruction text must render unchanged vs the clean anchor.
#[test]
fn t397_4_control_ball_engine_posture() {
    for leg in LEGS4 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for word in W397_KILL {
            let got = render_or_closed(&t, &idx, word, &format!("{leg}] kill-ball"));
            assert!(
                got.starts_with("SHFL."),
                "[{leg}] kill-ball misroute: {got}"
            );
        }
    }
}
