//! BUG-432 (F2-iter267): sm121a LDG/STG ARI (b9,b11) cavity closure.
//! 23 recs: R1C donor-clone sm103a x4 + R1EF + R1S surg x10 + R2 LTC128B x4.
//! Vendor law: arb432 (52) + arb432b (18) + arb432c (66) nvdisasm 13.3.73 raw -b
//! era-gated x4 AGREE EVERY / DIVERGENT=0. Data generated: bug432_data.inc
//! (gen432pins.py v2). Canonical graft a64b82b -> (iter267) via tools/sync_table.py.
use cubit::decoder::DecodeIndex;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug432_data.inc");

fn t121() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm121a.json")).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn dec121(w: u128) -> Option<String> {
    let t = t121();
    let idx = DecodeIndex::build(&t);
    dec(&t, &idx, w)
}

/// t432_1: match cells -- post-432 decode == verbatim vendor text x klasa.
#[test]
fn t432_1_match_cells() {
    let t = t121();
    for (w, vend) in LAW432_MATCH {
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*vend), "match drift {w:#034x}");
    }
}

/// t432_2: cavity closed + kill anchors -- vendor rc=1 -> HOLE on sm121a.
#[test]
fn t432_2_closed_and_kill() {
    let t = t121();
    for (w, exp) in LAW432_CLOSED.iter().chain(LAW432_KILLANCHOR.iter()) {
        assert_eq!(*exp, "HOLE");
        assert_eq!(
            dec(&t, &DecodeIndex::build(&t), *w),
            None,
            "kill/cavity claim {w:#034x}"
        );
    }
}

/// t432_3: gap-469 residuum pins (LDG.E ARURI mode-3/m2; rejestr 469-kand).
/// RIDE469 (F2-iter285): jedyna zmiana od ustawienia = heal 12/14 wpisow LDG
/// przez graft 469 (mg['E'] b92->vm + mg 0x981); engine==vendor nvdisasm
/// 13.3.73 raw -b x4 (work/bug469/gates_fails_compare.json). 2 wpisy STG
/// (128EFpl / STG64.fromplain128) zostaja HOLE = standing.
#[test]
fn t432_3_gap469_post_hole() {
    let t = t121();
    for (w, exp) in LAW432_GAP469.iter().chain(LAW432_GAP469_TEXT.iter()) {
        if *exp == "HOLE" {
            assert_eq!(
                dec(&t, &DecodeIndex::build(&t), *w),
                None,
                "469-class claim {w:#034x}"
            );
        } else {
            assert_eq!(dec(&t, &DecodeIndex::build(&t), *w).as_deref(), Some(*exp));
        }
    }
}

/// t432_4: standing illegal claims (471-kand note) -- snap post state.
#[test]
fn t432_4_standing_snap() {
    let t = t121();
    for (w, exp) in LAW432_STANDING.iter().chain(LAW432_STANDING_TRANSF.iter()) {
        assert_eq!(
            dec(&t, &DecodeIndex::build(&t), *w).as_deref(),
            Some(*exp),
            "standing drift {w:#034x}"
        );
    }
}

/// t432_4b/t432_5: standing snap + count tripwires (machine-gen manifest).
#[test]
fn t432_5_counts() {
    assert_eq!(LAW432_MATCH.len(), 678); // 31 law + 647 corpus432r carriers (432R; INC-268 rerun)
    assert_eq!(LAW432_CLOSED.len() + LAW432_KILLANCHOR.len(), 89);
    assert_eq!(LAW432_GAP469.len() + LAW432_GAP469_TEXT.len(), 14);
    assert_eq!(LAW432_STANDING.len() + LAW432_STANDING_TRANSF.len(), 2);
}
