//! SM121a text-parity pass of 2026-11-04 (session T-4, owner decision NEEDS_OWNER 17 "to 100 %").
//!
//! The GB10 census (`cold-face-bounces-fin-02` -> `ssh spark` -> gx4, NVIDIA GB10) left 60 SM121a
//! text differences against the recorded `nvdisasm -b SM121` output. They are closed by adopting the
//! measured SM120 rows for the shared keys (blackwell-isa `t4_sm121a_parity.py`: R2P, IMNMX, SEL.64
//! with its 33-bit immediate, REDUX without the duplicate op=0 AND group, BAR's clean per-form keys,
//! DEPBAR with the SBn token), by rebuilding the one SM121a-only harvest row (UIMNMX.U64 immediate
//! form) and by three cubit printer facts shared with SM120 (ATOMS/ARRIVES `[Rm+URn]` glyph now
//! fires for the whole sm_120 encoding family incl. sm_121a; the F2IP modifier order; the IMMA
//! `.ROW`/`.COL` matrix print). Parity on the 373 recorded mismatch words: 372/373 (the residue is
//! LEPC, a PC-relative target the isolated-word census renders at address 0 -- byte-identical in a
//! full disassembly). One representative word per fixed family is pinned here; the full re-run is the
//! README/KNOWN_ISSUES V3 figure.

use std::path::Path;

use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;

fn norm(s: &str) -> String {
    s.replace(".reuse", "").split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn sm121a_parity_fixtures_decode_to_the_vendor_text() {
    let table = IsaTable::load(Path::new("tables/sm121a.json")).unwrap();
    let idx = DecodeIndex::build(&table);
    let fixture = include_str!("fixtures/sm121a_parity_20261104.jsonl");
    let mut n = 0;
    for line in fixture.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let want = row["nvidia_sass"].as_str().unwrap();
        let decoded = idx.decode(word, 0, &table).expect("decode");
        let got = cubit::printer::to_sass(&decoded);
        assert_eq!(norm(&got), norm(want), "{} ({:032x})", row["key"].as_str().unwrap(), word);
        n += 1;
    }
    assert_eq!(n, 11, "fixture row count");
}
