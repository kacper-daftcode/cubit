//! mk64 (2026-08-13): the full rule of __syncwarp 01476c0a ghost records from
//! EIATTR-0x28 sites — candidate = a lane with a NOP instruction in .text, excluding
//! the middle of a [WARPSYNC*;NOP;ENDCOLLECTIVE] triple; sites with a real
//! instruction (e.g. WARPSYNC.ALL) are minis (mk14 ghost_mini76 / 4147760a); the
//! zero-param dialect (UTCATOMSWS+RET) covers the last lone NOP with the tail (mk27/mk28,
//! mkvmem). Corpus evidence: merclab/mk64 c4/c5 (EXACT 30554/30554, l2).
//! The 0x29 masks are irrelevant (0x050000xx also yields records).

use cubit::mercury::{merc_ghost64_lanes, merc_ghost64_split};
use std::collections::HashMap;

fn opmap(pairs: &[(u32, &str)]) -> impl Fn(u32) -> Option<String> {
    let m: HashMap<u32, String> = pairs.iter().map(|(l, o)| (*l, o.to_string())).collect();
    move |l: u32| m.get(&l).cloned()
}

#[test]
fn mk64_split_lone_nop() {
    // sites: lane 2 NOP, 5 NOP (lone) -> both full records
    let sites = vec![0x20, 0x50];
    let (full, mini) = merc_ghost64_split(&sites, opmap(&[(2, "NOP"), (5, "NOP")]));
    assert_eq!(full, vec![2, 5]);
    assert!(mini.is_empty());
}

#[test]
fn mk64_split_wc_triple_excluded() {
    // triple [WARPSYNC;NOP;ENDCOLLECTIVE] na lanes 10..12 + samotny NOP 20.
    // lane 11 gets NO record (covered by the d10102-47 of mk59).
    let sites = vec![0xb0, 0x140];
    let (full, mini) = merc_ghost64_split(
        &sites,
        opmap(&[(10, "WARPSYNC"), (11, "NOP"), (12, "ENDCOLLECTIVE"), (20, "NOP")]),
    );
    assert_eq!(full, vec![20]);
    assert!(mini.is_empty());
}

#[test]
fn mk64_split_mini_real_instr() {
    // a site with a real instruction (register-mask WARPSYNC) -> mini, not full.
    let sites = vec![0x30];
    let (full, mini) = merc_ghost64_split(&sites, opmap(&[(3, "WARPSYNC")]));
    assert!(full.is_empty());
    assert_eq!(mini, vec![3]);
    // edge: a lane-0 NOP without a predecessor -> candidate (no triple)
    let (full0, _) = merc_ghost64_split(&[0x0], opmap(&[(0, "NOP")]));
    assert_eq!(full0, vec![0]);
}

#[test]
fn mk64_lanes_proof_and_utca_reshape() {
    // mkvmem-wektor: site'y 0x20/0x1a0/0x1d0/0x380, wszystkie maski -1;
    // 0x1a0 = WARPSYNC.ALL (mini), 0x380 = lone-NOP pokrywany tailem
    // (utca_ret), capmerc ma 3 rekordy -> oczekiwane lane'y {2,26,29}.
    let sites = vec![0x20, 0x1a0, 0x1d0, 0x380];
    let op = opmap(&[(2, "NOP"), (26, "WARPSYNC"), (29, "NOP"), (56, "NOP")]);
    let v = merc_ghost64_lanes(&sites, &op, Some(3), true, &sites.iter().map(|s| s / 16).collect::<Vec<_>>());
    assert_eq!(v, vec![2, 26, 29]);
    // without utca_ret (the corpus path): full records only {2,29,56}
    let v2 = merc_ghost64_lanes(&sites, &op, Some(3), false, &[]);
    assert_eq!(v2, vec![2, 29, 56]);
}

#[test]
fn mk64_lanes_failclosed_legacy() {
    // a count divergence -> fail-closed to the mk14 rule (take(n) per legacy).
    let sites = vec![0x70, 0x80];
    let op = opmap(&[(7, "NOP"), (8, "NOP")]);
    let v = merc_ghost64_lanes(&sites, &op, Some(1), false, &[7, 8]);
    assert_eq!(v, vec![7]);
    // a cubin without capmerc -> legacy unchanged (keep-all)
    let v2 = merc_ghost64_lanes(&sites, &op, None, false, &[7]);
    assert_eq!(v2, vec![7]);
    // zero records in orig and no candidates -> empty (the reverse gate)
    let v3 = merc_ghost64_lanes(&sites, &op, Some(0), false, &[7, 8]);
    assert!(v3.is_empty());
}
