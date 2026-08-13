//! mk64 (2026-08-13): pelna regula rekordow-duchow __syncwarp 01476c0a z
//! site'ow EIATTR-0x28 — kandydat = lane z instr NOP w .text, wykluczajac
//! srodek triple'a [WARPSYNC*;NOP;ENDCOLLECTIVE]; site'y z realna instrukcja
//! (np. WARPSYNC.ALL) to mini (mk14 ghost_mini76 / 4147760a); dialekt
//! zero-param (UTCATOMSWS+RET) pokrywa ostatni lone-NOP tailem (mk27/mk28,
//! mkvmem). Dowody korpusowe: merclab/mk64 c4/c5 (EXACT 30554/30554, l2).
//! Maski 0x29 bez znaczenia (0x050000xx tez daja rekordy).

use cubit::mercury::{merc_ghost64_lanes, merc_ghost64_split};
use std::collections::HashMap;

fn opmap(pairs: &[(u32, &str)]) -> impl Fn(u32) -> Option<String> {
    let m: HashMap<u32, String> = pairs.iter().map(|(l, o)| (*l, o.to_string())).collect();
    move |l: u32| m.get(&l).cloned()
}

#[test]
fn mk64_split_lone_nop() {
    // site'y: lane 2 NOP, 5 NOP (samotne) -> oba pelne rekordy
    let sites = vec![0x20, 0x50];
    let (full, mini) = merc_ghost64_split(&sites, opmap(&[(2, "NOP"), (5, "NOP")]));
    assert_eq!(full, vec![2, 5]);
    assert!(mini.is_empty());
}

#[test]
fn mk64_split_wc_triple_excluded() {
    // triple [WARPSYNC;NOP;ENDCOLLECTIVE] na lanes 10..12 + samotny NOP 20.
    // lane 11 NIE dostaje rekordu (pokrywa go d10102-47 mk59).
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
    // site z realna instrukcja (WARPSYNC z maska rejestrowa) -> mini, nie pelny.
    let sites = vec![0x30];
    let (full, mini) = merc_ghost64_split(&sites, opmap(&[(3, "WARPSYNC")]));
    assert!(full.is_empty());
    assert_eq!(mini, vec![3]);
    // granica: lane 0 NOP bez poprzednika -> kandydat (brak triple'a)
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
    // bez utca_ret (sciezka korpusowa): same pelne rekordy {2,29,56}
    let v2 = merc_ghost64_lanes(&sites, &op, Some(3), false, &[]);
    assert_eq!(v2, vec![2, 29, 56]);
}

#[test]
fn mk64_lanes_failclosed_legacy() {
    // rozjazd liczbowy -> fail-closed do reguly mk14 (take(n) po legacy).
    let sites = vec![0x70, 0x80];
    let op = opmap(&[(7, "NOP"), (8, "NOP")]);
    let v = merc_ghost64_lanes(&sites, &op, Some(1), false, &[7, 8]);
    assert_eq!(v, vec![7]);
    // cubin bez capmerc -> legacy bez zmian (keep-all)
    let v2 = merc_ghost64_lanes(&sites, &op, None, false, &[7]);
    assert_eq!(v2, vec![7]);
    // zero rekordow w orig i brak kandydatow -> pusto (bramka odwrotna)
    let v3 = merc_ghost64_lanes(&sites, &op, Some(0), false, &[7, 8]);
    assert!(v3.is_empty());
}
