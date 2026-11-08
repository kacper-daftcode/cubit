//! BUG-487 (T-16, 2026-11-07): `_meta.key_aliases` share their target's modifier groups instead of deep-copying them.
//!
//! The loader used to clone the whole target entry under the retired name. That is quadratic in the measured
//! lattices: at blackwell-isa `75e9d20` the sm120 table has 39 203 rows and 14 613 aliases whose targets carry up
//! to 6 144 groups (`REDG_ARURI_R`), i.e. 36 804 246 cloned rows per loaded table — `cubit decode` of one word
//! took 21 GB and 8.5 s (3.9 GB / 1.9 s at `5cb10e5`), the test binaries 40-55 GB each, and the push gate's
//! parallel suite drove the build host out of memory (the production worker was OOM-killed, 18:59Z). With the
//! groups behind an `Arc` (`cubit::table::ModGroups`) the same load is 0.56 GB / 0.7 s and the alias keeps its
//! contract: present in `entries`, `encode_only`, the target's groups by name and by value.
//!
//! Pins: every alias entry shares its target's group map (pointer identity) on every table that carries aliases
//! (sm120: 14 613 → 72 targets; sm121a: 13 → 6); every alias is `encode_only` and its target is not; the number of
//! distinct group maps equals the number of real keys (no real key shares a map with another real key);
//! `num_groups()` counts each shared map once (the row count, not the alias-amplified sum); an alias and its
//! target resolve the same `(key, group)` rows through `IsaTable::get`.

use cubit::table::IsaTable;
use std::collections::HashMap;
use std::path::Path;

fn load(arch: &str) -> (IsaTable, HashMap<String, String>) {
    let p = format!("tables/{arch}.json.gz");
    let table = IsaTable::load(Path::new(&p)).unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&p)).unwrap()).unwrap();
    let aliases: HashMap<String, String> = raw["_meta"]["key_aliases"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect())
        .unwrap_or_default();
    (table, aliases)
}

#[test]
fn t487_1_every_alias_shares_its_targets_groups() {
    for arch in ["sm120", "sm121a"] {
        let (table, aliases) = load(arch);
        assert!(!aliases.is_empty(), "{arch}: the table carries aliases");
        for (old, new) in &aliases {
            let a = table.entries.get(old).unwrap_or_else(|| panic!("{arch}: alias {old} is an entry"));
            let t = table.entries.get(new).unwrap_or_else(|| panic!("{arch}: target {new} is an entry"));
            assert!(a.mod_groups.shares_with(&t.mod_groups), "{arch}: {old} -> {new} shares the group map");
            assert_eq!(a.mod_groups.len(), t.mod_groups.len(), "{arch}: {old} -> {new} same groups");
            assert!(a.encode_only, "{arch}: {old} is decoder-invisible");
            assert!(!t.encode_only, "{arch}: {new} is a real row");
            for (g, row) in &t.mod_groups {
                assert_eq!(table.get(old, g).map(|r| r.and_base), Some(row.and_base), "{arch}: {old}::{g} resolves like {new}");
            }
        }
    }
}

#[test]
fn t487_2_real_keys_own_their_maps() {
    for arch in ["sm120", "sm103a", "sm100a", "sm121a"] {
        let (table, aliases) = load(arch);
        let real: Vec<&String> = table.entries.keys().filter(|k| !aliases.contains_key(*k)).collect();
        // every real key owns its map: no two real keys share one (pointer identity, O(n) via a set)
        let mut owners: HashMap<*const cubit::table::ModGroupEntry, &String> = HashMap::new();
        for k in &real {
            let m = &table.entries[*k].mod_groups;
            // the address of the map's first row is a stable identity of the shared allocation; an empty map
            // (a key without groups) is skipped
            if let Some(first) = m.values().next() {
                if let Some(prev) = owners.insert(first as *const _, k) {
                    panic!("{arch}: real keys {prev} and {k} share a group map");
                }
            }
        }
        let rows: usize = real.iter().map(|k| table.entries[*k].mod_groups.len()).sum();
        assert_eq!(table.num_groups(), rows, "{arch}: num_groups counts every shared map once");
        assert_eq!(table.num_keys(), real.len() + aliases.len(), "{arch}: num_keys counts the aliases");
    }
}

#[test]
fn t487_3_sm120_alias_amplification_is_gone() {
    // The figure the deep copy materialised (36 804 246 rows for 39 203 real ones at 75e9d20): with shared maps the
    // table's groups are counted once, and the sum over alias entries is only a view of the same maps.
    let (table, aliases) = load("sm120");
    let real_rows = table.num_groups();
    let alias_view: usize = aliases.keys().map(|k| table.entries[k].mod_groups.len()).sum();
    assert!(real_rows < 60_000, "sm120 rows {real_rows}");
    assert!(alias_view > real_rows, "the alias view ({alias_view}) is larger than the rows ({real_rows}) — it is the shared maps seen through 14 613 names");
    assert!(aliases.len() >= 14_000, "sm120 aliases {}", aliases.len());
}
