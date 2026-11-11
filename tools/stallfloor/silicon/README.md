# tools/stallfloor/silicon — the evidence of the 'silicon' edition

`tables/dep_latency_sm120_silicon.json` is an EDITION of the sm_120 dependency table (`tables/dep_latency_sm120.json`): the
same table with a lower number in the entries it lists. It is never the default. `CUBIT_SCHED2_LAT=sm120-silicon` gives it to
the scheduler, `CUBIT_DEP_TABLE=sm120-silicon` to the read-only checks; code: `src/dep_edition.rs`.

This directory holds the evidence those entries stand on: digests of probe runs, as `tools/stallfloor/probe.py` files them
(one JSON per batch: `conditions`, `provenance`, `requests` with their `series`), and the floor files of the production
cards (the witnesses). **An entry without its evidence here does
not load, and `tests/dep_edition_silicon.rs` refuses it.** A digest that no entry names does not belong here either.

There is no entry yet, so there is no digest yet.

## An entry

```json
{ "id": "P1",
  "resource": "mma", "first": "QMMA", "second": "QMMA",
  "floor": 1, "floor_basis": "interlock", "L": 2,
  "evidence": [ { "file": "tools/stallfloor/silicon/<digest>.json", "sha256": "<64 hex>", "request": "<request id>" } ] }
```

| section of the edition | the target it names | today's number it may not exceed |
|---|---|---|
| `cells` | `producer`, `consumer`, `role` — an existing cell of the base table | that cell |
| `resources` | `resource`, `first`, `second` — one pair of member classes of an existing resource | the spacing behind `first` |
| `holds` | `hold` — `mma_a_fragment`, `mma_b_fragment`, `uniform_operand` | the hold of the scheduler |

`L` is the measured floor + 1. `floor_basis` is `wrong-below` (a wrong result was measured below the floor in the same family —
the positive control of the floor) or `interlock` (floor 1: no smaller distance exists). An entry never raises a number, and
nothing follows a lowered cell down: a role that borrowed it (the upper register of a 64-bit operand, `r3h` from `r3`) keeps
today's number.

## What the evidence of ONE entry must show

Runs, told apart by the digest's own `conditions` — the Server Edition card, and **at least two** cards of the Workstation
Edition (production's model: the floor of a model is the maximum over its cards), **each of those in both clock states**:

| run | how the digest shows it |
|---|---|
| the Server Edition card | `gpu` names it |
| a Workstation Edition card, fast clock | `gpu` names it; `card` names the card; `clock_busy_mean_mhz` ≥ 2 800 (short runs: the power cap does not bind) |
| the same card, capped | `gpu`, `card`; `power_limit` 400 W and `power_median_w` ≥ 380 (a sustained load beside the probe: at the cap, not near it) |

`conditions.card` is a name of the physical card that says nothing else about it (the files are public: not a serial number,
not a host name) — for instance the first hex digits of the sha256 of the card's UUID. Two digests with the same `card` are
one card.

In EACH run (summed over the requests the entry names in that run; only the series of the probe itself count — `raw` for a
producer → consumer request, `bare` otherwise — never a control series):

- the floor distance right in every thread at the occupancies `w1`, `w8`, `w32`, `g32` — and at the served grids `w12`
  (one CTA of 12 warps per SM) and `c2w9s` (two CTAs of 9 warps resident per SM) for a tensor row (the resource `mma`, the
  `mma_*` holds). The 376-CTA grid `c2w9` of the earlier batches holds ONE CTA per SM (KNOWN_ISSUES A31) and is not the
  served grid;
- a wrong result below the floor, unless the entry is an `interlock`;
- no wrong result at or above the floor, at any occupancy;
- clean controls: no `oracle_failures`, every series `ok`, no launch error, no kernel skipped;
- at least 100 000 000 thread-launches right at the entry's own distance `L` — a sweep finds a floor with 10^6 … 10^7 per
  distance; the entry's distance is run again on its own with the repetitions raised.

`sha256` is the digest of the file's bytes: a file changed after the entry was written is refused.

## The production cards as witnesses

An edition that has an entry names, in `witnesses`, the floor files of four production cards (`file`, `sha256`), and no
cell of it may lie below any of their floors + 1:

```json
{ "schema": "cubit-dep-witness-1", "arch": "sm_120",
  "conditions": { "gpu": "… Workstation Edition", "card": "<the card's name>" },
  "floors": [ { "producer": "FMNMX", "consumer": "SHFL", "role": "r1", "floor": 2 } ] }
```

`floor` is an issue distance in the table's own terms (producer class, consumer class, operand role). A witness is not
evidence of an entry: it can only refuse one.

## Checking an entry before handing it over

```sh
cargo test --release --test dep_edition_silicon   # the bundled edition against the files of this directory
cargo test --release --lib dep_edition            # what an entry does to the table
```

The first test of `tests/dep_edition_silicon.rs` prints every reason an entry falls short.
