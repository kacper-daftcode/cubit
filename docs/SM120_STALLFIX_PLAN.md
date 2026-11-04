# SM120 stall legalization (`stallfix`) — plan and prepared measurement

`cubit stallfix` raises the stall counts of hand-scheduled windows to measured minimum floors.
Today it has rules for sm_103a only (`tables/sm103a.json`, `stallfix` section; see
[POSTFIX103_STALLFIX.md](POSTFIX103_STALLFIX.md)). This document is the SM120 counterpart's plan:
what the rules look like, how they are measured, what is prepared and what still needs silicon.
Status 2026-11-04: **measured.** The harness ran on 2026-11-03 18:05Z on 4x NVIDIA RTX PRO 6000 Server
Edition (23 floors, §4), the `stallfix` section of `sm120.json` carries them (rules v3, blackwell-isa
2026-11-04), `cubit stallfix` applies them (`tests/stallfix_sm120.rs`), the harness lives in
[tools/stallfloor/](../tools/stallfloor/README.md). Still owed: the `r2ur` floor (harness v3 kernels
prepared) and the S12–S15 band (§4).

## 1. Rule format (the `stallfix` section of `sm120.json`)

The same keys as the sm_103a section, so the pass needs no new code paths:

| key | meaning | sm_103a value (for scale) |
|---|---|---|
| `arch` | scope lock against the plan's `arch` | `sm_103a` → `sm_120` |
| `rules_version`, `comment`, `provenance` | identification and the measurement that produced the floors | — |
| `cap_stall` | largest stall the pass may write | 11 (S≥12 hangs on B300; SM120: `Y:S12..S15` are decoder-reserved, so ≤ 11 as well) |
| `floor_global` | any producer → consumer at d0 in a window (register / predicate-carry ALU paths) | 4 |
| `floor_dmix_d0` | `IMAD.WIDE(.U32)[.X]` carry-out → `IADD3.X` carry-in at d0 | 5 |
| `floor_guard_d0`, `floor_guard_d2` | predicate producer → `@P`/`@!P` guard consumer at d0 / d2 | 7, 5 |
| `guard_d1_forbid`, `guard_d1_isetp_floor` | the guard-at-d1 pathology: class-resolved (isetp-class legal 5..11, data-class never) | true, 5 |
| `floor_xread_d0` | uniform ALU UR write → vector op reading the UR at d0 | 6 |
| `floor_r2ur_d0` | the R2UR conversion boundary at d0 (either direction) | 8 |
| `floor_uguard_d0`, `floor_uguard_d1` | `UISETP` → `@UP` guard at d0 / d1 | 10, 8 |
| `legacy_stall_risk_from` | stall value below which legacy text is reported | 1 |

Producers / consumers are classified by the pass's existing allowlist (IADD3.X dual carry-out,
ISETP predicate write, `.X` / IMAD.WIDE carry-out; carry-in consumers IADD3.X / IMAD*.X; non-uniform
guards). A measured SM120 section fills the same keys; a path that measures "no stall legalizes it"
becomes a `*_forbid` flag like `guard_d1_forbid`.

## 2. Measurement method (prepared under the session's GPU items)

One kernel per (path, distance d, producer stall S): producer and consumer `d` instructions apart,
every control code frozen (`[B------:R-:W-:-:Sxx]` on the producer, S01 elsewhere), the pair repeated
256 times per thread with a running checksum, 32 CTAs × 1 024 threads (occupancy pressure, as the
B300 measurement), 20 repetitions. The CPU model of each path gives the expected checksum; the floor
of (path, d) is the smallest S with zero mismatching threads over all repetitions, provided the
largest S of the grid is clean (otherwise the CPU model, not the silicon, is wrong and the path is
reported as `MODEL_MISMATCH`). MUFU is included as a control with the GPU's own largest-stall result
as reference (variable-latency producers are expected to need the scoreboard, not a stall).

Paths (names = rule keys): `rpath` (IADD3 → IADD3), `pcarry` (ISETP → SEL), `guard` (ISETP → `@P`
consumer), `dmix` (IMAD.WIDE.U32 carry-out → IADD3.X), `xchain` (IADD3.X → IADD3.X), `mufu`
(MUFU.RCP → FFMA), `urpath` (UIADD3 → UIADD3), `xread` (UIADD3 → IADD3 reading the UR), `r2ur`
(IADD3 → R2UR), `uguard` (UISETP → `@UP` consumer); d ∈ {0, 1, 2}; S ∈ {0 … 11} → 360 kernels,
all assembled by cubit and strict-round-tripped. Generator: `stallfloor_gen.py`; GPU runner:
`stallfloor_run.py` (writes `stall_floors.json` in the layout of §1); block script `run_block.sh
stallfloors` (≈ 10 min on one RTX 5090). Both live in the session's `T/gpu/` directory and will be
added under `tools/stallfloor/` with the measured section once the run exists.

## 3. Integration test (to add with the measured section)

`tests/stallfix_sm120.rs`: a window over each path's d0 pair at S00 must be raised to exactly the
measured floor and nothing else may change (byte diff = the stall digits), the `arch` lock must
reject a `sm_103a` plan against SM120 rules, and the `guard_d1` class resolution must match the
measurement. The sm_103a test (`tests/stallfix_*.rs`) is the template.

## 4. Measured floors (2026-11-03, 4x NVIDIA RTX PRO 6000 Server Edition)

Harness v2 (`tools/stallfloor/`), 370 cubit-assembled kernels, 32 CTAs × 1 024 threads × 20
repetitions, raw results `tools/stallfloor/stall_floors_sm120_20261103.json` (SHA-256 pinned in the
section's `provenance`). Every path but `r2ur` passed its model check (CPU model = scoreboarded
reference kernel, 0 of 32 768 threads differ). Floor = smallest producer stall S with 0 mismatching
threads such that every larger S is clean; `d` = number of one-cycle filler instructions between
producer and consumer.

| path (producer → consumer) | d0 | d1 | d2 | rule keys |
|---|---|---|---|---|
| `rpath` IADD3 → IADD3 | S04 | S00 | S00 | `floor_global` 4 (R1) |
| `xchain` IADD3.X cout → IADD3.X cin | S04 | S00 | S00 | `floor_global` |
| `urpath` UIADD3 → UIADD3 | S04 | S03 | S00 | `floor_global` (R7), `floor_urpath_d1` 3 |
| `pcarry` ISETP → SEL reading the predicate | S05 | S04 | S00 | `floor_pcarry_d0` 5, `floor_pcarry_d1` 4 (R11, new) |
| `dmix` IMAD.WIDE.U32 cout → IADD3.X cin | S05 | S00 | S00 | `floor_dmix_d0` 5 |
| `guard` ISETP → `@P0 IADD3` | **none ≤ S11** (641 888 / 655 360 wrong at S11) | S11 (S10: 643 744 wrong) | S09 | `guard_d0_forbid`, `floor_guard_d1` 11 (every class; `guard_d1_forbid` false), `floor_guard_d2` 9 |
| `xread` UIADD3 UR → vector IADD3 reading the UR | S06 | S04 | S02 | `floor_xread_d0/d1/d2` 6/4/2 |
| `uguard` UISETP → `@UP0 UIADD3` | S10 | S08 | S06 | `floor_uguard_d0/d1/d2` 10/8/6 |
| `mufu` MUFU.RCP → FFMA | none | none | none | variable latency: the scoreboard is the only legal schedule (the pass never writes barriers) |
| `r2ur` IADD3 → R2UR | model mismatch | — | — | `floor_r2ur_d0` = `cap_stall` 11 until measured (below) |

Readings:

- S00 was clean on every path at every distance, MUFU included: on sm_120 a stall count of 0 is a
  hardware interlock, not "no stall". It is never used as a floor (the pass never writes S00).
- The register and uniform ALU paths match sm_103a (`floor_global` 4, `dmix` 5, `xread` 6, `uguard`
  10/8); the predicate → guard path does not: sm_103a legalizes guard-d0 at S07, SM120 at no stall up
  to the cap. A guarded consumer directly after its predicate producer is a `stallfix` violation on
  SM120 (move it two slots away, or read the predicate as data: `pcarry` needs 5).
- `guard d1 = 11` is the single clean value measured (S12–S15 are outside the sweep: decoder-reserved
  with yield, unmeasured without); it is applied to every consumer class because no class split was
  measured on SM120 (the sm_103a isetp/data/atomic split stays sm_103a's).
- `r2ur`: the v2 CPU model summed every thread's own `a + b`, but `R2UR UR9, R6` broadcasts one
  lane's R6 (24 576 of 32 768 threads differed from the scoreboarded reference). Harness v3
  (2026-11-04) makes the r2ur inputs warp-uniform; the 37 kernels are regenerated and queued for the
  next GPU window. Until then the rules carry the cap for R2UR boundaries — the most conservative
  legal stall, not a guess.
- Occupancy: one geometry (32 CTAs × 1 024 threads) as in the sm_103a census; the 1×32 geometry was
  not run.

## 5. What still needs silicon

- The `r2ur` floor (v3 kernels, `tools/stallfloor/stallfloor_gen.py --paths r2ur`).
- The S12–S15 band without yield (whether it executes or hangs); `cap_stall` stays 11.
- Guard-d1 consumer classes other than data (isetp / atomic) and the 1×32 geometry.
