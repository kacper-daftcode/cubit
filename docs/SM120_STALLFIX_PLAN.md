# SM120 stall legalization (`stallfix`) — plan and prepared measurement

`cubit stallfix` raises the stall counts of hand-scheduled windows to measured minimum floors.
Today it has rules for sm_103a only (`tables/sm103a.json`, `stallfix` section; see
[POSTFIX103_STALLFIX.md](POSTFIX103_STALLFIX.md)). This document is the SM120 counterpart's plan:
what the rules look like, how they are measured, what is prepared and what still needs silicon.
Status 2026-11-02: rule format fixed, measurement harness written and assembled (CPU), **the
floors themselves need a GPU run** (`docs/KNOWN_ISSUES.md` A3).

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

## 4. What needs silicon

- The floors (§2 run). Expected scale: SM120 and SM103a share the issue pipeline model but not the
  clock or the uniform datapath details; nothing in the table today says SM120 floors equal SM103a's.
- Whether the guard-at-d1 pathology exists on SM120 at all (B300: data-class consumers never
  legalize).
- The S12–S15 band: decoder-reserved with yield on SM120; without yield they encode — whether they
  execute or hang is not measured (`cap_stall` stays 11 until then).
