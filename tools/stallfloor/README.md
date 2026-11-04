# SM120 stall-floor harness

The measurement behind the `stallfix` section of `tables/sm120.json` (rules v3; the pass is
`cubit stallfix`, the plan and the reading of every floor is [docs/SM120_STALLFIX_PLAN.md](../../docs/SM120_STALLFIX_PLAN.md)).

| file | role |
|---|---|
| `stallfloor_gen.py` | CPU side: one cubit-assembled kernel per (dependency path, distance d ∈ {0,1,2}, producer stall S ∈ {0..11}) plus one scoreboarded reference kernel per path — 370 cubins, every control code frozen, `index.json` |
| `stallfloor_run.py` | GPU side (CUDA driver API through `culaunch.py`): 32 CTAs × 1 024 threads × 20 repetitions per kernel, per-thread checksums against the CPU model, the model proven against the reference kernel first; writes `stall_floors.json` in the layout of the rule keys |
| `culaunch.py` | ctypes driver-API helper (shared with the other probe kernels) |
| `stall_floors_sm120_20261103.json` | the run of 2026-11-03 18:05Z on 4x NVIDIA RTX PRO 6000 Server Edition (harness v2): 23 floors, `r2ur` model mismatch, `mufu`/`guard d0` need the scoreboard |

```bash
python3 tools/stallfloor/stallfloor_gen.py --cubit target/release/cubit --table tables/sm120.json --out kernels_stall/
python3 tools/stallfloor/stallfloor_run.py kernels_stall/ --reps 20 --out stall_floors.json     # on the GPU host
```

Reading a floor: the smallest producer stall with zero mismatching threads over all repetitions such
that every larger stall is clean too. S00 is clean on every path at every distance (including MUFU):
on sm_120 a stall count of 0 behaves as a hardware interlock, not as "no stall", and is never used as
a floor. v3 (2026-11-04) fixes the `r2ur` path: `R2UR UR, R` broadcasts one lane's register, so its
inputs are warp-uniform now (regenerate with `--paths r2ur`); its floor is the one measurement still
owed, and until it exists the rules carry `floor_r2ur_d0 = cap_stall`.
