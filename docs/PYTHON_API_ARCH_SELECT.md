# Python API: native arch/table selection

The Python bindings use one process-wide ISA table: `CUBIT_TABLE` at first
use, else `tables/sm120.json` relative to CWD. `select_table` switches the
active table explicitly, so frontends driving multiple architectures
(sm_100a/sm_103a/sm_110a/sm_120/sm_121a) do not have to respawn processes
per arch.

## API
```python
import cubit
cubit.select_table("sm103a")        # arch name: sm120, 120, sm120a, 120a, sm103a, ...
cubit.select_table("tables/sm103a.json")  # or any explicit JSON path
cubit.current_table()               # -> "sm103a" (or canonical path string)
cubit.table_info()                  # (num_keys, num_groups) of the ACTIVE table
```
`select_table` returns `(num_keys, num_groups)` and raises `ValueError`
(listing attempted paths) for unknown specs, `IOError` for load failures.

## Semantics
- One active table per process; `encode`/`decode`/`decode_kernel`/`to_sass`/
  `asm` all use it. Switching is cheap: tables and their decode indexes are
  cached (keyed by canonical spec/path), so repeated arch flips do not reload.
- Default behavior without `select_table`: first use honors `CUBIT_TABLE`,
  then falls back to repo `tables/sm120.json`; the load error message points
  at `cubit.select_table()`.
- Arch-name resolution looks in `tables/<name>.json` (CWD) and in the
  compile-time crate root `tables/` directory.

## Scope / non-goals
No per-call `arch=` kwarg (would double the API surface); the process-global
selection matches single-kernel-builder workloads. Thread safety: table state
is behind an internal RwLock; typical use is single-threaded builder code.
