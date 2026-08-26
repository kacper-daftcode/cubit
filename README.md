# cubit

Open-source SASS assembler and disassembler for NVIDIA SM120 (Blackwell).
Assembles, disassembles, schedules, patches, and round-trips SM120 machine
code with full decode coverage on the validation corpus. Assembly and
disassembly require no nvcc or ptxas; the `roundtrip` command validates with
`cuobjdump` as an independent reference oracle.

## Install

```bash
cargo build --release
```

Rust 1.87+. The ISA tables ship with the repo.

## Usage

```bash
# Assemble SASS to cubin
cubit asm kernel.sass -o kernel.cubin

# Disassemble a cubin back to SASS
cubit disassemble kernel.cubin -k my_kernel

# Round-trip: binary → SASS text → binary (bit-exact)
cubit roundtrip kernel.cubin

# Rebuild edited SASS while preserving an nvcc cubin's ELF metadata
cubit asm modified.sass --template nvcc_kernel.cubin -o patched.cubin

# Encode a single instruction
cubit encode "IADD3 R5, PT, PT, R9, R4, R5 ;"
```

Round-trip is through SASS text: disassemble, edit, re-assemble. Use
`--frozen` on disassemble to preserve the original schedule verbatim (encoded
as `[B:R:W:S]` prefixes per instruction); with `--frozen` the scheduler is
bypassed — what you write is what you get.

A `.sass` file can contain multiple kernels (`.entry` / `.endentry` blocks);
cubit assembles them into a single multi-kernel cubin.

The assembler guards measured silicon traps fail-closed — constructs that
would mis-encode or mis-execute are a hard error, not a silent wrong binary.
See [docs/ENCODER_GUARDS.md](docs/ENCODER_GUARDS.md).

### Residue annotations

Some hardware bits are invisible in nvdisasm-compatible SASS text (convergence
barrier IDs, F2F mnemod order bits, epoch-window edges). For those,
disassembly appends an explicit annotation:

```
[B------:R-:W-:Y:S05]  @P1 BRA L_2310 !rsd[24:1] ;
F2F.F64.F32 R18, R19 !rsd[75:1,84:0] ;
```

`!rsd[...]` is applied as the last overlay stage at encode, so frozen
round-trips are bit-exact by construction on every decodable instruction.
Default text stays nvdisasm-compatible — the annotation appears only where
fidelity would otherwise be lost.

### Mercury (capmerc) sections

```bash
cubit merc-dump kernel.cubin -k my_kernel [--strict]
```

`cubit asm` emits the nvcc 13.3 companion sections statelessly (default;
`CUBIT_MERC13=0` selects byte-legacy output). It chooses the Mercury layout
per kernel: plain kernels keep the static stub; kernels containing
tcgen05/TMA-class instructions (`UTCHMMA`, `UTCQMMA`, `UTMALDG`/`UTMASTG`,
`UTCBAR`, …) are emitted Mercury-free unless `--mercury-stub <blob>` is
given. See [docs/MERC13_COMPANIONS.md](docs/MERC13_COMPANIONS.md).

### Scheduling

cubit assigns scheduling metadata (stalls, barriers, yields) automatically:
a dataflow-driven stall model, 6-scoreboard barrier allocation with
recycling, write-after-read barriers for variable-latency loads, QMMA
warp-cooperative constraints and drain insertion, and back-edge drains
before backward branches. Output verified on RTX 5090.

For hand-scheduling, cubit accepts inline control codes that override the
auto-scheduler per instruction:

```
[B------:R-:W-:Y:S05] FMUL R40, R40, R30 ;
```

See [docs/sasstuning.md](docs/sasstuning.md) for the measured field guide.

## SM103a stall legalizer

```bash
cubit stallfix --plan plan.json --rules tables/sm103a.json in.sass \
    [-o out.sass] [--report rep.json]
```

Raises stalls inside declared windows to the measured SM103a silicon floors
(raise-only, fail-closed, byte-proven re-parse). See
[docs/POSTFIX103_STALLFIX.md](docs/POSTFIX103_STALLFIX.md).

## Tables

Every architecture table published by
[blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa) is vendored
byte-exact under `tables/`, one file per architecture, with base revision and
SHA-256 pins in `tables/SOURCE.json`:

| table | arch | silicon | status |
|---|---|---|---|
| `sm120.json` | SM120 | RTX 5090 / DGX-class Blackwell | full pipeline + silicon REGRESS (frozen-RT bit-identical, 257/257 golden census) |
| `sm103a.json` | SM103a | B300 | full pipeline incl. scheduling cost model, stall-fix floors and operand roles as in-table sections (`cost_model`, `stallfix`, `operand_roles`) |
| `sm100a.json` | SM100a | B200 | encode/decode layer = canonical sm103a copy + tcgen05 delta layer (119/119 probe-pair byte parity); offline replay on the archived 20.0M-instruction sm_100 corpus: 99.92% EXACT-minus-sched. No B300 timing data is smeared in |
| `sm121a.json` | SM121A | GB10 (DGX Spark) | decode/encode incl. the `pred_inv4` trailing-pred map (fleet GB10 gold set passes 208/208); timing/fine-scheduling data pending a GB10 campaign |

Select per invocation with `-t tables/<arch>.json` / `CUBIT_TABLE`, or per
process with `cubit.select_table("<arch>")` (names like `sm100a` / `sm121a`
resolve to the vendored files directly). The output cubin's ELF header gets
its architecture flags from the active table. (The `cost_model` / `stallfix`
sections can also be passed to `--cost` / `--rules` simply by pointing them
at the arch table.)
Validation: `tools/sync_table.py --validate-only` (structure + control-bit
ratchet) and `--check` (byte-pin), plus the Cargo suite, which fails closed
on any table load error. `CUBIT_TABLE` overrides the active table strictly: a
missing or malformed override is an error, not a fallback.

## Python bindings

```bash
pip install -e .   # builds the native extension via maturin
```

```python
import cubit

lo, hi = cubit.encode("IADD3 R5, PT, PT, R9, R4, R5 ;", addr=0)
info = cubit.decode(lo, hi, addr=0)
code_bytes, n = cubit.asm("    EXIT ;\n", addr=0)
insns = cubit.decode_kernel("kernel.cubin", "my_kernel")
```

The active ISA table is switchable per process
(`cubit.select_table("sm103a")`) — see
[docs/PYTHON_API_ARCH_SELECT.md](docs/PYTHON_API_ARCH_SELECT.md).

## Examples

See [examples/](examples/) for complete kernels (QMMA GEMV, pipelined MMA,
IMMA U8, sparse GEMV) with host harnesses. On SM120, kernel parameters live
in the regular constant bank: use `LDC` / `LDC.64` for offsets beginning at
`c[0x0][0x380]`; `LDCU` remains appropriate for uniform descriptors such as
`c[0x0][0x358]`.

## Project layout

```
src/       Rust crate (lib + CLI binary)
tables/    ISA bitfield tables and provenance pins
examples/  Tensor-core kernel examples (.sass, host harnesses)
tests/     Encoding roundtrip + assembler integration tests
tools/     ISA table sync and validation scripts
docs/      Guards, emitter, scheduling, and tuning notes
```

## Limitations

- Hardware-validated targets: SM120 (RTX 5090) and SM103a (B300); SM100a and
  SM121A are covered by canonical-parity and fleet-golden evidence
  respectively (no fresh silicon campaign behind either yet — see the Tables
  section for exact gates).
- The ELF companion sections are regenerated by the sovereign emitter; the
  approximated fields are listed in
  [docs/MERC13_COMPANIONS.md](docs/MERC13_COMPANIONS.md).

## Related

- **[blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa)** — the SM120
  ISA database cubit encodes against.
- **[sasskit](https://github.com/kacper-daftcode/sasskit)** — post-compilation
  SASS optimizer built on cubit (mutation search, register recoloring).

## License

MIT — see [LICENSE](LICENSE).
