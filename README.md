# cubit

Open-source SASS assembler and disassembler for NVIDIA SM120 (Blackwell).

Assembles, disassembles, schedules, patches, and round-trips SM120 machine code.
100% decode rate across 47,244 instructions. Assembly and disassembly require
no nvcc or ptxas; the `roundtrip` validation command uses `cuobjdump` as an
independent reference oracle.

## Install

```bash
cargo build --release
```

Rust 1.70+. The ISA table (`tables/sm120.json`) ships with the repo.

### ISA table provenance

`tables/sm120.json` is a generated, byte-identical copy of the canonical
[`blackwell-isa`](https://github.com/kacper-daftcode/blackwell-isa) database.
Its pinned source commit and SHA-256 are recorded in `tables/SM120_SOURCE.json`;
do not edit the vendored table directly.

From sibling checkouts, update or verify it with:

```bash
python3 tools/sync_table.py
python3 tools/sync_table.py --check
```

`sync` rejects malformed masks, out-of-range fields, unknown extraction rules,
and baked control/reuse bits, then runs the Cargo suite against the candidate
before replacing the vendored copy. Tests honor `CUBIT_TABLE` and fail on table
load errors instead of skipping.

Release binaries and Python wheels embed the same vendored snapshot as a
working-directory-independent fallback. An explicit `CUBIT_TABLE` remains a
strict override: a missing or malformed override is an error, not a fallback.

## What it does

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

Round-trip is through SASS text: binary → disassemble to text → re-assemble from
text → binary. Bit-exact. This means you can disassemble, edit the SASS in a
text editor, re-assemble, and get a valid cubin back.

Use `--frozen` on disassemble to preserve the original schedule verbatim:

```bash
cubit disassemble kernel.cubin -k my_kernel --frozen > kernel.sass
# edit kernel.sass (schedule is encoded as [B:R:W:S] prefixes per instruction)
cubit asm kernel.sass -o modified.cubin
```

With `--frozen`, the scheduler is bypassed — what you write is what you get.
Without it, cubit re-schedules automatically.

## Scheduling

cubit assigns scheduling metadata (stalls, barriers, yields) automatically.
You write the instructions; it handles the control word.

- dataflow-driven stall assignment (per-pipe latency model from ISA database)
- 6-scoreboard barrier allocation with automatic recycling
- write-after-read barrier insertion for variable-latency instructions (LDG, LDS, LDGSTS)
- QMMA warp-cooperative constraints (stall ≥ 11, yield, no write_bar)
- QMMA drain insertion (UIADD3 URZ to clear wait_mask before tensor-core issue)
- back-edge drain before backward BRA (loop-carried barrier cleanup)
- ctrl_class-aware upper-32 bit generation (epoch handling per instruction class)

No manual scheduling annotations needed. Output verified on RTX 5090.

## Example: standalone SASS kernel

```sass
.entry gemv
    .param u64 d_out
    .param u64 d_a
    .param u64 d_b
    .param u32 K

    LDCU.64 UR14, c[0x0][0x358] ;
    S2R R16, SR_TID.X ;
    LDC.64 R12, c[0x0][0x380] ;
    QMMA.16832.F32.E4M3.E4M3 R8, R0, R4, R8 ;
    EXIT ;
.endentry
```

```bash
cubit asm gemv.sass -o gemv.cubin
# Load with cuModuleLoad + cuLaunchKernel
```

On SM120, kernel parameters live in the regular constant bank: use `LDC` /
`LDC.64` for offsets beginning at `c[0x0][0x380]`. `LDCU` remains appropriate
for uniform descriptors such as `c[0x0][0x358]`.

A `.sass` file can contain multiple kernels (`.entry` / `.endentry` blocks) —
cubit assembles them all into a single multi-kernel cubin.

See `examples/` for complete kernels (QMMA GEMV, pipelined MMA, IMMA U8, sparse GEMV).

## Python bindings

cubit exposes a Python module (via PyO3/maturin):

```bash
pip install -e .   # builds the native extension
```

```python
import cubit

# Encode one instruction → (lo64, hi64)
lo, hi = cubit.encode("IADD3 R5, PT, PT, R9, R4, R5 ;", addr=0)

# Decode → dict with opcode, operands, scheduling fields
info = cubit.decode(lo, hi, addr=0)

# Assemble a block of SASS → (bytes, instruction_count)
code_bytes, n = cubit.asm("""
    S2R R0, SR_TID.X ;
    IADD3 R0, PT, PT, R0, R1, RZ ;
    EXIT ;
""", addr=0)

# Disassemble a cubin kernel → list of dicts
insns = cubit.decode_kernel("kernel.cubin", "my_kernel")
```

## Patching nvcc cubins

When you need the CUDA runtime's ELF metadata (Mercury descriptors, EIATTR) but want
to modify the SASS:

```bash
nvcc -arch=sm_120 -cubin kernel.cu -o kernel.cubin
cubit disassemble kernel.cubin -k my_kernel --frozen > kernel.sass
# ... edit kernel.sass ...
cubit asm kernel.sass --template kernel.cubin -o patched.cubin
```

The patched cubin works with both driver API and runtime API (`cudaLaunchKernel`).
The separate `cubit patch` command is a diagnostic decode/re-encode normalizer;
it does not consume an edited SASS file.

## Project layout

```
src/                 Rust crate (lib + CLI binary)
tables/sm120.json    ISA bitfield table (2,001 instruction forms)
tables/SM120_SOURCE.json
                     canonical blackwell-isa revision and table digest
examples/            tensor-core kernel examples (.sass, .cu host harnesses)
tests/               encoding roundtrip + full assembler integration tests
tools/               ISA discovery, synchronization, and validation scripts
docs/                SM120 scheduling and optimization notes
```

## Limitations

- SM120 only (Blackwell: RTX 5090/5080/5070 Ti, DGX Spark).

## Related

- **[blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa)** — the SM120
  ISA database cubit uses for encoding.
- **[sasskit](https://github.com/kacper-daftcode/sasskit)** — post-compilation
  SASS optimizer built on cubit (mutation search, register recoloring).

## License

GPL-3.0 — see [LICENSE](LICENSE).
