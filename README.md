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

`tables/sm120.json` originates from the
[`blackwell-isa`](https://github.com/kacper-daftcode/blackwell-isa) database
(base revision and SHA-256 recorded in `tables/SM120_SOURCE.json`). The
vendored snapshot currently also carries a wave of cubit-side canon fixes
(names, mod-group layout, junk-row removal) that have not all flowed back
into the canonical database yet, so byte-pinning to an upstream revision is
temporarily suspended: validation is structural (`tools/sync_table.py
--validate-only`) plus the full Cargo suite, which fails closed on any table
load error. Byte-exact repinning resumes once the upstream consolidation
lands. Tests honor `CUBIT_TABLE` as a strict override: a missing or malformed
override is an error, not a fallback.

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


## Mercury (capmerc) support

```bash
# Parse and dump .nv.capmerc.text.* sections of any sm_100+ cubin
cubit merc-dump kernel.cubin -k my_kernel [--strict]
```

`src/mercury.rs` implements the CUDA-13.x Mercury wire format (kernel ordinal,
instruction-count field, TLV capability records, f(trim-count) tail).
The driver consumes these sections to transcode foreign-arch SASS to native
("Mercury uplift"); on the native path they are inert. Grammar v3 parses
**17,612/17,612 corpus sections (100%)** end-to-end (including tcgen05/FA4-class
sections), with 2-byte separator atoms (`d0 00`/`00 00`), dual-length
51/d1 records and mini-records 41/42 modelled.

Generator: `elf_builder::generate_mercury_full` reproduces nvcc-13.3 sections
byte-exactly for the canonical kernel family (lab gold suite: 50/91 true-equal,
remaining cases enumerated with named residual fields). Rules inside:
`tail = f(trim)` (100% on a 27.8k-kernel corpus), bitmap length
`B = trim - w0 - 2*n_ENDCOLLECTIVE` with w0 = {MEMBAR,ERRBAR,CGAERRBAR,DEPBAR,
LDGDEPBAR,LDGSTS,B2R}; record ordering/param-role/STG-field rules reproduced
from the nvcc emitter pipeline.

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

### Mercury sections and `cubit asm`

`cubit asm` chooses the Mercury layout per kernel automatically:

- Plain kernels keep the static Mercury stub (needed for driver-side
  descriptor/param setup when using `LDG.E desc[…]`/`STG.E`).
- Kernels containing tcgen05/TMA-class instructions (`UTCHMMA`, `UTCQMMA`,
  TMA `UTMALDG`/`UTMASTG`, `UTCBAR`, …) are emitted **Mercury-free** unless
  you pass `--mercury-stub <blob>`: the driver then falls back to analysing
  `.text` directly, which configures resources correctly. Confidence evidence
  (B300, CUDA 13.1): a Mercury-free FA4-class cubin passes
  `cuModuleLoadData` + symbol resolution, and the no-Mercury smoke kernel
  (LDCU/STG/BRA/DEPBAR) runs correctly end-to-end.

## Project layout

```
src/                 Rust crate (lib + CLI binary)
tables/sm120.json    ISA bitfield table (2,001 instruction forms)
tables/sm103a.json   SM103a (B300) bitfield table + cost/stallfix data
tables/SM120_SOURCE.json
                     canonical blackwell-isa revision and table digest
examples/            tensor-core kernel examples (.sass, .cu host harnesses)
tests/               encoding roundtrip + full assembler integration tests
tools/               ISA discovery, synchronization, and validation scripts
docs/                SM120 scheduling and optimization notes
```

## Strict round-trips: `!rsd[...]` residue annotations

Some hardware bits are invisible in nvdisasm-compatible SASS text (convergence
barrier IDs in branch byte 3, F2F mnemod order bits, epoch-window edges, ...).
For those, `disassemble` / `disassemble --frozen` append an explicit annotation:

```
[B------:R-:W-:Y:S05]  @P1 BRA L_2310 !rsd[24:1] ;
F2F.F64.F32 R18, R19 !rsd[75:1,84:0] ;
```

The parser collects `!rsd[b:v, [hi:lo]=0x..]` into `Instruction::rsd`; the
encoder applies it as the **last** overlay stage (after fields, branch/reuse,
scheduling, epoch merge). Result: frozen round-trips are bit-exact *by
construction* on every decodable instruction; `__raw__` remains only for
binary blobs inside `.text`. Default text stays nvdisasm-compatible — the
annotation appears only where fidelity would otherwise be lost, so its count
in a disassembly is a self-measuring table-completeness metric.

## Silicon quirk guards

The assembler knows a set of measured SM120/SM103a silicon traps and guards
them at the source (hard error instead of a silent mis-encode). The ones that
shape how you write SASS:

- **PRMT operand order is hardware order `(d, a, sel, b)`** — the selector is
  operand 3, as `nvdisasm` prints it. PTX spelling `prmt.b32 d, a, b, c` puts
  it last; text written in PTX order used to assemble with sel/b swapped.
- **`IMAD.HI[.U32]` is not encodable on sm_120** — silicon executes harvested
  "HI" words as `IMAD.WIDE.U32` (`Rd` = LOW half, `Rd+1` clobbered). Use
  `IMAD.WIDE[.U32] Rd, Ra, Rb, RZ` and read the high half from `Rd+1`, or the
  5-operand pout form.
- **Predicate index 7 is PT** — literal `P7`/`UP7` and above is a hard
  assembler error; it used to alias to always-true PT silently.
- **Plain `WARPSYNC R<n>` warns on sm_120** — legality depends on the
  surrounding schedule. Use `WARPSYNC.ALL ;`, or rely on intra-warp `STS`→`LDS`
  ordering.
- **Carry-in negation lives on `.X` forms** — a negated carry-in that has no
  bit in the selected form is a hard error, never a silent downgrade.
- **4-operand `IMAD.WIDE*` with `c != RZ` warns** — the c accumulator is the
  64-bit pair `(Rc, Rc+1)`; canonical spellings are the 5-op pout form or
  `c = RZ`.
- **Frozen `DEPBAR`/`MEMBAR` keep their control word** — fully-static barrier
  classes retain the `[B:R:W:Y:S]` prefix on re-encode.
- **REGCOUNT follows driver legality** — clamped to the 255 hardware maximum;
  `--eiattr-from` rebuilds treat the template's REGCOUNT as a floor.
- On sm_103a, odd-base `desc[UR][R.64]` register pairs for LDG/STG/atomics and
  the consumer `IMNMX` class are fail-closed (silicon-illegal there); the
  decoder still reads such words for RE of existing binaries.

`CUBIT_DISABLE_ERRATA=1` disables the guard layer (table-research escape
hatch only — production flows must not need it).

## Limitations

- Primary target: SM120 (RTX 5090/5080/5070 Ti, DGX Spark), validated against
  hardware. A vendored SM103a (B300) table with scheduling data and silicon
  guards ships alongside (`tables/sm103a.json`); other Blackwell-arch tables
  land as their campaigns close.
- Assembly output for `.text` is bit-stable; the ELF companion sections are
  regenerated by the sovereign emitter (see `docs/MERC13_COMPANIONS.md`),
  with known phase-1 approximations documented there.

## Related

- **[blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa)** — the SM120
  ISA database cubit uses for encoding.
- **[sasskit](https://github.com/kacper-daftcode/sasskit)** — post-compilation
  SASS optimizer built on cubit (mutation search, register recoloring).

## License

MIT — see [LICENSE](LICENSE).
