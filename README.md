# cubit

Open-source SASS assembler and disassembler for NVIDIA SM120 (Blackwell).

Assembles, disassembles, schedules, patches, and round-trips SM120 machine code.
100% decode rate across 47,244 instructions. No nvcc or ptxas required.

## Install

```bash
cargo build --release
```

Rust 1.70+. The ISA table (`tables/sm120.json`) ships with the repo.

## What it does

```bash
# Assemble SASS to cubin
cubit asm kernel.sass -o kernel.cubin

# Disassemble a cubin back to SASS
cubit disassemble kernel.cubin -k my_kernel

# Round-trip: binary → SASS text → binary (bit-exact)
cubit roundtrip kernel.cubin

# Patch an nvcc-compiled cubin (re-encode SASS, keep ELF metadata)
cubit patch nvcc_kernel.cubin -o patched.cubin

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
non-NOP bitmap of tracked instructions, TLV capability records, f(B) tail).
The driver consumes these sections to transcode foreign-arch SASS to native
("Mercury uplift"); on the native path they are inert. Grammar v1 covers
~91.5% of a 27,790-section corpus (tcgen05/TMA "phase-bitmap" sections like
FA4's are flagged v2 WIP). `elf_builder::generate_mercury_with_ops` emits
spec-conformant sections (historically-tail values verified against nvcc).

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
    LDCU.64 UR6, c[0x0][0x380] ;
    MOV R12, UR6 ;
    MOV R13, UR7 ;
    QMMA.16832.F32.E4M3.E4M3 R8, R0, R4, R8 ;
    EXIT ;
.endentry
```

```bash
cubit asm gemv.sass -o gemv.cubin
# Load with cuModuleLoad + cuLaunchKernel
```

On SM120, kernel params live in the uniform constant bank — use `LDCU`, not `LDC`.
cubit warns if it sees `LDC` reading param offsets in a standalone kernel.

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
cubit disassemble kernel.cubin -k my_kernel > kernel.sass
# ... edit kernel.sass ...
cubit patch kernel.cubin -o patched.cubin
```

The patched cubin works with both driver API and runtime API (`cudaLaunchKernel`).

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
tables/sm120.json    ISA bitfield table (~1,995 instruction forms)
examples/            tensor-core kernel examples (.sass, .cu host harnesses)
tests/               encoding roundtrip + full assembler integration tests
tools/               ISA discovery and validation scripts
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

## Limitations

- SM120 only (Blackwell: RTX 5090/5080/5070 Ti, DGX Spark).

## Related

- **[blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa)** — the SM120
  ISA database cubit uses for encoding.
- **[sasskit](https://github.com/kacper-daftcode/sasskit)** — post-compilation
  SASS optimizer built on cubit (mutation search, register recoloring).

## License

GPL-3.0 — see [LICENSE](LICENSE).
