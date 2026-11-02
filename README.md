# cubit

An assembler and disassembler for NVIDIA Blackwell SASS — the machine code of SM120 (RTX 50-series /
RTX PRO 6000), with tables for SM103a (B300), SM100a (B200) and SM121a (DGX Spark). It encodes SASS
text to 128-bit instruction words, decodes cubins back to text, rebuilds cubins byte for byte, and
assembles stand-alone kernels with their ELF metadata, without `nvcc` or `ptxas`. The instruction
tables come from [blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa), measured against
NVIDIA's `nvdisasm`; the project's own hand-written SM120 kernels have run in production since
2026-06.

**Coverage today (SM120, 2026-11-02).** The strict round trip — decode every word, print it,
re-parse the text, re-encode, compare all 128 bits — passes on **1 811 600 / 1 811 600 instructions**
of the production kernel set it is gated on: 169 cubins of FlashInfer 0.7.2 (sparse-MLA, CAKE
DSV4.1, MXFP8 GEMM), b12x MoE and DeepGEMM SM120 kernels. The whole-cubin path
(`disassemble --frozen` → `asm -T`) reproduces all 157 of those cubins that contain code byte for
byte. Those numbers are the definition of "coverage" used here; what is *not* covered is listed in
[docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## Install

```bash
git clone https://github.com/kacper-daftcode/cubit.git
cd cubit
cargo build --release          # Rust 1.87 or newer; the ISA tables ship in tables/
./target/release/cubit --help
```

No CUDA toolkit is needed to assemble or disassemble. The optional checks against NVIDIA's tools
(`cubit roundtrip`, the probes under `tools/probes/`) use `cuobjdump` / `nvdisasm` from a CUDA 13
installation.

## Quickstart

```bash
# Decode one instruction word (little-endian 128-bit hex) and encode text back
cubit decode 0x000fe200002000007780778068687832
cubit encode "HMUL2.BF16_V2 R104, R104, 5.19229685853482762853e+33, 5.19229685853482762853e+33 ;"

# Disassemble a cubin; --frozen keeps the compiler's schedule as [B:R:W:Y:S] prefixes and
# emits a self-contained .entry (registers, exact parameter layout, shared memory)
cubit disassemble kernel.cubin -k my_kernel
cubit disassemble --frozen kernel.cubin -o kernel.sass

# Rebuild the cubin from that text: byte-identical when nothing was changed
cubit asm -T kernel.cubin kernel.sass -o rebuilt.cubin && cmp kernel.cubin rebuilt.cubin

# Prove coverage on any cubin: every word must survive decode -> text -> encode
cubit roundtrip-strict kernel.cubin --report report.json --failures failures.jsonl

# Assemble a kernel written from scratch (directive format)
cat > add.sass <<'EOF'
.entry add_one
    .reg R0-R7
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R4, 0x1 ;
    STG.E desc[UR4][R2.64], R4 ;
    EXIT ;
.endentry
EOF
cubit asm add.sass -o add.cubin
```

Instruction syntax is NVIDIA's (`nvdisasm` output). On SM120 kernel parameters start at
`c[0x0][0x380]` (`LDC` / `LDC.64`), the global-memory descriptor for `LDG`/`STG` is loaded with
`LDCU.64 URx, c[0x0][0x358]`. The assembler schedules instructions it finds without a control code
(stalls, scoreboard barriers, yields, drains before back edges); a `[B------:R-:W-:Y:S01]` prefix
freezes the control code of that instruction.

## Commands

| command | one line |
|---|---|
| `asm` | assemble a `.sass` file into a cubin; `-T <cubin>` rebuilds a template's ELF around the new code, `--eiattr-from` copies only its metadata |
| `disassemble` | cubin (or host ELF) → SASS text; `--frozen` for re-assemblable text with the exact schedule and `.entry` header |
| `roundtrip-strict` | the coverage proof: every 128-bit word of every code section must decode, print, re-parse and re-encode identically |
| `roundtrip` | the legacy round trip against `cuobjdump` as the reference disassembler |
| `encode` / `decode` / `asm-text` | one instruction or a block of text ↔ instruction words |
| `patch` | disassemble → re-encode → write a patched cubin |
| `ra`, `sched`, `render` | passes over `.sass` text: windowed register renaming / allocation, list scheduling under a cost model, re-printing from the parsed form |
| `stallfix` | raise stalls in hand-scheduled windows to measured silicon floors (sm_103a rules; SM120: [docs/SM120_STALLFIX_PLAN.md](docs/SM120_STALLFIX_PLAN.md)) |
| `merc-dump` | dump the Mercury (`.nv.capmerc`) companion sections |
| `info` | table statistics |
| `validate` | re-encode a harvest records file (needs a private `records.jsonl`; the public table check is `tools/sync_table.py --validate-only`) |

`cubit <command> --help` has the full option list. Errors are fail-closed: an instruction the
encoder cannot prove, a reserved control code, a `.param` layout that disagrees with a template's
metadata, or a register count that would change a template kernel's occupancy stop the run with a
message that names the fix (`--allow-regcount-change`, the declarations to use, …).

### Directive format

```
.entry <name>
    .reg R0-R<n>               # registers the code uses
    .regcount <N>              # optional: the exact EIATTR_REGCOUNT (what --frozen writes)
    .param <type> <name> [offset=0x..] [space=N] [logalign=N]
                               # u8/u16/u32/u64/s*/f16/f32/f64, ptr (8-byte pointer), b8[N] (struct by value)
    .shared [.align A] <name>[<bytes>]
    <instructions, labels, optional [B:R:W:Y:S] control codes>
.endentry
```

A file may hold several `.entry` blocks; they become one multi-kernel cubin.

## Tables

The four architecture tables published by blackwell-isa are vendored byte-exact under `tables/` and
pinned by revision and SHA-256 in `tables/SOURCE.json`; `python3 tools/sync_table.py` re-vendors
and runs the suite, `--check` verifies the pins (CI), `--validate-only` checks structure, extraction
vocabulary, provenance convention and the control-bit ratchet. The tables are data, never edited
here: fixes go to blackwell-isa (`tools/probes/` holds the measurements that produced the SM120 rows
added since 2026-10).

| table | silicon | what the gate proves | not proved |
|---|---|---|---|
| `sm120.json` | RTX 5090 / RTX PRO 6000 (production kernels 2026-06..10) | strict census 1 811 600 / 1 811 600 words, 157 / 157 cubins byte-identical through `--frozen` → `asm -T`, the suite's measured-form fixtures | semantics of rows measured by encoding only ([docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) T6); 19 340 of 20 905 variants are harvest rows (T1) |
| `sm103a.json` | B300 | the suite (encode/decode fixtures, `stallfix` rules, cost model); 323 / 323 cubins byte-exact as of 2026-09-18 | not re-run since (needs the B300 corpus) |
| `sm100a.json` | B200 | encoding layer = SM103a + tcgen05 deltas; 99.92 % exact-minus-schedule on a 20 M-instruction archive as of 2026-08-26 | no B200 silicon run; scheduling data inherited |
| `sm121a.json` | GB10 (DGX Spark) | the suite's GB10 fixtures; 0 decode differences vs SM120 on 648 992 raw instructions as of 2026-09-18 | timing / scheduling data |

Select a table with `-t tables/<arch>.json` or `CUBIT_TABLE`; the output cubin's ELF flags follow the
table.

## Python bindings

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install maturin && pip install -e .     # builds the native extension (verified on Python 3.12, 2026-11-02)
```

```python
import cubit
lo, hi = cubit.encode("IADD3 R5, PT, PT, R9, R4, R5 ;", addr=0)
info = cubit.decode(lo, hi, addr=0)            # key, mod_group, fields ...
code, n = cubit.asm("    EXIT ;\n", addr=0)    # bytes, instruction count
insns = cubit.decode_kernel("kernel.cubin", "my_kernel")
cubit.select_table("sm103a")                   # per-process table switch
```

See [docs/PYTHON_API_ARCH_SELECT.md](docs/PYTHON_API_ARCH_SELECT.md).

## Documentation

- [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) — everything known to be imperfect, with status and what it needs
- [CHANGELOG.md](CHANGELOG.md) — user-visible changes and the table revisions they vendor
- [docs/TESTS.md](docs/TESTS.md) — index of the 425 test files (the `bugNNN` files are the encoder's executable specification)
- [docs/ENCODER_GUARDS.md](docs/ENCODER_GUARDS.md) — the fail-closed guards and the silicon traps behind them
- [docs/MERC13_COMPANIONS.md](docs/MERC13_COMPANIONS.md) — ELF companion sections: what a template rebuild copies, what a standalone build regenerates, what differs from nvcc
- [docs/SM120_CONTROL_OPEX.md](docs/SM120_CONTROL_OPEX.md) — the measured control-code layout and the reserved yield/stall combinations
- [docs/sasstuning.md](docs/sasstuning.md), [docs/nvcc-kloop-reference.md](docs/nvcc-kloop-reference.md) — scheduling notes for hand-written kernels (measured-on-date markers inside)
- [docs/SM120_STALLFIX_PLAN.md](docs/SM120_STALLFIX_PLAN.md), [docs/SCHED_LEGALITY_ORACLE.md](docs/SCHED_LEGALITY_ORACLE.md), [docs/POSTFIX103_STALLFIX.md](docs/POSTFIX103_STALLFIX.md) — scheduling legality
- [tools/probes/README.md](tools/probes/README.md) — the nvdisasm measurements behind the table rows

## Repository layout

```
src/            the crate (library + `cubit` binary)
tables/         vendored ISA tables + SOURCE.json pins (175 MB of JSON: four architectures)
tests/          425 test files (one binary each); tests/fixtures/ = nvdisasm fixtures of measured forms (< 1 MB)
tools/          sync_table.py (vendoring gate), asm_roundtrip.py, audit_table.py, audit_dynamic.py,
                gen_tests_index.py, check_public_surface.sh, probes/ (measurements)
examples/       SASS kernels with host harnesses (QMMA GEMV, pipelined MMA, IMMA U8, sparse GEMV),
                audit_manifest / audit_words / recheck_failures example binaries
test_data/      one SASS source used by the examples' tests
docs/           see above
```

## Limitations

- Encoding evidence is not semantic evidence: a row that round-trips says how `nvdisasm` names a
  word, not what the hardware does with it. Rows measured in 2026-10/11 without execution are
  listed in KNOWN_ISSUES T6.
- `stallfix` has silicon-measured rules for sm_103a only.
- A template rebuild (`asm -T`) copies the template's metadata; a kernel whose registers, shared
  memory or parameters differ from the template needs a standalone build or a matching template.
- The test suite takes about 90 minutes on 16 cores (each of the 425 test binaries loads the 46 MB
  table).
- Open items with their status: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## Related projects

- [blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa) — the ISA databases cubit vendors
  and the generated HTML references.
- [sasskit](https://github.com/kacper-daftcode/sasskit) — post-compilation SASS optimizer for SM120
  built on cubit (mutation search, register recoloring, scheduling analysis).

## License

MIT — see [LICENSE](LICENSE).
