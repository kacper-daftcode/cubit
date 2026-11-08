# cubit

An assembler and disassembler for NVIDIA Blackwell SASS — the machine code of SM120 (RTX 50-series /
RTX PRO 6000), with tables for SM103a (B300), SM100a (B200) and SM121a (DGX Spark). It encodes SASS
text to 128-bit instruction words, decodes cubins back to text, rebuilds cubins byte for byte, and
assembles stand-alone kernels with their ELF metadata, without `nvcc` or `ptxas`. The instruction
tables come from [blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa), measured against
NVIDIA's `nvdisasm`; the project's own hand-written SM120 kernels have run in production since
2026-06.

**Coverage today (SM120, gated on every push; last 2026-11-06).** The strict round trip — decode every word, print it,
re-parse the text, re-encode, compare all 128 bits — passes on **1 811 600 / 1 811 600 instructions**
of the production kernel set it is gated on: 169 cubins of FlashInfer 0.7.2 (sparse-MLA, CAKE
DSV4.1, MXFP8 GEMM), b12x MoE and DeepGEMM SM120 kernels. The whole-cubin path
(`disassemble --frozen` → `asm -T`) reproduces all 157 of those cubins that contain code byte for
byte. Those numbers are the definition of "coverage" used here; what is *not* covered is listed in
[docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

> **Re-clone notice (2026-11-03).** The repository history was rewritten once to remove a committed
> build directory (195 MB; see CHANGELOG 0.2.0). Clones and forks made before 2026-11-03 do not share
> history with `main` any more: re-clone instead of pulling.

## Install

```bash
git clone https://github.com/kacper-daftcode/cubit.git
cd cubit
cargo build --release          # Rust 1.87 or newer; the ISA tables ship in tables/ (gzip, read in place)
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
freezes the control code of that instruction. `CUBIT_SB_SHARE=1` selects the scoreboard-sharing
colouring (counter semantics, ptxas's practice): bit-identical results on the 84 production MoE
kernels it was measured on and time-neutral there (+0.3 %), 1.6× on scoreboard-starved kernels such
as the sparse-MLA attention; it stays opt-in (KNOWN_ISSUES A13). `CUBIT_RB_CHAIN=1` adds the 2026-06
read-barrier chain on sub-word global loads; with `CUBIT_SB_SHARE=1` it reproduces the shipped speed of
the MC4 MoE prefill kernels (K ≥ 4096) and costs 3–30 % on most others — a per-kernel switch, also
opt-in (KNOWN_ISSUES A19). `CUBIT_MMA_SRC_RB=0` drops the read barrier cubit puts on an MMA for its
source fragments (ptxas sets none; measured 2026-11-06 on the 90 production kernels: bits identical,
time-neutral — the decision whether the rule stays the default is the owner's, KNOWN_ISSUES A22).
`CUBIT_GUARDED_READER_SETTLES=1` lets the first reader of a load settle its write barrier guarded or not
(ptxas's practice; measured 2026-11-06: the 89 production MoE sources are byte-identical under it, V's
sparse-MLA kernel loses 6 prologue waits, bits identical, time within noise — opt-in, KNOWN_ISSUES A24).
`CUBIT_VERIFY=1` runs the read-only scoreboard verifier on every kernel it
assembles (frozen or scheduled) and prints each unprotected RAW / broken WAR; `CUBIT_VERIFY_RBPROBE=1`
adds the read-barrier coverage probe of the legality oracle (`tools/sched_oracle.py`, KNOWN_ISSUES A4).

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
| `stallfix` | raise stalls in hand-scheduled windows to measured silicon floors (sm_103a and SM120 rules; [docs/SM120_STALLFIX_PLAN.md](docs/SM120_STALLFIX_PLAN.md)) |
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

The four architecture tables published by blackwell-isa are vendored byte-exact under `tables/` as
`tables/<arch>.json.gz` (gzip; 0.5–0.9 MB each instead of 38–59 MB of JSON) and pinned by revision
and SHA-256 of the decompressed JSON in `tables/SOURCE.json`. Nothing has to be unpacked: the loader
(`cubit::table::read_table_bytes`, used by the CLI, the Python bindings and the tests) reads
`tables/sm120.json` from the plain file when one exists and from `tables/sm120.json.gz` otherwise
(decompression ≈ 30 ms), and `tools/tablefile.py` does the same for the Python tools. To read the
JSON directly, `python3 tools/sync_table.py --unpack` writes the plain `tables/<arch>.json` files
(git-ignored). `python3 tools/sync_table.py` re-vendors from a blackwell-isa checkout and runs the
suite, `--check` decompresses and verifies the pins (CI; a stale unpacked copy is an error),
`--validate-only` checks structure, extraction vocabulary, provenance convention and the control-bit
ratchet. The tables are data, never edited here: fixes go to blackwell-isa (`tools/probes/` holds
the measurements that produced the SM120 rows added since 2026-10).

| table | silicon | what the gate proves | not proved |
|---|---|---|---|
| `sm120.json` | RTX 5090 / RTX PRO 6000 (production kernels 2026-06..10; probe kernels 2026-11-02/03) | strict census 1 811 600 / 1 811 600 words, 157 / 157 cubins byte-identical through `--frozen` → `asm -T`, the suite's measured-form fixtures; the silicon laws below | semantics of rows measured by encoding only ([docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) T6); 7 of 38 838 variants carry no `_src` at blackwell-isa `89dc967` — every one a documented owner item (the alias-able groups of four mixed keys and the 50-bit `WARPSYNC.COLLECTIVE` immediate; 111 of 38 866 at `7f12b68`, 304 of 38 966 at `37d030f`, 18 841 of 26 598 on 2026-11-06 — the T1 production line of 2026-11-06/08 measured them family by family, [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) T1); their dynamic audit against nvdisasm closed at 0 rows on 2026-11-07 (the former `IMMA.SF` hypothesis is the measured `QMMA.SF` MXINT8 × MXINT8 variant, T5); the cuBLASLt sm_120 corpus on the GB10 host (92 543 words) has two decode holes left, `UFFMA.SAT` and a `UIMNMX.U64` form (the 95 `LDL.64 [R+UR+imm]` holes and the `MUFU` UR-form field were closed 2026-11-04; T1, V3) |
| `sm103a.json` | B300 | the suite (encode/decode fixtures, `stallfix` rules, cost model); re-run 2026-11-03 on the B300 host `cold-face-bounces-fin-02`: 177 / 177 SM103a cubins of the publish corpus byte-identical through `--frozen` → `asm -T` (104 words carried as `__raw__`), strict semantic round trip 77 548 / 77 656 words (coldface's third pass at `52767f9`, 2026-11-06) — the refused words are fail-closed refusals of silicon-unsafe forms (BUG-080 guarded ATOMS, BUG-004 predicate form) plus 2 re-encode residues of text-inert bits (`UMOV URd, 0x0` with a reuse bit; [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) V1, V5) | no silicon run of cubit-assembled SM103a kernels since 2026-09 |
| `sm100a.json` | B200 | encoding layer = SM103a + tcgen05 deltas; re-run 2026-11-03 on `cold-face-bounces-fin-02`: 99.924 % exact-minus-schedule on the archived 20 024 512-instruction sm_100 population (1 134 cubins with a vendor golden), 151 / 151 `cub_100a` cubins byte-identical through `--frozen` → `asm -T`, strict 8 108 / 8 136 words (third pass at `52767f9`, 2026-11-06; one text-inert-bit residue, `I2F.S16` — V5) | no B200 silicon run; scheduling data inherited; until 2026-11-03 cubit mis-read the sm_100a ELF flags as sm_10 (KNOWN_ISSUES A11) |
| `sm121a.json` | GB10 (DGX Spark) | the suite's GB10 fixtures; **re-run 2026-11-04 on the GB10 host `gx4`** (the 2026-09 census script over the 648 992-instruction corpus, 91 927 unique words): 91 927 / 91 927 decode, text parity initially 99.59 % (373 differences). **Closed to 100 % the same day** (session T-4, two batches) and **confirmed by the full re-run at the pushed revision** (`gx4`, 2026-11-05, cubit `2ac57c0`): **91 927 / 91 927 words decode, 1 text mismatch** — `LEPC`, a PC-relative target the isolated-word census renders at address 0 (byte-identical in a full disassembly). **Regression 2026-11-06 → 08: 564 signed FSETP words lost their decode** when a measured-family decoder arm applied to every table while the sm121a harvest rows had no sign fields; **closed 2026-11-08 (T-20) by measuring FSETP / DSETP on `-b SM121`** — 91 927 / 91 927 decode again, 1 text mismatch, strict re-encode 91 887 / 91 927 (the census now runs locally on the 91 927 unique words, `tests/sm121a_fsetp_dsetp.rs` pins the 2 688 family words). `tests/sm121a_parity_20261104.rs`; [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) V3 | timing / scheduling data; no cubit-assembled kernel executed on a GB10 |

Select a table with `-t tables/<arch>.json` (or the `.json.gz` path) or `CUBIT_TABLE`; the output
cubin's ELF flags follow the table.

**SM120 laws measured on silicon** (cubit-assembled probe kernels, driver-API launches, 2026-11-02 on an
RTX 5090 and 2026-11-03/04 on 4x NVIDIA RTX PRO 6000 Server Edition; **re-measured 2026-11-05 on a second
SKU, 2x RTX 5090 / GB202 — every law below holds identically**; logs under the session's `T/gpu/` and
`T/remote/rtx5090/`):

- *Register shadow* (BUG-040/075): a kernel declared at regcount N may use R0..R(N−3); touching
  R(N−2) or R(N−1) faults the launch (`CUDA_ERROR_ILLEGAL_INSTRUCTION`), measured at 64 and 128 with
  the safe pair as control. `asm` warns; kernels that reconfigure registers (`USETMAXREG`) are exempt.
- *`IMAD.WIDE` pairs* (BUG-008): the 4-operand form reads c as the 64-bit pair c:c+1 (nvcc's idiom),
  the 5-operand PT form is the same, c = RZ zero-extends, and an **odd c faults the launch** — the
  encoder refuses it and names the measurement.
- *F2I reuse bits* (BUG-362a): `F2I` words with a reuse bit set execute with the plain result although
  nvdisasm 13.1 and 13.3 refuse to print them; cubit decodes them (nvdisasm is a text oracle).
- *Packed `HMUL2` immediates* multiply like the register form (identity, negation, `.H1_H1` broadcast).
- *Stall floors* for `stallfix`: the measured dependency-path floors (`tables/sm120.json`, `stallfix`
  section, rules v4; [docs/SM120_STALLFIX_PLAN.md](docs/SM120_STALLFIX_PLAN.md) §4). The `r2ur` floor
  was measured 2026-11-04 (silicon v3, warp-uniform kernels) at 4 (= the global floor); a predicate producer
  directly followed by its `@P` guard consumer needs **S13** (v4, 2026-11-05: the S12..S15 band measured,
  S12 still wrong; the same law for a guarded branch); S00 behaves as a hardware interlock. The 26 v3
  floors and the model checks are identical on GB202.
- *Asynchronous forms* (2026-11-05, both SKUs): `ARRIVES.LDGSTSBAR.64.ARVCNT` arrives with
  `cp.async.mbarrier.arrive.noinc` semantics (the form without `.ARVCNT` is net-neutral), `UTMASTG.2D
  [smem, x, y], [tensor map]` stores the tensor-map box at the coordinates, and `LDSM.U4x16P64TO8.M816.2`
  gives lane *l* the four U4 elements of row *l/4*, columns 4·(l mod 4)..+3 of matrix *m* in `Rd+m`
  (zero-extended to bytes; `Rd+2`/`Rd+3` untouched).
- *Driver requirement:* cubit's standalone cubins carry the CUDA-13 ELF identity; a CUDA 12.9 driver
  (575.51.02) crashes in `cuModuleLoad` on it, 580.x drivers load it ([docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) A14).
- *The `.EL` descriptor-pair atomics* (NEEDS 28, 2026-11-05 on the RTX PRO 6000): `ATOMG.E.<op>.EL.STRONG.GPU
  Pd, Rd, desc[URm][Rn.64], Rb` (bits 63 + 76) executes, lands at the 64-bit descriptor address (> 4 GiB) and
  returns the old value like nvcc's non-EL pair — the 2026-03 "silent U32 downcast" was a mis-keyed table row,
  since rebuilt and pinned (KNOWN_ISSUES A15).
- *Atomics return through the write barrier* (BUG-482, 2026-11-05/06): a consumer of the `Rd` of an
  `ATOM*/ATOMG/ATOMS Pd, Rd, …` form that is not covered by the atomic's write barrier reads garbage
  (`0xac0799b5` for the expected `0x100`); the scheduler tracks the destination, the address and the data of
  the family since (A17).
- *`.nv.shared` is the whole per-CTA allocation* (BUG-483, 2026-11-05/06): a 1 KB over-declaration crossed the
  32 KB carveout step at 4 CTAs/SM and made the L1-bound MC4 MoE kernels 1.4–2.0× slower; the section is sized
  exactly now (A18).
- *IADD3 bit 76 is inert on sm_120* (NEEDS 35, 2026-11-06): the word nvdisasm `-b SM103` names `IADD.XOR`
  computes a+b+c on sm_120 silicon — `IADD.XOR` is an sm103a / sm100a row only; the sm120 rows keep the bit
  outside their masks.
- *Multi-register MMA operands are alignment-checked by the hardware* (BUG-037, 2026-06): an A / B / C fragment
  whose first register is off its alignment is `ILLEGAL_INSTRUCTION`; the encoder refuses such text
  (nvdisasm prints it).
- *Read-barrier policies, measured on the 84 production MoE kernels with K's harness* (2026-11-05/06, test
  host RTX PRO 6000): `CUBIT_RB_CHAIN=1` + `CUBIT_SB_SHARE=1` reproduce the 2026-06 speed of `mc4_k4096` /
  `mc4_k6144` (1.38× → 1.01×, 1.61× → 0.96× of the shipped time) and cost 3–30 % on 57 of the other 79 kernels
  (A19 — per-kernel switches, the default is the owner's NEEDS 31); `CUBIT_MMA_SRC_RB=0` changes no bit and no
  measurable time (C/B median 1.000; V's sparse-MLA kernel 1 055 → 1 054 µs) — the MMA-source read barriers are
  free on this set and stay on (A22, NEEDS 38); `CUBIT_GUARDED_READER_SETTLES=1` changes no MoE source and
  removes 6 prologue waits from V's kernel (bits identical, time within the run-to-run band — A24, NEEDS 37).
  Bits identical in every arm.

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
- [docs/TESTS.md](docs/TESTS.md) — index of the 468 test files (the `bugNNN` files are the encoder's executable specification)
- [docs/ENCODER_GUARDS.md](docs/ENCODER_GUARDS.md) — the fail-closed guards and the silicon traps behind them
- [docs/MERC13_COMPANIONS.md](docs/MERC13_COMPANIONS.md) — ELF companion sections: what a template rebuild copies, what a standalone build regenerates, what differs from nvcc
- [docs/SM120_CONTROL_OPEX.md](docs/SM120_CONTROL_OPEX.md) — the measured control-code layout and the reserved yield/stall combinations
- [docs/sasstuning.md](docs/sasstuning.md), [docs/nvcc-kloop-reference.md](docs/nvcc-kloop-reference.md) — scheduling notes for hand-written kernels (measured-on-date markers inside)
- [docs/SM120_STALLFIX_PLAN.md](docs/SM120_STALLFIX_PLAN.md), [docs/SCHED_LEGALITY_ORACLE.md](docs/SCHED_LEGALITY_ORACLE.md), [docs/POSTFIX103_STALLFIX.md](docs/POSTFIX103_STALLFIX.md) — scheduling legality
- [tools/probes/README.md](tools/probes/README.md) — the nvdisasm measurements behind the table rows

## Repository layout

```
src/            the crate (library + `cubit` binary)
tables/         vendored ISA tables (four architectures, gzip: 2.5 MB; 183 MB of JSON unpacked) + SOURCE.json pins
tests/          468 test files (one binary each); tests/fixtures/ = nvdisasm fixtures of measured forms (< 1 MB)
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
- `stallfix` rules are measured for sm_103a (v2) and SM120 (v4, 2026-11-03/05: the v3 floors + the S12..S15
  guard band); the SM120 R2UR boundary floor was measured 2026-11-04 (silicon v3) at 4.
- A template rebuild (`asm -T`) copies the template's metadata; a kernel whose registers, shared
  memory or parameters differ from the template needs a standalone build or a matching template.
- The test suite: `python3 tools/test_suite.py --release` runs the ~470 test binaries in parallel and finishes in about
  2 minutes on 16 cores (2026-11-06; the same passed / failed / ignored totals as `cargo test`); plain `cargo test --release`
  runs them one after another in about 12 minutes (parsed tables are cached per process from their second load on).
- A shipped cubin is reproduced byte for byte from its frozen text (`disassemble --frozen` →
  `asm -T`); re-assembling its `.sass` source with a newer cubit is a regeneration whose control codes
  follow the current allocator (KNOWN_ISSUES A20).
- Open items with their status: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## Related projects

- [blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa) — the ISA databases cubit vendors
  and the generated HTML references.
- [sasskit](https://github.com/kacper-daftcode/sasskit) — post-compilation SASS optimizer for SM120
  built on cubit (mutation search, register recoloring, scheduling analysis).

## License

MIT — see [LICENSE](LICENSE).
