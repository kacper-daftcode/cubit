# Dual-architecture FP16 silicon evidence, 2026-11-11

## Status and claim boundary

This is a curated evidence bundle for independent and T review. It is not a
canonical ISA adoption, a merge decision, or a Done claim. The GPU observations
are historical measurements from 2026-11-11. The accompanying validation is a
fresh CPU audit of those exact stored bytes; it is not a fresh GPU experiment.

The two independently measured devices were:

| Architecture | Device | Driver | CUDA toolkit readback |
|---|---|---|---|
| SM103a | NVIDIA B300 SXM6 AC | 595.91.07 | 12.8, ptxas V12.8.93, nvdisasm V12.8.90 |
| SM100a | NVIDIA B200 | 580.178.04 | 13.4, ptxas/nvdisasm V13.4.92 |

CUDA readback was performed without a CUDA context at 17:29:55 UTC on
2026-11-11. Both GPUs then reported 0 MiB and no compute applications. These
readbacks are publication context, not replacement measurement timestamps.
The original final records are retained in `gpu-final-sm*.json`, including the
actual timestamps around 12:03 UTC. No GPU process was changed by this work.

## FHADD: scoped non-SAT numerical semantics

Per architecture, 17 raw case files contain 187 completed launches:

| Scope | Cases | Launches per host | Output values per host |
|---|---:|---:|---:|
| FHADD core | 16 | 176 | 5632 |
| Plain BF16 H1 replay | 1 | 11 | 352 |
| Total including explicitly duplicated replay | 17 | 187 | 5984 |

Across the two architectures there are 374 launches, but the cross-architecture
comparison is exactly 5984 matched values per host, not 11968 new observations.
Every compared input, output and echo value matches. The canonical serialized
raw-observation SHA256 is
`079cc0b092252439b71a51627d0c87e1861277809e0fc41d1de400a1f0d28a21`
on both hosts. `verify.py` documents and recomputes that serialization.

For the 16 actual images, non-SAT operation and exercised inputs, each host
matches the independent exact-rational model of full-FP32 addition of the
selected F16/BF16 narrow half and the full FP32 operand. It covers F16/BF16,
H0/H1 and the plain/`RM`/`RP`/`RZ` variants named in SASS. The model implements
plain as round-to-nearest-even, `RM` downward, `RP` upward and `RZ` toward zero.
All 4800 finite results per host match the FP32-wide representation. The
competing `low_zero`, `replicated` and `low_ones` representations have
respectively 4743, 4743 and 4800 mismatches per host. The remaining classified
results per host are 680 NaN and 152 Inf observations. NaN class and Inf
class/sign are checked; NaN payload is preserved but not universalized.

The replay repeats `plain_bf16_h1` through a separately launched new worker.
Its cubin is byte-identical to the original case and all 352 projected input,
output and echo observations match. Files `replay-sm*.json` are byte-for-byte
duplicate archival copies of the corresponding raw replay. Replay is never
counted as new core coverage.

Not established: SAT, other operand roles, other half selectors, sign/absolute
or reuse fields, universal special-value payload behavior, memory/cache
behavior, timing, performance, or support outside the measured images.

## HSET2: bounded effects, semantic model still open

The selected decoded operations are
`HSET2.EQ.AND R10, R2, R4.H0_H0, PT` and
`HSET2.BF16_V2.BF.EQ.AND R10, R2, R4.H0_H0, PT`.
The dataset-only override in `sources/hset-sm_*/model.py` copies `a0/a1` into
`b0/b1`; the unmodified source model is retained as `hset_model_original.py`.
The driver is byte-identical to FHADD's checked driver in both architectures.

The primary A=B series has 22 launches per host, 352 F16 and 352 BF16 outputs
per host, intact canaries, preserved inputs and the expected echo. All 11
batches per form and host explicitly check A=B. The values match across B300
and B200 for both forms.

A separate non-mirrored model-falsification series also has 22 completed
launches per host. It rejects a simple per-halfword IEEE equality mask, with
**9 F16 and 40 BF16 expected-vs-actual mismatches on each host**, each out of
352 outputs. `hset-proven-sm*/` contains that different raw dataset and
`hset-evaluation.json` retains all mismatch records. It is a falsification
series, not extra accepted A=B coverage and not a successful semantic model.
Both stored HSET2 series together represent 44 launches per host, with every
count and digest labelled by series.

### HSET2 hash clarification

`hset-dual-execution.json` and the original `HSET_DUAL_REPORT.md` are preserved
unchanged. Their `sha256_outputs`/`Raw-output SHA256` labels do not specify the
serialization used at the time. Those legacy values are hashes of **nested JSON
batches of lowercase hex strings**, specifically
`json.dumps([obs["out"] for obs in raw_observations]).encode()` with standard
Python JSON separators. They are not byte-packed output hashes.

`VALIDATION.json` derives and identifies both serializations independently:

| Dataset | Serialization | F16 | BF16 |
|---|---|---|---|
| New A=B, `hset-eq-raw/` | legacy nested JSON | `8cced12a7cd50ea1f782d181f3bbc6f02b1bfe02f25b5c2d2261fe6422cb2943` | `29f6928725e23e426b6b616cd518e7fafcdaf5c1ec715b19e72a453dd1db74db` |
| New A=B, `hset-eq-raw/` | packed output words, little-endian u32 | `6ad8bf38170ce8be55741c0bd84cf2fff909b3f23cd26d8e688f39e328e5875a` | `6d708ae82e7d5aad89a63766389365e5a7b9163ee0271dcc3c02171d447b0c72` |
| Non-mirrored, `hset-proven-sm*/` | packed output words, little-endian u32 | `bbd953f5e5119347c7bb52f7b81098aeab306ed29341898f19a44db2b5209982` | `374e9a24e5e9f32fddd9a83e7418fe2f3c0d99648f9834d7ad0ceada65049ba8` |

The original reports' equality statements remain correct. This addendum binds
their hashes to the explicit datasets and encodings rather than silently
changing measurements. No failed Eq prediction is relabelled PASS. `EQ.XOR`,
other comparisons, other half selectors, SAT and timing remain outside scope.

## Harness and address bounds

Every accepted launch used grid `(1,1,1)`, block `(32,1,1)`, four separately
allocated 384-byte buffers, 1536 owned bytes total, a 60-second timeout with a
5-second kill grace, stop-first-error behavior and canaries. Named SASS
instructions load and store only at four actual supplied base pointers.

Each allocation records its concrete base and a 64-byte payload offset. For
input pairs, lane 31 loads bytes `[64 + 31*8, 64 + 31*8 + 8)`, ending at offset
320. For output and echo, lane 31 stores four bytes ending at offset 192. All
fit before the trailing canaries. In the observed launches, allocation starts
are separated by 512 bytes; only the first 384 bytes of each separate
allocation are owned. Gaps are neither used nor counted as the 1536 owned
bytes. The validator checks overlap, exact observed layout, per-lane address
extrema, raw canaries, echo, inputs and cubin identity rather than assuming a
contiguous shared allocation. The raw JSON retains canary verdicts and the raw
payload arrays, not full dumps of every guard word. The offline audit therefore
checks those recorded verdicts and the checked harness; it does not pretend to
remeasure hardware memory safety after the fact.

`text_and_word()` in `verify.py` parses the complete ELF64 headers, checks every
section's file bounds, requires `.text.unpack_probe` to contain exactly 17
instructions and extracts the measured operation at offset `0xd0` rather than
trusting a JSON field alone.

## Fresh CPU validation

From this directory, with Python 3.12 and numpy 1.26:

```sh
python3 verify.py --check VALIDATION.json
python3 manifest.py --check
```

`verify.py` recomputes the FHADD model from raw packed inputs, distinguishes all
8 finite batches from 3 special batches, checks non-SAT class boundaries,
compares raw replay and cross-architecture values, recreates every rejected
HSET2 mismatch record and verifies the final telemetry files. It performs no
CUDA calls and imports no CUDA driver.

The following separately repeats strict re-encoding and vendor/container
inspection, also without CUDA execution:

```sh
python3 cpu_replay.py \
  --cubit /path/to/historical/cubit \
  --tables /path/to/matching/tables \
  --nvdisasm /path/to/nvdisasm \
  --cuobjdump /path/to/cuobjdump
```

For this bundle that replay used cubit commit
`da65fec50178b5540c0698e922315448d11e29f0`, binary SHA256
`16757837d8653d55785eb05ae3dd365a20979ed0399c1dc8e66af1179d383ff2`,
matching table SHA256 values
`cd521b89a7f21da148fbf4f5f18f9243251bbff5ff8ff859af7c8661c036dccb`
(SM103a) and
`a979f673a3f37b0039d793ce434f062b8584c9d38d148093b2e0b516f44f3219`
(SM100a), and CUDA 13.3 V13.3.73 display tools. These are the measurement-time
candidate and matching tables, not a claim that current `main` contains FHADD.

The result is `CPU_REPLAY.json`: all 38 selected cubin paths pass their matching
architecture's strict roundtrip, 646 complete 128-bit comparisons in total.
There are 36 unique cubin hashes because the two replay copies are deliberately
duplicates. All fresh vendor decodes match the original decoded text. The full
container checks find ordinal/offset pairs `(0,0)`, `(1,8)`, `(2,16)`, `(3,24)`,
each size 8, `EIATTR_CBANK_PARAM_SIZE=0x20`, and
`EIATTR_EXIT_INSTR_OFFSETS=0x100`. Per-image `cuobjdump -elf` output is retained
under `cpu-replay/`.

The standalone cubits contain inherited donor notes mentioning an SM120/CUDA
13.1 template. Those notes are not relabelled as target execution evidence.
The final images explicitly identify SM103a or SM100a, use architecture-matched
cubit tables, pass full own-decoder and vendor inspection, contain the correct
entry ABI/EXIT metadata and have separate native execution records. No ELF flag
was flipped to pretend that the wrong B200 donor ran.

## Provenance and excluded preparation

`sources/` preserves selected final builders, SASS, decoded text, prepare JSON,
raw model/driver and executed cubins. Original Linux paths remain in those JSON
files as provenance; new validation and replay entry points are repo-local and
take external historical tool paths explicitly. Raw records reference the
accepted file hashes independently of those original paths.

HSET2 sources under `sources/hset-sm_*` come from the final
`hset-equal-sm_*` working directories. Earlier handoff wording pointing at
`hset-proven-sm*` for `prepare.json` was imprecise: those directories contain
the non-mirrored raw JSON files, while final `prepare.json` and build scripts
are in `hset-proven-sm_*`/`hset-equal-sm_*`; identical relevant cubins were
hash-checked before selection. The mixed prototype/final prepare metadata is
kept intact rather than rewritten as a clean build log.

The original reports retain a rejected wrong-B200-donor CUDA 209 attempt,
driver-preparation failures and the direct-PTX failures as preparation history.
They are not counted as arithmetic observations. This bundle deliberately
excludes the failed donor images, direct-PTX experiments, `hset_probe.py`, old
ctypes/payload experiments, `__pycache__`, unrelated helpers, keys and remote
home-directory trees. `hset-evaluation.json` contains preparation-time reporting
quirks, so `verify.py` independently recreates and compares all its mismatch
arrays instead of trusting the prose verdict.

The retained `audit-sm100a.json` contains an inherited `excluded: SM100
execution` policy label. It is not concealed: actual completed native B200
records in `raw-sm100a/` and `hset-eq-raw/` supersede that inherited label only
for the bounded cases here. Neither audit file is used as a replacement for the
raw records or CPU recomputation.

No GPU JUnit file is claimed or generated. The actual machine-readable products
are `VALIDATION.json`, `CPU_REPLAY.json`, raw per-image container logs,
`MANIFEST.json` and `SHA256SUMS`. `manifest.py --check` recomputes every file's
hash and exact inventory excluding only the two hash-list outputs themselves.
