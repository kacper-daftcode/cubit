# HSET2: bounded execution on SM103a and SM100a

Date: 2026-11-11.

## Result

Both independent GPUs completed two selected cases and 22 launches per host,
using the exact original driver that passed all FHADD checks:

- B300 SXM6 AC / SM103a, driver 595.91.07
- B200 / SM100a, driver 580.178.04

Every selected worker completed with canaries, raw inputs, output and echo
observed. No CUDA fault or foreign-process action occurred. These are records
of scoped **SILICON-EFFECT and cross-architecture reproducibility**, not a
complete semantic theorem for the mnemonic `EQ`.

## Dimensions and raw equality

- 11 launches for `plain_f16_h0` per arch: 352 output words on each.
- 11 launches for `plain_bf16_h0` per arch: 352 output words on each.
- For every observation batch, the first packed input word of A equals the
  corresponding first packed input word of B; this was checked 11/11 batches
  per form per host in the completed records.
- Exact output comparison has zero differences on all 352 F16 and 352 BF16
  records across the GPUs. Echo observations also match on every launch.

Raw-output SHA256:

- F16: `8cced12a7cd50ea1f782d181f3bbc6f02b1bfe02f25b5c2d2261fe6422cb2943`
- BF16: `29f6928725e23e426b6b616cd518e7fafcdaf5c1ec715b19e72a453dd1db74db`

The input case metadata remains split: these are two different arch-specific
cubins built by cubit with strict full-instruction validation. Binary-image
similarity is not used as a substitute for the executed value comparison.

## Boundary

The central operation in an already checked 17-instruction, four-pointer frame
was replaced by the selected HSET2 text. Every rebuilt cubin passed both the
assembler and strict roundtrip before loading. Each worker used exactly one
CTA, 32 threads, 1536 own guarded bytes and a bounded subprocess timeout.
There were no free-floating instruction words, unknown addresses or unknown
control-flow mutations.

An initial model that treated `EQ` as straightforward per-halfword equality
against an independently generated non-mirrored dataset produced mismatches.
I did not declare those rows PASS or retrofit a model to fit them. Instead the
execution is explicitly labelled a semantic hypothesis still open: exact raw
input/output is retained, but the operand-role and semantic mapping of this
limited HSET2 form remain to be derived from the actual evidence. No general
comparison set, other booleans, SAT, other half-selectors, NaN-payload law,
performance or timing claim is made.

The accepted payload path is the unchanged FHADD driver from the completed
FHADD measurement (`drive.py`). The only custom data operation in its final
working clone is `domain()` copying `a0` and `a1` into `b0` and `b1` for the
explicit A=B control series. Earlier handmade ctypes/payload wrappers and
rejected assembly variants are separate preparation failures, not numeric PASS
evidence. `EQ.XOR` was not shipped through the conflicting table/parser path.

## Evidence

- `hset-eq-raw/sm103a-f16.json` and `sm100a-f16.json`
- `hset-eq-raw/sm103a-bf16.json` and `sm100a-bf16.json`
- `hset-dual-execution.json`: raw cross-architecture equality, counts and
  accepted echo status.
- `hset-proven-sm103a/build_hset_variants.py` and
  `hset-proven-sm100a/build_hset_variants.py`, selected decoded SASS files and
  exact final `prepare.json`.
- `hset-evaluation.json`: the rejected simpler mask model; not an accepted
  semantic verdict.

FHADD's separate result is in `FHADD_DUAL_REPORT.md`. Nothing here changes
canonical tables, product code, `main` or publication status on its own.
