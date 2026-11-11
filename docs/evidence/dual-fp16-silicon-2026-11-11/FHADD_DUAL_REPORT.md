# Distributed silicon review: FHADD on SM103a and SM100a

Date: 2026-11-11. Owner explicitly delegated access to a physical B300 and a
B200. Each GPU was observed idle immediately before the owned measurements.

## Verified outcome

- B300 SXM6 AC (`SM103a`, driver 595.91.07), host `2e18c3feed2c`
- B200 (`SM100a`, driver 580.178.04), host `fine-hope-falters-fin-03`
- Each host completed **187 bounded launches**, covering 16 forms with all
  four rounding variants and F16/BF16 H0/H1, plus the separately labelled
  plain-BF16-H1 replay. There are **5632 basic numeric observations and 352
  replay observations per host**, with no ignored launch and no CUDA fault.
- Both independent `audit.py` runs return
  **SEMANTICS_PASS_SCOPED_NON_SAT**. The common winning representation is
  wide FP32, and each post-`plain_bf16_h1` replay exactly reproduces 352 raw
  outputs in that host.
- An additional per-index comparison finds **5984/5984 equal raw output
  values across B300 and B200**. The sorted serialized raw-observation SHA256
  is `079cc0b092252439b71a51627d0c87e1861277809e0fc41d1de400a1f0d28a21` on
  both hosts. Replay is reported separately and is not counted as new core
  coverage. The cubin and device metadata are not assumed identical.

## What is actually claimed

For these architecture-specific images and the measured non-SAT domain, the
result is wide FP32 addition of the selected F16/BF16 narrow half with the
full FP32 operand, under the exercised rounding and half-select variants.
Special-value claims are limited to NaN/Inf class and Inf sign; payload bits
are retained in raw output and are not universalized into a NaN-law claim.

**No benchmark, clock, power or timing conclusion is made.** No SAT,
sign/absolute/reuse-field or other instruction-family generalization is added.
B200 is an independent SM100a measurement, not a substitute test of a B300.
The raw files include device, parameter, buffer and echo checks separately.

## Harness and preparation

Every worker used grid 1x1x1, block 32, four owned guarded 384-byte
buffers (1536 bytes), a short subprocess timeout and a stop-first-error rule.
The FHADD input layouts, raw half registers, wide FP32 operand, result store,
exit and independent echo follow the proven prior bounded template. All 17
cubins per arch were assembled standalone with cubit, checked for the actual
LDC/LDG/FHADD/STG/EXIT forms and passed cubit `roundtrip-strict` before any GPU
launch. Complete SASS text has named operations only, no random instruction
words and no free fuzzing.

The SM103a replay is `bcdbdcd697bb48ac0f5dcc2dd2a0bb68827264e1f3e78a597a59c3fbd178a0ab`.
The SM100a replay is `1796c1adbd65aa841168b399c8241b841ef670590c78f2e10f5e3e4be199a2d7`.
Their binary images need not be identical; the tools decoded the correct
target explicitly and rebuilt correct `EIATTR_EXIT` metadata.

Infrastructure attempts kept separate from numeric results:

1. An initial transferred source-driver invocation lacked `case-results`;
   the parent logging failed before a raw result existed. The output directory
   was created and a bounded replay succeeded; it was not counted as a GPU
   compatibility failure.
2. The original donor produced `CUDA 209: no kernel image is available for
   execution on the device` on B200. That is an ELF-compatibility failure,
   not arithmetic evidence. A proper SM100a standalone image replaced the
   wrong image without faking its ELF header or copying stale metadata.
3. Initial direct-PTX mnemonic and template/toolchain attempts failed before
   launch and are not accepted as numeric proof. No stale metadata was
   approved, and no foreign process was killed.

## Artifacts

- `FHDDUAL_BUILD`: `build_fhadd_sass.py`, `probe-cuda/demo.sass`.
- `raw-sm103a/` and `raw-sm100a/`: all 17 raw case JSON files per arch.
- `audit-sm103a.json` and `audit-sm100a.json`: the original independent audit
  summaries; the inherited excluded-policy label is not used as a substitute
  for this later B200-only measurement.
- `compare_arch.py`, `cross-architecture-results.json`: the separate exact-
  value cross-check. `replay-sm103a.json` and `replay-sm100a.json` contain the
  earlier independent 352-value replay check.
- `gpu-final-sm103a.json`, `gpu-final-sm100a.json`: final GPU state.

The prior original B300 donor replay, whose cubin hash is d6b32c90..., is
retained separately. This batch changes no canonical table, PR source or
mainline commit.
