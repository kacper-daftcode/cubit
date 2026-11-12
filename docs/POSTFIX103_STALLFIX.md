# POSTFIX-103 v0 -- `cubit stallfix` (stall-sufficiency legalizer, sm_103a)

Implements the measured SM103a stall-sufficiency facts (B300 hardware
census):  the era stalls S00..S03 are physically
insufficient when the consumer sits in the DIRECTLY next slot (d0).

**The vendored section is v3 since 2026-11** -- the B300 stall-floor measurement, section "v3" at the end of this
file. The v0 / v1 / v2 sections below describe the rule semantics and the census of 2026-08-22 they were written
for; where v3 measured a path again its value replaces theirs (guard d0 7 -> 13 and d2 5 -> 9, the data-class
guard d1, the R2UR in-hop), and the tests of these semantics run on the frozen v2 rule set
(`tests/fixtures/stallfix_sm103a/rules_v2.json`).

## Measured floors of v0 (the census of 2026-08; DATA: the `stallfix` section of tables/sm103a.json)

| path | distance (slots) | min stall on the PRODUCER |
|------|------------------|---------------------------|
| any in-window instruction (R1 global floor) | -- | S04 |
| IMAD(.WIDE).X cout -> IADD3.X cin ("dmix") | d0 | S05 |
| ISETP / any measured P producer -> @Pn/@!Pn guard | d0 | S07 |
| the same, guard consumer | d2 (two between) | S05 |
| the same, guard consumer | d1 (one between) | FORBIDDEN -- FLAKY at every S<=8 under occupancy; no stall legalizes it, the schedule must change |

IADD3.X -> IADD3.X cin chains stay at the R1 floor (measured census:
S04 suffices at d0). At d>=1 plain ALU/P-carry paths pass at S>=1 already,
so they need nothing beyond R1; dmix at d1 needs S03 (also below R1).
Stalls are a 4-bit field; the policy cap is 11 (the census of 2026-08: S>=12 hangs. The measurement of 2026-11
ran every path at S12..S15 without the yield flag and none hung -- see "The cap" under v3).

Producer/consumer classification is the measured v0 allowlist: producers IADD3.X
(dual cout at operands 1/2), ISETP.* (dest at operand 0), ".X"/IMAD.WIDE
forms with cout at operand 1; cin consumers IADD3.X (last two operands)
and IMAD*.X (last operand); guards are non-uniform @Pn/@!Pn. A predicate
redefinition ends the chain (kill). Consumers outside the declaring
window are invisible to v0 -- choose windows carrying whole chains.

## Contract

* Raise-only: a stall is never lowered, B/R/W/Y bits are never touched
  (inputs above the cap are reported, untouched). The emission diff is
  exactly the stall digits of `[B..:R..:W..:Y:Sxx]` (1 byte per raise at
  slot +0xd), proven by a strict re-parse of the output before it is
  returned/written.
* Region contract: every instruction inside a declared window must be
  hand-scheduled (ctrl prefix present); a naked instruction aborts.
* Arch scope lock: plan.arch must equal rules.arch -- the floors are
  sm_103a silicon, not transferable by default.
* Fail-closed: strict parse, unknown kernel in plan, empty/overlapping/
  out-of-range windows, a naked in-window instruction or a guard-D1
  pattern all abort with rc!=0 and produce no output.

## Use

```sh
cubit stallfix --plan plan.json --rules tables/sm103a.json \
    [-o out.sass] [--report rep.json] in.sass
# plan.json: {"arch":"sm_103a","kernels":{"<name>":{"windows":[[s,e),...]}}}
```

pyo3: `cubit.stallfix_run(text, plan_json, rules_json) -> (out_text,
per_kernel_reports)` (build with `--features python`).

Worked example (sm_103a O3 mulmod windows [20,363), 3 kernels): 597 raises
S03->S04, every diff byte at slot byte 0xd — the pass touches stalls and
nothing else.

## v1: census-hi rules

guard-D1 (exactly one instruction between the P producer and the guard
consumer) is no longer uniformly rejected: it is CLASS-RESOLVED by the
consumer op. All classes below are silicon measurements on B300;

the pass invents no physics.

* R6 `isetp` (@P on `ISETP.*`): LEGAL for producer stalls 5..=11
  (det+match, 3 runs x 2 occupancy tiers incl. 296x256 and permuted
  kernel order). The pass floors the producer at
  `guard_d1_isetp_floor` (5) as usual (raise-only, cap 11).
  Producer stall >= `legacy_stall_risk_from` (12): violation -- the
  census bad band (S12/S13 flaky/mismatch; S14/15 clean is a resonance
  pocket, not a policy target).
* `data` (any other ALU consumer): forbidden at every S<=10 (census-hi
  extended the flaky zone 8 -> 10; the S11 clean result replicated 4/4
  but is a probe-geometry island, deliberately NOT a policy floor).
* `atomic` (@P on `ATOM*`/`RED*`): violation independent of stall --
  the guarded-atomic forms are silicon-gated on sm_103a: guarded
  non-EL ATOMG silent-corrupts its target cell even with an
  always-true guard (any stall, 1-warp included), while `.EL`
  hits ILLEGAL_ADDRESS on the default descriptor (form needs the
  descriptor-policy port, not postfix).

Also new: `legacy_stall_risk_from` (12) emits report-only
`high_stall_risk` rows (d0/d2 relations with producer stalls already in
the legacy zone -- postfix cannot lower them, elimination is the
remedy), and `d1_sites` enumerates every D1 pair per kernel with its
class and the action taken. Violations no longer bail at the first
site: the run aborts with the COMPLETE site map (JSON lines) for the
D1-elimination pass. Rules JSON carries `rules_version`; pre-v1 rules
files keep loading (serde defaults = v0 semantics).

cap_stall=11 is backed by sm_103a measurement: at S12+ the D0 data/isetp dependency classes miscompute
in non-monotonic, class/geometry-dependent pockets on B300.

## v2: uniform-domain census rules R7..R10

Source measurement: B300 sm_103a idle-window census: the UR/UP domain follows "uniform ALU == vector
ALU, cross-domain +2, R2UR +4, uniform guard +3".

* R7-urpath (`floor_global`=4): uniform-ALU UR write (UIADD3/UIMAD(.
  WIDE), role class `alu`) read by a same-domain (U-prefixed, `alu`/
  `cmp` class) consumer at d0 -- covers the measured urpath, ucarry
  (UIADD3.X dual-carry) and uwide (UIMAD.WIDE UR-pair) classes. The
  floor is R1's own; R7 adds rule attribution only. D>=1 is free.
* R8-xread (`floor_xread_d0`=6): uniform-ALU UR write consumed by a
  VECTOR op through a UR operand at d0 (measured uxread class).
* R9-r2ur (`floor_r2ur_d0`=8): the R2UR conversion boundary at d0 in
  either direction -- a vector `alu`/`cmp` R write feeding an R2UR
  read, or an R2UR-written UR feeding an `alu`/`cmp` consumer
  (measured usr2ur class; both hops decompose-consistent at S08).
* R10-uguard (`floor_uguard_d0`=10 / `floor_uguard_d1`=8): UISETP UP
  write -> @UP/@!UP guard. Unlike the P-domain guard-D1 pathology,
  the uniform guard at D1 is repairable with stalls (measured clean
  band 8..=11, 2 occupancy tiers, replicated); D2+ is clean at any
  stall. No uniform-guard configuration is ever a hard error.

Detection is data-driven: transfer sets come from
`reg_liveness::reg_xfer` (the `operand_roles` section of the arch table) and
`pred_liveness::pred_xfer` in Strict mode, restricted to the
measured class allowlist above; unknown families carry no tracked
state and never kill a chain (v0 doctrine). All v2 floors are
window-scoped and raise-only like the rest of the pass; `rules_version`
= "v2". Pre-v2 rules files keep loading (serde defaults = the measured
values).

## v3: the B300 stall-floor measurement of 2026-11 (the vendored section)

Since 2026-11 the `stallfix` section of `tables/sm103a.json` is **v3**: floors measured on B300 with the SM120
stall-floor harness of `tools/stallfloor/` ported to sm_103a. One cubit-assembled kernel per (path, distance d,
producer stall S): producer and consumer d one-cycle fillers apart, every other edge at S15 or behind a scoreboard, no
yield flag, 256 pairs per thread; 32 CTAs × 1 024 threads × 20 launches = 655 360 thread-runs per kernel; the reference
of a path is its own kernel with the tested edge behind scoreboard 0, so no CPU model is involved. Floor = the smallest
S with 0 wrong thread-runs such that every larger S is clean as well. Four nights on one B300 of an 8-GPU system
(2026-11-07: 24 paths, 1 176 kernels; -09: 12 paths; -10 and -11: the same 22 paths on both nights), 42 paths in all.
The four raw result files are test fixtures (`tests/fixtures/stallfix_sm103a/`); `tests/stallfix_sm103a_v3.rs`
recomputes every floor from their per-stall counts and holds each key of the section against the paths it stands for.

| path | producer → consumer | d0 / d1 / d2 | nights (2026-11-) | key (rule) |
|---|---|---|---|---|
| `rpath` | `IADD3 R6, PT, PT, R4, R5, RZ` → `IADD3 R8, PT, PT, R6, R5, RZ` | 4 / 0 / 0 | 07, 09, 10, 11 | `floor_global` (R1) |
| `xchain` | `IADD3.X R6, P0, PT, R4, R5, RZ, PT, !PT` → `IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT` | 4 / 0 / 0 | 07 | `floor_global` |
| `lop3` | `LOP3.LUT R6, R4, R5, RZ, 0x3c, !PT` → `IADD3 R8, PT, PT, R6, R5, RZ` | 4 / 0 / 0 | 07, 09, 10, 11 | `floor_global` |
| `mov` | `MOV R6, R4` → `IADD3 R8, PT, PT, R6, R5, RZ` | 4 / 0 / 0 | 09, 10, 11 | `floor_global` |
| `mov_imm` | `MOV R6, 0x80` → `IADD3 R8, PT, PT, R6, R5, RZ` ¹ | 4 / 0 / 0 | 10, 11 | `floor_global` |
| `pcarry` | `ISETP.LT.U32.AND P0, PT, R4, R5, PT` → `SEL R8, R4, R5, P0` | 4 / 0 / 0 | 07 | `floor_pcarry_d0` (R11) |
| `fsetp_sel` | `FSETP.GT.AND P0, PT, R4, R5, PT` → `SEL R8, R4, R5, P0` | 4 / 0 / 0 | 07 | `floor_pcarry_d0`; `pred_producers_op0` |
| `dmix` | `IMAD.WIDE.U32 R6, P0, R4, R5, RZ` → `IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT` | 5 / 0 / 0 | 07 | `floor_dmix_d0` (R2) |
| `guard` | `ISETP.LT.U32.AND P0, PT, R4, R5, PT` → `@P0 IADD3 R8, PT, PT, R4, R5, RZ` | 13 / 11 / 9 | 07 | `measured_guard_d0`, `guard_d1_data_floor`, `floor_guard_d2` (R3) |
| `fsetp_guard` | `FSETP.GT.AND P0, PT, R4, R5, PT` → `@P0 IADD3 R8, PT, PT, R4, R5, RZ` | 13 / 11 / 9 | 07 | the same; `pred_producers_op0` |
| `elect_guard` | `ELECT P0, URZ, PT` → `@P0 IADD3 R8, PT, PT, R4, R5, RZ` | 13 / 11 / 9 | 07 | the same; `pred_producers_op0` |
| `urpath` | `UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ` → `UIADD3 UR9, UPT, UPT, UR8, 0x5, URZ` | 4 / 3 / 0 | 07 | `floor_global` (R7), `floor_urpath_d1` |
| `xread` | `UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ` → `IADD3 R8, PT, PT, R4, UR8, RZ` | 6 / 4 / 2 | 07 | `floor_xread_d0` / `_d1` / `_d2` (R8) |
| `r2ur` | `IADD3 R6, PT, PT, R4, R5, RZ` → `R2UR UR9, R6` | 4 / 0 / 0 | 07 | `floor_r2ur_in_d0` (R9) |
| `r2ur_out` | `R2UR UR9, R12` → `UIADD3 UR10, UPT, UPT, UR9, 0x5, URZ` | 8 / 6 / 4 | 07 | `floor_r2ur_d0`, `floor_r2ur_out_d1` / `_d2` (R9) |
| `uguard` | `UISETP.LT.U32.AND UP0, UPT, UR8, 0x80000000, UPT` → `@UP0 UIADD3 UR9, UPT, UPT, UR9, 0x5, URZ` | 10 / 8 / 6 | 07 | `floor_uguard_d0` / `_d1` / `_d2` (R10) |
| `umov` | `UMOV UR10, UR9` → `UIADD3 UR11, UPT, UPT, UR10, 0x1, URZ` | 0 / 0 / 0 | 07 | `floor_umov_d0` 0: no rule |
| `ffma` | `FFMA R6, R4, R5, R4` → `FFMA R8, R6, R5, RZ` | 4 / 3 / 0 | 07 | `floor_fma_d0` / `_d1` (R13) |
| `fmul` | `FMUL R6, R4, R5` → `FADD R8, R6, R5` | 4 / 3 / 0 | 07 | R13 |
| `fmul2` | `FMUL2 R6, R4.F32x2.HI_LO, R4.F32` → `FADD R8, R7, R6` | 4 / 3 / 0 | 07 | R13 (not tracked: no operand-role row) |
| `hfma2` | `HFMA2 R6, R4, R5, R4` → `HADD2 R8, R6, R5` | 4 / 3 / 0 | 07 | R13 |
| `f2fp_pack` | `F2FP.BF16.F32.PACK_AB R6, R4, R5` → `IADD3 R8, PT, PT, R6, R5, RZ` | 4 / 0 / 0 | 07 | `floor_f2fp_d0` (R14) |
| `f2fp_unpack` | `F2FP.BF16.E2M1.UNPACK_B R6, R4, R5.B0` → `IADD3 R8, PT, PT, R6, R5, RZ` | 4 / 0 / 0 | 07 | R14 |
| `mufu` | `MUFU.RCP R6, R4` → `FFMA R8, R6, R5, RZ` | — / — / — | 07 | `mufu_scoreboard_only` (R16) |
| `imad` | `IMAD R6, R4, R5, RZ` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 07, 09, 10, 11 | `floor_imad_d0` / `_d1` (R12) |
| `imadwide_hi` | `IMAD.WIDE.U32 R6, R4, R5, RZ` → `IADD3 R8, PT, PT, R7, R5, RZ` | 5 / 3 / 0 | 07, 09, 10, 11 | R12 |
| `imad_mov` | `IMAD.MOV.U32 R6, RZ, RZ, R4` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_movs` | `IMAD.MOV R6, RZ, RZ, -R4` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_iadd` | `IMAD.IADD R6, R4, 0x1, R5` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_shl` | `IMAD.SHL.U32 R6, R4, 0x8, RZ` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_hi` | `IMAD.HI.U32 R6, R4, R5, RZ` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_u32` | `IMAD.U32 R6, R4, 0x38, RZ` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_u32_ur` | `IMAD.U32 R6, RZ, RZ, UR8` → `IADD3 R8, PT, PT, R6, R5, RZ` | 5 / 3 / 0 | 09, 10, 11 | R12 |
| `imad_mov_imm` | `IMAD.MOV.U32 R6, RZ, RZ, 0x80` → `IADD3 R8, PT, PT, R6, R5, RZ` ¹ | 5 / 3 / 0 | 10, 11 | R12 |
| `imad_mov_clob` | `IMAD.MOV.U32 R6, RZ, RZ, R4` → `IADD3 R8, PT, PT, R6, R5, RZ` ¹ | 5 / 3 / 0 | 10, 11 | R12 (the control of the constant-load method) |
| `alu_imad_a` | `IADD3 R6, PT, PT, R4, R5, RZ` → `IMAD R8, R6, R5, RZ` | 5 / 4 / 0 | 10, 11 | `floor_alu_imad_d0` / `_d1` (R17) |
| `alu_imad_c` | `IADD3 R6, PT, PT, R4, R5, RZ` → `IMAD R8, R4, R5, R6` | 5 / 4 / 0 | 10, 11 | R17 |
| `lop3_imad_a` | `LOP3.LUT R6, R4, R5, RZ, 0x3c, !PT` → `IMAD R8, R6, R5, RZ` | 5 / 4 / 0 | 10, 11 | R17 |
| `mov_imad_a` | `MOV R6, R4` → `IMAD R8, R6, R5, RZ` | 5 / 4 / 0 | 10, 11 | R17 |
| `imad_imad_a` | `IMAD R6, R4, R5, RZ` → `IMAD R8, R6, R5, RZ` | 4 / 3 / 0 | 10, 11 | `floor_imad_imad_d0` (R12 by consumer class) |
| `imad_imad_c` | `IMAD R6, R4, R5, RZ` → `IMAD R8, R4, R5, R6` | 4 / 3 / 0 | 10, 11 | the same |
| `imadmov_imad_a` | `IMAD.MOV.U32 R6, RZ, RZ, R4` → `IMAD R8, R6, R5, RZ` | 4 / 3 / 0 | 10, 11 | the same |

¹ the register is overwritten at the end of every iteration, so that a constant load has a stale value to tell apart;
`imad_mov_clob` shows that the method reproduces `imad_mov`. — = no stall up to S15 is clean. 0 = clean at every stall.
S00 is clean in every cell of every path, MUFU included: as on SM120 a stall count of 0 behaves as an interlock, not as
"no stall"; it is not a floor and the pass never writes it.

**Against v2** (the census of 2026-08-22, sections above):

* *guard d0* 7 → **13**. S01..S12 are not clean on any of the three predicate producers, S13 / S14 / S15 are. 13 is above
  `cap_stall`, so the pass cannot raise to it: `guard_d0_forbid`, the site is a violation. A producer that already
  stands at `measured_guard_d0` or above **without the yield flag** is the measured control and passes untouched — it
  is also what ptxas writes (below). v2 raised such a producer to S07.
* *guard d2* 5 → **9**.
* *guard d1* stays resolved by the consumer's class. A data consumer takes `guard_d1_data_floor` **11** instead of the
  ban (S01..S10 not clean, S11..S15 clean on the three producers; the census had measured the same clean S11 and
  declined it as an island). An ISETP consumer takes the same 11 (v2: 5) — not measured again: 5 comes from the census
  whose d0 and d2 floors this measurement replaces, and 11 lies inside the band 5..=11 it called legal. Kept from v2
  without a new measurement: the violation for an ISETP consumer behind a producer at `legacy_stall_risk_from` (12) or
  above, the violation for an atomic consumer, and the report-only `high_stall_risk` rows.
* *predicate producers*: `pred_producers_op0` puts FSETP and ELECT next to ISETP in the pass's allowlist — in front of
  the guard they measure ISETP's 13 / 11 / 9, FSETP in front of SEL the same 4 / 0 / 0. A rule set without the key
  tracks ISETP and the carry-outs alone, as before.
* *R2UR*: the vector → R2UR hop is **4** (`floor_r2ur_in_d0`; v2: 8), the R2UR → uniform consumer hop 8 / **6** / **4**
  (`floor_r2ur_d0`, `floor_r2ur_out_d1`, `floor_r2ur_out_d2`; v2: 8 at d0 only).
* *uniform paths at d1 / d2*: `floor_urpath_d1` 3, `floor_xread_d1` 4, `floor_xread_d2` 2, `floor_uguard_d2` 6. The d0
  values and `floor_uguard_d1` are v2's, confirmed (4, 6, 10, 8).
* *new producer classes*: IMAD / IMAD.WIDE data results 5 / 3 (R12 — the display aliases, `.HI`, `.U32` and the
  constant load included), FFMA / FMUL / HFMA2 / FMUL2 4 / 3 (R13), F2FP 4 (R14), UMOV free, MUFU scoreboard only (R16).
* *consumer class* (two nights, the same binaries): the result of a vector ALU instruction read by an IMAD needs **5**
  at d0 — at S04 every one of the 655 360 thread-runs is wrong — and **4** at d1 (R17, `floor_alu_imad_d0` / `_d1`;
  measured producers IADD3, LOP3.LUT, MOV; the IMAD read the value as its multiplicand and as its addend). The result
  of an IMAD read by an IMAD needs **4** at d0 (`floor_imad_imad_d0`, R12 by consumer class), 3 at d1 like every
  consumer. One cycle more when a value crosses between the ALU and the IMAD path, in either direction. R17 raises in
  front of every IMAD form (raise-only: the conservative side); `floor_imad_imad_d0` lowers a pair below its class
  floor and therefore names the measured forms only — `IMAD R, R, R, R` or `IMAD.MOV.U32 R, RZ, RZ, R` in front of
  `IMAD R, R, R, R`.
* *unchanged and confirmed*: `floor_global` 4, `floor_dmix_d0` 5, a predicate read as data 4 / 0 / 0.

**The cap.** `cap_stall` stays 11: the pass writes no S12..S15. That is a policy for what the pass writes, not a
measurement — on B300 these stalls execute without the yield flag and are clean wherever the floor is below them
(every cell of the S12..S15 columns but guard d0 S12 and MUFU). With the yield flag they are not measured. Raising the
cap would let the pass write S13 in front of a guard itself; it would then have to refuse a producer that carries
yield.

**Compiler practice** (a census, not a measurement: nvdisasm 13.3 over 240 sm_103a cubins of compiler output, 619 824
instructions). A predicate producer without a write barrier directly in front of its `@P` guard carries **S13 in 6 377
of 6 377 pairs** (ISETP 5 804, PLOP3 299, ELECT 274); with one or two instructions between, the stalls from the
producer to the consumer sum to 13 or more in 6 160 of 6 160 pairs. LOP3.LUT directly in front of an IMAD that reads
its result: S05 in 2 001 of 2 001 pairs; an IMAD form in front of an IMAD: S04 in 4 707 of 4 931 (S06 218, S07 6).
S12..S15 stand in 9 944 words, none of them with the yield flag (0 of 483 277 yield words carry S00 or S12..S15).

**Not measured**: S12..S15 with the yield flag; guard d1 with an ISETP or an atomic consumer; more than one occupancy
(every kernel ran as 32 CTAs × 1 024 threads; the census of 2026-08 ran 1 × 32, 148 × 256 and 296 × 256); an IMAD
consumer behind a float, F2FP or uniform producer; IMAD → IMAD for the other IMAD forms; FADD / FADD2 / HADD2 / HMUL2
as producers; the tensor chain, loads and stores; PLOP3 as a predicate producer (ptxas stalls it like ISETP; it is not
in the allowlist); sm_100a (no silicon of that target — its table carries no `stallfix` section).

**Found on the way**: `FMUL2` (and `FADD2`, `FFMA2`) have no row in the `operand_roles` section, so the pass tracks
nothing behind them and R13 never names an `FMUL2`. No schedule depends on it today — the float floors (4 and 3) do not
exceed the global floor every in-window instruction gets — but a role row for the packed-FP32 words is missing.
