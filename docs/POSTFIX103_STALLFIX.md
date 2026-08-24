# POSTFIX-103 v0 -- `cubit stallfix` (stall-sufficiency legalizer, sm_103a)

Implements the measured SM103a stall-sufficiency facts (B300 hardware
census):  the era stalls S00..S03 are physically
insufficient when the consumer sits in the DIRECTLY next slot (d0).

## Measured floors (DATA: tables/stallfix_sm103a.json)

| path | distance (slots) | min stall on the PRODUCER |
|------|------------------|---------------------------|
| any in-window instruction (R1 global floor) | -- | S04 |
| IMAD(.WIDE).X cout -> IADD3.X cin ("dmix") | d0 | S05 |
| ISETP / any measured P producer -> @Pn/@!Pn guard | d0 | S07 |
| the same, guard consumer | d2 (two between) | S05 |
| the same, guard consumer | d1 (one between) | FORBIDDEN -- FLAKY at every S<=8 under occupancy; no stall legalizes it, the schedule must change |

IADD3.X -> IADD3.X cin chains stay at the R1 floor (census b1dual/b2single:
S04 suffices at d0). At d>=1 plain ALU/P-carry paths pass at S>=1 already,
so they need nothing beyond R1; dmix at d1 needs S03 (also below R1).
Stalls are a 4-bit field; the policy cap is 11 (BUG-036: >=12 hangs).

Producer/consumer classification is the measured v0 allowlist (identical
to the silicon-validated reference postfix_ss.py): producers IADD3.X
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
cubit stallfix --plan plan.json --rules tables/stallfix_sm103a.json \
    [-o out.sass] [--report rep.json] in.sass
# plan.json: {"arch":"sm_103a","kernels":{"<name>":{"windows":[[s,e),...]}}}
```

pyo3: `cubit.stallfix_run(text, plan_json, rules_json) -> (out_text,
per_kernel_reports)` (build with `--features python`). barracuda facade:
`barracuda/stallfix.py` (`stallfix.run(text, plan)`), gates:
`barracuda/gates/ss3_gates.py` (G-SS3a..e; G-SS3a pins byte-identity with
the silicon-validated reference text of results/stallsuf/fss3/).

Parity anchors (sm_103a O3 mulmod windows [20,363) x 3 kernels): 597
raises S03->S04, cubin md5 49efe0fa.., diff vs era cubin = 597 bytes, all
at slot byte 0xd.

## v1: census-hi rules

guard-D1 (exactly one instruction between the P producer and the guard
consumer) is no longer uniformly rejected: it is CLASS-RESOLVED by the
consumer op. All classes below are silicon measurements on B300
(results/stallsuf/F-SS4-CENSUS-HI.md, raw logs results/stallsuf/fss4/raw/);

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

cap_stall=11 is now sm_103a-backed by measurement, not only inherited
from BUG-036: at S12+ the D0 data/isetp dependency classes miscompute
in non-monotonic, class/geometry-dependent pockets on B300.

## v2: uniform-domain census rules R7..R10

Source measurement: results/stallsuf/F-SS2.md (B300 sm_103a idle-window
census, gen_ss.py v3): the UR/UP domain follows "uniform ALU == vector
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
`reg_liveness::reg_xfer` (M3.5 operand_roles.json) and
`pred_liveness::pred_xfer` in Strict mode (M2), restricted to the
measured class allowlist above; unknown families carry no tracked
state and never kill a chain (v0 doctrine). All v2 floors are
window-scoped and raise-only like the rest of the pass; `rules_version`
= "v2". Pre-v2 rules files keep loading (serde defaults = the measured
values).
