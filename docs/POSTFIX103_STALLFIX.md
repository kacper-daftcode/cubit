# POSTFIX-103 v0 -- `cubit stallfix` (stall-sufficiency legalizer, sm_103a)

BARRACUDA b1 pass landing the STALLSUF-1 silicon facts (B300 census,
2026-08-22, 254 canonical runs): the era stalls S00..S03 are physically
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
