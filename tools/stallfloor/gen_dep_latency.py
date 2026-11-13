#!/usr/bin/env python3
"""Build cubit's sm_120 dependency-latency table (tables/dep_latency_sm120.json) from
  (1) ptxas's practice: the pair matrix mined from the frozen sm_120 census (dep_latency_census.py) — for every dense cell
      (producer class, consumer class, operand role) the minimum issue distance ptxas ever schedules, and
  (2) stall floors measured on sm_120 silicon (tools/stallfloor): a measured floor above the census minimum raises the cell;
      a measured floor below it is recorded (`silicon`) but the cell keeps ptxas's value (never below the vendor's practice).

  (3) the result register read (--result-census, --result-floors): the upper register of a multi-register result is priced
      apart for the producers of RESULT_HIGH. Its readers get their own cells (`result_high.cells`), mined from the census
      split by result register (result_register_census.py) with the rule of (1); a reader without such a cell keeps the
      pair's cell but never less than the largest floor measured for an upper register (`result_high.floor`). The cells
      of (1) and (2) are not touched by it: a binary that does not know `result_high` reads the table as before.
  (4) producer FORMS priced apart from their class (PRODUCER_FORMS -> `producer_forms`): the result of such a form is never
      read closer than the entry's L in any register / address role, except in the (consumer, role) pairs the entry names.
      It is written as it stands here (no census input); the cells of (1) - (3) are not touched by it.
  (5) cells written out (WRITTEN_CELLS): a pair the census walk does not see (the certified operand sets have no rule for
      the producer) and that is priced by ptxas's distance and a measured floor -- the cell stands here with its evidence.
  (6) cells on a measured floor (MEASURED_MIN_CELLS): ptxas's census MINIMUM of a pair to which rule (1) gives no cell
      (fewer than MIN_AT pairs at the minimum) or a clamped one (a minimum below the global floor of 4) -- taken only where
      a probe of this directory measured the pair's floor at or below that minimum on BOTH card models. The cell is the
      census minimum, never the floor: cubit does not stand closer than ptxas ever does. The generator reads the census row
      and the probe's result files and refuses an entry they do not carry.
  (7) a pair row of a --floors file that names what superseded it (key `superseded`: the pair's own kernels measured
      nothing, its `floor_d0` is another measurement's): the cell's `silicon` sentence is the one written here
      (SUPERSEDED_SILICON), not `floor d0 S<nn>`; such a row without a sentence stops the run.

usage: gen_dep_latency.py census_pairs.json out.json [--floors pair_floors.json ...] [--v6 cells.json ...]
                          [--mma-registers file] [--result-census census_pairs_result.json --result-floors floors.json]
"""
import sys, json, argparse, collections, os

VARIABLE = ["LDG", "LDS", "LDSM", "LDL", "LDC", "LDCU", "LD", "LDGSTS", "S2R", "S2UR", "MUFU", "SHFL", "ATOM", "ATOMG", "ATOMS",
            "RED", "REDG", "REDUX", "I2F", "F2I", "FLO", "POPC", "B2R", "TEX", "TLD", "TXQ", "LEPC", "GETLMEMBASE", "LDTM",
            "UTCATOMSWS"]
MMA = ["HMMA", "QMMA", "IMMA", "DMMA"]
MIN_N, MIN_AT = 50, 8
MAX_TIGHT = 7     # a fixed-latency ALU pair is never above 7 (-> MMA fragment) in the census' dense spikes
# producers whose upper result register is priced apart: the two halves of a 64-bit product are not ready together
# (silicon: the low register is readable from 1-3 issue cycles, the high one from 3-5; ptxas: low from 3, high from 4 / 5)
RESULT_HIGH = ["IMAD.WIDE"]
# producer FORMS priced apart from their class: the class of the table plus the modifiers the form does NOT carry. The
# class `CS2R` does not tell the 64-bit form (a register pair) from `CS2R.32`; silicon reads the pair form's result right
# from 6 issue cycles with one cycle closer wrong -- the table's default, with no margin --, and ptxas never reads it
# closer than 7: the form takes ptxas's 7 in every register / address role. The data of a shared-memory store (floor 3)
# keeps the default, and the 32-bit form keeps the class's cell, until their forms are measured.
PRODUCER_FORMS = [
    {"producer": "CS2R", "without": [".32"], "L": 7,
     "except": [{"consumer": "STS", "role": "r1"}],
     "basis": "ptxas: 22 116 of the census's 22 140 CS2R words are the 64-bit form (`CS2R Rn, <SR>` without `.32`: a "
              "register pair); no reader of either result register stands closer than 7 behind one (188 readers within 12 "
              "issue cycles: 26 at exactly 7 -- IMAD 20, STS 4, MUFU 2 --, 36 at 8); the other 24 words are the 32-bit form "
              "(`CS2R.32 Rn, SR_CgaSize` -> IMAD at 5), which is not this form and keeps the cell of the class",
     "silicon": "floor 6 into FMUL r2, FADD r1, LOP3 r1 (either result register), MOV r1, SHF r3 (the second register) "
                "and IADD r1 (the first) -- tools/stallfloor probe_sm120_20261111_b33 and its two _ws_ files: a Server "
                "Edition card, a Workstation Edition card alone and at its 400-W limit, 6 | 6 | 6, right at 6 / 7 / 8 / 11 / 26 "
                "on every grid, not right at 5 -- and into IMAD r1 / IADD3 r1 / LOP3 r1 (probe_sm120_20261110_b3, Server): the "
                "default 6 is the floor itself, without a margin -- a trial floor, not a number of this table; -> STS data "
                "floor 3 | 3 | 3 (probe_sm120_20261111_b35 and its _ws_ files): the exception keeps the default 6"},
    {"producer": "CS2UR", "without": [], "L": 6, "except": [],
     "basis": "ptxas: the 190 CS2UR words of the census (each a read of the global timer in the timeout check "
              "of a spin-wait) carry no write barrier and have their first reader 6 issue cycles behind them "
              "(184) or 16 (6), never closer",
     "silicon": "a reader closer than 6 takes the register's old content: `CS2UR UR6, SRZ` and `CS2UR.32` into "
                "MOV and into the low word of IADD.64 not right at 1 .. 5, right from 6 (two card models -- a "
                "Server Edition card, tools/stallfloor/probe_sm120_20261112_b53.json, and a Workstation "
                "Edition card alone and at its 400-W limit, "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_alone.json / "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_capped.json, the same floors; six grids, with and "
                "without the yield flag; the high word from 5, UIADD3 from 4 -- measurements, not numbers of "
                "this table); a write barrier on the word and a wait on its reader change no count: the word "
                "has no scoreboard result"},
]
# cells written out as they stand: the census walk has no row for the pair (the certified operand sets do not know the
# producer), ptxas's distance and the measured floor are the evidence
WRITTEN_CELLS = [
    {"producer": "CS2UR", "consumer": "IADD", "role": "u2", "L": 6,
     "basis": "ptxas: every CS2UR word of the vendor's sm_120 kernels is a read of the global timer for the "
              "timeout check of a spin-wait, none carries a write barrier, and its first reader -- `IADD.64 R, "
              "-R, UR` -- stands 6 issue cycles behind it or later, never closer",
     "silicon": "floor 6 on two card models (a Server Edition card, "
                "tools/stallfloor/probe_sm120_20261112_b53.json, six grids, with and without the yield flag; a "
                "Workstation Edition card alone and at its 400-W limit, "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_alone.json / "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_capped.json: the same floor): the low word into "
                "IADD.64 and the result into MOV not right at 1 .. 5, right from 6; a write barrier on the "
                "word and a wait on its reader change no count -- the cell is the floor itself, without a "
                "margin"},
]
# cells on a measured floor: ptxas's census MINIMUM of a pair that the dense-cell rule leaves to a default (fewer than MIN_AT
# pairs at the minimum) or clamps (a minimum below 4), where a probe measured the pair's floor at or below that minimum on
# both card models (`request` in every file of `probe_files`: a Server Edition card, a Workstation Edition card alone and
# at its power limit). The number of the cell is read off the census row; an entry the files do not carry stops the run.
# the `silicon` sentence of a cell whose pair row carries the key `superseded` (rule (7)): what the newer measurement says
SUPERSEDED_SILICON = {
    ("ISETP", "ISETP", "p"): (
        "a prohibition below 5 on two card models (a Server Edition card and a Workstation Edition card, "
        "tools/stallfloor/probe_sm120_20261112_b61.json and its two _ws_ files: the consumer takes the old "
        "predicate -- at 1 ... 3 issue cycles no thread-launch is right, at 4 at most 7264 of 73584640, from "
        "5 every one); the pair isetp_isetp of stall_floors_sm120_20261110_pairs.json (floor 1) measured "
        "nothing"),
}
MEASURED_MIN_CELLS = [
    {"producer": "UMOV", "consumer": "MOV", "role": "u1", "request": "pu_umov_mov_u1",
     "probe_files": ["probe_sm120_20261111_b46.json", "probe_sm120_20261111_b46_ws_2eabe5dcdba4_alone.json",
                     "probe_sm120_20261111_b46_ws_2eabe5dcdba4_capped.json"],
     "form": "`UMOV UR, imm` -> `MOV R, UR`"},
]
PRODUCER_FORMS_COMMENT = (" `producer_forms`: the result of a producer FORM named there -- the class plus the modifiers the form"
                          " does not carry (`CS2R` without `.32` = the 64-bit form, a register pair) -- is never read closer than"
                          " the entry's L in any register or address role: the larger of L and the pair's cell or default; the"
                          " (consumer, role) pairs of `except` keep their cell or default (a trailing h of the role is ignored).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("census")
    ap.add_argument("out")
    ap.add_argument("--floors", nargs="*", default=[])
    ap.add_argument("--census-desc", default="166 nvcc / ptxas cubins of the production sm_120 census (FlashInfer, DeepGEMM, "
                    "b12x, CUTLASS MXFP8), 1 811 600 instructions, cubit disassemble --frozen; fixed-latency producer -> "
                    "consumer pairs on fall-through paths")
    ap.add_argument("--v6", nargs="*", default=[], help="results of the population harness (cellfloor_run.py cells.json)")
    ap.add_argument("--mma-registers", help="MMA result register k -> an ordinary reader, per register "
                    "(mma_result_registers_sm120_*.json): the `to_data` row must hold every register's floor")
    ap.add_argument("--result-census", help="the census split by RESULT register (result_register_census.py): "
                    "cells for the readers of an upper register of the producers in RESULT_HIGH")
    ap.add_argument("--result-floors", help="silicon by result register (stall_floors_sm120_20261110_em_blk3.json: "
                    "IMAD.WIDE low / high register -> reader, either register of the pair form of CS2R -> reader)")
    a = ap.parse_args()
    assert bool(a.result_census) == bool(a.result_floors), "--result-census and --result-floors go together"
    rows = json.load(open(a.census))
    cells = {}
    skipped = collections.Counter()
    for r in rows:
        p, c, role = r["prod"], r["cons"], r["role"]
        if p in VARIABLE or p in MMA:
            skipped["variable/mma producer"] += 1
            continue
        if role == "r?":
            skipped["unknown role"] += 1
            continue
        if r["n"] < MIN_N or r["n_min"] < MIN_AT:
            skipped["sparse"] += 1
            continue
        L = r["min"]
        if role in ("g", "gc"):
            if L > 15:
                skipped["never tight"] += 1
                continue
            L = max(L, 5)
        else:
            if L > MAX_TIGHT:
                # the pair never occurs tightly in the census: its minimum is the shape of the code, not a latency -> default
                skipped["never tight"] += 1
                continue
            L = max(L, 4)                  # floor_global of the 2026-11-03 silicon run; late-read operands are not modelled
        cells[(p, c, role)] = dict(L=L, n=r["n"], n_min=r["n_min"], census_min=r["min"])
    # cells on a measured floor (MEASURED_MIN_CELLS): the census minimum, checked against the census row and the probe's files
    by_key = {(r["prod"], r["cons"], r["role"]): r for r in rows}
    here = os.path.dirname(os.path.abspath(__file__))
    measured_min = {}
    for m in MEASURED_MIN_CELLS:
        key = (m["producer"], m["consumer"], m["role"])
        r = by_key[key]
        assert key not in cells or cells[key]["L"] > r["min"], f"{key}: the dense-cell rule gives {cells.get(key)} already"
        floors, models = [], set()
        for fn in m["probe_files"]:
            req = [q for q in json.load(open(os.path.join(here, fn)))["requests"] if q["id"] == m["request"]]
            assert len(req) == 1, f"{key}: {fn} has {len(req)} requests `{m['request']}`"
            fl = req[0]["floor"]
            assert isinstance(fl["binding"], int) and fl["binding"] <= r["min"] and not fl["oracle_failures"] and not req[0]["errors"], \
                f"{key}: {fn} does not carry a floor at or below the census minimum {r['min']}: {fl}"
            floors.append(fl["binding"])
            models.add("workstation" if "_ws_" in fn else "server")
        assert models == {"server", "workstation"}, f"{key}: a cell on a measured floor needs both card models, not {models}"
        why = (f"fewer than {MIN_AT} pairs at the minimum" if r["n_min"] < MIN_AT else "fewer pairs than a dense cell needs" if r["n"] < MIN_N
               else "a minimum below the global floor of 4")
        measured_min[key] = {
            "producer": key[0], "consumer": key[1], "role": key[2], "L": r["min"],
            "basis": f"ptxas census min {r['min']} x {r['n_min']} of {r['n']} pairs -- no dense cell ({why}: the pair took the default); "
                     f"the census minimum is the cell because the pair's floor is measured at or below it on both card models "
                     f"(never closer than ptxas ever stands)",
            "silicon": f"floor {' | '.join(str(f) for f in floors)} for the form {m['form']} -- tools/stallfloor "
                       f"{m['probe_files'][0][:-len('.json')]} (request `{m['request']}`) and its _ws_ files: a Server Edition card, a "
                       f"Workstation Edition card alone and at its 400-W limit; the cell is ptxas's minimum, not the floor"}
        cells.pop(key, None)
    # MMA rows, written out explicitly (census: HMMA -> HMMA accumulate 29 x 2 368, HMMA -> FADD / FMUL 28; any MMA -> MMA 16)
    out_cells = []
    for (p, c, role), v in sorted(cells.items()):
        out_cells.append({"producer": p, "consumer": c, "role": role, "L": v["L"],
                          "basis": f"ptxas census min {v['census_min']} x {v['n_min']} of {v['n']} pairs"})
    for w in WRITTEN_CELLS:
        assert (w["producer"], w["consumer"], w["role"]) not in cells and (w["producer"], w["consumer"], w["role"]) not in measured_min
        out_cells.append(dict(w))
    out_cells += [measured_min[k] for k in sorted(measured_min)]
    doc = {
        "arch": "sm_120",
        "schema": 1,
        "comment": "Fixed-latency dependency table of cubit's opt-in dependency-aware stall model (CUBIT_SCHED2_LAT). L = "
                   "minimum issue distance in stall units (sum of the stall counts from the producer to the consumer on "
                   "every control-flow path) between a producer WITHOUT a write barrier and a consumer reading its result "
                   "in the given operand role. role: r<k> / a<k> = register / address-base operand at position k among the "
                   "non-predicate operands (destination = 0), u<k> = uniform register, p = predicate operand, g = guard, "
                   "gc = guard of a control-flow instruction, * = any role; a trailing h = a register above the named one of a "
                   "multi-register operand (the high half of a 64-bit addend / address: read later than the low half).",
        "provenance": {
            "census": a.census_desc,
            "dense_cell": f">= {MIN_N} pairs, >= {MIN_AT} at the minimum, minimum <= {MAX_TIGHT} (guards <= 15); every other pair takes a default",
            "silicon": [],
        },
        "defaults": {
            "data": 6, "mma_input": 7, "guard": 13, "pred_operand": 6, "uniform": 13,
            "comment": "cells the census does not show densely: the largest dense value of the kind (ALU data 6 = MOV -> SEL "
                       "false operand / SEL -> IMAD.WIDE addend; -> MMA fragment 7; predicate -> guard 13; uniform 13 = R2UR)",
        },
        "mma": {"classes": MMA, "to_mma_accumulate": 29, "to_data": 28,
                "comment": "MMA result (never scoreboarded): -> the C operand of an MMA 29 (census 2 368 at 29, never less on a "
                           "chain), -> any other consumer 28 (census: HMMA -> FADD / FMUL 28). Silicon 2026-11-10 (harness "
                           "v5b, 20 launches): HMMA -> FMUL floor 20; the accumulate operand of the next HMMA and two "
                           "HMMAs back to back are clean at every distance 1..30 (the tensor pipe interlocks them) -- "
                           "the rows keep ptxas's spacing"},
        "resources": [
            {"name": "mma", "members": MMA, "spacing": 16, "basis": "census: two MMAs never closer than 16 (7 060 HMMA / 5 351 QMMA pairs at 16)"},
            {"name": "mem", "members": ["LDS", "LDSM", "STS", "STSM", "LDG", "STG", "LDL", "STL", "LD", "ST", "LDGSTS", "SHFL",
                                        "ATOM", "ATOMG", "ATOMS", "RED", "REDG"], "spacing": 4,
             "basis": "census: memory-pipe instructions with anything between them never closer than 4 (47 975 at 4)"},
            {"name": "ldc", "members": ["LDC"], "spacing": 8, "basis": "census: LDC -> LDC 8 (1 209 adjacent, 2 172 non-adjacent at 8, never less)"},
            {"name": "mul", "members": ["IMAD", "IMAD.WIDE", "IMAD.HI"], "spacing_by_first": {"IMAD": 2, "IMAD.HI": 2, "IMAD.WIDE": 4},
             "basis": "census: IMAD -> IMAD / IMAD.WIDE 2 (5 345 / 3 678 adjacent at 2), IMAD.WIDE -> IMAD / IMAD.WIDE 4"},
            {"name": "bar", "members": ["BAR"], "then": {"mem": 6, "bar": 8},
             "basis": "census: BAR -> shared / global memory 6 (BUG-479: S05 fails on silicon), BAR -> BAR 8"},
        ],
        "barrier_arm": {"cycles": 2, "basis": "census: 0 of ~70 000 scoreboard setter -> first waiter pairs closer than 2 "
                        "(write barriers: MUFU 5 989 at 2, SHFL 10 096, LDS 3 360, I2F 2 520 ...; read barriers 3 443 at 2); an adjacent "
                        "waiter always finds the setter at S02 or more. Silicon 2026-11-10: `MUFU [W:Y:S01]` + waiter at S01 reads the "
                        "stale register (sparse_mla_prefill_v41 under CUBIT_SCHED2: softmax exp2, epilogue log2); in isolation "
                        "(harness v5b): MUFU / SHFL / LDC / LDS setter with yield at S01 and its waiter next = every thread wrong, "
                        "without yield, at S02 or with one instruction between = clean"},
        "variable_latency": VARIABLE,
        "cells": out_cells,
    }
    # silicon floors: {"cells": [{"producer","consumer","role","floor_d0", ...}], "run": "..."}
    idx = {(c["producer"], c["consumer"], c["role"]): c for c in out_cells}
    for fp in a.floors:
        fl = json.load(open(fp))
        doc["provenance"]["silicon"].append(fl.get("run", fp))
        for f in fl["cells"]:
            key = (f["producer"], f["consumer"], f["role"])
            floor = f["floor_d0"]
            c = idx.get(key)
            if c is None:
                # no dense census cell: the pair keeps the default; the floor is on record only
                doc["provenance"].setdefault("measured_without_cell", []).append(
                    {"producer": key[0], "consumer": key[1], "role": key[2], "floor_d0": floor})
                continue
            elif isinstance(floor, int) and floor > c["L"]:
                c["basis"] += f"; RAISED from {c['L']} by the silicon floor"
                c["L"] = floor
            if f.get("superseded"):
                if key not in SUPERSEDED_SILICON:
                    raise SystemExit(f"{fp}: the row of {' / '.join(key)} names what superseded it and SUPERSEDED_SILICON has no sentence for its cell")
                c["silicon"] = SUPERSEDED_SILICON[key]
                continue
            c["silicon"] = (f"floor d0 S{floor:02d}" if isinstance(floor, int) else str(floor)) + (f" ({f['note']})" if f.get("note") else "")
    # population harness v6: per cell, kernels at the tested latency Lt and at Lt - 1 (random registers / yield / neighbours)
    for fp in a.v6:
        v6 = json.load(open(fp))
        doc["provenance"]["silicon"].append(v6.get("run", fp))
        per = collections.defaultdict(dict)
        for c in v6["cells"]:
            per[c["cell"]][c["rel"]] = c
        for cell, d in per.items():
            p, rest = cell.split(" -> ")
            cc, role = rest.rsplit(" ", 1)
            c = idx.get((p, cc, role))
            at, below = d.get(0), d.get(-1)
            if at is None:
                continue
            Lt = at["L"]
            note = f"v6 S{Lt:02d}: {at['failing']}/{at['kernels']} kernels fail"
            if below is not None:
                note += f", S{Lt - 1:02d}: {below['failing']}/{below['kernels']}"
            if c is None:
                # a defaulted pair: the default was tested, no cell is created from it; the floor the sweep shows (the
                # smallest tested stall that is clean with every larger one clean) goes on record
                clean = sorted(Lt + rel for rel, x in d.items() if x["failing"] == 0)
                dirty = [Lt + rel for rel, x in d.items() if x["failing"]]
                floor = min((st for st in clean if all(st > b for b in dirty)), default=None)
                if floor is not None and dirty:
                    doc["provenance"].setdefault("measured_without_cell", []).append(
                        {"producer": p, "consumer": cc, "role": role, "floor_d0": floor, "harness": "v6"})
                continue
            if at["failing"] and c["L"] <= Lt:
                # the tested latency fails on silicon and the cell is not above it: never ship that
                c["basis"] += f"; RAISED from {c['L']} (fails on silicon at S{Lt:02d}) to the data default"
                c["L"] = max(Lt + 1, doc["defaults"]["data"])
            c["silicon"] = (c.get("silicon", "") + "; " if c.get("silicon") else "") + note
    if a.result_census:
        result_high(a, doc, idx)
    doc["comment"] += PRODUCER_FORMS_COMMENT
    doc["producer_forms"] = PRODUCER_FORMS
    out_cells.sort(key=lambda c: (c["producer"], c["consumer"], c["role"]))
    if a.mma_registers:
        mr = json.load(open(a.mma_registers))
        # floor of a result register = one above the last distance at which a reader saw a wrong value
        floors = collections.defaultdict(int)
        for fl in mr["floors"]:
            if fl["last_wrong"] is not None:
                floors[fl["result_register"]] = max(floors[fl["result_register"]], fl["last_wrong"] + 1)
        worst = max(floors.values())
        assert doc["mma"]["to_data"] >= worst, f"MMA -> reader row {doc['mma']['to_data']} below a measured floor {worst}"
        by_floor = collections.defaultdict(list)
        for r, fl in sorted(floors.items()):
            by_floor[fl].append(str(r))
        per = "; ".join(f"result register{'s' if len(rs) > 1 else ''} {' / '.join(rs)}: wrong up to {fl - 1}, clean from {fl}"
                        for fl, rs in sorted(by_floor.items()))
        old = "HMMA -> FMUL floor 20; "
        assert old in doc["mma"]["comment"]
        doc["mma"]["comment"] = doc["mma"]["comment"].replace(
            old, f"HMMA -> FMUL floor 20 on result registers 0 and 1; a second probe (result register k -> FMUL / FADD, "
                 f"nothing waited, distances 23..32): {per} -- `to_data` is the floor of the upper registers, without a "
                 f"margin; ")
        doc["provenance"]["silicon"].append(
            f"MMA result registers ({mr['what']}), {mr['geometry']}, core clock <= 2 370 MHz, 2026-11-10: "
            f"{len(mr['kernels'])} kernels")
    with open(a.out, "w") as f:
        f.write("{\n")
        keys = [k for k in doc if k != "cells"]
        for k in keys:
            f.write(f" {json.dumps(k)}: {json.dumps(doc[k])},\n")
        f.write(' "cells": [\n')
        f.write(",\n".join("  " + json.dumps(c) for c in out_cells))
        f.write("\n ]\n}\n")
    print(f"{len(out_cells)} cells; skipped {dict(skipped)}")
    by = collections.Counter(c["L"] for c in out_cells)
    print("L histogram:", sorted(by.items()))


def result_high(a, doc, idx):
    """`result_high`: the cells of the readers of an UPPER register of a multi-register result (RESULT_HIGH), the floor of
    such a reader without a cell, and the silicon of --result-floors on the cells of the producers it measured."""
    hidx = {}
    for r in json.load(open(a.result_census)):
        p, c, role = r["prod"], r["cons"], r["role"]
        if r["part"] != "high" or p not in RESULT_HIGH or role == "r?":
            continue
        if r["n"] < MIN_N or r["n_min"] < MIN_AT or r["min"] > MAX_TIGHT:
            continue                       # not dense, or never tight: no cell of its own (the rule of the ordinary cells)
        hidx[(p, c, role)] = {"producer": p, "consumer": c, "role": role, "L": max(r["min"], 4),
                              "basis": f"ptxas census min {r['min']} x {r['n_min']} of {r['n']} readers of the result's upper register"}
    fl = json.load(open(a.result_floors))
    hi, lo, pair = {}, {}, {}
    for f in fl["floors"]:
        if f["family"] not in ("wh", "cs"):
            continue
        p, rest = f["what"].split(" -> ")
        c, role = rest.rsplit(" ", 1)
        floor = max(f[g]["clean_from"] for g in fl["geometries"])      # the strictest geometry of the run
        d = {"hi": hi, "lo": lo}.get(f["which"], pair)
        d[(p, c, role)] = max(d.get((p, c, role), 0), floor)
    assert hi and all(k[0] in RESULT_HIGH for k in hi), "the result-register floors are of the producers in RESULT_HIGH"
    doc["comment"] += (" `result_high`: a reader of an UPPER register of a multi-register result of the producers named there"
                       " (the high half of a 64-bit product is ready later than its low half) takes the larger of the pair's"
                       " cell and the cell of `result_high.cells` for it; where the census has no dense cell for the upper"
                       " register it takes the pair's cell, but never less than `result_high.floor`.")
    doc["provenance"]["silicon"].append(
        f"result registers ({fl['run']}; {', '.join(fl['geometries'].values())}; 20 launches per kernel, S15 reference): "
        f"IMAD.WIDE low / high register -> reader, {len(lo)} + {len(hi)} pairs; either register of the pair form "
        f"`CS2R Rn, SRZ` -> reader, {len(pair)} pairs")
    # the pair form of CS2R: one number for both registers; a floor above the cell raises it (the rule of --floors)
    for key, floor in sorted(pair.items()):
        c = idx.get(key)
        if c is None:
            doc["provenance"].setdefault("measured_without_cell", []).append(
                {"producer": key[0], "consumer": key[1], "role": key[2], "floor_d0": floor, "harness": "pr-em-3"})
            continue
        if floor > c["L"]:
            c["basis"] += f"; RAISED from {c['L']} by the silicon floor"
            c["L"] = floor
        c["silicon"] = ((c["silicon"] + "; ") if c.get("silicon") else "") + (
            f"floor d0 S{floor:02d} on either register of the pair form `CS2R Rn, SRZ` (the census pairs are the 32-bit form)")
    measured = []
    for key in sorted(set(hi) | set(lo)):
        c, h = idx.get(key), hidx.get(key)
        if c is not None and key in lo:
            assert lo[key] <= c["L"], f"{key}: the cell {c['L']} is below the low register's floor {lo[key]}"
        if h is not None and key in hi:
            assert hi[key] <= h["L"], f"{key}: the upper register's cell {h['L']} is below its floor {hi[key]}"
            h["silicon"] = f"floor d0 S{hi[key]:02d}"
        measured.append({"producer": key[0], "consumer": key[1], "role": key[2], "floor_low": lo.get(key),
                         "floor_high": hi.get(key), "cell": c["L"] if c else None, "cell_high": h["L"] if h else None})
    floor = max(hi.values())
    for m in measured:                     # what a reader of the upper register is charged, pair by pair
        if m["floor_high"] is None:
            continue
        dflt = doc["defaults"]["data"]
        price = max(m["cell"], m["cell_high"]) if m["cell_high"] is not None and m["cell"] is not None else (
            m["cell_high"] if m["cell_high"] is not None else (max(m["cell"], floor) if m["cell"] is not None else dflt))
        assert price >= m["floor_high"], f"{m}: an upper-register reader is charged {price}"
        m["charged_high"] = price
    doc["result_high"] = {
        "producers": RESULT_HIGH, "floor": floor,
        "basis": "the largest floor measured for a reader of the upper register of an IMAD.WIDE result (silicon: -> IADD3 / LEA / "
                 "LOP3 / SHF / MOV / SEL 5, -> ISETP / IMAD 4, -> STS data 3; the low register 3 / 3 / 3 / 3 / 2 / 2 / 2 / 1 / 1); "
                 "ptxas reads the upper register never closer than 5, or 4 into the multiplier (census split by result register)",
        "cells": [hidx[k] for k in sorted(hidx)],
        "measured": measured,
    }


if __name__ == "__main__":
    main()
