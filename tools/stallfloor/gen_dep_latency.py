#!/usr/bin/env python3
"""Build cubit's sm_120 dependency-latency table (tables/dep_latency_sm120.json) from
  (1) ptxas's practice: the pair matrix mined from the frozen sm_120 census (dep_latency_census.py) — for every dense cell
      (producer class, consumer class, operand role) the minimum issue distance ptxas ever schedules, and
  (2) stall floors measured on sm_120 silicon (tools/stallfloor): a measured floor above the census minimum raises the cell;
      a measured floor below it is recorded (`silicon`) but the cell keeps ptxas's value (never below the vendor's practice).

usage: gen_dep_latency.py census_pairs.json out.json [--floors pair_floors.json ...] [--v6 cells.json ...]
"""
import sys, json, argparse, collections

VARIABLE = ["LDG", "LDS", "LDSM", "LDL", "LDC", "LDCU", "LD", "LDGSTS", "S2R", "S2UR", "MUFU", "SHFL", "ATOM", "ATOMG", "ATOMS",
            "RED", "REDG", "REDUX", "I2F", "F2I", "FLO", "POPC", "B2R", "TEX", "TLD", "TXQ", "LEPC", "GETLMEMBASE", "LDTM",
            "UTCATOMSWS"]
MMA = ["HMMA", "QMMA", "IMMA", "DMMA"]
MIN_N, MIN_AT = 50, 8
MAX_TIGHT = 7     # a fixed-latency ALU pair is never above 7 (-> MMA fragment) in the census' dense spikes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("census")
    ap.add_argument("out")
    ap.add_argument("--floors", nargs="*", default=[])
    ap.add_argument("--census-desc", default="166 nvcc / ptxas cubins of the production sm_120 census (FlashInfer, DeepGEMM, "
                    "b12x, CUTLASS MXFP8), 1 811 600 instructions, cubit disassemble --frozen; fixed-latency producer -> "
                    "consumer pairs on fall-through paths")
    ap.add_argument("--v6", nargs="*", default=[], help="results of the population harness (cellfloor_run.py cells.json)")
    a = ap.parse_args()
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
    # MMA rows, written out explicitly (census: HMMA -> HMMA accumulate 29 x 2 368, HMMA -> FADD / FMUL 28; any MMA -> MMA 16)
    out_cells = []
    for (p, c, role), v in sorted(cells.items()):
        out_cells.append({"producer": p, "consumer": c, "role": role, "L": v["L"],
                          "basis": f"ptxas census min {v['census_min']} x {v['n_min']} of {v['n']} pairs"})
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
            c["silicon"] = f"floor d0 S{floor:02d}" if isinstance(floor, int) else str(floor)
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
    out_cells.sort(key=lambda c: (c["producer"], c["consumer"], c["role"]))
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


if __name__ == "__main__":
    main()
