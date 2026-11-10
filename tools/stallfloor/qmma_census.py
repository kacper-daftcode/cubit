#!/usr/bin/env python3
"""ptxas's practice around QMMA on sm_120, mined through the operand slots (companion of slot_census.py).

cubit's register-liveness model has no def / use rule for the 7-operand QMMA.SF form (depdump: known = false, no defs,
no uses), so the pair census behind tables/dep_latency_sm120.json has no row with QMMA as producer or consumer: its MMA
rows (16 / 28 / 29) rest on HMMA. Here the operands are taken from the operand slots: slot 0 = result (4 registers),
slot 1 = A fragment, slot 2 = B fragment, slot 3 = accumulate operand (4 registers), slots 4 / 5 = the scale registers.

Linear walk per kernel (reset at unconditional transfers, as dep_latency_census.py). Distances in stall units (the sum
of the stall fields from the producer up to the consumer). Histograms of
  QMMA -> the next MMA that accumulates on its result            (accumulate chain)
  QMMA -> the first non-MMA reader of a result register          (reader), by reader class
  QMMA -> the next QMMA / any MMA                                 (issue spacing -- not a register pair, so not in
                                                                   census_pairs_slots_sm120.json)
  X    -> QMMA operand (A / B fragment register, scale register, accumulate register from a non-MMA producer)

usage: qmma_census.py <dir with *.dep.jsonl> <out.json>
"""
import sys, json, glob, collections, os

MMA = ("QMMA", "HMMA", "IMMA", "DMMA")
WIDTH = {0: 4, 1: 4, 2: 2, 3: 4, 4: 1, 5: 1}          # registers per QMMA.SF.16832 operand slot (A: 4 x 4 e4m3 bytes ... )
ROLE = {1: "A fragment", 2: "B fragment", 3: "accumulate", 4: "scale A", 5: "scale B"}


def qmma_sets(j):
    d, u = set(), {}
    for pos, kind, base in j["slots"]:
        if kind != "r":
            continue
        w = WIDTH.get(pos, 1)
        if pos == 0:
            d |= set(range(base, base + w))
        else:
            for r in range(base, base + w):
                u.setdefault(r, ROLE.get(pos, f"r{pos}"))
    return d, u


def main():
    files = sorted(glob.glob(sys.argv[1] + "/*.dep.jsonl"))
    H = collections.defaultdict(collections.Counter)
    EX = {}
    nq = 0
    for f in files:
        J = [json.loads(l) for l in open(f)]
        if not any(j["op"] == "QMMA" for j in J):
            continue
        D = {}            # reg -> (index, clock, is_qmma)
        clock = 0
        last_mma = None
        for i, j in enumerate(J):
            if j["i"] == 0:
                D.clear(); clock = 0; last_mma = None
            op = j["op"]
            if op == "QMMA":
                nq += 1
                d, u = qmma_sets(j)
                seen = set()
                for r, role in u.items():
                    p = D.get(r)
                    if p is None:
                        continue
                    pi, pc, pq = p
                    if (pi, role) in seen:
                        continue
                    seen.add((pi, role))
                    key = ("QMMA -> QMMA " + role) if pq else (f"{J[pi]['op']} -> QMMA {role}")
                    if J[pi]["wb"] != 7 and not pq:
                        key += " [scoreboarded producer]"
                    dist = min(clock - pc, 60)
                    H[key][dist] += 1
                    if key not in EX or dist < EX[key][0]:
                        EX[key] = (dist, os.path.basename(f)[:60], J[pi]["text"][:60], j["text"][:70])
                if last_mma is not None:
                    H["%s -> QMMA issue spacing" % J[last_mma[0]]["op"]][min(clock - last_mma[1], 60)] += 1
                last_mma = (i, clock)
                for r in d:
                    D[r] = (i, clock, True)
            else:
                if op in MMA:
                    if last_mma is not None and J[last_mma[0]]["op"] == "QMMA":
                        H["QMMA -> %s issue spacing" % op][min(clock - last_mma[1], 60)] += 1
                    last_mma = (i, clock)
                seen = set()
                for r in j["ru"]:
                    p = D.get(r)
                    if p is None or not p[2]:
                        continue
                    if p[0] in seen:
                        continue
                    seen.add(p[0])
                    key = f"QMMA -> {op} (reader)"
                    dist = min(clock - p[1], 60)
                    H[key][dist] += 1
                    if key not in EX or dist < EX[key][0]:
                        EX[key] = (dist, os.path.basename(f)[:60], J[p[0]]["text"][:60], j["text"][:70])
                for r in j["rd"]:
                    D[r] = (i, clock, False)
            clock += j["s"]
            g = j["guard"]
            if op in ("BRA", "JMP", "RET", "EXIT", "BRX", "JMX") and not (g and g["pred"] < 7):
                D.clear(); last_mma = None
    print(f"{len(files)} listings, {nq} QMMA")
    out = []
    for k, h in sorted(H.items(), key=lambda kv: -sum(kv[1].values())):
        n = sum(h.values()); mn = min(h)
        first = " ".join(f"{d}:{c}" for d, c in sorted(h.items())[:8])
        print(f"{k:44s} n={n:6d} min={mn:2d} x{h[mn]:5d} | {first} | e.g. {EX.get(k, ('', '', '', ''))[1:]}")
        out.append(dict(key=k, n=n, min=mn, n_min=h[mn], hist={str(d): c for d, c in sorted(h.items())}, example=EX.get(k)))
    json.dump(out, open(sys.argv[2], "w"), indent=1)


if __name__ == "__main__":
    main()
