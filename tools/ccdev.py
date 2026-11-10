#!/usr/bin/env python3
"""CS-1: control codes of a cubit-scheduled kernel that ptxas never uses on the opcode -- in a reference corpus.
   ccdev.py corpus.dep.jsonl new.dep.jsonl [ref.dep.jsonl of the same kernel]
Per opcode of the corpus: the stalls ptxas uses, the (stall, yield) pairs, whether it ever waits / sets a write barrier /
sets a read barrier. A deviation of the new schedule = a field value ptxas never puts on that opcode (candidates for an
illegal control code or for a law of the opcode the scheduler does not know)."""
import sys, json, collections
def load(p): return [json.loads(l) for l in open(p) if l.startswith("{") and '"op"' in l]
C = load(sys.argv[1]); N = load(sys.argv[2]); R = load(sys.argv[3]) if len(sys.argv) > 3 else None
def key(j):
    g = j.get("guard")
    never = bool(g and g["pred"] == 7 and g["neg"])
    return ("@!PT " if never else "") + j["opf"]
st = collections.defaultdict(lambda: dict(n=0, stalls=collections.Counter(), sy=collections.Counter(), wait=0, wb=0, rb=0, rbwb=0))
for j in C:
    s = st[key(j)]; s["n"] += 1; s["stalls"][j["s"]] += 1; s["sy"][(j["s"], j["y"])] += 1
    s["wait"] += j["wait"] != 0; s["wb"] += j["wb"] != 7; s["rb"] += j["rb"] != 7
    s["rbwb"] += (j["rb"] != 7 and j["wb"] != 7)
dev = collections.Counter(); ex = {}
for i, j in enumerate(N):
    if R and all(j[f] == R[i][f] for f in ("s", "y", "wb", "rb", "wait")): continue
    k = key(j); s = st.get(k)
    if s is None or s["n"] < 3:
        d = [("opcode not in the corpus (n<3)", "")]
    else:
        d = []
        if j["s"] not in s["stalls"]: d.append(("stall never used", f"S{j['s']:02d} (ptxas: {sorted(s['stalls'])})"))
        elif (j["s"], j["y"]) not in s["sy"]: d.append(("(stall, yield) never used", f"S{j['s']:02d} {'Y' if j['y'] else '-'}"))
        if j["wait"] and not s["wait"]: d.append(("waits, ptxas never", ""))
        if j["wb"] != 7 and not s["wb"]: d.append(("write barrier, ptxas never", ""))
        if j["rb"] != 7 and not s["rb"]: d.append(("read barrier, ptxas never", ""))
        if j["rb"] != 7 and j["wb"] != 7 and j["rb"] == j["wb"]: d.append(("R == W on one word", ""))
    for what, detail in d:
        dev[(what, k, detail)] += 1; ex.setdefault((what, k, detail), i)
print(f"{len(N)} instructions; deviations from ptxas's practice on the opcode ({sys.argv[1].split('/')[-1]}: {len(C)} instructions):")
for (what, k, detail), c in sorted(dev.items(), key=lambda kv: (kv[0][0], -kv[1])):
    n = st[k]["n"] if k in st else 0
    print(f"  {what:28s} {k:38s} x{c:4d}  {detail[:90]:90s} first at {ex[(what, k, detail)]}  (corpus n={n})")
