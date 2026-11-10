#!/usr/bin/env python3
"""The ptxas pair census of dep_latency_census.py with the two instruction forms cubit's reg_xfer
does not know (depdump: known = false, rd = ru = []) supplied from their operand slots:

  QMMA[.SF].16832...   result 4 registers, A fragment 4, B fragment 2, accumulate operand 4, scale-factor registers 1 each
  IADD.64              64-bit pairs: result, first operand, second operand (register pair or uniform pair)

Without them the census (census_pairs_sm120.json) has no row with QMMA or IADD.64 as producer or consumer, and every pair
through them is priced with a default of tables/dep_latency_sm120.json. Same walk, classes and roles as the original.

usage: slot_census.py <dir with *.dep.jsonl> <out.json> [table.json]
"""
import sys, json, glob, collections, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dep_latency_census as C

QW = {0: 4, 1: 4, 2: 2, 3: 4, 4: 1, 5: 1}


def patch(j):
    if j["known"]:
        return j, False
    if j["op"] == "QMMA":
        rd, ru, spans = [], [], []
        for pos, kind, base in j["slots"]:
            if kind != "r":
                continue
            w = QW.get(pos, 1)
            regs = list(range(base, base + w))
            if pos == 0:
                rd += regs
            else:
                ru += regs
            spans.append([base, w, pos == 0])
        j = dict(j, rd=rd, ru=sorted(set(ru)), spans=spans, known=True)
        return j, True
    if j["op"] == "IADD" and ".64" in j["mods"]:
        rd, ru, uu, spans = [], [], [], []
        for pos, kind, base in j["slots"]:
            if kind == "r":
                regs = [base, base + 1]
                if pos == 0:
                    rd += regs
                else:
                    ru += regs
                spans.append([base, 2, pos == 0])
            elif kind == "u" and pos > 0:
                uu += [base, base + 1]
        j = dict(j, rd=rd, ru=sorted(set(ru)), uu=sorted(set(uu)), spans=spans, known=True)
        return j, True
    return j, False


def mine(path, agg, ex, only):
    D = {}
    clock = 0
    for line in open(path):
        j = json.loads(line)
        j, patched = patch(j)
        if j["i"] == 0:
            D.clear(); clock = 0
        cc = C.klass(j)
        seen = set()
        for cls, r, role in C.uses(j):
            d = D.get((cls, r))
            if d is None:
                continue
            pj, pclock = d
            if pj["wb"] != 7:
                continue
            key = (C.klass(pj), cc, role)
            if (key, pj["i"]) in seen:
                continue
            seen.add((key, pj["i"]))
            if only and not (key[0] in only or key[1] in only):
                continue
            dist = clock - pclock
            agg[key][min(dist, 40)] += 1
            e = ex.get(key)
            if e is None or dist < e[0]:
                ex[key] = (dist, path.split("/")[-1], pj["i"], pj["text"], j["i"], j["text"])
        d = (j, clock)
        for r in j["rd"]:
            D[("R", r)] = d
        for u in j["ud"]:
            D[("U", u)] = d
        for p in j["pd"]:
            D[("P", p)] = d
        for p in j["upd"]:
            D[("UP", p)] = d
        clock += j["s"]
        g = j["guard"]
        if j["op"] in ("BRA", "JMP", "RET", "EXIT", "BRX", "JMX") and not (g and g["pred"] < 7):
            D.clear()


def main():
    files = sorted(glob.glob(sys.argv[1] + "/*.dep.jsonl"))
    agg = collections.defaultdict(collections.Counter)
    ex = {}
    for p in files:
        mine(p, agg, ex, {"QMMA", "IADD"})
    T = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else None
    cell = {(c["producer"], c["consumer"], c["role"]): c["L"] for c in T["cells"]} if T else {}
    rows = []
    for key, hist in agg.items():
        n = sum(hist.values()); mn = min(hist)
        rows.append(dict(prod=key[0], cons=key[1], role=key[2], n=n, min=mn, n_min=hist[mn], table_cell=cell.get(key),
                         hist={str(k): v for k, v in sorted(hist.items())}, example=ex[key]))
    rows.sort(key=lambda r: -r["n"])
    json.dump(rows, open(sys.argv[2], "w"), indent=0)
    print(f"{len(files)} listings; {len(rows)} (producer, consumer, role) rows through QMMA / IADD.64, {sum(r['n'] for r in rows)} pairs")
    for r in rows:
        if r["n"] >= 50:
            h = " ".join(f"{k}:{v}" for k, v in list(r["hist"].items())[:6])
            print(f"{r['prod']:11s} -> {r['cons']:11s} {r['role']:4s} n={r['n']:6d} min={r['min']:2d} x{r['n_min']:5d} cell={r['table_cell']} | {h}")


if __name__ == "__main__":
    main()
