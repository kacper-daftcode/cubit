#!/usr/bin/env python3
"""Write-after-read distances of a frozen schedule: how soon behind a READER of a register the schedule lets ANOTHER
instruction overwrite that register. The latency table prices read-after-write only; this is the other direction, the
one a barrier does not always cover (an MMA carries no read barrier under ptxas, a `UMOV` lands at once).

Straight-line text: the walk from a reader ends at a label, at an unconditional transfer, after 12 instructions.
Issue distance = the sum of the stall fields from the reader up to the instruction in front of the overwriter. A
reader with a read barrier whose overwriter waits a scoreboard is listed as kind `barrier`, every other site as
`distance`. Rows: (register file: R = per-thread, UR = uniform; reader class; overwriter class; kind).

    cargo run --release --example depdump -- -t tables/sm120.json.gz kernel.frozen.sass > kernel.dep.jsonl
    war_census.py --name NAME --out PREFIX [--min-sites N] corpus.dep.jsonl [...]     # PREFIX.json, PREFIX.txt
    war_census.py --against corpus.json [more.json ...] -- schedule.dep.jsonl         # sites below the corpus

`--against` lists every site of the schedule whose distance is below the smallest distance the corpus files have for
its (register file, reader class, overwriter class); a pair class the corpus does not have is listed when the distance
is below 3. A wait on the overwriter does not excuse an MMA reader (ptxas keeps 8 cycles behind an MMA whatever the
overwriter waits): those sites are compared with the corpus's `distance` rows like the others. Exit status 1 when a
site is below the corpus."""
import sys, json, collections, os


def cls(j):
    c = j["op"]
    if j["op"] in ("QMMA", "HMMA"):
        return "MMA"
    if ".HI" in j["opf"]:
        c += ".HI"
    if "WIDE" in j["opf"]:
        c += ".WIDE"
    return c


def fix(j):
    # a family the certified sets do not know (`ULEA`, `IADD.64`, `USHF`, ...: "known": false, empty sets): operand
    # slot 0 is the destination, the other register slots are sources (64-bit forms: the pair)
    if j.get("known", True) or j["rd"] or j["ru"] or j["ud"] or j["uu"] or not j["slots"]:
        return j
    wide = any(m in ("64", "U64", "S64") for m in j["opf"].split(".")[1:])
    for pos, (slot, kind, reg) in enumerate(j["slots"]):
        if kind not in ("r", "u") or (kind == "r" and reg == 255) or (kind == "u" and reg >= 63):
            continue
        tgt = j["rd" if kind == "r" else "ud"] if pos == 0 and j["op"] not in ("BRA", "BRX", "RET", "ISETP", "UISETP") else j["ru" if kind == "r" else "uu"]
        tgt.append(reg)
        if wide:
            tgt.append(reg + 1)
    return j


def scan(files):
    """rows[(file, reader class, overwriter class, kind)] = [(distance, dump, kernel, reader index, overwriter index,
    reader text, overwriter text, stalls between)]; the number of kernels and of instructions."""
    rows = collections.defaultdict(list)
    n_insn = n_kern = 0
    for f in files:
        byk = collections.OrderedDict()
        for l in open(f):
            if l.startswith("{") and '"op"' in l:
                j = fix(json.loads(l))
                byk.setdefault(j["k"], []).append(j)
        for K in byk.values():
            n_kern += 1
            n_insn += len(K)
            for i, x in enumerate(K):
                g = x.get("guard")
                if g and g["pred"] == 7 and g["neg"]:
                    continue  # a never-executed pad
                for uni, uses, dkey in ((False, x["ru"], "rd"), (True, x["uu"], "ud")):
                    for r in uses:
                        d = 0
                        for k in range(i, min(i + 13, len(K))):
                            y = K[k]
                            if k > i:
                                if r in y[dkey]:
                                    kind = "barrier" if (x["rb"] != 7 and y["wait"]) else "distance"
                                    rows[("UR" if uni else "R", cls(x), cls(y), kind)].append(
                                        (d, os.path.basename(f), x["k"], x["i"], y["i"], x["text"], y["text"], [z["s"] for z in K[i:k]]))
                                    break
                                if y["labels"]:
                                    break
                            if k > i and y["op"] in ("BRA", "EXIT", "RET", "BRX") and not (y.get("guard") and y["guard"]["pred"] < 7) and "DIV" not in y["opf"]:
                                break
                            d += y["s"]
    return rows, n_kern, n_insn


def census(name, prefix, minsites, files):
    rows, n_kern, n_insn = scan(files)
    out = {"name": name, "files": len(files), "kernels": n_kern, "instructions": n_insn, "definition": __doc__, "rows": []}
    lines = [f"# write-after-read census '{name}': {len(files)} file(s), {n_kern} kernel(s), {n_insn} instructions",
             f"# {'file':4s} {'reader':14s} {'overwriter':14s} {'kind':9s} {'sites':>7s} {'min':>4s} {'at min':>7s}  histogram distance:count"]
    for key, v in sorted(rows.items()):
        m = min(x[0] for x in v)
        h = collections.Counter(min(x[0], 32) for x in v)
        at = [x for x in v if x[0] == m]
        out["rows"].append({"file": key[0], "reader": key[1], "overwriter": key[2], "kind": key[3], "sites": len(v), "min": m, "at_min": len(at),
                            "hist": {str(d): c for d, c in sorted(h.items())},
                            "sites_at_min": [{"file": x[1], "kernel": x[2], "reader_i": x[3], "overwriter_i": x[4], "reader": x[5], "overwriter": x[6], "stalls": x[7]} for x in at[:4]]})
        if len(v) >= minsites:
            lines.append(f"  {key[0]:4s} {key[1]:14s} {key[2]:14s} {key[3]:9s} {len(v):7d} {m:4d} {len(at):7d}  " + " ".join(f"{d}:{c}" for d, c in sorted(h.items())[:10]))
    json.dump(out, open(prefix + ".json", "w"), indent=1)
    open(prefix + ".txt", "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


def against(corpora, schedule):
    mins = {}
    for c in corpora:
        for r in json.load(open(c))["rows"]:
            if r["kind"] != "distance":
                continue
            key = (r["file"], r["reader"], r["overwriter"])
            mins[key] = min(mins.get(key, 99), r["min"])
    rows, _, _ = scan([schedule])
    bad = collections.Counter()
    ex = {}
    unseen = collections.Counter()
    exu = {}
    for (f, rd, ow, kind), v in rows.items():
        for x in v:
            if kind == "barrier" and rd != "MMA":
                continue
            m = mins.get((f, rd, ow))
            if m is None:
                if x[0] < 3:
                    unseen[(f, rd, ow, x[0])] += 1
                    exu.setdefault((f, rd, ow, x[0]), x)
            elif x[0] < m:
                bad[(f, rd, ow, m, x[0])] += 1
                ex.setdefault((f, rd, ow, m, x[0]), x)
    print(f"{sum(bad.values())} write-after-read sites below the vendor's minimum of the pair class:")
    for (f, rd, ow, m, d), c in sorted(bad.items(), key=lambda kv: -(kv[0][3] - kv[0][4])):
        x = ex[(f, rd, ow, m, d)]
        print(f"   {f:3s} {rd:10s} -> {ow:10s} vendor min {m:2d}  here {d:2d}  x{c:3d}   [{x[3]}] {x[5][:44]} -> [{x[4]}] {x[6][:40]}")
    print(f"{sum(unseen.values())} sites of pair classes the corpus does not have (distance < 3)")
    for (f, rd, ow, d), c in sorted(unseen.items())[:12]:
        x = exu[(f, rd, ow, d)]
        print(f"   {f:3s} {rd:10s} -> {ow:10s} here {d:2d}  x{c:3d}   [{x[3]}] {x[5][:44]} -> [{x[4]}] {x[6][:40]}")
    return 1 if bad else 0


def main():
    a = sys.argv[1:]
    if not a or "-h" in a or "--help" in a:
        print(__doc__)
        return 2
    if "--against" in a:
        k = a.index("--")
        return against(a[a.index("--against") + 1:k], a[k + 1])
    name = a[a.index("--name") + 1]
    prefix = a[a.index("--out") + 1]
    minsites = int(a[a.index("--min-sites") + 1]) if "--min-sites" in a else 1
    files = [x for k, x in enumerate(a) if not x.startswith("--") and (k == 0 or a[k - 1] not in ("--name", "--out", "--min-sites"))]
    return census(name, prefix, minsites, files)


if __name__ == "__main__":
    sys.exit(main())
