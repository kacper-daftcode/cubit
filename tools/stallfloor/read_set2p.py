#!/usr/bin/env python3
"""The reader of a batch of SET requests under two predicates (probe.py 28: kind ord with "pguard" - the shared write
barrier of an attention kernel, `@P0 LDG.E.128` + `@P0 LDG.E.U8` + `@P2 LDG.E` on one barrier, ONE wait of the reader).

    read_set2p.py <batch dir> [--json out.json] [--grids]

Per request: the thread-launches NOT right / all per distance (the producers' spacing), summed over the grids, with the
classes seen (good | stale = the reader took the marker of EVERY executing producer in all iterations | other = a mixture
or anything else) and, with --grids, the same per grid.  Then every request WITH the reader's wait against its twin whose
wait bit stands behind the reader words (id + `_ew`, the positive control): the control says whether the wait is what made
the reader right (control not right) or whether the loads had landed anyway (control right too)."""
import json
import pathlib
import sys


def load(batch):
    b = pathlib.Path(batch)
    out = {}
    for rid in json.load(open(b / "batch.json"))["requests"]:
        fam = json.load(open(b / rid / "family.json"))
        q = fam["request"]
        if q["kind"] != "ord" or not q.get("pguard"):
            continue
        p = b / rid / "result.json"
        if not p.exists():
            out[rid] = None
            continue
        res = json.load(open(p))
        dist, grids = {}, {}
        for s in res["series"]:
            n = s["thread_launches_per_kernel"]
            g = grids.setdefault(s["occupancy"], {})
            for d in s["distances"]:
                cls = s["by_distance"][str(d)]
                ints = all(isinstance(v, int) for v in cls.values())
                good = cls.get("good", 0) if ints else 0
                g[d] = {"all": n, "not_right": n - good, "classes": cls}
                e = dist.setdefault(d, {"all": 0, "not_right": 0, "classes": {}})
                e["all"] += n
                e["not_right"] += n - good
                for k, v in cls.items():
                    e["classes"][k] = (e["classes"].get(k, 0) + v) if isinstance(v, int) and isinstance(e["classes"].get(k, 0), int) else v
        out[rid] = {"request": {k: q.get(k) for k in ("kind", "forms", "pguard", "cold", "wait", "rdist", "barrier", "yield", "reps", "distances", "occupancy")},
                    "nprod": len(str(q["forms"]).split(",")), "pair": fam["pair"], "modes": fam["modes"],
                    "by_distance": dist, "grids": grids, "errors": res.get("errors", []), "skipped": res.get("skipped_kernels", 0),
                    "conditions": {k: res["conditions"].get(k) for k in ("gpu", "driver", "clock_busy_mean_mhz", "clock_busy_max_mhz", "power_max_w", "block", "reps", "start_utc", "end_utc")}}
    return out


def main():
    a = sys.argv[1:]
    batch = a[0]
    data = load(batch)
    print(f"== {batch}")
    bad_wait, ctl_right = [], []
    for rid, r in data.items():
        if r is None:
            print(f"-- {rid}: NO RESULT FILE")
            continue
        q, c = r["request"], r["conditions"]
        tot_bad = sum(e["not_right"] for e in r["by_distance"].values())
        tot = sum(e["all"] for e in r["by_distance"].values())
        print(f"-- {rid}: {r['nprod']} producers ({q['forms']}), pguard {q['pguard']}, {'COLD' if q.get('cold') else 'warm'}, wait {q['wait']}, reader at {q.get('rdist') or 2}; hypotheses {r['modes']}; "
              f"not right {tot_bad} of {tot} over all distances and grids; errors {len(r['errors'])}, skipped {r['skipped']}; {c['gpu']}, driver {c['driver']}, "
              f"{c['clock_busy_mean_mhz']} MHz, power max {c['power_max_w']} W, block {c['block']}")
        for d in sorted(r["by_distance"]):
            e = r["by_distance"][d]
            print(f"      d {d:2d}: not right {e['not_right']:>10d} / {e['all']}" + ("" if not e["not_right"] else "   " + " ".join(f"{k} {v}" for k, v in sorted(e["classes"].items()))))
        if "--grids" in a or (q["wait"] == "reader" and tot_bad) or q["wait"] == "end":
            for g, rows in r["grids"].items():
                print(f"      grid {g}: " + "; ".join(f"{d}: {w['not_right']}/{w['all']}" + ("" if not w["not_right"] else " [" + " ".join(f"{k} {v}" for k, v in sorted(w['classes'].items()) if k != "good") + "]")
                                                      for d, w in sorted(rows.items())))
        if q["wait"] == "reader" and tot_bad:
            bad_wait.append(rid)
        if q["wait"] == "end":
            for g, rows in r["grids"].items():
                for d, w in rows.items():
                    if w["not_right"] == 0:
                        ctl_right.append((rid, g, d))
    print("== every request WITH the reader's wait against its control (the same text, the wait bit behind the reader words) - spacing: with the wait not right | control not right / all")
    for rid, r in data.items():
        if r is None or r["request"]["wait"] != "reader":
            continue
        tw = data.get(rid + "_ew")
        held = all(e["not_right"] == 0 for e in r["by_distance"].values())
        if tw is None:
            print(f"   {rid}: (no control: {'nothing executes' if r['modes'] == ['good'] else 'none in the batch'}) right at EVERY spacing on every grid: {'YES' if held else 'NO'}")
            continue
        ds = [d for d in sorted(r["by_distance"]) if d in tw["by_distance"]]
        row = [f"{d}: {r['by_distance'][d]['not_right']} | {tw['by_distance'][d]['not_right']} / {r['by_distance'][d]['all']}" for d in ds]
        allbad = [d for d in ds if tw["by_distance"][d]["not_right"] == tw["by_distance"][d]["all"]]
        frac = {d: round(100.0 * tw["by_distance"][d]["not_right"] / tw["by_distance"][d]["all"], 2) for d in ds}
        print(f"   {rid}: " + "; ".join(row))
        print(f"      -> with the wait the reader is right at EVERY spacing on every grid: {'YES' if held else 'NO'}; the control is not right in {frac} % of the thread-launches "
              f"(in every one at {allbad})")
    for rid in bad_wait:
        print(f"WAIT NOT RIGHT: {rid}")
    for rid, g, d in ctl_right:
        print(f"CONTROL RIGHT: {rid} on grid {g} at spacing {d} (the loads had landed: the control shows nothing there)")
    if "--json" in a:
        pathlib.Path(a[a.index("--json") + 1]).write_text(json.dumps({batch: data}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
