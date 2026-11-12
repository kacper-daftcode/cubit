#!/usr/bin/env python3
"""The reader of a batch of kind-`gp` requests (probe.py 27: a guarded wait under ANOTHER predicate - a vendor kernel's prologue
pointers with the reader's result as data).

    read_gp.py <batch dir> [--json out.json] [--grids]

Per request: the thread-launches NOT right / all per distance, summed over the grids, with the classes seen (good | stale =
the reader took the pair from before its load | drop2 = the reader's result was lost: the load landed behind the reader's
write | other = a mixture over the iterations or anything else) and, with --grids, the same per grid.  Then every request
WITH the carrier's wait against its twin WITHOUT it (id + `_ew`, the positive control): a guarded request "holds" at a
distance where it is right in every thread-launch; the control says whether the wait is what made it right there (control
not right) or whether the load had landed anyway (control right too)."""
import json
import pathlib
import sys


def load(batch):
    b = pathlib.Path(batch)
    out = {}
    for rid in json.load(open(b / "batch.json"))["requests"]:
        fam = json.load(open(b / rid / "family.json"))
        q = fam["request"]
        if q["kind"] != "gp":
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
        out[rid] = {"request": {k: q.get(k) for k in ("kind", "form", "guards", "pset", "wait", "reps", "distances")}, "pair": fam["pair"], "modes": fam["modes"],
                    "by_distance": dist, "grids": grids, "errors": res.get("errors", []), "skipped": res.get("skipped_kernels", 0),
                    "conditions": {k: res["conditions"].get(k) for k in ("gpu", "driver", "clock_busy_mean_mhz", "clock_busy_max_mhz", "power_max_w", "block", "reps", "start_utc", "end_utc")}}
    return out


def main():
    a = sys.argv[1:]
    batch = a[0]
    data = load(batch)
    print(f"== {batch}")
    bad_guarded = []
    for rid, r in data.items():
        if r is None:
            print(f"-- {rid}: NO RESULT FILE")
            continue
        q, c = r["request"], r["conditions"]
        tot_bad = sum(e["not_right"] for e in r["by_distance"].values())
        tot = sum(e["all"] for e in r["by_distance"].values())
        print(f"-- {rid}: form {q['form']}, guards {q['guards']}, pset {q['pset']}, wait {q['wait']}; hypotheses {r['modes']}; not right {tot_bad} of {tot} over all distances and grids; "
              f"errors {len(r['errors'])}, skipped {r['skipped']}; {c['gpu']}, driver {c['driver']}, {c['clock_busy_mean_mhz']} MHz, power max {c['power_max_w']} W, block {c['block']}")
        for d in sorted(r["by_distance"]):
            e = r["by_distance"][d]
            print(f"      d {d:2d}: not right {e['not_right']:>10d} / {e['all']}" + ("" if not e["not_right"] else "   " + " ".join(f"{k} {v}" for k, v in sorted(e["classes"].items()))))
        if "--grids" in a:
            for g, rows in r["grids"].items():
                print(f"      grid {g}: " + "; ".join(f"{d}: {w['not_right']}/{w['all']}" + ("" if not w["not_right"] else " [" + " ".join(f"{k} {v}" for k, v in sorted(w['classes'].items()) if k != "good") + "]")
                                                      for d, w in sorted(rows.items())))
        if q["wait"] == "guarded" and tot_bad:
            bad_guarded.append(rid)
    print("== every request WITH the carrier's wait against its control (the same text without that wait bit) - distance: guarded not right | control not right / all")
    for rid, r in data.items():
        if r is None or r["request"]["wait"] != "guarded":
            continue
        tw = data.get(rid + "_ew")
        held = all(e["not_right"] == 0 for e in r["by_distance"].values())
        if tw is None:
            print(f"   {rid}: (no control: the reader never executes) right at EVERY distance: {'YES' if held else 'NO'}")
            continue
        row = [f"{d}: {r['by_distance'][d]['not_right']} | {tw['by_distance'][d]['not_right']} / {r['by_distance'][d]['all']}" for d in sorted(r["by_distance"])]
        shown = [d for d in sorted(r["by_distance"]) if tw["by_distance"][d]["not_right"] > 0]
        allbad = [d for d in sorted(r["by_distance"]) if tw["by_distance"][d]["not_right"] == tw["by_distance"][d]["all"]]
        print(f"   {rid}: " + "; ".join(row))
        print(f"      -> with the carrier's wait the reader is right at EVERY distance: {'YES' if held else 'NO'}; the control is not right at the distances {shown} "
              f"(in every thread-launch at {allbad})")
    for rid in bad_guarded:
        print(f"GUARDED WAIT NOT RIGHT: {rid}")
    if "--json" in a:
        pathlib.Path(a[a.index("--json") + 1]).write_text(json.dumps({batch: data}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
