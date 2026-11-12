#!/usr/bin/env python3
"""The reader of a LANDING-TIME batch (kind `gw`, "wait": "end", "guard": "false" - b51): per request and PER GRID
the thread-launches not right / all at every swept distance, the classes seen, and the landing distance of the grid = the
smallest swept distance from which the reader is right in EVERY thread-launch at that distance and at every larger swept one
(None = not up to the largest swept distance).  A request of another shape is REFUSED (a control with the bit guard is not
right by construction and says nothing about the reader).

    read_lt.py <batch dir> [--json out.json]
"""
import json
import pathlib
import sys


def load(batch):
    b = pathlib.Path(batch)
    out = {}
    for rid in json.load(open(b / "batch.json"))["requests"]:
        fam = json.load(open(b / rid / "family.json"))
        q = fam["request"]
        if not (q["kind"] == "gw" and q.get("wait") == "end" and q.get("guard") == "false"):
            out[rid] = {"refused": f"REFUSED: kind {q['kind']}, wait {q.get('wait')}, guard {q.get('guard')} is not a landing-time request"}
            continue
        p = b / rid / "result.json"
        if not p.exists():
            out[rid] = None
            continue
        res = json.load(open(p))
        grids = {}
        for s in res["series"]:
            n = s["thread_launches_per_kernel"]
            rows = {}
            for d in s["distances"]:
                cls = s["by_distance"][str(d)]
                good = cls.get("good", 0) if all(isinstance(v, int) for v in cls.values()) else 0
                rows[d] = {"all": n, "not_right": n - good, "classes": cls}
                assert sum(v for v in cls.values() if isinstance(v, int)) == n or not all(isinstance(v, int) for v in cls.values()), (rid, s["occupancy"], d)
            ds = sorted(rows)
            land = None
            for i, d in enumerate(ds):
                if all(rows[x]["not_right"] == 0 for x in ds[i:]):
                    land = d
                    break
            last_bad = max((d for d in ds if rows[d]["not_right"]), default=None)
            grids[s["occupancy"]] = {"text": s["occupancy_text"], "rows": rows, "landing": land, "last_not_right": last_bad, "tool_floor": s["floor"],
                                     "launch_us_median_by_distance": s.get("launch_us_median_by_distance")}
        out[rid] = {"request": {k: q.get(k) for k in ("kind", "producer", "wait", "guard", "yield", "reps", "distances")}, "pair": fam["pair"], "grids": grids,
                    "errors": res.get("errors", []), "skipped": res.get("skipped_kernels", 0),
                    "conditions": {k: res["conditions"].get(k) for k in ("gpu", "driver", "clock_busy_mean_mhz", "clock_busy_max_mhz", "power_max_w", "block", "reps", "start_utc", "end_utc")}}
    return out


def main():
    a = sys.argv[1:]
    batch = a[0]
    data = load(batch)
    print(f"== {batch}")
    for rid, r in data.items():
        if r is None:
            print(f"-- {rid}: NO RESULT FILE")
            continue
        if "refused" in r:
            print(f"-- {rid}: {r['refused']}")
            continue
        q, c = r["request"], r["conditions"]
        print(f"-- {rid}: producer {q['producer']}, wait {q['wait']}, guard {q['guard']}, yield {q['yield'] or '-'}; errors {len(r['errors'])}, skipped {r['skipped']}; "
              f"{c['gpu']}, driver {c['driver']}, clock busy mean {c['clock_busy_mean_mhz']} MHz, power max {c['power_max_w']} W, block {c['block']}, reps {c['reps']}")
        for g, e in r["grids"].items():
            print(f"   grid {g} ({e['text']}): LANDING {e['landing']} (the smallest swept distance from which every thread-launch is right at it and beyond); "
                  f"last distance not right {e['last_not_right']}")
            for d in sorted(e["rows"]):
                w = e["rows"][d]
                print(f"      d {d:3d}: not right {w['not_right']:>9d} / {w['all']}" + ("" if not w["not_right"] else "   " + " ".join(f"{k} {v}" for k, v in sorted(w["classes"].items()))))
    print("== landing distance by grid (None = not right up to the largest swept distance)")
    for rid, r in data.items():
        if r is None or "refused" in r:
            continue
        print(f"   {rid}: " + " | ".join(f"{g} {e['landing']}" for g, e in r["grids"].items()))
    if "--json" in a:
        pathlib.Path(a[a.index("--json") + 1]).write_text(json.dumps({batch: data}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
