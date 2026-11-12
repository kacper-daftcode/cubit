#!/usr/bin/env python3
"""A plain reader of a batch of kind-`raw` requests (the CS2UR pairs of tool 27's third build): per request the
thread-launches NOT right / all per distance summed over the grids with the classes seen, the floor of every grid (the
runner's: the smallest swept distance from which every larger swept one is right too; None = the largest is not right) and
the binding floor over the grids; a request with "control": "stale" is a positive control (expect 0 % good).

    read_raw27.py <batch dir> [--json out.json]
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
        p = b / rid / "result.json"
        if not p.exists():
            out[rid] = None
            continue
        res = json.load(open(p))
        dist, floors = {}, {}
        for s in res["series"]:
            n = s["thread_launches_per_kernel"]
            floors[s["occupancy"]] = s["floor"]
            for d in s["distances"]:
                cls = s["by_distance"][str(d)]
                good = cls.get("good", 0) if all(isinstance(v, int) for v in cls.values()) else 0
                e = dist.setdefault(d, {"all": 0, "not_right": 0, "classes": {}, "by_grid": {}})
                e["all"] += n
                e["not_right"] += n - good
                e["by_grid"][s["occupancy"]] = n - good
                for k, v in cls.items():
                    e["classes"][k] = (e["classes"].get(k, 0) + v) if isinstance(v, int) and isinstance(e["classes"].get(k, 0), int) else v
        out[rid] = {"request": {k: q.get(k) for k in ("kind", "producer", "consumer", "control", "pbar", "yield", "salt", "reps", "distances")}, "pair": fam["pair"],
                    "by_distance": dist, "floors": floors, "binding": res["floor"]["binding"], "oracle_failures": res["floor"]["oracle_failures"],
                    "errors": res.get("errors", []), "skipped": res.get("skipped_kernels", 0),
                    "conditions": {k: res["conditions"].get(k) for k in ("gpu", "driver", "clock_busy_mean_mhz", "clock_busy_max_mhz", "power_max_w", "block", "reps")}}
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
        q, c = r["request"], r["conditions"]
        print(f"-- {rid}: {q['producer']} -> {q['consumer']}" + (" [POSITIVE CONTROL]" if q["control"] else "") + (" [the producer with a write barrier, the reader waits on it]" if q["pbar"] else "")
              + (" [yield]" if q["yield"] else "") + f"; binding floor {r['binding']}; floors by grid " + " ".join(f"{k}:{v}" for k, v in r["floors"].items())
              + f"; errors {len(r['errors'])}, skipped {r['skipped']}; {c['gpu']}, driver {c['driver']}, {c['clock_busy_mean_mhz']} MHz, power max {c['power_max_w']} W, block {c['block']}")
        for d in sorted(r["by_distance"]):
            e = r["by_distance"][d]
            print(f"      d {d:2d}: not right {e['not_right']:>10d} / {e['all']}" + ("" if not e["not_right"] else "   " + " ".join(f"{k} {v}" for k, v in sorted(e["classes"].items()))
                                                                               + "   by grid: " + " ".join(f"{g} {v}" for g, v in e["by_grid"].items() if v)))
    print("== floors (binding over the six grids; a control has none)")
    for rid, r in data.items():
        if r is not None:
            print(f"   {rid}: {r['binding']}" + ("   (POSITIVE CONTROL)" if r["request"]["control"] else ""))
    if "--json" in a:
        pathlib.Path(a[a.index("--json") + 1]).write_text(json.dumps({batch: data}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
