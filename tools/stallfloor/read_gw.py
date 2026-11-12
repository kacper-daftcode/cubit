#!/usr/bin/env python3
"""The reader of a batch of kind-`gw` requests (tool 26, second build: a wait carried by a word under a guard).

    read_gw.py <batch dir> [<batch dir of another run> ...] [--json out.json]

Per request: the thread-launches NOT right / all per distance, summed over the grids, the classes seen, the floor of every
series (grid) and the binding floor; a request with `wait: none` is the positive control of its guarded twin (it never
waits the producer's barrier: NOT a floor by distance - `wait: end` with the guard false in every iteration gives what
distance alone gives; with the guard a bit of the counter a request without the guarded wait is not right by construction:
its `@P4 PRMT` executes without a wait where the guard is true).  A guarded request "holds" at a distance only where its
twin WITHOUT any wait is not right at that distance."""
import json
import pathlib
import sys


def load(batch):
    b = pathlib.Path(batch)
    out = {}
    for rid in json.load(open(b / "batch.json"))["requests"]:
        fam = json.load(open(b / rid / "family.json"))
        if fam["request"]["kind"] not in ("gw", "lb"):      # (kind lb, third build: the same table; it has a control request, no twin)
            continue
        p = b / rid / "result.json"
        if not p.exists():
            out[rid] = None
            continue
        res = json.load(open(p))
        dist = {}
        floors = {}
        for s in res["series"]:
            floors[s["occupancy"]] = s["floor"]
            for d in s["distances"]:
                cls = s["by_distance"][str(d)]
                e = dist.setdefault(d, {"all": 0, "not_right": 0, "classes": {}})
                e["all"] += s["thread_launches_per_kernel"]
                for k, v in cls.items():
                    if isinstance(v, int):
                        e["classes"][k] = e["classes"].get(k, 0) + v
                        if k != "good":
                            e["not_right"] += v
                    else:
                        e["classes"][k] = v
                        e["not_right"] = e["all"]
        out[rid] = {"request": {k: fam["request"].get(k) for k in ("kind", "producer", "wait", "guard", "yield", "control", "reps")}, "pair": fam["pair"],
                    "by_distance": dist, "floors": floors, "binding": res["floor"]["binding"], "oracle_failures": res["floor"]["oracle_failures"],
                    "errors": res.get("errors", []), "skipped": res.get("skipped_kernels", 0),
                    "conditions": {k: res["conditions"].get(k) for k in ("gpu", "driver", "clock_busy_mean_mhz", "power_max_w", "block", "reps")}}
    return out


def main():
    a = sys.argv[1:]
    batches = [x for x in a if not x.startswith("--") and (a.index(x) == 0 or a[a.index(x) - 1] != "--json")]
    J = {}
    for batch in batches:
        data = load(batch)
        J[batch] = data
        print(f"== {batch}")
        for rid, r in data.items():
            if r is None:
                print(f"-- {rid}: NO RESULT FILE")
                continue
            q, c = r["request"], r["conditions"]
            print(f"-- {rid}: kind {q['kind']}, producer {q['producer']}, wait {q['wait']}, guard {q['guard']}, yield {q['yield'] or '-'}, control {q['control'] or '-'}; binding floor {r['binding']}; floors by grid "
                  + " ".join(f"{k}:{v}" for k, v in r["floors"].items()) + f"; errors {len(r['errors'])}, skipped {r['skipped']}"
                  + (f"; ORACLE: {r['oracle_failures']}" if r["oracle_failures"] else "") + f"; {c['gpu']}, {c['clock_busy_mean_mhz']} MHz, block {c['block']}")
            for d in sorted(r["by_distance"]):
                e = r["by_distance"][d]
                print(f"      d {d:2d}: not right {e['not_right']:>10d} / {e['all']}" + ("" if not e["not_right"] else "   " + " ".join(f"{k} {v}" for k, v in sorted(e["classes"].items()))))
        # twins: a guarded request against the same request without any wait
        print("-- the guarded wait against its control (the same text with no wait): distance: guarded not right | control not right / all")
        for rid, r in data.items():
            tw = data.get(rid + "_nw")
            if r is None or tw is None or r["request"]["wait"] != "guarded":
                continue
            row = []
            for d in sorted(r["by_distance"]):
                g, c = r["by_distance"][d], tw["by_distance"].get(d)
                row.append(f"{d}: {g['not_right']} | {c['not_right'] if c else '-'} / {g['all']}")
            shown = [d for d in sorted(r["by_distance"]) if tw["by_distance"].get(d) and tw["by_distance"][d]["not_right"] > 0]
            held = all(r["by_distance"][d]["not_right"] == 0 for d in r["by_distance"])
            print(f"   {rid}: " + "; ".join(row))
            print(f"      -> the guarded wait is right at EVERY distance: {'YES' if held else 'NO'}; the control is not right at the distances {shown} "
                  f"(there the wait is what made the reader right); the control's own floor: {tw['binding']} (it never waits the barrier: not a floor by distance)")
    if "--json" in a:
        pathlib.Path(a[a.index("--json") + 1]).write_text(json.dumps(J, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
