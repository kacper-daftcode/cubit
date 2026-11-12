#!/usr/bin/env python3
"""The reader of TIMES of a batch of kind-`thr` requests (tool 26; run by the service's runner 14, which writes the
median launch time per kernel as `launch_us_median_by_distance`).

    read_thr.py <batch dir> [--json out.json] [--label TEXT]

Per request and grid: per slot the median launch time, the thread-launches right / all, the ratio to the base stage (slot 1)
of the same request and grid, and the null (the last slot = the base stage again).  A SLOT WHOSE CHECKSUM IS NOT RIGHT IN
EVERY THREAD-LAUNCH HAS NO TIME (printed as REFUSED; nothing is computed from it).
Per stage and grid, where the batch holds the stage at two repeat counts: the SLOPE = time per stage iteration
(t(N2) - t(N1)) / ((N2 - N1) x 256), free of the launch's overhead, as nanoseconds and as a ratio to the base stage's slope,
and the intercept (the one-off part of a launch).  With the empty stage in the batch: the same ratio after the loop's
skeleton is taken off both.  Full SM against one warp: the slope on a full grid over the slope on w1, per slot.
Numbers are per ONE batch run (one card, one clock state): compare ratios inside a run, never times across runs."""
import json
import pathlib
import sys


def load(batch):
    b = pathlib.Path(batch)
    ids = json.load(open(b / "batch.json"))["requests"]
    out = {}
    for rid in ids:
        fam = json.load(open(b / rid / "family.json"))
        if fam["request"]["kind"] != "thr":
            continue
        p = b / rid / "result.json"
        if not p.exists():
            out[rid] = {"request": fam["request"], "points": fam["thr_points"], "missing": True}
            continue
        res = json.load(open(p))
        out[rid] = {"request": fam["request"], "points": fam["thr_points"], "missing": False, "errors": res.get("errors", []),
                    "skipped": res.get("skipped_kernels", 0), "conditions": res.get("conditions", {}), "series": {}}
        for s in res["series"]:
            slots = {}
            for d in s["distances"]:
                cls = s["by_distance"][str(d)]
                tl = s["thread_launches_per_kernel"]
                good = cls.get("good", 0) if isinstance(cls.get("good", 0), int) else 0
                ok = set(cls) == {"good"} and good == tl
                slots[d] = {"us": s["launch_us_median_by_distance"].get(str(d)), "good": good, "all": tl, "ok": ok, "classes": cls}
            out[rid]["series"][s["occupancy"]] = slots
    return out


def main():
    a = sys.argv[1:]
    batch = a[0]
    label = a[a.index("--label") + 1] if "--label" in a else batch
    data = load(batch)
    J = {"batch": batch, "label": label, "requests": {}, "slopes": [], "refused": [], "missing": []}
    print(f"== {label}")
    for rid, r in data.items():
        q = r["request"]
        names = {p["slot"]: p["name"] for p in r["points"]["slots"]}
        if r["missing"]:
            print(f"-- {rid}: NO RESULT FILE")
            J["missing"].append(rid)
            continue
        c = r["conditions"]
        print(f"-- {rid}: stage {q['stage']}, {q['repeat']} passes x 256 iterations, reps {c.get('reps')}; card {c.get('gpu')}, driver {c.get('driver')}, "
              f"busy clock mean {c.get('clock_busy_mean_mhz')} MHz (the batch), block {c.get('block')}; launch errors {len(r['errors'])}, skipped {r['skipped']}")
        J["requests"][rid] = {"stage": q["stage"], "repeat": q["repeat"], "grids": {}}
        for occ, slots in r["series"].items():
            base = slots.get(1)
            last = max(slots)
            print(f"   grid {occ}: slot name | median us | right / all | ratio to the base stage")
            g = {}
            for d in sorted(slots):
                s = slots[d]
                if not s["ok"] or s["us"] is None:
                    J["refused"].append({"request": rid, "grid": occ, "slot": d, "name": names.get(d), "classes": s["classes"]})
                    print(f"      {d:2d} {names.get(d, '?'):9s} REFUSED - checksum not right in every thread-launch: {s['classes']}")
                    g[d] = {"name": names.get(d), "us": None, "ok": False, "classes": s["classes"]}
                    continue
                ratio = (s["us"] / base["us"]) if (base and base["ok"] and base["us"]) else None
                g[d] = {"name": names.get(d), "us": s["us"], "ok": True, "good": s["good"], "all": s["all"], "ratio_to_base": ratio}
                print(f"      {d:2d} {names.get(d, '?'):9s} {s['us']:12.1f} | {s['good']} / {s['all']} | " + (f"{ratio:.4f}" if ratio is not None else "-"))
            if len(slots) > 1 and g.get(last, {}).get("ok") and g.get(1, {}).get("ok"):
                print(f"      null (slot {last} / slot 1): {g[last]['us'] / g[1]['us']:.4f}")
            J["requests"][rid]["grids"][occ] = g
    # slopes: the same stage and grid at two repeat counts
    by = {}
    for rid, r in J["requests"].items():
        for occ, g in r["grids"].items():
            by.setdefault((r["stage"], occ), []).append((r["repeat"], rid, g))
    slope = {}
    for (stage, occ), lst in sorted(by.items()):
        if len(lst) < 2:
            continue
        lst.sort(key=lambda x: x[0])
        (n1, r1, g1), (n2, r2, g2) = lst[0], lst[-1]
        print(f"-- slope, stage {stage}, grid {occ}: {r1} (N = {n1}) and {r2} (N = {n2}): slot name | ns per stage iteration | ratio to the base stage | intercept us")
        for d in sorted(g2):
            if d not in g1 or not (g1[d]["ok"] and g2[d]["ok"]):
                print(f"      {d:2d} {g2[d]['name']:9s} no slope (a slot without a time)")
                continue
            sl = (g2[d]["us"] - g1[d]["us"]) * 1000.0 / ((n2 - n1) * 256)
            ic = g1[d]["us"] - sl * n1 * 256 / 1000.0
            slope[(stage, occ, d)] = sl
            b = slope.get((stage, occ, 1))
            print(f"      {d:2d} {g2[d]['name']:9s} {sl:10.3f} | " + (f"{sl / b:.4f}" if b else "-") + f" | {ic:8.1f}")
            J["slopes"].append({"stage": stage, "grid": occ, "slot": d, "name": g2[d]["name"], "ns_per_iteration": sl, "ratio_to_base": (sl / b) if b else None,
                                "intercept_us": ic, "n1": n1, "n2": n2})
    # the stage's own part: the loop's skeleton (the empty stage) taken off; and full SM against one warp
    grids = sorted({occ for (stage, occ, _d) in slope if stage == "a"})
    if grids:
        print("-- stage a per slot: ns per iteration on each grid | the same minus the empty stage, as a ratio to the base stage | the grid over w1")
        nslot = max(d for (stage, _o, d) in slope if stage == "a")
        names = {s["slot"]: s["name"] for s in J["slopes"] if s["stage"] == "a"}
        for d in range(1, nslot + 1):
            row = [f"      {d:2d} {names.get(d, '?'):9s}"]
            for occ in grids:
                sl, b, e = slope.get(("a", occ, d)), slope.get(("a", occ, 1)), slope.get(("e", occ, 1))
                w1 = slope.get(("a", "w1", d))
                if sl is None:
                    row.append(f"{occ}: -")
                    continue
                net = ((sl - e) / (b - e)) if (e is not None and b and b != e) else None
                row.append(f"{occ}: {sl:9.3f} ns" + (f", net ratio {net:.4f}" if net is not None else "") + (f", x w1 {sl / w1:.3f}" if (w1 and occ != "w1") else ""))
                for s in J["slopes"]:
                    if (s["stage"], s["grid"], s["slot"]) == ("a", occ, d):
                        s["net_ratio_to_base"] = net
                        s["over_w1"] = (sl / w1) if (w1 and occ != "w1") else None
            print(" | ".join(row))
    print(f"refused slots: {len(J['refused'])}; requests without a result: {len(J['missing'])}")
    if "--json" in a:
        pathlib.Path(a[a.index("--json") + 1]).write_text(json.dumps(J, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
