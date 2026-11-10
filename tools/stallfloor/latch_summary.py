#!/usr/bin/env python3
"""one line per (kind, geometry) of a latch probe result: mismatching threads by issue distance (S + 15 * pad)."""
import json
import sys

j = json.load(open(sys.argv[1]))
mm = j["mismatches"]
refs = j.get("references", {})
pairs = sorted({k.split("/")[0] for k in mm})
for p in pairs:
    by = {}
    for k, v in mm.items():
        if k.split("/")[0] != p:
            continue
        pad = int(k.split("/pad")[1].split("_")[0])
        for s, n in v.items():
            by[int(s) + 15 * pad] = n
    if not by:
        continue
    ds = sorted(by)
    tot = max(by.values()) if by else 0
    last_bad = max([d for d in ds if by[d] != 0], default=0)
    first_clean_all = min([d for d in ds if all(by[e] == 0 for e in ds if e >= d)], default=None)
    pick = [1, 10, 15, 16, 18, 19, 20, 21, 22, 24, 26, 28, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75]
    cells = " ".join(f"{d}:{by[d]}" for d in pick if d in by)
    print(f"LATCH {p} [ref {refs.get(p, '?')[:24]}]: last distance with a mismatch {last_bad}, clean from {first_clean_all} | {cells}")
