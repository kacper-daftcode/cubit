#!/usr/bin/env python3
"""Which instruction classes does a frozen corpus synchronise with a scoreboard? Per opcode: how many of its register
results carry a write barrier, and for the results WITHOUT one how their first reader stands (straight-line text, 40
instructions): behind a wait (its wait mask is not empty) or not, and the smallest distance of a read without a wait.
An opcode whose results are never read without a scoreboard is a scoreboard class for the assembler that made the
corpus, whatever a scheduler's variable-latency list says. Found this way on ptxas's schedules: `F2F` (104 results:
52 with a write barrier, the other 52 read behind the barrier of a later `F2F`) and `BREV` (48 of 48 with a write
barrier), neither of them in cubit's lists.

    cargo run --release --example depdump -- kernel.frozen.sass > kernel.dep.jsonl
    scoreboard_class_census.py out.json file.dep.jsonl [...]"""
import sys, json, collections
out = sys.argv[1]; files = sys.argv[2:]
st = collections.defaultdict(lambda: dict(n=0, wb=0, nowb_reads=0, nowb_waited=0, min_unwaited=99, ex=None))
for f in files:
    byk = collections.OrderedDict()
    for l in open(f):
        if l.startswith("{") and '"op"' in l:
            j = json.loads(l); byk.setdefault(j["k"], []).append(j)
    for K in byk.values():
        for i, x in enumerate(K):
            if not x["rd"] and not x["ud"]: continue
            g = x.get("guard")
            if g and g["pred"] == 7 and g["neg"]: continue
            s = st[x["op"]]; s["n"] += 1
            if x["wb"] != 7: s["wb"] += 1; continue
            d = 0
            for k in range(i, min(i + 40, len(K))):
                y = K[k]
                if k > i:
                    if any(r in y["ru"] for r in x["rd"]) or any(r in y["uu"] for r in x["ud"]):
                        s["nowb_reads"] += 1
                        if y["wait"]: s["nowb_waited"] += 1
                        elif d < s["min_unwaited"]: s["min_unwaited"] = d; s["ex"] = (x["text"][:50], y["text"][:50], d)
                        break
                    if any(r in y["rd"] for r in x["rd"]) or y["labels"]: break
                d += y["s"]
rows = []
for op, s in st.items():
    rows.append(dict(op=op, results=s["n"], with_write_barrier=s["wb"], read_without_barrier=s["nowb_reads"], of_them_waited=s["nowb_waited"],
                     min_unwaited_distance=None if s["min_unwaited"] == 99 else s["min_unwaited"], example=s["ex"]))
rows.sort(key=lambda r: -r["results"])
json.dump(dict(files=len(files), rows=rows), open(out, "w"), indent=1)
print(f"{len(files)} file(s), {sum(r['results'] for r in rows)} results of {len(rows)} opcodes")
print("opcodes whose results are NEVER read without a scoreboard (own write barrier or a waiting reader), n >= 8:")
for r in rows:
    unw = r["read_without_barrier"] - r["of_them_waited"]
    if r["results"] >= 8 and unw == 0 and (r["with_write_barrier"] or r["of_them_waited"]):
        print(f"   {r['op']:14s} results {r['results']:7d}  with W {r['with_write_barrier']:7d}  without W: {r['read_without_barrier']} read, all behind a wait")
print("opcodes with a write barrier on SOME results and un-waited reads of the others (mixed), n >= 8:")
for r in rows:
    unw = r["read_without_barrier"] - r["of_them_waited"]
    if r["results"] >= 8 and r["with_write_barrier"] and unw:
        print(f"   {r['op']:14s} results {r['results']:7d}  with W {r['with_write_barrier']:7d}  un-waited reads {unw:6d}  min distance {r['min_unwaited_distance']}")
