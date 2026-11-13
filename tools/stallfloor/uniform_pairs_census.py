#!/usr/bin/env python3
"""The pairs on a uniform register in ptxas's own schedules, read by cubit's verifier.

`census_pairs_sm120.json` is mined from the certified operand sets (`examples/depdump`). They have no rule for several words of
the uniform datapath that the scheduler's operand model knows (`ULEA`, `USHF`, the uniform result of `VOTEU` ...), so a pair
whose producer or consumer is such a word has no row there -- the dependency table has no cell for it and prices it by
`defaults.uniform`. This script reads the same frozen census through the VERIFIER instead: `cubit asm <frozen listing>` under
CUBIT_SYNC_CLASSES=1 with CUBIT_DEP_VERIFY reports every fixed-latency pair of an author's schedule that stands below its
cell or below a default, on the shortest control-flow path. Per pair class -- (producer class, consumer class, the SET of roles
the register has in the consumer), in the table's own vocabulary -- it writes ptxas's smallest distance, how many pairs
stand at it and how many stand below what the table asks (`below`: a default, or a cell -- the cells that the global floor
of 4 clamps).

    uniform_pairs_census.py <cubit> <isa table> <dependency table json> <dir of *.frozen.sass> <out.json> [--jobs N]

The classes and roles are computed here from the two words of a reported pair (`dep_stall::dep_class`, `dep_stall::roles_of`
re-stated) and checked against cubit on every line: the distance the verifier asked for must be the largest of the roles'
cells / defaults in the table given (a line that does not agree stops the run). What the file is not: a census of every
pair -- a pair at or above its default is not reported by the verifier and not counted; the MINIMUM of a class that has
pairs below the default is what `gen_dep_latency.py` reads (`MEASURED_MIN_CELLS`). Run it with a binary whose bundled table
is the one given. Static, CPU only; nothing but the output file is written (the re-assembled cubins go to a scratch directory
that is removed)."""
import collections
import concurrent.futures
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

CTRL = {"BRA", "JMP", "RET", "EXIT", "BRX", "JMX", "CALL", "BREAK", "BSSY", "BSYNC", "CONT", "KILL"}
HEAD = re.compile(r"^\s+(\S+): DEP_VERIFY (\d+) below a table cell, (\d+) waits closer than the arming distance to their barrier's setter, "
                  r"(\d+) below a resource spacing, (\d+) below a default \((\d+) instructions")
DFLT = re.compile(r"^\s+DEP dflt \[(\d+)\] (.*?) -> \[(\d+)\] (.*) \((\w+) ([A-Z]+\d+)\): distance (\d+) < (\d+) \(default: no cell for the pair\)\s*$")
CELL = re.compile(r"^\s+DEP cell \[(\d+)\] (.*?) -> \[(\d+)\] (.*) \((\w+) ([A-Z]+\d+)\): distance (\d+) < (\d+)\s*$")
PRED = re.compile(r"^!?U?P(T|\d)$")


def split_ops(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse(text):
    t = text.strip()
    guard = None
    m = re.match(r"^@(!?)(U?)P(\d)\s+", t)
    if m:
        guard = dict(uniform=bool(m.group(2)), pred=int(m.group(3)))
        t = t[m.end():]
    parts = t.split(None, 1)
    full = parts[0]
    return dict(guard=guard, op=full.split(".")[0], mods=["." + x for x in full.split(".")[1:]], full=full, ops=split_ops(parts[1]) if len(parts) > 1 else [])


def dep_class(text):
    j = parse(text)
    op, mods = j["op"], j["mods"]
    if op == "F2FP":
        if any(m.startswith(".PACK") for m in mods):
            return "F2FP.PACK"
        if any(m.startswith(".UNPACK") for m in mods):
            return "F2FP.UNPACK"
    if op in ("IADD3", "UIADD3") and ".X" in mods:
        return op + ".X"
    if op == "IMAD" and ".WIDE" in mods:
        return "IMAD.WIDE"
    if op == "IMAD" and ".HI" in mods:
        return "IMAD.HI"
    if op == "HADD2" and ".F32" in mods:
        return "HADD2.F32"
    if op == "MOV" and ".64" in mods:
        return "MOV.64"
    return op


def roles_of(text, reg):
    """the roles a uniform register `URn` or a uniform predicate `UPn` has in the consumer `text`"""
    j = parse(text)
    out = []
    ctrl = j["op"] in CTRL
    if reg.startswith("UP"):
        n = int(reg[2:])
        g = j["guard"]
        if g and g["uniform"] and g["pred"] == n:
            out.append("gc" if ctrl else "g")
        if any(re.fullmatch(rf"!?UP{n}", o) for o in j["ops"]):
            out.append("gc" if ctrl else "p")
        return sorted(set(out))
    k = int(reg[2:])
    pos = 0
    for o in j["ops"]:
        if PRED.match(o):
            continue
        p = pos
        pos += 1
        o2 = o.replace(".reuse", "")
        m = re.fullmatch(r"[-~|!]?UR(\d+)\|?", o2)
        if m:
            if int(m.group(1)) in (k, k - 1):     # the register or the lower half of its pair
                out.append(f"u{p}")
        elif o2.startswith("desc["):
            m = re.match(r"desc\[UR(\d+)\]", o2)
            if m and int(m.group(1)) in (k, k - 1):   # a descriptor is a register pair
                out.append(f"u{p}")
        elif (o2.startswith("[") or o2.startswith("c[")) and re.search(rf"UR{k}(?!\d)", o2):
            out.append(f"u{p}")
    return sorted(set(out))


class Table:
    def __init__(self, path):
        t = json.load(open(path))
        self.d = t["defaults"]
        self.cells = {(c["producer"], c["consumer"], c["role"]): c["L"] for c in t["cells"]}
        self.mma = set(t["mma"]["classes"])

    def need(self, pc, cc, rs):
        """(the distance the table asks of the pair, the default used for the roles without a cell)"""
        best, used = 0, None
        for r in rs:
            l = self.cells.get((pc, cc, r))
            if l is None and r.endswith("h"):
                l = self.cells.get((pc, cc, r[:-1]))
            if l is None:
                used = "mma_input" if cc in self.mma else "guard" if r in ("g", "gc") else "pred_operand" if r == "p" else "uniform"
                l = self.d[used]
            best = max(best, l)
        return best, used


def one(args):
    cubit, isa, lst, scratch = args
    out = os.path.join(scratch, os.path.basename(lst) + ".cubin")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), "CUDA_VISIBLE_DEVICES": "", "CUBIT_SYNC_CLASSES": "1", "CUBIT_DEP_VERIFY": "1000000"}
    r = subprocess.run([cubit, "asm", lst, "-t", isa, "-o", out], capture_output=True, text=True, env=env)
    if os.path.exists(out):
        os.remove(out)
    kernels, rows = [], []
    for l in (r.stdout + r.stderr).splitlines():
        m = HEAD.match(l)
        if m:
            kernels.append(int(m.group(6)))
            continue
        if "DEP dflt" in l or "DEP cell" in l:
            m = DFLT.match(l) or CELL.match(l)
            assert m, f"{lst}: a `DEP` line this script cannot read: {l}"
            if m.group(6).startswith("U"):
                rows.append((m.group(2), m.group(4), m.group(6), int(m.group(7)), int(m.group(8)), "default" if "DEP dflt" in l else "cell"))
    return os.path.basename(lst), kernels, rows


def main():
    a = sys.argv[1:]
    jobs = 8
    if "--jobs" in a:
        k = a.index("--jobs")
        jobs = int(a[k + 1])
        del a[k:k + 2]
    cubit, isa, table, frozen, outp = a
    T = Table(table)
    lists = [l for l in sorted(glob.glob(os.path.join(frozen, "*.frozen.sass"))) if os.path.getsize(l) > 0]
    with tempfile.TemporaryDirectory() as scratch, concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        res = list(ex.map(one, [(cubit, isa, l, scratch) for l in lists]))
    acc = collections.defaultdict(lambda: dict(n=0, by=collections.Counter(), forms=collections.defaultdict(collections.Counter), default=None))
    for name, kernels, rows in res:
        for ptext, ctext, reg, have, need, below in rows:
            pc, cc, rs = dep_class(ptext), dep_class(ctext), roles_of(ctext, reg)
            if not rs:
                rs = ["*"]      # a position this script does not name: the class is kept apart, the check below still holds
            want, used = T.need(pc, cc, rs)
            assert want == need and (used is not None) == (below == "default"), \
                f"{name}: `{ptext}` -> `{ctext}` ({reg}): the verifier asked {need} ({below}), the table gives {want} for {pc} -> {cc} {rs}"
            x = acc[(pc, cc, "+".join(rs))]
            x["n"] += 1
            x["by"][have] += 1
            x["default"] = used if below == "default" else f"cell {need}"
            x["forms"][have][f"{parse(ptext)['full']} -> {parse(ctext)['full']}"] += 1
    rows = []
    for (pc, cc, rs), x in sorted(acc.items()):
        mn = min(x["by"])
        rows.append({"producer": pc, "consumer": cc, "roles": rs, "min": mn, "n_min": x["by"][mn], "n_below": x["n"], "below": x["default"],
                     "forms_at_min": [f"{k} x{v}" for k, v in x["forms"][mn].most_common(3)]})
    doc = {"what": "pairs on a uniform register or predicate that stand below a default or below a cell of the dependency table in ptxas's own sm_120 "
                   "schedules, read by CUBIT_DEP_VERIFY under CUBIT_SYNC_CLASSES=1 (tools/stallfloor/uniform_pairs_census.py); per (producer class, consumer "
                   "class, the set of roles the register has in the consumer): min = ptxas's smallest distance, n_min = the pairs at it, n_below = the pairs below "
                   "what the table asked (`below`)",
           "listings": len(lists), "kernels": sum(len(k) for _, k, _ in res), "instructions": sum(sum(k) for _, k, _ in res),
           "defaults": {k: T.d[k] for k in ("uniform", "guard", "pred_operand", "mma_input")}, "pairs": sum(x["n"] for x in acc.values()), "rows": rows}
    with open(outp, "w") as f:
        f.write("{\n" + ",\n".join(f' {json.dumps(k)}: {json.dumps(v)}' for k, v in doc.items() if k != "rows") + ',\n "rows": [\n'
                + ",\n".join("  " + json.dumps(r) for r in rows) + "\n ]\n}\n")
    print(f"{len(lists)} listings, {doc['kernels']} kernels, {doc['instructions']} instructions; {doc['pairs']} pairs on a uniform register or predicate below a default or a cell in {len(rows)} classes")


if __name__ == "__main__":
    main()
