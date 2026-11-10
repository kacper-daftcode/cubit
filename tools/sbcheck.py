#!/usr/bin/env python3
"""CS-1: a path-aware scoreboard oracle for frozen listings (independent of cubit's own verifier).

    sbcheck.py file.dep.jsonl [--kernel SUBSTR] [--list N] [--json out.json]
    (file.dep.jsonl: `cargo run --release --example depdump -- file.frozen.sass`)

Model (one warp's six scoreboards, counters): an instruction with a write barrier b arms b for the registers it
writes; a later instruction that waits b releases EVERY pending producer on b; an instruction with a read barrier c
keeps its operands latched until c is waited. On every control-flow path:

  RAW   a read of a register whose reaching definition is still pending on b must wait b;
  WAW   an overwriter of such a register must wait b too;
  WAR   an overwriter of an operand of a pending read-barrier holder must wait c.

Control flow: `BRA` / `JMP` to its target, falling through when it is conditional (a guard, a predicate operand, or
the `.DIV` / `.CONV` forms: they branch only when the warp diverged); `EXIT` / `RET` end a path unless guarded;
a register-indirect `BRX` / `JMX` reaches every block that no branch names and no fall-through enters (the case
blocks of nvcc's dispatch tables); `WARPSYNC.COLLECTIVE R, addr` forks to its address. ptxas's own schedules are
the calibration: they must come out clean.
"""
import sys, json, collections, re

UNCOND_XFER = ("BRA", "JMP", "BRX", "JMX", "BRXU", "JMXU", "EXIT", "RET")
SYNC_OWN = ("SYNCS", "ARRIVES", "UBLKCP", "UTMALDG", "UTMASTG", "UTMACMDFLUSH", "LDGDEPBAR", "DEPBAR", "FENCE", "USETMAXREG")


def regs_of(j):
    """(reads, writes, late) as sets of (kind, n)."""
    op = j["op"]
    g = j["guard"]
    never = bool(g and g["pred"] == 7 and g["neg"])
    if never:
        return set(), set(), set()
    reads, writes = set(), set()
    if op in SYNC_OWN:
        for pos, kind, n in j["slots"]:
            if kind in ("r", "a") and n != 255:
                reads.add(("R", n))
            elif kind == "u" and n not in (63, 255):
                reads.add(("U", n))
        if op == "SYNCS" and ".PHASECHK" in j["mods"]:
            for pos, kind, n in j["slots"]:
                if kind == "p":
                    writes.add(("P", n))
        if op == "USETMAXREG" and ".TRY_ALLOC" in j["mods"]:
            for pos, kind, n in j["slots"]:
                if kind == "q":
                    writes.add(("UP", n))
    else:
        reads |= {("R", r) for r in j["ru"] if r != 255} | {("U", u) for u in j["uu"] if u != 63}
        reads |= {("P", p) for p in j["pu"]} | {("UP", p) for p in j["upu"]}
        writes |= {("R", r) for r in j["rd"] if r != 255} | {("U", u) for u in j["ud"] if u != 63}
        writes |= {("P", p) for p in j["pd"]} | {("UP", p) for p in j["upd"]}
    # late-latched operands: the GPRs a memory instruction reads; a synchronisation word's uniform operands too
    # (ptxas: `[R2:W3] SYNCS.EXCH.64 URZ, [UR37], UR4` ... `[B--2---] UMOV UR4, UR36`), not the uniform descriptor of a
    # load / store (`@P0 STG.E.128 desc[UR4][R22.64], R16 [R0]` ... `UMOV UR4, 0xffffffff` without a wait)
    late = {x for x in reads if x[0] == "R" or (x[0] == "U" and op in SYNC_OWN)}
    if g and g["pred"] < 7:
        reads.add(("UP" if g["uniform"] else "P", g["pred"]))
    return reads, writes, late


def build_cfg(K):
    n = len(K)
    a2i = {j["addr"]: i for i, j in enumerate(K)}
    cond = []
    targets = set()
    for i, j in enumerate(K):
        g = j["guard"]
        guarded = bool(g and g["pred"] < 7)
        pred_operand = any(kind in ("p", "q") for pos, kind, nn in j["slots"]) and j["op"] in ("BRA", "JMP")
        divconv = j["op"] == "BRA" and (".DIV" in j["mods"] or ".CONV" in j["mods"])
        cond.append(guarded or pred_operand or divconv)
        if j["tgt"] is not None and j["tgt"] in a2i:
            targets.add(a2i[j["tgt"]])
        if j["op"] == "WARPSYNC" and ".COLLECTIVE" in j["mods"]:
            m = re.search(r",\s*(0x[0-9a-f]+)\s*$", j["text"])
            if m and int(m.group(1), 16) in a2i:
                targets.add(a2i[int(m.group(1), 16)])
        if j["op"] in ("BSSY",) and j["tgt"] is not None and j["tgt"] in a2i:
            targets.discard(a2i[j["tgt"]])       # a reconvergence point is named, not jumped to
    # the dead tail: the self-branch and the NOPs behind the last instruction that can execute
    tail = n
    while tail > 0 and (K[tail - 1]["op"] == "NOP" or (K[tail - 1]["op"] == "BRA" and K[tail - 1]["tgt"] == K[tail - 1]["addr"])):
        tail -= 1
    uncond = lambda i: K[i]["op"] in UNCOND_XFER and not cond[i]
    bssy_targets = {a2i[j["tgt"]] for j in K if j["op"] == "BSSY" and j["tgt"] in a2i}
    orphans = [i for i in range(1, tail) if uncond(i - 1) and i not in targets and i not in bssy_targets]
    succ = [[] for _ in range(n)]
    for i, j in enumerate(K):
        if i >= tail:
            continue
        op = j["op"]
        s = []
        if op in ("EXIT", "RET"):
            if cond[i] and i + 1 < n:
                s.append(i + 1)
        elif op in ("BRA", "JMP"):
            if j["tgt"] is not None and j["tgt"] in a2i:
                s.append(a2i[j["tgt"]])
                if cond[i] and i + 1 < n:
                    s.append(i + 1)
            elif i + 1 < n:
                s.append(i + 1)
        elif op in ("BRX", "JMX", "BRXU", "JMXU"):
            s = list(orphans)
            if i + 1 < n:
                s.append(i + 1)       # the dispatch base (the first case block follows the BRX)
        else:
            if i + 1 < n:
                s.append(i + 1)
            if op == "WARPSYNC" and ".COLLECTIVE" in j["mods"]:
                m = re.search(r",\s*(0x[0-9a-f]+)\s*$", j["text"])
                if m and int(m.group(1), 16) in a2i:
                    s.append(a2i[int(m.group(1), 16)])
            if op == "CALL" and j["tgt"] is not None and j["tgt"] in a2i:
                s.append(a2i[j["tgt"]])
        succ[i] = sorted(set(s))
    return succ, orphans, tail


def check(K, limit=0):
    n = len(K)
    succ, orphans, tail = build_cfg(K)
    R = [regs_of(j) for j in K]
    wb = [j["wb"] if j["wb"] < 6 else None for j in K]
    rb = [j["rb"] if j["rb"] < 6 else None for j in K]
    wait = [j["wait"] for j in K]
    guarded = [bool(j["guard"] and j["guard"]["pred"] < 7) for j in K]
    # state: owner[reg] -> frozenset of pending producers that reach; rarm -> frozenset of pending read-barrier holders
    IN = [None] * n
    IN[0] = ({}, frozenset())
    work = collections.deque([0])
    inq = [False] * n
    inq[0] = True
    viol = {}

    def waited(i, p_bar):
        return (wait[i] >> p_bar) & 1 == 1

    def step(i, st, record):
        owner, rarm = st
        reads, writes, late = R[i]
        j = K[i]
        # 1) waits (DEPBAR.LE SB0 drains scoreboard 0)
        wm = wait[i]
        if j["op"] == "DEPBAR":
            wm |= 1
        if wm:
            owner = {r: frozenset(p for p in ps if not (wm >> wb[p]) & 1) for r, ps in owner.items()}
            owner = {r: ps for r, ps in owner.items() if ps}
            rarm = frozenset(p for p in rarm if not (wm >> rb[p]) & 1)
        # 2) checks
        if record:
            for r in reads:
                for p in owner.get(r, ()):
                    viol.setdefault(("RAW", p, i, r), 1)
            for r in writes:
                if r in reads:
                    continue
                for p in owner.get(r, ()):
                    # complementary guards (`@!P1 LDS R99` / `@P1 LDS R99`) never both execute
                    gp, gi = K[p]["guard"], K[i]["guard"]
                    excl = bool(gp and gi and gp["pred"] == gi["pred"] and gp["uniform"] == gi["uniform"] and gp["neg"] != gi["neg"] and gp["pred"] < 7)
                    if p != i and not excl:
                        viol.setdefault(("WAW", p, i, r), 1)
            for p in rarm:
                # an overwriter that is itself a scoreboarded producer writes after its own (asynchronous) completion,
                # behind the holder in the same pipe: ptxas lets `LDS R157, [R157+0x3000]` follow `LDS R155, [R157+..] [R2]`
                if p == i or wb[i] is not None:
                    continue
                hit = R[p][2] & writes
                for r in hit:
                    viol.setdefault(("WAR", p, i, r), 1)
        # 3) definitions
        new_owner = dict(owner)
        for r in writes:
            if wb[i] is not None:
                new_owner[r] = (new_owner.get(r, frozenset()) | {i}) if guarded[i] else frozenset([i])
            elif not guarded[i]:
                new_owner.pop(r, None)
        if rb[i] is not None and R[i][2]:
            rarm = rarm | {i}
        return (new_owner, rarm)

    def merge(a, b):
        ao, ar = a
        bo, br = b
        ch = False
        no = dict(ao)
        for r, ps in bo.items():
            cur = no.get(r)
            if cur is None:
                no[r] = ps
                ch = True
            elif not ps <= cur:
                no[r] = cur | ps
                ch = True
        nr = ar | br
        if nr != ar:
            ch = True
        return (no, nr), ch

    steps = 0
    while work:
        i = work.popleft()
        inq[i] = False
        steps += 1
        out = step(i, IN[i], False)
        for s in succ[i]:
            if IN[s] is None:
                IN[s] = out
                ch = True
            else:
                IN[s], ch = merge(IN[s], out)
            if ch and not inq[s]:
                work.append(s)
                inq[s] = True
    for i in range(n):
        if IN[i] is not None:
            step(i, IN[i], True)
    unreached = sum(1 for i in range(tail) if IN[i] is None)
    return viol, dict(steps=steps, unreached=unreached, orphans=len(orphans), tail=tail)


def main():
    path = sys.argv[1]
    only = sys.argv[sys.argv.index("--kernel") + 1] if "--kernel" in sys.argv else None
    nlist = int(sys.argv[sys.argv.index("--list") + 1]) if "--list" in sys.argv else 0
    Ks = collections.OrderedDict()
    for l in open(path):
        j = json.loads(l)
        Ks.setdefault(j["k"], []).append(j)
    tot = collections.Counter()
    res = {}
    for name, K in Ks.items():
        if only and only not in name:
            continue
        viol, info = check(K)
        c = collections.Counter(k[0] for k in viol)
        tot.update(c)
        tot["insns"] += len(K)
        tot["unreached"] += info["unreached"]
        res[name] = dict(insns=len(K), raw=c["RAW"], waw=c["WAW"], war=c["WAR"], **info)
        print(f"{name[-56:]:56s} {len(K):5d} insns: RAW {c['RAW']:4d}  WAW {c['WAW']:4d}  WAR {c['WAR']:4d}   (unreached {info['unreached']}, indirect targets {info['orphans']})")
        if nlist:
            byk = collections.defaultdict(list)
            for (kind, p, i, r) in viol:
                byk[kind].append((p, i, r))
            for kind in ("RAW", "WAW", "WAR"):
                for p, i, r in sorted(byk[kind])[:nlist]:
                    print(f"    {kind} {r[0]}{r[1]}: [{p}] {K[p]['text'][:44]:44s} (W{K[p]['wb']} R{K[p]['rb']}) -> [{i}] {('@' if K[i]['guard'] else '') + K[i]['text'][:44]:45s} waits {K[i]['wait']:02x}")
    print(f"TOTAL {tot['insns']} insns: RAW {tot['RAW']}  WAW {tot['WAW']}  WAR {tot['WAR']}  unreached {tot['unreached']}")
    if "--json" in sys.argv:
        json.dump(res, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)


if __name__ == "__main__":
    main()
