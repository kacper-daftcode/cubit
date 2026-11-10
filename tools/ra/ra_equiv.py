#!/usr/bin/env python3
"""An independent check of a register renaming (CPU only), written for the sm_120 sparse-MLA prefill attention kernel.

It does NOT use cubit's operand-role table or its liveness: the hardware footprint of every opcode that kernel uses is
written out below by hand (what the instruction reads and writes on silicon, in 32-bit registers), guarded writes do
not kill, and the control flow is rebuilt from the labels. An opcode or operand form that is not modelled stops the
run: extend `footprint` before using it on another kernel.

    ra_equiv.py text  <orig.sass> <renamed.sass> <report.json>      source level
    ra_equiv.py words <orig.dis>  <renamed.dis>  <report.json>      `cubit disassemble` of the two cubins (the encoded words)
    ra_equiv.py live  <orig.sass>                                   liveness summary of one kernel (register pressure)

`text` checks, with the plan of the `cubit ra --mode full | apply` report (old numeral -> new numeral per domain):
  1. the two texts are the same instruction stream, token for token, once every register / predicate numeral of the
     original is sent through the plan (opcode, modifiers, selectors, immediates, labels, guards: nothing else moves);
  2. footprints: every multi-register operand (pair, quad, the implied high halves of 64-bit addresses and
     descriptors) lands on consecutive registers with the alignment the instruction needs: plan[base+k] == plan[base]+k;
  3. no clobber: with the TRUE liveness of the original (hand footprints, guarded writes keep the old value alive), the
     plan is injective on live-in and on live-out + written registers of every instruction;
  4. nothing is live at the entry, no register is read on any path before it is written.
`words` does 1. on the decoded words of the two cubins (control codes counted, not compared).
Exit code 0 = every check passed.
"""
import json
import re
import sys
from collections import defaultdict

RE_REG = re.compile(r"(?<![A-Za-z0-9_])(UR|R)(\d+)(?![0-9])")
RE_PRED = re.compile(r"(?<![A-Za-z0-9_])(UP|P)([0-6])(?![0-9A-Za-z_])")


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


class Ins:
    __slots__ = ("idx", "guard", "gneg", "op", "mods", "ops", "text", "labels", "line")

    def __init__(self, idx, text, labels, line):
        self.idx, self.text, self.labels, self.line = idx, text, labels, line
        t = text
        self.guard, self.gneg = None, False
        m = re.match(r"@(!?)(U?P)([0-7T])\s+", t)
        if m:
            self.gneg = m.group(1) == "!"
            self.guard = (m.group(2), 7 if m.group(3) == "T" else int(m.group(3)))
            t = t[m.end():]
        parts = t.split(None, 1)
        full = parts[0]
        self.op = full.split(".")[0]
        self.mods = full.split(".")[1:]
        self.ops = split_ops(parts[1]) if len(parts) > 1 else []


def parse_sass(path):
    """Instruction list of the (single) kernel of a directive-format .sass."""
    ins, pending = [], []
    for ln, raw in enumerate(open(path), 1):
        s = raw.split("//")[0].strip()
        if not s or s.startswith("."):
            continue
        while True:
            m = re.match(r"([A-Za-z_][A-Za-z0-9_.$]*)\s*:\s*", s)
            if not m:
                break
            pending.append(m.group(1))
            s = s[m.end():]
        if not s:
            continue
        s = re.sub(r"^\[[^\]]*\]\s*", "", s)          # a frozen control-code prefix
        assert s.endswith(";"), (path, ln, raw)
        s = s[:-1].strip()
        ins.append(Ins(len(ins), s, pending, ln))
        pending = []
    assert not pending, f"trailing labels {pending}"
    return ins


def parse_dis(path):
    """`cubit disassemble` output: (text without the sched comment, sched word) per instruction."""
    out = []
    for raw in open(path):
        m = re.match(r"\s*/\*([0-9a-f]+)\*/\s+(.*?)\s*(?:/\* @sched (0x[0-9a-f]+) \*/)?\s*;\s*$", raw)
        if m:
            out.append((m.group(2).strip(), m.group(3)))
    return out


# ----------------------------------------------------------------------------- hardware footprints (by hand)
def regs_in(tok):
    """(domain, number) of every register named in an operand token."""
    return [(d, int(n)) for d, n in RE_REG.findall(tok)]


def bare_reg(tok):
    m = re.fullmatch(r"[-~|]*(UR|R)(\d+)\|?((?:\.[A-Za-z0-9_]+)*)", tok)
    return (m.group(1), int(m.group(2))) if m else None


def footprint(i):
    """-> (defs, uses, pdefs, puses, spans): defs/uses = sets of (dom, n); spans = [(dom, base, width, align, why)]."""
    defs, uses, pdefs, puses, spans = set(), set(), set(), set(), []
    op, mods, ops = i.op, i.mods, i.ops

    def span(tok_or_reg, w, is_def, why, align=1):
        r = bare_reg(tok_or_reg) if isinstance(tok_or_reg, str) else tok_or_reg
        if r is None:
            return False
        dom, b = r
        spans.append((dom, b, w, align, why))
        for k in range(w):
            (defs if is_def else uses).add((dom, b + k))
        return True

    def use_any(tok, why):
        """a source operand: register (1), immediate / RZ / float (nothing)"""
        if bare_reg(tok):
            span(tok, 1, False, why)
        elif RE_REG.search(tok):
            raise SystemExit(f"unmodelled register operand {tok!r} in `{i.text}`")

    def pred_tok(tok):
        m = re.fullmatch(r"!?(U?P)([0-7T])", tok)
        if not m:
            return None
        return (m.group(1), 7 if m.group(2) == "T" else int(m.group(2)))

    def puse(tok):
        p = pred_tok(tok)
        assert p is not None, (tok, i.text)
        if p[1] != 7:
            puses.add(p)

    def pdef(tok):
        p = pred_tok(tok)
        assert p is not None, (tok, i.text)
        if p[1] != 7:
            pdefs.add(p)

    def addr(tok, why):
        """[R+off] (32-bit smem / cmem offset register) or desc[URa][Rb.64+off] (64-bit descriptor + 64-bit address)"""
        m = re.fullmatch(r"desc\[UR(\d+)\]\[R(\d+)\.64(?:\+0x[0-9a-f]+)?\]", tok)
        if m:
            span(("UR", int(m.group(1))), 2, False, why + " descriptor (64-bit)")
            span(("R", int(m.group(2))), 2, False, why + " address (64-bit)")
            return
        m = re.fullmatch(r"\[R(\d+)(?:\+0x[0-9a-f]+)?\]", tok)
        if m:
            span(("R", int(m.group(1))), 1, False, why + " smem address")
            return
        m = re.fullmatch(r"c\[0x[0-9a-f]+\]\[0x[0-9a-f]+\]", tok)
        if m:
            return
        raise SystemExit(f"unmodelled address {tok!r} in `{i.text}`")

    if i.guard and i.guard[1] != 7:
        puses.add(i.guard)

    if op in ("EXIT", "BRA", "BAR", "NOP"):
        pass
    elif op == "S2R":
        span(ops[0], 1, True, "S2R dest")
    elif op in ("LDC", "LDCU"):
        span(ops[0], 2 if "64" in mods else 1, True, f"{op} dest")
        addr(ops[1], op)
    elif op in ("ISETP", "FSETP"):
        pdef(ops[0]); pdef(ops[1])
        use_any(ops[2], "cmp a"); use_any(ops[3], "cmp b")
        puse(ops[4])
    elif op in ("SHF", "LOP3", "IADD3", "MOV", "FMUL", "FADD", "FFMA", "MUFU", "HADD2", "HMUL2", "F2FP", "UIADD3"):
        if op == "UIADD3":                      # the scheduler's writeback drain `@!UPT UIADD3 URZ, UPT, UPT, -URZ, -URZ, -URZ`
            assert all("URZ" in o or "UPT" in o for o in ops), i.text
        else:
            assert "WIDE" not in mods and "64" not in mods, i.text
            span(ops[0], 1, True, f"{op} dest") or (_ for _ in ()).throw(SystemExit(f"dest? {i.text}"))
            for o in ops[1:]:
                if pred_tok(o):
                    if op == "LOP3":
                        puse(o)             # LOP3.LUT R, R, R, R, lut, P : the trailing predicate is an input
                    else:
                        pdef(o)             # IADD3 R, P, P, ... : carry outputs
                else:
                    use_any(o, f"{op} src")
    elif op == "IMAD":
        if "WIDE" in mods:
            span(ops[0], 2, True, "IMAD.WIDE dest (64-bit)")
            pdef(ops[1])
            use_any(ops[2], "a"); use_any(ops[3], "b")
            if bare_reg(ops[4]):
                span(ops[4], 2, False, "IMAD.WIDE addend (64-bit)")
        else:
            span(ops[0], 1, True, "IMAD dest")
            for o in ops[1:]:
                use_any(o, "IMAD src")
    elif op in ("SEL", "FSEL", "VIMNMX", "FMNMX"):
        span(ops[0], 1, True, f"{op} dest")
        use_any(ops[1], "a"); use_any(ops[2], "b")
        puse(ops[3])
    elif op == "CS2R":
        assert ops[1] == "SRZ" and "32" not in mods, i.text
        span(ops[0], 2, True, "CS2R dest (64-bit: the pair is written)")
    elif op in ("LDG", "LDS"):
        w = 4 if "128" in mods else 2 if "64" in mods else 1
        span(ops[0], w, True, f"{op} dest")
        addr(ops[1], op)
    elif op in ("STG", "STS"):
        w = 4 if "128" in mods else 2 if "64" in mods else 1
        addr(ops[0], op)
        span(ops[1], w, False, f"{op} data")
    elif op == "LDSM":
        w = 4 if mods[-1] == "4" else 2 if mods[-1] == "2" else 1
        span(ops[0], w, True, f"LDSM dest x{w}")
        addr(ops[1], "LDSM")
    elif op == "HMMA":
        assert mods[0] == "16816", i.text
        span(ops[0], 4, True, "HMMA D", 4)
        span(ops[1], 4, False, "HMMA A", 4)
        span(ops[2], 2, False, "HMMA B", 2)
        if bare_reg(ops[3]):
            span(ops[3], 4, False, "HMMA C", 4)
        else:
            assert ops[3] == "RZ", i.text
    elif op == "SHFL":
        pdef(ops[0])
        span(ops[1], 1, True, "SHFL dest")
        use_any(ops[2], "SHFL src")
        for o in ops[3:]:
            use_any(o, "SHFL lane/mask")
    else:
        raise SystemExit(f"unmodelled opcode {op} in `{i.text}`")
    return defs, uses, pdefs, puses, spans


def successors(ins):
    lab = {}
    for i in ins:
        for l in i.labels:
            lab[l] = i.idx
    succ = []
    for i in ins:
        nxt = [i.idx + 1] if i.idx + 1 < len(ins) else []
        if i.op == "EXIT":
            succ.append(nxt if i.guard else [])
        elif i.op == "BRA":
            t = lab[i.ops[-1]]
            succ.append([t] + (nxt if i.guard else []))
        else:
            succ.append(nxt)
    return succ


def liveness(ins):
    """True liveness. A fact is (register, condition): condition None = needed whatever happens, (pred, negated) = needed
    only when that guard holds. A guarded write kills only the facts of its own guard (the old value survives when the
    guard is false); a write of a predicate turns the facts conditioned on it into unconditional ones (conservative).
    A register is live when any fact names it."""
    fp = [footprint(i) for i in ins]
    succ = successors(ins)
    n = len(ins)
    fin = [set() for _ in range(n)]
    fout = [set() for _ in range(n)]
    changed = True
    while changed:
        changed = False
        for k in range(n - 1, -1, -1):
            defs, uses, pdefs, puses, _ = fp[k]
            i = ins[k]
            g = (i.guard, i.gneg) if (i.guard and i.guard[1] != 7) else None
            o = set()
            for s in succ[k]:
                o |= fin[s]
            cur = set()
            for (r, c) in o:
                if r in defs or r in pdefs:
                    if g is None or c == g:
                        continue                      # killed
                if c is not None and c[0] in pdefs:
                    c = None                          # the guard it depended on is rewritten here
                cur.add((r, c))
            for u in uses:
                cur.add((u, g))
            for u in puses:
                cur.add((u, None))
            if o != fout[k] or cur != fin[k]:
                fout[k], fin[k] = o, cur
                changed = True
    live_in = [{r for r, _ in f} for f in fin]
    live_out = [{r for r, _ in f} for f in fout]
    return fp, succ, live_in, live_out


def load_plan(report):
    k = json.load(open(report))["kernels"][0]
    p = k["plan"]
    return {"R": {int(a): b for a, b in p["r"].items()}, "UR": {int(a): b for a, b in p["ur"].items()},
            "P": {int(a): b for a, b in p["p"].items()}, "UP": {int(a): b for a, b in p["up"].items()}}


def map_text(text, plan, strict=True):
    def rr(m):
        d, n = m.group(1), int(m.group(2))
        if n not in plan[d]:
            if strict:
                raise SystemExit(f"plan has no {d}{n} (in `{text}`)")
            return m.group(0)
        return f"{d}{plan[d][n]}"

    def pp(m):
        d, n = m.group(1), int(m.group(2))
        return f"{d}{plan[d].get(n, n)}"
    parts = text.split(None, 1)
    head = parts[0]
    if head.startswith("@"):
        g = RE_PRED.sub(pp, head)
        rest = parts[1].split(None, 1)
        opc = rest[0]
        ops = rest[1] if len(rest) > 1 else ""
        return f"{g} {opc}" + (" " + RE_PRED.sub(pp, RE_REG.sub(rr, ops)) if ops else "")
    ops = parts[1] if len(parts) > 1 else ""
    return head + (" " + RE_PRED.sub(pp, RE_REG.sub(rr, ops)) if ops else "")


def norm(text):
    return re.sub(r"\s+", " ", text.replace(" ,", ",")).strip()


def cmd_text(orig, ren, report):
    plan = load_plan(report)
    a, b = parse_sass(orig), parse_sass(ren)
    bad = 0
    print(f"instructions: original {len(a)}, renamed {len(b)}")
    if len(a) != len(b):
        print("FAIL: instruction counts differ"); return 1
    # 1. token equality under the plan (floats compared by value, `+0x0` offsets dropped, branch targets compared by
    #    the instruction they name: the renderer prints the last of several labels of one address)
    def canon(t, labidx):
        def f(m):
            s = m.group(0)
            try:
                return repr(float(s))
            except ValueError:
                return s
        t = re.sub(r"(?<![A-Za-z0-9_.\[x])-?\d+\.\d+(?:e[+-]?\d+)?(?![A-Za-z0-9_])", f, norm(t))
        t = t.replace("+0x0]", "]")
        m = re.match(r"((?:@\S+ )?BRA) (\S+)$", t)
        if m:
            t = f"{m.group(1)} #{labidx[m.group(2)]}"
        return t
    la = {l: i.idx for i in a for l in i.labels}
    lb = {l: i.idx for i in b for l in i.labels}
    nd = 0
    for x, y in zip(a, b):
        if canon(map_text(x.text, plan), la) != canon(y.text, lb) or bool(x.labels) != bool(y.labels):
            nd += 1
            if nd <= 10:
                print(f"  DIFF [{x.idx}] {x.text!r} -> expected {map_text(x.text, plan)!r}, got {y.text!r}; labels {x.labels} / {y.labels}")
    if la != lb:
        missing = sorted(set(la) ^ set(lb))
        moved = sorted(l for l in set(la) & set(lb) if la[l] != lb[l])
        if moved:
            nd += len(moved); print(f"  LABELS moved: {moved}")
        print(f"  (labels: {len(la)} in the original, {len(lb)} in the renamed text; only in one of them: {missing})")
    print(f"1. stream equality under the plan: {len(a) - nd} / {len(a)} instructions identical" + ("" if nd == 0 else "  FAIL"))
    bad += nd
    # 2. + 3. + 4.
    fp, succ, live_in, live_out = liveness(a)
    nspan = nbad = 0
    widths = defaultdict(int)
    for i, (defs, uses, pdefs, puses, spans) in zip(a, fp):
        for dom, base, w, align, why in spans:
            nspan += 1
            widths[w] += 1
            pm = plan[dom]
            ok = all(pm.get(base + k) == pm[base] + k for k in range(w)) and pm[base] % align == 0
            if not ok:
                nbad += 1
                if nbad <= 10:
                    print(f"  SPAN [{i.idx}] `{i.text}`: {why}: {dom}{base}..+{w - 1} -> {[pm.get(base + k) for k in range(w)]} (align {align})")
    print(f"2. footprints: {nspan} register spans (width 1/2/4: {widths[1]}/{widths[2]}/{widths[4]}), {nbad} torn or misaligned" + ("" if nbad == 0 else "  FAIL"))
    bad += nbad
    ncl = 0
    peak = 0
    for i, (defs, uses, pdefs, puses, spans) in zip(a, fp):
        for name, group in (("live-in", live_in[i.idx]), ("live-out + written", live_out[i.idx] | defs | pdefs)):
            seen = {}
            for dom, n in sorted(group):
                key = (dom, plan[dom].get(n, n))
                if key in seen and seen[key] != n:
                    ncl += 1
                    if ncl <= 10:
                        print(f"  CLOBBER [{i.idx}] `{i.text}`: {name}: {dom}{seen[key]} and {dom}{n} both -> {key[0]}{key[1]}")
                seen[key] = n
        peak = max(peak, len([1 for d, n in live_out[i.idx] | defs if d == "R"]))
    print(f"3. no clobber (true liveness, guarded writes keep the old value): {ncl} collisions; peak co-live R registers {peak}" + ("" if ncl == 0 else "  FAIL"))
    bad += ncl
    ent = sorted(live_in[0])
    print(f"4. live at entry: {ent if ent else 'none'}" + ("" if not ent else "  FAIL"))
    bad += len(ent)
    homes = len(set(plan["R"].values()))
    print(f"plan: R {len(plan['R'])} symbols -> {homes} registers (highest R{max(plan['R'].values())}), UR {plan['UR']}, P {plan['P']}")
    print("VERDICT text:", "PASS" if bad == 0 else f"NOT PASSED ({bad})")
    return 0 if bad == 0 else 1


def cmd_words(orig, ren, report):
    plan = load_plan(report)
    a, b = parse_dis(orig), parse_dis(ren)
    print(f"decoded instructions: original {len(a)}, renamed {len(b)}")
    if len(a) != len(b):
        print("FAIL: instruction counts differ"); return 1
    nd = sd = 0
    for k, ((x, sx), (y, sy)) in enumerate(zip(a, b)):
        if norm(map_text(x, plan, strict=False)) != norm(y):
            nd += 1
            if nd <= 10:
                print(f"  DIFF [{k}] {x!r} -> expected {map_text(x, plan, strict=False)!r}, got {y!r}")
        if sx != sy:
            sd += 1
    print(f"decoded words equal under the plan: {len(a) - nd} / {len(a)}" + ("" if nd == 0 else "  FAIL"))
    print(f"control words that differ between the two schedules: {sd} of {len(a)}")
    print("VERDICT words:", "PASS" if nd == 0 else f"NOT PASSED ({nd})")
    return 0 if nd == 0 else 1


def cmd_live(path):
    a = parse_sass(path)
    fp, succ, live_in, live_out = liveness(a)
    peak, where = 0, None
    for i, (defs, uses, pdefs, puses, spans) in zip(a, fp):
        c = len([1 for d, n in live_out[i.idx] | defs if d == "R"])
        if c > peak:
            peak, where = c, i
    used = sorted({n for f in fp for d, n in f[0] | f[1] if d == "R"})
    print(f"{path}: {len(a)} instructions, R registers named {len(used)} (highest R{used[-1]}), peak co-live {peak} at [{where.idx}] `{where.text}`; live at entry {sorted(live_in[0])}")
    return 0


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "text":
        sys.exit(cmd_text(*sys.argv[2:5]))
    if mode == "words":
        sys.exit(cmd_words(*sys.argv[2:5]))
    if mode == "live":
        sys.exit(cmd_live(sys.argv[2]))
    sys.exit(2)
