#!/usr/bin/env python3
"""sched_oracle.py -- the static scheduling-legality oracle of KNOWN_ISSUES A4
(docs/SCHED_LEGALITY_ORACLE.md), as a tool. R order C11 (2026-11-06).

The oracle proves a schedule never protects *less* than the frozen nvcc
schedule of the same stream -- the class of the 2026-06 2-CTA/SM WAR defect
(`ebbd1dc`, a missing store-address read barrier). It drives cubit's own
scoreboard verifier (`CUBIT_VERIFY=1 cubit asm` on frozen text; the verifier of
`src/scheduling_pass.rs` -- loop-aware, DEPBAR-aware, late-latch distance
semantics) so ALL register/operand extraction stays in cubit, and adds the one
layer the verifier cannot see by construction:

  * rb-coverage probe (the `ebbd1dc` shape): the verifier only tracks a
    late-latched operand if the reader carries a read barrier (R slot). A
    schedule that never SET the barrier is invisible to it. The probe runs
    the verifier in `CUBIT_VERIFY_RBPROBE=1` mode (cubit
    `verify_scoreboard_rb_probe`): every late-latching mem-op without a read
    barrier is tracked under a virtual barrier nothing ever waits, so every
    overwriter of its late-latched operands is a BROKEN WAR: an un-protected
    race on a late-latched operand -- exactly what the 2026-06 scheduler bug
    produced. (The first design injected a free barrier index into the R
    slot and re-verified; nvcc uses all six scoreboards on most real kernels,
    so that probe ran on none of them -- "no-free-barrier".) Findings on
    R255 (RZ, the architectural zero register: a write never changes what a
    store latches from it) are non-events and filtered; findings whose writer
    is not reachable from the mem-op in the static control-flow graph are
    listed as `unreachable` (the verifier's linear walk, not a race); a
    mem-op's late operands are released by a wait on its write barrier as
    well (its result landed, so its operands were consumed -- BUG-486).

Required properties (the oracle's own self-test, `--self-test`):
  P1  frozen nvcc schedules: 0 verifier findings, 0 probe findings per kernel;
  P2  the `ebbd1dc` reproducer is REJECTED:
        - wait-stripped variant (rb set, overwriter does not wait it) -> the
          verifier's BROKEN WAR;
        - rb-missing variant (the historical bug: no barrier ever set) -> the
          probe's WAR-UNPROTECTED;
  P3  per-kernel results (text + --json).

Modes:
  --cubin C [C ..]        oracle over cubins (frozen disassembly inside)
  --corpus LIST           a file with one cubin path per line (e.g. the
                          verify3 corpus103.txt); '#' comments allowed
  --text FILE.sass        oracle over already-frozen text (the K/k1/frozen
                          schedules for A19 come this way)
  --resched               additionally strip the control codes, let cubit
                          re-schedule (asm auto path) and oracle THAT
                          schedule too -- "cubit never protects less"
  --stats                 per-kernel schedule statistics (rb/wb/wait sites,
                          stall sums, rb histogram per late-latch class) --
                          the A19 barrier-accounting data
  --stallfix              invariant 6: run `cubit stallfix` in report mode
                          (plan = whole-kernel windows); total_raises == 0
                          means every ALU->ALU dependency sits at/above the
                          measured stall floors of the table
  --self-test             P1/P2 on an embedded reproducer; exit 1 on failure
  --json OUT              machine-readable results
  --cubit BIN             cubit binary (default: $CUBIT_BIN, then
                          <repo>/target/release/cubit)

The tool never mutates inputs; probe runs happen on temp copies.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# ---------------------------------------------------------------------------
# cubit driver
# ---------------------------------------------------------------------------

def find_cubit(explicit: str | None) -> str:
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get("CUBIT_BIN"):
        cands.append(os.environ["CUBIT_BIN"])
    cands.append(os.path.join(REPO, "target", "release", "cubit"))
    for c in cands:
        if c and os.access(c, os.X_OK):
            return c
    sys.exit("sched_oracle: no cubit binary (use --cubit or $CUBIT_BIN)")


def run_cubit(cubit, args, env=None, timeout=300):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([cubit, *args], capture_output=True, text=True,
                           timeout=timeout, env=e)


def elf_arch(cubin: str) -> str | None:
    """SM number from the ELF header (both identity layouts)."""
    try:
        with open(cubin, "rb") as f:
            b = f.read(0x34)
    except OSError:
        return None
    if len(b) < 0x34 or b[:4] != b"\x7fELF":
        return None
    ef = struct.unpack_from("<I", b, 0x30)[0]
    if (ef >> 24) == 0x06:          # CUDA-13 identity: 0x06_00_SS_fX
        return str((ef >> 8) & 0xFF)
    if ((ef >> 24) == 0x00) and (ef & 0xFF) == ((ef >> 16) & 0xFF):
        return str((ef >> 16) & 0xFF)  # CUDA-12 identity: 0x00_SS_05_SS
    return None


def table_for(path: str, prefer: str | None) -> str:
    if prefer:
        return os.path.join(REPO, "tables", prefer + ".json")
    if path.endswith((".sass", ".txt", ".frozen.sass")):
        with open(path) as f:
            head = f.read(4096)
        m = re.search(r";;\s*era=sm(\d+)", head)
        name = {"100": "sm100a", "103": "sm103a", "120": "sm120",
                "121": "sm121a"}.get(m.group(1) if m else "")
        if name is None:
            sys.exit(f"sched_oracle: no ;; era= header in {path}; pass --table")
        return os.path.join(REPO, "tables", name + ".json")
    arch = elf_arch(path)
    name = {"100": "sm100a", "103": "sm103a", "120": "sm120",
            "121": "sm121a"}.get(arch or "")
    if name is None:
        sys.exit(f"sched_oracle: cannot determine arch of {path} (e_flags)")
    return os.path.join(REPO, "tables", name + ".json")


# ---------------------------------------------------------------------------
# frozen text parsing
# ---------------------------------------------------------------------------

CTRL_RE = re.compile(
    r"\[B(?P<wait>[0-9-]{6}):R(?P<r>[0-9-]):W(?P<w>[0-9-]):(?P<y>[Y-]):S(?P<s>\d{2})\]")

LINE_CODE_RE = re.compile(
    r"^\s*(?P<label>L_[\w]+:\s*)?(?P<ccode>" + CTRL_RE.pattern
    + r")\s*(?P<body>.*)$")
TRAIL_CODE_RE = re.compile(
    r"^(?P<lead>\s*(?:L_[\w]+:\s*)?)(?P<body>.*?;)\s*(?P<ccode>" + CTRL_RE.pattern
    + r")\s*$")


class Code:
    __slots__ = ("wait", "r", "w", "y", "s")

    def __init__(self, wait=0, r="-", w="-", y=False, s=1):
        self.wait, self.r, self.w, self.y, self.s = wait, r, w, y, s

    def fmt(self):
        b = "".join(str(i) if self.wait & (1 << i) else "-" for i in range(6))
        return f"[B{b}:R{self.r}:W{self.w}:{'Y' if self.y else '-'}:S{self.s:02d}]"


class Insn:
    __slots__ = ("idx", "raw", "code", "body", "opcode", "lead", "trail")

    def __init__(self, idx, raw, code, body, lead, trail=False):
        self.idx, self.raw, self.code, self.body, self.lead = idx, raw, code, body, lead
        self.trail = trail
        m = re.match(r"(@!?U?P[T0-6]\s+)?([A-Z0-9@_.]+)", body.strip())
        self.opcode = (m.group(2) if m else body.split()[0]).split(".")[0]


def parse_frozen(text: str):
    """-> [(kernel_name, [Insn|str])] -- strings are non-instruction lines
    (directives/labels) preserved verbatim for re-emission."""
    kernels = []
    cur_name, cur = None, []
    idx = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith(".entry"):
            cur_name = stripped.split()[1]
            idx = 0
            cur = [raw]
            continue
        if cur_name is None:
            continue  # file header (;; era=..)
        if stripped.startswith(".endentry"):
            cur.append(raw)
            kernels.append((cur_name, cur))
            cur_name, cur = None, None
            continue
        m = LINE_CODE_RE.match(raw)
        if m:
            code = Code(
                wait=sum(1 << i for i, c in enumerate(m.group("wait")) if c != "-"),
                r=m.group("r"), w=m.group("w"),
                y=m.group("y") == "Y", s=int(m.group("s")))
            # lead = indentation + any label (`L_x: [code] INSN`), preserved
            # verbatim on re-emit so labels stay ahead of the code
            cur.append(Insn(idx, raw, code, m.group("body").strip(),
                            raw[: m.start("ccode")]))
            idx += 1
            continue
        m = TRAIL_CODE_RE.match(raw)
        if m and not stripped.startswith((".", "L_", ";;")):
            code = Code(
                wait=sum(1 << i for i, c in enumerate(m.group("wait")) if c != "-"),
                r=m.group("r"), w=m.group("w"),
                y=m.group("y") == "Y", s=int(m.group("s")))
            cur.append(Insn(idx, raw, code, m.group("body").strip(),
                            m.group("lead"), trail=True))
            idx += 1
            continue
        cur.append(raw)
    if cur_name is not None:
        kernels.append((cur_name, cur))
    return kernels


def emit(lines) -> str:
    out = []
    for it in lines:
        if isinstance(it, Insn):
            if it.trail:
                out.append(f"{it.lead}{it.body} {it.code.fmt()}")
            else:
                out.append(f"{it.lead}{it.code.fmt()} {it.body}")
        else:
            out.append(it)
    return "\n".join(out) + "\n"


def strip_codes(lines) -> str:
    out = []
    for it in lines:
        if isinstance(it, Insn):
            out.append(it.body)
        else:
            out.append(it)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# late-latch classification (mirrors scheduling_pass::late_operands /
# the verifier's rbp fill; conservative: a misclassification can only make the
# probe *find nothing* for that candidate, never invent a hazard)
# ---------------------------------------------------------------------------

GLOBAL_STORE = {"STG", "ST", "STGX"}
WARP_MMA = {"QMMA", "HMMA", "IMMA", "DMMA"}
ATOMIC = {"ATOM", "ATOMS", "ATOMG", "RED", "REDG"}
LOADS = {"LDG", "LDL", "LDS", "LDC", "LDCU", "LDGX", "LDSM", "LDGSTS", "LD"}

RNUM = re.compile(r"\bR(\d{1,3})\b")
ADDR_BASE = re.compile(r"\[R(\d{1,3})")


def reg_tokens(body: str):
    return {int(m.group(1)) for m in RNUM.finditer(body)}


def addr_base(body: str, wide_pair: bool):
    m = ADDR_BASE.search(body)
    if not m:
        return set()
    r = int(m.group(1))
    return {r, r + 1} if wide_pair else {r}


def data_width(opcode_full: str) -> int:
    if ".256" in opcode_full:
        return 8
    if ".128" in opcode_full:
        return 4
    if ".64" in opcode_full:
        return 2
    if ".U16" in opcode_full or ".S16" in opcode_full:
        return 1
    return 1


def late_latch_regs(body: str):
    """Conservative late-latched GPR set of one instruction (for batch
    disjointness + candidate triage only -- cubit's verifier does the actual
    hazard detection). Returns (class, regs). A misclassification can only
    make the probe find nothing for that candidate, never invent a hazard."""
    m = re.match(r"(@!?U?P[T0-6]\s+)?([A-Z0-9@_.]+)", body.strip())
    if not m:
        return None, set()
    opfull = m.group(2)
    op = opfull.split(".")[0]
    if op in GLOBAL_STORE:
        wide = ".64" in opfull or "WIDE" in opfull
        regs = addr_base(body, wide)
        w = data_width(opfull)
        toks = sorted(reg_tokens(body) - regs)
        if toks:
            r0 = toks[0]
            regs |= {r0 + i for i in range(w) if r0 + i < 255}
        return "store", regs
    if op in WARP_MMA:
        toks = sorted(reg_tokens(body))
        if toks:
            r0 = toks[0]
            return "mma", {r0 + i for i in range(4) if r0 + i < 255} | set(toks)
        return "mma", set()
    if op in ATOMIC:
        wide = op in ("ATOMG", "RED", "REDG", "ATOM")
        regs = addr_base(body, wide)
        toks = sorted(reg_tokens(body) - regs)
        if toks:
            r0 = toks[0]
            regs |= {r0 + i for i in range(2) if r0 + i < 255}
        return "atom", regs
    if op in LOADS:
        wide = ".64" in opfull
        regs = addr_base(body, wide)
        dest = sorted(reg_tokens(body) - regs)
        if dest and dest[0] in regs:
            return "load-selfref", set()  # consumes its address at issue
        return "load", regs
    return None, set()


# ---------------------------------------------------------------------------
# verify driver
# ---------------------------------------------------------------------------

EV_RE = re.compile(r"^\s+(UNPROTECTED RAW|BROKEN WAR|RECYCLE-STALE): (.*)$")
WAR_RE = re.compile(
    r"BROKEN WAR: insn\[(\d+)\] .* overwrites R(\d+) before rb \(barrier (\d+)\) "
    r"of mem-op insn\[(\d+)\]")
SUM_RE = re.compile(r"CUBIT_VERIFY: (\d+) unprotected RAW, (\d+) broken WAR, (\d+) recycle-stale")
LOOP_RE = re.compile(r"CUBIT_VERIFY_LOOP: (\d+) unresolvable control-flow edge")
ENC_RE = re.compile(r"^\s+(\S+): (\d+)/(\d+) encoded \((\d+) failed\)")


def verify_text(cubit, table, text, scratch, probe=False):
    """CUBIT_VERIFY=1 asm on frozen text -> per-kernel dicts with counts and
    parsed event lines. Verify runs before encoding, so even kernels whose
    re-encode fails (census real-gap words) still produce a report.
    `probe=True` adds CUBIT_VERIFY_RBPROBE=1 (the rb-coverage probe)."""
    src = os.path.join(scratch, "probe_in.sass")
    out = os.path.join(scratch, "probe_out.cubin")
    with open(src, "w") as f:
        f.write(text)
    env = {"CUBIT_VERIFY": "1"}
    if probe:
        env["CUBIT_VERIFY_RBPROBE"] = "1"
    try:
        r = run_cubit(cubit, ["asm", "--table", table, "--output", out, src],
                      env=env, timeout=600)
    except subprocess.TimeoutExpired:
        return None, [{"error": "asm timeout"}]
    kernels = []
    cur = None
    pending = []  # verifier events print BEFORE their kernel's summary line
    for line in (r.stderr or "").splitlines():
        m = SUM_RE.search(line)
        if m:
            cur = {"raw": int(m.group(1)), "war": int(m.group(2)),
                   "recycle": int(m.group(3)), "events": pending, "loop_unresolved": 0}
            pending = []
            kernels.append(cur)
            continue
        if cur is not None:
            m2 = LOOP_RE.search(line)
            if m2:
                cur["loop_unresolved"] = int(m2.group(1))
                continue
            if EV_RE.match(line):
                cur["events"].append(line.strip())
                continue
            m3 = ENC_RE.match(line)
            if m3:
                cur["name"], cur["encode_failed"] = m3.group(1), int(m3.group(4))
                cur = None
                continue
        if EV_RE.match(line):
            pending.append(line.strip())
    if not kernels:
        return r, [{"error": "no CUBIT_VERIFY output",
                    "stderr_tail": (r.stderr or "")[-400:], "rc": r.returncode}]
    return r, kernels


# ---------------------------------------------------------------------------
# the rb-coverage probe (the ebbd1dc shape)
# ---------------------------------------------------------------------------

def klass_of(cands, midx):
    for it, klass, _ in cands:
        if it.idx == midx:
            return klass
    return "?"


def probe_kernel(cubit, table, lines, scratch):
    """The rb-coverage probe: cubit's verifier in `CUBIT_VERIFY_RBPROBE=1` mode
    tracks every late-latching mem-op WITHOUT a read barrier under a virtual
    barrier nothing ever waits (`verify_scoreboard_rb_probe`), so each
    overwriter of such a mem-op's late-latched operands is a BROKEN WAR tagged
    "(probe: …)". One run per kernel; no free scoreboard needed (nvcc uses all
    six on most census kernels, which left the first design — inject a free
    barrier index into the R slot — with nothing to inject). RZ (R255) findings
    are filtered — the architectural zero register cannot race."""
    cands = []
    for it in lines:
        if not isinstance(it, Insn) or it.code.r != "-":
            continue
        klass, regs = late_latch_regs(it.body)
        regs = {r for r in regs if r < 255}
        if klass is None or not regs:
            continue
        cands.append((it, klass, regs))
    _, reps = verify_text(cubit, table, emit(lines), scratch, probe=True)
    findings = []
    for rep in reps:
        if "error" in rep:
            return {"status": "error", "findings": [], "n_candidates": len(cands),
                    "error": rep}
        for ev in rep.get("events", []):
            if "(probe:" not in ev:
                continue
            m = WAR_RE.search(ev)
            if not m:
                continue
            widx, r, midx = int(m.group(1)), int(m.group(2)), int(m.group(4))
            if r == 255:
                continue
            findings.append({"writer_idx": widx, "reg": r, "memop_idx": midx,
                             "class": klass_of(cands, midx), "event": ev})
    return {"status": "probed", "findings": findings, "n_candidates": len(cands),
            "probe_barrier": "virtual"}


# ---------------------------------------------------------------------------
# stats (the A19 barrier accounting)
# ---------------------------------------------------------------------------

def stats_kernel(lines):
    st = {"n": 0, "rb_sites": 0, "wb_sites": 0, "wait_sites": 0, "stall_sum": 0,
          "rb_hist": {}, "late_rb": {}, "late_norb": {}}
    for it in lines:
        if not isinstance(it, Insn):
            continue
        st["n"] += 1
        st["stall_sum"] += it.code.s
        if it.code.r != "-":
            st["rb_sites"] += 1
            st["rb_hist"][it.code.r] = st["rb_hist"].get(it.code.r, 0) + 1
        if it.code.w != "-":
            st["wb_sites"] += 1
        if it.code.wait:
            st["wait_sites"] += 1
        klass, _ = late_latch_regs(it.body)
        if klass in ("store", "mma", "atom", "load"):
            if it.code.r == "-":
                st["late_norb"][klass] = st["late_norb"].get(klass, 0) + 1
            else:
                st["late_rb"][klass] = st["late_rb"].get(klass, 0) + 1
    return st


# Verdict classes, measured on the sm_120 production census (T-9, 2026-11-06, 752
# frozen nvcc kernels / 1 811 600 words, `T/t9/oracle/`) -- the ptxas evidence
# cubit's stricter model is compared against:
#   * `mma-source-rb`: cubit's allocator protects an MMA's source fragments with
#     a read barrier when a later load overwrites them; ptxas sets a read
#     barrier on 0 of the census's 39 624 HMMA/QMMA (840 661 overwriter sites,
#     LDS/LDSM among them at S01) -- the MMA reads its fragments at issue on
#     sm_120.  DIVERGENCE (cubit stricter), never a REJECT.
#   * `store-latch-distance`: ptxas overwrites a global store's address/data
#     registers without waiting its read barrier (or without setting one) once
#     >= STORE_LATCH_FLOOR issue cycles have passed on the shortest control-flow
#     path (census minimum 20: `STG.E desc[UR12][R28.64+0x380], R39` ... `MOV R29`
#     in the FlashInfer sparse-MLA kernels; 132 sites between 20 and 42, 1 099
#     above; cubit's verifier: "distance does NOT cover a store" -- its 2026-06
#     race was at 25 cycles, a contradiction left to a silicon A/B).  >= floor:
#     DIVERGENCE with the distance; below: REJECT.
#   * `lds-address-latch` (soft): LDS/LDSM/LDL address registers overwritten
#     before the load's result is waited (ptxas does it at S01 and up; cubit's
#     model says the MIO replay can re-latch the address).  DIVERGENCE.
#   * `load-address-latch`: the verifier's own WAR on a load that carries a read
#     barrier, overwritten inside the 3-cycle LOAD_ADDR_LATCH window without the
#     wait (census: `LDGSTS` + `IADD.64` of its address pair at 2 cycles).
#     DIVERGENCE.
#   * `recycle`: a scoreboard re-armed by a producer of another latency class
#     while an earlier result is still pending -- a hazard under last-only
#     semantics, none under the counter semantics ptxas (and cubit's
#     CUBIT_SB_SHARE policy, A13) rely on.  DIVERGENCE.
#   * `guard-complement`: an UNPROTECTED RAW whose producer and consumer carry
#     complementary guards (`@P1 LDG R19` ... `@!P1 PRMT R19`) -- the verifier
#     is predicate-blind.  DIVERGENCE.
#   * `nonlinear-path`: the two instructions are connected only through a jump
#     (an unconditional BRA / EXIT / RET lies between them in the text): the
#     verifier's linear walk carried a fall-through state that no path has
#     and saw none of the waits on the real paths -- a limitation of the walk,
#     reported, not a race.  DIVERGENCE.
#   * `unreachable`: the writer is not reachable from the mem-op in the static
#     control-flow graph (a subroutine body behind the store's EXIT; the
#     verifier's walk is linear).  Listed, not counted.
# Everything else (an unprotected RAW, a store/atomic overwriter below the
# floor, a verifier WAR that is not a store-distance case) is a REJECT.
HARD_CLASSES = {"store", "atom"}
MMA_CLASSES = {"mma"}
SOFT_CLASSES = {"load", "load-selfref"}
STORE_LATCH_FLOOR = 20


def stall_distance(lines, a: int, b: int):
    """Sum of the S codes strictly between instruction a and b (linear)."""
    total = 0
    for it in lines:
        if isinstance(it, Insn) and a < it.idx < b:
            total += it.code.s
    return total


LABEL_RE = re.compile(r"\b(L_[\w]+)\b")
UNCOND_TERMINATORS = {"EXIT", "RET", "BRA", "JMP", "BRX", "BRXU", "JMX", "JMXU",
                      "KILL", "BREAK"}


def reachable_from(lines):
    """Forward reachability over the kernel's static control-flow graph:
    returns a function memop_idx -> set of instruction indices reachable from
    it (the mem-op itself excluded unless a loop returns to it).

    Successors: the fall-through unless the instruction is an UNGUARDED
    terminator (EXIT / RET / unconditional BRA / register-indirect dispatch /
    KILL / BREAK); the static label targets of BRA / CALL / BSSY-class
    operands (`L_x`); nothing for RET (a return continues at the CALL's
    fall-through, which the CALL already has). The verifier's walk is linear
    and carries state across such terminators (that is pessimism it keeps for
    cubit's own schedules); here it would turn a bare store before an EXIT
    into "races" against the out-of-line subroutines that follow it in the
    text (T-9's reading of the C11 corpus: 16 REJECTs were this + BUG-486)."""
    insns = [it for it in lines if isinstance(it, Insn)]
    label_at = {}
    for it in insns:
        for m in LABEL_RE.finditer(it.lead):
            label_at.setdefault(m.group(1), it.idx)
    # a label on its own line (no instruction) binds to the next instruction
    pending = []
    for it in lines:
        if isinstance(it, Insn):
            for lab in pending:
                label_at.setdefault(lab, it.idx)
            pending = []
        else:
            s = it.strip()
            if s.endswith(":") and s.startswith("L_"):
                pending.append(s[:-1])
    def bra_is_unconditional(body):
        # `BRA L_x` / `BRA PT, L_x` fall through never; `BRA P0, L_x`, `@P0 BRA`,
        # `BRA.DIV P0, URZ, L_x`, `BRA.CONV ~UR6, L_x` can.
        m = re.match(r"BRA((?:\.\w+)*)\s*(.*)$", body.split(";")[0])
        if not m or ".DIV" in m.group(1) or ".CONV" in m.group(1):
            return False
        toks = [t.strip() for t in m.group(2).split(",")]
        return not any(re.fullmatch(r"!?U?P[0-6]", t) for t in toks)

    succ = {}
    n = len(insns)
    for it in insns:
        out = set()
        body = it.body.strip()
        guarded = body.startswith("@")
        op = it.opcode
        terminates = op == "RET" or (
            not guarded and op in UNCOND_TERMINATORS
            and (op != "BRA" or bra_is_unconditional(body)))
        if not terminates and it.idx + 1 < n:
            out.add(it.idx + 1)
        if op in ("BRA", "CALL", "BSSY", "JMP", "BRX", "BRXU", "JMX", "JMXU"):
            for m in LABEL_RE.finditer(body):
                if m.group(1) in label_at:
                    out.add(label_at[m.group(1)])
        succ[it.idx] = out
    stall = {it.idx: it.code.s for it in insns}
    cache = {}

    def dist(start):
        """Shortest issue distance (sum of S codes of the instructions issued strictly between)
        from `start` to every instruction reachable from it (Dijkstra, non-negative weights)."""
        if start in cache:
            return cache[start]
        import heapq
        best = {}
        heap = [(0, k) for k in succ.get(start, ())]
        heapq.heapify(heap)
        while heap:
            d, k = heapq.heappop(heap)
            if k in best:
                continue
            best[k] = d
            for nk in succ.get(k, ()):
                if nk not in best:
                    heapq.heappush(heap, (d + stall.get(k, 0), nk))
        cache[start] = best
        return best

    def reach(start):
        return dist(start)
    reach.dist = dist
    return reach


def back_edge_distance(lines, memop, writer):
    """Issue distance of a loop-carried pair (writer index < mem-op index):
    stalls from the mem-op to the first backward branch after it whose
    target is at or before the writer, plus stalls from that target to the
    writer. None when no such branch exists (the verifier saw an edge the
    text does not show)."""
    insns = [it for it in lines if isinstance(it, Insn)]
    label_at = {}
    for it in insns:
        for m in LABEL_RE.finditer(it.lead):
            label_at.setdefault(m.group(1), it.idx)
    for it in insns:
        if it.idx < memop or it.opcode not in ("BRA", "JMP"):
            continue
        for m in LABEL_RE.finditer(it.body):
            t = label_at.get(m.group(1))
            if t is not None and t <= writer:
                d = sum(x.code.s for x in insns if memop < x.idx <= it.idx)
                d += sum(x.code.s for x in insns if t <= x.idx < writer)
                return d
    return None


def linear_segment_has_terminator(lines, a, b):
    """True when an UNGUARDED EXIT / RET / unconditional BRA / register dispatch lies strictly
    between a and b in text order (the verifier's linear walk crossed it)."""
    lo, hi = (a, b) if a < b else (b, a)
    for it in lines:
        if not isinstance(it, Insn) or not (lo < it.idx < hi):
            continue
        body = it.body.strip()
        if body.startswith("@"):
            continue
        if it.opcode == "RET" or (it.opcode in UNCOND_TERMINATORS and it.opcode != "BRA"):
            return True
        if it.opcode == "BRA":
            m = re.match(r"BRA((?:\.\w+)*)\s*(.*)$", body.split(";")[0])
            if m and ".DIV" not in m.group(1) and ".CONV" not in m.group(1):
                toks = [t.strip() for t in m.group(2).split(",")]
                if not any(re.fullmatch(r"!?U?P[0-6]", t) for t in toks):
                    return True
    return False


def guards_complementary(lines, a, b):
    """True when instructions a and b carry guards on the same predicate with
    opposite polarity (`@P1` / `@!P1`): at most one of them executes."""
    g = {}
    for it in lines:
        if isinstance(it, Insn) and it.idx in (a, b):
            m = re.match(r"@(!?)(U?P[0-6T])\b", it.body.strip())
            g[it.idx] = (m.group(2), m.group(1) == "!") if m else None
    ga, gb = g.get(a), g.get(b)
    return bool(ga and gb and ga[0] == gb[0] and ga[1] != gb[1] and ga[0] not in ("PT", "UPT"))


def classify_findings(findings, lines):
    """Tag each probe finding with reader class + issue distance and route it:
    hard (a store/atomic overwriter below STORE_LATCH_FLOOR -> REJECT),
    divergence (a documented class, see the table above), soft (LDS-address
    class) and unreachable (control-flow artefact)."""
    hard, soft, unreachable, diverg = [], [], [], []
    reach = reachable_from(lines)
    for f in findings:
        paths = reach(f["memop_idx"])
        if f["writer_idx"] not in paths:
            f["distance"] = None
            f["unreachable"] = True
            unreachable.append(f)
            continue
        # the shortest control-flow path, not the text order: a writer behind an unconditional
        # branch is reached through the branch's target, never by falling through it
        f["distance"] = paths[f["writer_idx"]]
        if f["writer_idx"] < f["memop_idx"]:
            f["wrap"] = True
        if linear_segment_has_terminator(lines, f["memop_idx"], f["writer_idx"]):
            # the verifier walked the text across an unconditional jump: the state it carried into
            # the writer is the fall-through state of a path that does not exist; whatever the real
            # paths do (waits, re-arms) it did not see -- a limitation of the linear walk, reported
            f["divergence"] = "nonlinear-path"
            diverg.append(f)
        elif f["class"] in MMA_CLASSES:
            f["divergence"] = "mma-source-rb"
            diverg.append(f)
        elif f["class"] in HARD_CLASSES:
            d = f["distance"]
            if isinstance(d, int) and d >= STORE_LATCH_FLOOR:
                f["divergence"] = "store-latch-distance"
                diverg.append(f)
            else:
                hard.append(f)
        else:
            f["divergence"] = "lds-address-latch"
            soft.append(f)
    return hard, soft, unreachable, diverg


def classify_verifier_events(events, lines):
    """Route the plain verifier's events: a BROKEN WAR on a store whose
    overwriter sits >= STORE_LATCH_FLOOR cycles away and an UNPROTECTED RAW
    between complementary guards are documented divergences; an event whose
    second instruction is not reachable from the first in the control-flow
    graph is the linear walk's artefact (listed as `unreachable`); everything
    else stays a core violation. Returns (core_raw, core_war, divergences,
    unreachable)."""
    core_raw = core_war = 0
    div, unreachable = [], []
    reach = reachable_from(lines)
    for ev in events:
        m = WAR_RE.search(ev)
        if m:
            widx, _r, midx = int(m.group(1)), int(m.group(2)), int(m.group(4))
            paths = reach(midx)
            if widx not in paths:
                unreachable.append({"event": ev})
                continue
            if linear_segment_has_terminator(lines, midx, widx):
                div.append({"divergence": "nonlinear-path", "event": ev})
                continue
            mop = ev.split("of mem-op insn[")[1].split("] ")[1].split()[0] if "of mem-op insn[" in ev else ""
            mbase = mop.split(".")[0]
            d = paths[widx]
            if mbase in GLOBAL_STORE and isinstance(d, int) and d >= STORE_LATCH_FLOOR:
                div.append({"divergence": "store-latch-distance", "distance": d, "event": ev})
            elif mbase in LOADS:
                # a load's address register overwritten inside cubit's LOAD_ADDR_LATCH window (3
                # issue cycles; LDS/LDSM/LDL never covered) while ptxas left the overwriter without
                # the wait: the address was consumed at issue (census: LDGSTS at 2 cycles)
                div.append({"divergence": "load-address-latch", "distance": d, "event": ev})
            else:
                core_war += 1
            continue
        mr = re.search(r"UNPROTECTED RAW: insn\[(\d+)\] .* <- var-producer insn\[(\d+)\]", ev)
        if mr:
            ci, pi = int(mr.group(1)), int(mr.group(2))
            if ci not in reach(pi):
                unreachable.append({"event": ev})
            elif guards_complementary(lines, ci, pi):
                div.append({"divergence": "guard-complement", "event": ev})
            elif linear_segment_has_terminator(lines, pi, ci):
                div.append({"divergence": "nonlinear-path", "event": ev})
            else:
                core_raw += 1
    return core_raw, core_war, div, unreachable


# ---------------------------------------------------------------------------
# stallfix report (invariant 6)
# ---------------------------------------------------------------------------

def stallfix_raises(cubit, table, text, scratch):
    arch = json.load(open(table))["stallfix"]["arch"]
    plan = {"arch": arch, "kernels": {}}
    for name, lines in parse_frozen(text):
        n = sum(1 for x in lines if isinstance(x, Insn))
        plan["kernels"][name] = {"windows": [[0, n]]}
    plan_path = os.path.join(scratch, "stallfix_plan.json")
    with open(plan_path, "w") as f:
        json.dump(plan, f)
    src = os.path.join(scratch, "stallfix_in.sass")
    with open(src, "w") as f:
        f.write(text)
    try:
        r = run_cubit(cubit, ["stallfix", "--plan", plan_path, "--rules", table, src],
                      timeout=600)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return {"error": (r.stderr or "")[-300:]}
    try:
        rep = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None
    return {"total_raises": rep.get("total_raises"),
            "kernels": {k.get("name"): k.get("total_raises", k.get("raises"))
                        for k in rep.get("kernels", [])}}


# ---------------------------------------------------------------------------
# oracle entry point over one frozen text
# ---------------------------------------------------------------------------

def oracle_text(cubit, table, text, scratch, do_stats=False, do_stallfix=False):
    results = []
    for name, lines in parse_frozen(text):
        res = {"name": name, "table": os.path.basename(table)}
        _, reps = verify_text(cubit, table, emit(lines), scratch)
        res["verify_errors"] = [x for x in reps if "error" in x]
        reps_ok = [x for x in reps if "error" not in x]
        rep = reps_ok[0] if reps_ok else {"raw": -1, "war": -1, "recycle": -1}
        res.update({k: rep.get(k, 0) for k in ("raw", "war", "recycle", "loop_unresolved")})
        res["verify_events"] = rep.get("events", [])[:20]
        core_raw, core_war, vdiv, vunr = classify_verifier_events(rep.get("events", []), lines)
        # the verifier prints every event, so the routed counts are exact
        res["core_raw"], res["core_war"] = core_raw, core_war
        res["verifier_divergences"] = vdiv
        res["verifier_unreachable"] = vunr
        res["core_events"] = [e for e in rep.get("events", [])
                              if (e.startswith("BROKEN WAR") or e.startswith("UNPROTECTED RAW"))
                              and e not in {x["event"] for x in vdiv} and e not in {x["event"] for x in vunr}][:12]
        probe = probe_kernel(cubit, table, lines, scratch)
        hard, soft, unreachable, diverg = classify_findings(probe.get("findings", []), lines)
        probe["findings_hard"] = hard
        probe["findings_soft"] = soft
        probe["findings_unreachable"] = unreachable
        probe["findings_divergence"] = diverg
        res["probe"] = probe
        res["rb_war_findings"] = len(hard) + len(soft)
        res["rb_war_hard"] = len(hard)
        res["rb_war_unreachable"] = len(unreachable) + len(vunr)
        dclasses = {}
        for f in diverg + vdiv + soft:
            dclasses[f["divergence"]] = dclasses.get(f["divergence"], 0) + 1
        if res["recycle"]:
            dclasses["recycle"] = res["recycle"]
        res["divergence_classes"] = dclasses
        if do_stats:
            res["stats"] = stats_kernel(lines)
        if do_stallfix:
            sf = stallfix_raises(cubit, table, emit(lines), scratch)
            res["stallfix_raises"] = (sf or {}).get("total_raises", "unavailable")
        # Verdict semantics (docs/SCHED_LEGALITY_ORACLE.md mode 2):
        #  REJECT      -- a core protection invariant is violated (RAW / WAR /
        #                 a hard late-latch probe finding: never acceptable);
        #  DIVERGENCE  -- cubit's model is stricter than nvcc's discipline on
        #                 this kernel (recycle over-approximation on nvcc's
        #                 fixed-latency producers, or LDS-replay-window probe
        #                 findings at large/loop-carried distances); the safe
        #                 direction for this oracle -- reported with data for
        #                 the owner/T doctrine, never silenced;
        #  ACCEPT      -- clean on every counter (probe findings whose writer
        #                 is not reachable from the mem-op in the control-flow
        #                 graph are listed, never counted: a linear-walk artefact).
        core_bad = res["core_raw"] or res["core_war"] or res["rb_war_hard"]
        if res["verify_errors"] or res["raw"] < 0:
            res["status"] = "ERROR"
        elif core_bad:
            res["status"] = "REJECT"
        elif dclasses:
            res["status"] = "DIVERGENCE"
        else:
            res["status"] = "ACCEPT"
        results.append(res)
    return results


# ---------------------------------------------------------------------------
# embedded reproducer (the ebbd1dc class) -- self-test P1/P2
# ---------------------------------------------------------------------------

REPRO_HEADER = ".entry war_repro\n    .reg R0-R15\n    .param ptr p0 offset=0x0\n"
REPRO_TAIL = "    .endentry\n"
REPRO_CLEAN = REPRO_HEADER + """    [B------:R-:W-:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W-:Y:S01] LDC.64 R2, c[0x0][0x380] ;
    [B------:R-:W-:Y:S01] LDC.64 R4, c[0x0][0x388] ;
    [B0-----:R-:W-:Y:S01] LDG.E.64 R8, desc[UR4][R4.64] ;
    [B------:R0:W-:Y:S01] STG.E.64 desc[UR4][R2.64], R8 ;
    [B0-----:R-:W-:Y:S01] IMAD.MOV.U32 R2, RZ, RZ, 0x10 ;
    [B------:R-:W-:Y:S01] EXIT ;
""" + REPRO_TAIL
# the historical defect, wait-stripped variant: the writer overwrites the
# store's address pair without waiting its read barrier -- verifier rejects
REPRO_WAIT_BROKEN = REPRO_HEADER + """    [B------:R-:W-:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W-:Y:S01] LDC.64 R2, c[0x0][0x380] ;
    [B------:R-:W-:Y:S01] LDC.64 R4, c[0x0][0x388] ;
    [B0-----:R-:W-:Y:S01] LDG.E.64 R8, desc[UR4][R4.64] ;
    [B------:R0:W-:Y:S01] STG.E.64 desc[UR4][R2.64], R8 ;
    [B------:R-:W-:Y:S01] IMAD.MOV.U32 R2, RZ, RZ, 0x10 ;
    [B------:R-:W-:Y:S01] EXIT ;
""" + REPRO_TAIL
# the pure 2026-06 shape: the read barrier was never set at all -- invisible
# to the verifier, must be caught by the rb-coverage probe
REPRO_RB_MISSING = REPRO_HEADER + """    [B------:R-:W-:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W-:Y:S01] LDC.64 R2, c[0x0][0x380] ;
    [B------:R-:W-:Y:S01] LDC.64 R4, c[0x0][0x388] ;
    [B0-----:R-:W-:Y:S01] LDG.E.64 R8, desc[UR4][R4.64] ;
    [B------:R-:W-:Y:S01] STG.E.64 desc[UR4][R2.64], R8 ;
    [B------:R-:W-:Y:S01] IMAD.MOV.U32 R2, RZ, RZ, 0x10 ;
    [B------:R-:W-:Y:S01] EXIT ;
""" + REPRO_TAIL


def self_test(cubit, scratch):
    table = os.path.join(REPO, "tables", "sm103a.json")
    ok = True

    def run(name, text, expect, expect_probe=False):
        nonlocal ok
        res = oracle_text(cubit, table, text, scratch)[0]
        good = res["status"] == expect and \
            (not expect_probe or res["rb_war_findings"] > 0)
        ok &= good
        print(f"  {'PASS' if good else 'FAIL'} {name}: status={res['status']} "
              f"(raw={res['raw']} war={res['war']} probe={res['rb_war_findings']})")
        if not good:
            print(json.dumps(res, indent=1)[:800])
        return res

    print("sched_oracle self-test (the ebbd1dc class, table sm103a):")
    run("P1  clean nvcc-style schedule ACCEPT ", REPRO_CLEAN, "ACCEPT")
    run("P2a wait-stripped  -> verifier REJECT", REPRO_WAIT_BROKEN, "REJECT")
    run("P2b rb-missing     -> probe    REJECT", REPRO_RB_MISSING, "REJECT",
        expect_probe=True)
    print("SELF-TEST:", "ALL-PASS" if ok else "FAILED")
    return ok


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="static scheduling-legality oracle (A4)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--cubin", nargs="+")
    g.add_argument("--corpus")
    g.add_argument("--text")
    g.add_argument("--self-test", action="store_true")
    ap.add_argument("--table", help="sm103a|sm100a|sm120 (default: from ELF e_flags)")
    ap.add_argument("--resched", action="store_true",
                    help="also oracle cubit's own re-schedule of the same stream")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--stallfix", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--cubit")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    cubit = find_cubit(args.cubit)
    scratch = tempfile.mkdtemp(prefix="sched_oracle_")

    if args.self_test:
        sys.exit(0 if self_test(cubit, scratch) else 1)

    paths = []
    if args.cubin:
        paths = args.cubin
    elif args.corpus:
        with open(args.corpus) as f:
            paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if args.limit:
        paths = paths[: args.limit]

    all_results = []
    if args.text:
        table = table_for(args.text, args.table)
        with open(args.text) as f:
            text = f.read()
        all_results = oracle_text(cubit, table, text, scratch, args.stats, args.stallfix)
        if args.resched:
            # cubit's own schedule = what it EMITS: strip the frozen codes,
            # auto-schedule + assemble, then oracle the emitted cubin's
            # (frozen-disassembled) schedule -- "cubit never protects less".
            for _name, lines in parse_frozen(text):
                bare = strip_codes(lines)
                src = os.path.join(scratch, "resched_in.sass")
                out = os.path.join(scratch, "resched_out.cubin")
                with open(src, "w") as f:
                    f.write(bare)
                r = run_cubit(cubit, ["asm", "--table", table, "--output", out, src],
                              timeout=600)
                if r.returncode != 0:
                    all_results.append({"name": _name + " [resched]",
                                        "status": "ERROR",
                                        "error": (r.stderr or "")[-300:]})
                    continue
                d = run_cubit(cubit, ["disassemble", "--frozen", "--table", table, out],
                              timeout=300)
                rs = oracle_text(cubit, table, d.stdout, scratch,
                                 args.stats, args.stallfix)
                for x in rs:
                    x["name"] += " [resched]"
                all_results.extend(rs)
    else:
        for i, cub in enumerate(paths):
            table = table_for(cub, args.table)
            r = run_cubit(cubit, ["disassemble", "--frozen", "--table", table, cub],
                          timeout=300)
            if r.returncode != 0:
                all_results.append({"cubin": cub, "status": "ERROR",
                                    "error": (r.stderr or r.stdout)[-300:]})
                continue
            fk = parse_frozen(r.stdout)
            res = oracle_text(cubit, table, r.stdout, scratch, args.stats, args.stallfix)
            for x in res:
                x["cubin"] = cub
            all_results.extend(res)
            if args.resched:
                for _name, lines in fk:
                    bare = strip_codes(lines)
                    src = os.path.join(scratch, "resched_in.sass")
                    out = os.path.join(scratch, "resched_out.cubin")
                    with open(src, "w") as f:
                        f.write(bare)
                    ra = run_cubit(cubit, ["asm", "--table", table, "--output", out, src],
                                   timeout=600)
                    if ra.returncode != 0:
                        all_results.append({"cubin": cub, "name": _name + " [resched]",
                                            "status": "ERROR",
                                            "error": (ra.stderr or "")[-300:]})
                        continue
                    da = run_cubit(cubit, ["disassemble", "--frozen", "--table", table, out],
                                   timeout=300)
                    rs = oracle_text(cubit, table, da.stdout, scratch,
                                     args.stats, args.stallfix)
                    for x in rs:
                        x["cubin"] = cub
                        x["name"] += " [resched]"
                    all_results.extend(rs)
            if (i + 1) % 25 == 0:
                acc = sum(1 for x in all_results if x.get("status") == "ACCEPT")
                print(f".. {i+1}/{len(paths)} cubins, ACCEPT so far: {acc}",
                      file=sys.stderr)

    acc = sum(1 for x in all_results if x.get("status") == "ACCEPT")
    div = sum(1 for x in all_results if x.get("status") == "DIVERGENCE")
    rej = sum(1 for x in all_results if x.get("status") == "REJECT")
    err = sum(1 for x in all_results if x.get("status") == "ERROR")
    print(f"ORACLE SUMMARY: {len(all_results)} kernel-verdicts  ACCEPT={acc} "
          f"DIVERGENCE={div} REJECT={rej} ERROR={err}")
    for x in all_results:
        if x.get("status") != "ACCEPT":
            print(f"  {x.get('status')}: {x.get('cubin', '')} {x.get('name', '?')} "
                  f"raw={x.get('core_raw', x.get('raw'))} war={x.get('core_war', x.get('war'))} "
                  f"probe_hard={x.get('rb_war_hard')} "
                  f"divergences={x.get('divergence_classes')} "
                  f"probe_unreachable={x.get('rb_war_unreachable', 0)}")
            for f_ in (x.get("probe") or {}).get("findings_hard", [])[:6]:
                print(f"      {f_['event']}")
            for f_ in (x.get("probe") or {}).get("findings_soft", [])[:6]:
                print(f"      [soft d={f_.get('distance')}] {f_['event'][:110]}")
            for f_ in (x.get("probe") or {}).get("findings_unreachable", [])[:4]:
                print(f"      [unreachable] {f_['event'][:110]}")
            for e in x.get("core_events", [])[:6]:
                print(f"      [core] {e[:120]}")
            if x.get("error"):
                print(f"      {x['error']}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=1)
        print(f"json -> {args.json}")


if __name__ == "__main__":
    main()

