#!/usr/bin/env python3
"""probe.py - stall-floor probes as a service (sm_120).  One request = one isolated kernel family = one short GPU block.

A REQUEST names a producer form and a consumer form (kind `raw`: from which issue distance does the consumer see the
producer's result?) or a store form and an overwriter form (kind `war`: from which issue distance may an instruction
rewrite a register a BARE store reads?), and what is swept: the distance in issue cycles, the occupancy (warps per SM)
and the memory traffic in front. The tool builds one frozen kernel per point (every control code written out, nothing
is scheduled), launches each `reps` times and classifies EVERY thread of every launch against a checksum computed on
the host from the kernel's arithmetic - the absolute oracle. No reference kernel is the judge (a comparison with a
reference kernel is blind when the reference itself is affected: docs/KNOWN_ISSUES.md A27).

    probe.py gen  <requests.json> --out <batch dir> [--cubit BIN] [--table sm120.json.gz] [--dep-table dep_latency_sm120.json]
                  CPU: kernels (.sass + .cubin), family.json (index + provenance), model.npz (the host-computed
                  checksums of every thread for each failure hypothesis), per request in <batch dir>/<id>/
    probe.py run  <batch dir> [--reps N] [--limit-s S]
                  GPU (device 0 of the container): launches + classification -> <batch dir>/<id>/result.json,
                  <batch dir>/floors.json; prints SUMMARY lines
    probe.py floor <batch dir | result.json ...>
                  the result as log lines: `floor: <pair> = N (conditions) ...`
    probe.py adapt <gate json | dir ...> --out req.json
                  requests written by emu120.gate (`kernels[i].probes`) -> a request file of this tool + the list of pairs
                  the catalogue cannot build yet
    probe.py list     the forms the catalogue knows
    probe.py selftest the host model against an independent scalar interpreter (CPU only)

Request (JSON object; a file holds one object or a list):
    {"id": "sts_d_iadd3", "kind": "raw", "producer": "IADD3", "consumer": "STS.data",
     "occupancy": ["w1", "w8", "w32"], "front": ["none", "sts128x15@9"], "distances": "1-15,20,30",
     "cell": {"producer": "IADD3", "consumer": "STS", "role": "r1"}, "note": "..."}
    {"id": "sts_d_lop3", "kind": "war", "store": "STS.data", "overwriter": "LOP3", "controls": true,
     "occupancy": ["w8", "g32"], "front": ["none", "sts128x15@4"], "distances": "1-15,18-75:3,90,105,150"}
Distance = the sum of the stall counts from the tested producer (store) to the consumer (overwriter): one stall
1..15 on the producer plus fillers of 15 cycles (`"via": "fill"`: stall 1 plus fillers of 1 cycle - the additive model).
Classes of a thread-launch (256 iterations each):
    good      the checksum of the intended values in all 256 iterations
    stale     raw: the consumer took the register's PREVIOUS content in all 256 iterations
    late      war: the store took the OVERWRITTEN register in all 256 iterations
    overtake  war: the read-back load saw the slot before the store in all 256 iterations
    other     a mixture (some iterations wrong) - or a model that does not describe the kernel: the far / control
              kernels of every series must be 100 % good, else the series has NO result (`oracle: FAILED`)
Floor of a series = the smallest swept distance from which every swept distance is 100 % good in every launch; the
binding floor of a request = the largest over its conditions. Floors enter cubit's table only through its gate.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time

TOOL = "probe.py 18 (2026-11-11)"
HERE = pathlib.Path(__file__).resolve().parent
SEED = 0x12345
REPEAT = 256
SMEM = 65536
# occupancy: name -> (CTAs, threads per CTA); the output buffer keeps 1 024 words per CTA (gid = ctaid * 1024 + tid)
GEOM = {"w1": (188, 32), "w2": (188, 64), "w4": (188, 128), "w8": (188, 256), "w16": (188, 512), "w32": (188, 1024),
        "g32": (32, 1024), "g8": (32, 256), "w12": (188, 384), "c2w9": (376, 288), "w9": (188, 288), "c2w9s": (376, 288), "c4w8": (752, 256)}
# shared memory per CTA (bytes) where it is not SMEM. An SM of these cards has 102 400 B (sharedMemPerMultiprocessor): a
# kernel that declares 65 536 B has ONE CTA resident per SM whatever the grid says - `c2w9` (376 CTAs) ran as two waves of
# 188 and was called "2 CTAs per SM" until 2026-11-11. `c2w9s` declares 49 152 B: two CTAs fit an SM, three do not.
SMEM_OF = {"c2w9s": 49152, "c4w8": 24576}      # c4w8: four CTAs fit an SM (98 304 B), five do not
SMEM_PER_SM = 102400
SMEM_PER_CTA_MAX = 101376
OCC = {"w1": "1 warp per SM (188 CTAs x 32)", "w2": "2 warps per SM (188 x 64)", "w4": "4 warps per SM (188 x 128)",
       "w8": "8 warps per SM (188 x 256)", "w16": "16 warps per SM (188 x 512)", "w32": "32 warps per SM (188 x 1 024)",
       "g32": "32 warps on each of 32 SMs (32 x 1 024)", "g8": "8 warps on each of 32 SMs (32 x 256)",
       "w12": "12 warps per SM (188 x 384)",
       "c2w9": "9 warps per SM, ONE CTA resident per SM (376 x 288 in two waves: 65 536 B of shared memory per CTA)",
       "w9": "9 warps per SM (188 x 288)",
       "c2w9s": "2 CTAs of 9 warps per SM (376 x 288; 49 152 B of shared memory per CTA)",
       "c4w8": "4 CTAs of 8 warps per SM (752 x 256; 24 576 B of shared memory per CTA)"}
NGID = 188 * 1024
DEF_CUBIT = str(HERE.parent.parent / "target" / "release" / "cubit")
DEF_TABLE = str(HERE.parent.parent / "tables" / "sm120.json.gz")
DEF_DEP = str(HERE.parent.parent / "tables" / "dep_latency_sm120.json")


def C(s=15, wait="", rb="-", wb="-", y=False):
    """a control code `[B<waits>:R<read barrier>:W<write barrier>:<yield>:S<stall>]`"""
    w = "".join(str(i) if str(i) in wait else "-" for i in range(6))
    return f"[B{w}:R{rb}:W{wb}:{'Y' if y else '-'}:S{s:02d}]"


class Ins:
    """one instruction: control code, text, what it does for the host model, its role in the probe"""
    __slots__ = ("ctl", "text", "sem", "tag", "dst")

    def __init__(self, text, sem, ctl=None, tag=None, dst=()):
        self.ctl, self.text, self.sem, self.tag, self.dst = ctl or C(), text, sem, tag, tuple(dst)

    def line(self):
        return f"{self.ctl} {self.text}"


def PAD():
    return Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",))


def FILL1():
    return Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(1))


# ------------------------------------------------------------------------------------------------ the catalogue
def fin(reg, src):
    """a finite float in +-[1, 2) from a random word"""
    return [Ins(f"LOP3.LUT R{reg}, R{src}, 0x807fffff, RZ, 0xc0, !PT ;", ("and", f"R{reg}", f"R{src}", 0x807fffff)),
            Ins(f"LOP3.LUT R{reg}, R{reg}, 0x3f800000, RZ, 0xfc, !PT ;", ("or", f"R{reg}", f"R{reg}", 0x3f800000))]


def data_producer(name, rd):
    """-> (pre, text, sem, table class): R<rd> = f(a, b) of the iteration (a = R4, b = R5)"""
    r = f"R{rd}"
    if name == "IADD3":
        return [], f"IADD3 {r}, PT, PT, R4, R5, RZ ;", ("add", r, "R4", "R5"), "IADD3"
    if name == "IMAD":
        return [], f"IMAD {r}, R4, 0x9, R5 ;", ("mad", r, "R4", 9, "R5"), "IMAD"
    if name == "LOP3":
        return [], f"LOP3.LUT {r}, R4, R5, RZ, 0x3c, !PT ;", ("xor", r, "R4", "R5"), "LOP3"
    if name == "MOV":
        return [], f"MOV {r}, R4 ;", ("mov", r, "R4"), "MOV"
    if name == "SHF":
        return [], f"SHF.R.U32.HI {r}, RZ, 0x3, R4 ;", ("shr", r, "R4", 3), "SHF"
    if name == "FADD":
        return fin(13, 4) + fin(14, 5), f"FADD.FTZ {r}, R13, R14 ;", ("fadd", r, "R13", "R14"), "FADD"
    if name == "FMUL":
        return fin(13, 4) + fin(14, 5), f"FMUL.FTZ {r}, R13, R14 ;", ("fmul", r, "R13", "R14"), "FMUL"
    if name == "SEL":          # P2 = a < b (set long before); SEL Rd, Ra, Rb, !P2 = P2 ? Rb : Ra
        return [P2_LT()], f"SEL {r}, R4, R5, !P2 ;", ("selnot", r, "R4", "R5", "P2"), "SEL"
    if name == "F2FP.SAT":     # both halves from the same finite float: the result does not depend on the order of the halves
        return fin(13, 4), f"F2FP.SATFINITE.BF16.F32.PACK_AB {r}, R13, R13 ;", ("bf16pack2", r, "R13"), "F2FP.PACK"
    if name == "IADD3.neg":
        return [], f"IADD3 {r}, PT, PT, -R4, 0x10, RZ ;", ("rsub", r, "R4", 0x10), "IADD3"
    if name == "PRMT":
        return [], f"PRMT {r}, R4, 0x7632, R5 ;", ("prmt", r, "R4", 0x7632, "R5"), "PRMT"
    if name == "IMAD.SHL":
        return [], f"IMAD.SHL.U32 {r}, R4, 0x10, RZ ;", ("mad", r, "R4", 0x10, "RZ"), "IMAD"
    if name == "IADD.64":      # the pair R(d+1):Rd = R5:R4 + 4
        return [], f"IADD.64 {r}, R4, 0x4 ;", ("add64i", r, "R4", 4), "IADD.64"
    if name == "CS2R":         # the pair form `CS2R Rn, SRZ`: R(d+1):Rd = 0; both registers hold the iteration's inputs until it lands
        return ([Ins(f"MOV {r}, R4 ;", ("mov", r, "R4")), Ins(f"MOV R{rd + 1}, R5 ;", ("mov", f"R{rd + 1}", "R5"))],
                f"CS2R {r}, SRZ ;", ("zero2", r), "CS2R")
    if name == "LEA":          # Ra + (Ra << 2), the form whose arithmetic the LEA consumer ran with
        return [], f"LEA {r}, R4, R4, 0x2 ;", ("mad", r, "R4", 5, "RZ"), "LEA"
    if name == "IMAD.WIDE":    # the pair R(d+1):Rd = R4 * R5
        return [], f"IMAD.WIDE.U32 {r}, R4, R5, RZ ;", ("mulw", r, "R4", "R5"), "IMAD.WIDE"
    raise SystemExit(f"unknown data producer {name!r} (probe.py list)")


def P2_LT():
    return Ins("ISETP.LT.U32.AND P2, PT, R4, R5, PT ;", ("ltu", "P2", "R4", "R5"))


DATA_PRODUCERS = ["IADD3", "IMAD", "LOP3", "MOV", "SHF", "FADD", "FMUL", "SEL", "F2FP.SAT", "IADD3.neg", "PRMT", "IMAD.SHL", "IADD.64", "IMAD.WIDE", "CS2R", "LEA"]
PAIR_PRODUCERS = {"IADD.64", "IMAD.WIDE", "CS2R"}      # they write R(d) and R(d+1)


def uniform_producer(name):
    """-> (pre, text, sem, class): UR6 = a warp-uniform value (the uniform datapath; UR4 / UR5 hold the memory descriptor)"""
    if name == "UMOV":         # an immediate; UR6 holds ANOTHER immediate until it lands
        return [Ins("UMOV UR6, 0x155 ;", ("mov", "UR6", 0x155))], "UMOV UR6, 0x400 ;", ("mov", "UR6", 0x400), "UMOV"
    if name == "UIADD3":       # UR8 counts the iterations
        return ([Ins("UIADD3 UR8, UPT, UPT, UR8, 0x1, URZ ;", ("add", "UR8", "UR8", 1))],
                "UIADD3 UR6, UPT, UPT, UR8, 0x650, URZ ;", ("add", "UR6", "UR8", 0x650), "UIADD3")
    raise SystemExit(f"unknown uniform producer {name!r} (probe.py list)")


UNIFORM_PRODUCERS = ["UMOV", "UIADD3"]


def addr_producer(name):
    """-> (pre, text, sem, class): R6 = the address of word k = a & 3 of the thread's slot 2 (R9 + 0x20 + 4 k)"""
    k = [Ins("LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;", ("and", "R7", "R4", 3))]
    k4 = k + [Ins("SHF.L.U32 R7, R7, 0x2, RZ ;", ("shl", "R7", "R7", 2)),
              Ins("IADD3 R7, PT, PT, R7, 0x20, RZ ;", ("add", "R7", "R7", 0x20))]
    if name == "IADD3":
        return k4, "IADD3 R6, PT, PT, R7, R9, RZ ;", ("add", "R6", "R7", "R9"), "IADD3"
    if name == "IMAD":
        return k, "IMAD R6, R7, 0x4, R13 ;", ("mad", "R6", "R7", 4, "R13"), "IMAD"      # R13 = R9 + 0x20 (prologue)
    if name == "LOP3":      # the low 6 bits of R9 are zero: OR adds
        return k4, "LOP3.LUT R6, R7, R9, RZ, 0xfc, !PT ;", ("or", "R6", "R7", "R9"), "LOP3"
    raise SystemExit(f"unknown address producer {name!r} (probe.py list)")


ADDR_PRODUCERS = ["IADD3", "IMAD", "LOP3"]
FOLD4 = [("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
         ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))]


def fold4(wait):
    return [Ins(t, s, ctl=C(wait=wait) if i == 0 else None) for i, (t, s) in enumerate(FOLD4)]


def ADD10(wait=""):
    return Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"), ctl=C(wait=wait))


RAW_CONSUMERS = {
    # name: (what the producer writes: "data" + its register, or "addr"; table consumer class, role; text of the description)
    "STS.data": ("data", 6, "STS", "r1", "the data register of a 32-bit shared store"),
    "STS128.d0": ("data", 24, "STS", "r1", "the FIRST data register of STS.128"),
    "STS128.d3": ("data", 27, "STS", "r1h", "the LAST data register of STS.128"),
    "STG.data": ("data", 6, "STG", "r1", "the data register of a global store"),
    "STS.addr": ("addr", 6, "STS", "a0", "the address register of a shared store"),
    "LDS.addr": ("addr", 6, "LDS", "a1", "the address register of a shared load"),
    "IADD3.r1": ("data", 6, "IADD3", "r1", "the first addend of IADD3"),
    "IADD3.r2": ("data", 6, "IADD3", "r2", "the second addend of IADD3"),
    "IMAD.r1": ("data", 6, "IMAD", "r1", "the multiplicand of IMAD"),
    "IMAD.r3": ("data", 6, "IMAD", "r3", "the addend of IMAD"),
    "LOP3.r1": ("data", 6, "LOP3", "r1", "the first operand of LOP3"),
    "MOV.r1": ("data", 6, "MOV", "r1", "the source of MOV"),
    "SHF.r1": ("data", 6, "SHF", "r1", "the shifted operand of SHF.L.U32"),
    "SEL.r1": ("data", 6, "SEL", "r1", "the first operand of SEL"),
    "PRMT.r1": ("data", 6, "PRMT", "r1", "the first operand of PRMT"),
    "I2FP.r1": ("data", 6, "I2FP", "r1", "the source of I2FP.F32.S32"),
    "IMAD.SHL.r1": ("data", 6, "IMAD", "r1", "the multiplicand of IMAD.SHL.U32"),
    "IADD.64.r1": ("data", 6, "IADD.64", "r1", "the LOW word of the first operand pair of IADD.64"),
    "IADD.64.r1h": ("data", 6, "IADD.64", "r1h", "the HIGH word of the first operand pair of IADD.64 (the producer writes a pair)"),
    "LEA.r1": ("data", 6, "LEA", "r1", "both operands of LEA Rd, Ra, Ra, 2"),
    "SHF.L.U64.HI.r1": ("data", 6, "SHF", "r1", "the operand PAIR of SHF.L.U64.HI (the producer writes a pair)"),
    "IMAD.WIDE.r3": ("data", 6, "IMAD.WIDE", "r3", "the LOW word of the 64-bit addend of IMAD.WIDE"),
    "IMAD.WIDE.r3h": ("data", 7, "IMAD.WIDE", "r3h", "the HIGH word of the 64-bit addend of IMAD.WIDE"),
    "UIADD3.u1": ("udata", 6, "UIADD3", "u1", "the uniform addend of UIADD3"),
    "MOV.u1": ("udata", 6, "MOV", "u1", "the uniform source of MOV R, UR"),
}
WAR_STORES = {
    # name: (overwriters, table class, description)
    "STS.data": (["LOP3", "IADD3", "LDS", "LDG"], "STS", "the data register of a bare 32-bit shared store (IADD3: + a constant, so the NUMBER of late iterations per thread is read from the checksum)"),
    "STS128.data": (["LOP3", "LDS128", "LDSM"], "STS", "the data registers of a bare STS.128 (LOP3: the last one)"),
    "STG.data": (["LOP3", "IADD3", "LDG", "LDS"], "STG", "the data register of a bare global store (IADD3: as for STS.data)"),
    "STS.addr": (["IADD3", "LDS"], "STS", "the address register of a bare shared store (LDS: a shared LOAD brings the other address - the vendor's practice)"),
    "STG.addr": (["MOV"], "STG", "the address pair (low register) of a bare global store"),
    # version 15 - not stores: a warp shuffle reads its source register of ANOTHER lane (`"read_barrier": "set"` puts the
    # vendor's read barrier on the shuffle in the bare variant too; nobody waits it before the reader)
    "SHFL.BFLY.src": (["LOP3", "IADD3", "IADD3.it"], "SHFL", "the source register of SHFL.BFLY PT, Rd, Rs, 0x1, 0x1f (every lane takes lane ^ 1's register)"),
    "SHFL.IDX.src": (["LOP3", "IADD3", "IADD3.it"], "SHFL", "the source register of SHFL.IDX PT, Rd, Rs, 0x1, 0x1f (every lane takes lane 1's register)"),
    # version 18 - WRITE AFTER WRITE, not stores either: the entry is the FIRST writer of a register (a scoreboarded producer
    # on write barrier 1), the "overwriter" is the SECOND writer d cycles behind it, which does not wait that barrier; the
    # reader waits it. A first write that lands after the second leaves the FIRST writer's value (mode `late`).
    # IADD3 writes (the first writer's value - the constant): the checksum counts the iterations in which the first write
    # came last; IADD3.it writes (that value - (iteration index + 1) x the constant): one such iteration is decoded to its
    # index + 1. A second writer LDS / LDG / SHFL is a scoreboarded producer itself (write barrier 2; the reader waits both).
    # ctl = the second writer WAITS barrier 1 (the vendor's practice: must be good); rb = no first writer at all.
    "LDS.dst": (["IADD3", "IADD3.it", "LDS", "LDG"], "LDS", "the destination of a shared load (it brings the value stored in front of it), written again behind it"),
    "LDG.dst": (["IADD3", "IADD3.it", "LDG", "LDS"], "LDG", "the destination of a global load (it brings the value stored in front of it), written again behind it"),
    "LDC.dst": (["IADD3", "IADD3.it"], "LDC", "the destination of LDC Rd, c[0x0][0x388] (the seed), written again behind it"),
    "S2R.dst": (["IADD3", "IADD3.it"], "S2R", "the destination of S2R Rd, SR_TID.X, written again behind it"),
    "SHFL.dst": (["IADD3", "LDS"], "SHFL", "the destination of SHFL.BFLY PT, Rd, Rs, 0x1, 0x1f, written again behind it"),
    "LDS128.dst": (["SHFL"], "LDS", "the first destination register of LDS.128, written again by a warp shuffle (the one unwaited pair of this kind in vendor text)"),
}
SHFL_STORES = ("SHFL.BFLY.src", "SHFL.IDX.src")
WAW_STORES = ("LDS.dst", "LDG.dst", "LDC.dst", "S2R.dst", "SHFL.dst", "LDS128.dst")
NEG_CONST = (-0x9e3779b1) & 0xFFFFFFFF      # 2^32 - LATE_CONST


def shfl_of(req):
    """the warp shuffle in a request's body: None | "bfly" | "idx" (its model needs the lanes the shuffle reads, too)"""
    if req.get("kind") == "war":
        if req.get("store") == "SHFL.IDX.src":
            return "idx"
        if req.get("store") in ("SHFL.BFLY.src", "SHFL.dst", "LDS128.dst"):
            return "bfly"
    if req.get("kind") == "ord" and req.get("older") == "SHFL":
        return "bfly"
    return None
LATE_CONST = 0x9e3779b1      # odd: (checksum - good) / LATE_CONST = the number of iterations in which the store took the rewritten data
FRONT_RE = re.compile(r"(sts128|sts|stg)x(\d+)@(\d+)")


def front_ins(front, kind_has_b_target):
    """the memory traffic in front of the tested instruction: K stores of the constant quad, stall S each"""
    if front in ("none", "", None):
        return []
    m = FRONT_RE.fullmatch(front)
    if not m:
        raise SystemExit(f"unknown front {front!r}: none | sts128xK@S | stsxK@S | stgxK@S")
    form, k, s = m.group(1), int(m.group(2)), int(m.group(3))
    if not (1 <= s <= 15 and 1 <= k <= 64):
        raise SystemExit(f"front {front!r}: K 1..64, S 1..15")
    out = []
    for i in range(k):
        if form == "sts128":      # slots 0 / 1 of the thread: they hold this quad already
            out.append(Ins(f"STS.128 [R9{'+0x10' if i % 2 else ''}], R20 ;", ("nop",), ctl=C(s)))
        elif form == "sts":
            off = 16 * (i % 2)
            out.append(Ins(f"STS [R9{('+0x%x' % off) if off else ''}], R20 ;", ("nop",), ctl=C(s)))
        else:                      # the thread's word B of the output buffer: it holds R20 already
            if kind_has_b_target:
                raise SystemExit("front stg...: not with STG.addr (word B is the target of a misdirected store there)")
            out.append(Ins("STG.E desc[UR4][R18.64], R20 ;", ("nop",), ctl=C(s)))
    return out


def front_id(front):
    return "f0" if front in ("none", "", None) else front.replace("@", "s")


def split_distance(d, via="stall"):
    """-> (stall of the tested instruction, fillers)"""
    if via == "fill":
        return 1, [FILL1() for _ in range(d - 1)]
    npad = (d - 1) // 15
    return d - 15 * npad, [PAD() for _ in range(npad)]


def body_raw(req, d, front):
    prod, cons = req["producer"], req["consumer"]
    what, rd, _cls, _role, _txt = RAW_CONSUMERS[cons]
    s, fill = split_distance(d, req.get("via", "stall"))
    b = []
    if what == "addr":
        pre, ptext, psem, _ = addr_producer(prod)
    elif what == "udata":
        pre, ptext, psem, _ = uniform_producer(prod)
    else:
        pre, ptext, psem, _ = data_producer(prod, rd)
    if cons == "STS128.d3":
        pre = pre + [Ins("MOV R24, R4 ;", ("mov", "R24", "R4")), Ins("MOV R25, R5 ;", ("mov", "R25", "R5")),
                     Ins("LOP3.LUT R26, R4, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R26", "R4", 0x33cc33cc))]
    if cons == "STS128.d0":
        pre = pre + [Ins("MOV R25, R4 ;", ("mov", "R25", "R4")), Ins("MOV R26, R5 ;", ("mov", "R26", "R5")),
                     Ins("LOP3.LUT R27, R4, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R27", "R4", 0x33cc33cc))]
    if cons == "SEL.r1" and prod != "SEL":
        pre = pre + [P2_LT()]
    if cons in ("IADD.64.r1h", "SHF.L.U64.HI.r1") and prod not in PAIR_PRODUCERS:
        raise SystemExit(f"{cons}: the producer must write a register pair ({', '.join(sorted(PAIR_PRODUCERS))})")
    if prod == "CS2R" and rd % 2:
        raise SystemExit("CS2R: the pair form is built on an even register only (not the last register of STS.128)")
    if cons.startswith("IMAD.WIDE.r3"):
        if prod in PAIR_PRODUCERS:
            raise SystemExit(f"{cons}: the producer writes ONE word of the addend pair (not {prod})")
        # the other word of the addend pair R7:R6 is the iteration's own, set long before
        pre = pre + [Ins("MOV R6, R5 ;", ("mov", "R6", "R5")) if cons == "IMAD.WIDE.r3h" else Ins("MOV R7, R5 ;", ("mov", "R7", "R5"))]
    b += pre
    b += front_ins(front, False)
    dst = ["UR6"] if what == "udata" else [f"R{rd}", f"R{rd + 1}"] if prod in PAIR_PRODUCERS else [f"R{rd}"]
    b.append(Ins(ptext, psem, ctl=C(s, y=req.get("yield") == "set"), tag="P", dst=dst))
    b += fill
    if cons == "STS.data":
        b += [Ins("STS [R9+0x20], R6 ;", ("sts", "R9", 0x20, "R6", 1), ctl=C(rb="2"), tag="C"),
              Ins("LDS R8, [R9+0x20] ;", ("lds", "R8", "R9", 0x20, 1), ctl=C(wb="1")), ADD10("12")]
    elif cons in ("STS128.d0", "STS128.d3"):
        b += [Ins("STS.128 [R9+0x20], R24 ;", ("sts", "R9", 0x20, "R24", 4), ctl=C(rb="2"), tag="C"),
              Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(wb="1"))] + fold4("12")
    elif cons == "STG.data":
        b += [Ins("STG.E desc[UR4][R16.64], R6 ;", ("stg", "R16", "R6"), ctl=C(rb="2"), tag="C"),
              Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wb="1")), ADD10("12")]
    elif cons == "STS.addr":
        b += [Ins("STS [R6], R4 ;", ("sts", "R6", 0, "R4", 1), ctl=C(rb="2"), tag="C"),
              Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(wb="1"))] + fold4("12")
    elif cons == "LDS.addr":
        b += [Ins("LDS R8, [R6] ;", ("lds", "R8", "R6", 0, 1), ctl=C(wb="1"), tag="C"), ADD10("1")]
    elif cons == "IADD3.r1":
        b += [Ins("IADD3 R8, PT, PT, R6, R5, RZ ;", ("add", "R8", "R6", "R5"), tag="C"), ADD10()]
    elif cons == "IADD3.r2":
        b += [Ins("IADD3 R8, PT, PT, R5, R6, RZ ;", ("add", "R8", "R5", "R6"), tag="C"), ADD10()]
    elif cons == "IMAD.r1":
        b += [Ins("IMAD R8, R6, 0x3, R5 ;", ("mad", "R8", "R6", 3, "R5"), tag="C"), ADD10()]
    elif cons == "IMAD.r3":
        b += [Ins("IMAD R8, R5, 0x3, R6 ;", ("mad", "R8", "R5", 3, "R6"), tag="C"), ADD10()]
    elif cons == "LOP3.r1":
        b += [Ins("LOP3.LUT R8, R6, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R8", "R6", 0x33cc33cc), tag="C"), ADD10()]
    elif cons == "MOV.r1":
        b += [Ins("MOV R8, R6 ;", ("mov", "R8", "R6"), tag="C"), ADD10()]
    elif cons == "SHF.r1":
        b += [Ins("SHF.L.U32 R8, R6, 0x2, RZ ;", ("shl", "R8", "R6", 2), tag="C"), ADD10()]
    elif cons == "SEL.r1":
        b += [Ins("SEL R8, R6, RZ, P2 ;", ("sel", "R8", "R6", "RZ", "P2"), tag="C"), ADD10()]
    elif cons == "PRMT.r1":
        b += [Ins("PRMT R8, R6, 0x7632, R5 ;", ("prmt", "R8", "R6", 0x7632, "R5"), tag="C"), ADD10()]
    elif cons == "I2FP.r1":
        b += [Ins("I2FP.F32.S32 R8, R6 ;", ("i2f", "R8", "R6"), tag="C"), ADD10()]
    elif cons == "IMAD.SHL.r1":
        b += [Ins("IMAD.SHL.U32 R8, R6, 0x10, RZ ;", ("mad", "R8", "R6", 0x10, "RZ"), tag="C"), ADD10()]
    elif cons in ("IADD.64.r1", "IADD.64.r1h"):      # R25:R24 = R7:R6 + 4; the low word (r1) or the high word (r1h) reaches the checksum
        # (a 64-bit pair sits on an EVEN register: `IADD.64 R13, ...` is "Misaligned Register", Xid 13, at the first launch)
        b += [Ins("IADD.64 R24, R6, 0x4 ;", ("add64i", "R24", "R6", 4), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IADD.64.r1" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IADD.64.r1" else "R25")), ADD10()]
    elif cons in ("IMAD.WIDE.r3", "IMAD.WIDE.r3h"):      # R25:R24 = R4 * R5 + R7:R6; the low (r3) or the high (r3h) word reaches the checksum
        b += [Ins("IMAD.WIDE.U32 R24, R4, R5, R6 ;", ("madw", "R24", "R4", "R5", "R6"), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IMAD.WIDE.r3" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IMAD.WIDE.r3" else "R25")), ADD10()]
    elif cons == "SHF.L.U64.HI.r1":      # R8 = the high word of (R7:R6) << 3
        b += [Ins("SHF.L.U64.HI R8, R6, 0x3, R7 ;", ("shl64hi", "R8", "R6", 3, "R7"), tag="C"), ADD10()]
    elif cons == "UIADD3.u1":
        b += [Ins("UIADD3 UR7, UPT, UPT, UR6, 0x630, URZ ;", ("add", "UR7", "UR6", 0x630), tag="C"),
              Ins("MOV R8, UR7 ;", ("mov", "R8", "UR7")), ADD10()]
    elif cons == "MOV.u1":
        b += [Ins("MOV R8, UR6 ;", ("mov", "R8", "UR6"), tag="C"), ADD10()]
    elif cons == "LEA.r1":
        b += [Ins("LEA R8, R6, R6, 0x2 ;", ("mad", "R8", "R6", 5, "RZ"), tag="C"), ADD10()]
    else:
        raise SystemExit(f"unknown raw consumer {cons!r} (probe.py list)")
    return b


ORD_PAIRS = [("LDS", "LDS"), ("LDS", "LDSM"), ("LDS", "LDG"), ("LDS128", "LDS"), ("LDG", "LDS"), ("LDG", "LDG"), ("LDS", "LDS128"),
             ("LDS", "LDS64"), ("LDS64", "LDS64"), ("LDS64", "LDS"), ("LDSU16", "LDS"), ("LDSU16", "LDS128"),
             # version 18: a YOUNGER producer of another class (with "older_barrier": "same": two producers of different
             # classes on ONE write barrier - does the barrier count them?); older LDC = the constant-bank load of the seed,
             # older SHFL = SHFL.BFLY; younger S2R R8, SR_TID.X / S2UR UR6, SR_CTAID.X / LDC.64 R30, c[0x0][0x380]
             ("LDS", "S2R"), ("LDC", "S2UR"), ("SHFL", "LDC64"), ("LDG", "S2R"), ("LDG", "S2UR"), ("LDG", "LDC64")]


def far_layout(threads):
    """the second region of a CTA's shared memory, behind the threads' 64-byte slots: word k of a thread = FARBASE +
    k * STRIDE + tid * 4, STRIDE >= 1 KB and >= one word per thread. -> (farbase, stride)"""
    stride = max(0x400, (threads * 4 + 0xFF) & ~0xFF)
    return threads * 64, stride


def smem_of(req, occ):
    """the shared memory the kernels of a request declare on a grid"""
    ctas, threads = GEOM[occ]
    smem = SMEM_OF.get(occ, SMEM)
    if req.get("kind") == "ord" and req.get("far") == "off" and threads * 64 + 0x240 > smem:
        raise SystemExit(f"{req['id']}: far = \"off\" does not fit the grid {occ} (the last thread's younger load would leave the {smem} B it declares)")
    if req.get("kind") == "ord" and req.get("nload") and req.get("place") == "far":
        fb, st = far_layout(threads)
        need = fb + int(req["nload"]) * st
        if need > smem:
            if occ in SMEM_OF:
                raise SystemExit(f"{req['id']}: {need} B of shared memory do not fit the grid {occ} ({smem} B per CTA)")
            smem = (need + 0xFFF) & ~0xFFF
    if smem > SMEM_PER_CTA_MAX:
        raise SystemExit(f"{req['id']}: {smem} B of shared memory per CTA (the card allows {SMEM_PER_CTA_MAX})")
    return smem


def body_ordn(req, d, front, variant):
    """N shared loads of one thread in flight (`nload` 2..8), d issue cycles apart, and ONE wait of the reader:
    `barrier` last = only the youngest load carries the write barrier (the vendor's cover of bare loads), all = every
    load carries the SAME barrier (cubit's allocator records stale reads for eight such loads 1 KB apart at >= 2 CTAs
    per SM). `place` near = words 0..N-1 of the thread's own 64 bytes, one base register; base2 = the same words, every
    second load through another base register (R7 = R9); far = N words STRIDE (>= 1 KB) apart in the second region of
    the CTA's shared memory (the thread's own words, written once in the prologue). Every destination holds a marker
    that changes each iteration until its load lands. From version 13 the reader takes ALL N registers within N / 2
    cycles of its wake-up (pairs summed at stall 1 into R6 / R8 / R12 / R13, weighed afterwards); version 12 read the
    oldest register at the wake-up and each further one 15 cycles later - a tight test of the oldest load only.
    `barrier` none = the POSITIVE CONTROL: no load carries a barrier and the reader does not wait (it must be wrong).
    variant ctl: every load is waited before the next is issued (must be right at every distance)."""
    n, place, bar = int(req["nload"]), req["place"], req["barrier"]
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    _fb, stride = far_layout(int(req.get("_threads", 1024)))
    b = [Ins(f"MOV R{24 + k}, R5 ;", ("mov", f"R{24 + k}", "R5")) for k in range(n)]
    if place == "base2":
        b.append(Ins("MOV R7, R9 ;", ("mov", "R7", "R9")))
    b += front_ins(front, False)
    for k in range(n):
        last = k == n - 1
        if place == "far":
            text, sem = f"LDS R{24 + k}, [R14{('+0x%x' % (k * stride)) if k else ''}] ;", ("ldsf", f"R{24 + k}", k)
        else:
            base = "R7" if (place == "base2" and k % 2) else "R9"
            text, sem = f"LDS R{24 + k}, [{base}{('+0x%x' % (4 * k)) if k else ''}] ;", ("lds", f"R{24 + k}", "R9", 4 * k, 1)
        if ctl:
            b.append(Ins(text, sem, ctl=C(1, wb="0"), tag="P", dst=[f"R{24 + k}"]))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(ys if last else d, wait="0")))
        else:
            wb = "1" if (bar != "none" and (last or bar == "all")) else "-"
            b.append(Ins(text, sem, ctl=C(ys if last else d, wb=wb), tag="P", dst=[f"R{24 + k}"]))
    cw = "0" if ctl else "" if bar == "none" else "1"
    tmp = ["R6", "R8", "R12", "R13"]
    for j in range((n + 1) // 2):      # the snapshots: one issue cycle apart, the first on the wait
        a, c = 24 + 2 * j, 24 + 2 * j + 1
        ct = C(1, wait=cw) if j == 0 else C(1)
        if c < 24 + n:
            b.append(Ins(f"IADD3 {tmp[j]}, PT, PT, R{a}, R{c}, RZ ;", ("add", tmp[j], f"R{a}", f"R{c}"), ctl=ct, tag="C"))
        else:
            b.append(Ins(f"MOV {tmp[j]}, R{a} ;", ("mov", tmp[j], f"R{a}"), ctl=ct, tag="C"))
    b.append(PAD())
    b.append(Ins(f"IMAD R6, R6, 0x3, RZ ;", ("mad", "R6", "R6", 3, "RZ")))
    for j in range(1, (n + 1) // 2):
        b.append(Ins(f"IMAD R6, {tmp[j]}, 0x{2 * j + 3:x}, R6 ;", ("mad", "R6", tmp[j], 2 * j + 3, "R6")))
    b.append(Ins("IADD3 R10, PT, PT, R10, R6, RZ ;", ("add", "R10", "R10", "R6")))
    return b


def body_ord(req, d, front, variant):
    """an OLDER load without a write barrier, d issue cycles in front of a YOUNGER load that carries one; the reader of the
    older load's result waits only on the younger load's barrier. variant ctl: the older load carries barrier 0 and the
    reader waits on it too (must be right at every distance)."""
    if req.get("nload"):
        return body_ordn(req, d, front, variant)
    older, younger = req["older"], req["younger"]
    if (older, younger) not in ORD_PAIRS:
        raise SystemExit(f"ord: older {older!r} / younger {younger!r} not in the catalogue (probe.py list)")
    s, fill = split_distance(d)
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    # "older_barrier": "same" = the older load carries the SAME write barrier as the younger one (two producers on one
    # scoreboard, one wait): right at every distance if the scoreboard COUNTS its producers, stale like the bare older
    # load if it only follows the last one
    wb0 = "0" if ctl else "1" if req.get("older_barrier") == "same" else "-"
    cw = "01" if ctl else "1"
    b = []
    # "far": the younger SHARED load reads another line of the CTA's shared memory, 1 KB away (another thread's 64 bytes:
    # R14 = R9 ^ 0x400, always inside the 64 KB the kernel declares); what it brings is not used and not modelled
    # "far": "off" (version 14) = the younger shared load on the SAME base register, 0x200 bytes away (another line; inside
    # the declared shared memory: `gen` refuses a grid where the last thread's address would not be)
    far = req.get("far")
    if far and younger not in ("LDS", "LDS128", "LDSM", "LDS64"):
        raise SystemExit("ord: `far` is for a younger SHARED load (LDS, LDS128, LDSM, LDS64)")
    ybase = "R14" if far is True else "R9"
    yoff = 0x230 if far == "off" else 0x30
    # "younger_guard": the younger load under a predicate - true (P0) or false (P3: the load does not happen; what its
    # write barrier then does for the reader's wait is the question)
    yg = {"true": "@P0 ", "false": "@P3 "}.get(req.get("younger_guard"), "")
    if far is True:
        b.append(Ins("LOP3.LUT R14, R9, 0x400, RZ, 0x3c, !PT ;", ("xor", "R14", "R9", 0x400)))
    # what the older load brings changes every iteration (a store with read barrier 3, waited by the fold); its destination
    # holds a marker (b) until the load lands
    if older == "LDS":
        b += [Ins("STS [R9+0x20], R4 ;", ("sts", "R9", 0x20, "R4", 1), ctl=C(rb="3")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("LDS R6, [R9+0x20] ;", ("lds", "R6", "R9", 0x20, 1), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    elif older == "LDSU16":      # 16 bits, zero-extended
        b += [Ins("STS [R9+0x20], R4 ;", ("sts", "R9", 0x20, "R4", 1), ctl=C(rb="3")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("LDS.U16 R6, [R9+0x20] ;", ("ldsu16", "R6", "R9", 0x20), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    elif older == "LDS64":
        b += [Ins("MOV R26, R4 ;", ("mov", "R26", "R4")), Ins("MOV R27, R5 ;", ("mov", "R27", "R5")),
              Ins("STS.64 [R9+0x20], R26 ;", ("sts", "R9", 0x20, "R26", 2), ctl=C(rb="3")),
              Ins("MOV R28, R5 ;", ("mov", "R28", "R5")), Ins("MOV R29, R5 ;", ("mov", "R29", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("LDS.64 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 2), ctl=C(s, wb=wb0), tag="P", dst=["R28", "R29"]))
    elif older == "LDS128":
        b += [Ins("MOV R24, R4 ;", ("mov", "R24", "R4")), Ins("MOV R25, R5 ;", ("mov", "R25", "R5")),
              Ins("LOP3.LUT R26, R4, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R26", "R4", 0x33cc33cc)),
              Ins("IADD3 R27, PT, PT, R4, R5, RZ ;", ("add", "R27", "R4", "R5")),
              Ins("STS.128 [R9+0x20], R24 ;", ("sts", "R9", 0x20, "R24", 4), ctl=C(rb="3")),
              Ins("MOV R28, R5 ;", ("mov", "R28", "R5")), Ins("MOV R29, R5 ;", ("mov", "R29", "R5")),
              Ins("MOV R30, R5 ;", ("mov", "R30", "R5")), Ins("MOV R31, R5 ;", ("mov", "R31", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(s, wb=wb0), tag="P", dst=["R28", "R29", "R30", "R31"]))
    elif older == "LDC":      # version 18: the constant-bank load of the seed; its destination holds the marker until it lands
        b.append(Ins("MOV R6, R5 ;", ("mov", "R6", "R5")))
        b += front_ins(front, False)
        b.append(Ins("LDC R6, c[0x0][0x388] ;", ("mov", "R6", SEED), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    elif older == "SHFL":     # version 18: a warp shuffle (its source differs between the lanes of a pair)
        b += [Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("SHFL.BFLY PT, R6, R14, 0x1, 0x1f ;", ("shfl", "R6", "R14", "bfly", 1), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    else:
        b += [Ins("STG.E desc[UR4][R16.64], R4 ;", ("stg", "R16", "R4"), ctl=C(rb="3")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("LDG.E R6, desc[UR4][R16.64] ;", ("ldg", "R6", "R16"), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    b += fill
    if younger == "LDS":
        b.append(Ins(f"{yg}LDS R8, [{ybase}+0x{yoff:x}] ;", ("poison", "R8", 1) if (far or yg) else ("lds", "R8", "R9", 0x30, 1), ctl=C(ys, wb="1")))
    elif younger == "LDS128":      # another access width than the older load (only behind an older LDS / LDS.U16: R24-R27 are free there)
        b.append(Ins(f"{yg}LDS.128 R24, [{ybase}+0x{yoff:x}] ;", ("poison", "R24", 4), ctl=C(ys, wb="1")))
    elif younger == "LDS64":       # (R30:R31: free behind every older form that pairs with it)
        b.append(Ins(f"{yg}LDS.64 R30, [{ybase}+0x{yoff:x}] ;", ("poison", "R30", 2), ctl=C(ys, wb="1")))
    elif younger == "LDSM":
        b.append(Ins(f"{yg}LDSM.16.M88.4 R24, [{ybase}+0x{yoff:x}] ;", ("poison", "R24", 4), ctl=C(ys, wb="1")))
    elif younger == "S2R":       # version 18: a younger producer of another class (what it brings is not used)
        b.append(Ins("S2R R8, SR_TID.X ;", ("mov", "R8", "R0"), ctl=C(ys, wb="1")))
    elif younger == "S2UR":      # ... into a uniform register (UR4 is the descriptor's)
        b.append(Ins("S2UR UR6, SR_CTAID.X ;", ("nop",), ctl=C(ys, wb="1")))
    elif younger == "LDC64":     # ... the pair R30:R31 (the output pointer: not modelled)
        b.append(Ins("LDC.64 R30, c[0x0][0x380] ;", ("poison", "R30", 2), ctl=C(ys, wb="1")))
    else:
        b.append(Ins("LDG.E R8, desc[UR4][R18.64] ;", ("ldg", "R8", "R18"), ctl=C(ys, wb="1")))
    if older == "LDS64":
        b.append(Ins("IADD3 R13, PT, PT, R28, R29, RZ ;", ("add", "R13", "R28", "R29"), ctl=C(wait=cw), tag="C"))
    elif older == "LDS128":
        b.append(Ins("IADD3 R13, PT, PT, R28, R31, RZ ;", ("add", "R13", "R28", "R31"), ctl=C(wait=cw), tag="C"))
    else:
        b.append(Ins("MOV R13, R6 ;", ("mov", "R13", "R6"), ctl=C(wait=cw), tag="C"))
    b.append(Ins("IADD3 R10, PT, PT, R10, R13, RZ ;", ("add", "R10", "R10", "R13"), ctl=C(wait="3")))
    return b


def body_war(req, d, front, variant):
    """variant: bare (the question), ctl (no overwriter), rb (read barrier on the store, the overwriter waits)"""
    store, over = req["store"], req["overwriter"]
    if store not in WAR_STORES or over not in WAR_STORES[store][0]:
        raise SystemExit(f"war: store {store!r} / overwriter {over!r} not in the catalogue (probe.py list)")
    s, fill = split_distance(d)
    rb = "2" if variant == "rb" else "-"
    ow = "2" if variant == "rb" else ""
    ctl = variant == "ctl"
    b = []
    load_over = over in ("LDS", "LDG", "LDS128", "LDSM") and not ctl
    back_wait = "0" if load_over else ""
    if store == "STS.data":
        b.append(Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")))
        b += front_ins(front, False)
        b.append(Ins("STS [R9+0x20], R6 ;", ("sts", "R9", 0x20, "R6", 1), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R6", "R6", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "IADD3":
            b.append(Ins(f"IADD3 R6, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), ctl=C(wait=ow), tag="O"))
        elif over == "LDS":
            b.append(Ins("LDS R6, [R9+0x30] ;", ("lds", "R6", "R9", 0x30, 1), ctl=C(wait=ow, wb="0"), tag="O"))
        else:
            b.append(Ins("LDG.E R6, desc[UR4][R18.64] ;", ("ldg", "R6", "R18"), ctl=C(wait=ow, wb="0"), tag="O"))
        b += [Ins("LDS R8, [R9+0x20] ;", ("lds", "R8", "R9", 0x20, 1), ctl=C(wait=back_wait, wb="1"), tag="B"), ADD10("1")]
    elif store == "STS128.data":
        b += [Ins("IADD3 R24, PT, PT, R4, R5, RZ ;", ("add", "R24", "R4", "R5")), Ins("MOV R25, R4 ;", ("mov", "R25", "R4")),
              Ins("MOV R26, R5 ;", ("mov", "R26", "R5")),
              Ins("LOP3.LUT R27, R24, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R27", "R24", 0x33cc33cc))]
        b += front_ins(front, False)
        b.append(Ins("STS.128 [R9+0x20], R24 ;", ("sts", "R9", 0x20, "R24", 4), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R27, R27, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R27", "R27", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "LDS128":
            b.append(Ins("LDS.128 R24, [R9+0x30] ;", ("lds", "R24", "R9", 0x30, 4), ctl=C(wait=ow, wb="0"), tag="O"))
        else:
            b.append(Ins("LDSM.16.M88.4 R24, [R9+0x30] ;", ("poison", "R24", 4), ctl=C(wait=ow, wb="0"), tag="O"))
        b += [Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(wait=back_wait, wb="1"), tag="B")] + fold4("1")
    elif store == "STG.data":
        b.append(Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")))
        b += front_ins(front, False)
        b.append(Ins("STG.E desc[UR4][R16.64], R6 ;", ("stg", "R16", "R6"), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R6", "R6", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "IADD3":
            b.append(Ins(f"IADD3 R6, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), ctl=C(wait=ow), tag="O"))
        elif over == "LDG":
            b.append(Ins("LDG.E R6, desc[UR4][R18.64] ;", ("ldg", "R6", "R18"), ctl=C(wait=ow, wb="0"), tag="O"))
        else:
            b.append(Ins("LDS R6, [R9+0x30] ;", ("lds", "R6", "R9", 0x30, 1), ctl=C(wait=ow, wb="0"), tag="O"))
        b += [Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wait=back_wait, wb="1"), tag="B"), ADD10("1")]
    elif store in SHFL_STORES:
        mode = "bfly" if store == "SHFL.BFLY.src" else "idx"
        rbset = req.get("read_barrier") == "set"
        srb = "2" if (variant == "rb" or rbset) else "-"
        behind = req.get("behind") in ("write_waiter", "younger_write")
        younger = req.get("behind") == "younger_write"
        if over == "IADD3.it":      # version 16: R7 = (iteration index + 1) * the odd constant (R7 is 0 before the loop)
            b.append(Ins(f"IADD3 R7, PT, PT, R7, 0x{LATE_CONST:x}, RZ ;", ("add", "R7", "R7", LATE_CONST)))
        # the source value must DIFFER between lanes 2k and 2k + 1 (a + b does not: b = gid ^ an odd constant)
        b.append(Ins("IMAD R6, R4, 0x9, R5 ;", ("mad", "R6", "R4", 9, "R5")))
        if younger:      # version 17: the YOUNGER shuffle's own source (it differs between the lanes of a pair too)
            b.append(Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")))
        b += front_ins(front, False)
        # (behind: the reader waits the WRITE barrier only - with a read barrier on the shuffle that is the shape of a barred
        # shuffle whose overwriter stands behind the write-barrier waiter and does not wait the read barrier)
        rwait = "12" if (srb == "2" and not behind) else "1"
        if younger:
            # version 17: the tested shuffle with NO write barrier, a younger shuffle with one `younger_gap` cycles behind
            # it, the reader that waits the YOUNGER one's barrier and takes both results (at stall s), then the rewrite of
            # the OLDER shuffle's source: the swept distance is waiter -> overwriter
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1),
                         ctl=C(int(req.get("younger_gap", 1)), rb=srb, wb="-"), tag="S"))
            b.append(Ins(f"SHFL.{mode.upper()} PT, R13, R14, 0x1, 0x1f ;", ("shfl", "R13", "R14", mode, 1), ctl=C(wb="1")))
            b.append(Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(s, wait="1")))
        elif behind:
            # version 16: the shuffle, then the reader of its result (it WAITS the shuffle's write barrier) at stall s, then
            # the rewrite of the source: the swept distance is waiter -> overwriter
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1), ctl=C(rb=srb, wb="1"), tag="S"))
            b.append(Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"), ctl=C(s, wait=rwait)))
        else:
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1), ctl=C(s, rb=srb, wb="1"), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R6", "R6", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "IADD3.it":
            b.append(Ins("IADD3 R6, PT, PT, R6, R7, RZ ;", ("add", "R6", "R6", "R7"), ctl=C(wait=ow), tag="O"))
        else:
            b.append(Ins(f"IADD3 R6, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), ctl=C(wait=ow), tag="O"))
        if younger:
            b.append(ADD10(""))
        elif not behind:
            b.append(ADD10(rwait))
    elif store in WAW_STORES:
        # version 18 - write after write. tag S = the FIRST writer (write barrier 1) at stall s, tag O = the SECOND writer
        # d cycles behind it; bare: the second writer does not wait; ctl: it waits barrier 1; rb: no first writer (a filler
        # in its place). The reader of the register waits barrier 1 (+ 3: the read barrier of the store that prepared the
        # first writer's value; + 2: a scoreboarded second writer's own barrier).
        sw = "1" if ctl else ""
        if over == "IADD3.it":      # R7 = -(iteration index + 1) * the constant (R7 is 0 before the loop)
            b.append(Ins(f"IADD3 R7, PT, PT, R7, 0x{NEG_CONST:x}, RZ ;", ("add", "R7", "R7", NEG_CONST)))
        dreg, vreg, rwait = "R6", None, "1"
        if store == "LDS.dst":
            b.append(Ins("STS [R9+0x20], R4 ;", ("sts", "R9", 0x20, "R4", 1), ctl=C(rb="3")))
            vreg, rwait = "R4", "13"
            first = Ins("LDS R6, [R9+0x20] ;", ("lds", "R6", "R9", 0x20, 1), ctl=C(s, wb="1"), tag="S")
        elif store == "LDG.dst":
            b.append(Ins("STG.E desc[UR4][R16.64], R4 ;", ("stg", "R16", "R4"), ctl=C(rb="3")))
            vreg, rwait = "R4", "13"
            first = Ins("LDG.E R6, desc[UR4][R16.64] ;", ("ldg", "R6", "R16"), ctl=C(s, wb="1"), tag="S")
        elif store == "LDC.dst":
            first = Ins("LDC R6, c[0x0][0x388] ;", ("mov", "R6", SEED), ctl=C(s, wb="1"), tag="S")
        elif store == "S2R.dst":
            vreg = "R0"
            first = Ins("S2R R6, SR_TID.X ;", ("mov", "R6", "R0"), ctl=C(s, wb="1"), tag="S")
        elif store == "SHFL.dst":
            b.append(Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")))
            vreg = "R4"
            first = Ins("SHFL.BFLY PT, R6, R14, 0x1, 0x1f ;", ("shfl", "R6", "R14", "bfly", 1), ctl=C(s, wb="1"), tag="S")
        else:                       # LDS128.dst: slot 2 of the thread holds R20..R23 (prologue)
            b.append(Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")))
            dreg = "R24"
            first = Ins("LDS.128 R24, [R9+0x20] ;", ("lds", "R24", "R9", 0x20, 4), ctl=C(s, wb="1"), tag="S")
        b += front_ins(front, False)
        b.append(first if variant != "rb" else Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(s)))
        b += fill
        if over == "IADD3":
            if vreg:
                b.append(Ins(f"IADD3 R6, PT, PT, {vreg}, 0x{NEG_CONST:x}, RZ ;", ("add", "R6", vreg, NEG_CONST), ctl=C(wait=sw), tag="O"))
            else:                   # the seed - the constant, as an immediate
                b.append(Ins(f"IADD3 R6, PT, PT, RZ, 0x{(SEED + NEG_CONST) & 0xFFFFFFFF:x}, RZ ;", ("add", "R6", "RZ", (SEED + NEG_CONST) & 0xFFFFFFFF),
                             ctl=C(wait=sw), tag="O"))
        elif over == "IADD3.it":
            if vreg:
                b.append(Ins(f"IADD3 R6, PT, PT, {vreg}, R7, RZ ;", ("add", "R6", vreg, "R7"), ctl=C(wait=sw), tag="O"))
            else:
                b.append(Ins(f"IADD3 R6, PT, PT, R7, 0x{SEED:x}, RZ ;", ("add", "R6", "R7", SEED), ctl=C(wait=sw), tag="O"))
        elif over == "LDS":         # slot 3 of the thread holds R20..R23
            b.append(Ins("LDS R6, [R9+0x30] ;", ("lds", "R6", "R9", 0x30, 1), ctl=C(wait=sw, wb="2"), tag="O"))
            rwait += "2"
        elif over == "LDG":         # word B of the thread holds R20
            b.append(Ins("LDG.E R6, desc[UR4][R18.64] ;", ("ldg", "R6", "R18"), ctl=C(wait=sw, wb="2"), tag="O"))
            rwait += "2"
        else:                       # SHFL (behind LDS.128)
            b.append(Ins("SHFL.BFLY PT, R24, R14, 0x1, 0x1f ;", ("shfl", "R24", "R14", "bfly", 1), ctl=C(wait=sw, wb="2"), tag="O"))
            rwait += "2"
        b.append(Ins(f"IADD3 R10, PT, PT, R10, {dreg}, RZ ;", ("add", "R10", "R10", dreg), ctl=C(wait=rwait)))
    elif store == "STS.addr":
        b += [Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")),
              Ins("IADD3 R7, PT, PT, R9, 0x20, RZ ;", ("add", "R7", "R9", 0x20))]
        b += front_ins(front, False)
        b.append(Ins("STS [R7], R6 ;", ("sts", "R7", 0, "R6", 1), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LDS":      # word 3 of slot 3 holds the address of slot 3 (prologue): the load brings the OTHER address
            b.append(Ins("LDS R7, [R9+0x3c] ;", ("lds", "R7", "R9", 0x3c, 1), ctl=C(wait=ow, wb="3"), tag="O"))
        else:
            b.append(Ins("IADD3 R7, PT, PT, R9, 0x30, RZ ;", ("add", "R7", "R9", 0x30), ctl=C(wait=ow), tag="O"))
        b += [Ins("LDS R8, [R9+0x20] ;", ("lds", "R8", "R9", 0x20, 1), ctl=C(wait="3" if (over == "LDS" and not ctl) else "", wb="0")),
              Ins("LDS R13, [R9+0x30] ;", ("lds", "R13", "R9", 0x30, 1), ctl=C(wb="1"), tag="B"),
              Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(wait="01")), ADD10()]
    elif store == "STG.addr":
        b += [Ins("IADD3 R14, PT, PT, R4, R5, RZ ;", ("add", "R14", "R4", "R5")),
              Ins("MOV R6, R16 ;", ("mov", "R6", "R16")), Ins("MOV R7, R17 ;", ("mov", "R7", "R17"))]
        b += front_ins(front, True)
        b.append(Ins("STG.E desc[UR4][R6.64], R14 ;", ("stg", "R6", "R14"), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b += [PAD(), PAD()]
        else:
            b += [Ins("MOV R6, R18 ;", ("mov", "R6", "R18"), ctl=C(wait=ow), tag="O"), Ins("MOV R7, R19 ;", ("mov", "R7", "R19"))]
        b += [Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wb="0")),
              Ins("LDG.E R13, desc[UR4][R18.64] ;", ("ldg", "R13", "R18"), ctl=C(wb="1"), tag="B"),
              Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(wait="01")), ADD10()]
    return b


MMA_FORMS = {"QMMA.SF.E4M3.E2M1": "QMMA.SF.16832.F32.E4M3.E2M1.E8", "HMMA.F16": "HMMA.16816.F32", "HMMA.BF16": "HMMA.16816.F32.BF16"}
# per form: the A fragment word on even iterations and what an odd iteration adds (1.0 -> 2.0 in every element), the B1 / B2
# words (1.0 / 2.0 in every element), the reduction length K (a result element = accumulator + K * a * b), the element
# mask of a fragment word and the value of its codes
MMA_SPEC = {"QMMA.SF.E4M3.E2M1": dict(a0=0x38383838, da=0x08080808, b1=0x08080808, b2=0x10101010, k=32, amask=0xFF, bmask=0xFF,
                                      aval={0x38: 1, 0x40: 2}, bval={0x08: 1, 0x10: 2}),
            "HMMA.F16": dict(a0=0x3c003c00, da=0x04000400, b1=0x3c003c00, b2=0x40004000, k=16, amask=0xFFFF, bmask=0xFFFF,
                             aval={0x3c00: 1, 0x4000: 2}, bval={0x3c00: 1, 0x4000: 2}),
            "HMMA.BF16": dict(a0=0x3f803f80, da=0x00800080, b1=0x3f803f80, b2=0x40004000, k=16, amask=0xFFFF, bmask=0xFFFF,
                              aval={0x3f80: 1, 0x4000: 2}, bval={0x3f80: 1, 0x4000: 2})}
MMA_VARIANTS = {"acc2": "another accumulator, the same A fragment, another B fragment (the served loops)",
                "chain": "the SAME accumulator in both (the accumulate chain)",
                "guard": "both under a guard, two different predicates, both true",
                "gfalse": "the second under a guard that is false (it must change nothing)",
                # the operand HOLD of an MMA: ONE MMA, and d cycles behind it a fixed-latency instruction rewrites a register
                # of its A or B fragment (the MMA must have read it: the result may not change)
                "hold_a_mov": "one MMA; MOV rewrites a register of its A fragment d cycles behind it",
                "hold_a_iadd3": "one MMA; IADD3 rewrites a register of its A fragment d cycles behind it",
                "hold_b_mov": "one MMA; MOV rewrites a register of its B fragment d cycles behind it",
                "hold_b_iadd3": "one MMA; IADD3 rewrites a register of its B fragment d cycles behind it",
                "hold_b_shf": "one MMA; SHF.R.U32.HI rewrites the upper register of its B fragment from the lower one, d cycles behind it",
                "hold_bl_mov": "one MMA; MOV rewrites the LOWER register of its B fragment d cycles behind it",
                # positive controls: the same rewrite 45 cycles IN FRONT of the MMA. The model ignores the rewrite, so `good` here
                # means "the rewritten register is not part of what the MMA reads" - a hold result on that register would be void
                "sens_a_mov": "CONTROL: MOV rewrites the A-fragment register IN FRONT of the MMA (the result must change: expect 0 % good)",
                "sens_b_mov": "CONTROL: MOV rewrites the upper B-fragment register IN FRONT of the MMA (expect 0 % good)",
                "sens_b_shf": "CONTROL: SHF.R.U32.HI rewrites the upper B-fragment register IN FRONT of the MMA (expect 0 % good)",
                "sens_bl_mov": "CONTROL: MOV rewrites the LOWER B-fragment register IN FRONT of the MMA (expect 0 % good)"}


MMAFRONT_RE = re.compile(r"mmax(\d+)@(\d+)")


def mma_front(front):
    """the tensor traffic in front of the MMA of a hold request: `mmaxK@S` = K MMAs of the same form on ANOTHER accumulator
    (R24, the same A fragment, the B2 fragment), stall S each - the tested MMA is issued S cycles behind the last of them.
    -> (K, S); (0, 0) for none"""
    if front in ("none", "", None):
        return 0, 0
    m = MMAFRONT_RE.fullmatch(front)
    if not m:
        raise SystemExit(f"unknown front {front!r} for an mma hold request: none | mmaxK@S")
    k, s = int(m.group(1)), int(m.group(2))
    if not (1 <= k <= 16 and 1 <= s <= 15):
        raise SystemExit(f"front {front!r}: K 1..16, S 1..15")
    return k, s


def body_mma(req, d, front="none"):
    """two block-scaled MMAs of one warp, d issue cycles apart. Every element of the A fragment is the same E4M3 code
    (1.0 on even iterations, 2.0 on odd), of the B fragments the same E2M1 code (B1 1.0, B2 2.0), the block scales are 1,
    and the accumulators are integer-valued floats 2^23 + k (k per thread and register): each result is its accumulator
    + 32 * a * b - an INTEGER add on the bit pattern, exact, whatever the fragment layout is."""
    form, var, fn, sp = MMA_FORMS[req["form"]], req["variant"], req["form"], MMA_SPEC[req["form"]]
    if fn.startswith("QMMA"):
        q = lambda rd, rb: f"{form} {rd}, R16, {rb}, {rd}, R14, R14, URZ ;"
    else:
        q = lambda rd, rb: f"{form} {rd}, R16, {rb}, {rd} ;"
    b = [Ins("LOP3.LUT R0, R11, 0x1, RZ, 0xc0, !PT ;", ("and", "R0", "R11", 1)),
         Ins(f"IMAD R16, R0, 0x{sp['da']:x}, RZ ;", ("mad", "R16", "R0", sp["da"], "RZ")),
         Ins(f"IADD3 R16, PT, PT, R16, 0x{sp['a0']:x}, RZ ;", ("add", "R16", "R16", sp["a0"])),
         Ins("MOV R17, R16 ;", ("mov", "R17", "R16")), Ins("MOV R18, R16 ;", ("mov", "R18", "R16")), Ins("MOV R19, R16 ;", ("mov", "R19", "R16")),
         Ins("LOP3.LUT R28, R4, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R28", "R4", 0x3fffff)),
         Ins("LOP3.LUT R28, R28, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R28", "R28", 0x4b000000)),
         Ins("IADD3 R29, PT, PT, R28, 0x1, RZ ;", ("add", "R29", "R28", 1)), Ins("IADD3 R30, PT, PT, R28, 0x2, RZ ;", ("add", "R30", "R28", 2)),
         Ins("IADD3 R31, PT, PT, R28, 0x3, RZ ;", ("add", "R31", "R28", 3)),
         Ins("LOP3.LUT R24, R5, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R24", "R5", 0x3fffff)),
         Ins("LOP3.LUT R24, R24, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R24", "R24", 0x4b000000)),
         Ins("IADD3 R25, PT, PT, R24, 0x1, RZ ;", ("add", "R25", "R24", 1)), Ins("IADD3 R26, PT, PT, R24, 0x2, RZ ;", ("add", "R26", "R24", 2)),
         Ins("IADD3 R27, PT, PT, R24, 0x3, RZ ;", ("add", "R27", "R24", 3)),
         PAD(), PAD()]
    if var.startswith("sens_"):
        if var.startswith("sens_bl"):
            b.insert(0, Ins("MOV R12, R13 ;", ("mov", "R12", "R13")))
        elif var.startswith("sens_b"):
            b.insert(0, Ins("MOV R13, R12 ;", ("mov", "R13", "R12")))
        tgt = "R17" if var.startswith("sens_a") else "R12" if var.startswith("sens_bl") else "R13"
        b.append(Ins("SHF.R.U32.HI R13, RZ, 0x5, R12 ;", ("nop",)) if var.endswith("_shf") else Ins(f"MOV {tgt}, R6 ;", ("nop",)))
        b += [PAD(), PAD(), PAD()]
        b.append(Ins(q("R28", "R12"), ("qmma", "R28", "R16", "R12", None, fn), tag="P", dst=["R28", "R29", "R30", "R31"]))
        b += [PAD(), PAD(), PAD()]
        for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                       ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
            b.append(Ins(t, sem))
        return b
    if var.startswith("hold_"):
        if var.startswith("hold_bl"):
            b.insert(0, Ins("MOV R12, R13 ;", ("mov", "R12", "R13")))      # the lower B register of the last iteration's overwrite
        elif var.startswith("hold_b"):
            b.insert(0, Ins("MOV R13, R12 ;", ("mov", "R13", "R12")))      # the B register of the last iteration's overwrite
        s, fill = split_distance(d)
        fk, fs = mma_front(front)
        for _ in range(fk):       # the traffic: K MMAs in front, another accumulator (not part of the checksum)
            b.append(Ins(q("R24", "R6"), ("qmma", "R24", "R16", "R6", None, fn), ctl=C(fs), tag="F"))
        b.append(Ins(q("R28", "R12"), ("qmma", "R28", "R16", "R12", None, fn), ctl=C(s, y=req.get("yield") == "set"), tag="P", dst=["R28", "R29", "R30", "R31"]))
        b += fill
        tgt = "R17" if var.startswith("hold_a") else "R12" if var.startswith("hold_bl") else "R13"
        if var.endswith("_mov"):       # R6 = the B2 word: another finite code in every element
            b.append(Ins(f"MOV {tgt}, R6 ;", ("mov", tgt, "R6"), tag="O"))
        elif var.endswith("_shf"):
            b.append(Ins("SHF.R.U32.HI R13, RZ, 0x5, R12 ;", ("shr", "R13", "R12", 5), tag="O"))
        else:
            b.append(Ins(f"IADD3 {tgt}, PT, PT, {tgt}, 0x8080808, RZ ;", ("add", tgt, tgt, 0x08080808), tag="O"))
        b += [PAD(), PAD(), PAD()]
        for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                       ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
            b.append(Ins(t, sem))
        return b
    g1 = "@P0 " if var in ("guard", "gfalse") else ""
    g2 = {"guard": "@P2 ", "gfalse": "@P3 "}.get(var, "")
    rd2 = "R28" if var == "chain" else "R24"
    if req.get("via", "stall") == "nop":      # the vendor's shape: the first MMA, a NOP of one cycle, the second
        npad = (d - 2) // 15
        s = d - 1 - 15 * npad
        fill = [Ins("NOP ;", ("nop",), ctl=C(1))] + [PAD() for _ in range(npad)]
    else:
        s, fill = split_distance(d)
    b.append(Ins(g1 + q("R28", "R12"), ("qmma", "R28", "R16", "R12", "P0" if g1 else None, fn), ctl=C(s, y=req.get("yield") == "set"), tag="P",
                 dst=["R28", "R29", "R30", "R31"]))
    b += fill
    b.append(Ins(g2 + q(rd2, "R6"), ("qmma", rd2, "R16", "R6", g2.strip("@ ") or None, fn), tag="C"))
    b += [PAD(), PAD(), PAD()]      # a reader of an MMA result is 45 cycles behind the second (the table's row: 28)
    for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                   ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IMAD R8, R24, 0xb, R8 ;", ("mad", "R8", "R24", 11, "R8")),
                   ("IMAD R8, R25, 0xd, R8 ;", ("mad", "R8", "R25", 13, "R8")), ("IMAD R8, R26, 0x11, R8 ;", ("mad", "R8", "R26", 17, "R8")),
                   ("IMAD R8, R27, 0x13, R8 ;", ("mad", "R8", "R27", 19, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
        b.append(Ins(t, sem))
    return b




def prologue(req, ctas):
    """the same for every kernel of a request (and, but for the address of word B, of the tool)"""
    half = 1024 * ctas * 4
    p = [Ins("LDCU.64 UR4, c[0x0][0x358] ;", ("nop",), ctl=C(4, wb="0")),
         Ins("S2R R0, SR_TID.X ;", ("nop",), ctl=C(4, wb="1")),
         Ins("S2R R1, SR_CTAID.X ;", ("nop",), ctl=C(4, wb="2")),
         Ins("LDC.64 R2, c[0x0][0x380] ;", ("nop",), ctl=C(4, wb="3")),
         Ins("LDC R4, c[0x0][0x388] ;", ("nop",), ctl=C(8, wb="4")),
         Ins("IMAD R1, R1, 0x400, R0 ;", ("mad", "R1", "R1", 0x400, "R0"), ctl=C(wait="01234")),      # gid
         Ins("MOV R12, R1 ;", ("mov", "R12", "R1")),
         Ins("IADD3 R4, PT, PT, R4, R12, RZ ;", ("add", "R4", "R4", "R12")),                         # a0 = seed + gid
         Ins("LOP3.LUT R5, R12, 0x5bd1e995, RZ, 0x3c, !PT ;", ("xor", "R5", "R12", 0x5bd1e995)),      # b0
         Ins("MOV R10, RZ ;", ("mov", "R10", 0)), Ins("MOV R11, RZ ;", ("mov", "R11", 0)), Ins("MOV R15, RZ ;", ("nop",)),
         Ins("IMAD R9, R0, 0x40, RZ ;", ("base", "R9")),                                             # the thread's 64 bytes
         Ins("LOP3.LUT R20, R12, 0xa5a5a5a5, RZ, 0x3c, !PT ;", ("xor", "R20", "R12", 0xa5a5a5a5)),
         Ins("MOV R21, 0xf0f0f0f ;", ("mov", "R21", 0x0f0f0f0f)), Ins("MOV R22, 0xdeadbeef ;", ("mov", "R22", 0xdeadbeef)),
         Ins("IMAD R23, R12, 0x9e3779b1, RZ ;", ("mad", "R23", "R12", 0x9e3779b1, "RZ")),
         Ins("STS.128 [R9+0x30], R20 ;", ("sts", "R9", 0x30, "R20", 4)), Ins("STS.128 [R9], R20 ;", ("sts", "R9", 0, "R20", 4)),
         Ins("STS.128 [R9+0x10], R20 ;", ("sts", "R9", 0x10, "R20", 4)), Ins("STS.128 [R9+0x20], R20 ;", ("sts", "R9", 0x20, "R20", 4)),
         PAD(), PAD(), PAD(), PAD()]
    if req["kind"] != "mma":
        p += [Ins("IMAD.WIDE.U32 R16, R1, 0x4, R2 ;", ("gaddr", "R16", 0)),                          # A = &out[gid]
              Ins(f"MOV R14, 0x{half:x} ;", ("nop",)),
              Ins("IMAD.WIDE.U32 R18, R14, 0x1, R16 ;", ("gaddr", "R18", 1)),                        # B = A + half
              Ins("STG.E desc[UR4][R18.64], R20 ;", ("stg", "R18", "R20")),
              PAD(), PAD()]
    else:
        # uniform fragments: every element of B1 is 1.0 and of B2 is 2.0 (E2M1, one element per byte at bits 5:2), unit
        # block scales (UE8M0 0x7f); R9 and R20..R23 are NOT touched (the bare stores above read them when they are served)
        sp = MMA_SPEC[req["form"]]
        p += [Ins(f"MOV R12, 0x{sp['b1']:x} ;", ("mov", "R12", sp["b1"])), Ins(f"MOV R13, 0x{sp['b1']:x} ;", ("mov", "R13", sp["b1"])),
              Ins(f"MOV R6, 0x{sp['b2']:x} ;", ("mov", "R6", sp["b2"])), Ins("MOV R14, 0x7f7f7f7f ;", ("mov", "R14", 0x7f7f7f7f)),
              Ins("ISETP.EQ.U32.AND P0, PT, RZ, RZ, PT ;", ("mov", "P0", 1)), Ins("ISETP.EQ.U32.AND P2, PT, RZ, RZ, PT ;", ("mov", "P2", 1)),
              Ins("ISETP.NE.U32.AND P3, PT, RZ, RZ, PT ;", ("mov", "P3", 0)),
              Ins(f"MOV R7, 0x{sp['b2']:x} ;", ("mov", "R7", sp["b2"])), Ins("MOV R8, RZ ;", ("mov", "R8", 0)),
              Ins("MOV R24, RZ ;", ("mov", "R24", 0)), Ins("MOV R25, RZ ;", ("mov", "R25", 0)),
              Ins("MOV R26, RZ ;", ("mov", "R26", 0)), Ins("MOV R27, RZ ;", ("mov", "R27", 0))]
        return p
    p += [Ins("MOV R7, RZ ;", ("mov", "R7", 0)), Ins("MOV R8, RZ ;", ("mov", "R8", 0)),
         Ins("MOV R13, RZ ;", ("mov", "R13", 0)), Ins("MOV R14, RZ ;", ("mov", "R14", 0)),
         Ins("MOV R24, RZ ;", ("mov", "R24", 0)), Ins("MOV R25, RZ ;", ("mov", "R25", 0)),
         Ins("MOV R26, RZ ;", ("mov", "R26", 0)), Ins("MOV R27, RZ ;", ("mov", "R27", 0))]
    addr = req["kind"] == "raw" and RAW_CONSUMERS[req["consumer"]][0] == "addr"
    if req["kind"] == "raw" and RAW_CONSUMERS[req["consumer"]][0] == "udata":
        p += [Ins("UMOV UR6, 0x0 ;", ("mov", "UR6", 0)), Ins("UMOV UR7, 0x0 ;", ("mov", "UR7", 0)), Ins("UMOV UR8, 0x0 ;", ("mov", "UR8", 0))]
    if req["kind"] == "raw" and (req["producer"] == "SEL" or req["consumer"] == "SEL.r1"):
        p.append(Ins("ISETP.LT.U32.AND P2, PT, RZ, RZ, PT ;", ("mov", "P2", 0)))
    if req["kind"] == "war" and req["store"] == "STS.addr" and req["overwriter"] == "LDS":
        # the address the overwriting load brings: word 3 of slot 3 := the address of slot 3 (a store with a read barrier, waited)
        p += [Ins("IADD3 R13, PT, PT, R9, 0x30, RZ ;", ("add", "R13", "R9", 0x30)),
              Ins("STS [R9+0x3c], R13 ;", ("sts", "R9", 0x3c, "R13", 1), ctl=C(rb="5")),
              Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")), PAD()]
    if addr:      # a stale ADDRESS must still be an address of the thread's own slot
        p += [Ins("IADD3 R6, PT, PT, R9, 0x20, RZ ;", ("add", "R6", "R9", 0x20)),
              Ins("IADD3 R13, PT, PT, R9, 0x20, RZ ;", ("add", "R13", "R9", 0x20))]
    else:
        p.append(Ins("MOV R6, RZ ;", ("mov", "R6", 0)))
    if req["kind"] == "ord" and req.get("younger_guard"):
        p += [Ins("ISETP.EQ.U32.AND P0, PT, RZ, RZ, PT ;", ("nop",)), Ins("ISETP.NE.U32.AND P3, PT, RZ, RZ, PT ;", ("nop",))]
    if req["kind"] == "ord" and req.get("nload") and req.get("place") == "far":
        # R14 = the thread's word in the second region; word k := a per-thread constant (a store with read barrier 5, waited)
        fb, stride = far_layout(int(req.get("_threads", 1024)))
        p += [Ins("IMAD R14, R0, 0x4, RZ ;", ("nop",)), Ins(f"IADD3 R14, PT, PT, R14, 0x{fb:x}, RZ ;", ("nop",))]
        for k in range(int(req["nload"])):
            c = (0x9e3779b1 * (k + 1)) & 0xFFFFFFFF
            p += [Ins(f"IADD3 R13, PT, PT, R20, 0x{c:x}, RZ ;", ("add", "R13", "R20", c)),
                  Ins(f"STS [R14{('+0x%x' % (k * stride)) if k else ''}], R13 ;", ("stsf", k, "R13"), ctl=C(rb="5")),
                  Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5"))]
        p += [PAD(), PAD()]
    return p


TAIL = [Ins("IADD3 R4, PT, PT, R4, 0x9e3779b9, RZ ;", ("add", "R4", "R4", 0x9e3779b9)),
        Ins("IADD3 R5, PT, PT, R5, 0x7f4a7c15, RZ ;", ("add", "R5", "R5", 0x7f4a7c15)),
        Ins("IADD3 R11, PT, PT, R11, 0x1, RZ ;", ("add", "R11", "R11", 1))]


def misaligned(text):
    """operands the card refuses at the first launch although the assembler takes them: a 64-bit register pair on an odd
    register, a 128-bit operand (or a tensor instruction's result / A fragment) off a multiple of four. -> list of problems"""
    bad = []
    for line in text.splitlines():
        m = re.match(r"\s*\[B[^\]]*\]\s+(?:@!?U?P[\dT]\s+)?(\S+)\s+(.*?)\s*;", line)
        if not m:
            continue
        op, rest = m.group(1), m.group(2)
        ops = [o.strip() for o in re.split(r",(?![^\[]*\])", rest)]
        regs = lambda o: [int(x) for x in re.findall(r"(?<![UA-Za-z])R(\d+)\b", o)]
        for n in re.findall(r"(?<![UA-Za-z])R(\d+)\.64", rest):
            if int(n) % 2:
                bad.append(f"{op}: a 64-bit address pair on R{n}")
        if op.startswith(("IADD.64", "CS2R", "LDC.64", "MOV.64", "IMAD.WIDE")):
            pair = ops[:1] if op.startswith(("CS2R", "LDC.64", "IMAD.WIDE")) else [o for o in ops if re.fullmatch(r"-?R\d+", o)]
            if op.startswith("IMAD.WIDE") and len(ops) >= 4 and re.fullmatch(r"R\d+", ops[-1]):
                pair = pair + [ops[-1]]
            for o in pair:
                for n in regs(o):
                    if n % 2:
                        bad.append(f"{op}: a 64-bit pair on R{n}")
        if op.startswith(("LDS.64", "STS.64", "LDG.E.64", "STG.E.64")):
            for o in ops:
                if "[" not in o:
                    for n in regs(o):
                        if n % 2:
                            bad.append(f"{op}: a 64-bit data pair on R{n}")
        if ".128" in op or op.startswith("LDSM"):
            for o in ops:
                if "[" not in o:
                    for n in regs(o):
                        if n % 4:
                            bad.append(f"{op}: a 128-bit operand on R{n}")
        if re.match(r"[A-Z]MMA", op):
            for k, o in enumerate(ops[:4]):
                for n in regs(o):
                    if n % (2 if k == 2 else 4):
                        bad.append(f"{op}: operand {k} on R{n}")
    return bad


def kernel_text(name, req, ctas, body, smem=SMEM):
    lines = [f".entry {name}", "    .reg R0-R31", "    .regcount 40", "    .param ptr out", "    .param u32 seed", f"    .shared smem[{smem}]"]
    lines += [f"    {i.line()}" for i in prologue(req, ctas)]
    lines.append("L_loop:")
    lines += [f"    {i.line()}" for i in body]
    lines += [f"    {i.line()}" for i in TAIL]
    lines += [f"    {C()} ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;", f"    {C()} @P1 BRA L_loop ;",
              f"    {C()} IMAD.WIDE.U32 R2, R1, 0x4, R2 ;", f"    {C()} STG.E desc[UR4][R2.64], R10 ;", f"    {C()} EXIT ;", ".endentry", ""]
    text = "\n".join(lines)
    bad = misaligned(text)
    if bad:
        raise SystemExit(f"{name}: refusing to write a kernel the card would trap on - {sorted(set(bad))}")
    return text


# ------------------------------------------------------------------------------------------------ the host model
class Poison(Exception):
    pass


def model(req, mode, gids=None, scalar=False):
    """the checksum (R10) every thread must end with, per failure hypothesis `mode`:
    good | stale (raw) | late, overtake (war). numpy over all gids, or (scalar=True) plain Python integers - the
    independent check of the vectorised code."""
    import numpy as np
    if gids is None:
        gids = np.arange(NGID, dtype=np.int64)
    if shfl_of(req) and not scalar:      # (version 18: also write-after-write with a shuffle, and an older shuffle of kind ord)
        gids = np.asarray(gids, dtype=np.int64)
        need = np.union1d(gids, (gids ^ 1) if shfl_of(req) == "bfly" else ((gids & ~31) | 1))
        if len(need) != len(gids):      # a shuffle reads another lane: model the closed set, return the threads asked for
            return model(req, mode, gids=need)[np.searchsorted(need, gids)]
    if req["kind"] == "war":
        body = body_war(req, 15, "none", "bare")
    elif req["kind"] == "ord":
        body = body_ord(req, 15, "none", "bare")
    elif req["kind"] == "mma":
        body = body_mma(dict(req, via="stall"), 15, req.get("_model_front", "none"))
    else:
        body = body_raw(dict(req, via="stall"), 15, "none")
    if mode in ("drop1", "drop2"):      # mma: the first / the second MMA changed nothing in any iteration
        body = [i for i in body if i.tag != ("P" if mode == "drop1" else "C")]
        mode = "good"
    pro = prologue(req, 188)
    if scalar:
        return [_scalar(int(g), pro, body, mode) for g in gids]
    n = len(gids)
    U = np.uint32
    R = {"R0": (gids % 1024).astype(U), "R1": (gids // 1024).astype(U), "R4": np.full(n, SEED, U),
         "R17": np.zeros(n, U), "R19": np.zeros(n, U), "RZ": np.zeros(n, U)}
    mem = np.zeros((n, 16), U)
    farmem = np.zeros((n, 16), U)
    G = np.zeros((n, 2), U)
    rows = np.arange(n)
    consts = {}

    def get(x):
        if isinstance(x, int):
            if x not in consts:
                consts[x] = np.full(n, x & 0xFFFFFFFF, U)
            return consts[x]
        v = R.get(x)
        if v is None:
            raise Poison(x)
        return v

    def reg(r, k):
        return f"R{int(r[1:]) + k}"

    def ex(sem):
        op = sem[0]
        if op == "nop":
            return
        if op == "mov":
            R[sem[1]] = get(sem[2])
        elif op == "add":
            R[sem[1]] = get(sem[2]) + get(sem[3])
        elif op == "xor":
            R[sem[1]] = get(sem[2]) ^ get(sem[3])
        elif op == "and":
            R[sem[1]] = get(sem[2]) & get(sem[3])
        elif op == "or":
            R[sem[1]] = get(sem[2]) | get(sem[3])
        elif op == "mad":
            R[sem[1]] = get(sem[2]) * get(sem[3]) + get(sem[4])
        elif op == "shl":
            R[sem[1]] = get(sem[2]) << U(sem[3])
        elif op == "shr":
            R[sem[1]] = get(sem[2]) >> U(sem[3])
        elif op in ("fadd", "fmul"):
            a, b = get(sem[2]).view(np.float32), get(sem[3]).view(np.float32)
            R[sem[1]] = ((a + b) if op == "fadd" else (a * b)).astype(np.float32).view(U)
        elif op == "ltu":
            R[sem[1]] = (get(sem[2]) < get(sem[3])).astype(U)
        elif op == "sel":           # P ? a : b
            R[sem[1]] = np.where(get(sem[4]) != 0, get(sem[2]), get(sem[3]))
        elif op == "selnot":        # !P ? a : b
            R[sem[1]] = np.where(get(sem[4]) != 0, get(sem[3]), get(sem[2]))
        elif op == "rsub":
            R[sem[1]] = get(sem[3]) - get(sem[2])
        elif op == "prmt":          # byte i of the result = byte (nibble i of the selector) of the 8 bytes Rb:Ra
            pool = get(sem[2]).astype(np.uint64) | (get(sem[4]).astype(np.uint64) << np.uint64(32))
            out = np.zeros(n, np.uint64)
            for k in range(4):
                nib = (sem[3] >> (4 * k)) & 7
                out |= ((pool >> np.uint64(8 * nib)) & np.uint64(0xFF)) << np.uint64(8 * k)
            R[sem[1]] = out.astype(U)
        elif op == "bf16pack2":     # round to nearest even at bit 16, the same bf16 in both halves
            x = get(sem[2])
            h = ((x.astype(np.uint64) + np.uint64(0x7FFF) + ((x >> U(16)) & U(1)).astype(np.uint64)) >> np.uint64(16)) & np.uint64(0xFFFF)
            R[sem[1]] = ((h << np.uint64(16)) | h).astype(U)
        elif op == "i2f":
            R[sem[1]] = get(sem[2]).view(np.int32).astype(np.float32).view(U)
        elif op == "add64i":        # the pair R(d+1):Rd = R(a+1):Ra + imm
            v = (get(sem[2]).astype(np.uint64) | (get(reg(sem[2], 1)).astype(np.uint64) << np.uint64(32))) + np.uint64(sem[3])
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "qmma":          # every element of the result = its accumulator + 32 * a * b (integer-valued, exact)
            if sem[4] is not None and not int(get(sem[4])[0]):
                return
            sp = MMA_SPEC[sem[5]]
            av, bv = int(get(sem[2])[0]) & sp["amask"], int(get(sem[3])[0]) & sp["bmask"]
            if (get(sem[2]) != get(sem[2])[0]).any() or av not in sp["aval"] or bv not in sp["bval"]:
                raise RuntimeError(f"model: an MMA fragment the model does not know ({sem})")
            for k in range(4):
                R[reg(sem[1], k)] = get(reg(sem[1], k)) + U(sp["k"] * sp["aval"][av] * sp["bval"][bv])
        elif op == "zero2":
            R[sem[1]] = np.zeros(n, U)
            R[reg(sem[1], 1)] = np.zeros(n, U)
        elif op == "shl64hi":       # the high word of (hi:lo) << k
            R[sem[1]] = (get(sem[4]) << U(sem[3])) | (get(sem[2]) >> U(32 - sem[3]))
        elif op == "mulw":
            v = get(sem[2]).astype(np.uint64) * get(sem[3]).astype(np.uint64)
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "madw":          # the pair R(d+1):Rd = Ra * Rb + R(c+1):Rc (mod 2^64)
            v = (get(sem[2]).astype(np.uint64) * get(sem[3]).astype(np.uint64)
                 + (get(sem[4]).astype(np.uint64) | (get(reg(sem[4], 1)).astype(np.uint64) << np.uint64(32))))
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "base":
            R[sem[1]] = np.zeros(n, U)
        elif op == "gaddr":
            R[sem[1]] = np.full(n, sem[2], U)
        elif op == "sts":
            a = get(sem[1]) + U(sem[2])
            if (a & U(3)).any() or (a > U(64 - 4 * sem[4])).any():
                raise RuntimeError(f"model: a shared store outside the thread's 64 bytes ({sem})")
            w = (a >> U(2)).astype(np.int64)
            for k in range(sem[4]):
                mem[rows, w + k] = get(reg(sem[3], k))
        elif op == "lds":
            a = get(sem[2]) + U(sem[3])
            if (a & U(3)).any() or (a > U(64 - 4 * sem[4])).any():
                raise RuntimeError(f"model: a shared load outside the thread's 64 bytes ({sem})")
            w = (a >> U(2)).astype(np.int64)
            for k in range(sem[4]):
                R[reg(sem[1], k)] = mem[rows, w + k]
        elif op == "ldsu16":        # 16 bits of the thread's slot, zero-extended
            a = get(sem[2]) + U(sem[3])
            R[sem[1]] = mem[rows, (a >> U(2)).astype(np.int64)] & U(0xFFFF)
        elif op == "poison":
            for k in range(sem[2]):
                R[reg(sem[1], k)] = None
        elif op == "stsf":          # word k of the thread's far region
            farmem[rows, sem[1]] = get(sem[2])
        elif op == "ldsf":
            R[sem[1]] = farmem[rows, sem[2]].copy()
        elif op == "stg":
            G[rows, get(sem[1]).astype(np.int64)] = get(sem[2])
        elif op == "ldg":
            R[sem[1]] = G[rows, get(sem[2]).astype(np.int64)]
        elif op == "shfl":          # every lane takes the register of another lane of its warp: lane ^ k (bfly) or lane k (idx)
            src = (gids ^ sem[4]) if sem[3] == "bfly" else ((gids & ~31) | sem[4])
            pos = np.minimum(np.searchsorted(gids, src), n - 1)
            if (gids[pos] != src).any():
                raise RuntimeError("model: a shuffle needs its source lanes among the modelled threads")
            R[sem[1]] = get(sem[2])[pos]
        else:
            raise RuntimeError(f"model: unknown op {sem}")

    for i in pro:
        ex(i.sem)
    last_b = max((k for k, i in enumerate(body) if i.tag == "B"), default=-1)
    for _ in range(REPEAT):
        old, deferred = {}, None
        for k, i in enumerate(body):
            if mode == "stale" and i.tag == "P":
                old.update({r: R[r] for r in i.dst if r in R})      # (several producers in front of one reader: all stale)
                ex(i.sem)
            elif mode == "stale" and i.tag == "C":
                cur = {r: R[r] for r in old}
                R.update(old)
                ex(i.sem)
                R.update(cur)
            elif mode in ("late", "overtake") and i.tag == "S":
                deferred = i
            elif mode == "late" and i.tag == "O":
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            elif mode == "overtake" and k == last_b:
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            else:
                ex(i.sem)
        if deferred is not None:
            raise RuntimeError(f"model: mode {mode} found no place for the deferred store")
        for i in TAIL:
            ex(i.sem)
    return R["R10"].copy()


def _machine(gid):
    """one thread on Python integers -> (its registers, get, ex)"""
    M = 0xFFFFFFFF
    R = {"R0": gid % 1024, "R1": gid // 1024, "R4": SEED, "R17": 0, "R19": 0, "RZ": 0}
    mem, farmem, G = [0] * 16, [0] * 16, [0, 0]

    def get(x):
        if isinstance(x, int):
            return x & M
        v = R.get(x)
        if v is None:
            raise Poison(x)
        return v

    def reg(r, k):
        return f"R{int(r[1:]) + k}"

    def ex(sem):
        import struct
        op = sem[0]
        if op == "nop":
            return
        if op == "mov":
            R[sem[1]] = get(sem[2])
        elif op == "add":
            R[sem[1]] = (get(sem[2]) + get(sem[3])) & M
        elif op == "xor":
            R[sem[1]] = get(sem[2]) ^ get(sem[3])
        elif op == "and":
            R[sem[1]] = get(sem[2]) & get(sem[3])
        elif op == "or":
            R[sem[1]] = get(sem[2]) | get(sem[3])
        elif op == "mad":
            R[sem[1]] = (get(sem[2]) * get(sem[3]) + get(sem[4])) & M
        elif op == "shl":
            R[sem[1]] = (get(sem[2]) << sem[3]) & M
        elif op == "shr":
            R[sem[1]] = get(sem[2]) >> sem[3]
        elif op in ("fadd", "fmul"):
            a = struct.unpack("<f", struct.pack("<I", get(sem[2])))[0]
            b = struct.unpack("<f", struct.pack("<I", get(sem[3])))[0]
            R[sem[1]] = struct.unpack("<I", struct.pack("<f", a + b if op == "fadd" else a * b))[0]
        elif op == "ltu":
            R[sem[1]] = 1 if get(sem[2]) < get(sem[3]) else 0
        elif op == "sel":
            R[sem[1]] = get(sem[2]) if get(sem[4]) else get(sem[3])
        elif op == "selnot":
            R[sem[1]] = get(sem[3]) if get(sem[4]) else get(sem[2])
        elif op == "rsub":
            R[sem[1]] = (get(sem[3]) - get(sem[2])) & M
        elif op == "prmt":
            pool = (get(sem[2]) | (get(sem[4]) << 32)).to_bytes(8, "little")
            R[sem[1]] = int.from_bytes(bytes(pool[(sem[3] >> (4 * k)) & 7] for k in range(4)), "little")
        elif op == "bf16pack2":
            x = get(sem[2])
            h = ((x + 0x7FFF + ((x >> 16) & 1)) >> 16) & 0xFFFF
            R[sem[1]] = (h << 16) | h
        elif op == "i2f":
            x = get(sem[2])
            R[sem[1]] = struct.unpack("<I", struct.pack("<f", float(x - (1 << 32) if x & 0x80000000 else x)))[0]
        elif op == "add64i":
            v = ((get(sem[2]) | (get(reg(sem[2], 1)) << 32)) + sem[3]) & 0xFFFFFFFFFFFFFFFF
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "qmma":
            if sem[4] is not None and not get(sem[4]):
                return
            sp = MMA_SPEC[sem[5]]
            av, bv = get(sem[2]) & sp["amask"], get(sem[3]) & sp["bmask"]
            for k in range(4):
                R[reg(sem[1], k)] = (get(reg(sem[1], k)) + sp["k"] * sp["aval"][av] * sp["bval"][bv]) & M
        elif op == "zero2":
            R[sem[1]] = 0
            R[reg(sem[1], 1)] = 0
        elif op == "shl64hi":
            R[sem[1]] = ((get(sem[4]) << sem[3]) | (get(sem[2]) >> (32 - sem[3]))) & M
        elif op == "mulw":
            v = get(sem[2]) * get(sem[3])
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "madw":
            v = (get(sem[2]) * get(sem[3]) + (get(sem[4]) | (get(reg(sem[4], 1)) << 32))) & 0xFFFFFFFFFFFFFFFF
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "base":
            R[sem[1]] = 0
        elif op == "gaddr":
            R[sem[1]] = sem[2]
        elif op == "sts":
            a = (get(sem[1]) + sem[2]) & M
            assert a % 4 == 0 and a + 4 * sem[4] <= 64, sem
            for k in range(sem[4]):
                mem[a // 4 + k] = get(reg(sem[3], k))
        elif op == "lds":
            a = (get(sem[2]) + sem[3]) & M
            assert a % 4 == 0 and a + 4 * sem[4] <= 64, sem
            for k in range(sem[4]):
                R[reg(sem[1], k)] = mem[a // 4 + k]
        elif op == "ldsu16":
            R[sem[1]] = mem[((get(sem[2]) + sem[3]) & M) // 4] & 0xFFFF
        elif op == "poison":
            for k in range(sem[2]):
                R[reg(sem[1], k)] = None
        elif op == "stsf":
            farmem[sem[1]] = get(sem[2])
        elif op == "ldsf":
            R[sem[1]] = farmem[sem[2]]
        elif op == "stg":
            G[get(sem[1])] = get(sem[2])
        elif op == "ldg":
            R[sem[1]] = G[get(sem[2])]
        else:
            raise RuntimeError(sem)

    return R, get, ex


def _scalar(gid, pro, body, mode):
    """the same semantics on Python integers, one thread (a body with a warp shuffle: the thread and the lane it reads,
    two interpreters in step)"""
    sh = [i.sem for i in body if i.sem[0] == "shfl"]
    if sh:
        if len({x[3:] for x in sh}) != 1:      # (version 18: mode stale too - the older shuffle of kind ord)
            raise RuntimeError("scalar model: one kind of shuffle per body")
        other = (gid ^ sh[0][4]) if sh[0][3] == "bfly" else ((gid & ~31) | sh[0][4])
        ms = [_machine(g) for g in dict.fromkeys([gid, other])]      # (the source lane last)

        def ex(sem):
            if sem[0] == "shfl":      # all lanes at once: read every source first, then write
                vals = [m[1](sem[2]) for m in ms]
                for k, m in enumerate(ms):
                    m[0][sem[1]] = vals[-1] if sem[3] == "idx" else vals[len(ms) - 1 - k]
            else:
                for m in ms:
                    m[2](sem)
        R = ms[0][0]
    else:
        R, _get, ex = _machine(gid)
    for i in pro:
        ex(i.sem)
    last_b = max((k for k, i in enumerate(body) if i.tag == "B"), default=-1)
    for _ in range(REPEAT):
        old, deferred = {}, None
        for k, i in enumerate(body):
            if mode == "stale" and i.tag == "P":
                old.update({r: R[r] for r in i.dst if r in R})
                ex(i.sem)
            elif mode == "stale" and i.tag == "C":
                cur = {r: R[r] for r in old}
                R.update(old)
                ex(i.sem)
                R.update(cur)
            elif mode in ("late", "overtake") and i.tag == "S":
                deferred = i
            elif mode == "late" and i.tag == "O":
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            elif mode == "overtake" and k == last_b:
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            else:
                ex(i.sem)
        for i in TAIL:
            ex(i.sem)
    return R["R10"]


def modes_of(req):
    if req["kind"] == "mma":
        if str(req.get("variant", "")).startswith(("hold_", "sens_")):
            return ["good", "drop1"]
        return ["good", "drop2"] if req.get("variant") == "gfalse" else ["good", "drop1", "drop2"]
    if req["kind"] == "war" and req.get("store") in SHFL_STORES + WAW_STORES:
        return ["good", "late"]      # (no read-back a late shuffle / a late first write could come behind)
    return ["good", "stale"] if req["kind"] in ("raw", "ord") else ["good", "late", "overtake"]


# ------------------------------------------------------------------------------------------------ requests
def parse_distances(spec):
    out = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+)(?::(\d+))?)?", part)
        if not m:
            raise SystemExit(f"distances: cannot read {part!r} (e.g. 1-15,18-75:3,90)")
        a = int(m.group(1))
        b = int(m.group(2) or a)
        st = int(m.group(3) or 1)
        out.update(range(a, b + 1, st))
    if not out or min(out) < 1 or max(out) > 1500:
        raise SystemExit("distances: 1 .. 1500 issue cycles")
    return sorted(out)


def normalise(req):
    r = dict(req)
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", r.get("id", "")):
        raise SystemExit(f"request id {r.get('id')!r}: lower-case letters, digits, underscore (it names files and kernels)")
    if r.get("kind") == "raw":
        if r.get("consumer") not in RAW_CONSUMERS:
            raise SystemExit(f"{r['id']}: raw consumer {r.get('consumer')!r} not in the catalogue (probe.py list)")
        what = RAW_CONSUMERS[r["consumer"]][0]
        if r.get("producer") not in (ADDR_PRODUCERS if what == "addr" else UNIFORM_PRODUCERS if what == "udata" else DATA_PRODUCERS):
            raise SystemExit(f"{r['id']}: producer {r.get('producer')!r} not in the catalogue for {r['consumer']} (probe.py list)")
        r.setdefault("distances", "1-15,20,30")
        r.setdefault("via", "stall")
    elif r.get("kind") == "war":
        if r.get("store") not in WAR_STORES or r.get("overwriter") not in WAR_STORES[r["store"]][0]:
            raise SystemExit(f"{r['id']}: store {r.get('store')!r} / overwriter {r.get('overwriter')!r} not in the catalogue (probe.py list)")
        if r.get("read_barrier") not in (None, "set") or (r.get("read_barrier") and r["store"] not in SHFL_STORES):
            raise SystemExit(f"{r['id']}: read_barrier is \"set\" (a shuffle that carries a read barrier nobody waits) or absent")
        if r.get("behind") not in (None, "write_waiter", "younger_write") or (r.get("behind") and r["store"] not in SHFL_STORES):
            raise SystemExit(f"{r['id']}: behind is \"write_waiter\" (the overwriter behind the reader that waited the shuffle's write barrier), "
                             "\"younger_write\" (a barrier-less shuffle read under a younger shuffle's write barrier) or absent")
        if r.get("behind") == "younger_write":
            r.setdefault("younger_gap", 1)
            if r.get("read_barrier") or not (isinstance(r["younger_gap"], int) and 1 <= r["younger_gap"] <= 15):
                raise SystemExit(f"{r['id']}: behind younger_write: the tested shuffle carries no barrier; younger_gap 1..15")
        r.setdefault("distances", "1-30,45" if r["store"] in SHFL_STORES else "1-15,18-75:3,90,105,150")
        r.setdefault("controls", True)
        r.setdefault("control_distances", "1,6,15,30,60,105")
    elif r.get("kind") == "ord":
        if r.get("nload"):
            r.setdefault("older", "LDS")
            r.setdefault("younger", "LDS")
            r.setdefault("place", "near")
            r.setdefault("barrier", "last")
            r.setdefault("distances", "1-4,8,15")
            if not (isinstance(r["nload"], int) and 2 <= r["nload"] <= 8) or (r["older"], r["younger"]) != ("LDS", "LDS") \
                    or r["place"] not in ("near", "far", "base2") or r["barrier"] not in ("last", "all", "none") or r.get("far") \
                    or r.get("older_barrier"):
                raise SystemExit(f"{r['id']}: an N-load request is older = younger = LDS, nload 2..8, place near | far | base2, barrier last | all | none")
        if r.get("older_barrier") not in (None, "same"):
            raise SystemExit(f"{r['id']}: older_barrier is \"same\" or absent")
        if r.get("far") not in (None, False, True, "off") or r.get("younger_guard") not in (None, "true", "false"):
            raise SystemExit(f"{r['id']}: far is true | \"off\" (the same base register, 0x200 away), younger_guard is \"true\" | \"false\"")
        if r.get("younger_guard") and r.get("younger") == "LDG":
            raise SystemExit(f"{r['id']}: a guarded younger load is a shared load")
            if max(parse_distances(r["distances"])) > 15:
                raise SystemExit(f"{r['id']}: the loads of an N-load request are at most 15 cycles apart (one stall, no fillers)")
        if r.get("older") == "SHFL" and r.get("far"):
            raise SystemExit(f"{r['id']}: an older shuffle has no `far` shape (R14 is its source)")
        if (r.get("older"), r.get("younger")) not in ORD_PAIRS:
            raise SystemExit(f"{r['id']}: older {r.get('older')!r} / younger {r.get('younger')!r} not in the catalogue (probe.py list)")
        r.setdefault("distances", "1-15,20,30")
        r.setdefault("controls", True)
        r.setdefault("control_distances", "1,4,15")
        r.setdefault("younger_stall", 2)
    elif r.get("kind") == "mma":
        r.setdefault("form", "QMMA.SF.E4M3.E2M1")
        r.setdefault("variant", "acc2")
        r.setdefault("via", "stall")
        if r["form"] not in MMA_FORMS or r["variant"] not in MMA_VARIANTS or r["via"] not in ("stall", "nop"):
            raise SystemExit(f"{r['id']}: mma form / variant / via not in the catalogue (probe.py list)")
        if r["variant"].startswith("sens_"):
            r["via"] = "stall"
            r["distances"] = "45"
        if r["variant"].startswith("hold_"):
            r["via"] = "stall"
            r.setdefault("distances", "1-12,15,20,30,45")
        r.setdefault("distances", "1-16,20,24,29,30,45,60" if r["via"] == "stall" else "2-16,20,24,29,30,45,60")
        if r["variant"].startswith("hold_"):
            r.setdefault("front", ["none"])
            for f in r["front"]:
                mma_front(f)
        else:
            r["front"] = ["none"]
    else:
        raise SystemExit(f"{r.get('id')}: kind must be raw, war, ord or mma")
    if r.get("yield") not in (None, "set") or (r.get("yield") and (r["kind"] not in ("raw", "mma") or r.get("via") != "stall")):
        raise SystemExit(f"{r['id']}: yield is \"set\" (the swept instruction of a raw / mma request carries the yield flag; via stall) or absent")
    r.setdefault("occupancy", ["w8", "w32"])
    r.setdefault("front", ["none"])
    r.setdefault("reps", 20)
    for o in r["occupancy"]:
        if o not in GEOM:
            raise SystemExit(f"{r['id']}: occupancy {o!r}: one of {', '.join(GEOM)}")
    r["distance_list"] = parse_distances(r["distances"])
    return r


def pair_text(r):
    if r["kind"] == "raw":
        return f"{r['producer']} -> {r['consumer']}"
    if r["kind"] == "mma" and r["variant"].startswith("sens_"):
        return f"{MMA_FORMS[r['form']]}: {MMA_VARIANTS[r['variant']]}"
    if r["kind"] == "mma" and r["variant"].startswith("hold_"):
        return f"{MMA_FORMS[r['form']]}: the operand hold ({MMA_VARIANTS[r['variant']]})"
    if r["kind"] == "mma":
        return (f"{MMA_FORMS[r['form']]} -> the same, issue spacing ({MMA_VARIANTS[r['variant']]}; "
                + ("first MMA + a NOP of one cycle + fillers" if r["via"] == "nop" else "the first MMA's stall + fillers") + ")")
    if r["kind"] == "ord" and r.get("nload"):
        where = {"near": "words of the thread's own line, one base register", "base2": "words of the thread's own line, every second load through another base register",
                 "far": "words >= 1 KB apart in the CTA's shared memory"}[r["place"]]
        return (f"{r['nload']} LDS of one thread in flight, ONE wait of the reader ({where}; "
                + {"last": "only the youngest load carries the write barrier", "all": "every load on the SAME write barrier",
                   "none": "POSITIVE CONTROL: no barrier and no wait - expect 0 % good"}[r["barrier"]] + ")")
    if r["kind"] == "ord" and r.get("older_barrier") == "same":
        return (f"{r['older']} and a younger {r['younger']} on ONE write barrier, one wait of the reader "
                f"(the younger load at stall {r.get('younger_stall', 2)} in front of the reader)")
    if r["kind"] == "ord":
        return (f"{r['older']} without a write barrier, read behind the wait on a younger {r['younger']}'s barrier "
                f"(the younger load at stall {r.get('younger_stall', 2)} in front of the reader"
                + ("; the younger load on the SAME base register, 0x200 bytes away" if r.get("far") == "off"
                   else "; the younger load reads ANOTHER line of shared memory, 1 KB away" if r.get("far") else "")
                + ({"true": "; the younger load under a guard that is TRUE", "false": "; the younger load under a guard that is FALSE (it does not happen)"}
                   .get(r.get("younger_guard"), "")) + ")")
    if r["store"] in SHFL_STORES:
        return (f"{r['store']} <- {r['overwriter']} (unwaited rewrite of the source register behind a warp shuffle"
                + ("; the shuffle carries a read barrier that the overwriter does not wait" if r.get("read_barrier") == "set"
                   else "; the shuffle carries no read barrier")
                + ("; the overwriter stands BEHIND the reader that waited the shuffle's write barrier - distance = waiter -> overwriter"
                   if r.get("behind") == "write_waiter" else
                   f"; the tested shuffle has NO write barrier either: a younger shuffle {r.get('younger_gap', 1)} cycle(s) behind it carries one, the reader "
                   "waits that and takes both results, the overwriter stands behind the reader - distance = waiter -> overwriter"
                   if r.get("behind") == "younger_write" else "")
                + ("; the overwriter adds (iteration index + 1) x a constant: one late iteration per thread is decoded to its index + 1"
                   if r["overwriter"] == "IADD3.it" else "") + ")")
    if r["store"] in WAW_STORES:
        return (f"{r['store']} <- {r['overwriter']} (write after write: the register is written again d cycles behind a pending scoreboarded "
                "write; the second writer does not wait the first's write barrier, the reader does"
                + ("; the second writer is a scoreboarded producer itself (its own barrier, waited by the reader)" if r["overwriter"] in ("LDS", "LDG", "SHFL") else "")
                + ("; the second writer's value carries (iteration index + 1) x a constant: one late first write per thread is decoded to its index + 1"
                   if r["overwriter"] == "IADD3.it" else "") + ")")
    return f"{r['store']} <- {r['overwriter']} (unwaited rewrite behind a bare store)"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def table_cell(dep_path, cell):
    """the price of the pair on cubit's table (the cell, or the default that applies), for the margin"""
    if not cell or not os.path.isfile(dep_path):
        return None
    t = json.load(open(dep_path))
    for c in t.get("cells", []):
        if (c["producer"], c["consumer"], c["role"]) == (cell["producer"], cell["consumer"], cell["role"]):
            return {"producer": c["producer"], "consumer": c["consumer"], "role": c["role"], "L": c["L"], "source": "cell",
                    "basis": c.get("basis", ""), "silicon": c.get("silicon", "")}
    role = cell["role"]
    d = t.get("defaults", {})
    L = d.get("guard") if role == "g" else d.get("uniform") if role.startswith("u") else d.get("data")
    return {"producer": cell["producer"], "consumer": cell["consumer"], "role": role, "L": L, "source": "default (no dense cell)"}


def cmd_gen(args):
    import numpy as np
    reqs = json.load(open(args.requests))
    if isinstance(reqs, dict):
        reqs = [reqs]
    reqs = [normalise(r) for r in reqs]
    if len({r["id"] for r in reqs}) != len(reqs):
        raise SystemExit("request ids must be unique in a batch")
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"refusing: {out} exists and is not empty (a batch is written once)")
    out.mkdir(parents=True, exist_ok=True)
    cubit = args.cubit
    prov = {"tool": TOOL, "tool_sha256": sha256(__file__), "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generated_on": socket.gethostname(), "cubit": cubit, "cubit_sha256": sha256(cubit),
            "cubit_version": subprocess.run([cubit, "--version"], capture_output=True, text=True).stdout.strip(),
            "isa_table": args.table, "isa_table_sha256": sha256(args.table),
            "dep_table": args.dep_table if os.path.isfile(args.dep_table) else None,
            "dep_table_sha256": sha256(args.dep_table) if os.path.isfile(args.dep_table) else None,
            "seed": SEED, "iterations": REPEAT}
    try:
        g = subprocess.run(["git", "-C", os.path.dirname(args.dep_table), "log", "-1", "--format=%h %s"], capture_output=True, text=True)
        prov["dep_table_commit"] = g.stdout.strip()[:120]
    except OSError:
        pass
    jobs = []
    total = 0
    for r in reqs:
        d = out / r["id"]
        (d / "k").mkdir(parents=True)
        kernels = []
        variants = ["bare"] + (["ctl", "rb"] if r["kind"] == "war" and r.get("controls") else [])
        if r["kind"] == "raw":
            variants = ["raw"]
        if r["kind"] == "ord":
            variants = ["bare"] + (["ctl"] if r.get("controls") else [])
        for occ in r["occupancy"]:
            ctas, threads = GEOM[occ]
            smem = smem_of(r, occ)
            rk = dict(r, _threads=threads)      # (the far shape of kind ord lays its second region out by the CTA's thread count)
            for front in r["front"]:
                for v in variants:
                    dl = r["distance_list"] if v in ("bare", "raw") else parse_distances(r["control_distances"])
                    for dist in dl:
                        name = f"{r['id']}_{v}_{occ}_{front_id(front)}_d{dist:04d}"
                        body = (body_raw(r, dist, front) if r["kind"] == "raw" else body_ord(rk, dist, front, v) if r["kind"] == "ord"
                                else body_mma(r, dist, front) if r["kind"] == "mma"
                                else body_war(r, dist, front, v))
                        (d / "k" / f"{name}.sass").write_text(kernel_text(name, rk, ctas, body, smem))
                        kernels.append({"name": name, "variant": v, "occupancy": occ, "front": front, "distance": dist,
                                        "ctas": ctas, "threads": threads, "smem": smem})
                        jobs.append((d, name))
        # (behind a write-barrier waiter a late shuffle is not "+ the constant": the reader has taken the result before)
        late_delta = LATE_CONST if (r["kind"] == "war" and r["overwriter"] in ("IADD3", "IADD3.it") and not r.get("behind")
                                    and r["store"] in ("STS.data", "STG.data", "LDS.dst", "LDG.dst", "LDC.dst", "S2R.dst") + SHFL_STORES) else None
        fam = {"request": r, "pair": pair_text(r) + (" [the swept instruction carries the YIELD flag]" if r.get("yield") else ""),
               "provenance": prov, "kernels": kernels, "modes": modes_of(r), "late_delta": late_delta,
               "table_cell": table_cell(args.dep_table, r.get("cell"))}
        (d / "family.json").write_text(json.dumps(fam, indent=1) + "\n")
        total += len(kernels)

    def build(job):
        d, name = job
        r = subprocess.run([cubit, "asm", "-t", args.table, str(d / "k" / f"{name}.sass"), "-o", str(d / "k" / f"{name}.cubin")],
                           capture_output=True, text=True)
        if r.returncode or not (d / "k" / f"{name}.cubin").is_file():
            return name, (r.stderr or r.stdout).strip().splitlines()[-1][:300]
        return None

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        failed = [f for f in ex.map(build, jobs) if f]
    print(f"{total} kernels of {len(reqs)} requests assembled into {out} in {time.time() - t0:.0f} s, {len(failed)} failed")
    for name, err in failed[:20]:
        print("  FAILED", name, err)
    if failed:
        return 1
    # the oracle: every thread's checksum per failure hypothesis, computed here once per request
    t0 = time.time()
    for r in reqs:
        cand = {}
        for mode in modes_of(r):
            try:
                cand[mode] = model(r, mode, gids=np.arange(1024 * max(max(GEOM[o][0] for o in r["occupancy"]), 188), dtype=np.int64))
            except Poison:
                pass      # the overwriter's result is not modelled (LDSM): no `late` hypothesis
        gids = np.array([0, 1, 255, 1023, 1024 + 31, 31 * 1024 + 1023, 187 * 1024 + 255, NGID - 1])
        for mode, v in cand.items():
            sc = model(r, mode, gids=gids, scalar=True)
            if [int(x) for x in v[gids]] != sc:
                raise SystemExit(f"{r['id']}: the vectorised model and the scalar interpreter disagree in mode {mode}")
        if any(np.array_equal(cand["good"], v) for m, v in cand.items() if m != "good") and r["kind"] != "mma":
            raise SystemExit(f"{r['id']}: a failure hypothesis gives the checksums of `good` - the probe could not see it")
        np.savez_compressed(out / r["id"] / "model.npz", **cand)
    print(f"host models of {len(reqs)} requests written in {time.time() - t0:.0f} s (each checked against the scalar interpreter on 8 threads)")
    (out / "batch.json").write_text(json.dumps({"requests": [r["id"] for r in reqs], "kernels": total, "provenance": prov}, indent=1) + "\n")
    return 0


# ------------------------------------------------------------------------------------------------ the GPU side
def smi(q):
    try:
        return subprocess.run(["nvidia-smi", f"--query-gpu={q}", "--format=csv,noheader", "-i", "0"], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:      # noqa: BLE001
        return f"? ({e})"


def series_floor(by):
    """by: {distance: {class: count}} -> (floor | None, last not-good distance | None, sorted distances)"""
    ds = sorted(by)
    bad = [d for d in ds if set(by[d]) != {"good"}]
    if not bad:
        return ds[0], None, ds
    if bad[-1] == ds[-1]:
        return None, bad[-1], ds
    return min(d for d in ds if d > bad[-1]), bad[-1], ds


def show(t):
    n = sum(v for v in t.values() if isinstance(v, int)) or 1
    return " ".join(f"{k} {100.0 * v / n:.2f}%" if isinstance(v, int) else f"{k} {v}"
                    for k, v in sorted(t.items(), key=lambda kv: -kv[1] if isinstance(kv[1], int) else 0))


class _FakeDriver:
    def __init__(self, owner):
        self.o = owner

    def cuModuleLoad(self, _mod, _path):
        return 0

    def cuModuleGetFunction(self, _fn, _mod, _name):
        return 0

    def cuModuleUnload(self, _mod):
        return 0


class FakeCuda:
    """PROBE_FAKE=1 - the runner's own logic on a CPU, no card and no nvidia-smi: every kernel "computes" the host model's
    `good` checksums, except the tested variants below distance 4, which give the first failure hypothesis."""

    def __init__(self):
        self.cu = _FakeDriver(self)
        self.now = None      # (kernel entry, candidates, order) of the kernel being launched

    def alloc(self, _nbytes):
        import ctypes
        return ctypes.c_uint64(0x10000)

    def free(self, _d):
        pass

    def memset32(self, *_a):
        pass

    def launch(self, *_a, **_k):
        pass

    def synchronize(self):
        pass

    def from_device(self, _d, nbytes, dtype=None):
        import numpy as np
        e, cand, order = self.now
        n = nbytes // 4
        own = (np.arange(n) % 1024) < e["threads"]
        m = order[1] if (e["variant"] in ("bare", "raw") and e["distance"] < 4 and len(order) > 1) else order[0]
        out = np.zeros(n, np.uint32)
        out[own] = cand[m][:n][own]
        return out

    def close(self):
        pass


def cmd_run(args):
    import ctypes
    import numpy as np
    sys.path.insert(0, str(HERE))
    fake_env = os.environ.get("PROBE_FAKE", "")
    fake = fake_env == "1" or (fake_env == "2" and (args.child or args.no_isolate))
    if not fake_env and not os.path.exists("/.dockerenv") and os.environ.get("PROBE_ALLOW_HOST") != "1":
        raise SystemExit("probe.py run: refusing - not inside a container: it would open a CUDA context on device 0 of this host "
                         "(PROBE_FAKE=1 | 2 = a CPU rehearsal; PROBE_ALLOW_HOST=1 only on a machine whose device 0 is yours to use)")
    if fake:
        def CK(rc, what=""):
            assert not rc, what
    else:
        from culaunch import Cuda, CK
    batch = pathlib.Path(args.batch)
    ids = json.load(open(batch / "batch.json"))["requests"]
    if args.only:
        ids = [i for i in ids if re.search(args.only, i)]
    if not fake and not args.child and not args.no_isolate:      # (PROBE_FAKE=2: the same path without a card - children run fake)
        return run_isolated(args, batch, ids)
    t0 = time.time()
    clock_csv = batch / "clock.csv"
    if args.child:
        mon = None
    elif fake:
        clock_csv.write_text("")
        mon = None
    else:
        mon = subprocess.Popen(["nvidia-smi", "--query-gpu=clocks.sm,power.draw,utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits",
                                "-i", "0", "-lms", "500"], stdout=open(clock_csv, "w"), stderr=subprocess.DEVNULL)
    q = (lambda _x: "FAKE (no card)") if fake else smi
    cond = {"gpu": q("name"), "driver": q("driver_version"), "clocks_max_sm": q("clocks.max.sm"), "power_limit": q("power.limit"),
            "host": socket.gethostname(), "image": os.environ.get("PROBE_IMAGE", ""), "block": os.environ.get("PROBE_BLOCK", ""),
            "runner_sha256": sha256(__file__), "in_container": os.path.exists("/.dockerenv"),
            "start_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    print(f"[probe] start {cond['start_utc']} {cond['gpu']} max {cond['clocks_max_sm']} limit {cond['power_limit']}; {len(ids)} requests", flush=True)
    cu = FakeCuda() if fake else Cuda(0)
    bufs = {}

    def buffer(ctas):
        if ctas not in bufs:
            nbytes = 1024 * ctas * 4 * 2
            keep = []
            for _ in range(8):      # a torn 64-bit address (new low word, old high word) must stay inside the buffer
                d = cu.alloc(nbytes)
                if (d.value & 0xFFFFFFFF) + nbytes < 2 ** 32:
                    break
                keep.append(d)
            else:
                raise RuntimeError("no output buffer inside one 4-GiB window")
            for k in keep:
                cu.free(k)
            bufs[ctas] = d
        return bufs[ctas]

    floors, skipped_total, dead, nkern = [], 0, 0, 0
    for rid in ids:
        fam = json.load(open(batch / rid / "family.json"))
        req = fam["request"]
        reps = args.reps or req.get("reps", 20)
        cand = dict(np.load(batch / rid / "model.npz"))
        order = [m for m in fam["modes"] if m in cand]
        late_inv = np.uint32(pow(int(fam["late_delta"]), -1, 2 ** 32)) if fam.get("late_delta") else None
        latek = {}
        results, errors, skipped = {}, [], 0
        eqfar, far_raw, ref_name, ltime = {}, {}, {}, {}
        tr = time.time()

        def run_kernel(e, nrep, far=None):
            """-> (classes per thread-launch, thread-launches equal to the reference kernel's output, the first output)"""
            ctas, threads = e["ctas"], e["threads"]
            n = 1024 * ctas
            own = (np.arange(n) % 1024) < threads
            d_out = buffer(ctas)
            tot, eq, first = {}, 0, None
            lt = []
            if fake:
                cu.now = (e, cand, order)
            mod = ctypes.c_void_p()
            try:
                CK(cu.cu.cuModuleLoad(ctypes.byref(mod), str(batch / rid / "k" / f"{e['name']}.cubin").encode()), "cuModuleLoad")
                fn = ctypes.c_void_p()
                CK(cu.cu.cuModuleGetFunction(ctypes.byref(fn), mod, e["name"].encode()), "cuModuleGetFunction")
                for _ in range(nrep):
                    cu.memset32(d_out, 0, 2 * n)
                    t1 = time.perf_counter()
                    cu.launch(fn, grid=(ctas, 1, 1), block=(threads, 1, 1), args=[d_out, ctypes.c_uint32(SEED)])
                    cu.synchronize()
                    lt.append(time.perf_counter() - t1)
                    o = cu.from_device(d_out, n * 4, dtype=np.uint32)
                    if first is None:
                        first = o
                    if far is not None:
                        eq += int(np.count_nonzero(own & (o == far)))
                    left = own.copy()
                    for m in order:
                        hit = left & (o == cand[m][:n])
                        c = int(np.count_nonzero(hit))
                        if c:
                            tot[m] = tot.get(m, 0) + c
                            left &= ~hit
                    c = int(np.count_nonzero(left))
                    if c:
                        tot["other"] = tot.get("other", 0) + c
                        if late_inv is not None:      # other = a mixture: how many of the 256 iterations were late, per thread
                            k = ((o[left] - cand["good"][:n][left]) * late_inv).astype(np.int64)
                            ok = (k >= 1) & (k <= 255)
                            st = latek.setdefault((e["variant"], e["occupancy"], e["front"], e["distance"]),
                                                  {"threads_decoded": 0, "threads_not_decoded": 0, "late_iterations": 0, "threads_with_one": 0, "max": 0})
                            st["threads_decoded"] += int(np.count_nonzero(ok))
                            st["threads_not_decoded"] += int(np.count_nonzero(~ok))
                            if ok.any():
                                st["late_iterations"] += int(k[ok].sum())
                                st["threads_with_one"] += int(np.count_nonzero(k[ok] == 1))
                                st["max"] = max(st["max"], int(k[ok].max()))
                    c = int(np.count_nonzero(~own & (o != 0)))
                    if c:
                        tot["STRAY_WORDS"] = tot.get("STRAY_WORDS", 0) + c
            finally:
                if mod:
                    cu.cu.cuModuleUnload(mod)
            if lt and nrep > 1:      # launch -> synchronize on the host's clock, the median over the launches (microseconds)
                ltime.setdefault((e["variant"], e["occupancy"], e["front"]), {})[e["distance"]] = round(1e6 * sorted(lt)[len(lt) // 2], 1)
            return tot, eq, first

        # the kernels of a request by condition (occupancy, front); the reference kernel of a condition runs first, once:
        # the control at its largest distance (war, ord) or the largest distance of the sweep (raw). Its output is NOT the
        # oracle - the host model is; it is kept so that every kernel also has its count of threads equal to it, and saved
        # when the model does not describe it (then the model can be repaired on the CPU and the counts still be read).
        groups = {}
        for e in fam["kernels"]:
            groups.setdefault((e["occupancy"], e["front"]), []).append(e)
        ref_v = "raw" if req["kind"] == "raw" else ("ctl" if any(e["variant"] == "ctl" for e in fam["kernels"]) else "bare")
        for gkey, ks in groups.items():
            refs = [e for e in ks if e["variant"] == ref_v]
            far = None
            if refs and not (time.time() - t0 > args.limit_s or dead >= 3):
                ref = max(refs, key=lambda e: e["distance"])
                try:
                    _t, _e, far = run_kernel(ref, 1)
                    far_raw[gkey], ref_name[gkey] = far, ref["name"]
                except Exception as ex:      # noqa: BLE001
                    errors.append(f"{ref['name']} (reference): {str(ex)[:120]}")
                    print(f"FAIL {ref['name']} (reference): {str(ex)[:160]}", flush=True)
                    dead += 1
            for e in ks:
                if time.time() - t0 > args.limit_s or dead >= 3:      # the time limit, or three kernels in a row failed to launch (a dead context)
                    skipped += 1
                    continue
                try:
                    tot, eq, _f = run_kernel(e, reps, far)
                    dead = 0
                except Exception as ex:      # noqa: BLE001
                    tot, eq = {"ERROR": str(ex)[:120]}, 0
                    errors.append(f"{e['name']}: {str(ex)[:120]}")
                    print(f"FAIL {e['name']}: {str(ex)[:160]}", flush=True)
                    dead += 1
                results.setdefault((e["variant"], e["occupancy"], e["front"]), {})[e["distance"]] = tot
                eqfar.setdefault((e["variant"], e["occupancy"], e["front"]), {})[e["distance"]] = eq
        skipped_total += skipped
        nkern += len(fam["kernels"]) - skipped
        # ---- per series
        series = []
        for (v, occ, front), by in sorted(results.items()):
            fl, last_bad, ds = series_floor(by)
            ctas, threads = GEOM[occ]
            tl = ctas * threads * reps
            # the oracle of a series: its own largest distance (raw) / its control kernels (war) must be 100 % good
            entry = {"variant": v, "occupancy": occ, "occupancy_text": OCC[occ], "front": front, "thread_launches_per_kernel": tl,
                     "iterations_per_thread": REPEAT, "distances": ds, "by_distance": {str(d): by[d] for d in ds},
                     "floor": fl, "last_not_good": last_bad,
                     "events_clean_at_floor": (tl * REPEAT) if fl is not None else 0,
                     "reference_kernel": ref_name.get((occ, front), ""),
                     "late_iterations_in_mixtures": {str(d): latek[(v, occ, front, d)] for d in ds if (v, occ, front, d) in latek},
                     "equal_to_reference_by_distance": {str(d): eqfar.get((v, occ, front), {}).get(d, 0) for d in ds},
                     "launch_us_median_by_distance": {str(d): ltime.get((v, occ, front), {}).get(d) for d in ds},
                     "smem_per_cta": next((e.get("smem", SMEM) for e in fam["kernels"] if e["occupancy"] == occ), SMEM)}
            series.append(entry)
        def find(v, occ, front):
            return next((s for s in series if (s["variant"], s["occupancy"], s["front"]) == (v, occ, front)), None)
        main_v = "raw" if req["kind"] == "raw" else "bare"
        per_cond, oracle_bad, bad_groups = {}, [], []
        for s in series:
            if s["variant"] != main_v:
                continue
            key = f"{s['occupancy']}/{s['front']}"
            if req["kind"] in ("war", "ord"):
                ctl = find("ctl", s["occupancy"], s["front"])
                if ctl is not None and ctl["last_not_good"] is not None:
                    oracle_bad.append(f"{key}: the control is not good ({show(ctl['by_distance'][str(ctl['last_not_good'])])})")
                    s["oracle"] = "FAILED"
                    bad_groups.append((s["occupancy"], s["front"]))
                    continue
                s["oracle"] = "ok (control: good in every thread)" if ctl is not None else "no control series"
                rbs = find("rb", s["occupancy"], s["front"])
                if rbs is not None:
                    s["read_barrier_control"] = "good at every distance" if rbs["last_not_good"] is None else f"NOT good to {rbs['last_not_good']}"
            else:
                far = s["by_distance"][str(s["distances"][-1])]
                if set(far) != {"good"}:
                    oracle_bad.append(f"{key}: the largest distance ({s['distances'][-1]}) is not good ({show(far)})")
                    s["oracle"] = "FAILED"
                    bad_groups.append((s["occupancy"], s["front"]))
                    continue
                s["oracle"] = f"ok (distance {s['distances'][-1]}: good in every thread)"
            per_cond[key] = s["floor"]
        vals = [v for v in per_cond.values()]
        binding = None if (not vals or any(v is None for v in vals)) else max(vals)
        incomplete = skipped > 0 or bool(errors)      # a series cut by the time limit or by a launch error has no floor
        if incomplete:
            oracle_bad.append(f"INCOMPLETE: {skipped} kernels not launched (time limit / dead context), {len(errors)} launch errors")
            binding = None
        cell = fam.get("table_cell")
        verdict, margin = "", None
        if req["kind"] == "raw" and cell and cell.get("L") is not None:
            if oracle_bad or not vals:
                verdict = "NO RESULT (oracle)"
            elif binding is None:
                verdict = f"TOO LOW: not clean up to the largest distance swept (table {cell['L']})"
            else:
                margin = cell["L"] - binding
                verdict = (f"holds: floor {binding} <= table {cell['L']} ({cell['source']}), margin {margin}" if margin >= 0
                           else f"TOO LOW: floor {binding} > table {cell['L']} ({cell['source']})")
        wanted = req.get("wanted")
        covers = None
        if wanted is not None and not oracle_bad and vals:
            covers = binding is not None and binding <= int(wanted)
            verdict += ("; " if verdict else "") + (f"wanted distance {wanted}: COVERED (floor {binding})" if covers
                                                    else f"wanted distance {wanted}: NOT covered (floor {'none' if binding is None else binding})")
        res = {"tool": TOOL, "request": req, "pair": fam["pair"], "provenance": fam["provenance"], "conditions": dict(cond, reps=reps),
               "table_cell": cell, "series": series, "floor": {"binding": binding, "per_condition": per_cond, "margin_vs_table": margin,
                                                              "wanted": wanted, "covers_wanted": covers,
                                                              "verdict": verdict, "oracle_failures": oracle_bad},
               "errors": errors, "skipped_kernels": skipped, "seconds": round(time.time() - tr, 1)}
        (batch / rid / "result.json").write_text(json.dumps(res, indent=1) + "\n")
        if bad_groups:      # what the reference kernels really produced, for the repair of the model on the CPU
            np.savez_compressed(batch / rid / "reference_raw.npz", **{f"{o}__{front_id(f)}": far_raw[(o, f)] for o, f in bad_groups if (o, f) in far_raw})
        floors.append({"id": rid, "pair": fam["pair"], "kind": req["kind"], "binding": binding, "per_condition": per_cond,
                       "verdict": verdict, "oracle_failures": oracle_bad, "errors": len(errors), "skipped": skipped})
        b = "none up to the largest distance swept" if binding is None and vals else binding
        print(f"RESULT {rid} [{fam['pair']}]: floor {b}; " + ", ".join(f"{k} {'NONE' if v is None else v}" for k, v in sorted(per_cond.items()))
              + (f"; {verdict}" if verdict else "") + (f"; ORACLE FAILED: {'; '.join(oracle_bad)[:300]}" if oracle_bad else "")
              + (f"; ERRORS {len(errors)}" if errors else "") + (f"; skipped {skipped}" if skipped else ""), flush=True)
        for s in series:
            if s["variant"] == main_v and s["last_not_good"] is not None:
                bd = s["by_distance"]
                pts = [d for d in s["distances"] if set(bd[str(d)]) != {"good"}]
                prof = " | ".join(f"d{d}: {show(bd[str(d)])}" for d in pts[:3] + pts[-2:])
                print(f"DETAIL {rid} {s['occupancy']}/{s['front']}: not good at {len(pts)} of {len(s['distances'])} distances, last {s['last_not_good']} || {prof}"[:700], flush=True)
    if args.child:      # one request in its own process: its row goes to the parent, which owns the clock and the summary
        for f in floors:
            (batch / f["id"] / "floor_row.json").write_text(json.dumps(dict(f, nkern=nkern, dead=dead)) + "\n")
        cu.close()
        return 0
    if mon is not None:
        mon.terminate()
    return finish(batch, ids, floors, cond, t0, nkern, skipped_total, dead, clock_csv, cu)


def run_isolated(args, batch, ids):
    """the default on a card: ONE PROCESS PER REQUEST. A kernel that traps kills its context - and with it only the rest of
    its own request; the next request starts in a fresh process with a fresh context."""
    t0 = time.time()
    clock_csv = batch / "clock.csv"
    fake2 = os.environ.get("PROBE_FAKE") == "2"
    if fake2:
        clock_csv.write_text("")
        mon = None
    else:
        mon = subprocess.Popen(["nvidia-smi", "--query-gpu=clocks.sm,power.draw,utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits",
                                "-i", "0", "-lms", "500"], stdout=open(clock_csv, "w"), stderr=subprocess.DEVNULL)
    q = (lambda _x: "FAKE (no card)") if fake2 else smi
    cond = {"gpu": q("name"), "driver": q("driver_version"), "clocks_max_sm": q("clocks.max.sm"), "power_limit": q("power.limit"),
            "host": socket.gethostname(), "image": os.environ.get("PROBE_IMAGE", ""), "block": os.environ.get("PROBE_BLOCK", ""),
            "runner_sha256": sha256(__file__), "one_process_per_request": True,
            "start_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    print(f"[probe] start {cond['start_utc']} {cond['gpu']} max {cond['clocks_max_sm']} limit {cond['power_limit']}; {len(ids)} requests, one process each", flush=True)
    floors, nkern, skipped_total = [], 0, 0
    for rid in ids:
        fam = json.load(open(batch / rid / "family.json"))
        row_p = batch / rid / "floor_row.json"
        if row_p.exists():
            row_p.unlink()
        left = args.limit_s - (time.time() - t0)
        rc = None
        if left > 5:
            cmd = [sys.executable, os.path.abspath(__file__), "run", str(batch), "--only", f"^{re.escape(rid)}$", "--child", "--limit-s", str(left)]
            rc = subprocess.run(cmd + (["--reps", str(args.reps)] if args.reps else []),
                                env=dict(os.environ, PROBE_FAKE="1") if fake2 else None).returncode
        if row_p.exists():
            row = json.load(open(row_p))
            nkern += row.pop("nkern", 0)
            row.pop("dead", None)
            skipped_total += row.get("skipped", 0)
            floors.append(row)
        else:
            why = "NOT RUN: the block's time limit" if rc is None else f"PROCESS FAILED (exit {rc}): no result"
            print(f"FAIL {rid}: {why}", flush=True)
            skipped_total += len(fam["kernels"])
            floors.append({"id": rid, "pair": fam["pair"], "kind": fam["request"]["kind"], "binding": None, "per_condition": {}, "verdict": "",
                           "oracle_failures": [why], "errors": 0 if rc is None else 1, "skipped": len(fam["kernels"])})
    if mon is not None:
        mon.terminate()
    return finish(batch, ids, floors, cond, t0, nkern, skipped_total, 0, clock_csv, None)


def finish(batch, ids, floors, cond, t0, nkern, skipped_total, dead, clock_csv, cu):
    # ---- conditions: the clock while busy
    busy = []
    pmax = 0.0
    for line in open(clock_csv):
        f = [x.strip() for x in line.split(",")]
        try:
            clk, pw, ut = float(f[0]), float(f[1]), float(f[2])
        except (ValueError, IndexError):
            continue
        pmax = max(pmax, pw)
        if ut >= 20:
            busy.append(clk)
    cond.update({"end_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "seconds": round(time.time() - t0, 1),
                 "clock_busy_mean_mhz": round(sum(busy) / len(busy)) if busy else None, "clock_busy_max_mhz": max(busy) if busy else None,
                 "power_max_w": pmax, "busy_samples": len(busy)})
    for rid in ids:
        p = batch / rid / "result.json"
        if not p.exists():
            continue
        r = json.load(open(p))
        r["conditions"].update(cond)
        p.write_text(json.dumps(r, indent=1) + "\n")
    (batch / "floors.json").write_text(json.dumps({"tool": TOOL, "conditions": cond, "floors": floors}, indent=1) + "\n")
    nor = sum(1 for f in floors if f["oracle_failures"])
    low = [f["id"] for f in floors if f["verdict"].startswith("TOO LOW")]
    print(f"SUMMARY probe batch {batch.name}: {len(ids)} requests, {nkern} kernels launched, {time.time() - t0:.0f} s of the card; oracle failures {nor}, "
          f"requests with launch errors {sum(1 for f in floors if f['errors'])}, kernels skipped {skipped_total}{' (ABORTED: three kernels in a row failed to launch)' if dead >= 3 else ''}; "
          f"clock while busy mean {cond['clock_busy_mean_mhz']} / max {cond['clock_busy_max_mhz']} MHz, power max {pmax:.0f} W", flush=True)
    def fl(f):
        return "NONE" if f["binding"] is None else str(f["binding"])
    raw = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "raw" and not f["oracle_failures"])
    war = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "war" and not f["oracle_failures"])
    print(f"SUMMARY raw floors (binding over the conditions): {raw}"[:290], flush=True)
    print(f"SUMMARY war floors (smallest distance from which an unwaited rewrite never reached the store; NONE = not up to the largest swept): {war}"[:290], flush=True)
    mmal = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "mma" and not f["oracle_failures"])
    if mmal:
        print(f"SUMMARY mma floors (two MMAs of one warp: smallest issue distance from which both results were always right): {mmal}"[:290], flush=True)
    ordl = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "ord" and not f["oracle_failures"])
    if ordl:
        print(f"SUMMARY ord floors (older load without a barrier -> younger load whose barrier the reader waits on; smallest distance from which the reader was always right): {ordl}"[:290], flush=True)
    print(f"SUMMARY table cells too low: {len(low)} {' '.join(low)}"[:290], flush=True)
    if cu is not None:
        cu.close()
    return 0


def cmd_floor(args):
    paths = []
    for p in args.paths:
        p = pathlib.Path(p)
        paths += sorted(p.glob("*/result.json")) if p.is_dir() else [p]
    for p in paths:
        r = json.load(open(p))
        req, fl, c = r["request"], r["floor"], r["conditions"]
        occ = ", ".join(sorted({s["occupancy"] for s in r["series"]}))
        fronts = ", ".join(sorted({s["front"] for s in r["series"]}))
        b = fl["binding"]
        n = "NONE up to %d" % max(req["distance_list"]) if b is None else str(b)
        per = ", ".join(f"{k} {'NONE' if v is None else v}" for k, v in sorted(fl["per_condition"].items()))
        cell = r.get("table_cell")
        tab = f"; table {cell['L']} ({cell['source']}): {fl['verdict']}" if cell and fl.get("verdict") else ""
        print(f"floor: {r['pair']} = {n} ({c.get('gpu', '?')}, clock {c.get('clock_busy_mean_mhz')} MHz busy, occupancy {occ}; front {fronts}; "
              f"{c.get('reps')} launches x 256 iterations per thread; per condition: {per}{tab}"
              + (f"; ORACLE FAILED {fl['oracle_failures'][:2]}" if fl.get("oracle_failures") else "") + f") [{p}]")
    return 0

# ------------------------------------------------------------------------------------------------ requests written by other tools
# The offline gate of the schedule search (emu120.gate) writes, per candidate, `kernels[i].probes`: one object per pair that nobody measured
#   {kind: "producer -> consumer (read after write)" | "reader -> overwriter (write after read)" | ..., first: {form, text, is},
#    second: {form, text, is}, operand_role, distance_wanted, distance_in_seed, sweep: {distance: [lo, hi], occupancy_warps_per_sm}, sites, kernel}
# `probe.py adapt` turns such files into a request file of this tool (one request per distinct pair, `wanted` = the smallest
# distance any site asks for) and lists what the catalogue cannot build yet - the work list of the catalogue.
ADAPT_PROD = {"IADD3": "IADD3", "IMAD": "IMAD", "LOP3.LUT": "LOP3", "MOV": "MOV", "SHF.R.U32.HI": "SHF", "SHF.L.U32": "SHF",
              "FADD": "FADD", "FADD.FTZ": "FADD", "FMUL": "FMUL", "FMUL.FTZ": "FMUL", "SEL": "SEL",
              "F2FP.SATFINITE.BF16.F32.PACK_AB": "F2FP.SAT", "PRMT": "PRMT", "IMAD.SHL.U32": "IMAD.SHL", "IADD.64": "IADD.64",
              "IMAD.WIDE.U32": "IMAD.WIDE", "IMAD.WIDE": "IMAD.WIDE"}
ADAPT_CONS = {("STS", "r1"): "STS.data", ("STS", "a0"): "STS.addr", ("STS.128", "r1"): "STS128.d0", ("STS.128", "r1h"): "STS128.d3",
              ("STG.E", "r1"): "STG.data", ("STG", "r1"): "STG.data", ("LDS", "a1"): "LDS.addr", ("LDS", "a0"): "LDS.addr",
              ("IADD3", "r1"): "IADD3.r1", ("IADD3", "r2"): "IADD3.r2", ("IMAD", "r1"): "IMAD.r1", ("IMAD", "r3"): "IMAD.r3",
              ("LOP3.LUT", "r1"): "LOP3.r1", ("MOV", "r1"): "MOV.r1", ("SHF.L.U32", "r1"): "SHF.r1", ("SEL", "r1"): "SEL.r1",
              ("PRMT", "r1"): "PRMT.r1", ("I2FP.F32.S32", "r1"): "I2FP.r1", ("IMAD.SHL.U32", "r1"): "IMAD.SHL.r1",
              ("IADD.64", "r1"): "IADD.64.r1", ("IADD.64", "r1h"): "IADD.64.r1h", ("LEA", "r1"): "LEA.r1"}
ADAPT_STORE = {("STS", "r1"): "STS.data", ("STS", "a0"): "STS.addr", ("STS.128", "r1"): "STS128.data", ("STS.128", "r1h"): "STS128.data",
               ("STG.E", "r1"): "STG.data", ("STG.E", "a0"): "STG.addr", ("STG.E", "a1"): "STG.addr"}
ADAPT_OVER = {"LOP3.LUT": "LOP3", "IADD3": "IADD3", "MOV": "MOV", "LDS": "LDS", "LDS.128": "LDS128", "LDSM.16.M88.4": "LDSM", "LDG.E": "LDG"}


def cmd_adapt(args):
    files = []
    for p in args.paths:
        p = pathlib.Path(p)
        files += sorted(p.rglob("*.json")) if p.is_dir() else [p]
    got, missing, nprobe = {}, {}, 0
    for f in files:
        try:
            doc = json.load(open(f))
        except (OSError, ValueError):
            continue
        for k in (doc.get("kernels") or []) if isinstance(doc, dict) else []:
            for pr in k.get("probes") or []:
                nprobe += 1
                kind = str(pr.get("kind", ""))
                a, b = pr.get("first") or {}, pr.get("second") or {}
                fa, fb = str(a.get("form", "")), str(b.get("form", ""))
                oa, ob = (fa.split() or [""])[0], (fb.split() or [""])[0]
                role = str(pr.get("operand_role", ""))
                sites = len(pr.get("sites") or [None])
                want = pr.get("distance_wanted")
                req = None
                if kind.startswith("producer -> consumer"):
                    cons = ADAPT_CONS.get((ob, role))
                    prod = ADAPT_PROD.get(oa)
                    if prod == "IADD3" and "-R" in str(a.get("text", "")):
                        prod = "IADD3.neg"
                    if cons and prod and prod in (ADDR_PRODUCERS if RAW_CONSUMERS[cons][0] == "addr" else DATA_PRODUCERS) \
                            and not (cons == "IADD.64.r1h" and prod not in PAIR_PRODUCERS):
                        mem = RAW_CONSUMERS[cons][2] in ("STS", "STG", "LDS")
                        req = {"kind": "raw", "producer": prod, "consumer": cons,
                               "front": ["none", "stgx15@4" if RAW_CONSUMERS[cons][2] == "STG" else "sts128x15@4"] if mem else ["none"],
                               "cell": {"producer": oa.replace(".LUT", ""), "consumer": RAW_CONSUMERS[cons][2], "role": role}}
                elif kind.startswith("reader -> overwriter"):
                    st, ov = ADAPT_STORE.get((oa, role)), ADAPT_OVER.get(ob)
                    if st and ov and ov in WAR_STORES[st][0]:
                        req = {"kind": "war", "store": st, "overwriter": ov, "front": ["none", "sts128x15@4"], "controls": True}
                if req is None:
                    m = missing.setdefault((kind, fa, fb, role), {"kind": kind, "first": fa, "second": fb, "operand_role": role, "sites": 0,
                                                                  "distance_wanted": want, "example": [a.get("text", ""), b.get("text", "")], "files": []})
                    m["sites"] += sites
                    if want is not None and (m["distance_wanted"] is None or want < m["distance_wanted"]):
                        m["distance_wanted"] = want
                    if str(f) not in m["files"]:
                        m["files"].append(str(f))
                    continue
                key = (req["kind"], req.get("producer") or req.get("store"), req.get("consumer") or req.get("overwriter"))
                hi = int((pr.get("sweep") or {}).get("distance", [1, 30])[1])
                r = got.setdefault(key, dict(req, occupancy=["w1", "w8", "w32"], sites=0, wanted=want, hi=hi, forms=[fa, fb]))
                r["sites"] += sites
                r["hi"] = max(r["hi"], hi)
                if want is not None and (r["wanted"] is None or want < r["wanted"]):
                    r["wanted"] = want
    out = []
    for (kind, x, y), r in sorted(got.items()):
        hi = min(max(r.pop("hi"), 30), 150)
        r["distances"] = "1-15" + (f",18-{hi}:3" if hi > 18 else "") + ("" if kind == "raw" else ",105,150")
        r["id"] = re.sub(r"[^a-z0-9]+", "_", f"g_{x}_{y}".lower())[:40].strip("_")
        r["note"] = f"from {nprobe} gate requests: {r.pop('sites')} site(s), forms {r.pop('forms')}"
        if r["wanted"] is None:
            r.pop("wanted")
        out.append(normalise(r) and r)
    outp = pathlib.Path(args.out)
    outp.write_text(json.dumps(out, indent=1) + "\n")
    miss = sorted(missing.values(), key=lambda m: -m["sites"])
    pathlib.Path(str(outp) + ".not_in_catalogue.json").write_text(json.dumps(miss, indent=1) + "\n")
    print(f"{nprobe} gate requests in {len(files)} files -> {len(out)} requests of this tool in {outp}; {len(miss)} distinct pairs ({sum(m['sites'] for m in miss)} sites) "
          f"are not in the catalogue: {outp}.not_in_catalogue.json")
    for m in miss[:12]:
        print(f"  not in the catalogue x{m['sites']}: {m['kind'][:24]} | {m['first']} -> {m['second']} ({m['operand_role']})")
    return 0


def cmd_list(_args):
    print("kind raw - producer -> consumer:")
    print("  data producers:", ", ".join(DATA_PRODUCERS), "| address producers:", ", ".join(ADDR_PRODUCERS), "| uniform producers:", ", ".join(UNIFORM_PRODUCERS))
    for k, v in RAW_CONSUMERS.items():
        print(f"  consumer {k:10s} {v[4]} (table class {v[2]}, role {v[3]}; producer kind: {v[0]})")
    print("kind war - a register of a BARE store rewritten behind it:")
    for k, v in WAR_STORES.items():
        print(f"  store {k:12s} overwriters {', '.join(v[0])}: {v[2]}")
    print("  a shuffle's source register: \"read_barrier\": \"set\" = the shuffle carries a read barrier in the bare variant too (the overwriter does not wait it)")
    print("  a shuffle's source register: overwriter IADD3.it adds (iteration index + 1) x the constant (which iteration is the late one); \"behind\": \"write_waiter\" = the overwriter behind the reader that waited the shuffle's WRITE barrier (distance = waiter -> overwriter); \"behind\": \"younger_write\" (+ \"younger_gap\": 1..15) = a barrier-less shuffle read under a YOUNGER shuffle's write barrier")
    print("  write after write (version 18): stores LDS.dst / LDG.dst / LDC.dst / S2R.dst / SHFL.dst / LDS128.dst = the FIRST writer of a register on write barrier 1, the overwriter = the second writer d cycles behind it (IADD3 / IADD3.it: the first writer's value - the constant, so late first writes are counted / decoded; LDS / LDG / SHFL: a scoreboarded second writer); ctl = the second writer waits barrier 1, rb = no first writer")
    print("  mixed producer classes (version 18): ord pairs with a younger S2R / S2UR / LDC64 and an older LDC / SHFL (\"older_barrier\": \"same\" = both on ONE write barrier); \"yield\": \"set\" on a raw / mma request = its swept instruction carries the yield flag")
    print("kind mma - two tensor instructions of one warp, d issue cycles apart (form; variant; via stall | nop):")
    print("  forms: " + ", ".join(f"{k} = {v}" for k, v in MMA_FORMS.items()))
    for k, v in MMA_VARIANTS.items():
        print(f"  variant {k:7s} {v}")
    print("kind ord - an OLDER load without a write barrier, read behind the wait on a YOUNGER load's barrier (older, younger):")
    print("  " + ", ".join(f"({a}, {b})" for a, b in ORD_PAIRS) + "; distance = older -> younger; `younger_stall` (default 2) = younger -> reader")
    print("  N loads in flight and ONE wait: \"nload\": 2..8, \"place\": near | base2 | far (>= 1 KB apart), \"barrier\": last (the older loads bare) | all (one shared barrier) | none (positive control: no wait); distance = load -> load, 1..15")
    print("  two loads on ONE write barrier: \"older_barrier\": \"same\" (does the scoreboard count its producers?)")
    print("occupancy:", "; ".join(f"{k} = {v}" for k, v in OCC.items()))
    print("front: none | sts128xK@S | stsxK@S | stgxK@S  (K stores of a constant at stall S in front of the tested instruction)")
    return 0


def cmd_selftest(_args):
    import numpy as np
    gids = np.array([0, 5, 1023, 1024, 40000, NGID - 1])
    n = 0
    for cons in RAW_CONSUMERS:
        what = RAW_CONSUMERS[cons][0]
        for prod in (ADDR_PRODUCERS if what == "addr" else UNIFORM_PRODUCERS if what == "udata" else DATA_PRODUCERS):
            if cons in ("IADD.64.r1h", "SHF.L.U64.HI.r1") and prod not in PAIR_PRODUCERS:
                continue
            if prod == "CS2R" and RAW_CONSUMERS[cons][1] % 2:
                continue
            if cons.startswith("IMAD.WIDE.r3") and prod in PAIR_PRODUCERS:
                continue
            r = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons})
            for mode in modes_of(r):
                v = model(r, mode, gids=gids)
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (prod, cons, mode)
                n += 1
            assert not np.array_equal(model(r, "good", gids=gids), model(r, "stale", gids=gids)), (prod, cons)
    for st, (overs, _c, _t) in WAR_STORES.items():
        for ov in overs:
            r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov})
            got = {}
            for mode in modes_of(r):
                try:
                    v = model(r, mode, gids=gids)
                except Poison:
                    continue
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (st, ov, mode)
                got[mode] = v
                n += 1
            # (behind a load overwriter `overtake` is `late`: a store served after the read-back was served after the overwriter too)
            assert all(not np.array_equal(got["good"], v) for m, v in got.items() if m != "good"), (st, ov)
    for var, form in [(v, f) for f in MMA_FORMS for v in MMA_VARIANTS]:
        r = normalise({"id": "selftest", "kind": "mma", "variant": var, "form": form})
        got = {m: model(r, m, gids=gids) for m in modes_of(r)}
        for m, v in got.items():
            assert [int(x) for x in v] == model(r, m, gids=gids, scalar=True), (var, m)
            n += 1
        assert var == "gfalse" or all(not np.array_equal(got["good"], v) for m, v in got.items() if m != "good"), var
        if var.startswith("hold_"):      # the tensor traffic in front writes another accumulator: the checksum may not move
            for fr in ("mmax1@7", "mmax8@1"):
                rf = dict(r, _model_front=fr)
                assert np.array_equal(model(rf, "good", gids=gids), got["good"]), (var, fr)
                assert [int(x) for x in got["good"]] == model(rf, "good", gids=gids, scalar=True), (var, fr)
                n += 1
    for older, younger, far in [(o, y, False) for o, y in ORD_PAIRS] + [("LDS", "LDS", True), ("LDS", "LDS128", True), ("LDS", "LDSM", True)]:
        r = normalise({"id": "selftest", "kind": "ord", "older": older, "younger": younger, "far": far})
        g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True)
        assert not np.array_equal(g, st), (older, younger)
        n += 2
    for older, younger, extra in [("LDS", "LDS64", {"far": "off"}), ("LDS64", "LDS64", {"far": "off"}), ("LDS", "LDS128", {"younger_guard": "true", "far": True}),
                                  ("LDS", "LDS128", {"younger_guard": "false", "far": True}), ("LDSU16", "LDS", {"far": True}), ("LDS64", "LDS", {})]:
        r = normalise(dict({"id": "selftest", "kind": "ord", "older": older, "younger": younger}, **extra))
        g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True)
        assert not np.array_equal(g, st), (older, younger, extra)
        n += 2
    assert misaligned("    [B------:R-:W-:-:S15] LDS.64 R29, [R9+0x20] ;") and not misaligned("    [B------:R-:W-:-:S15] LDS.64 R28, [R9+0x20] ;")
    for st in SHFL_STORES:      # a shuffle moves data between lanes: lanes 0 / 1 (and 2 / 3) of a warp must not end alike
        r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": "IADD3", "read_barrier": "set"})
        w = np.arange(64, dtype=np.int64)
        g, lt = model(r, "good", gids=w), model(r, "late", gids=w)
        assert not np.array_equal(g, lt), st
        if st == "SHFL.IDX.src":      # every lane of a warp ends with lane 1's sum; two warps, two sums
            assert len(set(int(x) for x in g[:32])) == 1 and len(set(int(x) for x in g)) == 2, st
        else:                          # lanes 0 and 1 swap their sums
            assert len(set(int(x) for x in g)) == 64 and int(g[0]) != int(g[1]), st
        assert [int(x) for x in g] == model(r, "good", gids=w, scalar=True) and [int(x) for x in lt] == model(r, "late", gids=w, scalar=True), st
        # every late iteration adds the overwriter's constant once, in every thread
        assert all(int(x) == (REPEAT * LATE_CONST) & 0xFFFFFFFF for x in (lt - g)), st
        n += 2
        # IADD3.it: late iteration i adds (i + 1) constants; the good checksum is the plain one's
        ri = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": "IADD3.it"})
        gi, li = model(ri, "good", gids=w), model(ri, "late", gids=w)
        assert np.array_equal(gi, g) and all(int(x) == (LATE_CONST * REPEAT * (REPEAT + 1) // 2) & 0xFFFFFFFF for x in (li - gi)), st
        # behind a write-barrier waiter: the same good checksum (the order of two instructions that do not depend on each
        # other changed), and a late shuffle is another checksum
        for ov in ("LOP3", "IADD3"):
            rb_ = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov, "behind": "write_waiter"})
            gb, lb = model(rb_, "good", gids=w), model(rb_, "late", gids=w)
            assert np.array_equal(gb, g) and not np.array_equal(gb, lb), (st, ov)
            assert [int(x) for x in gb] == model(rb_, "good", gids=w, scalar=True) and [int(x) for x in lb] == model(rb_, "late", gids=w, scalar=True), (st, ov)
            n += 2
            # a barrier-less shuffle under a younger shuffle's barrier: the checksum takes BOTH results (another one than
            # the plain shape's), a late older shuffle is another checksum again, and the gap does not enter the model
            ry = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov, "behind": "younger_write", "younger_gap": 4})
            gy, ly = model(ry, "good", gids=w), model(ry, "late", gids=w)
            assert not np.array_equal(gy, g) and not np.array_equal(gy, ly), (st, ov)
            assert [int(x) for x in gy] == model(ry, "good", gids=w, scalar=True) and [int(x) for x in ly] == model(ry, "late", gids=w, scalar=True), (st, ov)
            n += 2
    for st in WAW_STORES:      # version 18 - write after write: `late` = the FIRST writer's value in every iteration
        for ov in WAR_STORES[st][0]:
            r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov})
            w = np.arange(64, dtype=np.int64)
            g, lt = model(r, "good", gids=w), model(r, "late", gids=w)
            assert modes_of(r) == ["good", "late"] and not np.array_equal(g, lt), (st, ov)
            assert [int(x) for x in g] == model(r, "good", gids=w, scalar=True) and [int(x) for x in lt] == model(r, "late", gids=w, scalar=True), (st, ov)
            if ov == "IADD3" and st != "SHFL.dst":       # every late first write adds the constant once
                assert all(int(x) == (REPEAT * LATE_CONST) & 0xFFFFFFFF for x in (lt - g)), (st, ov)
            if ov == "IADD3.it":                         # late first write of iteration i adds (i + 1) constants
                assert all(int(x) == (LATE_CONST * REPEAT * (REPEAT + 1) // 2) & 0xFFFFFFFF for x in (lt - g)), (st, ov)
            # the controls: ctl differs from bare in ONE control code (the second writer waits barrier 1), rb in ONE
            # instruction (a filler with the same stall in the first writer's place)
            bare, ctl_, rb_ = (body_war(r, 7, "none", v) for v in ("bare", "ctl", "rb"))
            dc = [(a, c) for a, c in zip(bare, ctl_) if a.line() != c.line()]
            dr = [(a, c) for a, c in zip(bare, rb_) if a.line() != c.line()]
            assert len(bare) == len(ctl_) == len(rb_) and len(dc) == 1 and len(dr) == 1, (st, ov)
            assert dc[0][0].tag == "O" and dc[0][0].text == dc[0][1].text and dc[0][0].ctl[1:8] == "B------" and dc[0][1].ctl[1:8] == "B-1----", (st, ov)
            assert dr[0][0].tag == "S" and dr[0][1].sem == ("nop",) and dr[0][0].ctl[-4:] == dr[0][1].ctl[-4:] == "S07]", (st, ov)
            n += 2
    for prod, cons in (("IADD3", "STS.data"), ("IMAD", "IADD3.r1")):      # version 18 - the yield flag sits on the swept instruction only
        ry = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons, "yield": "set"})
        rn = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons})
        by, bn = body_raw(ry, 3, "none"), body_raw(rn, 3, "none")
        dy = [(a.line(), c.line()) for a, c in zip(by, bn) if a.line() != c.line()]
        assert len(by) == len(bn) and len(dy) == 1 and ":Y:S03]" in dy[0][0] and ":-:S03]" in dy[0][1], (prod, cons, dy)
        assert np.array_equal(model(ry, "good", gids=gids), model(rn, "good", gids=gids))
        n += 1
    for var in ("acc2", "hold_a_mov", "hold_b_mov"):
        ry = normalise({"id": "selftest", "kind": "mma", "variant": var, "yield": "set"})
        rn = normalise({"id": "selftest", "kind": "mma", "variant": var})
        by, bn = body_mma(ry, 2, "none"), body_mma(rn, 2, "none")
        dy = [(a.line(), c.line()) for a, c in zip(by, bn) if a.line() != c.line()]
        assert len(by) == len(bn) and len(dy) == 1 and ":Y:S02]" in dy[0][0] and "QMMA" in dy[0][0], (var, dy)
        n += 1
    for older, younger in ORD_PAIRS:
        r = normalise({"id": "selftest", "kind": "ord", "older": older, "younger": younger, "older_barrier": "same"})
        g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and not np.array_equal(g, st), (older, younger, "same")
        n += 1
    for nl in (2, 3, 4, 5, 8):
        for place in ("near", "base2", "far"):
            for bar in ("last", "all", "none"):
                r = normalise({"id": "selftest", "kind": "ord", "nload": nl, "place": place, "barrier": bar})
                g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
                assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True)
                assert not np.array_equal(g, st), (nl, place, bar)
                # one stale register alone must move the checksum too: the weights of the fold are distinct and odd
                n += 2
    assert smem_of({"id": "x", "kind": "ord", "nload": 8, "place": "far"}, "c2w9s") == 49152 and smem_of({"id": "x", "kind": "ord", "nload": 8, "place": "far"}, "w32") == 98304
    assert smem_of({"id": "x", "kind": "ord", "nload": 8, "place": "far"}, "c4w8") == 24576
    assert far_layout(288) == (18432, 1280) and far_layout(1024) == (65536, 4096) and far_layout(32) == (2048, 1024)
    print(f"selftest: {n} (pair, hypothesis) models equal the scalar interpreter on {len(gids)} threads; `good` differs from every failure hypothesis")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("requests")
    g.add_argument("--out", required=True)
    g.add_argument("--cubit", default=DEF_CUBIT)
    g.add_argument("--table", default=DEF_TABLE)
    g.add_argument("--dep-table", default=DEF_DEP)
    g.add_argument("--jobs", type=int, default=12)
    r = sub.add_parser("run")
    r.add_argument("batch")
    r.add_argument("--reps", type=int, default=0)
    r.add_argument("--limit-s", type=float, default=600)
    r.add_argument("--only", default="")
    r.add_argument("--child", action="store_true", help="(internal) one request in its own process")
    r.add_argument("--no-isolate", action="store_true", help="all requests in ONE process (a trapped kernel then ends the batch)")
    f = sub.add_parser("floor")
    f.add_argument("paths", nargs="+")
    ad = sub.add_parser("adapt")
    ad.add_argument("paths", nargs="+")
    ad.add_argument("--out", required=True)
    sub.add_parser("list")
    sub.add_parser("selftest")
    a = ap.parse_args()
    return {"gen": cmd_gen, "run": cmd_run, "floor": cmd_floor, "list": cmd_list, "selftest": cmd_selftest, "adapt": cmd_adapt}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
