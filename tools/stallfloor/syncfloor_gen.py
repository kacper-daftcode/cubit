#!/usr/bin/env python3
"""Synchronisation-word floor probes, CPU side (harness v7; pattern: pairfloor_gen.py).

The oracle of every probe is ptxas's own schedule: `sync_probes.cu` is compiled by nvcc (sm_120a), its frozen listing
(`cubit disassemble --frozen`) is the reference; a variant is the same kernel with ONE control field of the word under
test changed (the stall, the write / read barrier, the wait of the word's consumer) -- or one instruction replaced by a
NOP for the positive controls -- re-assembled over the nvcc cubin with `cubit asm -T` (same instruction count, so the
.nv.info records stay valid). The reference kernels are re-assembled the same way and must reproduce the nvcc cubin
byte for byte.

    python3 syncfloor_gen.py --cubit target/release/cubit --table tables/sm120.json.gz \
        --cubin sync_probes.cubin --out kernels_sync/            # writes <variant>.cubin + index.json
    python3 syncfloor_gen.py ... --cubin coll_probe.cubin --out kernels_coll/     # the collective-region probe
"""
import argparse, json, os, re, subprocess, sys

CC = re.compile(r"^(\s*(?:[A-Za-z_][A-Za-z_0-9\.]*:\s*)?)\[B([0-5\-]{6}):R([0-5\-]):W([0-5\-]):([Y\-]):S(\d\d)\]\s*(.*)$")


def edit(lines, pattern, occ, wait=None, rb=None, wb=None, y=None, s=None, text=None, before=False):
    """Change the control code (and optionally the text) of the occ-th instruction of `lines` whose text matches
    (`before`: of the instruction in front of it)."""
    k = -1
    for i, l in enumerate(lines):
        m = CC.match(l)
        if not m or not re.search(pattern, m.group(7)):
            continue
        k += 1
        if k != occ:
            continue
        if before:
            i -= 1
            while not CC.match(lines[i]):
                i -= 1
            m = CC.match(lines[i])
        pre, b, r, w, yy, ss, txt = m.groups()
        b = b if wait is None else wait
        r = r if rb is None else rb
        w = w if wb is None else wb
        yy = yy if y is None else y
        ss = ss if s is None else f"{int(s):02d}"
        if int(ss) >= 12 or int(ss) == 0:
            yy = "-"                       # the OPEX law: yield with S00 / S12..S15 is reserved on sm_120
        txt = txt if text is None else text
        lines[i] = f"{pre}[B{b}:R{r}:W{w}:{yy}:S{ss}] {txt}\n"
        return
    raise SystemExit(f"edit: no occurrence {occ} of /{pattern}/")


def variants():
    """(probe kernel, group, variant name, x value of the sweep or None, [edits])"""
    V = []
    TW = r"^SYNCS\.PHASECHK\.TRANS64\.TRYWAIT"
    # ---- mbarrier: the try_wait predicate and its first consumer (spin form and suspend-hint form)
    for kern, tag in (("p_mbar", "mbar"), ("p_mbars", "mbars")):
        for s in (1, 2, 3):
            V.append((kern, f"{tag}_bar", f"{tag}_bar_S{s:02d}", s, [dict(pattern=TW, occ=0, s=s)]))
        V.append((kern, f"{tag}_bar_noyield", f"{tag}_bar_noY_S01", 1, [dict(pattern=TW, occ=0, s=1, y="-")]))
        for s in (1, 2, 3, 4, 5, 6, 8, 10, 12, 15):
            V.append((kern, f"{tag}_nobar", f"{tag}_nobar_S{s:02d}", s,
                      [dict(pattern=TW, occ=0, s=s, wb="-"), dict(pattern=r"^@!P0 BRA", occ=0, wait="------")]))
    # ---- named barriers: the stall after BAR.ARV; the consumer's BAR.SYNC -> LDS distance as the control (BUG-479: 6)
    for s in (1, 2, 3, 4, 5, 6, 8):
        V.append(("p_named", "named_arv", f"named_arv_S{s:02d}", s, [dict(pattern=r"^BAR\.ARV", occ=0, s=s)]))
    for s in (1, 2, 3, 4, 5, 6):
        V.append(("p_named", "named_sync_lds", f"named_sync_S{s:02d}", s, [dict(pattern=r"^BAR\.SYNC\.DEFER_BLOCKING 0x1", occ=0, s=s)]))
    # ---- bulk copies
    for s in (1, 2, 4, 8, 12):
        V.append(("p_bulk", "bulk_load_stall", f"bulk_ld_S{s:02d}", s, [dict(pattern=r"^UBLKCP\.S\.G", occ=0, s=s)]))
    V.append(("p_bulk", "bulk_load_norb", "bulk_ld_noR", None,
              [dict(pattern=r"^UBLKCP\.S\.G", occ=0, rb="-"), dict(pattern=r"^@P0 BRA\.U\.ANY", occ=0, wait="------")]))
    V.append(("p_bulk", "bulk_arrive_norb", "bulk_arrive_noR", None,
              [dict(pattern=r"^SYNCS\.ARRIVE\.TRANS64 ", occ=0, rb="-"), dict(pattern=r"^BRA\.U !UP0", occ=0, wait="------")]))
    V.append(("p_bulk", "bulk_fence_nowb", "bulk_fence_noW", None,
              [dict(pattern=r"^FENCE\.VIEW\.ASYNC\.S", occ=0, wb="-"), dict(pattern=r"^UBLKCP\.G\.S", occ=0, wait="------")]))
    for s in (1, 3):
        V.append(("p_bulk", "bulk_membar_cta", f"bulk_membar_S{s:02d}", s, [dict(pattern=r"^MEMBAR\.ALL\.CTA", occ=0, s=s)]))
    V.append(("p_bulk", "bulk_store_norb", "bulk_st_noR", None,
              [dict(pattern=r"^UBLKCP\.G\.S", occ=0, rb="-"), dict(pattern=r"^BSYNC\.RECONVERGENT B0", occ=0, wait="------")]))
    V.append(("p_bulk", "bulk_flush_norb", "bulk_flush_noR", None, [dict(pattern=r"^UTMACMDFLUSH", occ=0, rb="-")]))
    for s in (1, 2, 4):
        V.append(("p_bulk", "bulk_depbar", f"bulk_depbar_S{s:02d}", s, [dict(pattern=r"^DEPBAR\.LE", occ=0, s=s)]))
    # ---- acquire / release (occurrence 0 = the writer CTA's poll / release, 1 = the reader's)
    V.append(("p_acqrel", "acq_ivall_early", "acq_ivall_early", None,
              [dict(pattern=r"^CCTL\.IVALL", occ=1, wait="------"), dict(pattern=r"^MOV R12, UR4", occ=0, wait="--2---")]))
    V.append(("p_acqrel", "acq_no_ivall (control)", "acq_ivall_nop", None, [dict(pattern=r"^CCTL\.IVALL", occ=1, text="NOP ;")]))
    for s in (1, 3):
        V.append(("p_acqrel", "rel_membar", f"rel_membar_S{s:02d}", s,
                  [dict(pattern=r"^MEMBAR\.ALL\.GPU", occ=0, s=s), dict(pattern=r"^@!P0 MEMBAR\.ALL\.GPU", occ=0, s=s)]))
        V.append(("p_acqrel", "rel_cgaerrbar", f"rel_cga_S{s:02d}", s,
                  [dict(pattern=r"^CGAERRBAR", occ=0, s=s), dict(pattern=r"^@!P0 CGAERRBAR", occ=0, s=s)]))
    V.append(("p_acqrel", "rel_chain_S01", "rel_chain_S01", 1,
              [dict(pattern=r"^MEMBAR\.ALL\.GPU", occ=0, s=1), dict(pattern=r"^@!P0 MEMBAR\.ALL\.GPU", occ=0, s=1),
               dict(pattern=r"^CGAERRBAR", occ=0, s=1), dict(pattern=r"^@!P0 CGAERRBAR", occ=0, s=1)]))
    V.append(("p_acqrel", "rel_no_membar (control)", "rel_membar_nop", None,
              [dict(pattern=r"^MEMBAR\.ALL\.GPU", occ=0, text="NOP ;"), dict(pattern=r"^@!P0 MEMBAR\.ALL\.GPU", occ=0, text="NOP ;")]))
    # ---- setmaxnreg
    TA = r"^USETMAXREG\.TRY_ALLOC"
    V.append(("p_setmaxnreg", "smr_try_bar", "smr_try_bar_S01", 1, [dict(pattern=TA, occ=0, s=1)]))
    for s in (1, 2, 4, 8, 13):
        V.append(("p_setmaxnreg", "smr_try_nobar", f"smr_try_nobar_S{s:02d}", s,
                  [dict(pattern=TA, occ=0, s=s, wb="-"), dict(pattern=r"^BRA\.U !UP0", occ=0, wait="------")]))
    for s in (1, 2):
        V.append(("p_setmaxnreg", "smr_retry_branch", f"smr_bra_S{s:02d}", s, [dict(pattern=r"^BRA\.U !UP0", occ=0, s=s)]))
    V.append(("p_setmaxnreg", "smr_dealloc_nowb", "smr_dealloc_noW", None, [dict(pattern=r"^USETMAXREG\.DEALLOC", occ=0, wb="-")]))
    for s in (1, 5):
        V.append(("p_setmaxnreg", "smr_warpsync", f"smr_warpsync_S{s:02d}", s, [dict(pattern=r"^WARPSYNC\.ALL", occ=1, s=s)]))
    # ---- the collective region (coll_probe.cu; occurrence 1 = the fallback of the shuffle inside the branch, the one that runs)
    WC, SH, EC = r"^WARPSYNC\.COLLECTIVE", r"^SHFL\.BFLY P0", r"^ENDCOLLECTIVE"
    V.append(("p_coll", "coll_end_nowait (control)", "coll_end_nowait", None, [dict(pattern=EC, occ=1, wait="------")]))
    V.append(("p_coll", "coll_end_nowait_reader_waits", "coll_end_reader_waits", None,
              [dict(pattern=EC, occ=1, wait="------"), dict(pattern=r"^MOV R2, R7", occ=1, wait="01----")]))
    V.append(("p_coll", "coll_end_waits_result_only", "coll_end_w_only", None, [dict(pattern=EC, occ=1, wait="-1----")]))
    V.append(("p_coll", "coll_end_waits_operands_only", "coll_end_r_only", None, [dict(pattern=EC, occ=1, wait="0-----")]))
    V.append(("p_coll", "coll_shfl_norb", "coll_shfl_noR", None, [dict(pattern=SH, occ=1, rb="-"), dict(pattern=EC, occ=1, wait="-1----")]))
    for s in (1, 2, 3, 4, 5, 6, 7):
        V.append(("p_coll", "coll_entry", f"coll_entry_S{s:02d}", s, [dict(pattern=WC, occ=1, s=s, before=True)]))
    for s in (1, 2, 3, 5):
        V.append(("p_coll", "coll_warpsync", f"coll_warpsync_S{s:02d}", s, [dict(pattern=WC, occ=1, s=s)]))
    for s in (1, 2, 4):
        V.append(("p_coll", "coll_shfl", f"coll_shfl_S{s:02d}", s, [dict(pattern=SH, occ=1, s=s)]))
    for s in (1, 2, 3, 5):
        V.append(("p_coll", "coll_end", f"coll_end_S{s:02d}", s, [dict(pattern=EC, occ=1, s=s)]))
    V.append(("p_coll", "coll_all_S01", "coll_all_S01", 1,
              [dict(pattern=WC, occ=1, s=1, before=True), dict(pattern=WC, occ=1, s=1), dict(pattern=SH, occ=1, s=1), dict(pattern=EC, occ=1, s=1)]))
    return V


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", default="tables/sm120.json.gz")
    ap.add_argument("--cubin", required=True, help="the nvcc build of sync_probes.cu")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    frozen = os.path.join(a.out, os.path.basename(a.cubin).replace(".cubin", "") + ".frozen.sass")
    subprocess.run([a.cubit, "disassemble", "-t", a.table, "--frozen", a.cubin, "-o", frozen], check=True, capture_output=True)
    text = open(frozen).read()
    kern = {}
    for blk in re.split(r"(?m)^(?=\.entry )", text):
        if blk.startswith(".entry"):
            kern[blk.split()[1]] = blk
    ref_bytes = open(a.cubin, "rb").read()
    index = []
    # the references: every kernel through the same path, byte-identical to nvcc's cubin
    for k in sorted(kern):
        src = os.path.join(a.out, f"ref_{k}.sass")
        open(src, "w").write(kern[k])
        out = os.path.join(a.out, f"ref_{k}.cubin")
        r = subprocess.run([a.cubit, "asm", "-t", a.table, "-T", a.cubin, "-k", k, src, "-o", out], capture_output=True, text=True)
        if r.returncode != 0 or open(out, "rb").read() != ref_bytes:
            raise SystemExit(f"reference {k}: the frozen round trip is not byte-identical\n{r.stdout[-600:]}{r.stderr[-600:]}")
        index.append(dict(name=k, probe=k, cubin=f"ref_{k}.cubin", reference=True, variant=f"ref_{k}", group="reference", x=None, edits=[]))
    for k, group, name, x, edits in variants():
        if k not in kern:
            continue                       # a variant of a probe kernel another cubin holds
        lines = kern[k].splitlines(keepends=True)
        for e in edits:
            edit(lines, **e)
        src = os.path.join(a.out, f"{name}.sass")
        open(src, "w").write("".join(lines))
        out = os.path.join(a.out, f"{name}.cubin")
        r = subprocess.run([a.cubit, "asm", "-t", a.table, "-T", a.cubin, "-k", k, src, "-o", out], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"{name}: asm failed\n{r.stdout[-800:]}{r.stderr[-800:]}")
        nb = open(out, "rb").read()
        diff = sum(1 for p, q in zip(ref_bytes, nb) if p != q)
        if len(nb) != len(ref_bytes):
            raise SystemExit(f"{name}: {len(nb)} bytes, the reference has {len(ref_bytes)}")
        index.append(dict(name=k, probe=k, cubin=f"{name}.cubin", reference=False, variant=name, group=group, x=x,
                          edits=[{kk: vv for kk, vv in e.items()} for e in edits], bytes_changed=diff))   # 0 = the point of the sweep that IS ptxas's schedule
    json.dump(index, open(os.path.join(a.out, "index.json"), "w"), indent=1)
    print(f"{len(index)} kernels ({sum(1 for e in index if e['reference'])} references, byte-identical to nvcc's cubin) -> {a.out}")


if __name__ == "__main__":
    main()
