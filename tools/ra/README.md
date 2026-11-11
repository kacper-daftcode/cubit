# Register allocation on sm_120: evidence and an independent check

What stands behind `cubit ra --mode full --target sm120` (`src/ra_target.rs`; the guide for generator authors is
[docs/RA_SYMBOLIC_REGISTERS.md](../../docs/RA_SYMBOLIC_REGISTERS.md)).

| file | role |
|---|---|
| `align_census.py` | CPU: where ptxas puts multi-register operands. Input: frozen disassemblies of nvcc / ptxas cubins (`cubit disassemble --frozen`). Counts, per operand shape, the base register modulo the operand's width. |
| `align_census_sm120.json` | its result of 2026-11-10 on the sm_120 census (166 cubins, 1 811 600 instructions): **no operand of any shape off its grid** — 64-bit pairs on even registers (`IMAD.WIDE` destination 23 339 / addend 18 437, address pairs of `LDG` 22 295 / `STG` 18 062 / `LD` 1 452 / `LDGSTS` 2 905 / `ATOMG` 116 / `REDG` 100 and their descriptors, `LDC.64` 7 009, `LDG.64` 1 282, `LDS.64` 2 633, `STS.64` 2 460, `STG.64` 2 704, `MOV.64` 4 121, `CS2R` 22 116, `LDSM` ×2 8 284, `LDCU.64` 8 102), quads on multiples of four (`LDG.128` 3 142, `LDS.128` 13 872, `STS.128` 1 768, `STG.128` 498, `LDSM` ×4 19 190, `HMMA` D / A / C 27 176 each, `QMMA` 12 448). |
| `gen_align_probes.py`, `probe_run.py` | silicon: 38 one-warp kernels, one shaped instruction each, the base register on its grid (the control) or off it; one process per kernel (a fault kills the context). |
| `align_probes_sm120_20261110.json` | their result on an RTX PRO 6000 Blackwell Server Edition: **15 of 15 controls exact; 23 of 23 off-grid kernels end the launch with CUDA_ERROR_ILLEGAL_INSTRUCTION (715)** — the `IMAD.WIDE` addend pair (5-operand spelling) and its destination pair, the destination of `LDC.64` / `LDG.E.64` / `LDS.64` / `CS2R` / `LDSM.2` on an odd register and of `LDG.E.128` / `LDS.128` / `LDSM.4` on 4k+1, 4k+2, 4k+3, the data of `STS.64` / `STS.128`, the address pair of `LDG` and `STG`, an odd uniform pair for `LDCU.64` + `desc[UR]`. The controls also show that `CS2R R8, SRZ` writes R8 and R9 and that `LDSM.16.MT88.2 R8` writes R8 and R9 only. cubit assembles all 38 without a word. |
| `gen_carry_probes.py` | silicon, BUG-008: the wide IMAD's pairs in the forms the first set left out — a real carry-out predicate, the carry-in form `.X`, a uniform addend — 16 kernels, and `--set3`: four more that decide whether the predicate behind `Rd` is the 64-bit carry. Run with `probe_run.py`. |
| `carry_probes_sm120_20261110.json` | its result (RTX PRO 6000 Blackwell Server Edition): **7 of 7 kernels with a pair on an odd register fault (715)** — odd addend and odd destination with a carry-out predicate and in the carry-in form, odd destination with a uniform addend, **an odd uniform addend pair** (`IMAD.WIDE.U32 R12, R6, R7, UR7`), and the first set's `imadw_c_b9` again; the nine controls return the right sum. The three controls with a carry-out predicate carry `WRONG` for their third word: the guard six issue cycles behind the IMAD read the predicate's earlier value. The four `imadwq_*` kernels (`--set3`: the guard 21 issue cycles behind, both polarities, with and without an overflow) settle it: **the predicate is the carry of the 64-bit sum** — set with an overflow, cleared without one. The encoder refuses all of these shapes since (`check_imad_wide_odd_pair`, KNOWN_ISSUES A2). |
| `ra_equiv.py` | CPU: an independent check of a renaming — its own hardware footprints (written by hand for the opcodes of the sparse-MLA prefill attention kernel; anything else stops the run), guard-aware liveness, the control flow from the labels. `text` compares the source and the renamed text under the plan, checks every multi-register operand for tearing and alignment, and looks for a clobber on every instruction; `words` compares `cubit disassemble` of the two cubins. |

```bash
python3 tools/ra/align_census.py <dir of *.frozen.sass> out.json
python3 tools/ra/gen_align_probes.py probes/ && for f in probes/*.sass; do CUBIT_ALLOW_OFF_GRID=1 cubit asm $f -t tables/sm120.json -o ${f%.sass}.cubin; done   # the off-grid probes are refused without the variable (BUG-488)
python3 tools/ra/probe_run.py probes/ --out probes.json                # on the GPU host
python3 tools/ra/gen_carry_probes.py probes2/ probes/                  # BUG-008: the other forms of the wide IMAD (odd ones: CUBIT_DISABLE_ERRATA=1 cubit asm)
cubit ra k.sass --mode full --target sm120 -o k.ra.sass --report k.ra.json
python3 tools/ra/ra_equiv.py text k.sass k.ra.sass k.ra.json
```
