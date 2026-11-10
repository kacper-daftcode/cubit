# Register allocation on sm_120: evidence and an independent check

What stands behind `cubit ra --mode full --target sm120` (`src/ra_target.rs`).

| file | role |
|---|---|
| `align_census.py` | CPU: where ptxas puts multi-register operands. Input: frozen disassemblies of nvcc / ptxas cubins (`cubit disassemble --frozen`). Counts, per operand shape, the base register modulo the operand's width. |
| `align_census_sm120.json` | its result of 2026-11-10 on the sm_120 census (166 cubins, 1 811 600 instructions): **no operand of any shape off its grid** — 64-bit pairs on even registers (`IMAD.WIDE` destination 23 339 / addend 18 437, address pairs of `LDG` 22 295 / `STG` 18 062 / `LD` 1 452 / `LDGSTS` 2 905 / `ATOMG` 116 / `REDG` 100 and their descriptors, `LDC.64` 7 009, `LDG.64` 1 282, `LDS.64` 2 633, `STS.64` 2 460, `STG.64` 2 704, `MOV.64` 4 121, `CS2R` 22 116, `LDSM` ×2 8 284, `LDCU.64` 8 102), quads on multiples of four (`LDG.128` 3 142, `LDS.128` 13 872, `STS.128` 1 768, `STG.128` 498, `LDSM` ×4 19 190, `HMMA` D / A / C 27 176 each, `QMMA` 12 448). |
| `ra_equiv.py` | CPU: an independent check of a renaming — its own hardware footprints (written by hand for the opcodes of the sparse-MLA prefill attention kernel; anything else stops the run), guard-aware liveness, the control flow from the labels. `text` compares the source and the renamed text under the plan, checks every multi-register operand for tearing and alignment, and looks for a clobber on every instruction; `words` compares `cubit disassemble` of the two cubins. |

```bash
python3 tools/ra/align_census.py <dir of *.frozen.sass> out.json
cubit ra k.sass --mode full --target sm120 -o k.ra.sass --report k.ra.json
python3 tools/ra/ra_equiv.py text k.sass k.ra.sass k.ra.json
```
