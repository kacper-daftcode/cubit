# CUBIT_MERC13 — sovereign companion-section emission (nvcc 13.3 laws)

`cubit asm` (non-template path, `build_cubin_mercury[_for_arch]`) can emit the
full companion set of a 13.3 nvcc cubin statelessly (no `-T` donor):

- `.debug_frame` + `.rela.debug_frame` (SASS CIE/FDE per kernel, CFI program
  from EXIT offsets; rela PC32 to func sym, reverse kernel order),
- `.nv.merc.debug_frame` + `.nv.merc.rela.debug_frame` (per kernel, computed),
- `.nv.merc.symtab` (13.3 layout, `.text.K` naming for the capmerc section,
  smem-anchor cluster, reserved/alias/cap values 0 in the Mercury domain),
- `.nv.merc.nv.info[.K]` (13.3 record law: 66/37=0x85/5a/17*/50/1b/[4c]/5f/
  [31]/[29+28]/4a/1c; global (2f,11)-reverse + (12)-forward),
- 13.3 `.symtab` (note syms, sh_info = count), `.strtab`/`.shstrtab` interner
  law, per-arch `.nv.compat` blobs, `.note.nv.cuinfo` sm/api desc,
- `.nv.shared.K` only for static-smem kernels; `.nv.constant0.K` exact end.

## Enabling
Default ON since 2026-08-24 (owner decision, anchor migration rt98
3d15ab6a -> 6a58a60642b913697d8ba3a3b9168504; .text bit-identical).
Set `CUBIT_MERC13=0` for the byte-legacy output
(`build_legacy`, verbatim) so the frozen chain reference of rt98
(3d15ab6a174d9765e60538d9fe575194) stays byte-exact. With the flag the chain
migrates to the evolved anchor (6a58a60642b913697d8ba3a3b9168504); flipping
the legacy mode remains available for frozen-chain reproduction.

## Known phase-1 approximations (verified-legal, not yet byte-exact)
Mercury func `st_size` = align16(capsule length); Mercury 0x1c exit offsets =
[earlier SASS exits +0x10] + [st−0x10]; the exact 13.3 values come from the
capsule VM expansion (see results/cubitfix/merc.md phase-2). `.nv.merc.rela.text.K`
for static-smem kernels is parked (capsule field offset law pending).
