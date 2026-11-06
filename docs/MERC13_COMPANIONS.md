# CUBIT_MERC13 — standalone companion-section emission (nvcc 13.3 laws)

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
Default: ON (the standalone emitter). Set `CUBIT_MERC13=0` for the byte-legacy
output (`build_legacy`, verbatim), e.g. to reproduce binaries assembled by
pre-merc13 cubit. Both modes keep `.text` bit-identical; only the companion
sections differ.

## What is and is not reproduced (status 2026-11-02)

Two paths exist and they differ in what they reproduce:

**Template rebuild (`asm -T <cubin>` / `--eiattr-from`)** copies the reference ELF and replaces
only the `.text.<kernel>` payloads. Everything else is the reference's bytes: `.nv.info` /
`.nv.info.<kernel>` records (with two exceptions below), `.nv.constant0`, relocations, Mercury
companions, string and symbol tables. Measured result: `disassemble --frozen` → `asm -T` reproduces
157 / 157 code-bearing census cubins byte for byte (`tools/asm_roundtrip.py`, 2026-11-02). What the
rebuild *does* touch: `EIATTR_REGCOUNT` (raise-only, see `--allow-regcount-change`) when the
instruction payload changed; and it refuses when the `.param` declarations disagree with the
reference's `EIATTR_KPARAM_INFO` (the driver lays arguments out per the copied metadata). Not
reproduced by construction: nothing — the metadata is not regenerated, so it cannot drift; the
price is that a kernel whose resources (registers, shared memory, parameters, barriers) differ from
the template's needs a standalone build or a matching template.

**Standalone build (`asm` without `-T`)** regenerates every section by the nvcc 13.3 laws above.
Verified legal (loads, launches, runs: the project's production kernels of 2026-06..10) but not
byte-identical to nvcc's output for the same instructions; the known differences:

| section / field | state | why |
|---|---|---|
| Mercury func symbol `st_size` | = align16(capsule length) | the exact 13.3 value comes from the capsule VM expansion, not modelled |
| Mercury `EIATTR_EXIT_INSTR_OFFSETS` (0x1c) | earlier SASS exits + 0x10, then st − 0x10 | same (capsule expansion) |
| `.nv.merc.rela.text.K` for static-smem kernels | not emitted | capsule field-offset law pending |
| `EIATTR_KPARAM_INFO` space / log-alignment nibbles | from the `.param` type (`ptr` → space 5; `b8[N]`, scalars → 0) or the explicit `space=` / `logalign=` attributes | nvcc derives them from the C type; cubit from the declaration |
| `EIATTR_CUDA_API_VERSION` | 0x85 unless the text says otherwise | the assembler has no compiler version |
| `EIATTR_MAX_THREADS`, `REQNTID`, `CRS_STACK_SIZE`, `UNUSED_LOAD_BYTE_OFFSET`, `INT_WARP_WIDE_INSTR_OFFSETS`, `MBARRIER_INSTR_OFFSETS` | emitted only where the text implies them (barrier count, VOTEU sites, …) | launch-bounds and compiler-analysis attributes have no SASS source |
| `.nv.constant0.K` contents | zeros of the exact size | constant-bank initial values are not part of SASS |

The template rebuild is the path for Phase 1b (byte-identical reassembly of compiler kernels with
edited instructions); the standalone build is the path for kernels written from scratch.

## Positional metadata under an edited template rebuild (A5, measured 2026-11-06)

The template rebuild copies `.nv.info.<kernel>` verbatim. Over the 759 kernels of the sm_120 production
census (168 cubins), four of its records are *positional* — lists of byte offsets into the kernel's `.text`:

| record | kernels | payload | law |
|---|---:|---|---|
| `EIATTR_EXIT_INSTR_OFFSETS` (0x1c) | 759 / 759 | `u32` offsets | exactly the `EXIT` words of the code (759 / 759 kernels) — regenerable |
| `EIATTR_COOP_GROUP_INSTR_OFFSETS` (0x28, with `COOP_GROUP_MASK_REGIDS` 0x29) | 661 | `u32` offsets | compiler analysis: the same opcodes occur outside the list (e.g. `S2R` 694 listed / 3 564 not) — not regenerable from the code |
| `EIATTR_INT_WARP_WIDE_INSTR_OFFSETS` (0x31) | 208 | `u32` offsets | mostly the `VOTEU` sites, with exceptions both ways — not regenerable |
| `EIATTR_MBARRIER_INSTR_OFFSETS` (0x39) | 522 | 16-byte entries `(offset, 0xff, mbarrier smem address, flags)` | compiler analysis — not regenerable |

No other record of the census addresses the code, and no census cubin relocates into `.text` (the
`.nv.constant0` contents and the Mercury companions are copied as before and are not positional in this
sense). Two consequences:

* **The frozen path (A20) is right to copy.** `disassemble --frozen` → `asm -T` keeps every instruction at
  its offset, so the copied records are exact; regenerating them could only introduce differences.
* **An edit that moves a listed instruction makes the copied records stale.** Since 2026-11-06 the rebuild
  checks, whenever the instruction payload changed, that every listed offset still holds the kind of
  instruction the template had there (and that every `EXIT` of the new code is in the EXIT list), and
  refuses otherwise with the record, the offset and both opcodes named. `--allow-stale-metadata` writes the
  cubin with the template's records as they are (one warning per entry). Same-length edits (register
  recolouring, immediate changes) and schedule-only edits never trip it. What a *correct* edited rebuild
  would need is translation, not regeneration — each recorded offset follows its instruction through the
  edit, which requires the instruction map of the frozen listing (the `/*addr*/` comments) and is not
  built; nothing shipped performs such edits. The EXIT list alone could be regenerated by its measured law.

A `KernelEntry` built from code bytes with an empty `KernelMeta::exit_offsets` (programmatic callers; the
`asm` path fills the list while parsing) used to get `EXIT_INSTR_OFFSETS = [0x0]`; it gets the code's
`EXIT` words now.
