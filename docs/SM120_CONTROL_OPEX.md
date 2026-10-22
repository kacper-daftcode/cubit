# SM120 scheduling control legality

Instruction bits 105–108 hold the four-bit stall count and bit 109 holds
yield. NVIDIA's SM120 decoder accepts the combined low-five value in
`0x00..0x0f` and `0x11..0x1b`. It rejects `0x10` and `0x1c..0x1f` as undefined
OPEX entries: yield with stall 0 or 12–15.

The fixture [sm120_control_opex.json](../tests/fixtures/sm120_control_opex.json)
records all 32 combinations for six independently decoded anchors: QMMA,
MOV, FFMA, LDS, BRA and NOP. Every word originally came from ordinary SASS
with an explicit control code. All six sweeps agree: 162 words accepted,
30 rejected. Each accepted NVIDIA instruction text reassembled through the
ordinary SASS path to the complete original 128-bit word. No residue, raw
instruction escape, original instruction bits or masks entered reassembly.
The fixture pins the NVIDIA decoder, encoder library, ISA table and sweep
artifacts by SHA-256 and retains the NVIDIA error for each rejected word.

The independent native-source census verified the exact physical-section
set and every source SHA-256 against the pinned CSV and manifest: 493
modules, 3933 sections, 11,874,176 instructions, zero reserved combinations.
The fixture records all 32 histogram bins and the census/CSV/manifest hashes.
This scope excludes companion Mercury sections outside the manifest; raw
`.text` words from mixed native/Mercury modules are not counterexamples to
this native encoding rule.

This is NVIDIA decoder and exact-reassembly evidence, not an execution or
latency measurement. It supplies no new instruction-readiness guarantee and
does not justify reducing stalls or changing scoreboard dependencies.

The SM120 encoder rejects reserved author controls and out-of-range stalls
before producing bytes. It does not change them. The scheduler can clear
yield on controls it generated, preserving stall, read barrier, write barrier
and wait mask. Explicit source controls and direct-IR overrides stay frozen
until encoder validation. CLI scheduling post-passes apply the same rule to
their generated controls. Other architecture tables retain their existing
encoding and scheduling behavior. Parsing and decoding remain tolerant so
reserved words can be inspected during reverse engineering.
