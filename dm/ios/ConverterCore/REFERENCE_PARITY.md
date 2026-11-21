# NSO rewriter reference parity

This document tracks the native Swift implementation against `dm/tools/patch_nso.py`.
The Python rewriter is the behavioral reference; a green Swift test suite is not proof of
full parity or successful game conversion.

## iOS app linkage

The `ConverterCore` Swift package is linked as a local package dependency of the `DmIOS` target in `dm/ios/project.yml`. The generated per-game Xcode project and the synthetic CI smoke project both link the package directory, and the launcher imports the module so Xcode must resolve and compile it. This verifies app-target integration only: the launcher does not yet invoke an end-to-end NSP conversion workflow.

The NSO input path now includes header validation, bounded LZ4 segment decompression, contiguous near/far image reconstruction, instruction planning, and batch emission for the supported rewrite subset. `NSORewritePipeline.process(file:codeRanges:)` coordinates those stages as one fail-closed operation. Callers must supply executable code ranges; the pipeline does not assume that every byte in the text segment is code. Its output is an NSO module image with the patch area appended, not a complete NCA/NSP/IPA. File-level NCA section-header parsing is now hash-verified against the SHA-256 digest stored in the NCA header. The parser identifies filesystem, hash, encryption, and metadata-hash modes while preserving version-specific extension bytes as opaque data. Section payload decryption, PFS0/ExeFS and RomFS extraction, full rewrite parity, and runtime handoff remain separate work.

## NCA inspection boundary\n\nThe NCA3 inspector reads the encrypted 0xC00-byte header only. `NCAFileSystemHeader` parses each selected 0x200-byte section header from that decrypted region and verifies its SHA-256 digest before interpreting fields. It accepts documented filesystem/hash/encryption enum values and rejects unknown values. It parses the hierarchical-SHA256 PFS0 superblock and the eight-byte section CTR seed. `NCASectionCTR` derives the counter for an absolute NCA file offset using the reference byte order. AES-CTR payload transformation, key selection/derivation, BKTR, sparse storage, and other encryption variants remain separate work.\n\n## Implemented in Swift and currently admitted by the batch emitter

| Rewrite | Python reference | Swift status |
|---|---|---|
| Plain x18 read/modify/write | `site_plain` | Implemented for instructions that do not write back to SP |
| MRS TPIDR_EL0 | `site_sysreg_read(..., KTLS)` | Implemented |
| MRS TPIDRRO_EL0 | `site_sysreg_read(..., KTLR)` | Implemented |
| MSR TPIDR_EL0 | `site_tpidr_write` | Implemented |
| SVC and CNT[P/V]CT_EL0 host gates | `site_gate` | Implemented |
| CTR_EL0 cache-line-size replacement | `ctr` classification / in-place MOVZ | Implemented |
| Stack-alignment correction | `site_sp_align` | Implemented |
| x18 used while writing SP | `site_sp` | Implemented as a separate emitter; batch-enabled |
| Conditional x18 branch | `site_cond` | Implemented for CBZ/CBNZ/TBZ/TBNZ; batch-enabled |
| ADR / ADRP involving x18 | `site_pcrel` | Implemented with absolute-target reconstruction; batch-enabled | Scratch registers are restored before returning to the original instruction.

## Known gaps: do not silently enable these

| Rewrite | Python reference | Swift status / required work |
|---|---|---|
| Indirect branch / jump table | `site_br`, `site_br_tab` | Planner identifies candidates; requires table/function analysis |
| BLR x18 / tail-call BR x18 | `site_blr`, `site_br_call` | Planner identifies candidates; no native emitter |
| Exclusive-instruction windows | `site_window`, `site_retry_window` | Planner identifies candidates; requires whole-window analysis |
| Spin-wait loop rewriting | spin-loop analysis and gate insertion | Not yet ported |
| Build-ID registered cuts / observation gates | CUTS / OBS tables | Not yet integrated into Swift pipeline |
| Function-matched cuts | `nso_match.py` | Not yet integrated |
| NRO input | NRO path in `patch_nso.py` | Not yet supported by the current NSO parser |

## Next implementation order

1. Add reference-vector parity tests for each currently supported emitter, including the exact
   emitted words, fixup offsets, gate return addresses, and site branch targets.
2. Port conditional x18 rewrites and SP-destination x18 rewrites as separate, fail-closed
   emitters. Verify every emitted conditional target by disassembling the generated block.
3. Port ADR/ADRP handling with explicit page-boundary and signed-range tests.
4. Implement jump-table, indirect-call, and exclusive-window analysis only after their
   context requirements are represented in the planner.
5. Add registered-cut and function-match support, then integrate the complete loader/runtime.

The batch emitter must continue rejecting every site kind not explicitly implemented and tested.
Never produce a partially rewritten image when a module contains an unresolved site.
