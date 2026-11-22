# NSO rewriter reference parity

This document tracks the native Swift implementation against dm/tools/patch_nso.py.
The Python rewriter is the behavioral reference; a green Swift test suite is not proof of
full parity or successful game conversion.

## iOS app linkage

The ConverterCore Swift package is linked as a local package dependency of the DmIOS target in dm/ios/project.yml. The generated per-game Xcode project and the synthetic CI smoke project both link the package directory, and the launcher imports the module so Xcode must resolve and compile it. This verifies app-target integration only: the launcher does not yet invoke an end-to-end NSP conversion workflow.

The NSO input path now includes header validation, bounded LZ4 segment decompression, contiguous near/far image reconstruction, instruction planning, and batch emission for the supported rewrite subset. NSORewritePipeline.process(file:codeRanges:) coordinates those stages as one fail-closed operation. Callers must supply executable code ranges; the pipeline does not assume that every byte in the text segment is code. Its output is an NSO module image with the patch area appended, not a complete NCA/NSP/IPA. NCA section-header parsing is hash-verified against the digest stored in the NCA header. Section payload crypto, PFS0/ExeFS extraction, RomFS IVFC verification and extraction integration, full rewrite parity, and runtime handoff remain separate work. The standalone RomFSArchive parser now validates the 0x50-byte image header, bounded metadata records, directory/file parent chains, UTF-8 path components, duplicate paths, and file extents; its extractor streams payloads into a staged directory. This parser does not itself verify the NCA IVFC tree, so it must not yet be used as a verified NCA RomFS extraction path.

## NCA inspection and crypto boundary

The NCA3 inspector reads the encrypted 0xC00-byte header only. NCAFileSystemHeader parses each selected 0x200-byte section header and verifies its SHA-256 digest. It parses the hierarchical-SHA256 PFS0 superblock and eight-byte section CTR seed. NCASectionCTR derives a counter from an absolute NCA file offset. NCASectionCTRCrypt applies AES-128/256-CTR to supplied bytes using a caller-selected key, including unaligned file ranges. The primitive is covered by a NIST AES-CTR known-answer vector and offset-slice parity tests. Standard NCA key-area selection and AES-ECB decryption are now implemented for pre-derived application/ocean/system keys in prod.keys; CTR/BKTR sections use decrypted slot 2. Title-key lookup from title.keys and generation-specific AES-ECB decryption using titlekek_## (or ticket_commonkey_## alias) are implemented for Rights ID NCAs. Master-key derivation remains unimplemented. NCASectionStreamDecryptor now decrypts standard AES-CTR sections to a separate file using bounded chunks (1 MiB by default, capped at 8 MiB), the parsed section seed, and the absolute NCA file offset. It rejects AES-XTS, CTREx, skip-layer-hash, automatic, and no-encryption modes rather than guessing their semantics; BKTR and sparse storage remain unimplemented. It accepts an already-resolved section key and does not yet orchestrate a complete NCA-to-filesystem extraction.

## Implemented in Swift and currently admitted by the batch emitter

| Rewrite | Python reference | Swift status |
|---|---|---|
| Plain x18 read/modify/write | site_plain | Implemented for instructions that do not write back to SP |
| MRS TPIDR_EL0 | site_sysreg_read(..., KTLS) | Implemented |
| MRS TPIDRRO_EL0 | site_sysreg_read(..., KTLR) | Implemented |
| MSR TPIDR_EL0 | site_tpidr_write | Implemented |
| SVC and CNT[P/V]CT_EL0 host gates | site_gate | Implemented |
| CTR_EL0 cache-line-size replacement | ctr classification / in-place MOVZ | Implemented |
| Stack-alignment correction | site_sp_align | Implemented |
| x18 used while writing SP | site_sp | Implemented as a separate emitter; batch-enabled |
| Conditional x18 branch | site_cond | Implemented for CBZ/CBNZ/TBZ/TBNZ; batch-enabled |
| ADR / ADRP involving x18 | site_pcrel | Implemented with absolute-target reconstruction; batch-enabled. Scratch registers are restored before returning to the original instruction. |

## Known gaps: do not silently enable these

| Rewrite | Python reference | Swift status / required work |
|---|---|---|
| Indirect branch / jump table | site_br, site_br_tab | Planner identifies candidates; requires table/function analysis |
| BLR x18 / tail-call BR x18 | site_blr, site_br_call | Planner identifies candidates; no native emitter |
| Exclusive-instruction windows | site_window, site_retry_window | Planner identifies candidates; requires whole-window analysis |
| Spin-wait loop rewriting | spin-loop analysis and gate insertion | Not yet ported |
| Build-ID registered cuts / observation gates | CUTS / OBS tables | Not yet integrated |
| Function-matched cuts | nso_match.py | Not yet integrated |
| NRO input | NRO path in patch_nso.py | Not yet supported by the current NSO parser |

## Next implementation order

1. Add reference-vector parity tests for each currently supported emitter, including exact emitted words, fixup offsets, gate return addresses, and site branch targets.
2. Complete loader/runtime integration only after the cryptographic and filesystem stages can fail closed.
3. Keep rejecting every rewrite site not explicitly implemented and tested; never emit a partially rewritten image when a module contains an unresolved site.
