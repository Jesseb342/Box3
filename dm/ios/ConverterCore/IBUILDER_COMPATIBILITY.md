# iBuilder v0.1.2 compatibility audit

Audit source: `Absenti/iBuilder` tag `v0.1.2`, commit
`104a2b754227cf040e77c20a368016c0fdb6a49c`. This is a source comparison, not
a claim that iBuilder code has been integrated or that its untested BC patches
work on a device.

## Findings

| Area | Box3 ConverterCore today | iBuilder source | Assessment |
|---|---|---|---|
| NSO loading | Swift `NSOImage` + `NSOSegmentLoader`; LZ4 compressed segments; reconstructed text/ro/data image | `ibuilder-nso` loads NSO and NRO, supports LZ4 and Nintendo ZBIC, validates Horizon page layout and segment bounds, optionally checks segment SHA-256, and exposes the full 32-byte build ID | Highest-value gap: ZBIC and NSO integrity checks. Reuse the loader rather than maintaining two subtly different format implementations. |
| AArch64 decode | SwiftPM Capstone wrapper; instruction recovery and register detail | `ibuilder-a64` uses `capstone-sys`, provides a compact decode representation and lightweight x18 scan | Existing decoder is adequate for current tests. Avoid bringing in a second Capstone binding unless the Rust rewriter is adopted. |
| AArch64 encode | Swift checked encoder for the instruction forms currently emitted | `ibuilder-a64::asm` contains the larger encoder set used by the full rewriter | Useful if adopting the Rust rewriter; otherwise port only missing encoders when a concrete rewrite needs them. |
| NSO rewrite | Swift planner/emitter is fail-closed and currently handles a bounded subset of rewrite sites | `ibuilder-rewrite` is a Rust port of the same `dm/tools/patch_nso.py` toolchain and includes detectors, jump solving, stubs, tables and game-specific handlers | Major potential time saver, but not a drop-in function: it expects the iBuilder profile/table layout and its output contract. Needs an adapter and parity tests. |
| Shader conversion | Existing Box3 shader tooling and Ryujinx translator assets | iBuilder splits shader archives, translates through its Ryujinx/SPIR-V-Cross toolchain, then builds a per-game Metal shader library | Significant overlap, but different cache/table contracts. Defer until the module rewrite interface is settled. |
| Mach-O assembly | Current Box3 IPA path uses Xcode/gen_embed and native host build tooling | `ibuilder-macho` is a Rust linker-less Mach-O framework assembler with no third-party runtime dependencies | Strong later candidate; compare output byte-for-byte before replacing the existing assembly path. |
| NCA/container extraction | Swift NCA3 inspection, CTR decryption, PFS0 integrity/extraction and standalone RomFS parsing | iBuilder app uses C# LibHac for NSP/XCI extraction; Rust `ibuilder-nup` targets NUP containers | Keep Box3's NCA work. iBuilder does not replace the NCA decryption/integrity implementation already in this branch. |

## Build and integration constraints

- The iBuilder workspace uses Rust edition 2024 and a multi-crate Cargo workspace.
- `ibuilder-nso` depends on `lz4_flex`, `sha2`, and `memmap2`; its ZBIC decoder is pure Rust.
- `ibuilder-rewrite` additionally depends on `ibuilder-a64`, Rayon, regex and memchr. Its output includes a rewritten image/patch plus fixups, gates, sites, cuts and observation tables.
- `ibuilder-a64` depends on `capstone-sys`; Box3 currently gets Capstone through SwiftPM.
- The iBuilder app itself is .NET/C# plus a C shim and Rust FFI. Importing its UI/application layer would be unnecessary and would couple Box3 to a different app architecture.
- Box3's current converter CI builds SwiftPM and Xcode projects. A Rust static library would require pinned Rust toolchain/targets, a reproducible Cargo build step for device and simulator architectures, C ABI headers, and explicit Xcode link integration. Do not add a network-fetched Cargo Git dependency to the production build.

## Recommended adoption order

1. **NSO loader parity first.** Vendor the MIT-licensed `ibuilder-nso` crate at the audited commit (including its license/attribution), expose a narrow C ABI for loading/reconstructing a module, and add Rust-vs-Swift fixture parity tests. This gains ZBIC support and the stricter validation without rewriting the Swift pipeline. Keep the Swift implementation as a test oracle during migration.
2. **Rewriter second.** If the Rust loader bridge builds for iOS, bring in `ibuilder-a64` and `ibuilder-rewrite` as a separate Rust static library. Adapt Box3's profile/code-range metadata and compare generated rewrite artifacts against the current desktop rewriter and Swift emitter. Do not replace the Swift path until parity is demonstrated.
3. **Mach-O assembly third.** Evaluate `ibuilder-macho` against Box3's existing IPA/framework assembly, using deterministic synthetic fixtures.
4. **Shader stages fourth.** Only then decide whether iBuilder's split/build chain can be adapted to Box3's shader chain and profile data.
5. **BC fallback remains a separate engine-host task.** The iBuilder BC patches 0410/0411 explicitly identify themselves as fork-only and say they were checked for patch application but not compiled or run. Treat them as source material, not validated device support. Retain the existing Box3 BC fallback and iPhone 14 validation as the acceptance test.

## Licensing and provenance

The iBuilder workspace declares MIT licensing. Any vendored crate must retain its upstream copyright/license notices and be pinned to the audited commit. Dependencies and copied patches retain their own license/provenance requirements; check those individually before copying them. The BC engine patches identify NX2Apple as their source and carry separate attribution in their headers.

## Explicit non-goals

- Do not import the iBuilder .NET UI or app shell.
- Do not replace Box3's NCA decryptor with a claim that iBuilder implements the same path.
- Do not claim BC CPU decoding is proven on the iPhone 14 based on source inspection alone.
- Do not make game conversion run automatically on repository commits.
