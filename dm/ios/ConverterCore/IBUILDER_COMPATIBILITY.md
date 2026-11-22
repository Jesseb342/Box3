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


## Runtime and game-IPA architecture audit (2026-11-22)

The iBuilder architecture documentation adds an important finding that changes
the integration order: a rewritten NSO is not itself a playable iOS game. A
complete game build requires a compatible engine host, shader library, framework
assembly, signing/export handling, and a player-mode app bundle.

The documented iBuilder chain is:

1. Read the game container and derive the per-game profile.
2. Rewrite the required ARM64 modules and emit the associated fixup/site/gate
   tables.
3. Split and translate shaders, then build the per-game Metal shader library.
4. Graft the rewritten modules onto a prebuilt nxnative/NX2Apple host dylib to
   produce `DmGameProbe.framework`, then sign the framework.
5. Export a player-mode app bundle containing the framework, shader library,
   profile/runtime data, rewrite tables, and game metadata; the app boots the
   framework in-process.

Relevant upstream sources at the audited v0.1.2 tag:

- `docs/ARCHITECTURE.md`: end-to-end chain, host responsibilities, Documents
  layout, and exported-game IPA layout.
- `docs/reference/pipeline.md`: stage driver, adapters, C ABI, memory/thermal
  gates, and boot-only state machine.
- `docs/reference/assemble-sign-pack.md`: `ibuilder-macho`,
  `ibuilder-sign`, and `ibuilder-pack` responsibilities and limitations.
- `crates/ibuilder-pipeline`: chain orchestration and the adapter contracts.
- `crates/ibuilder-macho`: linker-less Mach-O framework assembler.
- `crates/ibuilder-sign`: ad-hoc framework signature implementation.
- `crates/ibuilder-pack`: `.nxgame` package writer; this is not by itself an
  iOS IPA exporter.
- `app/gameapp` and `app/gameapp_shim_rust.c`: app/player integration and
  platform callbacks.

### Consequences for Swapp

- Swapp's current diagnostic IPA proves only that the Swapp shell installs and
  opens. It is not evidence that a game framework can be assembled or booted.
- Swapp's current NCA/NSP and NSO stages are only part of the chain. The missing
  runtime host and shader pipeline are critical dependencies, not optional
  packaging polish.
- The user's required output is the **Full** export: all game runtime files,
  shader data, rewrite tables, and RomFS must be inside one self-contained IPA.
  iBuilder also documents a Light export with RomFS beside the IPA; that format
  does not meet this project's requirement.
- The assembler source alone cannot create a playable game: it needs the exact
  compatible prebuilt host dylib and the complete matching rewritten module
  outputs. Its own documentation says the Rust-assembled framework has not
  been booted in its repository's tests.
- iBuilder's ad-hoc framework signature is not the same as signing the final
  app bundle. The final IPA must be suitable for SideStore to re-sign and
  install, and the framework must load under iOS code-signing rules.
- iBuilder's BC fallback patch 0096 explicitly says it was not tested on a
  device or simulator; patch-application/host-harness results are not proof of
  BC decoding on an A15 iPhone. Keep the known-good NXNative BC fallback
  profile as the device acceptance target rather than assuming iBuilder's
  fallback is ready.

### Revised integration order

1. Identify and pin the exact compatible nxnative/NX2Apple host source/build
   and its required runtime data. Verify licensing and whether a reproducible
   iOS device build is available. Without this, there is no executable game
   runtime to package.
2. Map the iBuilder engine host ABI, module/profile/table formats, and
   shader-library contract against the existing Swapp converter outputs.
3. Integrate the complete shader split/translate/build stages and the host
   callbacks they require.
4. Integrate `ibuilder-macho` and its framework assembly inputs; add structural
   and byte-parity tests before using it on a real game.
5. Implement the Full player-IPA exporter and validate every required file is
   embedded; reject Light/external-RomFS output.
6. Validate framework signing, SideStore installation, launch, and actual
   gameplay on the iPhone 14. Only then call the first-game milestone complete.

No upstream iBuilder BC patch is accepted as a substitute for the known-good
iPhone 14 BC path until the complete host has been built and a real game has
been tested on-device.


## Host availability and reproducibility check (2026-11-22)

A second source-tree check was made against the complete iBuilder v0.1.2 Git tree
(1,520 tracked paths). It contains the Rust assembler, signer, shader crates,
app shim, and engine patch series, but **does not contain** a prebuilt
`host-prebuilt-loadable-ios.dylib`, a vendored nxnative engine tree, or the
external iOSBuilder build worktree.

The upstream `scripts/build-host.sh` confirms that this is a real dependency,
not a missing file that can be generated from the iBuilder Rust crates alone.
It requires all of the following outside the iBuilder checkout:

- `IOSBUILDER_WORKTREE` (or `IOSBUILDER`), containing `out-stage/out-engine/engine`,
  `tools/`, `load/`, and `paches/`;
- the matching prebuilt video decoder archives in `out-stage/out-video/`
  (`libvpx` and `libdav1d`, device and simulator);
- Xcode's iOS SDK and the exact shader-chain ID expected by the game shader
  libraries;
- a pinned base engine and ordered patch set.

The script verifies the generated host's platform/minimum OS, exported symbols,
shader-chain marker, patch markers, and compatibility with the app shim before
publishing the dylib. It does not build the shader decoder archives itself.
Consequently, simply copying `ibuilder-macho` into Swapp or compiling the
iBuilder Rust workspace cannot produce a runnable game host.

### Existing Box3/NXNative trail

The Box3 branch already has `.github/workflows/NXnative-survey.yml`, an older
manual Captain Toad IPA workflow that checks out an NXNative revision and calls
`scripts/build_ipa_from_nsp.py`. This is a useful historical integration lead,
but it is not the current Swapp on-device workflow and must not be mistaken for
a verified Swapp build. Its checkout revision must be resolved and checked
against the actual NXNative repository before reuse.

### Required next engineering action

Before adding more assembler or IPA-export code, establish one reproducible
source for the host:

1. Resolve the exact NXNative/NX2Apple commit and patch stack that produced the
   previously working iPhone 14 BC fallback.
2. Determine whether its complete iOS host build can run from public,
   pinned sources in GitHub Actions without private/local iOSBuilder artifacts.
3. If it can, create a separate host-build workflow that outputs a verified
   device dylib plus a machine-readable manifest (source commits, patch hashes,
   toolchain, deployment target, exported symbols, shader-chain ID).
4. If it cannot, identify the smallest missing build inputs and a lawful,
   reproducible way to obtain them before attempting integration.

Until this is resolved, host integration is marked **blocked on reproducible
host provenance/build inputs**. Do not substitute a dummy dylib, a simulator
host, or an unverified prebuilt. The user-facing game IPA milestone remains
unmet.


## NXNative host source cross-check (2026-11-22)

The host audit was extended to the public NXNative source at
`seedds/nxnative`, commit
`a3663659342ef43afe1f29909c7c36d0cf7555be` (the exact base revision named
by iBuilder's host-build script).

This changes the conclusion slightly: the engine source itself is available in
the NXNative repository. Its tree includes `dm/host/`, `dm/ios/tools/`,
`dm/gfx/tools/`, the native loader, and the iOS packaging scripts. In
particular:

- `dm/ios/tools/build_ipa.sh` generates an Xcode project, builds the iOS
  executable, and packages the game resources into one IPA.
- `dm/ios/tools/gen_embed.py` places rewritten NSO module images into
  Mach-O sections consumed by the native loader.
- `dm/ios/tools/pack_ipa.py` packs the app, shader library, add-on content,
  and RomFS directly into one IPA. Its default mode includes the RomFS; the
  optional `DM_COPY_ROMFS=NO` mode explicitly does not meet Swapp's
  self-contained-output requirement.
- The build validates rewritten module tables, game profile, RomFS marker,
  shader-chain stamp, and required shader libraries before packaging.

There are therefore two different host integration strategies, and they must
not be conflated:

| Strategy | Runtime model | Main integration issue |
|---|---|---|
| NXNative direct executable | Host C sources and rewritten NSOs are compiled/embedded into a game-specific app executable; resources are packed beside it | Existing pipeline is a Mac/Xcode build, so it is not a drop-in on-device converter |
| iBuilder player framework | A prebuilt host dylib is combined with rewritten modules into `DmGameProbe.framework`; the player app loads it at runtime | iBuilder's host build script expects an iOSBuilder worktree and decoder archives not shipped in iBuilder |

### Updated recommendation

Use NXNative as the authoritative reference for the known working engine, shader
and all-in-one IPA behavior. Use iBuilder's Rust crates for reusable on-device
format/rewrite/assembly work only where their input/output contracts match.
Do not make Swapp depend on iBuilder's undocumented external build worktree if
the required host can instead be built reproducibly from the pinned public
NXNative source.

The next implementation investigation is to compare the two runtime models at
the binary boundary: the NXNative loader's embedded-section contract versus
iBuilder's framework host ABI and the existing Swapp Rust rewrite outputs.
Specifically determine whether Swapp can ship a prebuilt, generic NXNative host
and feed it per-game rewritten modules/resources at runtime, or whether a
framework assembled on-device is required. This decision controls whether
the next code task is a reusable host build/export workflow or the iBuilder
Mach-O framework bridge.

**Current evidence:** source and packaging logic are present in NXNative;
iBuilder documents the dynamic framework model; Swapp has not yet integrated
either runtime model, and no game IPA has been produced by Swapp.
