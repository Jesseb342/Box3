# On-device iOS converter: architecture and implementation plan

## Product boundary

Build a new, independent iOS application that converts a user's own Switch dump into an unsigned IPA **entirely on the iPhone or iPad**. The app must not send keys, NSP/XCI files, extracted content, or conversion work to GitHub Actions, a cloud runner, or a desktop.

GitHub Actions may compile/test the application and publish build artifacts. It is not part of the conversion path.

Nusa and Swapp are technical references, not products to patch or repackage. Do not replace files in the Nusa IPA, depend on Nusa's integrity checks, or ship Nusa binaries. Reimplement the required behavior using Box3/NXNative source and independently written glue.

## Existing assets and what they actually do

### Box3 / NXNative

The `bc-compact-fallback` branch is the starting point for this work because it contains the BC fallback work without the later Nusa-specific host-template experiment.

The repository already contains most of the game runtime:
- `dm/host`: Horizon-facing host and system-service implementation.
- `dm/gfx/nvn`, `dm/gfx/vk`, `dm/gfx/gl`: graphics translation/runtime.
- `dm/gfx/tex`: texture handling, including the software BC fallback work.
- `dm/games/<title-id>`: per-game compatibility profiles, patch data, shader maps, and metadata.
- `dm/ios/Sources`: the iOS game runtime shell, Metal view, virtual gamepad, launcher, and startup.
- `dm/ios/tools/pack_ipa.py`: ZIP/IPA packaging logic that can be adapted to a native iOS implementation.

The existing iOS app is a **game runtime**, not a general-purpose converter. Its build embeds one game's rewritten modules and profile resources into a generated Xcode project.

### Desktop-only conversion pieces that must be replaced or ported

The existing end-to-end build is not on-device:
- `dm/tools/nx_extract/Program.cs` is a .NET/LibHac command-line extractor for NSP/XCI, NCA, ExeFS, RomFS, update overlays, and DLC.
- `dm/tools/patch_nso.py` is a Python NSO/NRO rewriter. It depends on Python modules including LZ4 and Capstone and emits patched module images plus fixup/gate/cut/observation tables.
- Shader preparation uses the Ryujinx shader translator, SPIRV-Cross, game-specific shader data, and the Metal compiler.
- `dm/ios/tools/build_ipa.sh` invokes host-side Python tools, generates source/resource files, and calls Xcode.
- `dm/ios/tools/pack_ipa.py` is a Python ZIP writer. Its archive semantics are useful, but it cannot be called as-is from a native iOS app.

The new app must not shell out to these desktop tools. Port or compile their required functionality into libraries callable in-process on iOS.

## Lessons from Swapp and Nusa

### Swapp / Cuphead prototype

The prototype established useful early stages: importing game inputs, extracting NSP/DLC content, inspecting executables, and extracting the game's shader inventory. The Cuphead profile documented approximately 13,057 shaders building for iOS, but the prototype had not completed the full executable rewrite, shader translation/Metal compilation, or IPA packaging pipeline.

This is a useful validation case for the new pipeline, but the architecture must not be Cuphead-only.

### Nusa

Nusa demonstrates that the user-facing workflow and conversion can live in an iOS app. Binary analysis identified a converter/runtime split, dynamic guest-module loading through `Frameworks/GameModules.dylib`, and a separate shader-translation library (`dmsh_xlate_ios.dylib`). These are architectural clues only; their exact formats, calling conventions, and error handling still need to be mapped before any compatible implementation is written.

Nusa's shader translator is not the BC texture decoder. The A16 limitation is missing native BC texture formats; the Box3 software BC decode/fallback must remain in the new runtime.

### Nusa binary/component map from the public beta analysis

| Nusa component | Observed role | What the new app should learn from it |
|---|---|---|
| `NXConverter` | Main conversion executable in the app bundle | Keep conversion orchestration separate from the game runtime; reproduce required formats in our own source |
| `GameHostTemplate.bin` | Generic game-host/runtime template | Build one generic Box3 host rather than compiling a host executable per game |
| `ProbeTemplate.bin` | Separate probe/runtime template | Keep any preflight or compatibility-probe role separate from the converter and game host |
| `Frameworks/GameModules.dylib` | Dynamically loaded rewritten guest modules | Define a versioned module bundle and loader contract for rewritten main/sdk/subsdk modules |
| `Frameworks/dmsh_xlate_ios.dylib` | Shader translation library, with `dmsh_xlate_translate` / `dmsh_xlate_free` entry points observed in analysis | Study the in-process shader translation boundary; this is not a BC texture decoder |
| `HostResources/dm`, `HostResources/gl` | Runtime data such as shader maps, MSL, fonts, and configuration | Make runtime resources explicit, relocatable, and validated by a manifest |

The beta's host contained a fatal path for devices without native BC texture formats. That is why the new app must use Box3's BC software fallback in its own generic host. The previous experiment that replaced Nusa's host template is abandoned; none of its modified Nusa files are part of this branch.

## Proposed app architecture

Keep the app modular. UI code must orchestrate native conversion services and display progress; it must not contain file-format logic.

1. **iOS UI and job coordinator (Swift / SwiftUI)**
   - Import `prod.keys`, base NSP/XCI, optional update, and optional DLC with document pickers.
   - Persist user selections as security-scoped bookmarks where supported; copy inputs into an app-managed job workspace when necessary.
   - Validate required inputs before enabling Convert.
   - Show named stages, byte/file progress, cancellation, resumable checkpoints, and actionable errors.
   - Never upload inputs or keys.

2. **Package and content reader (native library)**
   - Read PFS0/HFS0 containers and XCI secure partitions.
   - Parse tickets, key sets, NCA headers/sections, and content metadata.
   - The raw NCA header (0xC00 bytes) is AES-XTS encrypted as six 0x200-byte data units. The XTS data-unit number is encoded using Nintendo's big-endian tweak convention (distinct from IEEE 1619's little-endian sequence-number representation). The new `AESXTS` implementation uses CommonCrypto's AES-ECB primitive and implements the XTS transform in Swift; `NCAHeader` continues to parse plaintext only.
   - The implementation is covered by an IEEE 1619 known-answer vector, plus independent full-sector AES-XTS known-answer vectors for Nintendo-style big-endian sector tweaks (sectors 0, 1, and 5). Those independent vectors verify the complete 0x200-byte ciphertext for each sector, not merely encrypt/decrypt round-tripping. It still needs comparison against hactool/LibHac output from a legally owned NCA fixture before it is treated as validated NCA decryption.
   - A local-only reference checker is available as the `nca-header-reference-check` Swift package executable. Supply the first 0xC00 bytes of a legally owned encrypted NCA, a 0xC00-byte plaintext header independently emitted by hactool/LibHac, and set `NCA_HEADER_KEY_HEX` in the local environment. It reports the first differing byte and never prints the key. No fixture, key, or game dump is stored in the repository or sent to CI.
   - Then implement NCA key-area decryption, title-key/ticket handling, AES-CTR/AES-CTR-Ex section reads, integrity verification, and BKTR update overlays. These are separate crypto/storage layers, not one generic decrypt operation.
   - Decrypt and verify NCA content; layer the selected update over the base program; extract DLC independently.
   - Preserve control metadata (NACP, icon, version, title ID) for the generated app.
   - Initial implementation should port the narrow, proven LibHac paths used by `nx_extract`; do not attempt an unrelated full Switch filesystem rewrite.

3. **Executable preparation (native library)**
   - Decompress NSO segments and handle NRO modules.
   - Port the existing NSO rewriter's instruction decoding, assertions, patch tables, relocation/fixup metadata, and output format.
   - Keep per-game profiles and build-ID-guarded patches data-driven.
   - Rewriter output must be byte-checked and schema-checked before the runtime accepts it.

4. **Shader pipeline (native iOS libraries)**
   - Extract and classify shader containers from the game's assets.
   - Port or compile the required Ryujinx translation stages so Maxwell/NVN shaders can be translated on-device.
   - Convert SPIR-V to MSL with SPIRV-Cross or an equivalent in-process library.
   - Cache translated MSL by source/profile/translator version. Apple documents `MTLDevice.makeLibrary(source:options:)` as compiling MSL source at runtime; this gives us an on-device route without `xcrun metal`.
   - Adapt the Box3 runtime to load/compile MSL source strings instead of requiring the desktop pipeline's prebuilt `.metallib` files. Use Metal binary archives for pipeline-state caching where supported.
   - Preserve separate Vulkan/OpenGL paths where a game uses them; do not assume every game is NVN.
   - Reuse precomputed profile data where available, but do not require a Mac-generated per-game shader library for the on-device workflow.
   - Validate runtime source compilation performance and API behavior on the actual iPhone 14 before committing to the final cache format.

5. **Runtime assembly and resource staging**
   - Build a generic Box3 host/runtime that loads rewritten guest modules and per-game resources from the job output, rather than compiling a different executable for every game.
   - Load the BC software fallback in the runtime path for devices without native BC support.
   - Keep game-specific profile data, shader maps, fixup tables, fonts, RomFS, and AOC in explicit versioned resource locations.
   - Nusa's dynamic module-loading model is a reference for this separation; implement and test our own loader contract.

6. **IPA and game-data packaging**
   - Produce an unsigned IPA with a valid `Payload/<App>.app` layout, correct executable permissions, Info.plist, icons, embedded runtime, and required resources.
   - Keep very large RomFS data in an external app Documents folder or a sharded archive where appropriate; make the generated app able to locate and mount it.
   - Verify ZIP integrity, required paths, Mach-O architecture, resource manifests, and module/fixup consistency before presenting the IPA.
   - Leave signing to the user's sideloading tool (for example, SideStore); do not claim the unsigned IPA is install-ready.

## Implementation sequence and acceptance gates

### Gate A — source/format inventory
- Record every desktop command and output contract used by the current build.
- Map Nusa's input/output formats and converter/runtime boundary from the public beta binary.
- Map the Swapp prototype's current code and exact Cuphead stopping point.
- Deliver a dependency and licensing inventory before copying or porting third-party code.

### Gate B — native import/extraction
- Implement on-device key parsing, PFS0/HFS0/XCI reading, AES-XTS NCA header decryption, NCA key-area/title-key handling, AES-CTR section decryption, integrity verification, update layering, and DLC extraction.
- Validate the decrypted NCA header against LibHac/hactool reference output, then validate extracted ExeFS/RomFS manifests and hashes from legally owned test dumps.
- Test large files, interrupted jobs, low free storage, and app suspension.

### Gate C — native executable rewrite
- Port NSO/NRO rewrite and metadata generation.
- Require deterministic output and regression tests against the current Python rewriter for supported fixtures.
- Refuse unsupported/unknown build layouts rather than silently generating a likely-broken IPA.

### Gate D — on-device shader build
- Complete Cuphead as the first end-to-end shader test, then validate at least one non-Unity/NVN title to prove the architecture is generic.
- Compare generated SPIR-V/MSL and Metal compile results with the existing desktop reference pipeline.
- Persist caches and resume safely after interruption.

### Gate E — generic runtime and packaging
- Load multiple guest modules dynamically from app-managed files.
- Package and verify an unsigned IPA entirely on-device.
- Confirm the BC fallback on A16 hardware with actual gameplay, not just unit tests.

### Gate F — broader game support
- Use profiles and compatibility reports to expand beyond Cuphead.
- Add XCI/NSZ/XCZ support only after the NSP path is reliable and memory-safe.

## Non-negotiable constraints

- No cloud or GitHub Actions conversion.
- No Nusa IPA modification or dependence on Nusa's app integrity checks.
- No game-specific hardcoding in the generic converter.
- No claims of device validation until a build is tested on the actual iPhone/iPad.
- Preserve the BC fallback and its regression tests.
- Keep user keys and game dumps local to the device.

## Immediate next engineering task

Continue Gate B with independent NCA crypto layers: run the local reference checker against hactool/LibHac output from a legally owned fixture, resolve any byte mismatch, then add NCA key-area and title-key handling with independent reference tests. Do not proceed to CTR sections until the header and key derivation stages have byte-for-byte reference tests.
