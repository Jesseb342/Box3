# Reuse assessment: Nusa architecture and Box3 implementation

Date: 2026-11-21
Working branch: `ios-on-device-converter`

## Scope and evidence

The independent app must remain a new Box3 application. The available Nusa evidence in this branch is the previously analyzed public beta binary/component map; this branch does not currently contain Nusa source files, Nusa Swift packages, or Nusa build targets. Repository branch inventory also contains no Nusa-source branch. Therefore, do not describe Nusa implementation code as already reusable until an actual source checkout/archive is located and its license and build requirements are verified.

This does not prevent reuse of the existing Box3/NXNative source. The strongest immediate reuse is already in this repository.

## Reuse matrix

| Capability | Existing source/evidence | Reuse decision | Remaining work |
|---|---|---|---|
| Game runtime and Horizon service layer | `dm/host` | Reuse Box3 runtime; adapt loading boundary | Make host generic and load generated modules/resources |
| Graphics translation | `dm/gfx/nvn`, `dm/gfx/vk`, `dm/gfx/gl` | Reuse Box3 graphics stack | iOS runtime integration and runtime shader-library loading |
| BC texture fallback | `dm/gfx/tex` and the known-good BC fallback baseline | Preserve and reuse | Verify the actual iPhone 14 gameplay path |
| Game profiles/patch data | `dm/games/<title-id>` | Reuse as data, not hardcoded converter logic | Define versioned profile/resource manifest |
| IPA layout semantics | `dm/ios/tools/pack_ipa.py` | Port the archive/layout rules | Native Swift packager and structural verifier |
| NSP/NCA extraction | `dm/tools/nx_extract/Program.cs` using LibHac | Reuse behavior/specification; port required LibHac path to an iOS-callable native library | Crypto reference validation, key-area/title-key, CTR, integrity, BKTR, filesystem |
| NSO/NRO rewrite | `dm/tools/patch_nso.py`, `nso_asm.py`, game patch modules | Reuse algorithm and patch tables as reference; port to native code | LZ4, AArch64 decoder/encoder, deterministic output parity |
| Nusa conversion orchestration | Public beta binary analysis only | Reproduce the architectural separation, not binary code | Need actual Nusa source or a fully documented input/output contract |
| Nusa generic host | Public beta binary analysis only | Use as design reference for generic host/module boundary | Implement Box3's own host and loader |
| Nusa shader translator | Public beta binary analysis only; observed `dmsh_xlate_translate` / `dmsh_xlate_free` boundary | No code reuse claim until source/license/API contract is available | Prefer Box3/Ryujinx + SPIRV-Cross native pipeline |
| Nusa BC decoder | No evidence that Nusa's shader translator performs BC decoding | Do not depend on it | Retain Box3 software BC fallback |

## Key conclusion

Nusa can save architectural discovery and product-design time, but its analyzed binary is not a source-code dependency. The directly reusable implementation is primarily the existing Box3/NXNative runtime, graphics stack, BC fallback, profiles, and desktop conversion algorithms.

Do not copy or link Nusa binaries, bypass its integrity checks, or make the new app depend on its app bundle. If a Nusa source archive becomes available, first inventory its files, license, dependencies, platform assumptions, and public interfaces; only then classify specific source modules as portable.

## Immediate implementation sequence

1. Keep the NCA cryptography gate closed until the local checker matches a real independently decrypted header. Do not add more crypto layers based only on self-generated vectors.
2. Define a versioned, game-agnostic module/resource manifest for the Box3 host. It must enumerate rewritten main/sdk/subsdk modules, fixup/gate/site metadata, game profile, shader assets, RomFS/AOC roots, title metadata, and BC fallback capability.
3. Implement a Swift manifest parser/validator with strict path containment, duplicate rejection, required-module checks, schema versioning, and hashes for staged files.
4. Port NSO rewrite as a separate native library with regression fixtures against the existing Python output. Keep the current Python implementation as a reference only; the iOS app must not invoke Python.
5. Build the native iOS staging/packaging layer around the generic manifest and existing Box3 runtime. Conversion stays entirely on-device; CI only compiles and tests code.

## Acceptance criteria for the next milestone

- Manifest parser rejects traversal, absolute paths, duplicate logical module names, unknown schema versions, missing required main module, and hash mismatches.
- Manifest round-trips deterministically.
- A fixture manifest can describe more than one game's module names without title-specific branches in the parser.
- CI compiles/tests the Swift package.
- No Nusa binary, key, or game dump is added to the repository.
