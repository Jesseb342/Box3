# Swapp: single-game IPA packaging contract

Status: player-bundle staging and a ZIP64-capable single-IPA packager are implemented with synthetic tests; full conversion-to-IPA integration and device runtime validation remain outstanding.

Swapp's output is **one self-contained, unsigned IPA per game**. The archive must contain exactly one
`Payload/<GameName>.app/` tree. No RAR, sidecar archive, split IPA, separately installed RomFS, or
external game-data folder is an acceptable final output.

## Player bundle layout

The player runtime is based on the MIT-licensed iBuilder v0.1.2 player/export path
(`Absenti/iBuilder`, tag `v0.1.2`). Its source contract is documented in
`app/gameapp/GameAppExport.cs` and `app/gameapp/GameAppMain.cs`.

Required game-specific bundle content:

- `Frameworks/DmGameProbe.framework/DmGameProbe`: assembled game framework, with a matching framework
  `Info.plist`.
- `ExportedGame/manifest.tsv`: player marker and game identity (title ID, dump name, display name,
  app build/export metadata).
- `ExportedGame/extract/flat/`: rewritten module images and their runtime tables.
- `ExportedGame/extract/RomFS.img`: complete game RomFS, inside the IPA.
- `ExportedGame/shaders/<title-id>/`: the game's compiled shader library and required shader metadata.
- `ExportedGame/documents/profile.tsv` and any required profile-derived/settings data.
- `Info.plist`: unique bundle ID, game display name, and game icon.

The iBuilder player runtime detects `ExportedGame/manifest.tsv`, loads the framework from
`Frameworks/DmGameProbe.framework/DmGameProbe`, and reads the bundled RomFS when the manifest does
not declare an external RomFS. Swapp must use the **full** export path, not iBuilder's optional slim
export mode.

The app bundle template must include the matching player executable, host runtime, and required
frameworks/resources. A framework assembled for one host build must never be paired with a different
player/host build.

## Conversion handoff

1. Parse the selected base NSP and optional update/DLC packages.
2. Extract and verify the executable and RomFS content.
3. Rewrite all required executable modules and preserve the exact per-module runtime tables.
4. Assemble `DmGameProbe.framework/DmGameProbe` against the pinned, compatible iOS host.
5. Build the game's shader library and stage all profile/runtime metadata.
6. Clone the pinned player app template, replace its app identity and icon, and copy the complete game
   payload into `ExportedGame/`.
7. Write one IPA and validate the ZIP contents, bundle identity, framework Mach-O, required runtime
   resources, and the presence of `RomFS.img` **inside** the archive.

## BC texture requirement

For iPhone 14/A15, the default path must use the already-proven BC fallback from
`mianmuhammadse/nxnative` commit
`d158df611bf2f3fa315c4f16585575cdfdb2a1d3` (profile v0, 486 shaders). Do not substitute or depend
on iBuilder's separately described untested BC patch. The final player host and shader pipeline must
actually include this tested fallback; passing standalone BC decoder tests is not by itself proof of
end-to-end integration.

## Provenance and release checks

- Pin the player-template release, host binary, source commits, and SHA-256 values.
- Preserve the MIT notices and all other third-party licenses in the Swapp distribution.
- Fail closed if the framework host provenance does not match the player template's expected host.
- Do not include game dumps, `prod.keys`, `title.keys`, or other user secrets in CI artifacts or releases.
- Do not call an IPA beta-ready until a legally owned real game has been converted, the IPA has been
  installed with SideStore, and the game has launched successfully on the target iPhone.
