#!/usr/bin/env python3
"""Build a Nusa-compatible, BC-fallback iOS host template.

The converter supplies guest modules separately as Frameworks/GameModules.dylib.
This build therefore deliberately leaves Gen/embed.S without guest modules;
the iOS bootstrap loads that external Mach-O image before the host loader runs.

Requires Xcode and XcodeGen. No game dump, keys, shaders, signing or device is
needed. GAME selects a compile-time profile only; it does not embed that
profile's guest modules or game resources.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "dm/games"))
import game


def run(project, env, *command, capture=False):
    return subprocess.run(
        [str(c) for c in command], cwd=project, env=env, check=True,
        text=True, stdout=subprocess.PIPE if capture else None,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="new output directory; must not already exist")
    args = parser.parse_args()

    profile = game.load(os.environ.get("GAME") or os.environ.get("DM_GAME") or "010015100B514000")
    root = args.output.resolve()
    root.mkdir(parents=True)
    ios = REPO / "dm/ios"
    project = root / "project"
    gen = project / "Gen"
    (gen / "dm").mkdir(parents=True)
    for name in ("Sources", "tools"):
        (project / name).symlink_to(ios / name, target_is_directory=True)
    shutil.copyfile(ios / "project.yml", project / "project.yml")
    assets = gen / "Assets.xcassets"
    assets.mkdir()
    (assets / "Contents.json").write_text(json.dumps({"info": {"author": "xcode", "version": 1}}))

    env = dict(
        os.environ, GAME=profile.id, DM_GAME=profile.id,
        DM_BUNDLE_ID="org.nxnative.nusa-template",
        DM_DISPLAY_NAME="Nusa BC Host Template", DM_APP_VERSION="1.0",
        DM_APP_CATEGORY=profile.get("app_category"), DM_TEAM_ID="",
        DM_SCHEME_NAME="DmIOS", DM_APPICON="", DM_SHOW_FPS="NO", DM_LANG="en-US",
    )

    # No guest code is embedded here. Nusa creates GameModules.dylib from the
    # converted game's rewritten modules, and main.m selects that image at boot.
    (gen / "embed.S").write_text(
        "// Nusa guest modules are loaded from Frameworks/GameModules.dylib.\n"
        ".section __TEXT,__text,regular,pure_instructions\n"
    )
    config = run(project, env, sys.executable, ios / "tools/gen_build.py",
                 REPO / "dm/host", gen, capture=True).stdout
    (gen / "dm.xcconfig").write_text(
        config + "OTHER_LDFLAGS = $(inherited) $(DM_FRAMEWORKS)\n"
    )
    run(project, env, "xcodegen", "generate")

    # Exercise the production resource-staging phase with harmless fixture data.
    romfs = root / "romfs-fixture"
    shaders = root / "shader-fixture"
    romfs.mkdir()
    shaders.mkdir()
    marker = "nusa-template-fixture.txt"
    (romfs / marker).write_text("Synthetic build fixture; not game data.\n")
    (shaders / marker).write_text("Synthetic build fixture; not a shader library.\n")
    chain_h = REPO / "dm/gfx/nvn/dmsh_chain.h"
    chain = next(
        line.split('"')[1] for line in chain_h.read_text().splitlines()
        if line.startswith('#define DMSH_CHAIN "')
    )
    derived = root / "derived"
    run(project, env, sys.executable, ios / "tools/gen_resources.py",
        project, romfs, marker, shaders, f"b-{chain}", "", derived, chain_h)
    run(project, env, "xcodebuild", "-project", project / "DmIOS.xcodeproj",
        "-scheme", "DmIOS", "-configuration", "Release",
        "-destination", "generic/platform=iOS", "-derivedDataPath", derived,
        "-jobs", "3", "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO",
        "CODE_SIGN_IDENTITY=", f"DM_XCODE_OUTPUT_ROOT={derived}",
        f"SYMROOT={derived}/Build/Products",
        f"OBJROOT={derived}/Build/Intermediates.noindex", "build")

    app = derived / "Build/Products/Release-iphoneos/DmIOS.app"
    info = plistlib.loads((app / "Info.plist").read_bytes())
    executable = app / info["CFBundleExecutable"]
    if not executable.is_file():
        raise RuntimeError(f"Missing linked host executable: {executable}")
    for source, packed in (
        (romfs / marker, app / "romfs" / marker),
        (shaders / marker, app / "msl" / f"b-{chain}" / marker),
    ):
        if source.read_bytes() != packed.read_bytes():
            raise RuntimeError(f"Resource staging failed: {packed}")
    if (app / "_CodeSignature").exists() or (app / "embedded.mobileprovision").exists():
        raise RuntimeError("Expected an unsigned host executable")

    binary = executable.read_bytes()
    required = (
        b"DM_TEST_NO_BC", b"DM_BC_SOFT", b"DM_NO_BC_ASTC",
        b"GameModules.dylib", b"boot: loaded external game modules",
        b"romfs.img", b"modules.txt", b"HostResources",
    )
    missing = [s.decode("ascii") for s in required if s not in binary]
    if missing:
        raise RuntimeError("Host is missing expected BC/Nusa integration markers: " + ", ".join(missing))
    forbidden = b"has no BC texture formats, which the games' textures use and the host does not decompress"
    if forbidden in binary:
        raise RuntimeError("The built host still contains the A17-only BC fatal path")
    out = root / "GameHostTemplate.bin"
    shutil.copyfile(executable, out)
    (root / "build-info.txt").write_text(
        f"source_branch=nusa-a16-bc-host\n"
        f"game_profile={profile.id}\n"
        f"host_source={REPO}\n"
        f"guest_modules=external Frameworks/GameModules.dylib\n"
        f"bc_fallback=enabled (DM_TEST_NO_BC / DM_BC_SOFT / DM_NO_BC_ASTC markers present)\n"
        f"romfs_image=Documents/romfs.img and bundled romfs.img supported\n"
        f"unsigned=true\n"
    )
    print(f"Nusa BC host template built: {out}", flush=True)


if __name__ == "__main__":
    main()
