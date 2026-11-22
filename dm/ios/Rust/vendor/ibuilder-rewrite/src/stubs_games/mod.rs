//! Ports of the per-game stub functions of the engine's `dm/games/<id>/patches.py`: the code-valued part of `FRAME_STEP`, `STUBS`, `MATCH_FRAME_STEP` and `MATCH_STUBS`.
//!
//! The data around them (which build IDs have a stub, each rule's name, size, fingerprints and `others`, the `fps_required` flag) is generated into `tables.rs` by
//! `tools/gen_patch_tables.py`; only the functions are ported by hand, one file per game, each with a [`GamePort`] that lists them. A port records the code digest of the
//! patch file it was verified against (`digest`, the one `tables::CODE_DIGESTS` carries): when an engine update changes the stub code, regenerating the tables changes the
//! digest, the port no longer applies (the rewrite stops with a message that asks for an app update instead of running a stale port), and `tests/patch_coverage.rs` /
//! `scripts/check-patch-coverage.sh` fail until the port is redone, differential-tested (`tools/stubtest.py`) and given the new digest.

use crate::stubs::{RulePort, StubFn};
use crate::tables;

mod acnh;
mod aoc;
mod astral;
mod botw;
mod hades;
mod kirby;
mod mkworld;
mod ocarina;
mod ori;
mod pokopia;
mod totk;
mod ttyd;
mod xenox;

#[cfg(all(test, feature = "oracle-tests"))]
mod difftest;

/// What one game's patch file registers as code, ported
pub struct GamePort {
    /// the game profile (the folder of `patches.py`)
    pub profile: &'static str,
    /// the patch file's code digest this port was verified against (`tables::CODE_DIGESTS`)
    pub digest: &'static str,
    /// `FRAME_STEP`: (NSO build ID, stub)
    pub frame_step: &'static [(&'static str, StubFn)],
    /// `STUBS`: (NSO build ID, stub)
    pub stubs: &'static [(&'static str, StubFn)],
    /// `MATCH_FRAME_STEP`: (module, the stubs of its rules in the file's order)
    pub match_frame_step: &'static [(&'static str, &'static [RulePort])],
    /// `MATCH_STUBS`: (module, the stubs of its rules in the file's order)
    pub match_stubs: &'static [(&'static str, &'static [RulePort])],
}

/// every ported game, in profile order
pub static PORTS: &[&GamePort] = &[
    &aoc::PORT,
    &xenox::PORT,
    &acnh::PORT,
    &astral::PORT,
    &botw::PORT,
    &ori::PORT,
    &hades::PORT,
    &kirby::PORT,
    &ttyd::PORT,
    &totk::PORT,
    &ocarina::PORT,
    &pokopia::PORT,
    &mkworld::PORT,
];

/// the port of a game profile, when its digest is the one of the patch file the tables were generated from
pub fn port(profile: &str) -> Option<&'static GamePort> {
    let current = tables::CODE_DIGESTS
        .iter()
        .find(|(p, _, _)| *p == profile)
        .map(|(_, _, d)| *d)?;
    PORTS
        .iter()
        .copied()
        .find(|g| g.profile == profile && g.digest == current)
}

/// `FRAME_STEP[build_id]` of the patch files, when ported
pub fn frame_step(build_id: &str) -> Option<StubFn> {
    let profile = crate::patches::frame_step_profile(build_id)?;
    port(profile)?
        .frame_step
        .iter()
        .find(|(b, _)| *b == build_id)
        .map(|(_, f)| *f)
}

/// `STUBS[build_id]` of the patch files, when ported
pub fn stubs(build_id: &str) -> Option<StubFn> {
    let profile = crate::patches::stubs_profile(build_id)?;
    port(profile)?
        .stubs
        .iter()
        .find(|(b, _)| *b == build_id)
        .map(|(_, f)| *f)
}

/// the ported stubs of a profile's `MATCH_FRAME_STEP` (`stub_rules == false`) or `MATCH_STUBS` rules of a module, one per rule of `tables`, when ported
pub fn match_rules(profile: &str, module: &str, stub_rules: bool) -> Option<&'static [RulePort]> {
    let g = port(profile)?;
    let list = if stub_rules {
        g.match_stubs
    } else {
        g.match_frame_step
    };
    let ports = list.iter().find(|(m, _)| *m == module).map(|(_, r)| *r)?;
    let want = if stub_rules {
        crate::patches::match_stub_rules(profile, module).len()
    } else {
        crate::patches::match_frame_step_rules(profile, module).len()
    };
    (ports.len() == want).then_some(ports)
}

/// `struct.pack('<f', value)` read back as an int: the bits of the float32 nearest to `value`
pub fn f32_bits(value: f64) -> u32 {
    (value as f32).to_bits()
}

/// `int.from_bytes(bytes.fromhex(hex), 'little')` of a word's 8 hex digits
pub fn orig_word(hex: &str) -> u32 {
    u32::from_le_bytes(crate::matching::unhex(hex).try_into().unwrap())
}

/// `struct.pack('<I', w).hex()`: the instruction word as the bytes of the module, in hex
pub fn word_hex(w: u32) -> String {
    w.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// the rows `ibuilder-rewrite --list-ported` prints, in the format of `tools/gen_patch_tables.py --coverage` (kind, profile or file, key, code digest, game): what this build
/// of the rewriter can rewrite. Data tables by key (they are generated, so they only differ from the engine's when `tables.rs` is stale), code-valued tables only when their
/// stub functions are ported and up to date with the tables
pub fn coverage_rows() -> Vec<[String; 5]> {
    let name_of = |p: &str| {
        tables::CODE_DIGESTS
            .iter()
            .find(|(q, _, _)| *q == p)
            .map(|(_, g, _)| g.to_string())
            .unwrap_or_else(|| "-".to_string())
    };
    let mut rows: Vec<[String; 5]> = Vec::new();
    let mut add = |kind: &str, who: &str, key: String, digest: &str| {
        rows.push([
            kind.to_string(),
            who.to_string(),
            key,
            digest.to_string(),
            name_of(who),
        ])
    };
    for (b, who, _) in tables::CUTS {
        add("CUTS", who, b.to_string(), "-");
    }
    for (b, _) in tables::OBS {
        add("OBS", "-", b.to_string(), "-");
    }
    for (b, _) in tables::CAPABILITIES {
        add("CAPABILITIES", "-", b.to_string(), "-");
    }
    for (module, rules) in tables::SDK_MATCH_CUTS {
        for r in *rules {
            add("MATCH_CUTS", "sdk", format!("{module}:{}", r.name), "-");
        }
    }
    for (profile, mods) in tables::PROFILE_MATCH_CUTS {
        for (module, rules) in *mods {
            for r in *rules {
                add("MATCH_CUTS", profile, format!("{module}:{}", r.name), "-");
            }
        }
    }
    for (b, profile) in tables::FRAME_STEP {
        if let Some(g) = port(profile).filter(|g| g.frame_step.iter().any(|(k, _)| k == b)) {
            add("FRAME_STEP", profile, b.to_string(), g.digest);
        }
    }
    for (b, profile) in tables::STUBS {
        if let Some(g) = port(profile).filter(|g| g.stubs.iter().any(|(k, _)| k == b)) {
            add("STUBS", profile, b.to_string(), g.digest);
        }
    }
    for (kind, list, stub_rules) in [
        ("MATCH_FRAME_STEP", tables::MATCH_FRAME_STEP, false),
        ("MATCH_STUBS", tables::MATCH_STUBS, true),
    ] {
        for (profile, module, rules) in list {
            if match_rules(profile, module, stub_rules).is_some() {
                let digest = port(profile).map(|g| g.digest).unwrap_or("-");
                for (i, r) in rules.iter().enumerate() {
                    add(kind, profile, format!("{module}#{i}:{}", r.name), digest);
                }
            }
        }
    }
    rows.sort();
    rows
}
