//! Frame step stubs and build-specific stubs ("Frame step in whole vsyncs" and "Stubs" of `patch_nso.py`): code a fix
//! needs in the patch area, branched to from its sites, assembled by a per-build function of the engine's patch files
//! (FRAME_STEP / STUBS of `dm/games/<id>/patches.py`), or by the one placed by the function it patches (MATCH_FRAME_STEP /
//! MATCH_STUBS rules, `nso_match.locate_stub`).
//!
//! Those functions are code, not data, so they are ported by hand (`stubs_games/`, one file per game); the data around them
//! (build IDs, rules, fingerprints) is generated (`tables.rs`). A build whose patch file has such a function that is not
//! ported (or whose port is older than the tables) stops the rewrite with a message that names the game and the build and
//! asks for an app update, instead of rewriting without it.

use crate::matching::{Function, Image, MatchError};
use crate::patches::{self, MatchRule};
use crate::rewriter::Rw;
use crate::stubs_games;
use crate::tables;
use crate::{Fail, Res};

/// What a stub function may do (`ctx` of the Python): assemble into the patch area, assert and write sites
pub struct StubCtx<'a, 'o> {
    pub rw: &'a mut Rw<'o>,
    /// the frame step's state page (0 for plain stubs)
    pub state: i64,
    pub base: i64,
    pub render_scale: i64,
    pub step_max: i64,
    pub capabilities: Vec<String>,
    pub fps_ready: bool,
    /// `ctx.others` of a MATCH_FRAME_STEP rule: label -> start of that function, None (a red line) when it did not match
    pub others: Vec<(&'static str, Option<i64>)>,
    /// `ctx.found` of an anchored rule: what its `find` returned (a site offset and a register)
    pub found: Option<(i64, i64)>,
    /// plain stubs or frame step stubs: the reason suffix of `put` and the stat name
    suffix: &'static str,
    stat: &'static str,
}

impl StubCtx<'_, '_> {
    /// `ctx.others.get(label)`: the start of the other function, None when the rule names none or it did not match
    pub fn other(&self, label: &str) -> Option<i64> {
        self.others
            .iter()
            .find(|(l, _)| *l == label)
            .and_then(|(_, o)| *o)
    }
    pub fn here(&self) -> i64 {
        self.rw.here()
    }
    pub fn emit(&mut self, w: u32) {
        self.rw.emit(w);
    }
    /// `ctx.capabilities.add(name)`
    pub fn add_capability(&mut self, name: &str) {
        if !self.capabilities.iter().any(|c| c == name) {
            self.capabilities.push(name.to_string());
        }
    }
    /// asserts a site's original bytes and that it is no rewrite site
    pub fn site(&mut self, off: i64, orig: &str) -> Res<()> {
        let what = if self.stat == "frame_step" {
            "frame step"
        } else {
            "stub"
        };
        let ob = crate::matching::unhex(orig);
        let cur = if off < 0 {
            None
        } else {
            self.rw.img.b.get(off as usize..off as usize + ob.len())
        };
        if cur != Some(&ob[..]) {
            return Err(Fail::new(format!(
                "{what} original bytes mismatch {off:#x}: {}",
                cur.map(crate::matching::hex).unwrap_or_default()
            )));
        }
        let mut o = off;
        while o < off + ob.len() as i64 {
            if self.rw.kind_at(o).is_some() || self.rw.in_window(o) {
                return Err(Fail::new(format!("{what} site is a rewrite site {o:#x}")));
            }
            o += 4;
        }
        Ok(())
    }
    /// writes words at a site (listed with the cuts)
    pub fn put(&mut self, off: i64, words: &[u32], why: &str) {
        let old =
            crate::matching::hex(&self.rw.img.b[off as usize..off as usize + 4 * words.len()]);
        for (i, w) in words.iter().enumerate() {
            self.rw.img.set(off + 4 * i as i64, *w);
        }
        let new =
            crate::matching::hex(&self.rw.img.b[off as usize..off as usize + 4 * words.len()]);
        self.rw.cuts.push(crate::rewriter::CutRow {
            off,
            old,
            new,
            why: format!("{why}{}", self.suffix),
        });
        self.rw.stat(self.stat);
    }
    /// the data address an adrp there and the add / load / store after it make, read from the original text
    pub fn address(&self, off: i64, lo_off: Option<i64>) -> Res<i64> {
        let what = if self.stat == "frame_step" {
            "frame step"
        } else {
            "stub"
        };
        let lo_off = lo_off.unwrap_or(off + 4);
        if !(lo_off > off && (off | lo_off) & 3 == 0) {
            return Err(Fail::new(format!(
                "{what}: invalid address instruction offsets"
            )));
        }
        let (a, b) = (self.rw.img.orig_word(off), self.rw.img.orig_word(lo_off));
        if a & 0x9f000000 != 0x90000000 {
            return Err(Fail::new(format!("{what}: no adrp at {off:#x}")));
        }
        let imm = ((((a >> 5) & 0x7ffff) << 2 | (a >> 29) & 3) as i64) << 12;
        let page = (off & !0xfff)
            + if imm & (1 << 32) != 0 {
                imm - (1 << 33)
            } else {
                imm
            };
        if (b >> 5) & 31 != a & 31 {
            return Err(Fail::new(format!(
                "{what}: the low instruction at {lo_off:#x} does not use the adrp register"
            )));
        }
        if b & 0xffc00000 == 0x91000000 {
            return Ok(page + ((b >> 10) & 0xfff) as i64);
        }
        if b & 0x3b000000 != 0x39000000 {
            return Err(Fail::new(format!(
                "{what}: no add, load or store after the adrp at {off:#x}"
            )));
        }
        let scale = 1i64 << (b >> 30);
        Ok(page
            + ((b >> 10) & 0xfff) as i64
                * scale
                * if b & 0x04800000 == 0x04800000 && b >> 30 == 0 {
                    16
                } else {
                    1
                })
    }
}

pub type StubFn = fn(&mut StubCtx) -> Res<()>;
/// `find(fn)` of an anchored rule: reads the function that calls the anchor and returns what the stub needs (a site offset and a register), or a `MatchError`
pub type FindFn = fn(&Function) -> Result<(i64, i64), MatchError>;

/// The code of one `MATCH_FRAME_STEP` / `MATCH_STUBS` rule (its data is the `MatchRule` of the tables at the same position)
pub struct RulePort {
    pub stub: StubFn,
    pub find: Option<FindFn>,
}

/// What `locate_stub` found: the rule, its stub, the start of its function and of each of its others (None: no unique match), and what an anchored rule's `find` returned
pub struct FsMatch {
    pub rule: &'static MatchRule,
    pub stub: StubFn,
    pub start: i64,
    pub others: Vec<(&'static str, Option<i64>)>,
    pub found: Option<(i64, i64)>,
}

/// the name of the selected game profile (`os.path.basename(DM_GAME)`)
fn profile_name(rw: &Rw) -> String {
    rw.opts
        .game
        .as_deref()
        .map(|g| {
            g.trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default()
}

/// the refusal for a patch file's code that this build of the rewriter does not have: which game and build, and that it needs an app update
fn unported(rw: &Rw, profile: &str, table: &str) -> Fail {
    let game = tables::CODE_DIGESTS
        .iter()
        .find(|(p, _, _)| *p == profile)
        .map(|(_, g, _)| *g)
        .unwrap_or(profile);
    Fail::new(format!(
        "{game} ({profile}, {} build {}): its {table} patch is code that this version of the app does not include yet (not ported to Rust, or older than the engine's patch file), \
         so the module cannot be rewritten without it; update the app",
        rw.name, rw.build_id
    ))
}

/// the test hook of the differential tests (`stubs_games::difftest`): a registered fingerprint replaced by the one of a synthetic function (compiled in the unit tests only)
#[cfg(test)]
pub static TEST_FINGERPRINTS: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

/// the fingerprints a rule is looked up with
fn effective(fps: &[&str]) -> Vec<String> {
    #[allow(unused_mut)]
    let mut v: Vec<String> = fps.iter().map(|s| s.to_string()).collect();
    #[cfg(test)]
    for (from, to) in TEST_FINGERPRINTS.lock().unwrap().iter() {
        for f in v.iter_mut() {
            if f == from {
                *f = to.clone();
            }
        }
    }
    v
}

fn locate_fn(module: &mut Image, size: usize, fps: &[&str]) -> Result<i64, MatchError> {
    let v = effective(fps);
    let refs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
    module.locate(size, &refs)
}

/// `nso_match.locate_stub`: the one rule whose function matches (fingerprinted, or anchored on an imported symbol and checked by its `find`), with the start of each of its
/// other functions; None, with a red line, when the image does not parse or not exactly one rule matches. A rule's other function that does not match is left out (a red
/// line) and the rest still goes in.
fn locate_stub(
    rw: &mut Rw,
    rules: &'static [MatchRule],
    ports: &'static [RulePort],
) -> Res<Option<FsMatch>> {
    if rules.is_empty() {
        return Ok(None);
    }
    let name = rules[0].name;
    let repr = crate::matching::py_repr(name);
    let mut lines: Vec<String> = Vec::new();
    let result = {
        let mut module = match Image::new(&rw.img.b, rw.text_end) {
            Ok(m) => m,
            Err(e) => {
                lines.push(format!("[RED] frame step {repr} skipped: {}", e.0));
                for l in lines {
                    rw.say(l);
                }
                return Ok(None);
            }
        };
        let (mut found, mut misses) = (Vec::new(), Vec::new());
        for (i, (rule, port)) in rules.iter().zip(ports).enumerate() {
            let got: Result<(i64, Option<(i64, i64)>), MatchError> = match (rule.calls, port.find) {
                (Some(calls), Some(find)) => (|| {
                    let callers = module.callers(calls);
                    if callers.len() != 1 {
                        return Err(MatchError(format!(
                            "{} functions call {calls} (need exactly one)",
                            callers.len()
                        )));
                    }
                    let (start, sites) = callers.into_iter().next().unwrap();
                    let f = module.function(start, sites);
                    Ok((start, Some(find(&f)?)))
                })(),
                (Some(calls), None) => Err(MatchError(format!(
                    "the rule anchored on {calls} has no find in this port"
                ))),
                (None, _) => {
                    locate_fn(&mut module, rule.size, rule.fingerprints).map(|s| (s, None))
                }
            };
            match got {
                Ok((start, f)) => found.push((i + 1, rule, port, start, f)),
                Err(e) => misses.push(e.0),
            }
        }
        if found.len() != 1 {
            lines.push(format!(
                "[RED] frame step {repr} skipped: {}",
                if found.is_empty() {
                    misses.join("; ")
                } else {
                    format!("{} implementations match (need exactly one)", found.len())
                }
            ));
            None
        } else {
            let (i, rule, port, start, got) = found.remove(0);
            lines.push(format!(
                "frame step {repr}: matched the function at {start:#x}{}{}",
                rule.calls
                    .map(|c| format!(" (the one that calls {c})"))
                    .unwrap_or_default(),
                if rules.len() > 1 {
                    format!(" (implementation {i} of {})", rules.len())
                } else {
                    String::new()
                }
            ));
            let mut others = Vec::new();
            for (label, size, fps) in rule.others {
                match locate_fn(&mut module, *size, fps) {
                    Ok(o) => {
                        lines.push(format!("frame step {repr}: {label} at {o:#x}"));
                        others.push((*label, Some(o)));
                    }
                    Err(e) => {
                        others.push((*label, None));
                        lines.push(format!(
                            "[RED] frame step {repr}: {label} left out: {}",
                            e.0
                        ));
                    }
                }
            }
            Some(FsMatch {
                rule,
                stub: port.stub,
                start,
                others,
                found: got,
            })
        }
    };
    for l in lines {
        rw.say(l);
    }
    Ok(result)
}

/// The frame step of a main with no FRAME_STEP of its build, placed by the function it patches (MATCH_FRAME_STEP),
/// found before any cut changes the image; and the matched stubs (MATCH_STUBS)
pub fn locate(rw: &mut Rw) -> Res<()> {
    let profile = profile_name(rw);
    if rw.name == "main" && patches::frame_step_profile(&rw.build_id).is_none() {
        let rules = patches::match_frame_step_rules(&profile, &rw.name);
        if !rules.is_empty() {
            let Some(ports) = stubs_games::match_rules(&profile, &rw.name, false) else {
                return Err(unported(rw, &profile, "MATCH_FRAME_STEP"));
            };
            rw.fs_match = locate_stub(rw, rules, ports)?;
        }
    }
    // Ordinary matched stubs do not declare a frame step. Keep their FPS dependency separate: finding the engine interval alone does not prove every consumer scales.
    let rules = patches::match_stub_rules(&profile, &rw.name);
    rw.native_fps_blocked = rules.iter().any(|r| r.fps_required);
    if !rules.is_empty() && patches::stubs_profile(&rw.build_id).is_none() {
        let Some(ports) = stubs_games::match_rules(&profile, &rw.name, true) else {
            return Err(unported(rw, &profile, "MATCH_STUBS"));
        };
        rw.stub_match = locate_stub(rw, rules, ports)?;
    }
    Ok(())
}

/// whether the build gets the frame step state page (`BUILD_ID in FRAME_STEP or FS_MATCH`)
pub fn has_frame_step(rw: &Rw) -> bool {
    patches::frame_step_profile(&rw.build_id).is_some() || rw.fs_match.is_some()
}

/// A chosen stub set: (function, base, other labels, found range, suffix).
type StubChoice = (
    StubFn,
    i64,
    Vec<(&'static str, Option<i64>)>,
    Option<(i64, i64)>,
    &'static str,
);

/// The frame step stubs and the build's stubs, in that order
pub fn emit(rw: &mut Rw) -> Res<()> {
    if rw.name == "main" && has_frame_step(rw) {
        // the build's stubs (FRAME_STEP of its patches.py), or those placed by their function (MATCH_FRAME_STEP: ctx.base is its start)
        let (f, base, others, found, suffix): StubChoice = match &rw.fs_match {
            Some(m) => (
                m.stub,
                m.start,
                m.others.clone(),
                m.found,
                " [function match]",
            ),
            None => {
                let Some(f) = stubs_games::frame_step(&rw.build_id) else {
                    let profile = patches::frame_step_profile(&rw.build_id).unwrap_or("");
                    return Err(unported(rw, profile, "FRAME_STEP"));
                };
                (f, 0, Vec::new(), None, "")
            }
        };
        rw.fs_state_off = rw.key_page_off + 0x4000;
        if rw.far {
            // the loader supplies zero-filled BSS/key pages for a front patch area: reserve the frame state after the key page there too
            rw.image_size = rw.fs_state_off + 0x4000;
        }
        let st = rw.fs_state_off;
        let tail_zero = rw
            .img
            .b
            .get(st as usize..)
            .map(|t| t.iter().all(|&x| x == 0))
            .unwrap_or(true);
        if !(st % 0x1000 == 0 && (rw.far || st + 0x40 <= rw.patch_off) && tail_zero) {
            return Err(Fail::new("frame step state page"));
        }
        rw.use_area(0);
        let mut ctx = StubCtx {
            rw,
            state: st,
            base,
            render_scale: 0,
            step_max: 0,
            capabilities: Vec::new(),
            fps_ready: false,
            others,
            found,
            suffix,
            stat: "frame_step",
        };
        f(&mut ctx)?;
        let (rs, sm, caps) = (ctx.render_scale, ctx.step_max, ctx.capabilities);
        rw.render_scale = rs;
        rw.step_max = sm;
        rw.fs_capabilities = caps;
    }
    let registered = patches::stubs_profile(&rw.build_id);
    if registered.is_some() || rw.stub_match.is_some() {
        let (f, base, others, found, suffix): StubChoice = match &rw.stub_match {
            Some(m) => (
                m.stub,
                m.start,
                m.others.clone(),
                m.found,
                " [function match]",
            ),
            None => {
                let Some(f) = stubs_games::stubs(&rw.build_id) else {
                    return Err(unported(rw, registered.unwrap_or(""), "STUBS"));
                };
                (f, 0, Vec::new(), None, "")
            }
        };
        rw.use_area(0);
        let mut ctx = StubCtx {
            rw,
            state: 0,
            base,
            render_scale: 0,
            step_max: 0,
            capabilities: Vec::new(),
            fps_ready: false,
            others,
            found,
            suffix,
            stat: "stub",
        };
        f(&mut ctx)?;
        if ctx.fps_ready {
            rw.native_fps_blocked = false;
        }
    }
    Ok(())
}
