//! The rewriter's state and driver: the top-level program of `patch_nso.py` as `rewrite()`.
//!
//! Python's module-level globals live in [`Rw`]; the phases keep the order of the Python source (the order matters:
//! the image is read after earlier phases changed it, stats and log lines come out in that order).

use crate::detect::{
    fps_target, monolith, snowdrop, ue_cvar, ue_fixed_rate, ue_malloc, ue_region, ue_ring,
    unity_bucket, unity_fps,
};
use crate::matching::{self, Outcome, hex, unhex};
use crate::patches;
use crate::{Fail, Res, hx};
use ibuilder_a64::asm::{self, NOP};
use ibuilder_a64::bits::rd32;
use ibuilder_a64::cs::Ins;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub const KEY_K18: u32 = 0;
pub const KEY_KTLS: u32 = 1;
pub const KEY_KTLR: u32 = 2;
pub const KEY_KGATE: u32 = 3;

pub const OBS_UE_MALLOC: i64 = 21;
pub const OBS_REGION_ASK: i64 = 22;
pub const OBS_REGION_GOT: i64 = 23;
pub const OBS_REGION_FREE: i64 = 24;
pub const OBS_STDALLOC_INIT: i64 = 25;
pub const OBS_UE_REGION: i64 = 26;

/// Switches of the Python driver (environment variables there)
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `DM_REWRITE_J`: the worker count the CALLER builds its rayon pool with (0 = all cores). `rewrite` does not read it: it runs
    /// on the rayon pool it is called in (`pool.install`), and that pool's size selects the 1-worker or the parallel paths
    pub workers: usize,
    /// `DM_PATCH_FRONT`: size of the patch area in front of the base (only set by the re-run)
    pub patch_front: Option<u64>,
    /// `DM_GAME`: the selected game profile (base game title ID or a path)
    pub game: Option<String>,
    /// the engine's `dm/games` folder (for `game.tsv`), and `DM_GAMES_DIR`
    pub games_dirs: Vec<PathBuf>,
    /// `DM_SPIN_LIST`: print every spin wait found
    pub spin_list: bool,
    /// the engine's `dm/tools` folder: only to write `build_src.sha256` (hashes of the Python sources)
    pub py_tools: Option<PathBuf>,
}

/// `(offset, original bytes hex, new bytes hex, reason)` of a cut applied to the image
#[derive(Debug, Clone)]
pub struct CutRow {
    pub off: i64,
    pub old: String,
    pub new: String,
    pub why: String,
}

/// `(offset, observation number, original word hex, reason)` of an observation gate
#[derive(Debug, Clone)]
pub struct ObsRow {
    pub off: i64,
    pub number: i64,
    pub word: String,
    pub why: String,
}

#[derive(Debug, Clone)]
pub struct Gate {
    pub ret: i64,
    pub kind: &'static str,
    pub arg: i64,
    pub orig: i64,
}

/// What the linear scan found at a word (`kinds` of the Python)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Svc(u32),
    TpidrR,
    TpidrW,
    TpidrroR,
    Cntpct(u32),
    Cntvct(u32),
    Ctr(u32),
    SpAlign(u32),
    X18,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Svc(_) => "svc",
            Kind::TpidrR => "tpidr_r",
            Kind::TpidrW => "tpidr_w",
            Kind::TpidrroR => "tpidrro_r",
            Kind::Cntpct(_) => "cntpct",
            Kind::Cntvct(_) => "cntvct",
            Kind::Ctr(_) => "ctr",
            Kind::SpAlign(_) => "sp_align",
            Kind::X18 => "x18",
        }
    }
}

/// The module image with a record of what was changed in the text: Python keeps `ORIG_TEXT`, a full copy; here only
/// the original word of each changed text word is kept.
pub struct Img {
    pub b: Vec<u8>,
    text_end: usize,
    orig: HashMap<usize, u32>,
}

impl Img {
    pub fn new(b: Vec<u8>, text_end: usize) -> Img {
        Img {
            b,
            text_end,
            orig: HashMap::new(),
        }
    }
    #[inline]
    pub fn w(&self, off: i64) -> u32 {
        rd32(&self.b, off as usize)
    }
    /// the word `ORIG_TEXT` holds (the text before any cut or site)
    pub fn orig_word(&self, off: i64) -> u32 {
        self.orig
            .get(&(off as usize))
            .copied()
            .unwrap_or_else(|| self.w(off))
    }
    fn log(&mut self, off: usize) {
        let a = off & !3;
        if a + 4 <= self.text_end && !self.orig.contains_key(&a) {
            let v = rd32(&self.b, a);
            self.orig.insert(a, v);
        }
    }
    pub fn set(&mut self, off: i64, w: u32) {
        let o = off as usize;
        self.log(o);
        self.b[o..o + 4].copy_from_slice(&w.to_le_bytes());
    }
    pub fn set_bytes(&mut self, off: i64, bytes: &[u8]) {
        let o = off as usize;
        let mut a = o & !3;
        while a < o + bytes.len() {
            self.log(a);
            a += 4;
        }
        self.b[o..o + bytes.len()].copy_from_slice(bytes);
    }
    /// text words whose current value differs from the original: (offset, original, current), ascending
    pub fn changed(&self) -> Vec<(usize, u32, u32)> {
        let mut v: Vec<(usize, u32, u32)> = self
            .orig
            .iter()
            .map(|(&a, &o)| (a, o, rd32(&self.b, a)))
            .filter(|&(_, o, c)| o != c)
            .collect();
        v.sort();
        v
    }
}

/// A Python dict keyed by address that keeps insertion order
#[derive(Debug, Clone)]
pub struct OrdMap<V> {
    pub items: Vec<(i64, V)>,
    idx: HashMap<i64, usize>,
}
impl<V> Default for OrdMap<V> {
    fn default() -> Self {
        OrdMap {
            items: Vec::new(),
            idx: HashMap::new(),
        }
    }
}
impl<V> OrdMap<V> {
    pub fn insert(&mut self, k: i64, v: V) {
        match self.idx.get(&k) {
            Some(&i) => self.items[i].1 = v,
            None => {
                self.idx.insert(k, self.items.len());
                self.items.push((k, v));
            }
        }
    }
    pub fn get(&self, k: i64) -> Option<&V> {
        self.idx.get(&k).map(|&i| &self.items[i].1)
    }
    pub fn contains(&self, k: i64) -> bool {
        self.idx.contains_key(&k)
    }
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.items.iter().map(|x| &x.1)
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Files and log of one rewrite (`<name>.*` of the Python)
pub struct Rewritten {
    pub name: String,
    /// text + ro + data (+ bss and key page unless FAR), as `IMG`
    pub image: Vec<u8>,
    /// the file is `image`, zeros up to `pad_to`, then `patch`
    pub pad_to: usize,
    pub patch: Vec<u8>,
    pub fixups: String,
    pub gates: String,
    pub sites: String,
    pub cuts: String,
    pub changed: String,
    pub obs: String,
    pub match_tsv: Option<String>,
    pub build_src: Option<String>,
    /// the lines the Python prints, the last being the stats line
    pub log: Vec<String>,
}

impl Rewritten {
    /// the bytes of `<name>.patched.bin`
    pub fn write_patched(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        w.write_all(&self.image)?;
        let zeros = vec![0u8; 1 << 16];
        let mut left = self.pad_to - self.image.len();
        while left > 0 {
            let n = left.min(zeros.len());
            w.write_all(&zeros[..n])?;
            left -= n;
        }
        w.write_all(&self.patch)
    }
}

/// The rewriter's global state.
pub struct Rw<'o> {
    pub opts: &'o Options,
    pub name: String,
    pub build_id: String,
    pub text_end: i64,
    pub ro_off: i64,
    pub data_off: i64,
    pub bss: i64,
    pub img: Img,
    // layout
    pub far: bool,
    pub front: i64,
    pub big_text: bool,
    pub two: bool,
    pub back_min: i64,
    pub gap: bool,
    pub split: Option<i64>,
    pub key_page_off: i64,
    pub image_size: i64,
    pub patch_off: i64,
    pub back_off: i64,
    pub file_image_len: i64,
    pub cuts: Vec<CutRow>,
    pub obs: Vec<ObsRow>,
    // emitter
    pub patch_front: Vec<u8>,
    pub patch_back: Vec<u8>,
    pub in_back: bool,
    pub fix: usize,
    pub gates: Vec<Gate>,
    pub stats: Vec<(&'static str, u64)>,
    pub log: Vec<String>,
    // hops
    pub holes: Option<Vec<i64>>,
    pub hops: Vec<(i64, Vec<i64>)>,
    // text structure
    pub starts: Vec<i64>,
    pub data_blocks: Vec<(i64, i64)>,
    pub code_ranges: Vec<(i64, i64)>,
    // analysis results
    pub kinds: Vec<(i64, Kind)>,
    pub done: HashSet<i64>,
    pub windows: Vec<Vec<Ins>>,
    pub retries: Vec<Vec<(Vec<Ins>, i64)>>,
    pub jumps: OrdMap<(i64, i64)>,
    pub tabjumps: OrdMap<Vec<i64>>,
    pub tailcalls: HashSet<i64>,
    /// conditional selects with an x18 source that get the stack-free rewrite (`selects` of `patch_nso.py`, engine patch 0409): address -> (what `select_x18` found, the dead temporary)
    pub selects: HashMap<i64, (crate::select::SelectArgs, u32)>,
    pub ordered: HashSet<i64>,
    // detector results (the fixups table)
    pub ue_cvars: Vec<(String, i64)>,
    pub fps_target: Option<(i64, i64)>,
    pub monolith_interval: Option<i64>,
    pub ue_fixed: Option<(i64, i64, u32)>,
    pub unity: unity_fps::UnityFps,
    pub ue_malloc: Option<ue_malloc::Found>,
    pub ue_region: Option<(i64, u32, Option<i64>)>,
    // frame step / stubs
    pub fs_state_off: i64,
    pub step_max: i64,
    pub render_scale: i64,
    pub fs_capabilities: Vec<String>,
    /// the function a MATCH_FRAME_STEP rule matched (`FS_MATCH`)
    pub fs_match: Option<crate::stubs::FsMatch>,
    /// the function a MATCH_STUBS rule matched (`STUB_MATCH`)
    pub stub_match: Option<crate::stubs::FsMatch>,
    pub native_fps_blocked: bool,
    pub match_tsv: Option<String>,
    // spin waits: (head, back-edges that enter the copy, instructions) and the text words they cover
    pub spin_sites: Vec<(i64, Vec<i64>, usize)>,
    pub spin_words: Vec<i64>,
}

impl<'o> Rw<'o> {
    pub fn stat(&mut self, k: &'static str) {
        match self.stats.iter_mut().find(|(n, _)| *n == k) {
            Some(e) => e.1 += 1,
            None => self.stats.push((k, 1)),
        }
    }
    pub fn say(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
    }
    /// `use_area(a)`: emit what follows into the patch area that reaches the code at offset a
    pub fn use_area(&mut self, a: i64) {
        self.in_back = self.two && a >= self.split.unwrap();
    }
    pub fn patch_base(&self) -> i64 {
        if self.in_back {
            self.back_off
        } else {
            self.patch_off
        }
    }
    pub fn patch_len(&self) -> usize {
        if self.in_back {
            self.patch_back.len()
        } else {
            self.patch_front.len()
        }
    }
    pub fn here(&self) -> i64 {
        self.patch_base() + self.patch_len() as i64
    }
    pub fn emit(&mut self, w: u32) {
        let p = if self.in_back {
            &mut self.patch_back
        } else {
            &mut self.patch_front
        };
        p.extend_from_slice(&w.to_le_bytes());
    }
    pub fn kind_at(&self, a: i64) -> Option<Kind> {
        self.kinds
            .binary_search_by_key(&a, |k| k.0)
            .ok()
            .map(|i| self.kinds[i].1)
    }
    pub fn in_window(&self, off: i64) -> bool {
        self.windows
            .iter()
            .any(|w| w[0].address <= off && off < w.last().unwrap().address + 4)
    }

    // ---- hops: branches beyond a b's reach ----
    fn hop_holes(&self) -> Vec<i64> {
        // the padding words that may hold a hop, in address order (the text as the file has it)
        let mut out = Vec::new();
        for &s in &self.starts {
            if s < 8 || s & 15 != 0 {
                continue;
            }
            #[allow(clippy::manual_isolate_lowest_one)]
            // `s & -s` mirrors the Python source; same bits as isolate_lowest_one
            let align = s & -s;
            let mut k = s;
            while k - 4 >= 0 && matches!(self.img.orig_word(k - 4), 0 | 0xD503201F) {
                k -= 4;
            }
            if k == s || s - k >= align || k < 4 {
                continue;
            }
            let p = self.img.orig_word(k - 4);
            if !(p & 0xFC000000 == 0x14000000
                || matches!(p & 0xFFFFFC1F, 0xD61F0000 | 0xD65F0000)
                || p & 0xFFE0001F == 0xD4200000)
            {
                continue;
            }
            if self.data_blocks.iter().any(|&(a, b)| a < s && k < b) {
                continue;
            }
            out.extend((k..s).step_by(4));
        }
        out
    }

    /// `reach_via(frm, to)`: `to` when a b at `frm` reaches it, else a hop that does (and that reaches `to`)
    pub fn reach_via(&mut self, frm: i64, to: i64) -> Res<i64> {
        const REACH: i64 = (1 << 27) - 4;
        if -REACH - 4 <= to - frm && to - frm <= REACH {
            return Ok(to);
        }
        if let Some((_, hs)) = self.hops.iter().find(|(t, _)| *t == to) {
            for &h in hs {
                if (h - frm).abs() <= REACH {
                    return Ok(h);
                }
            }
        }
        if self.holes.is_none() {
            self.holes = Some(self.hop_holes());
        }
        let (lo, hi) = (frm.max(to) - REACH, frm.min(to) + REACH);
        let holes = self.holes.as_mut().unwrap();
        let i = holes.partition_point(|&x| x < lo);
        if !(i < holes.len() && holes[i] <= hi) {
            return Err(Fail::new(format!(
                "no padding word for a hop from {} to {} (between {} and {})",
                hx(frm),
                hx(to),
                hx(lo),
                hx(hi)
            )));
        }
        let h = holes.remove(i);
        if self.img.w(h) != self.img.orig_word(h) {
            return Err(Fail::new(format!(
                "hop {h:#x} was written by something else"
            )));
        }
        let w = asm::b(h, to)?;
        self.img.set(h, w);
        match self.hops.iter_mut().find(|(t, _)| *t == to) {
            Some((_, v)) => v.push(h),
            None => self.hops.push((to, vec![h])),
        }
        self.stat("hop");
        Ok(h)
    }

    /// `BX(frm, to)`: a `b` from frm to `to`, through a hop when it does not reach
    pub fn bx(&mut self, frm: i64, to: i64) -> Res<u32> {
        let t = self.reach_via(frm, to)?;
        Ok(asm::b(frm, t)?)
    }

    pub fn put_branch(&mut self, at: i64, to: i64) -> Res<()> {
        let w = self.bx(at, to)?;
        self.img.set(at, w);
        Ok(())
    }

    // ---- emission helpers ----
    pub fn emit_key_addr(&mut self, reg: u32, kind: u32) -> Res<()> {
        self.fix += 1;
        let w = asm::adrp(reg, self.here(), self.key_page_off)?;
        self.emit(w);
        self.emit(asm::ldrx(reg, reg, kind));
        Ok(())
    }
    pub fn emit_slot_addr(&mut self, base: u32, key_reg: u32, kind: u32) -> Res<()> {
        self.emit_key_addr(key_reg, kind)?;
        self.emit(asm::addr(base, base, key_reg));
        Ok(())
    }
    /// `emit(BX(here(), to))`
    pub fn emit_bx(&mut self, to: i64) -> Res<()> {
        let w = self.bx(self.here(), to)?;
        self.emit(w);
        Ok(())
    }
    pub fn emit_gate_call(&mut self) -> Res<()> {
        self.emit(asm::mrs_tpidrro(30));
        self.emit_slot_addr(30, 29, KEY_KGATE)?;
        self.emit(asm::ldrx(30, 30, 0));
        self.emit(asm::ldrx(29, 31, 0));
        Ok(())
    }
}

fn pyhex_list(v: &[i64]) -> String {
    v.iter()
        .map(|x| format!("{x:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn align_up(v: i64, a: i64) -> i64 {
    (v + a - 1) & !(a - 1)
}

/// `patch_nso.py <module file> <output dir> <name>` for a module already read into memory. A request for a bigger patch
/// area in front of the module (the Python's re-exec) comes back as `Err(Fail { rerun_front: Some(n), .. })`:
/// call again with `Options::patch_front = Some(n)` (see [`rewrite`], which loops).
pub fn rewrite_once(file: &[u8], file_name: &str, name: &str, opts: &Options) -> Res<Rewritten> {
    let module =
        ibuilder_nso::load(file, file_name).map_err(|e| Fail::new(format!("[RED] {}", e.0)))?;
    let bss = module.bss as i64;
    let text_end = module.text_end() as i64;
    let (ro_off, data_off) = (module.segments[1].0 as i64, module.segments[2].0 as i64);
    let image_len = module.image.len() as i64;
    let build_id = hex(&module.build_id[..0x10]);
    // Every jump between the patch area and the code is a B (±128 MB). A patch area appended after the image (with bss)
    // cannot reach the code when it would start beyond 112 MB: it then sits FRONT bytes before the module base.
    let near_patch_off = align_up(align_up(image_len + bss, 0x4000) + 0x4000, 0x10000);
    let far = near_patch_off > 0x7000000;
    let mut front: i64 = 0x2000000;
    let big_text = far && text_end + front > 0x8000000 - 0x10000;
    let two = big_text && text_end > 0x8000000 - 0x10000;
    let (mut back_min, mut gap) = (0i64, false);
    let env_front = opts.patch_front.unwrap_or(0) as i64;
    if two {
        back_min =
            align_up(align_up(image_len + bss, 0x4000) + 0x8000, 0x10000) - 0x8000000 + 0x100000;
        gap = back_min >= 0x8000000 - 0x200000;
        front = if env_front != 0 {
            env_front
        } else if gap {
            0x1000000
        } else {
            0x1000000.min((0x8000000 - 0x100000 - back_min) & !0xFFFF)
        };
    } else if big_text {
        front = if env_front != 0 {
            env_front
        } else {
            (0x8000000 - 0x10000 - text_end) & !0xFFFF
        };
    }
    let split = if two {
        Some(if gap {
            0x8000000 - front - 0x100000
        } else {
            (0x8000000 - front - 0x100000).max(back_min)
        })
    } else {
        None
    };

    let mut image = module.image;
    if !far {
        image.resize(image.len() + bss as usize, 0);
    }
    let (key_page_off, image_size, patch_off, back_off, file_image_len);
    if far {
        file_image_len = align_up(image.len() as i64, 0x4000);
        key_page_off = align_up(image.len() as i64 + bss, 0x4000);
        image_size = key_page_off + 0x4000;
        patch_off = -front;
        back_off = if two {
            align_up(key_page_off + 0x8000, 0x10000)
        } else {
            0
        };
        if two && back_off - 0x8000000 + 0x100000 != back_min {
            return Err(Fail::new("BACK_MIN and BACK_OFF disagree"));
        }
    } else {
        key_page_off = align_up(image.len() as i64, 0x4000);
        image.resize(image.len() + 0x4000, 0);
        patch_off = align_up(image.len() as i64, 0x10000);
        image_size = 0;
        back_off = 0;
        file_image_len = 0;
    }
    let mut rw = Rw {
        opts,
        name: name.to_string(),
        build_id,
        text_end,
        ro_off,
        data_off,
        bss,
        img: Img::new(image, text_end as usize),
        far,
        front,
        big_text,
        two,
        back_min,
        gap,
        split,
        key_page_off,
        image_size,
        patch_off,
        back_off,
        file_image_len,
        cuts: Vec::new(),
        obs: Vec::new(),
        patch_front: Vec::new(),
        patch_back: Vec::new(),
        in_back: false,
        fix: 0,
        gates: Vec::new(),
        stats: Vec::new(),
        log: Vec::new(),
        holes: None,
        hops: Vec::new(),
        starts: Vec::new(),
        data_blocks: Vec::new(),
        code_ranges: Vec::new(),
        kinds: Vec::new(),
        done: HashSet::new(),
        windows: Vec::new(),
        retries: Vec::new(),
        jumps: OrdMap::default(),
        tabjumps: OrdMap::default(),
        tailcalls: HashSet::new(),
        selects: HashMap::new(),
        ordered: HashSet::new(),
        ue_cvars: Vec::new(),
        fps_target: None,
        monolith_interval: None,
        ue_fixed: None,
        unity: unity_fps::UnityFps::default(),
        ue_malloc: None,
        ue_region: None,
        fs_state_off: 0,
        step_max: 0,
        render_scale: 0,
        fs_capabilities: Vec::new(),
        fs_match: None,
        stub_match: None,
        native_fps_blocked: false,
        match_tsv: None,
        spin_sites: Vec::new(),
        spin_words: Vec::new(),
    };
    rw.run()?;
    rw.finish()
}

/// `rewrite_once`, run again with the patch area size it asks for (the driver loop that replaces `os.execve`)
pub fn rewrite(file: &[u8], file_name: &str, name: &str, opts: &Options) -> Res<Rewritten> {
    let mut o = opts.clone();
    let mut log_prefix: Vec<String> = Vec::new();
    for _ in 0..3 {
        match rewrite_once(file, file_name, name, &o) {
            Ok(mut r) => {
                if !log_prefix.is_empty() {
                    log_prefix.append(&mut r.log);
                    r.log = log_prefix;
                }
                return Ok(r);
            }
            Err(Fail {
                rerun_front: Some(n),
                msg,
            }) => {
                // the Python prints this line before it re-executes itself (its earlier output stays in the log)
                log_prefix.push(msg);
                o.patch_front = Some(n);
            }
            Err(e) => return Err(e),
        }
    }
    Err(Fail::new(
        "patch_nso asked to be re-executed more than twice",
    ))
}

impl Rw<'_> {
    /// The phases of `patch_nso.py` up to the output files, in order.
    fn run(&mut self) -> Res<()> {
        let name_is_main = self.name == "main";
        crate::mark("start");
        self.original_cuts()?;
        crate::mark("cuts/match");
        // Key page indices are fixed; the key page content is written by the loader as "actual key number × 8".

        // ---- Unreal console variables in main ----
        if name_is_main {
            let (found, why) =
                ue_cvar::find_all(&self.img.b, self.text_end, self.ro_off, self.data_off);
            self.ue_cvars = found;
            if !self.ue_cvars.is_empty() {
                let l: Vec<String> = self
                    .ue_cvars
                    .iter()
                    .map(|(n, o)| format!("{n} at {o:#x}"))
                    .collect();
                let n = self.name.clone();
                self.say(format!(
                    "{n}: Unreal console variables (ue_cvar.py): {}",
                    l.join(", ")
                ));
            }
            for w in why {
                if let Some(r) = w.strip_prefix("[RED] ") {
                    let n = self.name.clone();
                    self.say(format!(
                        "[RED] {n}: Unreal console variable {r}: the host cannot write it"
                    ));
                }
            }
            crate::mark("ue_cvar");
            // ---- a target frame rate the game steps by ----
            let (g, f, why) =
                fps_target::find(&self.img.b, self.text_end, self.ro_off, self.data_off);
            let n = self.name.clone();
            if let (Some(g), Some(f)) = (g, f) {
                self.fps_target = Some((g, f));
                self.say(format!("{n}: {why} (fps_target.py)"));
            } else if let Some(r) = why.strip_prefix("[RED] ") {
                self.say(format!("[RED] {n}: {r}: the host cannot write it"));
            }
            crate::mark("fps_target");
            // ---- Monolith's native interval ----
            let (mi, why) = monolith::find(&self.img.b, self.text_end, self.ro_off, self.data_off);
            if let Some(o) = mi {
                self.monolith_interval = Some(o);
                self.say(format!("{n}: {why} (monolith_fps.py)"));
            } else if let Some(r) = why.strip_prefix("[RED] ") {
                self.say(format!("[RED] {n}: {r}: the host cannot write it"));
            }
            crate::mark("monolith");
            // ---- Unreal's fixed frame rate ----
            if !self.ue_cvars.is_empty() {
                let (g, f, fl, why) = ue_fixed_rate::find_rate(
                    &self.img.b,
                    self.text_end,
                    self.ro_off,
                    self.data_off,
                );
                if let (Some(g), Some(f), Some(fl)) = (g, f, fl) {
                    self.ue_fixed = Some((g, f, fl));
                    self.say(format!("{n}: {why} (ue_fixed_rate.py)"));
                } else if let Some(r) = why.strip_prefix("[RED] ") {
                    self.say(format!("[RED] {n}: {r}: the host cannot write it"));
                }
            }
            crate::mark("ue_fixed");
            // ---- Unity's frame rate ----
            let (u, why) =
                unity_fps::find_fps(&self.img.b, self.text_end, self.ro_off, self.data_off);
            if u.target.is_some() || u.qs.is_some() {
                self.say(format!("{n}: {why} (unity_fps.py)"));
            }
            if why.contains("[RED] ") {
                self.say(format!(
                    "[RED] {n}: {why}: the host cannot write what is not read"
                ));
            }
            self.unity = u;
        }

        crate::mark("unity_fps");
        // ---- Unreal's FMallocBinned3 (any module) ----
        let (found, why) =
            ue_malloc::find_malloc(&self.img.b, self.text_end, self.ro_off, self.data_off);
        let n = self.name.clone();
        if let Some(f) = found {
            for &c in &f.calls {
                let old = hex(&self.img.b[c as usize..c as usize + 4]);
                self.cuts.push(CutRow {
                    off: c,
                    old,
                    new: hex(&NOP.to_le_bytes()),
                    why: format!(
                        "{why}: the constructor call → nop, gate OBS_UE_MALLOC on it (ue_malloc.py)"
                    ),
                });
                self.img.set(c, NOP);
            }
            self.say(format!("{n}: {why}"));
            self.ue_malloc = Some(f);
        } else if let Some(r) = why.strip_prefix("[RED] ") {
            self.say(format!("[RED] {n}: {r}: Unreal's own allocator runs"));
        }

        crate::mark("ue_malloc");
        if name_is_main {
            // ---- Unity's ALLOC_BUCKET BucketAllocator ----
            let (cut, why) =
                unity_bucket::find_cut(&self.img.b, self.text_end, self.ro_off, self.data_off);
            if let Some((off, old, new, cwhy)) = cut {
                self.img.set_bytes(off, &unhex(&new));
                self.cuts.push(CutRow {
                    off,
                    old,
                    new,
                    why: cwhy,
                });
                self.say(format!("{n}: {why}"));
            } else if let Some(r) = why.strip_prefix("[RED] ") {
                self.say(format!("[RED] {n}: {r}: its whole reservation stays"));
            }
            // ---- Snowdrop's three-pool page allocator ----
            let (sites, why) = snowdrop::find_sites(&self.img.b, self.text_end);
            if let Some(s) = sites {
                let (sizes, from) = self.snowdrop_sizes()?;
                for (off, ob, nb, cwhy) in snowdrop::cuts(&self.img.b, &s, sizes)? {
                    self.img.set_bytes(off, &unhex(&nb));
                    self.cuts.push(CutRow {
                        off,
                        old: ob,
                        new: nb,
                        why: cwhy,
                    });
                }
                self.say(format!(
                    "{n}: {why}: large {} MB, 512 KB pages {} MB, 64 KB pages {} MB ({from})",
                    sizes.0, sizes.1, sizes.2
                ));
            } else if let Some(r) = why.strip_prefix("[RED] ") {
                self.say(format!(
                    "[RED] {n}: {r}: its 12 GB reservation stays and fails on an iPhone"
                ));
            }
            // ---- Unreal's engine address region ----
            let (site, reg, x1, why) =
                ue_region::find_region(&self.img.b, self.text_end, self.ro_off, self.data_off);
            if let Some(s) = site {
                self.ue_region = Some((s, reg.unwrap(), x1));
                self.say(format!("{n}: {why}"));
            } else if let Some(r) = why.strip_prefix("[RED] ") {
                self.say(format!(
                    "[RED] {n}: {r}: the engine asks for its whole default region"
                ));
            }
            // ---- Unreal's NVN dynamic buffers ----
            let (load, old, new, why) =
                ue_ring::find_ring(&self.img.b, self.text_end, self.ro_off, self.data_off);
            if let Some(l) = load {
                self.cuts.push(CutRow {
                    off: l,
                    old: hex(&old.to_le_bytes()),
                    new: hex(&new.to_le_bytes()),
                    why: format!("{why} (ue_ring.py)"),
                });
                self.img.set(l, new);
                self.say(format!("{n}: {why}"));
            } else if let Some(r) = why.strip_prefix("[RED] ") {
                self.say(format!("[RED] {n}: {r}: its dynamic buffers keep 3 copies"));
            }
        }

        crate::mark("snowdrop/region/ring");
        self.analyze_and_emit()
    }

    /// `snowdrop_pools.profile_sizes()`: the selected profile's key, else DEFAULT
    fn snowdrop_sizes(&self) -> Res<((i64, i64, i64), String)> {
        let Some(game) = self.opts.game.as_deref().filter(|g| !g.is_empty()) else {
            return Ok((snowdrop::DEFAULT, "default, no DM_GAME".into()));
        };
        let Some(path) = crate::frame::find_game_tsv(self.opts, game) else {
            return Ok((snowdrop::DEFAULT, "default, no profile".into()));
        };
        let rows = crate::frame::read_rows(&path);
        let Some(words) = rows
            .iter()
            .find(|(k, _)| k == "snowdrop_pools")
            .map(|(_, v)| v.join("\t"))
        else {
            return Ok((
                snowdrop::DEFAULT,
                "default, the profile has no snowdrop_pools".into(),
            ));
        };
        let ws: Vec<&str> = words.split_whitespace().collect();
        let parsed: Option<Vec<i64>> = ws.iter().map(|x| crate::ins::try_pyint(x)).collect();
        match parsed {
            Some(v)
                if v.len() == 3
                    && v.iter().min().is_some_and(|&m| m > 0)
                    && v.iter().sum::<i64>() < 4096 =>
            {
                Ok(((v[0], v[1], v[2]), "profile".into()))
            }
            _ => Err(Fail::new(format!(
                "[RED] {}: snowdrop_pools takes the large, 512 KB and 64 KB ranges in MB, under 4 GB in all: {}",
                path.display(),
                ws.join(" ")
            ))),
        }
    }

    /// Lines 140-190 of the Python: the build's registered cuts, or the function-matched ones, then applying them.
    fn original_cuts(&mut self) -> Res<()> {
        let mut cuts: Vec<CutRow> = Vec::new();
        let registered = patches::cuts_for(&self.build_id);
        if let Some(c) = registered {
            for x in c {
                cuts.push(CutRow {
                    off: x.off,
                    old: x.old.to_string(),
                    new: x.new.to_string(),
                    why: x.why.to_string(),
                });
            }
        } else {
            let profile = self
                .opts
                .game
                .as_deref()
                .map(|g| {
                    g.trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string()
                })
                .unwrap_or_default();
            // the repository profile's build rows: the builds of this module the game was brought up on, and what they had cut
            let (mut known, mut own): (Vec<(String, String, usize)>, HashSet<String>) =
                (Vec::new(), HashSet::new());
            if !profile.is_empty()
                && let Some(p) = crate::frame::find_game_tsv_in_repo(self.opts, &profile)
            {
                for row in crate::frame::read_raw_rows(&p) {
                    let c: Vec<String> = row.split('\t').map(|x| x.trim().to_string()).collect();
                    if c[0] == "build" && c.len() > 3 {
                        let bid = c[3..]
                            .iter()
                            .filter_map(|x| x.split_once('='))
                            .filter(|(k, _)| *k == self.name)
                            .map(|(_, v)| v.to_string())
                            .next_back();
                        if let Some(bid) = bid.filter(|b| !b.is_empty()) {
                            own.insert(bid.clone());
                            if bid != self.build_id
                                && let Some(rc) = patches::cuts_for(&bid).filter(|c| !c.is_empty())
                            {
                                known.push((bid, c[2].clone(), rc.len()));
                            }
                        }
                    }
                }
            }
            let (mut outcomes, mut sdk_outcomes): (Vec<Outcome>, Vec<Outcome>) =
                (Vec::new(), Vec::new());
            let mut lines: Vec<String> = Vec::new();
            // one Image for both rule sets: the SDK rules reuse the bodies and fingerprints the profile's rules computed
            let mut shared = matching::LazyImage::new(&self.img.b, self.text_end);
            let r1 = matching::resolve_in(
                &mut shared,
                &patches::profile_match_cuts(&profile, &self.name),
                &mut |l| lines.push(l),
                Some(&mut outcomes),
                true,
            )
            .map_err(|e| Fail::new(e.0))?;
            let r2 = matching::resolve_in(
                &mut shared,
                &patches::sdk_match_cuts(&self.name),
                &mut |l| lines.push(l),
                Some(&mut sdk_outcomes),
                false,
            )
            .map_err(|e| Fail::new(e.0))?;
            for l in lines {
                self.say(l);
            }
            for (off, old, new, why) in r1.into_iter().chain(r2) {
                cuts.push(CutRow { off, old, new, why });
            }
            if !own.contains(&self.build_id)
                && (!known.is_empty() || !outcomes.is_empty() || !sdk_outcomes.is_empty())
            {
                let mut t = format!(
                    "# {} {}: not a registered build. registered: build ID, display version, cuts; patch (the game profile's) or sdk (SDK-wide): name, cut offsets or -, implementation or why not\n",
                    self.name, self.build_id
                );
                for (bid, disp, n) in &known {
                    t.push_str(&format!("registered\t{bid}\t{disp}\t{n}\n"));
                }
                for (kind, got) in [("patch", &outcomes), ("sdk", &sdk_outcomes)] {
                    for (name, offs, why) in got.iter() {
                        let o = match offs {
                            Some(o) if !o.is_empty() => pyhex_list(o).replace(", ", ","),
                            _ => "-".to_string(),
                        };
                        t.push_str(&format!("{kind}\t{name}\t{o}\t{why}\n"));
                    }
                }
                self.match_tsv = Some(t);
            }
        }
        // the frame step of a main with no FRAME_STEP of its build, placed by the function it patches (MATCH_FRAME_STEP)
        crate::stubs::locate(self)?;
        // The frame step state page is the page after the key page. An appended patch area starts on the first 64 KB
        // boundary after the key page, which is that page itself when the key page ends on such a boundary: a main that gets the
        // state page then starts its patch area 64 KB later.
        if crate::stubs::has_frame_step(self)
            && self.name == "main"
            && !self.far
            && self.patch_off < self.key_page_off + 0x4000 + 0x1000
        {
            self.patch_off += 0x10000;
        }
        for c in &cuts {
            let (ob, nb) = (unhex(&c.old), unhex(&c.new));
            let cur = self.img.b.get(c.off as usize..c.off as usize + ob.len());
            if !(ob.len() == nb.len() && cur == Some(&ob[..])) {
                let got = cur.map(hex).unwrap_or_default();
                return Err(Fail::new(format!(
                    "cut original bytes mismatch {:#x}: {got}",
                    c.off
                )));
            }
            self.img.set_bytes(c.off, &nb);
        }
        self.cuts = cuts;
        Ok(())
    }

    /// everything after the detectors: scans, sites, windows, spin waits (continued in `scan`, `sites`, `spin`)
    fn analyze_and_emit(&mut self) -> Res<()> {
        crate::scan::run(self)
    }

    fn finish(self) -> Res<Rewritten> {
        crate::output::finish(self)
    }
}
