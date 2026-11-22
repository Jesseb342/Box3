//! Conservative function matching for opt-in patches across game updates: a port of `dm/tools/nso_match.py`.
//!
//! Fingerprints cover an entire unwind function, its internal branches, constants and registers, and the bodies (or
//! imported names) of its direct callees. Only relocation addresses are normalised. No fuzzy matching or guessed
//! function boundaries; every locator finds exactly one place with its assumptions checked, or none.

use crate::fde::fde_ranges;
use crate::patches::{FnRule, Rule};
use ibuilder_a64::bits::{rd32, rd64};
use ibuilder_a64::cs;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchError(pub String);
impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
type Res<T> = Result<T, MatchError>;

/// the word some compilers leave after a call that does not return, which Capstone cannot decode; brk #0
const TRAP_WORD: u32 = 0xe7ffdefe;
const BRK: u32 = 0xd4200000;

/// The `size` bytes `struct.unpack_from(fmt, img, off)` reads, or None where it raises: a negative `off` counts from the
/// end (`struct.error` below `-len`), the bytes must lie inside the image (`struct.error`), and an `off` of 2^63 or more
/// does not fit a C ssize_t (`OverflowError`).
fn unpack_from(img: &[u8], off: i128, size: usize) -> Option<&[u8]> {
    if off >= 1 << 63 {
        return None;
    }
    let o = if off < 0 {
        off + img.len() as i128
    } else {
        off
    };
    let o = usize::try_from(o).ok()?;
    img.get(o..o.checked_add(size)?)
}

fn signed(n: i64, bits: u32) -> i64 {
    if n & (1 << (bits - 1)) != 0 {
        n - (1 << bits)
    } else {
        n
    }
}

/// (immediate-bit mask, signed byte displacement) for direct branches.
fn relative(w: u32) -> Option<(u32, i64)> {
    if w & 0x7c000000 == 0x14000000 {
        return Some((0x03ffffff, signed((w & 0x3ffffff) as i64, 26) * 4));
    }
    if w & 0xff000010 == 0x54000000 || w & 0x7e000000 == 0x34000000 {
        return Some((0x00ffffe0, signed(((w >> 5) & 0x7ffff) as i64, 19) * 4));
    }
    if w & 0x7e000000 == 0x36000000 {
        return Some((0x0007ffe0, signed(((w >> 5) & 0x3fff) as i64, 14) * 4));
    }
    None
}

#[derive(Clone, PartialEq, Eq)]
enum Callee {
    Import(String),
    Svc(u32),
    Function(i64, String),
}

/// `json.dumps(s)` of a string (ensure_ascii)
fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A function's body: the digest of its normalised words and its branches out of it (offset in it, target)
type Body = (String, Vec<(i64, i64)>);

/// `Image._body`: the [`Body`] of the function `start..end`. A function of the image bytes alone (and the bounds it is
/// given).
fn body_of(image: &[u8], start: i64, end: i64) -> Res<Body> {
    let code = &image[start as usize..end as usize];
    let words: Vec<u32> = code
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    // decoded as brk so that the rest of the function can be read; the digest still covers the word itself
    let dec: Vec<u8> = words
        .iter()
        .flat_map(|&w| (if w == TRAP_WORD { BRK } else { w }).to_le_bytes())
        .collect();
    let ins = cs::disasm(&dec, start);
    if ins.len() * 4 != code.len() {
        return Err(MatchError(format!("undecodable function at {start:#x}")));
    }
    let mut normalized = words.clone();
    let mut branches = Vec::new();
    for (i, (&w, op)) in words.iter().zip(&ins).enumerate() {
        if let Some((mask, delta)) = relative(w) {
            let target = op.address + delta;
            if !(start <= target && target < end) {
                normalized[i] &= !mask;
                branches.push((i as i64 * 4, target));
            }
        } else if w & 0x1f000000 == 0x10000000 {
            // ADR / ADRP
            let d = signed((((w >> 29) & 3) | ((w >> 5) & 0x7ffff) << 2) as i64, 21);
            if w & 0x80000000 != 0 || !(start <= op.address + d && op.address + d < end) {
                normalized[i] &= 0x9f00001f;
            }
        } else if w & 0x3b000000 == 0x18000000 {
            // literal load
            let target = op.address + signed(((w >> 5) & 0x7ffff) as i64, 19) * 4;
            if !(start <= target && target < end) {
                normalized[i] &= 0xff00001f;
            }
        }
        if w & 0x9f000000 != 0x90000000 {
            continue;
        }
        let rd = w & 31;
        let alias = match rd {
            29 => "fp",
            30 => "lr",
            _ => "",
        };
        let (xs, ws) = (format!("x{rd}"), format!("w{rd}"));
        for j in (i + 1)..(i + 9).min(words.len()) {
            let u = words[j];
            // the low part of an ADRP address, not an ordinary member offset
            if (u & 0xffc00000 == 0x91000000 || u & 0x3b000000 == 0x39000000) && (u >> 5) & 31 == rd
            {
                normalized[j] &= !0x3ffc00u32;
                break;
            }
            if relative(u).is_some() || matches!(ins[j].mn(), "br" | "blr" | "ret") {
                break;
            }
            let writes: &[u16] = ins[j].regs.as_ref().map(|r| &r.1[..]).unwrap_or(&[]);
            if writes.iter().any(|&r| {
                let n = cs::reg_name(r);
                n == xs || n == ws || n == alias
            }) {
                break;
            }
        }
    }
    let bytes: Vec<u8> = normalized.iter().flat_map(|w| w.to_le_bytes()).collect();
    let digest = hex(&Sha256::digest(&bytes));
    Ok((digest, branches))
}

pub struct Image<'a> {
    pub image: &'a [u8],
    pub text_end: i64,
    /// function start -> end, in the order of the sorted FDE ranges (the dict order of the Python)
    pub function_list: Vec<(i64, i64)>,
    pub functions: HashMap<i64, i64>,
    bodies: HashMap<i64, (String, Vec<(i64, i64)>)>,
    fingerprints: HashMap<i64, String>,
    imports: Option<HashMap<i64, String>>,
}

impl<'a> Image<'a> {
    pub fn new(image: &'a [u8], text_end: i64) -> Res<Image<'a>> {
        let ranges = fde_ranges(image)
            .map_err(|e| MatchError(format!("cannot read function boundaries: {e}")))?;
        let mut functions = HashMap::new();
        let mut function_list = Vec::new();
        for (start, end) in ranges {
            if !(0 <= start && start < end && end <= text_end.min(image.len() as i64))
                || start % 4 != 0
                || end % 4 != 0
            {
                continue;
            }
            if let Some(&e) = functions.get(&start) {
                if e != end {
                    return Err(MatchError(format!(
                        "conflicting function boundaries at {start:#x}"
                    )));
                }
                continue;
            }
            functions.insert(start, end);
            function_list.push((start, end));
        }
        Ok(Image {
            image,
            text_end,
            function_list,
            functions,
            bodies: HashMap::new(),
            fingerprints: HashMap::new(),
            imports: None,
        })
    }

    fn body(&mut self, start: i64) -> Res<&Body> {
        if !self.bodies.contains_key(&start) {
            let b = body_of(self.image, start, self.functions[&start])?;
            self.bodies.insert(start, b);
        }
        Ok(&self.bodies[&start])
    }

    /// With more than one worker: the bodies of the functions of `size` bytes and of their direct callees, decoded in
    /// parallel and put in the cache that `body` reads. `body_of` is a function of the image bytes alone, so a body
    /// found here is the one `body` would compute when asked; one that fails is left out (and fails again there, with the
    /// same message). The fingerprints are then computed one by one in function order as before; with one worker
    /// nothing is done here.
    pub fn prefetch_size(&mut self, size: usize) {
        if rayon::current_num_threads() < 2 {
            return;
        }
        let cands: Vec<i64> = self
            .function_list
            .iter()
            .filter(|&&(s, e)| (e - s) as usize == size)
            .map(|&(s, _)| s)
            .collect();
        self.prefetch(&cands);
        let mut callees: Vec<i64> = cands
            .iter()
            .filter_map(|s| self.bodies.get(s))
            .flat_map(|(_, br)| br.iter().map(|&(_, t)| t))
            .filter(|t| self.functions.contains_key(t))
            .collect();
        callees.sort_unstable();
        callees.dedup();
        self.prefetch(&callees);
    }

    fn prefetch(&mut self, starts: &[i64]) {
        use rayon::prelude::*;
        let todo: Vec<(i64, i64)> = starts
            .iter()
            .filter(|s| !self.bodies.contains_key(s))
            .filter_map(|&s| self.functions.get(&s).map(|&e| (s, e)))
            .collect();
        let image = self.image;
        let got: Vec<(i64, Res<Body>)> = todo
            .par_iter()
            .map(|&(s, e)| (s, body_of(image, s, e)))
            .collect();
        for (s, b) in got {
            if let Ok(b) = b {
                self.bodies.insert(s, b);
            }
        }
    }

    /// GOT slot -> symbol name from DT_JMPREL; unknown formats cannot match.
    fn import_slots(&mut self) -> &HashMap<i64, String> {
        if self.imports.is_none() {
            self.imports = Some(self.read_import_slots().unwrap_or_default());
        }
        self.imports.as_ref().unwrap()
    }

    /// Every value read here is the file's word. The Python wraps the whole body in
    /// `except (KeyError, ValueError, IndexError, struct.error): self.imports = {}`, so any read out of range, missing
    /// tag or bad name gives an EMPTY map (not the entries read so far); here each of those is a `None` (made empty by
    /// `import_slots`). Offsets are `i128` (Python ints) and every read goes through `unpack_from`, which has the bounds
    /// of `struct.unpack_from`, including a negative offset counting from the end (the dynamic section of a module whose
    /// MOD0 offset is negative). One case cannot be the same: an offset of 2^63 or more makes `struct.unpack_from` raise
    /// `OverflowError`, which the Python does not catch (the whole patch_nso.py run stops); here it is an empty map too.
    fn read_import_slots(&self) -> Option<HashMap<i64, String>> {
        let img = self.image;
        let mut out = HashMap::new();
        let mod_ = u32::from_le_bytes(unpack_from(img, 4, 4)?.try_into().ok()?) as i128;
        let dynp =
            mod_ + i32::from_le_bytes(unpack_from(img, mod_ + 4, 4)?.try_into().ok()?) as i128;
        let mut tags: HashMap<i64, u64> = HashMap::new();
        // range(dyn, min(len(img) - 15, dyn + 4096 * 16), 16)
        let lim = (img.len() as i128 - 15).min(dynp + 4096 * 16);
        let mut pos = dynp;
        while pos < lim {
            let e = unpack_from(img, pos, 16)?; // '<qQ'
            let tag = rd64(e, 0) as i64;
            let value = rd64(e, 8);
            if tag == 0 {
                break;
            }
            tags.insert(tag, value); // last one wins, as `tags[tag] = value`
            pos += 16;
        }
        if tags.get(&20) != Some(&7) {
            return Some(out); // DT_PLTREL must be DT_RELA
        }
        // range(tags[23], tags[23] + tags[2], 24): a size past the end of the image ends in struct.error (empty map)
        let (j, sz) = (*tags.get(&23)? as i128, *tags.get(&2)? as i128);
        let mut pos = j;
        while pos < j + sz {
            let e = unpack_from(img, pos, 24)?; // '<QQq'
            let (slot, info) = (rd64(e, 0), rd64(e, 8));
            pos += 24;
            if info & 0xffff_ffff != 1026 {
                continue; // R_AARCH64_JUMP_SLOT
            }
            let at = *tags.get(&6)? as i128 + (info >> 32) as i128 * 24;
            let name = rd32(unpack_from(img, at, 4)?, 0) as i128 + *tags.get(&5)? as i128;
            // img[name:img.index(0, name)].decode('utf-8'): no NUL at or after `name` is a ValueError, as is bad UTF-8
            let name = usize::try_from(name).ok()?;
            let e = img.get(name..)?.iter().position(|&c| c == 0)?;
            let s = String::from_utf8(img[name..name + e].to_vec()).ok()?;
            // the Python key is the unsigned slot; one of 2^63 or more can never equal the address `plt_import` looks up
            // (an i64), so it is left out instead of being wrapped onto a negative one
            if let Ok(slot) = i64::try_from(slot) {
                out.insert(slot, s);
            }
        }
        Some(out)
    }

    /// The imported symbol whose PLT entry is at `target`, else None. AArch64 PLT: adrp x16, page; ldr x17,[x16,#lo];
    /// add x16,x16,#lo; br x17
    fn plt_import(&mut self, target: i64) -> Option<String> {
        let lim = self.text_end.min(self.image.len() as i64) - 16;
        if 0 <= target && target <= lim {
            let t = target as usize;
            let (a, b, c, d) = (
                rd32(self.image, t),
                rd32(self.image, t + 4),
                rd32(self.image, t + 8),
                rd32(self.image, t + 12),
            );
            if a & 0x9f00001f == 0x90000010
                && b & 0xffc003ff == 0xf9400211
                && c & 0xffc003ff == 0x91000210
                && d == 0xd61f0220
            {
                let page = (target & !0xfff)
                    + (signed((((a >> 29) & 3) | ((a >> 5) & 0x7ffff) << 2) as i64, 21) << 12);
                let lo = (((b >> 10) & 0xfff) * 8) as i64;
                if (c >> 10) & 0xfff == lo as u32 {
                    return self.import_slots().get(&(page + lo)).cloned();
                }
            }
        }
        None
    }

    /// {function start: [offsets in it of each bl to the imported symbol `name`]}: the complete unwind functions that
    /// call it directly, in function order
    pub fn callers(&mut self, name: &str) -> Vec<(i64, Vec<i64>)> {
        let mut out: Vec<(i64, Vec<i64>)> = Vec::new();
        let mut plt: HashMap<i64, bool> = HashMap::new();
        let lim = (self.text_end.min(self.image.len() as i64) / 4 * 4) as usize;
        // by index: `plt_import` needs `self` mutably (its import map), and the list never changes
        for k in 0..self.function_list.len() {
            let (start, end) = self.function_list[k];
            for i in (start / 4)..(end / 4) {
                if (i as usize + 1) * 4 > lim {
                    break;
                }
                let w = rd32(self.image, i as usize * 4);
                if w & 0xfc000000 != 0x94000000 {
                    continue;
                }
                let target = 4 * i + signed((w & 0x3ffffff) as i64, 26) * 4;
                let hit = match plt.get(&target) {
                    Some(&h) => h,
                    None => {
                        let h = self.plt_import(target).as_deref() == Some(name);
                        plt.insert(target, h);
                        h
                    }
                };
                if hit {
                    match out.last_mut() {
                        Some((s, v)) if *s == start => v.push(4 * i - start),
                        _ => out.push((start, vec![4 * i - start])),
                    }
                }
            }
        }
        out
    }

    fn callee(&mut self, target: i64) -> Res<Callee> {
        let lim = self.text_end.min(self.image.len() as i64) - 16;
        if 0 <= target && target <= lim {
            let (a, b) = (
                rd32(self.image, target as usize),
                rd32(self.image, target as usize + 4),
            );
            if let Some(name) = self.plt_import(target) {
                return Ok(Callee::Import(name));
            }
            // the SDK's system call wrappers are assembly without unwind entries; `svc #n; ret` is identified by its number
            if a & 0xffe0001f == 0xd4000001
                && b == 0xd65f03c0
                && !self.functions.contains_key(&target)
            {
                return Ok(Callee::Svc((a >> 5) & 0xffff));
            }
        }
        let Some(&end) = self.functions.get(&target) else {
            return Err(MatchError(format!(
                "callee has no verified boundary or import at {target:#x}"
            )));
        };
        Ok(Callee::Function(end - target, self.body(target)?.0.clone()))
    }

    pub fn fingerprint(&mut self, start: i64) -> Res<String> {
        if let Some(f) = self.fingerprints.get(&start) {
            return Ok(f.clone());
        }
        let (body, branches) = self.body(start)?.clone();
        let mut refs = Vec::new();
        for (off, target) in branches {
            refs.push((off, self.callee(target)?));
        }
        // json.dumps([body, refs], separators=(',', ':'))
        let mut j = String::from("[");
        json_str(&body, &mut j);
        j.push_str(",[");
        for (k, (off, c)) in refs.iter().enumerate() {
            if k > 0 {
                j.push(',');
            }
            j.push_str(&format!("[{off},"));
            match c {
                Callee::Import(n) => {
                    j.push_str("[\"import\",");
                    json_str(n, &mut j);
                    j.push(']');
                }
                Callee::Svc(n) => j.push_str(&format!("[\"svc\",{n}]")),
                Callee::Function(sz, d) => {
                    j.push_str(&format!("[\"function\",{sz},"));
                    json_str(d, &mut j);
                    j.push(']');
                }
            }
            j.push(']');
        }
        j.push_str("]]");
        let fp = hex(&Sha256::digest(j.as_bytes()));
        self.fingerprints.insert(start, fp.clone());
        Ok(fp)
    }

    /// The start of the one function of this size with one of these fingerprints; MatchError unless exactly one matches
    pub fn locate(&mut self, size: usize, fingerprints: &[&str]) -> Res<i64> {
        self.prefetch_size(size);
        let mut matches = Vec::new();
        // by index: `fingerprint` needs `self` mutably (its caches), and the list never changes
        for k in 0..self.function_list.len() {
            let (start, end) = self.function_list[k];
            if (end - start) as usize != size {
                continue;
            }
            let Ok(digest) = self.fingerprint(start) else {
                continue;
            };
            if fingerprints.contains(&digest.as_str()) {
                matches.push(start);
            }
        }
        if matches.len() != 1 {
            return Err(MatchError(format!(
                "{} matching functions (need exactly one)",
                matches.len()
            )));
        }
        Ok(matches[0])
    }

    /// the cuts of one function rule: `(off, old, new, reason + " [function match]")`
    fn match_fn(&mut self, f: &FnRule) -> Res<Vec<(i64, String, String, String)>> {
        let start = self.locate(f.size, f.fingerprints)?;
        let mut cuts = Vec::new();
        for c in f.cuts {
            let off = start + c.off;
            let ob = unhex(c.old);
            let cur = self.image.get(off as usize..off as usize + ob.len());
            if cur != Some(&ob[..]) {
                return Err(MatchError(format!("original bytes differ at {off:#x}")));
            }
            cuts.push((
                off,
                c.old.to_string(),
                c.new.to_string(),
                format!("{} [function match]", c.why),
            ));
        }
        Ok(cuts)
    }

    /// The cuts of a rule of one or several functions: every function must match exactly once, at distinct places, or
    /// there are none. A miss names every function that did not match.
    pub fn match_patch(&mut self, rule: &Rule) -> Res<Vec<(i64, String, String, String)>> {
        if !rule.multi {
            return self.match_fn(&rule.functions[0]);
        }
        let n = rule.functions.len();
        let (mut cuts, mut starts, mut misses) = (Vec::new(), Vec::new(), Vec::new());
        for (i, f) in rule.functions.iter().enumerate() {
            let got = match self.match_fn(f) {
                Ok(g) => g,
                Err(e) => {
                    misses.push(format!("function {} of {n} ({} bytes): {e}", i + 1, f.size));
                    continue;
                }
            };
            let start = got[0].0 - f.cuts[0].off;
            if starts.contains(&start) {
                misses.push(format!(
                    "function {} of {n} matched a function another one did",
                    i + 1
                ));
            }
            starts.push(start);
            cuts.extend(got);
        }
        if !misses.is_empty() {
            let mut m = misses.join("; ");
            if misses.len() < n {
                m.push_str(&format!("; the other {} matched", n - misses.len()));
            }
            return Err(MatchError(m));
        }
        Ok(cuts)
    }
}

/// A function an anchored MATCH_FRAME_STEP rule located, for its `find` (`nso_match.Function`): start and end (module offsets), `calls` (offsets in it of its calls
/// to the anchor), `words` (its instruction words) and the module's text words, with checks that read the code (`uses`, `branch_targets`). They fail with a
/// `MatchError` on code they cannot read
pub struct Function<'a> {
    pub start: i64,
    pub end: i64,
    pub calls: Vec<i64>,
    pub words: Vec<u32>,
    /// the module's text, up to the last whole word (`text`)
    text: &'a [u8],
}

impl<'a> Image<'a> {
    /// `Function(module, start, calls)`
    pub fn function(&self, start: i64, calls: Vec<i64>) -> Function<'a> {
        let end = self.functions[&start];
        let words = self.image[start as usize..end as usize]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        let lim = (self.text_end.min(self.image.len() as i64) / 4 * 4) as usize;
        Function {
            start,
            end,
            calls,
            words,
            text: &self.image[..lim],
        }
    }
}

impl Function<'_> {
    /// the module's text words (`text`)
    pub fn text_words(&self) -> impl Iterator<Item = u32> + '_ {
        self.text
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
    }

    /// The registers of `regs` (x16, v16, ...: w and x name one, b / h / s / d / q / v one) any instruction of the function reads or writes
    pub fn uses(&self, regs: &[&str]) -> Res<std::collections::BTreeSet<String>> {
        fn base(r: &str) -> String {
            if r.is_empty() {
                return String::new();
            }
            let (head, tail) = r.split_at(1);
            if !tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit()) {
                match head {
                    "w" => return format!("x{tail}"),
                    "b" | "h" | "s" | "d" | "q" | "v" => return format!("v{tail}"),
                    _ => {}
                }
            }
            r.to_string()
        }
        let code: Vec<u8> = self
            .words
            .iter()
            .flat_map(|&w| (if w == TRAP_WORD { BRK } else { w }).to_le_bytes())
            .collect();
        let ins = cs::disasm(&code, self.start);
        if ins.len() != self.words.len() {
            return Err(MatchError(format!(
                "undecodable function at {:#x}",
                self.start
            )));
        }
        let mut got = std::collections::BTreeSet::new();
        for op in &ins {
            let Some((read, written)) = &op.regs else {
                return Err(MatchError(format!(
                    "cannot read the registers of {} at {:#x}",
                    op.mn(),
                    op.address
                )));
            };
            for &r in read.iter().chain(written) {
                let b = base(cs::reg_name(r));
                if regs.contains(&b.as_str()) {
                    got.insert(b);
                }
            }
        }
        Ok(got)
    }

    /// The module offsets inside the function that a direct branch in it goes to
    pub fn branch_targets(&self) -> std::collections::BTreeSet<i64> {
        let mut out = std::collections::BTreeSet::new();
        for (i, &w) in self.words.iter().enumerate() {
            if let Some((_, delta)) = relative(w) {
                let t = self.start + 4 * i as i64 + delta;
                if self.start <= t && t < self.end {
                    out.insert(t);
                }
            }
        }
        out
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Python's `repr()` of a str (quote choice and escapes)
pub fn py_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut o = String::new();
    o.push(q);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c == q => {
                o.push('\\');
                o.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                o.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => o.push(c),
        }
    }
    o.push(q);
    o
}

/// One outcome row of `resolve` (for `<name>.match.tsv`): (patch name, cut offsets or None, why / which implementation)
pub type Outcome = (String, Option<Vec<i64>>, String);

/// An [`Image`] built on first use and shared by several [`resolve_in`] calls over the same image bytes. Everything an
/// `Image` keeps besides the bytes (function bounds, bodies, fingerprints, import slots) is a function of those bytes,
/// and the borrow keeps them unchanged while it lives, so a later call gets exactly what a fresh `Image` would give it,
/// without decoding the functions an earlier call fingerprinted again.
pub struct LazyImage<'a> {
    image: &'a [u8],
    text_end: i64,
    built: Option<Result<Image<'a>, MatchError>>,
}

impl<'a> LazyImage<'a> {
    pub fn new(image: &'a [u8], text_end: i64) -> LazyImage<'a> {
        LazyImage {
            image,
            text_end,
            built: None,
        }
    }
    fn get(&mut self) -> Result<&mut Image<'a>, &MatchError> {
        let (image, text_end) = (self.image, self.text_end);
        self.built
            .get_or_insert_with(|| Image::new(image, text_end))
            .as_mut()
            .map_err(|e| &*e)
    }
}

/// Verified cuts without mutating the image; refuse missing/ambiguous rules. `report` receives the log lines.
/// `red == false` logs a patch that does not apply as a plain line (SDK-wide patches, which a module may not need).
pub fn resolve(
    image: &[u8],
    text_end: i64,
    rules: &[Rule],
    report: &mut dyn FnMut(String),
    outcomes: Option<&mut Vec<Outcome>>,
    red: bool,
) -> Res<Vec<(i64, String, String, String)>> {
    resolve_in(
        &mut LazyImage::new(image, text_end),
        rules,
        report,
        outcomes,
        red,
    )
}

/// [`resolve`] on a shared [`LazyImage`] (built at the first call with rules; a damaged image gives every call the same
/// refusal it would give alone)
pub fn resolve_in(
    shared: &mut LazyImage,
    rules: &[Rule],
    report: &mut dyn FnMut(String),
    outcomes: Option<&mut Vec<Outcome>>,
    red: bool,
) -> Res<Vec<(i64, String, String, String)>> {
    if rules.is_empty() {
        return Ok(vec![]);
    }
    let mut local = Vec::new();
    let outcomes = outcomes.unwrap_or(&mut local);
    // rules with the same name are one patch's reviewed implementations: exactly one of them must match
    let mut groups: Vec<(&str, Vec<&Rule>)> = Vec::new();
    for r in rules {
        match groups.iter_mut().find(|(n, _)| *n == r.name) {
            Some((_, v)) => v.push(r),
            None => groups.push((r.name, vec![r])),
        }
    }
    fn missed(
        report: &mut dyn FnMut(String),
        red: bool,
        name: &str,
        why: &str,
        outcomes: &mut Vec<Outcome>,
    ) {
        report(format!(
            "{}function patch {} skipped: {}",
            if red { "[RED] " } else { "" },
            py_repr(name),
            why
        ));
        outcomes.push((name.to_string(), None, why.to_string()));
    }
    let module = match shared.get() {
        Ok(m) => m,
        Err(e) => {
            for (name, _) in &groups {
                missed(report, red, name, &e.0, outcomes);
            }
            return Ok(vec![]);
        }
    };
    let mut cuts = Vec::new();
    for (name, alternatives) in &groups {
        let (mut found, mut misses) = (Vec::new(), Vec::new());
        for (i, rule) in alternatives.iter().enumerate() {
            match module.match_patch(rule) {
                Ok(g) => found.push((i + 1, g)),
                Err(e) => misses.push(e.0),
            }
        }
        if found.len() != 1 {
            let why = if !found.is_empty() {
                format!("{} implementations match (need exactly one)", found.len())
            } else {
                misses.join("; ")
            };
            missed(report, red, name, &why, outcomes);
            continue;
        }
        let (i, got) = found.pop().unwrap();
        let offs: Vec<String> = got.iter().map(|c| format!("{:#x}", c.0)).collect();
        let mut line = format!(
            "function patch {}: matched at {}",
            py_repr(name),
            offs.join(", ")
        );
        if alternatives.len() > 1 {
            line.push_str(&format!(" (implementation {i} of {})", alternatives.len()));
        }
        report(line);
        outcomes.push((
            name.to_string(),
            Some(got.iter().map(|c| c.0).collect()),
            format!("implementation {i} of {}", alternatives.len()),
        ));
        cuts.extend(got);
    }
    let mut occupied: Vec<(i64, i64)> = Vec::new();
    for (off, old, _, _) in &cuts {
        let span = (*off, *off + (old.len() / 2) as i64);
        if occupied.iter().any(|&(a, b)| span.0 < b && a < span.1) {
            return Err(MatchError("function patches overlap".into()));
        }
        occupied.push(span);
    }
    Ok(cuts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 0x200-byte image with a MOD0 at 0x10, its dynamic section at 0x10 + `mod_rel`, DT_JMPREL = `j` (two
    /// R_AARCH64_JUMP_SLOT entries at 0x100: slot 0x1000 -> symbol 1 "foo", slot 0x1008 -> symbol `sym2`), DT_PLTRELSZ =
    /// `sz`, DT_SYMTAB 0x140, DT_STRTAB 0x180. The same builder, run through the shipped engine's `_import_slots`
    /// (extracted verbatim from `dm/tools/nso_match.py`), gives the maps asserted below.
    fn table(mod_rel: i32, j: u64, sz: u64, sym2: u64) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        let put = |b: &mut Vec<u8>, o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
        put(&mut b, 4, &0x10u32.to_le_bytes());
        put(&mut b, 0x10, b"MOD0");
        put(&mut b, 0x14, &mod_rel.to_le_bytes());
        for (i, (t, v)) in [
            (20i64, 7u64),
            (23, j),
            (2, sz),
            (6, 0x140),
            (5, 0x180),
            (0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut b, 0x30 + 16 * i, &t.to_le_bytes());
            put(&mut b, 0x38 + 16 * i, &v.to_le_bytes());
        }
        for (o, slot, sym) in [(0x100, 0x1000u64, 1u64), (0x118, 0x1008, sym2)] {
            put(&mut b, o, &slot.to_le_bytes());
            put(&mut b, o + 8, &((sym << 32) | 1026).to_le_bytes());
        }
        put(&mut b, 0x140 + 24, &1u32.to_le_bytes());
        put(&mut b, 0x140 + 48, &5u32.to_le_bytes());
        put(&mut b, 0x180, b"\0foo\0bar\0");
        b
    }

    fn slots(img: &[u8]) -> Vec<(i64, String)> {
        let mut m = Image {
            image: img,
            text_end: 0,
            function_list: Vec::new(),
            functions: HashMap::new(),
            bodies: HashMap::new(),
            fingerprints: HashMap::new(),
            imports: None,
        };
        let mut v: Vec<(i64, String)> = m
            .import_slots()
            .iter()
            .map(|(k, s)| (*k, s.clone()))
            .collect();
        v.sort();
        v
    }

    /// The damaged tables below each panicked (an out-of-range `rd64`/`rd32`, or `j + sz` overflowing) before the reads
    /// were bounded; the Python gives an empty map for all of them.
    #[test]
    fn a_damaged_dynamic_table_gives_an_empty_import_map_like_the_python() {
        let both = vec![(0x1000, "foo".to_string()), (0x1008, "bar".to_string())];
        assert_eq!(slots(&table(0x20, 0x100, 48, 2)), both, "the honest table");
        // DT_JMPREL 12 bytes before the end: the entry's info word is past it (was: rd64 out of range)
        assert_eq!(slots(&table(0x20, 0x200 - 12, 24, 2)), vec![]);
        // DT_PLTRELSZ = 2^64 - 1: the walk runs off the end (was: `j + sz` overflow, a panic in a debug build)
        assert_eq!(slots(&table(0x20, 0x100, u64::MAX, 2)), vec![]);
        // a symbol index far past the symbol table (was: rd32 out of range)
        assert_eq!(slots(&table(0x20, 0x100, 48, 0xffff_ffff)), vec![]);
        // a MOD0 dynamic offset before the start of the image: struct.unpack_from counts a negative offset from the end,
        // so the Python reads the same table here (was: a negative offset cast to usize, out of range)
        assert_eq!(slots(&table(0x30 - 0x10 - 0x200, 0x100, 48, 2)), both);
        // ... and further back than the image is long: struct.error
        assert_eq!(slots(&table(-0x400, 0x100, 48, 2)), vec![]);
        // DT_JMPREL >= 2^63: the Python raises an uncaught OverflowError (the whole run stops); here the map is empty
        assert_eq!(slots(&table(0x20, 1 << 63, 48, 2)), vec![]);
        // every truncation of the honest table: never a panic
        let honest = table(0x20, 0x100, 48, 2);
        for n in 0..honest.len() {
            let _ = slots(&honest[..n]);
        }
    }
}
