//! Monolith's integer frame interval through reviewed engine functions (`monolith_fps.py`): whole unwind-function
//! fingerprints (see `matching`), addresses from relative relocations, never a build or title ID.

use crate::fde::{Rel, try_got_values};
use crate::matching::{Image, MatchError};
use ibuilder_a64::bits::{adrp_page, rd32};
use ibuilder_a64::cs;
use std::collections::{BTreeSet, HashMap};

struct Signature {
    size: usize,
    fingerprint: &'static str,
}
struct Implementation {
    name: &'static str,
    wait: Signature,
    duration: Signature,
    setter: Signature,
    margin_literal: Option<(i64, i64)>,
}

fn sig(size: usize, fingerprint: &'static str) -> Signature {
    Signature { size, fingerprint }
}

fn reviewed() -> Vec<Implementation> {
    vec![
        Implementation {
            name: "Monolith X",
            wait: sig(
                292,
                "117445a6c8a8990b03e8a0e8af7a1e52dbee46f8efac38e7f1fb9596981ef86e",
            ),
            duration: sig(
                152,
                "74a04be38c6f48c37b3ad9a1e3e341e35d0d19f0802f15a46d218517ebef526e",
            ),
            setter: sig(
                32,
                "5b3276a0309456b63d7a5ebf4477d5b4249b49b769e9033d540beb29823345ce",
            ),
            margin_literal: None,
        },
        Implementation {
            name: "Monolith 2",
            wait: sig(
                448,
                "86b7a37806e9cc4aa4840fe5517c9ee620c5becea0839ab48bbe2335bc788536",
            ),
            duration: sig(
                96,
                "e4096168156c605e698a4d5cadbb39819fcf1b6bbbc3f1621dbc4f1c25e569aa",
            ),
            setter: sig(
                32,
                "87d85cb2e136e4dd79434e7199db92e401b96aacce8ed6cb5dfa5fb816962dac",
            ),
            margin_literal: Some((0x70, 0x7c)),
        },
        Implementation {
            name: "Monolith 3",
            wait: sig(
                292,
                "12c6abb0e0a13b604256f1d30b2d32c3f1f54d064e2d26112cf249e363af4a5f",
            ),
            duration: sig(
                100,
                "e71a92e3001a7622d9e715d446c065457ebfd2c4b0463b1894a65274c323c2e8",
            ),
            setter: sig(
                32,
                "87d85cb2e136e4dd79434e7199db92e401b96aacce8ed6cb5dfa5fb816962dac",
            ),
            margin_literal: None,
        },
    ]
}

const RET: u32 = 0xd65f03c0;
const PERIOD: u32 = 0x3c888889;
const MARGIN: u32 = 0x3f7f3b64;

type Res<T> = Result<T, MatchError>;
fn me<T>(s: &str) -> Res<T> {
    Err(MatchError(s.to_string()))
}

fn matches(module: &mut Image, s: &Signature) -> Vec<i64> {
    // size filtering avoids disassembling unrelated functions in a large main
    let mut out = Vec::new();
    module.prefetch_size(s.size);
    // by index: `fingerprint` needs the module mutably (its caches), and the list never changes
    for i in 0..module.function_list.len() {
        let (start, end) = module.function_list[i];
        if (end - start) as usize != s.size {
            continue;
        }
        if let Ok(f) = module.fingerprint(start)
            && f == s.fingerprint
        {
            out.push(start);
        }
    }
    out
}

/// loader_census.adrp: (rd, page)
fn adrp(w: u32, pc: i64) -> Option<(u32, i64)> {
    if w & 0x9f000000 != 0x90000000 {
        None
    } else {
        Some((w & 31, adrp_page(w, pc)))
    }
}
/// loader_census.ldr64: (d, n, imm * 8)
fn ldr64(w: u32) -> Option<(u32, u32, i64)> {
    if w & 0xffc00000 == 0xf9400000 {
        Some((w & 31, (w >> 5) & 31, (((w >> 10) & 0xfff) * 8) as i64))
    } else {
        None
    }
}

/// Relative-relocation targets loaded through ADRP/LDR in one function.
fn got_refs(module: &Image, start: i64, relocations: &Rel) -> BTreeSet<i64> {
    let mut pages: HashMap<u32, i64> = HashMap::new();
    let mut refs = BTreeSet::new();
    let end = module.functions[&start];
    for ins in cs::disasm(&module.image[start as usize..end as usize], start) {
        let word = ins.word;
        let (page, load) = (adrp(word, ins.address), ldr64(word));
        let mut target = None;
        if let Some(l) = load
            && let Some(p) = pages.get(&l.1)
        {
            target = relocations.get(p + l.2);
        }
        if let Some((_, w)) = &ins.regs {
            for &reg in w {
                let name = cs::reg_name(reg);
                if (name.starts_with('x') || name.starts_with('w'))
                    && name.len() > 1
                    && name[1..].bytes().all(|c| c.is_ascii_digit())
                {
                    pages.remove(&name[1..].parse().unwrap());
                }
            }
        }
        if let Some(p) = page {
            pages.insert(p.0, p.1);
        }
        if let Some(t) = target {
            refs.insert(t);
        }
        match ins.mn() {
            "bl" | "blr" => {
                for r in 0..19 {
                    pages.remove(&r);
                }
            }
            "b" | "br" | "ret" => pages.clear(),
            _ => {}
        }
    }
    refs
}

#[derive(Clone, PartialEq)]
enum Val {
    Page(i64),
    Address(i64),
    Read(i64),
    Input,
}

/// Execute only the setter's address loads, integer load and two stores.
fn setter_fields(module: &Image, start: i64, relocations: &Rel) -> Res<(i64, i64)> {
    let mut values: HashMap<u32, Val> = HashMap::new();
    let mut writes: Vec<(i64, Option<Val>)> = Vec::new();
    let end = module.functions[&start];
    let mut at = start;
    while at < end {
        let word = rd32(module.image, at as usize);
        let here = at;
        at += 4;
        if let Some((d, p)) = adrp(word, here) {
            values.insert(d, Val::Page(p));
            continue;
        }
        if let Some((d, n, imm)) = ldr64(word) {
            match values.get(&n) {
                Some(Val::Page(p)) => {
                    let Some(t) = relocations.get(p + imm) else {
                        return me("setter GOT slot has no relative relocation");
                    };
                    values.insert(d, Val::Address(t));
                }
                _ => return me("setter has no GOT address"),
            }
            continue;
        }
        if word & 0xffc00000 == 0xb9400000 {
            // ldr wD,[xB,#offset]
            match values.get(&((word >> 5) & 31)) {
                Some(Val::Address(a)) if (word >> 10) & 0xfff == 0 => {
                    let a = *a;
                    values.insert(word & 31, Val::Read(a));
                }
                _ => return me("setter does not read the interval directly"),
            }
            continue;
        }
        if word & 0xffc00000 == 0xb9000000 {
            // str wS,[xB,#offset]
            let base = match values.get(&((word >> 5) & 31)) {
                Some(Val::Address(a)) if (word >> 10) & 0xfff == 0 => *a,
                _ => return me("setter does not write the interval directly"),
            };
            let source = if word & 31 == 0 {
                Some(Val::Input)
            } else {
                values.get(&(word & 31)).cloned()
            };
            writes.push((base, source));
            continue;
        }
        if word == RET && here == end - 4 {
            continue;
        }
        return me("setter contains an unreviewed operation");
    }
    if writes.len() != 2
        || writes[0].1 != Some(Val::Input)
        || writes[1].1 != Some(Val::Read(writes[0].0))
    {
        return me("setter does not save the old interval");
    }
    let (current, previous) = (writes[0].0, writes[1].0);
    if previous != current + 4 {
        return me("previous interval is not beside the current one");
    }
    Ok((current, previous))
}

fn literal(img: &[u8], page_at: i64, load_at: i64) -> Res<i64> {
    let page = adrp(rd32(img, page_at as usize), page_at);
    let word = rd32(img, load_at as usize);
    match page {
        Some((d, p)) if word & 0xffc00000 == 0xbd400000 && (word >> 5) & 31 == d => {
            Ok(p + (((word >> 10) & 0xfff) * 4) as i64)
        }
        _ => me("float literal has no reviewed ADRP/LDR address"),
    }
}

/// The context method must return exactly 1/60, including literal data.
fn period(module: &Image, start: i64, ro_off: i64, data_off: i64) -> bool {
    let size = module.functions.get(&start).map(|e| e - start).unwrap_or(0); // functions.get(start, start) - start
    let img = module.image;
    if size == 16 {
        let (a, b, c, d) = (
            rd32(img, start as usize),
            rd32(img, start as usize + 4),
            rd32(img, start as usize + 8),
            rd32(img, start as usize + 12),
        );
        if a & 0xffe00000 == 0x52800000
            && b & 0xffe00000 == 0x72a00000
            && a & 31 == b & 31
            && c == (0x1e270000 | (a & 31) << 5)
            && d == RET
        {
            return ((a >> 5) & 0xffff) | ((b >> 5) & 0xffff) << 16 == PERIOD;
        }
    }
    if size == 12 {
        let (b, c) = (rd32(img, start as usize + 4), rd32(img, start as usize + 8));
        if b & 31 == 0 && c == RET {
            let Ok(l) = literal(img, start, start + 4) else {
                return false;
            };
            return ro_off <= l && l <= data_off - 4 && rd32(img, l as usize) == PERIOD;
        }
    }
    false
}

/// (interval offset, evidence), or (None, why); a broken match is [RED].
pub fn find(img: &[u8], text_end: i64, ro_off: i64, data_off: i64) -> (Option<i64>, String) {
    let Ok(mut module) = Image::new(img, text_end) else {
        return (
            None,
            "no Monolith frame interval (no complete function boundaries)".into(),
        );
    };
    let (mut found, mut failures): (Vec<(i64, String)>, Vec<String>) = (Vec::new(), Vec::new());
    let mut relocations: Option<Rel> = None;
    for imp in reviewed() {
        let waits = matches(&mut module, &imp.wait);
        if waits.is_empty() {
            continue;
        }
        let r: Res<(i64, String)> = (|| {
            if waits.len() != 1 {
                return Err(MatchError(format!("{} matching waits", waits.len())));
            }
            let (duration, setter) = (
                matches(&mut module, &imp.duration),
                matches(&mut module, &imp.setter),
            );
            if duration.len() != 1 || setter.len() != 1 {
                return Err(MatchError(format!(
                    "{} duration getters and {} setters",
                    duration.len(),
                    setter.len()
                )));
            }
            let (wait, duration, setter) = (waits[0], duration[0], setter[0]);
            if relocations.is_none() {
                relocations = Some(try_got_values(img).map_err(|e| {
                    MatchError(format!("the module's relocations cannot be read ({e})"))
                })?);
            }
            let rel = relocations.as_ref().unwrap();
            let (current, previous) = setter_fields(&module, setter, rel)?;
            if current & 3 != 0 || !(data_off <= current && current <= img.len() as i64 - 8) {
                return me("interval pair is outside writable module data");
            }
            for off in [current, previous] {
                let v = rd32(img, off as usize) as i32;
                if !matches!(v, -1..=4) {
                    return me("interval pair has unexpected initial values");
                }
            }
            let shared: BTreeSet<i64> = got_refs(&module, wait, rel)
                .intersection(&got_refs(&module, duration, rel))
                .copied()
                .collect();
            if !shared.contains(&current) || shared.len() != 2 {
                return me("wait and duration getter do not share the interval and context");
            }
            let context = *shared.iter().find(|&&x| x != current).unwrap();
            if context & 7 != 0 || !(data_off <= context && context <= img.len() as i64 - 8) {
                return me("context pointer is outside writable module data");
            }
            let tables: Vec<i64> = rel
                .iter()
                .filter(|&(slot, target)| {
                    target == wait
                        && slot >= ro_off + 24
                        && period(&module, rel.get(slot - 24).unwrap_or(-1), ro_off, data_off)
                })
                .map(|(s, _)| s)
                .collect();
            if tables.is_empty() {
                return me("wait has no context vtable with a 1/60 period");
            }
            if let Some((a, b)) = imp.margin_literal {
                let at = literal(img, wait + a, wait + b)?;
                if !(ro_off <= at && at <= data_off - 4) || rd32(img, at as usize) != MARGIN {
                    return me("wait margin literal is not 0.997");
                }
            }
            Ok((
                current,
                format!(
                    "{} frame interval at {current:#x}: setter {setter:#x}, duration {duration:#x}, wait {wait:#x}, context {context:#x}",
                    imp.name
                ),
            ))
        })();
        match r {
            Ok(f) => found.push(f),
            Err(e) => failures.push(format!("{}: {}", imp.name, e.0)),
        }
    }
    if !failures.is_empty() {
        return (
            None,
            format!("[RED] Monolith frame interval: {}", failures.join("; ")),
        );
    }
    if found.len() > 1 {
        return (
            None,
            format!(
                "[RED] Monolith frame interval: {} complete implementations qualify",
                found.len()
            ),
        );
    }
    match found.pop() {
        Some((o, w)) => (Some(o), w),
        None => (None, "no reviewed Monolith frame interval".into()),
    }
}
