//! Unity's frame-rate settings, found in main through the engine's internal-call table, without a build ID
//! (`unity_fps.py`): `Application.targetFrameRate` and `QualitySettings.vSyncCount`.

use super::{find, find_all_img, text, word};
use crate::fde::{Rel, try_got_values};
use ibuilder_a64::bits::{adrp_page, is_adrp};
use std::collections::HashMap;

const TFR: &str = "UnityEngine.Application::set_targetFrameRate";
const VSYNC: &str = "UnityEngine.QualitySettings::get_vSyncCount";
const RET: u32 = 0xD65F03C0;

/// the target of b / bl at pc
fn branch(w: u32, pc: i64) -> i64 {
    let off = ((w & 0x3FFFFFF) << 2) as i64;
    pc + if off & (1 << 27) != 0 {
        off - (1 << 28)
    } else {
        off
    }
}

/// {internal call name: native function offset} from the name table and the function table right after it
fn icall_table(img: &[u8], rel: &Rel, ro_off: i64, data_off: i64) -> Vec<(String, i64)> {
    let name_at = |v: i64| -> Option<String> {
        if !(ro_off <= v && v < data_off) {
            return None;
        }
        let e = find(img, b"\0", v, v + 256);
        let s: &[u8] = match e {
            Some(e) if e as i64 > v => &img[v as usize..e],
            _ => b"",
        };
        // b'::' in s and s.isascii()
        if s.windows(2).any(|w| w == b"::") && s.is_ascii() {
            Some(String::from_utf8_lossy(s).into_owned())
        } else {
            None
        }
    };
    let mut pat = vec![0u8];
    pat.extend(TFR.as_bytes());
    pat.push(0);
    let Some(key) = find_all_img(img, &pat) else {
        return vec![];
    };
    let Some(slot) = rel.iter().find(|&(_, v)| v == key as i64 + 1).map(|x| x.0) else {
        return vec![];
    };
    let (mut start, mut end) = (slot, slot);
    while rel.get(start - 8).is_some_and(|v| name_at(v).is_some()) {
        start -= 8;
    }
    while rel.get(end).is_some_and(|v| name_at(v).is_some()) {
        end += 8;
    }
    let n = (end - start) / 8;
    if !(0..n).all(|i| rel.get(end + 8 * i).is_some_and(|v| 0 < v && v < ro_off)) {
        return vec![]; // the functions right after the names, one per name
    }
    let mut out: Vec<(String, i64)> = Vec::new();
    for i in 0..n {
        let name = name_at(rel.get(start + 8 * i).unwrap()).unwrap();
        let f = rel.get(end + 8 * i).unwrap();
        match out.iter_mut().find(|(n, _)| *n == name) {
            Some(e) => e.1 = f,
            None => out.push((name, f)),
        }
    }
    out
}

/// {internal call name: native function offset} for those of `names` that main registers from code (Unity 2019.4),
/// each registered exactly once
fn icall_code(
    img: &[u8],
    rel: &Rel,
    text_end: i64,
    ro_off: i64,
    data_off: i64,
    names: &[&str],
) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for name in names {
        let mut pat = vec![0u8];
        pat.extend(name.as_bytes());
        pat.push(0);
        let Some(s) = find(img, &pat, ro_off, data_off) else {
            continue;
        };
        let s = s as i64 + 1;
        let (lo, page) = (s & 0xFFF, s & !0xFFF);
        let word_ = 0x91000000u32 | (lo as u32) << 10; // add x0, x0, #lo
        let needle = word_.to_le_bytes();
        let t = text(img, text_end);
        let mut fns: Vec<i64> = Vec::new();
        for j in memchr::memmem::find_iter(t, &needle) {
            let j = j as i64;
            if j % 4 != 0
                || j < 16
                || !is_adrp(word(img, j - 4))
                || word(img, j - 4) & 31 != 0
                || adrp_page(word(img, j - 4), j - 4) != page
            {
                continue;
            }
            if word(img, j + 4) & 0xFC000000 != 0x94000000 {
                continue; // bl the register call
            }
            let (p, l) = (word(img, j - 12), word(img, j - 8)); // the function into x1, just before
            if !is_adrp(p) || p & 31 != 1 {
                continue;
            }
            let f = if l & 0xFFC003FF == 0xF9400021 {
                rel.get(adrp_page(p, j - 12) + (((l >> 10) & 0xFFF) * 8) as i64) // ldr x1, [x1, #slot]
            } else if l & 0xFFC003FF == 0x91000021 {
                Some(adrp_page(p, j - 12) + ((l >> 10) & 0xFFF) as i64) // add x1, x1, #lo
            } else {
                continue;
            };
            if let Some(f) = f
                && 0 <= f
                && f < text_end
                && !fns.contains(&f)
            {
                fns.push(f);
            }
        }
        if fns.len() == 1 {
            out.push((name.to_string(), fns[0]));
        }
    }
    out
}

/// f, or where the unconditional branches it starts with lead (up to `hops` of them), or None outside the text
fn follow(img: &[u8], mut f: i64, text_end: i64) -> Option<i64> {
    for _ in 0..2 {
        let u = word(img, f);
        if u & 0xFC000000 != 0x14000000 {
            break;
        }
        f = branch(u, f);
        if !(0 <= f && f < text_end) {
            return None;
        }
    }
    Some(f)
}

/// The global int32 the targetFrameRate setter stores w0 into (adrp xN, then str w0, [xN, #lo] among its first
/// instructions), or None
fn target_fps(img: &[u8], f: i64, text_end: i64) -> Option<i64> {
    let f = follow(img, f, text_end)?;
    let mut page: HashMap<u32, i64> = HashMap::new();
    for i in 0..8 {
        let a = f + 4 * i;
        let u = word(img, a);
        if is_adrp(u) {
            page.insert(u & 31, adrp_page(u, a));
            continue;
        }
        if u & 0xFFC00000 == 0xB9000000 && u & 31 == 0 {
            let n = (u >> 5) & 31;
            return page.get(&n).map(|p| p + (((u >> 10) & 0xFFF) * 4) as i64);
        }
        if u == RET {
            return None;
        }
    }
    None
}

/// The managers-array slot a manager getter reads
fn context_global(img: &[u8], mut f: i64, text_end: i64) -> Option<i64> {
    let w = |a: i64| word(img, a);
    let framed =
        w(f) == 0xA9BF7BFD && w(f + 4) == 0x910003FD && w(f + 16) == 0xA8C17BFD && w(f + 20) == RET;
    if framed {
        f += 8;
    }
    let u = w(f);
    if u & 0xFFE0001F != 0x52800000 {
        return None; // mov w0, #K
    }
    let v = w(f + 4);
    if v & 0xFC000000 != if framed { 0x94000000 } else { 0x14000000 } {
        return None; // b H (bl H in the framed form)
    }
    let h = branch(v, f + 4);
    if !(0 <= h && h < text_end - 12) {
        return None;
    }
    let (a, b, c, d) = (w(h), w(h + 4), w(h + 8), w(h + 12));
    if !is_adrp(a) || b & 0xFFC00000 != 0x91000000 || (b >> 5) & 31 != a & 31 {
        return None;
    }
    let (base, r) = (adrp_page(a, h) + ((b >> 10) & 0xFFF) as i64, b & 31);
    if c & 0xFFE0FC00 == 0xF860D800 && (c >> 5) & 31 == r && (c >> 16) & 31 == 0 {
        return Some(base + 8 * ((u >> 5) & 0xFFFF) as i64); // ldr x0, [xR, w0, sxtw #3]
    }
    // Unity 2017.4: add xR, xR, w0, sxtw #3; ldr x0, [xR, #off]
    if c & 0xFFE0FC00 == 0x8B20CC00
        && (c >> 16) & 31 == 0
        && c & 31 == r
        && (c >> 5) & 31 == r
        && d & 0xFFC003FF == (0xF9400000 | r << 5)
    {
        return Some(base + (((d >> 10) & 0xFFF) * 8) as i64 + 8 * ((u >> 5) & 0xFFFF) as i64);
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum R {
    Page(i64),
    Q,
    Idx,
    Arr,
    Imm(i64),
    Lvl(i64),
}

pub type Vsync = (i64, i64, i64, i64, i64);

/// (QualitySettings global, level index offset, levels offset, level size, count offset) from the vSyncCount getter
fn vsync_count(img: &[u8], f: i64, text_end: i64) -> Option<Vsync> {
    let f = follow(img, f, text_end)?;
    let mut regs: HashMap<u32, R> = HashMap::new();
    let (mut q, mut idx, mut arr): (Option<i64>, Option<i64>, Option<i64>) = (None, None, None);
    for i in 0..24 {
        let a = f + 4 * i;
        let u = word(img, a);
        let (d, n, m) = (u & 31, (u >> 5) & 31, (u >> 16) & 31);
        if u == RET {
            return None; // returned before the count was read
        }
        if is_adrp(u) {
            regs.insert(d, R::Page(adrp_page(u, a)));
        } else if u & 0xFC000000 == 0x94000000 {
            // bl: a manager getter, its result in x0
            let t = branch(u, a);
            q = if 0 <= t && t < text_end - 8 {
                context_global(img, t, text_end)
            } else {
                None
            };
            q?;
            regs.clear();
            regs.insert(0, R::Q);
        } else if u & 0xFFC00000 == 0xF9400000 {
            // ldr xD, [xN, #imm]
            let r = regs.get(&n).copied();
            let imm = (((u >> 10) & 0xFFF) * 8) as i64;
            match r {
                Some(R::Page(p)) if q.is_none() => {
                    q = Some(p + imm);
                    regs.insert(d, R::Q);
                }
                Some(R::Q) => {
                    arr = Some(imm);
                    regs.insert(d, R::Arr);
                }
                _ => {
                    regs.remove(&d);
                }
            }
        } else if u & 0xFFC00000 == 0xB9800000 {
            // ldrsw xD, [xN, #imm]
            if regs.get(&n) == Some(&R::Q) {
                idx = Some((((u >> 10) & 0xFFF) * 4) as i64);
                regs.insert(d, R::Idx);
            } else {
                regs.remove(&d);
            }
        } else if u & 0x7FE00000 == 0x52800000 {
            // mov wD / xD, #imm
            regs.insert(d, R::Imm(((u >> 5) & 0xFFFF) as i64));
        } else if u & 0xFFE00000 == 0x8B000000 && (u >> 22) & 3 == 0 {
            // add xD, xN, xM, lsl #s
            if regs.get(&n) == Some(&R::Arr) && regs.get(&m) == Some(&R::Idx) {
                regs.insert(d, R::Lvl(1i64 << ((u >> 10) & 63)));
            } else {
                regs.remove(&d);
            }
        } else if u & 0xFFE08000 == 0x9B000000 {
            // madd xD, xN, xM, xA
            let (ri, rt, ra) = (
                regs.get(&n).copied(),
                regs.get(&m).copied(),
                regs.get(&((u >> 10) & 31)).copied(),
            );
            match (ri, rt, ra) {
                (Some(R::Idx), Some(R::Imm(v)), Some(R::Arr)) => {
                    regs.insert(d, R::Lvl(v));
                }
                _ => {
                    regs.remove(&d);
                }
            }
        } else if u & 0xFFC00000 == 0xB9400000 {
            // ldr wD, [xN, #imm]: the count, from the level
            return match regs.get(&n) {
                Some(R::Lvl(sz)) if d == 0 => match (q, idx, arr) {
                    (Some(q), Some(idx), Some(arr)) => {
                        Some((q, idx, arr, *sz, (((u >> 10) & 0xFFF) * 4) as i64))
                    }
                    _ => None,
                },
                _ => None,
            };
        } else if u & 0x0A000000 != 0x08000000 || (u >> 22) & 1 != 0 {
            regs.remove(&d); // anything else that may write a register (stores and FP loads do not)
        }
    }
    None
}

#[derive(Default, Clone, Debug)]
pub struct UnityFps {
    pub target: Option<i64>,
    pub qs: Option<Vsync>,
}

/// ({target, qs} with what was found, reason); (empty, why) when main has no table. The reason has "[RED] " when the
/// table is there but a function's code was not read
pub fn find_fps(img: &[u8], text_end: i64, ro_off: i64, data_off: i64) -> (UnityFps, String) {
    let rel = match try_got_values(img) {
        Ok(r) => r,
        Err(e) => {
            return (
                UnityFps::default(),
                format!("[RED] Unity frame rate: the module's relocations cannot be read ({e})"),
            );
        }
    };
    let mut calls = icall_table(img, &rel, ro_off, data_off);
    if calls.is_empty() {
        calls = icall_code(img, &rel, text_end, ro_off, data_off, &[TFR, VSYNC]);
    }
    if calls.is_empty() {
        return (UnityFps::default(), "no Unity internal-call table".into());
    }
    let (mut out, mut why) = (UnityFps::default(), Vec::new());
    let get = |n: &str| calls.iter().find(|(k, _)| k == n).map(|x| x.1);
    if let Some(f) = get(TFR) {
        match target_fps(img, f, text_end) {
            Some(g) if g >= data_off => {
                out.target = Some(g);
                why.push(format!("targetFrameRate at {g:#x}"));
            }
            _ => why.push(format!("[RED] targetFrameRate setter at {f:#x} not read")),
        }
    }
    if let Some(f) = get(VSYNC) {
        match vsync_count(img, f, text_end) {
            Some(v) if v.0 >= data_off => {
                out.qs = Some(v);
                why.push(format!(
                    "vSyncCount at [[{:#x}]+{:#x}] + [[{:#x}]+{:#x}] * {:#x} + {:#x}",
                    v.0, v.2, v.0, v.1, v.3, v.4
                ));
            }
            _ => why.push(format!("[RED] vSyncCount getter at {f:#x} not read")),
        }
    }
    (
        out,
        format!("Unity internal calls ({}): {}", calls.len(), why.join(", ")),
    )
}
