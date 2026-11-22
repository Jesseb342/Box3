//! Unreal console variables in main found by their registered names, without a build ID (`ue_cvar.py`).
//!
//! A TAutoConsoleVariable is a global in main's data: its static constructor loads the name (adrp + add), registers
//! it through IConsoleManager (a blr), takes the object's address (adrp + add) and stores the variable's value
//! pointer at +0x10 (`str x0, [xN, #0x10]`).

use super::{find, word};
use ibuilder_a64::bits::{add_imm, adrp_page, branch_target, is_adrp};
use std::collections::{BTreeSet, HashMap, HashSet};

/// the variables the host may write
pub const NAMES: [&str; 5] = [
    "t.MaxFPS",
    "rhi.SyncInterval",
    "nvn.SyncInterval",
    "r.Streaming.PoolSize",
    "Project.FrameRateLimit",
];
const RET: u32 = 0xD65F03C0;

/// Whether the instruction `u` may write general register `r` (r < 31). Errs towards yes.
pub fn writes(u: u32, r: u32) -> bool {
    let (d, n, t2) = (u & 31, (u >> 5) & 31, (u >> 10) & 31);
    if u & 0x7C000000 == 0x14000000 {
        return u >> 31 != 0 && r == 30; // bl writes x30
    }
    if u & 0x1C000000 == 0x10000000 {
        return d == r;
    }
    if u & 0x0E000000 == 0x0A000000 {
        return d == r;
    }
    if u & 0x0A000000 == 0x08000000 {
        // loads and stores
        if u & 0x3F000000 == 0x08000000 {
            return r == d || r == t2 || r == (u >> 16) & 31;
        }
        if u & 0x3A000000 == 0x28000000 {
            return ((u >> 22) & 1 != 0 && (u >> 26) & 1 == 0 && (r == d || r == t2))
                || (matches!((u >> 23) & 3, 1 | 3) && r == n);
        }
        if u & 0x3B000000 == 0x18000000 {
            return d == r;
        }
        if u & 0x3B000000 == 0x38000000 {
            if (u >> 21) & 1 != 0 && (u >> 10) & 3 == 0 {
                return d == r; // atomics
            }
            if (u >> 21) & 1 == 0 && (u >> 10) & 1 != 0 && r == n {
                return true; // pre- and post-index
            }
            return (u >> 22) & 3 != 0 && d == r && (u >> 26) & 1 == 0;
        }
        if u & 0x3B000000 == 0x39000000 {
            return (u >> 22) & 3 != 0 && d == r && (u >> 26) & 1 == 0;
        }
        return false;
    }
    if u & 0x0E000000 == 0x0E000000 {
        return u & 0x5F20FC00 == 0x1E200000 && d == r;
    }
    if u & 0xFFF00000 == 0xD5300000 {
        return d == r;
    }
    false
}

/// The address in xr at byte offset t when the code before t made it by adrp xr (+ add xr, xr) with no other write
/// to xr since, and every path to t passes there.
pub fn base_of(img: &[u8], text_end: i64, r: u32, t: i64) -> Option<i64> {
    let mut lo: Option<i64> = None;
    let stop = (-4i64).max(t - 4 * 4096);
    let mut s = t - 4;
    let mut u = 0u32;
    let mut found = false;
    while s > stop {
        u = word(img, s);
        if u == RET || u & 0xFFFFFC1F == 0xD61F0000 {
            return None;
        }
        if u & 0xFC000000 == 0x14000000 {
            // b, but not over an else block
            match branch_target(u, s) {
                Some(target) if s < target && target <= t => {}
                _ => return None,
            }
        }
        if r < 19 && (u & 0xFC000000 == 0x94000000 || u & 0xFFFFFC1F == 0xD63F0000) {
            return None;
        }
        if writes(u, r) {
            if is_adrp(u) && u & 31 == r {
                found = true;
                break;
            }
            if lo.is_none()
                && let Some(a) = add_imm(u)
                && a.0 == a.1
                && a.1 == r
            {
                lo = Some(a.2);
                s -= 4;
                continue;
            }
            return None;
        }
        s -= 4;
    }
    if !found {
        return None;
    }
    let mut b = (s - 0x100000).max(0);
    let hi = text_end.min(t + 0x100000);
    while b < hi {
        if !(s <= b && b < t)
            && let Some(x) = branch_target(word(img, b), b)
            && s < x
            && x <= t
        {
            return None;
        }
        b += 4;
    }
    Some(adrp_page(u, s) + lo.unwrap_or(0))
}

/// The object registered under the name whose reference ends at byte offset j (`add x1, the name`), or None.
pub fn registered_at(img: &[u8], text_end: i64, j: i64) -> Option<i64> {
    let name_add = add_imm(word(img, j))?;
    if name_add.0 != 1 {
        return None;
    }
    let mut val: HashMap<u32, i64> = HashMap::new();
    let (mut name, mut registered) = (false, false);
    let mut stored: HashSet<(u32, i64)> = HashSet::new();
    let mut after = 0;
    let mut t = (j - 64).max(0);
    let end = text_end.min(j + 192);
    while t < end {
        let u = word(img, t);
        let call = u & 0xFC000000 == 0x94000000 || u & 0xFFFFFC1F == 0xD63F0000;
        if t < j && (call || u & 0xFC000000 == 0x14000000 || u == RET) {
            val.clear();
            t += 4;
            continue;
        }
        if call {
            if !registered {
                if !name {
                    return None;
                }
                if u >> 26 == 0x25 {
                    return val.get(&0).copied();
                }
                registered = true;
            } else {
                after += 1;
            }
            for r in 0..19 {
                val.remove(&r);
            }
            stored.retain(|(n, _)| *n >= 19);
            name = false;
            t += 4;
            continue;
        }
        if u & 0xFC000000 == 0x14000000 || u == RET {
            break;
        }
        if registered && u & 0xFFC00000 == 0xF9000000 {
            let (n, k) = ((u >> 5) & 31, (((u >> 10) & 0xFFF) * 8) as i64);
            if u & 31 == 0 && k == 0x10 && val.contains_key(&n) {
                return val.get(&n).copied();
            }
            if u & 31 == 0 && after != 0 && !val.contains_key(&n) && stored.contains(&(n, k - 0x10))
            {
                return base_of(img, text_end, n, t).map(|b| b + k - 0x10);
            }
            stored.insert((n, k));
            t += 4;
            continue;
        }
        let (a, d) = (add_imm(u), u & 31);
        let mut v: Option<i64> = None;
        if is_adrp(u) {
            if registered && d == 1 {
                break;
            }
            v = Some(adrp_page(u, t));
        } else if let Some(a) = a {
            v = val.get(&a.1).map(|x| x + a.2);
        } else if u & 0xFFE0FFE0 == 0xAA0003E0 {
            v = val.get(&((u >> 16) & 31)).copied();
        } else if u & 0x0A000000 == 0x08000000 {
            if (u >> 22) & 1 == 0 {
                t += 4;
                continue; // a store writes no register
            }
            if u & 0x3A000000 == 0x28000000 {
                val.remove(&((u >> 10) & 31));
            }
        } else if u & 0x1C000000 == 0x14000000 {
            t += 4;
            continue; // branches, system instructions
        }
        if d == 1 {
            name = t == j;
        }
        match v {
            None => {
                val.remove(&d);
            }
            Some(v) => {
                val.insert(d, v);
            }
        }
        t += 4;
    }
    None
}

/// (main's offset of the TAutoConsoleVariable registered under `name`, reason), or (None, why not); why starts
/// "[RED] " when the name is registered at more than one object
pub fn find_name(
    img: &[u8],
    text_end: i64,
    ro_off: i64,
    data_off: i64,
    name: &str,
) -> (Option<i64>, String) {
    let mut objs: BTreeSet<i64> = BTreeSet::new();
    for z in [2usize, 4] {
        // TCHAR: UTF-16 (UE 4.2x and 5), UTF-32 (older Switch builds)
        let mut pat: Vec<u8> = Vec::new();
        for c in name.chars() {
            if z == 2 {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    pat.extend_from_slice(&u.to_le_bytes());
                }
            } else {
                pat.extend_from_slice(&(c as u32).to_le_bytes());
            }
        }
        pat.extend(std::iter::repeat_n(0u8, z));
        let mut s = find(img, &pat, ro_off, data_off);
        while let Some(sv) = s {
            if sv % z == 0 {
                // its references: add xD, xN, #lo (after an adrp xN of its page, at most 5 words before)
                let lo = (sv & 0xFFF) as i64;
                let b1: [u8; 4] = [0, 1, 2, 3].map(|r| (((lo & 0x3F) << 2) as u8) | r);
                let hi_byte = (lo >> 6) as u8;
                // the Python regex is a lookahead at every byte offset p in [1, text_end): img[p] in b1,
                // img[p+1] == lo >> 6, img[p+2] == 0x91 (p + 2 < text_end)
                let lim = (text_end as usize).min(img.len());
                let mut p = 1usize;
                while p + 2 < lim {
                    if img[p + 2] == 0x91 && img[p + 1] == hi_byte && b1.contains(&img[p]) {
                        let j = p as i64 - 1;
                        if j % 4 == 0
                            && let Some(a) = add_imm(word(img, j))
                            && a.2 == lo
                        {
                            let ok = (((j - 20).max(0))..j).step_by(4).any(|i| {
                                // range(max(0, j - 20), j, 4) starts at max(0, j-20), stepping 4
                                let w = word(img, i);
                                is_adrp(w)
                                    && w & 31 == a.1
                                    && adrp_page(w, i) == (sv as i64 & !0xFFF)
                            });
                            if ok && let Some(o) = registered_at(img, text_end, j) {
                                objs.insert(o);
                            }
                        }
                    }
                    p += 1;
                }
            }
            s = find(img, &pat, sv as i64 + z as i64, data_off);
        }
    }
    if objs.is_empty() {
        return (None, format!("{name}: not registered"));
    }
    if objs.len() > 1 {
        let list: Vec<String> = objs.iter().map(|o| format!("{o:#x}")).collect();
        return (
            None,
            format!(
                "[RED] {name}: registered at {} objects ({})",
                objs.len(),
                list.join(", ")
            ),
        );
    }
    let o = *objs.iter().next().unwrap();
    (Some(o), format!("{name} at {o:#x}"))
}

/// {name: offset} of the NAMES registered once (in NAMES order), and the reasons of those not found (a [RED] one first)
pub fn find_all(
    img: &[u8],
    text_end: i64,
    ro_off: i64,
    data_off: i64,
) -> (Vec<(String, i64)>, Vec<String>) {
    let (mut found, mut why) = (Vec::new(), Vec::new());
    for n in NAMES {
        let (o, r) = find_name(img, text_end, ro_off, data_off, n);
        match o {
            Some(o) => found.push((n.to_string(), o)),
            None => why.push(r),
        }
    }
    // sorted(why, key=lambda r: not r.startswith('[RED] ')): stable, RED first
    let (mut red, rest): (Vec<_>, Vec<_>) = why.into_iter().partition(|r| r.starts_with("[RED] "));
    red.extend(rest);
    (found, red)
}
