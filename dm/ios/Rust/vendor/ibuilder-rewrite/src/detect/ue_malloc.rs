//! Unreal Engine 4 / 5's FMallocBinned3 in any module, found by what the engine itself holds, without a build ID
//! (`ue_malloc.py`). The chain, each link unique or nothing is cut: the allocator's name (UTF-16 "Binned3"), its
//! getter (GetDescriptiveName), the one data word holding the getter (a vtable slot), the constructor (the one
//! function other than the vtable's two destructors that stores the vtable's address), and its call sites.

use super::{find, text, word};
use crate::fde::{Rel, try_got_values};
use ibuilder_a64::bits::{adrp_page, is_adrp, rd64};
use std::collections::{BTreeMap, BTreeSet};

/// the getter's slot -> the slot layouts of hle_uemalloc.c
fn layout(slot: i64) -> Option<&'static str> {
    match slot {
        19 => Some("Unreal Engine 4.26 / 4.27"),
        22 => Some("Unreal Engine 5"),
        26 => Some("Unreal Engine 5.6"),
        _ => None,
    }
}
const RET: u32 = 0xD65F03C0;

pub struct Found {
    pub calls: Vec<i64>,
    pub vtable: i64,
    pub slot: i64,
}

fn is_adrp_rd(w: u32, rd: u32) -> bool {
    is_adrp(w) && w & 31 == rd
}

/// (Some(found), reason) when the chain holds; (None, why not) otherwise, with why starting "[RED] " when the
/// allocator is there but cannot be replaced (its pools would take the address space)
pub fn find_malloc(
    img: &[u8],
    text_end: i64,
    ro_off: i64,
    data_off: i64,
) -> (Option<Found>, String) {
    let name: Vec<u8> = "Binned3"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .chain([0, 0])
        .collect();
    let mut names = Vec::new();
    let mut s: i64 = -1;
    loop {
        match find(img, &name, s + 1, data_off) {
            None => break,
            Some(p) => {
                let p = p as i64;
                s = p;
                if p >= ro_off
                    && p % 2 == 0
                    && (p == ro_off || img[p as usize - 2..p as usize] == [0, 0])
                {
                    names.push(p);
                }
            }
        }
    }
    if names.is_empty() {
        return (None, "no FMallocBinned3 name".into());
    }
    if names.len() > 1 {
        let l: Vec<String> = names.iter().map(|x| format!("{x:#x}")).collect();
        return (
            None,
            format!(
                "[RED] {} FMallocBinned3 names: {}",
                names.len(),
                l.join(", ")
            ),
        );
    }
    let s = names[0];
    let mut tail = Vec::new();
    tail.extend((0x91000000u32 | ((s & 0xFFF) as u32) << 10).to_le_bytes()); // add x0, x0, #lo
    tail.extend(RET.to_le_bytes());
    let mut getters = Vec::new();
    let mut a: i64 = -1;
    loop {
        match find(img, &tail, a + 1, text_end) {
            None => break,
            Some(p) => {
                let p = p as i64;
                a = p;
                if p % 4 == 0
                    && p >= 4
                    && is_adrp_rd(word(img, p - 4), 0)
                    && adrp_page(word(img, p - 4), p - 4) == (s & !0xFFF)
                {
                    getters.push(p - 4);
                }
            }
        }
    }
    if getters.len() != 1 {
        return (
            None,
            format!(
                "[RED] FMallocBinned3 name at {s:#x}: {} getters",
                getters.len()
            ),
        );
    }
    let g = getters[0];
    // a module whose relocation table runs off the image is damaged (the Python's reader raises there): said, not guessed at
    let rel: Rel = match try_got_values(img) {
        Ok(r) => r,
        Err(e) => {
            return (
                None,
                format!(
                    "[RED] FMallocBinned3 name at {s:#x}: the module's relocations cannot be read ({e})"
                ),
            );
        }
    };
    let value = |a: i64| -> i64 { rel.get(a).unwrap_or_else(|| rd64(img, a as usize) as i64) };
    let mut slots: Vec<i64> = rel
        .iter()
        .filter(|&(o, v)| v == g && o >= data_off)
        .map(|x| x.0)
        .collect();
    // values in place (a module without relative relocations, or RELR)
    let gb = (g as u64).to_le_bytes();
    let mut a = data_off - 8;
    loop {
        // img.find(pack('<Q', g), a + 8)
        match find(img, &gb, a + 8, img.len() as i64) {
            None => break,
            Some(p) => {
                a = p as i64;
                if a % 8 == 0 && !slots.contains(&a) {
                    slots.push(a);
                }
            }
        }
    }
    if slots.len() != 1 {
        return (
            None,
            format!(
                "[RED] FMallocBinned3 getter at {g:#x}: {} vtable slots",
                slots.len()
            ),
        );
    }
    let is_code = |v: i64| 0 < v && v < text_end && v % 4 == 0;
    let mut vt = slots[0];
    while vt - 8 >= data_off && is_code(value(vt - 8)) {
        vt -= 8;
    }
    let slot = (slots[0] - vt) / 8;
    if (value(vt - 16), value(vt - 8)) != (0, 0) {
        return (
            None,
            format!(
                "[RED] FMallocBinned3 vtable at {vt:#x}: no offset to top and RTTI words of 0 before it"
            ),
        );
    }
    let Some(lay) = layout(slot) else {
        return (
            None,
            format!(
                "[RED] FMallocBinned3 vtable at {vt:#x}: the name getter is slot {slot}, a slot layout the host does not know"
            ),
        );
    };
    let dtors: BTreeSet<i64> = [value(vt), value(vt + 8)].into_iter().collect();
    // direct calls and jumps in the text: bl (top bits 100101) and b (000101), by target
    let t = text(img, text_end);
    let (mut bl, mut b): (BTreeMap<i64, Vec<i64>>, BTreeMap<i64, Vec<i64>>) =
        (BTreeMap::new(), BTreeMap::new());
    let mut a = 0usize;
    while a + 4 <= t.len() {
        let top = t[a + 3];
        if matches!(top, 0x94..=0x97 | 0x14..=0x17) {
            let w = word(img, a as i64);
            let tg = a as i64 + ((((w & 0x3FFFFFF) ^ 0x2000000) as i64) - 0x2000000) * 4;
            (if w >> 26 == 0x25 { &mut bl } else { &mut b })
                .entry(tg)
                .or_default()
                .push(a as i64);
        }
        a += 4;
    }
    // stores of the vtable's address: add xD, xN, #lo (after an adrp xN of its page), then str xD, [xM]
    let lo = (vt & 0xFFF) as u32;
    let hi_byte = (lo >> 6) as u8;
    let mut ctors: BTreeSet<i64> = BTreeSet::new();
    let mut a = 0usize;
    while a + 4 <= t.len() {
        if t[a + 2] == hi_byte && t[a + 3] == 0x91 {
            let w = word(img, a as i64);
            if (w >> 10) & 0xFFF == lo {
                let (n, d) = ((w >> 5) & 31, w & 31);
                let ai = a as i64;
                if (((ai - 32).max(0))..ai).step_by(4).any(|p| {
                    is_adrp_rd(word(img, p), n) && adrp_page(word(img, p), p) == (vt & !0xFFF)
                }) && (ai + 4..text_end.min(ai + 48))
                    .step_by(4)
                    .any(|q| word(img, q) & 0xFFFFFC1F == (0xF9000000 | d))
                {
                    let start = bl
                        .keys()
                        .chain(b.keys())
                        .chain(dtors.iter())
                        .filter(|&&t| t <= ai)
                        .max()
                        .copied();
                    match start {
                        Some(start) if !(start..ai).step_by(4).any(|q| word(img, q) == RET) => {
                            if !dtors.contains(&start) {
                                ctors.insert(start);
                            }
                        }
                        _ => {
                            return (
                                None,
                                format!(
                                    "[RED] FMallocBinned3 vtable at {vt:#x}: no function start for its store at {ai:#x}"
                                ),
                            );
                        }
                    }
                }
            }
        }
        a += 4;
    }
    if ctors.len() != 1 {
        let l: Vec<String> = ctors.iter().map(|x| format!("{x:#x}")).collect();
        return (
            None,
            format!(
                "[RED] FMallocBinned3 vtable at {vt:#x}: {} constructors ({})",
                ctors.len(),
                l.join(", ")
            ),
        );
    }
    let c = *ctors.iter().next().unwrap();
    let mut calls = bl.get(&c).cloned().unwrap_or_default();
    calls.sort();
    let jumps = b.get(&c).map(|v| v.len()).unwrap_or(0);
    if calls.is_empty() || jumps != 0 {
        return (
            None,
            format!(
                "[RED] FMallocBinned3 constructor at {c:#x}: {} calls and {jumps} jumps, not calls alone",
                calls.len()
            ),
        );
    }
    let cl: Vec<String> = calls.iter().map(|x| format!("{x:#x}")).collect();
    let why = format!(
        "FMallocBinned3 ({lay}): its constructor at {c:#x}, called at {}; its vtable {vt:#x}, the name getter slot {slot}",
        cl.join(", ")
    );
    (
        Some(Found {
            calls,
            vtable: vt,
            slot,
        }),
        why,
    )
}
