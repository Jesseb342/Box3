//! Unreal Engine's fixed frame rate, `UEngine::FixedFrameRate` on the engine object GEngine points to, found in main
//! without a build ID (`ue_fixed_rate.py`). Both links hold in any Unreal 4.22 to 5 build, each unique or nothing is
//! written: the property's reflection entry, GEngine where FEngineLoop::Init makes the engine, and the flag
//! bUseFixedFrameRate (a bitfield bool whose reflection entry holds the function that sets it).

use super::fps_target::writes;
use super::{find, word};
use crate::fde::{Rel, try_got_values};
use ibuilder_a64::bits::{adrp_page, is_adrp};
use std::collections::BTreeMap;

const NAME: &[u8] = b"FixedFrameRate\0";
const FLOAT: u8 = 0x0A; // EPropertyGenFlags::Float
const STORE_REACH: i64 = 0x100;
const RELOAD_REACH: i64 = 8;
const CALL_REACH: i64 = 6;
const BACK_REACH: i64 = 0x4000;

fn key() -> Vec<u8> {
    let mut k: Vec<u8> = "GameEngine"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    k.extend([0, 0]);
    k
}

/// {reflection entry offset: the property's offset in its class} of the float properties named FixedFrameRate
fn fields(img: &[u8], ro_off: i64, data_off: i64, rel: &Rel) -> Vec<(i64, i64)> {
    let mut names = Vec::new();
    let mut s = find(img, NAME, ro_off, data_off);
    while let Some(sv) = s {
        names.push(sv as i64);
        s = find(img, NAME, sv as i64 + 1, data_off);
    }
    let mut out = Vec::new();
    for (o, v) in rel.iter() {
        if !names.contains(&v) || o < data_off || o + 64 > img.len() as i64 {
            continue;
        }
        let ou = o as usize;
        let (kind, dim) = (
            img[ou + 24],
            i32::from_le_bytes(img[ou + 32..ou + 36].try_into().unwrap()),
        );
        if kind != FLOAT || dim != 1 {
            continue;
        }
        let a = u32::from_le_bytes(img[ou + 36..ou + 40].try_into().unwrap());
        let f = if a != 0 {
            a
        } else {
            u32::from_le_bytes(img[ou + 56..ou + 60].try_into().unwrap())
        }; // UE 4.22-5.0, else UE 5.1+
        if f != 0 && f % 4 == 0 && f < 0x4000 {
            out.push((o, f as i64));
        }
    }
    out
}

/// (byte offset, bit mask) of bUseFixedFrameRate in UEngine, from the set-bit function of its reflection entry
fn flag(img: &[u8], text_end: i64, ro_off: i64, data_off: i64, rel: &Rel) -> Option<(u32, u32)> {
    let s = find(img, b"bUseFixedFrameRate\0", ro_off, data_off)
        .map(|x| x as i64)
        .unwrap_or(-1);
    for (o, v) in rel.iter() {
        if v != s || o < data_off || img.get(o as usize + 24) != Some(&0x0C) {
            continue;
        }
        let mut fnp = None;
        let mut k = o + 8;
        while k < o + 0x50 {
            if let Some(t) = rel.get(k)
                && 0 < t
                && t < text_end
            {
                fnp = Some(t);
                break;
            }
            k += 8;
        }
        let Some(f) = fnp else { continue };
        let (ld, orr, st, ret) = (
            word(img, f),
            word(img, f + 4),
            word(img, f + 8),
            word(img, f + 12),
        );
        if ld & 0xFFC003E0 != 0x39400000 || st != (ld & !0x00400000) || ret != 0xD65F03C0 {
            continue; // ldrb wA, [x0, #off] / strb wA, [x0, #off] / ret
        }
        let a = ld & 31;
        if orr & 0xFFC003FF != (0x32000000 | a << 5 | a) || (orr >> 10) & 0x3F != 0 {
            continue; // orr wA, wA, #(one bit)
        }
        let mask = 1u32 << (32 - ((orr >> 16) & 0x3F) as i32).rem_euclid(32);
        if mask < 0x100 {
            return Some(((ld >> 10) & 0xFFF, mask));
        }
    }
    None
}

/// Word offsets of the `add xD, xN, #lo` that make the address of a UTF-16 "GameEngine" (alone or a longer string's
/// tail) after an adrp xN of its page
fn key_refs(img: &[u8], text_end: i64, ro_off: i64, data_off: i64) -> Vec<i64> {
    let kbytes = key();
    let mut out = Vec::new();
    let mut s = find(img, &kbytes, ro_off, data_off);
    while let Some(sv) = s {
        if sv % 2 == 0 {
            let lo = (sv & 0xFFF) as i64;
            let b1: [u8; 4] = [0, 1, 2, 3].map(|r| (((lo & 0x3F) << 2) as u8) | r);
            let hi_byte = (lo >> 6) as u8;
            let lim = (text_end as usize).min(img.len());
            // re.finditer over img[:text_end] with a lookahead at every byte offset p (p + 2 < text_end)
            let mut p = 0usize;
            while p + 2 < lim {
                if img[p + 2] == 0x91 && img[p + 1] == hi_byte && b1.contains(&img[p]) {
                    let j = p as i64 - 1;
                    if j % 4 == 0 && j >= 0 {
                        let w = word(img, j);
                        if w & 0xFFC00000 == 0x91000000 && ((w >> 10) & 0xFFF) as i64 == lo {
                            let n = (w >> 5) & 31;
                            if (((j - 20).max(0))..j).step_by(4).any(|i| {
                                let x = word(img, i);
                                is_adrp(x) && x & 31 == n && adrp_page(x, i) == (sv as i64 & !0xFFF)
                            }) {
                                out.push(j);
                            }
                        }
                    }
                }
                p += 1;
            }
        }
        s = find(img, &kbytes, sv as i64 + 2, data_off);
    }
    out.sort();
    out.dedup();
    out
}

/// The address register r holds at word offset i, from the last instruction before it that writes r
fn value(img: &[u8], rel: &Rel, i: i64, r: u32, depth: u32) -> Option<i64> {
    if depth > 3 {
        return None;
    }
    let lo = 0.max(i - BACK_REACH);
    let mut k = i - 4;
    while k > lo {
        let u = word(img, k);
        if is_adrp(u) && u & 31 == r {
            return Some(adrp_page(u, k));
        }
        if writes(u) != Some(r) {
            k -= 4;
            continue;
        }
        let n = (u >> 5) & 31;
        if u & 0xFFC00000 == 0x91000000 {
            return value(img, rel, k, n, depth + 1).map(|b| b + ((u >> 10) & 0xFFF) as i64);
        }
        if u & 0xFFC00000 == 0xF9400000 {
            // ldr xr, [xn, #imm]: a GOT slot holds the address
            return value(img, rel, k, n, depth + 1)
                .and_then(|b| rel.get(b + (((u >> 10) & 0xFFF) * 8) as i64));
        }
        if u & 0xFFE0FFE0 == 0xAA0003E0 {
            return value(img, rel, k, (u >> 16) & 31, depth + 1); // mov xr, xs
        }
        return None;
    }
    None
}

/// {GEngine candidate: [store offsets]}, in the order found
fn engine_global(
    img: &[u8],
    text_end: i64,
    ro_off: i64,
    data_off: i64,
    rel: &Rel,
) -> Vec<(i64, Vec<i64>)> {
    let mut found: Vec<(i64, Vec<i64>)> = Vec::new();
    for r#ref in key_refs(img, text_end, ro_off, data_off) {
        let mut k = r#ref + 4;
        let end = text_end.min(r#ref + STORE_REACH);
        while k < end {
            let u = word(img, k);
            if u & 0xFFC00000 != 0xF9000000 {
                k += 4;
                continue; // str xV, [xR, #lo]
            }
            let (r, lo) = ((u >> 5) & 31, (((u >> 10) & 0xFFF) * 8) as i64);
            let reload = 0xF9400000 | ((lo / 8) as u32) << 10 | r << 5; // ldr x0, [xR, #lo]
            let at = (k + 4..text_end.min(k + 4 * RELOAD_REACH))
                .step_by(4)
                .find(|&q| word(img, q) == reload);
            let Some(at) = at else {
                k += 4;
                continue;
            };
            if (k + 4..at)
                .step_by(4)
                .any(|q| writes(word(img, q)) == Some(r))
            {
                k += 4;
                continue;
            }
            if !(at + 4..text_end.min(at + 4 * CALL_REACH))
                .step_by(4)
                .any(|q| word(img, q) & 0xFFFFFC1F == 0xD63F0000)
            {
                k += 4;
                continue; // blr
            }
            let b = value(img, rel, k, r, 0);
            if let Some(b) = b
                && b + lo >= data_off
                && (b + lo) % 8 == 0
            {
                match found.iter_mut().find(|(g, _)| *g == b + lo) {
                    Some((_, v)) => v.push(k),
                    None => found.push((b + lo, vec![k])),
                }
            }
            break;
        }
    }
    found
}

/// (GEngine's offset in main, FixedFrameRate's offset in UEngine, bUseFixedFrameRate as byte offset << 8 | bit mask,
/// reason), or (None, None, None, why not); why starts "[RED] " when the property is there and the engine's creation
/// names more than one global, the property has more than one offset or its flag is not found
pub fn find_rate(
    img: &[u8],
    text_end: i64,
    ro_off: i64,
    data_off: i64,
) -> (Option<i64>, Option<i64>, Option<u32>, String) {
    let rel = match try_got_values(img) {
        Ok(r) => r,
        Err(e) => {
            return (
                None,
                None,
                None,
                format!(
                    "[RED] UEngine::FixedFrameRate: the module's relocations cannot be read ({e})"
                ),
            );
        }
    };
    let fs = fields(img, ro_off, data_off, &rel);
    if fs.is_empty() {
        return (None, None, None, "no UEngine::FixedFrameRate".into());
    }
    let mut offs: Vec<i64> = fs.iter().map(|x| x.1).collect();
    offs.sort();
    offs.dedup();
    if offs.len() > 1 {
        let l: Vec<String> = offs.iter().map(|f| format!("+{f:#x}")).collect();
        return (
            None,
            None,
            None,
            format!(
                "[RED] UEngine::FixedFrameRate: float properties of that name at {}",
                l.join(", ")
            ),
        );
    }
    let f = offs[0];
    let Some(fl) = flag(img, text_end, ro_off, data_off, &rel) else {
        return (
            None,
            None,
            None,
            format!(
                "[RED] UEngine::FixedFrameRate at +{f:#x}: no set-bit function of bUseFixedFrameRate of the known form"
            ),
        );
    };
    let gs = engine_global(img, text_end, ro_off, data_off, &rel);
    if gs.is_empty() {
        return (
            None,
            None,
            None,
            format!(
                "UEngine::FixedFrameRate at +{f:#x}: no engine creation (the \"GameEngine\" key, a store, its reload and a virtual call) names GEngine"
            ),
        );
    }
    if gs.len() > 1 {
        let mut sorted: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for (g, at) in &gs {
            sorted.insert(*g, at.clone());
        }
        let l: Vec<String> = sorted
            .iter()
            .map(|(g, at)| {
                format!(
                    "{g:#x} (at {})",
                    at.iter()
                        .map(|a| format!("{a:#x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect();
        return (
            None,
            None,
            None,
            format!(
                "[RED] UEngine::FixedFrameRate: the engine creation names {}: more than one global",
                l.join(", ")
            ),
        );
    }
    let (g, at) = gs.into_iter().next().unwrap();
    let min_entry = fs.iter().map(|x| x.0).min().unwrap();
    let atl: Vec<String> = at.iter().map(|a| format!("{a:#x}")).collect();
    (
        Some(g),
        Some(f),
        Some(fl.0 << 8 | fl.1),
        format!(
            "UEngine::FixedFrameRate at [{g:#x}]+{f:#x}, used while bit {:#x} of +{:#x} is set (GEngine, stored where the engine is made at {}; reflection entry {min_entry:#x})",
            fl.1,
            fl.0,
            atl.join(", ")
        ),
    )
}
