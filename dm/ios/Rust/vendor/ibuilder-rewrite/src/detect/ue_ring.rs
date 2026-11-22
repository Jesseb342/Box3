//! Unreal Engine 4's NVN dynamic buffers keep 4 copies instead of 3, found by the engine's own code, without a build
//! ID (`ue_ring.py`): the load of the copy count in the buffer's constructor becomes a mov.
//!
//! The chain, each link unique or nothing changes: the variable's name (UTF-16) in ro; its registration; the lock's
//! rotation over the slots at +8; the constructor's load of the count on the BUF_Dynamic path; the slot layout before it.

use super::{find, text, word};
use crate::fde::got_values;
use ibuilder_a64::bits::rd32;

const NAME: &str = "nvn.NumBufferedFrames";
const COPIES: u32 = 4;
const BACK: i64 = 0x200; // how far before the load the constructor's start of the object can be

fn adrp_page(w: u32, pc: i64) -> Option<i64> {
    if w & 0x9F000000 != 0x90000000 {
        return None;
    }
    let mut imm = (((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3)) as i64;
    if imm & (1 << 20) != 0 {
        imm -= 1 << 21;
    }
    Some((pc & !0xFFF) + (imm << 12))
}

/// The address of the int registered under the name at offset `name` of the image, or None: adrp + add x1 of the
/// name, then adrp + add x2 within 8 instructions
fn registered(img: &[u8], text_end: i64, name: i64) -> Option<i64> {
    let add = (0x91000021u32 | ((name & 0xFFF) as u32) << 10).to_le_bytes();
    let mut found: Vec<i64> = Vec::new();
    let mut a: i64 = -1;
    while let Some(p) = find(img, &add, a + 1, text_end) {
        a = p as i64;
        if a % 4 != 0 || a < 4 || adrp_page(word(img, a - 4), a - 4) != Some(name & !0xFFF) {
            continue;
        }
        let mut k = a + 4;
        let end = (a + 36).min(text_end - 4);
        while k < end {
            let (w, x) = (word(img, k), word(img, k + 4));
            if let Some(page) = adrp_page(w, k)
                && w & 31 == 2
                && x & 0xFFC003FF == 0x91000042
            {
                let v = page + ((x >> 10) & 0xFFF) as i64;
                if !found.contains(&v) {
                    found.push(v);
                }
                break;
            }
            k += 4;
        }
    }
    if found.len() == 1 { found.pop() } else { None }
}

/// all non-overlapping matches (re.finditer) of a 4-byte pattern given as a per-byte predicate, as start offsets
fn finditer4(t: &[u8], pred: impl Fn(&[u8]) -> bool) -> Vec<usize> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 4 <= t.len() {
        if pred(&t[p..p + 4]) {
            out.push(p);
            p += 4;
        } else {
            p += 1;
        }
    }
    out
}

/// Offsets of the lock's rotation over the slots at +8, its count at +0x5c and its index at +0x60
fn rotations(img: &[u8], text_end: i64) -> Vec<i64> {
    let mut out = Vec::new();
    // str w, [x, #0x60]: [any][0x60-0x63][0x00][0xb9]
    for a in finditer4(text(img, text_end), |b| {
        (0x60..=0x63).contains(&b[1]) && b[2] == 0 && b[3] == 0xb9
    }) {
        let a = a as i64;
        if a % 4 != 0 || a < 32 || a + 12 > text_end {
            continue;
        }
        let g = |o: i64| rd32(img, (a + o) as usize);
        let (c, cmp, blo, i0, inc, div, msub, st, ad, ld) = (
            g(-28),
            g(-24),
            g(-20),
            g(-16),
            g(-12),
            g(-8),
            g(-4),
            g(0),
            g(4),
            g(8),
        );
        let (b, ri) = ((st >> 5) & 31, st & 31);
        if c & 0xFFFFFC00 != 0xB9405C00 || (c >> 5) & 31 != b {
            continue;
        }
        if cmp != (0x7100081F | (c & 31) << 5) || blo & 0xFF00001F != 0x54000003 {
            continue;
        }
        if i0 & 0xFFFFFC00 != 0xB9406000 || (i0 >> 5) & 31 != b {
            continue;
        }
        if inc & 0xFFFFFC00 != 0x11000400
            || div & 0xFFE0FC00 != 0x1AC00800
            || msub & 0xFFE08000 != 0x1B008000
            || msub & 31 != ri
        {
            continue;
        }
        if ad & 0xFFE0FC00 != 0x8B204C00 || (ad >> 5) & 31 != b || (ad >> 16) & 31 != ri {
            continue;
        }
        if ld & 0xFFC00000 != 0xF9400000 || (ld >> 5) & 31 != ad & 31 || (ld >> 10) & 0xFFF != 1 {
            continue;
        }
        out.push(a);
    }
    out
}

/// The constructor before the load ends the slots at +0x28: `stur q, [x0, #0x18]` and a store to #0x28 with
/// writeback (str xzr or str q). With `base`, also `str xzr, [base, #0x5c]!`
fn layout_holds(img: &[u8], load: i64, base: Option<u32>) -> bool {
    let (mut q18, mut loc, mut kept) = (false, false, false);
    let mut a = (load - BACK).max(0);
    while a < load {
        let w = word(img, a);
        if w & 0xFFFFFFE0 == 0x3C818000 {
            q18 = true; // stur q, [x0, #0x18]
        }
        if w & 0xFFFFFC1F == 0xF8028C1F || w & 0xFFFFFC00 == 0x3C828C00 {
            loc = true; // str xzr, [xA, #0x28]! / str q, [xA, #0x28]!
        }
        if let Some(b) = base
            && w == (0xF805CC1F | b << 5)
        {
            kept = true; // str xzr, [base, #0x5c]!
        }
        a += 4;
    }
    q18 && loc && (base.is_none() || kept)
}

/// Offsets of the constructor's load of the count: the instruction that gives wM the variable's value, with M, on the
/// path of `tbz wU, #1`
fn loads(img: &[u8], text_end: i64, var: i64) -> Vec<(i64, u32)> {
    let mut got = None;
    let mut out = Vec::new();
    // tbz w, #1: [any][any][0x08-0x0f][0x36]
    for a in finditer4(text(img, text_end), |b| {
        (0x08..=0x0f).contains(&b[2]) && b[3] == 0x36
    }) {
        let a = a as i64;
        if a % 4 != 0 || a + 20 > text_end {
            continue;
        }
        let (adrp, w2, w3, w4) = (
            word(img, a + 4),
            word(img, a + 8),
            word(img, a + 12),
            word(img, a + 16),
        );
        let Some(page) = adrp_page(adrp, a + 4) else {
            continue;
        };
        let n = adrp & 31;
        let (load, st);
        if w2 & 0xFFC00000 == 0xB9400000 && (w2 >> 5) & 31 == n {
            // ldr wM, [xN, #lo]
            if page + (((w2 >> 10) & 0xFFF) * 4) as i64 != var {
                continue;
            }
            load = a + 8;
            st = w3;
        } else if w2 & 0xFFC00000 == 0xF9400000
            && (w2 >> 5) & 31 == n
            && w2 & 31 == n
            && w3 & 0xFFFFFC00 == 0xB9400000
            && (w3 >> 5) & 31 == n
        {
            // ldr xN, [xN, #got]; ldr wM, [xN]
            if got.is_none() {
                got = Some(got_values(img));
            }
            if got
                .as_ref()
                .unwrap()
                .get(page + (((w2 >> 10) & 0xFFF) * 8) as i64)
                != Some(var)
            {
                continue;
            }
            load = a + 12;
            st = w4;
        } else {
            continue;
        }
        let rm = word(img, load) & 31;
        if st & 0xFFC0001F != (0xB9000000 | rm) {
            continue;
        }
        let (field, base) = ((((st >> 10) & 0xFFF) * 4) as i64, (st >> 5) & 31);
        if (field == 0x5C && layout_holds(img, load, None))
            || (field == 0 && layout_holds(img, load, Some(base)))
        {
            out.push((load, rm));
        }
    }
    out
}

/// (offset of the load, its word, the word to put there, reason) when the chain holds; (None, why not) otherwise,
/// with why starting "[RED] " when the engine's ring of 3 is there but this chain does not find its count
pub type Ring = (Option<i64>, u32, u32, String);

pub fn find_ring(img: &[u8], text_end: i64, ro_off: i64, data_off: i64) -> Ring {
    let mut name: Vec<u8> = NAME.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    name.extend([0, 0]);
    let Some(nm) = find(img, &name, ro_off, data_off) else {
        return (None, 0, 0, format!("no {NAME}"));
    };
    let Some(var) = registered(img, text_end, nm as i64) else {
        return (
            None,
            0,
            0,
            format!("[RED] Unreal's {NAME} but not one registration of it"),
        );
    };
    if var + 4 > img.len() as i64 {
        return (
            None,
            0,
            0,
            format!("[RED] Unreal's {NAME} at {var:#x}, outside the image"),
        );
    }
    let val = rd32(img, var as usize);
    if val != 3 {
        return (
            None,
            0,
            0,
            format!("Unreal's {NAME} is {val}: no ring of 3"),
        );
    }
    let rot = rotations(img, text_end);
    if rot.is_empty() {
        return (
            None,
            0,
            0,
            format!("[RED] Unreal's {NAME} is 3 but no lock rotates over a buffer's slots"),
        );
    }
    let found = loads(img, text_end, var);
    if found.len() != 1 {
        let l: Vec<String> = found.iter().map(|(a, _)| format!("{a:#x}")).collect();
        return (
            None,
            0,
            0,
            format!(
                "[RED] Unreal's {NAME} is 3 but {} loads of a dynamic buffer's copy count ({})",
                found.len(),
                l.join(", ")
            ),
        );
    }
    let (load, rm) = found[0];
    (
        Some(load),
        rd32(img, load as usize),
        0x52800000 | COPIES << 5 | rm,
        format!(
            "Unreal's dynamic buffers: {NAME} at {var:#x} loaded at {load:#x}, {} lock rotations ({:#x}): {COPIES} copies",
            rot.len(),
            rot[0]
        ),
    )
}
