//! Snowdrop's three-pool page allocator in main, found by the engine's own code, without a build ID
//! (`snowdrop_pools.py`): its pools get the sizes the profile decides on. The constructor reserves 12 GB in one
//! address region, three adjacent 4 GB ranges: large allocations, 512 KB pages, 64 KB pages.

use super::find;
use crate::{Fail, Res};
use ibuilder_a64::bits::rd32;

const G4: u64 = 0x1_0000_0000;
const G12: u64 = 0x3_0000_0000;
const W1_ZERO: u32 = 0x2A1F03E1; // mov w1, wzr
const X2_ZERO: u32 = 0xAA1F03E2; // mov x2, xzr
const W5_64K: [u32; 2] = [0x52A00025, 0x321003E5]; // mov w5, #0x10000: movz, or orr w5, wzr, #0x10000
const WINDOW: i64 = 48;
pub const DEFAULT: (i64, i64, i64) = (2048, 512, 1280);

/// the text as a sequence of little-endian words, read in place (no copy of a 120 MB text)
pub struct W<'a> {
    img: &'a [u8],
    len: usize,
}
impl W<'_> {
    #[inline]
    fn at(&self, i: usize) -> u32 {
        rd32(self.img, i * 4)
    }
}

/// (rd, value) of a 64-bit register loaded from zero by one instruction, for the two encodings of these constants
fn load_imm(w: u32) -> Option<(u32, u64)> {
    if w & 0xFFE00000 == 0xD2C00000 {
        return Some((w & 31, (((w >> 5) & 0xFFFF) as u64) << 32)); // movz x, #imm, lsl #32
    }
    if w & 0xFFC003E0 == 0xB24003E0 {
        // orr x, xzr, #bitmask with a 64-bit element
        let (immr, imms) = ((w >> 16) & 63, (w >> 10) & 63);
        let v: u128 = if imms < 63 {
            (1u128 << (imms + 1)) - 1
        } else {
            (1u128 << 64) - 1
        };
        let r = ((v >> immr) | (v << (64 - immr))) & ((1u128 << 64) - 1);
        return Some((w & 31, r as u64));
    }
    None
}
fn loaded(w: u32, value: u64) -> bool {
    load_imm(w).map(|x| x.1) == Some(value)
}
fn is_bl(w: u32) -> bool {
    w & 0xFC000000 == 0x94000000
}
fn bl_target(w: u32, pc: i64) -> i64 {
    let imm = (w & 0x3FFFFFF) as i64;
    pc + (if imm & (1 << 25) != 0 {
        imm - (1 << 26)
    } else {
        imm
    }) * 4
}

/// (base register, [offsets]) of `str xT, [xN, #o]` or `stp xT, xT, [xN, #o]`, for rt = T
fn str_fields(w: u32, rt: u32) -> Option<(u32, Vec<i64>)> {
    if w & 0xFFC00000 == 0xF9000000 && w & 31 == rt {
        return Some(((w >> 5) & 31, vec![(((w >> 10) & 0xFFF) * 8) as i64]));
    }
    if w & 0xFFC00000 == 0xA9000000 && w & 31 == rt && (w >> 10) & 31 == rt {
        let imm = ((w >> 15) & 0x7F) as i64;
        let o = (if imm & 0x40 != 0 { imm - 0x80 } else { imm }) * 8;
        return Some(((w >> 5) & 31, vec![o, o + 8]));
    }
    None
}

/// `stp x?, x?, [xN, #off]`
fn stores_pair_at(w: u32, rn: u32, off: i64) -> bool {
    if w & 0xFFC00000 != 0xA9000000 || (w >> 5) & 31 != rn {
        return false;
    }
    let imm = ((w >> 15) & 0x7F) as i64;
    (if imm & 0x40 != 0 { imm - 0x80 } else { imm }) * 8 == off
}

/// the instruction indices of the constructor's parts (the Python dict, in word units until `find` scales them)
#[derive(Debug, Clone, Default)]
pub struct Sites {
    pub sizes: i64,
    pub end: i64,
    pub total: i64,
    pub pages: i64,
    pub w1_meta: i64,
    pub x2_meta: i64,
    pub w1: i64,
    pub x2: i64,
    pub field: i64,
    pub xs: u32,
}

fn check(w: &W, a: usize, k: usize) -> Result<Sites, String> {
    let calls: Vec<usize> = (a..(k + 8).min(w.len))
        .filter(|&j| is_bl(w.at(j)))
        .collect();
    if calls.len() < 4 || !(calls[2] < k && k < calls[3]) {
        return Err("not four calls with the page count before the last".into());
    }
    let (b0, b1, b2, b3) = (calls[0], calls[1], calls[2], calls[3]);
    let xa = w.at(a) & 31;
    let g12: Vec<usize> = (b1..b2).filter(|&j| loaded(w.at(j), G12)).collect();
    if g12.len() != 2 || w.at(g12[1]) & 31 != 0 {
        return Err("the second reservation is not 12 GB from x0".into());
    }
    let xb = w.at(g12[0]) & 31;
    if !(19..=28).contains(&xb) {
        return Err("the 12 GB end is not in a saved register".into());
    }
    // the object's register: mov xS, x0, before the first call
    let movs: Vec<u32> = (a.saturating_sub(8)..b0)
        .filter(|&j| w.at(j) & 0xFFFFFFE0 == 0xAA0003E0 && (19..=28).contains(&(w.at(j) & 31)))
        .map(|j| w.at(j) & 31)
        .collect();
    if movs.len() != 1 {
        return Err(format!(
            "{} moves of the object to a saved register",
            movs.len()
        ));
    }
    let xs = movs[0];
    // the three size fields
    let mut fields: Vec<i64> = Vec::new();
    for j in a + 1..b0 {
        if let Some((base, offs)) = str_fields(w.at(j), xa)
            && (base == 0 || base == xs)
        {
            for o in offs {
                if !fields.contains(&o) {
                    fields.push(o);
                }
            }
        }
    }
    let f = fields.iter().copied().min().unwrap_or(0);
    let mut sorted = fields.clone();
    sorted.sort();
    if sorted != vec![f, f + 8, f + 0x10] {
        let mut l: Vec<String> = sorted
            .iter()
            .map(|&x| format!("'{}'", crate::hx(x)))
            .collect();
        l.sort(); // sorted(hex(x) for x in fields): the strings sort as text
        return Err(format!("the 4 GB goes to fields [{}]", l.join(", ")));
    }
    // the two reservations and their free argument moves
    let t1 = bl_target(w.at(b1), b1 as i64 * 4);
    let t2 = bl_target(w.at(b2), b2 as i64 * 4);
    if t1 != t2 {
        return Err("the two reservations call different functions".into());
    }
    let mut args = Vec::new();
    for (lo, hi) in [(b0, b1), (b1, b2)] {
        let w1: Vec<usize> = (lo..hi).filter(|&j| w.at(j) == W1_ZERO).collect();
        let x2: Vec<usize> = (lo..hi).filter(|&j| w.at(j) == X2_ZERO).collect();
        if w1.len() != 1 || x2.len() != 1 || w1[0] > x2[0] {
            return Err("a reservation without mov w1, wzr then mov x2, xzr".into());
        }
        args.push(w1[0]);
        args.push(x2[0]);
    }
    if !(b1..b2).any(|j| stores_pair_at(w.at(j), xs, f + 0x28)) {
        return Err("the metadata's base does not go beside the fields".into());
    }
    if !(b2..b3).any(|j| stores_pair_at(w.at(j), xs, f + 0x18)) {
        return Err("the region's base does not go beside the fields".into());
    }
    if !(b2..b3).any(|j| w.at(j) & 0xFFE0FC00 == 0x8B000000 && (w.at(j) >> 16) & 31 == xb) {
        return Err("the region's end is not an add of the 12 GB register".into());
    }
    // R overwrites x1 before it calls on: its incoming x1 and x2 do not count
    let r = t1 / 4;
    if !(0 <= r && (r as usize) < w.len.saturating_sub(12)) {
        return Err("the reservation function is out of the text".into());
    }
    let r = r as usize;
    let end = (r..r + 12).find(|&j| is_bl(w.at(j)));
    match end {
        Some(end) if (r..end).any(|j| w.at(j) & 0xFFE0FFFF == 0xAA0003E1) => {}
        _ => return Err("the reservation function does not overwrite x1".into()),
    }
    Ok(Sites {
        sizes: a as i64,
        end: g12[0] as i64,
        total: g12[1] as i64,
        pages: k as i64,
        w1_meta: args[0] as i64,
        x2_meta: args[1] as i64,
        w1: args[2] as i64,
        x2: args[3] as i64,
        field: f,
        xs,
    })
}

/// (sites in bytes, why): the instruction offsets of the one constructor in the text and a line for the log; (None, why)
/// otherwise, with why starting "[RED] " when the shape is there but something differs, or is there twice
pub fn find_sites(img: &[u8], text_end: i64) -> (Option<Sites>, String) {
    let n = (text_end / 4) as usize;
    let w = W { img, len: n };
    let mut cands: Vec<(usize, usize)> = Vec::new();
    for pat in W5_64K {
        let needle = pat.to_le_bytes();
        let mut at: i64 = -1;
        while let Some(p) = find(img, &needle, at + 1, text_end) {
            at = p as i64;
            if at % 4 != 0 {
                continue;
            }
            let k = (at / 4) as usize;
            // for a in range(k - 1, max(-1, k - WINDOW), -1)
            let mut a = k as i64 - 1;
            let stop = (-1i64).max(k as i64 - WINDOW);
            while a > stop {
                if loaded(w.at(a as usize), G4) {
                    let c = (a as usize..k).filter(|&j| loaded(w.at(j), G12)).count();
                    if c >= 2 {
                        cands.push((a as usize, k));
                    }
                    break;
                }
                a -= 1;
            }
        }
    }
    if cands.is_empty() {
        return (None, "no Snowdrop three-pool allocator".into());
    }
    let (mut good, mut bad): (Vec<Sites>, Vec<(i64, String)>) = (Vec::new(), Vec::new());
    for (a, k) in cands {
        match check(&w, a, k) {
            Ok(s) => good.push(s),
            Err(why) => bad.push((a as i64 * 4, why)),
        }
    }
    if good.len() > 1 {
        let l: Vec<String> = good.iter().map(|s| format!("{:#x}", s.sizes * 4)).collect();
        return (
            None,
            format!(
                "[RED] {} Snowdrop three-pool allocators: {}",
                good.len(),
                l.join(", ")
            ),
        );
    }
    if good.is_empty() {
        let l: Vec<String> = bad
            .iter()
            .map(|(o, why)| format!("{o:#x}: {why}"))
            .collect();
        return (
            None,
            format!(
                "[RED] Snowdrop three-pool allocator shape, but {}",
                l.join("; ")
            ),
        );
    }
    let g = &good[0];
    let why = format!(
        "Snowdrop three-pool allocator at {:#x}, size fields at +{:#x}",
        g.sizes * 4,
        g.field
    );
    let s = Sites {
        sizes: g.sizes * 4,
        end: g.end * 4,
        total: g.total * 4,
        pages: g.pages * 4,
        w1_meta: g.w1_meta * 4,
        x2_meta: g.x2_meta * 4,
        w1: g.w1 * 4,
        x2: g.x2 * 4,
        field: g.field,
        xs: g.xs,
    };
    (Some(s), why)
}

fn movz_x(rd: u32, value: i64) -> Res<u32> {
    if !(value & 0xFFFF == 0 && 0 < value && value < 1 << 32) {
        return Err(Fail::new(format!("{value:#x}")));
    }
    Ok(0xD2A00000 | ((value >> 16) as u32) << 5 | rd)
}
fn str_x(rt: u32, rn: u32, off: i64) -> Res<u32> {
    if !(off % 8 == 0 && (0..0x8000).contains(&off)) {
        return Err(Fail::new(format!("{off:#x}")));
    }
    Ok(0xF9000000 | ((off / 8) as u32) << 10 | rn << 5 | rt)
}
fn movz_w5(n: i64) -> Res<u32> {
    if !(0 < n && n < 1 << 16) {
        return Err(Fail::new(n.to_string()));
    }
    Ok(0x52800005 | (n as u32) << 5)
}

/// The rewriter's cuts, (offset, old hex, new hex, why), for the sites of `find_sites` and the sizes in MB
pub fn cuts(
    img: &[u8],
    s: &Sites,
    sizes: (i64, i64, i64),
) -> Res<Vec<(i64, String, String, String)>> {
    let (large, p512, p64) = (sizes.0 << 20, sizes.1 << 20, sizes.2 << 20);
    let total = large + p512 + p64;
    let xa = rd32(img, s.sizes as usize) & 31;
    let xb = rd32(img, s.end as usize) & 31;
    let mut new: Vec<(i64, u32, String)> = vec![
        (
            s.sizes,
            movz_x(xa, p512)?,
            format!(
                "each range {} MB; the two that differ are set below",
                sizes.1
            ),
        ),
        (
            s.end,
            movz_x(xb, total)?,
            format!("combined range end {} MB", total >> 20),
        ),
        (
            s.w1,
            movz_x(1, large)?,
            "the large range; the reservation discards incoming x1".into(),
        ),
        (
            s.total,
            movz_x(0, total)?,
            format!("combined reservation {} MB", total >> 20),
        ),
        (
            s.x2,
            str_x(1, s.xs, s.field + 0x10)?,
            format!(
                "the large range field {} MB; the reservation never reads x2",
                sizes.0
            ),
        ),
        (
            s.pages,
            movz_w5(large >> 16)?,
            format!(
                "the large allocator's maximum 64 KB page count, matching its {} MB",
                sizes.0
            ),
        ),
    ];
    if p64 != p512 {
        new.push((
            s.w1_meta,
            movz_x(1, p64)?,
            "the 64 KB range; the reservation discards incoming x1".into(),
        ));
        new.push((
            s.x2_meta,
            str_x(1, s.xs, s.field)?,
            format!(
                "the 64 KB range field {} MB; the reservation never reads x2",
                sizes.2
            ),
        ));
    }
    new.sort_by_key(|x| (x.0, x.1)); // sorted(new): tuples compare by offset, then word
    let hex = |w: u32| {
        w.to_le_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    Ok(new
        .into_iter()
        .map(|(o, w, why)| {
            (
                o,
                hex(rd32(img, o as usize)),
                hex(w),
                format!("Snowdrop allocator: {why}"),
            )
        })
        .collect())
}
