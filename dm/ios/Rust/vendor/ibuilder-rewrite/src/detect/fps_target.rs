//! A target frame rate the game steps by, found in main by the code that reads and sets it (`fps_target.py`).
//!
//! The field is an int32 frame rate in an object a global points to. Its readers load it into a float register,
//! convert it and divide 60.0 by it; the game sets it with an immediate 30 or 60. A field with at least MIN_READERS
//! such readers and a store of 30 is the target; exactly one must be, or nothing is written.

use super::word;
use crate::fde::{Rel, got_values};
use ibuilder_a64::bits::{adrp_page, is_adrp};

const MIN_READERS: usize = 8;
const SIXTY: u32 = 0x42700000;

/// `movz wD, #imm{, lsl #16}`: (d, value)
fn movz_w(w: u32) -> Option<(u32, u32)> {
    if w & 0xFF800000 != 0x52800000 {
        return None;
    }
    Some((w & 31, ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 1))))
}

/// The general register an instruction writes, roughly: Rd of anything but stores, branches and FP / SIMD loads (None)
pub fn writes(u: u32) -> Option<u32> {
    if u & 0x0A000000 == 0x08000000 {
        if (u >> 22) & 1 == 0 || (u >> 26) & 1 != 0 {
            return None;
        }
        return Some(u & 31);
    }
    if u & 0x1C000000 == 0x14000000 {
        return None;
    }
    if u & 0x1F000000 == 0x1E000000
        && (u >> 29) & 1 == 0
        && !matches!(u & 0xFFFFFC00, 0x1E260000 | 0x9E660000)
    {
        return None;
    }
    Some(u & 31)
}

/// `globals_of(img)`: the global whose value register xB holds at word offset i (also used by `ue_fixed_rate`)
pub struct Globals<'a> {
    img: &'a [u8],
    rel: Option<Rel>,
}

impl<'a> Globals<'a> {
    pub fn new(img: &'a [u8]) -> Globals<'a> {
        Globals { img, rel: None }
    }

    /// The page adrp xA made a few words before word offset i, with xA written by nothing in between, or None
    fn page_of(&self, i: i64, a: u32) -> Option<i64> {
        let mut k = i - 4;
        let lo = 0.max(i - 24);
        while k > lo {
            let u = word(self.img, k);
            if is_adrp(u) && u & 31 == a {
                return Some(adrp_page(u, k));
            }
            if writes(u) == Some(a) {
                return None;
            }
            k -= 4;
        }
        None
    }

    /// The global whose value xB holds at word offset i (ldr xB, [xA] a few words before, xA the global's address)
    pub fn global_of(&mut self, i: i64, b: u32) -> Option<i64> {
        let mut k = i - 4;
        let lo = 0.max(i - 40);
        while k > lo {
            let u = word(self.img, k);
            if u & 31 == b && u & 0xFFC00000 == 0xF9400000 {
                // ldr xB, [xA, #imm]
                if (u >> 10) & 0xFFF != 0 {
                    return None;
                }
                let a = (u >> 5) & 31;
                let mut k2 = k - 4;
                let lo2 = 0.max(k - 32);
                while k2 > lo2 {
                    let v = word(self.img, k2);
                    if v & 31 != a {
                        k2 -= 4;
                        continue;
                    }
                    if v & 0xFFC00000 == 0x91000000 && (v >> 5) & 31 == a {
                        // add xA, xA, #lo
                        return self.page_of(k2, a).map(|p| p + ((v >> 10) & 0xFFF) as i64);
                    }
                    if v & 0xFFC00000 == 0xF9400000 && (v >> 5) & 31 == a {
                        // ldr xA, [xA, #got]: the GOT slot
                        let page = self.page_of(k2, a)?;
                        if self.rel.is_none() {
                            self.rel = Some(got_values(self.img));
                        }
                        return self
                            .rel
                            .as_ref()
                            .unwrap()
                            .get(page + (((v >> 10) & 0xFFF) * 8) as i64);
                    }
                    return None;
                }
                return None;
            }
            if writes(u) == Some(b) {
                return None; // xB written by something else
            }
            k -= 4;
        }
        None
    }
}

type Key = (i64, i64);

/// (offset of the global pointer, offset of the field, reason), or (None, None, why not); why starts "[RED] " when more
/// than one field qualifies
pub fn find(
    img: &[u8],
    text_end: i64,
    _ro_off: i64,
    data_off: i64,
) -> (Option<i64>, Option<i64>, String) {
    let mut gl = Globals::new(img);
    let mut readers: Vec<(Key, Vec<i64>)> = Vec::new();
    let mut stores: Vec<(Key, Vec<(i64, u32)>)> = Vec::new();
    fn push<T>(v: &mut Vec<(Key, Vec<T>)>, k: Key, x: T) {
        match v.iter_mut().find(|(kk, _)| *kk == k) {
            Some((_, l)) => l.push(x),
            None => v.push((k, vec![x])),
        }
    }
    let mut i = 0i64;
    while i < text_end {
        let u = word(img, i);
        if u & 0xFFC00000 == 0xBD400000 {
            // ldr sT, [xB, #F]
            let (t, b, f) = (u & 31, (u >> 5) & 31, (((u >> 10) & 0xFFF) * 4) as i64);
            let conv = (i + 4..text_end.min(i + 24))
                .step_by(4)
                .find(|&k| word(img, k) & 0xFFFFFFE0 == (0x5E21D800 | t << 5));
            if let Some(conv) = conv {
                let c = word(img, conv) & 31;
                let div = (conv + 4..text_end.min(conv + 20)).step_by(4).find(|&k| {
                    word(img, k) & 0xFFE0FC00 == 0x1E201800 && (word(img, k) >> 16) & 31 == c
                });
                if let Some(div) = div {
                    let m = (word(img, div) >> 5) & 31;
                    // fmov sM, wK, searching down from div - 4 to max(0, div - 48)
                    let mut fm = None;
                    let mut k = div - 4;
                    while k > 0.max(div - 48) {
                        if word(img, k) & 0xFFFFFC1F == (0x1E270000 | m) {
                            fm = Some(k);
                            break;
                        }
                        k -= 4;
                    }
                    if let Some(fm) = fm {
                        let mut ok = false;
                        let mut k = fm - 4;
                        while k > 0.max(fm - 32) {
                            if let Some(z) = movz_w(word(img, k))
                                && z == ((word(img, fm) >> 5) & 31, SIXTY)
                            {
                                ok = true;
                                break;
                            }
                            k -= 4;
                        }
                        if ok
                            && let Some(g) = gl.global_of(i, b)
                            && g >= data_off
                        {
                            push(&mut readers, (g, f), i);
                        }
                    }
                }
            }
        } else if u & 0xFFC00000 == 0xB9000000 {
            // str wK, [xB, #F]
            let (k_, b, f) = (u & 31, (u >> 5) & 31, (((u >> 10) & 0xFFF) * 4) as i64);
            let mut val = None;
            let mut k = i - 4;
            while k > 0.max(i - 32) {
                if let Some(z) = movz_w(word(img, k))
                    && z.0 == k_
                {
                    val = Some(z.1);
                    break;
                }
                k -= 4;
            }
            if matches!(val, Some(30) | Some(60))
                && let Some(g) = gl.global_of(i, b)
                && g >= data_off
            {
                push(&mut stores, (g, f), (i, val.unwrap()));
            }
        }
        i += 4;
    }
    let stores_of = |k: &Key| {
        stores
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let found: Vec<Key> = readers
        .iter()
        .filter(|(k, r)| r.len() >= MIN_READERS && stores_of(k).iter().any(|(_, v)| *v == 30))
        .map(|(k, _)| *k)
        .collect();
    if found.is_empty() {
        // max(readers.items(), key=len): the first of the longest
        let mut best: Option<&(Key, Vec<i64>)> = None;
        for r in &readers {
            if best.is_none_or(|b| r.1.len() > b.1.len()) {
                best = Some(r);
            }
        }
        let mut why = String::from("no target frame rate");
        if let Some(b) = best {
            let vs: Vec<String> = stores_of(&b.0).iter().map(|(_, v)| v.to_string()).collect();
            why.push_str(&format!(
                " (most readers: {} of [{:#x}]+{:#x}, stores [{}])",
                b.1.len(),
                b.0.0,
                b.0.1,
                vs.join(", ")
            ));
        }
        return (None, None, why);
    }
    if found.len() > 1 {
        let l: Vec<String> = found
            .iter()
            .map(|(g, f)| format!("[{g:#x}]+{f:#x}"))
            .collect();
        return (
            None,
            None,
            format!("[RED] target frame rate: {} qualify", l.join(", ")),
        );
    }
    let (g, f) = found[0];
    let st = stores_of(&(g, f));
    let rn = readers.iter().find(|(k, _)| *k == (g, f)).unwrap().1.len();
    let sets: Vec<String> = st.iter().map(|(a, v)| format!("{v} at {a:#x}")).collect();
    (
        Some(g),
        Some(f),
        format!(
            "target frame rate at [{g:#x}]+{f:#x}: {rn} readers of 60 / target, set to {}",
            sets.join(", ")
        ),
    )
}
