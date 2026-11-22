//! The detectors that find engine structures in a module without a build ID (ports of `ue_cvar.py`, `fps_target.py`,
//! `monolith_fps.py`, `ue_fixed_rate.py`, `unity_fps.py`, `ue_malloc.py`, `unity_bucket.py`, `snowdrop_pools.py`,
//! `ue_region.py`, `ue_ring.py`). Each reads the module image as it is when it is called and returns what it found
//! and the reason line the rewriter logs.

pub mod fps_target;
pub mod monolith;
pub mod snowdrop;
pub mod ue_cvar;
pub mod ue_fixed_rate;
pub mod ue_malloc;
pub mod ue_region;
pub mod ue_ring;
pub mod unity_bucket;
pub mod unity_fps;

use ibuilder_a64::bits::rd32;

/// `struct.unpack_from('<I', img, a)[0]` (a Python IndexError / struct.error here would abort the rewrite; the
/// detectors only read inside the image, so an out-of-range word reads as 0 instead of panicking)
#[inline]
pub fn word(img: &[u8], a: i64) -> u32 {
    if a >= 0 && (a as usize) + 4 <= img.len() {
        rd32(img, a as usize)
    } else {
        0
    }
}

/// `img.find(pat, start, end)`: the first match of `pat` that lies inside `img[start:end]`
pub fn find(img: &[u8], pat: &[u8], start: i64, end: i64) -> Option<usize> {
    let end = (end.max(0) as usize).min(img.len());
    let start = start.max(0) as usize;
    if start > end {
        return None;
    }
    memchr::memmem::find(&img[start..end], pat).map(|p| p + start)
}

/// `img.find(pat)` over the whole image
pub fn find_all_img(img: &[u8], pat: &[u8]) -> Option<usize> {
    memchr::memmem::find(img, pat)
}

/// `text` slice `img[:text_end]`
#[inline]
pub fn text(img: &[u8], text_end: i64) -> &[u8] {
    &img[..(text_end as usize).min(img.len())]
}
