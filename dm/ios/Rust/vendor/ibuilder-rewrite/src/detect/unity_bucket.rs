//! Unity's ALLOC_BUCKET BucketAllocator, found in main by its name without a build ID (`unity_bucket.py`): its block
//! limit is cut when its reservation is larger than an iPhone can spare.

use super::ue_cvar::writes;
use super::{find, word};
use ibuilder_a64::bits::{add_imm, adrp_page, is_adrp};

const NAME: &[u8] = b"ALLOC_BUCKET";
/// the reservation an iPhone's alias region can spare for it
const CAP: i64 = 256 << 20;

/// `mov wD, #imm` (movz, 32-bit): (d, value)
fn movz32(u: u32) -> Option<(u32, i64)> {
    if u & 0xFF800000 != 0x52800000 {
        return None;
    }
    Some((
        u & 31,
        (((u >> 5) & 0xFFFF) as i64) << (16 * ((u >> 21) & 3)),
    ))
}

/// The cut, `(offset, original bytes hex, new bytes hex, reason)`
pub type Cut = (i64, String, String, String);

/// (the cut or None, reason); the reason starts "[RED] " when the setup is there but not read
pub fn find_cut(img: &[u8], text_end: i64, ro_off: i64, data_off: i64) -> (Option<Cut>, String) {
    let mut pat = vec![0u8];
    pat.extend(NAME);
    pat.push(0);
    let Some(s) = find(img, &pat, ro_off, data_off) else {
        return (None, "no ALLOC_BUCKET".into());
    };
    let s = s as i64 + 1;
    let mut refs: Vec<(i64, u32)> = Vec::new();
    let mut j = 0i64;
    while j < text_end {
        if let Some(a) = add_imm(word(img, j))
            && a.2 == (s & 0xFFF)
            && (((j - 20).max(0))..j).step_by(4).any(|i| {
                let w = word(img, i);
                is_adrp(w) && w & 31 == a.1 && adrp_page(w, i) == (s & !0xFFF)
            })
        {
            refs.push((j, a.0));
        }
        j += 4;
    }
    if refs.len() != 1 {
        return (
            None,
            format!("[RED] ALLOC_BUCKET: {} references, not one", refs.len()),
        );
    }
    let (j, d) = refs[0];
    if d != 1 {
        return (
            None,
            format!("[RED] ALLOC_BUCKET at {j:#x}: the name is not loaded into x1"),
        );
    }
    // register -> (offset, value) of its last mov before the call
    let mut last: [Option<(i64, Option<i64>)>; 2] = [None, None];
    let mut t = j + 4;
    let end = text_end.min(j + 4 + 4 * 16);
    let mut called = false;
    while t < end {
        let u = word(img, t);
        if u & 0xFC000000 == 0x94000000 {
            called = true; // bl the constructor
            break;
        }
        if u & 0x7C000000 == 0x14000000
            || matches!(u & 0xFFFFFC1F, 0xD63F0000 | 0xD61F0000)
            || u == 0xD65F03C0
        {
            return (
                None,
                format!("[RED] ALLOC_BUCKET at {j:#x}: a branch before the constructor call"),
            );
        }
        let m = movz32(u);
        for (k, r) in [4u32, 5].into_iter().enumerate() {
            if writes(u, r) {
                last[k] = Some(match m {
                    Some((d, v)) if d == r => (t, Some(v)),
                    _ => (t, None),
                });
            }
        }
        t += 4;
    }
    if !called {
        return (
            None,
            format!("[RED] ALLOC_BUCKET at {j:#x}: no constructor call"),
        );
    }
    let (Some((_, Some(size))), Some((at, Some(blocks)))) = (last[0], last[1]) else {
        // Unity 2021 and later: the sizes come from the player's settings (boot.config), one block by default
        return (
            None,
            format!("ALLOC_BUCKET at {j:#x}: sizes set at run time, no cut"),
        );
    };
    if size == 0 || size & (size - 1) != 0 {
        return (
            None,
            format!("[RED] ALLOC_BUCKET at {j:#x}: block size {size:#x}"),
        );
    }
    let want = CAP / size - 1;
    if blocks <= want {
        return (
            None,
            format!("ALLOC_BUCKET: {blocks} blocks of {} MB, no cut", size >> 20),
        );
    }
    let (old, new) = (word(img, at), 0x52800005u32 | (want as u32) << 5);
    let hex = |w: u32| {
        w.to_le_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    (
        Some((
            at,
            hex(old),
            hex(new),
            format!(
                "Unity BucketAllocator ALLOC_BUCKET: at most {blocks} blocks of {} MB (a {} MB address region) → {want} ({} MB) (unity_bucket.py)",
                size >> 20,
                ((blocks + 1) * size) >> 20,
                CAP >> 20
            ),
        )),
        format!(
            "Unity ALLOC_BUCKET at {j:#x}: {blocks} → {want} blocks of {} MB at {at:#x}",
            size >> 20
        ),
    )
}
