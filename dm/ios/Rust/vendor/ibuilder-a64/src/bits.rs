//! Word-level helpers shared by the detectors (`adrp` page arithmetic, sign extension, branch targets).

/// Sign-extend the low `bits` bits of `v`.
#[inline]
pub fn sx(v: u32, bits: u32) -> i64 {
    let v = v as i64 & ((1i64 << bits) - 1);
    if v >> (bits - 1) != 0 {
        v - (1i64 << bits)
    } else {
        v
    }
}

/// The page `adrp` at `pc` computes (`adrp_page` of the Python detectors).
#[inline]
pub fn adrp_page(w: u32, pc: i64) -> i64 {
    let imm = ((((w >> 5) & 0x7FFFF) as i64) << 2 | ((w >> 29) & 3) as i64) << 12;
    let imm = if imm & (1i64 << 32) != 0 {
        imm - (1i64 << 33)
    } else {
        imm
    };
    (pc & !0xFFF) + imm
}

#[inline]
pub fn is_adrp(w: u32) -> bool {
    w & 0x9F00_0000 == 0x9000_0000
}

/// `add xD, xN, #imm` (64-bit, optionally shifted by 12): (d, n, imm)
#[inline]
pub fn add_imm(w: u32) -> Option<(u32, u32, i64)> {
    if w & 0xFF80_0000 != 0x9100_0000 {
        return None;
    }
    Some((
        w & 31,
        (w >> 5) & 31,
        (((w >> 10) & 0xFFF) as i64) << (12 * ((w >> 22) & 1)),
    ))
}

/// Target of the direct branch word `u` at `s` (b, bl, b.cond, cbz / cbnz, tbz / tbnz), or `None`.
pub fn branch_target(u: u32, s: i64) -> Option<i64> {
    if u & 0x7C00_0000 == 0x1400_0000 {
        return Some(s + 4 * sx(u & 0x3FF_FFFF, 26));
    }
    if u & 0xFF00_0010 == 0x5400_0000 || u & 0x7E00_0000 == 0x3400_0000 {
        return Some(s + 4 * sx((u >> 5) & 0x7FFFF, 19));
    }
    if u & 0x7E00_0000 == 0x3600_0000 {
        return Some(s + 4 * sx((u >> 5) & 0x3FFF, 14));
    }
    None
}

#[inline]
pub fn rd32(img: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(img[o..o + 4].try_into().unwrap())
}
#[inline]
pub fn rd64(img: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(img[o..o + 8].try_into().unwrap())
}
