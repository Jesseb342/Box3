//! AArch64 instruction encoders of the NSO rewriter: a port of `dm/tools/nso_asm.py` (the encoders of
//! `patch_nso.py` and of the per-build patch files). Each returns the instruction word; a branch asserts its
//! reach exactly as the Python `assert` does (here: `Err(AsmError)`).
//!
//! Addresses and offsets are `i64` because the patch area can sit before the module base (negative offsets);
//! Python's arbitrary precision integers behave like two's complement `i64` for every value used here.

use std::fmt;

/// An assertion of an encoder failed (a branch out of reach or a misaligned target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmError(pub String);

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for AsmError {}

pub type Result<T> = std::result::Result<T, AsmError>;

fn reach(what: &str, off: i64, bits: u32, frm: i64, to: i64) -> Result<()> {
    if off >= -(1i64 << bits) && off < (1i64 << bits) && off & 3 == 0 {
        Ok(())
    } else {
        Err(AsmError(format!(
            "{what} out of reach or misaligned: from {frm:#x} to {to:#x} (offset {off})"
        )))
    }
}

/// `b` from `frm` to `to` (±128 MB)
pub fn b(frm: i64, to: i64) -> Result<u32> {
    let off = to - frm;
    reach("b", off, 27, frm, to)?;
    Ok(0x1400_0000 | (((off >> 2) & 0x03FF_FFFF) as u32))
}
/// `bl` from `frm` to `to`
pub fn bl(frm: i64, to: i64) -> Result<u32> {
    Ok(b(frm, to)? | 0x8000_0000)
}
/// `cbnz wt, to` (±1 MB)
pub fn cbnzw(t: u32, frm: i64, to: i64) -> Result<u32> {
    let off = to - frm;
    reach("cbnz", off, 20, frm, to)?;
    Ok(0x3500_0000 | ((((off >> 2) & 0x7FFFF) as u32) << 5) | t)
}
fn pair(base: u32, t: u32, t2: u32, n: u32, off: i64) -> u32 {
    base | ((((off.div_euclid(8)) & 0x7F) as u32) << 15) | (t2 << 10) | (n << 5) | t
}
/// `stp xt, xt2, [xn, #off]`
pub fn stp(t: u32, t2: u32, n: u32, off: i64) -> u32 {
    pair(0xA900_0000, t, t2, n, off)
}
/// `ldp xt, xt2, [xn, #off]`
pub fn ldp(t: u32, t2: u32, n: u32, off: i64) -> u32 {
    pair(0xA940_0000, t, t2, n, off)
}
/// `stp xt, xt2, [xn, #off]!`
pub fn stp_pre(t: u32, t2: u32, n: u32, off: i64) -> u32 {
    pair(0xA980_0000, t, t2, n, off)
}
/// `ldp xt, xt2, [xn], #off`
pub fn ldp_post(t: u32, t2: u32, n: u32, off: i64) -> u32 {
    pair(0xA8C0_0000, t, t2, n, off)
}
/// `stur xt, [xn, #off]` (off may be negative)
pub fn stur(t: u32, n: u32, off: i64) -> u32 {
    0xF800_0000 | (((off & 0x1FF) as u32) << 12) | (n << 5) | t
}
/// `ldur xt, [xn, #off]`
pub fn ldur(t: u32, n: u32, off: i64) -> u32 {
    0xF840_0000 | (((off & 0x1FF) as u32) << 12) | (n << 5) | t
}
/// `ldr xt, [xn, #imm12 * 8]`
pub fn ldrx(t: u32, n: u32, imm12: u32) -> u32 {
    0xF940_0000 | (imm12 << 10) | (n << 5) | t
}
/// `str xt, [xn, #imm12 * 8]`
pub fn strx(t: u32, n: u32, imm12: u32) -> u32 {
    0xF900_0000 | (imm12 << 10) | (n << 5) | t
}
/// `mov xd, xm` (`orr xd, xzr, xm`)
pub fn movx(dd: u32, m: u32) -> u32 {
    0xAA00_03E0 | (m << 16) | dd
}
/// `mrs xt, tpidrro_el0`
pub fn mrs_tpidrro(t: u32) -> u32 {
    0xD53B_D060 | t
}
/// `adrp xd, target` placed at `pc`
pub fn adrp(dd: u32, pc: i64, target: i64) -> Result<u32> {
    let imm = ((target & !0xFFF) - (pc & !0xFFF)) >> 12;
    if !(-(1i64 << 20)..(1i64 << 20)).contains(&imm) {
        return Err(AsmError(format!(
            "adrp out of reach: from {pc:#x} to {target:#x}"
        )));
    }
    Ok(0x9000_0000 | (((imm & 3) as u32) << 29) | ((((imm >> 2) & 0x7FFFF) as u32) << 5) | dd)
}
/// `add xd, xn, #imm12{, lsl #12 if sh}`
pub fn addi(dd: u32, n: u32, imm12: u32, sh: u32) -> u32 {
    0x9100_0000 | (sh << 22) | (imm12 << 10) | (n << 5) | dd
}
/// `add xd, xn, xm`
pub fn addr(dd: u32, n: u32, m: u32) -> u32 {
    0x8B00_0000 | (m << 16) | (n << 5) | dd
}
/// `sub xd, xn, #imm12{, lsl #12 if sh}`
pub fn subi(dd: u32, n: u32, imm12: u32, sh: u32) -> u32 {
    0xD100_0000 | (sh << 22) | (imm12 << 10) | (n << 5) | dd
}
/// `br xn`
pub fn br(n: u32) -> u32 {
    0xD61F_0000 | (n << 5)
}
/// `cmp xn, xm` (`subs xzr, xn, xm`)
pub fn cmpr(n: u32, m: u32) -> u32 {
    0xEB00_001F | (m << 16) | (n << 5)
}
/// `b.eq to` (±1 MB)
pub fn beq(frm: i64, to: i64) -> Result<u32> {
    let off = to - frm;
    reach("b.eq", off, 20, frm, to)?;
    Ok(0x5400_0000 | ((((off >> 2) & 0x7FFFF) as u32) << 5))
}
/// `brk #imm`
pub fn brk(imm: u32) -> u32 {
    0xD420_0000 | ((imm & 0xFFFF) << 5)
}
/// `blr xn`
pub fn blr(n: u32) -> u32 {
    0xD63F_0000 | (n << 5)
}
pub const NOP: u32 = 0xD503_201F;

#[cfg(test)]
mod tests;
