//! The analysis phases of `patch_nso.py` (function boundaries, exclusive-access ordering, odd stack frames, the linear
//! scan for rewrite points, windows and jump tables per function) and the driver that then emits every site, the
//! observation gates, the frame step / stubs and the spin waits.

use crate::ins::{is_cond_branch_or_b, last_imm, num};
use crate::jump_solver::{self, Solved};
use crate::jumps;
use crate::pyset::PySet;
use crate::rewriter::{KEY_K18, Kind, ObsRow, Rw};
use crate::windows;
use crate::{Fail, Res};
use ibuilder_a64::bits::rd32;
use ibuilder_a64::cs::{self, Ins, OP_MEM, OP_REG, REG_SP};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const SPIN_WIN: i64 = 512;

// ---- Function boundaries (eh_frame_hdr) ----
fn function_starts(img: &[u8], text_end: i64) -> Res<Vec<i64>> {
    let g32 = |o: i64| -> Res<u32> {
        img.get(o as usize..o as usize + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .ok_or_else(|| Fail::new("short read"))
    };
    let m0 = g32(4)? as i64;
    if img.get(m0 as usize..m0 as usize + 4) != Some(b"MOD0") {
        return Err(Fail::new("assert IMG[m0:m0 + 4] == b'MOD0'"));
    }
    let ehs = m0 + g32(m0 + 16)? as i32 as i64;
    let rd = |o: i64, enc: u8| -> Res<(i64, i64)> {
        let (fmt, app) = (enc & 0xF, enc & 0x70);
        let (mut v, sz) = match fmt {
            0x3 => (g32(o)? as i64, 4),
            0xB => (g32(o)? as i32 as i64, 4),
            0x4 => (
                img.get(o as usize..o as usize + 8)
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()) as i64)
                    .ok_or_else(|| Fail::new("short read"))?,
                8,
            ),
            _ => return Err(Fail::new(format!("KeyError: {fmt}"))),
        };
        if app == 0x10 {
            v += o;
        }
        if app == 0x30 {
            v += ehs;
        }
        Ok((v, sz))
    };
    let h = img
        .get(ehs as usize..ehs as usize + 4)
        .ok_or_else(|| Fail::new("short read"))?;
    let (penc, cenc, tenc) = (h[1], h[2], h[3]);
    let mut o = ehs + 4;
    let (_, s) = rd(o, penc)?;
    o += s;
    let (nfde, s) = rd(o, cenc)?;
    o += s;
    let mut starts: Vec<i64> = Vec::new();
    for _ in 0..nfde {
        let (a, s) = rd(o, tenc)?;
        o += s;
        let (_, s) = rd(o, tenc)?;
        o += s;
        starts.push(a);
    }
    starts.sort();
    starts.dedup();
    starts.retain(|&x| x < text_end);
    Ok(starts)
}

// ---- Exclusive accesses without ordering ----
/// Offsets of the exclusive loads and stores without ordering: ldxr / ldxrb / ldxrh / ldxp and stxr / stxrb / stxrh /
/// stxp, any size (each with its fixed fields exact; not CAS or CASP). Setting bit 15 makes each the same instruction
/// with ordering.
fn exclusive_order_sites(img: &[u8], ranges: &[(i64, i64)]) -> Vec<i64> {
    let mut out = Vec::new();
    for &(s, e) in ranges {
        let mut o = s;
        while o + 4 <= e {
            let w = rd32(img, o as usize);
            if w & 0x3FFFFC00 == 0x085F7C00
                || w & 0xBFFF8000 == 0x887F0000
                || w & 0x3FE0FC00 == 0x08007C00
                || w & 0xBFE08000 == 0x88200000
            {
                out.push(o);
            }
            o += 4;
        }
    }
    out
}

/// (sub offset, add offset, size) of stack frames whose size is not a multiple of 16 (see `odd_sp_frames` in patch_nso.py)
fn odd_sp_frames(img: &[u8], ranges: &[(i64, i64)]) -> Vec<(i64, i64, u32)> {
    const WIN: i64 = 64;
    fn narrow(m: &str) -> Option<u32> {
        Some(match m {
            "ldrb" | "strb" | "ldrsb" | "ldurb" | "sturb" | "ldursb" => 1,
            "ldrh" | "strh" | "ldrsh" | "ldurh" | "sturh" | "ldursh" => 2,
            "ldrsw" | "ldursw" => 4,
            _ => return None,
        })
    }
    fn reg_bytes(c: char) -> Option<u32> {
        Some(match c {
            'x' => 8,
            'w' => 4,
            'q' => 16,
            'd' => 8,
            's' => 4,
            'h' => 2,
            'b' => 1,
            _ => return None,
        })
    }
    // True when the instruction leaves sp alone, or reads the frame within its first `size` bytes
    let inside = |ins: &Ins, size: u32| -> bool {
        if ins.group(cs::GRP_RET) || (ins.group(cs::GRP_JUMP) && !ins.group(cs::GRP_CALL)) {
            return false;
        }
        if ins.group(cs::GRP_CALL) || ins.group(cs::GRP_INT) {
            return true;
        }
        let (r, w): (&[u16], &[u16]) = match &ins.regs {
            Some((r, w)) => (r, w),
            None => (&[], &[]),
        };
        if !r.contains(&REG_SP) && !w.contains(&REG_SP) {
            return true;
        }
        let mems: Vec<&cs::Op> = ins.ops.iter().filter(|o| o.ty == OP_MEM).collect();
        let regs: Vec<&'static str> = ins
            .ops
            .iter()
            .filter(|o| o.ty == OP_REG)
            .map(|o| cs::reg_name(o.reg))
            .collect();
        if w.contains(&REG_SP)
            || ins.writeback
            || mems.len() != 1
            || mems[0].base != REG_SP
            || mems[0].index != 0
            || regs.is_empty()
            || regs.len() > 2
        {
            return false;
        }
        let width = narrow(ins.mn()).or_else(|| regs[0].chars().next().and_then(reg_bytes));
        match width {
            Some(width) => {
                0 <= mems[0].disp
                    && mems[0].disp as i64 + (width as i64) * regs.len() as i64 <= size as i64
            }
            None => false,
        }
    };
    let mut out = Vec::new();
    for &(s, e) in ranges {
        let mut o = s;
        while o + 4 <= e {
            let w = rd32(img, o as usize);
            if w & 0xFFC003FF == 0xD10003FF && (w >> 10) & 15 != 0 {
                // sub sp, sp, #imm (64-bit, no shift), imm not a multiple of 16
                let size = (w >> 10) & 0xFFF;
                let add = 0x910003FF | size << 10;
                let mut q = o + 4;
                let lim = e.min(o + 4 + 4 * WIN);
                while q < lim {
                    if rd32(img, q as usize) == add {
                        out.push((o, q, size));
                        break;
                    }
                    let Some(ins) = cs::decode(rd32(img, q as usize), q) else {
                        break;
                    };
                    if !inside(&ins, size) {
                        break;
                    }
                    q += 4;
                }
            }
            o += 4;
        }
    }
    out
}

/// `sub sp, sp, #n` (op 0xD10003FF) or `add sp, sp, #n` (0x910003FF); the immediate is 12 bits, optionally shifted by 12
fn sp_adjust(op: u32, n: u32) -> Res<u32> {
    if n <= 0xFFF {
        return Ok(op | n << 10);
    }
    if !(n & 0xFFF == 0 && n >> 12 <= 0xFFF) {
        return Err(Fail::new(format!("{n:#x}")));
    }
    Ok(op | 1 << 22 | (n >> 12) << 10)
}

/// Offsets of the completer of Trinity's per-frame rendezvous (see `trinity_completer_sites`)
fn trinity_completer_sites(img: &[u8], ranges: &[(i64, i64)]) -> Vec<i64> {
    let mut out = Vec::new();
    let needle: Vec<u8> = [0x88DFFD28u32, 0x7100091F]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(); // ldar w8,[x9]; cmp w8,#2
    for &(s, e) in ranges {
        let mut from = s;
        while let Some(o) = crate::detect::find(img, &needle, from, e) {
            let o = o as i64;
            let f = o - 40;
            if o % 4 == 0 && f >= s && o + 12 <= e {
                let w: Vec<u32> = (0..13).map(|i| rd32(img, (f + 4 * i) as usize)).collect();
                if w[..3] == [0xA9BE7BFD, 0xA9014FF4, 0x910003FD]
                    && w[3] & 0xFFC003FF == 0xF9400008
                    && w[4] == 0x52800029
                    && w[5] & 0xFFC003FF == 0x39000109
                    && w[6] & 0xFFC003FF == 0x39400109
                    && (w[6] >> 10) & 0xFFF == ((w[5] >> 10) & 0xFFF) + 1
                    && w[7] & 0xFF00001F == 0x34000009
                    && w[8] & 0xFFC003FF == 0xF9400114
                    && w[9] & 0xFFC003FF == 0x91000289
                    && w[12] & 0xFF00001F == 0x54000001
                {
                    out.push(f);
                }
            }
            from = o + 4;
        }
    }
    out
}

// ---- the linear scan for rewrite points ----
const SPIN_TOPS: [u32; 11] = [
    0x16, 0x17, 0x54, 0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37, 0xB6, 0xB7,
];

type ScanChunk = (Vec<(i64, Kind)>, Vec<(i64, i64)>);

/// One 1 MB piece of the scan: the rewrite points in it (in address order) and the spin wait candidates (head, back-edge)
fn scan_piece(img: &[u8], lo: i64, hi: i64) -> ScanChunk {
    let (mut kinds, mut spin) = (Vec::new(), Vec::new());
    let mut o = lo;
    while o < hi {
        let w = rd32(img, o as usize);
        let top = w >> 24;
        if top <= 0xB7 && SPIN_TOPS.contains(&top) {
            let t = top;
            let d: i64 = if t == 0x16 || t == 0x17 {
                (((w & 0x3FFFFFF) as i64) - (1 << 26)) * 4
            } else if t & 0x7E == 0x36 {
                if w & 0x40000 != 0 {
                    ((((w >> 5) & 0x3FFF) as i64) - (1 << 14)) * 4
                } else {
                    4
                }
            } else if t == 0x54 {
                if w & 0x800000 != 0 && w & 0x10 == 0 {
                    ((((w >> 5) & 0x7FFFF) as i64) - (1 << 19)) * 4
                } else {
                    4
                }
            } else if w & 0x800000 != 0 {
                ((((w >> 5) & 0x7FFFF) as i64) - (1 << 19)) * 4
            } else {
                4
            };
            if (-SPIN_WIN..=0).contains(&d) {
                spin.push((o + d, o));
            }
        }
        let k = if w & 0xFFE0001F == 0xD4000001 {
            Some(Kind::Svc((w >> 5) & 0xFFFF))
        } else if w & 0xFFFFFFE0 == 0xD53BD040 {
            Some(Kind::TpidrR)
        } else if w & 0xFFFFFFE0 == 0xD51BD040 {
            Some(Kind::TpidrW)
        } else if w & 0xFFFFFFE0 == 0xD53BD060 {
            Some(Kind::TpidrroR)
        } else if w & 0xFFFFFFE0 == 0xD53BE020 {
            Some(Kind::Cntpct(w & 31))
        } else if w & 0xFFFFFFE0 == 0xD53BE040 {
            Some(Kind::Cntvct(w & 31))
        } else if w & 0xFFFFFFE0 == 0xD53B0020 {
            // mrs xN, ctr_el0 (cache type): the Apple kernel does not expose it to user mode (SIGILL)
            Some(Kind::Ctr(w & 31))
        } else if w & 0xFFE0FFFF == 0xCB2063FF && (w >> 16) & 31 != 18 {
            // sub sp, sp, xN (extended register, LSL #0): sp may end up misaligned (site_sp_align); with x18 it is an x18 site
            Some(Kind::SpAlign((w >> 16) & 31))
        } else if cs::may_name_x18(w) && cs::names_x18(w, o) == Some(true) {
            Some(Kind::X18)
        } else {
            None
        };
        if let Some(k) = k {
            kinds.push((o, k));
        }
        o += 4;
    }
    (kinds, spin)
}

// ---- function containing an address ----
fn func_of(rw: &Rw, a: i64) -> (i64, i64) {
    let i = rw.starts.partition_point(|&x| x <= a) as i64 - 1;
    if i >= 0 {
        let i = i as usize;
        return (
            rw.starts[i],
            if i + 1 < rw.starts.len() {
                rw.starts[i + 1]
            } else {
                rw.text_end
            },
        );
    }
    if let Some(&first) = rw.starts.first() {
        (
            rw.data_blocks
                .iter()
                .filter(|&&(_, e)| e <= a)
                .map(|&(_, e)| e)
                .max()
                .unwrap_or(0),
            first,
        )
    } else {
        (a, a + 4)
    }
}

const BIG_FN: i64 = 0x40000;
const PIECE: i64 = 0x40000;
const PIECE_B: i64 = 0x10000;

/// [(start, end)] covering [fa, fb), and the far b / bl in it as [(site, target)]
type Pairs = Vec<(i64, i64)>;

fn pieces(img: &[u8], fa: i64, fb: i64) -> (Pairs, Pairs) {
    let n = ((fb - fa) / 4) as usize;
    let w = |i: usize| rd32(img, fa as usize + 4 * i);
    let mut cross = vec![0i32; n + 2];
    let mut far = Vec::new();
    for i in 0..n {
        let x = w(i);
        let t = x >> 24;
        let d: i64;
        if (t == 0x54 && x & 0x10 == 0) || t & 0x7E == 0x34 {
            let v = ((x >> 5) & 0x7FFFF) as i64;
            d = v - ((v & 0x40000) << 1);
        } else if t & 0x7E == 0x36 {
            let v = ((x >> 5) & 0x3FFF) as i64;
            d = v - ((v & 0x2000) << 1);
        } else if t & 0x7C == 0x14 {
            let v = (x & 0x3FFFFFF) as i64;
            d = v - ((v & 0x2000000) << 1);
            if t & 0x80 != 0 || 4 * d.abs() > PIECE_B {
                far.push((fa + 4 * i as i64, fa + 4 * (i as i64 + d)));
                continue;
            }
        } else {
            continue;
        }
        let (i64_i, nn) = (i as i64, n as i64);
        let lo = (i64_i.min(i64_i + d)).max(-1);
        let hi = (i64_i.max(i64_i + d)).min(nn);
        cross[(lo + 1) as usize] += 1;
        cross[(hi + 1) as usize] -= 1;
    }
    let mut cand: Vec<i64> = Vec::new();
    let mut c = 0i32;
    #[allow(clippy::needless_range_loop)]
    // `k` is also the word index (`w(k - 1)`) and the candidate value
    for k in 0..n {
        c += cross[k];
        let x = if k > 0 { w(k - 1) } else { 0 };
        if k > 0 && c == 0 && (matches!(x & 0xFFFFFC1F, 0xD65F0000 | 0xD61F0000) || x >> 26 == 0x05)
        {
            cand.push(k as i64);
        }
    }
    let mut cuts: Vec<i64> = Vec::new();
    let mut s = 0i64;
    let nn = n as i64;
    while s + PIECE / 4 < nn {
        let mut j = cand.partition_point(|&x| x <= s + PIECE / 4) as i64 - 1;
        if j < 0 || cand[j as usize] <= s {
            j = cand.partition_point(|&x| x <= s + PIECE / 4) as i64;
        }
        if j >= cand.len() as i64 {
            break;
        }
        s = cand[j as usize];
        cuts.push(s);
    }
    let mut b = vec![0i64];
    b.extend(&cuts);
    b.push(nn);
    (
        b.windows(2)
            .map(|p| (fa + 4 * p[0], fa + 4 * p[1]))
            .collect(),
        far,
    )
}

/// Words of text decoded ahead per batch of the per-function loop when it runs on several workers: 16 Ki words, about
/// 4 MB of `Ins` (a function bigger than that is a batch of its own)
const DECODE_BATCH_WORDS: i64 = 1 << 14;

/// A function's instructions. Capstone stops at the first word it cannot decode, so go on after it
fn disasm_fn(img: &[u8], fa: i64, fb: i64) -> Vec<Ins> {
    // one vector for the whole function (at most one instruction per word), decoded in runs: a run of n instructions
    // from `a` ends at an undecodable word, and decoding goes on after it, at a + 4 n + 4
    let mut out: Vec<Ins> = Vec::with_capacity(((fb - fa).max(0) / 4) as usize);
    let mut a = fa;
    while a < fb {
        let n = cs::disasm_into(&mut out, &img[a as usize..fb as usize], a);
        a += 4 * n as i64 + 4;
    }
    out
}

/// `branch_entries`: direct branches (b, bl, b.cond, cbz / cbnz, tbz / tbnz) from anywhere in the module's code into each
/// range from outside it, as the Python's sets (built in the same order: b / bl over every code range, then the
/// conditional branches of the windows a 1 MB branch can reach the ranges from). Only the ranges `want` (indexes into
/// `ranges`, ascending) are kept: the Python builds the set of every range but reads only those of the ranges it
/// solves, and a range's set does not depend on the others' (which range holds a target is decided against all of
/// `ranges`; the windows of the wanted ranges cover every conditional branch that can reach them, and visit them in the
/// same ascending order)
fn branch_entries(
    img: &[u8],
    code_ranges: &[(i64, i64)],
    ranges: &[(i64, i64)],
    want: &[usize],
) -> HashMap<usize, PySet> {
    let mut out: HashMap<usize, PySet> = want.iter().map(|&k| (k, PySet::new())).collect();
    if ranges.is_empty() || want.is_empty() {
        return out;
    }
    let lo_: Vec<i64> = ranges.iter().map(|r| r.0).collect();
    let far = |t: u32| (0x14..0x18).contains(&t) || (0x94..0x98).contains(&t);
    let near = |t: u32| {
        matches!(
            t,
            0x54 | 0x34 | 0x35 | 0xB4 | 0xB5 | 0x36 | 0x37 | 0xB6 | 0xB7
        )
    };
    let scan =
        |start: i64, end: i64, mark: &dyn Fn(u32) -> bool, out: &mut HashMap<usize, PySet>| {
            let n = (end - start) / 4;
            for i in 0..n.max(0) {
                let at = start + 4 * i;
                let w = rd32(img, at as usize);
                let t = w >> 24;
                if !mark(t) {
                    continue;
                }
                let d: i64 = if t == 0x54 || t & 0x7E == 0x34 {
                    if t == 0x54 && w & 0x10 != 0 {
                        continue;
                    }
                    let v = ((w >> 5) & 0x7FFFF) as i64;
                    v - ((v & 0x40000) << 1)
                } else if t & 0x7E == 0x36 {
                    let v = ((w >> 5) & 0x3FFF) as i64;
                    v - ((v & 0x2000) << 1)
                } else {
                    let v = (w & 0x3FFFFFF) as i64;
                    v - ((v & 0x2000000) << 1)
                };
                let dest = at + 4 * d;
                let k = lo_.partition_point(|&x| x <= dest) as i64 - 1;
                if k >= 0 {
                    let (ra, rb) = ranges[k as usize];
                    if dest < rb
                        && !(ra <= at && at < rb)
                        && let Some(s) = out.get_mut(&(k as usize))
                    {
                        s.add(dest as u64);
                    }
                }
            }
        };
    let mut windows: Vec<(i64, i64)> = Vec::new();
    for &k in want {
        let (a, b) = ranges[k];
        let (a, b) = (((a - (1 << 20)).max(0)) & !3, b + (1 << 20));
        match windows.last_mut() {
            Some(w) if a <= w.1 => w.1 = w.1.max(b),
            _ => windows.push((a, b)),
        }
    }
    for &(start, end) in code_ranges {
        scan(start, end, &far, &mut out);
        for &(a, b) in &windows {
            if start.max(a) < end.min(b) {
                scan(start.max(a), end.min(b), &near, &mut out);
            }
        }
    }
    out
}

/// The jump solver's state over one module (`solve_fn`, `table_at`, `half_pads` of patch_nso.py): the functions solved
/// so far, and what the first solve computes for all of them (the direct entries of every range, the landing pads)
/// What the first solve computes for all: the direct entries of the ranges [`may_solve`] picks (by index in `funcs`), and
/// the module's landing pads
type SolverInit = (HashMap<usize, PySet>, crate::fde::LandingPads);

struct Solver {
    /// the ranges the function loop walks (`funcs`), sorted
    funcs: Vec<(i64, i64)>,
    fde_starts: HashSet<i64>,
    solved: HashMap<(i64, i64), Result<Solved, String>>,
    /// answers computed ahead, in parallel, for ranges the loop is likely to ask about (several workers only): taken
    /// into `solved` when the loop first asks, as the Python's lazy solve would have computed them then
    pre: HashMap<(i64, i64), Result<Solved, String>>,
    /// None until the first solve: (the direct entries of the ranges [`may_solve`] picks, by index in `funcs`, landing
    /// pads) or the error that stopped them
    init: Option<Result<SolverInit, String>>,
    /// the direct entries of a range the loop solves that [`may_solve`] did not pick (made when asked)
    late: HashMap<usize, PySet>,
}

/// What one solve reads besides the instructions: the range's direct entries, its landing pads, and whether an FDE
/// describes it
struct SolveArgs<'a> {
    entries: &'a PySet,
    landing: Vec<(i64, Vec<(i64, i64)>)>,
    unwound: bool,
}

fn solve_with(img: &[u8], insl: &[Ins], a: &SolveArgs, outside: &PySet) -> Result<Solved, String> {
    jump_solver::solve(insl, img, a.entries, outside, &a.landing, a.unwound)
}

/// Whether the function loop may solve [fa, fb): it holds a `br x18` that is not, as far as its words show, a byte table
/// of the 16-instruction form (adr x18 / ldrb or ldrsb / add x18, x18, xI, lsl #2), the one form the loop settles
/// without the solver. Only decides what is computed ahead: a range it misses is solved when the loop asks, one it
/// wrongly includes costs a solve nobody reads.
fn may_solve(img: &[u8], fa: i64, fb: i64) -> bool {
    let w = |a: i64| rd32(img, a as usize);
    let mut at = fa;
    while at + 4 <= fb {
        if w(at) == 0xD61F0240 {
            let lo = (at - 64).max(fa);
            let back = || (0..(at - lo) / 4).map(move |i| w(at - 4 - 4 * i));
            let add = back().find(|&x| x & 0xFFE0FFFF == 0x8B000A52);
            let adr = back().any(|x| x & 0x9F00001F == 0x10000012);
            let byte = add.is_some_and(|x| {
                let m = (x >> 16) & 31;
                back()
                    .find(|&q| {
                        q & 31 == m
                            && matches!(
                                q & 0xFFE00C00,
                                0x38600800
                                    | 0x38A00800
                                    | 0x38E00800
                                    | 0x78600800
                                    | 0x78A00800
                                    | 0x78E00800
                            )
                    })
                    .is_some_and(|q| q & 0xFF000000 == 0x38000000)
            });
            if !(adr && byte) {
                return true;
            }
        }
        at += 4;
    }
    false
}

impl Solver {
    fn prepare(&mut self, rw: &Rw) -> Res<()> {
        if self.init.is_none() {
            let img = &rw.img.b[..];
            let want: Vec<usize> = (0..self.funcs.len())
                .into_par_iter()
                .filter(|&k| may_solve(img, self.funcs[k].0, self.funcs[k].1))
                .collect();
            let entries = branch_entries(img, &rw.code_ranges, &self.funcs, &want);
            self.init = Some(crate::fde::landing_pads(img).map(|p| (entries, p)));
        }
        match self.init.as_ref().unwrap() {
            Ok(_) => Ok(()),
            Err(e) => Err(Fail::new(e.clone())),
        }
    }

    /// Make the direct entries of [fa, fb) when the first step did not (a range [`may_solve`] missed)
    fn need_entries(&mut self, rw: &Rw, fa: i64, fb: i64) {
        let Ok(k) = self.funcs.binary_search(&(fa, fb)) else {
            return;
        };
        let Some(Ok((entries, _))) = &self.init else {
            return;
        };
        if entries.contains_key(&k) || self.late.contains_key(&k) {
            return;
        }
        let e = branch_entries(&rw.img.b, &rw.code_ranges, &self.funcs, &[k]);
        self.late.extend(e);
    }

    /// The arguments of a solve of [fa, fb), once `prepare` (and `need_entries`) ran
    fn args(&self, rw: &Rw, fa: i64, fb: i64) -> SolveArgs<'_> {
        static EMPTY: std::sync::OnceLock<PySet> = std::sync::OnceLock::new();
        let Some(Ok((entries, pads))) = &self.init else {
            unreachable!("prepare() runs first")
        };
        let empty = EMPTY.get_or_init(PySet::new);
        SolveArgs {
            entries: match self.funcs.binary_search(&(fa, fb)) {
                Ok(i) => entries
                    .get(&i)
                    .or_else(|| self.late.get(&i))
                    .unwrap_or(empty),
                Err(_) => empty,
            },
            landing: {
                // `{a: pads_at[a] for a in pad_starts[i:j]}`: the pads in [fa, fb), each with its ranges
                let lo = pads.partition_point(|r| r.0 < fa);
                let hi = pads.partition_point(|r| r.0 < fb);
                let mut l: Vec<(i64, Vec<(i64, i64)>)> = Vec::new();
                for &(pad, r) in &pads[lo..hi] {
                    match l.last_mut() {
                        Some(e) if e.0 == pad => e.1.push(r),
                        _ => l.push((pad, vec![r])),
                    }
                }
                l
            },
            unwound: (fa, fb) == func_of(rw, fa) && self.fde_starts.contains(&fa),
        }
    }

    /// With several workers: solve ahead, in parallel, every range [`may_solve`] picks (each solve is a function of the
    /// image, which the function loop does not write, and of the ranges). An error of the shared first step is left for
    /// the loop to raise where the Python would.
    fn presolve(&mut self, rw: &Rw) {
        if rayon::current_num_threads() < 2 || self.prepare(rw).is_err() {
            return;
        }
        let Some(Ok((entries, _))) = &self.init else {
            return;
        };
        let mut cand: Vec<usize> = entries.keys().copied().collect();
        cand.sort_unstable();
        let cand: Vec<(i64, i64)> = cand.into_iter().map(|k| self.funcs[k]).collect();
        let img = &rw.img.b[..];
        let args: Vec<SolveArgs> = cand.iter().map(|&(fa, fb)| self.args(rw, fa, fb)).collect();
        let empty = PySet::new();
        let out: Vec<Result<Solved, String>> = cand
            .par_iter()
            .zip(args.par_iter())
            .map(|(&(fa, fb), a)| solve_with(img, &disasm_fn(img, fa, fb), a, &empty))
            .collect();
        self.pre = cand.into_iter().zip(out).collect();
    }

    /// `solve_fn`: solve (fa, fb) with the targets `outside` of tables elsewhere, and keep the answer
    fn solve_fn(
        &mut self,
        rw: &Rw,
        fa: i64,
        fb: i64,
        insl: &[Ins],
        outside: &PySet,
    ) -> Res<&Solved> {
        self.prepare(rw)?;
        self.need_entries(rw, fa, fb);
        let r = match (outside.is_empty(), self.pre.remove(&(fa, fb))) {
            (true, Some(r)) => r,
            _ => solve_with(&rw.img.b, insl, &self.args(rw, fa, fb), outside),
        };
        self.solved.insert((fa, fb), r);
        match &self.solved[&(fa, fb)] {
            Ok(s) => Ok(s),
            Err(e) => Err(Fail::new(e.clone())),
        }
    }

    /// `table_at`: (targets, why) for the table the br at `at` reads
    fn table_at(
        &mut self,
        rw: &Rw,
        fa: i64,
        fb: i64,
        insl: &[Ins],
        at: i64,
    ) -> Res<(Option<Vec<i64>>, String)> {
        let s = match self.solved.get(&(fa, fb)) {
            Some(Ok(s)) => s,
            Some(Err(e)) => return Err(Fail::new(e.clone())),
            None => self.solve_fn(rw, fa, fb, insl, &PySet::new())?,
        };
        Ok((
            s.targets(at).cloned(),
            s.why(at).unwrap_or("not a dispatch").to_string(),
        ))
    }

    /// `half_pads`: the landing pads a halfword table needs (its largest entry + 1, from the table the solver read), or
    /// None (all 65,536)
    fn half_pads(
        &mut self,
        rw: &Rw,
        fa: i64,
        fb: i64,
        insl: &[Ins],
        at: i64,
        base: i64,
    ) -> Res<Option<i64>> {
        let (tgt, _) = self.table_at(rw, fa, fb, insl, at)?;
        let Some(tgt) = tgt.filter(|t| !t.is_empty()) else {
            return Ok(None);
        };
        if tgt.iter().any(|&t| t < base || (t - base) % 4 != 0) {
            return Ok(None);
        }
        Ok(Some(tgt.iter().map(|&t| t - base).max().unwrap() / 4 + 1))
    }
}

pub fn run(rw: &mut Rw) -> Res<()> {
    let name = rw.name.clone();
    let text_end = rw.text_end;
    rw.starts = function_starts(&rw.img.b, text_end)?;
    // Data blocks in the text are not code: words there that read as rewrite sites are left alone
    crate::mark("starts");
    rw.data_blocks = crate::fde::data_blocks(&rw.img.b, text_end).map_err(Fail::new)?;
    crate::mark("data_blocks");
    let mut cr = Vec::new();
    let mut prev = 0i64;
    for &(s, e) in &rw.data_blocks {
        cr.push((prev, s));
        prev = e;
    }
    cr.push((prev, text_end));
    rw.code_ranges = cr;

    // exclusive accesses: every one gets acquire or release ordering
    let ordered = exclusive_order_sites(&rw.img.b, &rw.code_ranges);
    for &o in &ordered {
        let w = rw.img.w(o) | 0x8000;
        rw.img.set(o, w);
    }
    if !ordered.is_empty() {
        rw.stats.push(("exclusive_ordered", ordered.len() as u64));
    }
    rw.ordered = ordered.into_iter().collect();
    // stack frames of a size that is not a multiple of 16
    for (s, a, size) in odd_sp_frames(&rw.img.b, &rw.code_ranges) {
        let r = (size + 15) & !15;
        let (ws, wa) = (sp_adjust(0xD10003FF, r)?, sp_adjust(0x910003FF, r)?);
        rw.img.set(s, ws);
        rw.img.set(a, wa);
        rw.stat("sp_frame");
    }
    crate::mark("exclusive+odd_sp");
    let trinity = trinity_completer_sites(&rw.img.b, &rw.code_ranges);
    if trinity.len() > 1 {
        let l: Vec<String> = trinity.iter().map(|o| format!("{o:#x}")).collect();
        rw.say(format!("[RED] {name}: {} functions have the shape of Trinity's rendezvous completer, so none gets its barrier: {}", trinity.len(), l.join(", ")));
    } else if let Some(&f) = trinity.first() {
        // the frame pointer's mov gives up its word: the ldr, the mov and the strb move up one and dmb ish follows the strb
        let (a, b, c) = (rw.img.w(f + 12), rw.img.w(f + 16), rw.img.w(f + 20));
        for (i, w) in [a, b, c, 0xD5033BBF].into_iter().enumerate() {
            rw.img.set(f + 8 + 4 * i as i64, w);
        }
        rw.stat("trinity_completer");
    }

    crate::mark("trinity");
    // linear scan: rewrite points and spin wait candidates, in 1 MB pieces over the code
    let mut pcs: Vec<(i64, i64)> = Vec::new();
    for &(start, end) in &rw.code_ranges {
        let mut lo = start;
        while lo < end {
            pcs.push((lo, (lo + 0x100000).min(end)));
            lo += 0x100000;
        }
    }
    let results: Vec<ScanChunk> = {
        let img = &rw.img.b[..];
        pcs.par_iter()
            .map(|&(lo, hi)| scan_piece(img, lo, hi))
            .collect()
    };
    let mut spin_cand: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for (k, s) in results {
        rw.kinds.extend(k);
        for (head, be) in s {
            spin_cand.entry(head).or_default().push(be);
        }
    }

    crate::mark("linear scan");
    // Take the instruction table per function, find the windows and jump tables
    let mut funcs: Vec<(i64, i64)> = {
        let set: std::collections::BTreeSet<(i64, i64)> = rw
            .kinds
            .iter()
            .filter(|(_, k)| *k == Kind::X18)
            .map(|&(a, _)| func_of(rw, a))
            .collect();
        set.into_iter().collect()
    };
    let mut far_into: Vec<(i64, i64)> = Vec::new();
    if funcs.iter().any(|&(fa, fb)| fb - fa > BIG_FN) {
        let sites18: Vec<i64> = rw
            .kinds
            .iter()
            .filter(|(_, k)| *k == Kind::X18)
            .map(|x| x.0)
            .collect();
        let mut split: Vec<(i64, i64)> = Vec::new();
        for &(fa, fb) in &funcs {
            if fb - fa <= BIG_FN {
                split.push((fa, fb));
                continue;
            }
            let (ps, far) = pieces(&rw.img.b, fa, fb);
            far_into.extend(far);
            for &(p, q) in &ps {
                if sites18.partition_point(|&x| x < p) < sites18.partition_point(|&x| x < q) {
                    split.push((p, q));
                }
            }
            rw.say(format!(
                "function {fa:#x}..{fb:#x} ({:.2} MB, no unwind entries) analysed in {} pieces",
                (fb - fa) as f64 / 1048576.0,
                ps.len()
            ));
        }
        funcs = split;
    }
    let mut solver = Solver {
        funcs: funcs.clone(),
        fde_starts: rw.starts.iter().copied().collect(),
        solved: HashMap::new(),
        pre: HashMap::new(),
        init: None,
        late: HashMap::new(),
    };
    solver.presolve(rw);
    let mut newly_accepted: HashSet<i64> = HashSet::new();
    let mut rmid_all: HashSet<i64> = HashSet::new();
    // the unwind functions' ends, for the conditional selects with an x18 source that need a proof about the rest of their function (`function_ends`, engine patch 0409)
    let function_ends: HashMap<i64, i64> = crate::fde::fde_ranges(&rw.img.b)
        .map_err(Fail::new)?
        .into_iter()
        .collect();

    // Decoding is most of this loop's time and reads only the image, which nothing in the loop writes (it records
    // windows, selects and tables in `rw`, never a word of `rw.img`): with more than one worker the functions are
    // decoded in parallel, a batch of consecutive ones at a time (bounded memory), and analysed one by one in their
    // order as before. With one worker a batch is one function, as it was.
    let batch_words: i64 = if rayon::current_num_threads() > 1 {
        DECODE_BATCH_WORDS
    } else {
        0
    };
    let mut decoded: std::collections::VecDeque<Vec<Ins>> = std::collections::VecDeque::new();
    for (k, &(fa, fb)) in funcs.iter().enumerate() {
        if decoded.is_empty() {
            let (mut end, mut words) = (k + 1, (fb - fa) / 4);
            while end < funcs.len() && words + (funcs[end].1 - funcs[end].0) / 4 <= batch_words {
                words += (funcs[end].1 - funcs[end].0) / 4;
                end += 1;
            }
            let img = &rw.img.b[..];
            decoded = if end - k == 1 {
                std::iter::once(disasm_fn(img, fa, fb)).collect()
            } else {
                funcs[k..end]
                    .par_iter()
                    .map(|&(a, b)| disasm_fn(img, a, b))
                    .collect::<Vec<_>>()
                    .into()
            };
        }
        let insl = decoded
            .pop_front()
            .expect("one decoded function per entry of funcs");
        let mut by_address: Option<HashMap<i64, &Ins>> = None;
        let ws = windows::find_windows(&insl);
        for wseg in &ws {
            rw.windows.push(wseg.clone());
            for x in wseg {
                rw.done.insert(x.address);
            }
            if wseg.iter().any(|x| x.mn() == "b") {
                newly_accepted.insert(wseg[0].address);
            }
        }
        for j in 0..insl.len() {
            let ins = &insl[j];
            if ins.mn() == "csel"
                && function_ends
                    .get(&fa)
                    .is_some_and(|&end| ins.address < end && end <= fb)
                && !rw.done.contains(&ins.address)
                && let Some(args) = crate::select::select_x18(ins)
            {
                let by =
                    by_address.get_or_insert_with(|| insl.iter().map(|p| (p.address, p)).collect());
                if let Some(temp) =
                    crate::select::select_scratch(ins.address, by, function_ends[&fa], args.0)?
                {
                    rw.selects.insert(ins.address, (args, temp));
                }
            }
            if !(ins.mn() == "br" && &*ins.op_str == "x18") {
                continue;
            }
            let (mut base, mut width): (Option<i64>, Option<i64>) = (None, None);
            // 16 instructions back, as for the offset-table form
            let ctx = &insl[j.saturating_sub(16)..j];
            for p in ctx.iter().rev() {
                if p.mn() == "adr" && p.op_str.starts_with("x18,") {
                    base = Some(p.ops[1].imm);
                    break;
                }
            }
            for p in ctx.iter().rev() {
                if p.mn() == "add"
                    && p.op_str.starts_with("x18, x18,")
                    && p.op_str.contains("lsl #2")
                {
                    // capstone names x30 'lr' (and x29 'fp')
                    let rn = cs::reg_name(p.ops[2].reg);
                    let idx: Option<u32> = match rn {
                        "lr" => Some(30),
                        "fp" => Some(29),
                        r => num(r),
                    };
                    for q in ctx.iter().rev() {
                        let q0 = num(cs::reg_name(q.ops.first().map(|o| o.reg).unwrap_or(0)));
                        if matches!(q.mn(), "ldrb" | "ldrsb") && q0 == idx {
                            width = Some(256);
                        }
                        if matches!(q.mn(), "ldrh" | "ldrsh") && q0 == idx {
                            // `(half_pads(...) if ldrh else None) or 65536 if base else 65536`
                            width = Some(match base.filter(|&b| b != 0) {
                                Some(b) if q.mn() == "ldrh" => solver
                                    .half_pads(rw, fa, fb, &insl, ins.address, b)?
                                    .filter(|&x| x != 0)
                                    .unwrap_or(65536),
                                _ => 65536,
                            });
                        }
                        if width.is_some_and(|w| w != 0) {
                            break;
                        }
                    }
                    break;
                }
            }
            if !(base.is_some_and(|b| b != 0) && width.is_some_and(|w| w != 0)) {
                // a byte or halfword table keeps its pads wherever its add is
                let at = ins.address;
                let far = jumps::jump_bytes_far(&insl, j, &mut |b| {
                    solver.half_pads(rw, fa, fb, &insl, at, b)
                })?;
                if let Some(far) = far {
                    rw.jumps.insert(at, far);
                    continue;
                }
                let (tgt, why) = solver.table_at(rw, fa, fb, &insl, at)?;
                let tgt = tgt.filter(|t| !t.is_empty());
                if tgt.is_none() && jumps::tail_call(&insl, j) {
                    rw.tailcalls.insert(at);
                    continue;
                }
                let Some(tgt) = tgt else {
                    return Err(Fail::new(format!("jump table {at:x}: {why}")));
                };
                rw.tabjumps.insert(at, tgt);
                continue;
            }
            rw.jumps
                .insert(ins.address, (base.unwrap(), width.unwrap()));
        }
        // No jump may land in the middle of a window, except a retry block's branch onto the window's store-exclusive
        let inwin: HashSet<i64> = ws
            .iter()
            .flat_map(|w| w.iter().map(|x| x.address))
            .collect();
        let heads: HashSet<i64> = ws.iter().map(|w| w[0].address).collect();
        let mut rmid: HashSet<i64> = HashSet::new();
        for k in 0..insl.len() {
            let x = &insl[k];
            if !is_cond_branch_or_b(x.mn()) {
                continue;
            }
            let t = last_imm(x);
            if inwin.contains(&t) && !heads.contains(&t) {
                let wseg = ws
                    .iter()
                    .find(|w| w.iter().any(|y| y.address == t))
                    .unwrap();
                if x.mn() != "bl" && wseg.iter().any(|y| y.address == x.address) {
                    newly_accepted.insert(wseg[0].address);
                    continue;
                }
                let rb = if !matches!(x.mn(), "b" | "bl") {
                    windows::retry_block(&insl, k, wseg)
                } else {
                    None
                };
                let Some(rb) = rb else {
                    return Err(Fail::new(format!("branch into window {:x}", x.address)));
                };
                if rb.0.iter().any(|y| rw.done.contains(&y.address)) {
                    return Err(Fail::new(format!(
                        "retry block overlaps a window {:x}",
                        rb.0[0].address
                    )));
                }
                let tail_addrs: HashSet<i64> = rb.1.iter().map(|y| y.address).collect();
                for y in &rb.1 {
                    if matches!(y.mn(), "cbz" | "cbnz" | "tbz" | "tbnz") || y.mn().starts_with("b.")
                    {
                        let dest = last_imm(y);
                        if !(!inwin.contains(&dest)
                            || heads.contains(&dest)
                            || tail_addrs.contains(&dest))
                        {
                            return Err(Fail::new(format!(
                                "retry copy branches into window {:x}",
                                y.address
                            )));
                        }
                    }
                }
                rw.retries.push(vec![
                    (rb.0.clone(), x.address + 4),
                    (rb.1.clone(), wseg.last().unwrap().address + 4),
                ]);
                for y in &rb.0 {
                    rw.done.insert(y.address);
                }
                for y in &rb.0[1..] {
                    rmid.insert(y.address);
                }
            }
        }
        for x in &insl {
            if is_cond_branch_or_b(x.mn()) && rmid.contains(&last_imm(x)) {
                return Err(Fail::new(format!(
                    "branch into retry block {:x}",
                    x.address
                )));
            }
        }
        for (a_, tgt) in rw.tabjumps.items.iter() {
            if fa <= *a_ && *a_ < fb && tgt.iter().any(|t| inwin.contains(t) && !heads.contains(t))
            {
                return Err(Fail::new(format!("jump table target into window {a_:x}")));
            }
        }
        rmid_all.extend(rmid);
    }
    if !far_into.is_empty() {
        // functions analysed in pieces: their far b / bl, and every jump table's targets, may not land inside a window or a retry block
        let win_mid: HashSet<i64> = rw
            .windows
            .iter()
            .flat_map(|w| w[1..].iter().map(|x| x.address))
            .collect();
        for &(at, to) in &far_into {
            if win_mid.contains(&to) || rmid_all.contains(&to) {
                return Err(Fail::new(format!(
                    "far branch into a window or retry block {at:x}"
                )));
            }
        }
        for (at, tgt) in rw.tabjumps.items.iter() {
            if tgt
                .iter()
                .any(|t| win_mid.contains(t) || rmid_all.contains(t))
            {
                return Err(Fail::new(format!(
                    "jump table target into a window or retry block {at:x}"
                )));
            }
        }
    }

    crate::mark("functions");
    // Direct branches from other functions were not part of the per-function entry check above.
    for w in &rw.windows {
        if newly_accepted.contains(&w[0].address)
            && !w.windows(2).all(|p| p[1].address == p[0].address + 4)
        {
            return Err(Fail::new(format!(
                "noncontiguous window {:x}",
                w[0].address
            )));
        }
    }
    let new_mid: HashSet<i64> = rw
        .windows
        .iter()
        .filter(|w| newly_accepted.contains(&w[0].address))
        .flat_map(|w| w[1..].iter().map(|x| x.address))
        .collect();
    // A table's targets in another function (or piece) are entries there that its proof did not see: prove those
    // functions again with them
    let range_of = |a: i64| -> Option<(i64, i64)> {
        let i = funcs.partition_point(|r| r.0 <= a) as i64 - 1;
        (i >= 0 && a < funcs[i as usize].1).then(|| funcs[i as usize])
    };
    let mut outside: Vec<((i64, i64), PySet)> = Vec::new();
    let mut add_outside = |r: (i64, i64), t: i64| match outside.iter_mut().find(|(x, _)| *x == r) {
        Some(e) => e.1.add(t as u64),
        None => {
            let mut s = PySet::new();
            s.add(t as u64);
            outside.push((r, s));
        }
    };
    for (at, tgt) in rw.tabjumps.items.iter() {
        for &t in tgt {
            if let Some(r) = range_of(t)
                && Some(r) != range_of(*at)
            {
                add_outside(r, t);
            }
        }
    }
    for (at, (b, width)) in rw.jumps.items.iter() {
        let Some(r0) = range_of(*at) else { continue };
        let mut t = *b;
        while t < b + 4 * width {
            if let Some(r) = range_of(t)
                && r != r0
            {
                add_outside(r, t);
            }
            t += 4;
        }
    }
    for ((fa, fb), ts) in &outside {
        let before: Vec<i64> = match solver.solved.get(&(*fa, *fb)) {
            None => continue,
            Some(Ok(s)) => s.found.iter().map(|(a, _)| *a).collect(),
            Some(Err(_)) => unreachable!("a failed solve stopped the module"),
        };
        let insl = disasm_fn(&rw.img.b, *fa, *fb);
        let found = solver.solve_fn(rw, *fa, *fb, &insl, ts)?.clone();
        for at in before {
            if let Some(tj) = rw.tabjumps.get(at) {
                let mut a: Vec<i64> = found.targets(at).cloned().unwrap_or_default();
                let mut b: Vec<i64> = tj.clone();
                a.sort_unstable();
                a.dedup();
                b.sort_unstable();
                b.dedup();
                if a != b {
                    return Err(Fail::new(format!(
                        "jump table {at:x}: an entry from another function is not proved"
                    )));
                }
            }
        }
    }
    drop(solver); // its answers, entries and landing pads are not needed past this point
    if !new_mid.is_empty() {
        for &(start, end) in &rw.code_ranges {
            let mut at = start;
            while at < end - 3 {
                let w = rw.img.w(at);
                let t = w >> 24;
                let d: i64 = if (t == 0x54 && w & 0x10 == 0) || t & 0x7E == 0x34 {
                    let v = ((w >> 5) & 0x7FFFF) as i64;
                    v - ((v & 0x40000) << 1)
                } else if t & 0x7E == 0x36 {
                    let v = ((w >> 5) & 0x3FFF) as i64;
                    v - ((v & 0x2000) << 1)
                } else if t & 0x7C == 0x14 {
                    let v = (w & 0x3FFFFFF) as i64;
                    v - ((v & 0x2000000) << 1)
                } else {
                    at += 4;
                    continue;
                };
                let dest = at + 4 * d;
                if new_mid.contains(&dest) && func_of(rw, at) != func_of(rw, dest) {
                    return Err(Fail::new(format!(
                        "branch into window from another function {at:x}"
                    )));
                }
                at += 4;
            }
        }
    }

    crate::mark("post checks");
    emit_all(rw, spin_cand)
}

/// Emission: windows, retry windows, every site, observation gates, address region gates, frame step, stubs, spin waits
fn emit_all(rw: &mut Rw, spin_cand: BTreeMap<i64, Vec<i64>>) -> Res<()> {
    let name = rw.name.clone();
    let windows = std::mem::take(&mut rw.windows);
    for wseg in &windows {
        rw.use_area(wseg[0].address);
        let (st, lo, _hi) = windows::site_window(rw, wseg)?;
        rw.stat("window");
        rw.put_branch(lo, st)?;
    }
    rw.windows = windows;
    let retries = std::mem::take(&mut rw.retries);
    for parts in &retries {
        rw.use_area(parts[0].0[0].address);
        let st = windows::site_retry_window(rw, parts)?;
        rw.stat("retry_window");
        rw.put_branch(parts[0].0[0].address, st)?;
    }
    rw.retries = retries;
    // every site, in address order
    let kinds = rw.kinds.clone();
    for &(a, k) in &kinds {
        if rw.done.contains(&a) {
            continue;
        }
        rw.use_area(a);
        let ins = crate::ins::dis(rw.img.w(a), a)?;
        // stat() is called after the site is emitted, as in the Python (a hop made while emitting is counted first)
        let (st, stat_name): (i64, &'static str) = match k {
            Kind::X18 => crate::sites::x18_site(rw, &ins)?,
            Kind::TpidrR => (
                crate::sites::site_sysreg_read(rw, &ins, crate::rewriter::KEY_KTLS)?,
                "tpidr_r",
            ),
            Kind::TpidrroR => (
                crate::sites::site_sysreg_read(rw, &ins, crate::rewriter::KEY_KTLR)?,
                "tpidrro_r",
            ),
            Kind::TpidrW => (crate::sites::site_tpidr_write(rw, &ins)?, "tpidr_w"),
            Kind::Svc(arg) => (crate::sites::site_gate(rw, &ins, "svc", arg as i64)?, "svc"),
            Kind::Cntpct(arg) => (
                crate::sites::site_gate(rw, &ins, "cntpct", arg as i64)?,
                "cntpct",
            ),
            Kind::Cntvct(arg) => (
                crate::sites::site_gate(rw, &ins, "cntvct", arg as i64)?,
                "cntvct",
            ),
            Kind::SpAlign(arg) => (crate::sites::site_sp_align(rw, &ins, arg)?, "sp_align"),
            Kind::Ctr(arg) => {
                // a constant: DminLine = 4 (64-byte lines); movz xN, #4, lsl #16, in place, or into the slot K18 for x18
                if arg == 18 {
                    (
                        crate::sites::site_slot_copy(
                            rw,
                            &ins,
                            crate::sites::Src::Word(0xD2A00080 | 15),
                            KEY_K18,
                        )?,
                        "ctr",
                    )
                } else {
                    rw.img.set(a, 0xD2A00080 | arg);
                    rw.stat("ctr");
                    continue;
                }
            }
        };
        rw.stat(stat_name);
        rw.put_branch(a, st)?;
    }

    crate::mark("site emission");
    // registered observation gates of the build
    let reg_obs: Vec<ObsRow> = crate::patches::obs_for(&rw.build_id)
        .iter()
        .map(|o| ObsRow {
            off: o.off,
            number: o.number,
            word: o.word.to_string(),
            why: o.why.to_string(),
        })
        .collect();
    rw.obs = reg_obs.clone();
    for o in &reg_obs {
        let w = rw.img.w(o.off);
        if format!("{w:08x}") != o.word {
            return Err(Fail::new(format!(
                "observation gate original instruction mismatch {:#x}: {w:08x}",
                o.off
            )));
        }
        if !(o.off < rw.text_end && rw.kind_at(o.off).is_none() && !rw.in_window(o.off)) {
            return Err(Fail::new(format!(
                "observation gate conflicts with a rewrite site {:#x}",
                o.off
            )));
        }
        rw.use_area(o.off);
        let st = crate::sites::site_obs(rw, o.off, o.number, w)?;
        rw.put_branch(o.off, st)?;
        rw.stat("obs");
    }

    // ---- Address regions (every module that defines the SDK's VammManager: sdk) ----
    let mut region_obs: Vec<ObsRow> = Vec::new();
    let (r_obs, why_not) = crate::sites::region_gates(rw)?;
    region_obs.extend(r_obs);
    if let Some(w) = why_not {
        rw.say(format!("{name}: no address region gates: {w}"));
    }
    region_obs.extend(crate::sites::stdalloc_gates(rw));
    // Unreal's FMallocBinned3: the gate on each cut constructor call, a nop now; x0 is the object
    if let Some(f) = rw.ue_malloc.as_ref().map(|f| f.calls.clone()) {
        for c in f {
            if !(rw.kind_at(c).is_none() && !rw.in_window(c)) {
                return Err(Fail::new(format!(
                    "FMallocBinned3 gate conflicts with a rewrite site {c:#x}"
                )));
            }
            region_obs.push(ObsRow {
                off: c,
                number: crate::rewriter::OBS_UE_MALLOC,
                word: format!("{:08x}", ibuilder_a64::asm::NOP),
                why: "FMallocBinned3 constructor call (cut): the object in x0; the host puts its allocator's vtable in (hle_uemalloc.c)".into(),
            });
        }
    }
    // Unreal's engine region: the gate on the store of its size, which the callback changes in that register and x1
    if let Some((off, reg, x1)) = rw.ue_region {
        if !(rw.kind_at(off).is_none() && !rw.in_window(off)) {
            return Err(Fail::new(format!(
                "engine region gate conflicts with a rewrite site {off:#x}"
            )));
        }
        region_obs.push(ObsRow {
            off,
            number: crate::rewriter::OBS_UE_REGION | (reg as i64) << 8,
            word: format!("{:08x}", rw.img.w(off)),
            why: format!("Unreal's engine region: its size in x{reg}, stored before nninitStartup reserves it; the host gives what the alias region has room for (hle_svc.c)"),
        });
        if let Some(x1) = x1 {
            if !(rw.kind_at(x1).is_none() && !rw.in_window(x1)) {
                return Err(Fail::new(format!(
                    "engine region size conflicts with a rewrite site {x1:#x}"
                )));
            }
            rw.img.set(x1, 0xAA0003E1 | reg << 16);
        }
    }
    for o in &region_obs {
        rw.use_area(o.off);
        let w = u32::from_str_radix(&o.word, 16).unwrap();
        let st = crate::sites::site_obs(rw, o.off, o.number, w)?;
        rw.put_branch(o.off, st)?;
        rw.stat("obs");
    }
    rw.obs.extend(region_obs);

    // ---- Frame step in whole vsyncs, Stubs ----
    crate::stubs::emit(rw)?;
    if rw.native_fps_blocked {
        rw.say(format!(
            "[RED] {name}: native frame target disabled: a required timing correction did not match"
        ));
    }

    crate::mark("obs/stubs");
    // ---- Spin waits (every module) ----
    crate::spin::run(rw, spin_cand)?;
    crate::mark("spin");
    Ok(())
}
