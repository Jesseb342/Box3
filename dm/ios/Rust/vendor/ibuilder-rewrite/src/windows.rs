//! Exclusive windows (`ldxr ... stxr` sequences that use x18): finding them, checking their branches, and the patch
//! copies `site_window` / `site_retry_window` (`patch_nso.py` "Exclusive windows").

use crate::ins::{
    dis, has18, is_cond_branch_or_b, last_imm, num, op_reg_name, pick, regs_in, subst,
};
use crate::rewriter::{KEY_K18, Rw};
use crate::{Fail, Res};
use ibuilder_a64::asm::{self, NOP};
use ibuilder_a64::cs::Ins;
use std::collections::{HashMap, HashSet};

pub const EXCL_LD: [&str; 8] = [
    "ldxr", "ldaxr", "ldxp", "ldaxp", "ldxrb", "ldaxrb", "ldxrh", "ldaxrh",
];
pub const EXCL_ST: [&str; 8] = [
    "stxr", "stlxr", "stxp", "stlxp", "stxrb", "stlxrb", "stxrh", "stlxrh",
];

pub fn is_ld(m: &str) -> bool {
    EXCL_LD.contains(&m)
}
pub fn is_st(m: &str) -> bool {
    EXCL_ST.contains(&m)
}

/// the exclusive windows of a function: an exclusive load to the next exclusive store within 16 instructions that
/// names x18 somewhere
pub fn find_windows(insl: &[Ins]) -> Vec<Vec<Ins>> {
    let mut out = Vec::new();
    for i in 0..insl.len() {
        if !is_ld(insl[i].mn()) {
            continue;
        }
        let mut j = i;
        while j < insl.len() && !is_st(insl[j].mn()) {
            j += 1;
        }
        if j >= insl.len() || j - i >= 16 {
            continue;
        }
        // Another exclusive load before the store: this one has no store of its own (a retry block)
        if insl[i + 1..j].iter().any(|x| is_ld(x.mn())) {
            continue;
        }
        if j + 1 < insl.len() && matches!(insl[j + 1].mn(), "cbz" | "cbnz") {
            j += 1;
        }
        let seg = &insl[i..=j];
        if seg.iter().any(has18) {
            out.push(seg.to_vec());
        }
    }
    out
}

/// An adrp inside a window, copied to pc: the same page from the copy's address (x18 as its stand-in S)
fn window_adrp(x: &Ins, s: u32, pc: i64) -> Res<u32> {
    let rd = num(op_reg_name(x, 0));
    Ok(asm::adrp(
        if rd == Some(18) {
            s
        } else {
            rd.ok_or_else(|| Fail::new("adrp register"))?
        },
        pc,
        x.ops[1].imm,
    )?)
}

/// For windows with a B, reject exits that carry a reservation through a stub's store.
fn check_window_branches(seg: &[Ins]) -> Res<()> {
    if !seg.iter().any(|x| x.mn() == "b") {
        return Ok(());
    }
    if !seg.windows(2).all(|p| p[1].address == p[0].address + 4) {
        return Err(Fail::new(format!(
            "noncontiguous window {:x}",
            seg[0].address
        )));
    }
    let by_addr: HashMap<i64, &Ins> = seg.iter().map(|x| (x.address, x)).collect();
    let mut pending: Vec<(i64, bool)> = vec![(seg[0].address, false)];
    let mut seen: HashSet<(i64, bool)> = HashSet::new();
    while let Some((addr, mut live)) = pending.pop() {
        let Some(x) = by_addr.get(&addr) else {
            if live {
                // Python's `{addr:x}` of a target before the module's start is `-bfc`, not two's complement
                let a = if addr < 0 {
                    format!("-{:x}", -addr)
                } else {
                    format!("{addr:x}")
                };
                return Err(Fail::new(format!(
                    "branch leaves window with live reservation {a}"
                )));
            }
            continue;
        };
        if !seen.insert((addr, live)) {
            continue;
        }
        let m = x.mn();
        if is_ld(m) {
            live = true;
        } else if is_st(m) || m == "clrex" {
            live = false;
        }
        if m == "b" {
            pending.push((last_imm(x), live));
        } else if matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz") || m.starts_with("b.") {
            pending.push((last_imm(x), live));
            pending.push((addr + 4, live));
        } else {
            pending.push((addr + 4, live));
        }
    }
    Ok(())
}

fn rewrite_branch(w: u32, m: &str, off: i64) -> u32 {
    let off = off as u32;
    if matches!(m, "tbz" | "tbnz") {
        (w & 0xFFF8001F) | ((off & 0x3FFF) << 5)
    } else {
        (w & 0xFF00001F) | ((off & 0x7FFFF) << 5)
    }
}

/// Emit the patch copy of an exclusive window; returns (start, lo, hi)
pub fn site_window(rw: &mut Rw, seg: &[Ins]) -> Res<(i64, i64, i64)> {
    check_window_branches(seg)?;
    let mut used = std::collections::BTreeSet::new();
    for x in seg {
        used.extend(regs_in(x));
    }
    let st = pick(&used, 2)?;
    let (s, t) = (st[0], st[1]);
    let (lo, hi) = (seg[0].address, seg.last().unwrap().address + 4);
    let start = rw.here();
    rw.emit(asm::stp(s, t, 31, -16));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, s, KEY_K18)?;
    rw.emit(asm::ldrx(s, t, 0));
    let copy0 = rw.here();
    let n = seg.len() as i64;
    // Exit stubs: the first stub right after the window must be the fall-through one; targets of branches leaving the window come after it.
    let exits = copy0 + 4 * n + 16;
    let mut ex_targets: Vec<i64> = Vec::new();
    let mut words: Vec<u32> = Vec::new();
    for (k, x) in seg.iter().enumerate() {
        let mut w = x.word;
        if has18(x) {
            w = subst(x, s)?;
        }
        let m = x.mn();
        if is_cond_branch_or_b(m) && m != "bl" {
            let tgt = last_imm(x);
            let newt = if lo <= tgt && tgt < hi {
                copy0 + (tgt - lo)
            } else {
                ex_targets.push(tgt);
                exits + 16 * (ex_targets.len() as i64 - 1)
            };
            let pc = copy0 + 4 * k as i64;
            let off = (newt - pc) >> 2;
            w = if m == "b" {
                asm::b(pc, newt)?
            } else {
                rewrite_branch(w, m, off)
            };
            let dd = dis(w, pc)?;
            if !(last_imm(&dd) == newt && dd.mn() == m) {
                return Err(Fail::new(
                    "assert dd.operands[-1].imm == newt and dd.mnemonic == m",
                ));
            }
        } else if m == "adrp" {
            w = window_adrp(x, s, copy0 + 4 * k as i64)?;
        } else if matches!(m, "adr" | "adrp" | "b" | "bl" | "br" | "blr" | "ret")
            || (m == "ldr" && !x.op_str.contains('['))
        {
            return Err(Fail::new(format!("{:#x}", x.address)));
        }
        words.push(w);
    }
    for w in words {
        rw.emit(w);
    }
    let mut targets = vec![hi];
    targets.extend(&ex_targets); // fall-through first
    for t_ in targets {
        rw.emit(asm::strx(s, t, 0));
        rw.emit(asm::ldp(s, t, 31, -16));
        rw.emit_bx(t_)?;
        rw.emit(NOP);
    }
    Ok((start, lo, hi))
}

/// The branch `insl[k]` lands in the middle of window `wseg`. Accepted only when it ends an out-of-line retry block that
/// re-enters the window at its store-exclusive. Returns (the retry block, the window from that store on), or None
pub fn retry_block(insl: &[Ins], k: usize, wseg: &[Ins]) -> Option<(Vec<Ins>, Vec<Ins>)> {
    let t = last_imm(&insl[k]);
    let tail: Vec<Ins> = wseg.iter().filter(|y| y.address >= t).cloned().collect();
    if tail.is_empty() || !is_st(tail[0].mn()) {
        return None;
    }
    let lo = (k as i64 - 8).max(-1);
    let mut p = k as i64 - 1;
    while p > lo {
        let q = &insl[p as usize];
        if is_ld(q.mn()) {
            return Some((insl[p as usize..=k].to_vec(), tail));
        }
        if matches!(
            q.mn(),
            "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
        ) || q.mn().starts_with("b.")
            || is_st(q.mn())
        {
            return None;
        }
        p -= 1;
    }
    None
}

/// A retry block gets a patch copy of its own: parts = [(retry block, its fall-through), (window from the store on, the
/// window's fall-through)] are copied one after the other under one prologue, each followed by its fall-through stub
pub fn site_retry_window(rw: &mut Rw, parts: &[(Vec<Ins>, i64)]) -> Res<i64> {
    let mut used = std::collections::BTreeSet::new();
    for (seg, _) in parts {
        for x in seg {
            used.extend(regs_in(x));
        }
    }
    let st = pick(&used, 2)?;
    let (s, t) = (st[0], st[1]);
    let start = rw.here();
    rw.emit(asm::stp(s, t, 31, -16));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, s, KEY_K18)?;
    rw.emit(asm::ldrx(s, t, 0));
    let mut pos: HashMap<i64, i64> = HashMap::new();
    let mut at = rw.here();
    for (seg, _) in parts {
        for x in seg {
            pos.insert(x.address, at);
            at += 4;
        }
        at += 16;
    }
    let exits = at;
    let mut ex_targets: Vec<i64> = Vec::new();
    for (seg, ft) in parts {
        for x in seg {
            let mut w = x.word;
            if has18(x) {
                w = subst(x, s)?;
            }
            let (m, pc) = (x.mn(), rw.here());
            if matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz") || m.starts_with("b.") {
                let tgt = last_imm(x);
                if !pos.contains_key(&tgt) && !ex_targets.contains(&tgt) {
                    ex_targets.push(tgt);
                }
                let newt = match pos.get(&tgt) {
                    Some(&p) => p,
                    None => exits + 16 * ex_targets.iter().position(|&e| e == tgt).unwrap() as i64,
                };
                let off = (newt - pc) >> 2;
                w = rewrite_branch(w, m, off);
                let dd = dis(w, pc)?;
                if !(last_imm(&dd) == newt && dd.mn() == m) {
                    return Err(Fail::new(
                        "assert dd.operands[-1].imm == newt and dd.mnemonic == m",
                    ));
                }
            } else if m == "adrp" {
                w = window_adrp(x, s, pc)?;
            } else if matches!(m, "adr" | "adrp" | "b" | "bl" | "br" | "blr" | "ret")
                || (m == "ldr" && !x.op_str.contains('['))
            {
                return Err(Fail::new(format!("{:#x}", x.address)));
            }
            rw.emit(w);
        }
        rw.emit(asm::strx(s, t, 0));
        rw.emit(asm::ldp(s, t, 31, -16));
        rw.emit_bx(*ft)?;
        rw.emit(NOP);
    }
    for tg in ex_targets {
        rw.emit(asm::strx(s, t, 0));
        rw.emit(asm::ldp(s, t, 31, -16));
        rw.emit_bx(tg)?;
        rw.emit(NOP);
    }
    Ok(start)
}
