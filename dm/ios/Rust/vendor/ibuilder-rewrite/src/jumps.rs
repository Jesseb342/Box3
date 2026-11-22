//! The `br x18` forms the shipped `patch_nso.py` still recognises by their instructions: indirect tail calls
//! (`tail_call`) and the byte / halfword table whose add is further back (`jump_bytes_far`). Each looks at one
//! function's decoded instructions (`insl`) around the `br` at index `j`. Offset tables are proved by
//! [`crate::jump_solver`] (the shipped engine replaced the older recognisers `jump_offsets`, `jump_adr_offsets`,
//! `jump_masked_pred`, `jump_guarded_tail`, `jump_guarded_cfg` and `half_count` with `jump_solver.py`).
//!
//! The Python matches Capstone's operand text with `re`; the same patterns are kept (see `ins::full`).

use crate::ins::{full, pyint, writes_reg};
use ibuilder_a64::cs::{self, Ins};
use std::collections::BTreeSet;

type Caps = Vec<Option<String>>;

fn fm(pat: &str, s: &str) -> Option<Caps> {
    full(pat, s)
}
fn g(c: &Caps, i: usize) -> &str {
    c[i].as_deref().unwrap_or("")
}
fn lastops(p: &Ins) -> i64 {
    p.ops.last().map(|o| o.imm).unwrap_or(0)
}
fn imm_of(s: &str) -> i64 {
    pyint(s)
}
fn names_written(p: &Ins) -> BTreeSet<&'static str> {
    match &p.regs {
        Some((_, w)) => w.iter().map(|&r| cs::reg_name(r)).collect(),
        None => BTreeSet::new(),
    }
}
fn num_of(name: &str) -> Option<i64> {
    crate::ins::num(name).map(|x| x as i64)
}

fn tail_call_at_end(insl: &[Ins], j: usize) -> bool {
    if j + 1 != insl.len() {
        return false;
    }
    for p in insl[..j].iter().rev() {
        if !names_written(p).contains("x18") {
            continue;
        }
        return p.mn() == "ldr"
            && fm(r"x18, \[(x\d+|sp)(, #(0x[0-9a-f]+|\d+))?\]", &p.op_str).is_some();
    }
    false
}

fn tail_call_padded(insl: &[Ins], j: usize) -> bool {
    if j + 1 >= insl.len()
        || insl[j + 1..]
            .iter()
            .any(|p| !(p.mn() == "nop" || (p.mn() == "udf" && &*p.op_str == "#0")))
    {
        return false;
    }
    if insl.windows(2).any(|p| p[1].address != p[0].address + 4) {
        return false;
    }
    for p in &insl[..j] {
        if !matches!(
            p.mn(),
            "mov" | "ldr" | "ldrh" | "ldp" | "add" | "str" | "stp"
        ) {
            return false;
        }
        let w = names_written(p);
        if ["sp", "wsp", "fp", "lr", "x29", "w29", "x30", "w30"]
            .iter()
            .any(|n| w.contains(n))
        {
            return false;
        }
    }
    for p in insl[..j].iter().rev() {
        let w = names_written(p);
        if !(w.contains("x18") || w.contains("w18")) {
            continue;
        }
        return matches!(p.mn(), "ldr" | "ldp")
            && fm(
                r"x18, (x\d+, )?\[(x\d+|sp)(, #(0x[0-9a-f]+|\d+))?\]",
                &p.op_str,
            )
            .is_some();
    }
    false
}

/// After terminal or padded unframed tails, a `br x18` with other code after it is a tail call only when the frame is
/// provably gone (see `tail_call` in patch_nso.py).
pub fn tail_call(insl: &[Ins], j: usize) -> bool {
    if j + 1 == insl.len() {
        return tail_call_at_end(insl, j);
    }
    if tail_call_padded(insl, j) {
        return true;
    }
    if j < 4 || insl.windows(2).any(|p| p[1].address != p[0].address + 4) {
        return false;
    }
    let cond =
        |p: &Ins| matches!(p.mn(), "cbz" | "cbnz" | "tbz" | "tbnz") || p.mn().starts_with("b.");
    // the last write of x18 is a plain pointer load
    let load = (0..j).rev().find(|&k| {
        let w = names_written(&insl[k]);
        w.contains("x18") || w.contains("w18")
    });
    let Some(load) = load else { return false };
    if !matches!(insl[load].mn(), "ldr" | "ldp")
        || fm(
            r"x18, (x\d+, )?\[(x\d+|sp)(, #(0x[0-9a-f]+|\d+))?\]",
            &insl[load].op_str,
        )
        .is_none()
    {
        return false;
    }
    // the frame. disp is the saved pair's offset from sp
    let thunk = insl[0].mn() == "stp" && &*insl[0].op_str == "x29, x30, [sp, #-0x10]!";
    let (restore, start, disp, mut saved, mut fp_set);
    if thunk {
        if insl[1].mn() != "mov" || &*insl[1].op_str != "x29, sp" {
            return false;
        }
        if insl[j - 1].mn() != "ldp" || &*insl[j - 1].op_str != "x29, x30, [sp], #0x10" {
            return false;
        }
        (restore, start, disp, saved, fp_set) = (j - 1, 2usize, 0i64, true, true);
    } else {
        let sub = if insl[0].mn() == "sub" {
            fm(r"sp, sp, #(0x[0-9a-f]+|\d+)", &insl[0].op_str)
        } else {
            None
        };
        let add = if insl[j - 1].mn() == "add" {
            fm(r"sp, sp, #(0x[0-9a-f]+|\d+)", &insl[j - 1].op_str)
        } else {
            None
        };
        let (Some(sub), Some(add)) = (sub, add) else {
            return false;
        };
        if imm_of(g(&sub, 1)) != imm_of(g(&add, 1)) {
            return false;
        }
        let r = (1..=j.saturating_sub(2)).rev().find(|&k| {
            insl[k].mn() == "ldp"
                && fm(r"x29, x30, \[sp(, #(0x[0-9a-f]+|\d+))?\]", &insl[k].op_str).is_some()
        });
        let Some(r) = r else { return false };
        restore = r;
        disp = insl[restore].ops.last().map(|o| o.disp as i64).unwrap_or(0);
        if disp < 0 || disp + 16 > imm_of(g(&sub, 1)) {
            return false;
        }
        (start, saved, fp_set) = (1usize, false, false);
    }
    let tail = restore.min(load); // no call or jump from here on
    let after_br = insl[j].address;
    let mut setup_end = insl[start].address; // no branch re-enters the frame's setup
    let mut targets: Vec<i64> = Vec::new();
    let mut guarded = false;
    for k in start..j - 1 {
        // the body and the epilogue; j - 1 is the frame's last restore or add sp
        let p = &insl[k];
        if k == restore {
            continue;
        }
        if cond(p) || p.mn() == "b" {
            let t = lastops(p);
            if !saved || k >= restore || (p.mn() == "b" && k >= tail) {
                return false;
            }
            if t > after_br {
                guarded = true;
            } else if thunk {
                return false;
            }
            targets.push(t);
            continue;
        }
        if matches!(p.mn(), "bl" | "blr") {
            // a saved x30, and x18 not live across the call
            if thunk || !saved || k >= tail {
                return false;
            }
            continue;
        }
        if matches!(
            p.mn(),
            "br" | "ret"
                | "udf"
                | "brk"
                | "hlt"
                | "svc"
                | "hvc"
                | "smc"
                | "msr"
                | "sys"
                | "dc"
                | "ic"
        ) {
            return false;
        }
        let w = names_written(p);
        if ["sp", "wsp", "lr", "x30", "w30"]
            .iter()
            .any(|n| w.contains(n))
        {
            return false;
        }
        if ["fp", "x29", "w29"].iter().any(|n| w.contains(n)) {
            let sets_fp = if p.mn() == "mov" {
                &*p.op_str == "x29, sp" && disp == 0
            } else {
                p.mn() == "add"
                    && p.op_str.starts_with("x29, sp, #")
                    && p.ops.get(2).map(|o| o.imm) == Some(disp)
            };
            if k > restore || fp_set || !saved || !sets_fp {
                return false;
            }
            fp_set = true;
            setup_end = insl[k + 1].address;
            continue;
        }
        if !saved && p.mn() == "stp" && *p.op_str == *insl[restore].op_str {
            saved = true;
            setup_end = insl[k + 1].address;
            continue;
        }
        if !p.op_str.contains('[')
            || p.mn().starts_with("ldr")
            || p.mn().starts_with("ldur")
            || p.mn().starts_with("ldp")
            || p.mn().starts_with("ldar")
            || p.mn().starts_with("prfm")
        {
            continue;
        }
        // regs_access does not report memory writes, so a stack store's bytes are checked against the saved pair
        if k > restore
            || !matches!(
                p.mn(),
                "str" | "strb" | "strh" | "stur" | "sturb" | "sturh" | "stp"
            )
            || p.writeback
        {
            return false;
        }
        let mem = p.ops.last().unwrap();
        let basen = cs::reg_name(mem.base);
        if !matches!(basen, "sp" | "fp" | "x29") {
            if thunk {
                return false;
            }
            continue;
        }
        if mem.index != 0 || (basen != "sp" && !fp_set) {
            return false;
        }
        let at = mem.disp as i64 + if basen != "sp" { disp } else { 0 };
        let mut size: i64 = match p.mn().chars().last() {
            Some('b') => 1,
            Some('h') => 2,
            _ => match cs::reg_name(p.ops[0].reg).chars().next() {
                Some('x') => 8,
                Some('w') => 4,
                Some('q') => 16,
                Some('d') => 8,
                Some('s') => 4,
                Some('h') => 2,
                Some('b') => 1,
                _ => 8,
            },
        };
        if p.mn() == "stp" {
            size *= 2;
        }
        if at < 0 || (at < disp + 16 && at + size > disp) {
            return false;
        }
    }
    if !saved {
        return false;
    }
    // what follows the br never comes back to a place whose stack it cannot vouch for
    let suffix = &insl[j + 1..];
    let mut leaves = false;
    for p in suffix {
        if p.mn() == "bl" {
            let t = lastops(p);
            if insl[0].address <= t && t <= insl.last().unwrap().address {
                return false;
            }
            leaves = true;
        } else if (cond(p) || p.mn() == "b") && lastops(p) <= after_br {
            return false;
        }
    }
    if thunk
        && (!guarded
            || !leaves
            || !matches!(suffix.last().unwrap().mn(), "bl" | "udf" | "b")
            || suffix
                .iter()
                .any(|p| matches!(p.mn(), "ret" | "br" | "blr")))
    {
        return false;
    }
    // nothing re-enters the frame's setup, or lands past the restore: the frame's end is what the proof rests on
    !targets
        .iter()
        .any(|&t| t < setup_end || (insl[restore].address < t && t <= after_br))
}

/// The byte / halfword table form with its add further back (Octopath Traveler 0 main+0x37f9bc8: adr x18,#L; ldrb
/// w0,[x17,x15]; add x18,x18,x0,lsl #2, then 17 register moves before br x18). Up to 32 instructions back, and x18 must
/// not change between the add and the br. Returns (base, width) or None; `half(base)`: the pads a halfword table needs
/// (`half_pads`, from the jump solver: Err is an exception of the solver that stops the module)
pub fn jump_bytes_far(
    insl: &[Ins],
    j: usize,
    half: &mut dyn FnMut(i64) -> Result<Option<i64>, crate::Fail>,
) -> Result<Option<(i64, i64)>, crate::Fail> {
    let b0 = j.saturating_sub(32);
    let ctx = &insl[b0..j];
    let mut found: Option<usize> = None;
    for k in (0..ctx.len()).rev() {
        let p = &ctx[k];
        if p.mn() == "add" && p.op_str.starts_with("x18, x18,") && p.op_str.contains("lsl #2") {
            found = Some(k);
            break;
        }
        if writes_reg(p, "x18") {
            return Ok(None);
        }
    }
    let Some(k) = found else { return Ok(None) };
    let p = &ctx[k];
    let rnm = cs::reg_name(p.ops[2].reg);
    let idx: Option<i64> = match rnm {
        "lr" => Some(30),
        "fp" => Some(29),
        r => num_of(r),
    };
    let Some(base) = ctx[..k]
        .iter()
        .rev()
        .find(|q| q.mn() == "adr" && q.op_str.starts_with("x18,"))
        .map(|q| q.ops[1].imm)
    else {
        return Ok(None);
    };
    let Some(ld) = ctx[..k].iter().rev().find(|q| {
        matches!(q.mn(), "ldrb" | "ldrsb" | "ldrh" | "ldrsh")
            && num_of(cs::reg_name(q.ops[0].reg)) == idx
    }) else {
        return Ok(None);
    };
    if matches!(ld.mn(), "ldrb" | "ldrsb") {
        Ok(Some((base, 256)))
    } else {
        // `half(base) or 65536`
        Ok(Some((
            base,
            half(base)?.filter(|&x| x != 0).unwrap_or(65536),
        )))
    }
}
