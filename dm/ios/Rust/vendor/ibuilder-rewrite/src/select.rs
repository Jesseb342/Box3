//! Conditional selects with a guest x18 source (`select_x18`, `select_scratch`, `site_select` of `patch_nso.py`, engine patch 0409, upstream nxnative 0b5fd602, refs #2623):
//! a `csel` that selects between x18 and another register no longer spills two registers over the guest stack (which corrupted live data below sp: Super Mario 3D All-Stars:
//! Super Mario Sunshine's PCM). Only the arm that selects x18 needs the key page; there the destination's old value is dead, so the destination and one dead
//! caller-saved temporary (x9..x17) load K18 without touching the stack. The temporary must be proven dead by a bounded search of the unwind function: when it cannot be,
//! the select keeps the old path (`site_plain`).

use crate::ins::{last_imm, num, regs_in, regset};
use crate::rewriter::{KEY_K18, Rw};
use crate::{Fail, Res};
use ibuilder_a64::asm::{self, NOP};
use ibuilder_a64::cs::Ins;
use std::collections::{BTreeSet, HashMap};

/// what `select_x18` found: (destination, the other source, the condition that selects the other source, 64-bit)
pub type SelectArgs = (u32, u32, u32, bool);

/// A CSEL with one guest x18 source and a normal register destination (`select_x18`)
pub fn select_x18(ins: &Ins) -> Option<SelectArgs> {
    let word = ins.word;
    let (rd, rn, rm, cond) = (
        word & 31,
        (word >> 5) & 31,
        (word >> 16) & 31,
        (word >> 12) & 15,
    );
    if word & 0x7FE00C00 != 0x1A800000
        || rd == 18
        || rd == 31
        || (rn == 18) == (rm == 18)
        || cond >= 14
    {
        return None;
    }
    Some((
        rd,
        if rn == 18 { rm } else { rn },
        cond ^ (rn == 18) as u32,
        word >> 31 != 0,
    ))
}

// Only these instructions can carry a proof of a dead register across them. The first operand of a writer is a full xN/wN definition unless the instruction
// also reads it (including as an address register). A wN definition zeros the high half of xN. Stores, compares and NOP can never end a register's lifetime.
fn select_writes(m: &str) -> bool {
    matches!(
        m,
        "adr"
            | "adrp"
            | "add"
            | "adds"
            | "and"
            | "ands"
            | "asr"
            | "bic"
            | "csel"
            | "eor"
            | "ldr"
            | "ldrb"
            | "ldrh"
            | "ldrsb"
            | "ldrsh"
            | "ldrsw"
            | "ldur"
            | "lsl"
            | "lsr"
            | "mov"
            | "movn"
            | "movz"
            | "mul"
            | "orn"
            | "orr"
            | "sbfx"
            | "sub"
            | "subs"
            | "ubfx"
    )
}
fn select_reads(m: &str) -> bool {
    matches!(
        m,
        "cmp" | "cmn" | "tst" | "nop" | "str" | "strb" | "strh" | "stur" | "sturb" | "sturh"
    )
}

/// `re.findall(r'\b[xw]\d+\b', s)` as register numbers
fn named_regs(s: &str) -> Vec<u32> {
    let b = s.as_bytes();
    let w = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if (b[i] == b'x' || b[i] == b'w') && (i == 0 || !w(b[i - 1])) {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 && (j == b.len() || !w(b[j])) {
                out.push(s[i + 1..j].parse::<u32>().unwrap_or(u32::MAX));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

struct Search<'a> {
    by_address: &'a HashMap<i64, &'a Ins>,
    function_end: i64,
    budget: u32,
}

impl Search<'_> {
    /// the registers of `pending` that are overwritten before a read on every path from `pc`, or reach a normal return inside the function
    fn dead_after(&mut self, pc: i64, pending: &BTreeSet<u32>) -> Res<BTreeSet<u32>> {
        if pending.is_empty() || self.budget == 0 || pc >= self.function_end {
            return Ok(BTreeSet::new());
        }
        let Some(&ins) = self.by_address.get(&pc) else {
            return Ok(BTreeSet::new());
        };
        self.budget -= 1;
        let m = ins.mn();
        if m == "ret" && ins.op_str.is_empty() {
            return Ok(pending.clone());
        }
        if m == "b" {
            return self.dead_after(last_imm(ins), pending);
        }
        if m.starts_with("b.") || matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz") {
            let in_ins = regs_in(ins);
            let pending: BTreeSet<u32> = pending.difference(&in_ins).copied().collect();
            let fall = self.dead_after(pc + 4, &pending)?; // both operands of the Python's `&` are evaluated, the fall-through first
            let taken = self.dead_after(last_imm(ins), &pending)?;
            return Ok(fall.intersection(&taken).copied().collect());
        }
        if !select_writes(m) && !select_reads(m) {
            return Ok(BTreeSet::new());
        }
        let mut dead = BTreeSet::new();
        if select_writes(m) && !ins.writeback {
            let (dst, sources) = match ins.op_str.split_once(',') {
                Some((d, s)) => (d, s),
                None => (&*ins.op_str, ""),
            };
            if let Some(dst_n) = num(dst).filter(|d| pending.contains(d)) {
                // the Python's `regset(ins)` raises when Capstone cannot list the registers of the instruction
                if ins.regs.is_none() {
                    return Err(Fail::new(format!(
                        "capstone: regs_access failed for {} {}",
                        m, ins.op_str
                    )));
                }
                let (reads, _) = regset(ins);
                if !(reads.iter().any(|n| num(n) == Some(dst_n))
                    || named_regs(sources).contains(&dst_n))
                {
                    dead.insert(dst_n);
                }
            }
        }
        let in_ins = regs_in(ins);
        let rest_pending: BTreeSet<u32> = pending.difference(&in_ins).copied().collect();
        dead.extend(self.dead_after(pc + 4, &rest_pending)?);
        Ok(dead)
    }
}

/// One dead AAPCS64 temporary for a select, or None. The old value must be overwritten before a read on every path, or reach a normal return inside the same unwind
/// function. Keep x0-x8, callee-saved registers and LR out of the search. Calls, unknown instructions, outgoing branches and an exhausted search budget give no proof.
pub fn select_scratch(
    at: i64,
    by_address: &HashMap<i64, &Ins>,
    function_end: i64,
    rd: u32,
) -> Res<Option<u32>> {
    let mut s = Search {
        by_address,
        function_end,
        budget: 64,
    };
    let pending: BTreeSet<u32> = (9..18).filter(|&r| r != rd).collect();
    Ok(s.dead_after(at + 4, &pending)?.into_iter().next())
}

/// Split CSEL on its original flags. Only the arm selecting x18 needs the key page. In that arm the destination's old value is dead, so the destination and one dead
/// temporary can load K18 without touching the guest stack.
pub fn site_select(rw: &mut Rw, ins: &Ins, args: SelectArgs, temp: u32) -> Res<i64> {
    let (rd, other, other_cond, wide) = args;
    let (start, skip) = (rw.here(), rw.patch_len());
    rw.emit(NOP); // filled with the conditional branch once the other arm's address is known
    rw.emit(asm::mrs_tpidrro(temp));
    rw.emit_slot_addr(temp, rd, KEY_K18)?;
    rw.emit(if wide {
        asm::ldrx(rd, temp, 0)
    } else {
        0xB9400000 | (temp << 5) | rd
    }); // ldr wD,[xT] zero-extends the result
    rw.emit_bx(ins.address + 4)?;
    let w = asm::beq(start, rw.here())? | other_cond;
    let p = if rw.in_back {
        &mut rw.patch_back
    } else {
        &mut rw.patch_front
    };
    p[skip..skip + 4].copy_from_slice(&w.to_le_bytes());
    if !wide || rd != other {
        let mv = asm::movx(rd, other);
        rw.emit(if wide { mv } else { mv & 0x7FFFFFFF });
    }
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}
