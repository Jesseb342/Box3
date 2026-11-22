//! Unreal Engine 4 / 5's engine address region in main, found by the engine's own code, without a build ID
//! (`ue_region.py`): an observation gate goes on the store of the region's size right before nninitStartup reserves it.
//!
//! The chain, each link unique or nothing is gated: the option's name "SwitchVirtualAddressSpaceSize" in ro;
//! nninitStartup, the defined symbol; in that function, the one bl to the PLT stub of
//! nn::os::AllocateAddressRegion(uintptr_t *, size_t) whose straight-line code sets x0 to the region's base variable
//! and stores the size in the word after it.

use super::{find, text, word};
use crate::fde::defined;
use ibuilder_a64::bits::rd32;
use ibuilder_a64::cs::{self, Ins, OP_IMM, OP_MEM, OP_REG, reg_name};
use std::collections::{BTreeSet, HashMap};

const OPTION: &[u8] = b"SwitchVirtualAddressSpaceSize";
const ALLOCATE: &str = "_ZN2nn2os21AllocateAddressRegionEPmm";

#[derive(Clone, Copy, PartialEq, Debug)]
enum V {
    C(u64),
    Page,
    Lo(i64),
}

fn is_branch(i: &Ins) -> bool {
    matches!(
        i.mn(),
        "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || i.mn().starts_with("b.")
}

/// (offset of the size store, its register S, the offset of a later instruction that sets x1 to the same constant, or
/// None) for the bl at `call`, or a reason it is not the engine region's reservation
fn size_store(
    img: &[u8],
    call: i64,
    start: i64,
) -> Result<(i64, Option<u32>, Option<i64>), String> {
    let mut a = call;
    while a - 4 >= start && a - call > -64 {
        let Some(i) = cs::decode(rd32(img, (a - 4) as usize), a - 4) else {
            return Err("StopIteration: undecodable word before the call".into());
        };
        if is_branch(&i) {
            break;
        }
        a -= 4;
    }
    // vals: register -> value; last: register -> where it was last written
    let mut vals: HashMap<String, V> = HashMap::new();
    let mut last: HashMap<String, i64> = HashMap::new();
    // (address, register number or None for xzr, displacement, value held by the stored register)
    let mut stores: Vec<(i64, Option<u32>, i64, Option<V>)> = Vec::new();
    for ins in cs::disasm(&img[a as usize..call as usize], a) {
        let ops = &ins.ops;
        let m = ins.mn();
        let reg = |o: &cs::Op| reg_name(o.reg);
        if m == "str"
            && ops.len() >= 2
            && reg(&ops[0]).starts_with('x')
            && ops[1].ty == OP_MEM
            && !ins.writeback
            && ops[1].index == 0
        {
            let r0 = reg(&ops[0]);
            let n = if r0 != "xzr" {
                Some(r0[1..].parse::<u32>().unwrap_or(0))
            } else {
                None
            };
            stores.push((ins.address, n, ops[1].disp as i64, vals.get(r0).copied()));
            continue;
        }
        let d = if !ops.is_empty() && ops[0].ty == OP_REG {
            reg(&ops[0])
        } else {
            ""
        };
        let mut v: Option<V> = None; // the value the instruction gives d, read before its writes clear what it reads
        if !d.starts_with('x') {
        } else if m == "mov" && ops[1].ty == OP_IMM {
            v = Some(V::C(ops[1].imm as u64));
        } else if m == "mov" && ops[1].ty == OP_REG {
            v = vals.get(reg(&ops[1])).copied();
        } else if m == "adrp" {
            v = Some(V::Page);
        } else if m == "add"
            && ops.len() == 3
            && ops[2].ty == OP_IMM
            && vals.get(reg(&ops[1])) == Some(&V::Page)
        {
            v = Some(V::Lo(ops[2].imm));
        }
        if let Some((_, w)) = &ins.regs {
            for &x in w {
                // ins.reg_name(w).replace('w', 'x', 1)
                let n = reg_name(x).replacen('w', "x", 1);
                vals.remove(&n);
                last.insert(n, ins.address);
            }
        }
        if let Some(v) = v {
            vals.insert(d.to_string(), v);
        }
    }
    let Some(V::Lo(x0)) = vals.get("x0").copied() else {
        return Err("x0 is no base variable".into());
    };
    stores.retain(|s| s.2 == x0 + 8);
    let Some(&(off, s, _, val)) = stores.last() else {
        return Err("no store of the size beside the base variable".into());
    };
    let Some(s) = s else {
        return Err("the size stored is xzr".into());
    };
    let x1_at = last.get("x1").copied();
    if let Some(x1_at) = x1_at
        && x1_at > off
    {
        // the same constant set again after the store, with S still holding it
        if matches!(val, Some(V::C(_)))
            && vals.get("x1").copied() == val
            && last.get(&format!("x{s}")).copied().unwrap_or(off) <= off
        {
            return Ok((off, Some(s), Some(x1_at)));
        }
        return Err(format!("x1 written after the size store at {off:#x}"));
    }
    if s != 1 && !(matches!(val, Some(V::C(_))) && vals.get("x1").copied() == val) {
        return Err(format!("x1 is not the x{s} stored at {off:#x}"));
    }
    Ok((off, Some(s), None))
}

/// Offsets of the PLT stubs of the import `name`
fn plt_stubs(img: &[u8], text_end: i64, name: &str) -> BTreeSet<i64> {
    fn inner(img: &[u8], text_end: i64, name: &str) -> Option<BTreeSet<i64>> {
        let g32 = |o: usize| {
            img.get(o..o + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        };
        let g64 = |o: usize| {
            img.get(o..o + 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        };
        let m = g32(4)? as usize;
        if img.get(m..m + 4)? != b"MOD0" {
            return Some(BTreeSet::new());
        }
        let dynp = (m as i64 + g32(m + 4)? as i32 as i64) as usize;
        let mut tags: HashMap<i64, u64> = HashMap::new();
        for k in 0..4096usize {
            let t = g64(dynp + 16 * k)? as i64;
            let v = g64(dynp + 16 * k + 8)?;
            if t == 0 {
                break;
            }
            tags.entry(t).or_insert(v);
        }
        if tags.get(&20) != Some(&7) {
            return Some(BTreeSet::new()); // DT_PLTREL: RELA
        }
        let mut slots = BTreeSet::new();
        let (j, sz) = (*tags.get(&23)? as usize, *tags.get(&2)? as usize);
        let mut r = j;
        while r < j + sz {
            let slot = g64(r)? as i64;
            let info = g64(r + 8)?;
            r += 24;
            if info & 0xffff_ffff != 1026 {
                continue;
            }
            let n = *tags.get(&5)? as usize
                + g32(*tags.get(&6)? as usize + (info >> 32) as usize * 24)? as usize;
            let e = img.get(n..)?.iter().position(|&c| c == 0)?;
            if &img[n..n + e] == name.as_bytes() {
                slots.insert(slot);
            }
        }
        let mut out = BTreeSet::new();
        let needle = 0xD61F0220u32.to_le_bytes();
        let mut a: i64 = -1;
        while !slots.is_empty() {
            let Some(p) = find(img, &needle, a + 1, text_end) else {
                break;
            };
            a = p as i64;
            if a % 4 != 0 || a < 12 {
                continue;
            }
            let (p, l, d) = (
                rd32(img, a as usize - 12),
                rd32(img, a as usize - 8),
                rd32(img, a as usize - 4),
            );
            if p & 0x9F00001F != 0x90000010
                || l & 0xFFC003FF != 0xF9400211
                || d & 0xFFC003FF != 0x91000210
            {
                continue;
            }
            let mut page = ((((p >> 5) & 0x7FFFF) << 2 | ((p >> 29) & 3)) as i64) << 12;
            if page & (1 << 32) != 0 {
                page -= 1 << 33;
            }
            let lo = (((l >> 10) & 0xFFF) * 8) as i64;
            if ((d >> 10) & 0xFFF) as i64 == lo
                && (((a - 12) & !0xFFF) + page + lo) != 0
                && slots.contains(&(((a - 12) & !0xFFF) + page + lo))
            {
                out.insert(a - 12);
            }
        }
        Some(out)
    }
    inner(img, text_end, name).unwrap_or_default()
}

/// (gate site, size register, the instruction to make `mov x1, xS` or None, reason)
pub type Region = (Option<i64>, Option<u32>, Option<i64>, String);

/// One candidate: (gate site, size register, store, a count, a size).
type RegionHit = (i64, i64, i64, u32, Option<i64>);

pub fn find_region(img: &[u8], text_end: i64, ro_off: i64, data_off: i64) -> Region {
    if find(img, OPTION, ro_off, data_off).is_none() {
        return (None, None, None, "no engine region option".into());
    }
    let syms = defined(img);
    let Some(&sym) = syms.get("nninitStartup") else {
        return (
            None,
            None,
            None,
            "[RED] Unreal's engine region option but no nninitStartup symbol".into(),
        );
    };
    let stubs = plt_stubs(img, text_end, ALLOCATE);
    if stubs.is_empty() {
        return (
            None,
            None,
            None,
            "[RED] Unreal's engine region option but no nn::os::AllocateAddressRegion import"
                .into(),
        );
    }
    let w = |a: i64| word(img, a);
    let target = |a: i64| a + ((((w(a) & 0x3FFFFFF) ^ 0x2000000) as i64) - 0x2000000) * 4;
    // function starts: the targets of every bl and the defined symbols; a function here runs from its start to the next
    let mut starts: BTreeSet<i64> = syms
        .values()
        .filter(|&&(o, n)| n != 0 && o < text_end)
        .map(|&(o, _)| o)
        .collect();
    let t = text(img, text_end);
    let mut a = 0usize;
    while a + 4 <= t.len() {
        if matches!(t[a + 3], 0x94..=0x97) && w(a as i64) >> 26 == 0x25 {
            starts.insert(target(a as i64));
        }
        a += 4;
    }
    let starts: Vec<i64> = starts.into_iter().collect();
    let end = |a: i64| -> i64 {
        let i = starts.partition_point(|&x| x <= a);
        if i < starts.len() {
            starts[i]
        } else {
            text_end
        }
    };
    let entry = sym.0;
    // nninitStartup is a b to the engine's function or calls it first
    let fns: Vec<i64> = if w(entry) >> 26 == 0x05 {
        vec![target(entry)]
    } else {
        let mut v = vec![entry];
        let mut a = entry;
        while a < entry + sym.1 {
            if w(a) >> 26 == 0x25 {
                v.push(target(a));
            }
            a += 4;
        }
        v
    };
    let (mut found, mut why): (Vec<RegionHit>, Vec<String>) = (Vec::new(), Vec::new());
    for &start in &fns {
        let mut p = start;
        let e = end(start);
        while p < e {
            if w(p) >> 26 == 0x25 && stubs.contains(&target(p)) {
                match size_store(img, p, start) {
                    Ok((off, s, x1)) => found.push((p, start, off, s.unwrap(), x1)),
                    Err(no) => why.push(format!("{p:#x}: {no}")),
                }
            }
            p += 4;
        }
    }
    if found.len() != 1 {
        let fl: Vec<String> = fns.iter().map(|f| format!("{f:#x}")).collect();
        let extra: String = why.iter().map(|x| format!("; {x}")).collect();
        return (
            None,
            None,
            None,
            format!(
                "[RED] Unreal's engine region: {} reservations in nninitStartup ({}){extra}",
                found.len(),
                fl.join(", ")
            ),
        );
    }
    let (call, start, off, s, x1_mov) = found[0];
    let mut msg = format!(
        "Unreal's engine region: reserved at {call:#x} in nninitStartup's {start:#x}, its size stored from x{s} at {off:#x}"
    );
    if let Some(x) = x1_mov {
        msg.push_str(&format!(", x1 set from it at {x:#x}"));
    }
    (Some(off), Some(s), x1_mov, msg)
}
