//! Rewrite blocks of each kind (`site_*` of `patch_nso.py`): what is emitted into the patch area for an x18 access, a
//! system register access, an svc or timer read, an observation gate, and so on. Each returns the address of its block.

use crate::ins::{dis, has18, last_imm, pick, regs_in, sp_delta, subst};
use crate::rewriter::{Gate, KEY_K18, KEY_KTLS, ObsRow, Rw};
use crate::{Fail, Res};
use ibuilder_a64::asm::{self, NOP};
use ibuilder_a64::cs::Ins;

/// the dispatch of the x18 sites in `patch_nso.py` (lines 1714-1724): the block's start and the name of its stat
pub fn x18_site(rw: &mut Rw, ins: &Ins) -> Res<(i64, &'static str)> {
    let a = ins.address;
    let m = ins.mn();
    if m == "br" && rw.tailcalls.contains(&a) {
        return Ok((site_br_call(rw)?, "br_call"));
    }
    if m == "br" {
        let st = if let Some(t) = rw.tabjumps.get(a).cloned() {
            site_br_tab(rw, &t)?
        } else if let Some(&(base, count)) = rw.jumps.get(a) {
            site_br(rw, base, count)?
        } else {
            return Err(Fail::new(format!(
                "unresolved br x18 dispatch: module={} build_id={} address={:#x} (decimal {}) word={:#010x} operands={}; analyzed_offset_tables={} analyzed_target_tables={} recognized_tail_calls={}. The branch target table was not proven, so this module was not rewritten.",
                rw.name,
                rw.build_id,
                a,
                a,
                ins.word,
                ins.op_str,
                rw.jumps.items.len(),
                rw.tabjumps.items.len(),
                rw.tailcalls.len()
            )));
        };
        return Ok((st, "br"));
    }
    if matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz") {
        return Ok((site_cond(rw, ins)?, "cond"));
    }
    if matches!(m, "adr" | "adrp") {
        return Ok((site_pcrel(rw, ins)?, "pcrel"));
    }
    if m == "blr" {
        return Ok((site_blr(rw, ins)?, "blr"));
    }
    if ins.op_str.starts_with("sp,") || ins.op_str.starts_with("wsp,") {
        return Ok((site_sp(rw, ins)?, "sp"));
    }
    if casp_pair18(ins) {
        return Ok((site_casp(rw, ins)?, "casp"));
    }
    if let Some(&(args, temp)) = rw.selects.get(&a) {
        return Ok((crate::select::site_select(rw, ins, args, temp)?, "select"));
    }
    if matches!(m, "ret" | "b" | "bl") || (m == "ldr" && !ins.op_str.contains('[')) {
        return Err(Fail::new(format!("{a:x} {m} {}", ins.op_str)));
    }
    Ok((site_plain(rw, ins)?, "plain"))
}

pub fn site_plain(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let st = pick(&regs_in(ins), 2)?;
    let (s, t) = (st[0], st[1]);
    let dlt = sp_delta(ins)?; // instructions that modify sp write below sp, so the scratch save is placed deep in the reserved area
    let save: i64 = if dlt == 0 { -16 } else { -112 };
    if !(dlt == 0 || dlt >= -96) {
        return Err(Fail::new(format!("sp delta {dlt} at {:x}", ins.address)));
    }
    let start = rw.here();
    rw.emit(asm::stp(s, t, 31, save));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, s, KEY_K18)?;
    rw.emit(asm::ldrx(s, t, 0));
    let w = subst(ins, s)?;
    rw.emit(w);
    rw.emit(asm::strx(s, t, 0)); // always write back: capstone can miss reporting a write (the adds w18 instance)
    rw.emit(asm::ldp(s, t, 31, save - dlt));
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

/// Destination is sp and a source is x18 (Engage's alloca: mov x18, sp; sub x18, x18, x0; mov sp, x18).
pub fn site_sp(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let st = pick(&regs_in(ins), 2)?;
    let (s, t) = (st[0], st[1]);
    let start = rw.here();
    rw.emit(asm::stp(s, t, 31, -16));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, s, KEY_K18)?;
    rw.emit(asm::ldrx(s, t, 0));
    rw.emit(asm::addi(t, 31, 0, 0)); // mov T, sp (in add immediate, 31 is sp)
    let w = subst(ins, s)?;
    rw.emit(w);
    rw.emit(asm::ldp(s, t, t, -16));
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

/// Whether ins is a compare and swap of a register pair (casp, caspa, caspl, caspal; x or w) whose compare pair (Rs) or
/// new-value pair (Rt) is x18, x19
pub fn casp_pair18(ins: &Ins) -> bool {
    let w = ins.word;
    w & 0xBFA07C00 == 0x08207C00 && [(w >> 16) & 31, w & 31].contains(&18)
}

pub fn site_casp(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let w = ins.word;
    let (rs, rn, rt) = ((w >> 16) & 31, (w >> 5) & 31, w & 31);
    if rn == 18 {
        return Err(Fail::new(format!(
            "casp with x18 as its base and in a pair {:x} {}",
            ins.address, ins.op_str
        )));
    }
    let mut used = regs_in(ins);
    used.insert(18);
    used.insert(19);
    let p = (0..16u32)
        .step_by(2)
        .find(|r| !used.contains(r) && !used.contains(&(r + 1)))
        .ok_or_else(|| Fail::new("StopIteration"))?;
    let mut avoid = used.clone();
    avoid.insert(p);
    avoid.insert(p + 1);
    let t = (0..16u32)
        .find(|r| !avoid.contains(r))
        .ok_or_else(|| Fail::new("StopIteration"))?;
    let mut nw = w;
    if rs == 18 {
        nw = (nw & !(31 << 16)) | (p << 16);
    }
    if rt == 18 {
        nw = (nw & !31) | p;
    }
    // want = re.sub(r'\b([xw])(18|19)\b', ...)
    let b = ins.op_str.as_bytes();
    let wc = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut want = String::new();
    let mut i = 0;
    while i < b.len() {
        if (b[i] == b'x' || b[i] == b'w')
            && i + 2 < b.len()
            && b[i + 1] == b'1'
            && (b[i + 2] == b'8' || b[i + 2] == b'9')
            && (i == 0 || !wc(b[i - 1]))
            && (i + 3 == b.len() || !wc(b[i + 3]))
        {
            want.push(b[i] as char);
            want.push_str(&(p + (b[i + 2] == b'9') as u32).to_string());
            i += 3;
        } else {
            want.push(b[i] as char);
            i += 1;
        }
    }
    let dd = dis(nw, ins.address)?;
    if !(dd.mnemonic == ins.mnemonic && *dd.op_str == *want) {
        return Err(Fail::new(format!(
            "casp subst fail {:x} {} {}: {} {}",
            ins.address, ins.mnemonic, ins.op_str, dd.mnemonic, dd.op_str
        )));
    }
    let start = rw.here();
    rw.emit(asm::stp(p, p + 1, 31, -16));
    rw.emit(asm::stur(t, 31, -24));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, p, KEY_K18)?;
    rw.emit(asm::ldrx(p, t, 0));
    rw.emit(asm::movx(p + 1, 19));
    rw.emit(nw);
    if rs == 18 {
        rw.emit(asm::strx(p, t, 0));
        rw.emit(asm::movx(19, p + 1));
    }
    rw.emit(asm::ldur(t, 31, -24));
    rw.emit(asm::ldp(p, p + 1, 31, -16));
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

/// `sub sp, sp, xN` (no shift): the register is rounded up to 16 first, which the add then gives back too.
pub fn site_sp_align(rw: &mut Rw, ins: &Ins, n: u32) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::addi(n, n, 15, 0));
    rw.emit(0x927CEC00 | n << 5 | n); // add xN, xN, #15; and xN, xN, #~15
    rw.emit(ins.word);
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

pub fn site_cond(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let w = ins.word;
    let st = pick(&regs_in(ins), 2)?;
    let (s, t) = (st[0], st[1]);
    let tgt = last_imm(ins);
    let start = rw.here();
    rw.emit(asm::stp(s, t, 31, -16));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, s, KEY_K18)?;
    rw.emit(asm::ldrx(s, t, 0));
    let m = ins.mn();
    let taken = rw.here() + 4 * 3;
    let off = ((taken - rw.here()) >> 2) as u32;
    let nw = if matches!(m, "cbz" | "cbnz") {
        (w & 0xFF000000) | ((off & 0x7FFFF) << 5) | s
    } else {
        (w & 0xFFF80000) | ((off & 0x3FFF) << 5) | s
    };
    let pc = rw.here();
    rw.emit(nw);
    let dd = dis(nw, pc)?;
    if !(dd.mn() == m && last_imm(&dd) == taken) {
        return Err(Fail::new(
            "assert dd.mnemonic == m and dd.operands[-1].imm == taken",
        ));
    }
    rw.emit(asm::ldp(s, t, 31, -16));
    rw.emit_bx(ins.address + 4)?;
    if rw.here() != taken {
        return Err(Fail::new("assert here() == taken"));
    }
    rw.emit(asm::ldp(s, t, 31, -16));
    rw.emit_bx(tgt)?;
    Ok(start)
}

pub fn site_pcrel(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let tgt = ins.ops[1].imm;
    let st = pick(&Default::default(), 2)?;
    let (s, t) = (st[0], st[1]);
    let start = rw.here();
    rw.emit(asm::stp(s, t, 31, -16));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, s, KEY_K18)?; // S first serves as a temporary for the key page offset; the next instruction then loads the target value
    let pc = rw.here();
    let w = asm::adrp(s, pc, tgt)?;
    rw.emit(w);
    if ins.mn() == "adr" {
        rw.emit(asm::addi(s, s, (tgt & 0xFFF) as u32, 0));
    }
    rw.emit(asm::strx(s, t, 0));
    rw.emit(asm::ldp(s, t, 31, -16));
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

/// Jump table `br x18`: target = base + 4i. Stash x16 in the red zone, equally spaced landing pads, restore x16,
/// original target.
pub fn site_br(rw: &mut Rw, base: i64, count: i64) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::stur(16, 31, -16));
    rw.emit(asm::stur(17, 31, -24));
    rw.emit(asm::mrs_tpidrro(16));
    rw.emit_slot_addr(16, 17, KEY_K18)?;
    rw.emit(asm::ldrx(16, 16, 0));
    rw.emit(asm::ldur(17, 31, -24));
    let padbase = start + 4 * 24;
    let delta = padbase - base;
    let dl = delta.abs();
    let mut ops: Vec<u32> = Vec::new();
    let (mut hi, lo) = (dl >> 12, dl & 0xFFF);
    while hi != 0 {
        let h = hi.min(0xFFF);
        ops.push(if delta >= 0 {
            asm::addi(16, 16, h as u32, 1)
        } else {
            asm::subi(16, 16, h as u32, 1)
        });
        hi -= h;
    }
    if lo != 0 {
        ops.push(if delta >= 0 {
            asm::addi(16, 16, lo as u32, 0)
        } else {
            asm::subi(16, 16, lo as u32, 0)
        });
    }
    if ops.len() > 12 {
        return Err(Fail::new("assert len(ops) <= 12"));
    }
    for o in ops {
        rw.emit(o);
    }
    rw.emit(asm::br(16));
    while rw.here() < padbase {
        rw.emit(NOP);
    }
    let tails = padbase + 4 * count;
    for i in 0..count {
        rw.emit_bx(tails + 8 * i)?;
    }
    for i in 0..count {
        rw.emit(0xF85F0000 | (31 << 5) | 16); // ldur x16,[sp,#-16]
        rw.emit_bx(base + 4 * i)?;
    }
    Ok(start)
}

/// Offset-table `br x18`: the table is constant, so all targets are read at rewrite time.
pub fn site_br_tab(rw: &mut Rw, targets: &[i64]) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::stur(16, 31, -16));
    rw.emit(asm::stur(17, 31, -24));
    rw.emit(asm::mrs_tpidrro(16));
    rw.emit_slot_addr(16, 17, KEY_K18)?;
    rw.emit(asm::ldrx(16, 16, 0));
    let mut uniq: Vec<i64> = targets.to_vec();
    uniq.sort();
    uniq.dedup();
    let pads = rw.here() + 4 * (4 * uniq.len() as i64 + 1);
    for (k, &t) in uniq.iter().enumerate() {
        let w = asm::adrp(17, rw.here(), t)?;
        rw.emit(w);
        rw.emit(asm::addi(17, 17, (t & 0xFFF) as u32, 0));
        rw.emit(asm::cmpr(16, 17));
        let w = asm::beq(rw.here(), pads + 12 * k as i64)?;
        rw.emit(w);
    }
    rw.emit(asm::brk(0x18));
    for &t in &uniq {
        rw.emit(asm::ldur(16, 31, -16));
        rw.emit(asm::ldur(17, 31, -24));
        rw.emit_bx(t)?;
    }
    Ok(start)
}

/// `blr x18`: x16 = guest x18, x30 = the instruction after the original blr, br x16
pub fn site_blr(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::mrs_tpidrro(16));
    rw.emit_slot_addr(16, 17, KEY_K18)?;
    rw.emit(asm::ldrx(16, 16, 0));
    let ret = ins.address + 4;
    let w = asm::adrp(30, rw.here(), ret)?;
    rw.emit(w);
    rw.emit(asm::addi(30, 30, (ret & 0xFFF) as u32, 0));
    rw.emit(asm::br(16));
    Ok(start)
}

/// `br x18` as an indirect tail call: x16 = guest x18, br x16
pub fn site_br_call(rw: &mut Rw) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::mrs_tpidrro(16));
    rw.emit_slot_addr(16, 17, KEY_K18)?;
    rw.emit(asm::ldrx(16, 16, 0));
    rw.emit(asm::br(16));
    Ok(start)
}

/// where a slot copy takes its value from: a thread slot, or a word that puts the value in x15 (`mrs x18, ctr_el0`)
pub enum Src {
    Key(u32),
    Word(u32),
}

/// A system register access whose general-purpose register is x18: a copy from one thread slot to another
pub fn site_slot_copy(rw: &mut Rw, ins: &Ins, src: Src, dst: u32) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::stp(16, 17, 31, -16));
    rw.emit(asm::stur(15, 31, -24));
    match src {
        Src::Key(k) => {
            rw.emit(asm::mrs_tpidrro(16));
            rw.emit_slot_addr(16, 17, k)?;
            rw.emit(asm::ldrx(15, 16, 0));
        }
        Src::Word(w) => rw.emit(w),
    }
    rw.emit(asm::mrs_tpidrro(16));
    rw.emit_slot_addr(16, 17, dst)?;
    rw.emit(asm::strx(15, 16, 0));
    rw.emit(asm::ldur(15, 31, -24));
    rw.emit(asm::ldp(16, 17, 31, -16));
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

/// `mrs xN, tpidr_el0 / tpidrro_el0` -> xN = thread slot value
pub fn site_sysreg_read(rw: &mut Rw, ins: &Ins, kind: u32) -> Res<i64> {
    let n = ins.word & 31;
    if n == 18 {
        return site_slot_copy(rw, ins, Src::Key(kind), KEY_K18);
    }
    let tmp = if n != 16 { 16 } else { 17 };
    let start = rw.here();
    rw.emit(asm::stur(tmp, 31, -16));
    rw.emit(asm::mrs_tpidrro(n));
    rw.emit_slot_addr(n, tmp, kind)?;
    rw.emit(asm::ldrx(n, n, 0));
    rw.emit(asm::ldur(tmp, 31, -16)); // tmp is saved by borrowing the red zone
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

pub fn site_tpidr_write(rw: &mut Rw, ins: &Ins) -> Res<i64> {
    let n = ins.word & 31;
    if n == 18 {
        return site_slot_copy(rw, ins, Src::Key(KEY_K18), KEY_KTLS);
    }
    let mut avoid = std::collections::BTreeSet::new();
    avoid.insert(n);
    let t = pick(&avoid, 1)?[0];
    let start = rw.here();
    rw.emit(0xF81F0000 | (31 << 5) | t); // stur xT,[sp,#-16]
    let tmp = [16u32, 17]
        .into_iter()
        .find(|x| *x != n && *x != t)
        .ok_or_else(|| Fail::new("StopIteration"))?;
    rw.emit(asm::stur(tmp, 31, -24));
    rw.emit(asm::mrs_tpidrro(t));
    rw.emit_slot_addr(t, tmp, KEY_KTLS)?;
    rw.emit(asm::strx(n, t, 0));
    rw.emit(asm::ldur(tmp, 31, -24));
    rw.emit(0xF85F0000 | (31 << 5) | t); // ldur xT,[sp,#-16]
    rw.emit_bx(ins.address + 4)?;
    Ok(start)
}

/// svc / mrs cntpct_el0 -> host gate. The gate address is taken from thread slot KGATE; the gate looks up gates.tsv by
/// return point (the address of this block's ldp).
pub fn site_gate(rw: &mut Rw, ins: &Ins, kind: &'static str, arg: i64) -> Res<i64> {
    let start = rw.here();
    rw.emit(asm::stp_pre(29, 30, 31, -16));
    rw.emit_gate_call()?;
    rw.emit(asm::blr(30));
    let ret = rw.here();
    rw.emit(asm::ldp_post(29, 30, 31, 16));
    rw.emit_bx(ins.address + 4)?;
    rw.gates.push(Gate {
        ret,
        kind,
        arg,
        orig: ins.address,
    });
    Ok(start)
}

/// Observation gate: original entry instruction -> enter the host gate (arg = observation number) -> restore x29/x30 ->
/// execute the original instruction -> jump back to off+4.
pub fn site_obs(rw: &mut Rw, off: i64, oid: i64, word: u32) -> Res<i64> {
    let ins = dis(word, off)?;
    let m = ins.mn();
    if matches!(
        m,
        "adr" | "adrp" | "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || m.starts_with("b.")
        || (m.starts_with("ldr") && !ins.op_str.contains('['))
        || has18(&ins)
    {
        return Err(Fail::new(format!(
            "observation gate original instruction cannot be relocated {off:#x} {m} {}",
            ins.op_str
        )));
    }
    let start = rw.here();
    rw.emit(asm::stp_pre(29, 30, 31, -16));
    rw.emit_gate_call()?;
    rw.emit(asm::blr(30));
    let ret = rw.here();
    rw.emit(asm::ldp_post(29, 30, 31, 16));
    rw.emit(word);
    rw.emit_bx(off + 4)?;
    rw.gates.push(Gate {
        ret,
        kind: "obs",
        arg: oid,
        orig: off,
    });
    Ok(start)
}

// ---- Address regions (every module that defines the SDK's VammManager: sdk) ----

/// The three observation gates found by the SDK's own symbols, or why not
pub fn region_gates(rw: &mut Rw) -> Res<(Vec<ObsRow>, Option<String>)> {
    let sym = crate::fde::defined(&rw.img.b);
    let ask = sym
        .get("_ZN2nn2os6detail11VammManager21AllocateAddressRegionEPmm")
        .copied();
    let free = sym
        .get("_ZN2nn2os6detail11VammManager17FreeAddressRegionEm")
        .copied();
    let (Some(ask), Some(free)) = (ask, free) else {
        return Ok((vec![], None));
    };
    let (got, reg) = match crate::fde::out_store(&rw.img.b, ask.0, ask.1) {
        Ok(x) => x,
        Err(e) => return Ok((vec![], Some(e))),
    };
    let sites = [
        (
            ask.0,
            crate::rewriter::OBS_REGION_ASK,
            "VammManager::AllocateAddressRegion entry: the size in x2".to_string(),
        ),
        (
            got,
            crate::rewriter::OBS_REGION_GOT | (reg as i64) << 8,
            format!(
                "VammManager::AllocateAddressRegion: the new region's address in x{reg}, stored through the out pointer"
            ),
        ),
        (
            free.0,
            crate::rewriter::OBS_REGION_FREE,
            "VammManager::FreeAddressRegion entry: the address in x1".to_string(),
        ),
    ];
    for (off, _, _) in &sites {
        if *off >= rw.text_end || rw.kind_at(*off).is_some() || rw.in_window(*off) {
            return Ok((
                vec![],
                Some(format!("no observation gate possible at {off:#x}")),
            ));
        }
    }
    Ok((
        sites
            .into_iter()
            .map(|(off, number, why)| ObsRow {
                off,
                number,
                word: format!("{:08x}", rw.img.w(off)),
                why,
            })
            .collect(),
        None,
    ))
}

/// nn::mem::StandardAllocator::Initialize(this, void *address, size_t size[, bool]): at its entry the host gives a
/// region of virtual address memory no more address space than the alias region has room for
pub fn stdalloc_gates(rw: &mut Rw) -> Vec<ObsRow> {
    let sym = crate::fde::defined(&rw.img.b);
    let mut out = Vec::new();
    let name = rw.name.clone();
    for n in [
        "_ZN2nn3mem17StandardAllocator10InitializeEPvm",
        "_ZN2nn3mem17StandardAllocator10InitializeEPvmb",
    ] {
        let Some(&(off, _)) = sym.get(n) else {
            continue;
        };
        if off >= rw.text_end || rw.kind_at(off).is_some() || rw.in_window(off) {
            rw.say(format!(
                "{name}: no StandardAllocator gate at {off:#x}: a rewrite site"
            ));
            continue;
        }
        out.push(ObsRow {
            off,
            number: crate::rewriter::OBS_STDALLOC_INIT,
            word: format!("{:08x}", rw.img.w(off)),
            why: format!("StandardAllocator::Initialize(void *, size_t{}) entry: the size in x2, capped when the address in x1 is null", if n.ends_with('b') { ", bool" } else { "" }),
        });
    }
    out
}
