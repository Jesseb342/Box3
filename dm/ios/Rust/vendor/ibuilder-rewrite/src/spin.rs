//! Spin waits (every module): a guest loop that polls memory until another thread changes it fills only its own core on
//! the Switch, where any higher-priority thread pinned there preempts it, so the spin costs the game nothing; on the host
//! it takes a whole core from the threads doing the work. A loop counts as a spin wait only when it provably cannot leave
//! by itself (see "Spin waits" in `patch_nso.py`). Its region is copied into the patch area; the original back-edges jump
//! to the copy, the copy's back-edges go through a spin gate (the host yields there), exits go back to the original code.
//!
//! The search only reads the (site-rewritten, otherwise original) image, so it runs on all cores (`rayon`); its result
//! is a set of regions keyed by head address, so the output does not depend on the thread count.

use crate::rewriter::{Gate, Rw};
use crate::{Fail, Res, hx};
use ibuilder_a64::asm;
use ibuilder_a64::bits::rd32;
use ibuilder_a64::cs::{self, Ins, OP_IMM, OP_MEM, OP_REG, reg_name};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

const SPIN_PATHS: i64 = 256;
const SPIN_STEPS: i64 = 4096;
const SPIN_STORES: usize = 4;
const SPIN_LSE: [&str; 8] = [
    "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
];
const SPIN_BAD: [&str; 40] = [
    "bl", "blr", "br", "ret", "eret", "svc", "hvc", "smc", "brk", "hlt", "udf", "mrs", "msr",
    "sys", "sysl", "wfe", "wfi", "sev", "sevl", "clrex", "dc", "ic", "at", "tlbi", "drps", "dcps1",
    "dcps2", "dcps3", "blraa", "blrab", "blraaz", "blrabz", "braa", "brab", "braaz", "brabz",
    "retaa", "retab", "eretaa", "eretab",
];

// Instruction words that end every path through them, told apart by their encoding alone
const SPIN_STOP: [(u32, u32); 12] = [
    (0xFC000000, 0x94000000),
    (0xFE000000, 0xD6000000),
    (0xFF000000, 0xD4000000),
    (0x3FC00000, 0x39000000),
    (0x3FC00000, 0x3D000000),
    (0x3FC00000, 0x3D800000),
    (0x3FE00000, 0x38000000),
    (0x3FE00C00, 0x38200800),
    (0x3FE00000, 0x3C000000),
    (0x3FE00000, 0x3C800000),
    (0x3A400000, 0x28000000),
    (0x3F200C00, 0x38200000),
];

/// register key: x0..x30 = 0..30, sp = 31, v0..v31 = 32..63, nzcv = 64, other names interned from 65
type Reg = u8;
const R_SP: Reg = 31;
const R_NZCV: Reg = 64;
fn other_regs() -> &'static Mutex<Vec<String>> {
    static O: std::sync::OnceLock<Mutex<Vec<String>>> = std::sync::OnceLock::new();
    O.get_or_init(|| Mutex::new(Vec::new()))
}

/// `spin_norm(name)`: w / x and the vector views merged; zero registers are None
fn spin_norm(n: &str) -> Option<Reg> {
    let n = match n {
        "fp" => "x29",
        "lr" => "x30",
        "wsp" => "sp",
        o => o,
    };
    if n == "wzr" || n == "xzr" {
        return None;
    }
    let b = n.as_bytes();
    if b.len() >= 2
        && b[1..].iter().all(|c| c.is_ascii_digit())
        && let Ok(d) = n[1..].parse::<u32>()
    {
        if b[0] == b'w' || b[0] == b'x' {
            return Some(d as Reg);
        }
        if matches!(b[0], b'b' | b'h' | b's' | b'd' | b'q' | b'v') {
            return Some(32 + d as Reg);
        }
    }
    if n == "sp" {
        return Some(R_SP);
    }
    if n == "nzcv" {
        return Some(R_NZCV);
    }
    let mut o = other_regs().lock().unwrap();
    let i = match o.iter().position(|x| x == n) {
        Some(i) => i,
        None => {
            o.push(n.to_string());
            o.len() - 1
        }
    };
    Some(65 + i as Reg)
}

/// A set of `Reg` (a `u8`: every value has its bit), as a 256-bit mask: the same members, unions, differences and
/// intersections as the `BTreeSet<Reg>` (Python `set`) it replaces, and `iter` lists the members in ascending order
/// as the BTreeSet did, without allocating
#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct RegSet([u64; 4]);
impl RegSet {
    fn of(it: impl IntoIterator<Item = Option<Reg>>) -> RegSet {
        let mut s = [0u64; 4];
        for r in it.into_iter().flatten() {
            s[(r >> 6) as usize] |= 1u64 << (r & 63);
        }
        RegSet(s)
    }
    fn union(&self, o: &RegSet) -> RegSet {
        RegSet(std::array::from_fn(|i| self.0[i] | o.0[i]))
    }
    fn diff(&self, o: &RegSet) -> RegSet {
        RegSet(std::array::from_fn(|i| self.0[i] & !o.0[i]))
    }
    fn meets(&self, o: &RegSet) -> bool {
        (0..4).any(|i| self.0[i] & o.0[i] != 0)
    }
    /// the members, ascending
    fn iter(&self) -> impl Iterator<Item = Reg> + '_ {
        (0..4usize).flat_map(move |i| {
            let mut w = self.0[i];
            std::iter::from_fn(move || {
                if w == 0 {
                    return None;
                }
                let b = w.trailing_zeros();
                w &= w - 1;
                Some((i as u32 * 64 + b) as Reg)
            })
        })
    }
}

/// `spin_rw(ins)`: (registers read, registers written)
fn spin_rw(ins: &Ins) -> (RegSet, RegSet) {
    let m = ins.mn();
    let regs: Vec<Option<Reg>> = ins
        .ops
        .iter()
        .filter(|o| o.ty == OP_REG)
        .map(|o| spin_norm(reg_name(o.reg)))
        .collect();
    let ops = RegSet::of(regs.iter().copied());
    if matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz") {
        return (ops, RegSet::default());
    }
    if m.starts_with("b.") {
        return (RegSet::of([Some(R_NZCV)]), RegSet::default());
    }
    if m == "b" {
        return (RegSet::default(), RegSet::default());
    }
    let nz = RegSet::of([Some(R_NZCV)]);
    if matches!(m, "cmp" | "cmn" | "tst" | "fcmp" | "fcmpe") {
        return (ops, nz);
    }
    if matches!(m, "ccmp" | "ccmn" | "fccmp" | "fccmpe") {
        return (ops.union(&nz), nz);
    }
    let (r, w) = match &ins.regs {
        Some((r, w)) => (
            RegSet::of(r.iter().map(|&x| spin_norm(reg_name(x)))),
            RegSet::of(w.iter().map(|&x| spin_norm(reg_name(x)))),
        ),
        None => (RegSet::default(), RegSet::default()),
    };
    if m.starts_with("ld") || m.starts_with("prfm") || m.starts_with("prfum") {
        return (r, w.union(&ops));
    }
    (
        r.union(&RegSet::of(regs[1.min(regs.len())..].iter().copied())),
        w.union(&RegSet::of(regs[..1.min(regs.len())].iter().copied())),
    )
}

#[derive(Clone, Copy, PartialEq)]
enum SK {
    Br,
    Pc,
    Ok,
}

/// 'br' direct branch, 'pc' adr / adrp, 'ok' a load or register / flag arithmetic, None anything else
fn spin_kind(ins: &Option<Arc<Ins>>) -> Option<SK> {
    let ins = ins.as_ref()?;
    let m = ins.mn();
    if matches!(m, "b" | "cbz" | "cbnz" | "tbz" | "tbnz") || m.starts_with("b.") {
        return Some(SK::Br);
    }
    if matches!(m, "adr" | "adrp") {
        return Some(SK::Pc);
    }
    if SPIN_BAD.contains(&m)
        || m.starts_with("st")
        || m.starts_with("cas")
        || m.starts_with("swp")
        || SPIN_LSE.iter().any(|p| m.starts_with(p))
    {
        return None;
    }
    let mem = ins.ops.iter().any(|o| o.ty == OP_MEM);
    if m.starts_with("ld") || m.starts_with("prfm") || m.starts_with("prfum") {
        return if mem { Some(SK::Ok) } else { None }; // no memory operand: a pc-relative literal load
    }
    if mem { None } else { Some(SK::Ok) }
}

/// Decoded instructions of the unchanged image, by address (per job; the Python's global `spin_dec`)
pub struct SpinCache<'a> {
    img: &'a [u8],
    map: HashMap<i64, Option<Arc<Ins>>>,
}

impl<'a> SpinCache<'a> {
    pub fn new(img: &'a [u8]) -> SpinCache<'a> {
        SpinCache {
            img,
            map: HashMap::new(),
        }
    }
    fn ins(&mut self, a: i64) -> Option<Arc<Ins>> {
        if let Some(x) = self.map.get(&a) {
            return x.clone();
        }
        if self.map.len() > 400_000 {
            self.map.clear();
        }
        let o = pyoff(self.img, a);
        let r = if o + 4 <= self.img.len() {
            cs::decode_no_regs(rd32(self.img, o), a).map(Arc::new)
        } else {
            None
        };
        self.map.insert(a, r.clone());
        r
    }
}

fn rname(x: &Ins, i: usize) -> &'static str {
    x.ops.get(i).map(|o| reg_name(o.reg)).unwrap_or("")
}
fn op_imm(x: &Ins, i: usize) -> i64 {
    x.ops.get(i).map(|o| o.imm).unwrap_or(0)
}

/// ld(a)xr wA,[xN]; add|sub wB,wA,#k; st(l)xr wS,wB,[xN]; cbnz wS,<the load> at a
struct Rmw {
    base: Reg,
    k: i64,
    defs: RegSet,
    ins: Vec<Arc<Ins>>,
}

fn spin_rmw(c: &mut SpinCache, a: i64) -> Option<Rmw> {
    let l: Vec<Option<Arc<Ins>>> = (0..4).map(|i| c.ins(a + 4 * i)).collect();
    if l.iter().any(|x| x.is_none()) {
        return None;
    }
    let l: Vec<Arc<Ins>> = l.into_iter().map(|x| x.unwrap()).collect();
    if !matches!(l[0].mn(), "ldxr" | "ldaxr")
        || !matches!(l[1].mn(), "add" | "sub")
        || !matches!(l[2].mn(), "stxr" | "stlxr")
        || l[3].mn() != "cbnz"
    {
        return None;
    }
    if l[1].ops.len() != 3 || l[1].ops[2].ty != OP_IMM || l[1].op_str.contains("lsl") {
        return None;
    }
    let base = l[0].ops.get(1)?;
    let st = l[2].ops.get(2)?;
    if base.disp != 0 || base.index != 0 || st.base != base.base || st.disp != 0 {
        return None;
    }
    if rname(&l[1], 1) != rname(&l[0], 0)
        || rname(&l[2], 1) != rname(&l[1], 0)
        || rname(&l[3], 0) != rname(&l[2], 0)
        || op_imm(&l[3], 1) != a
    {
        return None;
    }
    let k = l[1].ops[2].imm * if l[1].mn() == "add" { 1 } else { -1 };
    Some(Rmw {
        base: spin_norm(reg_name(base.base))?,
        k,
        defs: RegSet::of([
            spin_norm(rname(&l[0], 0)),
            spin_norm(rname(&l[1], 0)),
            spin_norm(rname(&l[2], 0)),
        ]),
        ins: l,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NK {
    Rmw,
    Acq,
    Rel,
    Tst,
    Stc,
    Br,
    Pc,
    Ok,
}

struct Lock {
    kind: NK,
    bn: Reg,
    ins: Vec<Arc<Ins>>,
    pre: usize,
    n: usize,
    uses: RegSet,
    defs: RegSet,
}

fn plain(x: &Ins, i: usize) -> bool {
    x.ops
        .get(i)
        .is_some_and(|o| o.ty == OP_MEM && o.index == 0 && o.disp == 0)
}

/// An exclusive spin lock sequence or a test loop entered at a (see `spin_lock` in patch_nso.py)
fn spin_lock(c: &mut SpinCache, a: i64) -> Option<Lock> {
    let l: Vec<Option<Arc<Ins>>> = (0..6).map(|i| c.ins(a + 4 * i)).collect();
    let l0 = l[0].clone()?;
    let all = l.iter().all(|x| x.is_some());
    let g = |i: usize| -> Option<Arc<Ins>> { l[i].clone() };
    let m0 = l0.mn();
    if matches!(m0, "ldxr" | "ldaxr") && all && rname(&l0, 0).starts_with('w') && plain(&l0, 1) {
        let (l1, l2, l3, l4, l5) = (
            g(1).unwrap(),
            g(2).unwrap(),
            g(3).unwrap(),
            g(4).unwrap(),
            g(5).unwrap(),
        );
        let base = l0.ops[1].base;
        let bn = spin_norm(reg_name(base))?;
        if l1.mn() == "cbnz"
            && rname(&l1, 0) == rname(&l0, 0)
            && op_imm(&l1, 1) == a
            && matches!(l2.mn(), "stxr" | "stlxr")
            && plain(&l2, 2)
            && l2.ops[2].base == base
            && !matches!(rname(&l2, 1), "wzr" | "xzr")
            && l3.mn() == "cbnz"
            && rname(&l3, 0) == rname(&l2, 0)
            && op_imm(&l3, 1) == a
        {
            return Some(Lock {
                kind: NK::Acq,
                bn,
                ins: vec![l0.clone(), l1.clone(), l2.clone(), l3.clone()],
                pre: 0,
                n: 4,
                uses: RegSet::of([Some(bn), spin_norm(rname(&l2, 1))]),
                defs: RegSet::of([spin_norm(rname(&l0, 0)), spin_norm(rname(&l2, 0))]),
            });
        }
        if l1.mn() == "cmp"
            && rname(&l1, 0) == rname(&l0, 0)
            && l1.ops.get(1).is_some_and(|o| o.ty == OP_IMM)
            && l2.mn() == "b.ne"
            && op_imm(&l2, 0) == a
            && matches!(l3.mn(), "stxr" | "stlxr")
            && rname(&l3, 1) == "wzr"
            && plain(&l3, 2)
            && l3.ops[2].base == base
            && l4.mn() == "cbnz"
            && rname(&l4, 0) == rname(&l3, 0)
            && op_imm(&l4, 1) == a
        {
            return Some(Lock {
                kind: NK::Rel,
                bn,
                ins: vec![l0.clone(), l1.clone(), l2.clone(), l3.clone(), l4.clone()],
                pre: 0,
                n: 5,
                uses: RegSet::of([Some(bn)]),
                defs: RegSet::of([
                    spin_norm(rname(&l0, 0)),
                    spin_norm(rname(&l3, 0)),
                    Some(R_NZCV),
                ]),
            });
        }
        if l1.mn() == "cbz"
            && rname(&l1, 0) == rname(&l0, 0)
            && op_imm(&l1, 1) == a + 16
            && l2.mn() == "clrex"
            && l3.mn() == "b"
            && op_imm(&l3, 0) == a
            && matches!(l4.mn(), "stxr" | "stlxr")
            && plain(&l4, 2)
            && l4.ops[2].base == base
            && !matches!(rname(&l4, 1), "wzr" | "xzr")
            && l5.mn() == "cbnz"
            && rname(&l5, 0) == rname(&l4, 0)
            && op_imm(&l5, 1) == a
        {
            return Some(Lock {
                kind: NK::Acq,
                bn,
                ins: vec![
                    l0.clone(),
                    l1.clone(),
                    l2.clone(),
                    l3.clone(),
                    l4.clone(),
                    l5.clone(),
                ],
                pre: 0,
                n: 6,
                uses: RegSet::of([Some(bn), spin_norm(rname(&l4, 1))]),
                defs: RegSet::of([spin_norm(rname(&l0, 0)), spin_norm(rname(&l4, 0))]),
            });
        }
        let p = c.ins(a - 4);
        if let Some(p) = p
            && p.mn() == "clrex"
            && l1.mn() == "cmp"
            && rname(&l1, 0) == rname(&l0, 0)
            && l1.ops.get(1).is_some_and(|o| o.ty == OP_IMM)
            && l2.mn() == "b.ne"
            && op_imm(&l2, 0) == a - 4
            && matches!(l3.mn(), "stxr" | "stlxr")
            && rname(&l3, 1) == "wzr"
            && plain(&l3, 2)
            && l3.ops[2].base == base
            && l4.mn() == "cbnz"
            && rname(&l4, 0) == rname(&l3, 0)
            && op_imm(&l4, 1) == a
        {
            return Some(Lock {
                kind: NK::Rel,
                bn,
                ins: vec![
                    p,
                    l0.clone(),
                    l1.clone(),
                    l2.clone(),
                    l3.clone(),
                    l4.clone(),
                ],
                pre: 1,
                n: 5,
                uses: RegSet::of([Some(bn)]),
                defs: RegSet::of([
                    spin_norm(rname(&l0, 0)),
                    spin_norm(rname(&l3, 0)),
                    Some(R_NZCV),
                ]),
            });
        }
    }
    if m0 == "stlr" && l0.ops.len() == 2 && matches!(rname(&l0, 0), "wzr" | "xzr") && plain(&l0, 1)
    {
        let bn = spin_norm(reg_name(l0.ops[1].base))?;
        return Some(Lock {
            kind: NK::Rel,
            bn,
            ins: vec![l0.clone()],
            pre: 0,
            n: 1,
            uses: RegSet::of([Some(bn)]),
            defs: RegSet::default(),
        });
    }
    if matches!(m0, "ldr" | "ldrb" | "ldrh")
        && l[..3].iter().all(|x| x.is_some())
        && l0.ops.len() == 2
        && rname(&l0, 0).starts_with('w')
        && l0.ops[1].ty == OP_MEM
        && l0.ops[1].index == 0
        && !l0.writeback
    {
        let (l1, l2) = (g(1).unwrap(), g(2).unwrap());
        if l1.mn() == "cmp"
            && rname(&l1, 0) == rname(&l0, 0)
            && l1.ops.get(1).is_some_and(|o| o.ty == OP_IMM)
            && matches!(l2.mn(), "b.eq" | "b.ne")
            && op_imm(&l2, 0) == a
        {
            let bn = spin_norm(reg_name(l0.ops[1].base))?;
            return Some(Lock {
                kind: NK::Tst,
                bn,
                ins: vec![l0.clone(), l1, l2],
                pre: 0,
                n: 3,
                uses: RegSet::of([Some(bn)]),
                defs: RegSet::of([spin_norm(rname(&l0, 0)), Some(R_NZCV)]),
            });
        }
    }
    None
}

/// str / strb / strh / stur / sturb / sturh of a w register or zr to [xN{,#imm}]: (value register or None, base register)
fn spin_store(ins: &Option<Arc<Ins>>) -> Option<(Option<Reg>, Reg)> {
    let ins = ins.as_ref()?;
    if !matches!(
        ins.mn(),
        "str" | "strb" | "strh" | "stur" | "sturb" | "sturh"
    ) || ins.writeback
        || ins.ops.len() != 2
    {
        return None;
    }
    let (v, o) = (&ins.ops[0], &ins.ops[1]);
    if v.ty != OP_REG || o.ty != OP_MEM || o.index != 0 {
        return None;
    }
    let vn = reg_name(v.reg);
    if !(vn.starts_with('w') || vn == "xzr") {
        return None;
    }
    Some((spin_norm(vn), spin_norm(reg_name(o.base))?))
}

/// Python indexes a negative offset from the end of the image (a spin head before the module's first word, which only
/// a module that branches out of its own start can have): the same here, so the two agree on any input
#[inline]
fn pyoff(img: &[u8], a: i64) -> usize {
    (if a < 0 { a + img.len() as i64 } else { a }) as usize
}

/// a back-edge to T can be reached from T without passing a word of SPIN_STOP
fn spin_quick(img: &[u8], t0: i64, hi: i64) -> bool {
    let mut seen: HashSet<i64> = HashSet::new();
    let mut todo = vec![t0];
    while let Some(a) = todo.pop() {
        if seen.contains(&a) || !(t0 <= a && a <= hi) {
            continue;
        }
        seen.insert(a);
        let w = rd32(img, pyoff(img, a));
        let t = w >> 24;
        let succ: Vec<i64> = if (0x14..=0x17).contains(&t) {
            vec![a + ((((w & 0x3FFFFFF) ^ 0x2000000) as i64) - 0x2000000) * 4]
        } else if t == 0x54 || t & 0x7E == 0x34 {
            vec![
                a + ((((w >> 5) & 0x7FFFF) ^ 0x40000) as i64 - 0x40000) * 4,
                a + 4,
            ]
        } else if t & 0x7E == 0x36 {
            vec![
                a + ((((w >> 5) & 0x3FFF) ^ 0x2000) as i64 - 0x2000) * 4,
                a + 4,
            ]
        } else if SPIN_STOP.iter().any(|&(m, v)| w & m == v)
            && !(matches!(w & 0xBFC00000, 0xB9000000 | 0x39000000 | 0x79000000)
                || matches!(w & 0xBFE00C00, 0xB8000000 | 0x38000000 | 0x78000000))
        {
            continue; // str / strb / strh (immediate, unscaled) may store the same on every pass
        } else {
            vec![a + 4]
        };
        if succ.contains(&t0) {
            return true;
        }
        todo.extend(succ);
    }
    false
}

#[derive(Clone)]
struct Node {
    kind: NK,
    base: Reg,
    k: i64,
    ins: Vec<Arc<Ins>>,
    pre: usize,
    uses: RegSet,
    defs: RegSet,
    succ: Vec<i64>,
    has_rw: bool,
}

pub struct Region {
    pub t: i64,
    r: Vec<i64>,
    nodes: HashMap<i64, Node>,
    valid: BTreeSet<i64>,
}

impl Region {
    /// the text words this region's instructions occupy (for `changed.tsv`)
    pub fn words(&self) -> Vec<i64> {
        let mut out = Vec::new();
        for a in &self.r {
            let n = &self.nodes[a];
            for i in 0..n.ins.len() {
                out.push(a + 4 * (i as i64 - n.pre as i64));
            }
        }
        out
    }
    pub fn n_ins(&self) -> usize {
        self.r.iter().map(|a| self.nodes[a].ins.len()).sum()
    }
    pub fn back_edges(&self) -> Vec<i64> {
        self.valid.iter().copied().collect()
    }
}

enum R1 {
    None,
    Vary(BTreeSet<i64>),
    Region(Region),
}

struct SpinNo;

struct Walk<'n> {
    nodes: &'n HashMap<i64, Node>,
    r: &'n HashSet<i64>,
    t: i64,
    cnt: [i64; 2],
    bad_back: BTreeSet<i64>,
    path: Vec<i64>,
}

impl Walk<'_> {
    fn walk(
        &mut self,
        a: i64,
        ver: &BTreeMap<Reg, i64>,
        delta: &BTreeMap<(bool, Reg, i64), i64>,
    ) -> Result<(), SpinNo> {
        self.cnt[1] += 1;
        if self.cnt[1] > SPIN_STEPS {
            return Err(SpinNo);
        }
        let n = &self.nodes[&a];
        let mut delta = delta.clone();
        if matches!(n.kind, NK::Rmw | NK::Acq | NK::Rel) {
            // exclusive adds and lock / unlock pairs, each kind on its own
            let key = (n.kind != NK::Rmw, n.base, *ver.get(&n.base).unwrap_or(&0));
            let d = delta.entry(key).or_insert(0);
            *d += n.k;
            if n.kind != NK::Rmw && !(0 <= *d && *d <= 1) {
                return Err(SpinNo); // a release before its acquire or a second acquire: not a lock this pass takes once
            }
        }
        let mut ver = ver.clone();
        for r in n.defs.iter() {
            *ver.entry(r).or_insert(0) += 1;
        }
        for &s in &n.succ {
            if s == self.t {
                self.cnt[0] += 1;
                if self.cnt[0] > SPIN_PATHS {
                    return Err(SpinNo);
                }
                if delta.values().any(|&v| v != 0) {
                    self.bad_back.insert(a);
                }
            } else if self.r.contains(&s) {
                if self.path.contains(&s) {
                    return Err(SpinNo);
                }
                self.path.push(s);
                let res = self.walk(s, &ver, &delta);
                self.path.pop();
                res?;
            }
        }
        Ok(())
    }
}

fn prune(nodes: &HashMap<i64, Node>, t: i64, ends: &BTreeSet<i64>) -> HashSet<i64> {
    let mut keep: HashSet<i64> = ends.iter().copied().collect();
    let mut more = true;
    while more {
        more = false;
        for (a, n) in nodes.iter() {
            if !keep.contains(a) && n.succ.iter().any(|s| keep.contains(s) && *s != t) {
                keep.insert(*a);
                more = true;
            }
        }
    }
    keep
}

fn spin_region1(
    c: &mut SpinCache,
    rw: &SpinCtx,
    t: i64,
    bes: &[i64],
    ban: &BTreeSet<i64>,
    stores: bool,
    head: bool,
) -> R1 {
    let hi = *bes.iter().max().unwrap();
    if rw.data_blocks.iter().any(|&(s, e)| s < hi + 4 && t < e) || !spin_quick(c.img, t, hi) {
        return R1::None;
    }
    let mut nodes: HashMap<i64, Node> = HashMap::new();
    let (mut back, mut bad): (BTreeSet<i64>, HashSet<i64>) = (BTreeSet::new(), HashSet::new());
    let mut inner: HashSet<i64> = HashSet::new();
    let mut todo = vec![t];
    while let Some(a) = todo.pop() {
        if nodes.contains_key(&a) || bad.contains(&a) {
            continue;
        }
        if ban.contains(&a) {
            bad.insert(a);
            continue;
        }
        let rmw = if a + 12 <= hi && rd32(c.img, pyoff(c.img, a)) & 0x3FE00000 == 0x08400000 {
            spin_rmw(c, a)
        } else {
            None
        }; // ldxr / ldaxr
        let mut lk = if rmw.is_some() { None } else { spin_lock(c, a) };
        if let Some(l) = &lk
            && a == t
            && (l.kind == NK::Tst || !head)
        {
            lk = None; // the region's own test loop, or a lock sequence taken as plain instructions (spin_region)
        }
        let n: Node;
        if let Some(r) = rmw {
            n = Node {
                kind: NK::Rmw,
                base: r.base,
                k: r.k,
                ins: r.ins,
                pre: 0,
                uses: RegSet::of([Some(r.base)]),
                defs: r.defs,
                succ: vec![a + 16],
                has_rw: true,
            };
        } else if let Some(l) = lk {
            let k = match l.kind {
                NK::Acq => 1,
                NK::Rel => -1,
                _ => 0,
            };
            n = Node {
                kind: l.kind,
                base: l.bn,
                k,
                ins: l.ins,
                pre: l.pre,
                uses: l.uses,
                defs: l.defs,
                succ: vec![a + 4 * l.n as i64],
                has_rw: true,
            };
        } else if stores && {
            let x = c.ins(a);
            spin_store(&x).is_some()
        } {
            let x = c.ins(a);
            let st = spin_store(&x).unwrap();
            let uses = RegSet::of([Some(st.1), st.0]);
            n = Node {
                kind: NK::Stc,
                base: 0,
                k: 0,
                ins: vec![x.unwrap()],
                pre: 0,
                uses,
                defs: RegSet::default(),
                succ: vec![a + 4],
                has_rw: true,
            };
        } else {
            let x = c.ins(a);
            let Some(k) = spin_kind(&x) else {
                bad.insert(a);
                continue;
            };
            let x = x.unwrap();
            let succ = if k == SK::Br {
                let tg = x.ops.last().map(|o| o.imm).unwrap_or(0);
                if x.mn() == "b" {
                    vec![tg]
                } else {
                    vec![tg, a + 4]
                }
            } else {
                vec![a + 4]
            };
            n = Node {
                kind: match k {
                    SK::Br => NK::Br,
                    SK::Pc => NK::Pc,
                    SK::Ok => NK::Ok,
                },
                base: 0,
                k: 0,
                ins: vec![x],
                pre: 0,
                uses: RegSet::default(),
                defs: RegSet::default(),
                succ,
                has_rw: false,
            };
        }
        let pre = n.pre as i64;
        if (0..n.ins.len() as i64).any(|i| rw.touched.contains(&(a + 4 * (i - pre)))) {
            bad.insert(a);
            continue;
        }
        if n.kind == NK::Rmw {
            inner.extend([a + 4, a + 8, a + 12]);
        }
        if matches!(n.kind, NK::Acq | NK::Rel | NK::Tst) {
            for i in 0..n.ins.len() as i64 {
                let x = a + 4 * (i - pre);
                if x != a {
                    inner.insert(x);
                }
            }
        }
        let succ = n.succ.clone();
        nodes.insert(a, n);
        for s in succ {
            if s == t {
                back.insert(a);
            } else if t < s && s <= hi {
                todo.push(s);
            }
        }
    }
    if back.is_empty()
        || inner.iter().any(|x| nodes.contains_key(x))
        || nodes
            .values()
            .any(|n| n.succ.iter().any(|s| inner.contains(s)))
    {
        return R1::None;
    }
    let mut r = prune(&nodes, t, &back);
    for a in r.iter().copied().collect::<Vec<_>>() {
        let n = nodes.get_mut(&a).unwrap();
        if !n.has_rw {
            // the cache keeps instructions without their register lists: decode this one in full
            let full = cs::decode(n.ins[0].word, n.ins[0].address).expect("decoded before");
            let (u, d) = spin_rw(&full);
            n.uses = u;
            n.defs = d;
            n.has_rw = true;
        }
    }
    // every path from T to a back-edge: no inner cycle, and the exclusive adds on each address sum to 0
    let mut w = Walk {
        nodes: &nodes,
        r: &r,
        t,
        cnt: [0, 0],
        bad_back: BTreeSet::new(),
        path: vec![t],
    };
    if w.walk(t, &BTreeMap::new(), &BTreeMap::new()).is_err() {
        return R1::None;
    }
    let bad_back = w.bad_back;
    let valid: BTreeSet<i64> = back.difference(&bad_back).copied().collect();
    if valid.is_empty() {
        return R1::None;
    }
    r = prune(&nodes, t, &valid);
    // no state carried from one pass to the next: nothing live at T is written in R
    let mut live: HashMap<i64, RegSet> = r.iter().map(|&a| (a, RegSet::default())).collect();
    let mut order: Vec<i64> = r.iter().copied().collect();
    order.sort_by(|a, b| b.cmp(a));
    let mut more = true;
    while more {
        more = false;
        for &a in &order {
            let n = &nodes[&a];
            let mut out = RegSet::default();
            for &s in &n.succ {
                if s == t {
                    if valid.contains(&a) {
                        out = out.union(&live[&t]);
                    }
                } else if r.contains(&s) {
                    out = out.union(&live[&s]);
                }
            }
            let new = n.uses.union(&out.diff(&n.defs));
            if new != live[&a] {
                live.insert(a, new);
                more = true;
            }
        }
    }
    let defs = r
        .iter()
        .fold(RegSet::default(), |acc, a| acc.union(&nodes[a].defs));
    if r.iter().any(|a| nodes[a].kind == NK::Stc)
        && !r.iter().any(|a| {
            matches!(nodes[a].kind, NK::Rmw | NK::Acq | NK::Rel | NK::Tst)
                || nodes[a].ins[0].mn().starts_with("ld")
        })
    {
        return R1::None; // stores and nothing polled
    }
    let vary: BTreeSet<i64> = r
        .iter()
        .filter(|a| nodes[a].kind == NK::Stc && nodes[a].uses.meets(&defs))
        .copied()
        .collect(); // a store's value and address must come from registers no pass writes
    if !vary.is_empty() {
        return R1::Vary(vary);
    }
    if r.iter().filter(|a| nodes[a].kind == NK::Stc).count() > SPIN_STORES {
        return R1::None;
    }
    if live[&t].meets(&defs) {
        return R1::None;
    }
    let mut rl: Vec<i64> = r.iter().copied().collect();
    rl.sort();
    let keep: HashMap<i64, Node> = nodes.into_iter().filter(|(a, _)| r.contains(a)).collect();
    R1::Region(Region {
        t,
        r: rl,
        nodes: keep,
        valid,
    })
}

/// The read-only context of the search
pub struct SpinCtx<'a> {
    pub data_blocks: &'a [(i64, i64)],
    pub touched: &'a HashSet<i64>,
}

/// The spin wait region with head `t` (bes: the backward branches to t found by the scan), or None
fn spin_region(c: &mut SpinCache, rw: &SpinCtx, t: i64, bes: &[i64]) -> Option<Region> {
    // Every `spin_region1` starts with this test, which depends on neither the head kind, the ban nor the stores flag: when
    // it fails the Python's loop comes out empty-handed whatever the lock sequence at T is, so nothing is decoded for it
    let hi = *bes.iter().max().unwrap();
    if rw.data_blocks.iter().any(|&(s, e)| s < hi + 4 && t < e) || !spin_quick(c.img, t, hi) {
        return None;
    }
    let lk = spin_lock(c, t);
    let heads: &[bool] = if lk
        .as_ref()
        .is_some_and(|l| matches!(l.kind, NK::Acq | NK::Rel))
    {
        &[true, false]
    } else {
        &[true]
    };
    let mut g: Option<Region> = None;
    for &head in heads {
        let mut ban: BTreeSet<i64> = BTreeSet::new();
        let mut cur = R1::None;
        for _ in 0..8 {
            cur = spin_region1(c, rw, t, bes, &ban, true, head);
            match &cur {
                R1::Vary(s) => {
                    ban.extend(s.iter().copied());
                }
                _ => break,
            }
        }
        let old = spin_region1(c, rw, t, bes, &BTreeSet::new(), false, head); // the region without stores, which the search took before: the wider one only when it covers its back-edges
        g = match (cur, old) {
            (R1::Region(gr), R1::Region(or_)) => {
                if or_.valid.is_subset(&gr.valid) {
                    Some(gr)
                } else {
                    Some(or_)
                }
            }
            (R1::Region(gr), _) => Some(gr),
            (_, R1::Region(or_)) => Some(or_),
            _ => None,
        };
        if g.is_some() {
            break;
        }
    }
    g
}

fn spin_rebranch(rw: &mut Rw, x: &Ins, pc: i64, tgt: i64) -> Res<u32> {
    let w = x.word;
    let off = tgt - pc;
    if x.mn() == "b" {
        return rw.bx(pc, tgt);
    }
    if matches!(x.mn(), "tbz" | "tbnz") {
        if !((-(1 << 15)..(1 << 15)).contains(&off) && off % 4 == 0) {
            return Err(Fail::new(format!("spin wait tbz out of range {}", hx(pc))));
        }
        return Ok((w & !(0x3FFF << 5)) | ((((off >> 2) as u32) & 0x3FFF) << 5));
    }
    if !((-(1 << 20)..(1 << 20)).contains(&off) && off % 4 == 0) {
        return Err(Fail::new(format!(
            "spin wait branch out of range {}",
            hx(pc)
        )));
    }
    Ok((w & !(0x7FFFF << 5)) | ((((off >> 2) as u32) & 0x7FFFF) << 5))
}

enum Fix {
    /// a word to be a b to the copy of `info` (or the original when not copied)
    Ft(i64),
    /// a retry branch of a node: re-encode `x` to the copy of node `a`
    Copy(Arc<Ins>, i64),
    /// a test loop's branch back, which goes to the original loop through a trampoline
    Orig(Arc<Ins>, i64),
    /// a direct branch of the region
    Br(Arc<Ins>),
}

fn spin_emit(rw: &mut Rw, g: &Region) -> Res<()> {
    let (t, r, nodes, valid) = (g.t, &g.r, &g.nodes, &g.valid);
    rw.use_area(t);
    let mut cpy: HashMap<i64, i64> = HashMap::new();
    let mut fixes: Vec<(usize, Fix)> = Vec::new();
    let mut tramp: HashMap<i64, i64> = HashMap::new();
    for (i, &a) in r.iter().enumerate() {
        let n = &nodes[&a];
        cpy.insert(a, rw.here());
        let x = &n.ins[0];
        match n.kind {
            NK::Rmw => {
                for y in &n.ins[..3] {
                    rw.emit(y.word);
                }
                fixes.push((rw.patch_len(), Fix::Copy(n.ins[3].clone(), a))); // retry: the copy's exclusive load
                rw.emit(0);
            }
            NK::Acq | NK::Rel => {
                // copied as they are: their branches stay inside the sequence
                cpy.insert(a, rw.here() + 4 * n.pre as i64);
                for y in &n.ins {
                    rw.emit(y.word);
                }
            }
            NK::Tst => {
                // its branch back goes to the original loop, which passes its own spin gate when it is a spin wait itself
                for y in &n.ins[..2] {
                    rw.emit(y.word);
                }
                fixes.push((rw.patch_len(), Fix::Orig(n.ins[2].clone(), a)));
                rw.emit(0);
            }
            NK::Pc => {
                let rd = spin_norm(rname(x, 0)).ok_or_else(|| Fail::new("pc register"))? as u32;
                let tgt = x.ops[1].imm;
                let w = asm::adrp(rd, rw.here(), tgt)?;
                rw.emit(w);
                if x.mn() == "adr" {
                    rw.emit(asm::addi(rd, rd, (tgt & 0xFFF) as u32, 0));
                }
            }
            NK::Br => {
                fixes.push((rw.patch_len(), Fix::Br(x.clone())));
                rw.emit(0);
            }
            _ => rw.emit(x.word),
        }
        if !(n.kind == NK::Br && x.mn() == "b") {
            let ft = a + 4 * (n.ins.len() as i64 - n.pre as i64);
            if !(i + 1 < r.len() && r[i + 1] == ft) {
                fixes.push((rw.patch_len(), Fix::Ft(ft))); // the next instruction is not the next one copied
                rw.emit(0);
            }
        }
    }
    let pause = rw.here();
    rw.emit(asm::stp_pre(29, 30, 31, -16));
    rw.emit_gate_call()?;
    rw.emit(asm::blr(30));
    let ret = rw.here();
    rw.emit(asm::ldp_post(29, 30, 31, 16));
    rw.gates.push(Gate {
        ret,
        kind: "spin",
        arg: 0,
        orig: t,
    });
    let h = rw.here();
    let w = rw.bx(h, cpy[&t])?;
    rw.emit(w);
    let base = rw.patch_base();
    for (idx, fix) in fixes {
        let pc = base + idx as i64;
        let w = match fix {
            Fix::Ft(ft) => rw.bx(pc, *cpy.get(&ft).unwrap_or(&ft))?,
            Fix::Orig(x, a) => {
                let o = out(rw, &mut tramp, a)?;
                spin_rebranch(rw, &x, pc, o)?
            }
            Fix::Copy(x, a) => spin_rebranch(rw, &x, pc, cpy[&a])?,
            Fix::Br(x) => {
                let (tg, cond) = (x.ops.last().map(|o| o.imm).unwrap_or(0), x.mn() != "b");
                let d = if tg == t && valid.contains(&x.address) {
                    pause
                } else if cpy.contains_key(&tg) && tg != t {
                    cpy[&tg]
                } else if cond {
                    out(rw, &mut tramp, tg)?
                } else {
                    tg
                };
                spin_rebranch(rw, &x, pc, d)?
            }
        };
        let p = if rw.in_back {
            &mut rw.patch_back
        } else {
            &mut rw.patch_front
        };
        p[idx..idx + 4].copy_from_slice(&w.to_le_bytes());
    }
    for &b in valid {
        let x = nodes[&b].ins[0].clone();
        if x.mn() == "b" {
            rw.put_branch(b, cpy[&t])?;
        } else {
            let st = rw.here();
            let w = spin_rebranch(rw, &x, st, cpy[&t])?;
            rw.emit(w);
            rw.emit_bx(b + 4)?;
            rw.put_branch(b, st)?;
        }
    }
    rw.stat("spin");
    Ok(())
}

/// an exit taken by a conditional branch: through a b next to the copy
fn out(rw: &mut Rw, tramp: &mut HashMap<i64, i64>, t: i64) -> Res<i64> {
    if let Some(&x) = tramp.get(&t) {
        return Ok(x);
    }
    let h = rw.here();
    tramp.insert(t, h);
    rw.emit_bx(t)?;
    Ok(h)
}

/// `find_spin_regions()` and `spin_emit` of every region, in address order
pub fn run(rw: &mut Rw, spin_cand: BTreeMap<i64, Vec<i64>>) -> Res<()> {
    // spin_touched = set(kinds) | done | observation gate offsets | cut words
    let mut touched: HashSet<i64> = rw.kinds.iter().map(|k| k.0).collect();
    touched.extend(rw.done.iter().copied());
    touched.extend(rw.obs.iter().map(|o| o.off));
    for c in &rw.cuts {
        let n = (c.old.len() / 2) as i64;
        let mut o = c.off;
        while o < c.off + n {
            touched.insert(o);
            o += 4;
        }
    }
    let heads: Vec<(i64, Vec<i64>)> = spin_cand.into_iter().collect();
    let regions: Vec<Region> = {
        let img = &rw.img.b[..];
        let ctx = SpinCtx {
            data_blocks: &rw.data_blocks,
            touched: &touched,
        };
        let found: Vec<Option<Region>> = heads
            .par_iter()
            .map_init(
                || SpinCache::new(img),
                |c, (t, bes)| spin_region(c, &ctx, *t, bes),
            )
            .collect();
        found.into_iter().flatten().collect()
    };
    // spin_regions are found on the unchanged image first: emitting patches back-edges
    rw.spin_sites = regions
        .iter()
        .map(|g| (g.t, g.back_edges(), g.n_ins()))
        .collect();
    rw.spin_words = regions.iter().flat_map(|g| g.words()).collect();
    for g in &regions {
        spin_emit(rw, g)?;
    }
    if rw.opts.spin_list {
        let name = rw.name.clone();
        let lines: Vec<String> = rw
            .spin_sites
            .iter()
            .map(|(t, bes, n)| {
                format!(
                    "{name} spin wait {t:#x} ({n} instructions), back-edges {}",
                    bes.iter()
                        .map(|b| format!("{b:#x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect();
        for l in lines {
            rw.say(l);
        }
    }
    Ok(())
}
