//! Offset jump tables proved by dataflow over a function's control flow: the port of the shipped engine's
//! `dm/tools/jump_solver.py` (engine 75c73361, 704 lines). Its docstring, shortened:
//!
//! A dispatch is `br xD` where xD = C + (entry << s), the entry loaded from a table (ldrsw / ldrb / ldrh / ldrsb / ldrsh
//! [xB, xI ...]) and C a constant (the table base itself, or an adr). One forward analysis over the function proves, for
//! every such dispatch at once, which values the index can take at the load and which constant the base holds, on every
//! path that reaches it. The tables' entries then become edges of the control flow, and the analysis runs again until no
//! table changes. A register holds a symbolic value: a root (an unknown value, created where a register was written or
//! where paths with different values join) and a chain of operations applied to it (a 32-bit truncation, an and with a
//! mask, a complement, an add). Each root carries a range, the set of its possible low 12 bits and the range of its low
//! 32 bits. A guard (cmp / b.cond, tst / b.cond, cbz, tbz) refines the root, so every register derived from it narrows at
//! once. Two readings: the first knows every number the code writes and gives the control flow; the second reads the
//! `br x18` tables again on that control flow with those numbers unknown.
//!
//! The port is line for line, and keeps what makes the Python's answer what it is beyond the arithmetic:
//! * the order of the fixpoint's work list, which the widening (after `WIDEN` visits) and the order of the results depend
//!   on: the seeds are iterated in the order of a CPython set of ints ([`crate::pyset::PySet`]), the states in the
//!   insertion order of a dict, the work list is the same stack;
//! * Python's integers: every value is an `i128` (the Python ints here stay within 2**65 in magnitude);
//! * Python's exceptions: `Unsupported` (an instruction the analysis does not know, no fixpoint) is caught by `solve`,
//!   which then fails every dispatch of the function, as the Python does; a `TypeError` of the Python (its `State.key`
//!   sorts the constraint dict, whose keys are tuples that cannot always be ordered: a root `('x', root, i, 64)` beside a
//!   root `('x', k, i', i, 64)`) stops the whole module in the Python, and here too ([`Stop::Fatal`]), with the
//!   Python's message, found by replaying CPython's sort on the same keys in the same order (`py_sort_check`).

use crate::pyset::PySet;
use ibuilder_a64::cs::{self, GRP_CALL, GRP_INT, GRP_JUMP, GRP_RET, Ins, OP_IMM, OP_MEM, OP_REG};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

type I = i128;
const M32: I = (1 << 32) - 1;
const M64: I = (1 << 64) - 1;
const LOW: I = 0xfff;
const MAXC: usize = 8;
const MAXN: I = 1 << 16;
const ENUM: I = 1 << 12;
const WIDEN: u32 = 6;
const OUTER: usize = 16;
const STEPS: u64 = 3_000_000;

/// Capstone's ARM64_SFT_LSL, and the extenders the table loads accept
const SFT_LSL: u8 = 1;
const EXT_INVALID: u8 = 0;
const EXT_UXTW: u8 = 3;
const EXT_UXTX: u8 = 4;
const EXT_SXTW: u8 = 7;
const EXT_SXTX: u8 = 8;

fn mask(w: u32) -> I {
    if w == 32 { M32 } else { M64 }
}

/// What ends a solve early: `Unsupported` is the Python's exception of that name (caught by [`solve`]); `Fatal` is any
/// other exception, which stops the module
#[derive(Debug)]
pub enum Stop {
    Unsupported(String),
    Fatal(String),
}
type R<T> = Result<T, Stop>;

/// A multiply-rotate hasher for the solver's maps of small keys (roots, chains, constant sets, addresses): SipHash was a
/// tenth of the solver's time, and nothing here is fed by an adversary who could aim at collisions beyond slowness
#[derive(Default, Clone, Copy)]
struct Fx(u64);
impl std::hash::Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, b: &[u8]) {
        for &x in b {
            self.write_u64(x as u64);
        }
    }
    fn write_u8(&mut self, i: u8) {
        self.write_u64(i as u64)
    }
    fn write_u16(&mut self, i: u16) {
        self.write_u64(i as u64)
    }
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64)
    }
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    fn write_u128(&mut self, i: u128) {
        self.write_u64(i as u64);
        self.write_u64((i >> 64) as u64);
    }
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64)
    }
}
type FxMap<K, V> = HashMap<K, V, std::hash::BuildHasherDefault<Fx>>;

// ---- the 4096-bit sets of low 12 bits ----

/// A set of low 12 bits: the two common sets (all, none) need no memory, the others share theirs
#[derive(Clone, Debug)]
enum Bits {
    Full,
    Zero,
    Set(Rc<[u64; 64]>),
}

impl PartialEq for Bits {
    fn eq(&self, o: &Bits) -> bool {
        match (self, o) {
            (Bits::Full, Bits::Full) | (Bits::Zero, Bits::Zero) => true,
            (Bits::Set(a), Bits::Set(b)) => Rc::ptr_eq(a, b) || **a == **b,
            _ => false, // a Set is never all ones nor all zeros (from_words)
        }
    }
}
impl Eq for Bits {}

impl Bits {
    fn full() -> Bits {
        Bits::Full
    }
    fn zero() -> Bits {
        Bits::Zero
    }
    fn from_words(w: [u64; 64]) -> Bits {
        if w == [u64::MAX; 64] {
            Bits::Full
        } else if w == [0; 64] {
            Bits::Zero
        } else {
            Bits::Set(Rc::new(w))
        }
    }
    fn is_full(&self) -> bool {
        matches!(self, Bits::Full)
    }
    fn is_zero(&self) -> bool {
        matches!(self, Bits::Zero)
    }
    fn has(&self, b: I) -> bool {
        let b = (b & LOW) as usize;
        match self {
            Bits::Full => true,
            Bits::Zero => false,
            Bits::Set(w) => w[b >> 6] >> (b & 63) & 1 != 0,
        }
    }
    fn and(&self, o: &Bits) -> Bits {
        match (self, o) {
            (Bits::Full, x) | (x, Bits::Full) => x.clone(),
            (Bits::Zero, _) | (_, Bits::Zero) => Bits::Zero,
            (Bits::Set(a), Bits::Set(b)) => {
                if Rc::ptr_eq(a, b) {
                    return self.clone();
                }
                let mut w = [0u64; 64];
                for (i, x) in w.iter_mut().enumerate() {
                    *x = a[i] & b[i];
                }
                Bits::from_words(w)
            }
        }
    }
    fn or(&self, o: &Bits) -> Bits {
        match (self, o) {
            (Bits::Full, _) | (_, Bits::Full) => Bits::Full,
            (Bits::Zero, x) | (x, Bits::Zero) => x.clone(),
            (Bits::Set(a), Bits::Set(b)) => {
                if Rc::ptr_eq(a, b) {
                    return self.clone();
                }
                let mut w = [0u64; 64];
                for (i, x) in w.iter_mut().enumerate() {
                    *x = a[i] | b[i];
                }
                Bits::from_words(w)
            }
        }
    }
    /// The members, ascending (`_bits`)
    fn members(&self) -> Vec<I> {
        match self {
            Bits::Full => (0..4096).collect(),
            Bits::Zero => vec![],
            Bits::Set(w) => {
                let mut out = Vec::new();
                for (i, &x) in w.iter().enumerate() {
                    let mut x = x;
                    while x != 0 {
                        let t = x.trailing_zeros() as usize;
                        out.push((i * 64 + t) as I);
                        x &= x - 1;
                    }
                }
                out
            }
        }
    }
}

struct BitsBuilder([u64; 64]);
impl BitsBuilder {
    fn new() -> Self {
        BitsBuilder([0; 64])
    }
    fn set(&mut self, b: I) {
        let b = (b & LOW) as usize;
        self.0[b >> 6] |= 1 << (b & 63);
    }
    fn set_range(&mut self, a: usize, b: usize) {
        // bits a..=b, a <= b < 4096
        for i in a..=b {
            self.0[i >> 6] |= 1 << (i & 63);
        }
    }
    fn done(self) -> Bits {
        Bits::from_words(self.0)
    }
}

/// The low-12-bit set of the values lo..hi
fn pattern(lo: I, hi: I) -> Bits {
    if hi < lo {
        return Bits::zero();
    }
    if hi - lo >= LOW {
        return Bits::full();
    }
    let (a, b) = ((lo & LOW) as usize, (hi & LOW) as usize);
    let mut bb = BitsBuilder::new();
    if a <= b {
        bb.set_range(a, b);
    } else {
        bb.set_range(0, b);
        bb.set_range(a, 4095);
    }
    bb.done()
}

// ---- values ----

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Op {
    W,
    And(I),
    Not(u32),
    Add(I, u32),
}

type RootId = u32;
type ChainId = u32;
type SetId = u32;

/// The Python's root tuples: `('seed', k, n, 64)`, `('z',)`, `('d', k, n, w)`, `('e', k, n, w)`, `('k', k, n, 64)`,
/// `('p', k, i, w)`, `('x', root, i, 64)` (detach), `('x', k, i', i, 64)` (join), `('r', root, chain, 64)`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum RootData {
    Seed(i64, u8),
    Z,
    D(i64, u8, u8),
    E(i64, u8, u8),
    K(i64, u8),
    P(i64, u8, u8),
    XD(RootId, u8),
    XJ(i64, u8, u8),
    R(RootId, ChainId),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Val {
    /// constants: the values and the numbers among them (a mov wrote them, not an adrp / adr)
    C(SetId, SetId),
    /// a root and a chain of operations
    S(RootId, ChainId),
    /// a table target: the load's instruction, the constants added, the shift
    T(u32, SetId, u32),
    /// unknown (`('?',)`)
    Q,
}

#[derive(Clone, Debug, PartialEq)]
struct Con {
    lo: I,
    hi: I,
    bits: Bits,
    lo32: I,
    hi32: I,
}

#[derive(Clone, Debug)]
struct Abs {
    lo: I,
    hi: I,
    bits: Bits,
}

impl Abs {
    fn new(lo: I, hi: I, bits: Bits) -> Abs {
        let bits = bits.and(&pattern(lo, hi));
        Abs { lo, hi, bits }
    }
    fn of(vals: impl IntoIterator<Item = I>) -> Abs {
        let (mut lo, mut hi, mut any) = (0, 0, false);
        let mut bb = BitsBuilder::new();
        for v in vals {
            if !any {
                lo = v;
                hi = v;
                any = true;
            } else {
                lo = lo.min(v);
                hi = hi.max(v);
            }
            bb.set(v);
        }
        if !any {
            return Abs::new(1, 0, Bits::zero());
        }
        Abs::new(lo, hi, bb.done())
    }
    fn empty(&self) -> bool {
        self.lo > self.hi || self.bits.is_zero()
    }
    fn members(&self) -> Option<Vec<I>> {
        if self.empty() {
            return Some(vec![]);
        }
        if self.hi - self.lo < ENUM {
            return Some((self.lo..=self.hi).filter(|&v| self.bits.has(v)).collect());
        }
        None
    }
    fn union(&self, o: &Abs) -> Abs {
        if self.empty() {
            return o.clone();
        }
        if o.empty() {
            return self.clone();
        }
        Abs::new(self.lo.min(o.lo), self.hi.max(o.hi), self.bits.or(&o.bits))
    }
    fn con(&self) -> Con {
        mk(self.lo, self.hi, &self.bits, 0, M32)
    }
}

/// A root's constraint (`_mk`)
fn mk(lo: I, hi: I, bs: &Bits, lo32: I, hi32: I) -> Con {
    let (mut lo, mut hi, mut lo32, mut hi32) = (lo, hi, lo32, hi32);
    if hi <= M32 {
        lo32 = lo32.max(lo);
        hi32 = hi32.min(hi);
        lo = lo32;
        hi = hi32;
    }
    let bits = bs.and(&pattern(lo, hi)).and(&pattern(lo32, hi32));
    Con {
        lo,
        hi,
        bits,
        lo32,
        hi32,
    }
}

fn cunion(a: &Con, b: &Con) -> Con {
    mk(
        a.lo.min(b.lo),
        a.hi.max(b.hi),
        &a.bits.or(&b.bits),
        a.lo32.min(b.lo32),
        a.hi32.max(b.hi32),
    )
}

fn apply(chain: &[Op], mut v: I) -> I {
    for op in chain {
        v = match *op {
            Op::W => v & M32,
            Op::And(m) => v & m,
            Op::Not(w) => !v & mask(w),
            Op::Add(a, w) => (v + a) & mask(w),
        };
    }
    v
}

fn masked(chain: &[Op]) -> bool {
    chain.iter().any(|op| matches!(op, Op::And(m) if *m <= LOW))
}

/// An upper bound of a chain's output for a root of width w (`_top`)
fn top(chain: &[Op], w: u32) -> I {
    let mut hi = mask(w);
    for op in chain {
        match *op {
            Op::W => hi = hi.min(M32),
            Op::And(m) => hi = hi.min(m),
            Op::Not(w) | Op::Add(_, w) => hi = mask(w),
        }
    }
    hi
}

/// The low-12-bit set of op's outputs for inputs with low bits in bs (`_image`)
fn image(bs: &Bits, op: Op) -> Bits {
    match op {
        Op::W | Op::Not(_) | Op::Add(..) if bs.is_full() => Bits::full(),
        Op::And(m) if bs.is_full() => Abs::of((0..4096).map(|b| b & m)).bits,
        _ => Abs::of(bs.members().into_iter().map(|b| apply(&[op], b) & LOW)).bits,
    }
}

// ---- tests of a guard ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cond {
    Eq,
    Ne,
    Hs,
    Lo,
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
    Nv,
}

fn cond_of(s: &str) -> Option<Cond> {
    Some(match s {
        "eq" => Cond::Eq,
        "ne" => Cond::Ne,
        "hs" | "cs" => Cond::Hs,
        "lo" | "cc" => Cond::Lo,
        "mi" => Cond::Mi,
        "pl" => Cond::Pl,
        "vs" => Cond::Vs,
        "vc" => Cond::Vc,
        "hi" => Cond::Hi,
        "ls" => Cond::Ls,
        "ge" => Cond::Ge,
        "lt" => Cond::Lt,
        "gt" => Cond::Gt,
        "le" => Cond::Le,
        "al" => Cond::Al,
        "nv" => Cond::Nv,
        _ => return None,
    })
}

/// `_cond`: the condition that holds of the compared value on this edge, its imm (masked) and width, and the interval
/// of the value it allows; None when it bounds nothing usable
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CmpTest {
    cond: Cond,
    imm: I,
    w: u32,
}

fn cond_test(cond: Cond, imm: I, w: u32, taken: bool) -> Option<(CmpTest, Option<(I, I)>)> {
    let m = mask(w);
    let imm = imm & m;
    let cond = if taken {
        cond
    } else {
        match cond {
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Hi => Cond::Ls,
            Cond::Ls => Cond::Hi,
            Cond::Hs => Cond::Lo,
            Cond::Lo => Cond::Hs,
            Cond::Gt => Cond::Le,
            Cond::Le => Cond::Gt,
            Cond::Ge => Cond::Lt,
            Cond::Lt => Cond::Ge,
            _ => return None,
        }
    };
    let t = CmpTest { cond, imm, w };
    let iv = match cond {
        Cond::Eq => Some((imm, imm)),
        Cond::Hi => Some((imm + 1, m)),
        Cond::Ls => Some((0, imm)),
        Cond::Hs => Some((imm, m)),
        Cond::Lo => Some((0, imm - 1)),
        Cond::Ne | Cond::Gt | Cond::Le | Cond::Ge | Cond::Lt => None,
        _ => return None,
    };
    Some((t, iv))
}

fn signed(x: I, w: u32) -> I {
    if x & (1 << (w - 1)) != 0 {
        x - (1 << w)
    } else {
        x
    }
}

/// The test a guard's edge makes of a value (`_pred` of its key)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pred {
    Cmp(CmpTest),
    Tst(I, bool),
    Bit(I, bool),
    Zero(bool),
}

impl Pred {
    fn test(&self, x: I) -> bool {
        match *self {
            Pred::Cmp(CmpTest { cond, imm, w }) => match cond {
                Cond::Eq => x == imm,
                Cond::Ne => x != imm,
                Cond::Hi => x > imm,
                Cond::Ls => x <= imm,
                Cond::Hs => x >= imm,
                Cond::Lo => x < imm,
                Cond::Gt => signed(x, w) > signed(imm, w),
                Cond::Le => signed(x, w) <= signed(imm, w),
                Cond::Ge => signed(x, w) >= signed(imm, w),
                Cond::Lt => signed(x, w) < signed(imm, w),
                _ => unreachable!("flag_edge refines only on a condition _cond reads"),
            },
            Pred::Tst(m, zero) => {
                if zero {
                    x & m == 0
                } else {
                    x & m != 0
                }
            }
            Pred::Bit(b, zero) => {
                let bit = shr(x, b) & 1;
                if zero { bit == 0 } else { bit != 0 }
            }
            Pred::Zero(zero) => {
                if zero {
                    x == 0
                } else {
                    x != 0
                }
            }
        }
    }
}

// ---- registers ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reg {
    Zr,
    X(u8, u32),
}

fn reg_of_name(n: &str) -> Option<Reg> {
    match n {
        "xzr" | "wzr" => return Some(Reg::Zr),
        "lr" => return Some(Reg::X(30, 64)),
        "fp" => return Some(Reg::X(29, 64)),
        _ => {}
    }
    let b = n.as_bytes();
    if b.len() >= 2 && (b[0] == b'x' || b[0] == b'w') && b[1..].iter().all(|c| c.is_ascii_digit()) {
        let v: u32 = n[1..].parse().ok()?;
        if v > 30 {
            return None; // not a general-purpose register number this analysis tracks (never printed by Capstone)
        }
        return Some(Reg::X(v as u8, if b[0] == b'x' { 64 } else { 32 }));
    }
    None
}

/// `_name(p.reg_name(id))` (cached by register id)
fn reg_id(id: u16) -> Option<Reg> {
    thread_local! {
        static T: std::cell::RefCell<HashMap<u16, Option<Reg>>> = std::cell::RefCell::new(HashMap::new());
    }
    T.with(|t| {
        *t.borrow_mut()
            .entry(id)
            .or_insert_with(|| reg_of_name(cs::reg_name(id)))
    })
}

/// `_reg(p, op)`
fn reg_op(op: &cs::Op) -> Option<Reg> {
    if op.ty != OP_REG {
        return None;
    }
    reg_id(op.reg)
}

fn imm_sh(op: &cs::Op) -> I {
    let v = op.imm as I;
    if op.shift_type() == SFT_LSL && op.shift_value != 0 {
        v << op.shift_value
    } else {
        v
    }
}

// ---- the arena of roots, chains and constant sets of one Function ----

#[derive(Default)]
struct Arena {
    roots: Vec<RootData>,
    root_ix: FxMap<RootData, RootId>,
    /// bit 0: the root holds an ('x', root, i, 64) somewhere; bit 1: an ('x', k, i', i, 64)
    root_x: Vec<u8>,
    chains: Vec<Rc<[Op]>>,
    chain_ix: FxMap<Rc<[Op]>, ChainId>,
    sets: Vec<Rc<[I]>>,
    set_ix: FxMap<Rc<[I]>, SetId>,
}

impl Arena {
    fn new() -> Arena {
        let mut a = Arena::default();
        a.chain(&[]);
        a
    }
    fn root(&mut self, r: RootData) -> RootId {
        if let Some(&id) = self.root_ix.get(&r) {
            return id;
        }
        let x = match r {
            RootData::XD(inner, _) => 1 | self.root_x[inner as usize],
            RootData::XJ(..) => 2,
            RootData::R(inner, _) => self.root_x[inner as usize],
            _ => 0,
        };
        let id = self.roots.len() as RootId;
        self.roots.push(r);
        self.root_x.push(x);
        self.root_ix.insert(r, id);
        id
    }
    fn chain(&mut self, c: &[Op]) -> ChainId {
        if let Some(&id) = self.chain_ix.get(c) {
            return id;
        }
        let rc: Rc<[Op]> = Rc::from(c);
        let id = self.chains.len() as ChainId;
        self.chains.push(rc.clone());
        self.chain_ix.insert(rc, id);
        id
    }
    fn chain_plus(&mut self, c: ChainId, op: Op) -> ChainId {
        let mut v = self.chains[c as usize].to_vec();
        v.push(op);
        self.chain(&v)
    }
    fn set(&mut self, mut v: Vec<I>) -> SetId {
        v.sort_unstable();
        v.dedup();
        if let Some(&id) = self.set_ix.get(&v[..]) {
            return id;
        }
        let rc: Rc<[I]> = Rc::from(v);
        let id = self.sets.len() as SetId;
        self.sets.push(rc.clone());
        self.set_ix.insert(rc, id);
        id
    }
    fn s(&self, id: SetId) -> Rc<[I]> {
        self.sets[id as usize].clone()
    }
    fn ch(&self, id: ChainId) -> Rc<[Op]> {
        self.chains[id as usize].clone()
    }
    /// `root[-1]` as a width (`('z',)` reads as 64: `_mask('z')` is M64)
    fn width(&self, r: RootId) -> u32 {
        match self.roots[r as usize] {
            RootData::D(_, _, w) | RootData::E(_, _, w) | RootData::P(_, _, w) => w as u32,
            _ => 64,
        }
    }
    fn default_con(&self, r: RootId) -> Con {
        let hi = if self.roots[r as usize] == RootData::Z {
            M64
        } else {
            mask(self.width(r))
        };
        Con {
            lo: 0,
            hi,
            bits: Bits::full(),
            lo32: 0,
            hi32: M32,
        }
    }
}

// ---- Python's ordering of the root tuples (only to find the TypeError of `State.key`'s sort) ----

#[derive(Clone, Copy)]
enum PyE {
    Str(&'static str),
    Int(I),
    Root(RootId),
    Chain(ChainId),
    Op(Op),
}

fn py_elems(a: &Arena, e: PyE) -> Vec<PyE> {
    use PyE::*;
    match e {
        Root(r) => match a.roots[r as usize] {
            RootData::Seed(k, n) => vec![Str("seed"), Int(k as I), Int(n as I), Int(64)],
            RootData::Z => vec![Str("z")],
            RootData::D(k, n, w) => vec![Str("d"), Int(k as I), Int(n as I), Int(w as I)],
            RootData::E(k, n, w) => vec![Str("e"), Int(k as I), Int(n as I), Int(w as I)],
            RootData::K(k, n) => vec![Str("k"), Int(k as I), Int(n as I), Int(64)],
            RootData::P(k, i, w) => vec![Str("p"), Int(k as I), Int(i as I), Int(w as I)],
            RootData::XD(r, i) => vec![Str("x"), Root(r), Int(i as I), Int(64)],
            RootData::XJ(k, pi, i) => {
                vec![Str("x"), Int(k as I), Int(pi as I), Int(i as I), Int(64)]
            }
            RootData::R(r, c) => vec![Str("r"), Root(r), Chain(c), Int(64)],
        },
        Chain(c) => a.chains[c as usize].iter().map(|&o| Op(o)).collect(),
        Op(o) => match o {
            self::Op::W => vec![Str("w")],
            self::Op::And(m) => vec![Str("and"), Int(m)],
            self::Op::Not(w) => vec![Str("not"), Int(w as I)],
            self::Op::Add(x, w) => vec![Str("add"), Int(x), Int(w as I)],
        },
        _ => vec![],
    }
}

fn py_eq(a: &Arena, x: PyE, y: PyE) -> bool {
    use PyE::*;
    match (x, y) {
        (Str(p), Str(q)) => p == q,
        (Int(p), Int(q)) => p == q,
        (Root(p), Root(q)) => p == q,
        (Chain(p), Chain(q)) => p == q,
        (Op(p), Op(q)) => p == q,
        (Str(_), _) | (_, Str(_)) | (Int(_), _) | (_, Int(_)) => false,
        // tuples of different kinds: equal when their items are
        _ => {
            let (u, v) = (py_elems(a, x), py_elems(a, y));
            u.len() == v.len() && u.iter().zip(&v).all(|(&p, &q)| py_eq(a, p, q))
        }
    }
}

fn py_type(e: PyE) -> &'static str {
    match e {
        PyE::Str(_) => "str",
        PyE::Int(_) => "int",
        _ => "tuple",
    }
}

/// `x < y` with Python's semantics; Err(the TypeError's message) when the two cannot be ordered
fn py_lt(a: &Arena, x: PyE, y: PyE) -> Result<bool, String> {
    use PyE::*;
    match (x, y) {
        (Str(p), Str(q)) => Ok(p < q),
        (Int(p), Int(q)) => Ok(p < q),
        (Str(_), _) | (_, Str(_)) | (Int(_), _) | (_, Int(_)) => Err(format!(
            "'<' not supported between instances of '{}' and '{}'",
            py_type(x),
            py_type(y)
        )),
        _ => {
            let (u, v) = (py_elems(a, x), py_elems(a, y));
            let mut i = 0;
            while i < u.len() && i < v.len() && py_eq(a, u[i], v[i]) {
                i += 1;
            }
            if i >= u.len() || i >= v.len() {
                return Ok(u.len() < v.len());
            }
            py_lt(a, u[i], v[i])
        }
    }
}

/// CPython's `list.sort` of `sorted(self.cons.items())` (fewer than 64 items: count_run, then binary insertion), only
/// to know whether it raises; the items are (root, constraint) with distinct roots, so only roots are compared
fn py_sort_check(a: &Arena, keys: &[RootId]) -> Result<(), String> {
    let n = keys.len();
    if n < 2 {
        return Ok(());
    }
    let lt = |x: RootId, y: RootId| py_lt(a, PyE::Root(x), PyE::Root(y));
    let mut v: Vec<RootId> = keys.to_vec();
    // count_run
    let mut r = 1;
    while r < n {
        if lt(v[r], v[r - 1])? {
            break;
        }
        r += 1;
    }
    if r < n {
        let mut ascending_done = false;
        if r > 1 {
            if lt(v[0], v[r - 1])? {
                ascending_done = true;
            } else {
                v[..r].reverse();
            }
        }
        if !ascending_done {
            r += 1;
            let mut neq = 0usize;
            while r < n {
                if lt(v[r], v[r - 1])? {
                    if neq > 0 {
                        neq += 1;
                        v[r - neq..r].reverse();
                        neq = 0;
                    }
                } else if lt(v[r - 1], v[r])? {
                    break;
                } else {
                    neq += 1;
                }
                r += 1;
            }
            if neq > 0 {
                neq += 1;
                v[r - neq..r].reverse();
            }
            v[..r].reverse();
            while r < n {
                if lt(v[r], v[r - 1])? {
                    break;
                }
                r += 1;
            }
        }
    }
    if r < n {
        // binarysort(v, n, ok = r)
        let mut ok = r.max(1);
        while ok < n {
            let pivot = v[ok];
            let (mut l, mut rr) = (0usize, ok);
            while l < rr {
                let m = (l + rr) >> 1;
                if lt(pivot, v[m])? {
                    rr = m;
                } else {
                    l = m + 1;
                }
            }
            v.copy_within(l..ok, l + 1);
            v[l] = pivot;
            ok += 1;
        }
    }
    Ok(())
}

// ---- states ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlagKind {
    Cmp,
    Tst,
}

/// The last compare: (kind, value, imm, width, register)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Flags {
    kind: FlagKind,
    v: Val,
    imm: I,
    w: u32,
    n: u8,
}

#[derive(Clone, Debug)]
struct State {
    regs: [Val; 31],
    /// root -> constraint, in the insertion order of the Python dict
    cons: Vec<(RootId, Con)>,
    flags: Option<Flags>,
}

impl State {
    fn get(&self, r: RootId) -> Option<&Con> {
        self.cons.iter().find(|(k, _)| *k == r).map(|(_, c)| c)
    }
    fn con(&self, a: &Arena, r: RootId) -> Con {
        self.get(r).cloned().unwrap_or_else(|| a.default_con(r))
    }
    fn set_con(&mut self, r: RootId, c: Con) {
        if let Some(e) = self.cons.iter_mut().find(|(k, _)| *k == r) {
            e.1 = c;
        } else {
            self.cons.push((r, c));
        }
    }
    fn tidy(&mut self, a: &Arena) {
        if self.cons.is_empty() {
            return;
        }
        let (mut live, mut n) = ([0 as RootId; 32], 0);
        for v in &self.regs {
            if let Val::S(r, _) = v {
                live[n] = *r;
                n += 1;
            }
        }
        if let Some(f) = &self.flags
            && let Val::S(r, _) = f.v
        {
            live[n] = r;
            n += 1;
        }
        let live = &live[..n];
        self.cons
            .retain(|(r, c)| live.contains(r) && *c != a.default_con(*r));
    }
    /// `State.key()`'s sort: the TypeError it raises, if any
    fn key_check(&self, a: &Arena) -> R<()> {
        let x = self
            .cons
            .iter()
            .fold(0u8, |m, (r, _)| m | a.root_x[*r as usize]);
        if x != 3 {
            return Ok(()); // only roots of both 'x' shapes can be unordered
        }
        let keys: Vec<RootId> = self.cons.iter().map(|(r, _)| *r).collect();
        py_sort_check(a, &keys).map_err(Stop::Fatal)
    }
    fn same_key(&self, o: &State) -> bool {
        self.regs == o.regs
            && self.flags == o.flags
            && self.cons.len() == o.cons.len()
            && self.cons.iter().all(|(r, c)| o.get(*r) == Some(c))
    }
}

/// `new.key() != old.key()`: new's key is made first, then old's (either sort may raise)
fn key_differs(a: &Arena, new: &State, old: &State) -> R<bool> {
    new.key_check(a)?;
    old.key_check(a)?;
    Ok(!new.same_key(old))
}

// ---- instructions ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mn {
    Trap,
    Ret,
    B,
    BCond(Cond),
    Cbz,
    Cbnz,
    Tbz,
    Tbnz,
    Bl,
    Blr,
    Svc,
    Brs,
    Br,
    Cmp,
    Cmn,
    Tst,
    Subs,
    Adds,
    Ands,
    Cset,
    Csetm,
    Adrp,
    Mov,
    Add,
    Sub,
    And,
    Mvn,
    Uxtb,
    Uxth,
    Ubfx,
    Lsr,
    Sxtw,
    Cinc,
    Csinc,
    Csel,
    /// a table load: entry size and signedness
    Load(u8, bool),
    Nop,
    Udf,
    Other,
}

fn mn_of(m: &str) -> Mn {
    match m {
        "brk" | "hlt" | "eret" | "drps" | "eretaa" | "eretab" => Mn::Trap,
        "udf" => Mn::Udf,
        "ret" | "retaa" | "retab" => Mn::Ret,
        "b" => Mn::B,
        "cbz" => Mn::Cbz,
        "cbnz" => Mn::Cbnz,
        "tbz" => Mn::Tbz,
        "tbnz" => Mn::Tbnz,
        "bl" => Mn::Bl,
        "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => Mn::Blr,
        "svc" | "hvc" | "smc" => Mn::Svc,
        "braa" | "brab" | "braaz" | "brabz" => Mn::Brs,
        "br" => Mn::Br,
        "cmp" => Mn::Cmp,
        "cmn" => Mn::Cmn,
        "tst" => Mn::Tst,
        "subs" => Mn::Subs,
        "adds" => Mn::Adds,
        "ands" => Mn::Ands,
        "cset" => Mn::Cset,
        "csetm" => Mn::Csetm,
        "adrp" | "adr" => Mn::Adrp,
        "mov" => Mn::Mov,
        "add" => Mn::Add,
        "sub" => Mn::Sub,
        "and" => Mn::And,
        "mvn" => Mn::Mvn,
        "uxtb" => Mn::Uxtb,
        "uxth" => Mn::Uxth,
        "ubfx" => Mn::Ubfx,
        "lsr" => Mn::Lsr,
        "sxtw" => Mn::Sxtw,
        "cinc" => Mn::Cinc,
        "csinc" => Mn::Csinc,
        "csel" => Mn::Csel,
        "ldrsw" => Mn::Load(4, true),
        "ldrb" => Mn::Load(1, false),
        "ldrsb" => Mn::Load(1, true),
        "ldrh" => Mn::Load(2, false),
        "ldrsh" => Mn::Load(2, true),
        "nop" => Mn::Nop,
        _ => match m.strip_prefix("b.").and_then(cond_of) {
            Some(c) => Mn::BCond(c),
            None => Mn::Other,
        },
    }
}

fn is_trap(m: Mn) -> bool {
    matches!(m, Mn::Trap | Mn::Udf)
}

/// The table load's mnemonic of a 't' value's instruction
fn load_of(m: Mn) -> (u8, bool) {
    match m {
        Mn::Load(s, sg) => (s, sg),
        _ => unreachable!("a table target comes from a table load"),
    }
}

struct Func<'a> {
    insl: &'a [Ins],
    mns: &'a [Mn],
    img: &'a [u8],
    consts: bool,
    at: &'a FxMap<i64, usize>,
    leaders: Vec<bool>,
    /// (call address, state after the call) once `run` has started
    calls: Vec<(i64, State)>,
    /// how many calls `run` stepped (`len(self.calls)` of the Python)
    ncalls: usize,
    /// landing pad index -> call ranges, in the order given
    landing: Vec<(usize, Vec<(i64, i64)>)>,
    reached: Vec<bool>,
    /// {br address: targets} of the last round
    edges_out: BTreeMap<i64, Vec<i64>>,
    a: Arena,
    zero: Val,
    zroot: RootId,
    empty: ChainId,
}

type Loads = HashMap<usize, Vec<(Option<SetId>, Option<Abs>)>>;
/// insertion-ordered {br address: value}
type Found = Vec<(i64, Vec<i64>)>;
type Failed = Vec<(i64, String)>;

fn dict_set<V>(d: &mut Vec<(i64, V)>, k: i64, v: V) {
    if let Some(e) = d.iter_mut().find(|(x, _)| *x == k) {
        e.1 = v;
    } else {
        d.push((k, v));
    }
}

impl<'a> Func<'a> {
    fn new(
        insl: &'a [Ins],
        mns: &'a [Mn],
        img: &'a [u8],
        consts: bool,
        at: &'a FxMap<i64, usize>,
    ) -> Func<'a> {
        let mut a = Arena::new();
        let zs = a.set(vec![0]);
        let zroot = a.root(RootData::Z);
        Func {
            insl,
            mns,
            img,
            consts,
            at,
            leaders: vec![false; insl.len()],
            calls: Vec::new(),
            ncalls: 0,
            landing: Vec::new(),
            reached: vec![false; insl.len()],
            edges_out: BTreeMap::new(),
            a,
            zero: Val::C(zs, zs),
            zroot,
            empty: 0,
        }
    }

    fn set_of(&self, id: SetId) -> Rc<[I]> {
        self.a.s(id)
    }

    // -- values --

    fn eval(&self, st: &State, v: Val) -> Option<Abs> {
        match v {
            Val::C(vs, _) => Some(Abs::of(self.set_of(vs).iter().copied())),
            Val::S(root, chain) => {
                let chain = self.a.ch(chain);
                let Con {
                    mut lo,
                    mut hi,
                    bits,
                    lo32,
                    hi32,
                } = st.con(&self.a, root);
                let mut bs = bits;
                if masked(&chain) {
                    let a = Abs::of(bs.members().into_iter().map(|b| apply(&chain, b)));
                    return Some(Abs::new(a.lo, a.hi, a.bits));
                }
                if hi - lo < ENUM {
                    return Some(Abs::of(
                        (lo..=hi).filter(|&x| bs.has(x)).map(|x| apply(&chain, x)),
                    ));
                }
                let low32 = chain.first() == Some(&Op::W);
                if low32 && hi32 - lo32 < ENUM {
                    return Some(Abs::of(
                        (lo32..=hi32)
                            .filter(|&x| bs.has(x))
                            .map(|x| apply(&chain, x)),
                    ));
                }
                for (i, op) in chain.iter().enumerate() {
                    match *op {
                        Op::W => {
                            if hi <= M32 {
                            } else if i == 0 {
                                lo = lo32;
                                hi = hi32;
                            } else {
                                lo = 0;
                                hi = M32;
                            }
                        }
                        Op::And(m) => {
                            lo = 0;
                            hi = hi.min(m);
                        }
                        Op::Not(w) => {
                            let m = mask(w);
                            if hi <= m {
                                (lo, hi) = (m - hi, m - lo);
                            } else {
                                (lo, hi) = (0, m);
                            }
                        }
                        Op::Add(x, w) => {
                            let m = mask(w);
                            if 0 <= lo + x && hi + x <= m {
                                (lo, hi) = (lo + x, hi + x);
                            } else {
                                (lo, hi) = (0, m);
                            }
                        }
                    }
                    bs = image(&bs, *op);
                }
                Some(Abs::new(lo, hi, bs))
            }
            _ => None,
        }
    }

    /// `_filter`: the low-12-bit patterns of bs whose output through chain passes the test
    fn filter(chain: &[Op], bs: &Bits, pred: Pred, low: bool) -> Bits {
        let mut bb = BitsBuilder::new();
        for b in bs.members() {
            let y = apply(chain, b);
            if pred.test(if low { y & LOW } else { y }) {
                bb.set(b);
            }
        }
        bb.done()
    }

    /// `_refine`: narrow v (held by register reg) to the values that pass the test; false when the edge cannot be taken
    fn refine(
        &mut self,
        st: &mut State,
        v: Val,
        reg: Option<u8>,
        pred: Pred,
        interval: Option<(I, I)>,
        low: bool,
    ) -> bool {
        match v {
            Val::C(vs, ns) => {
                let keep: Vec<I> = self
                    .set_of(vs)
                    .iter()
                    .copied()
                    .filter(|&x| pred.test(x))
                    .collect();
                if keep.is_empty() {
                    return false;
                }
                if let Some(r) = reg
                    && st.regs[r as usize] == v
                {
                    let nums: Vec<I> = self
                        .set_of(ns)
                        .iter()
                        .copied()
                        .filter(|x| keep.contains(x))
                        .collect();
                    let (k, n) = (self.a.set(keep), self.a.set(nums));
                    st.regs[r as usize] = Val::C(k, n);
                }
                true
            }
            Val::S(root, chain_id) => {
                let chain = self.a.ch(chain_id);
                let Con {
                    mut lo,
                    mut hi,
                    bits,
                    mut lo32,
                    mut hi32,
                } = st.con(&self.a, root);
                let mut bs = bits;
                if masked(&chain) {
                    bs = Self::filter(&chain, &bs, pred, false);
                } else if hi - lo < ENUM {
                    let keep: Vec<I> = (lo..=hi)
                        .filter(|&x| bs.has(x) && pred.test(apply(&chain, x)))
                        .collect();
                    if keep.is_empty() {
                        return false;
                    }
                    let a = Abs::of(keep);
                    (lo, hi, bs) = (a.lo, a.hi, a.bits);
                } else if chain.first() == Some(&Op::W) && hi32 - lo32 < ENUM {
                    let keep: Vec<I> = (lo32..=hi32)
                        .filter(|&x| bs.has(x) && pred.test(apply(&chain, x)))
                        .collect();
                    if keep.is_empty() {
                        return false;
                    }
                    let a = Abs::of(keep);
                    (lo32, hi32, bs) = (a.lo, a.hi, a.bits);
                } else {
                    if low {
                        bs = Self::filter(&chain, &bs, pred, true);
                    }
                    if let Some((plo0, phi0)) = interval {
                        let (mut plo, mut phi) = (plo0, phi0);
                        let mut ok = true;
                        for i in (0..chain.len()).rev() {
                            match chain[i] {
                                Op::W => {
                                    if i == 0 && hi <= M32 {
                                        continue;
                                    }
                                    if i == 0 {
                                        lo32 = lo32.max(plo);
                                        hi32 = hi32.min(phi);
                                        (plo, phi) = (0, M64);
                                        break;
                                    }
                                    if top(&chain[..i], self.a.width(root)) > M32 {
                                        ok = false;
                                        break;
                                    }
                                }
                                Op::Not(w) => {
                                    let m = mask(w);
                                    (plo, phi) = (m - phi, m - plo);
                                }
                                Op::Add(x, w) => {
                                    let m = mask(w);
                                    if plo - x < 0 || phi - x > m {
                                        ok = false;
                                        break;
                                    }
                                    (plo, phi) = (plo - x, phi - x);
                                }
                                Op::And(_) => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            lo = lo.max(plo);
                            hi = hi.min(phi);
                        } else {
                            // the chain cannot be undone: the registers holding exactly this value get it as a root of
                            // its own, narrowed
                            let Some(a) = self.eval(st, v) else {
                                return true;
                            };
                            let (lo2, hi2) = (a.lo.max(plo0), a.hi.min(phi0));
                            if lo2 > hi2 || a.bits.and(&pattern(lo2, hi2)).is_zero() {
                                return false;
                            }
                            let own = self.a.root(RootData::R(root, chain_id));
                            let nv = Val::S(own, self.empty);
                            for r in st.regs.iter_mut() {
                                if *r == v {
                                    *r = nv;
                                }
                            }
                            st.set_con(own, mk(lo2, hi2, &a.bits, 0, M32));
                            if let Some(f) = &mut st.flags
                                && f.v == v
                            {
                                f.v = nv;
                            }
                            return true;
                        }
                    }
                }
                let c = mk(lo, hi, &bs, lo32, hi32);
                if c.lo > c.hi || c.lo32 > c.hi32 || c.bits.is_zero() {
                    return false;
                }
                st.set_con(root, c);
                true
            }
            _ => true,
        }
    }

    /// `_addresses`: the constants of a 'c' value that can be a table's base (a number inside page zero cannot)
    fn addresses(&mut self, vs: SetId, ns: SetId) -> SetId {
        let (v, n) = (self.set_of(vs), self.set_of(ns));
        let keep: Vec<I> = v
            .iter()
            .copied()
            .filter(|x| !n.contains(x) || *x >= 0x1000)
            .collect();
        self.a.set(keep)
    }

    fn detach(&mut self, st: &mut State, root: RootId, n: u8) {
        let stale = |a: &Arena, r: RootId| {
            r == root || matches!(a.roots[r as usize], RootData::R(inner, _) if inner == root)
        };
        for i in 0..31 {
            if let Val::S(r, c) = st.regs[i]
                && stale(&self.a, r)
                && (i != n as usize || r != root)
            {
                let old = self.a.root(RootData::XD(r, i as u8));
                st.regs[i] = Val::S(old, c);
                if let Some(cn) = st.get(r).cloned() {
                    st.set_con(old, cn);
                }
            }
        }
        if let Some(f) = &st.flags
            && let Val::S(r, _) = f.v
            && stale(&self.a, r)
        {
            st.flags = None;
        }
        let a = &self.a;
        st.cons.retain(|(r, _)| !stale(a, *r));
    }

    fn fresh(&mut self, st: &mut State, k: usize, n: u8, w: u32) -> Val {
        let root = self.a.root(RootData::D(k as i64, n, w as u8));
        self.detach(st, root, n);
        Val::S(root, self.empty)
    }

    fn trunc(&mut self, v: Val) -> Option<Val> {
        match v {
            Val::C(vs, ns) => {
                let a: Vec<I> = self.set_of(vs).iter().map(|x| x & M32).collect();
                let b: Vec<I> = self.set_of(ns).iter().map(|x| x & M32).collect();
                Some(Val::C(self.a.set(a), self.a.set(b)))
            }
            Val::S(root, chain) => {
                if top(&self.a.ch(chain), self.a.width(root)) <= M32 {
                    Some(v)
                } else {
                    Some(Val::S(root, self.a.chain_plus(chain, Op::W)))
                }
            }
            _ => None,
        }
    }

    fn val(&mut self, st: &State, r: Reg) -> Val {
        match r {
            Reg::Zr => {
                if self.consts {
                    self.zero
                } else {
                    Val::S(self.zroot, self.empty)
                }
            }
            Reg::X(n, w) => {
                let v = st.regs[n as usize];
                if w == 32 {
                    self.trunc(v).unwrap_or(Val::Q)
                } else {
                    v
                }
            }
        }
    }

    /// The value r reads, for a value derived from it: a register holding a few small numbers gets a root of its own
    /// holding exactly them
    fn linked(&mut self, st: &mut State, k: usize, r: Reg) -> Val {
        if let Reg::X(n, _) = r
            && let v @ Val::C(vs, ns) = st.regs[n as usize]
            && vs == ns
            && self
                .set_of(vs)
                .iter()
                .copied()
                .max()
                .is_some_and(|m| m < ENUM)
        {
            let root = self.a.root(RootData::K(k as i64, n));
            self.detach(st, root, n);
            st.regs[n as usize] = Val::S(root, self.empty);
            st.set_con(root, Abs::of(self.set_of(vs).iter().copied()).con());
            if let Some(f) = &st.flags
                && f.n == n
                && f.v == v
            {
                st.flags = None;
            }
        }
        self.val(st, r)
    }

    fn put(&mut self, st: &mut State, d: (u8, u32), v: Val) {
        let (n, w) = d;
        let v = if w == 32 && matches!(v, Val::C(..) | Val::S(..)) {
            self.trunc(v).unwrap()
        } else {
            v
        };
        if let Some(f) = &st.flags
            && f.n == n
            && !matches!(f.v, Val::S(..))
        {
            st.flags = None;
        }
        st.regs[n as usize] = v;
    }

    fn op(&mut self, st: &mut State, k: usize, d: (u8, u32), src: Val, op: Op) {
        match src {
            Val::C(vs, ns) => {
                let a: Vec<I> = self.set_of(vs).iter().map(|&x| apply(&[op], x)).collect();
                let b: Vec<I> = self.set_of(ns).iter().map(|&x| apply(&[op], x)).collect();
                let v = Val::C(self.a.set(a), self.a.set(b));
                self.put(st, d, v)
            }
            Val::S(root, chain) => {
                let c = self.a.chain_plus(chain, op);
                self.put(st, d, Val::S(root, c))
            }
            _ => {
                let v = self.fresh(st, k, d.0, d.1);
                self.put(st, d, v)
            }
        }
    }

    fn unknown(&mut self, st: &mut State, k: usize) {
        let p = &self.insl[k];
        let ws: Vec<u16> = match &p.regs {
            Some((_, w)) => w.to_vec(),
            None => vec![],
        };
        for id in ws {
            if let Some(Reg::X(n, w)) = reg_id(id) {
                let v = self.fresh(st, k, n, w);
                self.put(st, (n, w), v);
            }
        }
    }

    fn clobber(&mut self, st: &mut State, k: usize) {
        for n in (0..19u8).chain([30u8]) {
            st.regs[n as usize] = self.fresh(st, k, n, 64);
        }
        st.flags = None;
    }

    // -- instructions --

    fn nxt(&self, k: usize) -> Option<usize> {
        (k + 1 < self.insl.len() && self.insl[k + 1].address == self.insl[k].address + 4)
            .then_some(k + 1)
    }

    /// Run instruction k on st: [(successor instruction, its state)]
    fn step(
        &mut self,
        mut st: State,
        k: usize,
        edges: &HashMap<usize, Vec<i64>>,
        loads: &mut Loads,
        record_calls: bool,
    ) -> R<Vec<(usize, State)>> {
        let p = &self.insl[k];
        let m = self.mns[k];
        let nxt = self.nxt(k);
        match m {
            Mn::Trap | Mn::Udf | Mn::Ret => return Ok(vec![]),
            Mn::B => {
                return Ok(match self.at.get(&p.ops[0].imm) {
                    Some(&t) => vec![(t, st)],
                    None => vec![],
                });
            }
            Mn::BCond(c) => {
                let mut out = Vec::new();
                for (taken, dest) in [(true, self.at.get(&p.ops[0].imm).copied()), (false, nxt)] {
                    let Some(dest) = dest else { continue };
                    let mut s2 = st.clone();
                    if s2.flags.is_some() && !self.flag_edge(&mut s2, c, taken) {
                        continue;
                    }
                    out.push((dest, s2));
                }
                return Ok(out);
            }
            Mn::Cbz | Mn::Cbnz | Mn::Tbz | Mn::Tbnz => {
                let r = reg_op(&p.ops[0]);
                let v = match r {
                    Some(r) => self.val(&st, r),
                    None => Val::Q,
                };
                let last = p.ops.last().map(|o| o.imm).unwrap_or(0);
                let mut out = Vec::new();
                for (taken, dest) in [(true, self.at.get(&last).copied()), (false, nxt)] {
                    let Some(dest) = dest else { continue };
                    let mut s2 = st.clone();
                    let zero = matches!(m, Mn::Cbz | Mn::Tbz) == taken;
                    let n = match r {
                        Some(Reg::X(n, _)) => Some(n),
                        _ => None,
                    };
                    let ok = if matches!(m, Mn::Cbz | Mn::Cbnz) {
                        self.refine(
                            &mut s2,
                            v,
                            n,
                            Pred::Zero(zero),
                            if zero { Some((0, 0)) } else { None },
                            false,
                        )
                    } else {
                        let b = p.ops[1].imm as I;
                        let w = match r {
                            Some(Reg::X(_, w)) => w as I,
                            _ => 64,
                        };
                        let iv = if zero && b == w - 1 {
                            Some((0, (1 << b) - 1))
                        } else {
                            None
                        };
                        self.refine(&mut s2, v, n, Pred::Bit(b, zero), iv, b < 12)
                    };
                    if ok {
                        out.push((dest, s2));
                    }
                }
                return Ok(out);
            }
            Mn::Bl | Mn::Blr | Mn::Svc => {
                self.clobber(&mut st, k);
                if matches!(m, Mn::Bl | Mn::Blr) && record_calls {
                    // the state after the call is only read by the landing pads: without any, only the count is kept
                    self.ncalls += 1;
                    if !self.landing.is_empty() {
                        self.calls.push((p.address, st.clone()));
                    }
                }
                return Ok(nxt.map(|n| vec![(n, st)]).unwrap_or_default());
            }
            Mn::Brs => return Ok(vec![]),
            Mn::Br => {
                let mut out = Vec::new();
                if let Some(ts) = edges.get(&k) {
                    for t in ts {
                        if let Some(&i) = self.at.get(t) {
                            out.push((i, st.clone()));
                        }
                    }
                }
                return Ok(out);
            }
            _ => {}
        }
        if [GRP_JUMP, GRP_CALL, GRP_RET, GRP_INT]
            .iter()
            .any(|&g| p.group(g))
        {
            return Err(Stop::Unsupported(format!("{} at {:#x}", p.mn(), p.address)));
        }
        self.data(&mut st, k, loads);
        Ok(nxt.map(|n| vec![(n, st)]).unwrap_or_default())
    }

    fn flag_edge(&mut self, st: &mut State, cond: Cond, taken: bool) -> bool {
        let f = st.flags.unwrap();
        if f.kind == FlagKind::Tst {
            if !matches!(cond, Cond::Eq | Cond::Ne) {
                return true;
            }
            let zero = (cond == Cond::Eq) == taken;
            return self.refine(
                st,
                f.v,
                Some(f.n),
                Pred::Tst(f.imm, zero),
                None,
                f.imm <= LOW,
            );
        }
        let Some((t, iv)) = cond_test(cond, f.imm, f.w, taken) else {
            return true;
        };
        if let Some((a, b)) = iv
            && a > b
        {
            return false;
        }
        self.refine(st, f.v, Some(f.n), Pred::Cmp(t), iv, false)
    }

    fn data(&mut self, st: &mut State, k: usize, loads: &mut Loads) {
        let insl = self.insl;
        let p = &insl[k];
        let m = self.mns[k];
        let ops = p.ops.as_slice();
        if ops.is_empty() {
            return self.unknown(st, k);
        }
        let dst = reg_op(&ops[0]);
        let dreg = match dst {
            Some(Reg::X(n, w)) => Some((n, w)),
            _ => None,
        };
        if matches!(
            m,
            Mn::Cmp | Mn::Cmn | Mn::Tst | Mn::Subs | Mn::Adds | Mn::Ands
        ) {
            let mut flags = None;
            let three = matches!(m, Mn::Subs | Mn::Adds | Mn::Ands);
            let a = if three { ops.get(1) } else { ops.first() };
            let r = if ops.len() >= 2 {
                a.and_then(reg_op)
            } else {
                None
            };
            let want = if three { 3 } else { 2 };
            if let Some(r @ Reg::X(rn, rw)) = r
                && ops.last().unwrap().ty == OP_IMM
                && ops.len() == want
            {
                let v = if three {
                    self.linked(st, k, r)
                } else {
                    self.val(st, r)
                };
                let imm = imm_sh(ops.last().unwrap());
                let (kind, fimm) = match m {
                    Mn::Cmp | Mn::Subs => (FlagKind::Cmp, imm),
                    Mn::Cmn | Mn::Adds => (FlagKind::Cmp, -imm & mask(rw)),
                    _ => (FlagKind::Tst, imm),
                };
                flags = Some(Flags {
                    kind,
                    v,
                    imm: fimm,
                    w: rw,
                    n: rn,
                });
                if three && let Some(d) = dreg {
                    let op = match m {
                        Mn::Ands => Op::And(imm),
                        Mn::Adds => Op::Add(imm, d.1),
                        _ => Op::Add(-imm, d.1),
                    };
                    self.op(st, k, d, v, op);
                }
            } else if three {
                self.unknown(st, k);
            }
            st.flags = flags;
            return;
        }
        let sets = p.update_flags;
        if matches!(m, Mn::Cset | Mn::Csetm)
            && let Some(d) = dreg
        {
            let x = vec![0, if m == Mn::Cset { 1 } else { mask(d.1) }];
            if !self.consts {
                let nv = self.fresh(st, k, d.0, d.1);
                if let Val::S(r, _) = nv {
                    st.set_con(r, Abs::of(x.iter().copied()).con());
                }
                return self.put(st, d, nv);
            }
            let s = self.a.set(x);
            return self.put(st, d, Val::C(s, s));
        }
        let Some(d) = dreg else {
            self.unknown(st, k);
            if sets {
                st.flags = None;
            }
            return;
        };
        if m == Mn::Adrp {
            let s = self.a.set(vec![ops[1].imm as I]);
            let e = self.a.set(vec![]);
            return self.put(st, d, Val::C(s, e));
        }
        if m == Mn::Mov && ops.len() == 2 {
            if ops[1].ty == OP_IMM || reg_op(&ops[1]) == Some(Reg::Zr) {
                if !self.consts {
                    let v = self.fresh(st, k, d.0, d.1);
                    return self.put(st, d, v);
                }
                let x = (if ops[1].ty == OP_IMM {
                    ops[1].imm as I
                } else {
                    0
                }) & mask(d.1);
                let s = self.a.set(vec![x]);
                return self.put(st, d, Val::C(s, s));
            }
            if let Some(r) = reg_op(&ops[1])
                && ops[1].shift_value == 0
            {
                let v = self.linked(st, k, r);
                let v = if v != Val::Q {
                    v
                } else {
                    self.fresh(st, k, d.0, d.1)
                };
                return self.put(st, d, v);
            }
        }
        let src = if ops.len() > 1 { reg_op(&ops[1]) } else { None };
        if let Some(src) = src
            && !sets
        {
            let v = self.linked(st, k, src);
            if v != Val::Q {
                if matches!(m, Mn::Add | Mn::Sub) && ops.len() == 3 && ops[2].ty == OP_IMM {
                    let x = imm_sh(&ops[2]) * if m == Mn::Add { 1 } else { -1 };
                    return self.op(st, k, d, v, Op::Add(x, d.1));
                }
                if m == Mn::And && ops.len() == 3 && ops[2].ty == OP_IMM {
                    let imm = imm_sh(&ops[2]);
                    return self.op(st, k, d, v, if imm == M32 { Op::W } else { Op::And(imm) });
                }
                if m == Mn::Mvn && ops.len() == 2 && ops[1].shift_value == 0 {
                    return self.op(st, k, d, v, Op::Not(d.1));
                }
                if matches!(m, Mn::Uxtb | Mn::Uxth) && ops.len() == 2 {
                    return self.op(
                        st,
                        k,
                        d,
                        v,
                        Op::And(if m == Mn::Uxtb { 0xff } else { 0xffff }),
                    );
                }
                if m == Mn::Ubfx && ops.len() == 4 && ops[2].imm == 0 {
                    return self.op(st, k, d, v, Op::And(pow2(ops[3].imm) - 1));
                }
                if (m == Mn::Lsr && ops.len() == 3 && ops[2].ty == OP_IMM)
                    || (m == Mn::Ubfx && ops.len() == 4)
                {
                    let s = ops[2].imm as I;
                    let topv = if m == Mn::Lsr {
                        shr(mask(d.1), s)
                    } else {
                        pow2(ops[3].imm) - 1
                    };
                    let a = self.eval(st, v);
                    let nv = self.fresh(st, k, d.0, d.1);
                    let (lo, hi) = match (&a, m) {
                        (Some(a), Mn::Lsr) => (shr(a.lo, s), shr(a.hi, s).min(topv)),
                        _ => (0, topv),
                    };
                    if let Val::S(r, _) = nv {
                        st.set_con(r, mk(lo, hi, &pattern(lo, hi), 0, M32));
                    }
                    return self.put(st, d, nv);
                }
                if m == Mn::Sxtw && ops.len() == 2 {
                    let a = self.eval(st, v);
                    let nv = if a.is_some_and(|a| a.hi <= 0x7fffffff) {
                        v
                    } else {
                        self.fresh(st, k, d.0, d.1)
                    };
                    return self.put(st, d, nv);
                }
                if matches!(m, Mn::Cinc | Mn::Csinc) && matches!(ops.len(), 2 | 3) {
                    let rb = if ops.len() == 3 {
                        reg_op(&ops[2])
                    } else {
                        Some(src)
                    };
                    if let Some(rb) = rb {
                        let vb = self.linked(st, k, rb);
                        let w_ = d.1;
                        let (a, b) = (self.eval(st, v), self.eval(st, vb));
                        let nv = self.fresh(st, k, d.0, w_);
                        if let (Some(a), Some(b)) = (a, b)
                            && b.hi < mask(w_)
                        {
                            let u = a.union(&Abs::new(
                                b.lo + 1,
                                b.hi + 1,
                                image(&b.bits, Op::Add(1, w_)),
                            ));
                            if let Val::S(r, _) = nv {
                                st.set_con(r, u.con());
                            }
                        }
                        return self.put(st, d, nv);
                    }
                }
                if m == Mn::Csel
                    && ops.len() == 3
                    && let Some(rb) = reg_op(&ops[2])
                {
                    let vb = self.val(st, rb);
                    if v == vb {
                        return self.put(st, d, v);
                    }
                    if let (Val::C(a1, a2), Val::C(b1, b2)) = (v, vb) {
                        let mut u: Vec<I> = self.set_of(a1).to_vec();
                        u.extend(self.set_of(b1).iter().copied());
                        u.sort_unstable();
                        u.dedup();
                        if u.len() <= MAXC {
                            let mut n: Vec<I> = self.set_of(a2).to_vec();
                            n.extend(self.set_of(b2).iter().copied());
                            let (s1, s2) = (self.a.set(u), self.a.set(n));
                            return self.put(st, d, Val::C(s1, s2));
                        }
                    }
                    let (a, b) = (self.eval(st, v), self.eval(st, vb));
                    let nv = self.fresh(st, k, d.0, d.1);
                    if let (Some(a), Some(b)) = (a, b)
                        && let Val::S(r, _) = nv
                    {
                        st.set_con(r, a.union(&b).con());
                    }
                    return self.put(st, d, nv);
                }
            }
        }
        if let Mn::Load(size, sgn) = m
            && ops.len() == 2
            && ops[1].ty == OP_MEM
            && ops[1].index != 0
            && ops[1].disp == 0
        {
            let mo = &ops[1];
            let scale = (size as u32).ilog2();
            let (b, i) = (reg_id(mo.base), reg_id(mo.index));
            if let (Some(Reg::X(bn, _)), Some(ir @ Reg::X(..))) = (b, i)
                && mo.shift_value as u32 == scale
                && matches!(
                    mo.ext(),
                    EXT_INVALID | EXT_UXTW | EXT_SXTW | EXT_UXTX | EXT_SXTX
                )
            {
                let bv = st.regs[bn as usize];
                let iv = self.val(st, ir);
                let mut ia = if matches!(iv, Val::C(..) | Val::S(..)) {
                    self.eval(st, iv)
                } else {
                    None
                };
                if let Some(a) = &ia
                    && matches!(mo.ext(), EXT_SXTW | EXT_SXTX)
                    && a.hi
                        > (if mo.ext() == EXT_SXTW {
                            0x7fffffff
                        } else {
                            M64 >> 1
                        })
                {
                    ia = None;
                }
                let base = match bv {
                    Val::C(vs, ns) => Some(self.addresses(vs, ns)),
                    _ => None,
                };
                loads.entry(k).or_default().push((base, ia));
                let root = self.a.root(RootData::E(k as i64, d.0, d.1 as u8));
                self.detach(st, root, d.0);
                if !sgn {
                    st.set_con(
                        root,
                        mk(0, (1 << (8 * size as u32)) - 1, &Bits::full(), 0, M32),
                    );
                }
                return self.put(st, d, Val::S(root, self.empty));
            }
        }
        if m == Mn::Add
            && ops.len() == 3
            && d.1 == 64
            && let Some(Reg::X(ra, 64)) = reg_op(&ops[1])
            && let Some(Reg::X(rb, 64)) = reg_op(&ops[2])
            && matches!(ops[2].ext(), EXT_INVALID | EXT_UXTX | EXT_SXTX)
            && matches!(ops[2].shift_type(), 0 | SFT_LSL)
        {
            let (va, vb, sh) = (
                st.regs[ra as usize],
                st.regs[rb as usize],
                ops[2].shift_value as u32,
            );
            let entry = |a: &Arena, v: Val| match v {
                Val::S(r, c) => c == 0 && matches!(a.roots[r as usize], RootData::E(..)),
                _ => false,
            };
            let load_k = |a: &Arena, v: Val| match v {
                Val::S(r, _) => match a.roots[r as usize] {
                    RootData::E(k, ..) => k as u32,
                    _ => 0,
                },
                _ => 0,
            };
            if entry(&self.a, vb)
                && let Val::C(vs, ns) = va
            {
                let ad = self.addresses(vs, ns);
                let kk = load_k(&self.a, vb);
                return self.put(st, d, Val::T(kk, ad, sh));
            }
            if entry(&self.a, va)
                && let Val::C(vs, ns) = vb
                && sh == 0
            {
                let ad = self.addresses(vs, ns);
                let kk = load_k(&self.a, va);
                return self.put(st, d, Val::T(kk, ad, 0));
            }
        }
        self.unknown(st, k);
        if sets {
            st.flags = None;
        }
    }

    // -- the fixpoint --

    fn join(&mut self, a: &State, b: &State, k: i64, visits: u32) -> State {
        let widen = visits > WIDEN;
        let mut regs = [Val::Q; 31];
        let mut cons: Vec<(RootId, Con)> = Vec::new();
        let set_c = |cons: &mut Vec<(RootId, Con)>, r: RootId, c: Con| {
            if let Some(e) = cons.iter_mut().find(|(x, _)| *x == r) {
                e.1 = c;
            } else {
                cons.push((r, c));
            }
        };
        let mut phis: Vec<RootId> = Vec::new();
        let mut pairs: Vec<((RootId, RootId), RootId)> = Vec::new();
        let mut assigned = [false; 31];
        for i in 0..31 {
            let (x, y) = (a.regs[i], b.regs[i]);
            if x == y {
                regs[i] = x;
                if let Val::S(r, _) = x {
                    let ca = a.con(&self.a, r);
                    let c = cunion(&ca, &b.con(&self.a, r));
                    let c = if widen { self.widen(&ca, c, r) } else { c };
                    set_c(&mut cons, r, c);
                }
                continue;
            }
            if let (Val::C(x1, x2), Val::C(y1, y2)) = (x, y) {
                let (sx, sy) = (self.set_of(x1), self.set_of(y1));
                let mut u: Vec<I> = sx.to_vec();
                u.extend(sy.iter().copied());
                u.sort_unstable();
                u.dedup();
                let subset = sy.iter().all(|v| sx.contains(v));
                if u.len() <= MAXC && !(widen && !subset) {
                    let mut n: Vec<I> = self.set_of(x2).to_vec();
                    n.extend(self.set_of(y2).iter().copied());
                    let (s1, s2) = (self.a.set(u), self.a.set(n));
                    regs[i] = Val::C(s1, s2);
                    continue;
                }
            }
            if let (Val::S(xr, xc), Val::S(yr, yc)) = (x, y)
                && xc == yc
            {
                let key = (xr, yr);
                let root = match pairs.iter().find(|(kk, _)| *kk == key) {
                    Some((_, r)) => *r,
                    None => {
                        let wm = |r: RootId| {
                            if self.a.roots[r as usize] == RootData::Z {
                                M64
                            } else {
                                mask(self.a.width(r))
                            }
                        };
                        let w = if wm(xr).max(wm(yr)) == M32 { 32 } else { 64 };
                        let root = self.a.root(RootData::P(k, i as u8, w));
                        pairs.push((key, root));
                        phis.push(root);
                        let mut c = cunion(&a.con(&self.a, xr), &b.con(&self.a, yr));
                        if widen && xr == root {
                            c = self.widen(&a.con(&self.a, root), c, root);
                        }
                        set_c(&mut cons, root, c);
                        root
                    }
                };
                regs[i] = Val::S(root, xc);
                assigned[i] = true;
                continue;
            }
            let (ea, eb) = (self.eval(a, x), self.eval(b, y));
            let w = match (&ea, &eb) {
                (Some(p), Some(q)) if p.hi.max(q.hi) <= M32 => 32,
                _ => 64,
            };
            let root = self.a.root(RootData::P(k, i as u8, w));
            if !phis.contains(&root) {
                phis.push(root);
            }
            assigned[i] = true;
            regs[i] = Val::S(root, self.empty);
            if let (Some(p), Some(q)) = (ea, eb) {
                let mut c = p.union(&q).con();
                if widen && x == Val::S(root, self.empty) {
                    c = self.widen(&a.con(&self.a, root), c, root);
                }
                set_c(&mut cons, root, c);
            }
        }
        // a register still holding a phi of this point from an earlier pass keeps it as a root of its own
        for i in 0..31 {
            if let Val::S(r, c) = regs[i]
                && phis.contains(&r)
                && !assigned[i]
            {
                let pi = match self.a.roots[r as usize] {
                    RootData::P(_, pi, _) => pi,
                    _ => unreachable!(),
                };
                let old = self.a.root(RootData::XJ(k, pi, i as u8));
                regs[i] = Val::S(old, c);
                if let Some(cn) = cons.iter().find(|(x, _)| *x == r).map(|(_, c)| c.clone()) {
                    set_c(&mut cons, old, cn);
                }
            }
        }
        let flags = match (a.flags, b.flags) {
            (Some(fa), Some(fb)) if fa == fb => match fa.v {
                Val::S(r, _) if phis.contains(&r) => None,
                _ => Some(fa),
            },
            (None, None) => None,
            _ => None,
        };
        let mut st = State { regs, cons, flags };
        st.tidy(&self.a);
        st
    }

    fn widen(&self, old: &Con, new: Con, root: RootId) -> Con {
        if new == *old {
            return new;
        }
        let d = self.a.default_con(root);
        let (lo, hi) = if (new.lo, new.hi) == (old.lo, old.hi) {
            (new.lo, new.hi)
        } else {
            (d.lo, d.hi)
        };
        let (lo32, hi32) = if (new.lo32, new.hi32) == (old.lo32, old.hi32) {
            (new.lo32, new.hi32)
        } else {
            (d.lo32, d.hi32)
        };
        let bits = if new.bits == old.bits {
            new.bits.clone()
        } else {
            Bits::full()
        };
        mk(lo, hi, &bits, lo32, hi32)
    }

    fn seed_state(&mut self, k: usize) -> State {
        let mut regs = [Val::Q; 31];
        for (n, r) in regs.iter_mut().enumerate() {
            let root = self.a.root(RootData::Seed(k as i64, n as u8));
            *r = Val::S(root, self.empty);
        }
        State {
            regs,
            cons: Vec::new(),
            flags: None,
        }
    }

    /// The fixpoint from the seeds and, once the paths they start are done, from the landing pads
    #[allow(clippy::type_complexity)]
    fn run(
        &mut self,
        seeds: &PySet,
        edges: &HashMap<usize, Vec<i64>>,
    ) -> R<(Vec<Option<Box<State>>>, Vec<usize>, Loads)> {
        let n = self.insl.len();
        // boxed: most instructions never hold a state, and a state is ~600 bytes
        let mut states: Vec<Option<Box<State>>> = vec![None; n];
        let mut order: Vec<usize> = Vec::new();
        let mut visits: Vec<u32> = vec![0; n];
        let mut loads: Loads = HashMap::new();
        let mut work: Vec<usize> = Vec::new();
        let mut steps: u64 = 0;
        self.calls.clear();
        self.ncalls = 0;
        for k in seeds.iter() {
            let k = k as usize;
            if states[k].is_none() {
                order.push(k);
            }
            states[k] = Some(Box::new(self.seed_state(k)));
            visits[k] = 1;
            work.push(k);
        }
        let mut reached = vec![false; n];
        let mut done = 0usize;
        loop {
            if work.is_empty() {
                if done == self.ncalls {
                    break;
                }
                done = self.ncalls;
                let landing = self.landing.clone();
                for (k, ranges) in &landing {
                    let k = *k;
                    let after: Vec<State> = self
                        .calls
                        .iter()
                        .filter(|(a, _)| ranges.iter().any(|&(lo, hi)| lo <= *a && *a < hi))
                        .map(|(_, c)| c.clone())
                        .collect();
                    if after.is_empty() {
                        continue;
                    }
                    let mut land = after[0].clone();
                    for c in &after[1..] {
                        land = self.join(&land, c, -1, 1);
                    }
                    land.tidy(&self.a);
                    let changed = match states[k].take() {
                        None => {
                            states[k] = Some(Box::new(land));
                            order.push(k);
                            true
                        }
                        Some(old) => {
                            let new = self.join(&old, &land, k as i64, visits[k] + 1);
                            let d = key_differs(&self.a, &new, &old)?;
                            states[k] = Some(if d { Box::new(new) } else { old });
                            d
                        }
                    };
                    if changed {
                        visits[k] += 1;
                        work.push(k);
                    }
                }
                if work.is_empty() {
                    break;
                }
            }
            while let Some(k0) = work.pop() {
                let mut k = k0;
                let mut st = (**states[k].as_ref().unwrap()).clone();
                loop {
                    steps += 1;
                    reached[k] = true;
                    if steps > STEPS {
                        return Err(Stop::Unsupported("no fixpoint".into()));
                    }
                    let mut succ = self.step(st, k, edges, &mut loads, true)?;
                    if succ.len() == 1
                        && succ[0].0 == k + 1
                        && !self.leaders[k + 1]
                        && states[k + 1].is_none()
                    {
                        k += 1;
                        st = succ.pop().unwrap().1;
                        continue;
                    }
                    for (dest, mut s2) in succ {
                        s2.tidy(&self.a);
                        match states[dest].take() {
                            None => {
                                states[dest] = Some(Box::new(s2));
                                order.push(dest);
                                visits[dest] = 1;
                                work.push(dest);
                            }
                            Some(old) => {
                                visits[dest] += 1;
                                let new = self.join(&old, &s2, dest as i64, visits[dest]);
                                let d = key_differs(&self.a, &new, &old)?;
                                states[dest] = Some(if d { Box::new(new) } else { old });
                                if d {
                                    work.push(dest);
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        self.reached = reached;
        Ok((states, order, loads))
    }

    /// Unreached code after a terminator and padding: a function's start (text without unwind entries)
    fn starts(&self) -> PySet {
        let insl = self.insl;
        let mut out = PySet::new();
        for (k, p) in insl.iter().enumerate() {
            if self.reached[k] || k == 0 || matches!(self.mns[k], Mn::Nop | Mn::Udf) {
                continue;
            }
            let mut j = k as i64 - 1;
            while j >= 0
                && self.mns[j as usize] == Mn::Udf
                && insl[j as usize + 1].address == insl[j as usize].address + 4
            {
                j -= 1;
            }
            let padded = j < k as i64 - 1 || insl[k - 1].address + 4 != p.address;
            if padded
                && (j < 0
                    || matches!(self.mns[j as usize], Mn::B | Mn::Br | Mn::Ret | Mn::Brs)
                    || is_trap(self.mns[j as usize])
                    || insl[j as usize].address + 4 != insl[j as usize + 1].address)
            {
                out.add(k as u64);
            }
        }
        out
    }

    fn solve(
        &mut self,
        entries: &PySet,
        outside: &PySet,
        fixed: &BTreeMap<i64, Vec<i64>>,
        landing: &[(i64, Vec<(i64, i64)>)],
        unwound: bool,
    ) -> R<(Found, Failed)> {
        let insl = self.insl;
        self.landing = landing
            .iter()
            .filter_map(|(a, r)| self.at.get(a).map(|&i| (i, r.clone())))
            .collect();
        let mut direct = vec![false; insl.len()];
        let mut calls = PySet::new();
        for (k, p) in insl.iter().enumerate() {
            let m = self.mns[k];
            if (matches!(
                m,
                Mn::B | Mn::Cbz | Mn::Cbnz | Mn::Tbz | Mn::Tbnz | Mn::BCond(_)
            ) || (m == Mn::Other && p.mn().starts_with("b.")))
                && let Some(&t) = p.ops.last().and_then(|o| self.at.get(&o.imm))
            {
                direct[t] = true;
            }
            if m == Mn::Bl
                && let Some(&t) = self.at.get(&p.ops[0].imm)
            {
                calls.add(t as u64);
            }
        }
        let mut zero = PySet::new();
        zero.add(0);
        let named = entries.copy().or(&outside.copy());
        let mut third = PySet::new();
        for a in named.iter() {
            if let Some(&i) = self.at.get(&(a as i64)) {
                third.add(i as u64);
            }
        }
        let mut seeds = zero.or(&calls).or(&third);
        let mut edges: HashMap<usize, Vec<i64>> = HashMap::new();
        for (a, ts) in fixed {
            if let Some(&i) = self.at.get(a) {
                let mut t = ts.clone();
                t.sort_unstable();
                edges.insert(i, t);
            }
        }
        self.edges_out.clear();
        for _ in 0..OUTER {
            let mut leaders = direct.clone();
            for s in seeds.iter() {
                leaders[s as usize] = true;
            }
            for (i, _) in &self.landing {
                leaders[*i] = true;
            }
            for ts in edges.values() {
                for t in ts {
                    if let Some(&i) = self.at.get(t) {
                        leaders[i] = true;
                    }
                }
            }
            self.leaders = leaders;
            let (states, order, loads) = self.run(&seeds, &edges)?;
            let (found, failed, spread) = self.read(&states, &order, &loads)?;
            let mut new = edges.clone();
            for (a, ts) in found.iter().chain(spread.iter()) {
                let i = self.at[a];
                let mut v = new.get(&i).cloned().unwrap_or_default();
                v.extend(ts.iter().copied());
                v.sort_unstable();
                v.dedup();
                new.insert(i, v);
            }
            if new == edges {
                let more = if unwound {
                    PySet::new()
                } else {
                    self.starts().sub(&seeds)
                };
                if more.is_empty() {
                    self.edges_out = edges
                        .iter()
                        .map(|(k, ts)| (insl[*k].address, ts.clone()))
                        .collect();
                    return Ok((found, failed));
                }
                seeds.merge(&more);
                continue;
            }
            edges = new;
        }
        self.edges_out = edges
            .iter()
            .map(|(k, ts)| (insl[*k].address, ts.clone()))
            .collect();
        Ok((
            vec![],
            insl.iter()
                .enumerate()
                .filter(|(k, _)| self.mns[*k] == Mn::Br)
                .map(|(_, p)| (p.address, "tables kept changing".to_string()))
                .collect(),
        ))
    }

    /// Each br's value, from a last walk of every block from its fixpoint state, and the tables they read
    #[allow(clippy::type_complexity)]
    fn read(
        &mut self,
        states: &[Option<Box<State>>],
        order: &[usize],
        loads: &Loads,
    ) -> R<(Found, Failed, Found)> {
        let mut values: Vec<(usize, Vec<Val>)> = Vec::new();
        let none: HashMap<usize, Vec<i64>> = HashMap::new();
        for &k0 in order {
            let mut st = (**states[k0].as_ref().unwrap()).clone();
            let mut k = k0;
            loop {
                if self.mns[k] == Mn::Br {
                    let v = match reg_op(&self.insl[k].ops[0]) {
                        Some(Reg::X(n, _)) => st.regs[n as usize],
                        _ => Val::Q,
                    };
                    match values.iter_mut().find(|(x, _)| *x == k) {
                        Some(e) => e.1.push(v),
                        None => values.push((k, vec![v])),
                    }
                    break;
                }
                let mut scratch: Loads = HashMap::new();
                let mut succ = self.step(st, k, &none, &mut scratch, false)?;
                if succ.len() == 1
                    && succ[0].0 == k + 1
                    && !self.leaders[k + 1]
                    && states[k + 1].is_none()
                {
                    k += 1;
                    st = succ.pop().unwrap().1;
                    continue;
                }
                break;
            }
        }
        let (mut found, mut failed, mut spread): (Found, Failed, Found) = (vec![], vec![], vec![]);
        for (k, vs) in values {
            let a = self.insl[k].address;
            if !vs.iter().all(|v| matches!(v, Val::T(..))) {
                let why = if vs.iter().any(|v| matches!(v, Val::T(..))) {
                    "a table target joined with another value"
                } else {
                    "not a table"
                };
                dict_set(&mut failed, a, why.to_string());
                continue;
            }
            let ks: Vec<(u32, u32)> = vs
                .iter()
                .map(|v| match v {
                    Val::T(kl, _, sh) => (*kl, *sh),
                    _ => unreachable!(),
                })
                .collect();
            if ks.iter().any(|x| *x != ks[0]) {
                dict_set(
                    &mut failed,
                    a,
                    "more than one table load reaches the br".to_string(),
                );
                continue;
            }
            let (kl, sh) = (ks[0].0 as usize, ks[0].1);
            let mut cs: Vec<I> = Vec::new();
            for v in &vs {
                if let Val::T(_, s, _) = v {
                    cs.extend(self.set_of(*s).iter().copied());
                }
            }
            cs.sort_unstable();
            cs.dedup();
            let recs = loads.get(&kl).map(|v| &v[..]).unwrap_or(&[]);
            match self.table(kl, &cs, sh, recs) {
                Ok(t) => {
                    dict_set(&mut found, a, t);
                    continue;
                }
                Err(why) => dict_set(&mut failed, a, why),
            }
            let (size, sgn) = load_of(self.mns[kl]);
            if size <= 2 && !sgn && sh == 2 && cs.len() == 1 {
                // an unproved byte or halfword table still lands only on its pads
                let c = cs[0];
                let last = self.insl.last().unwrap().address as I;
                let lim = (1i128 << (8 * size as u32)).min((last + 4 - c).div_euclid(4) + 1);
                let mut pads = Vec::new();
                let mut e: I = 0;
                while e < lim {
                    let t = c + 4 * e;
                    if i64::try_from(t).is_ok_and(|t| self.at.contains_key(&t)) {
                        pads.push(t as i64);
                    }
                    e += 1;
                }
                dict_set(&mut spread, a, pads);
            }
        }
        Ok((found, failed, spread))
    }

    fn table(
        &self,
        kl: usize,
        cs: &[I],
        sh: u32,
        recs: &[(Option<SetId>, Option<Abs>)],
    ) -> Result<Vec<i64>, String> {
        if recs.is_empty() {
            return Err("the table load is not reached".into());
        }
        let (size, sgn) = load_of(self.mns[kl]);
        let mut bases: Vec<I> = Vec::new();
        let mut idx: Option<Abs> = None;
        for (b, a) in recs {
            let Some(b) = b else {
                return Err("the table base is not a constant".into());
            };
            let Some(a) = a else {
                return Err("the index is not bounded".into());
            };
            bases.extend(self.set_of(*b).iter().copied());
            idx = Some(match idx {
                None => a.clone(),
                Some(i) => i.union(a),
            });
        }
        let Some(idx) = idx else {
            return Err("the table load is not reached".into());
        };
        let n = idx.hi + 1;
        if idx.empty() {
            return Err("no index reaches the load".into());
        }
        if n > MAXN {
            return Err(format!("the index reaches {}", py_hex(idx.hi)));
        }
        let size_i = size as I;
        bases.sort_unstable();
        bases.dedup();
        bases.retain(|&b| 0 <= b && b + size_i * n <= self.img.len() as I);
        if bases.len() != 1 || cs.len() != 1 {
            return Err(format!(
                "{} table bases and {} target bases",
                bases.len(),
                cs.len()
            ));
        }
        let (tb, c) = (bases[0], cs[0]);
        let entry = |i: I| -> I {
            let o = (tb + size_i * i) as usize;
            let v: I = match (size, sgn) {
                (4, _) => i32::from_le_bytes(self.img[o..o + 4].try_into().unwrap()) as I,
                (1, false) => self.img[o] as I,
                (1, true) => self.img[o] as i8 as I,
                (2, false) => u16::from_le_bytes(self.img[o..o + 2].try_into().unwrap()) as I,
                _ => i16::from_le_bytes(self.img[o..o + 2].try_into().unwrap()) as I,
            };
            c + (v << sh)
        };
        let ok = |t: I| i64::try_from(t).is_ok_and(|t| self.at.contains_key(&t));
        let mut targets: Vec<I> = (0..n).map(entry).collect();
        if !targets.iter().all(|&t| ok(t)) {
            let Some(reach) = idx.members() else {
                return Err("a target is not an instruction of the function".into());
            };
            targets = reach.into_iter().map(entry).collect();
            if !targets.iter().all(|&t| ok(t)) {
                return Err("a target is not an instruction of the function".into());
            }
        }
        Ok(targets.into_iter().map(|t| t as i64).collect())
    }
}

fn pow2(e: i64) -> I {
    if (0..127).contains(&e) { 1 << e } else { 0 }
}

fn shr(v: I, s: I) -> I {
    if s >= 127 {
        if v < 0 { -1 } else { 0 }
    } else if s < 0 {
        v
    } else {
        v >> s
    }
}

/// Python's `f'{v:#x}'`
fn py_hex(v: I) -> String {
    if v < 0 {
        format!("-{:#x}", -v)
    } else {
        format!("{v:#x}")
    }
}

/// What [`solve`] proves for one function: {br address: targets} in the Python dict's order, {br address: reason}
#[derive(Clone, Debug, Default)]
pub struct Solved {
    pub found: Vec<(i64, Vec<i64>)>,
    pub failed: Vec<(i64, String)>,
}

impl Solved {
    pub fn targets(&self, at: i64) -> Option<&Vec<i64>> {
        self.found.iter().find(|(a, _)| *a == at).map(|(_, t)| t)
    }
    pub fn why(&self, at: i64) -> Option<&str> {
        self.failed
            .iter()
            .find(|(a, _)| *a == at)
            .map(|(_, w)| w.as_str())
    }
}

/// `jump_solver.solve`: {br address: targets} and {br address: reason} for the function `insl` (decoded with details).
/// entries: direct branches into it from elsewhere; outside: targets in it of tables elsewhere (both as the Python's
/// sets, whose order counts); landing: [(landing pad, [(start, end) of the calls it catches])] in address order;
/// unwound: false for text without unwind entries. `Err` is an exception of the Python that stops the module.
pub fn solve(
    insl: &[Ins],
    img: &[u8],
    entries: &PySet,
    outside: &PySet,
    landing: &[(i64, Vec<(i64, i64)>)],
    unwound: bool,
) -> Result<Solved, String> {
    if insl.is_empty() {
        return Ok(Solved::default());
    }
    let mns: Vec<Mn> = insl.iter().map(|p| mn_of(p.mn())).collect();
    let mut at: FxMap<i64, usize> = FxMap::default();
    for (k, p) in insl.iter().enumerate() {
        at.insert(p.address, k);
    }
    let x18 = PySet::from_iter_ordered(
        insl.iter()
            .filter(|p| p.mn() == "br" && &*p.op_str == "x18")
            .map(|p| p.address as u64),
    );
    let mut edges: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    let (mut found, mut failed, mut guarded) = (vec![], vec![], vec![]);
    for _ in 0..OUTER {
        let round = (|| -> R<_> {
            let mut full = Func::new(insl, &mns, img, true, &at);
            let (fo, fa) = full.solve(entries, outside, &edges, landing, unwound)?;
            let mut used = edges.clone();
            for (a, ts) in &full.edges_out {
                let mut v = used.get(a).cloned().unwrap_or_default();
                v.extend(ts.iter().copied());
                v.sort_unstable();
                v.dedup();
                used.insert(*a, v);
            }
            let mut guard = Func::new(insl, &mns, img, false, &at);
            let (gu, _) = guard.solve(entries, outside, &used, landing, unwound)?;
            Ok((fo, fa, used, gu))
        })();
        let (fo, fa, used, gu) = match round {
            Ok(r) => r,
            Err(Stop::Unsupported(e)) => {
                return Ok(Solved {
                    found: vec![],
                    failed: insl
                        .iter()
                        .filter(|p| p.mn() == "br")
                        .map(|p| (p.address, e.clone()))
                        .collect(),
                });
            }
            Err(Stop::Fatal(e)) => return Err(e),
        };
        found = fo;
        failed = fa;
        guarded = gu;
        let mut new = used.clone();
        for (a, ts) in &guarded {
            let mut v = new.get(a).cloned().unwrap_or_default();
            v.extend(ts.iter().copied());
            v.sort_unstable();
            v.dedup();
            new.insert(*a, v);
        }
        if new == used {
            break;
        }
        edges = new;
    }
    for a in x18.iter() {
        let a = a as i64;
        if let Some((_, t)) = guarded.iter().find(|(x, _)| *x == a) {
            dict_set(&mut found, a, t.clone());
            failed.retain(|(x, _)| *x != a);
        }
    }
    Ok(Solved { found, failed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    enum Lit {
        S(String),
        N(i128),
        T(Vec<Lit>),
    }

    /// A Python literal of nested tuples, strings and ints (`repr` of a root)
    fn parse(s: &[u8], i: &mut usize) -> Lit {
        while s[*i] == b' ' {
            *i += 1;
        }
        match s[*i] {
            b'(' => {
                *i += 1;
                let mut v = Vec::new();
                loop {
                    while s[*i] == b' ' || s[*i] == b',' {
                        *i += 1;
                    }
                    if s[*i] == b')' {
                        *i += 1;
                        return Lit::T(v);
                    }
                    v.push(parse(s, i));
                }
            }
            b'\'' => {
                let j = *i + 1 + s[*i + 1..].iter().position(|&c| c == b'\'').unwrap();
                let t = String::from_utf8(s[*i + 1..j].to_vec()).unwrap();
                *i = j + 1;
                Lit::S(t)
            }
            _ => {
                let j = *i
                    + s[*i..]
                        .iter()
                        .position(|&c| c == b',' || c == b')')
                        .unwrap();
                let n = std::str::from_utf8(&s[*i..j])
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                *i = j;
                Lit::N(n)
            }
        }
    }

    fn num(l: &Lit) -> i128 {
        match l {
            Lit::N(n) => *n,
            _ => panic!("{l:?}"),
        }
    }

    fn op(l: &Lit) -> Op {
        let Lit::T(v) = l else { panic!() };
        let Lit::S(k) = &v[0] else { panic!() };
        match k.as_str() {
            "w" => Op::W,
            "and" => Op::And(num(&v[1])),
            "not" => Op::Not(num(&v[1]) as u32),
            _ => Op::Add(num(&v[1]), num(&v[2]) as u32),
        }
    }

    fn root(a: &mut Arena, l: &Lit) -> RootId {
        let Lit::T(v) = l else { panic!() };
        let Lit::S(k) = &v[0] else { panic!() };
        let n = |i: usize| num(&v[i]);
        let r = match (k.as_str(), v.len()) {
            ("seed", _) => RootData::Seed(n(1) as i64, n(2) as u8),
            ("z", _) => RootData::Z,
            ("d", _) => RootData::D(n(1) as i64, n(2) as u8, n(3) as u8),
            ("e", _) => RootData::E(n(1) as i64, n(2) as u8, n(3) as u8),
            ("k", _) => RootData::K(n(1) as i64, n(2) as u8),
            ("p", _) => RootData::P(n(1) as i64, n(2) as u8, n(3) as u8),
            ("x", 4) => {
                let inner = root(a, &v[1]);
                RootData::XD(inner, n(2) as u8)
            }
            ("x", _) => RootData::XJ(n(1) as i64, n(2) as u8, n(3) as u8),
            _ => {
                let inner = root(a, &v[1]);
                let Lit::T(ops) = &v[2] else { panic!() };
                let ops: Vec<Op> = ops.iter().map(op).collect();
                let c = a.chain(&ops);
                RootData::R(inner, c)
            }
        };
        a.root(r)
    }

    /// The replay of CPython's sort raises exactly when the Python's sorted() does, with its message
    /// (tests/fixtures/solver/sort_cases.txt, written by tools/sortcases.py with the reference Python 3.14.1)
    #[test]
    fn the_sort_of_the_constraints_raises_where_the_python_does() {
        let text = include_str!("../tests/fixtures/solver/sort_cases.txt");
        let (mut n, mut raised) = (0, 0);
        for l in text.lines() {
            let (want, roots) = l.split_once('\t').unwrap();
            let mut a = Arena::new();
            let ids: Vec<RootId> = roots
                .split(';')
                .map(|r| root(&mut a, &parse(r.as_bytes(), &mut 0)))
                .collect();
            let got = match py_sort_check(&a, &ids) {
                Ok(()) => "ok".to_string(),
                Err(m) => format!("TypeError: {m}"),
            };
            assert_eq!(got, want, "{roots}");
            if want != "ok" {
                raised += 1;
                // only roots of both 'x' shapes can be unordered: the shortcut of State::key_check is sound
                let x = ids.iter().fold(0u8, |m, r| m | a.root_x[*r as usize]);
                assert_eq!(x, 3, "{roots}");
            }
            n += 1;
        }
        assert!(n >= 400 && raised >= 100, "{n} cases, {raised} raise");
    }
}
