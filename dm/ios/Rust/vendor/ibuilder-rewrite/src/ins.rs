//! Helpers over decoded instructions: the register bookkeeping and text matching `patch_nso.py` does on Capstone's
//! output (`regset`, `num`, `written_w`, `writes_reg`, `has18`, `regs_in`, `pick`, `subst`, `sp_delta`, ...).

use crate::{Fail, Res};
use ibuilder_a64::cs::{self, Ins, reg_name};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// A cached, compiled ASCII-mode pattern (`re.compile`); the pattern text is the Python one.
pub fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| {
        Regex::new(&format!("(?-u){pat}")).unwrap_or_else(|e| panic!("bad pattern {pat}: {e}"))
    })
}

/// Patterns `full` keeps per thread before its cache starts again (review r5 P15: it had no bound; `ibuilder_shader::finish::rx::cached` has the same 256). The recognisers' set is a few
/// templates times 32 registers, so the bound is not reached in practice; it only caps what an unforeseen caller could pile up.
const FULL_CAP: usize = 256;

thread_local! {
    /// `full`'s compiled patterns, by pattern text: the recognisers interpolate register names, so the set is small; each worker thread compiles each pattern once (at most `FULL_CAP` kept)
    static FULL: std::cell::RefCell<std::collections::HashMap<String, Regex>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// `re.fullmatch(pat, s)` with a pattern built at run time (register names interpolated). The compiled pattern is
/// cached per thread (the same text compiles to the same automaton: the match is unchanged, whether it came from the cache or not).
pub fn full(pat: &str, s: &str) -> Option<Vec<Option<String>>> {
    FULL.with(|cache| {
        let mut cache = cache.borrow_mut();
        if !cache.contains_key(pat) {
            let r = Regex::new(&format!("(?-u)^(?:{pat})$"))
                .unwrap_or_else(|e| panic!("bad pattern {pat}: {e}"));
            if cache.len() >= FULL_CAP {
                cache.clear();
            }
            cache.insert(pat.to_string(), r);
        }
        cache[pat].captures(s).map(|c| {
            c.iter()
                .map(|m| m.map(|m| m.as_str().to_string()))
                .collect()
        })
    })
}

/// Python's `int(s, 0)` for the forms Capstone prints: optional sign, `0x` hex or decimal
pub fn pyint(s: &str) -> i64 {
    let (neg, t) = match s.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, s),
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).unwrap()
    } else {
        t.parse::<i64>().unwrap()
    };
    if neg { -v } else { v }
}

/// `int(s, 0)` that reports a malformed number as None (Python raises ValueError)
pub fn try_pyint(s: &str) -> Option<i64> {
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, t),
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else {
        t.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

/// `has18`: the operand text names x18 / w18 as a whole word
pub fn has18(ins: &Ins) -> bool {
    cs::has_xw18(ins.op_str.as_bytes())
}

/// `num(name)`: N of a register name `xN` / `wN`, else None
pub fn num(name: &str) -> Option<u32> {
    let b = name.as_bytes();
    if b.len() >= 2 && (b[0] == b'x' || b[0] == b'w') && b[1..].iter().all(|c| c.is_ascii_digit()) {
        name[1..].parse().ok()
    } else {
        None
    }
}

/// `regset(ins)`: the names of the registers read and written (as `regs_access()` lists them)
pub fn regset(ins: &Ins) -> (BTreeSet<&'static str>, BTreeSet<&'static str>) {
    match &ins.regs {
        Some((r, w)) => (
            r.iter().map(|&x| reg_name(x)).collect(),
            w.iter().map(|&x| reg_name(x)).collect(),
        ),
        None => (BTreeSet::new(), BTreeSet::new()),
    }
}

fn canon(n: &'static str) -> &'static str {
    match n {
        "lr" => "x30",
        "fp" => "x29",
        o => o,
    }
}

/// The general-purpose registers `p` writes, as register numbers N of wN (a write of wN or xN changes the same
/// register); capstone's `lr` / `fp` are x30 / x29; s0, d0, q0 and the like are not w0. Capstone lists a compare's
/// first operand as written too, so a caller that only wants real writes leaves compares out.
pub fn written_w(p: &Ins) -> BTreeSet<u32> {
    match &p.regs {
        Some((_, w)) => w.iter().filter_map(|&x| num(canon(reg_name(x)))).collect(),
        None => BTreeSet::new(),
    }
}

/// Whether `p` changes the general-purpose register `reg` (xN or wN): a write of wN clears the upper half of xN too,
/// and a compare only sets the flags
pub fn writes_reg(p: &Ins, reg: &str) -> bool {
    !matches!(p.mn(), "cmp" | "cmn" | "tst") && num(reg).is_some_and(|n| written_w(p).contains(&n))
}

/// registers named in the operand text (`\b[xw](\d+)\b`) plus those `regs_access` lists, as numbers
pub fn regs_in(ins: &Ins) -> BTreeSet<u32> {
    let b = ins.op_str.as_bytes();
    let w = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut s = BTreeSet::new();
    let mut i = 0;
    while i < b.len() {
        if (b[i] == b'x' || b[i] == b'w') && (i == 0 || !w(b[i - 1])) {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 && (j == b.len() || !w(b[j])) {
                s.insert(ins.op_str[i + 1..j].parse::<u32>().unwrap());
                i = j;
                continue;
            }
        }
        i += 1;
    }
    let (rd, wr) = regset(ins);
    for n in rd.iter().chain(wr.iter()) {
        if let Some(k) = num(n) {
            s.insert(k);
        }
    }
    s
}

/// `pick(avoid, n)`: the first `n` registers x0..x15 not in `avoid` and not x18
pub fn pick(avoid: &BTreeSet<u32>, n: usize) -> Res<Vec<u32>> {
    let out: Vec<u32> = (0..16)
        .filter(|r| !avoid.contains(r) && *r != 18)
        .take(n)
        .collect();
    if out.len() != n {
        return Err(Fail::new("pick: not enough free registers"));
    }
    Ok(out)
}

/// `dis(w, addr)`: the one instruction `w` decodes to at `addr` (an assertion otherwise)
pub fn dis(w: u32, addr: i64) -> Res<Ins> {
    cs::decode(w, addr).ok_or_else(|| Fail::new(format!("{w:#x}")))
}

/// `subst(ins, S)`: x18/w18 -> xS/wS, only the register field positions changed, verified against the disassembly text
pub fn subst(ins: &Ins, s: u32) -> Res<u32> {
    let w = ins.word;
    // want = re.sub(r'\b([xw])18\b', ...)
    let b = ins.op_str.as_bytes();
    let wc = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut want = String::new();
    let mut i = 0;
    while i < b.len() {
        if (b[i] == b'x' || b[i] == b'w')
            && i + 2 < b.len()
            && b[i + 1] == b'1'
            && b[i + 2] == b'8'
            && (i == 0 || !wc(b[i - 1]))
            && (i + 3 == b.len() || !wc(b[i + 3]))
        {
            want.push(b[i] as char);
            want.push_str(&s.to_string());
            i += 3;
        } else {
            want.push(b[i] as char);
            i += 1;
        }
    }
    let pos: Vec<u32> = [0u32, 5, 10, 16]
        .into_iter()
        .filter(|p| (w >> p) & 31 == 18)
        .collect();
    for k in (1..=pos.len()).rev() {
        // itertools.combinations(pos, k) in lexicographic order
        let mut idx: Vec<usize> = (0..k).collect();
        loop {
            let mut nw = w;
            for &ix in &idx {
                nw = (nw & !(31 << pos[ix])) | (s << pos[ix]);
            }
            if let Some(dd) = cs::decode(nw, ins.address)
                && dd.mnemonic == ins.mnemonic
                && *dd.op_str == *want
            {
                return Ok(nw);
            }
            // next combination
            let n = pos.len();
            let mut i = k;
            let mut advanced = false;
            while i > 0 {
                i -= 1;
                if idx[i] != i + n - k {
                    idx[i] += 1;
                    for j in i + 1..k {
                        idx[j] = idx[j - 1] + 1;
                    }
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
    }
    Err(Fail::new(format!(
        "subst fail {:x} {} {}",
        ins.address, ins.mnemonic, ins.op_str
    )))
}

/// `sp_delta(ins)`: the amount an instruction writes back to sp (pre-index `[sp, #i]!` / post-index `[sp], #i`), 0 if
/// sp is not written back
pub fn sp_delta(ins: &Ins) -> Res<i64> {
    static PRE: OnceLock<Regex> = OnceLock::new();
    static POST: OnceLock<Regex> = OnceLock::new();
    static SPD: OnceLock<Regex> = OnceLock::new();
    if let Some(m) = re(&PRE, r"\[sp, #(-?(?:0x)?[0-9a-f]+)\]!").captures(&ins.op_str) {
        return Ok(pyint(&m[1]));
    }
    if let Some(m) = re(&POST, r"\[sp\], #(-?(?:0x)?[0-9a-f]+)$").captures(&ins.op_str) {
        return Ok(pyint(&m[1]));
    }
    if re(&SPD, r"^(sp|wsp),").is_match(&ins.op_str) {
        return Err(Fail::new(format!(
            "writes sp: {:x} {}",
            ins.address, ins.op_str
        )));
    }
    Ok(0)
}

pub fn op_reg_name(ins: &Ins, i: usize) -> &'static str {
    reg_name(ins.ops[i].reg)
}

/// `x.operands[-1].imm`
pub fn last_imm(ins: &Ins) -> i64 {
    ins.ops.last().map(|o| o.imm).unwrap_or(0)
}

pub fn is_cond_branch_or_b(m: &str) -> bool {
    matches!(m, "b" | "bl" | "cbz" | "cbnz" | "tbz" | "tbnz") || m.starts_with("b.")
}

#[cfg(test)]
mod full_cache_tests {
    use super::*;

    /// Review r5 P15: past `FULL_CAP` distinct patterns the cache starts again instead of growing, and every answer is the uncached one.
    #[test]
    fn the_pattern_cache_is_bounded_and_changes_no_match() {
        for round in 0..2 {
            for i in 0..(FULL_CAP + 50) {
                let pat = format!(r"x{i}, #(\d+)");
                let got = full(&pat, &format!("x{i}, #{round}{i}"));
                assert_eq!(
                    got,
                    Some(vec![
                        Some(format!("x{i}, #{round}{i}")),
                        Some(format!("{round}{i}"))
                    ])
                );
                assert_eq!(full(&pat, &format!("x{i}, #z")), None);
                assert!(FULL.with(|c| c.borrow().len()) <= FULL_CAP);
            }
        }
    }
}
