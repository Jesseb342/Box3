//! CPython 3.14's `set` of small non-negative integers, as far as its iteration order goes (`Objects/setobject.c`:
//! `set_add_entry`, `set_insert_clean`, `set_table_resize`, `set_merge`, `set_difference`, `set_discard_entry`).
//!
//! `jump_solver.py` iterates sets of instruction indices and addresses (the seeds of its fixpoint, its `br x18`
//! addresses) and the order it visits them in decides the order of its work list, which the widening of the fixpoint
//! and the order of its results depend on. A set of ints iterates in hash-table slot order, which is a function of the
//! values AND of the order they were added (collisions, dummies of removed keys, resizes). This type keeps the same
//! table as CPython does, so iterating it gives the same order. Only ints whose hash is the value itself are kept
//! (0 <= v < 2**61 - 1: instruction indices and module addresses).

const MINSIZE: usize = 8;
const LINEAR_PROBES: usize = 9;
const PERTURB_SHIFT: u32 = 5;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    Empty,
    Dummy,
    Key(u64),
}

#[derive(Clone, Debug)]
pub struct PySet {
    table: Vec<Slot>,
    fill: usize,
    used: usize,
}

impl Default for PySet {
    fn default() -> Self {
        PySet::new()
    }
}

impl PySet {
    pub fn new() -> PySet {
        PySet {
            table: vec![Slot::Empty; MINSIZE],
            fill: 0,
            used: 0,
        }
    }

    fn mask(&self) -> usize {
        self.table.len() - 1
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// `set(iterable)` / a set display or comprehension: the items added one by one in this order
    pub fn from_iter_ordered(it: impl IntoIterator<Item = u64>) -> PySet {
        let mut s = PySet::new();
        for k in it {
            s.add(k);
        }
        s
    }

    /// `set_lookkey`: the slot of key, or the first never-used slot that ends its probe sequence
    fn lookup(&self, key: u64) -> usize {
        let mask = self.mask();
        let mut perturb = key as usize;
        let mut i = key as usize & mask;
        loop {
            let probes = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            for j in 0..=probes {
                match self.table[i + j] {
                    Slot::Empty => return i + j,
                    Slot::Key(k) if k == key => return i + j,
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
    }

    pub fn contains(&self, key: u64) -> bool {
        matches!(self.table[self.lookup(key)], Slot::Key(_))
    }

    /// `set_add_entry`
    pub fn add(&mut self, key: u64) {
        let mask = self.mask();
        let mut perturb = key as usize;
        let mut i = key as usize & mask;
        let mut freeslot: Option<usize> = None;
        let found = loop {
            let probes = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            let mut hit = None;
            for j in 0..=probes {
                match self.table[i + j] {
                    Slot::Empty => {
                        hit = Some(Err(i + j));
                        break;
                    }
                    Slot::Key(k) if k == key => {
                        hit = Some(Ok(()));
                        break;
                    }
                    Slot::Dummy => freeslot = Some(i + j), // the last dummy seen (3.14 keeps overwriting it)
                    Slot::Key(_) => {}
                }
            }
            if let Some(h) = hit {
                break h;
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        };
        let Err(unused) = found else { return };
        if let Some(f) = freeslot {
            self.table[f] = Slot::Key(key);
            self.used += 1;
            return;
        }
        self.table[unused] = Slot::Key(key);
        self.fill += 1;
        self.used += 1;
        if self.fill * 5 < mask * 3 {
            return;
        }
        self.resize(if self.used > 50000 {
            self.used * 2
        } else {
            self.used * 4
        });
    }

    /// `set_discard_entry` (the slot becomes a dummy)
    pub fn discard(&mut self, key: u64) -> bool {
        let s = self.lookup(key);
        if let Slot::Key(_) = self.table[s] {
            self.table[s] = Slot::Dummy;
            self.used -= 1;
            true
        } else {
            false
        }
    }

    fn insert_clean(table: &mut [Slot], key: u64) {
        let mask = table.len() - 1;
        let mut perturb = key as usize;
        let mut i = key as usize & mask;
        loop {
            if table[i] == Slot::Empty {
                table[i] = Slot::Key(key);
                return;
            }
            if i + LINEAR_PROBES <= mask {
                for j in 1..=LINEAR_PROBES {
                    if table[i + j] == Slot::Empty {
                        table[i + j] = Slot::Key(key);
                        return;
                    }
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
    }

    /// `set_table_resize`
    fn resize(&mut self, minused: usize) {
        let mut newsize = MINSIZE;
        while newsize <= minused {
            newsize <<= 1;
        }
        if newsize == MINSIZE && self.table.len() == MINSIZE && self.fill == self.used {
            return; // the small table, no dummies: nothing to do
        }
        let old = std::mem::replace(&mut self.table, vec![Slot::Empty; newsize]);
        self.fill = self.used;
        for s in old {
            if let Slot::Key(k) = s {
                Self::insert_clean(&mut self.table, k);
            }
        }
    }

    /// The members in iteration order (`set_next`)
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.table.iter().filter_map(|s| match s {
            Slot::Key(k) => Some(*k),
            _ => None,
        })
    }

    /// `set_merge` (`self |= other`, `set(other)`, the second half of `a | b`)
    pub fn merge(&mut self, other: &PySet) {
        if other.used == 0 {
            return;
        }
        if (self.fill + other.used) * 5 >= self.mask() * 3 {
            self.resize((self.used + other.used) * 2);
        }
        if self.fill == 0 && self.mask() == other.mask() && other.fill == other.used {
            for (a, b) in self.table.iter_mut().zip(&other.table) {
                if let Slot::Key(k) = b {
                    *a = Slot::Key(*k);
                }
            }
            self.fill = other.fill;
            self.used = other.used;
            return;
        }
        if self.fill == 0 {
            self.fill = other.used;
            self.used = other.used;
            for k in other.iter() {
                Self::insert_clean(&mut self.table, k);
            }
            return;
        }
        for k in other.iter() {
            self.add(k);
        }
    }

    /// `set(self)` / `set_copy`: a new set merged from this one
    pub fn copy(&self) -> PySet {
        let mut s = PySet::new();
        s.merge(self);
        s
    }

    /// `self | other` (`set_or`)
    pub fn or(&self, other: &PySet) -> PySet {
        let mut s = self.copy();
        s.merge(other);
        s
    }

    /// `self - other` (`set_difference`, both sets)
    pub fn sub(&self, other: &PySet) -> PySet {
        if (self.len() >> 2) > other.len() {
            // set_copy_and_difference: copy, then discard every member of other (in its order); dummies stay unless
            // more than a quarter of the table is dummies
            let mut r = self.copy();
            for k in other.iter() {
                r.discard(k);
            }
            if r.fill - r.used > r.mask() / 4 {
                r.resize(if r.used > 50000 {
                    r.used * 2
                } else {
                    r.used * 4
                });
            }
            return r;
        }
        let mut r = PySet::new();
        for k in self.iter() {
            if !other.contains(k) {
                r.add(k);
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::PySet;
    use std::collections::HashMap;

    /// The iteration orders CPython 3.14.1 gives after random adds, unions, differences, in-place unions and copies
    /// (tests/fixtures/solver/pyset_cases.txt, written by tools/pysetcases.py)
    #[test]
    fn iteration_order_is_cpythons() {
        let text = include_str!("../tests/fixtures/solver/pyset_cases.txt");
        let mut n = 0;
        for l in text.lines() {
            let (ops, want) = l.split_once("=>").unwrap();
            let mut s: HashMap<String, PySet> = "ABCD"
                .chars()
                .map(|c| (c.to_string(), PySet::new()))
                .collect();
            for op in ops.split(';').filter(|o| !o.is_empty()) {
                let w: Vec<&str> = op.split(' ').collect();
                match w[0] {
                    "add" => s.get_mut(w[1]).unwrap().add(w[2].parse().unwrap()),
                    "or" => {
                        let r = s[w[2]].or(&s[w[3]]);
                        s.insert(w[1].into(), r);
                    }
                    "sub" => {
                        let r = s[w[2]].sub(&s[w[3]]);
                        s.insert(w[1].into(), r);
                    }
                    "ior" => {
                        let b = s[w[2]].clone();
                        s.get_mut(w[1]).unwrap().merge(&b);
                    }
                    _ => {
                        let r = s[w[2]].copy();
                        s.insert(w[1].into(), r);
                    }
                }
            }
            let got: Vec<String> = "ABCD"
                .chars()
                .map(|c| {
                    let v: Vec<String> = s[&c.to_string()].iter().map(|x| x.to_string()).collect();
                    format!("{c}:{}", v.join(","))
                })
                .collect();
            assert_eq!(got.join(" "), want, "{ops}");
            n += 1;
        }
        assert!(n >= 30);
    }
}
