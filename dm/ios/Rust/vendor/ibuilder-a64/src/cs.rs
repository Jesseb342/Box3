//! A thin, safe wrapper over the Capstone C library (AArch64 only) with exactly the surface `patch_nso.py` uses
//! from the Python bindings: mnemonic, `op_str`, operands (type, register, immediate, memory base/index/disp),
//! instruction groups, writeback, `regs_access()` and `reg_name()`.
//!
//! `unsafe` is confined to this module and is limited to the FFI calls (the handle is owned by `Decoder`,
//! one `cs_insn` scratch buffer is reused, strings are copied out before the next decode).

use capstone_sys as sys;
use std::ffi::CStr;

pub const OP_REG: u32 = 1;
pub const OP_IMM: u32 = 2;
pub const OP_MEM: u32 = 3;

pub const GRP_JUMP: u8 = 1;
pub const GRP_CALL: u8 = 2;
pub const GRP_RET: u8 = 3;
pub const GRP_INT: u8 = 4;
pub const GRP_IRET: u8 = 5;

pub const REG_SP: u16 = sys::arm64_reg::ARM64_REG_SP as u16;

/// `ins.reg_name(id)` without a decoder: Capstone's register names are a static table, the same for every handle.
pub fn reg_name(id: u16) -> &'static str {
    static TABLE: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let d = Decoder::new(false);
        (0..1024u32)
            .map(|i| {
                // SAFETY: Capstone returns a pointer to a static table entry or NULL
                let p = unsafe { sys::cs_reg_name(d.h, i) };
                if p.is_null() {
                    ""
                } else {
                    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
                }
            })
            .collect()
    });
    t.get(id as usize).copied().unwrap_or("")
}

thread_local! {
    static DETAIL: std::cell::RefCell<Decoder> = std::cell::RefCell::new(Decoder::new(true));
    static LITE: std::cell::RefCell<Decoder> = std::cell::RefCell::new(Decoder::new(false));
}

/// Decode one word with detail on this thread's decoder.
pub fn decode(word: u32, address: i64) -> Option<Ins> {
    DETAIL.with(|d| d.borrow_mut().decode(word, address))
}
/// Decode one word on this thread's detail decoder without the register access lists (`regs` is `None`).
pub fn decode_no_regs(word: u32, address: i64) -> Option<Ins> {
    DETAIL.with(|d| d.borrow_mut().decode_no_regs(word, address))
}
/// `md.disasm(code, address)` on this thread's detail decoder (stops at the first undecodable word).
pub fn disasm(code: &[u8], address: i64) -> Vec<Ins> {
    DETAIL.with(|d| d.borrow_mut().disasm(code, address))
}
/// [`Decoder::disasm_into`] on this thread's detail decoder.
pub fn disasm_into(out: &mut Vec<Ins>, code: &[u8], address: i64) -> usize {
    DETAIL.with(|d| d.borrow_mut().disasm_into(out, code, address))
}
/// Whether a word decodes at all (no detail needed).
pub fn decodes(word: u32, address: i64) -> bool {
    LITE.with(|d| d.borrow_mut().decode_lite(word, address, |_, _| {}))
}
/// `Some(names x18/w18)` for a decodable word, `None` otherwise (the x18 scan's per-word test).
pub fn names_x18(word: u32, address: i64) -> Option<bool> {
    LITE.with(|d| d.borrow_mut().names_x18(word, address))
}

/// One operand of an instruction as Capstone's AArch64 detail reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Op {
    /// Capstone `arm64_op_type` (OP_REG / OP_IMM / OP_MEM, others as numbers)
    pub ty: u32,
    /// register id (OP_REG)
    pub reg: u16,
    /// immediate (OP_IMM); for branches and adr/adrp the absolute target
    pub imm: i64,
    /// memory operand base/index register ids and displacement (OP_MEM)
    pub base: u16,
    pub index: u16,
    pub disp: i32,
    /// `op.shift.value` (an AArch64 shift amount: at most 63)
    pub shift_value: u8,
    /// `op.shift.type` (Capstone `arm64_shifter`, 0..=5) in the low 4 bits and `op.ext` (`arm64_extender`, 0..=8) in the
    /// high 4: two bytes for the three fields keep `Op` at the 24 bytes it had without them (decoded instructions are
    /// held by the million)
    pub shift_ext: u8,
}

impl Op {
    /// `op.shift.type`: 0 none, 1 LSL, 2 MSL, 3 LSR, 4 ASR, 5 ROR
    #[inline]
    pub fn shift_type(&self) -> u8 {
        self.shift_ext & 15
    }
    /// `op.ext`: 0 none, 1 UXTB, 2 UXTH, 3 UXTW, 4 UXTX, 5 SXTB, 6 SXTH, 7 SXTW, 8 SXTX
    #[inline]
    pub fn ext(&self) -> u8 {
        self.shift_ext >> 4
    }
}

/// Bytes of text kept inside [`Text`] itself; longer text goes to the heap. Capstone's AArch64 mnemonics are at most
/// a dozen characters and nearly every operand text is shorter than this, so a decode allocates nothing for them.
const TEXT_INLINE: usize = 30;

/// A string of Capstone's output (mnemonic or operand text), stored inline when it is short. It derefs to `str`, so
/// it compares, slices and formats exactly like the `Box<str>` it replaces (the text itself is never changed).
#[derive(Clone)]
pub struct Text(TextRepr);

#[derive(Clone)]
enum TextRepr {
    /// (length, bytes): `bytes[..length]` is valid UTF-8 (copied from a `&str`)
    Inline(u8, [u8; TEXT_INLINE]),
    Heap(Box<str>),
}

impl Text {
    pub fn new(s: &str) -> Text {
        if s.len() <= TEXT_INLINE {
            let mut b = [0u8; TEXT_INLINE];
            b[..s.len()].copy_from_slice(s.as_bytes());
            Text(TextRepr::Inline(s.len() as u8, b))
        } else {
            Text(TextRepr::Heap(s.into()))
        }
    }
    #[inline]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            // SAFETY: an inline Text is only made by `new` from the bytes of a `&str` (whole: `s.len()` bytes), so the
            // first `n` bytes are valid UTF-8
            TextRepr::Inline(n, b) => unsafe { std::str::from_utf8_unchecked(&b[..*n as usize]) },
            TextRepr::Heap(s) => s,
        }
    }
}
impl std::ops::Deref for Text {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl std::fmt::Display for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.as_str(), f)
    }
}
impl std::fmt::Debug for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}
impl PartialEq for Text {
    fn eq(&self, o: &Text) -> bool {
        self.as_str() == o.as_str()
    }
}
impl Eq for Text {}
impl PartialEq<str> for Text {
    fn eq(&self, o: &str) -> bool {
        self.as_str() == o
    }
}
impl PartialEq<&str> for Text {
    fn eq(&self, o: &&str) -> bool {
        self.as_str() == *o
    }
}

/// A short list stored inline up to `N` items (the common case), on the heap beyond. Derefs to a slice, like the
/// `Vec` it replaces; the items and their order are the ones pushed.
#[derive(Clone)]
pub struct Small<T: Copy + Default, const N: usize>(SmallRepr<T, N>);

#[derive(Clone)]
enum SmallRepr<T: Copy + Default, const N: usize> {
    Inline(u8, [T; N]),
    Heap(Box<[T]>),
}

impl<T: Copy + Default, const N: usize> Small<T, N> {
    pub fn from_slice(s: &[T]) -> Self {
        if s.len() <= N && N <= u8::MAX as usize {
            let mut b = [T::default(); N];
            b[..s.len()].copy_from_slice(s);
            Small(SmallRepr::Inline(s.len() as u8, b))
        } else {
            Small(SmallRepr::Heap(s.into()))
        }
    }
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        match &self.0 {
            SmallRepr::Inline(n, b) => &b[..*n as usize],
            SmallRepr::Heap(v) => v,
        }
    }
}
impl<T: Copy + Default, const N: usize> Default for Small<T, N> {
    fn default() -> Self {
        Small(SmallRepr::Inline(0, [T::default(); N]))
    }
}
impl<T: Copy + Default, const N: usize> std::ops::Deref for Small<T, N> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}
impl<'a, T: Copy + Default, const N: usize> IntoIterator for &'a Small<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}
impl<T: Copy + Default + std::fmt::Debug, const N: usize> std::fmt::Debug for Small<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_slice(), f)
    }
}
impl<T: Copy + Default + PartialEq, const N: usize> PartialEq for Small<T, N> {
    fn eq(&self, o: &Self) -> bool {
        self.as_slice() == o.as_slice()
    }
}
impl<T: Copy + Default + Eq, const N: usize> Eq for Small<T, N> {}

/// The operands of an instruction (Capstone's AArch64 detail has at most 8; four cover nearly all)
pub type Ops = Small<Op, 4>;
/// A register list of `cs_regs_access` (at most 64 ids; seven cover nearly all)
pub type RegList = Small<u16, 7>;

/// A decoded instruction (with detail).
#[derive(Debug, Clone)]
pub struct Ins {
    pub address: i64,
    pub word: u32,
    pub mnemonic: Text,
    pub op_str: Text,
    pub ops: Ops,
    /// registers read / written as `cs_regs_access` lists them (explicit and implicit); `None` when Capstone
    /// reports an error for the instruction (the Python `regs_access()` raises there)
    pub regs: Option<(RegList, RegList)>,
    /// bit n set = instruction is in group n (jump 1, call 2, ret 3, int 4, iret 5)
    pub groups: u32,
    /// `cs_arm64.writeback` (what the Python binding exposes as `ins.writeback`)
    pub writeback: bool,
    /// `cs_arm64.update_flags` (`ins.update_flags`)
    pub update_flags: bool,
}

impl Ins {
    #[inline]
    pub fn group(&self, g: u8) -> bool {
        self.groups >> g & 1 != 0
    }
    #[inline]
    pub fn mn(&self) -> &str {
        &self.mnemonic
    }
}

pub struct Decoder {
    h: sys::csh,
    ins: *mut sys::cs_insn,
    detail: bool,
    names: Vec<Option<&'static str>>,
}

// SAFETY: the handle and the scratch instruction are owned by the Decoder and only used through &mut self
// (or &self for read-only name lookups, which Capstone documents as thread-safe on a handle no one reopens).
unsafe impl Send for Decoder {}

/// The NUL-terminated text of one of Capstone's fixed `char` arrays (mnemonic, op_str), as `CStr::to_string_lossy`
/// reads it (Capstone writes ASCII, so the lossy branch is never taken in practice), without allocating when short.
fn cstr(p: &[core::ffi::c_char]) -> Text {
    let n = p.iter().position(|&c| c == 0).unwrap_or(p.len());
    // SAFETY: c_char -> u8 reinterpretation of the same initialised bytes of the array
    let b: &[u8] = unsafe { core::slice::from_raw_parts(p.as_ptr() as *const u8, n) };
    match std::str::from_utf8(b) {
        Ok(s) => Text::new(s),
        Err(_) => Text::new(&String::from_utf8_lossy(b)),
    }
}

impl Decoder {
    /// AArch64 disassembler, `detail` = Capstone's `md.detail = True`
    pub fn new(detail: bool) -> Decoder {
        let mut h: sys::csh = 0;
        // SAFETY: plain FFI initialisation; the handle is closed in Drop
        let err = unsafe {
            sys::cs_open(
                sys::cs_arch::CS_ARCH_ARM64,
                sys::cs_mode::CS_MODE_ARM,
                &mut h,
            )
        };
        assert_eq!(err, sys::cs_err::CS_ERR_OK, "cs_open failed");
        if detail {
            // SAFETY: valid handle
            let err = unsafe {
                sys::cs_option(
                    h,
                    sys::cs_opt_type::CS_OPT_DETAIL,
                    sys::cs_opt_value::CS_OPT_ON as usize,
                )
            };
            assert_eq!(err, sys::cs_err::CS_ERR_OK, "cs_option(detail) failed");
        }
        // SAFETY: valid handle
        let ins = unsafe { sys::cs_malloc(h) };
        assert!(!ins.is_null());
        Decoder {
            h,
            ins,
            detail,
            names: Vec::new(),
        }
    }

    /// `ins.reg_name(id)`: the register's name ("x0", "w0", "lr", "fp", "sp", "xzr", ...)
    pub fn reg_name(&mut self, id: u16) -> &'static str {
        let i = id as usize;
        if i >= self.names.len() {
            self.names.resize(i + 1, None);
        }
        if let Some(n) = self.names[i] {
            return n;
        }
        // SAFETY: Capstone returns a pointer to a static table entry (or NULL)
        let p = unsafe { sys::cs_reg_name(self.h, id as u32) };
        let n: &'static str = if p.is_null() {
            ""
        } else {
            unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
        };
        self.names[i] = Some(n);
        n
    }

    /// One line of the Capstone equivalence dump, the format of `crates/ibuilder-rewrite/tools/cs_dump.py` (the Python `capstone` 5.0.7 the oracle used): address, then `-` for a word
    /// that does not decode, else mnemonic, `op_str`, the five groups (jump call ret int iret), writeback, the operands (`R<reg>`, `I<imm>`, `M<base>,<index>,<disp>`, `T<type>`) and the
    /// `regs_access()` read and written lists (`ERR` when Capstone refuses them). No newline. `examples/cs_probe.rs dump` and the golden test (`tests/cs_golden.rs`) both print with it.
    pub fn probe_line(&mut self, word: u32, address: u32) -> String {
        let Some(i) = self.decode(word, address as i64) else {
            return format!("{address:#x}\t-");
        };
        let mut ops = Vec::new();
        for op in &i.ops {
            ops.push(match op.ty {
                OP_REG => format!("R{}", self.reg_name(op.reg)),
                OP_IMM => format!("I{}", op.imm),
                OP_MEM => format!(
                    "M{},{},{}",
                    self.reg_name(op.base),
                    self.reg_name(op.index),
                    op.disp
                ),
                t => format!("T{t}"),
            });
        }
        let g: String = (1..=5)
            .map(|g| if i.group(g) { '1' } else { '0' })
            .collect();
        let (rr, rw) = match &i.regs {
            Some((r, w)) => (
                r.iter()
                    .map(|x| self.reg_name(*x))
                    .collect::<Vec<_>>()
                    .join(","),
                w.iter()
                    .map(|x| self.reg_name(*x))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            None => ("ERR".to_string(), "ERR".to_string()),
        };
        format!(
            "{address:#x}\t{}\t{}\t{g}\t{}\t{}\t{rr}\t{rw}",
            i.mn(),
            i.op_str,
            i.writeback as u8,
            ops.join(";")
        )
    }

    /// Decode the word at `address` (4 bytes little endian); `None` when Capstone cannot decode it.
    pub fn decode(&mut self, word: u32, address: i64) -> Option<Ins> {
        self.decode_bytes(&word.to_le_bytes(), address)
    }

    fn decode_bytes(&mut self, bytes: &[u8; 4], address: i64) -> Option<Ins> {
        self.decode_bytes_opt(bytes, address, true)
    }

    fn decode_bytes_opt(&mut self, bytes: &[u8; 4], address: i64, want_regs: bool) -> Option<Ins> {
        let mut code = bytes.as_ptr();
        let mut size = 4usize;
        let mut addr = address as u64;
        // SAFETY: the buffer outlives the call; `ins` is the scratch instruction of this decoder
        let ok = unsafe { sys::cs_disasm_iter(self.h, &mut code, &mut size, &mut addr, self.ins) };
        if !ok {
            return None;
        }
        // SAFETY: cs_disasm_iter filled the scratch instruction
        let i = unsafe { &*self.ins };
        let mut out = Ins {
            address,
            word: u32::from_le_bytes(*bytes),
            mnemonic: cstr(&i.mnemonic),
            op_str: cstr(&i.op_str),
            ops: Ops::default(),
            regs: None,
            groups: 0,
            writeback: false,
            update_flags: false,
        };
        if self.detail {
            // SAFETY: detail is on, so Capstone filled `detail`
            let d = unsafe { &*i.detail };
            for g in &d.groups[..d.groups_count as usize] {
                if *g < 32 {
                    out.groups |= 1 << *g;
                }
            }
            // SAFETY: AArch64 handle: the arm64 member of the union is the live one
            let a = unsafe { &d.__bindgen_anon_1.arm64 };
            out.writeback = a.writeback;
            out.update_flags = a.update_flags;
            let mut ops = [Op::default(); 8];
            let n_ops = (a.op_count as usize).min(a.operands.len());
            for k in 0..n_ops {
                let o = &a.operands[k];
                let ty = o.type_ as u32;
                // SAFETY: the union member read matches the operand type Capstone reports
                let u = &o.__bindgen_anon_1;
                let mut op = Op {
                    ty,
                    reg: 0,
                    imm: 0,
                    base: 0,
                    index: 0,
                    disp: 0,
                    shift_value: o.shift.value.min(255) as u8,
                    shift_ext: (o.shift.type_ as u32 as u8 & 15) | ((o.ext as u32 as u8 & 15) << 4),
                };
                match ty {
                    OP_REG => op.reg = unsafe { u.reg } as u16,
                    OP_IMM | 64 => op.imm = unsafe { u.imm },
                    OP_MEM => {
                        let m = unsafe { u.mem };
                        op.base = m.base as u16;
                        op.index = m.index as u16;
                        op.disp = m.disp;
                    }
                    _ => {}
                }
                ops[k] = op;
            }
            out.ops = Ops::from_slice(&ops[..n_ops]);
            if want_regs {
                let mut rr: sys::cs_regs = [0; 64];
                let mut wr: sys::cs_regs = [0; 64];
                let (mut rc, mut wc) = (0u8, 0u8);
                // SAFETY: arrays are cs_regs-sized as the API requires
                let e = unsafe {
                    sys::cs_regs_access(self.h, self.ins, &mut rr, &mut rc, &mut wr, &mut wc)
                };
                if e == sys::cs_err::CS_ERR_OK {
                    out.regs = Some((
                        RegList::from_slice(&rr[..rc as usize]),
                        RegList::from_slice(&wr[..wc as usize]),
                    ));
                }
            }
        }
        Some(out)
    }

    /// Like `decode` but without `cs_regs_access`: `regs` stays `None` (for callers that read mnemonic, operands and
    /// groups only and call `decode` again for the few instructions whose register lists they need)
    pub fn decode_no_regs(&mut self, word: u32, address: i64) -> Option<Ins> {
        self.decode_bytes_opt(&word.to_le_bytes(), address, false)
    }

    /// Mnemonic and operand text only (no detail): for scans that read the text alone.
    pub fn decode_lite(&mut self, word: u32, address: i64, f: impl FnOnce(&str, &str)) -> bool {
        let bytes = word.to_le_bytes();
        let mut code = bytes.as_ptr();
        let mut size = 4usize;
        let mut addr = address as u64;
        // SAFETY: as decode_bytes
        let ok = unsafe { sys::cs_disasm_iter(self.h, &mut code, &mut size, &mut addr, self.ins) };
        if !ok {
            return false;
        }
        let i = unsafe { &*self.ins };
        // SAFETY: NUL-terminated arrays inside the scratch instruction
        let (m, o) = unsafe {
            (
                CStr::from_ptr(i.mnemonic.as_ptr()),
                CStr::from_ptr(i.op_str.as_ptr()),
            )
        };
        f(&m.to_string_lossy(), &o.to_string_lossy());
        true
    }

    /// Whether Capstone's operand text for the word names x18 / w18 (`\b[xw]18\b`), or `None` when the word does
    /// not decode. Allocation-free: this is the hot loop of the x18 scan.
    pub fn names_x18(&mut self, word: u32, address: i64) -> Option<bool> {
        let bytes = word.to_le_bytes();
        let mut code = bytes.as_ptr();
        let mut size = 4usize;
        let mut addr = address as u64;
        // SAFETY: as decode_bytes
        let ok = unsafe { sys::cs_disasm_iter(self.h, &mut code, &mut size, &mut addr, self.ins) };
        if !ok {
            return None;
        }
        let i = unsafe { &*self.ins };
        let n = i
            .op_str
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(i.op_str.len());
        // SAFETY: c_char -> u8 reinterpretation of the same bytes
        let s: &[u8] = unsafe { core::slice::from_raw_parts(i.op_str.as_ptr() as *const u8, n) };
        Some(has_xw18(s))
    }

    /// `md.disasm(code, address)`: sequential decoding that stops at the first word Capstone cannot decode.
    pub fn disasm(&mut self, code: &[u8], address: i64) -> Vec<Ins> {
        let mut out = Vec::with_capacity(code.len() / 4);
        self.disasm_into(&mut out, code, address);
        out
    }

    /// [`Decoder::disasm`] appending to `out` (no new vector, no capacity reserved: the caller reserves once when it
    /// decodes a function in several runs); returns how many instructions it appended.
    pub fn disasm_into(&mut self, out: &mut Vec<Ins>, code: &[u8], address: i64) -> usize {
        let n0 = out.len();
        let mut a = address;
        for w in code.as_chunks::<4>().0 {
            match self.decode_bytes(w, a) {
                Some(i) => out.push(i),
                None => break,
            }
            a += 4;
        }
        out.len() - n0
    }
}

/// Cheap necessary condition for "the operand text names x18 / w18": every general-purpose register operand of an
/// A64 instruction is one of the 5-bit fields at bits 0, 5, 10 and 16, so a word with none of them equal to 18 cannot
/// name x18 / w18. (Checked against Capstone on every distinct text word of the three Grizzy modules, 6.8 M words in
/// all with 2.4 M fuzzed ones, and by the unit test below.) The x18 scan decodes only the words that pass.
#[inline]
pub fn may_name_x18(w: u32) -> bool {
    (w & 31) == 18 || ((w >> 5) & 31) == 18 || ((w >> 10) & 31) == 18 || ((w >> 16) & 31) == 18
}

/// `re.search(r'\b[xw]18\b', s)`: a standalone register name x18 / w18 (word characters are [A-Za-z0-9_])
pub fn has_xw18(s: &[u8]) -> bool {
    let w = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let n = s.len();
    let mut i = 0;
    while i + 3 <= n {
        if (s[i] == b'x' || s[i] == b'w')
            && s[i + 1] == b'1'
            && s[i + 2] == b'8'
            && (i == 0 || !w(s[i - 1]))
            && (i + 3 == n || !w(s[i + 3]))
        {
            return true;
        }
        i += 1;
    }
    false
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: both were created by cs_open / cs_malloc in `new`
        unsafe {
            sys::cs_free(self.ins, 1);
            sys::cs_close(&mut self.h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn word_boundaries() {
        assert!(has_xw18(b"x0, x18"));
        assert!(has_xw18(b"w18, #1"));
        assert!(has_xw18(b"[x18, #8]"));
        assert!(!has_xw18(b"x181"));
        assert!(!has_xw18(b"ax18"));
        assert!(!has_xw18(b"v18.4s"));
        assert!(has_xw18(b"x1, w18, sxtw"));
    }
    #[test]
    fn x18_prefilter_is_a_superset() {
        // xorshift words: every one that names x18/w18 must pass may_name_x18
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let mut named = 0;
        for i in 0..1_500_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let w = (x >> 16) as u32 ^ (i as u32).rotate_left(7);
            if names_x18(w, 0x1000) == Some(true) {
                named += 1;
                assert!(may_name_x18(w), "{w:#010x}");
            }
        }
        assert!(named > 1000, "sample too small: {named}");
    }

    #[test]
    fn decodes_basic() {
        let mut d = Decoder::new(true);
        // ldr x18, [x0]
        let i = d.decode(0xF9400012, 0x100).unwrap();
        assert_eq!(&*i.mnemonic, "ldr");
        assert_eq!(&*i.op_str, "x18, [x0]");
        assert_eq!(i.ops.len(), 2);
        assert_eq!(i.ops[1].ty, OP_MEM);
        // b #+8
        let b = d.decode(0x14000002, 0x100).unwrap();
        assert_eq!(&*b.mnemonic, "b");
        assert_eq!(b.ops[0].imm, 0x108);
        assert!(b.group(GRP_JUMP));
    }
}
