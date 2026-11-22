//! ZBIC: the compression of NSO segments from system 22.0.0 on (NSO flag bit 7). A zstd frame (RFC 8878) that differs from stock Zstandard in
//! two places only:
//!
//! 1. the frame magic is `ZBIC` (`5a 42 49 43`) instead of `28 b5 2f fd`;
//! 2. every FSE table description (the three sequence tables of a block, and the table of an FSE-compressed Huffman weight list) is coded
//!    another way: instead of the variable-width bit fields of RFC 8878 section 4.1.1, as a mixed-radix number built from a binary
//!    interpolative coding of the table's cumulative counts. Everything else (blocks, literals, Huffman streams, sequence bitstreams,
//!    offsets and repeat offsets, predefined tables) is stock zstd, so one decoder serves both with a switch for the description reader.
//!
//! This is a decoder written from the zstd format (RFC 8878) and from the behaviour of the ZBIC coding, which was measured (see
//! `docs/crates/SWITCH2-RUST.md`, "ZBIC"): 3,500+ (table, description) pairs from the `zbic` compressor against stock zstd's tables of the same
//! data, then the three segments of a real `main` against their SHA-256. No Zstandard or ZBIC source code was copied or ported.
//!
//! ## The description (as measured)
//!
//! `b0` is the first byte: its low 7 bits plus one are the description's length in bytes (`b0` included), bit 7 says that the table has
//! low-probability symbols (count `-1`: they take one cell and may step the cumulative count down). The other bytes are read **from the
//! last toward the first** into a 64-bit state that is topped up one byte at a time while it is below `2^40` (the first byte read is the
//! most significant; the window `[2^40, 2^40 + 2^24)` is the one place where the two known compressors differ, see `REFILL_LOW`);
//! digits come out of the state as `state % radix`, `state /= radix`, least significant first:
//!
//! 1. `m - 1`, radix 52 (`m` = the largest symbol; tables of one symbol are RLE and never described)
//! 2. `log - 5`, radix 8 (the table has `2^log` cells)
//! 3. `F - 1`, radix `2^log` where `F` is the final cumulative value (the sum of the counts, a `-1` counting as `-1`)
//! 4. the walk: the cumulative counts `C_k = c_0 + .. + c_(k-1)` at positions 0..=U, `U` the smallest power of two above `m` (so
//!    `C_0 = 0`, `C_(m+1) = ... = C_U = F`), coded by binary interpolative coding in right-first preorder (visit the middle
//!    position `mid = (l + r) / 2` of an interval whose end values are known, then the interval's right half, then its left half).
//!    The digit of a position is `C_mid - (C_l - down(l, mid))` in radix `(C_r + down(mid, r)) - (C_l - down(l, mid)) + 1`, where
//!    `down(a, b)` is the number of symbols in `a..b` that exist (`index <= m`) when the flag is set and 0 when it is not (a table
//!    without low-probability symbols has non-decreasing cumulative counts).
//!
//! The counts are the differences of the cumulative counts; the table is then built as in stock zstd.

use std::fmt;

pub const ZBIC_MAGIC: [u8; 4] = *b"ZBIC";
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// Block_Maximum_Size
const BLOCK_MAX: usize = 128 << 10;

/// which description coding and magic a frame uses
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    /// ZBIC: magic `ZBIC`, interpolative table descriptions
    Zbic,
    /// stock Zstandard: magic `28 b5 2f fd`, RFC 8878 table descriptions (the test oracle of this decoder's shared machinery)
    Zstd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

type R<T> = Result<T, Error>;

macro_rules! bail {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

/// Decompresses the ZBIC frame(s) in `src` into `out` from its start; returns how many bytes were written. A frame that would write more
/// than `out` holds is an error.
pub fn decompress_into(src: &[u8], out: &mut [u8]) -> R<usize> {
    decode(src, out, Variant::Zbic)
}

/// The same decoder for stock Zstandard frames (the tests compare it with libzstd).
pub fn zstd_decompress_into(src: &[u8], out: &mut [u8]) -> R<usize> {
    decode(src, out, Variant::Zstd)
}

pub fn decode(src: &[u8], out: &mut [u8], variant: Variant) -> R<usize> {
    let mut dec = Decoder::new(variant);
    let mut p = 0usize;
    let mut o = 0usize;
    while p < src.len() {
        let (used, wrote) = dec.frame(&src[p..], &mut out[o..])?;
        p += used;
        o += wrote;
    }
    if p == 0 {
        bail!("empty input");
    }
    Ok(o)
}

// ---- FSE ------------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct FseEntry {
    new_state: u16,
    symbol: u8,
    nb_bits: u8,
}

#[derive(Clone, Default)]
struct FseTable {
    log: u32,
    e: Vec<FseEntry>,
}

/// FSE_buildDTable: counts (`-1` = low probability) summing to `2^log` in absolute value
fn build_fse(counts: &[i16], log: u32) -> R<FseTable> {
    let size = 1usize << log;
    if counts.len() > 256 {
        bail!("FSE table: more than 256 symbols");
    }
    let sum: i64 = counts.iter().map(|&c| (c as i64).abs()).sum();
    if sum != size as i64 {
        bail!("FSE table: counts sum to {sum}, not {size}");
    }
    let mut e = vec![FseEntry::default(); size];
    let mut next = [0u16; 256];
    let mut high = size as isize - 1;
    for (s, &c) in counts.iter().enumerate() {
        if c == -1 {
            e[high as usize].symbol = s as u8;
            high -= 1;
            next[s] = 1;
        } else if c >= 0 {
            next[s] = c as u16;
        } else {
            bail!("FSE table: count {c}");
        }
    }
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut pos = 0usize;
    for (s, &c) in counts.iter().enumerate() {
        for _ in 0..c.max(0) {
            e[pos].symbol = s as u8;
            pos = (pos + step) & mask;
            while pos as isize > high {
                pos = (pos + step) & mask;
            }
        }
    }
    if pos != 0 {
        bail!("FSE table: the symbols do not fill it");
    }
    for ent in e.iter_mut().take(size) {
        let s = ent.symbol as usize;
        let ns = next[s] as u32;
        next[s] += 1;
        let nb = log - (31 - ns.leading_zeros());
        ent.nb_bits = nb as u8;
        ent.new_state = ((ns << nb) - size as u32) as u16;
    }
    Ok(FseTable { log, e })
}

/// RFC 8878 4.1.1: a table description in the stock coding -> (counts, log, bytes used)
fn parse_desc_std(buf: &[u8], max_log: u32, max_sym: usize) -> R<(Vec<i16>, u32, usize)> {
    let mut bit = 0usize;
    let rd = |n: u32, bit: &mut usize| -> R<u32> {
        let mut v = 0u32;
        for i in 0..n {
            let byte = *buf
                .get(*bit >> 3)
                .ok_or_else(|| Error("FSE table description is cut short".into()))?;
            v |= (((byte >> (*bit & 7)) & 1) as u32) << i;
            *bit += 1;
        }
        Ok(v)
    };
    let log = rd(4, &mut bit)? + 5;
    if log > max_log {
        bail!("FSE accuracy log {log} above {max_log}");
    }
    let mut remaining = (1i32 << log) + 1;
    let mut threshold = 1i32 << log;
    let mut nbits = log + 1;
    let mut counts: Vec<i16> = vec![];
    let mut prev0 = false;
    while remaining > 1 && counts.len() <= max_sym {
        if prev0 {
            loop {
                let rep = rd(2, &mut bit)?;
                counts.resize(counts.len() + rep as usize, 0);
                if rep != 3 {
                    break;
                }
            }
            prev0 = false;
            if counts.len() > max_sym + 1 {
                bail!("FSE table has too many symbols");
            }
            continue;
        }
        let mx = (2 * threshold - 1) - remaining;
        let low = rd(nbits - 1, &mut bit)? as i32;
        let count = if low < mx {
            low
        } else {
            let hi = rd(1, &mut bit)? as i32;
            let mut c = low | (hi << (nbits - 1));
            if c >= threshold {
                c -= mx;
            }
            c
        };
        let count = count - 1;
        remaining -= count.abs();
        counts.push(count as i16);
        prev0 = count == 0;
        while remaining < threshold {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 || counts.len() > max_sym + 1 {
        bail!("FSE table description is damaged");
    }
    Ok((counts, log, (bit + 7) >> 3))
}

/// The state of a description is topped up, a byte at a time from the end of the description toward its start, while it is below `2^40` (`REFILL_LOW`), and
/// never when it is at `2^40 + 2^24` (`REFILL_HIGH`) or above. Between the two, a state of `[2^40, 2^40 + 2^24)`, the format does not say by itself:
/// the `zbic` compressor flushes a byte there (it keeps its state below `2^48 + 2^32`), the compressor of the real modules does not (below `2^48`), and
/// both streams decode with the one decoder. So the decoder tries both: [`parse_desc_zbic`] runs the description with every choice for the states
/// that fall in that window (a few in 100,000 descriptions have one) and takes the first that ends with a valid table and no byte or state left over.
/// Measured on 1,324,246 descriptions of the `zbic` compressor and the 4,881 of the three segments of Ocarina of Time's `main`: every one has
/// exactly such a decode; `2^40` alone fails 1 in 25,000 of the compressor's, `2^40 + 2^24` alone fails one of `main`'s.
const REFILL_LOW: u64 = 1 << 40;
const REFILL_HIGH: u64 = (1 << 40) + (1 << 24);
/// the choices tried in the window: 2^this masks at most
const AMBIGUOUS_MAX_BITS: u32 = 10;

/// One run of a description with the choices `mask` (bit `k` set: load a byte at the k-th state that falls in the window).
/// The first is `None` when damaged (a bound that crosses, counts that are not a table), else (counts, log, nothing left over); the second is how many windows were met
fn run_desc_zbic(
    b: &[u8],
    flag: bool,
    max_log: u32,
    max_sym: usize,
    mask: u32,
) -> (Option<(Vec<i16>, u32, bool)>, u32) {
    let len = b.len();
    let mut pos = len;
    let mut state: u64 = 0;
    let mut seen: u32 = 0;
    let refill = |state: &mut u64, pos: &mut usize, seen: &mut u32| {
        while *pos > 1 {
            if *state < REFILL_LOW {
            } else if *state < REFILL_HIGH {
                let take = if *seen < 32 {
                    mask >> *seen & 1 != 0
                } else {
                    false
                };
                *seen += 1;
                if !take {
                    break;
                }
            } else {
                break;
            }
            *pos -= 1;
            *state = (*state << 8) | b[*pos] as u64;
        }
    };
    refill(&mut state, &mut pos, &mut seen);
    let digit = |radix: u64, state: &mut u64, pos: &mut usize, seen: &mut u32| -> u64 {
        let d = *state % radix;
        *state /= radix;
        refill(state, pos, seen);
        d
    };
    let m = digit(52, &mut state, &mut pos, &mut seen) as usize + 1;
    let log = digit(8, &mut state, &mut pos, &mut seen) as u32 + 5;
    if log > max_log || m > max_sym {
        return (None, seen);
    }
    let t = 1u64 << log;
    let f = digit(t, &mut state, &mut pos, &mut seen) as i64 + 1;
    let mut u = 1usize;
    while u < m + 1 {
        u <<= 1;
    }
    let mut known = vec![i64::MIN; u + 1];
    known[0] = 0;
    known[u] = f;
    let down = |a: usize, b: usize| -> i64 {
        if flag {
            (b.min(m + 1) as i64 - a as i64).max(0)
        } else {
            0
        }
    };
    // right-first preorder: visit mid, then the right half, then the left half
    let mut stack: Vec<(usize, usize)> = vec![(0, u)];
    while let Some((l, r)) = stack.pop() {
        if r - l < 2 {
            continue;
        }
        let mid = (l + r) / 2;
        let lo = known[l] - down(l, mid);
        let hi = known[r] + down(mid, r);
        if hi < lo {
            return (None, seen);
        }
        let x = digit((hi - lo + 1) as u64, &mut state, &mut pos, &mut seen);
        known[mid] = lo + x as i64;
        stack.push((l, mid));
        stack.push((mid, r));
    }
    let mut counts = Vec::with_capacity(m + 1);
    let mut sum = 0i64;
    for k in 0..=m {
        let c = known[k + 1] - known[k];
        if !(-1..=t as i64).contains(&c) {
            return (None, seen);
        }
        sum += c.abs();
        counts.push(c as i16);
    }
    if sum != t as i64 {
        return (None, seen);
    }
    (Some((counts, log, state == 0 && pos <= 1)), seen)
}

/// The ZBIC description (see the module doc) -> (counts, log, bytes used)
fn parse_desc_zbic(buf: &[u8], max_log: u32, max_sym: usize) -> R<(Vec<i16>, u32, usize)> {
    let Some(&b0) = buf.first() else {
        bail!("FSE table description is cut short")
    };
    let len = (b0 & 0x7f) as usize + 1;
    if len > buf.len() {
        bail!("FSE table description is cut short");
    }
    let flag = b0 >> 7 != 0;
    let b = &buf[..len];
    // no state in the window (nearly always): one run decides
    let (first, windows) = run_desc_zbic(b, flag, max_log, max_sym, 0);
    let mut fallback: Option<(Vec<i16>, u32)> = None;
    if let Some((c, l, exact)) = first {
        if exact {
            return Ok((c, l, len));
        }
        fallback = Some((c, l));
    }
    for mask in 1u32..(1u32 << windows.clamp(1, AMBIGUOUS_MAX_BITS)) {
        if let (Some((c, l, exact)), _) = run_desc_zbic(b, flag, max_log, max_sym, mask) {
            if exact {
                return Ok((c, l, len));
            }
            fallback.get_or_insert((c, l));
        }
    }
    // a table that is valid but leaves bytes or state over: taken (the segment's SHA-256 decides), as a decoder that does not look at the leftover would
    match fallback {
        Some((c, l)) => Ok((c, l, len)),
        None => bail!("FSE table description is damaged"),
    }
}

// ---- backward bit reader -------------------------------------------------------------------------------------------------------

/// A stream written forward, read backward: the last byte carries a marker bit above the data, and the first bits read are the highest.
struct Rev<'a> {
    buf: &'a [u8],
    /// bits not read yet (negative: read past the start)
    pos: isize,
}

impl<'a> Rev<'a> {
    fn new(buf: &'a [u8]) -> R<Rev<'a>> {
        let Some(&last) = buf.last() else {
            bail!("empty bit stream")
        };
        if last == 0 {
            bail!("bit stream without its end marker");
        }
        Ok(Rev {
            buf,
            pos: ((buf.len() - 1) * 8) as isize + (7 - last.leading_zeros()) as isize,
        })
    }

    #[inline(always)]
    fn load(&self, idx: usize) -> u64 {
        if idx + 8 <= self.buf.len() {
            u64::from_le_bytes(self.buf[idx..idx + 8].try_into().unwrap())
        } else {
            let mut w = [0u8; 8];
            let n = self.buf.len().saturating_sub(idx);
            w[..n].copy_from_slice(&self.buf[idx.min(self.buf.len())..idx.min(self.buf.len()) + n]);
            u64::from_le_bytes(w)
        }
    }

    /// the next `n` (<= 32) bits without consuming them; bits before the start of the stream read as zeros
    #[inline(always)]
    fn peek(&self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let p = self.pos - n as isize;
        let mask = (1u64 << n) - 1;
        if p >= 0 {
            ((self.load((p >> 3) as usize) >> (p & 7)) & mask) as u32
        } else {
            let have = n as isize + p; // bits that exist
            if have <= 0 {
                0
            } else {
                (((self.load(0) & ((1u64 << have) - 1)) << (-p)) & mask) as u32
            }
        }
    }

    #[inline(always)]
    fn skip(&mut self, n: u32) {
        self.pos -= n as isize;
    }

    #[inline(always)]
    fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.skip(n);
        v
    }

    fn overflowed(&self) -> bool {
        self.pos < 0
    }

    fn finished(&self) -> bool {
        self.pos == 0
    }
}

// ---- Huffman ------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct HufTable {
    log: u32,
    /// `(symbol << 8) | bits` by the next `log` bits
    e: Vec<u16>,
}

fn build_huf(mut weights: Vec<u8>) -> R<HufTable> {
    let mut total: u32 = 0;
    for &w in &weights {
        if w > 12 {
            bail!("Huffman weight {w}");
        }
        if w > 0 {
            total += 1 << (w - 1);
        }
    }
    if total == 0 {
        bail!("Huffman weights are all zero");
    }
    let log = 32 - total.leading_zeros(); // highbit + 1
    if log > 12 {
        bail!("Huffman table log {log}");
    }
    let rest = (1u32 << log) - total;
    if rest == 0 || rest & (rest - 1) != 0 {
        bail!("Huffman weights do not complete a power of two");
    }
    weights.push((32 - rest.leading_zeros()) as u8); // the last symbol's weight: highbit(rest) + 1
    if weights.len() > 256 {
        bail!("Huffman table with {} symbols", weights.len());
    }
    let mut rank_count = [0u32; 14];
    for &w in &weights {
        rank_count[w as usize] += 1;
    }
    let mut rank_start = [0u32; 14];
    let mut next = 0u32;
    for w in 1..=log as usize {
        rank_start[w] = next;
        next += rank_count[w] << (w - 1);
    }
    let mut e = vec![0u16; 1 << log];
    for (s, &w) in weights.iter().enumerate() {
        if w == 0 {
            continue;
        }
        let w = w as usize;
        let nb = log + 1 - w as u32;
        let fill = 1u32 << (w - 1);
        let start = rank_start[w] as usize;
        let entry = ((s as u16) << 8) | nb as u16;
        e[start..start + fill as usize].fill(entry);
        rank_start[w] += fill;
    }
    Ok(HufTable { log, e })
}

fn huf_decode_stream(t: &HufTable, stream: &[u8], out: &mut [u8]) -> R<()> {
    let mut r = Rev::new(stream)?;
    let log = t.log;
    for o in out.iter_mut() {
        let en = t.e[r.peek(log) as usize];
        *o = (en >> 8) as u8;
        r.skip((en & 0xff) as u32);
    }
    if !r.finished() {
        bail!("Huffman stream is not used up exactly (corrupt)");
    }
    Ok(())
}

// ---- sequences ----------------------------------------------------------------------------------------------------------------

const LL_PREDEF: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const OF_PREDEF: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
const ML_PREDEF: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

fn bases(first: u32, bits: &[u8]) -> Vec<u32> {
    let mut v = Vec::with_capacity(bits.len());
    let mut b = first;
    for &n in bits {
        v.push(b);
        b += 1 << n;
    }
    v
}

pub struct Decoder {
    variant: Variant,
    ll_base: Vec<u32>,
    ml_base: Vec<u32>,
    // per frame
    ll: Option<FseTable>,
    of: Option<FseTable>,
    ml: Option<FseTable>,
    huf: Option<HufTable>,
    rep: [u32; 3],
    lits: Vec<u8>,
}

impl Decoder {
    pub fn new(variant: Variant) -> Decoder {
        Decoder {
            variant,
            ll_base: bases(0, &LL_BITS),
            ml_base: bases(3, &ML_BITS),
            ll: None,
            of: None,
            ml: None,
            huf: None,
            rep: [1, 4, 8],
            lits: Vec::new(),
        }
    }

    fn desc(&self, buf: &[u8], max_log: u32, max_sym: usize) -> R<(Vec<i16>, u32, usize)> {
        match self.variant {
            Variant::Zbic => parse_desc_zbic(buf, max_log, max_sym),
            Variant::Zstd => parse_desc_std(buf, max_log, max_sym),
        }
    }

    /// One frame at the start of `src` into `out`: (bytes of `src` used, bytes written)
    pub fn frame(&mut self, src: &[u8], out: &mut [u8]) -> R<(usize, usize)> {
        let magic = match self.variant {
            Variant::Zbic => ZBIC_MAGIC,
            Variant::Zstd => ZSTD_MAGIC,
        };
        if src.len() < 5 || src[..4] != magic {
            bail!(
                "not a {} frame (magic {:02x?})",
                if self.variant == Variant::Zbic {
                    "ZBIC"
                } else {
                    "zstd"
                },
                &src[..src.len().min(4)]
            );
        }
        let fhd = src[4];
        if fhd & 0x08 != 0 {
            bail!("frame header with a reserved bit set");
        }
        if fhd & 3 != 0 {
            bail!("frame with a dictionary");
        }
        let single = (fhd >> 5) & 1 != 0;
        let checksum = (fhd >> 2) & 1 != 0;
        let mut p = 5usize;
        if !single {
            p += 1; // window descriptor: the whole output is addressable, so the window is not needed
        }
        let fcs_len = match (fhd >> 6, single) {
            (0, true) => 1,
            (0, false) => 0,
            (1, _) => 2,
            (2, _) => 4,
            _ => 8,
        };
        let mut content: Option<u64> = None;
        if fcs_len > 0 {
            let Some(b) = src.get(p..p + fcs_len) else {
                bail!("frame header is cut short")
            };
            let mut v = 0u64;
            for (i, x) in b.iter().enumerate() {
                v |= (*x as u64) << (8 * i);
            }
            if fcs_len == 2 {
                v += 256;
            }
            content = Some(v);
        }
        p += fcs_len;
        if p > src.len() {
            bail!("frame header is cut short");
        }
        if let Some(c) = content
            && c > out.len() as u64
        {
            bail!(
                "frame decompresses to {c:#x} bytes, more than the {:#x} it may",
                out.len()
            );
        }
        self.ll = None;
        self.of = None;
        self.ml = None;
        self.huf = None;
        self.rep = [1, 4, 8];
        let mut o = 0usize;
        loop {
            let Some(h) = src.get(p..p + 3) else {
                bail!("block header is cut short")
            };
            let h = h[0] as usize | (h[1] as usize) << 8 | (h[2] as usize) << 16;
            p += 3;
            let last = h & 1 != 0;
            let size = h >> 3;
            match (h >> 1) & 3 {
                0 => {
                    if size > BLOCK_MAX {
                        bail!("raw block of {size} bytes");
                    }
                    let Some(b) = src.get(p..p + size) else {
                        bail!("raw block is cut short")
                    };
                    let Some(dst) = out.get_mut(o..o + size) else {
                        bail!("output is larger than expected")
                    };
                    dst.copy_from_slice(b);
                    p += size;
                    o += size;
                }
                1 => {
                    if size > BLOCK_MAX {
                        bail!("RLE block of {size} bytes");
                    }
                    let Some(&b) = src.get(p) else {
                        bail!("RLE block is cut short")
                    };
                    let Some(dst) = out.get_mut(o..o + size) else {
                        bail!("output is larger than expected")
                    };
                    dst.fill(b);
                    p += 1;
                    o += size;
                }
                2 => {
                    if size > BLOCK_MAX {
                        bail!("compressed block of {size} bytes");
                    }
                    let Some(b) = src.get(p..p + size) else {
                        bail!("compressed block is cut short")
                    };
                    o += self.block(b, out, o)?;
                    p += size;
                }
                _ => bail!("reserved block type"),
            }
            if last {
                break;
            }
        }
        if checksum {
            if src.len() < p + 4 {
                bail!("content checksum is cut short");
            }
            p += 4; // XXH64's low 32 bits: the segment's SHA-256 in the NSO header is the check
        }
        if let Some(c) = content
            && c != o as u64
        {
            bail!("frame decompresses to {o:#x} bytes, its header says {c:#x}");
        }
        Ok((p, o))
    }

    /// A compressed block: literals section, sequences section; returns the bytes it wrote. `done` = bytes of this frame written before it
    fn block(&mut self, b: &[u8], out: &mut [u8], start: usize) -> R<usize> {
        let (consumed, _) = self.literals(b)?;
        let mut p = consumed;
        let Some(&s0) = b.get(p) else {
            bail!("sequences section is missing")
        };
        p += 1;
        let nseq = match s0 {
            0 => 0usize,
            1..=127 => s0 as usize,
            128..=254 => {
                let Some(&s1) = b.get(p) else {
                    bail!("sequences header is cut short")
                };
                p += 1;
                ((s0 as usize - 128) << 8) + s1 as usize
            }
            255 => {
                let Some(x) = b.get(p..p + 2) else {
                    bail!("sequences header is cut short")
                };
                p += 2;
                x[0] as usize + ((x[1] as usize) << 8) + 0x7f00
            }
        };
        if nseq == 0 {
            if p != b.len() {
                bail!(
                    "a block without sequences has {} bytes after its header",
                    b.len() - p
                );
            }
            let n = self.lits.len();
            let Some(dst) = out.get_mut(start..start + n) else {
                bail!("output is larger than expected")
            };
            dst.copy_from_slice(&self.lits);
            return Ok(n);
        }
        let Some(&modes) = b.get(p) else {
            bail!("sequences header is cut short")
        };
        p += 1;
        if modes & 3 != 0 {
            bail!("reserved bits of the sequence modes are set");
        }
        for (i, (mode, max_log, max_sym)) in [
            ((modes >> 6) & 3, 9u32, 35usize),
            ((modes >> 4) & 3, 8, 31),
            ((modes >> 2) & 3, 9, 52),
        ]
        .into_iter()
        .enumerate()
        {
            let t = match mode {
                0 => {
                    let (c, l): (&[i16], u32) = match i {
                        0 => (&LL_PREDEF, 6),
                        1 => (&OF_PREDEF, 5),
                        _ => (&ML_PREDEF, 6),
                    };
                    build_fse(c, l)?
                }
                1 => {
                    let Some(&sym) = b.get(p) else {
                        bail!("RLE table symbol is missing")
                    };
                    p += 1;
                    if sym as usize > max_sym {
                        bail!("RLE table symbol {sym}");
                    }
                    FseTable {
                        log: 0,
                        e: vec![FseEntry {
                            new_state: 0,
                            symbol: sym,
                            nb_bits: 0,
                        }],
                    }
                }
                2 => {
                    let (counts, log, used) = self.desc(&b[p..], max_log, max_sym)?;
                    p += used;
                    build_fse(&counts, log)?
                }
                _ => {
                    // repeat: the previous block's table
                    let have = match i {
                        0 => &self.ll,
                        1 => &self.of,
                        _ => &self.ml,
                    };
                    if have.is_none() {
                        bail!("a repeated sequence table with none before it");
                    }
                    continue;
                }
            };
            match i {
                0 => self.ll = Some(t),
                1 => self.of = Some(t),
                _ => self.ml = Some(t),
            }
        }
        let (ll, of, ml) = (
            self.ll.as_ref().unwrap(),
            self.of.as_ref().unwrap(),
            self.ml.as_ref().unwrap(),
        );
        let mut r = Rev::new(&b[p..])?;
        let mut sll = r.read(ll.log) as usize;
        let mut sof = r.read(of.log) as usize;
        let mut sml = r.read(ml.log) as usize;
        let mut pos = start; // output (the frame's, so matches reach back into earlier blocks)
        let mut lp = 0usize; // literals
        let lits = &self.lits;
        for i in 0..nseq {
            let (ell, eof, eml) = (ll.e[sll], of.e[sof], ml.e[sml]);
            let (llc, ofc, mlc) = (ell.symbol as usize, eof.symbol as u32, eml.symbol as usize);
            if llc >= LL_BITS.len() || mlc >= ML_BITS.len() || ofc > 31 {
                bail!("sequence code out of range");
            }
            let ov = (1u64 << ofc) + r.read(ofc) as u64;
            let mlen = self.ml_base[mlc] as usize + r.read(ML_BITS[mlc] as u32) as usize;
            let llen = self.ll_base[llc] as usize + r.read(LL_BITS[llc] as u32) as usize;
            if i + 1 < nseq {
                sll = ell.new_state as usize + r.read(ell.nb_bits as u32) as usize;
                sml = eml.new_state as usize + r.read(eml.nb_bits as u32) as usize;
                sof = eof.new_state as usize + r.read(eof.nb_bits as u32) as usize;
            }
            if r.overflowed() {
                bail!("sequence bit stream is read past its start (corrupt)");
            }
            // the offset: values 1..=3 are the repeat offsets
            let offset: usize = if ov > 3 {
                let a = (ov - 3) as u32;
                self.rep = [a, self.rep[0], self.rep[1]];
                a as usize
            } else {
                let idx = (ov as usize - 1) + (llen == 0) as usize;
                match idx {
                    0 => self.rep[0] as usize,
                    1 => {
                        let a = self.rep[1];
                        self.rep = [a, self.rep[0], self.rep[2]];
                        a as usize
                    }
                    2 => {
                        let a = self.rep[2];
                        self.rep = [a, self.rep[0], self.rep[1]];
                        a as usize
                    }
                    _ => {
                        let a = self.rep[0].wrapping_sub(1);
                        if a == 0 {
                            bail!("a repeat offset of zero");
                        }
                        self.rep = [a, self.rep[0], self.rep[1]];
                        a as usize
                    }
                }
            };
            if llen > lits.len() - lp {
                bail!("a sequence takes more literals than the block has");
            }
            if pos + llen + mlen > out.len() {
                bail!("output is larger than expected");
            }
            out[pos..pos + llen].copy_from_slice(&lits[lp..lp + llen]);
            lp += llen;
            pos += llen;
            copy_match(out, pos, offset, mlen)?;
            pos += mlen;
        }
        if !r.finished() {
            bail!("sequence bit stream is not used up exactly (corrupt)");
        }
        let rest = lits.len() - lp;
        let Some(dst) = out.get_mut(pos..pos + rest) else {
            bail!("output is larger than expected")
        };
        dst.copy_from_slice(&lits[lp..]);
        Ok(pos + rest - start)
    }

    /// The literals section at the start of `b` into `self.lits`; returns (bytes used, regenerated size)
    fn literals(&mut self, b: &[u8]) -> R<(usize, usize)> {
        let Some(&b0) = b.first() else {
            bail!("literals section is missing")
        };
        let ltype = b0 & 3;
        let sf = (b0 >> 2) & 3;
        let rd = |n: usize| -> R<u64> {
            let Some(x) = b.get(..n) else {
                bail!("literals header is cut short")
            };
            let mut v = 0u64;
            for (i, y) in x.iter().enumerate() {
                v |= (*y as u64) << (8 * i);
            }
            Ok(v)
        };
        self.lits.clear();
        if ltype < 2 {
            let (hdr, regen) = match sf {
                0 | 2 => (1usize, (b0 >> 3) as usize),
                1 => (2, (rd(2)? >> 4) as usize),
                _ => (3, (rd(3)? >> 4) as usize),
            };
            if regen > BLOCK_MAX {
                bail!("literals section of {regen} bytes");
            }
            if ltype == 0 {
                let Some(x) = b.get(hdr..hdr + regen) else {
                    bail!("raw literals are cut short")
                };
                self.lits.extend_from_slice(x);
                return Ok((hdr + regen, regen));
            }
            let Some(&x) = b.get(hdr) else {
                bail!("RLE literal is missing")
            };
            self.lits.resize(regen, x);
            return Ok((hdr + 1, regen));
        }
        let (hdr, streams4, regen, csz) = match sf {
            0 => {
                let v = rd(3)?;
                (
                    3usize,
                    false,
                    ((v >> 4) & 0x3ff) as usize,
                    ((v >> 14) & 0x3ff) as usize,
                )
            }
            1 => {
                let v = rd(3)?;
                (
                    3,
                    true,
                    ((v >> 4) & 0x3ff) as usize,
                    ((v >> 14) & 0x3ff) as usize,
                )
            }
            2 => {
                let v = rd(4)?;
                (
                    4,
                    true,
                    ((v >> 4) & 0x3fff) as usize,
                    ((v >> 18) & 0x3fff) as usize,
                )
            }
            _ => {
                let v = rd(5)?;
                (
                    5,
                    true,
                    ((v >> 4) & 0x3ffff) as usize,
                    ((v >> 22) & 0x3ffff) as usize,
                )
            }
        };
        if regen > BLOCK_MAX {
            bail!("literals section of {regen} bytes");
        }
        let Some(mut body) = b.get(hdr..hdr + csz) else {
            bail!("compressed literals are cut short")
        };
        if ltype == 2 {
            // the Huffman tree description
            let Some(&hb) = body.first() else {
                bail!("Huffman tree description is missing")
            };
            let mut weights: Vec<u8> = Vec::new();
            let used = if hb >= 128 {
                let n = hb as usize - 127;
                let nbytes = n.div_ceil(2);
                let Some(x) = body.get(1..1 + nbytes) else {
                    bail!("Huffman weights are cut short")
                };
                for i in 0..n {
                    weights.push(if i % 2 == 0 {
                        x[i / 2] >> 4
                    } else {
                        x[i / 2] & 15
                    });
                }
                1 + nbytes
            } else {
                let hb = hb as usize;
                let Some(x) = body.get(1..1 + hb) else {
                    bail!("Huffman weights are cut short")
                };
                let (counts, log, dl) = self.desc(x, 6, 12)?;
                if dl >= hb {
                    bail!("Huffman weight stream is missing");
                }
                let t = build_fse(&counts, log)?;
                let mut r = Rev::new(&x[dl..])?;
                let mut s1 = r.read(t.log) as usize;
                let mut s2 = r.read(t.log) as usize;
                loop {
                    let e = t.e[s1];
                    weights.push(e.symbol);
                    s1 = e.new_state as usize + r.read(e.nb_bits as u32) as usize;
                    if r.overflowed() {
                        weights.push(t.e[s2].symbol);
                        break;
                    }
                    let e = t.e[s2];
                    weights.push(e.symbol);
                    s2 = e.new_state as usize + r.read(e.nb_bits as u32) as usize;
                    if r.overflowed() {
                        weights.push(t.e[s1].symbol);
                        break;
                    }
                    if weights.len() > 255 {
                        bail!("more than 255 Huffman weights");
                    }
                }
                if weights.len() > 255 {
                    bail!("more than 255 Huffman weights");
                }
                1 + hb
            };
            self.huf = Some(build_huf(weights)?);
            body = &body[used..];
        }
        let Some(t) = self.huf.as_ref() else {
            bail!("treeless literals with no Huffman table before them")
        };
        self.lits.resize(regen, 0);
        if !streams4 {
            huf_decode_stream(t, body, &mut self.lits)?;
        } else {
            let Some(j) = body.get(..6) else {
                bail!("Huffman jump table is cut short")
            };
            let s1 = j[0] as usize | (j[1] as usize) << 8;
            let s2 = j[2] as usize | (j[3] as usize) << 8;
            let s3 = j[4] as usize | (j[5] as usize) << 8;
            let rest = &body[6..];
            if s1 + s2 + s3 >= rest.len() {
                bail!("Huffman streams do not fit");
            }
            let seg = regen.div_ceil(4);
            if regen < 6 {
                // zstd refuses fewer than 6 literals in four streams
                bail!("four Huffman streams for {regen} literals");
            }
            let bounds = [0, s1, s1 + s2, s1 + s2 + s3, rest.len()];
            let (a, bb) = self.lits.split_at_mut(seg.min(regen));
            let (c, rest_l) = bb.split_at_mut(seg.min(bb.len()));
            let (d, e) = rest_l.split_at_mut(seg.min(rest_l.len()));
            huf_decode_stream(t, &rest[bounds[0]..bounds[1]], a)?;
            huf_decode_stream(t, &rest[bounds[1]..bounds[2]], c)?;
            huf_decode_stream(t, &rest[bounds[2]..bounds[3]], d)?;
            huf_decode_stream(t, &rest[bounds[3]..bounds[4]], e)?;
        }
        Ok((hdr + csz, regen))
    }
}

/// the match: `len` bytes from `offset` back of `out[pos]`; an offset below the length overlaps (the copy repeats the pattern)
#[inline(always)]
fn copy_match(out: &mut [u8], pos: usize, offset: usize, len: usize) -> R<()> {
    if offset == 0 || offset > pos {
        bail!("a match with offset {offset} at {pos}");
    }
    let src = pos - offset;
    if offset >= len {
        out.copy_within(src..src + len, pos);
    } else {
        for i in 0..len {
            out[pos + i] = out[src + i];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rev_reads_the_top_bits_first() {
        // stream: bytes [0b1010_1100, 0b0000_0111]: marker is bit 2 of the last byte; data bits below it: 11 then the first byte
        let r = Rev::new(&[0b1010_1100, 0b0000_0111]).unwrap();
        assert_eq!(r.pos, 8 + 2);
        let mut r = r;
        assert_eq!(r.read(2), 0b11);
        assert_eq!(r.read(4), 0b1010);
        assert_eq!(r.read(4), 0b1100);
        assert!(r.finished());
    }

    #[test]
    fn descriptions_in_the_refill_window() {
        // the window [2^40, 2^40 + 2^24): a state there is topped up by the `zbic` compressor's streams and left alone by the real modules'.
        // From the real `main` (a Match Length table: left alone) and from the compressor (a Literal Length and an Offset table: topped up)
        let (c, log, _) =
            parse_desc_zbic(&hex("134ae17a4a06673f49993f432afa7748ae5d7403"), 9, 52).unwrap();
        assert_eq!(log, 7);
        assert_eq!(
            c,
            [
                0, 5, 29, 16, 16, 10, 4, 4, 7, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1
            ]
        );
        let (c, log, _) = parse_desc_zbic(&hex("0afedfeefb3bdeec200034"), 9, 35).unwrap();
        assert_eq!(
            (log, c),
            (
                8,
                vec![42, 60, 121, 20, 10, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]
            )
        );
        let (c, log, _) = parse_desc_zbic(&hex("0bc2525e68fa6979500cac03"), 8, 31).unwrap();
        assert_eq!(
            (log, c),
            (7, vec![18, 0, 15, 1, 1, 5, 4, 3, 36, 20, 7, 5, 5, 7, 1])
        );
        let (c, log, _) = parse_desc_zbic(&hex("8cd281712d6adb5aa88c070034"), 8, 31).unwrap();
        assert_eq!(
            (log, c),
            (
                8,
                vec![159, 0, -1, -1, 4, 5, 5, 7, 7, 14, 9, 13, 10, 13, 5, 3]
            )
        );
        let (c, log, _) = parse_desc_zbic(&hex("8fd57ddc9f658fccff6b00fb060e7901"), 8, 31).unwrap();
        assert_eq!(
            (log, c),
            (
                8,
                vec![160, 0, 8, 13, 9, 14, 11, 8, 6, 5, 5, 3, 3, 3, 3, 2, 2, 1]
            )
        );
    }

    #[test]
    fn a_description_that_is_no_table_is_an_error() {
        assert!(parse_desc_zbic(&[0x00], 9, 35).is_err());
        assert!(parse_desc_zbic(&[0x05, 1, 2], 9, 35).is_err());
        assert!(parse_desc_zbic(&[], 9, 35).is_err());
        // the table of the first test with the log above what the caller allows
        assert!(parse_desc_zbic(&[0x03, 0xc8, 0xfe, 0x67], 6, 35).is_err());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_description_of_two_symbols() {
        // the ZBIC compressor's description of the counts (127, 1) at accuracy log 7: 03 c8 fe 67
        let (c, log, used) = parse_desc_zbic(&[0x03, 0xc8, 0xfe, 0x67], 9, 35).unwrap();
        assert_eq!((c, log, used), (vec![127, 1], 7, 4));
    }

    #[test]
    fn a_description_with_a_low_probability_symbol() {
        // (-1, 509, 2) at log 9: 84 f1 3b 10 1a
        let (c, log, _) = parse_desc_zbic(&[0x84, 0xf1, 0x3b, 0x10, 0x1a], 9, 35).unwrap();
        assert_eq!((c, log), (vec![-1, 509, 2], 9));
    }

    #[test]
    fn a_huffman_weight_description() {
        // (0, 15, 11, 5, 1) at log 5: 04 63 ca 8a 26
        let (c, log, used) = parse_desc_zbic(&[0x04, 0x63, 0xca, 0x8a, 0x26], 6, 12).unwrap();
        assert_eq!((c, log, used), (vec![0, 15, 11, 5, 1], 5, 5));
    }
}
