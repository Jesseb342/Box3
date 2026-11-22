//! The one loader of Switch code modules: an NSO (ExeFS) or an NRO (loaded at run time with nn::ro) to its memory
//! image of text + ro + data, bss not included. Port of `dm/tools/nso.py`, with the same checks in the same order
//! (a damaged or truncated file is an [`Error`], never a wrong image):
//!
//! * NSO, as Horizon's loader: memory offsets on pages, text at 0, then ro, then data, none overlapping; sizes below
//!   2 GiB; a compressed segment is no larger stored than loaded and must decompress to exactly its size; a segment
//!   whose check-hash flag is set must match its SHA-256 in the header.
//! * NRO, as nn::ro: sizes in whole pages, text at 0, ro and data right after, data ending at the module's size.
//! * Beyond Horizon, so a small file cannot claim gigabytes: a compressed segment is at most what LZ4 produces from
//!   its stored bytes (255 bytes per byte) and the image no more than that of the whole file.
//! * Compression: LZ4 (`lz4_flex`), and ZBIC (NSO flag bit 7, system 22.0.0 on: Nintendo's zstd variant, its own magic and
//!   table-description coding) through [`zbic`], a pure-Rust decoder in this crate (no C, no extra dependency). A ZBIC segment
//!   has no LZ4-style bound on its ratio, so it is held only to its own size.
//!
//! The image is allocated once (zeroed, lazily committed by the OS) and every segment is decompressed straight into
//! it, so a module costs its image size and nothing else; the input may be a memory map.

use sha2::{Digest, Sha256};
use std::fmt;

pub mod zbic;

pub const PAGE: u32 = 0x1000;
/// an LZ4 block produces at most 255 bytes per stored byte
pub const LZ4_MAX_RATIO: u64 = 255;
/// The most a zstd/ZBIC stream can expand: a block is at most 128 KiB of output and costs at least 4 input bytes (3-byte header + one RLE byte).
pub const ZSTD_MAX_RATIO: u64 = 32768;
/// Slack on top of `ZSTD_MAX_RATIO` for the frame header and the last block.
const ZSTD_SLACK: u64 = 128 << 10;
/// Horizon reads segment sizes as s32
pub const SIZE_MAX: u32 = 0x7FFF_FFFF;
const NSO_ZSTD: u32 = 1 << 7;
const NRO_COMPRESSED: u32 = 1 << 1;
pub const NAMES: [&str; 3] = ["text", "ro", "data"];

/// A damaged, truncated or unsupported module (the Python `nso.Error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

macro_rules! err {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

/// A loaded module: its memory image (text + ro + data at their memory offsets), the (memory offset, size) of the
/// three segments, the bss size and the 0x20-byte build ID (the one tools key on is its first 0x10).
#[derive(Debug)]
pub struct Module {
    pub image: Vec<u8>,
    pub segments: [(u32, u32); 3],
    pub bss: u32,
    pub build_id: [u8; 0x20],
}

impl Module {
    pub fn text_end(&self) -> u32 {
        self.segments[0].1
    }
}

fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

/// Module of the file's bytes `d` (NSO0 or NRO0); `name` goes into the error messages.
pub fn load(d: &[u8], name: &str) -> Result<Module> {
    let (flags, stored, csz, bss, build_id);
    if d.get(..4) == Some(b"NSO0") {
        if d.len() < 0x100 {
            err!("{name}: the NSO header is cut short ({} bytes)", d.len());
        }
        flags = u32le(d, 0xc);
        let mut st = [(0u32, 0u32, 0u32); 3];
        let mut cs = [0u32; 3];
        for i in 0..3 {
            st[i] = (
                u32le(d, 0x10 + i * 0x10),
                u32le(d, 0x14 + i * 0x10),
                u32le(d, 0x18 + i * 0x10),
            );
            let c = u32le(d, 0x60 + 4 * i);
            cs[i] = if flags >> i & 1 != 0 { c } else { st[i].2 };
        }
        stored = st;
        csz = cs;
        bss = u32le(d, 0x3c);
        build_id = d[0x40..0x60].try_into().unwrap();
        for i in 0..3 {
            let (fo, mo, sz) = stored[i];
            let c = csz[i];
            let what = format!("{name}: {} segment", NAMES[i]);
            if mo % PAGE != 0 {
                err!("{what} is at {mo:#x}, not on a page");
            }
            if sz > SIZE_MAX {
                err!("{what} claims {sz:#x} bytes, more than Horizon loads");
            }
            if fo as u64 + c as u64 > d.len() as u64 {
                err!(
                    "{what} is stored at {fo:#x}..{:#x}, past the end of the file ({:#x} bytes): the file is cut short or damaged",
                    fo as u64 + c as u64,
                    d.len()
                );
            }
            if flags >> i & 1 != 0 && c > sz {
                err!("{what} is stored compressed in {c:#x} bytes, more than its {sz:#x}");
            }
            if flags >> i & 1 != 0 && flags & NSO_ZSTD == 0 && sz as u64 > c as u64 * LZ4_MAX_RATIO
            {
                err!("{what} claims {sz:#x} bytes from {c:#x} stored, more than LZ4 can produce");
            }
        }
        if stored[0].1 != 0 {
            err!("{name}: text segment is at {:#x}, not at 0", stored[0].1);
        }
        for i in 1..3 {
            if (stored[i].1 as u64) < stored[i - 1].1 as u64 + stored[i - 1].2 as u64 {
                err!(
                    "{name}: {} segment at {:#x} overlaps the {} segment before it",
                    NAMES[i],
                    stored[i].1,
                    NAMES[i - 1]
                );
            }
        }
    } else if d.get(0x10..0x14) == Some(b"NRO0") {
        // The file is the image itself: each segment stored at its memory offset, uncompressed; +0x18 the module's
        // size, +0x1c flags, +0x20 text, +0x28 ro, +0x30 data as {offset, size}, +0x38 bss size, +0x40 the build ID
        if d.len() < 0x80 {
            err!("{name}: the NRO header is cut short ({} bytes)", d.len());
        }
        let size = u32le(d, 0x18);
        let nflags = u32le(d, 0x1c);
        if nflags & NRO_COMPRESSED != 0 {
            err!(
                "{name}: a compressed NRO (system 23.0.0+), which this loader does not decode yet"
            );
        }
        flags = 0;
        let mut st = [(0u32, 0u32, 0u32); 3];
        for (i, seg) in st.iter_mut().enumerate() {
            let (o, sz) = (u32le(d, 0x20 + 8 * i), u32le(d, 0x24 + 8 * i));
            *seg = (o, o, sz);
        }
        stored = st;
        csz = [st[0].2, st[1].2, st[2].2];
        bss = u32le(d, 0x38);
        build_id = d[0x40..0x60].try_into().unwrap();
        let mut at = 0u64;
        for i in 0..3 {
            let (o, _, sz) = stored[i];
            if sz % PAGE != 0 || o as u64 != at {
                err!(
                    "{name}: {} segment {o:#x}..{:#x} is not whole pages right after the one before it (at {at:#x})",
                    NAMES[i],
                    o as u64 + sz as u64
                );
            }
            at += sz as u64;
        }
        if at != size as u64 {
            err!("{name}: the segments end at {at:#x}, not at the module's size {size:#x}");
        }
        if size as usize > d.len() {
            err!(
                "{name}: the module is {size:#x} bytes, the file {:#x}: the file is cut short or damaged",
                d.len()
            );
        }
    } else {
        err!(
            "{name}: not an NSO or NRO (magic {:?})",
            &d[..d.len().min(4)]
        );
    }
    let end = stored[2].1 as u64 + stored[2].2 as u64;
    // the bound on what the file can fill depends on the codec: x255 for LZ4, x32768 (+ slack) for zstd/ZBIC (flag bit 7 of an NSO)
    let bound = if flags & NSO_ZSTD != 0 {
        d.len() as u64 * ZSTD_MAX_RATIO + ZSTD_SLACK
    } else {
        d.len() as u64 * LZ4_MAX_RATIO
    };
    if end > bound {
        err!(
            "{name}: the segments span {end:#x} bytes, more than a file of {:#x} bytes can fill (a gap of zeros between them)",
            d.len()
        );
    }
    let mut img = vec![0u8; end as usize];
    for i in 0..3 {
        let (fo, mo, sz) = stored[i];
        let c = csz[i] as usize;
        let raw = &d[fo as usize..fo as usize + c];
        let out = &mut img[mo as usize..mo as usize + sz as usize];
        let what = format!("{name}: {} segment", NAMES[i]);
        if flags >> i & 1 != 0 {
            if flags & NSO_ZSTD != 0 {
                match zbic::decompress_into(raw, out) {
                    Ok(n) if n == sz as usize => {}
                    Ok(n) => err!(
                        "{what}: ZBIC decompresses to {n:#x} bytes, not the {sz:#x} of the header: the file is damaged"
                    ),
                    Err(e) => err!("{what}: ZBIC does not decompress ({e})"),
                }
            } else {
                match lz4_flex::block::decompress_into(raw, out) {
                    Ok(n) if n == sz as usize => {}
                    Ok(n) => err!(
                        "{what} decompresses to {n:#x} bytes, not the {sz:#x} of the header: the file is damaged"
                    ),
                    Err(e) => err!("{what} does not decompress ({e})"),
                }
            }
        } else {
            if raw.len() != sz as usize {
                err!(
                    "{what} decompresses to {:#x} bytes, not the {sz:#x} of the header: the file is damaged",
                    raw.len()
                );
            }
            out.copy_from_slice(raw);
        }
        if flags >> (3 + i) & 1 != 0
            && Sha256::digest(&*out).as_slice() != &d[0xa0 + 0x20 * i..0xc0 + 0x20 * i]
        {
            err!("{what} does not match its SHA-256 in the header: the file is damaged");
        }
    }
    Ok(Module {
        image: img,
        segments: [
            (stored[0].1, stored[0].2),
            (stored[1].1, stored[1].2),
            (stored[2].1, stored[2].2),
        ],
        bss,
        build_id,
    })
}

/// `load` of a file by path (memory-mapped); the error carries the path.
pub fn read(path: &std::path::Path) -> Result<Module> {
    let f = std::fs::File::open(path).map_err(|e| Error(format!("{}: {e}", path.display())))?;
    // SAFETY: the map is only read while `load` runs; a file truncated by someone else meanwhile is the caller's problem
    // as it is for any mapped input
    let m =
        unsafe { memmap2::Mmap::map(&f) }.map_err(|e| Error(format!("{}: {e}", path.display())))?;
    load(&m, &path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_nso(text: &[u8], compress: bool) -> Vec<u8> {
        let mut h = vec![0u8; 0x100];
        h[..4].copy_from_slice(b"NSO0");
        let seg = if compress {
            lz4_flex::block::compress(text)
        } else {
            text.to_vec()
        };
        let flags: u32 = if compress { 1 | 8 } else { 8 };
        h[0xc..0x10].copy_from_slice(&flags.to_le_bytes());
        h[0x10..0x14].copy_from_slice(&0x100u32.to_le_bytes());
        h[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
        h[0x18..0x1c].copy_from_slice(&(text.len() as u32).to_le_bytes());
        // ro and data: empty at the page after text
        let end = (text.len() as u32 + 0xfff) & !0xfff;
        for i in 1..3 {
            h[0x10 + i * 0x10 + 4..0x10 + i * 0x10 + 8].copy_from_slice(&end.to_le_bytes());
            h[0x10 + i * 0x10..0x10 + i * 0x10 + 4]
                .copy_from_slice(&(0x100 + seg.len() as u32).to_le_bytes());
        }
        h[0x60..0x64].copy_from_slice(&(seg.len() as u32).to_le_bytes());
        h[0xa0..0xc0].copy_from_slice(Sha256::digest(text).as_slice());
        h.extend_from_slice(&seg);
        h
    }

    #[test]
    fn loads_plain_and_lz4() {
        let text: Vec<u8> = (0..0x1800u32).map(|i| (i % 7) as u8).collect();
        for c in [false, true] {
            let f = tiny_nso(&text, c);
            let m = load(&f, "t").unwrap();
            assert_eq!(&m.image[..text.len()], &text[..]);
            assert_eq!(m.segments[0], (0, text.len() as u32));
        }
    }

    /// A valid, very compressible ZBIC module (16 MiB of zeros as RLE blocks, ~500 bytes) is above x255 and must load.
    #[test]
    fn loads_highly_compressible_zbic() {
        let total = 16usize << 20;
        let mut seg = b"ZBIC".to_vec();
        seg.extend_from_slice(&[0x00, 0x00]); // frame header descriptor, window descriptor
        let blocks = total / (128 << 10);
        for b in 0..blocks {
            let last = (b + 1 == blocks) as u32;
            let h = last | 1 << 1 | ((128u32 << 10) << 3); // RLE block
            seg.extend_from_slice(&h.to_le_bytes()[..3]);
            seg.push(0);
        }
        let mut h = vec![0u8; 0x100];
        h[..4].copy_from_slice(b"NSO0");
        h[0xc..0x10].copy_from_slice(&(1u32 | 8 | NSO_ZSTD).to_le_bytes());
        h[0x18..0x1c].copy_from_slice(&(total as u32).to_le_bytes());
        for i in 0..3 {
            let (fo, mo, sz) = if i == 0 {
                (0x100u32, 0, total as u32)
            } else {
                (0x100 + seg.len() as u32, total as u32, 0)
            };
            h[0x10 + i * 0x10..0x14 + i * 0x10].copy_from_slice(&fo.to_le_bytes());
            h[0x14 + i * 0x10..0x18 + i * 0x10].copy_from_slice(&mo.to_le_bytes());
            h[0x18 + i * 0x10..0x1c + i * 0x10].copy_from_slice(&sz.to_le_bytes());
        }
        h[0x60..0x64].copy_from_slice(&(seg.len() as u32).to_le_bytes());
        h[0xa0..0xc0].copy_from_slice(Sha256::digest(vec![0u8; total]).as_slice());
        h.extend_from_slice(&seg);
        assert!(
            h.len() as u64 * LZ4_MAX_RATIO < total as u64,
            "the probe must be above the LZ4 bound"
        );
        let m = load(&h, "t").unwrap();
        assert_eq!(m.image.len(), total);
        assert!(m.image.iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_damage() {
        let text: Vec<u8> = vec![1u8; 0x1000];
        let mut f = tiny_nso(&text, false);
        let n = f.len();
        f[n - 1] ^= 1;
        assert!(load(&f, "t").unwrap_err().0.contains("SHA-256"));
        assert!(load(&f[..0x80], "t").unwrap_err().0.contains("cut short"));
        assert!(load(b"XXXX", "t").unwrap_err().0.contains("not an NSO"));
    }
}
