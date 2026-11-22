//! Positioned, bounded-memory I/O. The Python assembler holds the host, every module piece, a `bytearray` of
//! the whole image and a final `bytes(out)` copy at once (~4x the 190 MB framework). Here the image is never
//! materialised: pieces are copied from their source to their final file offset through one reusable chunk
//! buffer with `pread` / `pwrite`, and the gaps between pieces are holes of a pre-sized file (zeros).
//!
//! `pread`/`pwrite` (std's `FileExt`) rather than `mmap`: no `unsafe`, constant memory, and written pages go
//! to the page cache instead of being dirty pages of this process's address space (which count against an
//! iOS app's jetsam footprint).

use crate::error::{Error, Result};
use std::fs::File;
use std::io;

/// Copy granularity. 1 MiB keeps the per-call overhead negligible and the footprint tiny.
pub const CHUNK: usize = 1 << 20;

/// Random-access reads (a file, or a byte slice in tests).
#[allow(clippy::len_without_is_empty)]
pub trait ReadAt {
    fn len(&self) -> io::Result<u64>;
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

/// Random-access writes into a pre-sized output (a file, or a growable buffer in tests).
pub trait WriteAt {
    /// Set the final length first: every byte not written afterwards reads as zero.
    fn set_len(&mut self, len: u64) -> io::Result<()>;
    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()>;
}

#[cfg(unix)]
impl ReadAt for File {
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }
}

#[cfg(unix)]
impl WriteAt for File {
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        File::set_len(self, len)
    }
    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(self, buf, offset)
    }
}

impl ReadAt for [u8] {
    fn len(&self) -> io::Result<u64> {
        Ok(<[u8]>::len(self) as u64)
    }
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| eof())?;
        let end = start.checked_add(buf.len()).ok_or_else(eof)?;
        let src = self.get(start..end).ok_or_else(eof)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn len(&self) -> io::Result<u64> {
        Ok(Vec::len(self) as u64)
    }
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.as_slice().read_exact_at(buf, offset)
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end")
}

/// An in-memory output (tests, small files): `set_len` zero-fills, writes patch in place.
#[derive(Default, Debug)]
pub struct MemSink(pub Vec<u8>);

impl WriteAt for MemSink {
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.0.resize(len as usize, 0);
        Ok(())
    }
    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        let start = offset as usize;
        let end = start + buf.len();
        if end > self.0.len() {
            self.0.resize(end, 0);
        }
        self.0[start..end].copy_from_slice(buf);
        Ok(())
    }
}

impl ReadAt for MemSink {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.0.as_slice().read_exact_at(buf, offset)
    }
}

/// Read `len` bytes at `off` into a fresh Vec, bounds-checked against the source length.
pub fn read_vec<R: ReadAt + ?Sized>(src: &R, off: u64, len: u64, what: &str) -> Result<Vec<u8>> {
    let total = src
        .len()
        .map_err(|e| Error::io(format!("{what}: length"), e))?;
    let end = off
        .checked_add(len)
        .ok_or_else(|| Error::invalid(format!("{what}: range overflows")))?;
    if end > total {
        return Err(Error::invalid(format!(
            "{what}: {off:#x}+{len:#x} is past the end ({total:#x})"
        )));
    }
    let mut v = vec![0u8; len as usize];
    src.read_exact_at(&mut v, off)
        .map_err(|e| Error::io(what.to_string(), e))?;
    Ok(v)
}

/// Copy `len` bytes `src[src_off..]` -> `dst[dst_off..]` through `buf` (the caller's reusable chunk buffer).
pub fn copy_range<R: ReadAt + ?Sized, W: WriteAt + ?Sized>(
    src: &R,
    src_off: u64,
    dst: &mut W,
    dst_off: u64,
    len: u64,
    buf: &mut [u8],
    what: &str,
) -> Result<()> {
    let mut done = 0u64;
    while done < len {
        let n = ((len - done) as usize).min(buf.len());
        src.read_exact_at(&mut buf[..n], src_off + done)
            .map_err(|e| Error::io(format!("{what}: read at {:#x}", src_off + done), e))?;
        dst.write_all_at(&buf[..n], dst_off + done)
            .map_err(|e| Error::io(format!("{what}: write at {:#x}", dst_off + done), e))?;
        done += n as u64;
    }
    Ok(())
}
