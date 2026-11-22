//! Port of `tools/fix_tlv.py`: copy `__DATA,__thread_vars` from a naturally-linked dylib into one linked with
//! `-Wl,-segaddr,__DATA,<addr>`.
//!
//! Measured linker quirk (ld 27106.1): when `-segaddr __DATA` moves the writable segment, ld adds the
//! segment's vmaddr delta to every TLV descriptor's `offset` field (third word of each `{thunk, key, offset}`
//! entry). The fix links the same objects once without `-segaddr` (true offsets) and copies the section
//! back, after checking the two sections differ **only** in that word, by one constant.

use crate::error::{Error, Result};
use crate::io::{ReadAt, WriteAt, read_vec};
use crate::macho::*;

/// `(addr, size, file offset)` of `segname,sectname` (`find_section`).
pub fn find_section<R: ReadAt + ?Sized>(
    r: &R,
    segname: &str,
    sectname: &str,
) -> Result<Option<(u64, u64, u32)>> {
    let head = read_vec(r, 0, 32, "Mach-O header")?;
    let ncmds = rd_u32(&head, 16)?;
    let sizeofcmds = rd_u32(&head, 20)? as u64;
    // `ncmds` commands of at least 8 bytes each must fit in `sizeofcmds`, and a command smaller than its own header does not move `off`: 2^32 turns of the loop for a file that is only damaged
    // (review r2, N2; `macho::parse` has had both checks since the first review)
    if u64::from(ncmds) * 8 > sizeofcmds {
        return Err(Error::invalid(format!(
            "{ncmds} load commands cannot fit in sizeofcmds {sizeofcmds}"
        )));
    }
    let area = read_vec(r, 0, 32 + sizeofcmds, "load commands")?;
    let mut off = 32usize;
    for i in 0..ncmds {
        let cmd = rd_u32(&area, off)?;
        let cs = rd_u32(&area, off + 4)? as usize;
        if cs < 8 {
            return Err(Error::invalid(format!(
                "load command {i} (cmd {cmd:#x}) has cmdsize {cs}, smaller than its own 8-byte header"
            )));
        }
        if cmd == LC_SEGMENT_64 {
            let seg = nul_str(
                area.get(off + 8..off + 24)
                    .ok_or_else(|| Error::invalid("truncated segment command"))?,
            );
            let nsects = rd_u32(&area, off + 64)?;
            let mut so = off + 72;
            if seg == segname.as_bytes() {
                for _ in 0..nsects {
                    let sn = nul_str(
                        area.get(so..so + 16)
                            .ok_or_else(|| Error::invalid("truncated section"))?,
                    );
                    let nseg = nul_str(
                        area.get(so + 16..so + 32)
                            .ok_or_else(|| Error::invalid("truncated section"))?,
                    );
                    let addr = rd_u64(&area, so + 32)?;
                    let size = rd_u64(&area, so + 40)?;
                    let foff = rd_u32(&area, so + 48)?;
                    if sn == sectname.as_bytes() && nseg == segname.as_bytes() {
                        return Ok(Some((addr, size, foff)));
                    }
                    so += 80;
                }
            }
        }
        off += cs;
    }
    Ok(None)
}

fn nul_str(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlvOutcome {
    /// The two sections already agree (`fix_tlv: already correct, nothing to do`).
    AlreadyCorrect,
    /// `count` descriptors patched; `delta` was the constant the linker added to each offset word.
    Patched { count: u64, delta: i128 },
}

/// Fix `seg`'s `__DATA,__thread_vars` from `natural`'s. Only the section's bytes are rewritten (in place), which
/// leaves the file byte-identical to what the Python tool writes back.
pub fn fix_tlv<N: ReadAt + ?Sized, S: ReadAt + WriteAt + ?Sized>(
    natural: &N,
    seg: &mut S,
) -> Result<TlvOutcome> {
    let a = find_section(natural, "__DATA", "__thread_vars")?;
    let b = find_section(&*seg, "__DATA", "__thread_vars")?;
    let (a, b) = match (a, b) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(Error::invalid("__DATA,__thread_vars not found in both")),
    };
    if a.1 != b.1 {
        return Err(Error::invalid(format!(
            "__thread_vars sizes differ: {} vs {}",
            a.1, b.1
        )));
    }
    if a.1 % 24 != 0 {
        return Err(Error::invalid(format!(
            "__thread_vars size {} is not a multiple of 24",
            a.1
        )));
    }
    let good = read_vec(natural, a.2 as u64, a.1, "natural __thread_vars")?;
    let bad = read_vec(&*seg, b.2 as u64, b.1, "segaddr __thread_vars")?;
    // sanity: entries must match except the third word, which differs by one constant
    let mut deltas: Vec<i128> = Vec::new();
    for i in (0..good.len()).step_by(24) {
        if good[i..i + 16] != bad[i..i + 16] {
            return Err(Error::invalid(format!(
                "entry {}: thunk/key differ, not only the offset",
                i / 24
            )));
        }
        let d = rd_u64(&bad, i + 16)? as i128 - rd_u64(&good, i + 16)? as i128;
        if !deltas.contains(&d) {
            deltas.push(d);
        }
    }
    if deltas == [0] {
        return Ok(TlvOutcome::AlreadyCorrect);
    }
    if deltas.len() != 1 {
        return Err(Error::invalid(format!(
            "offset deltas are not a single constant: {deltas:?}"
        )));
    }
    seg.write_all_at(&good, b.2 as u64)
        .map_err(|e| Error::io("writing __thread_vars", e))?;
    Ok(TlvOutcome::Patched {
        count: b.1 / 24,
        delta: deltas[0],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MemSink;

    /// A one-segment image with `__DATA,__thread_vars` at file offset 0x200, filled with `entries`.
    fn image(entries: &[[u64; 3]]) -> Vec<u8> {
        let size = entries.len() as u64 * 24;
        let seg = Segment {
            name: "__DATA".into(),
            vmaddr: 0x8000_0000,
            vmsize: 0x4000,
            fileoff: 0x200,
            filesize: size,
            maxprot: 3,
            initprot: 3,
            flags: 0,
            secs: vec![
                Section::plain("__data", 0x8000_0000, 8, 0, 3, 0),
                Section::plain("__thread_vars", 0x8000_0010, size, 0x200, 3, 0x13),
            ],
        };
        let lc = seg_lc_bytes(&seg).unwrap();
        let mut f = Vec::new();
        for v in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            MH_DYLIB,
            1,
            lc.len() as u32,
            0,
            0,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend(lc);
        f.resize(0x200, 0);
        for e in entries {
            for w in e {
                f.extend_from_slice(&w.to_le_bytes());
            }
        }
        f
    }

    #[test]
    fn find_section_locates_thread_vars() {
        let f = image(&[[1, 2, 8]]);
        assert_eq!(
            find_section(&f, "__DATA", "__thread_vars").unwrap(),
            Some((0x8000_0010, 24, 0x200))
        );
        assert_eq!(find_section(&f, "__DATA", "__nope").unwrap(), None);
        assert_eq!(find_section(&f, "__TEXT", "__thread_vars").unwrap(), None);
    }

    #[test]
    fn patches_the_constant_the_linker_added() {
        let good = image(&[[0xA, 0xB, 0x8], [0xC, 0xD, 0x10]]);
        let bad = image(&[[0xA, 0xB, 0x8 + 0x7fec0000], [0xC, 0xD, 0x10 + 0x7fec0000]]);
        let mut sink = MemSink(bad.clone());
        let r = fix_tlv(&good, &mut sink).unwrap();
        assert_eq!(
            r,
            TlvOutcome::Patched {
                count: 2,
                delta: 0x7fec0000
            }
        );
        assert_eq!(sink.0, good, "the whole file now equals the natural link");
        // second run: nothing to do
        assert_eq!(
            fix_tlv(&good, &mut sink).unwrap(),
            TlvOutcome::AlreadyCorrect
        );
    }

    #[test]
    fn refuses_when_more_than_the_offset_differs() {
        let good = image(&[[0xA, 0xB, 0x8]]);
        let bad_key = image(&[[0xA, 0xBB, 0x8 + 0x1000]]);
        assert!(fix_tlv(&good, &mut MemSink(bad_key)).is_err());
        let good2 = image(&[[1, 2, 8], [3, 4, 16]]);
        let two_deltas = image(&[[1, 2, 8 + 0x1000], [3, 4, 16 + 0x2000]]);
        let e = fix_tlv(&good2, &mut MemSink(two_deltas)).unwrap_err();
        assert!(e.to_string().contains("single constant"), "{e}");
        let short = image(&[[1, 2, 8]]);
        assert!(
            fix_tlv(&good2, &mut MemSink(short)).is_err(),
            "size mismatch"
        );
    }
    /// A header claiming `ncmds` commands in `sizeofcmds` bytes, then `cmds` (review r2, N2: `find_section` walked `ncmds` turns even when a command did not move `off`)
    fn header_with(ncmds: u32, sizeofcmds: u32, cmds: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        for v in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            MH_DYLIB,
            ncmds,
            sizeofcmds,
            0,
            0,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(cmds);
        f
    }

    #[test]
    fn find_section_refuses_commands_that_cannot_advance_or_cannot_fit() {
        let zero_size = [0x02u8, 0, 0, 0, 0, 0, 0, 0]; // LC_SYMTAB (not a segment: nothing else is read) with cmdsize 0
        let cmds = [zero_size.as_slice(); 3].concat();
        // counts the old loop finished in a second come first: on the old code the test fails there and never reaches u32::MAX
        for (ncmds, sizeofcmds) in [
            (100_000_000u32, 8u32),
            (1, 8),
            (3, 24),
            (u32::MAX, 8),
            (u32::MAX, 24),
        ] {
            let b = header_with(ncmds, sizeofcmds, &cmds);
            assert!(
                find_section(&b, "__TEXT", "__text").is_err(),
                "ncmds {ncmds} sizeofcmds {sizeofcmds}: answered Ok instead of refusing a header that cannot be right"
            );
        }
    }
}
