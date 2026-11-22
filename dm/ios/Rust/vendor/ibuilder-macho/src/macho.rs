//! Mach-O primitives shared by the assembler and the probe writer: constants, little-endian field access,
//! the 64-bit header/load-command/segment/section parser (`assemble.py parse`) and the segment-command
//! builder (`assemble.py seg_command` / `macho_write.py seg_command`, which emit the same bytes).

use crate::error::{Error, Result};

/// 16 KiB: the page the engine's sections are aligned to (and arm64 iOS's page size).
pub const PG: u64 = 0x4000;
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
pub const CPU_TYPE_ARM64: u32 = 0x0100000C;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const MH_DYLIB: u32 = 6;
pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_TWOLEVEL: u32 = 0x80;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xB;
pub const LC_LOAD_DYLIB: u32 = 0xC;
pub const LC_ID_DYLIB: u32 = 0xD;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
pub const LC_UUID: u32 = 0x1B;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_IOSSIMULATOR: u32 = 7;

pub const S_REGULAR: u32 = 0;
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

pub const VM_PROT_READ: u32 = 1;
pub const VM_PROT_WRITE: u32 = 2;
pub const VM_PROT_EXECUTE: u32 = 4;
pub const VM_PROT_RX: u32 = VM_PROT_READ | VM_PROT_EXECUTE;
pub const VM_PROT_RW: u32 = VM_PROT_READ | VM_PROT_WRITE;
pub const VM_PROT_R: u32 = VM_PROT_READ;

/// Load commands whose `dataoff` (offset 8) points into `__LINKEDIT`.
pub const LINKEDIT_DATA: [u32; 8] = [
    LC_CODE_SIGNATURE,
    LC_SEGMENT_SPLIT_INFO,
    LC_FUNCTION_STARTS,
    LC_DATA_IN_CODE,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
];

pub fn align(x: u64, a: u64) -> u64 {
    (x + a - 1) & !(a - 1)
}

/// `name` as a NUL-padded field of `size` bytes (Python `fixed`; its `assert len(b) <= size` is an error here).
pub fn fixed(name: &[u8], size: usize) -> Result<Vec<u8>> {
    if name.len() > size {
        return Err(Error::invalid(format!(
            "{} longer than {size}",
            String::from_utf8_lossy(name)
        )));
    }
    let mut v = name.to_vec();
    v.resize(size, 0);
    Ok(v)
}

pub fn uleb(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            return out;
        }
    }
}

// ---- little-endian field access (bounds-checked: Python's struct.unpack_from raises struct.error) -----
pub fn rd_u32(b: &[u8], off: usize) -> Result<u32> {
    let s = off
        .checked_add(4)
        .and_then(|e| b.get(off..e))
        .ok_or_else(|| {
            Error::invalid(format!(
                "read of u32 at {off:#x} is out of range ({:#x} bytes)",
                b.len()
            ))
        })?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn rd_u64(b: &[u8], off: usize) -> Result<u64> {
    let s = off
        .checked_add(8)
        .and_then(|e| b.get(off..e))
        .ok_or_else(|| {
            Error::invalid(format!(
                "read of u64 at {off:#x} is out of range ({:#x} bytes)",
                b.len()
            ))
        })?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub fn wr_u32(b: &mut [u8], off: usize, v: u32) -> Result<()> {
    let len = b.len();
    let s = off
        .checked_add(4)
        .and_then(|e| b.get_mut(off..e))
        .ok_or_else(|| {
            Error::invalid(format!(
                "write of u32 at {off:#x} is out of range ({len:#x} bytes)"
            ))
        })?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// `v` -> u32, or the error `struct.pack` would raise.
pub fn to_u32(v: i128, what: &str) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::invalid(format!("{what}: {v} does not fit a 32-bit field")))
}

// ---- parsed structures --------------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
}

impl Section {
    /// A plain section (reloff/nreloc/reserved all 0), as both Python writers emit.
    pub fn plain(name: &str, addr: u64, size: u64, offset: u32, align: u32, flags: u32) -> Section {
        Section {
            name: name.to_string(),
            addr,
            size,
            offset,
            align,
            reloff: 0,
            nreloc: 0,
            flags,
            r1: 0,
            r2: 0,
            r3: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub flags: u32,
    pub secs: Vec<Section>,
}

#[derive(Clone, Copy, Debug)]
pub struct LoadCmd {
    pub cmd: u32,
    pub cmdsize: u32,
    pub off: usize,
}

#[derive(Clone, Debug)]
pub struct Header {
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub lc_end: u64,
    /// Lowest file offset of any file-backed section (the room before it is the header slack).
    pub first_sec_off: Option<u64>,
}

fn cstr(b: &[u8]) -> Result<String> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8(b[..end].to_vec())
        .map_err(|_| Error::invalid("non-UTF-8 segment/section name"))
}

/// Parse the header and the load commands out of `data` = the file's first `32 + sizeofcmds` bytes
/// (`assemble.py parse`). Only `LC_SEGMENT_64` commands are decoded further.
pub fn parse(data: &[u8]) -> Result<(Header, Vec<LoadCmd>, Vec<Segment>)> {
    let magic = rd_u32(data, 0)?;
    if magic != MH_MAGIC_64 {
        return Err(Error::invalid(format!("not a 64-bit Mach-O ({magic:#x})")));
    }
    let ncmds = rd_u32(data, 16)?;
    let sizeofcmds = rd_u32(data, 20)?;
    let flags = rd_u32(data, 24)?;
    // Both counts are the file's word. A load command is at least its 8-byte header, so `ncmds` of them cannot be more than `sizeofcmds / 8`; and a command whose `cmdsize` is smaller than its
    // header does not move the offset, so `ncmds` of them (up to 2^32) would be pushed one by one before the check after the loop. Neither reaches the loop. (review finding 4.1)
    if u64::from(ncmds) * 8 > u64::from(sizeofcmds) {
        return Err(Error::invalid(format!(
            "{ncmds} load commands cannot fit in sizeofcmds {sizeofcmds}"
        )));
    }
    let mut lcs = Vec::with_capacity(ncmds as usize);
    let mut off = 32usize;
    for i in 0..ncmds {
        let cmd = rd_u32(data, off)?;
        let cmdsize = rd_u32(data, off + 4)?;
        if cmdsize < 8 {
            return Err(Error::invalid(format!(
                "load command {i} (cmd {cmd:#x}) has cmdsize {cmdsize}, smaller than its own 8-byte header"
            )));
        }
        lcs.push(LoadCmd { cmd, cmdsize, off });
        off = off
            .checked_add(cmdsize as usize)
            .ok_or_else(|| Error::invalid("load command size overflows"))?;
    }
    if off as u64 != 32 + sizeofcmds as u64 {
        return Err(Error::invalid(format!(
            "LC end {off} != 32+sizeofcmds {}",
            32 + sizeofcmds as u64
        )));
    }
    let mut segs = Vec::new();
    for lc in &lcs {
        if lc.cmd != LC_SEGMENT_64 {
            continue;
        }
        let o = lc.off;
        let name = cstr(
            data.get(o + 8..o + 24)
                .ok_or_else(|| Error::invalid("truncated segment command"))?,
        )?;
        let vmaddr = rd_u64(data, o + 24)?;
        let vmsize = rd_u64(data, o + 32)?;
        let fileoff = rd_u64(data, o + 40)?;
        let filesize = rd_u64(data, o + 48)?;
        let maxprot = rd_u32(data, o + 56)?;
        let initprot = rd_u32(data, o + 60)?;
        let nsects = rd_u32(data, o + 64)?;
        let flags = rd_u32(data, o + 68)?;
        let mut secs = Vec::new();
        let mut so = o + 72;
        for _ in 0..nsects {
            let sname = cstr(
                data.get(so..so + 16)
                    .ok_or_else(|| Error::invalid("truncated section"))?,
            )?;
            secs.push(Section {
                name: sname,
                addr: rd_u64(data, so + 32)?,
                size: rd_u64(data, so + 40)?,
                offset: rd_u32(data, so + 48)?,
                align: rd_u32(data, so + 52)?,
                reloff: rd_u32(data, so + 56)?,
                nreloc: rd_u32(data, so + 60)?,
                flags: rd_u32(data, so + 64)?,
                r1: rd_u32(data, so + 68)?,
                r2: rd_u32(data, so + 72)?,
                r3: rd_u32(data, so + 76)?,
            });
            so += 80;
        }
        segs.push(Segment {
            name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            flags,
            secs,
        });
    }
    let first_sec_off = segs
        .iter()
        .flat_map(|s| s.secs.iter())
        .map(|s| s.offset)
        .filter(|&o| o != 0)
        .min()
        .map(u64::from);
    let hdr = Header {
        ncmds,
        sizeofcmds,
        flags,
        lc_end: 32 + sizeofcmds as u64,
        first_sec_off,
    };
    Ok((hdr, lcs, segs))
}

/// The bytes of an `LC_SEGMENT_64` command (72 + 80 * nsects bytes). Section `segname` is the segment's.
pub fn seg_lc_bytes(seg: &Segment) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(64 + 80 * seg.secs.len());
    body.extend(fixed(seg.name.as_bytes(), 16)?);
    for v in [seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize] {
        body.extend_from_slice(&v.to_le_bytes());
    }
    for v in [seg.maxprot, seg.initprot, seg.secs.len() as u32, seg.flags] {
        body.extend_from_slice(&v.to_le_bytes());
    }
    for s in &seg.secs {
        body.extend(fixed(s.name.as_bytes(), 16)?);
        body.extend(fixed(seg.name.as_bytes(), 16)?);
        body.extend_from_slice(&s.addr.to_le_bytes());
        body.extend_from_slice(&s.size.to_le_bytes());
        for v in [
            s.offset, s.align, s.reloff, s.nreloc, s.flags, s.r1, s.r2, s.r3,
        ] {
            body.extend_from_slice(&v.to_le_bytes());
        }
    }
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    out.extend(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_up_to_power_of_two() {
        assert_eq!(align(0, PG), 0);
        assert_eq!(align(1, PG), PG);
        assert_eq!(align(PG, PG), PG);
        assert_eq!(align(PG + 1, PG), 2 * PG);
        assert_eq!(align(0x7383be4, PG), 0x7384000);
        assert_eq!(align(13, 8), 16);
    }

    #[test]
    fn uleb_matches_dwarf_examples() {
        assert_eq!(uleb(0), [0x00]);
        assert_eq!(uleb(2), [0x02]);
        assert_eq!(uleb(127), [0x7f]);
        assert_eq!(uleb(128), [0x80, 0x01]);
        assert_eq!(uleb(624485), [0xe5, 0x8e, 0x26]);
    }

    /// a 64-bit Mach-O header (32 bytes) claiming `ncmds` commands in `sizeofcmds`, then `cmds`
    fn header_with(ncmds: u32, sizeofcmds: u32, cmds: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&ncmds.to_le_bytes());
        b[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
        b.extend_from_slice(cmds);
        b
    }

    /// `cmdsize == 0` kept `off` where it was, so `ncmds` (up to 2^32) commands were pushed one by one before the check after the loop (review finding 4.1)
    #[test]
    fn load_commands_that_cannot_advance_or_cannot_fit_are_errors_not_a_loop() {
        let zero_size = [0x19u8, 0, 0, 0, 0, 0, 0, 0]; // LC_SEGMENT_64 with cmdsize 0
        for (ncmds, sizeofcmds) in [(u32::MAX, 8u32), (u32::MAX, u32::MAX), (1, 8), (3, 24)] {
            let b = header_with(ncmds, sizeofcmds, &[zero_size.as_slice(); 3].concat());
            assert!(parse(&b).is_err(), "ncmds {ncmds} sizeofcmds {sizeofcmds}");
        }
        // more commands than 8 bytes each can fill sizeofcmds
        assert!(parse(&header_with(1000, 64, &[0u8; 64])).is_err());
        // a size that moves the offset past the data
        let big = [0x19u8, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(parse(&header_with(1, 8, &big)).is_err());
        // an honest header with no commands still parses
        let (h, lcs, segs) = parse(&header_with(0, 0, &[])).unwrap();
        assert_eq!((h.ncmds, lcs.len(), segs.len()), (0, 0, 0));
    }

    #[test]
    fn fixed_pads_and_rejects_long_names() {
        assert_eq!(fixed(b"__TEXT", 16).unwrap(), b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(fixed(b"0123456789abcdef", 16).unwrap().len(), 16);
        assert!(fixed(b"0123456789abcdefg", 16).is_err());
    }

    #[test]
    fn segment_command_layout() {
        let seg = Segment {
            name: "__DMmainW".into(),
            vmaddr: 0x1111_2222_3333_4444,
            vmsize: 0x8000,
            fileoff: 0x4000,
            filesize: 0x8000,
            maxprot: 3,
            initprot: 3,
            flags: 0x10,
            secs: vec![Section::plain("__img", 0x1_0000, 0x8000, 0x4000, 14, 0)],
        };
        let b = seg_lc_bytes(&seg).unwrap();
        assert_eq!(b.len(), 72 + 80);
        assert_eq!(rd_u32(&b, 0).unwrap(), LC_SEGMENT_64);
        assert_eq!(rd_u32(&b, 4).unwrap() as usize, b.len());
        assert_eq!(&b[8..17], b"__DMmainW");
        assert_eq!(rd_u64(&b, 24).unwrap(), 0x1111_2222_3333_4444);
        assert_eq!(rd_u32(&b, 56).unwrap(), 3); // maxprot
        assert_eq!(rd_u32(&b, 64).unwrap(), 1); // nsects
        assert_eq!(rd_u32(&b, 68).unwrap(), 0x10); // flags
        // section: sectname, then segname, then addr/size/offset/align
        assert_eq!(&b[72..77], b"__img");
        assert_eq!(&b[88..97], b"__DMmainW");
        assert_eq!(rd_u64(&b, 72 + 32).unwrap(), 0x1_0000);
        assert_eq!(rd_u32(&b, 72 + 48).unwrap(), 0x4000);
        assert_eq!(rd_u32(&b, 72 + 52).unwrap(), 14);
    }

    #[test]
    fn parse_round_trips_a_segment_command() {
        let seg = Segment {
            name: "__TEXT".into(),
            vmaddr: 0,
            vmsize: 0x8000,
            fileoff: 0,
            filesize: 0x8000,
            maxprot: 5,
            initprot: 5,
            flags: 0,
            secs: vec![
                Section::plain(
                    "__text",
                    0x1000,
                    0x10,
                    0x1000,
                    2,
                    S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
                ),
                Section::plain("__bss", 0x2000, 0x10, 0, 3, 1),
            ],
        };
        let lc = seg_lc_bytes(&seg).unwrap();
        let mut file = Vec::new();
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
            file.extend_from_slice(&v.to_le_bytes());
        }
        file.extend(&lc);
        let (hdr, lcs, segs) = parse(&file).unwrap();
        assert_eq!(hdr.ncmds, 1);
        assert_eq!(hdr.lc_end, 32 + lc.len() as u64);
        assert_eq!(lcs.len(), 1);
        assert_eq!(segs, vec![seg]);
        // only file-backed sections (offset != 0) count for the header slack
        assert_eq!(hdr.first_sec_off, Some(0x1000));
    }

    #[test]
    fn parse_rejects_non_macho_and_inconsistent_sizes() {
        assert!(parse(&[0u8; 32]).is_err());
        let mut h = Vec::new();
        for v in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_DYLIB, 0, 8, 0, 0] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        assert!(parse(&h).is_err()); // sizeofcmds 8 but no commands
    }
}
