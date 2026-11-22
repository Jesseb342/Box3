//! The hand-made Mach-O writer: port of `tools/macho_write.py`.
//!
//! Emits a real `MH_DYLIB` for arm64 (iOS simulator or device) with no linker: a stand-in `__TEXT,__text`
//! entry point, the engine-shaped `__dm<name>x0` / `__DMPROBEW,__img` / `__dm<name>x1` sections (16 KiB
//! aligned), and the load commands a clang-built framework carries (`LC_SEGMENT_64`, `LC_ID_DYLIB`,
//! `LC_BUILD_VERSION`, `LC_LOAD_DYLIB`, `LC_DYLD_CHAINED_FIXUPS`, `LC_DYLD_EXPORTS_TRIE`, `LC_SYMTAB`,
//! `LC_DYSYMTAB`, `LC_UUID`, `LC_FUNCTION_STARTS`, `LC_SOURCE_VERSION`).
//!
//! The only non-deterministic input is `LC_UUID` (Python: `uuid4()`); here it is a parameter so a test can
//! pin it ([`ProbeParams::uuid`]) and the default draws it from `/dev/urandom` with the v4 bit pattern.

use crate::error::{Error, Result};
use crate::macho::*;
use std::fs;
use std::io::Read;

/// Slack left between the load commands and `__text` so a signer can append `LC_CODE_SIGNATURE`.
pub const HEADER_SLACK: u64 = 0x200;

/// `'27.2'` -> `(27 << 16) | (2 << 8) | 0`, the `LC_BUILD_VERSION` word. Python: `int(x)` per component.
pub fn encode_version(v: &str) -> Result<u32> {
    let mut parts = Vec::new();
    for x in v.split('.') {
        let n: u64 = x.trim().parse().map_err(|_| {
            Error::invalid(format!("invalid literal for int(): {x:?} in version {v:?}"))
        })?;
        parts.push(n);
    }
    while parts.len() < 3 {
        parts.push(0);
    }
    let w = (parts[0] << 16) | (parts[1] << 8) | parts[2];
    u32::try_from(w).map_err(|_| Error::invalid(format!("version {v:?} does not fit 32 bits")))
}

// ---- arm64 encoders for the four instructions the stand-in entry point uses ----------------------------
pub fn enc_movz_w0(imm16: u32) -> u32 {
    0x5280_0000 | ((imm16 & 0xFFFF) << 5)
}

pub fn enc_ret() -> u32 {
    0xD65F_03C0
}

/// `ADRP rd, target`, the page-relative address of `target` computed from the instruction's own `pc`.
pub fn enc_adrp(rd: u32, pc: u64, target: u64) -> Result<u32> {
    let imm = (((target & !0xFFF) as i64) - ((pc & !0xFFF) as i64)) >> 12;
    if !(-(1 << 20)..(1 << 20)).contains(&imm) {
        return Err(Error::invalid("ADRP immediate out of range"));
    }
    let immlo = (imm & 0x3) as u32;
    let immhi = ((imm >> 2) & 0x7FFFF) as u32;
    Ok(0x9000_0000 | (immlo << 29) | (immhi << 5) | rd)
}

pub fn enc_add_x(rd: u32, rn: u32, imm12: u32) -> Result<u32> {
    if imm12 >= 4096 {
        return Err(Error::invalid("ADD immediate out of range"));
    }
    Ok(0x9100_0000 | (imm12 << 10) | (rn << 5) | rd)
}

pub fn enc_ldr_w(rt: u32, rn: u32, imm12: u32) -> Result<u32> {
    if imm12 >= 4096 {
        return Err(Error::invalid("LDR immediate out of range"));
    }
    Ok(0xB940_0000 | (imm12 << 10) | (rn << 5) | rt)
}

/// `adrp x0, target ; add x0, x0, #lo12 ; ldr w0, [x0] ; ret` -- returns the word `target` holds.
pub fn entry_code(pc: u64, target: u64) -> Result<Vec<u8>> {
    let words = [
        enc_adrp(0, pc, target)?,
        enc_add_x(0, 0, (target & 0xFFF) as u32)?,
        enc_ldr_w(0, 0, 0)?,
        enc_ret(),
    ];
    Ok(words.iter().flat_map(|w| w.to_le_bytes()).collect())
}

// ---- the export trie ------------------------------------------------------------------------------------
/// `symbols: [(name, vmaddr)]` -> the trie blob dyld reads to resolve an exported symbol.
///
/// Node layout: `uleb(terminalSize) [terminal info] u8(childCount) { edge-string uleb(childOffset) }...`;
/// terminal info is `uleb(flags) uleb(address)`. One level deep: each root edge carries a whole symbol name.
/// Offsets are laid out to a fixed point, since a uleb's length depends on the offset it encodes.
#[allow(clippy::needless_range_loop)]
pub fn build_export_trie(symbols: &[(&str, u64)]) -> Result<Vec<u8>> {
    let n = symbols.len();
    let mut term: Vec<Vec<u8>> = vec![Vec::new()];
    let mut root_edges: Vec<Vec<u8>> = Vec::new();
    for (name, addr) in symbols {
        let mut t = uleb(0);
        t.extend(uleb(*addr));
        term.push(t);
        let mut e = name.as_bytes().to_vec();
        e.push(0);
        root_edges.push(e);
    }
    // preorder: node 0 is the root, nodes 1..=n are the terminals; the root's i-th edge leads to node i+1
    let sizes = |offsets: &[u64]| -> Vec<u64> {
        (0..=n)
            .map(|i| {
                let mut s = (uleb(term[i].len() as u64).len() + term[i].len() + 1) as u64;
                if i == 0 {
                    for (j, e) in root_edges.iter().enumerate() {
                        s += (e.len() + uleb(offsets[j + 1]).len()) as u64;
                    }
                }
                s
            })
            .collect()
    };
    let mut offsets = vec![0u64; n + 1];
    for _ in 0..8 {
        let sz = sizes(&offsets);
        let mut new = vec![0u64; n + 1];
        for i in 1..=n {
            new[i] = new[i - 1] + sz[i - 1];
        }
        if new == offsets {
            break;
        }
        offsets = new;
    }
    let sz = sizes(&offsets);
    if sz.iter().sum::<u64>() != offsets[n] + sz[n] {
        return Err(Error::invalid("export trie offsets did not converge"));
    }
    let mut blob = Vec::new();
    for i in 0..=n {
        blob.extend(uleb(term[i].len() as u64));
        blob.extend(&term[i]);
        if i == 0 {
            blob.push(root_edges.len() as u8);
            for (j, e) in root_edges.iter().enumerate() {
                blob.extend(e);
                blob.extend(uleb(offsets[j + 1]));
            }
        } else {
            blob.push(0);
        }
    }
    if blob.len() as u64 != sz.iter().sum::<u64>() {
        return Err(Error::invalid("export trie size mismatch"));
    }
    Ok(blob)
}

// ---- load command builders ------------------------------------------------------------------------------
fn u32s(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

pub fn dylib_id_command(name: &str) -> Result<Vec<u8>> {
    let mut body = fixed(name.as_bytes(), name.len() + 1)?;
    body.resize(body.len() + ((8 - body.len() % 8) % 8), 0);
    let mut out = u32s(&[LC_ID_DYLIB, (8 + 16 + body.len()) as u32, 24, 1, 0, 0]);
    out.extend(body);
    Ok(out)
}

/// `LC_LOAD_DYLIB`: dyld refuses a dylib that links no libSystem at all.
pub fn load_dylib_command(name: &str, current: u32, compat: u32) -> Result<Vec<u8>> {
    let mut body = fixed(name.as_bytes(), name.len() + 1)?;
    body.resize(body.len() + ((8 - body.len() % 8) % 8), 0);
    let mut out = u32s(&[
        LC_LOAD_DYLIB,
        (8 + 16 + body.len()) as u32,
        24,
        2,
        current,
        compat,
    ]);
    out.extend(body);
    Ok(out)
}

pub fn build_version_command(platform: u32, minos: &str, sdk: &str) -> Result<Vec<u8>> {
    let tool = u32s(&[3, (27106 << 8) | 1]); // tool 3 = clang
    let mut out = u32s(&[
        LC_BUILD_VERSION,
        (8 + 16 + tool.len()) as u32,
        platform,
        encode_version(minos)?,
        encode_version(sdk)?,
        1,
    ]);
    out.extend(tool);
    Ok(out)
}

pub fn linkedit_command(cmd: u32, off: u64, size: u64) -> Result<Vec<u8>> {
    Ok(u32s(&[
        cmd,
        16,
        to_u32(off as i128, "linkedit dataoff")?,
        to_u32(size as i128, "linkedit datasize")?,
    ]))
}

pub fn symtab_command(symoff: u64, nsyms: u32, stroff: u64, strsize: u64) -> Result<Vec<u8>> {
    Ok(u32s(&[
        LC_SYMTAB,
        24,
        to_u32(symoff as i128, "symoff")?,
        nsyms,
        to_u32(stroff as i128, "stroff")?,
        to_u32(strsize as i128, "strsize")?,
    ]))
}

pub fn dysymtab_command(
    nextdefsym: u32,
    ilocalsym: u32,
    nlocalsym: u32,
    nundefsym: u32,
) -> Vec<u8> {
    let iextdefsym = ilocalsym + nlocalsym;
    let iundefsym = iextdefsym + nextdefsym; // dyld requires this exact identity
    let mut fields = vec![
        ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym,
    ];
    fields.extend([0u32; 12]);
    let mut out = u32s(&[LC_DYSYMTAB, (8 + 4 * fields.len()) as u32]);
    out.extend(u32s(&fields));
    out
}

pub fn uuid_command(uuid: &[u8; 16]) -> Vec<u8> {
    let mut out = u32s(&[LC_UUID, 24]);
    out.extend_from_slice(uuid);
    out
}

pub fn source_version_command(version: u64) -> Vec<u8> {
    let mut out = u32s(&[LC_SOURCE_VERSION, 16]);
    out.extend_from_slice(&version.to_le_bytes());
    out
}

/// A `dyld_chained_fixups_header` with no imports and no chains. `starts_offset` is 8-aligned (32) and
/// `imports_format` is a known value (1 = DYLD_CHAINED_IMPORT) even with `imports_count` 0, as clang emits.
pub fn chained_fixups_blob(seg_count: u32) -> Vec<u8> {
    let starts_off = 32u32;
    let mut starts = seg_count.to_le_bytes().to_vec();
    starts.resize(4 + 4 * seg_count as usize, 0);
    let imp_off = starts_off + starts.len() as u32;
    let mut blob = u32s(&[0, starts_off, imp_off, imp_off, 0, 1, 0]);
    blob.resize(starts_off as usize, 0);
    blob.extend(starts);
    blob.resize(blob.len() + ((8 - blob.len() % 8) % 8), 0);
    blob
}

/// Everything `build` takes (Python's CLI flags).
#[derive(Clone, Debug)]
pub struct ProbeParams {
    pub platform: u32,
    pub name: String,
    pub magic: u32,
    pub minos: String,
    pub sdk: String,
    /// `LC_UUID` payload. `None`: random, version-4 bits set (like Python's `uuid4()`).
    pub uuid: Option<[u8; 16]>,
}

impl ProbeParams {
    /// The Python CLI's defaults for `--platform sim|ios`.
    pub fn for_platform(sim: bool) -> ProbeParams {
        ProbeParams {
            platform: if sim {
                PLATFORM_IOSSIMULATOR
            } else {
                PLATFORM_IOS
            },
            name: "DmProbe".into(),
            magic: 0x5A17BEEF,
            minos: if sim { "27.0" } else { "26.0" }.into(),
            sdk: "27.2".into(),
            uuid: None,
        }
    }
}

/// The `info` dict `build()` returns (printed by the CLI as `k=v`, in this order).
#[derive(Clone, Debug)]
pub struct ProbeInfo {
    pub size: u64,
    pub platform: u32,
    pub text_off: u64,
    pub x0_off: u64,
    pub x1_off: u64,
    pub w_fileoff: u64,
    pub le_fileoff: u64,
    pub magic: u32,
    pub entry_sym: String,
    pub marker_sym: String,
    pub id_dylib: String,
}

pub fn random_uuid_v4() -> Result<[u8; 16]> {
    let mut b = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| Error::io("reading /dev/urandom for LC_UUID", e))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(b)
}

/// Pack the `__LINKEDIT` blobs, each 8-byte aligned (dyld refuses a mis-aligned exports trie).
fn emit_linkedit(blobs: &[(&str, &[u8])]) -> (Vec<u8>, Vec<(String, u64)>) {
    let mut out = Vec::new();
    let mut offs = Vec::new();
    for (name, data) in blobs {
        offs.push((name.to_string(), out.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len() + ((8 - data.len() % 8) % 8), 0);
    }
    (out, offs)
}

fn off_of(offs: &[(String, u64)], name: &str) -> u64 {
    offs.iter()
        .find(|(n, _)| n == name)
        .map(|(_, o)| *o)
        .unwrap_or(0)
}

/// Build the probe dylib in memory (it is 64 KiB). Returns the file bytes and the info dict.
pub fn build_probe(p: &ProbeParams) -> Result<(Vec<u8>, ProbeInfo)> {
    let id_dylib = format!("@rpath/{0}.framework/{0}", p.name);
    let entry_sym = "_dm_probe_entry"; // the Mach-O symbol carries the leading underscore; dlsym takes the C name
    let marker_sym = "_dmgame_image_marker";

    // ---- content -----------------------------------------------------------------------------------
    let mut x0 = vec![0u8; PG as usize]; // __TEXT,__dm<name>x0 (data stand-in)
    x0[..4].copy_from_slice(&p.magic.to_le_bytes()); // what the entry point reads back
    x0[4..10].copy_from_slice(b"DMGAME");
    let x1 = vec![0u8; PG as usize]; // __TEXT,__dm<name>x1 (patch area)
    let wimg = vec![0u8; PG as usize]; // __DMPROBEW,__img (rw image)

    // Section/segment layout (file == vm space; __TEXT has fileoff 0 and vmaddr 0):
    //   [header + load commands][__text][pad][x0 16K][x1 16K] | [W,__img 16K] | [__LINKEDIT]
    let n_segments = 3u32;
    struct Layout {
        x0_off: u64,
        x1_off: u64,
        text_vmsize: u64,
        text_filesize: u64,
        w_vmaddr: u64,
        w_fileoff: u64,
        w_vmsize: u64,
        w_filesize: u64,
        le_vmaddr: u64,
        le_fileoff: u64,
    }
    let layout = |text_off: u64| -> Layout {
        let x0_off = align(text_off + 16, PG); // 16 bytes of entry code in __text
        let x1_off = align(x0_off + x0.len() as u64, PG);
        let text_vmsize = align(x1_off + x1.len() as u64, PG);
        let text_filesize = text_vmsize;
        let w_fileoff = text_filesize;
        let w_filesize = wimg.len() as u64;
        let w_vmsize = align(w_filesize, PG);
        let w_vmaddr = text_vmsize;
        let le_fileoff = align(w_fileoff + w_filesize, PG);
        let le_vmaddr = w_vmaddr + w_vmsize;
        Layout {
            x0_off,
            x1_off,
            text_vmsize,
            text_filesize,
            w_vmaddr,
            w_fileoff,
            w_vmsize,
            w_filesize,
            le_vmaddr,
            le_fileoff,
        }
    };

    let uuid = match p.uuid {
        Some(u) => u,
        None => random_uuid_v4()?,
    };

    // The load-command stream for a given text_off / __LINKEDIT payload (the commands' *sizes* do not depend on
    // either, only their fields do, which is why one provisional pass converges).
    struct Pass {
        lcs: Vec<Vec<u8>>,
        text: Vec<u8>,
        le: Vec<u8>,
        l: Layout,
    }
    let pass = |text_off: u64, final_pass: bool| -> Result<Pass> {
        let l = layout(text_off);
        let cf = chained_fixups_blob(n_segments);
        let exports = build_export_trie(&[(entry_sym, text_off), (marker_sym, l.x0_off)])?;
        let (fn_starts, nlists, strtab) = if final_pass {
            let mut f = uleb(text_off);
            f.push(0);
            let mut st = vec![0u8, 0u8];
            let mut name_off = Vec::new();
            for s in [entry_sym, marker_sym] {
                name_off.push(st.len() as u32);
                st.extend_from_slice(s.as_bytes());
                st.push(0);
            }
            let mut nl = Vec::new();
            for (stroff, sect, value) in
                [(name_off[0], 1u8, text_off), (name_off[1], 2u8, l.x0_off)]
            {
                nl.extend_from_slice(&stroff.to_le_bytes());
                nl.push(0x0F); // N_SECT | N_EXT
                nl.push(sect);
                nl.extend_from_slice(&0u16.to_le_bytes());
                nl.extend_from_slice(&value.to_le_bytes());
            }
            (f, nl, st)
        } else {
            // provisional pass: only the blobs' sizes matter (they feed the __LINKEDIT size fields)
            let f = if text_off != 0 {
                let mut f = uleb(text_off);
                f.push(0);
                f
            } else {
                vec![0]
            };
            let mut st = vec![0u8, 0u8];
            st.extend_from_slice(entry_sym.as_bytes());
            st.push(0);
            st.extend_from_slice(marker_sym.as_bytes());
            st.push(0);
            (f, vec![0u8; 32], st)
        };
        let (le, off) = emit_linkedit(&[
            ("cf", &cf),
            ("exp", &exports),
            ("fn", &fn_starts),
            ("sym", &nlists),
            ("str", &strtab),
        ]);
        let le_size = le.len() as u64;
        let text_sec = Section::plain(
            "__text",
            text_off,
            16,
            to_u32(text_off as i128, "text offset")?,
            2,
            S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
        );
        let text_seg = Segment {
            name: "__TEXT".into(),
            vmaddr: 0,
            vmsize: l.text_vmsize,
            fileoff: 0,
            filesize: l.text_filesize,
            maxprot: VM_PROT_RX,
            initprot: VM_PROT_RX,
            flags: 0,
            secs: vec![
                text_sec,
                Section::plain(
                    "__dmprobex0",
                    l.x0_off,
                    x0.len() as u64,
                    to_u32(l.x0_off as i128, "x0")?,
                    14,
                    S_REGULAR,
                ),
                Section::plain(
                    "__dmprobex1",
                    l.x1_off,
                    x1.len() as u64,
                    to_u32(l.x1_off as i128, "x1")?,
                    14,
                    S_REGULAR,
                ),
            ],
        };
        let w_seg = Segment {
            name: "__DMPROBEW".into(),
            vmaddr: l.w_vmaddr,
            vmsize: l.w_vmsize,
            fileoff: l.w_fileoff,
            filesize: l.w_filesize,
            maxprot: VM_PROT_RW,
            initprot: VM_PROT_RW,
            flags: 0,
            secs: vec![Section::plain(
                "__img",
                l.w_fileoff,
                wimg.len() as u64,
                to_u32(l.w_fileoff as i128, "w")?,
                14,
                S_REGULAR,
            )],
        };
        let le_seg = Segment {
            name: "__LINKEDIT".into(),
            vmaddr: l.le_vmaddr,
            vmsize: align(le_size, PG),
            fileoff: l.le_fileoff,
            filesize: le_size,
            maxprot: VM_PROT_R,
            initprot: VM_PROT_R,
            flags: 0,
            secs: vec![],
        };
        let lcs = vec![
            seg_lc_bytes(&text_seg)?,
            seg_lc_bytes(&w_seg)?,
            seg_lc_bytes(&le_seg)?,
            dylib_id_command(&id_dylib)?,
            build_version_command(p.platform, &p.minos, &p.sdk)?,
            load_dylib_command("/usr/lib/libSystem.B.dylib", 0x054F2803, 0x00010000)?,
            linkedit_command(
                LC_DYLD_CHAINED_FIXUPS,
                l.le_fileoff + off_of(&off, "cf"),
                cf.len() as u64,
            )?,
            linkedit_command(
                LC_DYLD_EXPORTS_TRIE,
                l.le_fileoff + off_of(&off, "exp"),
                exports.len() as u64,
            )?,
            symtab_command(
                l.le_fileoff + off_of(&off, "sym"),
                2,
                l.le_fileoff + off_of(&off, "str"),
                strtab.len() as u64,
            )?,
            dysymtab_command(2, 0, 0, 0),
            uuid_command(&uuid),
            linkedit_command(
                LC_FUNCTION_STARTS,
                l.le_fileoff + off_of(&off, "fn"),
                fn_starts.len() as u64,
            )?,
            source_version_command(0),
        ];
        let text = if final_pass {
            entry_code(text_off, l.x0_off)?
        } else {
            Vec::new()
        };
        Ok(Pass { lcs, text, le, l })
    };

    let mut provisional = 0u64;
    let mut converged = false;
    for _ in 0..3 {
        let ps = pass(provisional, false)?;
        let total: u64 = ps.lcs.iter().map(|c| c.len() as u64).sum();
        let got = align(32 + total + HEADER_SLACK, 16);
        if got == provisional {
            converged = true;
            break;
        }
        provisional = got;
    }
    if !converged {
        return Err(Error::invalid("text_off did not converge"));
    }
    let text_off = provisional;

    // final values with the converged text_off
    let fin = pass(text_off, true)?;
    let l = &fin.l;
    if fin.text.len() != 16 {
        return Err(Error::invalid("entry code is not 16 bytes"));
    }
    let sizeofcmds: u64 = fin.lcs.iter().map(|c| c.len() as u64).sum();
    if align(32 + sizeofcmds + HEADER_SLACK, 16) != text_off {
        return Err(Error::invalid("load-command pass did not converge"));
    }
    let header = u32s(&[
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        MH_DYLIB,
        fin.lcs.len() as u32,
        sizeofcmds as u32,
        MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL,
        0,
    ]);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend(&header);
    for c in &fin.lcs {
        buf.extend(c);
    }
    if buf.len() as u64 > text_off {
        return Err(Error::invalid(format!(
            "load commands overflow into __text ({} > {text_off})",
            buf.len()
        )));
    }
    buf.resize(text_off as usize, 0);
    buf.extend(&fin.text);
    buf.resize(l.x0_off as usize, 0);
    buf.extend(&x0);
    buf.resize(l.x1_off as usize, 0);
    buf.extend(&x1);
    buf.resize(l.w_fileoff as usize, 0);
    buf.extend(&wimg);
    buf.resize(l.le_fileoff as usize, 0);
    buf.extend(&fin.le);

    let info = ProbeInfo {
        size: buf.len() as u64,
        platform: p.platform,
        text_off,
        x0_off: l.x0_off,
        x1_off: l.x1_off,
        w_fileoff: l.w_fileoff,
        le_fileoff: l.le_fileoff,
        magic: p.magic,
        entry_sym: entry_sym.into(),
        marker_sym: marker_sym.into(),
        id_dylib,
    };
    Ok((buf, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_version_packs_xxyyzz() {
        assert_eq!(encode_version("27.2").unwrap(), (27 << 16) | (2 << 8));
        assert_eq!(encode_version("26.0").unwrap(), 26 << 16);
        assert_eq!(encode_version("26.1.3").unwrap(), (26 << 16) | (1 << 8) | 3);
        assert_eq!(encode_version("28").unwrap(), 28 << 16);
        assert!(encode_version("x.1").is_err());
    }

    #[test]
    fn arm64_encoders_match_known_words() {
        // `adrp x0, 0x4000 ; add x0,x0,#0 ; ldr w0,[x0] ; ret` (docs/MACHO.md), pc in the same page 0
        assert_eq!(enc_adrp(0, 0x590, 0x4000).unwrap(), 0x9000_0020);
        assert_eq!(enc_add_x(0, 0, 0).unwrap(), 0x9100_0000);
        assert_eq!(enc_ldr_w(0, 0, 0).unwrap(), 0xB940_0000);
        assert_eq!(enc_ret(), 0xD65F_03C0);
        assert_eq!(enc_movz_w0(0x1234), 0x5280_0000 | (0x1234 << 5));
        // backwards reference: negative page delta (two's complement in immhi/immlo)
        let w = enc_adrp(3, 0x10_000, 0x1000).unwrap();
        assert_eq!(w & 0x1f, 3);
        let immlo = (w >> 29) & 3;
        let immhi = (w >> 5) & 0x7FFFF;
        let imm = ((immhi << 2) | immlo) as i64;
        let imm = if imm & (1 << 20) != 0 {
            imm - (1 << 21)
        } else {
            imm
        };
        assert_eq!(imm, -15);
        assert!(enc_adrp(0, 0, 1 << 40).is_err());
        assert!(enc_add_x(0, 0, 4096).is_err());
    }

    /// A reader for the trie dyld walks: returns the address of `name`, or None.
    fn trie_lookup(trie: &[u8], name: &str) -> Option<u64> {
        fn uleb_at(b: &[u8], p: &mut usize) -> u64 {
            let mut r = 0u64;
            let mut shift = 0;
            loop {
                let x = b[*p];
                *p += 1;
                r |= ((x & 0x7f) as u64) << shift;
                if x & 0x80 == 0 {
                    return r;
                }
                shift += 7;
            }
        }
        let mut node = 0usize;
        let mut rest = name.as_bytes();
        loop {
            let mut p = node;
            let tsize = uleb_at(trie, &mut p) as usize;
            if rest.is_empty() {
                if tsize == 0 {
                    return None;
                }
                let _flags = uleb_at(trie, &mut p);
                return Some(uleb_at(trie, &mut p));
            }
            p += tsize;
            let nchild = trie[p] as usize;
            p += 1;
            let mut next = None;
            for _ in 0..nchild {
                let start = p;
                while trie[p] != 0 {
                    p += 1;
                }
                let edge = &trie[start..p];
                p += 1;
                let off = uleb_at(trie, &mut p) as usize;
                if rest.starts_with(edge) {
                    next = Some((off, edge.len()));
                    break;
                }
            }
            let (off, n) = next?;
            node = off;
            rest = &rest[n..];
        }
    }

    #[test]
    fn export_trie_resolves_every_symbol() {
        let syms = [
            ("_dm_probe_entry", 0x590u64),
            ("_dmgame_image_marker", 0x4000),
            ("_far", 0x7fff_0000_1234),
        ];
        let t = build_export_trie(&syms).unwrap();
        for (n, a) in syms {
            assert_eq!(trie_lookup(&t, n), Some(a), "{n}");
        }
        assert_eq!(trie_lookup(&t, "_nope"), None);
        // the blob is a function of its input alone
        assert_eq!(t, build_export_trie(&syms).unwrap());
    }

    #[test]
    fn load_command_sizes_and_padding() {
        let id = dylib_id_command("@rpath/DmProbe.framework/DmProbe").unwrap();
        assert_eq!(rd_u32(&id, 4).unwrap() as usize, id.len());
        assert_eq!(id.len() % 8, 0);
        assert_eq!(rd_u32(&id, 8).unwrap(), 24); // name offset
        let ld = load_dylib_command("/usr/lib/libSystem.B.dylib", 0x054F2803, 0x10000).unwrap();
        assert_eq!(rd_u32(&ld, 0).unwrap(), LC_LOAD_DYLIB);
        assert_eq!(ld.len() % 8, 0);
        assert_eq!(
            build_version_command(PLATFORM_IOS, "26.0", "27.2")
                .unwrap()
                .len(),
            32
        );
        let ds = dysymtab_command(2, 0, 0, 0);
        assert_eq!(ds.len(), 80);
        assert_eq!(rd_u32(&ds, 16).unwrap(), 0); // iextdefsym
        assert_eq!(rd_u32(&ds, 24).unwrap(), 2); // iundefsym = iextdefsym + nextdefsym
        assert_eq!(symtab_command(1, 2, 3, 4).unwrap().len(), 24);
        assert_eq!(
            linkedit_command(LC_FUNCTION_STARTS, 1, 2).unwrap().len(),
            16
        );
        assert_eq!(uuid_command(&[7; 16]).len(), 24);
        assert_eq!(source_version_command(0).len(), 16);
    }

    #[test]
    fn chained_fixups_blob_is_the_clang_shape() {
        let b = chained_fixups_blob(3);
        assert_eq!(b.len() % 8, 0);
        assert_eq!(rd_u32(&b, 4).unwrap(), 32); // starts_offset, 8-aligned
        assert_eq!(rd_u32(&b, 20).unwrap(), 1); // imports_format = DYLD_CHAINED_IMPORT
        assert_eq!(rd_u32(&b, 32).unwrap(), 3); // seg_count
        assert_eq!(rd_u32(&b, 8).unwrap(), 32 + 4 + 12); // imports_offset
    }

    fn params() -> ProbeParams {
        let mut p = ProbeParams::for_platform(true);
        p.uuid = Some([0xAB; 16]);
        p
    }

    #[test]
    fn probe_layout_is_page_aligned_and_parses() {
        let (bytes, info) = build_probe(&params()).unwrap();
        assert_eq!(bytes.len() as u64, info.size);
        for off in [info.x0_off, info.x1_off, info.w_fileoff, info.le_fileoff] {
            assert_eq!(off % PG, 0, "{off:#x}");
        }
        assert_eq!(info.text_off % 16, 0);
        let (hdr, lcs, segs) = parse(&bytes).unwrap();
        assert_eq!(lcs.len(), 13);
        assert_eq!(hdr.ncmds, 13);
        // header slack: a signer can append LC_CODE_SIGNATURE (16 bytes) before __text
        assert!(info.text_off - hdr.lc_end >= HEADER_SLACK);
        assert_eq!(hdr.first_sec_off, Some(info.text_off));
        let names: Vec<&str> = segs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["__TEXT", "__DMPROBEW", "__LINKEDIT"]);
        let text = &segs[0];
        assert_eq!(
            text.secs
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["__text", "__dmprobex0", "__dmprobex1"]
        );
        // __LINKEDIT is the last file segment and ends at EOF
        let le = &segs[2];
        assert_eq!(le.fileoff + le.filesize, bytes.len() as u64);
        // the marker section holds the magic word and "DMGAME"
        let x0 = info.x0_off as usize;
        assert_eq!(&bytes[x0..x0 + 4], &0x5A17BEEFu32.to_le_bytes());
        assert_eq!(&bytes[x0 + 4..x0 + 10], b"DMGAME");
        // the entry code reads that word: adrp resolves to the page of x0
        assert_eq!(
            rd_u32(&bytes, info.text_off as usize).unwrap(),
            enc_adrp(0, info.text_off, info.x0_off).unwrap()
        );
    }

    #[test]
    fn probe_uuid_is_the_only_nondeterminism() {
        let (a, _) = build_probe(&params()).unwrap();
        let (b, _) = build_probe(&params()).unwrap();
        assert_eq!(a, b);
        let mut p = params();
        p.uuid = Some([0xCD; 16]);
        let (c, _) = build_probe(&p).unwrap();
        let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != c[i]).collect();
        assert_eq!(diff.len(), 16, "only the 16 UUID bytes differ");
        assert!(diff.windows(2).all(|w| w[1] == w[0] + 1));
        let r = random_uuid_v4().unwrap();
        assert_eq!(r[6] >> 4, 4);
        assert_eq!(r[8] >> 6, 0b10);
    }

    #[test]
    fn probe_device_and_simulator_differ_in_platform_only_fields() {
        let (sim, _) = build_probe(&params()).unwrap();
        let mut p = ProbeParams::for_platform(false);
        p.uuid = Some([0xAB; 16]);
        let (ios, info) = build_probe(&p).unwrap();
        assert_eq!(info.platform, PLATFORM_IOS);
        assert_eq!(sim.len(), ios.len());
        assert_ne!(sim, ios);
    }
}
