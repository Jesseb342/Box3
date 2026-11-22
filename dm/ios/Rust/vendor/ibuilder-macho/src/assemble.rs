//! The framework assembler: port of `tools/assemble.py`.
//!
//! Writes ONE loadable Mach-O dylib, with no linker, from a prebuilt generic iOS host dylib plus a game's
//! rewritten modules (`<name>.patched.bin` + `<name>.fixups.tsv`). See `docs/ASSEMBLER.md` in iOSBuilder for
//! why the host's segments cannot move and why the game's `x0`/`x1` sections must live inside the host's
//! single `__TEXT` segment. In short, the output is:
//!
//! ```text
//! [host header, load commands rebuilt][host __TEXT content][game x0.. x1..]   __TEXT, grown
//! [__DM<name>W,__img]...                                                      one rw segment per module
//! [host __DATA_CONST][host __DATA]                                            moved in the file, same vmaddr
//! [host __LINKEDIT, chained-fixups blob grown by 4 B per added segment]       last file segment
//! ```
//!
//! Unlike the Python tool this never builds the image in memory: [`Plan::new`] does all the layout and every
//! check first (so a failure leaves the output untouched, as in Python), then [`Plan::write`] streams each
//! piece from its source to its final offset through one 1 MiB buffer.

use crate::embed::{FixupsHeader, Mode, abspath, piece_ranges};
use crate::error::{Error, Result};
use crate::io::{CHUNK, ReadAt, WriteAt, copy_range, read_vec};
use crate::macho::*;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

/// The segments the prebuild places high, leaving the vm range `[__TEXT end, 0x7fff0000)` free for the game.
pub const HIGH_SEGMENTS: [&str; 2] = ["__DATA_CONST", "__DATA"];

/// Where a piece's bytes come from. The piece is `len` bytes long; bytes past the source's are zero.
#[derive(Clone, Debug)]
pub enum PieceData {
    /// All zeros (`--synthetic`).
    Zeros,
    /// `fill` bytes of `path` starting at `offset`, zero-padded to the piece length (`section_bytes`).
    File {
        path: PathBuf,
        offset: u64,
        fill: u64,
    },
    /// Literal bytes (tests).
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct Piece {
    pub len: u64,
    pub data: PieceData,
}

impl Piece {
    pub fn zeros(len: u64) -> Piece {
        Piece {
            len,
            data: PieceData::Zeros,
        }
    }
    pub fn bytes(v: Vec<u8>) -> Piece {
        Piece {
            len: v.len() as u64,
            data: PieceData::Bytes(v),
        }
    }
}

/// One module's three pieces: `x0` (original text), `w` (read/write image) and `x1` (patch area).
#[derive(Clone, Debug)]
pub struct ModulePieces {
    pub name: String,
    pub x0: Piece,
    pub w: Piece,
    pub x1: Piece,
}

/// A module's rewritten files.
#[derive(Clone, Debug)]
pub struct ModuleSource {
    pub name: String,
    pub patched_bin: PathBuf,
    pub fixups_tsv: PathBuf,
}

impl ModuleSource {
    /// `<dir>/<name>.patched.bin` and `<dir>/<name>.fixups.tsv`, the layout `assemble.py --game` expects.
    pub fn in_dir(dir: &Path, name: &str) -> ModuleSource {
        ModuleSource {
            name: name.to_string(),
            patched_bin: dir.join(format!("{name}.patched.bin")),
            fixups_tsv: dir.join(format!("{name}.fixups.tsv")),
        }
    }

    /// `pieces()` + `section_bytes()`: cut the module's image at the engine's 16K-aligned boundaries.
    pub fn pieces(&self) -> Result<ModulePieces> {
        let sz = std::fs::metadata(&self.patched_bin)
            .map_err(|e| Error::io(self.patched_bin.display().to_string(), e))?
            .len();
        let hdr = FixupsHeader::read(&self.fixups_tsv)?;
        let ranges = piece_ranges(&hdr, sz, Mode::Assemble)?;
        let bin = abspath(&self.patched_bin);
        let mk = |&(lo, hi): &(u64, u64)| -> Result<Piece> {
            let fill = sz.min(hi) as i128 - lo as i128;
            if fill < 0 {
                return Err(Error::invalid(format!(
                    "{}: piece {lo:#x}..{hi:#x} starts past the end of the file ({sz:#x})",
                    bin.display()
                )));
            }
            Ok(Piece {
                len: hi - lo,
                data: PieceData::File {
                    path: bin.clone(),
                    offset: lo,
                    fill: fill as u64,
                },
            })
        };
        Ok(ModulePieces {
            name: self.name.clone(),
            x0: mk(&ranges[0])?,
            w: mk(&ranges[1])?,
            x1: mk(&ranges[2])?,
        })
    }
}

/// `--synthetic`: one zero page per section, no game files.
pub fn synthetic_pieces(names: &[String]) -> Vec<ModulePieces> {
    names
        .iter()
        .map(|n| ModulePieces {
            name: n.clone(),
            x0: Piece::zeros(PG),
            w: Piece::zeros(PG),
            x1: Piece::zeros(PG),
        })
        .collect()
}

/// What `build()` returns in its info dict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssembleInfo {
    pub size: u64,
    pub host_size: u64,
    pub text_end_old: u64,
    pub text_size_new: u64,
    pub game_bytes: u64,
    pub w_bytes: u64,
    pub n_load_commands: usize,
    pub header_slack_used: u64,
    pub header_slack_total: i64,
}

#[derive(Clone, Debug)]
pub struct AssembleReport {
    pub info: AssembleInfo,
    /// The segments of the output, in load-command order (`ordered` in `build()`).
    pub segments: Vec<Segment>,
}

struct DataPart {
    host_off: u64,
    len: u64,
    new_off: u64,
}

/// A fully laid-out assembly: everything but the bulk bytes is computed (and every check has passed).
pub struct Plan {
    host_len: u64,
    content_end: u64,
    total_len: u64,
    new_lc_bytes: Vec<u8>,
    ncmds: u32,
    /// (file offset, module index, 0 = x0 / 1 = x1) in section order: all x0 first, then all x1.
    game_secs: Vec<(u64, usize, u8)>,
    w_offsets: Vec<u64>,
    data_parts: Vec<DataPart>,
    le_old_off: u64,
    le_old_size: u64,
    le_new_off: u64,
    cf_rel: u64,
    cf_size: u64,
    new_cf: Vec<u8>,
    report: AssembleReport,
}

/// Add `delta` (+`extra` for offsets at/after `extra_at`) to every file offset in this load command that
/// points into `__LINKEDIT` (`retarget` in `build()`).
/// The host's chained-fixups `starts_in_image` array: (where it starts in the blob, its `seg_count` offsets). The count is the blob's word: it must fit in the blob before it is
/// reserved (a crafted `u32` would ask for ~16 GiB; review finding 4.1).
fn read_old_starts(cf: &[u8]) -> Result<(usize, Vec<u32>)> {
    let starts_off = rd_u32(cf, 4)? as usize;
    let old_count = rd_u32(cf, starts_off)? as usize;
    let room = cf.len().saturating_sub(starts_off + 4) / 4;
    ensure!(
        old_count <= room,
        "the host's chained-fixups blob counts {old_count} segments but holds room for {room} after its starts_in_image at {starts_off:#x}"
    );
    let mut old_arr: Vec<u32> = Vec::with_capacity(old_count);
    for i in 0..old_count {
        old_arr.push(rd_u32(cf, starts_off + 4 + 4 * i)?);
    }
    Ok((starts_off, old_arr))
}

fn retarget(b: &mut [u8], cmd: u32, delta: i128, extra_at: u64, extra: u64) -> Result<()> {
    fn add32(b: &mut [u8], off: usize, delta: i128, extra_at: u64, extra: u64) -> Result<()> {
        let v = rd_u32(b, off)?;
        if v != 0 {
            let bump = if u64::from(v) >= extra_at {
                extra as i128
            } else {
                0
            };
            wr_u32(
                b,
                off,
                to_u32(v as i128 + delta + bump, "re-pointed __LINKEDIT offset")?,
            )?;
        }
        Ok(())
    }
    if LINKEDIT_DATA.contains(&cmd) {
        add32(b, 8, delta, extra_at, extra)?;
    } else if cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY {
        for off in [8, 16, 24, 32, 40] {
            add32(b, off, delta, extra_at, extra)?; // rebase/bind/weak/lazy/export off
        }
    } else if cmd == LC_SYMTAB {
        add32(b, 8, delta, extra_at, extra)?; // symoff
        add32(b, 16, delta, extra_at, extra)?; // stroff
    } else if cmd == LC_DYSYMTAB {
        for off in [32, 40, 48, 56, 64, 72] {
            add32(b, off, delta, extra_at, extra)?; // toc/modtab/extrefsym/indirectsym/extrel/locrel
        }
    }
    Ok(())
}

impl Plan {
    /// Lay out the assembly of `host` + `modules`. Reads only the host's header, load commands and
    /// chained-fixups blob.
    pub fn new<R: ReadAt + ?Sized>(host: &R, modules: &[ModulePieces], tag: &str) -> Result<Plan> {
        let host_len = host.len().map_err(|e| Error::io("host length", e))?;
        let head = read_vec(host, 0, 32, "host header")?;
        let magic = rd_u32(&head, 0)?;
        ensure!(magic == MH_MAGIC_64, "not a 64-bit Mach-O ({magic:#x})");
        let sizeofcmds = rd_u32(&head, 20)? as u64;
        let lc_area = read_vec(host, 0, 32 + sizeofcmds, "host load commands")?;
        let (hdr, lcs, segs) = parse(&lc_area)?;
        // dict comprehension semantics: a later segment of the same name wins
        let mut byname: HashMap<&str, usize> = HashMap::new();
        for (i, s) in segs.iter().enumerate() {
            byname.insert(s.name.as_str(), i);
        }
        let (text, le) = match (byname.get("__TEXT"), byname.get("__LINKEDIT")) {
            (Some(&t), Some(&l)) => (&segs[t], &segs[l]),
            _ => return Err(Error::invalid("host has no __TEXT/__LINKEDIT")),
        };
        ensure!(
            text.fileoff == 0 && text.vmaddr == 0,
            "the host's __TEXT is not at file/vm 0"
        );
        for name in HIGH_SEGMENTS {
            if let Some(&i) = byname.get(name) {
                ensure!(
                    segs[i].vmaddr >= 0x1000_0000,
                    "the prebuild must place {name} high (a gap after __TEXT for the game); rebuild the host with assemble_prebuild.sh"
                );
            }
        }
        // The sizes are the host's word (review r2, N3): `fileoff + filesize` and the `align(.. + 0x3fff)` of the layout below wrap near 2^64 (a panic in a debug build, a wrong layout in a release one).
        ensure!(
            le.fileoff.checked_add(le.filesize) == Some(host_len),
            "__LINKEDIT is not the last file segment"
        );
        ensure!(
            text.filesize <= host_len,
            "__TEXT's filesize {:#x} is past the end of the host ({host_len:#x} bytes)",
            text.filesize
        );

        // ---- lay the game's x0/x1 into __TEXT, right after the host's __TEXT content --------------------
        let mut x0x1: Vec<(String, usize, u8, u64)> = Vec::new(); // (section name, module, 0|1, len)
        for (i, m) in modules.iter().enumerate() {
            x0x1.push((format!("__dm{tag}{}x0", m.name), i, 0, m.x0.len));
        }
        for (i, m) in modules.iter().enumerate() {
            x0x1.push((format!("__dm{tag}{}x1", m.name), i, 1, m.x1.len));
        }
        let content_end = align(text.filesize, PG);
        let mut game_secs: Vec<Section> = Vec::new();
        let mut game_offsets: Vec<(u64, usize, u8)> = Vec::new();
        let mut cur = content_end;
        for (sname, mi, kind, len) in &x0x1 {
            cur = align(cur, PG);
            game_secs.push(Section::plain(
                sname,
                cur,
                *len,
                to_u32(cur as i128, "game section offset")?,
                14,
                S_REGULAR,
            ));
            game_offsets.push((cur, *mi, *kind));
            cur += len;
        }
        let text_new_size = align(cur, PG);
        let gap_end = HIGH_SEGMENTS
            .iter()
            .filter_map(|n| byname.get(n).map(|&i| segs[i].vmaddr))
            .min()
            .unwrap_or(1 << 62);
        ensure!(
            text_new_size < gap_end,
            "the game's sections do not fit in the gap the prebuild reserved"
        );

        // ---- W segments in the same free range, their file content after the game's ----------------------
        let mut w_segs: Vec<Segment> = Vec::new();
        let mut w_offsets: Vec<u64> = Vec::new();
        let mut vm = text_new_size;
        let mut wfo = text_new_size;
        for m in modules {
            vm = align(vm, PG);
            let sec = Section::plain(
                "__img",
                vm,
                m.w.len,
                to_u32(wfo as i128, "W section offset")?,
                14,
                S_REGULAR,
            );
            w_segs.push(Segment {
                name: format!("__DM{tag}{}W", m.name),
                vmaddr: vm,
                vmsize: align(m.w.len, PG),
                fileoff: wfo,
                filesize: align(m.w.len, PG),
                maxprot: 3,
                initprot: 3,
                flags: 0,
                secs: vec![sec],
            });
            w_offsets.push(wfo);
            vm += m.w.len;
            wfo += align(m.w.len, PG);
        }

        // ---- the chained-fixups blob: seg_count must equal the number of LC_SEGMENT_64 commands, and the
        //      per-segment structs are indexed by a segment's position in the load-command list. ------------
        let cf_lc = lcs
            .iter()
            .find(|l| l.cmd == LC_DYLD_CHAINED_FIXUPS)
            .ok_or_else(|| Error::invalid("the host has no LC_DYLD_CHAINED_FIXUPS"))?;
        let cf_off = rd_u32(&lc_area, cf_lc.off + 8)? as u64;
        let cf_size = rd_u32(&lc_area, cf_lc.off + 12)? as u64;
        ensure!(
            cf_off >= le.fileoff && cf_off + cf_size <= le.fileoff + le.filesize,
            "the chained-fixups blob ({cf_off:#x}+{cf_size:#x}) is not inside __LINKEDIT"
        );
        let cf = read_vec(host, cf_off, cf_size, "chained-fixups blob")?;
        let (starts_off, old_arr) = read_old_starts(&cf)?;
        let old_count = old_arr.len();
        let insert_at = starts_off + 4 + 4 * old_count;
        let insert_abs = cf_off + insert_at as u64;
        let grow_raw = 4 * (segs.len() as i64 + w_segs.len() as i64 - old_count as i64);
        ensure!(
            grow_raw >= 0,
            "the host's fixups blob counts more segments than it has plus the game's"
        );
        let grow = align(grow_raw as u64, 8); // one u32 per new segment, 8-padded
        let le_size_new = le.filesize + grow;

        // ---- file placement of the host's writable content (its vmaddr is untouched) ---------------------
        let mut data_parts: Vec<DataPart> = Vec::new();
        let mut fpos = align(wfo, PG);
        let mut data_new: HashMap<&str, u64> = HashMap::new();
        for name in ["__DATA_CONST", "__DATA"] {
            let i = *byname
                .get(name)
                .ok_or_else(|| Error::invalid(format!("KeyError: the host has no {name}")))?;
            let seg = &segs[i];
            data_new.insert(name, fpos);
            ensure!(
                seg.fileoff
                    .checked_add(seg.filesize)
                    .is_some_and(|end| end <= host_len),
                "{name} extends past the end of the host"
            );
            data_parts.push(DataPart {
                host_off: seg.fileoff,
                len: seg.filesize,
                new_off: fpos,
            });
            fpos = align(fpos + seg.filesize, PG);
        }
        let le_new_off = fpos;

        // ---- rebuild the segments: __TEXT (grown), the W segments, __DATA_CONST/__DATA (moved in file),
        //      __LINKEDIT (moved, and grown by the fixups array) -- ascending vmaddr, __LINKEDIT last ------
        let mut new_text = text.clone();
        new_text.filesize = text_new_size;
        new_text.vmsize = text_new_size;
        new_text.secs.extend(game_secs);
        let moved = |name: &str| -> Result<Segment> {
            let seg = &segs[byname[name]];
            let mut s = seg.clone();
            let new_off = data_new[name];
            let delta = new_off as i128 - seg.fileoff as i128;
            s.fileoff = new_off;
            for sec in &mut s.secs {
                if sec.offset != 0 {
                    sec.offset = to_u32(sec.offset as i128 + delta, "moved section offset")?;
                }
            }
            Ok(s)
        };
        let new_dc = moved("__DATA_CONST")?;
        let new_dd = moved("__DATA")?;
        let mut new_le = le.clone();
        new_le.fileoff = le_new_off;
        new_le.filesize = le_size_new;
        new_le.secs = Vec::new();
        let mut data_two = vec![new_dc, new_dd];
        data_two.sort_by_key(|s| s.vmaddr); // stable, like Python's sorted()
        let mut ordered: Vec<Segment> = vec![new_text];
        ordered.extend(w_segs);
        ordered.extend(data_two);
        ordered.push(new_le);

        // ---- extend the fixups blob: one seg_info_offset per segment, structs moved by `grow` ------------
        let mut idx: HashMap<&str, usize> = HashMap::new();
        for (i, s) in ordered.iter().enumerate() {
            idx.insert(s.name.as_str(), i);
        }
        let mut new_arr = vec![0u32; ordered.len()];
        for (i, s) in segs.iter().enumerate() {
            let o = *old_arr.get(i).ok_or_else(|| {
                Error::invalid(format!(
                    "IndexError: the fixups blob has no entry for segment {i} ({})",
                    s.name
                ))
            })?;
            if o != 0 {
                let j = *idx.get(s.name.as_str()).ok_or_else(|| {
                    Error::invalid(format!("KeyError: segment {} has chained fixups but is not carried into the output", s.name))
                })?;
                new_arr[j] = to_u32(o as i128 + grow as i128, "seg_info_offset")?;
            }
        }
        let mut new_cf = cf[..starts_off].to_vec();
        new_cf.extend((ordered.len() as u32).to_le_bytes());
        for v in &new_arr {
            new_cf.extend(v.to_le_bytes());
        }
        let pad = grow as i64 - (4 * new_arr.len() as i64 - 4 * old_count as i64);
        if pad > 0 {
            new_cf.resize(new_cf.len() + pad as usize, 0); // keep the blob 8-aligned
        }
        if insert_at <= cf.len() {
            new_cf.extend_from_slice(&cf[insert_at..]);
        }
        wr_u32(
            &mut new_cf,
            8,
            to_u32(rd_u32(&cf, 8)? as i128 + grow as i128, "imports_offset")?,
        )?;
        wr_u32(
            &mut new_cf,
            12,
            to_u32(rd_u32(&cf, 12)? as i128 + grow as i128, "symbols_offset")?,
        )?;
        ensure!(
            new_cf.len() as u64 == cf_size + grow,
            "chained-fixups blob grew to {} (want {})",
            new_cf.len(),
            cf_size + grow
        );
        let cf_rel = cf_off - le.fileoff;

        // ---- rebuild the load-command stream: segments (ascending vmaddr, __LINKEDIT last) then the rest --
        let mut rebuilt: Vec<Vec<u8>> = Vec::new();
        for s in &ordered {
            rebuilt.push(seg_lc_bytes(s)?);
        }
        let delta_le = le_new_off as i128 - le.fileoff as i128;
        for lc in &lcs {
            if lc.cmd == LC_SEGMENT_64 {
                continue;
            }
            let mut b = lc_area[lc.off..lc.off + lc.cmdsize as usize].to_vec();
            retarget(&mut b, lc.cmd, delta_le, insert_abs, grow)?;
            if lc.cmd == LC_DYLD_CHAINED_FIXUPS {
                let datasize = to_u32(
                    rd_u32(&b, 12)? as i128 + grow as i128,
                    "chained fixups datasize",
                )?;
                wr_u32(&mut b, 12, datasize)?;
            }
            rebuilt.push(b);
        }
        let new_lc_bytes: Vec<u8> = rebuilt.concat();
        let first_sec_off = hdr
            .first_sec_off
            .ok_or_else(|| Error::invalid("the host has no file-backed section"))?;
        let slack = first_sec_off as i64 - hdr.lc_end as i64;
        if new_lc_bytes.len() as i64 > slack {
            return Err(Error::invalid(format!(
                "host header slack too small: need {}, have {slack} (prebuild the host with -Wl,-headerpad)",
                new_lc_bytes.len()
            )));
        }

        // ---- the file's final length: the furthest end of anything written --------------------------------
        let mut total = content_end.min(host_len).max(text_new_size);
        for (i, m) in modules.iter().enumerate() {
            total = total.max(w_offsets[i] + m.w.len);
        }
        for p in &data_parts {
            total = total.max(p.new_off + p.len);
        }
        total = total.max(le_new_off + le_size_new);

        let info = AssembleInfo {
            size: total,
            host_size: host_len,
            text_end_old: content_end,
            text_size_new: text_new_size,
            game_bytes: x0x1.iter().map(|x| x.3).sum(),
            w_bytes: modules.iter().map(|m| m.w.len).sum(),
            n_load_commands: rebuilt.len(),
            header_slack_used: new_lc_bytes.len() as u64,
            header_slack_total: slack,
        };
        Ok(Plan {
            host_len,
            content_end,
            total_len: total,
            ncmds: rebuilt.len() as u32,
            new_lc_bytes,
            game_secs: game_offsets,
            w_offsets,
            data_parts,
            le_old_off: le.fileoff,
            le_old_size: le.filesize,
            le_new_off,
            cf_rel,
            cf_size,
            new_cf,
            report: AssembleReport {
                info,
                segments: ordered,
            },
        })
    }

    pub fn report(&self) -> &AssembleReport {
        &self.report
    }

    /// Write the assembled image into `out` (a pre-sized file: unwritten ranges stay zero). Peak memory is
    /// one [`CHUNK`] plus the load commands and the fixups blob.
    pub fn write<R: ReadAt + ?Sized, W: WriteAt + ?Sized>(
        &self,
        host: &R,
        modules: &[ModulePieces],
        out: &mut W,
    ) -> Result<()> {
        out.set_len(self.total_len)
            .map_err(|e| Error::io("sizing the output", e))?;
        let mut buf = vec![0u8; CHUNK];
        // host header + __TEXT content (`out = host[:content_end]`), then the rebuilt load commands over it
        let head_len = self.content_end.min(self.host_len);
        copy_range(host, 0, out, 0, head_len, &mut buf, "host __TEXT")?;
        out.write_all_at(&self.new_lc_bytes, 32)
            .map_err(|e| Error::io("writing load commands", e))?;
        let mut counts = [0u8; 8];
        counts[..4].copy_from_slice(&self.ncmds.to_le_bytes());
        counts[4..].copy_from_slice(&(self.new_lc_bytes.len() as u32).to_le_bytes());
        out.write_all_at(&counts, 16)
            .map_err(|e| Error::io("writing ncmds/sizeofcmds", e))?;
        // the game's x0 / x1 sections, then the W segments
        for &(off, mi, kind) in &self.game_secs {
            let m = &modules[mi];
            let piece = if kind == 0 { &m.x0 } else { &m.x1 };
            write_piece(
                piece,
                out,
                off,
                &mut buf,
                &format!("{} {}", m.name, if kind == 0 { "x0" } else { "x1" }),
            )?;
        }
        for (i, m) in modules.iter().enumerate() {
            write_piece(
                &m.w,
                out,
                self.w_offsets[i],
                &mut buf,
                &format!("{} W", m.name),
            )?;
        }
        // the host's __DATA_CONST / __DATA, moved in the file
        for p in &self.data_parts {
            copy_range(
                host,
                p.host_off,
                out,
                p.new_off,
                p.len,
                &mut buf,
                "host data segment",
            )?;
        }
        // __LINKEDIT with the chained-fixups blob replaced by the grown one
        let before = self.cf_rel;
        copy_range(
            host,
            self.le_old_off,
            out,
            self.le_new_off,
            before,
            &mut buf,
            "host __LINKEDIT (before fixups)",
        )?;
        out.write_all_at(&self.new_cf, self.le_new_off + before)
            .map_err(|e| Error::io("writing the chained-fixups blob", e))?;
        let after_old = before + self.cf_size;
        copy_range(
            host,
            self.le_old_off + after_old,
            out,
            self.le_new_off + before + self.new_cf.len() as u64,
            self.le_old_size - after_old,
            &mut buf,
            "host __LINKEDIT (after fixups)",
        )?;
        Ok(())
    }
}

fn write_piece<W: WriteAt + ?Sized>(
    piece: &Piece,
    out: &mut W,
    dst: u64,
    buf: &mut [u8],
    what: &str,
) -> Result<()> {
    match &piece.data {
        PieceData::Zeros => Ok(()),
        PieceData::Bytes(v) => {
            ensure!(
                v.len() as u64 <= piece.len,
                "{what}: piece bytes exceed its length"
            );
            out.write_all_at(v, dst)
                .map_err(|e| Error::io(what.to_string(), e))
        }
        PieceData::File { path, offset, fill } => {
            let f = File::open(path).map_err(|e| Error::io(path.display().to_string(), e))?;
            ensure!(*fill <= piece.len, "{what}: piece fill exceeds its length");
            copy_range(&f, *offset, out, dst, *fill, buf, what)
        }
    }
}

/// Do two paths name the same file (same device and inode)? False when either does not exist.
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

/// The game side of an assembly.
#[derive(Clone, Debug)]
pub enum Game {
    /// `--game <dir> --modules ...`: `<dir>/<name>.patched.bin` + `.fixups.tsv`.
    Dir { dir: PathBuf, modules: Vec<String> },
    /// Explicit per-module files (they need not share a directory).
    Sources(Vec<ModuleSource>),
    /// `--synthetic`: a zero page per section.
    Synthetic { modules: Vec<String> },
}

impl Game {
    pub fn pieces(&self) -> Result<Vec<ModulePieces>> {
        match self {
            Game::Dir { dir, modules } => modules
                .iter()
                .map(|n| ModuleSource::in_dir(dir, n).pieces())
                .collect(),
            Game::Sources(v) => v.iter().map(ModuleSource::pieces).collect(),
            Game::Synthetic { modules } => Ok(synthetic_pieces(modules)),
        }
    }
}

/// `assemble.build(host, out, game_dir, modules, synthetic, tag)`: assemble `host` + `game` into the file
/// `out`. Layout and checks come first; the output file is created only once they pass, and a partial file
/// is removed if writing fails.
pub fn assemble_files(host: &Path, out: &Path, game: &Game, tag: &str) -> Result<AssembleReport> {
    let host_file = File::open(host).map_err(|e| Error::io(host.display().to_string(), e))?;
    let modules = game.pieces()?;
    let plan = Plan::new(&host_file, &modules, tag)?;
    // Python reads every input into memory before it writes, so `out == input` happens to work there. Streaming
    // would truncate the input under our feet: refuse instead.
    let inputs = std::iter::once(host).chain(
        modules
            .iter()
            .flat_map(|m| [&m.x0, &m.w, &m.x1])
            .filter_map(|p| match &p.data {
                PieceData::File { path, .. } => Some(path.as_path()),
                _ => None,
            }),
    );
    for input in inputs {
        if same_file(input, out) {
            return Err(Error::invalid(format!(
                "the output {} is also an input ({}); the assembler streams and would overwrite it",
                out.display(),
                input.display()
            )));
        }
    }
    let mut out_file = File::create(out).map_err(|e| Error::io(out.display().to_string(), e))?;
    if let Err(e) = plan.write(&host_file, &modules, &mut out_file) {
        drop(out_file);
        let _ = std::fs::remove_file(out);
        return Err(e);
    }
    Ok(plan.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MemSink;
    use crate::writer::{
        chained_fixups_blob, dylib_id_command, linkedit_command, load_dylib_command, symtab_command,
    };

    /// A miniature host shaped like the prebuild's output: __TEXT at 0, __DATA_CONST/__DATA placed high,
    /// __LINKEDIT last, with a chained-fixups blob that has `starts_in_image` for the two data segments.
    pub(crate) fn synthetic_host(headerpad_slack: u64) -> Vec<u8> {
        const SG_READ_ONLY: u32 = 0x10;
        let text_size = 0x8000u64;
        let dc_off = 0x8000u64;
        let dd_off = 0xC000u64;
        let le_off = 0x10000u64;
        // __LINKEDIT payload: [cf][exports][funcstarts][symtab 2 nlists][strtab], 8-aligned blobs
        let mut cf = chained_fixups_blob(4);
        // make seg 1 (__DATA_CONST) and seg 2 (__DATA) carry a starts struct each
        // starts_in_image at 32: seg_count(4) + 4 offsets; put two 8-byte structs after it, 8-aligned
        let starts_struct_off = 32 + 4 + 16;
        cf.resize(starts_struct_off + 24, 0xEE);
        cf[36 + 4..36 + 8].copy_from_slice(&(starts_struct_off as u32).to_le_bytes());
        cf[36 + 8..36 + 12].copy_from_slice(&((starts_struct_off + 8) as u32).to_le_bytes());
        // imports_offset / symbols_offset after the structs (counts stay 0)
        let imp = (starts_struct_off + 24) as u32;
        cf[8..12].copy_from_slice(&imp.to_le_bytes());
        cf[12..16].copy_from_slice(&imp.to_le_bytes());
        while !cf.len().is_multiple_of(8) {
            cf.push(0);
        }
        let exports: Vec<u8> = (0..24u8).map(|i| 0x30 + i).collect();
        let fstarts: Vec<u8> = vec![0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let nlists: Vec<u8> = (0..32u8).map(|i| 0x50 + i).collect();
        let strtab: Vec<u8> = b"\0_a\0_b\0\0\0\0\0\0".to_vec();
        let mut le = Vec::new();
        let mut offs = [0u64; 5];
        for (i, blob) in [&cf, &exports, &fstarts, &nlists, &strtab]
            .iter()
            .enumerate()
        {
            offs[i] = le.len() as u64;
            le.extend_from_slice(blob);
            while le.len() % 8 != 0 {
                le.push(0);
            }
        }
        let secs_text = vec![
            Section::plain(
                "__text",
                0x4000,
                0x100,
                0x4000,
                2,
                S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS,
            ),
            Section::plain("__const", 0x4400, 0x40, 0x4400, 4, S_REGULAR),
        ];
        let segs = [
            Segment {
                name: "__TEXT".into(),
                vmaddr: 0,
                vmsize: text_size,
                fileoff: 0,
                filesize: text_size,
                maxprot: VM_PROT_RX,
                initprot: VM_PROT_RX,
                flags: 0,
                secs: secs_text,
            },
            Segment {
                name: "__DATA_CONST".into(),
                vmaddr: 0x7fff_0000,
                vmsize: 0x4000,
                fileoff: dc_off,
                filesize: 0x4000,
                maxprot: VM_PROT_RW,
                initprot: VM_PROT_RW,
                flags: SG_READ_ONLY,
                secs: vec![Section::plain(
                    "__got",
                    0x7fff_0000,
                    0x20,
                    dc_off as u32,
                    3,
                    6,
                )],
            },
            Segment {
                name: "__DATA".into(),
                vmaddr: 0x8000_0000,
                vmsize: 0x8000,
                fileoff: dd_off,
                filesize: 0x4000,
                maxprot: VM_PROT_RW,
                initprot: VM_PROT_RW,
                flags: 0,
                secs: vec![
                    Section::plain("__data", 0x8000_0000, 0x100, dd_off as u32, 3, S_REGULAR),
                    Section::plain("__bss", 0x8000_4000, 0x4000, 0, 3, 1),
                ],
            },
            Segment {
                name: "__LINKEDIT".into(),
                vmaddr: 0x8000_8000,
                vmsize: 0x4000,
                fileoff: le_off,
                filesize: le.len() as u64,
                maxprot: VM_PROT_R,
                initprot: VM_PROT_R,
                flags: 0,
                secs: vec![],
            },
        ];
        let mut dysym = crate::writer::dysymtab_command(2, 0, 0, 0);
        // a few nonzero table offsets into __LINKEDIT, to check they are re-pointed
        dysym[56..60].copy_from_slice(&((le_off + offs[4]) as u32).to_le_bytes()); // indirectsymoff
        let mut lcs: Vec<Vec<u8>> = Vec::new();
        for s in &segs {
            lcs.push(seg_lc_bytes(s).unwrap());
        }
        lcs.push(dylib_id_command("@rpath/H.framework/H").unwrap());
        lcs.push(
            linkedit_command(LC_DYLD_CHAINED_FIXUPS, le_off + offs[0], cf.len() as u64).unwrap(),
        );
        lcs.push(
            linkedit_command(LC_DYLD_EXPORTS_TRIE, le_off + offs[1], exports.len() as u64).unwrap(),
        );
        lcs.push(
            symtab_command(le_off + offs[3], 2, le_off + offs[4], strtab.len() as u64).unwrap(),
        );
        lcs.push(dysym);
        lcs.push(
            linkedit_command(LC_FUNCTION_STARTS, le_off + offs[2], fstarts.len() as u64).unwrap(),
        );
        lcs.push(load_dylib_command("/usr/lib/libSystem.B.dylib", 0x054F2803, 0x10000).unwrap());
        let sizeofcmds: usize = lcs.iter().map(Vec::len).sum();
        assert!(
            32 + sizeofcmds as u64 + headerpad_slack <= 0x4000,
            "test host layout"
        );
        let mut f = vec![0u8; (le_off as usize) + le.len()];
        for (i, v) in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            MH_DYLIB,
            lcs.len() as u32,
            sizeofcmds as u32,
            MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL,
            0,
        ]
        .iter()
        .enumerate()
        {
            f[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        let mut p = 32;
        for c in &lcs {
            f[p..p + c.len()].copy_from_slice(c);
            p += c.len();
        }
        for (i, b) in f[0x4000..0x8000].iter_mut().enumerate() {
            *b = (i % 251) as u8 ^ 0x5A; // host __TEXT content
        }
        for (i, b) in f[dc_off as usize..dd_off as usize].iter_mut().enumerate() {
            *b = (i % 241) as u8 ^ 0xC0; // __DATA_CONST
        }
        for (i, b) in f[dd_off as usize..le_off as usize].iter_mut().enumerate() {
            *b = (i % 239) as u8 ^ 0xD0; // __DATA
        }
        f[le_off as usize..].copy_from_slice(&le);
        f
    }

    fn pieces3() -> Vec<ModulePieces> {
        let mk = |tag: u8, n: usize| {
            Piece::bytes((0..n).map(|i| tag.wrapping_add((i % 7) as u8)).collect())
        };
        vec![
            ModulePieces {
                name: "main".into(),
                x0: mk(0x10, 0x8000),
                w: mk(0x20, 0x4000),
                x1: mk(0x30, 0x4000),
            },
            ModulePieces {
                name: "sdk".into(),
                x0: mk(0x40, 0x4000),
                w: mk(0x50, 0x8000),
                x1: mk(0x60, 0x4000),
            },
        ]
    }

    #[test]
    fn assembled_layout_is_valid() {
        let host = synthetic_host(0x200);
        let mods = pieces3();
        let plan = Plan::new(&host, &mods, "").unwrap();
        let mut out = MemSink::default();
        plan.write(&host, &mods, &mut out).unwrap();
        let out = out.0;
        assert_eq!(out.len() as u64, plan.report().info.size);
        let (hdr, lcs, segs) =
            parse(&out[..32 + u32::from_le_bytes(out[20..24].try_into().unwrap()) as usize])
                .unwrap();
        let names: Vec<&str> = segs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "__TEXT",
                "__DMmainW",
                "__DMsdkW",
                "__DATA_CONST",
                "__DATA",
                "__LINKEDIT"
            ]
        );
        // __TEXT grew to cover x0 x0 x1 x1 (sections after the host's own two)
        let text = &segs[0];
        let sec_names: Vec<&str> = text.secs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            sec_names,
            [
                "__text",
                "__const",
                "__dmmainx0",
                "__dmsdkx0",
                "__dmmainx1",
                "__dmsdkx1"
            ]
        );
        assert_eq!(text.filesize, text.vmsize);
        assert_eq!(text.filesize % PG, 0);
        for s in &text.secs[2..] {
            assert_eq!(s.addr % PG, 0);
            assert_eq!(u64::from(s.offset), s.addr, "__TEXT maps identity");
            assert_eq!(s.align, 14);
        }
        // sizes the loader checks (x0 = r16(TEXT_END), x1 = patch area)
        assert_eq!(text.secs[2].size, 0x8000);
        assert_eq!(text.secs[3].size, 0x4000);
        // W segments: rw, file == vm, page-aligned, in the free gap
        for (i, w) in segs[1..3].iter().enumerate() {
            assert_eq!(w.maxprot, 3);
            assert_eq!(w.initprot, 3);
            assert_eq!(w.fileoff, w.vmaddr);
            assert_eq!(w.fileoff % PG, 0);
            assert!(w.vmaddr >= text.vmsize && w.vmaddr + w.vmsize < 0x7fff_0000);
            assert_eq!(w.secs[0].name, "__img");
            assert_eq!(w.secs[0].size, mods[i].w.len);
        }
        // the host's writable segments keep vmaddr, flags and section content, but moved in the file
        let dc = &segs[3];
        assert_eq!(dc.vmaddr, 0x7fff_0000);
        assert_eq!(dc.flags, 0x10, "SG_READ_ONLY must survive");
        assert_eq!(dc.fileoff % PG, 0);
        assert_eq!(
            &out[dc.fileoff as usize..(dc.fileoff + dc.filesize) as usize],
            &host[0x8000..0xC000]
        );
        assert_eq!(u64::from(dc.secs[0].offset), dc.fileoff);
        let dd = &segs[4];
        assert_eq!(
            &out[dd.fileoff as usize..(dd.fileoff + dd.filesize) as usize],
            &host[0xC000..0x10000]
        );
        assert_eq!(dd.secs[1].offset, 0, "__bss stays offset 0");
        // __LINKEDIT is the last file segment and ends at EOF
        let le = &segs[5];
        assert_eq!(le.fileoff + le.filesize, out.len() as u64);
        assert_eq!(le.fileoff % PG, 0);
        // piece bytes landed at their offsets, zero-padded
        let ms = &text.secs;
        assert_eq!(
            &out[ms[2].offset as usize..ms[2].offset as usize + 0x8000],
            match &mods[0].x0.data {
                PieceData::Bytes(v) => v.as_slice(),
                _ => unreachable!(),
            }
        );
        assert_eq!(
            &out[segs[2].fileoff as usize..segs[2].fileoff as usize + 0x8000],
            match &mods[1].w.data {
                PieceData::Bytes(v) => v.as_slice(),
                _ => unreachable!(),
            }
        );
        // host __TEXT content is untouched past the load commands
        assert_eq!(&out[0x4000..0x8000], &host[0x4000..0x8000]);
        // header counts match the rebuilt stream
        assert_eq!(hdr.ncmds as usize, lcs.len());
        assert_eq!(plan.report().info.n_load_commands, lcs.len());
        assert_eq!(
            plan.report().info.game_bytes,
            0x8000 + 0x4000 + 0x4000 + 0x4000
        );
        assert_eq!(plan.report().info.w_bytes, 0x4000 + 0x8000);
    }

    /// The host's segment sizes are the file's word (review r2, N3): `align(x + 16383)` and `fileoff + filesize` wrapped in a release build and panicked in a debug one. A size that cannot be inside
    /// the host is refused before any of that arithmetic.
    #[test]
    fn a_host_whose_segment_sizes_overflow_is_refused_not_wrapped() {
        let host = synthetic_host(0x200);
        let sizeofcmds = u32::from_le_bytes(host[20..24].try_into().unwrap()) as usize;
        let (_, lcs, segs) = parse(&host[..32 + sizeofcmds]).unwrap();
        let seg_lc = |name: &str| {
            lcs.iter()
                .filter(|l| l.cmd == LC_SEGMENT_64)
                .zip(&segs)
                .find(|(_, s)| s.name == name)
                .map(|(l, _)| l.off)
                .unwrap()
        };
        for (name, huge) in [
            ("__TEXT", u64::MAX - 0xf),
            ("__TEXT", 1 << 40),
            ("__DATA_CONST", u64::MAX - 0xf),
            ("__DATA", u64::MAX),
            ("__LINKEDIT", u64::MAX - 0xf),
        ] {
            let mut bad = host.clone();
            let at = seg_lc(name) + 48; // filesize
            bad[at..at + 8].copy_from_slice(&huge.to_le_bytes());
            let r = std::panic::catch_unwind(|| Plan::new(&bad, &pieces3(), "").map(|_| ()));
            let r = r.unwrap_or_else(|_| {
                panic!("{name} filesize {huge:#x}: panicked (a debug-build overflow check)")
            });
            let e = r
                .expect_err(&format!(
                    "{name} filesize {huge:#x} cannot be inside a host of {:#x} bytes",
                    host.len()
                ))
                .to_string();
            assert!(
                e.contains("past the end")
                    || e.contains("not the last file segment")
                    || e.contains("extends past"),
                "{name} {huge:#x}: {e}"
            );
        }
    }

    #[test]
    fn every_linkedit_offset_is_repointed() {
        let host = synthetic_host(0x200);
        let mods = pieces3();
        let plan = Plan::new(&host, &mods, "").unwrap();
        let mut out = MemSink::default();
        plan.write(&host, &mods, &mut out).unwrap();
        let out = out.0;
        let (_, hl, hs) = parse(&host[..32 + rd_u32(&host, 20).unwrap() as usize]).unwrap();
        let (_, ol, os) = parse(&out[..32 + rd_u32(&out, 20).unwrap() as usize]).unwrap();
        let old_le = hs.iter().find(|s| s.name == "__LINKEDIT").unwrap();
        let new_le = os.iter().find(|s| s.name == "__LINKEDIT").unwrap();
        let delta = new_le.fileoff - old_le.fileoff;
        let grow = new_le.filesize - old_le.filesize;
        assert_eq!(grow % 8, 0);
        assert_eq!(grow, 8); // two added segments, 4 bytes each, rounded to 8
        let cf_old = hl.iter().find(|l| l.cmd == LC_DYLD_CHAINED_FIXUPS).unwrap();
        let cf_off_old = rd_u32(&host, cf_old.off + 8).unwrap() as u64;
        let cf_size_old = rd_u32(&host, cf_old.off + 12).unwrap() as u64;
        let ob: Vec<&LoadCmd> = hl.iter().filter(|l| l.cmd != LC_SEGMENT_64).collect();
        let nb: Vec<&LoadCmd> = ol.iter().filter(|l| l.cmd != LC_SEGMENT_64).collect();
        assert_eq!(ob.len(), nb.len());
        for (a, b) in ob.iter().zip(nb.iter()) {
            assert_eq!(
                a.cmd, b.cmd,
                "non-segment commands keep their order (LC_LOAD_DYLIB ordinals)"
            );
            // compare every u32 field of the command that points into LINKEDIT
            let fields: &[usize] = match a.cmd {
                LC_SYMTAB => &[8, 16],
                LC_DYSYMTAB => &[32, 40, 48, 56, 64, 72],
                c if LINKEDIT_DATA.contains(&c) => &[8],
                _ => &[],
            };
            for &f in fields {
                let v_old = rd_u32(&host, a.off + f).unwrap() as u64;
                let v_new = rd_u32(&out, b.off + f).unwrap() as u64;
                if v_old == 0 {
                    assert_eq!(v_new, 0);
                } else {
                    let want = v_old + delta + if v_old >= cf_off_old + 52 { grow } else { 0 }; // 52 = insert_at: starts_in_image (32) + count + 4 entries
                    assert_eq!(v_new, want, "cmd {:#x} field {f}", a.cmd);
                }
            }
            if a.cmd == LC_DYLD_CHAINED_FIXUPS {
                assert_eq!(
                    rd_u32(&out, b.off + 12).unwrap() as u64,
                    cf_size_old + grow,
                    "datasize grows"
                );
            }
        }
        // the fixups blob: seg_count 6, DATA_CONST/DATA keep their starts structs (shifted by grow)
        let cf_new = ol.iter().find(|l| l.cmd == LC_DYLD_CHAINED_FIXUPS).unwrap();
        let cf_off = rd_u32(&out, cf_new.off + 8).unwrap() as usize;
        let cf = &out[cf_off..cf_off + (cf_size_old + grow) as usize];
        assert_eq!(rd_u32(cf, 32).unwrap(), 6);
        let arr: Vec<u32> = (0..6).map(|i| rd_u32(cf, 36 + 4 * i).unwrap()).collect();
        // new order: __TEXT, __DMmainW, __DMsdkW, __DATA_CONST, __DATA, __LINKEDIT
        assert_eq!(arr, [0u32, 0, 0, 52 + 8, 60 + 8, 0], "{arr:?}");
        // imports/symbols offsets moved by grow; the structs and trailing bytes are intact
        let old_cf = &host[cf_off_old as usize..(cf_off_old + cf_size_old) as usize];
        assert_eq!(
            rd_u32(cf, 8).unwrap(),
            rd_u32(old_cf, 8).unwrap() + grow as u32
        );
        assert_eq!(
            rd_u32(cf, 12).unwrap(),
            rd_u32(old_cf, 12).unwrap() + grow as u32
        );
        assert_eq!(&cf[(52 + grow as usize)..], &old_cf[52..]);
        // all other LINKEDIT bytes are copied verbatim
        let rest_old =
            &host[(cf_off_old + cf_size_old) as usize..(old_le.fileoff + old_le.filesize) as usize];
        let rest_new_start = cf_off + cf.len();
        assert_eq!(
            &out[rest_new_start..rest_new_start + rest_old.len()],
            rest_old
        );
    }

    #[test]
    fn synthetic_pieces_are_zero_pages_and_tag_prefixes_names() {
        let host = synthetic_host(0x200);
        let names = vec!["main".to_string(), "sdk".to_string()];
        let mods = synthetic_pieces(&names);
        let plan = Plan::new(&host, &mods, "T").unwrap();
        let segs = &plan.report().segments;
        assert_eq!(segs[1].name, "__DMTmainW");
        assert_eq!(segs[0].secs.last().unwrap().name, "__dmTsdkx1");
        let mut out = MemSink::default();
        plan.write(&host, &mods, &mut out).unwrap();
        let t = &segs[0];
        let s = &t.secs[2];
        assert!(
            out.0[s.offset as usize..(s.offset as u64 + s.size) as usize]
                .iter()
                .all(|&b| b == 0)
        );
    }

    /// the blob's `seg_count` is the file's word: a count the blob cannot hold is an error that says so, not a 16 GiB reservation (review finding 4.1)
    #[test]
    fn a_fixups_blob_that_counts_more_segments_than_it_holds_is_an_error() {
        let mods = pieces3();
        let host = synthetic_host(0x200);
        let (_, lcs, _) =
            parse(&host[..32 + u32::from_le_bytes(host[20..24].try_into().unwrap()) as usize])
                .unwrap();
        let cf_lc = lcs
            .iter()
            .find(|l| l.cmd == LC_DYLD_CHAINED_FIXUPS)
            .unwrap();
        let cf_off =
            u32::from_le_bytes(host[cf_lc.off + 8..cf_lc.off + 12].try_into().unwrap()) as usize;
        let starts_off =
            u32::from_le_bytes(host[cf_off + 4..cf_off + 8].try_into().unwrap()) as usize;
        for count in [u32::MAX, 0x4000_0000, 0x1000] {
            let mut bad = host.clone();
            bad[cf_off + starts_off..cf_off + starts_off + 4].copy_from_slice(&count.to_le_bytes());
            let e = Plan::new(&bad, &mods, "")
                .err()
                .unwrap_or_else(|| panic!("count {count:#x} must be refused"));
            assert!(e.to_string().contains("chained-fixups blob counts"), "{e}");
        }
        // the honest blob is unchanged
        assert!(Plan::new(&host, &mods, "").is_ok());
        // and the reader on its own
        assert!(super::read_old_starts(&[0u8; 4]).is_err());
    }

    #[test]
    fn failure_modes_are_errors_not_panics() {
        let mods = pieces3();
        // not a Mach-O
        assert!(Plan::new(&vec![0u8; 64], &mods, "").is_err());
        // a section name longer than 16 bytes (`__dm` + 10-char module + `x0` = 16 is ok, 11 is not)
        let host = synthetic_host(0x200);
        let long = vec![ModulePieces {
            name: "abcdefghijk".into(),
            x0: Piece::zeros(PG),
            w: Piece::zeros(PG),
            x1: Piece::zeros(PG),
        }];
        assert!(Plan::new(&host, &long, "").is_err());
        let ok10 = vec![ModulePieces {
            name: "abcdefghij".into(),
            x0: Piece::zeros(PG),
            w: Piece::zeros(PG),
            x1: Piece::zeros(PG),
        }];
        assert!(Plan::new(&host, &ok10, "").is_ok());
        // header slack: add enough segments that the load commands no longer fit before __text (0x4000)
        let many: Vec<ModulePieces> = (0..60)
            .map(|i| ModulePieces {
                name: format!("m{i}"),
                x0: Piece::zeros(PG),
                w: Piece::zeros(PG),
                x1: Piece::zeros(PG),
            })
            .collect();
        let e = Plan::new(&host, &many, "").err().expect("must not fit");
        assert!(e.to_string().contains("header slack too small"), "{e}");
        // a host whose writable segments are not high is refused
        let mut low = host.clone();
        // __DATA_CONST vmaddr lives in the 2nd segment command: after header(32) + __TEXT cmd (72+2*80)
        let dc_cmd = 32 + 72 + 2 * 80;
        low[dc_cmd + 24..dc_cmd + 32].copy_from_slice(&0x9000u64.to_le_bytes());
        let e = Plan::new(&low, &mods, "").err().expect("low segment");
        assert!(e.to_string().contains("place __DATA_CONST high"), "{e}");
    }

    #[test]
    fn write_is_idempotent_and_deterministic() {
        let host = synthetic_host(0x200);
        let mods = pieces3();
        let plan = Plan::new(&host, &mods, "").unwrap();
        let mut a = MemSink::default();
        let mut b = MemSink::default();
        plan.write(&host, &mods, &mut a).unwrap();
        plan.write(&host, &mods, &mut b).unwrap();
        assert_eq!(a.0, b.0);
    }
}
