//! Where an NSO's text holds code: function ranges from `.eh_frame`, data blocks in the text that no function covers
//! (`nso_code.py`), the module's defined dynamic symbols (`nso_syms.defined`) and its relative relocations
//! (`loader_census.got_values`). All of them read the module image only.

use ibuilder_a64::bits::rd32;
use std::collections::BTreeMap;

pub const DATA_MIN: i64 = 0x1000;

// Every offset below comes from the module itself (MOD0 -> eh_frame_hdr -> FDE table -> CIE -> dynamic table -> symbols and relocations). A damaged or crafted module must come back as an `Err`
// (or an empty answer where the Python's reader is lenient), never a panic or an allocation that aborts: `ibuilder-nso` promises "a damaged file is an error, never a wrong image", and a release
// build is `panic = "abort"`. So: no `img[..]`, no unchecked `+`/`*` on a value read from the image, no `with_capacity` of one. For every well-formed module the answers are exactly those of before.

fn short() -> String {
    "short read".to_string()
}
/// `img[o..o + n]`, or "short read" when it is not all inside the image (an `o` that wrapped from a negative offset included)
fn bytes_at(img: &[u8], o: usize, n: usize) -> Result<&[u8], String> {
    img.get(o..o.checked_add(n).ok_or_else(short)?)
        .ok_or_else(short)
}
fn i32_at(img: &[u8], o: usize) -> Result<i64, String> {
    bytes_at(img, o, 4).map(|b| i32::from_le_bytes(b.try_into().unwrap()) as i64)
}
fn u32_at(img: &[u8], o: usize) -> Result<i64, String> {
    bytes_at(img, o, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as i64)
}
fn u64_at(img: &[u8], o: usize) -> Result<i64, String> {
    bytes_at(img, o, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()) as i64)
}
fn i64_at(img: &[u8], o: usize) -> Result<i64, String> {
    u64_at(img, o)
}
fn u8_at(img: &[u8], o: usize) -> Result<u8, String> {
    img.get(o).copied().ok_or_else(short)
}
/// `base + k * size` as an offset into the image
fn nth(base: usize, k: usize, size: usize) -> Result<usize, String> {
    k.checked_mul(size)
        .and_then(|d| base.checked_add(d))
        .ok_or_else(short)
}
/// an offset from the file (signed, or an unsigned that does not fit) as a `usize`; a negative one is outside the image
fn pos(v: i64) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| short())
}

/// (eh_frame_hdr offset, its end) from the MOD0 header
pub fn eh_frame_hdr(img: &[u8]) -> Result<(i64, i64), String> {
    let m0 = pos(u32_at(img, 4)?)?;
    if img.get(m0..m0.saturating_add(4)) != Some(b"MOD0") {
        return Err("no MOD0".into());
    }
    Ok((
        m0 as i64 + i32_at(img, m0 + 16)?,
        m0 as i64 + i32_at(img, m0 + 20)?,
    ))
}

/// `nso_code._read`: a value in pointer encoding `enc` at `o`, and its size
fn read_enc(img: &[u8], o: i64, enc: u8, ehs: i64) -> Result<(i64, i64), String> {
    let (fmt, app) = (enc & 0xF, enc & 0x70);
    let ou = pos(o)?;
    let (mut v, sz) = match fmt {
        0x1 => {
            // uleb128 (the shipped engine reads it: the call-site tables of an LSDA use it)
            let (v, end) = uleb(img, ou)?;
            (v as i64, (end - ou) as i64)
        }
        0x3 => (u32_at(img, ou)?, 4),
        0xB => (i32_at(img, ou)?, 4),
        0x0 | 0x4 => (u64_at(img, ou)?, 8),
        0xC => (i64_at(img, ou)?, 8),
        _ => return Err(format!("pointer encoding {enc:#x} at {o:#x}")),
    };
    if app == 0x10 {
        v = v.checked_add(o).ok_or_else(short)?;
    } else if app == 0x30 {
        v = v.checked_add(ehs).ok_or_else(short)?;
    }
    Ok((v, sz))
}

fn uleb(img: &[u8], mut o: usize) -> Result<(u64, usize), String> {
    let (mut r, mut sh) = (0u64, 0u32);
    loop {
        let b = u8_at(img, o)?;
        o += 1;
        if sh < 64 {
            r |= ((b & 0x7F) as u64) << sh;
        }
        sh = sh.saturating_add(7);
        if b & 0x80 == 0 {
            return Ok((r, o));
        }
    }
}

/// [(function start, FDE offset)] from the eh_frame_hdr binary search table; empty when the module has no valid
/// eh_frame_hdr
pub fn fde_table(img: &[u8]) -> Result<Vec<(i64, i64)>, String> {
    let (ehs, ehe) = eh_frame_hdr(img)?;
    if ehe - ehs < 12 {
        return Ok(vec![]);
    }
    let hdr = bytes_at(img, pos(ehs)?, 4)?;
    if hdr[0] != 1 || hdr[3] == 0xFF || hdr[3] == 0 {
        return Ok(vec![]);
    }
    let (penc, cenc, tenc) = (hdr[1], hdr[2], hdr[3]);
    let mut o = ehs + 4;
    let (_, s) = read_enc(img, o, penc, ehs)?;
    o += s;
    let (n, s) = read_enc(img, o, cenc, ehs)?;
    o += s;
    // an entry is two encoded values of at least 4 bytes each: a count the rest of the image cannot hold is a damaged table (and never a reservation of that many entries)
    let room = img.len().saturating_sub(pos(o)?) / 8;
    if n > 0 && n as u64 > room as u64 {
        return Err(format!(
            "the FDE table claims {n} entries, more than the {room} the image holds after {o:#x}"
        ));
    }
    let mut out = Vec::with_capacity(n.max(0) as usize);
    for _ in 0..n {
        let (a, s) = read_enc(img, o, tenc, ehs)?;
        o += s;
        let (f, s) = read_enc(img, o, tenc, ehs)?;
        o += s;
        out.push((a, f));
    }
    Ok(out)
}

/// Sorted [(start, end)] of every function the FDEs describe (pc begin and pc range, in the encoding the FDE's CIE gives)
pub fn fde_ranges(img: &[u8]) -> Result<Vec<(i64, i64)>, String> {
    let (ehs, _) = eh_frame_hdr(img)?;
    let mut cies: BTreeMap<i64, u8> = BTreeMap::new();
    let mut cie_encoding = |cie: i64| -> Result<u8, String> {
        if let Some(e) = cies.get(&cie) {
            return Ok(*e);
        }
        let mut p = pos(cie)?.checked_add(8).ok_or_else(short)?;
        let ver = u8_at(img, p)?;
        p += 1;
        let z = img
            .get(p..)
            .ok_or_else(short)?
            .iter()
            .position(|&c| c == 0)
            .ok_or("no NUL in augmentation")?;
        let aug = &img[p..p + z];
        p += aug.len() + 1;
        p = uleb(img, p)?.1; // code alignment
        while u8_at(img, p)? & 0x80 != 0 {
            p += 1; // data alignment (sleb)
        }
        p += 1;
        p = if ver == 1 { p + 1 } else { uleb(img, p)?.1 }; // return address register
        let mut enc = 0u8;
        if aug.first() == Some(&b'z') {
            p = uleb(img, p)?.1;
            for &ch in &aug[1..] {
                match ch {
                    b'R' => {
                        enc = u8_at(img, p)?;
                        p += 1;
                    }
                    b'P' => {
                        let pe = u8_at(img, p)?;
                        p += 1;
                        p += read_enc(img, p as i64, pe, ehs)?.1 as usize;
                    }
                    b'L' => p += 1,
                    _ => {}
                }
            }
        }
        cies.insert(cie, enc);
        Ok(enc)
    };
    let mut out = Vec::new();
    for (_, f) in fde_table(img)? {
        let cptr = f.checked_add(4).ok_or_else(short)?;
        let enc = cie_encoding(cptr - u32_at(img, pos(cptr)?)?)?;
        let (st, s) = read_enc(img, f + 8, enc, ehs)?;
        let (ln, _) = read_enc(img, f + 8 + s, enc & 0xF, ehs)?;
        out.push((st, st.saturating_add(ln)));
    }
    out.sort();
    Ok(out)
}

/// {landing pad: [(start, end) of the calls it catches]}
/// as (pad, (call start, call end)) rows sorted by pad, a pad's ranges in the order the tables list them (the Python's
/// dict of lists, flat: 24 bytes a row)
pub type LandingPads = Vec<(i64, (i64, i64))>;
/// (FDE pointer encoding, LSDA encoding, augmented with a personality) of a CIE
type CieInfo = (u8, Option<u8>, bool);
/// (landing pad, (call start, call end)) of one LSDA
type PadRows = Vec<(i64, (i64, i64))>;

/// `nso_code.landing_pads`: {landing pad: [(start, end) of the calls it catches]} from every FDE's LSDA (C++
/// exceptions), the pads in address order and each pad's ranges in the order the tables list them. Only a CIE with a
/// personality routine ('P') has such an LSDA; a table this reader does not know (or whose records leave its function)
/// is skipped, as the Python skips it (`ValueError`, `IndexError`, `struct.error`). An unreadable MOD0 / FDE table is an
/// error, as in the Python (raised outside its `try`).
pub fn landing_pads(img: &[u8]) -> Result<LandingPads, String> {
    let (ehs, _) = eh_frame_hdr(img)?;
    // (FDE pointer encoding, LSDA encoding, augmented with a personality)
    let mut cies: BTreeMap<i64, CieInfo> = BTreeMap::new();
    let cie = |cies: &mut BTreeMap<i64, CieInfo>, c: i64| -> Result<CieInfo, String> {
        if let Some(e) = cies.get(&c) {
            return Ok(*e);
        }
        let mut p = pos(c)?.checked_add(8).ok_or_else(short)?;
        let ver = u8_at(img, p)?;
        p += 1;
        let z = img
            .get(p..)
            .ok_or_else(short)?
            .iter()
            .position(|&c| c == 0)
            .ok_or("no NUL in augmentation")?;
        let aug = &img[p..p + z];
        p += aug.len() + 1;
        p = uleb(img, p)?.1;
        while u8_at(img, p)? & 0x80 != 0 {
            p += 1;
        }
        p += 1;
        p = if ver == 1 { p + 1 } else { uleb(img, p)?.1 };
        let (mut enc, mut lenc) = (0u8, None);
        if aug.first() == Some(&b'z') {
            p = uleb(img, p)?.1;
            for &ch in &aug[1..] {
                match ch {
                    b'R' => {
                        enc = u8_at(img, p)?;
                        p += 1;
                    }
                    b'P' => {
                        let pe = u8_at(img, p)?;
                        p += 1;
                        p = p
                            .checked_add(read_enc(img, p as i64, pe, ehs)?.1 as usize)
                            .ok_or_else(short)?;
                    }
                    b'L' => {
                        lenc = Some(u8_at(img, p)?);
                        p += 1;
                    }
                    _ => {}
                }
            }
        }
        let e = (enc, lenc, aug.first() == Some(&b'z') && aug.contains(&b'P'));
        cies.insert(c, e);
        Ok(e)
    };
    let add = |a: i64, b: i64| a.checked_add(b).ok_or_else(short);
    let mut out: LandingPads = Vec::new();
    for (_, f) in fde_table(img)? {
        let one = |cies: &mut BTreeMap<i64, CieInfo>| -> Result<PadRows, String> {
            let cptr = add(f, 4)?;
            let (enc, lenc, z) = cie(cies, cptr - u32_at(img, pos(cptr)?)?)?;
            let Some(lenc) = lenc else { return Ok(vec![]) };
            if lenc == 0xFF || !z {
                return Ok(vec![]);
            }
            let (st, s) = read_enc(img, add(f, 8)?, enc, ehs)?;
            let mut p = add(add(f, 8)?, s)?;
            let (ln, s) = read_enc(img, p, enc & 0xF, ehs)?;
            p = add(p, s)?;
            p = uleb(img, pos(p)?)?.1 as i64; // augmentation length
            let (lsda, _) = read_enc(img, p, lenc, ehs)?;
            if lsda == 0 {
                return Ok(vec![]);
            }
            let mut p = lsda;
            let lpe = u8_at(img, pos(p)?)?;
            p = add(p, 1)?;
            let mut lpstart = st;
            if lpe != 0xFF {
                let (v, s) = read_enc(img, p, lpe, ehs)?;
                lpstart = v;
                p = add(p, s)?;
            }
            let tte = u8_at(img, pos(p)?)?;
            p = add(p, 1)?;
            if tte != 0xFF {
                p = uleb(img, pos(p)?)?.1 as i64;
            }
            let cse = u8_at(img, pos(p)?)?;
            p = add(p, 1)?;
            let (n, q) = uleb(img, pos(p)?)?;
            p = q as i64;
            let end = add(p, i64::try_from(n).map_err(|_| short())?)?;
            let mut got = Vec::new();
            while p < end {
                let (cs, s) = read_enc(img, p, cse & 0xF, ehs)?;
                p = add(p, s)?;
                let (cl, s) = read_enc(img, p, cse & 0xF, ehs)?;
                p = add(p, s)?;
                let (lp, s) = read_enc(img, p, cse & 0xF, ehs)?;
                p = add(p, s)?;
                p = uleb(img, pos(p)?)?.1 as i64; // action
                let lpa = add(lpstart, lp)?;
                if add(cs, cl)? > ln || (lp != 0 && !(st <= lpa && lpa < add(st, ln)?)) {
                    return Err("a call site outside its function".into());
                }
                if lp != 0 {
                    got.push((lpa, (add(st, cs)?, add(add(st, cs)?, cl)?)));
                }
            }
            Ok(got)
        };
        // a table this reader does not know: its pads stay unseen, as without exception tables
        if let Ok(got) = one(&mut cies) {
            out.extend(got);
        }
    }
    out.sort_by_key(|r| r.0); // stable: a pad's ranges keep their order
    Ok(out)
}

/// Sorted [(start, end)] of the data blocks in text [0, text_end): a stretch of at least DATA_MIN bytes between FDE
/// ranges in which more than a quarter of the words do not decode as instructions.
pub fn data_blocks(img: &[u8], text_end: i64) -> Result<Vec<(i64, i64)>, String> {
    if text_end < 0 || text_end as u64 > img.len() as u64 {
        return Err(format!(
            "the text ends at {text_end:#x}, past the module's image of {:#x} bytes",
            img.len()
        ));
    }
    // An NRO's text includes its header: keep the entry branch and MOD0 pointer (+0..+8), never scan +8..+0x80
    let nro = img.get(0x10..0x14) == Some(b"NRO0");
    let mut gaps = Vec::new();
    let mut last: i64 = if nro { 0x80 } else { 0 };
    for (s, e) in fde_ranges(img)? {
        if s >= text_end {
            break;
        }
        if s > last {
            gaps.push((last, s));
        }
        last = last.max(e);
    }
    if last < text_end {
        gaps.push((last, text_end));
    }
    let mut out = if nro { vec![(8, 0x80)] } else { vec![] };
    for (s, e) in gaps {
        let (s, e) = ((s + 3) & !3, e & !3);
        if e - s < DATA_MIN {
            continue;
        }
        let undecodable = (s..e)
            .step_by(4)
            .filter(|&a| !ibuilder_a64::cs::decodes(rd32(img, a as usize), a))
            .count() as i64;
        if undecodable * 4 > (e - s) / 4 {
            out.push((s, e));
        }
    }
    Ok(out)
}

/// The dynamic table tags of the module (`DT_*` -> value), first occurrence wins; `Err` when not readable
fn dyn_tags(img: &[u8]) -> Result<BTreeMap<i64, u64>, String> {
    let mod0 = pos(u32_at(img, 4)?)?;
    if img.get(mod0..mod0.saturating_add(4)) != Some(b"MOD0") {
        return Err("no MOD0".into());
    }
    let dynp = pos(mod0 as i64 + i32_at(img, mod0 + 4)?)?;
    let mut tags = BTreeMap::new();
    for i in 0..4096usize {
        let t = i64_at(img, nth(dynp, i, 16)?)?;
        let v = u64_at(img, nth(dynp, i, 16)?.checked_add(8).ok_or_else(short)?)? as u64;
        if t == 0 {
            break;
        }
        tags.entry(t).or_insert(v);
    }
    Ok(tags)
}

/// `nso_syms.defined`: {name: (offset, size)} of the module's defined dynamic symbols; empty without a symbol table
/// it can read.
pub fn defined(img: &[u8]) -> BTreeMap<String, (i64, i64)> {
    fn inner(img: &[u8]) -> Result<BTreeMap<String, (i64, i64)>, String> {
        let mod0 = pos(u32_at(img, 4)?)?;
        if img.get(mod0..mod0.saturating_add(4)) != Some(b"MOD0") {
            return Ok(BTreeMap::new());
        }
        let tags = dyn_tags(img)?;
        let symtab = usize::try_from(*tags.get(&6).ok_or("KeyError")?).map_err(|_| short())?;
        let strtab = usize::try_from(*tags.get(&5).ok_or("KeyError")?).map_err(|_| short())?;
        // no DT_HASH: the symbols run up to the string table; a string table below the symbols is no symbols (Python's negative `range`)
        let n = if let Some(h) = tags.get(&4) {
            u32_at(
                img,
                usize::try_from(*h)
                    .map_err(|_| short())?
                    .checked_add(4)
                    .ok_or_else(short)?,
            )? as usize
        } else {
            strtab.saturating_sub(symtab) / 24
        };
        let mut out = BTreeMap::new();
        for i in 1..n {
            let b = nth(symtab, i, 24)?;
            let name = u32_at(img, b)? as usize;
            let shndx = u16::from_le_bytes(
                bytes_at(img, b.checked_add(6).ok_or_else(short)?, 2)?
                    .try_into()
                    .unwrap(),
            );
            let value = u64_at(img, b.checked_add(8).ok_or_else(short)?)?;
            let size = u64_at(img, b.checked_add(16).ok_or_else(short)?)?;
            if shndx != 0 {
                let s = strtab.checked_add(name).ok_or_else(short)?;
                let tail = img.get(s..).ok_or_else(short)?;
                let e = tail.iter().position(|&c| c == 0).ok_or("no NUL")?;
                let nm: String = tail[..e].iter().map(|&c| c as char).collect(); // decode('latin1')
                out.insert(nm, (value, size));
            }
        }
        Ok(out)
    }
    inner(img).unwrap_or_default()
}

/// A Python `dict` of address -> value: insertion order is iteration order, a repeated key keeps its place.
#[derive(Default, Clone, Debug)]
pub struct Rel {
    order: Vec<(i64, i64)>,
    idx: std::collections::HashMap<i64, usize>,
}
impl Rel {
    pub fn insert(&mut self, k: i64, v: i64) {
        match self.idx.get(&k) {
            Some(&i) => self.order[i].1 = v,
            None => {
                self.idx.insert(k, self.order.len());
                self.order.push((k, v));
            }
        }
    }
    pub fn get(&self, k: i64) -> Option<i64> {
        self.idx.get(&k).map(|&i| self.order[i].1)
    }
    pub fn iter(&self) -> impl Iterator<Item = (i64, i64)> + '_ {
        self.order.iter().copied()
    }
    pub fn len(&self) -> usize {
        self.order.len()
    }
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// `loader_census.got_values`: {address: the address it holds once relocated} for the image's relative relocations
/// (RELA R_AARCH64_RELATIVE, and RELR, whose addend is in place). Never panics: on a module whose dynamic table or relocations run off the image
/// it returns what it had read until then (the Python's reader raises there; [`try_got_values`] is the one that says so). The detectors that can say why use `try_got_values`.
pub fn got_values(img: &[u8]) -> Rel {
    let mut out = Rel::default();
    let _ = collect_got(img, &mut out);
    out
}

/// [`got_values`], but a module whose relocation tables cannot be read is an `Err` (what the Python's reader raises there), with no partial answer.
pub fn try_got_values(img: &[u8]) -> Result<Rel, String> {
    let mut out = Rel::default();
    collect_got(img, &mut out).map(|()| out)
}

fn collect_got(img: &[u8], out: &mut Rel) -> Result<(), String> {
    let mod0 = pos(u32_at(img, 4)?)?;
    if img.get(mod0..mod0.saturating_add(4)) != Some(b"MOD0") {
        return Ok(());
    }
    let dynp = pos(mod0 as i64 + i32_at(img, mod0 + 4)?)?;
    let mut tags: BTreeMap<i64, u64> = BTreeMap::new();
    for k in 0..4096usize {
        let at = nth(dynp, k, 16)?;
        let (t, v) = (
            i64_at(img, at)?,
            u64_at(img, at.checked_add(8).ok_or_else(short)?)? as u64,
        );
        if t == 0 {
            break;
        }
        tags.entry(t).or_insert(v);
    }
    let tag = |t: i64, what: &str| -> Result<usize, String> {
        usize::try_from(
            *tags
                .get(&t)
                .ok_or_else(|| format!("{what} is not in the dynamic table"))?,
        )
        .map_err(|_| short())
    };
    // DT_RELA / DT_RELASZ: RELATIVE, and ABS64 / GLOB_DAT of a symbol the module defines
    for k in 0..(*tags.get(&8).unwrap_or(&0) / 24) as usize {
        let base = nth(tag(7, "DT_RELA")?, k, 24)?;
        let off = u64_at(img, base)?;
        let info = u64_at(img, base.checked_add(8).ok_or_else(short)?)?;
        let add = u64_at(img, base.checked_add(16).ok_or_else(short)?)?;
        let ty = info & 0xffff_ffff;
        if ty == 1027 {
            out.insert(off, add);
        } else if (ty == 257 || ty == 1025) && tags.contains_key(&6) {
            let s = nth(tag(6, "DT_SYMTAB")?, (info as u64 >> 32) as usize, 24)?
                .checked_add(6)
                .ok_or_else(short)?;
            let shndx = u16::from_le_bytes(bytes_at(img, s, 2)?.try_into().unwrap());
            let value = u64_at(img, s.checked_add(2).ok_or_else(short)?)?;
            if shndx != 0 {
                out.insert(off, value.wrapping_add(add));
            }
        }
    }
    // DT_RELR / DT_RELRSZ
    let mut wh: i64 = 0;
    for k in 0..(*tags.get(&35).unwrap_or(&0) / 8) as usize {
        let e = u64_at(img, nth(tag(36, "DT_RELR")?, k, 8)?)? as u64;
        if e & 1 == 0 {
            wh = e as i64;
            out.insert(wh, u64_at(img, pos(wh)?)?);
            wh = wh.checked_add(8).ok_or_else(short)?;
        } else {
            for b in 0..63 {
                if e >> (b + 1) & 1 != 0 {
                    let a = wh.checked_add(b as i64 * 8).ok_or_else(short)?;
                    out.insert(a, u64_at(img, pos(a)?)?);
                }
            }
            wh = wh.checked_add(63 * 8).ok_or_else(short)?;
        }
    }
    Ok(())
}

/// `nso_code.out_store`: (offset, register) of the one store through a function's second argument, an out pointer
/// (x1, copied once in the prologue: `mov xB, x1 ... str xA, [xB]`). Err when that shape is not there.
pub fn out_store(img: &[u8], start: i64, size: i64) -> Result<(i64, u32), String> {
    use ibuilder_a64::cs;
    // `img[start:start + size]` of the Python clamps and finds no prologue in what is not there; here a function outside the image is an Err all the same
    let end = start
        .checked_add(size)
        .ok_or("the function's range overflows")?;
    let code = img
        .get(pos(start)?..pos(end)?)
        .ok_or_else(|| format!("the function at {start:#x}+{size:#x} is not inside the image"))?;
    let ins = cs::disasm(code, start);
    let mut out = Vec::new();
    for i in ins.iter().take(16) {
        if i.mn() == "mov" {
            let op = i.op_str.as_ref();
            // x\d+, x1
            if let Some(d) = op.strip_suffix(", x1")
                && d.len() > 1
                && d.starts_with('x')
                && d[1..].bytes().all(|c| c.is_ascii_digit())
            {
                out.push(i);
            }
        }
    }
    if out.len() != 1 {
        return Err("no single copy of the out pointer in the prologue".into());
    }
    let xb = out[0].op_str.split(',').next().unwrap().to_string();
    let st: Vec<_> = ins
        .iter()
        .filter(|i| {
            i.mn() == "str" && {
                let op: &str = &i.op_str;
                op.strip_suffix(&format!(", [{xb}]")).is_some_and(|d| {
                    d.len() > 1 && d.starts_with('x') && d[1..].bytes().all(|c| c.is_ascii_digit())
                })
            }
        })
        .collect();
    if st.len() != 1 {
        return Err(format!("{} stores through the out pointer", st.len()));
    }
    let reg: u32 = st[0].op_str.split(',').next().unwrap_or("")[1..]
        .parse()
        .map_err(|_| format!("the store at {:#x} has no register number", st[0].address))?;
    Ok((st[0].address, reg))
}
