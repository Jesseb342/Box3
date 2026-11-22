//! The engine's section layout: where a rewritten module's `*.patched.bin` is cut into the pieces the
//! loader `vm_remap`s (`__TEXT,__dm<name>x0`, `__DM<name>W,__img`, `__TEXT,__dm<name>x1`[, `x2`]).
//!
//! Port of `engine/dm/ios/tools/gen_embed.py` (`pieces`, `place`, the assembly generator) and of its
//! verbatim transcription in `tools/assemble.py` (`pieces`). The two differ in the asserts they make
//! (gen_embed.py is stricter, see [`Mode`]); the ranges they return are the same.

use crate::error::{Error, Result};
use crate::macho::{PG, align};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Which Python tool's input checks to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `tools/assemble.py pieces`
    Assemble,
    /// `dm/ios/tools/gen_embed.py pieces`: additionally `KEY_PAGE_OFF % 16K == 0` (patch area after the
    /// base) and `file size % 16K == 0` when there is a back patch area.
    GenEmbed,
}

/// The `# KEY<TAB>VALUE` header of a `<module>.fixups.tsv`.
///
/// Python reads it as `dict(l[2:].split() for l in open(path))`: *every* line drops its first two characters
/// and must then hold exactly two whitespace-separated tokens (else `ValueError`); a later key wins.
#[derive(Clone, Debug, Default)]
pub struct FixupsHeader {
    map: HashMap<String, String>,
}

impl FixupsHeader {
    pub fn parse(text: &str) -> Result<Self> {
        let mut map = HashMap::new();
        for (i, line) in text.lines().enumerate() {
            let rest: String = line.chars().skip(2).collect();
            let toks: Vec<&str> = rest.split_whitespace().collect();
            if toks.len() != 2 {
                return Err(Error::invalid(format!(
                    "fixups header line {}: dictionary update sequence element has length {}; 2 is required",
                    i + 1,
                    toks.len()
                )));
            }
            map.insert(toks[0].to_string(), toks[1].to_string());
        }
        Ok(FixupsHeader { map })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).map_err(|e| Error::io(path.display().to_string(), e))?;
        Self::parse(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    /// `int(hdr[key], 16)`; a missing key is Python's `KeyError`.
    pub fn hex(&self, key: &str) -> Result<i128> {
        let v = self
            .get(key)
            .ok_or_else(|| Error::invalid(format!("fixups header has no {key}")))?;
        parse_hex(v).ok_or_else(|| {
            Error::invalid(format!(
                "fixups header {key}: invalid literal for int() with base 16: {v:?}"
            ))
        })
    }

    /// `int(hdr.get(key, default), 16)`.
    pub fn hex_or(&self, key: &str, default: &str) -> Result<i128> {
        let v = self.get(key).unwrap_or(default);
        parse_hex(v).ok_or_else(|| {
            Error::invalid(format!(
                "fixups header {key}: invalid literal for int() with base 16: {v:?}"
            ))
        })
    }
}

/// Python `int(s, 16)`: optional sign, optional `0x`/`0X`, hex digits (single `_` between digits allowed).
pub fn parse_hex(s: &str) -> Option<i128> {
    let t = s.trim();
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return None;
    }
    let mut v: i128 = 0;
    for c in t.chars().filter(|&c| c != '_') {
        let d = c.to_digit(16)? as i128;
        v = v.checked_mul(16).and_then(|v| v.checked_add(d))?;
    }
    Some(if neg { -v } else { v })
}

/// Python `f"{v:#x}"` (signed values print as `-0x..`, not as two's complement).
pub fn hex_py(v: i128) -> String {
    if v < 0 {
        format!("-{:#x}", -v)
    } else {
        format!("{v:#x}")
    }
}

/// The module's `(x0, W, x1[, x2])` file ranges as `(start, end)`, exactly as `pieces()` computes them.
/// `sz` is the size of `<name>.patched.bin`.
pub fn piece_ranges(hdr: &FixupsHeader, sz: u64, mode: Mode) -> Result<Vec<(u64, u64)>> {
    let te = hdr.hex("TEXT_END")?;
    let po = hdr.hex("PATCH_OFF")?;
    let ko = hdr.hex("KEY_PAGE_OFF")?;
    let ks = hdr.hex("KEY_PAGE_SIZE")?;
    let pg = PG as i128;
    let te_u = u64::try_from(te).map_err(|_| Error::invalid("TEXT_END is negative"))?;
    let a = align(te_u, PG) as i128;
    let end = align(sz, PG) as i128;
    let ok = |c: bool, what: &str| -> Result<()> {
        if c {
            Ok(())
        } else {
            Err(Error::invalid(format!("layout assertion failed: {what}")))
        }
    };
    let to_u64 = |v: i128| -> Result<u64> {
        u64::try_from(v).map_err(|_| Error::invalid(format!("piece offset {v} out of range")))
    };
    if po < 0 {
        // patch area before the base (patch_nso.py FAR)
        let fl = hdr.hex("FILE_IMAGE_LEN")?;
        let bl = hdr.hex_or("BACK_LEN", "0")?;
        ok(
            fl.rem_euclid(pg) == 0
                && a <= fl
                && ko.rem_euclid(pg) == 0
                && ks == pg
                && ko >= fl
                && bl.rem_euclid(pg) == 0,
            "fl % PG == 0 and a <= fl and ko % PG == 0 and ks == PG and ko >= fl and bl % PG == 0",
        )?;
        if mode == Mode::GenEmbed {
            ok(
                bl == 0 || (sz as i128).rem_euclid(pg) == 0,
                "not bl or sz % PG == 0",
            )?;
        }
        ok(bl >= 0, "BACK_LEN is negative")?;
        let mut v = vec![
            (0, to_u64(a)?),
            (to_u64(a)?, to_u64(fl)?),
            (to_u64(fl)?, to_u64(end - bl)?),
        ];
        if bl != 0 {
            v.push((to_u64(end - bl)?, to_u64(end)?));
        }
        Ok(v)
    } else {
        ok(
            po.rem_euclid(pg) == 0 && a <= ko && ko + ks <= po && ks == pg,
            "po % PG == 0 and a <= ko and ko + ks <= po and ks == PG",
        )?;
        if mode == Mode::GenEmbed {
            ok(ko.rem_euclid(pg) == 0, "ko % PG == 0")?;
        }
        Ok(vec![
            (0, to_u64(a)?),
            (to_u64(a)?, to_u64(po)?),
            (to_u64(po)?, to_u64(end)?),
        ])
    }
}

/// `os.path.abspath` for a path that may be relative: lexical, no symlink resolution.
pub fn abspath(p: &Path) -> PathBuf {
    let base = if p.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    let joined = base.join(p);
    // POSIX: exactly two leading slashes are kept by normpath
    let two_slashes =
        joined.to_string_lossy().starts_with("//") && !joined.to_string_lossy().starts_with("///");
    let mut out = PathBuf::from(if two_slashes { "//" } else { "/" });
    for c in joined.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

/// Text that goes into the generated assembly inside a quoted string (`.ascii`, `.incbin`): no `"`, no `\`, no control character (a newline would start a new directive). A name or path
/// from `nro.tsv` or the output folder is the file system's, not ours; the `.S` goes to clang (review finding 4.8).
fn asm_string_ok(what: &str, s: &str) -> Result<()> {
    match s.chars().find(|&c| c == '"' || c == '\\' || c.is_control()) {
        Some(c) => Err(Error::invalid(format!(
            "{what} {s:?} contains {c:?}, which would break the generated assembly"
        ))),
        None => Ok(()),
    }
}

/// Text that becomes part of a section name (not quoted): the above, and no whitespace, `,` or `;`.
fn asm_name_ok(what: &str, s: &str) -> Result<()> {
    asm_string_ok(what, s)?;
    match s
        .chars()
        .find(|&c| c.is_whitespace() || c == ',' || c == ';')
    {
        Some(c) => Err(Error::invalid(format!(
            "{what} {s:?} contains {c:?}, which a section name cannot hold"
        ))),
        None => Ok(()),
    }
}

fn place(asm: &mut Vec<String>, bin: &str, sz: u64, lo: u64, hi: u64) -> Result<()> {
    asm_string_ok("the path of a module image", bin)?;
    let fill = sz.min(hi) as i128 - lo as i128;
    asm.push("    .p2align 14".into());
    asm.push(format!(
        "    .incbin \"{bin}\", {}, {}",
        hex_py(lo as i128),
        hex_py(fill)
    ));
    let span = hi as i128 - lo as i128;
    if span > fill {
        asm.push(format!("    .space {}", hex_py(span - fill)));
    }
    asm.push("    .p2align 14".into());
    Ok(())
}

/// Options of `gen_embed.py`.
#[derive(Clone, Debug, Default)]
pub struct GenEmbedOptions {
    pub tag: String,
    pub jit: Option<PathBuf>,
}

/// `gen_embed.py <dir> <out.S> <modules...>`: returns `(assembly text, link flags line)`; the Python script
/// writes the first to the output file and prints the second.
pub fn gen_embed(dir: &Path, names: &[String], opts: &GenEmbedOptions) -> Result<(String, String)> {
    struct Mod {
        bin: String,
        sz: u64,
        parts: Vec<(u64, u64)>,
    }
    let tag = &opts.tag;
    asm_name_ok("the tag", tag)?;
    let load = |n: &str| -> Result<Mod> {
        asm_string_ok("the module name", n)?;
        let hdr = FixupsHeader::read(&dir.join(format!("{n}.fixups.tsv")))?;
        let bin_path = abspath(&dir.join(format!("{n}.patched.bin")));
        let sz = fs::metadata(&bin_path)
            .map_err(|e| Error::io(bin_path.display().to_string(), e))?
            .len();
        let parts = piece_ranges(&hdr, sz, Mode::GenEmbed)?;
        Ok(Mod {
            bin: bin_path.to_string_lossy().into_owned(),
            sz,
            parts,
        })
    };
    let mut asm: Vec<String> =
        vec!["// Generated by dm/ios/tools/gen_embed.py; do not edit".into()];
    let mut flags: Vec<String> = Vec::new();
    for n in names {
        let m = load(n)?;
        asm_name_ok("the module name", n)?; // it becomes part of four section names
        let sects = [
            format!("__TEXT,__dm{tag}{n}x0"),
            format!("__DM{tag}{n}W,__img"),
            format!("__TEXT,__dm{tag}{n}x1"),
            format!("__TEXT,__dm{tag}{n}x2"),
        ];
        for (sect, &(lo, hi)) in sects.iter().zip(m.parts.iter()) {
            if sect.split(',').any(|x| x.chars().count() > 16) {
                return Err(Error::invalid(format!("section name too long: {sect}")));
            }
            asm.push(format!("    .section {sect}"));
            place(&mut asm, &m.bin, m.sz, lo, hi)?;
        }
        flags.push(format!("-Wl,-segprot,__DM{tag}{n}W,rw,rw"));
    }
    let tab = dir.join("nro.tsv");
    let nros: Vec<String> = if tab.exists() {
        let text = fs::read_to_string(&tab).map_err(|e| Error::io(tab.display().to_string(), e))?;
        text.lines()
            .filter(|ln| {
                !ln.trim().is_empty() && !ln.starts_with('#') && !ln.starts_with("refused\t")
            })
            .map(|ln| ln.split('\t').next().unwrap_or("").to_string())
            .collect()
    } else {
        Vec::new()
    };
    if !nros.is_empty() {
        let mut at = [0u64; 3];
        let mut rows: Vec<(String, Vec<u64>)> = Vec::new();
        let sects = [
            format!("__TEXT,__dm{tag}_nro_x0"),
            format!("__DM{tag}_NRO_W,__img"),
            format!("__TEXT,__dm{tag}_nro_x1"),
        ];
        for (i, sect) in sects.iter().enumerate() {
            asm.push(format!("    .section {sect}"));
            for (k, n) in nros.iter().enumerate() {
                let m = load(n)?;
                let (lo, hi) = *m
                    .parts
                    .get(i)
                    .ok_or_else(|| Error::invalid("NRO piece index"))?;
                if m.parts.len() != 3 {
                    return Err(Error::invalid(format!(
                        "NRO {n} has a back patch area, which the packed NRO sections do not hold"
                    )));
                }
                if i == 0 {
                    rows.push((n.clone(), Vec::new()));
                }
                rows[k].1.push(at[i]);
                rows[k].1.push(hi - lo);
                at[i] += hi - lo;
                place(&mut asm, &m.bin, m.sz, lo, hi)?;
            }
        }
        asm.push(format!("    .section __DATA,__dm{tag}_nro_tab"));
        asm.push("    .p2align 3".into());
        for (name, vals) in &rows {
            let len = name.chars().count();
            if len >= 32 {
                return Err(Error::invalid(format!(
                    "NRO name {name} is 32 characters or longer"
                )));
            }
            asm_string_ok("the NRO name", name)?;
            asm.push(format!("    .ascii \"{name}\""));
            asm.push(format!("    .space {}", 32 - len));
            let q: Vec<String> = vals.iter().map(|&v| hex_py(v as i128)).collect();
            asm.push(format!("    .quad {}", q.join(", ")));
        }
        flags.push(format!("-Wl,-segprot,__DM{tag}_NRO_W,rw,rw"));
    }
    if let Some(jit) = &opts.jit {
        let jit = abspath(jit);
        let sz = fs::metadata(&jit)
            .map_err(|e| Error::io(jit.display().to_string(), e))?
            .len();
        asm.push(format!("    .section __TEXT,__dm{tag}_jit"));
        place(&mut asm, &jit.to_string_lossy(), sz, 0, align(sz, PG))?;
    }
    let mut text = asm.join("\n");
    text.push('\n');
    Ok((text, flags.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(kv: &[(&str, &str)]) -> FixupsHeader {
        let text: String = kv.iter().map(|(k, v)| format!("# {k}\t{v}\n")).collect();
        FixupsHeader::parse(&text).unwrap()
    }

    #[test]
    fn parse_hex_like_python() {
        assert_eq!(parse_hex("0x4000"), Some(0x4000));
        assert_eq!(parse_hex("-0xc60000"), Some(-0xc60000));
        assert_eq!(parse_hex("c60000"), Some(0xc60000));
        assert_eq!(parse_hex("0X1_0"), Some(0x10));
        assert!(parse_hex("").is_none());
        assert!(parse_hex("0x").is_none());
        assert!(parse_hex("12g").is_none());
        assert!(parse_hex("1__0").is_none());
    }

    #[test]
    fn hex_py_formats_signed_like_python() {
        assert_eq!(hex_py(0), "0x0");
        assert_eq!(hex_py(0x2a80000), "0x2a80000");
        assert_eq!(hex_py(-0x1000), "-0x1000");
    }

    #[test]
    fn header_parse_follows_dict_of_split() {
        let h = FixupsHeader::parse(
            "# PATCH_OFF\t-0xc60000\n# TEXT_END\t0x7383be4\n# TEXT_END\t0x10\n",
        )
        .unwrap();
        assert_eq!(h.hex("PATCH_OFF").unwrap(), -0xc60000);
        assert_eq!(h.hex("TEXT_END").unwrap(), 0x10); // later key wins
        assert!(h.hex("NOPE").is_err());
        assert_eq!(h.hex_or("BACK_LEN", "0").unwrap(), 0);
        // a line with 1 or 3 tokens, or an empty line, is a ValueError in Python
        assert!(FixupsHeader::parse("# ONLY\n").is_err());
        assert!(FixupsHeader::parse("# A\tB\tC\n").is_err());
        assert!(FixupsHeader::parse("# A\t1\n\n").is_err());
    }

    #[test]
    fn ranges_for_the_grizzy_layouts() {
        // main: patch area before the base (FAR); sz is main.patched.bin's size
        let main = hdr(&[
            ("PATCH_OFF", "-0xc60000"),
            ("KEY_PAGE_OFF", "0xa204000"),
            ("KEY_PAGE_SIZE", "0x4000"),
            ("TEXT_END", "0x7383be4"),
            ("FILE_IMAGE_LEN", "0x9e04000"),
        ]);
        let r = piece_ranges(&main, 167_018_996, Mode::Assemble).unwrap();
        assert_eq!(
            r,
            vec![
                (0, 0x7384000),
                (0x7384000, 0x9e04000),
                (0x9e04000, 0x9f4c000)
            ]
        );
        // sdk: patch area after the data
        let sdk = hdr(&[
            ("PATCH_OFF", "0xc80000"),
            ("KEY_PAGE_OFF", "0xc78000"),
            ("KEY_PAGE_SIZE", "0x4000"),
            ("TEXT_END", "0x68db70"),
        ]);
        let r = piece_ranges(&sdk, 13_756_200, Mode::GenEmbed).unwrap();
        assert_eq!(
            r,
            vec![(0, 0x690000), (0x690000, 0xc80000), (0xc80000, 0xd20000)]
        );
    }

    #[test]
    fn back_patch_area_adds_an_x2_piece() {
        let h = hdr(&[
            ("PATCH_OFF", "-0x10000"),
            ("KEY_PAGE_OFF", "0x20000"),
            ("KEY_PAGE_SIZE", "0x4000"),
            ("TEXT_END", "0x8000"),
            ("FILE_IMAGE_LEN", "0x10000"),
            ("BACK_LEN", "0x4000"),
        ]);
        let r = piece_ranges(&h, 0x20000, Mode::GenEmbed).unwrap();
        assert_eq!(
            r,
            vec![
                (0, 0x8000),
                (0x8000, 0x10000),
                (0x10000, 0x1c000),
                (0x1c000, 0x20000)
            ]
        );
    }

    #[test]
    fn layout_asserts_reject_bad_headers() {
        let bad_ks = hdr(&[
            ("PATCH_OFF", "0x10000"),
            ("KEY_PAGE_OFF", "0x8000"),
            ("KEY_PAGE_SIZE", "0x2000"),
            ("TEXT_END", "0x4000"),
        ]);
        assert!(piece_ranges(&bad_ks, 0x20000, Mode::Assemble).is_err());
        // KEY_PAGE_OFF not page-aligned: only gen_embed.py asserts it in the positive branch
        let unaligned = hdr(&[
            ("PATCH_OFF", "0x10000"),
            ("KEY_PAGE_OFF", "0x8001"),
            ("KEY_PAGE_SIZE", "0x4000"),
            ("TEXT_END", "0x4000"),
        ]);
        assert!(piece_ranges(&unaligned, 0x20000, Mode::Assemble).is_ok());
        assert!(piece_ranges(&unaligned, 0x20000, Mode::GenEmbed).is_err());
    }

    #[test]
    fn text_for_the_assembly_has_no_quote_backslash_or_control_character() {
        for ok in [
            "main",
            "nnSdk",
            "subsdk0",
            "a b",
            "x.y-z_1",
            "\u{e9}t\u{e9}",
        ] {
            assert!(asm_string_ok("name", ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "a\"b",
            "a\\b",
            "a\nb",
            "a\rb",
            "a\tb",
            "a\0b",
            "\u{7f}",
            "x\"\n    .incbin \"/etc/passwd\"",
        ] {
            let e = asm_string_ok("name", bad).expect_err(bad);
            assert!(
                e.to_string().contains("break the generated assembly"),
                "{e}"
            );
        }
        // a section name also refuses what ends or splits one
        for ok in ["main", "sdk", "subsdk0", "nro_x0", "a.b-c_1", ""] {
            assert!(asm_name_ok("name", ok).is_ok(), "{ok:?}");
        }
        for bad in ["a b", "a,b", "a;b", "a\"b"] {
            assert!(asm_name_ok("name", bad).is_err(), "{bad:?}");
        }
    }

    /// the `--jit` file's path goes into `.incbin "<path>"`: a quote in it ended the string (the .S then holds whatever follows); it is refused before the text exists
    #[test]
    fn a_path_with_a_quote_in_it_is_refused_not_written_into_the_assembly() {
        let base = std::env::var("IBUILDER_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let d = base.join(format!("ibuilder-macho-embed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let ok = d.join("jit.bin");
        fs::write(&ok, vec![0u8; 16]).unwrap();
        let (text, _) = gen_embed(
            &d,
            &[],
            &GenEmbedOptions {
                tag: String::new(),
                jit: Some(ok.clone()),
            },
        )
        .unwrap();
        assert!(text.contains(".incbin \""), "{text}");
        let bad = d.join("ji\"t.bin");
        fs::write(&bad, vec![0u8; 16]).unwrap();
        let e = gen_embed(
            &d,
            &[],
            &GenEmbedOptions {
                tag: String::new(),
                jit: Some(bad),
            },
        )
        .expect_err("a quote in the path");
        assert!(
            e.to_string().contains("break the generated assembly"),
            "{e}"
        );
        let e = gen_embed(
            &d,
            &[],
            &GenEmbedOptions {
                tag: "a b".into(),
                jit: None,
            },
        )
        .expect_err("a space in the tag");
        assert!(e.to_string().contains("section name"), "{e}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn abspath_is_lexical() {
        assert_eq!(abspath(Path::new("/a/b/../c/./d")), PathBuf::from("/a/c/d"));
        assert_eq!(abspath(Path::new("/a//b")), PathBuf::from("/a/b"));
        assert_eq!(abspath(Path::new("/..")), PathBuf::from("/"));
    }
}
