//! A few lines of `argparse`-compatible option handling for the CLIs (no `clap`: it is not needed and would be
//! a dependency to ship). Supports `--opt value`, `--opt=value`, unambiguous prefixes (`--mod` for `--modules`),
//! flags, and `nargs='+'` options. Errors exit with status 2 and a usage line, like argparse.

use std::collections::HashMap;

pub struct Spec {
    pub name: &'static str,
    /// 0 = flag, 1 = one value, 2 = one or more values (`nargs='+'`)
    pub arity: u8,
}

#[derive(Default, Debug)]
pub struct Parsed {
    pub values: HashMap<&'static str, Vec<String>>,
    pub positionals: Vec<String>,
}

impl Parsed {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|v| v.last())
            .map(String::as_str)
    }
    pub fn all(&self, name: &str) -> Option<&[String]> {
        self.values.get(name).map(Vec::as_slice)
    }
    pub fn flag(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }
}

fn looks_like_option(a: &str) -> bool {
    a.starts_with('-') && a.len() > 1 && !a[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
}

pub fn parse(prog: &str, usage: &str, specs: &[Spec], args: &[String]) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    let mut i = 0;
    let fail = |m: String| format!("usage: {prog} {usage}\n{prog}: error: {m}");
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            out.positionals.extend(args[i..].iter().cloned());
            break;
        }
        if !a.starts_with("--") {
            if looks_like_option(a) {
                return Err(fail(format!("unrecognized arguments: {a}")));
            }
            out.positionals.push(a.clone());
            continue;
        }
        let (key, inline) = match a.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let name = &key[2..];
        let spec = match specs.iter().find(|s| s.name == name) {
            Some(s) => s,
            None => {
                let cands: Vec<&Spec> = specs.iter().filter(|s| s.name.starts_with(name)).collect();
                match cands.len() {
                    1 => cands[0],
                    0 => return Err(fail(format!("unrecognized arguments: {a}"))),
                    _ => return Err(fail(format!("ambiguous option: {key}"))),
                }
            }
        };
        let entry = out.values.entry(spec.name).or_default();
        match spec.arity {
            0 => {
                if inline.is_some() {
                    return Err(fail(format!(
                        "argument --{}: ignored explicit argument",
                        spec.name
                    )));
                }
            }
            1 => {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        if i < args.len() && !looks_like_option(&args[i]) {
                            i += 1;
                            args[i - 1].clone()
                        } else {
                            return Err(fail(format!(
                                "argument --{}: expected one argument",
                                spec.name
                            )));
                        }
                    }
                };
                entry.push(v);
            }
            _ => {
                entry.clear(); // argparse replaces, it does not append, for a repeated nargs option
                if let Some(v) = inline {
                    entry.push(v);
                }
                while i < args.len() && !looks_like_option(&args[i]) {
                    entry.push(args[i].clone());
                    i += 1;
                }
                if entry.is_empty() {
                    return Err(fail(format!(
                        "argument --{}: expected at least one argument",
                        spec.name
                    )));
                }
            }
        }
    }
    Ok(out)
}

/// Python `int(s, 0)`: optional sign, `0x`/`0o`/`0b` prefixes or decimal (no leading zeros), `_` separators.
pub fn parse_int_auto(s: &str) -> Result<i128, String> {
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let lower = t.to_ascii_lowercase();
    let (radix, digits) = if let Some(r) = lower.strip_prefix("0x") {
        (16, r.to_string())
    } else if let Some(r) = lower.strip_prefix("0o") {
        (8, r.to_string())
    } else if let Some(r) = lower.strip_prefix("0b") {
        (2, r.to_string())
    } else {
        (10, lower.clone())
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return Err(format!("invalid literal for int() with base 0: {s:?}"));
    }
    if radix == 10
        && digits.len() > 1
        && digits.starts_with('0')
        && digits.chars().any(|c| c != '0' && c != '_')
    {
        return Err(format!("invalid literal for int() with base 0: {s:?}"));
    }
    let v = i128::from_str_radix(&digits.replace('_', ""), radix)
        .map_err(|_| format!("invalid literal for int() with base 0: {s:?}"))?;
    Ok(if neg { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs() -> Vec<Spec> {
        vec![
            Spec {
                name: "host",
                arity: 1,
            },
            Spec {
                name: "modules",
                arity: 2,
            },
            Spec {
                name: "synthetic",
                arity: 0,
            },
            Spec {
                name: "out",
                arity: 1,
            },
        ]
    }
    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_like_argparse() {
        let p = parse(
            "t",
            "u",
            &specs(),
            &v(&["--host", "h", "--mod", "a", "b", "--synthetic", "--out=o"]),
        )
        .unwrap();
        assert_eq!(p.get("host"), Some("h"));
        assert_eq!(p.all("modules").unwrap(), ["a", "b"]);
        assert!(p.flag("synthetic"));
        assert_eq!(p.get("out"), Some("o"));
        assert!(parse("t", "u", &specs(), &v(&["--nope"])).is_err());
        assert!(parse("t", "u", &specs(), &v(&["--host"])).is_err());
        assert!(parse("t", "u", &specs(), &v(&["--modules"])).is_err());
    }

    #[test]
    fn int_auto_matches_python() {
        assert_eq!(parse_int_auto("0x5A17BEEF").unwrap(), 0x5A17BEEF);
        assert_eq!(parse_int_auto("305419896").unwrap(), 305419896);
        assert_eq!(parse_int_auto("0o17").unwrap(), 15);
        assert_eq!(parse_int_auto("0b101").unwrap(), 5);
        assert_eq!(parse_int_auto("0").unwrap(), 0);
        assert!(parse_int_auto("010").is_err());
        assert!(parse_int_auto("zz").is_err());
    }
}
