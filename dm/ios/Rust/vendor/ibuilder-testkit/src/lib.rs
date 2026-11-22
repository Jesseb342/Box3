//! Shared test helpers: byte-exact file comparison against the Python oracle, SHA-256, peak RSS, and [`skip`] for a test that cannot run on this machine.
//! Test-only utility crate: it is never linked into the shipped app.
use sha2::{Digest, Sha256};
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// How many times [`skip`] ran in this process (a test binary), and the one-time registration of the line printed when the process ends.
static SKIPPED: AtomicUsize = AtomicUsize::new(0);
/// the tests that skipped (a test may skip several times: once per input)
static SKIPPED_TESTS: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());
static REPORT: Once = Once::new();

/// Runs at process exit (`atexit`): libtest has no end-of-run hook and hides the stderr of a PASSED test, so a test binary whose tests skipped said nothing at its end. This line is written straight
/// to fd 2 (libtest's capture only covers `print!` / `eprint!` inside a test thread), so a plain `cargo test` shows it right under that binary's "test result: ok" line.
extern "C" fn report_skips_at_exit() {
    let n = SKIPPED.load(Ordering::SeqCst);
    if n == 0 {
        return;
    }
    let tests = SKIPPED_TESTS.lock().map(|t| t.len()).unwrap_or(0);
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "?".into());
    let msg = format!(
        "\nibuilder-testkit: {tests} test(s) skipped ({n} skip call(s)) in {exe}: those of the tests above that said `ok` compared NOTHING (a fixture is missing on this machine). They are listed in {}; {STRICT_ENV}=1 makes each one fail.\n",
        skip_log_path().display()
    );
    // SAFETY: write(2) of a buffer that lives for the call; nothing else is done at exit.
    unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
}

/// Set to `1` and a test that [`skip`]s FAILS instead: nothing may be silently unverified (a CI machine with every fixture, or a check before a release).
pub const STRICT_ENV: &str = "IBUILDER_STRICT_FIXTURES";
/// Where [`skip`] appends one line per skip (default `$CARGO_TARGET_DIR/skipped-tests.log`, else `<workspace>/target/skipped-tests.log`); `scripts/test-report.sh` points it at a fresh file.
pub const SKIP_LOG_ENV: &str = "IBUILDER_SKIP_LOG";

/// The log [`skip`] appends to.
pub fn skip_log_path() -> PathBuf {
    if let Some(p) = std::env::var_os(SKIP_LOG_ENV).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    let target = match std::env::var_os("CARGO_TARGET_DIR").filter(|p| !p.is_empty()) {
        Some(t) => PathBuf::from(t),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
    };
    target.join("skipped-tests.log")
}

/// A test that needs something this machine does not have (a game's files, the Python oracle, a tool, an opt-in switch) calls this and returns. Libtest counts such a test as PASSED and hides its
/// stderr, so a run that compared nothing looked like a run that compared everything (review finding 3.2). So a skip is made loud and countable:
///   * printed (`SKIP <crate> <test>: <reason>`, visible with `--nocapture`),
///   * appended, as one line `crate<TAB>test<TAB>reason`, to the file named by [`skip_log_path`] (what `scripts/test-report.sh` counts and lists),
///   * and, when `IBUILDER_STRICT_FIXTURES=1`, a PANIC: the test fails.
///
/// Call it at the place where the test gives up, with the reason a person can act on ("the Grizzy ExeFS is not at <path>").
pub fn skip(reason: &str) {
    let krate = std::env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "?".into());
    let thread = std::thread::current();
    let test = thread.name().unwrap_or("?");
    let one_line = reason.replace(['\n', '\r', '\t'], " ");
    eprintln!("SKIP {krate} {test}: {one_line}");
    SKIPPED.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut t) = SKIPPED_TESTS.lock() {
        t.insert(test.to_string());
    }
    // SAFETY: registers a plain `extern "C" fn()` once per process.
    REPORT.call_once(|| unsafe {
        libc::atexit(report_skips_at_exit);
    });
    let path = skip_log_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        // one write() of a whole line: tests run in parallel threads (and test binaries one after another) and append to the same file
        let _ = f.write_all(format!("{krate}\t{test}\t{one_line}\n").as_bytes());
    }
    if std::env::var(STRICT_ENV).is_ok_and(|v| v == "1") {
        panic!("{STRICT_ENV}=1: {krate} {test} would be skipped: {one_line}");
    }
}

/// `true` when `path` exists; otherwise [`skip`]s with a reason naming it and returns `false`: `if !have(p) { return; }`.
pub fn have(path: impl AsRef<Path>) -> bool {
    let p = path.as_ref();
    if p.exists() {
        true
    } else {
        skip(&format!(
            "the fixture {} is not on this machine",
            p.display()
        ));
        false
    }
}

/// The workspace root (the folder holding `Cargo.toml` and `scripts/`).
pub fn repo_root() -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::canonicalize(&p).unwrap_or(p)
}

/// One `NAME=value` / `export NAME=value` line of a shell-style env file: `Some((NAME, raw value))`, `None` for a comment, a blank line or anything else (a `.` or an `if` line is not an
/// assignment the tests read).
fn assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    if line.starts_with('#') {
        return None;
    }
    let line = line
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let ok = key
        .chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && key.chars().all(|c| c == '_' || c.is_ascii_alphanumeric());
    ok.then_some((key, value))
}

/// The value of an assignment as the shell reads it (review r4 B6): one word, made of plain text, `'...'` (literal), `"..."` (expanded) and `\x`; `$NAME`, `${NAME}`, `${NAME-default}` and
/// `${NAME:-default}` expanded through `lookup` (the default itself expanded too, so `${A-$B}` and `${A-${B}/x}` read like the shell's); an unquoted space ends the word and what follows must
/// be a `#` comment. Anything else the shell would do (`$(...)`, backquotes, `${A:=...}`, an unterminated quote, a second word) is an `Err` saying so: a test must not read another value than
/// the scripts do, and skip in silence.
fn shell_value(raw: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let chars: Vec<char> = raw.trim_start().chars().collect();
    let mut i = 0;
    let out = word(&chars, &mut i, lookup, false)?;
    let rest: String = chars[i..].iter().collect();
    let rest = rest.trim_start();
    if !rest.is_empty() && !rest.starts_with('#') {
        return Err(format!(
            "more than one word after the '=' ({rest:?}): quote the value"
        ));
    }
    Ok(out)
}

/// One shell word from `c[*i..]`, up to an unquoted blank (or, when `in_braces`, the `}` that closes a `${...}`).
fn word(
    c: &[char],
    i: &mut usize,
    lookup: &dyn Fn(&str) -> Option<String>,
    in_braces: bool,
) -> Result<String, String> {
    let mut out = String::new();
    while *i < c.len() {
        let ch = c[*i];
        match ch {
            ' ' | '\t' if !in_braces => break,
            '}' if in_braces => break,
            '\'' => {
                *i += 1;
                let start = *i;
                while *i < c.len() && c[*i] != '\'' {
                    *i += 1;
                }
                if *i >= c.len() {
                    return Err("an unterminated '...'".into());
                }
                out.extend(&c[start..*i]);
                *i += 1;
            }
            '"' => {
                *i += 1;
                loop {
                    if *i >= c.len() {
                        return Err("an unterminated \"...\"".into());
                    }
                    match c[*i] {
                        '"' => {
                            *i += 1;
                            break;
                        }
                        '\\' if *i + 1 < c.len() && matches!(c[*i + 1], '"' | '\\' | '$' | '`') => {
                            out.push(c[*i + 1]);
                            *i += 2;
                        }
                        '$' => out.push_str(&dollar(c, i, lookup)?),
                        '`' => return Err("a command substitution (`...`)".into()),
                        x => {
                            out.push(x);
                            *i += 1;
                        }
                    }
                }
            }
            '\\' => {
                if *i + 1 < c.len() {
                    out.push(c[*i + 1]);
                }
                *i += 2;
            }
            '$' => out.push_str(&dollar(c, i, lookup)?),
            '`' => return Err("a command substitution (`...`)".into()),
            x => {
                out.push(x);
                *i += 1;
            }
        }
    }
    Ok(out)
}

/// The expansion at `c[*i] == '$'`.
fn dollar(
    c: &[char],
    i: &mut usize,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let name_char = |x: char| x == '_' || x.is_ascii_alphanumeric();
    *i += 1;
    match c.get(*i) {
        Some('(') => Err("a command substitution ($(...))".into()),
        Some('{') => {
            *i += 1;
            let start = *i;
            while *i < c.len() && name_char(c[*i]) {
                *i += 1;
            }
            let name: String = c[start..*i].iter().collect();
            if name.is_empty() {
                return Err("a ${...} with no variable name".into());
            }
            let value = lookup(&name);
            match c.get(*i) {
                Some('}') => {
                    *i += 1;
                    Ok(value.unwrap_or_default())
                }
                Some('-') | Some(':') => {
                    let colon = c[*i] == ':';
                    if colon {
                        *i += 1;
                        if c.get(*i) != Some(&'-') {
                            return Err(format!(
                                "${{{name}:{}...}}: only ${{NAME-default}} and ${{NAME:-default}} are read",
                                c.get(*i).copied().unwrap_or(' ')
                            ));
                        }
                    }
                    *i += 1;
                    let default = word(c, i, lookup, true)?;
                    if c.get(*i) != Some(&'}') {
                        return Err(format!("an unterminated ${{{name}-...}}"));
                    }
                    *i += 1;
                    Ok(match value {
                        Some(v) if !(colon && v.is_empty()) => v,
                        _ => default,
                    })
                }
                _ => Err(format!(
                    "${{{name}...}}: only ${{NAME}}, ${{NAME-default}} and ${{NAME:-default}} are read"
                )),
            }
        }
        Some(&x) if name_char(x) && !x.is_ascii_digit() => {
            let start = *i;
            while *i < c.len() && name_char(c[*i]) {
                *i += 1;
            }
            let name: String = c[start..*i].iter().collect();
            Ok(lookup(&name).unwrap_or_default())
        }
        _ => Ok("$".into()), // a lone '$' is itself
    }
}

/// Every assignment of a shell-style env file, evaluated in order as the shell would (the process environment holds the variables' first values, a later assignment replaces an earlier one,
/// and a value reads the variables as they are at its line): NAME -> value. `Err` names the first line the shell would read otherwise.
fn eval_env_file(text: &str) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut vars: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let Some((name, raw)) = assignment(line) else {
            continue;
        };
        let lookup = |v: &str| vars.get(v).cloned().or_else(|| std::env::var(v).ok());
        let value =
            shell_value(raw, &lookup).map_err(|e| format!("line {}: {name}=...: {e}", n + 1))?;
        vars.insert(name.to_string(), value);
    }
    Ok(vars)
}

/// The value one line assigns to `name`, read with the process environment alone (the tests of the parser).
#[cfg(test)]
fn parse_assignment(line: &str, name: &str) -> Option<String> {
    let (key, raw) = assignment(line)?;
    if key != name {
        return None;
    }
    shell_value(raw, &|v: &str| std::env::var(v).ok()).ok()
}

/// A setting of this machine's fixtures: the process environment first, else the value `scripts/local.env` (optional, gitignored; the file the shell scripts source too) gives it, read
/// as the shell reads it (`eval_env_file`), else `None`. So a plain `cargo test` finds the same inputs as `scripts/test-report.sh`, and a contributor who has none of them gets skips (see
/// [`skip`]) rather than failures. A line the shell would read differently than this parser can is not guessed at: it panics, naming the line (a test that skipped there would compare
/// nothing in silence).
pub fn local_env(name: &str) -> Option<String> {
    if let Some(v) = std::env::var(name).ok().filter(|v| !v.is_empty()) {
        return Some(v);
    }
    let file = repo_root().join("scripts/local.env");
    let text = fs::read_to_string(&file).ok()?;
    match eval_env_file(&text) {
        Ok(vars) => vars.get(name).cloned().filter(|v| !v.is_empty()),
        Err(e) => panic!(
            "{}: {e}: the tests read only NAME=value, \"...\", '...', $NAME, ${{NAME}}, ${{NAME-default}} and ${{NAME:-default}}; write the line in those terms",
            file.display()
        ),
    }
}

/// The checkout of the original iOSBuilder project (`$IOSBUILDER`, else `<workspace>/../iOSBuilder`): read-only reference data produced by the Python toolchain. Never write here.
pub fn iosbuilder() -> String {
    local_env("IOSBUILDER").unwrap_or_else(|| {
        repo_root()
            .parent()
            .unwrap_or(Path::new("/"))
            .join("iOSBuilder")
            .to_string_lossy()
            .into_owned()
    })
}
/// The iOSBuilder tree that holds the newest work (`$IOSBUILDER_WORKTREE`, else the checkout itself).
pub fn iosbuilder_worktree() -> String {
    local_env("IOSBUILDER_WORKTREE").unwrap_or_else(iosbuilder)
}
/// A folder of generated oracle outputs (`$IBUILDER_SCRATCH`; the files the `tools/` scripts of the crates write). When it is not set the path names the variable, so a skip says what to set.
pub fn scratch() -> PathBuf {
    PathBuf::from(
        local_env("IBUILDER_SCRATCH").unwrap_or_else(|| "<IBUILDER_SCRATCH is not set>".into()),
    )
}
/// The earlier folder of generated oracle outputs (`$IBUILDER_SCRATCH_OLD`, else [`scratch`]): the outputs of the first part of the work; both may be the same folder.
pub fn scratch_old() -> PathBuf {
    local_env("IBUILDER_SCRATCH_OLD")
        .map(PathBuf::from)
        .unwrap_or_else(scratch)
}

/// A fixture folder that `format!("{NAME}/...")` prints, so a path reads like it did when the folder was a constant: [`IOSBUILDER`], [`SCRATCH`], [`SCRATCH_OLD`].
pub struct FixtureDir(fn() -> String);
impl std::fmt::Display for FixtureDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&(self.0)())
    }
}
fn scratch_string() -> String {
    scratch().to_string_lossy().into_owned()
}
fn scratch_old_string() -> String {
    scratch_old().to_string_lossy().into_owned()
}
/// [`iosbuilder`]
pub static IOSBUILDER: FixtureDir = FixtureDir(iosbuilder);
/// [`scratch`]
pub static SCRATCH: FixtureDir = FixtureDir(scratch_string);
/// [`scratch_old`]
pub static SCRATCH_OLD: FixtureDir = FixtureDir(scratch_old_string);
pub fn grizzy_exefs(module: &str) -> String {
    format!("{IOSBUILDER}/out/ref-out-grizzy/ExeFS/{module}")
}
pub fn grizzy_oracle(module: &str, file: &str) -> String {
    format!("{IOSBUILDER}/out-py/pyrewrite/out/{module}/{file}")
}

/// Offset of the first differing byte, or None when identical (lengths included).
pub fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let n = a.len().min(b.len());
    (0..n)
        .find(|&i| a[i] != b[i])
        .or(if a.len() != b.len() { Some(n) } else { None })
}

/// Compare two files; Err carries sizes, the first differing offset and the bytes around it.
pub fn compare_files(a: impl AsRef<Path>, b: impl AsRef<Path>) -> Result<(), String> {
    let (pa, pb) = (a.as_ref(), b.as_ref());
    let da = fs::read(pa).map_err(|e| format!("{}: {e}", pa.display()))?;
    let db = fs::read(pb).map_err(|e| format!("{}: {e}", pb.display()))?;
    match first_diff(&da, &db) {
        None => Ok(()),
        Some(i) => Err(format!(
            "{} ({} B) != {} ({} B): first difference at {i:#x}: {:02x?} vs {:02x?}",
            pa.display(),
            da.len(),
            pb.display(),
            db.len(),
            &da[i.saturating_sub(4)..(i + 8).min(da.len())],
            &db[i.saturating_sub(4)..(i + 8).min(db.len())]
        )),
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Peak resident set size of this process in bytes (macOS reports bytes, Linux KiB).
pub fn peak_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    // macOS and iOS report bytes; Linux/Android report KiB.
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        ru.ru_maxrss as u64
    } else {
        ru.ru_maxrss as u64 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    /// the env vars are the process's: the skip tests run one at a time
    static ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn a_skip_is_logged_with_its_crate_test_and_reason_and_strict_mode_makes_it_a_failure() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir =
            std::env::temp_dir().join(format!("ibuilder-testkit-skip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let log = dir.join("nested/skipped-tests.log");
        // SAFETY: serialized by ENV; no other thread of this test binary reads these variables meanwhile
        unsafe {
            std::env::set_var(SKIP_LOG_ENV, &log);
            std::env::remove_var(STRICT_ENV);
        }
        skip("the Grizzy ExeFS\nis not at /x");
        assert!(!have(dir.join("absent")));
        let text = fs::read_to_string(&log).unwrap();
        let rows: Vec<Vec<&str>> = text.lines().map(|l| l.split('\t').collect()).collect();
        assert_eq!(rows.len(), 2, "{text}");
        assert_eq!(rows[0][0], "ibuilder-testkit");
        assert!(rows[0][1].contains("a_skip_is_logged"), "{:?}", rows[0]);
        assert_eq!(
            rows[0][2], "the Grizzy ExeFS is not at /x",
            "a newline in a reason would break the one-line format"
        );
        assert!(rows[1][2].contains("absent") && rows[1][2].contains("not on this machine"));
        assert!(have(&dir), "a fixture that is there is not a skip");
        // strict: the same call panics (and still logs)
        unsafe { std::env::set_var(STRICT_ENV, "1") };
        let r = std::panic::catch_unwind(|| skip("needs the oracle"));
        let msg = *r
            .expect_err("a strict skip must panic")
            .downcast::<String>()
            .unwrap();
        assert!(
            msg.contains("IBUILDER_STRICT_FIXTURES=1") && msg.contains("needs the oracle"),
            "{msg}"
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap().lines().count(),
            3,
            "a strict skip is still on the record"
        );
        unsafe {
            std::env::remove_var(STRICT_ENV);
            std::env::remove_var(SKIP_LOG_ENV);
        }
        let _ = fs::remove_dir_all(&dir);
        // this test skips on purpose: it must not be what the exit summary of this binary reports
        SKIPPED.store(0, Ordering::SeqCst);
        SKIPPED_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    #[test]
    fn env_file_assignments() {
        assert_eq!(
            parse_assignment("export A=/x/y", "A").as_deref(),
            Some("/x/y")
        );
        assert_eq!(
            parse_assignment("  A=\"/with space\"  ", "A").as_deref(),
            Some("/with space")
        );
        assert_eq!(parse_assignment("A='q'", "A").as_deref(), Some("q"));
        // the form scripts/local.env uses so that an environment value wins: the default when the variable is not set
        assert_eq!(
            parse_assignment(
                "export IBR_TK_UNSET_X=\"${IBR_TK_UNSET_X-/d/e}\"",
                "IBR_TK_UNSET_X"
            )
            .as_deref(),
            Some("/d/e")
        );
        assert_eq!(
            parse_assignment(
                "IBR_TK_UNSET_Y=${IBR_TK_UNSET_Y:-$HOME/f}",
                "IBR_TK_UNSET_Y"
            ),
            Some(format!("{}/f", std::env::var("HOME").unwrap_or_default()))
        );
        assert_eq!(
            parse_assignment("A=${IBR_TK_UNSET_Z-}", "A").as_deref(),
            Some("")
        );
        assert_eq!(parse_assignment("# A=/no", "A"), None);
        assert_eq!(parse_assignment("AB=/other", "A"), None);
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(
            parse_assignment("A=$HOME/x", "A"),
            Some(format!("{home}/x"))
        );
        assert_eq!(
            parse_assignment("A=${HOME}/x", "A"),
            Some(format!("{home}/x"))
        );
    }

    /// Review r4 B6: the forms the shell reads otherwise than the old parser did: a comment after a quoted value, a default that names another variable, a value in apostrophes; and a line
    /// the parser cannot read the shell's way is an error, never a silent other value.
    #[test]
    fn env_file_values_are_read_as_the_shell_reads_them() {
        let lookup = |v: &str| match v {
            "B" => Some("/b".to_string()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        let v = |raw: &str| shell_value(raw, &lookup);
        assert_eq!(v("\"/a\" # a comment").as_deref(), Ok("/a"));
        assert_eq!(v("/a # a comment").as_deref(), Ok("/a"));
        assert_eq!(v("/a#not-a-comment").as_deref(), Ok("/a#not-a-comment"));
        assert_eq!(v("\"${UNSET_A-$B}\"").as_deref(), Ok("/b"));
        assert_eq!(v("\"${UNSET_A-${B}/x}\"").as_deref(), Ok("/b/x"));
        assert_eq!(v("${B-/never}").as_deref(), Ok("/b"));
        assert_eq!(v("${EMPTY-/d}").as_deref(), Ok(""));
        assert_eq!(v("${EMPTY:-/d}").as_deref(), Ok("/d"));
        assert_eq!(
            v("'${X-v}'").as_deref(),
            Ok("${X-v}"),
            "literal in apostrophes"
        );
        assert_eq!(v("\"a b\"/c\\ d").as_deref(), Ok("a b/c d"));
        assert_eq!(v("\"price \\$5\"").as_deref(), Ok("price $5"));
        assert_eq!(v("$B/x-$UNSET_A-y").as_deref(), Ok("/b/x--y"));
        assert_eq!(
            v("/Users/me/x-y-z").as_deref(),
            Ok("/Users/me/x-y-z"),
            "a '-' in a plain value is text"
        );
        for bad in [
            "\"$(pwd)\"",
            "`pwd`",
            "\"/a",
            "'/a",
            "${A:=x}",
            "/a /b",
            "${A-x",
        ] {
            assert!(v(bad).is_err(), "{bad} must be refused: {:?}", v(bad));
        }
        // the whole file, in order: a later line reads an earlier one; the last assignment wins; the environment holds the first values
        let text = "# c\nexport IBR_TK_A=\"/one\"   # first\nexport IBR_TK_W=\"${IBR_TK_W-$IBR_TK_A}\"\nIBR_TK_A=/two\nif [ -f x ]; then . x; fi\n";
        let vars = eval_env_file(text).unwrap();
        assert_eq!(vars.get("IBR_TK_W").map(String::as_str), Some("/one"));
        assert_eq!(vars.get("IBR_TK_A").map(String::as_str), Some("/two"));
        let err = eval_env_file("A=/a\nB=\"$(pwd)\"\n").unwrap_err();
        assert!(err.contains("line 2") && err.contains("B="), "{err}");
    }

    /// This machine's `scripts/local.env`, when there is one, gives every variable the value bash gives it (names only in the message: the values are machine paths).
    #[test]
    fn this_machines_local_env_reads_like_bash() {
        let file = repo_root().join("scripts/local.env");
        let Ok(text) = fs::read_to_string(&file) else {
            skip("no scripts/local.env on this machine");
            return;
        };
        let vars = eval_env_file(&text).expect("scripts/local.env is read the shell's way");
        for name in vars.keys() {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!(
                    ". \"$1\" >/dev/null 2>&1; printf %s \"${{{name}}}\""
                ))
                .arg("bash")
                .arg(&file)
                .output();
            let Ok(out) = out else {
                skip("bash is not installed");
                return;
            };
            assert!(
                String::from_utf8_lossy(&out.stdout) == vars[name].as_str(),
                "{name}: bash and the parser differ (the values are not printed: machine paths)"
            );
        }
    }

    #[test]
    fn diff() {
        assert_eq!(first_diff(b"abc", b"abc"), None);
        assert_eq!(first_diff(b"abc", b"abd"), Some(2));
        assert_eq!(first_diff(b"ab", b"abc"), Some(2));
    }
}
