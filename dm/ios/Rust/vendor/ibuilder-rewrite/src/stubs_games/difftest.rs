//! Differential test of the ported stub functions against the real Python: `tests/fixtures/stubs/` holds synthetic modules (`tools/stubtest.py --export`: the registered build ID, or
//! functions of a matched rule's sizes with the original bytes at the stubs' sites; no game code) and the SHA-256 of every file the engine's `patch_nso.py` wrote for them and of
//! what it printed, or the message it stopped with. A matched rule's fingerprints are those of the game's functions, which cannot be made without the game: the fixture's `fpmap`
//! says which synthetic fingerprint stands in for which registered one (the Python run had the same substitution in its copy of `patches.py`), and the test puts it into
//! `stubs::TEST_FINGERPRINTS`, which only unit tests have. The cases per entry: `ok`, `mismatch` (a site's original bytes changed), `far` (a patch area before the base) and, for a
//! matched rule, `miss` / `dup` / `miss-other<n>` (a function not found, found twice, an `others` function not found), and for the anchored rule its `find`'s refusals.

use crate::{Options, rewrite};
use ibuilder_testkit::sha256_hex;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Default)]
struct Case {
    meta: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
}

#[test]
fn stub_ports_match_the_python_oracle() {
    // `STUB_FIXTURES=<dir>`: the fixtures of a partial run of `tools/stubtest.py --export <dir>` (development); the repository's are the full set
    let custom = std::env::var_os("STUB_FIXTURES").map(std::path::PathBuf::from);
    let dir = custom
        .clone()
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stubs"));
    let manifest = fs::read_to_string(dir.join("manifest.tsv")).unwrap();
    let mut cases: BTreeMap<String, Case> = BTreeMap::new();
    for l in manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let c: Vec<&str> = l.splitn(4, '\t').collect();
        let e = cases.entry(c[0].to_string()).or_default();
        match c[1] {
            "meta" => {
                e.meta.insert(c[2].to_string(), c[3].to_string());
            }
            _ => {
                e.files.insert(
                    if c[1] == "stdout" {
                        "stdout".to_string()
                    } else {
                        c[2].to_string()
                    },
                    c[3].to_string(),
                );
            }
        }
    }
    assert!(
        custom.is_some() || cases.len() >= 80,
        "the manifest has {} cases",
        cases.len()
    );
    let (mut ok, mut failed) = (0, 0);
    for (name, case) in &cases {
        let file = fs::read(dir.join(format!("{name}.nso"))).unwrap();
        {
            let mut t = crate::stubs::TEST_FINGERPRINTS.lock().unwrap();
            t.clear();
            if case.meta["fpmap"] != "-" {
                for pair in case.meta["fpmap"].split(',') {
                    let (a, b) = pair.split_once('=').unwrap();
                    t.push((a.to_string(), b.to_string()));
                }
            }
        }
        let opts = Options {
            workers: 2,
            game: Some(case.meta["profile"].clone()),
            ..Default::default()
        };
        let got = rewrite(&file, name, &case.meta["module"], &opts);
        crate::stubs::TEST_FINGERPRINTS.lock().unwrap().clear();
        match (case.meta["result"].as_str(), got) {
            ("ok", Ok(r)) => {
                let mut sums: BTreeMap<String, String> = BTreeMap::new();
                sums.insert(
                    "stdout".into(),
                    sha256_hex(format!("{}\n", r.log.join("\n")).as_bytes()),
                );
                let mut bin = Vec::new();
                r.write_patched(&mut bin).unwrap();
                sums.insert("patched.bin".into(), sha256_hex(&bin));
                for (k, v) in [
                    ("fixups.tsv", &r.fixups),
                    ("sites.tsv", &r.sites),
                    ("gates.tsv", &r.gates),
                    ("cuts.tsv", &r.cuts),
                    ("obs.tsv", &r.obs),
                    ("changed.tsv", &r.changed),
                ] {
                    sums.insert(k.into(), sha256_hex(v.as_bytes()));
                }
                if let Some(m) = &r.match_tsv {
                    sums.insert("match.tsv".into(), sha256_hex(m.as_bytes()));
                }
                assert_eq!(
                    sums, case.files,
                    "{name}: the output differs from the Python oracle"
                );
                ok += 1;
            }
            ("fail", Err(e)) => {
                let want = &case.meta["error"];
                // a bare `assert` of the Python has no message: only the fact that both stop is comparable then
                if !want.is_empty() && want != "AssertionError" {
                    assert_eq!(
                        &e.msg, want,
                        "{name}: the message differs from the Python's"
                    );
                }
                failed += 1;
            }
            (want, got) => panic!(
                "{name}: the Python {want}, this one {:?}",
                got.map(|_| "ok")
            ),
        }
    }
    eprintln!(
        "{ok} stub cases identical to the Python oracle, {failed} stopped with the Python's message"
    );
}
