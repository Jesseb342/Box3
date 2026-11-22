//! Switch NSO rewriter: AArch64 module -> an image that can execute natively on Apple systems. A Rust port of
//! `dm/tools/patch_nso.py` (and the detector modules it imports), producing byte-identical output files.
//!
//! The Apple kernel modifies x18 and tpidr_el0; Horizon's thread area, svc and timers have no counterpart on Apple.
//! See `docs/crates/REWRITE-RUST.md` for the mapping from the Python source to these modules.

pub mod detect;
pub mod fde;
pub mod frame;
pub mod ins;
pub mod jump_solver;
pub mod jumps;
pub mod matching;
pub mod output;
pub mod patches;
pub mod pyset;
pub mod rewriter;
pub mod scan;
pub mod select;
pub mod sites;
pub mod spin;
pub mod stubs;
pub mod stubs_games;
// generated file, kept exactly as tools/gen_patch_tables.py writes it (rustfmt would reflow it, so a regeneration would not reproduce the committed text)
#[rustfmt::skip]
pub mod tables;
pub mod windows;

use std::fmt;

/// A failed assertion or a fatal `[RED]` exit of the Python rewriter, or the request to run again with a bigger patch
/// area in front of the module (the `os.execve` re-exec of the Python, which cannot exist on iOS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub msg: String,
    /// `Some(n)`: the patch area does not fit before the base; rewrite again with `DM_PATCH_FRONT = n`
    pub rerun_front: Option<u64>,
}

impl Fail {
    pub fn new(msg: impl Into<String>) -> Fail {
        Fail {
            msg: msg.into(),
            rerun_front: None,
        }
    }
}
impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}
impl std::error::Error for Fail {}
impl From<ibuilder_a64::asm::AsmError> for Fail {
    fn from(e: ibuilder_a64::asm::AsmError) -> Fail {
        Fail::new(e.0)
    }
}
impl From<ibuilder_nso::Error> for Fail {
    fn from(e: ibuilder_nso::Error) -> Fail {
        Fail::new(format!("[RED] {}", e.0))
    }
}

pub type Res<T> = Result<T, Fail>;

/// Python's `f'{x:#x}'`: `0x...`, `-0x...` for a negative number
pub fn hx(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", v.unsigned_abs())
    } else {
        format!("{v:#x}")
    }
}

pub use rewriter::{Options, Rewritten, rewrite};

/// `IBR_TIMING=1`: print the time since the previous mark to stderr (development aid; no effect on the output)
pub fn mark(what: &str) {
    use std::sync::Mutex;
    use std::time::Instant;
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    if std::env::var_os("IBR_TIMING").is_none() {
        return;
    }
    let now = Instant::now();
    let mut l = LAST.lock().unwrap();
    let d = l
        .map(|t| now.duration_since(t).as_secs_f64())
        .unwrap_or(0.0);
    eprintln!("[timing] {what}: {d:.3}s");
    *l = Some(now);
}
