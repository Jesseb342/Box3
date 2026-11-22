//! Error type. The Python tools fail with `assert` / `SystemExit(msg)` / `struct.error`; here every such
//! failure is an `Error` carrying the same kind of message, so a pipeline can report it instead of aborting.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// An I/O failure, with what was being done.
    Io { context: String, source: io::Error },
    /// The input is not what the tool expects (not a Mach-O, a layout rule is violated, a table is malformed).
    /// Mirrors the Python `assert` / `SystemExit` paths.
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Invalid(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io {
            context: "I/O error".into(),
            source: e,
        }
    }
}

/// `ensure!(cond, "message {}", x)` -> `return Err(Error::Invalid(..))` when `cond` is false.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !($cond) {
            return Err($crate::Error::Invalid(format!($($arg)+)));
        }
    };
}
