//! ibuilder-macho: the linker-less Mach-O framework assembler, ported from iOSBuilder's Python tools.
//!
//! | Python | Rust |
//! |---|---|
//! | `tools/assemble.py` | [`assemble`] (`Plan`, `assemble_files`) |
//! | `tools/macho_write.py` | [`writer`] (`build_probe`, load-command builders, export trie, arm64 encoders) |
//! | `tools/fix_tlv.py` | [`tlv`] (`fix_tlv`, `find_section`) |
//! | `engine/dm/ios/tools/gen_embed.py` | [`embed`] (`piece_ranges`, `gen_embed`) |
//!
//! Library code is pure std, `forbid(unsafe_code)`, with no `fork`/`exec`/shell-out and no macOS-only API,
//! so it builds for `aarch64-apple-ios`. Output is byte-identical to the Python tools (see `docs/crates/MACHO-RUST.md`).
#![forbid(unsafe_code)]

#[macro_use]
pub mod error;
pub mod assemble;
pub mod cli;
pub mod embed;
pub mod io;
pub mod macho;
pub mod tlv;
pub mod writer;

pub use assemble::{
    AssembleInfo, AssembleReport, Game, ModulePieces, ModuleSource, Piece, PieceData, Plan,
    assemble_files, synthetic_pieces,
};
pub use error::{Error, Result};
