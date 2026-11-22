//! AArch64 support for the rewriter: instruction encoders (`asm`, port of `nso_asm.py`) and a Capstone-backed
//! decoder (`cs`). Small word-level helpers used by the detectors live in `bits`.
pub mod asm;
pub mod bits;
pub mod cs;
