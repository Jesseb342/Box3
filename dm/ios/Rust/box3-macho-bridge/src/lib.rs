//! C ABI for assembling a game's rewritten modules onto a verified iOS host dylib.
use ibuilder_macho::{assemble_files, Game};
use std::{ffi::{c_char, CStr}, panic::{catch_unwind, AssertUnwindSafe}, path::PathBuf, ptr};

fn set_error(dst: *mut c_char, cap: usize, message: &str) {
    if dst.is_null() || cap == 0 { return; }
    let bytes = message.as_bytes();
    let n = bytes.len().min(cap - 1);
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), n); *dst.add(n) = 0; }
}

unsafe fn read_utf8<'a>(value: *const c_char, field: &str) -> Result<&'a str, String> {
    if value.is_null() { return Err(format!("{field} is null")); }
    unsafe { CStr::from_ptr(value) }.to_str().map_err(|_| format!("{field} must be UTF-8"))
}

/// Assemble host + rewritten module files. modules_csv example: "main,sdk,subsdk0".
/// Returns 0 success, 1 invalid arguments, 2 assembly failure, 3 panic.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn box3_macho_assemble(
    host_path: *const c_char, output_path: *const c_char, game_dir: *const c_char,
    modules_csv: *const c_char, tag: *const c_char, out_size: *mut u64,
    error: *mut c_char, error_capacity: usize,
) -> i32 {
    if !out_size.is_null() { unsafe { *out_size = 0; } }
    let args = (|| -> Result<_, String> {
        let host = unsafe { read_utf8(host_path, "host_path")? };
        let output = unsafe { read_utf8(output_path, "output_path")? };
        let dir = unsafe { read_utf8(game_dir, "game_dir")? };
        let csv = unsafe { read_utf8(modules_csv, "modules_csv")? };
        let tag = if tag.is_null() { "" } else { unsafe { read_utf8(tag, "tag")? } };
        let modules: Vec<String> = csv.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
        if modules.is_empty() { return Err("at least one module is required".into()); }
        if modules.iter().any(|m| !m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
            return Err("module names may contain only ASCII letters, digits, '_' and '-'".into());
        }
        Ok((PathBuf::from(host), PathBuf::from(output), PathBuf::from(dir), modules, tag.to_owned()))
    })();
    let (host, output, dir, modules, tag) = match args {
        Ok(v) => v, Err(e) => { set_error(error, error_capacity, &e); return 1; }
    };
    match catch_unwind(AssertUnwindSafe(|| assemble_files(&host, &output, &Game::Dir { dir, modules }, &tag))) {
        Ok(Ok(report)) => { if !out_size.is_null() { unsafe { *out_size = report.info.size; } } 0 }
        Ok(Err(e)) => { set_error(error, error_capacity, &e.to_string()); 2 }
        Err(_) => { set_error(error, error_capacity, "panic in Mach-O assembler"); 3 }
    }
}
