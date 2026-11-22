//! Narrow C ABI for the vendored iBuilder NSO/NRO loader.
//! The returned module owns its reconstructed image until box3_nso_free.
use std::{ffi::c_char, ptr, slice};
use ibuilder_nso::Module;

#[repr(C)]
pub struct Box3NsoModule { inner: Module }

fn write_error(dst: *mut c_char, cap: usize, message: &str) {
    if dst.is_null() || cap == 0 { return; }
    let bytes = message.as_bytes();
    let n = bytes.len().min(cap - 1);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), n);
        *dst.add(n) = 0;
    }
}

/// Returns 0 on success; otherwise 1 for invalid arguments and 2 for a rejected module.
/// On success, *out_module receives an opaque handle released with box3_nso_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn box3_nso_load(
    data: *const u8, data_len: usize, out_module: *mut *mut Box3NsoModule,
    error: *mut c_char, error_capacity: usize,
) -> i32 {
    if out_module.is_null() || data.is_null() || data_len == 0 {
        write_error(error, error_capacity, "invalid input pointer or empty module");
        return 1;
    }
    unsafe { *out_module = ptr::null_mut(); }
    let bytes = unsafe { slice::from_raw_parts(data, data_len) };
    match ibuilder_nso::load(bytes, "input module") {
        Ok(inner) => {
            let handle = Box::new(Box3NsoModule { inner });
            unsafe { *out_module = Box::into_raw(handle); }
            0
        }
        Err(e) => { write_error(error, error_capacity, &e.0); 2 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn box3_nso_image(handle: *const Box3NsoModule, out_len: *mut usize) -> *const u8 {
    if handle.is_null() { return ptr::null(); }
    let module = unsafe { &*handle };
    if !out_len.is_null() { unsafe { *out_len = module.inner.image.len(); } }
    module.inner.image.as_ptr()
}

/// Copies the three (memory offset, memory size) pairs, BSS size and 32-byte build ID.
/// Output pointers may be null when a caller does not need that field.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn box3_nso_metadata(
    handle: *const Box3NsoModule, segments: *mut u32, bss: *mut u32, build_id: *mut u8,
) -> i32 {
    if handle.is_null() { return 1; }
    let module = unsafe { &*handle };
    if !segments.is_null() {
        for (i, (offset, size)) in module.inner.segments.iter().enumerate() {
            unsafe { *segments.add(i * 2) = *offset; *segments.add(i * 2 + 1) = *size; }
        }
    }
    if !bss.is_null() { unsafe { *bss = module.inner.bss; } }
    if !build_id.is_null() {
        unsafe { ptr::copy_nonoverlapping(module.inner.build_id.as_ptr(), build_id, 32); }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn box3_nso_free(handle: *mut Box3NsoModule) {
    if !handle.is_null() { drop(unsafe { Box::from_raw(handle) }); }
}
