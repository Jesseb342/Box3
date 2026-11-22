//! Narrow C ABI for the pinned iBuilder NSO rewrite engine.
use std::{ffi::{c_char, CStr}, ptr, slice};
use ibuilder_rewrite::{Options, Rewritten, rewrite};

#[repr(C)]
pub struct Box3RewriteResult { inner: Rewritten }

fn set_error(dst: *mut c_char, cap: usize, message: &str) {
    if dst.is_null() || cap == 0 { return; }
    let bytes = message.as_bytes(); let n = bytes.len().min(cap - 1);
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), n); *dst.add(n) = 0; }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn box3_rewrite_nso(data: *const u8, data_len: usize, module_name: *const c_char, game_profile: *const c_char, out_result: *mut *mut Box3RewriteResult, error: *mut c_char, error_capacity: usize) -> i32 {
    if data.is_null() || data_len == 0 || module_name.is_null() || out_result.is_null() { set_error(error,error_capacity,"invalid rewrite input"); return 1; }
    unsafe { *out_result = ptr::null_mut(); }
    let name = match unsafe { CStr::from_ptr(module_name) }.to_str() { Ok(v) if !v.is_empty()=>v, _=>{set_error(error,error_capacity,"module name must be non-empty UTF-8");return 1;} };
    let game = if game_profile.is_null(){None}else{match unsafe{CStr::from_ptr(game_profile)}.to_str(){Ok(v) if !v.is_empty()=>Some(v.to_owned()),Ok(_)=>None,Err(_)=>{set_error(error,error_capacity,"game profile must be UTF-8");return 1;}}};
    let input=unsafe{slice::from_raw_parts(data,data_len)};
    let options=Options{workers:1,patch_front:None,game,games_dirs:Vec::new(),spin_list:false,py_tools:None};
    let pool=match rayon::ThreadPoolBuilder::new().num_threads(1).build(){Ok(p)=>p,Err(e)=>{set_error(error,error_capacity,&e.to_string());return 3;}};
    match pool.install(||rewrite(input,"in-memory NSO",name,&options)) {Ok(inner)=>{unsafe{*out_result=Box::into_raw(Box::new(Box3RewriteResult{inner}));}0},Err(e)=>{set_error(error,error_capacity,&e.to_string());2}}
}

fn bytes(handle:*const Box3RewriteResult, which:u32)->(*const u8,usize){if handle.is_null(){return(ptr::null(),0);}let r=unsafe{&(*handle).inner};let b:&[u8]=match which{0=>&r.image,1=>&r.patch,2=>r.fixups.as_bytes(),3=>r.gates.as_bytes(),4=>r.sites.as_bytes(),5=>r.cuts.as_bytes(),6=>r.changed.as_bytes(),_=>r.obs.as_bytes()};(b.as_ptr(),b.len())}
macro_rules! getter {($fn:ident,$n:expr)=>{#[unsafe(no_mangle)]pub unsafe extern "C" fn $fn(h:*const Box3RewriteResult,n:*mut usize)->*const u8{let(p,l)=bytes(h,$n);if !n.is_null(){unsafe{*n=l;}}p}};}
getter!(box3_rewrite_image,0); getter!(box3_rewrite_patch,1); getter!(box3_rewrite_fixups,2); getter!(box3_rewrite_gates,3); getter!(box3_rewrite_sites,4); getter!(box3_rewrite_cuts,5); getter!(box3_rewrite_changed,6); getter!(box3_rewrite_obs,7);
#[unsafe(no_mangle)] pub unsafe extern "C" fn box3_rewrite_pad_to(h:*const Box3RewriteResult)->usize{if h.is_null(){0}else{unsafe{(*h).inner.pad_to}}}
#[unsafe(no_mangle)] pub unsafe extern "C" fn box3_rewrite_free(h:*mut Box3RewriteResult){if !h.is_null(){drop(unsafe{Box::from_raw(h)});}}
