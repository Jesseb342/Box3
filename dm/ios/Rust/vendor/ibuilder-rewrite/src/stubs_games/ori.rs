//! Ori and the Will of the Wisps 1.2.1 (v196608) main (01008DD013200000): `STUBS` of `dm/games/01008DD013200000/patches.py`.

use crate::Res;
use crate::stubs::StubCtx;
use crate::stubs_games::GamePort;
use ibuilder_a64::asm::{self, b, bl, cbnzw};

pub static PORT: GamePort = GamePort {
    profile: "01008DD013200000",
    digest: "e8e4ec5c299a4b67",
    frame_step: &[],
    stubs: &[("11c33c7c2dbd3c5491841f67495c7ee8", ori_registry_lock)],
    match_frame_step: &[],
    match_stubs: &[],
};

/// Ori and the Will of the Wisps 1.2.1 (v196608) main (01008DD013200000): Unity's constant-buffer table functions run
/// under the registry mutex when they work on the shared device
pub fn ori_registry_lock(ctx: &mut StubCtx) -> Res<()> {
    const LOCK: i64 = 0xcbebd0; // Unity's Mutex::Lock / Unlock (an nn::os mutex at +8, created recursive)
    const UNLOCK: i64 = 0xcbebe0;
    const MUTEX: i64 = 0x2df18; // adrp + ldr of the registry mutex's pointer, where the job devices lock it
    // (function, its first instruction, the register holding the device, what it does)
    // table rows are kept one per line as written (rustfmt would put every field of every row on its own line)
    #[rustfmt::skip]
    const WRAPPED: [(i64, &str, u32, &str); 10] = [
        (0x2d640, "ff4302d1", 0, "insert a layout"),
        (0x34f80, "ffc301d1", 0, "register a layout and its members (main thread)"),
        (0x353c0, "f60f1df8", 0, "look up a member (main thread)"),
        (0x24550, "ff0302d1", 1, "apply a program's parameters (render thread, per draw)"),
        (0x24de0, "ffc301d1", 0, "set a constant buffer (render thread)"),
        (0x2d200, "ff0302d1", 0, "set several constant buffers (render thread)"),
        (0x35510, "ff0301d1", 0, "write a buffer's values (render thread)"),
        (0x25110, "fc6fbaa9", 0, "move a layout's bound slots (render thread)"),
        (0x29330, "083858f9", 0, "reset the layouts' slots"),
        (0x29120, "f40f1ef8", 1, "copy the table into a graphics-job device"),
    ];
    let slot = ctx.address(MUTEX, None)?;
    fn mutex_call(ctx: &mut StubCtx, slot: i64, f: i64) -> Res<()> {
        let w = asm::adrp(0, ctx.here(), slot)?;
        ctx.emit(w);
        ctx.emit(asm::ldrx(0, 0, ((slot & 0xfff) / 8) as u32));
        let w = bl(ctx.here(), f)?;
        ctx.emit(w);
        Ok(())
    }
    for (f, first, dev, what) in WRAPPED {
        ctx.site(f, first)?;
        let start = ctx.here();
        let orig = start + 4 * 23; // the original first instruction, after the 23 words below
        ctx.emit(0xb96f8810 | dev << 5); // ldr w16, [x<dev>, #0x2f88]   device thread index (x16 is dead at a call)
        let w = cbnzw(16, ctx.here(), orig)?; // a job device: as before
        ctx.emit(w);
        ctx.emit(asm::stp_pre(29, 30, 31, -0x60));
        ctx.emit(0x910003fd); // stp x29, x30, [sp, #-0x60]!; mov x29, sp
        for i in 0..4 {
            ctx.emit(asm::stp(2 * i, 2 * i + 1, 31, 0x10 + 0x10 * i as i64)); // the arguments x0..x7
        }
        mutex_call(ctx, slot, LOCK)?;
        for i in 0..4 {
            ctx.emit(asm::ldp(2 * i, 2 * i + 1, 31, 0x10 + 0x10 * i as i64));
        }
        let w = bl(ctx.here(), orig)?;
        ctx.emit(w);
        ctx.emit(asm::strx(0, 31, 2)); // str x0, [sp, #0x10]   the result (the insert's entry)
        mutex_call(ctx, slot, UNLOCK)?;
        ctx.emit(asm::ldrx(0, 31, 2));
        ctx.emit(asm::ldp_post(29, 30, 31, 0x60));
        ctx.emit(0xd65f03c0); // ret
        if ctx.here() != orig {
            return Err(crate::Fail::new("assert here() == orig"));
        }
        let ob = crate::matching::unhex(first);
        ctx.emit(u32::from_le_bytes(ob.try_into().unwrap()));
        let w = b(ctx.here(), f + 4)?;
        ctx.emit(w);
        let w = b(f, start)?;
        ctx.put(f, &[w], &format!("Unity's constant-buffer table: {what} on the shared device under the registry mutex"));
    }
    Ok(())
}
