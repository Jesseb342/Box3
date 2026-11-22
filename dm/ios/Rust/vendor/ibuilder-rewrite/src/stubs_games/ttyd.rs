//! Paper Mario: The Thousand-Year Door 1.0.1 main (0100ECD018EBE000): `FRAME_STEP` of `dm/games/0100ECD018EBE000/patches.py`.

use crate::Res;
use crate::stubs::StubCtx;
use crate::stubs_games::GamePort;
use ibuilder_a64::asm::{self, b};

pub static PORT: GamePort = GamePort {
    profile: "0100ECD018EBE000",
    digest: "3e95811b9093c606",
    frame_step: &[("0effe4af1dec3a7966b934d4a7c3d2bf", ttyd_frame_step)],
    stubs: &[],
    match_frame_step: &[],
    match_stubs: &[],
};

/// the base clock steps by the host's vsyncs
pub fn ttyd_frame_step(ctx: &mut StubCtx) -> Res<()> {
    let st = ctx.state;
    ctx.site(0x2e77f8, "604600bd")?;
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xb9400211u32, // ldr w17,[x16]          target fps (float bits; 0 = off)
        0x34000111,    // cbz w17,orig (+8)
        0xb9402211,    // ldr w17,[x16,#0x20]    step in vsyncs
        0x340000d1,    // cbz w17,orig (+6)      not decided yet
        0x1e230220,    // ucvtf s0,w17           the base clock's step
        0xf9401a10,    // ldr x16,[x16,#0x30]
    ] {
        ctx.emit(w);
    }
    ctx.emit(0x8b110210); // add x16,x16,x17
    let w = asm::adrp(17, ctx.here(), st)?;
    ctx.emit(w);
    ctx.emit(0xf9001a30); // str x16,[x17,#0x30]    vsyncs stepped
    ctx.emit(0xbd004660); // orig: str s0,[x19,#0x44]; back
    let w = b(ctx.here(), 0x2e77fc)?;
    ctx.emit(w);
    let w = b(0x2e77f8, start)?;
    ctx.put(0x2e77f8, &[w], "frame step: the base clock steps by the host's vsyncs (state page target fps; 0 = the game's measured step)");
    Ok(())
}
