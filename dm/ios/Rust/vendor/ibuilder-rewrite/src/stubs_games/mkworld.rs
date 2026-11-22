//! Mario Kart World (0400C3F00006E000): `MATCH_FRAME_STEP` of `dm/games/0400C3F00006E000/patches.py`: the framework's frame interval comes from the host's step, at most 2 (the
//! game's own intervals); the game's 30 fps mode stays its own and is published as a step the game fixes (state +0x24). Two reviewed implementations of one patch: v0's function
//! (main+0x3a9e28, the mode load at +0xa0) and 1.8.0's (main+0x69cbb0, one word shorter, the mode load at +0xa4).

use crate::Res;
use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::GamePort;
use ibuilder_a64::asm::{self, b};

pub static PORT: GamePort = GamePort {
    profile: "0400C3F00006E000",
    digest: "236905b34e8165d7",
    frame_step: &[],
    stubs: &[],
    match_frame_step: &[(
        "main",
        &[
            RulePort {
                stub: frame_step_v0,
                find: None,
            },
            RulePort {
                stub: frame_step_1_8_0,
                find: None,
            },
        ],
    )],
    match_stubs: &[],
};

fn frame_step_v0(ctx: &mut StubCtx) -> Res<()> {
    frame_step(ctx, 0xa0)
}

fn frame_step_1_8_0(ctx: &mut StubCtx) -> Res<()> {
    frame_step(ctx, 0xa4)
}

/// `frame_step(ctx, at)`: the mode load at `base + at`, the interval store 0x9c after it
fn frame_step(ctx: &mut StubCtx, at: i64) -> Res<()> {
    let (site, interval) = (ctx.base + at, ctx.base + at + 0x9c);
    ctx.step_max = 2; // the stub caps the step at the game's own intervals: the host holds frames at most 2 vsyncs, or hold 3 played at 2/3 speed and the debt it paid back was lost
    ctx.site(site, "681242b9")?; // ldr w8,[x19,#0x210]
    ctx.site(interval, "681602b9")?; // str w8,[x19,#0x214]: the interval, then the frame goes on
    let start = ctx.here();
    let st = ctx.state;
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xb9400211u32, // ldr w17,[x16]          target fps (0 = off)
        0x34000211,    // cbz w17,orig (+16)
        0xb9421268,    // ldr w8,[x19,#0x210]    the game's frame mode
        0x7100091f,    // cmp w8,#2
        0x54000100,    // b.eq fixed (+8)        its 30 fps mode
        0xb900261f,    // str wzr,[x16,#0x24]    no step the game fixes
        0xb9402211,    // ldr w17,[x16,#0x20]    step in vsyncs
        0x34000151,    // cbz w17,orig (+10)     not decided yet
        0x52800048,    // mov w8,#2
        0x71000a3f,    // cmp w17,#2
        0x1a889228,    // csel w8,w17,w8,ls      at most 2
        0x14000002,    // b count (+2)
        0xb9002608,    // fixed: str w8,[x16,#0x24]   the host holds 2 vsyncs
        0xf9401a11,    // count: ldr x17,[x16,#0x30]
        0x8b284231,    // add x17,x17,w8,uxtw
        0xf9001a11,    // str x17,[x16,#0x30]    vsyncs stepped
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), interval)?;
    ctx.emit(w);
    ctx.emit(0xb9421268);
    let w = b(ctx.here(), site + 4)?; // orig: ldr w8,[x19,#0x210]; back
    ctx.emit(w);
    let w = b(site, start)?;
    ctx.put(site, &[w], "frame interval: the host's step, at most 2, unless the game's 30 fps mode is set (state page target fps; 0 = the game's choice by CPU time)");
    Ok(())
}
