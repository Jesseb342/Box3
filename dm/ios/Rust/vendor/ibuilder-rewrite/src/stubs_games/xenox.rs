//! Xenoblade Chronicles X: Definitive Edition (0100453019AA8000): `MATCH_STUBS` of `dm/games/0100453019AA8000/patches.py`: the orbit camera integrates its configured angular
//! speed once per update; the stub multiplies the loaded gain by the game's own 30 Hz elapsed-time ratio. (Its `CUTS` / `MATCH_CUTS` are data, in `tables.rs`.)
//! The rule has `fps_required`: native engine frame targets stay off unless the stub installs every correction (`ctx.fps_ready`).

use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::GamePort;
use crate::{Fail, Res};
use ibuilder_a64::asm::{self, b, ldrx};

pub static PORT: GamePort = GamePort {
    profile: "0100453019AA8000",
    digest: "f435a833d11b6ac0",
    frame_step: &[],
    stubs: &[],
    match_frame_step: &[],
    match_stubs: &[(
        "main",
        &[RulePort {
            stub: camera_step,
            find: None,
        }],
    )],
};

/// Integrate stick-driven camera rotation with the game's elapsed frame time. The orbit controller curves each stick axis, then multiplies both angles by its configured
/// common gain. That gain was applied once per update at the original 30 fps. Scale the loaded gain, keeping the input curve, saved sensitivities and parameter table
/// unchanged. The task's own timing routine clamps elapsed seconds to [1/fps, 2/fps], with fps = 60/(interval or 2).
pub fn camera_step(ctx: &mut StubCtx) -> Res<()> {
    let (Some(setter), Some(elapsed_fn), Some(_)) = (
        ctx.other("interval setter"),
        ctx.other("elapsed seconds"),
        ctx.other("clamped task step"),
    ) else {
        return Ok(());
    };
    // the setter interleaves two ADRPs with their two loads; its first pair addresses the GOT slot pointing to the live interval, not a fixed global
    let interval = ctx.address(setter, Some(setter + 8))?;
    let elapsed = ctx.address(elapsed_fn, None)?;
    if !(interval % 8 == 0 && elapsed % 8 == 0) {
        return Err(Fail::new("AssertionError"));
    }
    let site = ctx.base + 0x1ec;
    ctx.site(site, "a8b640bd")?; // ldr s8,[x21,#0xb4]: common angular gain
    let start = ctx.here();
    ctx.emit(0xbd40b6a8); // the original gain load
    let w = asm::adrp(8, ctx.here(), interval)?;
    ctx.emit(w);
    ctx.emit(ldrx(8, 8, ((interval & 0xfff) / 8) as u32)); // GOT -> interval pointer
    for word in [
        0xb9400108u32, // ldr w8,[x8]
        0x7100011f,    // cmp w8,#0
        0x52800049,    // mov w9,#2
        0x1a880128,    // csel w8,w9,w8,eq
        0x52800789,    // mov w9,#60
        0x1ac80d28,    // sdiv w8,w9,w8: fps
        0x1e220101,    // scvtf s1,w8
        0x1e2e1002,    // fmov s2,#1
        0x1e211841,    // fdiv s1,s2,s1: nominal seconds
    ] {
        ctx.emit(word);
    }
    let w = asm::adrp(8, ctx.here(), elapsed)?;
    ctx.emit(w);
    ctx.emit(ldrx(8, 8, ((elapsed & 0xfff) / 8) as u32)); // frame object pointer
    for word in [
        0x1e204022u32, // fmov s2,s1: absent frame object clamps to nominal
        0xb4000048,    // cbz x8,+8
        0xbd626d02,    // ldr s2,[x8,#0x226c]: elapsed seconds
        0x1e212825,    // fadd s5,s1,s1: upper bound
        0x1e252040,    // fcmp s2,s5
        0x1e22cca5,    // fcsel s5,s5,s2,gt
        0x1e212040,    // fcmp s2,s1
        0x1e254c22,    // fcsel s2,s1,s5,mi
        0x1e27d001,    // fmov s1,#30
        0x1e210842,    // fmul s2,s2,s1: 30 Hz frame ratio
        0x1e220908,    // fmul s8,s8,s2: integrate angular speed
    ] {
        ctx.emit(word);
    }
    let w = b(ctx.here(), site + 4)?;
    ctx.emit(w);
    // x8/x9 and s1/s2/s5 are overwritten before use after this site in both reviewed bodies; the next FCMP replaces flags before a conditional use
    let w = b(site, start)?;
    ctx.put(
        site,
        &[w],
        "camera angular integration: use the game's clamped elapsed frame time",
    );
    ctx.fps_ready = true;
    Ok(())
}
