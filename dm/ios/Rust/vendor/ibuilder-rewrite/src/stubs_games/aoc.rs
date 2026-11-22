//! Hyrule Warriors: Age of Calamity (01002B00111A2000): `FRAME_STEP` (1.3.0, by build ID: the addresses found there) and `MATCH_FRAME_STEP` (any other build, placed by its
//! four functions) of `dm/games/01002B00111A2000/patches.py`. The game steps a fixed amount per update from two 30 fps values; its updates are not held by the presents, so the
//! stubs run them at the cap and the host's frame step paces only the presents: the KIDS frame task's fps and the frame-rate block become the cap, the update's vsyncs are marked
//! (+0x28) and the device frame rate becomes 59.94 / those vsyncs; the object's steps are scaled by its fps x vsyncs / 60 and the vsyncs are counted; the event cutscenes' two
//! counters move on every other update at a 60 fps cap.

use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::{GamePort, f32_bits};
use crate::{Fail, Res};
use ibuilder_a64::asm::{self, b};

pub static PORT: GamePort = GamePort {
    profile: "01002B00111A2000",
    digest: "4d29f25150d5d6ab",
    frame_step: &[("c3cf52bf2b05d7310884971b50bcccb8", frame_step_1_3_0)],
    stubs: &[],
    match_frame_step: &[(
        "main",
        &[RulePort {
            stub: matched_frame_step,
            find: None,
        }],
    )],
    match_stubs: &[],
};

/// The frame step at the KIDS frame task (`kids`), nnMain's device config (`nn_main`), the scene update's event counters (`scene`), the game's frame-rate block (`block`: its four
/// words) and the global holding the KTGL device (`device`); `rate` is 59.94's float in read-only data, or None to make it in a register (one instruction more)
fn stub(
    ctx: &mut StubCtx,
    kids: i64,
    nn_main: i64,
    scene: i64,
    block: i64,
    device: i64,
    rate: Option<i64>,
) -> Res<()> {
    if !(block % 4 == 0 && (block & 0xfff) + 0xc < 0x1000 && device % 8 == 0) {
        return Err(Fail::new("AssertionError"));
    }
    let more: u32 = if rate.is_some() { 0 } else { 1 }; // the forward branches over the device part
    let st = ctx.state;
    let (s_task, s_steps, s_device) = (kids + 0x134, kids + 0x2e0, nn_main + 0x1e60);
    ctx.site(s_task, "68734339")?;
    ctx.site(s_steps, "e83640b9")?;
    ctx.site(s_device, "4900c0f2")?;
    // nnMain builds KTGL's device config on its stack and inits the device once: {1920, 1080, 3, 9, 5, interval 2, 9, ...}. The device keeps the interval and its frame rate,
    // 59.94 / interval. Interval 1 above a 30 fps cap (the engine's own 60 fps mode), else the game's 2. x16, x17 and the flags are dead up to the init call
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xb9400210u32, // ldr w16,[x16]          target fps (float bits)
        0x52a83e11,    // mov w17,#0x41f00000    30.0
        0x6b11021f,    // cmp w16,w17
        0x5400006d,    // b.le two (+3)
        0xf2c00029,    // movk x9,#0x1,lsl #32   interval 1
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), s_device + 4)?;
    ctx.emit(w);
    ctx.emit(0xf2c00049); // two: movk x9,#0x2,lsl #32 (the original)
    let w = b(ctx.here(), s_device + 4)?;
    ctx.emit(w);
    let w = b(s_device, start)?;
    ctx.put(s_device, &[w], "KTGL device config present interval: 1 above a 30 fps cap, else the game's 2 (state page target fps)");
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xbd400210u32, // ldr s16,[x16]          target fps (0 = off)
        0x1e202208,    // fcmp s16,#0.0
        0x540001ad,    // b.le off (+13)
        0x1e380208,    // fcvtzs w8,s16          the cap
        0xb9003268,    // str w8,[x19,#0x30]     the task's fps
        0x52800791,    // mov w17,#60
        0x1ac80a31,    // udiv w17,w17,w8        vsyncs per update
        0xb9002a11,    // str w17,[x16,#0x28]    this update's vsyncs (on)
    ] {
        ctx.emit(w);
    }
    let w = asm::adrp(16, ctx.here(), block)?;
    ctx.emit(w);
    let lo = (block & 0xfff) as u32;
    for w in [
        0xb9000208 | (lo / 4) << 10, // str w8,[x16,#lo]       the game's frame-rate block: fps
        0xb9000211 | ((lo + 4) / 4) << 10, // str w17,[x16,#lo+4]    interval
        0xb9000208 | ((lo + 8) / 4) << 10, // str w8,[x16,#lo+8]     fps
        0x1e220111,                  // scvtf s17,w8
        0xbd000211 | ((lo + 12) / 4) << 10, // str s17,[x16,#lo+12]   float fps (the battle's step is 1 / it)
        0x14000007,                         // b dev (+7)
        0xb9002a1f,                         // off: str wzr,[x16,#0x28]
        0xb9403268,                         // ldr w8,[x19,#0x30]     the game's fps
        0x34000008 | (12 + more) << 5,      // cbz w8,orig
        0x52800791,                         // mov w17,#60
        0x1ac80a31,                         // udiv w17,w17,w8        vsyncs per update at that fps
        0x34000011 | (9 + more) << 5,       // cbz w17,orig
    ] {
        ctx.emit(w);
    }
    let w = asm::adrp(16, ctx.here(), device)?; // dev:
    ctx.emit(w);
    for w in [
        0xf9400210 | (((device & 0xfff) / 8) as u32) << 10, // ldr x16,[x16,#lo]     the KTGL device
        0xb4000010 | (6 + more) << 5,                       // cbz x16,orig
    ] {
        ctx.emit(w);
    }
    if let Some(rate) = rate {
        let w = asm::adrp(8, ctx.here(), rate)?;
        ctx.emit(w);
        ctx.emit(0xbd400110 | (((rate & 0xfff) / 4) as u32) << 10); // ldr s16,[x8,#lo]  59.94
    } else {
        let bits = f32_bits(59.94);
        ctx.emit(0x52800008 | (bits & 0xffff) << 5);
        ctx.emit(0x72a00008 | (bits >> 16) << 5);
        ctx.emit(0x1e270110); // mov / movk w8; fmov s16,w8: 59.94
    }
    for w in [
        0x1e230231u32, // ucvtf s17,w17
        0x1e311a10,    // fdiv s16,s16,s17
        0xbd32d210,    // str s16,[x16,#0x32d0]  the device frame rate
        0x39437368,    // orig: ldrb w8,[x27,#0xdc]
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), s_task + 4)?;
    ctx.emit(w);
    let w = b(s_task, start)?;
    ctx.put(s_task, &[w], "KIDS frame task: fps and the frame-rate block = the cap, vsyncs per update marked; device frame rate 59.94 / vsyncs (state page target fps; 0 = the game's 30)");
    let start = ctx.here();
    ctx.emit(0xbd4036f0); // ldr s16,[x23,#0x34]    the frame-rate object's step
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xb9402a11u32, // ldr w17,[x16,#0x28]    vsyncs per update (0 = off)
        0x340001f1,    // cbz w17,off (+15)
        0xf9401a08,    // ldr x8,[x16,#0x30]
        0x8b314108,    // add x8,x8,w17,uxtw
        0xf9001a08,    // str x8,[x16,#0x30]     vsyncs stepped
        0xb9404ae8,    // ldr w8,[x23,#0x48]     the object's fps
        0x34000148,    // cbz w8,off (+10)
        0x1b087e31,    // mul w17,w17,w8
        0x1e230231,    // ucvtf s17,w17
        0x52800788,    // mov w8,#60
        0x1e230112,    // ucvtf s18,w8
        0x1e321a31,    // fdiv s17,s17,s18       its fps x vsyncs / 60
        0xbd4046e0,    // ldr s0,[x23,#0x44]
        0x1e310a10,    // fmul s16,s16,s17
        0x1e310800,    // fmul s0,s0,s17
        0x14000002,    // b out (+2)
        0xbd4046e0,    // off: ldr s0,[x23,#0x44]
        0x1e260208,    // out: fmov w8,s16
        0xb9001a68,    // str w8,[x19,#0x18]     the update's step
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), s_steps + 0xc)?;
    ctx.emit(w);
    let w = b(s_steps, start)?;
    ctx.put(s_steps, &[w], "KIDS frame task: the frame-rate object's steps \u{d7} its fps \u{d7} vsyncs per update / 60 (state page target fps; 0 = as the game sets them)");
    // In-engine cutscenes (events) count whole 30 fps frames, one per update. While an event plays, the scene's update keeps the cutscene's frame and its frames left; each update
    // adds 1 to the frame and takes 1 from the frames left, whatever the update's length, so at a 60 fps cap the cameras and animations ran at twice their speed while voices and
    // subtitles kept real time. Both counters now move on every other update at a 60 fps cap (the state page's vsyncs per update = 1, on even counted vsyncs, +0x30, which the stub
    // at main+0x166dc60 steps once per update); at a 30 fps cap or with the frame step off they move on every update, as the game does. x16, x17 and the flags are dead at both sites
    ctx.site(scene + 0x86c, "4a050011")?;
    ctx.site(scene + 0x890, "4a050051")?;
    for (site, step, what) in [
        (scene + 0x86c, 0x1100054au32, "frame"),
        (scene + 0x890, 0x5100054a, "frames left"),
    ] {
        let start = ctx.here();
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        for w in [
            0xb9402a11u32, // ldr w17,[x16,#0x28]    vsyncs per update (1 at a 60 fps cap, 2 at 30, 0 off)
            0x7100063f,    // cmp w17,#1
            0x54000061,    // b.ne step (+3)
            0xf9401a11,    // ldr x17,[x16,#0x30]    vsyncs counted
            0x37000051,    // tbnz w17,#0,back (+2)  odd: not on this update
            step,          // step: add / sub w10,w10,#1 (the original)
        ] {
            ctx.emit(w);
        }
        let w = b(ctx.here(), site + 4)?; // back
        ctx.emit(w);
        let w = b(site, start)?;
        ctx.put(site, &[w], &format!("event cutscene's {what}: stepped on every other update at a 60 fps cap (state page vsyncs per update; 30 fps frames, as on the Switch)"));
    }
    Ok(())
}

/// 1.3.0 (v327680): the addresses found there; its main is not on the drives to fingerprint, so it keeps this build entry
fn frame_step_1_3_0(ctx: &mut StubCtx) -> Res<()> {
    stub(
        ctx,
        0x166d980,
        0x8d94b0 - 0x1e60,
        0x857510,
        0x269e150,
        0x2bac798,
        Some(0x1ef5f3c),
    )
}

/// Any build whose KIDS frame task, nnMain, scene update and frame-rate block writer match: all four or nothing, as a part alone runs the game at the wrong speed (the locator
/// prints a red line for the one not found). The KTGL device's global comes from the task's own load of it (+0xd70), the frame-rate block from its writer's store of the fps
/// (+0x3c); 59.94 is made in a register
fn matched_frame_step(ctx: &mut StubCtx) -> Res<()> {
    let (Some(nn_main), Some(scene), Some(writer)) = (
        ctx.other("nnMain"),
        ctx.other("scene update"),
        ctx.other("frame-rate block writer"),
    ) else {
        return Ok(());
    };
    let kids = ctx.base;
    let block = ctx.address(writer + 0x3c, None)?;
    let device = ctx.address(kids + 0xd70, None)?;
    stub(ctx, kids, nn_main, scene, block, device, None)
}
