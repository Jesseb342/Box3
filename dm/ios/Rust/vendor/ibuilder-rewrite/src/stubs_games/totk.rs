//! The Legend of Zelda: Tears of the Kingdom (0100F2C0115B6000): `FRAME_STEP` (1.4.2, by build ID) and `MATCH_FRAME_STEP` (any build whose six functions match) of
//! `dm/games/0100F2C0115B6000/patches.py`. The game picks a present interval each frame and steps its game time by 60 / fps; the stub replaces that logic with the host's step
//! (int fps = 60 / step, and the float fps the same), by the measured frame time until the host has decided one, with the lead paid back by later frames; prerendered movies hold 30,
//! the D-pad menu fade starts at full rate and the swapchain argument becomes 1 (FPSLocker's fixes), and the render scale (state +0x10) sizes each view.

use crate::Res;
use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::{GamePort, word_hex};
use ibuilder_a64::asm::{self, NOP, b, stp_pre};

pub static PORT: GamePort = GamePort {
    profile: "0100F2C0115B6000",
    digest: "5536d41bd577a0d6",
    frame_step: &[("5cb42b1cf25469fb0635fd046453d843", frame_step_1_4_2)],
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

const B1: [u32; 16] = [
    0xbd400200, // ldr s0,[x16]           target fps
    0x1e202008, // fcmp s0,#0.0
    0x54000640, // b.eq off (+50)        target 0: original path
    0xb9402202, // ldr w2,[x16,#0x20]     step in vsyncs
    0x340001a2, // cbz w2,elapsed (+13)   not decided yet: by the measured frame time
    0x1e230041, // ucvtf s1,w2
    0x1e27d003, // fmov s3,#30.0
    0x1e211872, // fdiv s18,s3,s1
    0x1e322a52, // fadd s18,s18,s18       fps = 60 / step
    0xbd002412, // str s18,[x0,#0x24]     float fps
    0x52800785, // mov w5,#60
    0x1ac208a5, // udiv w5,w5,w2
    0xb9005005, // str w5,[x0,#0x50]      integer fps
    0xf9401a04, // ldr x4,[x16,#0x30]
    0x8b224084, // add x4,x4,w2,uxtw
    0xf9001a04, // str x4,[x16,#0x30]     vsyncs stepped
];
const B2: [u32; 34] = [
    0xf9406c22, // elapsed: ldr x2,[x1,#0xd8]  last frame time in 19.2 MHz ticks
    0x9e630041, // ucvtf d1,x2
    0x529f0003, // mov w3,#0xf800
    0x72a02483, // movk w3,#0x124,lsl #16 (19,200,000)
    0x1e630062, // ucvtf d2,w3
    0x1e621821, // fdiv d1,d1,d2          elapsed seconds
    0xb9400604, // ldr w4,[x16,#4]        movie flag
    0x1e27d003, // fmov s3,#30.0
    0x7100009f, // cmp w4,#0
    0x1e201c60, // fcsel s0,s3,s0,ne      cap = movie ? 30 : target
    0x1e22c000, // fcvt d0,s0
    0x1e6e1003, // fmov d3,#1.0
    0x1e601864, // fdiv d4,d3,d0          shortest step 1 / cap
    0x1e65d005, // fmov d5,#15.0
    0x1e651865, // fdiv d5,d3,d5          longest step 1 / 15
    0xfd400606, // ldr d6,[x16,#8]        lead
    0x1e663827, // fsub d7,d1,d6
    0x1e6448e7, // fmax d7,d7,d4
    0x1e6558e7, // fmin d7,d7,d5          step = clamp(elapsed - lead)
    0x1e6728c6, // fadd d6,d6,d7
    0x1e6138c6, // fsub d6,d6,d1          lead += step - elapsed
    0x2f00e410, // movi d16,#0
    0x1e7048c6, // fmax d6,d6,d16
    0x1e6a1011, // fmov d17,#0.25
    0x1e7158c6, // fmin d6,d6,d17         lead in [0, 0.25]
    0xfd000606, // str d6,[x16,#8]
    0x1e671872, // fdiv d18,d3,d7         fps = 1 / step
    0x1e624252, // fcvt s18,d18
    0xbd002412, // str s18,[x0,#0x24]     float fps
    0x1e380245, // fcvtzs w5,s18
    0xb9005005, // str w5,[x0,#0x50]      integer fps
    0xfd400e13, // ldr d19,[x16,#0x18]
    0x1e672a73, // fadd d19,d19,d7
    0xfd000e13, // str d19,[x16,#0x18]    game seconds stepped
];
const B3: [u32; 5] = [
    0xb9400210, 0x34000070, 0x52800021, 0x14000002,
    0x3940a261, // ldr w16,[x16]; cbz w16,off; mov w1,#1; b end; off: ldrb w1,[x19,#0x28]
];
const B4: [u32; 9] = [
    0xbd401106, // ldr s6,[x8,#0x10]   render scale
    0x1e250840, // fmul s0,s2,s5       (original)
    0x1e240861, // fmul s1,s3,s4       (original)
    0x1e2020c8, // fcmp s6,#0.0
    0x5400006d, // b.le skip (+12)     not set
    0x1e260800, // fmul s0,s0,s6
    0x1e260821, // fmul s1,s1,s6
    0x52a8d008, // skip: mov w8,#0x46800000 (original)
    0x1e270104, // fmov s4,w8          (original)
];
const B5: [u32; 7] = [
    0xbd401107, // ldr s7,[x8,#0x10]
    0x1e2e1010, // fmov s16,#1.0
    0x1e3020e0, // fcmp s7,s16
    0x54000080, // b.eq done (+16)     scale 1: the game's dynamic resolution
    0x1e2020e8, // fcmp s7,#0.0
    0x5400004d, // b.le done (+8)      not set
    0x1e204206, // fmov s6,s16         a fixed scale: no dynamic multiplier
];

/// The frame step at the frame-step function (`step`), the two readers of the integer fps (`read1`, `read2`), the D-pad menu fade (`fade`), the swapchain argument (`swap`) and
/// the view render size (`view`): each patched at its own offsets. `fade_regs`: the menu entry's base register and the fade's destination, x24 and s10 on 1.4.3, x25 and s9 on 1.4.2
#[allow(clippy::too_many_arguments)] // one offset per patched site of a build; a struct would only rename the arguments
fn stub(
    ctx: &mut StubCtx,
    step: i64,
    read1: i64,
    read2: i64,
    fade: i64,
    swap: i64,
    view: i64,
    fade_regs: (u32, u32),
) -> Res<()> {
    let (base, dst) = fade_regs;
    let fmadd = 0x1f080400 | dst; // fmadd s<dst>,s0,s8,s1
    let st = ctx.state;
    // frame step (replaces ldrb w9,[x0,#0x58], the first instruction after the prologue)
    ctx.site(step + 0x18, "09604139")?;
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in B1 {
        ctx.emit(w);
    }
    let w = b(ctx.here(), step + 0x110)?; // the original epilogue
    ctx.emit(w);
    for w in B2 {
        ctx.emit(w);
    }
    let w = b(ctx.here(), step + 0x110)?; // the original epilogue
    ctx.emit(w);
    ctx.emit(0x39416009);
    let w = b(ctx.here(), step + 0x1c)?; // off: ldrb w9,[x0,#0x58]; back
    ctx.emit(w);
    let w = b(step + 0x18, start)?;
    ctx.put(step + 0x18, &[w], "frame step from the host in whole vsyncs, by elapsed time until it has decided one (state page target fps; 0 = original interval logic)");
    // the two readers of the integer fps: float fps when on; the scvtf a few instructions later moves into the stub (s0 is not touched in between)
    for (site, cvt, r) in [
        (read1 + 0x34, read1 + 0x4c, 19u32),
        (read2 + 0x4c, read2 + 0x58, 22),
    ] {
        ctx.site(site, &word_hex(0xbd425000 | r << 5))?;
        ctx.site(cvt, "00d8215e")?;
        let start = ctx.here();
        ctx.emit(stp_pre(16, 17, 31, -16));
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        for w in [
            0xb9400211u32,       // ldr w17,[x16]
            0x34000071,          // cbz w17,off (+12)
            0xbd422400 | r << 5, // ldr s0,[xR,#0x224]  float fps
            0x14000003,          // b done (+12)
            0xbd425000 | r << 5, // off: ldr s0,[xR,#0x250]  integer fps
            0x5e21d800,          // scvtf s0,s0
            0xa8c147f0,          // done: ldp x16,x17,[sp],#16
        ] {
            ctx.emit(w);
        }
        let w = b(ctx.here(), site + 4)?;
        ctx.emit(w);
        let w = b(site, start)?;
        ctx.put(
            site,
            &[w],
            "game step reads the float fps (original integer fps and scvtf when off)",
        );
        ctx.put(cvt, &[NOP], "scvtf moved into the stub at the load");
    }
    // D-pad menu fade (w8 is overwritten right after the site)
    ctx.site(fade + 0x130, &(String::from("0820201e") + &word_hex(fmadd)))?;
    let start = ctx.here();
    let w = asm::adrp(8, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xb9400108u32,
        0x340001a8, // ldr w8,[x8]; cbz w8,off (+52)
        0x1e202028,
        0x54000101, // fcmp s1,#0.0; b.ne go
        0x785fa008 | base << 5,
        0x7100151f,
        0x540000a1, // ldurh w8,[x<base>,#-6]; cmp w8,#5; b.ne go
        0x785f8008 | base << 5,
        0x7100151f,
        0x54000041, // ldurh w8,[x<base>,#-8]; cmp w8,#5; b.ne go
        0x1e2e1008, // fmov s8,#1.0
        fmadd,
        0x1e202008,
        0x14000003, // go: fmadd s<dst>,s0,s8,s1; fcmp s0,#0.0; b end
        0x1e202008,
        fmadd, // off: the original fcmp s0,#0.0; fmadd s<dst>,s0,s8,s1
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), fade + 0x138)?;
    ctx.emit(w);
    let w = b(fade + 0x130, start)?;
    ctx.put(
        fade + 0x130,
        &[w, NOP],
        "D-pad menu fade starts at full rate under fractional steps (FPSLocker)",
    );
    // swapchain argument (x16 is dead before the bl that follows)
    ctx.site(swap + 0x1a4, "61a24039")?;
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in B3 {
        ctx.emit(w);
    }
    let w = b(ctx.here(), swap + 0x1a8)?;
    ctx.emit(w);
    let w = b(swap + 0x1a4, start)?;
    ctx.put(
        swap + 0x1a4,
        &[w],
        "swapchain argument 1 when on (FPSLocker)",
    );
    // Render scale (state +0x10, float written by the loader: DM_RENDER_SCALE, 1.0 by default). main+0xd5c24 sizes each view: screen size x the view's scale (5/6 for the scene: 1600x896
    // docked) x the dynamic-resolution multiplier, clamped to 8..16384 and floored to the view's alignment. The stub multiplies both extents by the factor (s6, w8 and the flags are dead
    // at main+0xd5cc0: s6 is set to 8.0 right after); any factor but 1.0 also replaces the dynamic multiplier (main+0xd5d80) with 1, so the size is fixed. 1.0 = bit-exact original
    ctx.site(view + 0x9c, "08d0a8524008251e6108241e0401271e")?;
    ctx.site(view + 0x15c, "062940bd")?;
    let start = ctx.here();
    let w = asm::adrp(8, ctx.here(), st)?;
    ctx.emit(w);
    for w in B4 {
        ctx.emit(w);
    }
    let w = b(ctx.here(), view + 0xac)?;
    ctx.emit(w);
    let w = b(view + 0x9c, start)?;
    ctx.put(
        view + 0x9c,
        &[w],
        "view render size x the host render scale (1.0 = original)",
    );
    ctx.render_scale = 1;
    let start = ctx.here();
    ctx.emit(0xbd402906); // ldr s6,[x8,#0x28] (original: the dynamic multiplier); x8 is dead after it
    let w = asm::adrp(8, ctx.here(), st)?;
    ctx.emit(w);
    for w in B5 {
        ctx.emit(w);
    }
    let w = b(ctx.here(), view + 0x160)?;
    ctx.emit(w);
    let w = b(view + 0x15c, start)?;
    ctx.put(
        view + 0x15c,
        &[w],
        "dynamic resolution only at render scale 1.0",
    );
    Ok(())
}

/// Any build whose six functions match: all or nothing, as the readers without the step (or the step without them) run the game at the wrong speed (the locator prints a red
/// line for the one not found)
fn matched_frame_step(ctx: &mut StubCtx) -> Res<()> {
    let parts: Vec<Option<i64>> = [
        "game step reader 1",
        "game step reader 2",
        "menu fade",
        "swapchain argument",
        "view render size",
    ]
    .iter()
    .map(|k| ctx.other(k))
    .collect();
    let [Some(r1), Some(r2), Some(fade), Some(swap), Some(view)] = parts[..] else {
        return Ok(());
    };
    let base = ctx.base;
    stub(ctx, base, r1, r2, fade, swap, view, (24, 10))
}

/// Tears of the Kingdom 1.4.2 (main 5cb42b1c...) is packed from a derived profile and has no match rule of its own, so its functions are named by offset
fn frame_step_1_4_2(ctx: &mut StubCtx) -> Res<()> {
    stub(
        ctx,
        0x2d4e50,
        0x2d46fc,
        0x37ea10,
        0x387260,
        0xbbf0b4,
        0x102470,
        (25, 9),
    )
}
