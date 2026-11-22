//! The Legend of Zelda: Ocarina of Time (Switch 2, 0400486024DEC000): `FRAME_STEP` (the v131072 main's build ID) and `MATCH_FRAME_STEP` (the same stubs found by their
//! functions' fingerprints) of `dm/games/0400486024DEC000/patches.py`: the frame ratio from the host's step, the dynamic resolution, and the screen shape stubs
//! (`_camera_aspect`: widescreen / Hor+ for `screen_aspect wide`, the `ANAMORPHIC_ASPECT` capability) that only the build-ID form has.

use crate::Res;
use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::{GamePort, f32_bits, word_hex};
use ibuilder_a64::asm::{self, b};

pub static PORT: GamePort = GamePort {
    profile: "0400486024DEC000",
    digest: "0b2386f18f0034bd",
    frame_step: &[("e0f3ccfaf50065ae4ea01eb5aeb13b1a", frame_step_v131072)],
    stubs: &[],
    match_frame_step: &[(
        "main",
        &[RulePort {
            stub: ocarina_frame_step,
            find: None,
        }],
    )],
    match_stubs: &[],
};

/// `frame_step_v131072`: the registered build's stubs: its three functions at their v131072 offsets, then the screen shape stubs
pub fn frame_step_v131072(ctx: &mut StubCtx) -> Res<()> {
    ctx.base = 0x6e6be0;
    ctx.others = vec![
        ("dynamic resolution", Some(0x8065e0)),
        ("dynamic resolution update", Some(0x805aa0)),
    ];
    ocarina_frame_step(ctx)?;
    camera_aspect(ctx)
}

/// the frame ratio: the function divides its base rate (60.0, or 30.0 while bit 0 of [x21+0x24f] is set) by the int frame rate at [x21+0x2c8] (fdiv s8,s1,s0 at +0xe4);
/// the stub gives the ratio the host's step instead: step x base / 60, and counts the vsyncs stepped. Until the host has decided a step, and at fps_target 0, the division runs
pub fn ocarina_frame_step(ctx: &mut StubCtx) -> Res<()> {
    let (st, base) = (ctx.state, ctx.base);
    let site = base + 0xe4;
    ctx.site(site, "2818201e")?; // fdiv s8,s1,s0
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xb9400211u32, // ldr w17,[x16]          target fps (0 = off)
        0x340001b1,    // cbz w17,orig (+13)
        0xb9402211,    // ldr w17,[x16,#0x20]    step in vsyncs
        0x34000171,    // cbz w17,orig (+11)     not decided yet
        0x1e230220,    // ucvtf s0,w17
        0xf9401a10,    // ldr x16,[x16,#0x30]
        0x8b110210,    // add x16,x16,x17
    ] {
        ctx.emit(w);
    }
    let w = asm::adrp(17, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xf9001a30u32, // str x16,[x17,#0x30]    vsyncs stepped
        0x1e210808,    // fmul s8,s0,s1          step x base rate
        0x52a84e10,    // mov w16,#0x42700000    60.0
        0x1e270200,    // fmov s0,w16
        0x1e201908,    // fdiv s8,s8,s0          / 60
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), site + 4)?;
    ctx.emit(w);
    ctx.emit(0x1e201828); // orig: fdiv s8,s1,s0; back
    let w = b(ctx.here(), site + 4)?;
    ctx.emit(w);
    let w = b(site, start)?;
    ctx.put(site, &[w], "frame ratio: the host's step \u{d7} base rate / 60 instead of base rate / the game's frame rate (state page target fps; 0 = the game's ratio)");
    ocarina_dynamic_resolution(ctx)
}

/// the level function of the game's dynamic resolution, held at full resolution (state +0x40 = 0) or climbing on the load measured at each level (DM_DYNAMIC_RESOLUTION)
const DRS_CONTROLLER: [u32; 61] = [
    0xb9404211, 0x35000071, 0x2a1f03e0, 0xd65f03c0, 0xbd400800, 0xbd401001, 0xb9417402, 0xb941a003,
    0x7100005f, 0x1a9fa042, 0x528001e9, 0x6b09005f, 0x1a89d042, 0xb9420204, 0x11000484, 0xb9020204,
    0xb9420605, 0xb9420a06, 0x6b0200bf, 0x1a8617e6, 0xb9020602, 0xb9020a06, 0x35000046, 0xb9020e1f,
    0x91084207, 0x91094208, 0x710020df, 0x5400040b, 0x1e212000, 0x540001ad, 0xb9420e0b, 0x1100056b,
    0xb9020e0b, 0x7100217f, 0x5400032b, 0xbc2258e0, 0xb8225904, 0x51000469, 0x1100044a, 0x6b09015f,
    0x1a89d140, 0xd65f03c0, 0xb9020e1f, 0xbc2258e0, 0xb8225904, 0x34000182, 0x51000449, 0xb869590a,
    0x340000ea, 0x4b0a008a, 0x7109615f, 0x54000088, 0xbc6958e2, 0x1e212040, 0x540000aa, 0x2a0903e0,
    0xd65f03c0, 0x2a1f03e0, 0xd65f03c0, 0x2a0203e0, 0xd65f03c0,
];

fn ocarina_dynamic_resolution(ctx: &mut StubCtx) -> Res<()> {
    let st = ctx.state;
    // not both found in this build (a red line from the locator): the game's own dynamic resolution
    let (Some(site), Some(_)) = (
        ctx.other("dynamic resolution"),
        ctx.other("dynamic resolution update"),
    ) else {
        return Ok(());
    };
    ctx.site(site, "017c40bd")?; // ldr s1,[x0,#0x7c]
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in DRS_CONTROLLER {
        ctx.emit(w);
    }
    let w = b(site, start)?;
    ctx.put(site, &[w], "dynamic resolution level: 0 (full resolution), or with state +0x40 (DM_DYNAMIC_RESOLUTION) a climb on the load measured at each level");
    ctx.add_capability("DYNAMIC_RESOLUTION");
    Ok(())
}

// ---- the screen shape stubs (`_camera_aspect` and its helpers) ----

const ASPECT_STATE: i64 = 0xa4; // loader.c writes float ow / 1080.0f here when DM_SCREEN_ASPECT >= 1.8 (0 = 16:9)
const ASPECT_ACK: i64 = 0x284;
const PROJECTION_ACK: i64 = 0x288; // one last-applied aspect per camera site

fn addi(rd: u32, rn: u32, imm: u32) -> u32 {
    0x91000000 | ((imm & 0xfff) << 10) | (rn << 5) | rd
}
fn movz(wd: u32, imm: u32) -> u32 {
    0x52800000 | ((imm & 0xffff) << 5) | wd
}
fn movk16(wd: u32, imm: u32) -> u32 {
    0x72a00000 | ((imm & 0xffff) << 5) | wd
}
fn fmov_sw(sd: u32, wn: u32) -> u32 {
    0x1e270000 | (wn << 5) | sd
}
fn fsub(sd: u32, sn: u32, sm: u32) -> u32 {
    0x1e203800 | (sm << 16) | (sn << 5) | sd
}
fn fabs(sd: u32, sn: u32) -> u32 {
    0x1e20c000 | (sn << 5) | sd
}
fn fcmp(sn: u32, sm: u32) -> u32 {
    0x1e202000 | (sm << 16) | (sn << 5)
}
fn ldr_s(st: u32, xn: u32, off: u32) -> u32 {
    0xbd400000 | ((off / 4) << 10) | (xn << 5) | st
}
fn ldar_w(wt: u32, xn: u32) -> u32 {
    0x88dffc00 | (xn << 5) | wt
}
fn stlr_w(wt: u32, xn: u32) -> u32 {
    0x889ffc00 | (xn << 5) | wt
}
fn str_s(st: u32, xn: u32, off: u32) -> u32 {
    0xbd000000 | ((off / 4) << 10) | (xn << 5) | st
}
fn cbz_w(wt: u32, frm: i64, to: i64) -> u32 {
    0x34000000 | ((((to - frm) >> 2) & 0x7ffff) as u32) << 5 | wt
}
fn b_cond(frm: i64, to: i64, cond: u32) -> u32 {
    0x54000000 | ((((to - frm) >> 2) & 0x7ffff) as u32) << 5 | cond
}

fn load_f32(words: &mut Vec<u32>, reg: u32, value: f64) {
    let bits = f32_bits(value);
    words.extend([movz(16, bits), movk16(16, bits >> 16), fmov_sw(reg, 16)]);
}

fn state_addr(ctx: &StubCtx, words: &mut Vec<u32>, reg: u32, off: i64) -> Res<()> {
    let pc = ctx.here() + words.len() as i64 * 4;
    words.extend([
        asm::adrp(reg, pc, ctx.state + off)?,
        addi(reg, reg, ((ctx.state + off) & 0xfff) as u32),
    ]);
    Ok(())
}

fn append_stub(
    ctx: &mut StubCtx,
    site: i64,
    original: usize,
    words: &[u32],
    reason: &str,
) -> Res<()> {
    let start = ctx.here();
    for &w in words {
        ctx.emit(w);
    }
    let w = b(ctx.here(), site + 4 * original as i64)?;
    ctx.emit(w);
    let mut put = vec![b(site, start)?];
    put.extend(std::iter::repeat_n(0xd503201fu32, original - 1));
    ctx.put(site, &put, reason);
    Ok(())
}

fn projection(
    ctx: &mut StubCtx,
    site: i64,
    original: u32,
    base: u32,
    aspect_reg: u32,
    projection_ack: i64,
) -> Res<()> {
    ctx.site(site, &word_hex(original))?;
    let mut w = vec![original];
    load_f32(&mut w, 16, 16.0 / 9.0);
    w.extend([fsub(17, aspect_reg, 16), fabs(17, 17)]);
    load_f32(&mut w, 16, 0.01);
    w.push(fcmp(17, 16));
    let stock = w.len();
    w.push(0);
    state_addr(ctx, &mut w, 17, projection_ack)?;
    w.push(ldar_w(16, 17));
    let no_ack = w.len();
    w.push(0);
    w.push(fmov_sw(16, 16));
    w.extend([fsub(17, aspect_reg, 16), fabs(17, 17)]);
    load_f32(&mut w, 16, 0.01);
    w.push(fcmp(17, 16));
    let stale = w.len();
    w.push(0);
    let apply = w.len();
    state_addr(ctx, &mut w, 17, ASPECT_STATE)?;
    w.push(ldar_w(16, 17));
    let disabled = w.len();
    w.push(0);
    w.push(fmov_sw(aspect_reg, 16));
    w.push(str_s(aspect_reg, base, 176));
    state_addr(ctx, &mut w, 17, ASPECT_ACK)?;
    w.push(stlr_w(16, 17));
    state_addr(ctx, &mut w, 17, projection_ack)?;
    w.push(stlr_w(16, 17));
    let skip_restore = w.len();
    w.push(0);
    let disabled_at = w.len();
    load_f32(&mut w, aspect_reg, 16.0 / 9.0);
    w.push(str_s(aspect_reg, base, 176));
    w.push(0x2a1f03f0);
    state_addr(ctx, &mut w, 17, ASPECT_ACK)?;
    w.push(stlr_w(16, 17));
    state_addr(ctx, &mut w, 17, projection_ack)?;
    w.push(stlr_w(16, 17));
    let end = w.len();
    let h = ctx.here();
    let at = |i: usize| h + i as i64 * 4;
    w[stock] = b_cond(at(stock), at(apply), 3);
    w[no_ack] = cbz_w(16, at(no_ack), at(end));
    w[stale] = b_cond(at(stale), at(end), 2);
    w[disabled] = cbz_w(16, at(disabled), at(disabled_at));
    w[skip_restore] = b(at(skip_restore), at(end))?;
    append_stub(
        ctx,
        site,
        1,
        &w,
        "camera projection: use drawable aspect for 16:9 views, restore stock ratio when disabled",
    )
}

/// `_camera_aspect`: adapted by the engine from craftycorvid/oot-mod (MIT) for 0400486024DEC000 v131072 main
fn camera_aspect(ctx: &mut StubCtx) -> Res<()> {
    for (i, (site, original, base, areg)) in [
        (0x3485cc0i64, 0x2d558400u32, 0u32, 1u32),
        (0x004f1e8, 0x2d558ea0, 21, 3),
        (0x023b9a8, 0x2d558c00, 0, 3),
        (0x033b82c, 0x2d558440, 2, 1),
    ]
    .into_iter()
    .enumerate()
    {
        projection(
            ctx,
            site,
            original,
            base,
            areg,
            PROJECTION_ACK + i as i64 * 4,
        )?;
    }

    // render-view aspect
    let site = 0x025d76ci64;
    let orig = [0x1e2202a1u32, 0x1e221821];
    ctx.site(site, &(word_hex(orig[0]) + &word_hex(orig[1])))?;
    let mut w = orig.to_vec();
    load_f32(&mut w, 16, 16.0 / 9.0);
    w.extend([fsub(17, 1, 16), fabs(17, 17)]);
    load_f32(&mut w, 16, 0.01);
    w.push(fcmp(17, 16));
    let skip_view = w.len();
    w.push(0);
    state_addr(ctx, &mut w, 17, ASPECT_STATE)?;
    w.push(ldar_w(16, 17));
    let skip_off = w.len();
    w.push(0);
    w.push(fmov_sw(1, 16));
    let end = w.len();
    let h = ctx.here();
    w[skip_view] = b_cond(h + skip_view as i64 * 4, h + end as i64 * 4, 2);
    w[skip_off] = cbz_w(16, h + skip_off as i64 * 4, h + end as i64 * 4);
    append_stub(
        ctx,
        site,
        orig.len(),
        &w,
        "render-view aspect: match the widened camera on the output view",
    )?;

    // full-screen 2D layout
    let site = 0x0774368i64;
    let orig_w = 0xad401041u32;
    ctx.site(site, &word_hex(orig_w))?;
    let mut w = vec![
        orig_w,
        0x1e260030,
        movz(17, f32_bits(2.0 / 3840.0)),
        movk16(17, f32_bits(2.0 / 3840.0) >> 16),
        0x6b11021f,
    ];
    let ne_x = w.len();
    w.push(0);
    w.extend([
        0x0e0c3c00 | (4 << 5) | 16,
        0x12007800 | (16 << 5) | 16,
        movz(17, f32_bits(2.0 / 2160.0)),
        movk16(17, f32_bits(2.0 / 2160.0) >> 16),
        0x6b11021f,
    ]);
    let ne_y = w.len();
    w.push(0);
    w.extend([0xd1000000 | (0x1b8 << 10) | 17, 0xf9400000 | (17 << 5) | 16]);
    let mut bg_branches = Vec::new();
    for vt in [0x4bed098i64, 0x4be4fb0, 0x4be7b30, 0x4be61c8] {
        let pc = ctx.here() + w.len() as i64 * 4;
        w.extend([
            asm::adrp(17, pc, vt)?,
            addi(17, 17, (vt & 0xfff) as u32),
            0xeb00001f | (17 << 16) | (16 << 5),
            0x54000000,
        ]);
        bg_branches.push(w.len() - 1);
    }
    state_addr(ctx, &mut w, 17, ASPECT_STATE)?;
    w.push(ldar_w(16, 17));
    let zero = w.len();
    w.push(0);
    let bits = f32_bits(16.0 / 9.0);
    w.extend([
        movz(17, bits),
        movk16(17, bits >> 16),
        fmov_sw(17, 17),
        fmov_sw(18, 16),
        0x1e201800 | (18 << 16) | (17 << 5) | 18,
        0x1e260000 | (18 << 5) | 16,
        0x4e040c00 | (16 << 5) | 17,
        0x6e20dc00 | (17 << 16) | (1 << 5) | 1,
    ]);
    let end = w.len();
    let h = ctx.here();
    let at = |i: usize| h + i as i64 * 4;
    w[ne_x] = b_cond(at(ne_x), at(end), 1);
    w[ne_y] = b_cond(at(ne_y), at(end), 1);
    w[zero] = cbz_w(16, at(zero), at(end));
    for i in bg_branches {
        w[i] = b_cond(at(i), at(end), 0);
    }
    append_stub(
        ctx,
        site,
        1,
        &w,
        "full-screen 2D layout: keep the HUD at 16:9 when the picture fills a wider drawable",
    )?;

    // movie viewport
    let site = 0x3b5c758i64;
    let orig_w = 0xa941a269u32;
    ctx.site(site, &word_hex(orig_w))?;
    let mut w = vec![
        0xd1000000 | (40 << 10) | (29 << 5) | 14,
        ldr_s(22, 14, 8),
        ldr_s(23, 14, 16),
        0x1e203800 | (22 << 16) | (23 << 5) | 18,
    ];
    state_addr(ctx, &mut w, 17, ASPECT_STATE)?;
    w.push(ldar_w(16, 17));
    let no_wide = w.len();
    w.push(0);
    w.push(fmov_sw(19, 16));
    load_f32(&mut w, 20, 16.0 / 9.0);
    w.push(0x1e201800 | (19 << 16) | (20 << 5) | 20);
    load_f32(&mut w, 21, 1.0);
    w.push(fsub(20, 21, 20));
    load_f32(&mut w, 21, 0.5);
    w.extend([
        0x1e200800 | (21 << 16) | (20 << 5) | 20,
        0x1e200800 | (20 << 16) | (18 << 5) | 18,
        0x1e202800 | (18 << 16) | (22 << 5) | 22,
        0x1e203800 | (18 << 16) | (23 << 5) | 23,
        str_s(22, 14, 8),
        str_s(23, 14, 16),
    ]);
    let end = w.len();
    let h = ctx.here();
    w[no_wide] = cbz_w(16, h + no_wide as i64 * 4, h + end as i64 * 4);
    w.push(orig_w);
    append_stub(
        ctx,
        site,
        1,
        &w,
        "movie viewport: letterbox pre-rendered movies within the centred 16:9 HUD",
    )?;

    // speech bubble anchor
    let site = 0x020c2b0i64;
    let orig_w = 0x52a89e08u32;
    ctx.site(site, &word_hex(orig_w))?;
    let mut w = Vec::new();
    state_addr(ctx, &mut w, 17, ASPECT_STATE)?;
    w.push(ldar_w(16, 17));
    let no_wide = w.len();
    w.push(0);
    w.push(fmov_sw(16, 16));
    load_f32(&mut w, 17, 1080.0);
    w.extend([
        0x1e200800 | (17 << 16) | (16 << 5) | 16,
        0x1e260000 | (16 << 5) | 8,
    ]);
    let end = w.len();
    let h = ctx.here();
    w[no_wide] = cbz_w(16, h + no_wide as i64 * 4, h + end as i64 * 4);
    w.push(orig_w);
    append_stub(
        ctx,
        site,
        1,
        &w,
        "speech bubble anchor: keep the bubble over the speaker when the HUD is centred",
    )?;

    ctx.add_capability("ANAMORPHIC_ASPECT");
    Ok(())
}
