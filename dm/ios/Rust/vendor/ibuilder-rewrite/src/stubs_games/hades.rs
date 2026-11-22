//! Hades II (0100A00019DE0000): `MATCH_FRAME_STEP` of `dm/games/0100A00019DE0000/patches.py`, an anchored rule: the render size. The app's init sets the size of everything the
//! game draws once, right after `nn::vi::CreateLayer`: `mov x8,#0x500; movk x8,#0x2d0,lsl #32` (1280 | 720 << 32). The stub sizes it by the host's render scale (state +0x10),
//! each side rounded to a multiple of 4; 1.0, or no scale written, keeps the game's constant. Up to 3.0 (3840x2160).
//!
//! The function is found as the one that calls CreateLayer, not by its fingerprint; `find_size` checks what the stub relies on in that build's code.

use crate::matching::{Function, MatchError};
use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::{GamePort, word_hex};
use crate::{Fail, Res, hx};
use ibuilder_a64::asm::{self, b};

pub static PORT: GamePort = GamePort {
    profile: "0100A00019DE0000",
    digest: "4e3b160adf47cb59",
    frame_step: &[],
    stubs: &[],
    match_frame_step: &[(
        "main",
        &[RulePort {
            stub: render_size,
            find: Some(find_size),
        }],
    )],
    match_stubs: &[],
};

/// `is_size(words, i)`: movz xN,#0x500 then movk xN,#0x2d0,lsl #32 at words[i]: N, else None
fn is_size(w: u32, next: Option<u32>) -> Option<u32> {
    (w & 0xffffffe0 == 0xd280a000 && next == Some(0xf2c05a00 | (w & 31))).then_some(w & 31)
}

/// (offset of the size in the function, its register) after the checks of the rule; a `MatchError` otherwise
fn find_size(f: &Function) -> Result<(i64, i64), MatchError> {
    let sites: Vec<(i64, u32)> = (0..f.words.len())
        .filter_map(|i| {
            is_size(f.words[i], f.words.get(i + 1).copied()).map(|rd| (4 * i as i64, rd))
        })
        .collect();
    if sites.len() != 1 {
        return Err(MatchError(format!(
            "{} 1280x720 sizes in the function at {} (need one)",
            sites.len(),
            hx(f.start)
        )));
    }
    let (off, rd) = sites[0];
    if f.calls.len() != 1 || f.calls[0] > off {
        return Err(MatchError(format!(
            "the size at {} does not follow the one CreateLayer call ({} calls)",
            hx(f.start + off),
            f.calls.len()
        )));
    }
    let mut n = 0;
    let mut it = f.text_words().peekable();
    while let Some(w) = it.next() {
        if is_size(w, it.peek().copied()).is_some() {
            n += 1;
        }
    }
    if n != 1 {
        return Err(MatchError(format!(
            "{n} 1280x720 sizes in main's text (need one)"
        )));
    }
    if f.branch_targets().contains(&(f.start + off + 4)) {
        return Err(MatchError(format!(
            "a branch lands on the movk at {}",
            hx(f.start + off + 4)
        )));
    }
    let used = f.uses(&["x16", "x17", "v16", "v17", "v18"])?;
    if !used.is_empty() {
        return Err(MatchError(format!(
            "the function at {} uses {}, which the stub writes",
            hx(f.start),
            used.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    Ok((off, rd as i64))
}

fn render_size(ctx: &mut StubCtx) -> Res<()> {
    let Some((off, rd)) = ctx.found else {
        return Err(Fail::new(
            "TypeError: cannot unpack non-iterable NoneType object",
        ));
    };
    let rd = rd as u32;
    let site = ctx.base + off;
    ctx.site(
        site,
        &(word_hex(0xd280a000 | rd) + &word_hex(0xf2c05a00 | rd)),
    )?; // mov xN,#0x500; movk xN,#0x2d0,lsl #32
    let start = ctx.here();
    let st = ctx.state;
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    for w in [
        0xbd401210u32,   // ldr s16,[x16,#0x10]      render scale
        0x1e2e1011,      // fmov s17,#1.0
        0x1e312200,      // fcmp s16,s17
        0x540001e0,      // b.eq orig                1.0: the game's size
        0x1e202208,      // fcmp s16,#0.0
        0x540001ad,      // b.le orig                none written
        0x52802811,      // mov w17,#320
        0x1e220231,      // scvtf s17,w17
        0x1e300a31,      // fmul s17,s17,s16
        0x1e200231,      // fcvtns w17,s17           width / 4
        0x52801690,      // mov w16,#180
        0x1e220212,      // scvtf s18,w16
        0x1e300a52,      // fmul s18,s18,s16
        0x1e200250,      // fcvtns w16,s18           height / 4
        0x531e7631,      // lsl w17,w17,#2
        0x531e7610,      // lsl w16,w16,#2
        0xaa108220 | rd, // orr xN,x17,x16,lsl #32   width | height << 32
    ] {
        ctx.emit(w);
    }
    let w = b(ctx.here(), site + 8)?;
    ctx.emit(w);
    ctx.emit(0xd280a000 | rd);
    ctx.emit(0xf2c05a00 | rd);
    let w = b(ctx.here(), site + 8)?; // orig: mov xN,#0x500; movk xN,#0x2d0,lsl #32; back
    ctx.emit(w);
    let w = b(site, start)?;
    ctx.put(site, &[w], "render size: 1280x720 times the host's render scale (state +0x10; 1.0 = the game's 1280x720)");
    ctx.render_scale = 3; // the largest scale the stub takes (3840x2160)
    Ok(())
}
