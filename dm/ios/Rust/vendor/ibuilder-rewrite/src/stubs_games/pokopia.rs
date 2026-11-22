//! Pokemon Pokopia (0400A3A01EE4C000) v327680 main: `FRAME_STEP` of `dm/games/0400A3A01EE4C000/patches.py`. The game has no frame step stubs: FRAME_STEP only gives its main
//! the state page that the screen shape stubs read (DM_SCREEN_ASPECT wider than 16:9); with it unset the page stays zero and every stub runs the original instructions.
//! The stubs are data (`STUBS`, the word lists of the Python's `_stubs`, with its `adrp` markers), emitted by `screen_shape_v327680`.

use crate::Res;
use crate::stubs::StubCtx;
use crate::stubs_games::{GamePort, word_hex};
use ibuilder_a64::asm::{self, b, bl};

pub static PORT: GamePort = GamePort {
    profile: "0400A3A01EE4C000",
    digest: "bc2823cbfff5f1c7",
    frame_step: &[("816c5358e8178d802fcec4a7ce5a741a", screen_shape_v327680)],
    stubs: &[],
    match_frame_step: &[],
    match_stubs: &[],
};

/// a word of a stub: as is, `adrp x<n>, state` (the Python's 'adrp9' / 'adrp16' / 'adrp8'), or the `_widen` block
enum W {
    R(u32),
    Adrp(u32),
    Widen,
}

const WIDE_W: i64 = 0xa0; // state page offsets (loader.c)
const WIDE_A: i64 = 0xa4;

/// w9 width, w10 height, w11 the output width: w9 x w11 / 1920, rounded up to even, when w9 x 9 == w10 x 16
const WIDEN: [u32; 12] = [
    0x5280020c, // mov w12, #16
    0x1b0c7d4c, // mul w12, w10, w12
    0x5280012d, // mov w13, #9
    0x1b0d7d2d, // mul w13, w9, w13
    0x6b0d019f, // cmp w12, w13
    0x54000101, // b.ne done (+8)
    0x1b0b7d2c, // mul w12, w9, w11
    0x111dfd8c, // add w12, w12, #1919
    0x5280f00d, // mov w13, #1920
    0x1acd098c, // udiv w12, w12, w13
    0x1100058c, // add w12, w12, #1
    0x121f798c, // and w12, w12, #~1
];

/// (name, site, reason, words) in the order of the Python's `_stubs`; the site's original bytes are `ORIG`
static STUBS: &[(&str, i64, &str, &[W])] = &[
    (
        "rt",
        0x16ae7a8,
        "render target descriptor: a 16:9 size takes the screen's width",
        &[
            W::R(0xb9401037), // orig: ldr w23, [x1, #0x10]
            W::Adrp(9),
            W::R(0xb940a12b), // ldr w11, [x9, #0xa0]   the output width (0 = 16:9)
            W::R(0x3400024b), // cbz w11, done
            W::R(0xb940ad2c), // ldr w12, [x9, #0xac]   set while the album makes its photo textures ('album_on' / 'album_off')
            W::R(0x3500020c), // cbnz w12, done
            W::R(0x29402829), // ldp w9, w10, [x1]
            W::R(0x340001ca), // cbz w10, done
            W::Widen,
            W::R(0xb900002c), // str w12, [x1]
        ],
    ),
    (
        "win",
        0x105c0e0,
        "texture descriptor (the swap chain): a 16:9 size takes the screen's width",
        &[
            W::R(0xf9400021), // orig: ldr x1, [x1]
            W::Adrp(9),
            W::R(0xb940a12b), // ldr w11, [x9, #0xa0]
            W::R(0x3400020b), // cbz w11, done
            W::R(0x2942a849), // ldp w9, w10, [x2, #0x14]
            W::R(0x340001ca), // cbz w10, done
            W::Widen,
            W::R(0xb900144c), // str w12, [x2, #0x14]
        ],
    ),
    (
        "album_on",
        0x100dec4,
        "the album's photo textures keep their size (state +0xac set)",
        &[
            W::R(0xaa0003f3), // orig: mov x19, x0
            W::Adrp(9),
            W::R(0x5280002a), // mov w10, #1
            W::R(0xb900ad2a), // str w10, [x9, #0xac]
        ],
    ),
    (
        "album_off",
        0x100e478,
        "the album's photo textures keep their size (state +0xac cleared)",
        &[
            W::R(0x2a1303e0), // orig: mov w0, w19
            W::Adrp(8),
            W::R(0xb900ad1f), // str wzr, [x8, #0xac]
        ],
    ),
    (
        "cam",
        0x1e225ec,
        "camera projection: a 16:9 camera takes the screen's ratio (Hor+)",
        &[
            W::Adrp(16),
            W::R(0xb940a611), // ldr w17, [x16, #0xa4]  the screen's ratio (0 = 16:9)
            W::R(0x340000f1), // cbz w17, orig
            W::R(0xb9414c08), // ldr w8, [x0, #0x14c]   the camera's ratio
            W::R(0x5291c730), // mov w16, #0x8e39
            W::R(0x72a7fc70), // movk w16, #0x3fe3, lsl #16   16/9
            W::R(0x6b10011f), // cmp w8, w16
            W::R(0x54000041), // b.ne orig
            W::R(0xb9014c11), // str w17, [x0, #0x14c]
            W::R(0x39456008), // orig: ldrb w8, [x0, #0x158]
        ],
    ),
    (
        "anchor",
        0x100c6b4,
        "a point in the world lands where the wider camera draws it, in the canvas's coordinates",
        &[
            W::Adrp(9),
            W::R(0xb940a129), // ldr w9, [x9, #0xa0]
            W::R(0x34000129), // cbz w9, orig
            W::R(0x1e230123), // ucvtf s3, w9
            W::R(0x1e2c1004), // fmov s4, #0.5
            W::R(0x1e243821), // fsub s1, s1, s4     (x_ndc + 1) / 2 - 0.5
            W::R(0x1e230821), // fmul s1, s1, s3
            W::R(0x52a88e09), // mov w9, #0x44700000  960.0
            W::R(0x1e270124), // fmov s4, w9
            W::R(0x1e242821), // fadd s1, s1, s4
            W::R(0x14000002), // b done
            W::R(0x1e220821), // orig: fmul s1, s1, s2   x 1920.0
        ],
    ),
    (
        "rect_w",
        0xdea6ac,
        "a full-canvas screen rect spans the screen's width (the door wipe's black)",
        &[
            W::Adrp(16),
            W::R(0xb940a211), // ldr w17, [x16, #0xa0]   the output width (0 = 16:9)
            W::R(0x34000111), // cbz w17, orig
            W::R(0xb9401a70), // ldr w16, [x19, #0x18]   the rect's width in the canvas
            W::R(0x711e021f), // cmp w16, #1920
            W::R(0x540000a1), // b.ne orig
            W::R(0xb9401e70), // ldr w16, [x19, #0x1c]   its height
            W::R(0x7110e21f), // cmp w16, #1080
            W::R(0x54000041), // b.ne orig
            W::R(0x1e230222), // ucvtf s2, w17          the screen's width
            W::R(0x1e38004a), // orig: fcvtzs w10, s2
        ],
    ),
    (
        "rect_x",
        0xdea6bc,
        "a screen rect's centre is placed in the canvas in the middle of the screen",
        &[
            W::R(0x1e210901), // orig: fmul s1, s8, s1   x scale
            W::Adrp(16),
            W::R(0xb940a211), // ldr w17, [x16, #0xa0]
            W::R(0x34000111), // cbz w17, done
            W::R(0x1e230223), // ucvtf s3, w17
            W::R(0x1e2c1004), // fmov s4, #0.5
            W::R(0x1e240863), // fmul s3, s3, s4        width / 2
            W::R(0x52a88e10), // mov w16, #0x44700000   960.0
            W::R(0x1e270204), // fmov s4, w16
            W::R(0x1f088c83), // fmsub s3, s4, s8, s3   width / 2 - 960 x scale
            W::R(0x1e232821), // fadd s1, s1, s3
        ],
    ),
    (
        "hud",
        0x1e82690,
        "full-screen pictures stretch to the screen's width; the gameplay HUD's listed panes move out by the extra half-width",
        &[
            W::Adrp(16),
            W::R(0xb940a210), // ldr w16, [x16, #0xa0]   the output width (0 = 16:9)
            W::R(0x340004f0), // cbz w16, orig
            W::R(0x39444a6a), // ldrb w10, [x19, #0x112]
            W::R(0x7100055f), // cmp w10, #1
            W::R(0x54000060), // b.eq size
            W::R(0x71000d5f), // cmp w10, #3
            W::R(0x54000261), // b.ne listed
            W::R(0x79c1e26a), // size: ldrsh w10, [x19, #0xf0]
            W::R(0x711e015f), // cmp w10, #1920
            W::R(0x5400020b), // b.lt listed
            W::R(0xd503201f), // nop
            W::R(0xd503201f), // nop
            W::R(0xd503201f), // nop
            W::R(0xf9406a6b), // ldr x11, [x19, #0xd0]   the parent
            W::R(0xb400016b), // cbz x11, listed
            W::R(0x3944496a), // ldrb w10, [x11, #0x112]
            W::R(0x3500012a), // cbnz w10, listed
            W::R(0x1e220206), // scvtf s6, w16
            W::R(0x5280f00a), // mov w10, #1920
            W::R(0x1e220147), // scvtf s7, w10
            W::R(0x1e2718c6), // fdiv s6, s6, s7
            W::R(0x3dc00123), // ldr q3, [x9]            the global matrix's x axis
            W::R(0x4f869063), // fmul v3.4s, v3.4s, v6.s[0]
            W::R(0x3d800123), // str q3, [x9]
            W::R(0x14000010), // b orig
            W::R(0xb940c26a), // listed: ldr w10, [x19, #0xc0]   the pane's name hash
            W::R(0x10000211), // adr x17, list
            W::R(0xb840462b), // 1: ldr w11, [x17], #4
            W::R(0x3400018b), // cbz w11, orig           not listed
            W::R(0x6b0a017f), // cmp w11, w10
            W::R(0x54ffffa1), // b.ne 1b
            W::R(0xbd403123), // ldr s3, [x9, #0x30]     the global x the matrix calc just stored
            W::R(0x511e0210), // sub w16, w16, #1920
            W::R(0x13017e10), // asr w16, w16, #1        the extra half-width
            W::R(0x1e220206), // scvtf s6, w16
            W::R(0x1e2140c7), // fneg s7, s6
            W::R(0x1e202068), // fcmp s3, #0.0
            W::R(0x1e264ce6), // fcsel s6, s7, s6, mi    towards the pane's side
            W::R(0x1e262863), // fadd s3, s3, s6
            W::R(0xbd003123), // str s3, [x9, #0x30]
            W::R(0xf9401909), // orig: ldr x9, [x8, #0x30]
            W::R(0x1400000b), // b over the list
            W::R(0xd81f3cb5),
            W::R(0xf13b1a7c),
            W::R(0x0623e2bd),
            W::R(0x1b0caafe),
            W::R(0x1569295d),
            W::R(0x31d72b49),
            W::R(0xe75fc20a),
            W::R(0x2074df4f),
            W::R(0x78801aae),
            W::R(0),
        ],
    ),
];
static GET: &[W] = &[
    W::Adrp(9),
    W::R(0xb940a129), // ldr w9, [x9, #0xa0]
    W::R(0x340000e9), // cbz w9, ret
    W::R(0x1b097c00), // mul w0, w0, w9
    W::R(0x111dfc00), // add w0, w0, #1919
    W::R(0x5280f00a), // mov w10, #1920
    W::R(0x1aca0800), // udiv w0, w0, w10
    W::R(0x11000400), // add w0, w0, #1
    W::R(0x121f7800), // and w0, w0, #~1
    W::R(0xd65f03c0), // ret
];
static CANVAS: &[u32] = &[
    0xf941a908, // ldr x8, [x8, #0x350]
    0xb4000128, // cbz x8, none
    0xb9404900, // ldr w0, [x8, #0x48]
    0xb9404d09, // ldr w9, [x8, #0x4c]
    0x531c6d29, // lsl w9, w9, #4
    0x5280012a, // mov w10, #9
    0x1aca0929, // udiv w9, w9, w10
    0x6b09001f, // cmp w0, w9
    0x1a808120, // csel w0, w9, w0, hi
    0xd65f03c0, // ret
    0x5280f000, // none: mov w0, #1920
    0xd65f03c0, // ret
];

/// the original bytes at each stub's site (`_orig`)
const ORIG: &[(&str, &str)] = &[
    ("anchor", "2108221e"),
    ("rect_w", "4a00381e"),
    ("rect_x", "0109211e"),
    ("rt", "371040b9"),
    ("win", "210040f9"),
    ("cam", "08604539"),
    ("album_on", "f30300aa"),
    ("album_off", "e003132a"),
    ("hud", "091940f9"),
];

/// `_float_sites`: (site, register) of the renderer's 1920.0 constants
const FLOAT_SITES: [(i64, u32); 8] = [
    (0x104f364, 8),
    (0x104f61c, 8),
    (0xfff1c4, 8),
    (0xfff450, 8),
    (0xd3aac, 9),
    (0x100edd4, 9),
    (0x1018bac, 8),
    (0x1018c08, 8),
];

const GET_SITES: [(i64, &str); 3] = [
    (0x103a1c4, "render width (1920)"),
    (
        0x103a1ec,
        "render width of a dynamic resolution level (the table)",
    ),
    (0x103a1f4, "render width of a level out of range (1920)"),
];

const CANVAS_SITES: [i64; 37] = [
    0x86bf88, 0x9bc69c, 0x9bc8d0, 0x9bced4, 0x9c0ee0, 0x9c1630, 0x9c1658, 0x9c29c4, 0x9c29ec,
    0x9c3344, 0x9c44e0, 0x9c4500, 0x9c4b08, 0x9c4b30, 0x9f3ff4, 0x9f4050, 0x9f407c, 0x9f4190,
    0x9f41bc, 0x9f41e4, 0xdbf458, 0xdda9e4, 0xddab50, 0xde5064, 0xdea66c, 0xe0c3e4, 0xe8d438,
    0xe8d62c, 0xe8e7a8, 0xe8ef98, 0xe8f320, 0xe8fab0, 0xe8fd20, 0xe902b0, 0xeb5ce0, 0xf0f45c,
    0xf10074,
];

fn emit_words(ctx: &mut StubCtx, words: &[W]) -> Res<()> {
    for w in words {
        match w {
            W::Adrp(r) => {
                let a = asm::adrp(*r, ctx.here(), ctx.state)?;
                ctx.emit(a);
            }
            W::R(w) => ctx.emit(*w),
            W::Widen => {
                for &w in &WIDEN {
                    ctx.emit(w);
                }
            }
        }
    }
    Ok(())
}

pub fn screen_shape_v327680(ctx: &mut StubCtx) -> Res<()> {
    for (name, site, why, words) in STUBS {
        let orig = ORIG
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, o)| *o)
            .unwrap();
        ctx.site(*site, orig)?;
        let start = ctx.here();
        emit_words(ctx, words)?;
        let w = b(ctx.here(), site + 4)?;
        ctx.emit(w);
        let w = b(*site, start)?;
        ctx.put(
            *site,
            &[w],
            &format!("screen shape: {why} (DM_SCREEN_ASPECT, state +{WIDE_W:#x} / +{WIDE_A:#x})"),
        );
    }
    for (site, n) in FLOAT_SITES {
        let orig = (if site == 0x1018c08 {
            0xd2800000u32
        } else {
            0x52800000
        }) | 0x44f0 << 5
            | 1 << 21
            | n;
        ctx.site(site, &word_hex(orig))?;
        let start = ctx.here();
        let w = asm::adrp(n, ctx.here(), ctx.state)?;
        ctx.emit(w);
        ctx.emit(0xb940a800 | n << 5 | n);
        ctx.emit(0x35000040 | n);
        ctx.emit(orig);
        let w = b(ctx.here(), site + 4)?;
        ctx.emit(w);
        let w = b(site, start)?;
        ctx.put(site, &[w], "screen shape: the renderer's 1920.0 becomes the output width (DM_SCREEN_ASPECT, state +0xa8)");
    }
    for (site, why) in GET_SITES {
        ctx.site(site, "c0035fd6")?;
        let start = ctx.here();
        emit_words(ctx, GET)?;
        let w = b(site, start)?;
        ctx.put(site, &[w], &format!("screen shape: {why} takes the screen's width (DM_SCREEN_ASPECT, state +{WIDE_W:#x})"));
    }
    let start = ctx.here();
    let w = asm::adrp(8, ctx.here(), 0x3451000)?;
    ctx.emit(w);
    for &w in CANVAS {
        ctx.emit(w);
    }
    for site in CANVAS_SITES {
        ctx.site(site, &word_hex(bl(site, 0xd3ca0)?))?;
        let w = bl(site, start)?;
        ctx.put(site, &[w], "screen shape: the UI's text and map scale takes the 16:9 canvas's width, min(width, height x 16 / 9) (DM_SCREEN_ASPECT)");
    }
    ctx.add_capability("WIDE_ASPECT");
    Ok(())
}
