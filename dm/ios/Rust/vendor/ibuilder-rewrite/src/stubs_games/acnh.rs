//! Animal Crossing: New Horizons (01006F8002326000) 3.0.3 (v2228224) main: `FRAME_STEP` of `dm/games/01006F8002326000/patches.py`. The game has no frame step stubs: FRAME_STEP only
//! gives its main the state page that the screen shape stubs read (DM_SCREEN_ASPECT, as for Breath of the Wild); with it unset the page stays zero and every stub runs the original
//! instructions. A screen taller than 16:9 keeps the picture's width (1920) and takes the height of the screen's ratio (state +0x48), the layout space 1280 x 2/3 of it (+0x4c, +0x50
//! as a float); each stub is one bit of the conversion site mask (+0x54, DM_SCREEN_ASPECT_SITES, all on by default); a height of 0 (16:9) leaves the original value.

use crate::Res;
use crate::stubs::StubCtx;
use crate::stubs_games::{GamePort, word_hex};
use ibuilder_a64::asm::{self, b};

pub static PORT: GamePort = GamePort {
    profile: "01006F8002326000",
    digest: "a7a061b0102df320",
    frame_step: &[("ff1d1c05670db6021c85b624a710b963", screen_shape)],
    stubs: &[],
    match_frame_step: &[],
    match_stubs: &[],
};

/// (site, the stub's words after `adrp x16, state`, the last one the site's original instruction, reason)
static SIZE_SITES: &[(i64, &[u32], &str)] = &[
    (
        0x5c9b80,
        &[
            0xb9405611, // ldr w17, [x16, #0x54]   sites
            0x360000d1, // tbz w17, #0, orig
            0xb9404a11, // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
            0x34000091, // cbz w17, orig
            0x1b117d28, // mul w8, w9, w17         height = width x the output's height / 1920 (each mode of the table: 960 → 672, 1280 → 896, 1920 → 1344)
            0x5280f011, // mov w17, #1920
            0x1ad10908, // udiv w8, w8, w17
            0x290c2029, // orig: stp w9, w8, [x1, #0x60]
        ],
        "graphics create arg +0x60: the display size in the screen's shape (bit 0)",
    ),
    (
        0x5c9b94,
        &[
            0xb9405611, // ldr w17, [x16, #0x54]
            0x36080091, // tbz w17, #1, orig
            0xb9404e11, // ldr w17, [x16, #0x4c]   the layout height (0 = 16:9)
            0x34000051, // cbz w17, orig
            0xb3607e28, // bfi x8, x17, #32, #32   1280 x the layout height
            0xf9001028, // orig: str x8, [x1, #0x20]
        ],
        "graphics create arg +0x20: 1280 x the layout height (bit 1)",
    ),
    (
        0x5cdd74,
        &[
            0xb9405611, // ldr w17, [x16, #0x54]
            0x361000d1, // tbz w17, #2, orig
            0xb9404a11, // ldr w17, [x16, #0x48]
            0x34000091, // cbz w17, orig
            0x1b117d28, // mul w8, w9, w17
            0x5280f011, // mov w17, #1920
            0x1ad10908, // udiv w8, w8, w17
            0x29002149, // orig: stp w9, w8, [x10]
        ],
        "platform config slot 7: the static display size in the screen's shape (bit 2)",
    ),
    (
        0x5cddd4,
        &[
            0xb9405611, // ldr w17, [x16, #0x54]
            0x361800b1, // tbz w17, #3, orig
            0xb9404e11, // ldr w17, [x16, #0x4c]
            0x34000071, // cbz w17, orig
            0xb9405211, // ldr w17, [x16, #0x50]   the layout height as a float
            0xb3607e29, // bfi x9, x17, #32, #32   1280.0 x the layout height
            0xf9029d09, // orig: str x9, [x8, #0x538]
        ],
        "platform config slot 8: the static layout size 1280.0 x the layout height (bit 3)",
    ),
    (
        0x5cdcc8,
        &[
            0xb9405611, // ldr w17, [x16, #0x54]
            0x36200091, // tbz w17, #4, orig
            0xb9404a11, // ldr w17, [x16, #0x48]
            0x34000051, // cbz w17, orig
            0xb3607e28, // bfi x8, x17, #32, #32   1920 x the output's height
            0xf8014028, // orig: stur x8, [x1, #0x14]
        ],
        "platform config slot 3: the arg's 1920x1080 in the screen's shape (bit 4)",
    ),
];
/// `_duo_anchor`: duo_anchor.c compiled by clang to position-independent code without data; each entry is 8 hex digits of the Python's string, as one word of the `int(.., 16)` the stub emits
static DUO_ANCHOR: [u32; 182] = [
    0xbd400021, 0x1e202028, 0x54000041, 0xd65f03c0, 0xf9400c08, 0xb4ffffc8, 0x52800609, 0xaa0803ea,
    0xf9400d4b, 0xb400008b, 0xaa0b03ea, 0x71000529, 0x54ffff81, 0xbd405540, 0x52a88f49, 0x1e270122,
    0x1e222000, 0x1e2e1000, 0x1e2f1002, 0x1e20ac40, 0xbd407002, 0x2d4a1403, 0x1e220864, 0x1e228862,
    0x1e202088, 0x1e244c44, 0xbd408403, 0x1e2308a2, 0x1e2388a5, 0x1e202048, 0x1e224ca5, 0xf9401409,
    0x9100800a, 0xbd401022, 0x1e220802, 0x1e222080, 0x540003cb, 0xbd401426, 0x1e260806, 0x1e2620a0,
    0x5400034b, 0xbd401826, 0x1e260806, 0x1e2620a0, 0x540002c8, 0xbd407c06, 0x1e20c0c6, 0x52a8440b,
    0x1e270167, 0x1e270807, 0x1e2720c0, 0x540001e5, 0xbd408c06, 0x1e20c0d0, 0x1e272200, 0x54000165,
    0xeb0a013f, 0x54fff941, 0xf9400008, 0xf9405508, 0xeb02011f, 0x54fff8c0, 0xbd400420, 0xbd408001,
    0x1e210800, 0x1400001c, 0xeb0a013f, 0x540004c1, 0xbd401426, 0x1e260806, 0x1e2620a0, 0x5400044b,
    0x52a88689, 0x1e270126, 0x1e260806, 0xbd400427, 0x1e301010, 0x1f0740c6, 0x1e2620a0, 0x54000345,
    0xbd408c06, 0x1e20c0d0, 0x52a84409, 0x1e270131, 0x1e310811, 0x1e312200, 0x54000265, 0xf9400009,
    0xf9405529, 0xeb02013f, 0x540001e0, 0xbd408000, 0x1e2008e0, 0xbd008000, 0xbd400420, 0x1e200860,
    0xbd008400, 0xbd400420, 0xbd408801, 0x1e210800, 0xbd008800, 0xbd400420, 0x1e2008c0, 0xbd008c00,
    0xd65f03c0, 0x1e222080, 0x540000ab, 0xbd401423, 0x1e230803, 0x1e2320a0, 0x54fff2aa, 0xf9400009,
    0xf9405529, 0x52a8500a, 0x1e270143, 0x1e230803, 0xeb02013f, 0x54000081, 0x1e232080, 0x1e2354a8,
    0x54fff164, 0x1e200821, 0x52800609, 0x14000004, 0xaa0a03e8, 0x71000529, 0x54000440, 0xf9400d0a,
    0xb400034a, 0xbd407104, 0x2d4a1905, 0x1e2408a7, 0x1e2488a4, 0x1e2020e8, 0x1e274c84, 0xbd408505,
    0x1e2508c7, 0x1e2588c5, 0x1e2020e8, 0x1e274ca5, 0x1e222080, 0x540000ab, 0xbd401426, 0x1e260806,
    0x1e2620a0, 0x54fffd6a, 0xf9400108, 0xf9405508, 0xeb02011f, 0x54ffedc1, 0x1e232080, 0x1e2354a8,
    0x54fffc84, 0x17ffff6a, 0x2d460d02, 0x1e230863, 0x1f020c42, 0x1e2a1003, 0x1e232040, 0x54ffec8c,
    0xbd407c02, 0x1e20c042, 0x52a87908, 0x1e270103, 0x1e230803, 0x1e232040, 0x52a870e8, 0x1e270102,
    0x52a86cc8, 0x1e270103, 0x1e22ac62, 0x1e220802, 0xbd408c00, 0x1e20c003, 0x1e222060, 0x54ffea8b,
    0x1e214022, 0x1e202008, 0x1e22cc21, 0x1e212800, 0xbd008c00, 0xd65f03c0,
];

const PANE_DRAW_SELF: i64 = 0x27e2c8; // nn::ui2d::Pane::DrawSelf (vtable main+0x474d1f8 slot 21, empty): the game's null panes, alignments, captures and parts keep it
const TANF_PLT: i64 = 0x3f03330; // main's PLT stubs of the SDK's tanf and atanf
const ATANF_PLT: i64 = 0x3f03360;
const DUO_CALC: i64 = 0x0;

/// `_bl`: no reach assertion, as in the Python's helper of this file
fn bl_unchecked(frm: i64, to: i64) -> u32 {
    0x94000000 | ((((to - frm) >> 2) & 0x3FFFFFF) as u32)
}

fn screen_shape(ctx: &mut StubCtx) -> Res<()> {
    let st = ctx.state;
    for (at, words, why) in SIZE_SITES {
        ctx.site(*at, &word_hex(*words.last().unwrap()))?;
        let start = ctx.here();
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        for &w in *words {
            ctx.emit(w);
        }
        let w = b(ctx.here(), at + 4)?;
        ctx.emit(w);
        let w = b(*at, start)?;
        ctx.put(*at, &[w], why);
    }
    // Every frame main+0x1527ebc picks the resolution table's mode into [main+0x512e2e0], divides the entry by the framebuffer's size into the 3D views' render scale and sets
    // the display buffer's crop to the entry: the presented picture was cropped back to the top 1920x1080 of the 1920x1344 window. The two loads of the entry take the height of
    // the screen's shape, the width x the output's height / 1920 in integers (1920 -> 1344 exactly; a float product truncated to 1343). Bit 7 of the sites
    for (at, orig, cvt, back) in [
        (0x1527f00i64, 0x2d400500u32, 0x1e380010u32, 0x1e220201u32), // ldp s0, s1, [x8]; fcvtzs w16, s0; scvtf s1, w16
        (0x1527f2c, 0x2d400d02, 0x1e380050, 0x1e220203), // ldp s2, s3, [x8]; fcvtzs w16, s2; scvtf s3, w16
    ] {
        ctx.site(at, &word_hex(orig))?;
        let start = ctx.here();
        ctx.emit(orig); // the original load
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        for w in [
            0xb9405611u32, // ldr w17, [x16, #0x54]   sites
            0x36380111,    // tbz w17, #7, back (+8)
            0xb9404a11,    // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
            0x340000d1,    // cbz w17, back (+6)
            cvt,           // fcvtzs w16, <width>
            0x1b117e10,    // mul w16, w16, w17
            0x5280f011,    // mov w17, #1920
            0x1ad10a10,    // udiv w16, w16, w17
            back,          // scvtf <height>, w16
        ] {
            ctx.emit(w);
        }
        let w = b(ctx.here(), at + 4)?;
        ctx.emit(w);
        let w = b(at, start)?;
        ctx.put(at, &[w], "resolution table entry of the frame (crop, render scale): the height of the screen's shape (bit 7)");
    }
    // The layouts' DrawInfo takes the framebuffer's size twice, 1920.0 x 1080.0 at +0x108 and 1920 x 1080 at +0x138, which nn::ui2d's scissors and captures map the screen with:
    // both take the output's height. Each stub runs the site's original movk first. v16 is dead there, x16 / x17 free. Bit 8 of the sites
    for (at, orig, words) in [
        (
            0x31cee60i64,
            0xf2e890f8u32,
            &[0x1e230230u32, 0x1e260211, 0xb3607e38][..],
        ), // movk x24, #0x4487, lsl #48; ucvtf s16, w17; fmov w17, s16; bfi x24, x17, #32, #32
        (0x31cee9c, 0xf2c08708, &[0xb3607e28][..]), // movk x8, #0x438, lsl #32; bfi x8, x17, #32, #32
    ] {
        ctx.site(at, &word_hex(orig))?;
        let start = ctx.here();
        ctx.emit(orig);
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        let n = 3 + words.len() as u32; // from the tbz to the branch back (the cbz: n - 2)
        ctx.emit(0xb9405611); // ldr w17, [x16, #0x54]   sites
        ctx.emit(0x36400011 | (n << 5)); // tbz w17, #8, back
        ctx.emit(0xb9404a11); // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
        ctx.emit(0x34000011 | ((n - 2) << 5)); // cbz w17, back
        for &w in words {
            ctx.emit(w);
        }
        let w = b(ctx.here(), at + 4)?;
        ctx.emit(w);
        let w = b(at, start)?;
        ctx.put(
            at,
            &[w],
            "layouts' DrawInfo: the framebuffer's size in the screen's shape (bit 8)",
        );
    }
    // The scene camera's vertical angle: the field camera keeps it in radians at +0x2cc and reads it twice, for its sead::PerspectiveProjection and for main+0x151424c, the views that
    // follow it. Both loads widen it to 2 atan(tan(fovy / 2) k), k = (16/9) / the screen's ratio (state +0x5c), so the sides are 16:9's and the taller screen shows more above and
    // below. The second site's x0 is main+0x151424c's argument: saved around the calls. Bit 5 of the sites
    for at in [0x7a895ci64, 0x7a89a8] {
        ctx.site(at, "80ce42bd")?;
        let start = ctx.here();
        ctx.emit(0xbd42ce80); // orig: ldr s0, [x20, #0x2cc]
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        ctx.emit(0xb9405611); // ldr w17, [x16, #0x54]   sites
        ctx.emit(0x362801b1); // tbz w17, #5, back (+13)
        ctx.emit(0xb9404a11); // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
        ctx.emit(0x34000171); // cbz w17, back (+11)
        ctx.emit(0xf81f0fe0); // str x0, [sp, #-16]!
        ctx.emit(0x1e2c1001); // fmov s1, #0.5
        ctx.emit(0x1e210800); // fmul s0, s0, s1
        ctx.emit(bl_unchecked(ctx.here(), TANF_PLT));
        let w = asm::adrp(16, ctx.here(), st)?;
        ctx.emit(w);
        ctx.emit(0xbd405e01); // ldr s1, [x16, #0x5c]   k
        ctx.emit(0x1e210800); // fmul s0, s0, s1
        ctx.emit(bl_unchecked(ctx.here(), ATANF_PLT));
        ctx.emit(0x1e202800); // fadd s0, s0, s0        the widened angle
        ctx.emit(0xf84107e0); // ldr x0, [sp], #16
        let w = b(ctx.here(), at + 4)?;
        ctx.emit(w);
        let w = b(at, start)?;
        ctx.put(at, &[w], "field camera: its vertical angle widened so the taller screen keeps 16:9's sides (bit 5)");
    }
    let code = ctx.here();
    for w in DUO_ANCHOR {
        ctx.emit(w);
    }
    ctx.site(0x27d570, "68624139")?;
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    ctx.emit(0xb9405611); // ldr w17, [x16, #0x54]   sites
    ctx.emit(0x36480111); // tbz w17, #9, orig (+8)
    ctx.emit(0xb9404a11); // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
    ctx.emit(0x340000d1); // cbz w17, orig (+6)
    ctx.emit(0xaa1303e0); // mov x0, x19             the pane
    ctx.emit(0x91020201); // add x1, x16, #0x80      the parameters
    let w = asm::adrp(2, ctx.here(), PANE_DRAW_SELF)?;
    ctx.emit(w);
    ctx.emit(0x91000042 | ((PANE_DRAW_SELF & 0xFFF) as u32) << 10); // add x2, x2, #lo12: nn::ui2d::Pane::DrawSelf
    ctx.emit(bl_unchecked(ctx.here(), code + DUO_CALC));
    ctx.emit(0x39416268); // orig: ldrb w8, [x19, #0x58]
    let w = b(ctx.here(), 0x27d574)?;
    ctx.emit(w);
    let w = b(0x27d570, start)?;
    ctx.put(0x27d570, &[w], "nn::ui2d::Pane::Calculate after the global matrix: duo_calc (the HUD at the taller screen's edges, full-screen backgrounds stretched)");
    // The field of view: the game camera (main+0x386a6a0) copies its sead::PerspectiveProjection into its parameters, sets near, far and the vertical angle there from the parameters
    // and copies them back. A taller picture of the same vertical angle shows less at the sides: the angle is widened where it is computed (main+0x386a7a0: fmul s8, s0, s9, the
    // half angle; s9 = 0.5) to 2 atan(tan(fovy / 2) k), so the sides stay those of 16:9 and the taller screen shows more above and below. Bit 5 of the sites. Caller-saved
    // registers are dead there but s0 (the game calls sinf right after)
    ctx.site(0x386a7a0, "0808291e")?;
    let start = ctx.here();
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    ctx.emit(0xb9404a11); // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
    ctx.emit(0x34000171); // cbz w17, orig (+11)
    ctx.emit(0xb9405611); // ldr w17, [x16, #0x54]   sites
    ctx.emit(0x36280131); // tbz w17, #5, orig (+9)
    ctx.emit(0x1e2c1002); // fmov s2, #0.5
    ctx.emit(0x1e220800); // fmul s0, s0, s2
    ctx.emit(bl_unchecked(ctx.here(), TANF_PLT));
    let w = asm::adrp(16, ctx.here(), st)?;
    ctx.emit(w);
    ctx.emit(0xbd405e01); // ldr s1, [x16, #0x5c]   k
    ctx.emit(0x1e210800); // fmul s0, s0, s1
    ctx.emit(bl_unchecked(ctx.here(), ATANF_PLT));
    ctx.emit(0x1e202800); // fadd s0, s0, s0        the widened angle
    ctx.emit(0x1e290808); // orig: fmul s8, s0, s9
    let w = b(ctx.here(), 0x386a7a4)?;
    ctx.emit(w);
    let w = b(0x386a7a0, start)?;
    ctx.put(
        0x386a7a0,
        &[w],
        "game camera: the vertical angle widened so the taller screen keeps 16:9's sides (bit 5)",
    );
    // The layouts' projection: nn::ui2d::DrawInfo::SetProjectionMtx (main+0x265100, 13 callers) copies the game's projection of a layout's rectangle into DrawInfo +0x10 (4x4). On the
    // taller screen its y row is divided by the vertical stretch (layout height / 720, state +0x84) before the return, so layouts keep their shape, centred, with room above and
    // below. Only a 16:9 projection is divided (|m5| / |m0| within 5 % of 16/9); another shape (a square render target) is left alone. Bit 6 of the sites. At the return s0..s4 are free
    ctx.site(0x265140, "c0035fd6")?;
    let start = ctx.here();
    let mut w: Vec<u32> = vec![
        asm::adrp(16, start, st)?,
        0xb9404a11, // ldr w17, [x16, #0x48]   the output's height (0 = 16:9)
        0,          // cbz w17, ret_end
        0xb9405611, // ldr w17, [x16, #0x54]
        0,          // tbz w17, #6, ret_end
        0xbd401001, // ldr s1, [x0, #0x10]     m0
        0x1e20c021, // fabs s1, s1
        0xbd402402, // ldr s2, [x0, #0x24]     m5
        0x1e20c042, // fabs s2, s2
        0x5291c731, // mov w17, #0x8e39
        0x72a7fc71, // movk w17, #0x3fe3, lsl #16   16/9
        0x1e270223, // fmov s3, w17
        0x1e230823, // fmul s3, s1, s3
        0x7ea3d443, // fabd s3, s2, s3
        0x529999b1, // mov w17, #0xcccd
        0x72a7a991, // movk w17, #0x3d4c, lsl #16   0.05
        0x1e270224, // fmov s4, w17
        0x1e240824, // fmul s4, s1, s4
        0x1e242060, // fcmp s3, s4
        0,          // b.gt ret_end            not 16:9: as it is
        0x5291c731, // mov w17, #0x8e39
        0x72a7fc71, // movk w17, #0x3fe3, lsl #16   s3 = 16/9
        0x1e270223, // fmov s3, w17
        0xbd405a00, // ldr s0, [x16, #0x58]    r = 1920 / oh
        0x1e232000, // fcmp s0, s3
        0,          // b.gt wide_path
        0xbd408600, // ldr s0, [x16, #0x84]    taller: anc[1] = lh / 720
    ];
    for i in [1u32, 4, 5, 6, 7, 9, 13] {
        let o = (0x10 + 4 * i) / 4;
        w.extend([0xbd400001 | (o << 10), 0x1e201821, 0xbd000001 | (o << 10)]);
    }
    w.push(0xd65f03c0); // ret
    let wide_idx = w.len() as u32;
    w.push(0x1e201860); // wide: fdiv s0, s3, s0   (16/9) / r
    for i in [0u32, 1, 2, 3, 4, 8, 12] {
        let o = (0x10 + 4 * i) / 4;
        w.extend([0xbd400001 | (o << 10), 0x1e200821, 0xbd000001 | (o << 10)]);
    }
    let ret_idx = w.len() as u32;
    w.push(0xd65f03c0); // ret_end: ret
    w[2] = 0x34000011 | (((ret_idx - 2) & 0x7ffff) << 5); // cbz w17, ret_end
    w[4] = 0x36300011 | (((ret_idx - 4) & 0x3fff) << 5); // tbz w17, #6, ret_end
    w[19] = 0x5400000c | (((ret_idx - 19) & 0x7ffff) << 5); // b.gt ret_end
    w[25] = 0x5400000c | (((wide_idx - 25) & 0x7ffff) << 5); // b.gt wide_path
    for insn in w {
        ctx.emit(insn);
    }
    let w = b(0x265140, start)?;
    ctx.put(0x265140, &[w], "nn::ui2d::DrawInfo::SetProjectionMtx: y row divided on taller screens, x row scaled on wider screens (bit 6)");
    ctx.add_capability("HEIGHT_WIDE_ASPECT");
    Ok(())
}
