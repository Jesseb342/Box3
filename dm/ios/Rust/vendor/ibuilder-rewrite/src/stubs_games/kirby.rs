//! Kirby's Dream Buffet (0100A8E016236000): `MATCH_STUBS` of `dm/games/0100A8E016236000/patches.py`: Modules.InitializeBaseSystem completes its queued initialization through
//! the game's own queue before its caller submits Info and Decor. The native bindings and the task runner are matched as complete functions; the runner proves the
//! instance / type-name layout, and the extra wait also requires the exact class and method names, since this queue serves unrelated frame work.

use crate::stubs::{RulePort, StubCtx};
use crate::stubs_games::GamePort;
use crate::{Fail, Res};
use ibuilder_a64::asm::{self, b, bl, blr, cbnzw, ldp_post, ldrx, ldur};

pub static PORT: GamePort = GamePort {
    profile: "0100A8E016236000",
    digest: "dc0d9927d4c17035",
    frame_step: &[],
    stubs: &[],
    match_frame_step: &[],
    match_stubs: &[(
        "main",
        &[RulePort {
            stub: initialize_base_system,
            find: None,
        }],
    )],
};

/// a word of the stub: as is, or one that needs the address of a label (the Python's lambdas of the program counter)
enum It {
    W(u32),
    /// `adrp x<reg>, label`
    Adrp(u32, &'static str),
    /// `add x<reg>, x<reg>, #label & 0xfff`
    AddLo(u32, &'static str),
    /// `b.ne label` (`BEQ(pc, label) | 1`)
    Bne(&'static str),
    /// `cbnz w<reg>, label`, or with `cbz` set `cbz x<reg>, label` (`CBNZW(...) ^ 0x81000000`)
    Cbnz(u32, &'static str, bool),
    /// `bl label`
    Bl(&'static str),
    /// `adrp x16, <absolute address>`
    AdrpAt(u32, i64),
    /// `b <absolute address>`
    BAt(i64),
}

/// Complete BaseSystem before the caller queues dependent Info setup
pub fn initialize_base_system(ctx: &mut StubCtx) -> Res<()> {
    let (Some(execute), Some(_)) = (ctx.other("execute and wait"), ctx.other("task runner")) else {
        return Ok(()); // the matcher already reported the missing companion; install nothing
    };
    let add = ctx.base;
    ctx.site(add, "ff0302d1")?; // sub sp,sp,#0x80
    ctx.site(execute, "fd7bbda9")?; // stp x29,x30,[sp,#-0x30]!
    let start = ctx.here();
    let mut words: Vec<It> = Vec::new();
    let mut labels: Vec<(&'static str, i64)> = Vec::new();
    macro_rules! label {
        ($name:expr) => {
            labels.push(($name, start + 4 * words.len() as i64))
        };
    }
    // compare the string at x9 with the one at `name`, branching to `return` on a difference
    fn match_string(
        words: &mut Vec<It>,
        labels: &mut Vec<(&'static str, i64)>,
        start: i64,
        name: &'static str,
        loop_name: &'static str,
    ) {
        words.push(It::Adrp(10, name));
        words.push(It::AddLo(10, name));
        labels.push((loop_name, start + 4 * words.len() as i64));
        words.extend([It::W(0x3840152b), It::W(0x3840154c), It::W(0x6b0c017f)]); // ldrb w11,[x9],#1; ldrb w12,[x10],#1; cmp w11,w12
        words.push(It::Bne("return"));
        words.push(It::Cbnz(11, loop_name, false));
    }
    // keep the original native-call context across Add, whose x0 result is not the context; its argument slots remain {queue, instance, method name}
    words.extend([
        It::W(asm::stp_pre(29, 30, 31, -0x20)),
        It::W(0x910003fd),
        It::W(asm::strx(0, 31, 2)),
    ]);
    words.push(It::Bl("original"));
    words.extend([
        It::W(ldrx(0, 31, 2)),
        It::W(ldrx(8, 0, 0)),
        It::W(ldrx(8, 8, 0x88 / 8)),
        It::W(ldrx(9, 8, 2)),
    ]);
    // null names / instances are not the Modules task; compare the full names, including NUL, so unrelated tasks and similarly named classes keep Add
    words.push(It::Cbnz(9, "return", true)); // cbz x9,return
    match_string(&mut words, &mut labels, start, "method", "method loop");
    words.push(It::W(ldrx(9, 8, 1)));
    words.push(It::Cbnz(9, "return", true));
    words.extend([It::W(ldur(9, 9, -8)), It::W(ldrx(9, 9, 1))]);
    match_string(&mut words, &mut labels, start, "class", "class loop");
    words.push(It::W(ldrx(0, 31, 2)));
    words.push(It::AdrpAt(16, execute));
    words.extend([
        It::W(asm::addi(16, 16, (execute & 0xfff) as u32, 0)),
        It::W(blr(16)),
    ]);
    label!("return");
    words.extend([It::W(ldp_post(29, 30, 31, 0x20)), It::W(0xd65f03c0)]);
    label!("original");
    words.push(It::W(0xd10203ff)); // original sub sp,sp,#0x80
    words.push(It::BAt(add + 4));
    for (name, value) in [
        ("method", &b"InitializeBaseSystem\0"[..]),
        ("class", &b"Scn.Step.Modules\0"[..]),
    ] {
        label!(name);
        let mut v = value.to_vec();
        while v.len() % 4 != 0 {
            v.push(0);
        }
        words.extend(
            v.as_chunks::<4>()
                .0
                .iter()
                .map(|c| It::W(u32::from_le_bytes(*c))),
        );
    }
    let at = |labels: &[(&'static str, i64)], name: &str| {
        labels
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, a)| *a)
            .ok_or_else(|| Fail::new(format!("KeyError: {name:?}")))
    };
    for it in &words {
        let pc = ctx.here();
        let w = match it {
            It::W(w) => *w,
            It::Adrp(r, l) => asm::adrp(*r, pc, at(&labels, l)?)?,
            It::AddLo(r, l) => asm::addi(*r, *r, (at(&labels, l)? & 0xfff) as u32, 0),
            It::Bne(l) => asm::beq(pc, at(&labels, l)?)? | 1,
            It::Cbnz(r, l, cbz) => {
                cbnzw(*r, pc, at(&labels, l)?)? ^ if *cbz { 0x81000000 } else { 0 }
            }
            It::Bl(l) => bl(pc, at(&labels, l)?)?,
            It::AdrpAt(r, a) => asm::adrp(*r, pc, *a)?,
            It::BAt(a) => b(pc, *a)?,
        };
        ctx.emit(w);
    }
    let w = b(add, start)?;
    ctx.put(add, &[w], "Modules.InitializeBaseSystem: finish its queued initialization before Info/Decor are added");
    Ok(())
}
