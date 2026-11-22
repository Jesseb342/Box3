//! The output files of the rewrite (`<name>.patched.bin` and the tables beside it) and the stats line, as
//! `patch_nso.py` writes them. Numbers are written like Python's `f'{x:#x}'` (`hx`).

use crate::matching::hex;
use crate::rewriter::{Rewritten, Rw};
use crate::{Fail, Res, hx};
use sha2::{Digest, Sha256};
use std::path::Path;

fn dict_repr(stats: &[(&'static str, u64)]) -> String {
    let items: Vec<String> = stats.iter().map(|(k, v)| format!("'{k}': {v}")).collect();
    format!("{{{}}}", items.join(", "))
}

pub(crate) fn finish(mut rw: Rw) -> Res<Rewritten> {
    let name = rw.name.clone();
    let back_len = ((rw.patch_back.len() as i64 + 0x3FFF) & !0x3FFF) as usize;
    let mut patch = std::mem::take(&mut rw.patch_front);
    let patch_front_len = patch.len();
    let pad_to: usize = if rw.far {
        if rw.big_text && patch.len() as i64 > rw.front - 0x4000 && rw.opts.patch_front.is_none() {
            let need = (patch.len() as i64 + 0x4000 + 0xFFFF) & !0xFFFF;
            let line = format!(
                "{name}: patch area of {:#x} bytes does not fit in {:#x} before the base; rewriting again with {need:#x}",
                patch.len(),
                rw.front
            );
            let mut log = std::mem::take(&mut rw.log);
            log.push(line);
            return Err(Fail {
                msg: log.join("\n"),
                rerun_front: Some(need as u64),
            });
        }
        if patch.len() as i64 > rw.front - 0x4000 {
            return Err(Fail::new(format!(
                "patch area of {:#x} bytes does not fit in the {:#x} before the base",
                patch.len(),
                rw.front
            )));
        }
        if rw.two {
            if rw.image_size > rw.back_off {
                return Err(Fail::new(
                    "back patch area overlaps the key page or the frame step page",
                ));
            }
            rw.image_size = rw.back_off + back_len as i64;
            let pad = (-(patch.len() as i64) & 0x3FFF) as usize;
            patch.extend(std::iter::repeat_n(0u8, pad));
            patch.extend_from_slice(&rw.patch_back);
            patch.extend(std::iter::repeat_n(0u8, back_len - rw.patch_back.len()));
        }
        rw.file_image_len as usize
    } else {
        rw.patch_off as usize
    };

    // build_src.sha256: the hashes of the Python sources (only when the engine's tools folder is given)
    let build_src = match &rw.opts.py_tools {
        Some(dir) => Some(build_src_sha256(dir)?),
        None => None,
    };

    // fixups.tsv
    let mut f = String::new();
    f.push_str(&format!(
        "# PATCH_OFF\t{}\n# KEY_PAGE_OFF\t{:#x}\n# KEY_PAGE_SIZE\t0x4000\n# TEXT_END\t{:#x}\n# RO_OFF\t{:#x}\n# DATA_OFF\t{:#x}\n",
        hx(rw.patch_off),
        rw.key_page_off,
        rw.text_end,
        rw.ro_off,
        rw.data_off
    ));
    if rw.far {
        f.push_str(&format!(
            "# IMAGE_SIZE\t{:#x}\n# FILE_IMAGE_LEN\t{:#x}\n",
            rw.image_size, rw.file_image_len
        ));
    }
    if rw.two {
        f.push_str(&format!(
            "# BACK_OFF\t{:#x}\n# BACK_LEN\t{back_len:#x}\n",
            rw.back_off
        ));
    }
    for (k, i) in [("K18", 0), ("KTLS", 1), ("KTLR", 2), ("KGATE", 3)] {
        f.push_str(&format!("# KEY_{k}_IDX\t{i}\n"));
    }
    if rw.fs_state_off != 0 {
        f.push_str(&format!("# FPS_STATE_OFF\t{:#x}\n", rw.fs_state_off));
    }
    if let Some(m) = &rw.ue_malloc {
        f.push_str(&format!(
            "# UE_MALLOC_VT\t{:#x}\n# UE_MALLOC_SLOT\t{:#x}\n",
            m.vtable, m.slot
        ));
    }
    if let Some((g, fl)) = rw.fps_target {
        f.push_str(&format!(
            "# FPS_TARGET_PTR\t{g:#x}\n# FPS_TARGET_FIELD\t{fl:#x}\n"
        ));
    }
    if let Some(m) = rw.monolith_interval {
        f.push_str(&format!("# MONOLITH_INTERVAL\t{m:#x}\n"));
    }
    if rw.native_fps_blocked {
        f.push_str("# NATIVE_FPS_BLOCKED\t0x1\n");
    }
    if let Some((g, fl, flag)) = rw.ue_fixed {
        f.push_str(&format!("# UE_FIXED_RATE_PTR\t{g:#x}\n# UE_FIXED_RATE_FIELD\t{fl:#x}\n# UE_FIXED_RATE_FLAG\t{flag:#x}\n"));
    }
    if let Some(t) = rw.unity.target {
        f.push_str(&format!("# UNITY_TARGET_FPS\t{t:#x}\n"));
    }
    if let Some(q) = rw.unity.qs {
        for (k, v) in ["PTR", "IDX", "ARR", "SIZE", "VSYNC"]
            .iter()
            .zip([q.0, q.1, q.2, q.3, q.4])
        {
            f.push_str(&format!("# UNITY_QS_{k}\t{v:#x}\n"));
        }
    }
    for (n, o) in &rw.ue_cvars {
        f.push_str(&format!("# UE_CVAR:{n}\t{o:#x}\n"));
    }
    if rw.render_scale != 0 {
        if !(1..=9).contains(&rw.render_scale) {
            return Err(Fail::new(format!(
                "render scale stub: ctx.render_scale is a whole largest scale, 1 to 9: {}",
                rw.render_scale
            )));
        }
        f.push_str(&format!("# RENDER_SCALE\t{}\n", rw.render_scale));
    }
    if rw.step_max != 0 {
        if !(1..=3).contains(&rw.step_max) {
            return Err(Fail::new(format!(
                "frame step stub: ctx.step_max is a whole step, 1 to 3: {}",
                rw.step_max
            )));
        }
        f.push_str(&format!("# STEP_MAX\t{}\n", rw.step_max));
    }
    if name == "main" {
        let mut caps: std::collections::BTreeSet<String> =
            crate::patches::capabilities_for(&rw.build_id)
                .iter()
                .map(|s| s.to_string())
                .collect();
        caps.extend(rw.fs_capabilities.iter().cloned());
        for c in caps {
            let ok = c.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
                && c.chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
            if !ok {
                return Err(Fail::new(format!("invalid capability {c}")));
            }
            f.push_str(&format!("# {c}\t1\n"));
        }
    }
    f.push_str(&format!("# BUILD_ID\t{}\n", rw.build_id));

    // gates.tsv
    let mut gates = String::new();
    for g in &rw.gates {
        gates.push_str(&format!(
            "{}\t{}\t{}\t{:#x}\n",
            hx(g.ret),
            g.kind,
            g.arg,
            g.orig
        ));
    }
    // sites.tsv
    let mut sites = String::new();
    for (a, k) in &rw.kinds {
        if !rw.done.contains(a) {
            sites.push_str(&format!("{a:#x}\t{}\n", k.name()));
        }
    }
    for w in &rw.windows {
        sites.push_str(&format!(
            "{:#x}\tW\t{:#x}\n",
            w[0].address,
            w.last().unwrap().address + 4
        ));
    }
    for (a, (b, c)) in rw.jumps.items.iter() {
        sites.push_str(&format!("{a:#x}\tJ\t{b:#x}\t{c}\n"));
    }
    for (a, tgt) in rw.tabjumps.items.iter() {
        let l: Vec<String> = tgt.iter().map(|t| format!("{t:#x}")).collect();
        sites.push_str(&format!("{a:#x}\tT\t{}\n", l.join(" ")));
    }
    for (t, bes, _) in &rw.spin_sites {
        let l: Vec<String> = bes.iter().map(|b| format!("{b:#x}")).collect();
        sites.push_str(&format!("{t:#x}\tS\t{}\n", l.join(" ")));
    }
    // cuts.tsv
    let mut cuts = format!("# BUILD_ID\t{}\n", rw.build_id);
    for c in &rw.cuts {
        cuts.push_str(&format!("{:#x}\t{}\t{}\t{}\n", c.off, c.old, c.new, c.why));
    }
    // changed.tsv: the text words whose instructions no longer run as the file has them
    let mut words: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for (a, orig, cur) in rw.img.changed() {
        // not an exclusive access that only gained ordering
        if rw.ordered.contains(&(a as i64)) && cur == (orig | 0x8000) {
            continue;
        }
        words.insert(a as i64);
    }
    for w in &rw.windows {
        let (lo, hi) = (w[0].address, w.last().unwrap().address + 4);
        words.extend((lo..hi).step_by(4));
    }
    words.extend(rw.spin_words.iter().copied());
    let mut runs: Vec<(i64, i64)> = Vec::new();
    for w in words {
        match runs.last_mut() {
            Some(r) if r.0 + r.1 == w => r.1 += 4,
            _ => runs.push((w, 4)),
        }
    }
    let mut changed = format!("# BUILD_ID\t{}\n", rw.build_id);
    for (o, n) in runs {
        changed.push_str(&format!("{o:#x}\t{n:#x}\n"));
    }
    // obs.tsv
    let mut obs = format!("# BUILD_ID\t{}\n", rw.build_id);
    for o in &rw.obs {
        obs.push_str(&format!(
            "{:#x}\t{}\t{}\t{}\n",
            o.off, o.number, o.word, o.why
        ));
    }
    // the stats line and the data blocks line
    let mut line = format!(
        "{name} {} cuts {} obs {} patch {} PATCH_OFF {}",
        dict_repr(&rw.stats),
        rw.cuts.len(),
        rw.obs.len(),
        patch_front_len + rw.patch_back.len(),
        hx(rw.patch_off)
    );
    if rw.two {
        line.push_str(&format!(
            " BACK_OFF {:#x} back {}",
            rw.back_off,
            rw.patch_back.len()
        ));
    }
    line.push_str(&format!(" slot_refs {} gates {}", rw.fix, rw.gates.len()));
    rw.say(line);
    if !rw.data_blocks.is_empty() {
        let l: Vec<String> = rw
            .data_blocks
            .iter()
            .map(|(s, e)| format!("{s:#x}..{e:#x}"))
            .collect();
        rw.say(format!("{name} data blocks left alone: {}", l.join(", ")));
    }
    Ok(Rewritten {
        name,
        image: std::mem::take(&mut rw.img.b),
        pad_to,
        patch,
        fixups: f,
        gates,
        sites,
        cuts,
        changed,
        obs,
        match_tsv: rw.match_tsv.take(),
        build_src,
        log: std::mem::take(&mut rw.log),
    })
}

/// The hashes of the Python sources the rewriter is built from, the same file `patch_nso.py` writes (one line per file,
/// by path from `dm/tools`): only meaningful beside the engine's Python tools, so it is written only on request.
pub fn build_src_sha256(tools: &Path) -> Res<String> {
    let mut files: Vec<String> = [
        "patch_nso.py",
        "nso.py",
        "nso_code.py",
        "nso_asm.py",
        "ue_cvar.py",
        "ue_malloc.py",
        "fps_target.py",
        "monolith_fps.py",
        "ue_fixed_rate.py",
        "unity_fps.py",
        "unity_bucket.py",
        "ue_region.py",
        "ue_ring.py",
        "snowdrop_pools.py",
        "loader_census.py",
        "sdk_patches.py",
        "engine_patches.py",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let games = tools.join("../games");
    let mut ids: Vec<String> = std::fs::read_dir(&games)
        .map_err(|e| Fail::new(format!("{}: {e}", games.display())))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("patches.py").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    ids.sort();
    files.extend(
        ids.into_iter()
            .map(|id| format!("../games/{id}/patches.py")),
    );
    let mut out = String::new();
    for rel in files {
        let data = std::fs::read(tools.join(&rel)).map_err(|e| Fail::new(format!("{rel}: {e}")))?;
        out.push_str(&format!("{}  {rel}\n", hex(&Sha256::digest(&data))));
    }
    Ok(out)
}
