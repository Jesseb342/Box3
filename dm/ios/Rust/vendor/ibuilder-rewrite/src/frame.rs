//! Game profiles (`dm/games/<id>/game.tsv`): the little of `game.py` the rewriter reads (the profile's rows).

use crate::rewriter::Options;
use std::path::{Path, PathBuf};

/// `game.find_dir(name)`'s `game.tsv`: a path is taken as is, a title ID is looked up in the search folders in order
pub fn find_game_tsv(opts: &Options, name: &str) -> Option<PathBuf> {
    let p = if name.contains('/') {
        PathBuf::from(name).join("game.tsv")
    } else {
        opts.games_dirs
            .iter()
            .map(|d| d.join(name).join("game.tsv"))
            .find(|p| p.exists())?
    };
    if p.is_file() { Some(p) } else { None }
}

/// The repository profile's `game.tsv` (the first games folder only), for the build rows
pub fn find_game_tsv_in_repo(opts: &Options, profile: &str) -> Option<PathBuf> {
    let p = opts.games_dirs.first()?.join(profile).join("game.tsv");
    if p.is_file() { Some(p) } else { None }
}

/// the raw lines of a file (`read_text().splitlines()`), empty when unreadable
pub fn read_raw_rows(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|t| t.lines().map(String::from).collect())
        .unwrap_or_default()
}

/// `Game.rows`: (key, values) of every line that is not blank or a comment
pub fn read_rows(path: &Path) -> Vec<(String, Vec<String>)> {
    read_raw_rows(path)
        .into_iter()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            (
                c[0].trim().to_string(),
                c[1..].iter().map(|v| v.trim().to_string()).collect(),
            )
        })
        .collect()
}
