use ibuilder_macho::{assemble_files, Game};
use std::{env, path::PathBuf, process};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!("usage: assemble_host_candidate <host.dylib> <output.dylib> <tag> <module> [module ...]");
        process::exit(2);
    }
    let host = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let tag = &args[2];
    let modules = args[3..].to_vec();
    let game = Game::Synthetic { modules: modules.clone() };

    match assemble_files(&host, &output, &game, tag) {
        Ok(report) => {
            println!("Synthetic host assembly succeeded.");
            println!("Host bytes: {}", report.info.host_size);
            println!("Output bytes: {}", report.info.size);
            println!("Modules: {}", modules.join(", "));
            println!("Load commands: {}", report.info.n_load_commands);
            println!("Reserved __TEXT gap used: {} bytes", report.info.game_bytes + report.info.w_bytes);
        }
        Err(error) => {
            eprintln!("Synthetic host assembly failed: {error}");
            process::exit(1);
        }
    }
}
