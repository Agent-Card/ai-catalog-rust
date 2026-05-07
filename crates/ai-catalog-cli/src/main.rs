// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::process;

fn main() {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let exit_code = ai_catalog_cli::run(std::env::args(), &mut stdin, &mut stdout, &mut stderr)
        .unwrap_or_else(|error| {
            eprintln!("failed to write CLI output: {error}");
            1
        });

    process::exit(exit_code);
}
