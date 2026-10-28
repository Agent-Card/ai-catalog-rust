// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
// SPDX-License-Identifier: Apache-2.0

//! `cargo run -p ai-catalog-discover --example discover -- example.com`

fn main() {
    let input = std::env::args()
        .nth(1)
        .expect("usage: discover <domain or URL>");
    match ai_catalog_discover::discover(&input) {
        Ok(found) => {
            println!("{} ({})", found.url, found.method);
            for entry in &found.catalog.entries {
                println!("  {} [{}]", entry.identifier, entry.entry_type);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
