# Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

default:
	@just --list

build:
	cargo build --workspace

lint:
	cargo fmt --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

coverage:
	toolchain="$(awk -F'"' '/^channel = / {print $2}' rust-toolchain.toml)"; \
	host="$(rustc -vV | sed -n 's/^host: //p')"; \
	toolchain_root="$(dirname "$(dirname "$(rustup which rustc --toolchain "$toolchain")")")"; \
	LLVM_COV="$toolchain_root/lib/rustlib/$host/bin/llvm-cov" \
	LLVM_PROFDATA="$toolchain_root/lib/rustlib/$host/bin/llvm-profdata" \
	cargo llvm-cov --workspace --summary-only
