# Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# renovate: datasource=github-releases depName=renovatebot/renovate versioning=semver
RENOVATE_VERSION := "44.107.0"

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

renovate-sync *OPTS: _renovate
	renovate --platform "${RENOVATE_PLATFORM:-local}" {{ OPTS }}

_renovate:
	npm list -g renovate@{{ RENOVATE_VERSION }} >/dev/null 2>&1 || npm install -g renovate@{{ RENOVATE_VERSION }}
