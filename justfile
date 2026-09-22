# Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-rust)
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# renovate: datasource=github-releases depName=renovatebot/renovate versioning=semver
RENOVATE_VERSION := "44.107.0"

BIN_DIR := justfile_directory() / ".bin"
# The version is part of the path, so a bump installs fresh instead of
# reusing whatever is already there.
RENOVATE_HOME := BIN_DIR / ("renovate-" + RENOVATE_VERSION)
RENOVATE_BIN := RENOVATE_HOME / "node_modules" / ".bin" / "renovate"

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

# Sync dependencies with Renovate (local and analytical unless RENOVATE_PLATFORM is set)
renovate-sync *OPTS: _renovate
	"{{ RENOVATE_BIN }}" --platform "${RENOVATE_PLATFORM:-local}" {{ OPTS }}

_renovate:
	[ -x "{{ RENOVATE_BIN }}" ] || npm install --prefix "{{ RENOVATE_HOME }}" --no-audit --no-fund --loglevel=error renovate@{{ RENOVATE_VERSION }}
