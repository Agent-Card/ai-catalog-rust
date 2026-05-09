# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

default:
	@just --list

set windows-shell := ["powershell", "-NoLogo", "-NoProfile", "-Command"]

demo_oci_layout_command := if os_family() == "windows" {
	"powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File ./demo/oci-layout-walkthrough.ps1"
} else {
	"./demo/oci-layout-walkthrough.sh"
}

build:
	cargo build --workspace

lint:
	cargo fmt --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

demo-oci-layout:
	{{demo_oci_layout_command}}

coverage:
	toolchain="$(awk -F'"' '/^channel = / {print $2}' rust-toolchain.toml)"; \
	host="$(rustc -vV | sed -n 's/^host: //p')"; \
	toolchain_root="$(dirname "$(dirname "$(rustup which rustc --toolchain "$toolchain")")")"; \
	LLVM_COV="$toolchain_root/lib/rustlib/$host/bin/llvm-cov" \
	LLVM_PROFDATA="$toolchain_root/lib/rustlib/$host/bin/llvm-profdata" \
	cargo llvm-cov --workspace --summary-only