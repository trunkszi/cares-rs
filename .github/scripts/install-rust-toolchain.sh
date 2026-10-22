#!/usr/bin/env bash
# Install the pinned toolchain without changing other jobs' default toolchain.
set -euo pipefail

channel="$(python3 -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
mapfile -t components < <(python3 -c 'import tomllib; print("\n".join(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"].get("components", [])))')
mapfile -t targets < <(python3 -c 'import tomllib; print("\n".join(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"].get("targets", [])))')
args=(--profile minimal)
for component in "${components[@]}" "$@"; do
  [ -z "$component" ] || args+=(--component "$component")
done
for target in "${targets[@]}"; do
  [ -z "$target" ] || args+=(--target "$target")
done

rustup_root="${RUSTUP_HOME:-$HOME/.rustup}"
mkdir -p "$rustup_root"
exec 9>"$rustup_root/cares-rs-ci.lock"
flock 9
rustup toolchain install "$channel" "${args[@]}"
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "RUSTUP_TOOLCHAIN=$channel" >> "$GITHUB_ENV"
fi
RUSTUP_TOOLCHAIN="$channel" rustc --version
RUSTUP_TOOLCHAIN="$channel" cargo --version
