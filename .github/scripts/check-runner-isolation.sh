#!/usr/bin/env bash
# Check checkout ownership and allocate job-specific temporary state.
set -euo pipefail

workspace="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
workspace="$(cd "$workspace" && pwd -P)"
if [ -n "${RUNNER_WORKSPACE:-}" ]; then
  runner_workspace="$(cd "$RUNNER_WORKSPACE" && pwd -P)"
  case "$workspace/" in
    "$runner_workspace/"*) ;;
    *) echo "::error::workspace $workspace is outside $runner_workspace"; exit 1 ;;
  esac
fi

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  case "$CARGO_TARGET_DIR" in
    /*) target="$CARGO_TARGET_DIR" ;;
    *) target="$workspace/$CARGO_TARGET_DIR" ;;
  esac
  target="$(realpath -m "$target")"
  case "$target/" in
    "$workspace/"*) ;;
    *) echo "::error::CARGO_TARGET_DIR=$target is outside $workspace"; exit 1 ;;
  esac
fi

origin="$(git -C "$workspace" remote get-url origin 2>/dev/null || true)"
case "$origin" in
  https://github.com/trunkszi/cares-rs|https://github.com/trunkszi/cares-rs.git|git@github.com:trunkszi/cares-rs.git) ;;
  *) echo "::error::unexpected checkout origin: ${origin:-none}"; exit 1 ;;
esac

if [ -n "${GITHUB_ENV:-}" ]; then
  temp_root="${RUNNER_TEMP:-$workspace/target/ci-tmp}"
  mkdir -p "$temp_root"
  temp_dir="$(mktemp -d "$temp_root/cares-rs.XXXXXXXX")"
  echo "TMPDIR=$temp_dir" >> "$GITHUB_ENV"
  echo "Temporary state: $temp_dir"
fi

if [ -e /tmp/.cares-rs-ci-private ]; then
  host_shm="$(awk '$5 == "/dev/shm" { print $3 }' /proc/1/mountinfo)"
  own_shm="$(stat -c '%Hd:%Ld' /dev/shm)"
  if [ -z "$host_shm" ] || [ "$host_shm" = "$own_shm" ]; then
    echo "::error::runner requests private shared memory but shares the host mount"
    exit 1
  fi
fi

echo "Runner isolation checks passed for $workspace"
