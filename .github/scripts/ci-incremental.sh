#!/usr/bin/env bash
# Validate repository invariants and test changed packages with their consumers.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
base="${1:-HEAD~1}"
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  base=HEAD
fi
base="$(git rev-parse "$base^{commit}")"
export CARES_CI_BASE="$base"
echo "Incremental CI base: $base"

python3 - <<'PY'
import pathlib
import subprocess
import sys
import tomllib

paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
).decode().split("\0")
errors = []
manifests = []
for name in sorted(set(paths) - {""}):
    path = pathlib.Path(name)
    if not path.is_file():
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if len(text.splitlines()) > 800:
        errors.append(f"{name}: exceeds 800 lines")
    if any(
        0x3400 <= ord(ch) <= 0x9FFF
        or 0xF900 <= ord(ch) <= 0xFAFF
        or 0x20000 <= ord(ch) <= 0x323AF
        for ch in text
    ):
        errors.append(f"{name}: contains CJK characters")
    if "".join(map(chr, [104, 102, 116])) in text.lower():
        errors.append(f"{name}: contains a forbidden identifier fragment")
    if path.name == "Cargo.toml":
        manifests.append(path)

for path in manifests:
    with path.open("rb") as handle:
        document = tomllib.load(handle)

    def visit(table):
        for key, value in table.items():
            if key.endswith("dependencies") and isinstance(value, dict):
                for name, spec in value.items():
                    package = spec.get("package", name) if isinstance(spec, dict) else name
                    if name.startswith(("tokio", "futures", "async", "smol")) or package.startswith(
                        ("tokio", "futures", "async", "smol")
                    ):
                        errors.append(f"{path}: forbidden runtime dependency {name}")
                    if path == pathlib.Path("Cargo.toml") and not isinstance(spec, dict):
                        errors.append(f"{path}: dependency {name} must use an inline table")
            elif isinstance(value, dict):
                visit(value)

    visit(document)
    if path == pathlib.Path("Cargo.toml"):
        in_dependencies = False
        for line in path.read_text().splitlines():
            if line.startswith("["):
                in_dependencies = line.endswith("dependencies]")
            elif in_dependencies and line.strip() and not line.lstrip().startswith("#"):
                if "=" in line and not line.split("=", 1)[1].lstrip().startswith("{"):
                    errors.append(f"{path}: dependency must use an inline table: {line}")

if errors:
    for error in errors:
        print(f"::error::{error}", file=sys.stderr)
    sys.exit(1)
print(f"Repository invariants passed ({len(manifests)} manifests)")
PY

if [ "${CI_INVARIANTS_ONLY:-0}" = 1 ]; then
  exit 0
fi

# Use Cargo's package dependency metadata to include every reverse dependent.
selection="$(python3 - <<'PY'
import json
import os
import pathlib
import subprocess

meta = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True
))
members = set(meta["workspace_members"])
packages = {p["name"]: p for p in meta["packages"] if p["id"] in members}
base = os.environ["CARES_CI_BASE"]
head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
changed = set(subprocess.check_output(
    ["git", "diff", "--name-only", f"{base}...HEAD"], text=True
).splitlines())
changed.update(subprocess.check_output(
    ["git", "diff", "--name-only", "HEAD"], text=True
).splitlines())
changed.update(subprocess.check_output(
    ["git", "ls-files", "--others", "--exclude-standard"], text=True
).splitlines())
run_all = base == head or os.environ.get("GITHUB_EVENT_NAME") in (
    "schedule", "workflow_dispatch"
)
selected = set()
root = pathlib.Path(meta["workspace_root"])
for name in changed:
    if name in ("Cargo.toml", "Cargo.lock", "deny.toml", "rust-toolchain.toml", "rustfmt.toml") or name.startswith(".github/"):
        run_all = True
    for package, data in packages.items():
        directory = pathlib.Path(data["manifest_path"]).parent.relative_to(root)
        if pathlib.Path(name).is_relative_to(directory):
            selected.add(package)
if run_all:
    selected.update(packages)
while True:
    consumers = {
        name for name, package in packages.items()
        if any(dep["name"] in selected for dep in package["dependencies"])
    }
    if consumers <= selected:
        break
    selected.update(consumers)
for name in sorted(selected):
    print(name)
PY
)"

if [ -z "$selection" ]; then
  echo "No workspace packages affected."
  exit 0
fi
mapfile -t packages <<< "$selection"

cargo fmt --all -- --check
for package in "${packages[@]}"; do
  echo "Checking $package with the default upstream source"
  cargo clippy -p "$package" --all-targets -- -D warnings
  cargo test -p "$package"
done
for package in "${packages[@]}"; do
  case "$package" in
    cares-sys|cares)
      echo "Checking $package with the pinned stable upstream source"
      cargo clippy -p "$package" --all-targets --no-default-features --features stable -- -D warnings
      cargo test -p "$package" --no-default-features --features stable
      ;;
  esac
done

echo "Incremental CI passed for: ${packages[*]}"
