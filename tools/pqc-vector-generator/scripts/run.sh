#!/usr/bin/env bash
# Build against an explicitly chosen Sequoia checkout without editing Cargo.toml.
set -euo pipefail
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 SEQUOIA_CHECKOUT GENERATOR_COMMAND [ARGS...]" >&2
    exit 2
fi
SEQUOIA="$(realpath "$1")"
shift
GENERATOR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 - "$GENERATOR" "$WORK" "$SEQUOIA" <<'PY'
import json, pathlib, shutil, sys
source, destination, sequoia = map(pathlib.Path, sys.argv[1:])
shutil.copytree(source / 'src', destination / 'src')
shutil.copyfile(source / 'build.rs', destination / 'build.rs')
shutil.copyfile(source / 'Cargo.lock', destination / 'Cargo.lock')
manifest = (source / 'Cargo.toml').read_text().replace(
    'path = "../../../sequoia/openpgp"', 'path = ' + json.dumps(str(sequoia / 'openpgp')))
(destination / 'Cargo.toml').write_text(manifest)
PY
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$GENERATOR/target}" \
    cargo run --locked --manifest-path "$WORK/Cargo.toml" -- "$@"
