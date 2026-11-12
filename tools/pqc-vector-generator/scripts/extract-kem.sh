#!/usr/bin/env bash
# Run the upstream test-only extractor in a copy; never modify the source checkout.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "Usage: $0 VECTOR_DIR SEQUOIA_CHECKOUT" >&2
    exit 2
fi
VECTOR_DIR="$(realpath "$1")"
SEQUOIA="$(realpath "$2")"
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 - "$SEQUOIA" "$WORK/sequoia" <<'PYCODE'
import pathlib, shutil, sys
assert 'fn extract_nist_bp_vector_kem_values' in (pathlib.Path(sys.argv[1]) / 'openpgp/src/crypto/tests.rs').read_text(), 'compatible Sequoia KEM extractor not found'
shutil.copytree(sys.argv[1], sys.argv[2], ignore=shutil.ignore_patterns('.git', 'target'))
PYCODE
PQC_VECTOR_DIR="$VECTOR_DIR" CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/../target/extractor}" cargo test --locked --manifest-path "$WORK/sequoia/openpgp/Cargo.toml" \
    --no-default-features --features crypto-openssl --lib \
    crypto::tests::extract_nist_bp_vector_kem_values -- --ignored --exact --nocapture
