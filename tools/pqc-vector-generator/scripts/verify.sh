#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 VECTOR_DIR [SQ]"
    exit 2
fi

VECTOR_DIR="$(realpath "$1")"
SQ="${2:-sq}"

if [[ ! -d "$VECTOR_DIR" ]]; then
    echo "Vector directory not found: $VECTOR_DIR" >&2
    exit 1
fi

if ! command -v "$SQ" >/dev/null 2>&1 && [[ ! -x "$SQ" ]]; then
    echo "sq executable not found: $SQ" >&2
    exit 1
fi

pairs=(
    "41 37"
    "42 38"
    "43 39"
    "44 40"
)

echo "Using vector directory: $VECTOR_DIR"
echo "Using sq: $SQ"
echo

echo "=== Detached signatures ==="

for pair in "${pairs[@]}"; do
    read -r primary sub <<< "$pair"

    echo
    echo "--- ${primary}/${sub} ---"

    "$SQ" verify \
        --signer-file "$VECTOR_DIR/pubkey-primary${primary}-sub${sub}.asc" \
        --signature-file "$VECTOR_DIR/detached-alg${primary}.asc" \
        "$VECTOR_DIR/Testing.txt"
done

echo
echo "=== Encrypted and signed messages ==="

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

for pair in "${pairs[@]}"; do
    read -r primary sub <<< "$pair"

    echo
    echo "--- ${primary}/${sub} ---"

    plaintext="$tmpdir/plaintext-${primary}.txt"

    "$SQ" decrypt \
        --recipient-file "$VECTOR_DIR/seckey-primary${primary}-sub${sub}.asc" \
        --signer-file "$VECTOR_DIR/pubkey-primary${primary}-sub${sub}.asc" \
        --output "$plaintext" \
        "$VECTOR_DIR/encrypted-alg${sub}_signed-alg${primary}.asc"

    cmp "$VECTOR_DIR/Testing.txt" "$plaintext"

    echo "Plaintext: OK"
done

echo
echo "=== Encrypted packet structure ==="

for pair in "${pairs[@]}"; do
    read -r primary sub <<< "$pair"

    echo
    echo "--- ${primary}/${sub} ---"

    dump="$(
        "$SQ" packet dump \
            "$VECTOR_DIR/encrypted-alg${sub}_signed-alg${primary}.asc" \
            2>&1
    )"

    echo "$dump" | grep -E \
        'Public-Key Encrypted Session Key Packet|Sym. Encrypted and Integrity Protected Data Packet|Version:|Pk algo:|Symmetric algo:|AEAD algo:|Chunk size:'
done

echo
echo "=== Detached signature structure ==="

for pair in "${pairs[@]}"; do
    read -r primary sub <<< "$pair"

    echo
    echo "--- alg ${primary} ---"

    "$SQ" packet dump \
        "$VECTOR_DIR/detached-alg${primary}.asc" \
        | grep -E \
            'Version:|Type:|Pk algo:|Hash algo:|Signature creation time:|Issuer Fingerprint:'
done

echo
echo "=== Metadata ==="

metadata_missing=0

for primary in 41 42 43 44; do
    metadata="$VECTOR_DIR/metadata-alg${primary}.json"

    if [[ -s "$metadata" ]]; then
        echo "metadata-alg${primary}.json: OK"
    else
        echo "metadata-alg${primary}.json: not present"
        metadata_missing=1
    fi
done

echo
echo "Cryptographic vector verification completed successfully."

if [[ "$metadata_missing" -ne 0 ]]; then
    echo "Note: KEM metadata is generated separately by the Sequoia test-only extractor."
fi
