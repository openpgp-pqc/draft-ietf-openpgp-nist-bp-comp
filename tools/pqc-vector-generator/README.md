# NIST/Brainpool PQC OpenPGP Test Vector Generator

This utility generates the OpenPGP test vectors used by `draft-ietf-openpgp-nist-bp-comp`.

It generates vectors for the following composite algorithms:

| Signature algorithm | ID | KEM algorithm | ID |
|---|---:|---|---:|
| ML-DSA-65 + ECDSA-NIST-P-384 | 41 | ML-KEM-768 + ECDH-NIST-P-384 | 37 |
| ML-DSA-87 + ECDSA-NIST-P-521 | 42 | ML-KEM-1024 + ECDH-NIST-P-521 | 38 |
| ML-DSA-65 + ECDSA-brainpoolP384r1 | 43 | ML-KEM-768 + ECDH-brainpoolP384r1 | 39 |
| ML-DSA-87 + ECDSA-brainpoolP512r1 | 44 | ML-KEM-1024 + ECDH-brainpoolP512r1 | 40 |

## Requirements

The generator depends on a Sequoia OpenPGP checkout containing support for these NIST/Brainpool PQC composite algorithms.

By default, `Cargo.toml` assumes the following directory layout:

```text
repos/
├── sequoia/
└── draft-ietf-openpgp-nist-bp-comp/
    └── tools/
        └── pqc-vector-generator/
```

and therefore uses:

```toml
sequoia-openpgp = {
    path = "../../../sequoia/openpgp",
    default-features = false,
    features = ["crypto-openssl"]
}
```

Adjust this path if your checkout layout differs.

An OpenSSL backend with the required PQC support is required.

For independent verification of generated vectors, a compatible `sq` build is also required.

## Generated Test Data

All signature and encryption vectors operate on the literal data:

```text
Testing
```

including the terminating newline.

The exact octets are:

```text
54 65 73 74 69 6e 67 0a
```

The generator writes this input to `Testing.txt`.

## Certificate Structure

Each generated certificate consists of:

- a v6 composite signature primary key;
- a v6 Direct Key self-signature;
- the User ID `PQC user (Test Key) <pqc-test-key@example.com>`;
- a v6 positive certification self-signature;
- one v6 composite KEM encryption subkey; and
- a v6 subkey binding signature.

The primary key carries the `Certify` and `Sign` flags.

The encryption subkey carries the `Encrypt for Transport` and `Encrypt at Rest` flags.

Certificate preferences are:

- Features: SEIPDv1 and SEIPDv2
- AEAD: AES-256/OCB, AES-192/OCB, AES-128/OCB
- Symmetric algorithms: AES-256, AES-192, AES-128
- Hash algorithms: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- Compression: Uncompressed

## Hash Algorithms

Certificate signatures use:

| Signature algorithm | Hash |
|---|---|
| 41 | SHA3-256 |
| 42 | SHA3-512 |
| 43 | SHA3-256 |
| 44 | SHA3-512 |

Detached signatures use:

| Signature algorithm | Hash |
|---|---|
| 41 | SHA-256 |
| 42 | SHA3-512 |
| 43 | SHA-256 |
| 44 | SHA3-512 |

Signatures embedded in encrypted messages use SHA-256 for all four signature algorithms.

## Encrypted Messages

Encrypted messages use:

- a v6 PKESK;
- a v2 SEIPD packet;
- AES-256;
- OCB; and
- the Sequoia streaming encryptor's default chunk size.

The test vectors currently included in the draft were generated with a resulting chunk size of 4096 octets.

## Commands

Generate only certificates:

```bash
cargo run -- generate-keys --output /tmp/pqc-vectors
```

Generate detached signatures using certificates already present in the output directory:

```bash
cargo run -- generate-detached --output /tmp/pqc-vectors
```

Generate encrypted and signed messages:

```bash
cargo run -- generate-message --output /tmp/pqc-vectors
```

Generate the complete set:

```bash
cargo run -- all --output /tmp/pqc-vectors
```

Existing generated files are not overwritten unless `--force` is explicitly supplied.

For publication-quality vectors, generate the complete set into a new empty directory and do not subsequently regenerate individual files.

## Output Files

Certificates:

```text
seckey-primary41-sub37.asc
pubkey-primary41-sub37.asc

seckey-primary42-sub38.asc
pubkey-primary42-sub38.asc

seckey-primary43-sub39.asc
pubkey-primary43-sub39.asc

seckey-primary44-sub40.asc
pubkey-primary44-sub40.asc
```

Detached signatures:

```text
detached-alg41.asc
detached-alg42.asc
detached-alg43.asc
detached-alg44.asc
```

Encrypted and signed messages:

```text
encrypted-alg37_signed-alg41.asc
encrypted-alg38_signed-alg42.asc
encrypted-alg39_signed-alg43.asc
encrypted-alg40_signed-alg44.asc
```

Test input:

```text
Testing.txt
```

## Extracting KEM Intermediate Values

The Internet-Draft additionally records the following intermediate values for each encrypted message:

- `mlkemKeyShare`;
- `ecdhKeyShare`;
- the output of `multiKeyCombine`; and
- the OpenPGP session key.

These values are intentionally not extracted by this standalone generator.

The calculation relies on Sequoia-internal cryptographic APIs. To avoid duplicating cryptographic logic or exposing production APIs solely for test-vector generation, these values are extracted using a test-only helper in the Sequoia OpenPGP source tree.

The helper reads the generated secret certificate and encrypted message, performs the same decapsulation and combiner operations as Sequoia's implementation, independently decrypts the PKESK, and produces one metadata file per suite:

```text
metadata-alg41.json
metadata-alg42.json
metadata-alg43.json
metadata-alg44.json
```

Each file contains values of the form:

```json
{
  "recipient": "...",
  "pkAlgorithm": "...",
  "mlkemKeyShare": "...",
  "ecdhKeyShare": "...",
  "multiKeyCombine": "...",
  "sessionKey": "..."
}
```

The test-only extractor should always be run against the exact generated vector set that will be published.

## Verification

The supplied `scripts/verify.sh` script verifies a complete generated vector directory using `sq`.

Example:

```bash
./scripts/verify.sh /tmp/pqc-vectors /path/to/sq
```

The script verifies:

- all four detached signatures;
- all four encrypted-message signatures;
- successful decryption;
- exact recovery of `Testing.txt`;
- v6 PKESKs;
- v2 SEIPD;
- AES-256/OCB; and
- detached-signature packet structure.

KEM intermediate metadata must be generated separately using the Sequoia test-only extractor described above.

## Reproducibility

The generator intentionally uses the system time and cryptographically secure randomness.

Therefore, repeated runs do not produce byte-identical vectors. In particular, the following values will change:

- key material;
- fingerprints;
- signatures;
- ciphertexts;
- KEM intermediate values; and
- session keys.

A published vector set must therefore be treated as one atomic generated artifact.

The recommended procedure is:

1. Generate the complete set once into a new directory.
2. Extract the KEM intermediate metadata from that exact set.
3. Verify that exact set.
4. Record the fingerprints and KEM values from that exact set in the draft.
5. Copy the exact generated OpenPGP artifacts into `test-vectors/`.
6. Do not regenerate any individual member of the published set.

This keeps the prose, fingerprints, KEM values, signatures, keys, and encrypted messages mutually consistent.
