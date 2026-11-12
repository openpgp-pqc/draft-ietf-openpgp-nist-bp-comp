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
[dependencies.sequoia-openpgp]
path = "../../../sequoia/openpgp"
default-features = false
features = ["crypto-openssl"]
```

Adjust this path if your checkout layout differs.

The vector set in this pull request was generated with the Sequoia
implementations developed in the following merge requests:

- [assigned algorithm IDs 37–44](https://gitlab.com/sequoia-pgp/sequoia/-/merge_requests/1886);
- [NIST/Brainpool PQC cipher suites](https://gitlab.com/sequoia-pgp/sequoia/-/merge_requests/1887); and
- [the test-only KEM intermediate-value extractor](https://gitlab.com/fluppe2/sequoia/-/merge_requests/1).

These references identify the implementation branches used for the published
vectors; the local path dependency allows the generator to be built from those
checkouts.

An OpenSSL backend with the required PQC support is required.

Verification uses the generator's `verify` command with the same compatible
Sequoia dependency. Python 3 with the `cryptography` package is required for the
separate metadata check. A compatible `sq` is optional for additional verification.
The system `sq` may lack these experimental composite algorithms.

The message-digest vector update was generated and verified with Sequoia commit
`dbe031ac388179b45e6e6c25272130ba92d79e48`, which includes assigned IDs 37–44
and the test-only KEM extractor. The older `pqc-nist-bp` branch using private
IDs 100–107 is incompatible with these vectors.

To prepare a compatible checkout without changing an existing Sequoia checkout:

```bash
git clone https://gitlab.com/fluppe2/sequoia.git /tmp/sequoia-vectors
git -C /tmp/sequoia-vectors fetch origin refs/merge-requests/1/head
git -C /tmp/sequoia-vectors checkout --detach dbe031ac388179b45e6e6c25272130ba92d79e48
```

Use `scripts/run.sh /tmp/sequoia-vectors COMMAND ...` instead of `cargo run -- COMMAND ...`
when the compatible checkout is elsewhere. This builds a temporary copy of the
generator against the specified path, using the checked-in lockfile, without
editing either checkout. It also copies the build-time compatibility guard.
Build artifacts are cached in the generator's `target/`.

The build guard checks that the selected source maps the composite algorithms
in both directions to IDs 37–44 and fails with a compatibility diagnostic for
an old private-ID checkout. It targets the recorded Sequoia source layout.
Plain `cargo run` requires a compatible sibling checkout; `cargo run --locked`
may reject an incompatible dependency version before reaching the guard.
The verification wrapper requires `SEQUOIA_CHECKOUT` or an explicit
`PQC_VECTOR_GENERATOR` binary and never silently builds against the sibling.

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
- Hash algorithms: SHA2-384, SHA2-512, SHA3-512
- Compression: Uncompressed

## Hash Algorithms

Certificate signatures use:

| Signature algorithm | Hash |
|---|---|
| 41 | SHA3-512 |
| 42 | SHA3-512 |
| 43 | SHA3-512 |
| 44 | SHA3-512 |

Detached signatures use:

| Signature algorithm | Hash |
|---|---|
| 41 | SHA2-384 |
| 42 | SHA3-512 |
| 43 | SHA2-384 |
| 44 | SHA3-512 |

Signatures embedded in encrypted messages use SHA2-384 for algorithms 41 and 43,
and SHA3-512 for algorithms 42 and 44. These choices concern message digests;
all certificate signatures use SHA3-512 to satisfy the 384-bit minimum for
every signature type. The KEM combiner still uses SHA3-256; it is not a signature.
The message vectors deliberately exercise both SHA2 and SHA3; each suite uses
the same digest algorithm in its detached and embedded signatures.

The recorded Sequoia revision excludes SHA3 from its streaming signer's hash
list. Encrypted-message generation therefore signs the fixed payload through
`SignatureBuilder` and derives the v6 one-pass packet from that signature,
including its salt, before serializing the literal and signature packets.

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

To refresh certificate signatures and preferences while retaining the key packets
and fingerprints, use:

```sh
tools/pqc-vector-generator/scripts/run.sh /tmp/sequoia-vectors generate-keys \
  --suite 42 --suite 44 --output test-vectors --force --reuse-keys
```

This reconstructs the fixed vector certificate with SHA3-512 self-signatures
and the supported hash preferences. It uses the retained primary key's creation
time for the replacement self-signatures so retained message signatures still
have valid bindings at their original signing times. This mode targets these
fixed test certificates; use it only for public test keys.

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

For a new vector set, generate the complete set into a new empty directory.
For a scoped digest update, use the staged procedure below. The global `--suite`
option selects primary algorithm IDs and can be repeated (for example,
`--suite 41 --suite 43`). Without it, all four suites are processed.

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

These values are extracted separately from this standalone generator.

The calculation relies on Sequoia-internal cryptographic APIs. To avoid duplicating cryptographic logic or exposing production APIs solely for test-vector generation, these values are extracted using a test-only helper in the Sequoia OpenPGP source tree.

The helper reads the generated secret certificate and encrypted message, performs the same decapsulation and combiner operations as Sequoia's implementation, decrypts the PKESK using the normal implementation, and produces one metadata file per suite:

```text
metadata-alg41.json
metadata-alg42.json
metadata-alg43.json
metadata-alg44.json
```

The filenames use the primary signature algorithm ID to identify the complete signature/KEM suite.

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

## Extractor command

Run the recorded upstream test-only extractor in an isolated temporary copy of
the compatible Sequoia checkout:

```bash
./scripts/extract-kem.sh /tmp/pqc-vectors /tmp/sequoia-vectors
```

The wrapper runs the ignored unit test
`crypto::tests::extract_nist_bp_vector_kem_values` with `PQC_VECTOR_DIR` set.
It extracts all four suites and writes their metadata beside the vectors.
It does not modify the supplied Sequoia checkout. Cargo may download test
dependencies on the first run. Keep the metadata with the published artifacts.

## Verification

Verify a complete candidate or published directory:

```bash
SEQUOIA_CHECKOUT=/tmp/sequoia-vectors ./scripts/verify.sh /tmp/pqc-vectors
```

The script verifies:

- all detached and embedded signatures, with the intended suite-specific hashes;
- v6 signature and one-pass signature packets and the expected signing key;
- the exact packet sequence, v6 PKESK algorithm and recipient;
- v2 SEIPD, AES-256/OCB, and 4096-octet chunks;
- successful authenticated decryption and exact recovery of `Testing.txt`;
- metadata session keys against normal Sequoia PKESK decryption;
- cryptographic validity of all three self-signatures in both public and secret
  certificates, SHA3-512 hashes, and the exact allowed hash preference list;
- each draft section's certificate hash statement, primary/subkey fingerprints, KEM values, and both message
  digest statements against the verified artifacts and metadata; and
- metadata recipients and share lengths, the SHA3-256 combiner via Python
  `hashlib`, and AES key unwrap via Python `cryptography`.

The verifier uses Sequoia's `NullPolicy` for these fixed test
artifacts. Cryptographic verification and explicit packet/hash assertions are
still enforced; this is not a production certificate-policy assessment.
The metadata check requires all four JSON files. The generator's standalone
`verify` command can also run before extraction, when JSON files are absent.

Optionally supply a compatible `sq` as a second argument for additional signature
and decryption checks and packet dumps:

```bash
SEQUOIA_CHECKOUT=/tmp/sequoia-vectors ./scripts/verify.sh /tmp/pqc-vectors /path/to/sq
```

`PQC_VECTOR_GENERATOR=/path/to/binary` can select an already-built generator
instead of invoking Cargo. The wrapper checks the repository's markdown by
default; `PQC_DRAFT=/path/to/candidate.md` selects a staged draft. The native
command accepts `--draft PATH` to enable these same checks.

Run the saved regression checks after building the generator:

```bash
python3 scripts/test-verification.py target/debug/pqc-vector-generator
```

They exercise the complete published set, fresh encrypted-message generation for
all four suites, and rejection of missing or incorrect
digest statements in each of the eight message subsections, missing or incorrect
certificate hash statements, legacy SHA3-256 self-signed public/secret
certificates, certificate refresh with retained messages, stale draft fingerprints
and KEM values, corrupted session keys/shares, and a missing payload newline.

## Updating selected message digests

From the repository root, stage the complete existing set and replace only the
selected message artifacts using the existing certificates. The example below
selects suites 41 and 43; use `--suite 42 --suite 44` to update the larger suites:

```bash
mkdir /tmp/pqc-sha384
cp test-vectors/*.asc test-vectors/Testing.txt /tmp/pqc-sha384/
tools/pqc-vector-generator/scripts/run.sh /tmp/sequoia-vectors generate-detached \
  --suite 41 --suite 43 --output /tmp/pqc-sha384 --force
tools/pqc-vector-generator/scripts/run.sh /tmp/sequoia-vectors generate-message \
  --suite 41 --suite 43 --output /tmp/pqc-sha384 --force
tools/pqc-vector-generator/scripts/extract-kem.sh /tmp/pqc-sha384 /tmp/sequoia-vectors
# Update the draft values and digest statements from the extracted metadata first.
SEQUOIA_CHECKOUT=/tmp/sequoia-vectors \
  tools/pqc-vector-generator/scripts/verify.sh /tmp/pqc-sha384
```

Use a new staging directory; do not copy stale metadata into it. Update the four
KEM values in each affected draft section from the new metadata. Retain the
certificates and fingerprints, certificate signatures, and unselected artifacts.
When certificate hashes or preferences change, refresh or regenerate the
certificates too; all published self-signatures now use SHA3-512.
Copy the changed armored files and the extracted metadata together only
after verification. Check that the remaining armored files are byte-identical.

## Independent implementation verification

The coauthor is tracking verification of all four detached signatures and all
four encrypted and signed messages with a second OpenPGP implementation
supporting IDs 37–44 separately, before last call. Record the implementation
revision, commands, and results. The current primary verification uses the
generating Sequoia implementation, and the separate Python check covers only
KEM relationships.
A second frontend using Sequoia is not a second cryptographic implementation.

## Reproducibility

The generator normally uses the system time and cryptographically secure randomness.
The fixed-certificate `--reuse-keys` mode retains the key packets and uses their
original primary-key creation time for replacement certificate signatures.

Therefore, repeated runs do not produce byte-identical vectors. In particular, the following values will change:

- key material;
- fingerprints;
- signatures;
- ciphertexts;
- KEM intermediate values; and
- session keys.

A published vector set must therefore be treated as one atomic generated artifact.

For a completely new key/vector set, the recommended procedure is:

1. Generate the complete set once into a new directory.
2. Extract the KEM intermediate metadata from that exact set.
3. Verify that exact set.
4. Record the fingerprints and KEM values from that exact set in the draft.
5. Copy the exact generated OpenPGP artifacts into `test-vectors/`.
6. Do not regenerate any individual member of the published set.

This keeps the prose, fingerprints, KEM values, signatures, keys, and encrypted messages mutually consistent.
