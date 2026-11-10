# Independent composite vector sanity check

This standalone Python verifier checks the published composite ML-DSA/ECDSA
signatures and hybrid KEM chains without executing Sequoia or the repository's
generator or verifier.
Its default inputs are the files in this checkout's [`test-vectors/`](../../test-vectors/)
directory. No duplicate vector files or archived verification package are needed.

**This verification is performed outside the OpenPGP implementation ecosystem
and is used only as an additional sanity check.** It combines an ad-hoc packet
parser with general-purpose cryptographic libraries. It complements testing by
OpenPGP implementations and does not replace interoperability testing or a full
protocol/conformance review.

## Setup and run

Requirements:

- Python 3.9.2 or later and `cryptography` 50.0.0 (pinned in `requirements.txt`).
- An OpenSSL command-line executable, version 3.5 or later, with ML-DSA and ML-KEM support.
  This is separate from the OpenSSL backend bundled with Python `cryptography`.

From the repository root:

```sh
python3 -m venv tools/stephan/.venv
tools/stephan/.venv/bin/python -m pip install -r tools/stephan/requirements.txt
tools/stephan/.venv/bin/python tools/stephan/verify.py
```

The verifier resolves the default vector directory relative to its own location,
so it also works when invoked from a different working directory. It prints
each result, exits with status 0 only when all checks pass, and exits nonzero on
a failed check, missing input, or unavailable cryptographic operation. It writes
no output files unless `--output` is supplied.

To retain a machine-readable report and an execution log:

```sh
tools/stephan/.venv/bin/python tools/stephan/verify.py \
  --output tools/stephan/results.json > tools/stephan/execution.log 2>&1
```

Optional arguments:

| Argument | Purpose |
|---|---|
| `--vectors /path/to/test-vectors` | Verify an alternate directory with the same published filenames and four-suite layout. |
| `--openssl /path/to/openssl` | Select a particular OpenSSL command-line executable. |
| `--output /path/to/results.json` | Write full digests, signature-packet SHA-256 values, input checksums, runtime versions, and results. The parent directory must already exist. |

## Checks performed

For each of the four suites (41/37, 42/38, 43/39, 44/40), including both
Brainpool curves, the verifier checks both ECDSA and ML-DSA for:

- The detached signature over `Testing.txt`.
- The direct-key signature, User ID certification, and subkey-binding signature
  in each public and secret certificate.
- The inline signature in the authenticated, decrypted encrypted message.

It independently parses the armored packets, extracts public keys and signature
components, and reconstructs the salted OpenPGP v6 digest. ECDSA uses that digest
with `Prehashed`; pure ML-DSA uses the digest as its message with an empty context.
Each ML-DSA signature is also checked using system OpenSSL's
`pkeyutl -verify -rawin`. This is a second invocation of OpenSSL, not a separate
ML-DSA implementation. Both checks are independent of Sequoia's OpenPGP processing.

Every signature is accompanied by negative controls: ECDSA rejects a modified
digest; ML-DSA rejects a modified digest, modified signature, and incorrect context.
The public portions and signatures of public and secret certificates must agree.

For each encrypted message the verifier also:

1. Extracts the unencrypted ECDH scalar and 64-byte ML-KEM seed from the secret
   subkey, reconstructs both public keys, and compares them in full with the
   packet's public material.
2. Checks that the PKESK algorithm and recipient fingerprint identify that subkey.
3. Parses the ephemeral ECDH point and ML-KEM ciphertext from the actual PKESK,
   validates the curve points, and computes both constituent shared secrets.
4. Repeats ML-KEM decapsulation through system OpenSSL's `pkeyutl -decap` and
   compares the result with Python's decapsulation. Both use OpenSSL implementations
   of ML-KEM, not separate primitive implementations.
5. Recomputes the SHA3-256 composite combiner, including its algorithm binding
   and domain separator, and unwraps the session key with AES-256 key unwrap.
6. Compares the recovered shared secrets, combiner output, session key, and
   recipient fingerprint with the published metadata.
7. Uses the **independently recovered session key** to decrypt SEIPDv2, checking
   chunk authentication and the final summary tag. The literal payload must
   equal `Testing.txt`, and its inline composite signature must verify.

Metadata is used only for expected-output comparisons, never to supply keying
material. A modified ML-KEM ciphertext is also decapsulated: its implicit-rejection
shared secret must differ and the resulting combiner key must fail AES key unwrap.
Only the public test-vector secret keys are used; the script accepts the current
unencrypted v6 key and PKESK formats, not arbitrary secret-key protection schemes.

The expected final output for the current publication set is:

```text
ALL PASS: 32 occurrences, 20 unique composite signatures, 4 hybrid KEM chains, 4 authenticated encrypted messages.
```

The three certificate signatures occur in both public and secret certificates,
so the 32 checked occurrences correspond to 20 distinct composite signatures.
The script intentionally requires the current vector layout and counts; it is
not a general OpenPGP validator. It does not evaluate certificate trust,
expiration, critical subpacket policy, or one-pass signature field consistency.
Its packet parser only supports the encodings needed by these vectors and does
not check armor CRCs. A successful run is evidence for the enumerated
cryptographic vector checks, not complete implementation interoperability.

## Recorded verification

The initial independent run used the vectors at commit
`2b41cdcdddcd7d5ca310ff9d88a4c491189d8b14` on 2026-11-10. All 20 distinct
composite signatures passed both component checks, all four encrypted messages
passed authenticated decryption, and the negative controls were rejected.
The extended run on the same date also passed all four full hybrid KEM chains,
including both ML-KEM decapsulation invocations, both public-key reconstructions,
the combiner and key unwrap, metadata comparisons, and ciphertext negative controls.
These runs used `cryptography` 50.0.0 (OpenSSL 4.0.1 backend) and system OpenSSL
3.5.7. The JSON report generated by a new run records its actual inputs and
runtime rather than assuming that historical revision.

The parser and hash construction follow
[RFC 9580, Sections 5.2.3 and 5.2.4](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3),
and the draft's composite-signature packet format and ML-DSA verification rules.
Authenticated decryption follows
[RFC 9580, Section 5.13.2](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.13.2).
The KEM packet encodings follow this draft; the combiner follows
[RFC 9980, Section 4.2.1](https://www.rfc-editor.org/rfc/rfc9980.html#section-4.2.1),
and AES key unwrap follows
[RFC 3394](https://www.rfc-editor.org/rfc/rfc3394.html).
