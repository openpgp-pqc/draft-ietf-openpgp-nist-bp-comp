# Published vector set

The literal payload is the eight bytes in `Testing.txt`: `54 65 73 74 69 6e 67 0a`.

The message-digest update replaces the detached signatures and encrypted-and-signed
messages for suites 41/37 (NIST P-384) and 43/39 (brainpoolP384r1) with SHA2-384.
The encrypted messages for suites 42/38 (NIST P-521) and 44/40 (brainpoolP512r1)
use SHA3-512, matching their retained detached signatures. The vectors deliberately
exercise both hash families.

All direct-key, User ID certification, and subkey-binding self-signatures use
SHA3-512. Certificate hash preferences are SHA2-384, SHA2-512, and SHA3-512.
The 41/37 and 43/39 keys were regenerated to replace their former SHA3-256
self-signatures, and all dependent artifacts and metadata were regenerated.
The 42/38 and 44/40 certificates were re-signed over their existing key packets
to update preferences; their fingerprints and message artifacts are retained.
The SHA3-256 KEM combiner is unchanged.

Generation and verification used:

- Sequoia commit `dbe031ac388179b45e6e6c25272130ba92d79e48` from
  <https://gitlab.com/fluppe2/sequoia/-/merge_requests/1> (assigned IDs and KEM extractor).
- The generator source and lockfile under `tools/pqc-vector-generator/`.
- Rust/Cargo 1.92.0 and OpenSSL 3.5.5.
- Python 3.14 and cryptography 46.0.5 for the separate combiner/unwrap check.

Each `metadata-alg*.json` was extracted from the exact corresponding encrypted
message and secret certificate. The draft records the matching values for all four suites. These are public test keys
and public test-vector session keys.

To verify this directory with the recorded Sequoia checkout:

```sh
SEQUOIA_CHECKOUT=/path/to/compatible/sequoia \
  tools/pqc-vector-generator/scripts/verify.sh test-vectors
```

See the generator README for checkout and regeneration commands. Treat the
armored artifacts, metadata, and matching draft text as one publication set.

The verification wrapper also checks the draft statements against these artifacts
and metadata. The coauthor is tracking verification by a second complete
OpenPGP implementation separately, before last call; see the generator README.

For an independent, standalone check of both components of all published
composite signatures, hybrid KEM key establishment (including ML-KEM
decapsulation), and authenticated message decryption, see
[`tools/stephan/`](../tools/stephan/). It reads this directory by default and
uses Python `cryptography` and the OpenSSL command-line tool, without Sequoia.
This verification is performed outside the OpenPGP implementation ecosystem and
is used only as an additional sanity check. It complements, rather than replaces,
interoperability testing by OpenPGP implementations.
