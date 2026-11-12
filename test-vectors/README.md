For an independent, standalone check of both components of all published
composite signatures, hybrid KEM key establishment (including ML-KEM
decapsulation), and authenticated message decryption, see
[`tools/verification_OpenSSL_Python/`](../tools/verification_OpenSSL_Python/). It reads this directory by default and
uses Python `cryptography` and the OpenSSL command-line tool, without Sequoia.
This verification is performed outside the OpenPGP implementation ecosystem and
is used only as an additional sanity check. It complements, rather than replaces,
interoperability testing by OpenPGP implementations.
