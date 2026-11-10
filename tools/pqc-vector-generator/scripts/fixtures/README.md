# Legacy certificate regression fixtures

The two `weak-*-primary41-sub37.asc` files are the original public test
certificate and public test secret certificate from commit `cfc95ab7b3c11fbcd57cf1b2fe157e964393ccde`,
copied verbatim from `test-vectors/`. Their three self-signatures use
SHA3-256. They are deliberately nonconforming under the 384-bit minimum and
must be rejected by the verifier in either public or secret certificate input.

These fixtures are only negative test inputs, not part of the published vector
set. Their keys and secret material were already public.
