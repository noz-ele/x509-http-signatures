# Non-goals

This package intentionally does not provide:

- general PKI path building, AIA fetching, OS trust-store access, CRL, or OCSP;
- a replacement for TLS-layer mTLS validation;
- support for RSA, Ed25519, other curves, or negotiable signature profiles;
- arbitrary RFC 9421 component selection or multiple signatures;
- protection for request headers outside method, target URI, and content digest;
- streaming body signing or verification;
- exactly-once challenge consumption or a replay database;
- certificate issuance, private-key storage, rotation, or recovery;
- Browser Grant, cookies, sessions, authorization policy, or admin UI handoff;
- HTTP responses or application-specific HTTP status mapping.

EdgCA deliberately bounds certificate validation to its supported chain model.
This package preserves that boundary.
