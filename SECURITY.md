# Security policy

## Supported versions

The latest published minor version receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately
through GitHub Security Advisories for this repository.

## Security model

- Trust anchors and the HMAC challenge key are explicit caller inputs.
- The package does not use an operating-system trust store, fetch AIA data, or
  perform revocation checks.
- A presented certificate is public data. Authentication is established only
  after its chain and the RFC 9421 proof-of-possession signature both verify.
- Challenges are stateless and can be replayed until they expire. Applications
  that require exactly-once semantics must persist and consume challenge IDs.
- Signed request bodies are buffered to compute and check `Content-Digest`.
  Applications must reject oversized requests before calling this package.
- The fixed profile binds the HTTP method, full target URI, and body digest.
  Header fields outside that profile are not integrity protected.
- HMAC byte keys shorter than 32 bytes are rejected. Keep the challenge key in
  a secret store and rotate it according to application policy.
