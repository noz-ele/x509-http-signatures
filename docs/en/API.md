# API reference

The package is ESM-only. Shared modules use Web Crypto and web platform APIs;
only the CLI imports Node.js modules.

## Common types

```ts
interface ClientCertificatePresentation {
  leafCertificateDer: Uint8Array;
  chainCertificatesDer: Uint8Array[];
  subjectHint?: string;
  issuerHint?: string;
}

interface VerifiedClientCertificate {
  leafCertificatePem: string;
  fingerprintSha256: string;
  subject: string;
}
```

Hints are diagnostic metadata. Certificate validation and the returned subject
never trust them.

## `fromRfc9440ClientCertificates(input)`

Import from `@noz-ele/x509-http-signatures/rfc9440`.

```ts
function fromRfc9440ClientCertificates(input: {
  certificate: unknown;
  certificateChain?: unknown;
  subjectHint?: string;
  issuerHint?: string;
  limits?: Partial<CertificatePresentationLimits>;
}): ClientCertificatePresentation;
```

`certificate` is the singleton RFC 9440 `Client-Cert` byte sequence.
`certificateChain` is the RFC 9440 list used by `Client-Cert-Chain`; it excludes
the leaf and is ordered from the leaf's direct issuer toward the root.

Defaults match Cloudflare's encoded-data bounds and EdgCA's bounded hierarchy:

```ts
{
  maxLeafCertificateBytes: 10 * 1024,
  maxChainBytes: 16 * 1024,
  maxChainCertificates: 2
}
```

## `fromCloudflareTlsClientAuth(value, options?)`

Import from `@noz-ele/x509-http-signatures/cloudflare`.

The input is deliberately `unknown`; this package does not depend on
`@cloudflare/workers-types`. It checks `certPresented`, `certRFC9440`,
`certChainRFC9440`, and both `TooLarge` flags before delegating to the RFC 9440
parser. Cloudflare's Subject and Issuer values are retained only as hints.

## `verifyClientCertificate(options)`

Import from `@noz-ele/x509-http-signatures/server`.

```ts
function verifyClientCertificate(options: {
  presentation: ClientCertificatePresentation;
  trustedRootCertificatesPem: readonly string[];
  purpose: "clientAuth";
  at?: Date | number;
}): Promise<VerifiedClientCertificate>;
```

The function converts the presented DER values to PEM, removes exact trust
anchor matches from the presented chain, and calls EdgCA's bounded chain
validator with the `clientAuth` purpose. The SHA-256 fingerprint is lowercase
hex without separators. The subject is parsed from the validated leaf DER.

## `issueSignatureChallenge(options)`

Import from `@noz-ele/x509-http-signatures/server`.

```ts
type ChallengeSigningKey = CryptoKey | Uint8Array;

function issueSignatureChallenge(options: {
  certificate: VerifiedClientCertificate;
  audience: string;
  challengeSigningKey: ChallengeSigningKey;
  expiresInSeconds?: number;
}): Promise<{
  acceptSignature: string;
  expiresAt: Date;
}>;
```

The default lifetime is 60 seconds; accepted values are 1 through 300 seconds.
Byte keys must be at least 32 bytes. `CryptoKey` values must be HMAC-SHA-256
secret keys with the usage required by the operation (normally both `sign` and
`verify`).

The returned RFC 9421 request has the label `x509`, the fixed component list,
`alg="ecdsa-p256-sha256"`, the certificate fingerprint as `keyid`, the fixed
tag, and a stateless HMAC-protected `nonce`. `created` and `expires` are bare
request parameters as required for `Accept-Signature`.

## `signRequest(options)`

Import from `@noz-ele/x509-http-signatures/client`.

```ts
interface HttpMessageSigner {
  sign(
    data: Uint8Array,
    algorithm: "ecdsa-p256-sha256"
  ): Promise<Uint8Array>;
}

function signRequest(options: {
  request: Request;
  acceptSignature: string;
  signer: HttpMessageSigner;
}): Promise<Request>;
```

The signer must return a 64-byte IEEE P1363 P-256 ECDSA signature. The function
buffers a clone of the request body, computes RFC 9530 `sha-256`, constructs the
RFC 9421 signature base, and returns a new request. The input remains readable
and its headers are unchanged.

## `verifySignedRequest(options)`

Import from `@noz-ele/x509-http-signatures/server`.

```ts
function verifySignedRequest(options: {
  request: Request;
  certificate: VerifiedClientCertificate;
  challengeSigningKey: ChallengeSigningKey;
  expectedAudience: string;
  clockSkewSeconds?: number;
}): Promise<{
  certificateFingerprint: string;
  certificateSubject: string;
  challengeId: string;
  createdAt: Date;
  expiresAt: Date;
}>;
```

The default allowed clock skew is 5 seconds, with an accepted range of 0 to 60.
Verification checks the fixed component set, signature metadata, HMAC, audience,
certificate fingerprint binding, timestamps, body digest, and ECDSA signature.

## Errors

All protocol rejection errors are `X509HttpSignatureError` values with a stable
`code`:

```ts
type X509HttpSignatureErrorCode =
  | "certificate_not_presented"
  | "certificate_too_large"
  | "certificate_invalid"
  | "challenge_invalid"
  | "challenge_expired"
  | "content_digest_invalid"
  | "signature_input_invalid"
  | "signature_invalid"
  | "certificate_mismatch";
```

Invalid developer configuration, such as a short HMAC key or an empty trust
anchor list, throws `TypeError`. The library does not choose HTTP status codes.
