# @noz-ele/x509-http-signatures

> [日本語](https://github.com/noz-ele/x509-http-signatures/blob/main/docs/jp/README.md) | English

X.509 client-certificate proof of possession for HTTP requests. This ESM-only
TypeScript package connects RFC 9440 certificate presentation, RFC 9421 HTTP
Message Signatures, RFC 9530 content digests, Cloudflare Workers, and EdgCA.

## Features

- Runtime-neutral certificate presentation with strict size and count limits.
- RFC 9440 `Client-Cert` and `Client-Cert-Chain` parsing.
- A Cloudflare adapter for `request.cf.tlsClientAuth` without a Workers-types dependency.
- Bounded EdgCA chain validation for the `clientAuth` purpose.
- Stateless, HMAC-authenticated, short-lived RFC 9421 challenges.
- Immutable request signing and verification with a fixed security profile.
- A Node.js CLI that prints curl-ready signature headers.

The fixed signature profile covers these components, in this order:

```text
@method
@target-uri
content-digest
```

It uses `ecdsa-p256-sha256`, `sha-256` content digests, and the application tag
`x509-http-signature`.

## Install

```sh
npm install @noz-ele/x509-http-signatures
```

Node.js 20+, modern browsers, and Cloudflare Workers are supported. All shared
cryptography uses Web Crypto. CommonJS `require` is not supported.

## Package entry points

```ts
import type {
  ClientCertificatePresentation,
  VerifiedClientCertificate
} from "@noz-ele/x509-http-signatures";

import {
  signRequest,
  type HttpMessageSigner
} from "@noz-ele/x509-http-signatures/client";

import {
  issueSignatureChallenge,
  verifyClientCertificate,
  verifySignedRequest
} from "@noz-ele/x509-http-signatures/server";

import {
  fromRfc9440ClientCertificates
} from "@noz-ele/x509-http-signatures/rfc9440";

import {
  fromCloudflareTlsClientAuth
} from "@noz-ele/x509-http-signatures/cloudflare";
```

The root entry point is an aggregate surface. Use the purpose-specific entry
points when you want a smaller, capability-specific dependency graph.

## Server flow

```ts
import {
  fromCloudflareTlsClientAuth
} from "@noz-ele/x509-http-signatures/cloudflare";
import {
  issueSignatureChallenge,
  verifyClientCertificate,
  verifySignedRequest
} from "@noz-ele/x509-http-signatures/server";

const presentation = fromCloudflareTlsClientAuth(
  request.cf?.tlsClientAuth
);

const certificate = await verifyClientCertificate({
  presentation,
  trustedRootCertificatesPem: [env.CLIENT_CA_PEM],
  purpose: "clientAuth"
});

const challengeSigningKey = Uint8Array.from(
  atob(env.CHALLENGE_HMAC_KEY_BASE64),
  (character) => character.charCodeAt(0)
);

const challenge = await issueSignatureChallenge({
  certificate,
  audience: "https://api.example.com/admin",
  challengeSigningKey,
  expiresInSeconds: 60
});

// Return this on a 401 response. Keep challenge responses uncacheable.
const headers = new Headers({
  "Accept-Signature": challenge.acceptSignature,
  "Cache-Control": "no-store"
});

// On the following signed request:
const proof = await verifySignedRequest({
  request,
  certificate,
  challengeSigningKey,
  expectedAudience: "https://api.example.com/admin"
});
```

`challengeSigningKey` is either a non-extractable HMAC-SHA-256 `CryptoKey`
(with the usage required by the operation, normally both `sign` and `verify`)
or at least 32 bytes of secret key material. Store it as a Worker secret, never in
`wrangler.jsonc` or source control.

## Client flow

```ts
import { signRequest } from "@noz-ele/x509-http-signatures/client";
import { signData } from "@noz-ele/edgca/sign";

const signedRequest = await signRequest({
  request,
  acceptSignature,
  signer: {
    sign(data, algorithm) {
      if (algorithm !== "ecdsa-p256-sha256") throw new Error("unsupported");
      return signData({
        privateKey,
        data,
        signatureFormat: "ieee-p1363"
      });
    }
  }
});
```

The input `Request` is not consumed or mutated. The returned request contains
`Content-Digest`, `Signature-Input`, and `Signature`.

## CLI and curl

```sh
x509-http-signatures sign-request \
  --method POST \
  --url https://api.example.com/admin \
  --accept-signature-file accept-signature.txt \
  --key client.key.pem \
  --body request.json
```

The command prints three curl-ready header lines. Send the same method, URL, and
body bytes that were supplied to the command.

See [the English API reference](https://github.com/noz-ele/x509-http-signatures/blob/main/docs/en/API.md),
[non-goals](https://github.com/noz-ele/x509-http-signatures/blob/main/docs/en/NON_GOALS.md),
and the [Japanese guide](https://github.com/noz-ele/x509-http-signatures/blob/main/docs/jp/README.md).

## Development

```sh
npm install
npm run typecheck
npm test
npm pack --dry-run
```

Maintainers should follow [RELEASING.md](RELEASING.md) for the first npm
publication and the GitHub trusted-publishing workflow used by later releases.

## Security

HTTP Message Signatures are one layer in an application authentication design.
Read [SECURITY.md](SECURITY.md) and the documented non-goals before deployment.
