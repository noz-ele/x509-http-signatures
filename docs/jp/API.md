# API リファレンス

## 共通型

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

hint は診断用であり、検証結果や返却する subject の根拠には使いません。

## `fromRfc9440ClientCertificates(input)`

`@noz-ele/x509-http-signatures/rfc9440` から import します。

RFC 9440 の `Client-Cert` singleton byte sequence と、leaf を含まない
`Client-Cert-Chain` list を parse します。既定制限は leaf 10 KiB、chain
合計 16 KiB、chain 証明書 2 本です。制限は `limits` で小さくも大きくも
変更できます。

## `fromCloudflareTlsClientAuth(value, options?)`

`@noz-ele/x509-http-signatures/cloudflare` から import します。

`unknown` を受け取り、Cloudflare metadata の `certPresented`、
`certRFC9440`、`certChainRFC9440`、両 `TooLarge` flag を構造検査します。
Cloudflare Workers 型 package への runtime / type dependency はありません。

## `verifyClientCertificate(options)`

```ts
function verifyClientCertificate(options: {
  presentation: ClientCertificatePresentation;
  trustedRootCertificatesPem: readonly string[];
  purpose: "clientAuth";
  at?: Date | number;
}): Promise<VerifiedClientCertificate>;
```

提示 chain に trust anchor 自身が含まれる場合は DER 完全一致で除外し、EdgCA の
`verifyCertificateChain()` を `clientAuth` purpose で呼びます。fingerprint は
separator なしの lowercase SHA-256 hex、subject は検証済み leaf DER から取得します。

## `issueSignatureChallenge(options)`

```ts
function issueSignatureChallenge(options: {
  certificate: VerifiedClientCertificate;
  audience: string;
  challengeSigningKey: CryptoKey | Uint8Array;
  expiresInSeconds?: number;
}): Promise<SignatureChallenge>;
```

既定 60 秒、指定可能範囲 1〜300 秒です。byte key は 32 byte 以上、`CryptoKey`
は `sign` 用 HMAC-SHA-256 secret key を要求します。`Accept-Signature` の
`nonce` は version、audience、certificate fingerprint、challenge ID、発行時刻、
期限を持つ HMAC 保護 token です。

## `signRequest(options)`

```ts
interface HttpMessageSigner {
  sign(
    data: Uint8Array,
    algorithm: "ecdsa-p256-sha256"
  ): Promise<Uint8Array>;
}
```

`@noz-ele/x509-http-signatures/client` から import します。signer は P-256 の
64-byte IEEE P1363 signature を返します。body clone から SHA-256 digest と
signature base を作り、署名 header を持つ新しい `Request` を返します。

## `verifySignedRequest(options)`

```ts
function verifySignedRequest(options: {
  request: Request;
  certificate: VerifiedClientCertificate;
  challengeSigningKey: CryptoKey | Uint8Array;
  expectedAudience: string;
  clockSkewSeconds?: number;
}): Promise<VerifiedSignedRequest>;
```

固定 component、metadata、HMAC、audience、certificate binding、時刻、body
digest、EdgCA による ECDSA signature を検証します。clock skew は既定 5 秒、
指定可能範囲 0〜60 秒です。

## Error

protocol の拒否は `X509HttpSignatureError` で返します。

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

短すぎる HMAC key や空の trust anchor list など、呼び出し側設定の誤りは
`TypeError` です。HTTP status への変換は application が行います。
