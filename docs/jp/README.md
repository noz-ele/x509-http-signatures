# @noz-ele/x509-http-signatures

> 日本語 | [English](../../README.md)

X.509 クライアント証明書に対応する秘密鍵の所持を、HTTP request への署名で
確認する TypeScript パッケージです。RFC 9440、RFC 9421、RFC 9530、
Cloudflare Workers、EdgCA を接続します。

## 機能

- 実行環境に依存しない `ClientCertificatePresentation`
- RFC 9440 `Client-Cert` / `Client-Cert-Chain` の制限付き parse
- Workers 型 package に依存しない `request.cf.tlsClientAuth` adapter
- EdgCA による明示的 trust anchor までの `clientAuth` chain 検証
- HMAC 署名された短寿命・ステートレス challenge
- RFC 9530 body digest と RFC 9421 request 署名
- curl から利用できる Node.js CLI

署名対象は次の 3 component に固定しています。

```text
@method
@target-uri
content-digest
```

algorithm は `ecdsa-p256-sha256`、tag は `x509-http-signature` です。

## Install

```sh
npm install @noz-ele/x509-http-signatures
```

ESM-only です。Node.js 20+、modern browser、Cloudflare Workers に対応します。

## Cloudflare Worker

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

// Worker secret は文字列なので、API 境界で 32 byte 以上へ decode します。
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

// 初回 response は cache させません。
return new Response(null, {
  status: 401,
  headers: {
    "Accept-Signature": challenge.acceptSignature,
    "Cache-Control": "no-store"
  }
});

// 次の署名付き request では以下を実行します。
const proof = await verifySignedRequest({
  request,
  certificate,
  challengeSigningKey,
  expectedAudience: "https://api.example.com/admin"
});
```

`request.cf.tlsClientAuth` は `unknown` として構造検査します。
`certPresented`、RFC 9440 field、10 KiB / 16 KiB のサイズ超過 flag を確認し、
Cloudflare の Subject/Issuer 文字列は診断用 hint としてだけ扱います。

Worker secret は `wrangler.jsonc` の `vars` に書かず、`wrangler secret put` 等で
登録してください。生成済み `Env` 型を利用し、手書きの binding interface は
避けてください。

## Client

```ts
import { signRequest } from "@noz-ele/x509-http-signatures/client";
import { signData } from "@noz-ele/edgca/sign";

const signedRequest = await signRequest({
  request,
  acceptSignature,
  signer: {
    sign(data) {
      return signData({
        privateKey,
        data,
        signatureFormat: "ieee-p1363"
      });
    }
  }
});
```

入力 `Request` は直接変更せず、`Content-Digest`、`Signature-Input`、
`Signature` を設定した新しい `Request` を返します。

## CLI と curl

```sh
x509-http-signatures sign-request \
  --method POST \
  --url https://api.example.com/admin \
  --accept-signature-file accept-signature.txt \
  --key client.key.pem \
  --body request.json
```

CLI は curl に渡せる 3 header を標準出力へ出します。CLI に指定した method、
URL、body byte と実際の curl request を一致させてください。秘密鍵は暗号化されて
いない PKCS#8 `PRIVATE KEY` PEM の P-256 鍵を受け付けます。

詳細は [API](API.md) と [非目標](NON_GOALS.md) を参照してください。

## Development

```sh
npm install
npm run typecheck
npm test
npm pack --dry-run
```
