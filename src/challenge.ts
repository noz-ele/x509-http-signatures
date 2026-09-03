import { copyArrayBuffer, decodeBase64Url, decodeUtf8, encodeBase64Url, utf8 } from "./bytes.js";
import { X509HttpSignatureError } from "./error.js";
import {
  SIGNATURE_ALGORITHM,
  SIGNATURE_TAG,
  quoteStructuredString,
  serializeComponents
} from "./http-fields.js";
import type { ChallengeSigningKey, SignatureChallenge, VerifiedClientCertificate } from "./types.js";

export interface ChallengeClaims {
  v: 1;
  aud: string;
  kid: string;
  jti: string;
  iat: number;
  exp: number;
}

async function useHmacKey(
  key: ChallengeSigningKey,
  usage: "sign" | "verify"
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    if (key.length < 32) {
      throw new TypeError("challengeSigningKey must contain at least 32 bytes");
    }
    return crypto.subtle.importKey(
      "raw",
      copyArrayBuffer(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      [usage]
    );
  }
  if (
    key.type !== "secret" ||
    key.algorithm.name !== "HMAC" ||
    (key.algorithm as HmacKeyAlgorithm).hash.name !== "SHA-256" ||
    !key.usages.includes(usage)
  ) {
    throw new TypeError(`challengeSigningKey must be an HMAC-SHA-256 key usable for ${usage}`);
  }
  return key;
}

function assertClaims(value: unknown): asserts value is ChallengeClaims {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("challenge payload is not an object");
  }
  const claims = value as Partial<ChallengeClaims>;
  if (
    claims.v !== 1 ||
    typeof claims.aud !== "string" || claims.aud.length === 0 ||
    typeof claims.kid !== "string" || claims.kid.length === 0 ||
    typeof claims.jti !== "string" || claims.jti.length === 0 ||
    !Number.isSafeInteger(claims.iat) ||
    !Number.isSafeInteger(claims.exp) ||
    claims.exp! <= claims.iat!
  ) {
    throw new Error("challenge payload has invalid claims");
  }
}

export function decodeChallengeClaimsUnverified(token: string): ChallengeClaims {
  const parts = token.split(".");
  if (parts.length !== 2 || parts[0] === undefined) {
    throw new X509HttpSignatureError("challenge_invalid", "Malformed challenge token");
  }
  try {
    const value: unknown = JSON.parse(decodeUtf8(decodeBase64Url(parts[0])));
    assertClaims(value);
    return value;
  } catch (cause) {
    if (cause instanceof X509HttpSignatureError) throw cause;
    throw new X509HttpSignatureError("challenge_invalid", "Malformed challenge payload", { cause });
  }
}

export async function verifyChallengeToken(
  token: string,
  key: ChallengeSigningKey
): Promise<ChallengeClaims> {
  const parts = token.split(".");
  if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) {
    throw new X509HttpSignatureError("challenge_invalid", "Malformed challenge token");
  }
  const hmacKey = await useHmacKey(key, "verify");
  const signature = decodeBase64Url(parts[1]);
  if (signature.length !== 32) {
    throw new X509HttpSignatureError("challenge_invalid", "Invalid challenge MAC length");
  }
  const valid = await crypto.subtle.verify(
    "HMAC",
    hmacKey,
    copyArrayBuffer(signature),
    copyArrayBuffer(utf8(parts[0]))
  );
  if (!valid) {
    throw new X509HttpSignatureError("challenge_invalid", "Invalid challenge MAC");
  }
  return decodeChallengeClaimsUnverified(token);
}

export interface IssueSignatureChallengeOptions {
  certificate: VerifiedClientCertificate;
  audience: string;
  challengeSigningKey: ChallengeSigningKey;
  expiresInSeconds?: number;
}

export async function issueSignatureChallenge(
  options: IssueSignatureChallengeOptions
): Promise<SignatureChallenge> {
  const expiresInSeconds = options.expiresInSeconds ?? 60;
  if (
    options.audience.length === 0 ||
    utf8(options.audience).length > 2048 ||
    !Number.isSafeInteger(expiresInSeconds) ||
    expiresInSeconds < 1 ||
    expiresInSeconds > 300
  ) {
    throw new TypeError(
      "audience must contain 1 to 2048 UTF-8 bytes and expiresInSeconds must be between 1 and 300"
    );
  }
  if (!/^[0-9a-f]{64}$/.test(options.certificate.fingerprintSha256)) {
    throw new TypeError("certificate.fingerprintSha256 must be lowercase SHA-256 hex");
  }

  const now = Math.floor(Date.now() / 1000);
  const random = new Uint8Array(16);
  crypto.getRandomValues(random);
  const claims: ChallengeClaims = {
    v: 1,
    aud: options.audience,
    kid: options.certificate.fingerprintSha256,
    jti: encodeBase64Url(random),
    iat: now,
    exp: now + expiresInSeconds
  };
  const payload = encodeBase64Url(utf8(JSON.stringify(claims)));
  const hmacKey = await useHmacKey(options.challengeSigningKey, "sign");
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", hmacKey, copyArrayBuffer(utf8(payload)))
  );
  const nonce = `${payload}.${encodeBase64Url(mac)}`;
  const acceptSignature = [
    `x509=${serializeComponents()}`,
    `alg=${quoteStructuredString(SIGNATURE_ALGORITHM)}`,
    `keyid=${quoteStructuredString(options.certificate.fingerprintSha256)}`,
    `nonce=${quoteStructuredString(nonce)}`,
    `tag=${quoteStructuredString(SIGNATURE_TAG)}`,
    "created",
    "expires"
  ].join(";");
  return { acceptSignature, expiresAt: new Date(claims.exp * 1000) };
}
