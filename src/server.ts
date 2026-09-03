import { verifyCertificateSignature } from "@noz-ele/edgca/verify";
import { bytesEqual } from "./bytes.js";
import {
  issueSignatureChallenge,
  verifyChallengeToken,
  type IssueSignatureChallengeOptions
} from "./challenge.js";
import {
  verifyClientCertificate,
  type VerifyClientCertificateOptions
} from "./certificate.js";
import { X509HttpSignatureError } from "./error.js";
import {
  SIGNATURE_ALGORITHM,
  SIGNATURE_TAG,
  assertFixedComponents,
  buildSignatureBase,
  createContentDigest,
  parseContentDigest,
  parseParameterizedInnerList,
  parseSignatureField,
  readRequestBody
} from "./http-fields.js";
import type {
  ChallengeSigningKey,
  SignatureChallenge,
  VerifiedClientCertificate,
  VerifiedSignedRequest
} from "./types.js";

export { issueSignatureChallenge, verifyClientCertificate };
export type { IssueSignatureChallengeOptions, VerifyClientCertificateOptions };

export interface VerifySignedRequestOptions {
  request: Request;
  certificate: VerifiedClientCertificate;
  challengeSigningKey: ChallengeSigningKey;
  expectedAudience: string;
  clockSkewSeconds?: number;
}

function requiredString(
  parameters: ReadonlyMap<string, string | number | true>,
  name: string
): string {
  const value = parameters.get(name);
  if (typeof value !== "string") {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      `Signature-Input parameter ${name} must be a string`
    );
  }
  return value;
}

function requiredInteger(
  parameters: ReadonlyMap<string, string | number | true>,
  name: string
): number {
  const value = parameters.get(name);
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      `Signature-Input parameter ${name} must be an integer`
    );
  }
  return value;
}

export async function verifySignedRequest(
  options: VerifySignedRequestOptions
): Promise<VerifiedSignedRequest> {
  const skew = options.clockSkewSeconds ?? 5;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 60) {
    throw new TypeError("clockSkewSeconds must be an integer between 0 and 60");
  }
  const inputValue = options.request.headers.get("Signature-Input");
  if (inputValue === null) {
    throw new X509HttpSignatureError("signature_input_invalid", "Signature-Input is missing");
  }
  if (inputValue.length > 8192) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "Signature-Input exceeds the supported size limit"
    );
  }
  const input = parseParameterizedInnerList(inputValue, "signature_input_invalid");
  assertFixedComponents(input.components, "signature_input_invalid");
  if (input.parameters.size !== 6) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "Signature-Input must contain exactly the fixed profile parameters"
    );
  }

  const created = requiredInteger(input.parameters, "created");
  const expires = requiredInteger(input.parameters, "expires");
  const nonce = requiredString(input.parameters, "nonce");
  const algorithm = requiredString(input.parameters, "alg");
  const keyid = requiredString(input.parameters, "keyid");
  const tag = requiredString(input.parameters, "tag");
  if (algorithm !== SIGNATURE_ALGORITHM || tag !== SIGNATURE_TAG) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "Signature-Input does not match the fixed algorithm and tag"
    );
  }
  if (keyid !== options.certificate.fingerprintSha256) {
    throw new X509HttpSignatureError(
      "certificate_mismatch",
      "Signature keyid does not match the verified certificate"
    );
  }

  const challenge = await verifyChallengeToken(nonce, options.challengeSigningKey);
  if (challenge.aud !== options.expectedAudience) {
    throw new X509HttpSignatureError(
      "challenge_invalid",
      "The challenge audience does not match"
    );
  }
  if (challenge.kid !== options.certificate.fingerprintSha256) {
    throw new X509HttpSignatureError(
      "certificate_mismatch",
      "The challenge certificate binding does not match"
    );
  }
  const now = Math.floor(Date.now() / 1000);
  if (now > challenge.exp + skew) {
    throw new X509HttpSignatureError("challenge_expired", "The signature challenge has expired");
  }
  if (
    expires !== challenge.exp ||
    created > now + skew ||
    created < challenge.iat - skew ||
    created >= expires
  ) {
    throw new X509HttpSignatureError(
      "challenge_invalid",
      "Signature timestamps do not match the challenge lifetime"
    );
  }

  let body: Uint8Array;
  try {
    body = await readRequestBody(options.request);
  } catch (cause) {
    throw new X509HttpSignatureError(
      "content_digest_invalid",
      "The request body cannot be read for digest verification",
      { cause }
    );
  }
  const suppliedDigest = parseContentDigest(options.request.headers.get("Content-Digest"));
  const calculatedValue = await createContentDigest(body);
  const calculatedDigest = parseContentDigest(calculatedValue);
  if (!bytesEqual(suppliedDigest, calculatedDigest)) {
    throw new X509HttpSignatureError(
      "content_digest_invalid",
      "Content-Digest does not match the request body"
    );
  }

  const signature = parseSignatureField(
    options.request.headers.get("Signature"),
    input.label
  );
  if (signature.length !== 64) {
    throw new X509HttpSignatureError(
      "signature_invalid",
      "The HTTP message signature must be a 64-byte IEEE P1363 value"
    );
  }
  const signatureBase = buildSignatureBase(
    options.request,
    options.request.headers.get("Content-Digest")!,
    input.serializedValue
  );

  let signatureValid: boolean;
  try {
    signatureValid = await verifyCertificateSignature({
      certificatePem: options.certificate.leafCertificatePem,
      data: signatureBase,
      signature,
      signatureFormat: "ieee-p1363"
    });
  } catch (cause) {
    throw new X509HttpSignatureError(
      "signature_invalid",
      "Unable to verify the HTTP message signature",
      { cause }
    );
  }
  if (!signatureValid) {
    throw new X509HttpSignatureError("signature_invalid", "The HTTP message signature is invalid");
  }

  return {
    certificateFingerprint: options.certificate.fingerprintSha256,
    certificateSubject: options.certificate.subject,
    challengeId: challenge.jti,
    createdAt: new Date(created * 1000),
    expiresAt: new Date(expires * 1000)
  };
}
