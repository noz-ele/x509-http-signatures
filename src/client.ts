import { encodeBase64 } from "./bytes.js";
import { decodeChallengeClaimsUnverified } from "./challenge.js";
import { X509HttpSignatureError } from "./error.js";
import {
  SIGNATURE_ALGORITHM,
  SIGNATURE_TAG,
  assertFixedComponents,
  buildSignatureBase,
  createContentDigest,
  parseParameterizedInnerList,
  quoteStructuredString,
  readRequestBody,
  serializeComponents
} from "./http-fields.js";
import type { HttpMessageSigner } from "./types.js";

export type { HttpMessageSigner } from "./types.js";

export interface SignRequestOptions {
  request: Request;
  acceptSignature: string;
  signer: HttpMessageSigner;
}

function requireAcceptParameter(
  parameters: ReadonlyMap<string, string | number | true>,
  name: string,
  expected: string | true
): void {
  if (parameters.get(name) !== expected) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      `Accept-Signature has an unsupported ${name} parameter`
    );
  }
}

export async function signRequest(options: SignRequestOptions): Promise<Request> {
  if (options.acceptSignature.length > 8192) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "Accept-Signature exceeds the supported size limit"
    );
  }
  const request = parseParameterizedInnerList(
    options.acceptSignature,
    "signature_input_invalid"
  );
  assertFixedComponents(request.components, "signature_input_invalid");
  if (request.parameters.size !== 6) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "Accept-Signature must contain exactly the fixed profile parameters"
    );
  }
  requireAcceptParameter(request.parameters, "alg", SIGNATURE_ALGORITHM);
  requireAcceptParameter(request.parameters, "tag", SIGNATURE_TAG);
  requireAcceptParameter(request.parameters, "created", true);
  requireAcceptParameter(request.parameters, "expires", true);
  const keyid = request.parameters.get("keyid");
  const nonce = request.parameters.get("nonce");
  if (typeof keyid !== "string" || typeof nonce !== "string") {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "Accept-Signature must contain string keyid and nonce parameters"
    );
  }

  const challenge = decodeChallengeClaimsUnverified(nonce);
  if (challenge.kid !== keyid) {
    throw new X509HttpSignatureError(
      "certificate_mismatch",
      "The challenge and Accept-Signature key identifiers differ"
    );
  }
  const created = Math.floor(Date.now() / 1000);
  if (created >= challenge.exp) {
    throw new X509HttpSignatureError("challenge_expired", "The signature challenge has expired");
  }

  let body: Uint8Array;
  try {
    body = await readRequestBody(options.request);
  } catch (cause) {
    throw new X509HttpSignatureError(
      "signature_input_invalid",
      "The request body cannot be read for signing",
      { cause }
    );
  }
  const contentDigest = await createContentDigest(body);
  const signatureParameters = [
    serializeComponents(),
    `created=${created}`,
    `expires=${challenge.exp}`,
    `nonce=${quoteStructuredString(nonce)}`,
    `alg=${quoteStructuredString(SIGNATURE_ALGORITHM)}`,
    `keyid=${quoteStructuredString(keyid)}`,
    `tag=${quoteStructuredString(SIGNATURE_TAG)}`
  ].join(";");
  const signatureBase = buildSignatureBase(
    options.request,
    contentDigest,
    signatureParameters
  );
  const signature = await options.signer.sign(signatureBase, SIGNATURE_ALGORITHM);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new X509HttpSignatureError(
      "signature_invalid",
      "The signer must return a 64-byte IEEE P1363 P-256 signature"
    );
  }

  const headers = new Headers(options.request.headers);
  headers.set("Content-Digest", contentDigest);
  headers.set("Signature-Input", `${request.label}=${signatureParameters}`);
  headers.set("Signature", `${request.label}=:${encodeBase64(signature)}:`);

  if (options.request.body === null) {
    return new Request(options.request, { headers });
  }
  return new Request(options.request, { headers, body: body.slice().buffer });
}
