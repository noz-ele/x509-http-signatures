import { decodeBase64 } from "./bytes.js";
import { X509HttpSignatureError } from "./error.js";
import {
  DEFAULT_CERTIFICATE_PRESENTATION_LIMITS,
  type CertificatePresentationLimits,
  type ClientCertificatePresentation
} from "./types.js";

export interface Rfc9440ClientCertificatesInput {
  certificate: unknown;
  certificateChain?: unknown;
  subjectHint?: string;
  issuerHint?: string;
  limits?: Partial<CertificatePresentationLimits>;
}

function resolveLimits(
  values: Partial<CertificatePresentationLimits> | undefined
): CertificatePresentationLimits {
  const limits = {
    ...DEFAULT_CERTIFICATE_PRESENTATION_LIMITS,
    ...values
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new TypeError(`${name} must be a positive safe integer`);
    }
  }
  return limits;
}

function parseByteSequence(value: string, maxBytes: number): Uint8Array {
  if (value.length < 3 || value[0] !== ":" || value.at(-1) !== ":") {
    throw new X509HttpSignatureError(
      "certificate_invalid",
      "RFC 9440 certificates must be Structured Field byte sequences"
    );
  }
  const encoded = value.slice(1, -1);
  if (encoded.length > Math.ceil(maxBytes / 3) * 4) {
    throw new X509HttpSignatureError(
      "certificate_too_large",
      "An RFC 9440 certificate exceeds the configured size limit"
    );
  }
  const decoded = decodeBase64(encoded, "certificate_invalid");
  if (decoded.length > maxBytes) {
    throw new X509HttpSignatureError(
      "certificate_too_large",
      "An RFC 9440 certificate exceeds the configured size limit"
    );
  }
  return decoded;
}

function parseChain(
  value: unknown,
  limits: CertificatePresentationLimits
): Uint8Array[] {
  if (value === undefined || value === null || value === "") return [];
  if (typeof value !== "string") {
    throw new X509HttpSignatureError(
      "certificate_invalid",
      "Client-Cert-Chain must be a string"
    );
  }
  const items = value.split(",");
  if (items.length > limits.maxChainCertificates) {
    throw new X509HttpSignatureError(
      "certificate_too_large",
      "The certificate chain exceeds the configured certificate-count limit"
    );
  }
  const certificates: Uint8Array[] = [];
  let remaining = limits.maxChainBytes;
  for (const item of items) {
    const certificate = parseByteSequence(item.trim(), remaining);
    certificates.push(certificate);
    remaining -= certificate.length;
  }
  return certificates;
}

export function fromRfc9440ClientCertificates(
  input: Rfc9440ClientCertificatesInput
): ClientCertificatePresentation {
  if (typeof input.certificate !== "string" || input.certificate === "") {
    throw new X509HttpSignatureError(
      "certificate_not_presented",
      "Client-Cert was not presented"
    );
  }

  const limits = resolveLimits(input.limits);
  const leafCertificateDer = parseByteSequence(
    input.certificate,
    limits.maxLeafCertificateBytes
  );
  const chainCertificatesDer = parseChain(input.certificateChain, limits);

  if (leafCertificateDer.length > limits.maxLeafCertificateBytes) {
    throw new X509HttpSignatureError(
      "certificate_too_large",
      "The leaf certificate exceeds the configured size limit"
    );
  }
  const chainBytes = chainCertificatesDer.reduce(
    (total, certificate) => total + certificate.length,
    0
  );
  if (chainBytes > limits.maxChainBytes) {
    throw new X509HttpSignatureError(
      "certificate_too_large",
      "The certificate chain exceeds the configured size limit"
    );
  }

  return {
    leafCertificateDer,
    chainCertificatesDer,
    ...(input.subjectHint === undefined ? {} : { subjectHint: input.subjectHint }),
    ...(input.issuerHint === undefined ? {} : { issuerHint: input.issuerHint })
  };
}
