import { X509HttpSignatureError } from "./error.js";
import { fromRfc9440ClientCertificates } from "./rfc9440.js";
import type {
  CertificatePresentationLimits,
  ClientCertificatePresentation
} from "./types.js";

export interface CloudflareTlsClientAuthOptions {
  limits?: Partial<CertificatePresentationLimits>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(
  input: Record<string, unknown>,
  name: string
): string | undefined {
  const value = input[name];
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") {
    throw new X509HttpSignatureError(
      "certificate_invalid",
      `Cloudflare tlsClientAuth.${name} must be a string`
    );
  }
  return value;
}

export function fromCloudflareTlsClientAuth(
  tlsClientAuth: unknown,
  options: CloudflareTlsClientAuthOptions = {}
): ClientCertificatePresentation {
  if (!isRecord(tlsClientAuth)) {
    throw new X509HttpSignatureError(
      "certificate_not_presented",
      "Cloudflare did not provide TLS client-auth metadata"
    );
  }

  const presented = tlsClientAuth.certPresented;
  if (presented === "0" || presented === false || presented === undefined) {
    throw new X509HttpSignatureError(
      "certificate_not_presented",
      "A TLS client certificate was not presented"
    );
  }
  if (presented !== "1" && presented !== true) {
    throw new X509HttpSignatureError(
      "certificate_invalid",
      "Cloudflare tlsClientAuth.certPresented has an invalid value"
    );
  }

  if (
    tlsClientAuth.certRFC9440TooLarge === true ||
    tlsClientAuth.certChainRFC9440TooLarge === true
  ) {
    throw new X509HttpSignatureError(
      "certificate_too_large",
      "Cloudflare omitted certificate data because it exceeded a platform limit"
    );
  }
  for (const name of ["certRFC9440TooLarge", "certChainRFC9440TooLarge"] as const) {
    const value = tlsClientAuth[name];
    if (value !== undefined && typeof value !== "boolean") {
      throw new X509HttpSignatureError(
        "certificate_invalid",
        `Cloudflare tlsClientAuth.${name} must be a boolean`
      );
    }
  }

  const certificate = optionalString(tlsClientAuth, "certRFC9440");
  if (certificate === undefined) {
    throw new X509HttpSignatureError(
      "certificate_not_presented",
      "Cloudflare did not provide the RFC 9440 leaf certificate"
    );
  }

  const certificateChain = optionalString(tlsClientAuth, "certChainRFC9440");
  const subjectHint = optionalString(tlsClientAuth, "certSubjectDN");
  const issuerHint = optionalString(tlsClientAuth, "certIssuerDN");
  return fromRfc9440ClientCertificates({
    certificate,
    ...(certificateChain === undefined ? {} : { certificateChain }),
    ...(subjectHint === undefined ? {} : { subjectHint }),
    ...(issuerHint === undefined ? {} : { issuerHint }),
    ...(options.limits === undefined ? {} : { limits: options.limits })
  });
}
