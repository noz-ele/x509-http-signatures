import { verifyCertificateChain } from "@noz-ele/edgca/verify";
import { bytesEqual, copyArrayBuffer, fromPem, toHex, toPem } from "./bytes.js";
import { X509HttpSignatureError } from "./error.js";
import type { ClientCertificatePresentation, VerifiedClientCertificate } from "./types.js";
import { readCertificateSubject } from "./x509-subject.js";

export interface VerifyClientCertificateOptions {
  presentation: ClientCertificatePresentation;
  trustedRootCertificatesPem: readonly string[];
  purpose: "clientAuth";
  at?: Date | number;
}

export async function verifyClientCertificate(
  options: VerifyClientCertificateOptions
): Promise<VerifiedClientCertificate> {
  if (options.trustedRootCertificatesPem.length === 0) {
    throw new TypeError("trustedRootCertificatesPem must not be empty");
  }

  try {
    const rootDer = options.trustedRootCertificatesPem.map((pem) => fromPem("CERTIFICATE", pem));
    const intermediates = options.presentation.chainCertificatesDer.filter(
      (candidate) => !rootDer.some((root) => bytesEqual(candidate, root))
    );
    const leafCertificatePem = toPem("CERTIFICATE", options.presentation.leafCertificateDer);
    const result = await verifyCertificateChain({
      certificatePem: leafCertificatePem,
      intermediateCertificatesPem: intermediates.map((certificate) => toPem("CERTIFICATE", certificate)),
      trustedRootCertificatesPem: options.trustedRootCertificatesPem,
      purpose: options.purpose,
      ...(options.at === undefined ? {} : { at: options.at })
    });
    if (!result.valid) {
      throw new Error(`certificate chain rejected at ${result.certificateIndex}: ${result.reason}`);
    }
    const fingerprint = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        copyArrayBuffer(options.presentation.leafCertificateDer)
      )
    );
    return {
      leafCertificatePem,
      fingerprintSha256: toHex(fingerprint),
      subject: readCertificateSubject(options.presentation.leafCertificateDer)
    };
  } catch (cause) {
    if (cause instanceof X509HttpSignatureError) throw cause;
    throw new X509HttpSignatureError(
      "certificate_invalid",
      "Client certificate verification failed",
      { cause }
    );
  }
}
