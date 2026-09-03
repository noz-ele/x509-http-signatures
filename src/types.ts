export interface ClientCertificatePresentation {
  leafCertificateDer: Uint8Array;
  chainCertificatesDer: Uint8Array[];
  subjectHint?: string;
  issuerHint?: string;
}

export interface VerifiedClientCertificate {
  leafCertificatePem: string;
  fingerprintSha256: string;
  subject: string;
}

export interface SignatureChallenge {
  acceptSignature: string;
  expiresAt: Date;
}

export interface VerifiedSignedRequest {
  certificateFingerprint: string;
  certificateSubject: string;
  challengeId: string;
  createdAt: Date;
  expiresAt: Date;
}

export type HttpMessageSignatureAlgorithm = "ecdsa-p256-sha256";

export interface HttpMessageSigner {
  sign(
    data: Uint8Array,
    algorithm: HttpMessageSignatureAlgorithm
  ): Promise<Uint8Array>;
}

export type ChallengeSigningKey = CryptoKey | Uint8Array;

export interface CertificatePresentationLimits {
  maxLeafCertificateBytes: number;
  maxChainBytes: number;
  maxChainCertificates: number;
}

export const DEFAULT_CERTIFICATE_PRESENTATION_LIMITS = Object.freeze({
  maxLeafCertificateBytes: 10 * 1024,
  maxChainBytes: 16 * 1024,
  maxChainCertificates: 2
}) satisfies CertificatePresentationLimits;
