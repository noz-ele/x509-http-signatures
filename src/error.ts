export type X509HttpSignatureErrorCode =
  | "certificate_not_presented"
  | "certificate_too_large"
  | "certificate_invalid"
  | "challenge_invalid"
  | "challenge_expired"
  | "content_digest_invalid"
  | "signature_input_invalid"
  | "signature_invalid"
  | "certificate_mismatch";

export class X509HttpSignatureError extends Error {
  readonly code: X509HttpSignatureErrorCode;

  constructor(
    code: X509HttpSignatureErrorCode,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "X509HttpSignatureError";
    this.code = code;
  }
}
