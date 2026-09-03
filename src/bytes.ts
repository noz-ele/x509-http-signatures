import { X509HttpSignatureError } from "./error.js";
import type { X509HttpSignatureErrorCode } from "./error.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
  return textDecoder.decode(value);
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function decodeBase64(
  value: string,
  code: X509HttpSignatureErrorCode = "signature_input_invalid"
): Uint8Array {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new X509HttpSignatureError(code, "Invalid canonical base64 value");
  }

  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    if (encodeBase64(bytes) !== value) {
      throw new Error("non-canonical base64");
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof X509HttpSignatureError) throw cause;
    throw new X509HttpSignatureError(code, "Invalid base64 value", { cause });
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBase64(bytes)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new X509HttpSignatureError("challenge_invalid", "Invalid base64url value");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + padding;
  try {
    const decoded = decodeBase64(base64);
    if (encodeBase64Url(decoded) !== value) {
      throw new Error("non-canonical base64url");
    }
    return decoded;
  } catch (cause) {
    throw new X509HttpSignatureError("challenge_invalid", "Invalid base64url value", { cause });
  }
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function toPem(label: string, bytes: Uint8Array): string {
  const base64 = encodeBase64(bytes);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export function fromPem(label: string, pem: string): Uint8Array {
  const escapedLabel = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(
    `^\\s*-----BEGIN ${escapedLabel}-----\\s*([A-Za-z0-9+/=\\r\\n]+?)\\s*-----END ${escapedLabel}-----\\s*$`
  ).exec(pem);
  if (match?.[1] === undefined) {
    throw new X509HttpSignatureError(
      "certificate_invalid",
      `Expected one ${label} PEM block`
    );
  }
  return decodeBase64(match[1].replace(/[\r\n]/g, ""), "certificate_invalid");
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function copyArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}
