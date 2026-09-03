import { copyArrayBuffer, decodeBase64, encodeBase64 } from "./bytes.js";
import { X509HttpSignatureError, type X509HttpSignatureErrorCode } from "./error.js";

export const SIGNATURE_COMPONENTS = Object.freeze([
  "@method",
  "@target-uri",
  "content-digest"
] as const);
export const SIGNATURE_ALGORITHM = "ecdsa-p256-sha256" as const;
export const SIGNATURE_TAG = "x509-http-signature" as const;

export type StructuredParameterValue = string | number | true;

export interface ParsedParameterizedInnerList {
  label: string;
  components: string[];
  parameters: ReadonlyMap<string, StructuredParameterValue>;
  serializedValue: string;
}

function fail(code: X509HttpSignatureErrorCode, message: string): never {
  throw new X509HttpSignatureError(code, message);
}

function parseString(
  input: string,
  start: number,
  code: X509HttpSignatureErrorCode
): { value: string; next: number } {
  if (input[start] !== '"') fail(code, "Expected a Structured Field string");
  let value = "";
  for (let index = start + 1; index < input.length; index += 1) {
    const character = input[index]!;
    if (character === '"') return { value, next: index + 1 };
    if (character === "\\") {
      const escaped = input[index + 1];
      if (escaped !== '"' && escaped !== "\\") {
        fail(code, "Invalid Structured Field string escape");
      }
      value += escaped;
      index += 1;
      continue;
    }
    const point = character.charCodeAt(0);
    if (point < 0x20 || point > 0x7e) {
      fail(code, "Invalid character in Structured Field string");
    }
    value += character;
  }
  return fail(code, "Unterminated Structured Field string");
}

export function quoteStructuredString(value: string): string {
  for (const character of value) {
    const point = character.charCodeAt(0);
    if (point < 0x20 || point > 0x7e) {
      throw new TypeError("Structured Field strings must contain printable ASCII only");
    }
  }
  return `"${value.replace(/(["\\])/g, "\\$1")}"`;
}

export function parseParameterizedInnerList(
  fieldValue: string,
  code: X509HttpSignatureErrorCode
): ParsedParameterizedInnerList {
  const input = fieldValue.trim();
  const labelMatch = /^([a-z*][a-z0-9_.*-]*)=/.exec(input);
  if (labelMatch === null) fail(code, "Invalid signature dictionary label");
  const label = labelMatch[1]!;
  let index = labelMatch[0].length;
  const serializedStart = index;
  if (input[index] !== "(") fail(code, "Signature dictionary value must be an Inner List");
  index += 1;
  const components: string[] = [];

  while (true) {
    while (input[index] === " ") index += 1;
    if (input[index] === ")") {
      index += 1;
      break;
    }
    const item = parseString(input, index, code);
    components.push(item.value);
    index = item.next;
    if (input[index] !== " " && input[index] !== ")") {
      fail(code, "Invalid separator in covered component list");
    }
  }
  if (components.length === 0) fail(code, "Covered component list cannot be empty");

  const parameters = new Map<string, StructuredParameterValue>();
  while (index < input.length) {
    if (input[index] !== ";") fail(code, "Invalid signature parameter separator");
    index += 1;
    const nameMatch = /^[a-z*][a-z0-9_.*-]*/.exec(input.slice(index));
    if (nameMatch === null) fail(code, "Invalid signature parameter name");
    const name = nameMatch[0];
    index += name.length;
    if (parameters.has(name)) fail(code, `Duplicate signature parameter: ${name}`);

    let value: StructuredParameterValue = true;
    if (input[index] === "=") {
      index += 1;
      if (input[index] === '"') {
        const parsed = parseString(input, index, code);
        value = parsed.value;
        index = parsed.next;
      } else {
        const integerMatch = /^-?(?:0|[1-9][0-9]*)/.exec(input.slice(index));
        if (integerMatch === null) fail(code, `Invalid value for signature parameter: ${name}`);
        value = Number(integerMatch[0]);
        if (!Number.isSafeInteger(value)) fail(code, `Unsafe integer parameter: ${name}`);
        index += integerMatch[0].length;
      }
    }
    parameters.set(name, value);
  }

  return {
    label,
    components,
    parameters,
    serializedValue: input.slice(serializedStart)
  };
}

export function assertFixedComponents(
  components: readonly string[],
  code: X509HttpSignatureErrorCode
): void {
  if (
    components.length !== SIGNATURE_COMPONENTS.length ||
    components.some((component, index) => component !== SIGNATURE_COMPONENTS[index])
  ) {
    fail(code, "The signature does not use the required covered components");
  }
}

export function serializeComponents(): string {
  return `(${SIGNATURE_COMPONENTS.map(quoteStructuredString).join(" ")})`;
}

export function buildSignatureBase(
  request: Request,
  contentDigest: string,
  serializedSignatureParams: string
): Uint8Array {
  const value = [
    `"@method": ${request.method}`,
    `"@target-uri": ${request.url}`,
    `"content-digest": ${contentDigest}`,
    `"@signature-params": ${serializedSignatureParams}`
  ].join("\n");
  return new TextEncoder().encode(value);
}

export async function readRequestBody(request: Request): Promise<Uint8Array> {
  if (request.body === null) return new Uint8Array();
  return new Uint8Array(await request.clone().arrayBuffer());
}

export async function createContentDigest(body: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", copyArrayBuffer(body))
  );
  return `sha-256=:${encodeBase64(digest)}:`;
}

export function parseContentDigest(value: string | null): Uint8Array {
  if (value === null) {
    fail("content_digest_invalid", "Content-Digest is missing");
  }
  const match = /^sha-256=:([A-Za-z0-9+/]+={0,2}):$/.exec(value);
  if (match?.[1] === undefined) {
    fail("content_digest_invalid", "Content-Digest must contain one sha-256 value");
  }
  const digest = decodeBase64(match[1], "content_digest_invalid");
  if (digest.length !== 32) {
    fail("content_digest_invalid", "The sha-256 digest must contain 32 bytes");
  }
  return digest;
}

export function parseSignatureField(
  value: string | null,
  expectedLabel: string
): Uint8Array {
  if (value === null) fail("signature_invalid", "Signature is missing");
  const match = /^([a-z*][a-z0-9_.*-]*)=:([A-Za-z0-9+/]+={0,2}):$/.exec(value.trim());
  if (match?.[1] !== expectedLabel || match[2] === undefined) {
    fail("signature_invalid", "Signature does not match the requested label");
  }
  return decodeBase64(match[2], "signature_invalid");
}
