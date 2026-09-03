import { X509HttpSignatureError } from "./error.js";

interface DerElement {
  tag: number;
  contentStart: number;
  contentEnd: number;
}

const OID_NAMES: Readonly<Record<string, string>> = Object.freeze({
  "2.5.4.3": "CN",
  "2.5.4.4": "SN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "street",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.12": "title",
  "2.5.4.42": "GN",
  "0.9.2342.19200300.100.1.1": "UID",
  "0.9.2342.19200300.100.1.25": "DC",
  "1.2.840.113549.1.9.1": "emailAddress"
});

function readElement(bytes: Uint8Array, offset: number, boundary = bytes.length): DerElement & { next: number } {
  if (offset + 2 > boundary) throw new Error("truncated DER element");
  const tag = bytes[offset]!;
  const firstLength = bytes[offset + 1]!;
  let length = firstLength;
  let headerLength = 2;
  if ((firstLength & 0x80) !== 0) {
    const octets = firstLength & 0x7f;
    if (octets === 0 || octets > 4 || offset + 2 + octets > boundary) {
      throw new Error("invalid DER length");
    }
    length = 0;
    for (let index = 0; index < octets; index += 1) {
      length = length * 256 + bytes[offset + 2 + index]!;
    }
    if (length < 128) throw new Error("non-minimal DER length");
    headerLength += octets;
  }
  const contentStart = offset + headerLength;
  const contentEnd = contentStart + length;
  if (contentEnd > boundary) throw new Error("DER length exceeds parent");
  return { tag, contentStart, contentEnd, next: contentEnd };
}

function children(bytes: Uint8Array, element: DerElement): DerElement[] {
  const result: DerElement[] = [];
  let offset = element.contentStart;
  while (offset < element.contentEnd) {
    const child = readElement(bytes, offset, element.contentEnd);
    result.push(child);
    offset = child.next;
  }
  return result;
}

function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) throw new Error("empty OID");
  const first = bytes[0]!;
  const arcs = [Math.min(2, Math.floor(first / 40)), first < 80 ? first % 40 : first - 80];
  let value = 0;
  let continuing = false;
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f);
    if (!Number.isSafeInteger(value)) throw new Error("OID arc is too large");
    continuing = (byte & 0x80) !== 0;
    if (!continuing) {
      arcs.push(value);
      value = 0;
    }
  }
  if (continuing) throw new Error("truncated OID");
  return arcs.join(".");
}

function decodeBmpString(bytes: Uint8Array): string {
  if (bytes.length % 2 !== 0) throw new Error("invalid BMPString");
  let result = "";
  for (let index = 0; index < bytes.length; index += 2) {
    result += String.fromCharCode((bytes[index]! << 8) | bytes[index + 1]!);
  }
  return result;
}

function decodeUniversalString(bytes: Uint8Array): string {
  if (bytes.length % 4 !== 0) throw new Error("invalid UniversalString");
  let result = "";
  for (let index = 0; index < bytes.length; index += 4) {
    const point =
      bytes[index]! * 0x1000000 +
      bytes[index + 1]! * 0x10000 +
      bytes[index + 2]! * 0x100 +
      bytes[index + 3]!;
    result += String.fromCodePoint(point);
  }
  return result;
}

function decodeDirectoryString(tag: number, bytes: Uint8Array): string {
  if (tag === 0x0c) return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (tag === 0x1e) return decodeBmpString(bytes);
  if (tag === 0x1c) return decodeUniversalString(bytes);
  if ([0x12, 0x13, 0x14, 0x16, 0x1a].includes(tag)) {
    return Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  }
  throw new Error(`unsupported subject string tag 0x${tag.toString(16)}`);
}

function escapeDnValue(value: string): string {
  let escaped = value.replace(/([,+=<>#;"\\])/g, "\\$1");
  escaped = escaped.replace(/^ /, "\\ ").replace(/ $/, "\\ ");
  if (escaped.startsWith("#")) escaped = `\\${escaped}`;
  return escaped;
}

export function readCertificateSubject(certificateDer: Uint8Array): string {
  try {
    const certificate = readElement(certificateDer, 0);
    if (certificate.tag !== 0x30 || certificate.next !== certificateDer.length) {
      throw new Error("certificate is not a single DER sequence");
    }
    const certificateFields = children(certificateDer, certificate);
    const tbs = certificateFields[0];
    if (tbs?.tag !== 0x30) throw new Error("missing TBSCertificate");
    const tbsFields = children(certificateDer, tbs);
    const hasVersion = tbsFields[0]?.tag === 0xa0;
    const subject = tbsFields[hasVersion ? 5 : 4];
    if (subject?.tag !== 0x30) throw new Error("missing certificate subject");

    const rdns = children(certificateDer, subject).map((set) => {
      if (set.tag !== 0x31) throw new Error("invalid subject RDN");
      return children(certificateDer, set).map((attribute) => {
        if (attribute.tag !== 0x30) throw new Error("invalid subject attribute");
        const fields = children(certificateDer, attribute);
        const oid = fields[0];
        const value = fields[1];
        if (oid?.tag !== 0x06 || value === undefined || fields.length !== 2) {
          throw new Error("invalid subject attribute fields");
        }
        const oidText = decodeOid(certificateDer.subarray(oid.contentStart, oid.contentEnd));
        const valueText = decodeDirectoryString(
          value.tag,
          certificateDer.subarray(value.contentStart, value.contentEnd)
        );
        return `${OID_NAMES[oidText] ?? oidText}=${escapeDnValue(valueText)}`;
      }).join("+");
    });
    return rdns.join(",");
  } catch (cause) {
    throw new X509HttpSignatureError(
      "certificate_invalid",
      "Unable to read the certificate subject",
      { cause }
    );
  }
}
