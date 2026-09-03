#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { signData } from "@noz-ele/edgca/sign";
import { signRequest } from "./client.js";

const HELP = `Usage:
  x509-http-signatures sign-request --method <method> --url <url>
    (--accept-signature <value> | --accept-signature-file <path>)
    --key <pkcs8-pem> [--body <path>]

Prints Content-Digest, Signature-Input, and Signature header lines. The body
file is read as raw bytes. Omit --body for an empty body.`;

function decodePrivateKeyPem(pem: string): Uint8Array {
  const match = /^\s*-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END PRIVATE KEY-----\s*$/.exec(pem);
  if (match?.[1] === undefined) {
    throw new Error("--key must contain one unencrypted PKCS#8 PRIVATE KEY PEM block");
  }
  return Uint8Array.from(Buffer.from(match[1].replace(/[\r\n]/g, ""), "base64"));
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === undefined || command === "--help" || command === "-h") {
    process.stdout.write(`${HELP}\n`);
    return;
  }
  if (command !== "sign-request") {
    throw new Error(`Unknown command: ${command}\n\n${HELP}`);
  }
  const { values } = parseArgs({
    args,
    strict: true,
    allowPositionals: false,
    options: {
      method: { type: "string" },
      url: { type: "string" },
      "accept-signature": { type: "string" },
      "accept-signature-file": { type: "string" },
      key: { type: "string" },
      body: { type: "string" },
      help: { type: "boolean", short: "h" }
    }
  });
  if (values.help === true) {
    process.stdout.write(`${HELP}\n`);
    return;
  }
  if (
    values.method === undefined ||
    values.url === undefined ||
    values.key === undefined ||
    (values["accept-signature"] === undefined) ===
      (values["accept-signature-file"] === undefined)
  ) {
    throw new Error(`Missing or conflicting required options\n\n${HELP}`);
  }

  const acceptSignature = values["accept-signature"] ??
    (await readFile(values["accept-signature-file"]!, "utf8")).trim();
  const keyDer = decodePrivateKeyPem(await readFile(values.key, "utf8"));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    keyDer.slice().buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  keyDer.fill(0);
  const body = values.body === undefined ? undefined : await readFile(values.body);
  const method = values.method.toUpperCase();
  if (body !== undefined && (method === "GET" || method === "HEAD")) {
    throw new Error(`--body cannot be used with ${method}`);
  }
  const request = new Request(values.url, {
    method,
    ...(body === undefined || method === "GET" || method === "HEAD" ? {} : { body })
  });
  const signed = await signRequest({
    request,
    acceptSignature,
    signer: {
      sign(data, algorithm) {
        if (algorithm !== "ecdsa-p256-sha256") {
          throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
        return signData({
          privateKey,
          data,
          signatureFormat: "ieee-p1363"
        });
      }
    }
  });
  for (const name of ["Content-Digest", "Signature-Input", "Signature"]) {
    process.stdout.write(`${name}: ${signed.headers.get(name)}\n`);
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
