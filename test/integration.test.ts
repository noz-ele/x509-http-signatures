import { createRootCA, issueClientCert } from "@noz-ele/edgca";
import { signData } from "@noz-ele/edgca/sign";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";
import { fromCloudflareTlsClientAuth } from "../src/cloudflare.js";
import { X509HttpSignatureError } from "../src/error.js";
import { fromRfc9440ClientCertificates } from "../src/rfc9440.js";
import {
  issueSignatureChallenge,
  verifyClientCertificate,
  verifySignedRequest
} from "../src/server.js";
import { signRequest } from "../src/client.js";

interface Fixture {
  rootPem: string;
  rootDer: Uint8Array;
  clientDer: Uint8Array;
  privateKey: CryptoKey;
}

function rfc9440(bytes: Uint8Array): string {
  return `:${Buffer.from(bytes).toString("base64")}:`;
}

function expectCode(error: unknown, code: string): boolean {
  return error instanceof X509HttpSignatureError && error.code === code;
}

const execFileAsync = promisify(execFile);

function privateKeyPem(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString("base64");
  return `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
}

describe("X.509 HTTP signature flow", () => {
  let fixture: Fixture;

  beforeAll(async () => {
    const root = await createRootCA({
      subject: [{ type: "CN", value: "test-root" }],
      days: 30
    });
    const client = await issueClientCert({
      ca: root,
      subject: [
        { type: "CN", value: "alice" },
        { type: "O", value: "Example" }
      ],
      days: 1
    });
    fixture = {
      rootPem: root.certPem,
      rootDer: root.certDer,
      clientDer: client.certDer,
      privateKey: client.privateKey
    };
  });

  it("parses Cloudflare metadata, validates the chain, and verifies a signed request", async () => {
    const presentation = fromCloudflareTlsClientAuth({
      certPresented: "1",
      certRFC9440: rfc9440(fixture.clientDer),
      certRFC9440TooLarge: false,
      certChainRFC9440: rfc9440(fixture.rootDer),
      certChainRFC9440TooLarge: false,
      certSubjectDN: "CN=untrusted-hint",
      certIssuerDN: "CN=test-root"
    });
    const certificate = await verifyClientCertificate({
      presentation,
      trustedRootCertificatesPem: [fixture.rootPem],
      purpose: "clientAuth"
    });
    expect(certificate.subject).toBe("CN=alice,O=Example");
    expect(certificate.subject).not.toBe(presentation.subjectHint);
    expect(certificate.fingerprintSha256).toMatch(/^[0-9a-f]{64}$/);

    const challengeKey = new Uint8Array(32).fill(0x42);
    const challenge = await issueSignatureChallenge({
      certificate,
      audience: "https://api.example.test/admin",
      challengeSigningKey: challengeKey
    });
    const unsigned = new Request("https://api.example.test/admin?mode=test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: true })
    });
    const signed = await signRequest({
      request: unsigned,
      acceptSignature: challenge.acceptSignature,
      signer: {
        sign(data) {
          return signData({
            privateKey: fixture.privateKey,
            data,
            signatureFormat: "ieee-p1363"
          });
        }
      }
    });

    expect(unsigned.bodyUsed).toBe(false);
    expect(unsigned.headers.has("Signature")).toBe(false);
    expect(signed.headers.get("Content-Digest")).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:/);
    const proof = await verifySignedRequest({
      request: signed,
      certificate,
      challengeSigningKey: challengeKey,
      expectedAudience: "https://api.example.test/admin"
    });
    expect(proof.certificateFingerprint).toBe(certificate.fingerprintSha256);
    expect(proof.certificateSubject).toBe("CN=alice,O=Example");
    expect(proof.challengeId).toMatch(/^[A-Za-z0-9_-]+$/);

    const changedBody = new Request(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: JSON.stringify({ ok: false })
    });
    await expect(
      verifySignedRequest({
        request: changedBody,
        certificate,
        challengeSigningKey: challengeKey,
        expectedAudience: "https://api.example.test/admin"
      })
    ).rejects.toSatisfy((error: unknown) => expectCode(error, "content_digest_invalid"));
  });

  it("binds signatures to the target URI and challenge audience", async () => {
    const presentation = fromRfc9440ClientCertificates({
      certificate: rfc9440(fixture.clientDer),
      certificateChain: rfc9440(fixture.rootDer)
    });
    const certificate = await verifyClientCertificate({
      presentation,
      trustedRootCertificatesPem: [fixture.rootPem],
      purpose: "clientAuth"
    });
    const challengeKey = new Uint8Array(32).fill(0x11);
    const challenge = await issueSignatureChallenge({
      certificate,
      audience: "admin-api",
      challengeSigningKey: challengeKey
    });
    const signed = await signRequest({
      request: new Request("https://example.test/a"),
      acceptSignature: challenge.acceptSignature,
      signer: {
        sign(data) {
          return signData({
            privateKey: fixture.privateKey,
            data,
            signatureFormat: "ieee-p1363"
          });
        }
      }
    });
    const moved = new Request("https://example.test/b", { headers: signed.headers });
    await expect(
      verifySignedRequest({
        request: moved,
        certificate,
        challengeSigningKey: challengeKey,
        expectedAudience: "admin-api"
      })
    ).rejects.toSatisfy((error: unknown) => expectCode(error, "signature_invalid"));
    await expect(
      verifySignedRequest({
        request: signed,
        certificate,
        challengeSigningKey: challengeKey,
        expectedAudience: "other-api"
      })
    ).rejects.toSatisfy((error: unknown) => expectCode(error, "challenge_invalid"));
  });

  it("prints curl-ready headers from the CLI", async () => {
    const presentation = fromRfc9440ClientCertificates({
      certificate: rfc9440(fixture.clientDer),
      certificateChain: rfc9440(fixture.rootDer)
    });
    const certificate = await verifyClientCertificate({
      presentation,
      trustedRootCertificatesPem: [fixture.rootPem],
      purpose: "clientAuth"
    });
    const challengeKey = new Uint8Array(32).fill(0x27);
    const challenge = await issueSignatureChallenge({
      certificate,
      audience: "cli-test",
      challengeSigningKey: challengeKey
    });
    const directory = await mkdtemp(join(tmpdir(), "x509-http-signatures-"));
    try {
      const keyPath = join(directory, "client.key.pem");
      const bodyPath = join(directory, "body.txt");
      const pkcs8 = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", fixture.privateKey)
      );
      await Promise.all([
        writeFile(keyPath, privateKeyPem(pkcs8)),
        writeFile(bodyPath, "hello")
      ]);
      pkcs8.fill(0);
      const { stdout } = await execFileAsync(process.execPath, [
        "dist/cli.js",
        "sign-request",
        "--method", "POST",
        "--url", "https://example.test/cli",
        "--accept-signature", challenge.acceptSignature,
        "--key", keyPath,
        "--body", bodyPath
      ]);
      const headers = new Headers();
      for (const line of stdout.trim().split(/\r?\n/)) {
        const separator = line.indexOf(":");
        headers.set(line.slice(0, separator), line.slice(separator + 1).trim());
      }
      const proof = await verifySignedRequest({
        request: new Request("https://example.test/cli", {
          method: "POST",
          headers,
          body: "hello"
        }),
        certificate,
        challengeSigningKey: challengeKey,
        expectedAudience: "cli-test"
      });
      expect(proof.certificateFingerprint).toBe(certificate.fingerprintSha256);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects absent, malformed, and oversized certificate metadata", () => {
    expect(() => fromCloudflareTlsClientAuth({ certPresented: "0" })).toThrowError(
      expect.objectContaining({ code: "certificate_not_presented" })
    );
    expect(() => fromCloudflareTlsClientAuth({
      certPresented: "1",
      certRFC9440TooLarge: true,
      certChainRFC9440TooLarge: false
    })).toThrowError(expect.objectContaining({ code: "certificate_too_large" }));
    expect(() => fromRfc9440ClientCertificates({ certificate: "not-a-byte-sequence" }))
      .toThrowError(expect.objectContaining({ code: "certificate_invalid" }));
    expect(() => fromRfc9440ClientCertificates({
      certificate: rfc9440(new Uint8Array(2)),
      limits: { maxLeafCertificateBytes: 1 }
    })).toThrowError(expect.objectContaining({ code: "certificate_too_large" }));
  });
});
