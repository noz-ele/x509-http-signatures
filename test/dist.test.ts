import { describe, expect, it } from "vitest";

describe("published entry points", () => {
  it("load from package exports", async () => {
    const [root, client, server, rfc9440, cloudflare] = await Promise.all([
      import("@noz-ele/x509-http-signatures"),
      import("@noz-ele/x509-http-signatures/client"),
      import("@noz-ele/x509-http-signatures/server"),
      import("@noz-ele/x509-http-signatures/rfc9440"),
      import("@noz-ele/x509-http-signatures/cloudflare")
    ]);
    expect(root.X509HttpSignatureError).toBeTypeOf("function");
    expect(root.signRequest).toBe(client.signRequest);
    expect(root.verifySignedRequest).toBe(server.verifySignedRequest);
    expect(client.signRequest).toBeTypeOf("function");
    expect(server.verifySignedRequest).toBeTypeOf("function");
    expect(rfc9440.fromRfc9440ClientCertificates).toBeTypeOf("function");
    expect(cloudflare.fromCloudflareTlsClientAuth).toBeTypeOf("function");
  });
});
