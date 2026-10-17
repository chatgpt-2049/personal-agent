import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createEd25519Csr } from "../app/lib/csr.ts";

const address = "0x1111111111111111111111111111111111111111";
const { privateKey } = generateKeyPairSync("ed25519");
const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();

test("CSR signature and CN are verified by OpenSSL", async () => {
  const csr = await createEd25519Csr(pem, address);
  const result = execFileSync("openssl", ["req", "-verify", "-noout", "-subject"], { input: csr, encoding: "utf8" });
  assert.ok(result.includes(address));
  assert.ok(!csr.includes("PRIVATE KEY"));
});

test("rejects invalid addresses, non-PEM, oversized, and non-Ed25519 keys", async () => {
  await assert.rejects(createEd25519Csr(pem, "invalid"));
  await assert.rejects(createEd25519Csr("ab".repeat(32), address));
  await assert.rejects(createEd25519Csr("x".repeat(17000), address));
  const ec = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  await assert.rejects(createEd25519Csr(ec.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), address));
});
