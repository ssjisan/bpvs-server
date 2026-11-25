import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
const dir = mkdtempSync(join(tmpdir(), "bpvs-"));
process.env.KEY_DIR = dir;
process.env.KEY_ID = "test";
process.env.TOKEN_PEPPER = "test-secret";
execFileSync(process.execPath, ["src/keys.js"], { env: process.env });
const { seal, unseal, protectSecret, revealSecret } =
  await import("../src/crypto.js");
test("signed encrypted payload round trip and tampering", () => {
  const data = { qid: "test", qty: 50000 };
  const token = seal(data);
  assert.deepEqual(unseal(token), data);
  const parts = token.split(".");
  parts[4] = (parts[4][0] === "A" ? "B" : "A") + parts[4].slice(1);
  assert.throws(() => unseal(parts.join(".")));
});
test("TOTP secret storage", () =>
  assert.equal(revealSecret(protectSecret("ABC")), "ABC"));
after(() => rmSync(dir, { recursive: true, force: true }));
