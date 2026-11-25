
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  publicEncrypt,
  privateDecrypt,
  sign,
  verify,
  constants,
  createHmac,
} from "node:crypto";

import { readFileSync } from "node:fs";

const b = (x) => Buffer.from(x).toString("base64url"),
  u = (x) => Buffer.from(x, "base64url");

export const keyId = process.env.KEY_ID || "v1";

// Environment variable mapping for existing v1 keys
const keyEnvironmentMap = {
  "sign-private": "QR_SIGN_PRIVATE_KEY",
  "sign-public": "QR_SIGN_PUBLIC_KEY",
  "encrypt-private": "QR_ENCRYPT_PRIVATE_KEY",
  "encrypt-public": "QR_ENCRYPT_PUBLIC_KEY",
};

// Load keys from Vercel environment variables
// or local PEM files
function key(id, type) {
  if (!/^[a-zA-Z0-9_-]{1,32}$/.test(id)) {
    throw Error("Invalid key ID");
  }

  const envName = keyEnvironmentMap[type];

  if (!envName) {
    throw Error("Invalid key type");
  }

  // Environment variables contain the existing v1 keys
  if (id === "v1") {
    const envValue = process.env[envName];

    if (envValue?.trim()) {
      return Buffer.from(envValue.trim(), "base64");
    }
  }

  // Vercel production must use environment variables
  if (process.env.VERCEL === "1") {
    throw Error(
      `Missing QR key configuration for ${id}-${type}`
    );
  }

  // Local development fallback
  const keyDirectory = process.env.KEY_DIR || "./keys";

  return readFileSync(
    `${keyDirectory}/${id}-${type}.pem`
  );
}

export function seal(data) {
  const raw = Buffer.from(JSON.stringify(data));

  const sig = sign(
    null,
    raw,
    key(keyId, "sign-private")
  );

  const aes = randomBytes(32),
    iv = randomBytes(12);

  const c = createCipheriv("aes-256-gcm", aes, iv);

  c.setAAD(Buffer.from(`BPVS1.${keyId}`));

  const ciphertext = Buffer.concat([
    c.update(JSON.stringify({ p: b(raw), s: b(sig) })),
    c.final(),
  ]);

  const wrapped = publicEncrypt(
    {
      key: key(keyId, "encrypt-public"),
      oaepHash: "sha256",
      padding: constants.RSA_PKCS1_OAEP_PADDING,
    },
    aes,
  );

  return [
    "BPVS1",
    keyId,
    b(wrapped),
    b(iv),
    b(ciphertext),
    b(c.getAuthTag()),
  ].join(".");
}

export function unseal(value) {
  const parts = value.split(".");

  if (
    parts.length !== 6 ||
    parts[0] !== "BPVS1" ||
    value.length > 4096
  ) {
    throw Error("Invalid QR");
  }

  const [, id, w, iv, ct, tag] = parts;

  const aes = privateDecrypt(
    {
      key: key(id, "encrypt-private"),
      oaepHash: "sha256",
      padding: constants.RSA_PKCS1_OAEP_PADDING,
    },
    u(w),
  );

  const d = createDecipheriv(
    "aes-256-gcm",
    aes,
    u(iv)
  );

  d.setAAD(Buffer.from(`BPVS1.${id}`));
  d.setAuthTag(u(tag));

  const { p, s } = JSON.parse(
    Buffer.concat([
      d.update(u(ct)),
      d.final(),
    ])
  );

  if (
    !verify(
      null,
      u(p),
      key(id, "sign-public"),
      u(s)
    )
  ) {
    throw Error("Invalid signature");
  }

  return JSON.parse(u(p));
}

export const digest = (t) =>
  createHmac("sha256", process.env.TOKEN_PEPPER)
    .update(t)
    .digest("hex");

export function protectSecret(value) {
  const iv = randomBytes(12),
    c = createCipheriv(
      "aes-256-gcm",
      Buffer.from(digest("totp-storage"), "hex"),
      iv,
    );

  return [
    b(iv),
    b(
      Buffer.concat([
        c.update(value, "utf8"),
        c.final(),
      ])
    ),
    b(c.getAuthTag()),
  ].join(".");
}

export function revealSecret(value) {
  const [iv, ct, tag] = value.split(".").map(u);

  const d = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(digest("totp-storage"), "hex"),
    iv,
  );

  d.setAuthTag(tag);

  return Buffer.concat([
    d.update(ct),
    d.final(),
  ]).toString();
}
