/**
 * proxyCredentialEncryption.ts
 *
 * AES-256-GCM encryption for proxy credentials stored in the scan_proxies table.
 *
 * Key derivation: SHA-256 of SESSION_SECRET (already required env var).
 * Ciphertext format: "gcm:v1:<iv_hex>:<authTag_hex>:<ciphertext_hex>"
 * Plain strings that don't start with "gcm:v1:" are treated as legacy
 * plaintext and returned as-is (no crash on unencrypted rows from before
 * this feature was deployed).
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";

const ALGO = "aes-256-gcm";
const PREFIX = "gcm:v1:";

function deriveKey(): Buffer {
  const secret = process.env.SESSION_SECRET ?? "sentinelware-default-dev-secret-do-not-use-in-prod";
  return createHash("sha256").update(secret).digest();
}

function deriveKeyFromSecret(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

export function encryptCredential(plaintext: string): string {
  const key = deriveKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
}

export function decryptCredential(stored: string): string {
  if (!stored.startsWith(PREFIX)) {
    return stored;
  }
  const parts = stored.slice(PREFIX.length).split(":");
  if (parts.length !== 3) {
    return stored;
  }
  const [ivHex, authTagHex, ciphertextHex] = parts as [string, string, string];
  try {
    const key = deriveKey();
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const ciphertext = Buffer.from(ciphertextHex, "hex");
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return stored;
  }
}

/**
 * Decrypt a stored credential using an explicit secret rather than the
 * current SESSION_SECRET environment variable.  Used during key rotation to
 * read rows that were encrypted with the old key.
 *
 * Returns null when decryption fails (wrong key, corrupted data, or the value
 * is a legacy plaintext string that was never encrypted).
 */
export function decryptCredentialWithSecret(stored: string, oldSecret: string): string | null {
  if (!stored.startsWith(PREFIX)) {
    return stored;
  }
  const parts = stored.slice(PREFIX.length).split(":");
  if (parts.length !== 3) {
    return null;
  }
  const [ivHex, authTagHex, ciphertextHex] = parts as [string, string, string];
  try {
    const key = deriveKeyFromSecret(oldSecret);
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const ciphertext = Buffer.from(ciphertextHex, "hex");
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return null;
  }
}
