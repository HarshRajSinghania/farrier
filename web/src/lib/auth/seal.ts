/**
 * Encrypted, authenticated cookie values: a JWE (dir + A256GCM) whose key is derived with
 * HKDF-SHA256 from FARRIER_SESSION_SECRET and a purpose label, so a value sealed for one
 * purpose (the login transaction) never opens as another (the session).
 *
 * AES-GCM authenticates as well as encrypts: any change to the cookie fails to open.
 * Imports only `jose` so it runs under `node --test`.
 */
import { EncryptJWT, jwtDecrypt } from "jose";

export const MIN_SECRET_BYTES = 32;

const keys = new Map<string, Promise<Uint8Array>>();

function deriveKey(secret: string, purpose: string): Promise<Uint8Array> {
  const id = `${purpose}\u0000${secret}`;
  let key = keys.get(id);
  if (!key) {
    const enc = new TextEncoder();
    key = crypto.subtle
      .importKey("raw", enc.encode(secret), "HKDF", false, ["deriveBits"])
      .then((base) =>
        crypto.subtle.deriveBits(
          { name: "HKDF", hash: "SHA-256", salt: enc.encode("farrier-dashboard"), info: enc.encode(purpose) },
          base,
          256,
        ),
      )
      .then((bits) => new Uint8Array(bits));
    if (keys.size > 16) keys.clear();
    keys.set(id, key);
  }
  return key;
}

export function secretProblem(secret: string | undefined): string | null {
  if (!secret) return "FARRIER_SESSION_SECRET is not set";
  if (new TextEncoder().encode(secret).length < MIN_SECRET_BYTES)
    return `FARRIER_SESSION_SECRET must be at least ${MIN_SECRET_BYTES} bytes (try: openssl rand -base64 48)`;
  return null;
}

/** Seal `payload` until `expiresAt` (unix seconds). */
export async function seal(
  payload: Record<string, unknown>,
  secret: string,
  purpose: string,
  expiresAt: number,
): Promise<string> {
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: purpose })
    .setIssuedAt()
    .setExpirationTime(expiresAt)
    .encrypt(await deriveKey(secret, purpose));
}

/** The payload, or null when the value is missing, tampered with, expired or sealed for another purpose. */
export async function unseal<T extends Record<string, unknown>>(
  token: string | undefined | null,
  secret: string,
  purpose: string,
): Promise<(T & { exp: number; iat: number }) | null> {
  if (!token || token.length > 8192) return null;
  try {
    const { payload, protectedHeader } = await jwtDecrypt(token, await deriveKey(secret, purpose), {
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
    });
    if (protectedHeader.typ !== purpose) return null;
    return payload as T & { exp: number; iat: number };
  } catch {
    return null;
  }
}
