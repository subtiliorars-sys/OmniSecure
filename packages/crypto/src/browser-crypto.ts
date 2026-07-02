import type { EncryptedBlob, UserKeys } from "@omnisecure/core";
import { DEFAULT_KDF } from "@omnisecure/core";

const IV_LENGTH = 12;

function toBase64(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copy));
}

async function stretchMasterKey(password: string, email: string, iterations = DEFAULT_KDF.iterations): Promise<Uint8Array> {
  const salt = await sha256(new TextEncoder().encode(email.trim().toLowerCase()));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new Uint8Array(salt), iterations, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  return new Uint8Array(bits);
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", new Uint8Array(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptJsonBrowser<T>(key: Uint8Array, value: T): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await importAesKey(key);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext));
  return { iv: toBase64(iv), data: toBase64(encrypted) };
}

export async function decryptJsonBrowser<T>(key: Uint8Array, blob: EncryptedBlob): Promise<T> {
  const iv = fromBase64(blob.iv);
  const data = fromBase64(blob.data);
  const aesKey = await importAesKey(key);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv) }, aesKey, new Uint8Array(data));
  return JSON.parse(new TextDecoder().decode(decrypted)) as T;
}

export async function unlockSymmetricKeyBrowser(
  password: string,
  email: string,
  userKeys: UserKeys,
): Promise<Uint8Array> {
  const stretched = await stretchMasterKey(password, email);
  const stored = fromBase64(userKeys.stretchedMasterKey);
  if (stored.length !== stretched.length || !stored.every((b, i) => b === stretched[i]!)) {
    throw new Error("Invalid master password");
  }
  const symmetric = await decryptBytesBrowser(stretched, userKeys.encryptedSymmetricKey);
  return symmetric;
}

export async function encryptBytesBrowser(key: Uint8Array, bytes: Uint8Array): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const aesKey = await importAesKey(key);
  const payload = Uint8Array.from(bytes);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: Uint8Array.from(iv) }, aesKey, payload));
  return { iv: toBase64(iv), data: toBase64(encrypted) };
}

export async function decryptBytesBrowser(key: Uint8Array, blob: EncryptedBlob): Promise<Uint8Array> {
  const iv = fromBase64(blob.iv);
  const data = fromBase64(blob.data);
  const aesKey = await importAesKey(key);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    aesKey,
    new Uint8Array(data),
  );
  return new Uint8Array(decrypted);
}

export function randomKeyBrowser(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}
