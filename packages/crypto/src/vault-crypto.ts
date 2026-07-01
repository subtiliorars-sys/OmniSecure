import { createCipheriv, createDecipheriv, createHash, pbkdf2Sync, randomBytes, generateKeyPairSync, privateDecrypt, publicEncrypt } from "node:crypto";
import type { EncryptedBlob, UserKeys } from "@omnisecure/core";
import { DEFAULT_KDF } from "@omnisecure/core";

const AES_ALGO = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export function toBase64(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

export function fromBase64(value: string): Buffer {
  return Buffer.from(value, "base64");
}

export function hashMasterPassword(password: string, email: string): string {
  return createHash("sha256")
    .update(`${password.toLowerCase()}${email.trim().toLowerCase()}`)
    .digest("hex");
}

export function stretchMasterKey(password: string, email: string, iterations = DEFAULT_KDF.iterations): Buffer {
  const salt = createHash("sha256")
    .update(email.trim().toLowerCase())
    .digest();
  return pbkdf2Sync(password, salt, iterations, 32, "sha256");
}

export function encryptBytes(key: Buffer, plaintext: Buffer): EncryptedBlob {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(AES_ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: toBase64(iv),
    data: toBase64(Buffer.concat([encrypted, authTag])),
  };
}

export function decryptBytes(key: Buffer, blob: EncryptedBlob): Buffer {
  const iv = fromBase64(blob.iv);
  const payload = fromBase64(blob.data);
  const ciphertext = payload.subarray(0, payload.length - AUTH_TAG_LENGTH);
  const authTag = payload.subarray(payload.length - AUTH_TAG_LENGTH);
  const decipher = createDecipheriv(AES_ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encryptString(key: Buffer, value: string): EncryptedBlob {
  return encryptBytes(key, Buffer.from(value, "utf8"));
}

export function decryptString(key: Buffer, blob: EncryptedBlob): string {
  return decryptBytes(key, blob).toString("utf8");
}

export function encryptJson<T>(key: Buffer, value: T): EncryptedBlob {
  return encryptString(key, JSON.stringify(value));
}

export function decryptJson<T>(key: Buffer, blob: EncryptedBlob): T {
  return JSON.parse(decryptString(key, blob)) as T;
}

export function generateUserKeys(password: string, email: string): {
  masterPasswordHash: string;
  stretchedMasterKey: Buffer;
  symmetricKey: Buffer;
  userKeys: UserKeys;
} {
  const masterPasswordHash = hashMasterPassword(password, email);
  const stretchedMasterKey = stretchMasterKey(password, email);
  const symmetricKey = randomBytes(32);

  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const userKeys: UserKeys = {
    stretchedMasterKey: toBase64(stretchedMasterKey),
    encryptedSymmetricKey: encryptBytes(stretchedMasterKey, symmetricKey),
    publicKey: toBase64(Buffer.from(publicKey, "utf8")),
    encryptedPrivateKey: encryptBytes(symmetricKey, Buffer.from(privateKey, "utf8")),
  };

  return { masterPasswordHash, stretchedMasterKey, symmetricKey, userKeys };
}

export function unlockSymmetricKey(password: string, email: string, userKeys: UserKeys): Buffer {
  const stretchedMasterKey = stretchMasterKey(password, email);
  const stored = fromBase64(userKeys.stretchedMasterKey);
  if (!stored.equals(stretchedMasterKey)) {
    throw new Error("Invalid master password");
  }
  return decryptBytes(stretchedMasterKey, userKeys.encryptedSymmetricKey);
}

export function createSendKey(): Buffer {
  return randomBytes(32);
}

export function wrapKeyForSend(sendKey: Buffer, payloadKey: Buffer): EncryptedBlob {
  return encryptBytes(sendKey, payloadKey);
}

export function rsaEncrypt(publicKeyPem: string, data: Buffer): Buffer {
  return publicEncrypt(
    { key: publicKeyPem, padding: 4 /* RSA_PKCS1_OAEP_PADDING */ },
    data,
  );
}

export function rsaDecrypt(privateKeyPem: string, data: Buffer): Buffer {
  return privateDecrypt(
    { key: privateKeyPem, padding: 4 },
    data,
  );
}

export function generateAccessToken(): string {
  return toBase64(randomBytes(32)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function generateTotpSecret(): string {
  return toBase64(randomBytes(20));
}

export function verifyTotp(_secret: string, _code: string): boolean {
  // Placeholder — production uses RFC 6238; integrate with OmniAuth patterns.
  return _code.length === 6 && /^\d+$/.test(_code);
}
