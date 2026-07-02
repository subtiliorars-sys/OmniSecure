import { createHash } from "node:crypto";

export function webauthnUserHandle(email: string): Uint8Array<ArrayBuffer> {
  const hash = createHash("sha256").update(email.trim().toLowerCase()).digest();
  return Uint8Array.from(hash.subarray(0, 32)) as Uint8Array<ArrayBuffer>;
}
