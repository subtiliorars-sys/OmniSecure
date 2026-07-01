export function encodeSendKey(key: Uint8Array): string {
  return btoa(String.fromCharCode(...key))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function decodeSendKey(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const mod = padded.length % 4;
  const base64 = mod ? padded + "=".repeat(4 - mod) : padded;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function readSendKeyFromLocation(location: Location): Uint8Array | null {
  const hash = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
  if (!hash) return null;
  const params = new URLSearchParams(hash);
  const encoded = params.get("k");
  return encoded ? decodeSendKey(encoded) : null;
}

export async function hashSendPassword(password: string, accessId: string): Promise<string> {
  const text = `${password.toLowerCase()}${accessId}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function sendKeyFromPassword(password: string, accessId: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${password.toLowerCase()}${accessId}:send`),
  );
  return new Uint8Array(digest);
}
