/**
 * RFC 6238 TOTP — compatible with Bitwarden / Google Authenticator secrets.
 */

export interface TotpOptions {
  period?: number;
  digits?: number;
  algorithm?: "SHA1" | "SHA256" | "SHA512";
  timestamp?: number;
}

export async function generateTotp(secret: string, options: TotpOptions = {}): Promise<string> {
  const period = options.period ?? 30;
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? "SHA1";
  const counter = Math.floor((options.timestamp ?? Date.now()) / 1000 / period);
  return generateHotp(secret, counter, { digits, algorithm });
}

export async function generateHotp(
  secret: string,
  counter: number,
  options: Pick<TotpOptions, "digits" | "algorithm"> = {},
): Promise<string> {
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? "SHA1";
  const key = decodeBase32(normalizeTotpSecret(secret));
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(4, counter >>> 0, false);

  const hmac = await hmacDigest(algorithm, key, new Uint8Array(buffer));
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  return String(code % 10 ** digits).padStart(digits, "0");
}

export function parseOtpAuthSecret(uri: string): string | null {
  try {
    const url = new URL(uri);
    if (url.protocol !== "otpauth:") return null;
    return decodeURIComponent(url.searchParams.get("secret") ?? "") || null;
  } catch {
    return null;
  }
}

export function normalizeTotpSecret(secret: string): string {
  const trimmed = secret.trim();
  const fromUri = parseOtpAuthSecret(trimmed);
  return (fromUri ?? trimmed).replace(/\s+/g, "").toUpperCase();
}

async function hmacDigest(
  algorithm: "SHA1" | "SHA256" | "SHA512",
  key: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const hash = algorithm === "SHA256" ? "SHA-256" : algorithm === "SHA512" ? "SHA-512" : "SHA-1";
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(key),
    { name: "HMAC", hash },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, new Uint8Array(message));
  return new Uint8Array(signature);
}

function decodeBase32(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.replace(/=+$/g, "").replace(/\s+/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of cleaned) {
    const index = alphabet.indexOf(char);
    if (index === -1) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}
