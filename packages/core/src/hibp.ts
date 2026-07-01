/**
 * Have I Been Pwned k-anonymity password range check.
 * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
 */

export interface PwnedPasswordResult {
  exposed: boolean;
  count: number;
}

export async function sha1Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-1", data);
  return [...new Uint8Array(hash)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export async function checkPasswordPwned(
  password: string,
  fetchImpl: typeof fetch = fetch,
): Promise<PwnedPasswordResult> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" },
  });
  if (!response.ok) {
    throw new Error(`HIBP API error: ${response.status}`);
  }

  const body = await response.text();
  for (const line of body.split("\n")) {
    const [hashSuffix, countRaw] = line.trim().split(":");
    if (hashSuffix?.toUpperCase() === suffix) {
      const count = Number.parseInt(countRaw ?? "0", 10);
      return { exposed: true, count: Number.isFinite(count) ? count : 0 };
    }
  }

  return { exposed: false, count: 0 };
}

export async function checkPasswordsPwned(
  passwords: string[],
  options: { fetchImpl?: typeof fetch; delayMs?: number } = {},
): Promise<Map<string, PwnedPasswordResult>> {
  const unique = [...new Set(passwords.filter(Boolean))];
  const results = new Map<string, PwnedPasswordResult>();
  const delayMs = options.delayMs ?? 350;
  const fetchImpl = options.fetchImpl ?? fetch;

  for (const password of unique) {
    results.set(password, await checkPasswordPwned(password, fetchImpl));
    if (delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return results;
}
