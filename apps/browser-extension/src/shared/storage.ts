export interface ExtensionSession {
  apiUrl: string;
  token: string;
  email: string;
  userKeys: {
    stretchedMasterKey: string;
    encryptedSymmetricKey: { iv: string; data: string };
    publicKey: string;
    encryptedPrivateKey: { iv: string; data: string };
  };
  unlockedKey?: string;
}

export interface DecryptedLogin {
  id: string;
  name: string;
  username?: string;
  password?: string;
  uris: string[];
}

export const DEFAULT_API = "http://localhost:8787";

export async function getSession(): Promise<ExtensionSession | null> {
  const { session } = await chrome.storage.local.get("session");
  return (session as ExtensionSession | undefined) ?? null;
}

export async function saveSession(session: ExtensionSession | null): Promise<void> {
  if (session) {
    await chrome.storage.local.set({ session });
  } else {
    await chrome.storage.local.remove("session");
  }
}

export async function api<T>(path: string, session: ExtensionSession, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${session.apiUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.token}`,
      ...(init.headers as Record<string, string> | undefined),
    },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message ?? "Request failed");
  return data as T;
}

export function hostnameMatches(uri: string, hostname: string): boolean {
  try {
    const parsed = new URL(uri.includes("://") ? uri : `https://${uri}`);
    const host = parsed.hostname.replace(/^www\./, "");
    const current = hostname.replace(/^www\./, "");
    return host === current || current.endsWith(`.${host}`) || host.endsWith(`.${current}`);
  } catch {
    return uri.toLowerCase().includes(hostname.toLowerCase());
  }
}

export function filterLoginsForHost(logins: DecryptedLogin[], hostname: string): DecryptedLogin[] {
  return logins.filter((login) => {
    if (!login.uris.length) return false;
    return login.uris.some((uri) => hostnameMatches(uri, hostname));
  });
}
