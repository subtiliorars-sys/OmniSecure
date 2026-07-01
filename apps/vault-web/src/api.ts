const API = import.meta.env.VITE_API_URL ?? "";

export interface Session {
  token: string;
  email: string;
  userKeys: {
    stretchedMasterKey: string;
    encryptedSymmetricKey: { iv: string; data: string };
    publicKey: string;
    encryptedPrivateKey: { iv: string; data: string };
  };
}

export async function api<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API}${path}`, { ...options, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message ?? "Request failed");
  return data as T;
}

export function saveSession(session: Session): void {
  localStorage.setItem("omnisecure_session", JSON.stringify(session));
}

export function loadSession(): Session | null {
  const raw = localStorage.getItem("omnisecure_session");
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem("omnisecure_session");
}
