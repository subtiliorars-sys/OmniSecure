import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";

const API_URL = Constants.expoConfig?.extra?.apiUrl ?? "http://localhost:8787";

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

export async function saveSession(session: Session): Promise<void> {
  await SecureStore.setItemAsync("omnisecure_session", JSON.stringify(session));
}

export async function loadSession(): Promise<Session | null> {
  const raw = await SecureStore.getItemAsync("omnisecure_session");
  return raw ? JSON.parse(raw) as Session : null;
}

export async function clearSession(): Promise<void> {
  await SecureStore.deleteItemAsync("omnisecure_session");
}

export async function api<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_URL}${path}`, { ...options, headers });
  const data = await response.json() as T & { message?: string };
  if (!response.ok) throw new Error(String((data as { message?: string }).message ?? "Request failed"));
  return data;
}
