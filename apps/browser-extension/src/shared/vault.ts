import type { EncryptedCipher, SyncResponse } from "@omnisecure/core";
import { decryptJsonBrowser } from "@omnisecure/crypto/browser";
import type { DecryptedLogin, ExtensionSession } from "./storage.js";
import { api } from "./storage.js";

interface LoginData {
  username?: string;
  password?: string;
  uris?: string[];
}

export async function loadDecryptedLogins(session: ExtensionSession): Promise<DecryptedLogin[]> {
  if (!session.unlockedKey) return [];
  const key = Uint8Array.from(atob(session.unlockedKey), (c) => c.charCodeAt(0));
  const sync = await api<SyncResponse>("/api/vault/sync", session);
  const logins: DecryptedLogin[] = [];

  for (const cipher of sync.ciphers) {
    if (cipher.type !== "login") continue;
    try {
      const data = await decryptJsonBrowser<LoginData>(key, cipher.encryptedData);
      logins.push({
        id: cipher.id,
        name: cipher.name,
        username: data.username,
        password: data.password,
        uris: data.uris ?? [],
      });
    } catch {
      // skip undecryptable
    }
  }

  return logins;
}

export function encryptedCipherFromSync(c: EncryptedCipher): EncryptedCipher {
  return c;
}
