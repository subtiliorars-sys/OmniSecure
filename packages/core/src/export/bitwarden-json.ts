import type { Cipher, CipherType, Folder } from "../types.js";

export function exportBitwardenJson(ciphers: Cipher[], folders: Folder[]): string {
  const payload = {
    encrypted: false,
    folders: folders.map((folder) => ({ id: folder.id, name: folder.name })),
    items: ciphers.map((cipher) => mapCipherToJsonItem(cipher)),
  };
  return JSON.stringify(payload, null, 2);
}

function mapCipherToJsonItem(cipher: Cipher): Record<string, unknown> {
  const base: Record<string, unknown> = {
    id: cipher.id,
    organizationId: cipher.organizationId ?? null,
    folderId: cipher.folderId ?? null,
    type: mapTypeToBitwarden(cipher.type),
    name: cipher.name,
    notes: cipher.notes ?? null,
    favorite: Boolean(cipher.favorite),
    reprompt: Boolean(cipher.reprompt),
  };

  if (cipher.type === "login") {
    const data = cipher.data as { username?: string; password?: string; totp?: string; uris?: string[] };
    base.login = {
      username: data.username ?? null,
      password: data.password ?? null,
      totp: data.totp ?? null,
      uris: (data.uris ?? []).map((uri) => ({ uri, match: null })),
    };
  }

  if (cipher.type === "secureNote") {
    base.secureNote = { type: 0 };
  }

  return base;
}

function mapTypeToBitwarden(type: CipherType): number {
  switch (type) {
    case "login":
      return 1;
    case "secureNote":
      return 2;
    case "card":
      return 3;
    case "identity":
      return 4;
    case "sshKey":
      return 5;
    default:
      return 1;
  }
}
