import type { Cipher, CipherType, Folder, LoginCipherData } from "../types.js";

const CSV_HEADERS = [
  "folder",
  "favorite",
  "type",
  "name",
  "notes",
  "fields",
  "reprompt",
  "login_uri",
  "login_username",
  "login_password",
  "login_totp",
] as const;

export function exportBitwardenCsv(
  ciphers: Cipher[],
  folders: Folder[],
): string {
  const folderNames = new Map(folders.map((folder) => [folder.id, folder.name]));
  const rows = [CSV_HEADERS.join(",")];

  for (const cipher of ciphers) {
    rows.push(buildCsvRow(cipher, folderNames.get(cipher.folderId ?? "") ?? ""));
  }

  return rows.join("\n");
}

function buildCsvRow(cipher: Cipher, folderName: string): string {
  const login = cipher.type === "login" ? (cipher.data as LoginCipherData) : undefined;
  const values = [
    folderName,
    cipher.favorite ? "1" : "0",
    mapTypeToBitwarden(cipher.type),
    cipher.name,
    cipher.notes ?? "",
    "",
    cipher.reprompt ? "1" : "0",
    (login?.uris ?? []).join("\n"),
    login?.username ?? "",
    login?.password ?? "",
    login?.totp ?? "",
  ];
  return values.map(escapeCsv).join(",");
}

function mapTypeToBitwarden(type: CipherType): string {
  switch (type) {
    case "login":
      return "login";
    case "secureNote":
      return "secureNote";
    case "card":
      return "card";
    case "identity":
      return "identity";
    case "sshKey":
      return "sshKey";
    default:
      return "login";
  }
}

function escapeCsv(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
