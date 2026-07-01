/**
 * Parse Bitwarden unencrypted CSV export into vault items.
 * @see https://bitwarden.com/help/export-your-data/
 */
import type { CipherType, LoginCipherData } from "../types.js";

export interface BitwardenCsvRow {
  folder?: string;
  favorite?: boolean;
  type: CipherType | "note" | "identity";
  name: string;
  notes?: string;
  reprompt?: boolean;
  login?: LoginCipherData;
  raw: Record<string, string>;
}

const HEADER_ALIASES: Record<string, string> = {
  folder: "folder",
  favorite: "favorite",
  type: "type",
  name: "name",
  notes: "notes",
  fields: "fields",
  reprompt: "reprompt",
  login_uri: "login_uri",
  login_username: "login_username",
  login_password: "login_password",
  login_totp: "login_totp",
};

export function parseBitwardenCsv(csvText: string): BitwardenCsvRow[] {
  const rows = parseCsvRows(csvText.trim());
  if (rows.length === 0) return [];

  const header = rows[0]!.map(normalizeHeader);
  const dataRows = rows.slice(1);
  const results: BitwardenCsvRow[] = [];

  for (const cells of dataRows) {
    if (cells.every((c) => !c.trim())) continue;
    const raw: Record<string, string> = {};
    for (let i = 0; i < header.length; i++) {
      const key = header[i]!;
      raw[key] = cells[i] ?? "";
    }

    const typeRaw = (raw.type ?? "login").toLowerCase();
    const type = mapBitwardenType(typeRaw);
    const uris = (raw.login_uri ?? "")
      .split(/\r?\n/)
      .map((u) => u.trim())
      .filter(Boolean);

    const row: BitwardenCsvRow = {
      folder: raw.folder?.trim() || undefined,
      favorite: raw.favorite === "1" || raw.favorite?.toLowerCase() === "true",
      type,
      name: raw.name?.trim() || "Untitled",
      notes: raw.notes?.trim() || undefined,
      reprompt: raw.reprompt === "1" || raw.reprompt?.toLowerCase() === "true",
      raw,
    };

    if (type === "login") {
      row.login = {
        username: raw.login_username?.trim() || undefined,
        password: raw.login_password || undefined,
        uris,
        totp: raw.login_totp?.trim() || undefined,
      };
    }

    results.push(row);
  }

  return results;
}

function mapBitwardenType(value: string): BitwardenCsvRow["type"] {
  switch (value) {
    case "login":
      return "login";
    case "securenote":
    case "note":
      return "secureNote";
    case "card":
      return "card";
    case "identity":
      return "identity";
    case "sshkey":
    case "ssh":
      return "sshKey";
    default:
      return "login";
  }
}

function normalizeHeader(value: string): string {
  const key = value.trim().toLowerCase().replace(/\s+/g, "_");
  return HEADER_ALIASES[key] ?? key;
}

/** RFC-style CSV parser with quoted fields. */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    const next = text[i + 1];

    if (inQuotes) {
      if (char === '"' && next === '"') {
        field += '"';
        i++;
      } else if (char === '"') {
        inQuotes = false;
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else if (char === "\r") {
      // skip
    } else {
      field += char;
    }
  }

  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

export function bitwardenRowsToCipherData(row: BitwardenCsvRow): Record<string, unknown> {
  if (row.type === "login" && row.login) {
    return row.login as Record<string, unknown>;
  }
  if (row.type === "secureNote") {
    return { type: "secureNote", notes: row.notes ?? "" };
  }
  return { notes: row.notes ?? "" };
}
