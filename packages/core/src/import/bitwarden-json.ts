/**
 * Parse Bitwarden unencrypted JSON export.
 * @see https://bitwarden.com/help/export-your-data/
 */
import type { BitwardenCsvRow } from "./bitwarden-csv.js";
import { bitwardenRowsToCipherData } from "./bitwarden-csv.js";

export { bitwardenRowsToCipherData };

export interface BitwardenJsonExport {
  encrypted?: boolean;
  folders?: Array<{ id?: string; name: string }>;
  items: BitwardenJsonItem[];
}

export interface BitwardenJsonItem {
  id?: string;
  organizationId?: string | null;
  folderId?: string | null;
  type: number;
  name: string;
  notes?: string | null;
  favorite?: boolean;
  reprompt?: boolean;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: Array<{ uri?: string; match?: number | null } | string>;
  };
  secureNote?: { type?: number };
  card?: Record<string, string | null | undefined>;
  identity?: Record<string, string | null | undefined>;
  sshKey?: Record<string, string | null | undefined>;
}

export function parseBitwardenJson(jsonText: string): BitwardenCsvRow[] {
  const parsed = JSON.parse(jsonText) as BitwardenJsonExport;
  if (parsed.encrypted) {
    throw new Error("Encrypted Bitwarden JSON exports are not supported — export unencrypted JSON or CSV");
  }
  if (!Array.isArray(parsed.items)) {
    throw new Error("Invalid Bitwarden JSON: missing items array");
  }

  const folderById = new Map<string, string>();
  for (const folder of parsed.folders ?? []) {
    if (folder.id) folderById.set(folder.id, folder.name);
  }

  return parsed.items.map((item) => mapJsonItem(item, folderById));
}

function mapJsonItem(
  item: BitwardenJsonItem,
  folderById: Map<string, string>,
): BitwardenCsvRow {
  const type = mapJsonType(item.type);
  const uris = (item.login?.uris ?? [])
    .map((entry) => (typeof entry === "string" ? entry : entry.uri ?? ""))
    .map((uri) => uri.trim())
    .filter(Boolean);

  const row: BitwardenCsvRow = {
    type,
    name: item.name?.trim() || "Untitled",
    notes: item.notes?.trim() || undefined,
    favorite: Boolean(item.favorite),
    reprompt: Boolean(item.reprompt),
    folder: item.folderId ? folderById.get(item.folderId) : undefined,
    raw: {},
  };

  if (type === "login") {
    row.login = {
      username: item.login?.username?.trim() || undefined,
      password: item.login?.password || undefined,
      totp: item.login?.totp?.trim() || undefined,
      uris,
    };
  }

  return row;
}

function mapJsonType(value: number): BitwardenCsvRow["type"] {
  switch (value) {
    case 1:
      return "login";
    case 2:
      return "secureNote";
    case 3:
      return "card";
    case 4:
      return "identity";
    case 5:
      return "sshKey";
    default:
      return "login";
  }
}

export function bitwardenJsonFolderNames(jsonText: string): string[] {
  const parsed = JSON.parse(jsonText) as BitwardenJsonExport;
  return (parsed.folders ?? []).map((folder) => folder.name).filter(Boolean);
}
