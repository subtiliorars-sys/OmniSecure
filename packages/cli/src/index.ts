#!/usr/bin/env node
import { Command } from "commander";
import { generatePassphrase, generatePassword, generateUsername, scorePasswordStrength, parseBitwardenCsv, bitwardenRowsToCipherData, parseBitwardenJson, exportBitwardenCsv, exportBitwardenJson, checkPasswordPwned } from "@omnisecure/core";
import { encryptJson, unlockSymmetricKey, decryptJson } from "@omnisecure/crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CONFIG_DIR = join(homedir(), ".omnisecure");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");
const API_URL = process.env.OMNISECURE_API ?? "http://localhost:8787";

interface CliConfig {
  apiUrl: string;
  token?: string;
  email?: string;
  userKeys?: {
    stretchedMasterKey: string;
    encryptedSymmetricKey: { iv: string; data: string };
    publicKey: string;
    encryptedPrivateKey: { iv: string; data: string };
  };
}

function loadConfig(): CliConfig {
  if (!existsSync(CONFIG_FILE)) {
    return { apiUrl: API_URL };
  }
  return JSON.parse(readFileSync(CONFIG_FILE, "utf8")) as CliConfig;
}

function saveConfig(config: CliConfig): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

async function api(path: string, options: RequestInit = {}): Promise<Response> {
  const config = loadConfig();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  if (config.token) headers.Authorization = `Bearer ${config.token}`;
  return fetch(`${config.apiUrl}${path}`, { ...options, headers });
}

const program = new Command();
program
  .name("omsecure")
  .description("OmniSecure CLI — password manager, secrets, and secure sharing for OmniTender")
  .version("0.3.0");

program
  .command("register")
  .description("Create a new OmniSecure account")
  .requiredOption("-e, --email <email>")
  .requiredOption("-p, --password <password>")
  .option("-n, --name <name>")
  .action(async (opts: { email: string; password: string; name?: string }) => {
    const res = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email: opts.email, masterPassword: opts.password, name: opts.name }),
    });
    const data = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      console.error(String(data.message ?? "Registration failed"));
      process.exit(1);
    }
    saveConfig({
      apiUrl: API_URL,
      token: data.token as string,
      email: opts.email,
      userKeys: data.userKeys as CliConfig["userKeys"],
    });
    console.log("Account created. Session saved to ~/.omnisecure/config.json");
  });

program
  .command("login")
  .description("Log in to OmniSecure")
  .requiredOption("-e, --email <email>")
  .requiredOption("-p, --password <password>")
  .action(async (opts: { email: string; password: string }) => {
    const res = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: opts.email, masterPassword: opts.password }),
    });
    const data = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      console.error(String(data.message ?? "Login failed"));
      process.exit(1);
    }
    saveConfig({
      apiUrl: API_URL,
      token: data.token as string,
      email: opts.email,
      userKeys: data.userKeys as CliConfig["userKeys"],
    });
    console.log(`Logged in as ${opts.email}`);
  });

program
  .command("sync")
  .description("Sync vault from server")
  .action(async () => {
    const res = await api("/api/vault/sync");
    const data = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      console.error(String(data.message ?? "Sync failed"));
      process.exit(1);
    }
    console.log(JSON.stringify(data, null, 2));
  });

program
  .command("generate")
  .description("Generate a secure password")
  .option("-l, --length <n>", "password length", "20")
  .action((opts: { length: string }) => {
    console.log(generatePassword({ length: Number(opts.length) }));
  });

program
  .command("passphrase")
  .description("Generate a secure passphrase")
  .option("-w, --words <n>", "word count", "6")
  .action((opts: { words: string }) => {
    console.log(generatePassphrase(Number(opts.words)));
  });

program
  .command("username")
  .description("Generate a random username")
  .action(() => {
    console.log(generateUsername());
  });

program
  .command("strength")
  .description("Score password strength")
  .argument("<password>")
  .action((password: string) => {
    console.log(JSON.stringify(scorePasswordStrength(password), null, 2));
  });

program
  .command("secret-set")
  .description("Store an encrypted secret in a project")
  .requiredOption("-p, --project <projectId>")
  .requiredOption("-k, --key <key>")
  .requiredOption("--value <value>")
  .requiredOption("--master-password <password>")
  .action(async (opts: { project: string; key: string; value: string; masterPassword: string }) => {
    const config = loadConfig();
    if (!config.email || !config.userKeys) {
      console.error("Run omsecure login first");
      process.exit(1);
    }
    const symmetricKey = unlockSymmetricKey(opts.masterPassword, config.email, config.userKeys);
    const encryptedValue = encryptJson(symmetricKey, opts.value);
    const res = await api(`/api/secrets/projects/${opts.project}/secrets`, {
      method: "POST",
      body: JSON.stringify({ key: opts.key, encryptedValue }),
    });
    const data = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      console.error(String(data.message ?? "Failed to store secret"));
      process.exit(1);
    }
    console.log(`Secret stored: ${String(data.id)}`);
  });

program
  .command("import")
  .description("Import vault items from Bitwarden CSV or JSON export")
  .requiredOption("-f, --file <path>", "Path to Bitwarden export file")
  .requiredOption("--master-password <password>", "Master password to encrypt imported items")
  .option("--format <format>", "csv or json (auto-detected from extension when omitted)")
  .action(async (opts: { file: string; masterPassword: string; format?: string }) => {
    const config = loadConfig();
    if (!config.token || !config.email || !config.userKeys) {
      console.error("Run omsecure login first");
      process.exit(1);
    }
    const text = readFileSync(opts.file, "utf8");
    const format = opts.format ?? (opts.file.toLowerCase().endsWith(".json") ? "json" : "csv");
    const rows = format === "json" ? parseBitwardenJson(text) : parseBitwardenCsv(text);
    if (!rows.length) {
      console.error("No items found in export file");
      process.exit(1);
    }
    const symmetricKey = unlockSymmetricKey(opts.masterPassword, config.email, config.userKeys);
    const ciphers = rows.map((row) => ({
      type: row.type === "secureNote" ? "secureNote" : row.type,
      name: row.name,
      notes: row.notes,
      folderName: row.folder,
      favorite: row.favorite,
      reprompt: row.reprompt,
      encryptedData: encryptJson(symmetricKey, bitwardenRowsToCipherData(row)),
    }));
    const folders = [...new Set(rows.map((r) => r.folder).filter(Boolean))] as string[];
    const res = await api("/api/vault/import", {
      method: "POST",
      body: JSON.stringify({ folders, ciphers }),
    });
    const data = (await res.json()) as Record<string, unknown>;
    if (!res.ok) {
      console.error(String(data.message ?? "Import failed"));
      process.exit(1);
    }
    console.log(`Imported ${String(data.imported)} items (${String(data.foldersCreated)} folders)`);
  });

program
  .command("export")
  .description("Export decrypted vault to Bitwarden CSV or JSON (writes local file)")
  .requiredOption("-o, --output <path>", "Output file path")
  .requiredOption("--master-password <password>", "Master password to decrypt vault items")
  .option("--format <format>", "csv or json (auto-detected from extension when omitted)")
  .action(async (opts: { output: string; masterPassword: string; format?: string }) => {
    const config = loadConfig();
    if (!config.token || !config.email || !config.userKeys) {
      console.error("Run omsecure login first");
      process.exit(1);
    }
    const res = await api("/api/vault/sync");
    const sync = (await res.json()) as {
      folders: Array<{ id: string; name: string; createdAt: string; updatedAt: string }>;
      ciphers: Array<{
        id: string;
        type: string;
        name: string;
        notes?: string;
        folderId?: string | null;
        favorite?: boolean;
        reprompt?: boolean;
        encryptedData: { iv: string; data: string };
        createdAt: string;
        updatedAt: string;
      }>;
    };
    if (!res.ok) {
      console.error("Sync failed");
      process.exit(1);
    }
    const symmetricKey = unlockSymmetricKey(opts.masterPassword, config.email, config.userKeys);
    const ciphers = sync.ciphers.map((cipher) => ({
      id: cipher.id,
      type: cipher.type as "login",
      name: cipher.name,
      notes: cipher.notes,
      folderId: cipher.folderId,
      favorite: cipher.favorite,
      reprompt: cipher.reprompt,
      data: decryptJson(symmetricKey, cipher.encryptedData) as Record<string, unknown>,
      createdAt: cipher.createdAt,
      updatedAt: cipher.updatedAt,
    }));
    const format = opts.format ?? (opts.output.toLowerCase().endsWith(".json") ? "json" : "csv");
    const content = format === "json"
      ? exportBitwardenJson(ciphers, sync.folders)
      : exportBitwardenCsv(ciphers, sync.folders);
    writeFileSync(opts.output, content, "utf8");
    console.log(`Exported ${ciphers.length} items to ${opts.output}`);
  });

program
  .command("breach-check")
  .description("Check whether a password appears in known data breaches (HIBP k-anonymity)")
  .argument("<password>")
  .action(async (password: string) => {
    const result = await checkPasswordPwned(password);
    console.log(JSON.stringify(result, null, 2));
  });

program.parse();
