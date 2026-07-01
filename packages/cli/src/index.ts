#!/usr/bin/env node
import { Command } from "commander";
import { generatePassphrase, generatePassword, generateUsername, scorePasswordStrength, parseBitwardenCsv, bitwardenRowsToCipherData } from "@omnisecure/core";
import { encryptJson, unlockSymmetricKey } from "@omnisecure/crypto";
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
  .version("0.1.0");

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
  .description("Import vault items from Bitwarden CSV export")
  .requiredOption("-f, --file <path>", "Path to Bitwarden export CSV")
  .requiredOption("--master-password <password>", "Master password to encrypt imported items")
  .action(async (opts: { file: string; masterPassword: string }) => {
    const config = loadConfig();
    if (!config.token || !config.email || !config.userKeys) {
      console.error("Run omsecure login first");
      process.exit(1);
    }
    const csv = readFileSync(opts.file, "utf8");
    const rows = parseBitwardenCsv(csv);
    if (!rows.length) {
      console.error("No items found in CSV");
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

program.parse();
