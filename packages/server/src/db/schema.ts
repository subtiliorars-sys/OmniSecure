import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export function createDatabase(path: string): Database.Database {
  mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);
  return db;
}

function migrate(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT,
      master_password_hash TEXT NOT NULL,
      encrypted_symmetric_key_iv TEXT NOT NULL,
      encrypted_symmetric_key_data TEXT NOT NULL,
      stretched_master_key TEXT NOT NULL,
      public_key TEXT NOT NULL,
      encrypted_private_key_iv TEXT NOT NULL,
      encrypted_private_key_data TEXT NOT NULL,
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      premium INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ciphers (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      organization_id TEXT,
      type TEXT NOT NULL,
      name TEXT NOT NULL,
      notes TEXT,
      folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
      favorite INTEGER NOT NULL DEFAULT 0,
      reprompt INTEGER NOT NULL DEFAULT 0,
      encrypted_data_iv TEXT NOT NULL,
      encrypted_data_data TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cipher_collections (
      cipher_id TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
      collection_id TEXT NOT NULL,
      PRIMARY KEY (cipher_id, collection_id)
    );

    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      identifier TEXT NOT NULL UNIQUE,
      plan TEXT NOT NULL DEFAULT 'free',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS organization_users (
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'confirmed',
      PRIMARY KEY (organization_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS collections (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      external_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sends (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      access_id TEXT NOT NULL UNIQUE,
      name TEXT,
      type TEXT NOT NULL,
      max_access_count INTEGER,
      access_count INTEGER NOT NULL DEFAULT 0,
      expiration_date TEXT,
      password_hash TEXT,
      disabled INTEGER NOT NULL DEFAULT 0,
      encrypted_payload_iv TEXT NOT NULL,
      encrypted_payload_data TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secret_projects (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secrets (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES secret_projects(id) ON DELETE CASCADE,
      key_name TEXT NOT NULL,
      note TEXT,
      encrypted_value_iv TEXT NOT NULL,
      encrypted_value_data TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS service_accounts (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_hint TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS emergency_access (
      id TEXT PRIMARY KEY,
      grantor_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      grantee_email TEXT NOT NULL,
      wait_days INTEGER NOT NULL DEFAULT 7,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      organization_id TEXT,
      user_id TEXT,
      event_type TEXT NOT NULL,
      metadata TEXT,
      created_at TEXT NOT NULL
    );
  `);
}

export type AppDatabase = Database.Database;
