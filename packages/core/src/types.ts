export type CipherType =
  | "login"
  | "secureNote"
  | "card"
  | "identity"
  | "sshKey"
  | "passkey";

export type TwoFactorMethod = "authenticator" | "email" | "webauthn" | "recovery";

export interface EncryptedBlob {
  iv: string;
  data: string;
}

export interface UserKeys {
  /** Base64-encoded stretched master key (never sent to server). */
  stretchedMasterKey: string;
  /** Base64-encoded symmetric vault key, encrypted with master key. */
  encryptedSymmetricKey: EncryptedBlob;
  /** Base64-encoded public key for org sharing. */
  publicKey: string;
  /** Base64-encoded private key, encrypted with symmetric key. */
  encryptedPrivateKey: EncryptedBlob;
}

export interface LoginCipherData {
  username?: string;
  password?: string;
  uris?: string[];
  totp?: string;
  passkeyCredentialId?: string;
}

export interface CardCipherData {
  cardholderName?: string;
  brand?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  code?: string;
}

export interface IdentityCipherData {
  title?: string;
  firstName?: string;
  middleName?: string;
  lastName?: string;
  company?: string;
  email?: string;
  phone?: string;
  address1?: string;
  address2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  ssn?: string;
  passportNumber?: string;
  licenseNumber?: string;
}

export interface SecureNoteCipherData {
  type?: string;
  notes?: string;
}

export interface SshKeyCipherData {
  privateKey?: string;
  publicKey?: string;
  fingerprint?: string;
}

export type CipherData =
  | LoginCipherData
  | CardCipherData
  | IdentityCipherData
  | SecureNoteCipherData
  | SshKeyCipherData
  | Record<string, unknown>;

export interface Cipher {
  id: string;
  type: CipherType;
  name: string;
  notes?: string;
  folderId?: string | null;
  organizationId?: string | null;
  collectionIds?: string[];
  favorite?: boolean;
  reprompt?: boolean;
  data: CipherData;
  createdAt: string;
  updatedAt: string;
}

export interface Folder {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedCipher {
  id: string;
  type: CipherType;
  name: string;
  notes?: string;
  folderId?: string | null;
  organizationId?: string | null;
  collectionIds?: string[];
  favorite?: boolean;
  reprompt?: boolean;
  /** AES-GCM encrypted JSON of CipherData */
  encryptedData: EncryptedBlob;
  createdAt: string;
  updatedAt: string;
}

export interface Organization {
  id: string;
  name: string;
  identifier: string;
  plan: "free" | "teams" | "enterprise";
  createdAt: string;
}

export interface Collection {
  id: string;
  organizationId: string;
  name: string;
  externalId?: string;
  createdAt: string;
}

export interface SendLink {
  id: string;
  accessId: string;
  name?: string;
  type: "text" | "file";
  maxAccessCount?: number;
  accessCount: number;
  expirationDate?: string;
  passwordProtected: boolean;
  disabled: boolean;
  /** Encrypted payload — server never sees plaintext */
  encryptedPayload: EncryptedBlob;
  createdAt: string;
}

export interface SecretProject {
  id: string;
  organizationId: string;
  name: string;
  createdAt: string;
}

export interface Secret {
  id: string;
  projectId: string;
  key: string;
  note?: string;
  /** Encrypted value */
  encryptedValue: EncryptedBlob;
  createdAt: string;
  updatedAt: string;
}

export interface ServiceAccount {
  id: string;
  organizationId: string;
  name: string;
  accessTokenHint: string;
  createdAt: string;
}

export interface VaultHealthReport {
  weakPasswords: number;
  reusedPasswords: number;
  exposedPasswords: number;
  unsecureWebsites: number;
  items: Array<{
    cipherId: string;
    name: string;
    issues: string[];
  }>;
}

export interface SyncResponse {
  profile: {
    id: string;
    email: string;
    name?: string;
    premium: boolean;
  };
  folders: Folder[];
  ciphers: EncryptedCipher[];
  collections: Collection[];
  organizations: Organization[];
  sends: SendLink[];
  syncTimestamp: string;
}

export interface ApiError {
  code: string;
  message: string;
}

export const DEFAULT_KDF = {
  iterations: 600_000,
  algorithm: "PBKDF2-SHA256" as const,
};

export const GENERATOR_DEFAULTS = {
  passwordLength: 20,
  passphraseWords: 6,
  usernameLength: 12,
};
