# Bitwarden → OmniSecure Feature Parity

This document maps [Bitwarden products and features](https://bitwarden.com/tools-and-features/) to OmniSecure implementation status.

**Legend:** ✅ Implemented · 🚧 Partial · 📋 Planned

## Password Manager (Personal & Business)

| Bitwarden feature | OmniSecure | Status |
|-------------------|------------|--------|
| Zero-knowledge encryption | `@omnisecure/crypto` PBKDF2 + AES-256-GCM | ✅ |
| Unlimited devices / sync | `/api/vault/sync` | ✅ |
| Login, card, identity, secure note item types | Cipher types in core + vault API | ✅ |
| SSH key storage | `sshKey` cipher type | ✅ |
| Passkey management | `passkey` cipher type | 📋 |
| Folders | `/api/vault/folders` | ✅ |
| Favorites, reprompt | Cipher fields | ✅ |
| Password / passphrase / username generators | `@omnisecure/core` + `/api/tools/*` | ✅ |
| Password strength tester | `/api/tools/password-strength` | ✅ |
| Vault health reports (weak/reused) | `analyzeVaultHealth()` + web UI | ✅ |
| Data breach reports (HIBP) | — | 📋 |
| Integrated TOTP authenticator | Use [OmniAuth](https://github.com/subtiliorars-sys/OmniAuth) | 🚧 |
| Encrypted file attachments | — | 📋 |
| Emergency access | `/api/emergency-access` | 🚧 |
| Import / export | — | 📋 |
| Biometric unlock | — | 📋 |
| Offline cache | Web localStorage session | 🚧 |
| Browser extension autofill | — | 📋 |
| Mobile apps (iOS/Android) | — | 📋 |
| Desktop app | Web vault + CLI | 🚧 |
| Phishing protection | — | 📋 |

## Bitwarden Send

| Feature | OmniSecure | Status |
|---------|------------|--------|
| Encrypted text sharing | `/api/send` | ✅ |
| Expiration / max access | DB fields + validation | ✅ |
| Password-protected Send | password hash on link | ✅ |
| File Send | `type: file` supported | 🚧 |

## Secrets Manager

| Feature | OmniSecure | Status |
|---------|------------|--------|
| Projects | `/api/secrets/organizations/:id/projects` | ✅ |
| Secrets (encrypted KV) | `/api/secrets/projects/:id/secrets` | ✅ |
| Service accounts + API tokens | `/api/secrets/organizations/:id/service-accounts` | ✅ |
| Secret versioning | — | 📋 |
| Access policies (granular) | Org roles (owner/admin/user) | 🚧 |
| CI/CD integrations | CLI `secret-set` | 🚧 |
| Self-host | Docker Compose | ✅ |

## Business / Enterprise

| Feature | OmniSecure | Status |
|---------|------------|--------|
| Organizations | `/api/organizations` | ✅ |
| Collections (shared items) | DB + cipher_collections | ✅ |
| RBAC (owner/admin/user) | organization_users.role | ✅ |
| Audit event logs | `/api/organizations/:id/events` | ✅ |
| SSO (SAML/OIDC) | — | 📋 |
| SCIM provisioning | — | 📋 |
| Directory sync (LDAP) | — | 📋 |
| Enterprise policies | — | 📋 |
| Account recovery (admin) | — | 📋 |
| Access Intelligence | Vault health as foundation | 📋 |
| SIEM integration | Audit events export | 📋 |
| Self-host / private cloud | Docker | ✅ |
| Domain claim verification | — | 📋 |

## Free public tools (no account)

Bitwarden hosts standalone generators at bitwarden.com/tools. OmniSecure exposes the same via API:

- `GET /tools/password`
- `GET /tools/passphrase`
- `GET /tools/username`
- `POST /tools/password-strength`

## Why build OmniSecure?

OmniTender handles merchant payments and operations. Staff, partners, and developers need **credential isolation** that stays inside the OmniTender ecosystem:

1. **OmniSecure** — vaults, org sharing, dev secrets
2. **OmniAuth** — 2FA for staff consoles
3. **Self-host option** — full data sovereignty for compliance

Bitwarden remains the gold standard we emulate; OmniSecure is our AGPL-licensed, ecosystem-native implementation.
