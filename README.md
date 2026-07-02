# OmniSecure

**OmniTender identity security suite** — an open-source, zero-knowledge password manager, secrets manager, and secure sharing platform inspired by [Bitwarden](https://bitwarden.com).

Built for the [OmniTender](https://github.com/subtiliorars-sys/OmniTender) ecosystem alongside [OmniAuth](https://github.com/subtiliorars-sys/OmniAuth) (TOTP authenticator).

## Products

| Product | Description | Bitwarden equivalent |
|---------|-------------|---------------------|
| **Password Manager** | Encrypted vault for logins, cards, identities, notes, SSH keys, passkeys | Bitwarden Password Manager |
| **Secrets Manager** | Projects, secrets, service accounts for dev/ops teams | Bitwarden Secrets Manager |
| **Send** | Encrypted text/file sharing via expiring links | Bitwarden Send |
| **Security Tools** | Password, passphrase, username generators; strength tester | Bitwarden free tools |
| **CLI** | `omsecure` — sync, generate, secrets automation | `bw` CLI |
| **Browser extension** | Autofill badge + popup | Bitwarden extension |

## Architecture

```
apps/browser-extension/ Chrome/Edge extension (autofill)
apps/vault-web/          Web vault (React + Vite)
apps/mobile/               Expo mobile app (iOS/Android)
packages/server         REST API (Fastify + SQLite/Postgres)
packages/crypto         Zero-knowledge crypto (Node + Web Crypto)
packages/core           Shared types, generators, health reports
packages/cli            omsecure command-line tool
docker/                 Self-host with Docker Compose
```

**Zero-knowledge model:** Master password never leaves the client. The server stores only encrypted blobs (ciphers, secrets, Send payloads). Key derivation uses PBKDF2-SHA256 (600k iterations).

## Quick start

### Prerequisites

- Node.js 20+
- [pnpm](https://pnpm.io) 9+

### Development

```bash
git clone https://github.com/subtiliorars-sys/OmniSecure.git
cd OmniSecure
pnpm install
pnpm build
pnpm dev
```

- API: http://localhost:8787
- Web vault: http://localhost:5173

### CLI

```bash
pnpm cli register -e you@example.com -p "your-master-password"
pnpm cli sync
pnpm cli generate
pnpm cli secret-set -p <projectId> -k API_KEY --value "sk-..." --master-password "..."
pnpm cli import -f bitwarden-export.csv --master-password "..."
pnpm build:extension   # → apps/browser-extension/dist (load unpacked in Chrome)
```

### Self-host (Docker)

```bash
cd docker
cp .env.example .env   # edit JWT_SECRET
docker compose up -d
```

See [docs/SELF-HOST.md](docs/SELF-HOST.md).

## Documentation

- [Bitwarden feature parity map](docs/BITWARDEN-PARITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Self-hosting guide](docs/SELF-HOST.md)
- [Deployment options](docs/DEPLOYMENT.md)
- [Fly.io + Cloudflare Pages](docs/DEPLOY-FLY-CLOUDFLARE.md) — Fly.io, Railway, Docker prod
- [OmniTender ecosystem](docs/OMNITENDER-ECOSYSTEM.md)

## Roadmap

**v0.1:** Core vault, sync, orgs, collections, Send, Secrets Manager API, CLI, web vault, self-host Docker.

**v0.2:** Browser extension, Bitwarden CSV import, ecosystem wiring.

**v0.3:** HIBP breach checks, Bitwarden JSON import/export, TOTP codes in vault, emergency access UI, SIEM audit export, Send receive page, Firefox extension manifest, CI.

**v0.4 (current):** Mobile app (Expo), SSO (OIDC/SAML), SCIM provisioning, WebAuthn passkeys, encrypted attachments, emergency vault-key handoff, deployment guides (Fly.io + prod Docker).

**v0.5:** Postgres driver, SAML signature validation, desktop app, Helm chart.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

## Related repos

- [OmniTender](https://github.com/subtiliorars-sys/OmniTender) — company brain
- [OmniAuth](https://github.com/subtiliorars-sys/OmniAuth) — TOTP authenticator
- [omnitender-web](https://github.com/subtiliorars-sys/omnitender-web) — public marketing site
