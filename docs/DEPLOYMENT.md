# OmniSecure deployment options

OmniSecure can run anywhere Node.js 20+ and SQLite (or future Postgres) are available. Pick the tier that matches your compliance and scale needs.

## Quick comparison

| Option | Best for | Components | Est. cost |
|--------|----------|------------|-----------|
| **Docker Compose (Lite)** | Solo / small team self-host | API + nginx web + SQLite volume | VPS ~$5–20/mo |
| **Docker Compose (Prod)** | Small org production | API + web + Postgres + TLS reverse proxy | VPS ~$20–50/mo |
| **Fly.io** | Managed edge deploy, low ops | API machine + static web | ~$0–15/mo hobby |
| **Railway / Render** | Git-push deploy | Dockerfile or Node service | Usage-based |
| **Kubernetes** | Large org, HA | Helm chart (roadmap) | Cluster cost |

---

## 1. Docker Compose (recommended self-host)

```bash
cd docker
cp .env.example .env
# Set JWT_SECRET, WEBAUTHN_* , OMNISECURE_PUBLIC_URL
docker compose up -d
```

- Web vault: http://localhost:8080  
- API: http://localhost:8787  

See [SELF-HOST.md](./SELF-HOST.md) for backup and upgrade steps.

### Production compose (Postgres-ready)

```bash
docker compose -f docker-compose.prod.yml up -d
```

Uses `docker-compose.prod.yml` with optional Postgres service and attachment volume.

---

## 2. Fly.io + Cloudflare Pages (recommended production)

**Split stack:** API on Fly.io, vault web on Cloudflare Pages (use an existing Pages project until you assign a permanent domain).

See **[DEPLOY-FLY-CLOUDFLARE.md](./DEPLOY-FLY-CLOUDFLARE.md)** for step-by-step setup, secrets, and GitHub Actions.

Quick API deploy:

```bash
fly deploy --config fly.toml
curl https://omnisecure-api.fly.dev/health
```

---

## 3. Fly.io only

1. Install [flyctl](https://fly.io/docs/hands-on/install-flyctl/)
2. From repo root:

```bash
fly launch --config fly.toml --no-deploy
fly secrets set JWT_SECRET=$(openssl rand -hex 32)
fly secrets set WEBAUTHN_RP_ID=your-domain.com
fly secrets set WEBAUTHN_ORIGIN=https://vault.your-domain.com
fly deploy
```

Deploy static web separately (Cloudflare Pages, Fly Machines + nginx, or GitHub Pages pointing API URL at Fly app).

`fly.toml` in repo root targets the API Dockerfile.

---

## 4. Railway / Render

**Railway**

1. New project → Deploy from GitHub → `OmniSecure`
2. Service root: `docker/Dockerfile.api` context `..`
3. Env: `JWT_SECRET`, `OMNISECURE_PUBLIC_URL`, `WEBAUTHN_*`
4. Add volume mount at `/data` for SQLite

**Render**

1. New Web Service → Docker → `docker/Dockerfile.api`
2. Disk mount: `/data`
3. Static site service for `apps/vault-web/dist` after `pnpm build`

---

## 4. GitHub Pages + hosted API

Pattern used by **omnitender-web**:

- Marketing / vault static assets on GitHub Pages
- API on Fly.io, Railway, or private VPS
- Set `VITE_API_URL` at build time for vault-web

```bash
VITE_API_URL=https://api.omni-tender.com pnpm --filter @omnisecure/vault-web build
```

---

## 5. Environment variables (production)

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Session signing secret |
| `OMNISECURE_DB` | No | SQLite path (default `./data/omnisecure.db`) |
| `OMNISECURE_PUBLIC_URL` | Prod | Web vault origin (SSO redirects) |
| `OMNISECURE_API_URL` | Prod | Public API URL |
| `WEBAUTHN_RP_ID` | Passkeys | Registrable domain (no scheme) |
| `WEBAUTHN_ORIGIN` | Passkeys | Full web origin |
| `WEBAUTHN_RP_NAME` | No | Display name |
| `ATTACHMENT_MAX_BYTES` | No | Default 5 MB |

---

## 6. Mobile app (Expo)

```bash
cd apps/mobile
pnpm install
pnpm start
```

Configure `app.json` → `extra.apiUrl` to your production API. Build with EAS for App Store / Play Store distribution.

---

## 7. Enterprise checklist

- [ ] TLS termination (Caddy, nginx, Cloudflare)
- [ ] Strong `JWT_SECRET` in secrets manager
- [ ] WebAuthn RP ID matches production domain
- [ ] SSO IdP configured per org (`PUT /api/organizations/:orgId/idp`)
- [ ] SCIM token issued for directory sync (`POST /api/organizations/:orgId/scim-tokens`)
- [ ] Audit log export to SIEM (`GET /api/organizations/:orgId/events/export`)
- [ ] SQLite or Postgres backup schedule
- [ ] Dependabot / `pnpm audit` in CI

---

## Related

- [SELF-HOST.md](./SELF-HOST.md) — Lite Docker stack
- [ARCHITECTURE.md](./ARCHITECTURE.md) — Zero-knowledge model
- [BITWARDEN-PARITY.md](./BITWARDEN-PARITY.md) — Feature matrix
