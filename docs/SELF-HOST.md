# Self-hosting OmniSecure

Deploy OmniSecure on your own infrastructure for full data sovereignty — equivalent to [Bitwarden self-host](https://bitwarden.com/help/install-on-premise/).

## Docker Compose (recommended)

```bash
cd docker
cp .env.example .env
# Edit JWT_SECRET to a long random string
docker compose up -d
```

Services:

| Service | Port | Description |
|---------|------|-------------|
| `api` | 8787 | OmniSecure REST API |
| `vault-web` | 8080 | Static web vault (nginx) |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | *(required)* | Signs session JWTs |
| `OMNISECURE_DB` | `/data/omnisecure.db` | SQLite path inside container |
| `PORT` | `8787` | API listen port |

### Persistent data

Mount `./data` to retain vault database across restarts:

```yaml
volumes:
  - ./data:/data
```

## Manual install

```bash
pnpm install
pnpm build
JWT_SECRET=$(openssl rand -hex 32) node packages/server/dist/index.js
```

Serve `apps/vault-web/dist` with any static file server, proxy `/api` to the API.

## Kubernetes (planned)

Helm chart will mirror Bitwarden's multi-container pattern:

- API deployment
- PostgreSQL StatefulSet
- Ingress with TLS
- Optional Redis for session cache

## Upgrades

1. Pull latest image / git tag
2. `docker compose pull && docker compose up -d`
3. Database migrations run automatically on API startup

## Backup

Backup the SQLite file or Postgres volume. **Without the master password, encrypted data cannot be recovered** — store emergency export procedures in your org runbook.

## Lite vs full deployment

| Tier | Components | Use case |
|------|------------|----------|
| **Lite** | API + SQLite + web | Solo dev, small team |
| **Full** | API + Postgres + Redis + reverse proxy | Production org |

OmniSecure v0.1 ships the Lite stack; Full tier is on the roadmap.
