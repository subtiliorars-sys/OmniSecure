# Deploy OmniSecure: Fly.io API + Cloudflare Pages vault

Production layout:

| Layer | Host | Role |
|-------|------|------|
| **API** | `https://omnisecure-api.fly.dev` | Fastify + SQLite on Fly volume |
| **Vault web** | Your Cloudflare Pages URL | Static React app (`apps/vault-web`) |

Use an existing Cloudflare Pages project (custom domain or `*.pages.dev`) until you dedicate a permanent hostname. Update Fly secrets when the vault URL changes.

---

## 1. Fly.io API (one-time + deploy)

### Prerequisites

- [flyctl](https://fly.io/docs/hands-on/install-flyctl/) installed and logged in (`fly auth login`)
- Fly volume for SQLite persistence

### First-time setup

From repo root:

```powershell
# Create app + persistent volume (skip if already created)
fly apps create omnisecure-api
fly volumes create omnisecure_data --size 1 --region iad -a omnisecure-api

# Secrets — replace vault host with YOUR Cloudflare Pages URL
$jwt = -join ((1..32 | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }))
fly secrets set `
  JWT_SECRET=$jwt `
  OMNISECURE_PUBLIC_URL=https://YOUR-VAULT.pages.dev `
  OMNISECURE_API_URL=https://omnisecure-api.fly.dev `
  WEBAUTHN_RP_ID=YOUR-VAULT.pages.dev `
  WEBAUTHN_ORIGIN=https://YOUR-VAULT.pages.dev `
  WEBAUTHN_RP_NAME=OmniSecure `
  -a omnisecure-api
```

See `deploy/fly.env.example` for all variables.

### Deploy / update API

```powershell
pnpm deploy:fly
# or
fly deploy --config fly.toml
```

Verify:

```powershell
curl https://omnisecure-api.fly.dev/health
```

### Custom API domain (optional)

1. Fly dashboard → **omnisecure-api** → **Certificates** → add `api.yourdomain.com`
2. Cloudflare DNS → CNAME `api` → `omnisecure-api.fly.dev`
3. Update `OMNISECURE_API_URL` secret and Cloudflare `VITE_API_URL`

---

## 2. Cloudflare Pages (vault web)

### Option A — Connect GitHub (recommended)

1. Cloudflare dashboard → **Workers & Pages** → open an existing Pages project (or **Create** → **Connect to Git**)
2. Repository: `subtiliorars-sys/OmniSecure`, branch `main`
3. Build settings:

| Setting | Value |
|---------|--------|
| Framework | None |
| Root directory | `/` |
| Build command | `pnpm install && pnpm build:vault` |
| Build output | `apps/vault-web/dist` |
| Node.js version | 20 |

4. **Environment variables** (Production):

```
VITE_API_URL=https://omnisecure-api.fly.dev
```

5. Save and deploy. SPA routing uses `apps/vault-web/public/_redirects` (copied into `dist`).

### Option B — Manual / CLI deploy

```powershell
cd C:\Users\hrmread\OmniSecure
$env:VITE_API_URL="https://omnisecure-api.fly.dev"
pnpm build:vault
npx wrangler pages deploy apps/vault-web/dist --project-name=YOUR_PAGES_PROJECT
```

### Option C — GitHub Actions (automatic)

Add repo secrets:

| Secret | Purpose |
|--------|---------|
| `FLY_API_TOKEN` | Fly deploy token |
| `CLOUDFLARE_API_TOKEN` | Pages deploy (Account → API Tokens → Edit Cloudflare Workers) |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |

Optional repo variables:

| Variable | Default |
|----------|---------|
| `VITE_API_URL` | `https://omnisecure-api.fly.dev` |
| `CLOUDFLARE_PAGES_PROJECT` | `omnisecure-vault` |

Push to `main` runs `.github/workflows/deploy.yml`.

---

## 3. After both are live

1. **Update Fly secrets** so SSO redirects and WebAuthn match the real vault URL:

   ```powershell
   fly secrets set `
     OMNISECURE_PUBLIC_URL=https://YOUR-VAULT.pages.dev `
     WEBAUTHN_RP_ID=YOUR-VAULT.pages.dev `
     WEBAUTHN_ORIGIN=https://YOUR-VAULT.pages.dev `
     -a omnisecure-api
   ```

2. **Passkeys** require `WEBAUTHN_RP_ID` = registrable domain (no `https://`).

3. **CORS** — API uses reflective CORS; vault and API must both be HTTPS in production.

4. **Send links** — use vault origin, e.g. `https://YOUR-VAULT.pages.dev/send/abc123#k=...`

---

## 4. Reusing an existing Pages project

If you already have a Pages project on a domain you plan to repurpose:

1. Point that project at this repo with the build settings above, **or**
2. Deploy to a `*.pages.dev` subdomain first, then attach your custom domain in Pages → **Custom domains**

No code changes needed when switching domains — only `VITE_API_URL` (Pages) and Fly `OMNISECURE_*` / `WEBAUTHN_*` secrets.

---

## 5. Costs (typical hobby)

- **Fly.io**: ~$0–5/mo with auto-stop + 1 GB volume
- **Cloudflare Pages**: free tier for static sites

---

## Related

- [DEPLOYMENT.md](./DEPLOYMENT.md) — all deployment options
- [SELF-HOST.md](./SELF-HOST.md) — Docker self-host
