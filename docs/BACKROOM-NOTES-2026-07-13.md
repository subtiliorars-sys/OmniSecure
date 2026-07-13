# Backroom notes — OmniSecure — 2026-07-13

**Agent:** Cursor backroom ID8 pulse (B-02 / tick 4 deepen)  
**Constraint:** docs only — no auth / secrets / CI credential changes

## Open PRs

| PR | Note |
|----|------|
| #1 | Bump uuid 11.1.1 → 14.0.0 — MERGEABLE; leave for Dependabot/owner review; **not touched** |
| #2 | This branch — verify notes (draft) |

## Local verify (no auth change)

Root scripts from `package.json` (pnpm workspace, Node ≥20):

```powershell
pnpm install
pnpm run build          # all packages
pnpm run test           # all packages
pnpm run lint
pnpm run dev            # server + vault-web parallel
pnpm run build:vault    # core + crypto + vault-web only
```

Do **not** run `pnpm run deploy:fly` from this lane (deploy is owner-gated).

Do not edit secrets, passkey policy, or CI credentials.

## Health surface

Workspace apps live under `apps/` / `packages/`. Prefer package `test`/`build` over inventing a new `/health` probe until a dedicated smoke script exists.

## Hub note (2026-07-13 ~09:16)

Lead pipeline relay audit: **PASS** (`crm_relay.configured=true`). Unrelated to OmniSecure; recorded so backroom idle ticks stay honest.
