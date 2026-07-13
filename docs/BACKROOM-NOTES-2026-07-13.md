# Backroom notes — OmniSecure — 2026-07-13

**Agent:** Cursor backroom ID8 pulse (B-02)  
**Constraint:** docs only — no auth / secrets / CI credential changes

## Open PRs

| PR | Note |
|----|------|
| #1 | Bump uuid 11.1.1 → 14.0.0 — leave for Dependabot/owner review; **not touched** this tick |

## Local verify (no auth change)

From repo root (pnpm workspace):

```powershell
pnpm install
pnpm -r --if-present run build
pnpm -r --if-present run test
```

If a package exposes a health script, prefer that over changing auth policy. Do not edit secrets, passkey policy, or CI credentials in this lane.

## Next safe deepen (later tick)

- Confirm which app under `apps/` owns `/health` if any
- Add a one-line pointer in README only if missing (separate commit)
