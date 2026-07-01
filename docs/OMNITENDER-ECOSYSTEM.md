# OmniSecure in the OmniTender Ecosystem

OmniSecure is the **identity and secrets layer** for OmniTender — parallel to how Bitwarden sits alongside business operations for thousands of companies.

## Repo map

| Repository | Role |
|------------|------|
| [OmniTender](https://github.com/subtiliorars-sys/OmniTender) | Company brain — policies, sales, compliance |
| **OmniSecure** (this repo) | Password manager + secrets manager + Send |
| [OmniAuth](https://github.com/subtiliorars-sys/OmniAuth) | Mobile TOTP authenticator for staff |
| [omnitender-web](https://github.com/subtiliorars-sys/omnitender-web) | Public marketing site |
| [OmniVerse](https://github.com/subtiliorars-sys/OmniVerse) | SMS/WhatsApp company bot |

## Recommended staff stack

1. **OmniSecure** — store merchant portal logins, API keys, partner credentials
2. **OmniAuth** — 2FA for OmniSecure account and staff consoles
3. **OmniSecure org collections** — share credentials with least privilege (sales vs ops vs dev)

## Developer workflow

```bash
# Service account for CI
omsecure login -e devops@omnitender.us -p "$MASTER"
# Store API keys in Secrets Manager project
omsecure secret-set -p $PROJECT -k STRIPE_SECRET --value "$KEY" --master-password "$MASTER"
```

## Fleet registry

Add OmniSecure to `MeniscusMaximus-Preview/fleet/repo-registry.json` when syncing the org repo list.

Suggested entry:

```json
{
  "name": "OmniSecure",
  "url": "https://github.com/subtiliorars-sys/OmniSecure",
  "role": "Identity security — password manager, secrets, Send",
  "visibility": "public"
}
```

## Compliance notes

- Zero-knowledge architecture supports PCI-adjacent credential hygiene (no PAN storage in OmniSecure)
- Self-host option for merchants requiring data residency
- Audit logs for enterprise org activity

See OmniTender `docs/compliance/` for policy alignment before merchant-facing launch.
