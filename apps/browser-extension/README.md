# OmniSecure Browser Extension

Chrome/Edge extension for **autofill** from your OmniSecure vault.

## Build

```bash
pnpm install
pnpm build:extension
```

Load unpacked extension from `apps/browser-extension/dist/`:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select `apps/browser-extension/dist`

## Features

- Sign in with OmniSecure account (zero-knowledge — master password stays local)
- Detect login forms on any website
- Floating **OS** badge when vault has matching URIs
- Popup: list matches for current tab + one-click autofill

## Configuration

Default API: `http://localhost:8787`. Change in the extension popup when signing in, or point to your self-hosted OmniSecure server.

## Development

```bash
pnpm --filter @omnisecure/browser-extension run dev
```

Rebuild after changes, then click **Reload** on `chrome://extensions`.
