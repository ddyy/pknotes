# pknotes

pknotes ("passkey notes") is end-to-end encrypted markdown notes on Cloudflare Workers. The encryption key comes from your passkey, so there is no master password and nothing the server could ever read.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ddyy/pknotes)

> **Status**: working and self-hostable. It has not had an independent security audit, and there is no rate limiting or abuse protection yet. Treat it as a personal deployment, not a public service.

## How the encryption works

```
Passkey (iCloud Keychain / Google Password Manager / security key)
   │  WebAuthn PRF extension → 32 deterministic, credential-bound bytes
   ▼
HKDF-SHA256 → KEK (key-encryption key, never leaves the browser)
   │  unwraps
   ▼
Master key (random AES-256, generated once at signup)
   │  encrypts (AES-256-GCM, fresh IV per save)
   ▼
Notes (markdown)
```

- One WebAuthn ceremony does double duty: the server verifies the assertion (login), the client reads the PRF output (decryption). The PRF bytes never leave the browser.
- The server (Workers + D1) stores WebAuthn public keys, wrapped copies of the master key, and note ciphertext. A full database dump yields nothing readable.
- Each passkey wraps the same master key, so adding a device is a single wrap with no re-encryption. Passkeys sync through their platform (iCloud Keychain etc.), which gives you multi-device access for free.
- A one-time recovery code (160-bit, shown once at signup) also wraps the master key. The server stores a hash of a *verifier* derived from the code; the KEK derived from it stays client-side.

## Stack

- **Worker**: [Hono](https://hono.dev) + `@simplewebauthn/server`, sessions via HMAC-signed HttpOnly cookies
- **Storage**: D1 (`migrations/`)
- **Client**: React + Vite (`@cloudflare/vite-plugin`), CodeMirror 6 markdown editor, `markdown-it` + DOMPurify preview
- **Crypto**: WebCrypto only. AES-256-GCM, HKDF-SHA256, WebAuthn PRF.

## Develop

```sh
npm install
npm run dev   # applies local D1 migrations automatically, then starts vite + workerd on localhost:5173
```

Passkeys work on `localhost` without HTTPS. `.dev.vars` holds the dev `SESSION_SECRET` (created automatically on first run).

## Deploy

**One click**: use the button at the top. Cloudflare clones the repo into your account, provisions the D1 database (the placeholder `database_id` in `wrangler.jsonc` is replaced for you), and asks for `SESSION_SECRET` during setup. Use a long random string, e.g. `openssl rand -base64 32`. Migrations run as part of the deploy script.

**Manual**:

```sh
npx wrangler d1 create pknotes            # once; put the id in wrangler.jsonc
npx wrangler secret put SESSION_SECRET    # long random string
npm run deploy                            # build + migrate + deploy
```

## Requirements & caveats

- Browsers need the WebAuthn **PRF extension**: Chrome/Edge, Safari 18+ (iOS/iPadOS 18.4+), recent Firefox.
- The **passkey provider** must support PRF too. Google Password Manager, iCloud Keychain, 1Password, and FIDO2 hardware keys with `hmac-secret` all do. The **Bitwarden extension does not** ([bitwarden#13838](https://github.com/orgs/bitwarden/discussions/13838)); dismiss its prompt to fall back to your browser's built-in passkeys. pknotes detects the gap at signup and fails with a clear message before creating an account.
- The master key lives in memory only while unlocked; a page reload locks the vault.
- Losing every passkey **and** the recovery code means the notes are gone for good. That is the point of zero-knowledge: nobody can reset what the server cannot read.
- When the same note is saved from two devices, both versions are kept (one becomes a "conflict copy" note). Nothing is merged.
