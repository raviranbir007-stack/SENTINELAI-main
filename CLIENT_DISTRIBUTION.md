# Client Distribution Guide (No Plaintext .env)

This flow lets you distribute SENTINELAI to client machines without shipping plaintext `.env`.

## What You Get

- A zip package that **excludes** `.env`.
- An encrypted env bundle: `secure/.env.enc`.
- A launcher script that asks for password at runtime:
  - `tools/run_with_locked_env.sh`

## 1) Build Client Zip on Your Admin Machine

From project root:

```bash
chmod +x tools/create_client_release.sh
./tools/create_client_release.sh
```

What it does:

1. Copies project to `dist/SENTINELAI-main` excluding `.env` and local artifacts.
2. Encrypts your root `.env` into `secure/.env.enc` using AES-256 + PBKDF2.
3. Creates zip at `dist/sentinelai-client-release-<timestamp>.zip`.

Default unlock password: `ranbir@69`

You can override it by exporting `SENTINEL_RELEASE_PASSWORD` before packaging.

## 2) On Client Machine

1. Unzip package.
2. Install dependencies / venv if needed.
3. Start with locked env launcher:

```bash
chmod +x tools/run_with_locked_env.sh
./tools/run_with_locked_env.sh
```

For admin run with sudo:

```bash
./tools/run_with_locked_env.sh --sudo
```

Per your role logic:

- non-sudo run => client-safe mode
- sudo run => admin mode

If you press Enter at the unlock prompt, the launcher uses the default password `ranbir@69`.

## 3) About Password Handling

- If needed, set `SENTINEL_RELEASE_PASSWORD` to rotate the release password without editing scripts.
- Keep unlock password out of git and logs.
- Rotate password and regenerate package if leaked.

## 4) Optional Force Overrides (if needed)

You can force behavior with env flags:

- `SENTINEL_FORCE_CLIENT_MODE=true`
- `SENTINEL_FORCE_ADMIN_INFRA=true`

Use only for diagnostics.
