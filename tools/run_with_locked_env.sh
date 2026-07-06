#!/usr/bin/env bash
set -euo pipefail

# Runtime launcher for packaged release.
# Prompts for unlock password, decrypts secure/.env.enc to a temporary .env,
# starts the integrated server, then removes .env on exit.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENC_ENV="$ROOT_DIR/secure/.env.enc"
TMP_ENV="$ROOT_DIR/.env"
DEFAULT_UNLOCK_PASSWORD="${SENTINEL_RELEASE_PASSWORD:-CHANGE_ME_RELEASE_PASSWORD}"

if [[ ! -f "$ENC_ENV" ]]; then
  echo "ERROR: Encrypted env file not found at $ENC_ENV"
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required but not installed."
  exit 1
fi

cleanup() {
  if [[ -f "$TMP_ENV" ]]; then
    chmod 600 "$TMP_ENV" 2>/dev/null || true
    rm -f "$TMP_ENV"
  fi
}
trap cleanup EXIT INT TERM

read -r -s -p "Enter env unlock password [press Enter to use SENTINEL_RELEASE_PASSWORD]: " ENV_PASSWORD
echo

if [[ -z "$ENV_PASSWORD" ]]; then
  ENV_PASSWORD="$DEFAULT_UNLOCK_PASSWORD"
fi

if [[ -z "$ENV_PASSWORD" ]]; then
  echo "ERROR: No unlock password provided."
  echo "Set SENTINEL_RELEASE_PASSWORD or type the password when prompted."
  exit 1
fi

if ! printf '%s' "$ENV_PASSWORD" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 250000 \
  -in "$ENC_ENV" -out "$TMP_ENV" -pass stdin 2>/dev/null; then
  echo "ERROR: Invalid password or corrupted encrypted env bundle."
  exit 1
fi

unset ENV_PASSWORD
chmod 600 "$TMP_ENV" 2>/dev/null || true

echo "Environment unlocked for this run. Starting system..."
cd "$ROOT_DIR"

# Keep package tree read-only during runtime. The decrypted .env is the only
# temporary writable secret and is removed on exit.
find "$ROOT_DIR" -type d -not -path "$ROOT_DIR/.git*" -exec chmod 555 {} + 2>/dev/null || true
find "$ROOT_DIR" -type f -not -path "$TMP_ENV" -not -path "$ENC_ENV" -exec chmod 444 {} + 2>/dev/null || true
chmod 600 "$TMP_ENV" 2>/dev/null || true

# Keep sudo behavior optional:
# - with sudo: admin behavior (per your privilege logic)
# - without sudo: client-safe behavior
if [[ ${1:-} == "--sudo" ]]; then
  shift
  exec sudo "$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/server/run_server.py" "$@"
else
  exec "$ROOT_DIR/.venv/bin/python" "$ROOT_DIR/server/run_server.py" "$@"
fi
