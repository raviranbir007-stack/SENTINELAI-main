#!/usr/bin/env bash
set -euo pipefail

# Build a client-ready release zip:
# - excludes plaintext .env
# - includes encrypted env bundle at secure/.env.enc
# - intended to be unlocked by tools/run_with_locked_env.sh on client machine

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
STAGING_DIR="$DIST_DIR/SENTINELAI-main"
DATE_TAG="$(date +%Y%m%d_%H%M%S)"
ZIP_NAME="sentinelai-client-release-${DATE_TAG}.zip"
ZIP_PATH="$DIST_DIR/$ZIP_NAME"
DEFAULT_RELEASE_PASSWORD="${SENTINEL_RELEASE_PASSWORD:-CHANGE_ME_RELEASE_PASSWORD}"

if [[ ! -f "$ROOT_DIR/.env" ]]; then
  echo "ERROR: $ROOT_DIR/.env not found."
  echo "Create your admin .env first, then run this script."
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required but not installed."
  exit 1
fi

echo "Creating client release package..."
mkdir -p "$DIST_DIR"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

echo "Copying project (excluding secrets and local artifacts)..."
rsync -a \
  --exclude '.git' \
  --exclude '.github' \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '*.pyo' \
  --exclude '*.db' \
  --exclude '.env' \
  --exclude 'dist' \
  --exclude 'logs' \
  --exclude 'server/generated_reports' \
  "$ROOT_DIR/" "$STAGING_DIR/"

mkdir -p "$STAGING_DIR/secure"

if [[ -z "$DEFAULT_RELEASE_PASSWORD" ]]; then
  echo "ERROR: SENTINEL_RELEASE_PASSWORD is not set."
  echo "Set it before running this script, for example:"
  echo "  export SENTINEL_RELEASE_PASSWORD='set-a-strong-password'"
  exit 1
fi

PASS1="$DEFAULT_RELEASE_PASSWORD"
PASS2="$DEFAULT_RELEASE_PASSWORD"

echo "Using release password from SENTINEL_RELEASE_PASSWORD."

echo "Encrypting .env -> secure/.env.enc"
printf '%s' "$PASS1" | openssl enc -aes-256-cbc -pbkdf2 -iter 250000 -salt \
  -in "$ROOT_DIR/.env" \
  -out "$STAGING_DIR/secure/.env.enc" \
  -pass stdin

unset PASS1 PASS2

echo "Writing release notes..."
cat > "$STAGING_DIR/secure/README_UNLOCK.txt" <<'EOF'
This package does NOT include plaintext .env.

To run with locked env:
1) chmod +x tools/run_with_locked_env.sh
2) ./tools/run_with_locked_env.sh

The script will prompt for the unlock password and start server/run_server.py.
EOF

echo "Locking package permissions (read-only tree)..."
find "$STAGING_DIR" -type d -exec chmod 555 {} +
find "$STAGING_DIR" -type f -exec chmod 444 {} +
chmod 555 "$STAGING_DIR/tools/run_with_locked_env.sh" "$STAGING_DIR/tools/create_client_release.sh" 2>/dev/null || true
chmod 444 "$STAGING_DIR/secure/.env.enc" "$STAGING_DIR/secure/README_UNLOCK.txt" 2>/dev/null || true

echo "Creating zip: $ZIP_PATH"
(
  cd "$DIST_DIR"
  zip -rq "$ZIP_NAME" "SENTINELAI-main"
)

echo
echo "DONE"
echo "Release zip: $ZIP_PATH"
echo "Plaintext .env is excluded from the package."
