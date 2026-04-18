#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "[env-backup] Skipped: .env not found at $ENV_FILE"
    exit 0
fi

if [[ -n "${SUDO_USER:-}" && -d "/home/${SUDO_USER}" ]]; then
    USER_HOME="/home/${SUDO_USER}"
else
    USER_HOME="${HOME}"
fi

BACKUP_DIR="${SENTINEL_ENV_BACKUP_DIR:-$USER_HOME/.config/sentinelai/env-backups}"
mkdir -p "$BACKUP_DIR"

# Ensure backup files are only readable by the current user.
umask 077

timestamp="$(date +%Y%m%d-%H%M%S)"
target="$BACKUP_DIR/.env.$timestamp"
latest="$BACKUP_DIR/.env.latest"

cp "$ENV_FILE" "$target"
chmod 600 "$target"

cp "$ENV_FILE" "$latest"
chmod 600 "$latest"

# Keep latest 30 timestamped backups.
ls -1t "$BACKUP_DIR"/.env.[0-9]* 2>/dev/null | tail -n +31 | xargs -r rm -f

echo "[env-backup] Saved: $target"
echo "[env-backup] Latest: $latest"