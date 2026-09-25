#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"
TARGET_DIR="$DATA_DIR/nuclei-templates"
REPO_URL="https://github.com/projectdiscovery/nuclei-templates.git"

mkdir -p "$DATA_DIR"

if [[ -d "$TARGET_DIR/.git" ]]; then
  echo "Refreshing existing nuclei-templates checkout..."
  git -C "$TARGET_DIR" fetch --all --prune
  git -C "$TARGET_DIR" reset --hard origin/main
else
  echo "Cloning nuclei-templates into $TARGET_DIR"
  git clone "$REPO_URL" "$TARGET_DIR"
fi

echo "Done."
