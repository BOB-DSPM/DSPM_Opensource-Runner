set -euo pipefail

ensure_steampipe() {
  if command -v steampipe >/dev/null 2>&1; then
    return 0
  fi
  echo "[INFO] steampipe not found; installing locally..."
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) sp_arch=amd64 ;;
    aarch64|arm64) sp_arch=arm64 ;;
    *) echo "[ERROR] unsupported arch: $arch" >&2; return 1 ;;
  esac
  url="https://github.com/turbot/steampipe/releases/latest/download/steampipe_linux_${sp_arch}.tar.gz"
  mkdir -p "$HOME/.local/bin"
  tmp="$(mktemp -d)"
  curl -fsSL "$url" -o "$tmp/steampipe.tgz"
  tar -xzf "$tmp/steampipe.tgz" -C "$tmp" steampipe
  mv "$tmp/steampipe" "$HOME/.local/bin/steampipe"
  chmod +x "$HOME/.local/bin/steampipe"
  rm -rf "$tmp"
  export PATH="$HOME/.local/bin:$PATH"
}

# Ensure Steampipe CLI and AWS plugin are available before app start
ensure_steampipe
if command -v steampipe >/dev/null 2>&1; then
  steampipe plugin install aws || true
  echo "[INFO] starting steampipe service..."
  if ! steampipe service start >/dev/null 2>&1; then
    echo "[WARN] steampipe service start failed; retry with local listen"
    steampipe service start --database-listen local || true
  fi
  steampipe service status || true
fi

uvicorn app.main:app --host 0.0.0.0 --port 8800
