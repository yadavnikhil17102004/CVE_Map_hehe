#!/usr/bin/env bash
set -euo pipefail

# Manual deploy helper for VPS runtime.
# This script runs from local machine and executes a safe, repeatable deploy flow over SSH.
#
# Defaults match current documented production setup:
# - dirty workspace: ~/CVE-Intel
# - clean deploy worktree: ~/CVE-Intel-deploy
# - compose project: ~/cve-intel-vps
# - compose service: api

VPS_HOST="${VPS_HOST:-172.175.241.146}"
VPS_USER="${VPS_USER:-nixk2000}"
SOURCE_REPO_DIR="${SOURCE_REPO_DIR:-/home/nixk2000/CVE-Intel}"
DEPLOY_WORKTREE_DIR="${DEPLOY_WORKTREE_DIR:-/home/nixk2000/CVE-Intel-deploy}"
COMPOSE_DIR="${COMPOSE_DIR:-/home/nixk2000/cve-intel-vps}"
COMPOSE_SERVICE="${COMPOSE_SERVICE:-api}"
TARGET_REF="${TARGET_REF:-origin/main}"
STATIC_ROOT="${STATIC_ROOT:-/var/www/cve-intel}"
PURGE_EXTRA_HTML="${PURGE_EXTRA_HTML:-false}"

REMOTE="${VPS_USER}@${VPS_HOST}"

echo "[deploy] remote=${REMOTE}"
echo "[deploy] source=${SOURCE_REPO_DIR}"
echo "[deploy] worktree=${DEPLOY_WORKTREE_DIR}"
echo "[deploy] compose_dir=${COMPOSE_DIR} service=${COMPOSE_SERVICE}"
echo "[deploy] target_ref=${TARGET_REF}"
echo "[deploy] static_root=${STATIC_ROOT}"
echo "[deploy] purge_extra_html=${PURGE_EXTRA_HTML}"

ssh "${REMOTE}" "bash -s" <<EOF
set -euo pipefail

echo "[1/10] fetch latest remote in source repo"
cd "${SOURCE_REPO_DIR}"
git fetch origin
git log "${TARGET_REF}" -1 --oneline

echo "[2/10] ensure clean deploy worktree exists"
if [ ! -d "${DEPLOY_WORKTREE_DIR}/.git" ] && [ ! -f "${DEPLOY_WORKTREE_DIR}/.git" ]; then
  git worktree add "${DEPLOY_WORKTREE_DIR}" "${TARGET_REF}"
fi

echo "[3/10] update deploy worktree to target ref"
cd "${DEPLOY_WORKTREE_DIR}"
git fetch origin
git checkout "${TARGET_REF}"
git rev-parse --short HEAD

echo "[4/10] verify compose context references deploy worktree"
cd "${COMPOSE_DIR}"
grep -n "context:" docker-compose.yml || true

echo "[5/10] inspect Caddyfile and static-site directives"
if [ -f /etc/caddy/Caddyfile ]; then
  sudo sed -n '1,220p' /etc/caddy/Caddyfile
else
  CADDY_PATH=\$(sudo find / -name Caddyfile 2>/dev/null | head -1 || true)
  if [ -n "\${CADDY_PATH}" ]; then
    echo "[caddy] using \${CADDY_PATH}"
    sudo sed -n '1,220p' "\${CADDY_PATH}"
  else
    echo "[caddy] Caddyfile not found"
  fi
fi

echo "[6/10] rebuild container image"
sudo docker compose build "${COMPOSE_SERVICE}"

echo "[7/10] restart container"
sudo docker compose up -d "${COMPOSE_SERVICE}"

echo "[8/10] wait for API readiness + runtime logs"
for i in \$(seq 1 20); do
  if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    echo "[api] healthy on attempt \${i}"
    break
  fi
  if [ "\${i}" -eq 20 ]; then
    echo "[api] failed readiness after retries"
    sudo docker logs --since 10m cveintel-api || true
    exit 1
  fi
  sleep 2
done

sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "cveintel|NAME"
sudo docker logs --since 5m cveintel-api || true

echo "[9/10] sync static pages to Caddy root + API smoke checks"
sudo mkdir -p "${STATIC_ROOT}"
MANAGED_HTML_FILES="index.html dashboard.html workspace.html news.html operations.html docs.html"
for f in ${MANAGED_HTML_FILES} style.css; do
  if [ -f "${DEPLOY_WORKTREE_DIR}/\${f}" ]; then
    sudo install -m 644 "${DEPLOY_WORKTREE_DIR}/\${f}" "${STATIC_ROOT}/\${f}"
  fi
done
if [ -d "${DEPLOY_WORKTREE_DIR}/assets" ]; then
  sudo mkdir -p "${STATIC_ROOT}/assets"
  sudo cp -a "${DEPLOY_WORKTREE_DIR}/assets/." "${STATIC_ROOT}/assets/"
fi

echo "[sync] static root html inventory"
sudo find "${STATIC_ROOT}" -maxdepth 1 -type f -name '*.html' -printf '%f\n' | sort

EXTRA_HTML=\$(comm -23 \
  <(sudo find "${STATIC_ROOT}" -maxdepth 1 -type f -name '*.html' -printf '%f\n' | sort) \
  <(printf '%s\n' ${MANAGED_HTML_FILES} | sort) || true)

if [ -n "\${EXTRA_HTML}" ]; then
  echo "[sync] extra html files found in static root:"
  printf '%s\n' "\${EXTRA_HTML}"
  if [ "${PURGE_EXTRA_HTML}" = "true" ]; then
    echo "[sync] purging extra html files"
    while IFS= read -r html_file; do
      [ -n "\${html_file}" ] || continue
      sudo rm -f "${STATIC_ROOT}/\${html_file}"
    done <<< "\${EXTRA_HTML}"
  else
    echo "[sync] keeping extras (set PURGE_EXTRA_HTML=true to remove)"
  fi
fi

curl -sS https://cve-intel.duckdns.org/api/health
curl -sI "https://cve-intel.duckdns.org/api/search?page=1&per_page=5" | grep -i -E "HTTP/|cache-control|content-encoding|content-length|vary" || true
curl -sI "https://cve-intel.duckdns.org/api/news?page=1&per_page=5" | grep -i -E "HTTP/|cache-control|content-encoding|content-length|vary" || true

echo "[10/10] static-page rollout checks"
curl -s "https://cve-intel.duckdns.org/dashboard.html" | grep -o 'href="[^"]*"' | sort -u
curl -s "https://cve-intel.duckdns.org/dashboard.html" | grep -q 'href="workspace.html"'
curl -s "https://cve-intel.duckdns.org/dashboard.html" | grep -q 'href="operations.html"'
curl -s "https://cve-intel.duckdns.org/dashboard.html" | grep -q 'href="docs.html"'
curl -sI "https://cve-intel.duckdns.org/operations.html" | grep -i -E "HTTP/|content-type|cache-control" || true
EOF

echo "[deploy] done"
