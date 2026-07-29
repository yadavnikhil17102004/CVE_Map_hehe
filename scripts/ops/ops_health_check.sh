#!/usr/bin/env bash
set -euo pipefail

STATUS_FILE="/var/log/cveintel/ops_health_status.json"
ALERT_STATE_FILE="/var/log/cveintel/ops_health_alert_state.txt"
mkdir -p /var/log/cveintel

SCRAPE_MAX_AGE_SECONDS="${SCRAPE_MAX_AGE_SECONDS:-25200}"        # 7h
SCRAPE_ACTIVE_MAX_SECONDS="${SCRAPE_ACTIVE_MAX_SECONDS:-21600}"  # 6h
NEWS_MAX_AGE_SECONDS="${NEWS_MAX_AGE_SECONDS:-5400}"             # 90m
BACKUP_MAX_AGE_SECONDS="${BACKUP_MAX_AGE_SECONDS:-93600}"        # 26h
SNAPSHOT_MAX_AGE_SECONDS="${SNAPSHOT_MAX_AGE_SECONDS:-691200}"   # 8d
ALERT_COOLDOWN_SECONDS="${ALERT_COOLDOWN_SECONDS:-1800}"         # 30m
OPS_HEALTH_TEST_MODE="${OPS_HEALTH_TEST_MODE:-false}"
# Keep success notifications recovery-only by default to avoid channel fatigue.
OPS_HEALTH_NOTIFY_OK_EVERY_RUN="${OPS_HEALTH_NOTIFY_OK_EVERY_RUN:-false}"

now_epoch="$(date -u +%s)"
now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
now_label="$(date -u +'%Y-%m-%d %H:%M UTC')"

send_alert() {
  local msg="$1"
  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
    local telegram_url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    curl -fsS -m 10 -X POST "$telegram_url" \
      --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
      --data-urlencode "text=${msg}" >/dev/null || \
      logger -t cveintel-ops-health "Telegram alert delivery failed. ${msg}"
    return
  fi

  if [[ -n "${ALERT_WEBHOOK_URL:-}" ]]; then
    local payload
    payload="$(printf '{"text":"%s","content":"%s"}' "$msg" "$msg")"
    curl -fsS -m 10 -H "Content-Type: application/json" -d "$payload" "$ALERT_WEBHOOK_URL" >/dev/null || \
      logger -t cveintel-ops-health "Webhook alert delivery failed. ${msg}"
    return
  fi

  logger -t cveintel-ops-health "No alert destination configured (need TELEGRAM_* or ALERT_WEBHOOK_URL). ${msg}"
}

safe_last_unix() {
  local unit="$1"
  local pattern="$2"
  local line
  line="$(journalctl -u "$unit" -g "$pattern" --no-pager -n 1 -o short-unix 2>/dev/null | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    echo 0
    return
  fi
  echo "${line%%.*}"
}

file_ts_to_epoch() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo 0
    return
  fi
  date -u -d "$(stat -c %y "$path")" +%s 2>/dev/null || echo 0
}

fmt_duration() {
  local s="$1"
  if (( s < 60 )); then
    printf "%ss" "$s"
  elif (( s < 3600 )); then
    printf "%sm" $((s / 60))
  elif (( s < 86400 )); then
    printf "%sh %sm" $((s / 3600)) $(((s % 3600) / 60))
  else
    printf "%sd %sh" $((s / 86400)) $(((s % 86400) / 3600))
  fi
}

last_scrape_error_excerpt() {
  journalctl -u cveintel-scrape.service --since "-3 hours" --no-pager -o cat 2>/dev/null \
    | grep -E "Postgres upsert failed|Window [0-9]+ failed|NVD read attempt|NVD request attempt|context deadline exceeded|Failed to start" \
    | tail -n 2 || true
}

status_ok=true
errors=()
details=()
error_codes=()

scrape_last_epoch="$(safe_last_unix cveintel-scrape.service "scrape cycle complete")"
scrape_start_epoch="$(safe_last_unix cveintel-scrape.service "Starting cveintel-scrape.service")"
news_last_epoch="$(safe_last_unix cveintel-news.service "news cycle complete")"
backup_status_epoch="$(file_ts_to_epoch /var/log/cveintel/backup_status.json)"
snapshot_status_epoch="$(file_ts_to_epoch /var/log/cveintel/public_snapshot_status.json)"
scrape_active_state="$(systemctl show -p ActiveState --value cveintel-scrape.service 2>/dev/null || echo unknown)"

scrape_age=$(( now_epoch - scrape_last_epoch ))
scrape_active_age=$(( now_epoch - scrape_start_epoch ))
news_age=$(( now_epoch - news_last_epoch ))
backup_age=$(( now_epoch - backup_status_epoch ))
snapshot_age=$(( now_epoch - snapshot_status_epoch ))

scrape_line="Scrape: UNKNOWN"
if [[ "$scrape_active_state" == "active" || "$scrape_active_state" == "activating" ]]; then
  if [[ "$scrape_start_epoch" -eq 0 ]]; then
    scrape_line="Scrape: ACTIVE (in progress; freshness intentionally excluded)"
  elif (( scrape_active_age > SCRAPE_ACTIVE_MAX_SECONDS )); then
    status_ok=false
    error_codes+=("scrape_stuck_active")
    errors+=("scrape appears stuck active for $(fmt_duration "$scrape_active_age") (ceiling $(fmt_duration "$SCRAPE_ACTIVE_MAX_SECONDS"))")
    details+=("Scrape run exceeded active ceiling; alerting despite active state.")
    scrape_line="Scrape: STUCK ACTIVE (running $(fmt_duration "$scrape_active_age"), ceiling $(fmt_duration "$SCRAPE_ACTIVE_MAX_SECONDS"))"
  else
    scrape_line="Scrape: ACTIVE (running $(fmt_duration "$scrape_active_age"), freshness intentionally excluded)"
  fi
elif [[ "$scrape_last_epoch" -eq 0 || "$scrape_age" -gt "$SCRAPE_MAX_AGE_SECONDS" ]]; then
  status_ok=false
  error_codes+=("scrape_stale")
  errors+=("scrape freshness exceeded: last success $(fmt_duration "$scrape_age") ago (threshold $(fmt_duration "$SCRAPE_MAX_AGE_SECONDS"))")
  details+=("Scrape has no recent successful completion.")
  scrape_line="Scrape: STALE (last success $(fmt_duration "$scrape_age") ago; threshold $(fmt_duration "$SCRAPE_MAX_AGE_SECONDS"))"
else
  scrape_line="Scrape: OK (last success $(fmt_duration "$scrape_age") ago; threshold $(fmt_duration "$SCRAPE_MAX_AGE_SECONDS"))"
fi

news_line="News: UNKNOWN"
if [[ "$news_last_epoch" -eq 0 || "$news_age" -gt "$NEWS_MAX_AGE_SECONDS" ]]; then
  status_ok=false
  error_codes+=("news_stale")
  errors+=("news freshness exceeded: last success $(fmt_duration "$news_age") ago (threshold $(fmt_duration "$NEWS_MAX_AGE_SECONDS"))")
  news_line="News: STALE (last success $(fmt_duration "$news_age") ago; threshold $(fmt_duration "$NEWS_MAX_AGE_SECONDS"))"
else
  news_line="News: OK (last success $(fmt_duration "$news_age") ago; threshold $(fmt_duration "$NEWS_MAX_AGE_SECONDS"))"
fi

backup_line="Backup: UNKNOWN"
if [[ "$backup_status_epoch" -eq 0 || "$backup_age" -gt "$BACKUP_MAX_AGE_SECONDS" ]]; then
  status_ok=false
  error_codes+=("backup_stale")
  errors+=("backup status stale: last update $(fmt_duration "$backup_age") ago (threshold $(fmt_duration "$BACKUP_MAX_AGE_SECONDS"))")
  backup_line="Backup: STALE (last update $(fmt_duration "$backup_age") ago; threshold $(fmt_duration "$BACKUP_MAX_AGE_SECONDS"))"
else
  backup_line="Backup: OK (last update $(fmt_duration "$backup_age") ago; threshold $(fmt_duration "$BACKUP_MAX_AGE_SECONDS"))"
fi

snapshot_line="Snapshot: UNKNOWN"
if [[ "$snapshot_status_epoch" -eq 0 || "$snapshot_age" -gt "$SNAPSHOT_MAX_AGE_SECONDS" ]]; then
  status_ok=false
  error_codes+=("snapshot_stale")
  errors+=("snapshot status stale: last update $(fmt_duration "$snapshot_age") ago (threshold $(fmt_duration "$SNAPSHOT_MAX_AGE_SECONDS"))")
  snapshot_line="Snapshot: STALE (last update $(fmt_duration "$snapshot_age") ago; threshold $(fmt_duration "$SNAPSHOT_MAX_AGE_SECONDS"))"
else
  snapshot_line="Snapshot: OK (last update $(fmt_duration "$snapshot_age") ago; threshold $(fmt_duration "$SNAPSHOT_MAX_AGE_SECONDS"))"
fi

status_str="ok"
if [[ "$status_ok" != true ]]; then
  status_str="failed"
fi

{
  echo "{"
  echo "  \"last_updated\": \"${now_iso}\","
  echo "  \"status\": \"${status_str}\","
  echo "  \"test_mode\": \"${OPS_HEALTH_TEST_MODE}\","
  echo "  \"scrape_last_success_epoch\": ${scrape_last_epoch},"
  echo "  \"scrape_age_seconds\": ${scrape_age},"
  echo "  \"scrape_active_state\": \"${scrape_active_state}\","
  echo "  \"scrape_active_age_seconds\": ${scrape_active_age},"
  echo "  \"news_last_success_epoch\": ${news_last_epoch},"
  echo "  \"news_age_seconds\": ${news_age},"
  echo "  \"backup_status_age_seconds\": ${backup_age},"
  echo "  \"snapshot_status_age_seconds\": ${snapshot_age},"
  echo "  \"error_count\": ${#errors[@]}"
  if [[ "${#errors[@]}" -gt 0 ]]; then
    echo "  ,\"errors\": ["
    for i in "${!errors[@]}"; do
      comma=","
      if [[ "$i" -eq $((${#errors[@]} - 1)) ]]; then
        comma=""
      fi
      printf "    \"%s\"%s\n" "${errors[$i]}" "$comma"
    done
    echo "  ]"
  fi
  echo "}"
} > "$STATUS_FILE"

last_alert_epoch=0
last_alert_key=""
if [[ -f "$ALERT_STATE_FILE" ]]; then
  last_alert_epoch="$(awk -F'|' '{print $1}' "$ALERT_STATE_FILE" 2>/dev/null || echo 0)"
  last_alert_key="$(awk -F'|' '{print $2}' "$ALERT_STATE_FILE" 2>/dev/null || true)"
fi

if [[ "$status_ok" == true ]]; then
  should_notify_ok=false
  if [[ "${OPS_HEALTH_NOTIFY_OK_EVERY_RUN,,}" == "true" ]]; then
    should_notify_ok=true
  elif [[ -n "$last_alert_key" && "$last_alert_key" != "ok" ]]; then
    # Recovery edge: previous health state was non-OK and now recovered.
    should_notify_ok=true
  fi

  if [[ "$should_notify_ok" == true ]]; then
    prefix="✅ CVE-Intel Ops OK"
    if [[ "${OPS_HEALTH_TEST_MODE,,}" == "true" ]]; then
      prefix="🧪 TEST OK — CVE-Intel Ops"
    fi
    ok_msg="${prefix} — ${now_label}

${scrape_line}
${news_line}
${backup_line}
${snapshot_line}

Details: Health checks are within thresholds."
    send_alert "$ok_msg"
  fi

  echo "${now_epoch}|ok" > "$ALERT_STATE_FILE"
  exit 0
fi

alert_key="$(printf '%s|' "${error_codes[@]}")"

should_alert=false
if [[ "$alert_key" != "$last_alert_key" ]]; then
  should_alert=true
elif (( now_epoch - last_alert_epoch > ALERT_COOLDOWN_SECONDS )); then
  should_alert=true
fi

if [[ "$should_alert" == true ]]; then
  prefix="🔴 CVE-Intel Ops Alert"
  if [[ "${OPS_HEALTH_TEST_MODE,,}" == "true" ]]; then
    prefix="🧪 TEST ALERT — CVE-Intel Ops"
  fi

  msg="${prefix} — ${now_label}

${scrape_line}
${news_line}
${backup_line}
${snapshot_line}"

  if [[ "${#details[@]}" -gt 0 ]]; then
    msg="${msg}

Details: ${details[*]}"
  fi

  if printf '%s' "${errors[*]}" | grep -qi "scrape"; then
    excerpt="$(last_scrape_error_excerpt)"
    if [[ -n "$excerpt" ]]; then
      msg="${msg}

Recent scrape logs:
${excerpt}"
    fi
  fi

  send_alert "$msg"
  echo "${now_epoch}|${alert_key}" > "$ALERT_STATE_FILE"
fi

exit 1
