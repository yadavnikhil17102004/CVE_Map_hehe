#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone


TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
ALLOWED_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
OFFSET_FILE = os.environ.get("TELEGRAM_OFFSET_FILE", "/var/log/cveintel/telegram_bot_offset.txt")
POLL_TIMEOUT = int(os.environ.get("TELEGRAM_POLL_TIMEOUT", "30"))
POLL_SLEEP = float(os.environ.get("TELEGRAM_POLL_SLEEP", "2"))
OPS_STATUS_FILE = "/var/log/cveintel/ops_health_status.json"
BACKUP_STATUS_FILE = "/var/log/cveintel/backup_status.json"
SNAPSHOT_STATUS_FILE = "/var/log/cveintel/public_snapshot_status.json"


def run(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except Exception:
        return ""


def fmt_duration(seconds):
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_offset(offset):
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w", encoding="utf-8") as f:
        f.write(str(offset))


def read_offset():
    try:
        with open(OFFSET_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def tg_request(method, params=None):
    if params is None:
        params = {}
    base = f"https://api.telegram.org/bot{TOKEN}/{method}"
    data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(base, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_message(chat_id, text):
    return tg_request("sendMessage", {"chat_id": str(chat_id), "text": text})


def last_epoch(unit, pattern):
    output = run(["journalctl", "-u", unit, "-g", pattern, "--no-pager", "-n", "1", "-o", "short-unix"])
    if not output:
        return 0
    try:
        line = output.splitlines()[-1]
        return int(line.split(".", 1)[0])
    except Exception:
        return 0


def service_state(unit):
    out = run(["systemctl", "show", "-p", "ActiveState", "-p", "Result", "--value", unit]).splitlines()
    active = out[0] if len(out) > 0 else "unknown"
    result = out[1] if len(out) > 1 else "unknown"
    return active, result


def vm_state():
    rg = os.environ.get("AZ_RESOURCE_GROUP", "").strip()
    vm = os.environ.get("AZ_VM_NAME", "").strip()
    if not rg or not vm:
        return "unknown (AZ_RESOURCE_GROUP/AZ_VM_NAME not set)"
    if not shutil.which("az"):
        return "unknown (az CLI not installed on VPS)"
    if rg and vm and shutil.which("az"):
        state = run(
            [
                "az",
                "vm",
                "get-instance-view",
                "-g",
                rg,
                "-n",
                vm,
                "--query",
                "instanceView.statuses[?starts_with(code,'PowerState/')].displayStatus | [0]",
                "-o",
                "tsv",
            ]
        )
        if state:
            return state
    return "unknown (az not logged in or VM query failed)"


def db_counts():
    db = os.environ.get("POSTGRES_DB", "").strip()
    user = os.environ.get("POSTGRES_USER", "").strip()
    pwd = os.environ.get("POSTGRES_PASSWORD", "").strip()
    host = os.environ.get("POSTGRES_HOST", "127.0.0.1").strip()
    port = os.environ.get("POSTGRES_PORT", "5432").strip()
    if not db or not user or not pwd:
        return "unavailable"

    env = os.environ.copy()
    env["PGPASSWORD"] = pwd

    def query(sql):
        try:
            out = subprocess.check_output(
                ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-Atc", sql],
                text=True,
                stderr=subprocess.DEVNULL,
                env=env,
            ).strip()
            return out if out else "0"
        except Exception:
            return "?"

    cve_repos = query("SELECT COUNT(*) FROM cve_repos;")
    cve_distinct = query("SELECT COUNT(DISTINCT cve_id) FROM cve_repos;")
    nvd_intel = query("SELECT COUNT(*) FROM nvd_intel;")
    return f"cve_repos={cve_repos}, cve_ids={cve_distinct}, nvd_intel={nvd_intel}"


def build_status():
    now = int(time.time())
    now_label = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scrape_active, scrape_result = service_state("cveintel-scrape.service")
    news_active, news_result = service_state("cveintel-news.service")
    backup_active, backup_result = service_state("cveintel-backup.service")
    snap_active, snap_result = service_state("cveintel-public-snapshot.service")

    scrape_last = last_epoch("cveintel-scrape.service", "scrape cycle complete")
    news_last = last_epoch("cveintel-news.service", "news cycle complete")

    backup = load_json(BACKUP_STATUS_FILE)
    snap = load_json(SNAPSHOT_STATUS_FILE)
    ops = load_json(OPS_STATUS_FILE)

    scrape_age = fmt_duration(now - scrape_last) if scrape_last else "unknown"
    news_age = fmt_duration(now - news_last) if news_last else "unknown"
    backup_last = backup.get("last_updated") or backup.get("last_run_utc") or "unknown"
    snap_last = snap.get("last_updated") or snap.get("last_run_utc") or "unknown"
    vm = vm_state()
    ops_state = ops.get("status", "unknown")

    lines = [
        f"🟢 CVE-Intel Status — {now_label}",
        "",
        f"VM: {vm}",
        f"Ops health: {ops_state}",
        f"Scrape: {scrape_active}/{scrape_result} (last success {scrape_age} ago)",
        f"News: {news_active}/{news_result} (last success {news_age} ago)",
        f"Backup: {backup_active}/{backup_result} (last status {backup_last})",
        f"Snapshot: {snap_active}/{snap_result} (last status {snap_last})",
    ]
    return "\n".join(lines)


def build_scrape():
    now = int(time.time())
    now_label = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    active, result = service_state("cveintel-scrape.service")
    start = last_epoch("cveintel-scrape.service", "Starting cveintel-scrape.service")
    end = last_epoch("cveintel-scrape.service", "scrape cycle complete")
    last_age = fmt_duration(now - end) if end else "unknown"
    duration = "unknown"
    if start and end and end >= start:
        duration = fmt_duration(end - start)

    counts = db_counts()
    lines = [
        f"🛠 Scrape Status — {now_label}",
        f"State: {active}/{result}",
        f"Last success age: {last_age}",
        f"Last cycle duration: {duration}",
        f"DB totals: {counts}",
    ]
    return "\n".join(lines)


def build_backup():
    now_label = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = load_json(BACKUP_STATUS_FILE)
    if not status:
        return f"💾 Backup Status — {now_label}\nNo backup status file found."

    last_run = status.get("last_updated") or status.get("last_run_utc") or "unknown"
    st = status.get("status", "unknown")
    dump_size = (
        status.get("dump_size_bytes")
        or status.get("db_dump_size_bytes")
        or status.get("latest_dump_size_bytes")
        or "unknown"
    )
    return (
        f"💾 Backup Status — {now_label}\n"
        f"State: {st}\n"
        f"Last run: {last_run}\n"
        f"Dump size bytes: {dump_size}"
    )


def build_help():
    return (
        "CVE-Intel bot commands:\n"
        "/status - full ops snapshot\n"
        "/scrape - scrape run details + DB row totals\n"
        "/backup - backup status + dump size\n"
        "/help - this help"
    )


def handle_command(text):
    cmd = (text or "").strip().split()[0].lower()
    if cmd == "/status":
        return build_status()
    if cmd == "/scrape":
        return build_scrape()
    if cmd == "/backup":
        return build_backup()
    return build_help()


def main():
    if not TOKEN or not ALLOWED_CHAT_ID:
        raise SystemExit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    offset = read_offset()
    while True:
        try:
            res = tg_request("getUpdates", {"timeout": str(POLL_TIMEOUT), "offset": str(offset)})
            for upd in res.get("result", []):
                offset = int(upd["update_id"]) + 1
                save_offset(offset)
                msg = upd.get("message") or {}
                chat = msg.get("chat") or {}
                chat_id = str(chat.get("id", ""))
                text = msg.get("text", "")
                if not text:
                    continue
                if chat_id != ALLOWED_CHAT_ID:
                    print(f"ignored message from unauthorized chat_id={chat_id}", flush=True)
                    continue
                print(f"handling command: {text}", flush=True)
                reply = handle_command(text)
                send_message(chat_id, reply)
                print("command response sent", flush=True)
        except Exception:
            time.sleep(POLL_SLEEP)


if __name__ == "__main__":
    main()
