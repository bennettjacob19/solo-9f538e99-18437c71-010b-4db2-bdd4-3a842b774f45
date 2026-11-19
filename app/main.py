"""Entrypoint: wire up storage, snapshot, DNS server, prober, and web UI.

Run:  python -m app.main
Env:  ZONE_DB (default ./data/zone.db), DNS_BIND (0.0.0.0), DNS_PORT (5353),
      WEB_HOST (0.0.0.0), WEB_PORT (8000), REFRESH_INTERVAL (2.0 seconds),
      PROBE_INTERVAL (2.0 seconds), PROBE_TIMEOUT (1.5 seconds)
"""

import os
import sys
import threading
import time

import uvicorn

from .deps import runtime
from .dns_server import start_dns_server
from .prober import ProbeEngine
from .store import Store
from .zone import snapshot_from_rows


def log(msg):
    print(f"[zonedns] {msg}", file=sys.stderr, flush=True)


def load_current_into_holder():
    current = runtime.store.load_current()
    if current is None:
        log("no published version in database yet")
        return
    runtime.holder.set(
        snapshot_from_rows(current["id"], current["created_at"], current["rows"])
    )
    log(f"loaded current version v{current['id']} "
        f"({len(current['rows'])} records) from database")


def refresh_loop():
    """Safety net: re-sync the in-memory snapshot with the DB pointer.

    Normal publishes swap the snapshot immediately; this only matters if the
    DB changed out-of-band. Reads never block queries."""
    while True:
        time.sleep(runtime.refresh_interval)
        try:
            vid = runtime.store.current_version_id()
            snap = runtime.holder.get()
            if vid is not None and (snap is None or snap.version_id != vid):
                log(f"refresh: DB current version is v{vid}, reloading snapshot")
                load_current_into_holder()
        except Exception as exc:  # keep serving the in-memory snapshot
            log(f"refresh: {exc!r}")


def main():
    db_path = os.environ.get("ZONE_DB", os.path.join("data", "zone.db"))
    dns_bind = os.environ.get("DNS_BIND", "0.0.0.0")
    dns_port = int(os.environ.get("DNS_PORT", "5353"))
    web_host = os.environ.get("WEB_HOST", "0.0.0.0")
    web_port = int(os.environ.get("WEB_PORT", "8000"))
    runtime.refresh_interval = float(os.environ.get("REFRESH_INTERVAL", "2.0"))

    db_dir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(db_dir, exist_ok=True)

    runtime.store = Store(db_path)
    runtime.store.init()
    runtime.dns_query_host = os.environ.get("DNS_QUERY_HOST", "127.0.0.1")
    runtime.dns_query_port = dns_port

    load_current_into_holder()  # restart: resume exactly the committed version

    start_dns_server(runtime.holder.get, dns_bind, dns_port)
    log(f"authoritative UDP DNS for svc.test. on {dns_bind}:{dns_port}")

    threading.Thread(target=refresh_loop, daemon=True).start()

    probe_interval = float(os.environ.get("PROBE_INTERVAL", "2.0"))
    probe_timeout = float(os.environ.get("PROBE_TIMEOUT", "1.5"))
    runtime.prober = ProbeEngine(
        runtime.holder.get,
        host=runtime.dns_query_host,
        interval=probe_interval,
        timeout=probe_timeout,
    )
    saved_probe = runtime.store.load_probe_settings()
    if saved_probe:
        # Restart: resume probing from the persisted settings, but the state
        # machine starts from "pending" -- a previous "ok" is never inherited.
        runtime.prober.apply_settings(
            saved_probe["name"], saved_probe["port"],
            note="服务启动，载入已保存的探测设置")
    threading.Thread(target=runtime.prober.run, daemon=True).start()
    if saved_probe:
        log(f"probing {saved_probe['name']} @ {runtime.dns_query_host}:"
            f"{saved_probe['port']} every {probe_interval:g}s")
    else:
        log(f"probe engine idle (no settings yet), interval {probe_interval:g}s")

    log(f"web UI on http://{web_host}:{web_port}")
    uvicorn.run("app.web:app", host=web_host, port=web_port, log_level="info")


if __name__ == "__main__":
    main()
