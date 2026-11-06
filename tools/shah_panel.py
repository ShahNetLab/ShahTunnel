#!/usr/bin/env python3
"""Read-only local dashboard for ShahTunnel.

The service intentionally binds to 127.0.0.1 only. Use SSH port forwarding
for remote access; do not publish this unauthenticated read-only panel directly.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = "1.0.0"
DEFAULT_CONFIG_DIR = Path(os.environ.get("SHAH_TUNNEL_CONFIG_DIR", "/etc/ravanreverse"))
MAX_LOG_LINES = 100
PROBE_TIMEOUT = 0.8


def safe_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def parse_host_port(address: str):
    """Parse host:port (including bracketed IPv6); reject malformed values."""
    if not isinstance(address, str) or not address.strip():
        return None
    value = address.strip()
    try:
        if value.startswith("["):
            end = value.find("]")
            if end < 0 or end + 1 >= len(value) or value[end + 1] != ":":
                return None
            host, port_text = value[1:end], value[end + 2:]
        else:
            host, port_text = value.rsplit(":", 1)
            if ":" in host:  # IPv6 addresses must be bracketed, matching net.SplitHostPort.
                return None
        port = int(port_text)
        if not host or not (1 <= port <= 65535):
            return None
        return host, port
    except (ValueError, TypeError):
        return None


def endpoint_probe(address: str, label: str, timeout: float = PROBE_TIMEOUT):
    parsed = parse_host_port(address)
    result = {"label": label, "address": address, "ok": False, "latency_ms": None,
              "status": "invalid address"}
    if not parsed:
        return result
    host, port = parsed
    # Wildcard listen addresses cannot be dialed; probe their loopback socket.
    if host in ("0.0.0.0", "::", "*"):
        host = "::1" if ":" in address and address.startswith("[") else "127.0.0.1"
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000
        result.update(ok=True, latency_ms=round(elapsed, 1), status="TCP reachable")
    except OSError as exc:
        result["status"] = f"TCP unavailable ({exc.__class__.__name__})"
    return result


def unit_name(config_path: Path, config_dir: Path):
    try:
        if config_path.resolve() == (config_dir / "config.json").resolve():
            return "ravanreverse"
    except OSError:
        pass
    profile_id = config_path.stem
    if not profile_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in profile_id):
        return None
    return f"ravanreverse@{profile_id}"


def metrics_path(config_path: Path, config_dir: Path):
    try:
        if config_path.resolve() == (config_dir / "config.json").resolve():
            return config_dir / "runtime.json"
    except OSError:
        pass
    return config_dir / "runtime" / f"{config_path.stem}.json"


def discover_profiles(config_dir: Path):
    candidates = []
    legacy = config_dir / "config.json"
    if legacy.is_file():
        candidates.append(legacy)
    named_dir = config_dir / "tunnels"
    if named_dir.is_dir():
        candidates.extend(sorted(named_dir.glob("*.json")))

    profiles = []
    for path in candidates:
        cfg = safe_json(path)
        if not cfg or cfg.get("role") not in ("hub", "agent", "relay"):
            continue
        unit = unit_name(path, config_dir)
        if not unit:
            continue
        name = str(cfg.get("name") or ("legacy" if path == legacy else path.stem))[:64]
        profiles.append({
            "id": path.stem if path != legacy else "legacy",
            "name": name,
            "role": cfg.get("role"),
            "unit": unit,
            "config_path": str(path),
            "config": cfg,
            "metrics_path": metrics_path(path, config_dir),
        })
    return profiles


def command_output(args, timeout=4):
    if not shutil.which(args[0]):
        return 127, "command unavailable"
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                check=False)
        return result.returncode, ((result.stdout or "") + (result.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, "command timed out"
    except OSError as exc:
        return 1, str(exc)


def service_info(unit: str):
    rc, output = command_output([
        "systemctl", "show", unit,
        "--property=ActiveState", "--property=SubState", "--property=NRestarts",
        "--property=ActiveEnterTimestamp", "--no-pager",
    ])
    values = {}
    if rc == 0:
        for line in output.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
    else:
        active_rc, active_text = command_output(["systemctl", "is-active", unit])
        values["ActiveState"] = active_text if active_text else "unknown"
        values["SubState"] = ""
        values["NRestarts"] = "0"
        if active_rc == 127:
            values["ActiveState"] = "systemd unavailable"
    try:
        restarts = int(values.get("NRestarts", "0"))
    except ValueError:
        restarts = 0
    return {
        "state": values.get("ActiveState") or "unknown",
        "substate": values.get("SubState") or "",
        "restarts": restarts,
        "since": values.get("ActiveEnterTimestamp") or "",
    }


def read_metrics(path: Path):
    data = safe_json(path)
    if not data:
        return {"present": False, "connected": False, "active_connections": 0,
                "total_connections": 0, "bytes_sent": 0, "bytes_received": 0,
                "updated": None, "age_seconds": None, "fresh": False}
    updated = data.get("updated")
    age = None
    if isinstance(updated, str):
        try:
            parsed = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            age = max(0, round((datetime.now(timezone.utc) - parsed).total_seconds(), 1))
        except ValueError:
            pass
    try:
        active = max(0, int(data.get("active_connections", 0)))
        total = max(0, int(data.get("total_connections", 0)))
        sent = max(0, int(data.get("bytes_sent", 0)))
        received = max(0, int(data.get("bytes_received", 0)))
    except (ValueError, TypeError):
        active = total = sent = received = 0
    return {
        "present": True,
        "connected": bool(data.get("connected")),
        "active_connections": active,
        "total_connections": total,
        "bytes_sent": sent,
        "bytes_received": received,
        "updated": updated,
        "age_seconds": age,
        "fresh": age is not None and age <= 30,
    }


def offset_address(address: str, delta: int):
    parsed = parse_host_port(address)
    if not parsed:
        return None
    host, port = parsed
    shifted = port + delta
    if not 1 <= shifted <= 65535:
        return None
    formatted_host = f"[{host}]" if ":" in host else host
    return f"{formatted_host}:{shifted}"


def profile_endpoints(profile):
    cfg = profile["config"]
    role = profile["role"]
    transport = str(cfg.get("transport") or "auto").lower()
    items = []
    port_mappings = cfg.get("ports") if isinstance(cfg.get("ports"), list) else []
    if role == "agent":
        hub = cfg.get("hub_addr")
        if hub:
            hub = str(hub)
            items.append(("Hub control", hub))
            if transport in ("adaptive", "http2_connect", "http_connect_auto"):
                shifted = offset_address(hub, 1)
                if shifted:
                    items.append(("Hub HTTP/2 CONNECT", shifted))
            if transport in ("adaptive", "http1_connect", "http_connect_auto"):
                shifted = offset_address(hub, 2)
                if shifted:
                    items.append(("Hub HTTP/1.1 CONNECT", shifted))
        for mapping in port_mappings:
            if isinstance(mapping, dict) and mapping.get("target"):
                label = f"Target {str(mapping.get('id') or 'port')[:32]}"
                items.append((label, str(mapping["target"])))
    else:
        control = cfg.get("control_listen")
        if control:
            control = str(control)
            items.append(("Control listener", control))
            if transport in ("adaptive", "http2_connect", "http_connect_auto"):
                shifted = offset_address(control, 1)
                if shifted:
                    items.append(("HTTP/2 CONNECT listener", shifted))
            if transport in ("adaptive", "http1_connect", "http_connect_auto"):
                shifted = offset_address(control, 2)
                if shifted:
                    items.append(("HTTP/1.1 CONNECT listener", shifted))
        for mapping in port_mappings:
            if not isinstance(mapping, dict):
                continue
            address = mapping.get("listen")
            if address:
                label = f"Public {str(mapping.get('id') or 'port')[:32]}"
                items.append((label, str(address)))
            if role == "relay" and mapping.get("target"):
                label = f"Relay target {str(mapping.get('id') or 'port')[:24]}"
                items.append((label, str(mapping["target"])))
    # Avoid duplicate network probes while preserving the original labels.
    seen = set()
    unique = []
    for label, address in items:
        if address not in seen:
            seen.add(address)
            unique.append((label, address))
    return unique[:64]


def cpu_percent():
    def snapshot():
        try:
            parts = Path("/proc/stat").read_text().split()
            values = [int(item) for item in parts[1:8]]
            return sum(values), values[3] + values[4]
        except (OSError, ValueError, IndexError):
            return 0, 0
    total1, idle1 = snapshot()
    time.sleep(0.08)
    total2, idle2 = snapshot()
    delta = total2 - total1
    return round(100 * (delta - (idle2 - idle1)) / delta, 1) if delta > 0 else 0.0


def memory_info():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            if rest.strip():
                values[key] = int(rest.strip().split()[0])
    except (OSError, ValueError):
        pass
    total = values.get("MemTotal", 0) // 1024
    available = values.get("MemAvailable", 0) // 1024
    used = max(0, total - available)
    return {"total_mb": total, "used_mb": used,
            "percent": round(100 * used / total, 1) if total else 0.0}


def disk_info():
    try:
        usage = shutil.disk_usage("/")
        return {"total_gb": round(usage.total / 2**30, 1),
                "used_gb": round(usage.used / 2**30, 1),
                "percent": round(100 * usage.used / usage.total, 1) if usage.total else 0.0}
    except OSError:
        return {"total_gb": 0, "used_gb": 0, "percent": 0.0}


def uptime_text():
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return "نامشخص"
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    return f"{days} روز، {hours} ساعت، {minutes} دقیقه" if days else f"{hours} ساعت، {minutes} دقیقه"


def build_status(config_dir: Path):
    profiles = discover_profiles(config_dir)
    probe_jobs = {}
    enriched = []
    for profile in profiles:
        service = service_info(profile["unit"])
        metrics = read_metrics(profile["metrics_path"])
        endpoints = [{"label": label, "address": address, "ok": False,
                      "latency_ms": None, "status": "checking"}
                     for label, address in profile_endpoints(profile)]
        current = {
            "id": profile["id"], "name": profile["name"], "role": profile["role"],
            "unit": profile["unit"], "service": service, "metrics": metrics,
            "endpoints": endpoints,
        }
        enriched.append(current)
        for index, (label, address) in enumerate(profile_endpoints(profile)):
            probe_jobs[(len(enriched) - 1, index)] = (address, label)

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(endpoint_probe, address, label): key
                   for key, (address, label) in probe_jobs.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                enriched[key[0]]["endpoints"][key[1]] = future.result()
            except Exception:
                enriched[key[0]]["endpoints"][key[1]]["status"] = "probe error"

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    return {
        "version": VERSION,
        "hostname": hostname,
        "uptime": uptime_text(),
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "cpu_percent": cpu_percent(),
        "memory": memory_info(),
        "disk": disk_info(),
        "profiles": enriched,
    }


def read_logs(unit: str):
    rc, output = command_output([
        "journalctl", "-u", unit, "-n", str(MAX_LOG_LINES), "--no-pager", "-o", "short-iso",
    ], timeout=8)
    if rc != 0:
        return output or "لاگی در دسترس نیست."
    return output[-24000:] if output else "هنوز لاگی ثبت نشده است."


class Handler(BaseHTTPRequestHandler):
    server_version = "ShahTunnelPanel"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Avoid recording browser query strings or potentially sensitive metadata.
        print(f"[shah-panel] {self.client_address[0]} - {fmt % args}", flush=True)

    def send_body(self, status, body, content_type="application/json; charset=utf-8"):
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def host_is_local(self):
        raw_host = self.headers.get("Host", "")
        try:
            parsed_host = urlparse(f"//{raw_host}")
            host = (parsed_host.hostname or "").lower()
            port = parsed_host.port
        except ValueError:
            return False
        return host in ("127.0.0.1", "localhost") and (port is None or port == self.server.server_port)

    def do_GET(self):  # noqa: N802
        if not self.host_is_local():
            self.send_body(421, json.dumps({"error": "local Host header required"}))
            return
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            index = Path(__file__).resolve().parent / "web" / "index.html"
            try:
                self.send_body(200, index.read_text(encoding="utf-8"), "text/html; charset=utf-8")
            except OSError:
                self.send_body(500, "فایل رابط کاربری پیدا نشد.", "text/plain; charset=utf-8")
            return
        if parsed.path == "/api/health":
            self.send_body(200, json.dumps({"ok": True, "version": VERSION}))
            return
        if parsed.path == "/api/status":
            try:
                status = build_status(self.server.config_dir)
                self.send_body(200, json.dumps(status, ensure_ascii=False))
            except Exception as exc:
                self.send_body(500, json.dumps({"error": f"status collection failed: {exc.__class__.__name__}"}))
            return
        if parsed.path == "/api/logs":
            profile_id = parse_qs(parsed.query).get("profile", [""])[0]
            profile = next((p for p in discover_profiles(self.server.config_dir) if p["id"] == profile_id), None)
            if profile is None:
                self.send_body(404, json.dumps({"error": "profile not found"}))
                return
            logs = read_logs(profile["unit"])
            self.send_body(200, json.dumps({"unit": profile["unit"], "log": logs}, ensure_ascii=False))
            return
        self.send_body(404, json.dumps({"error": "not found"}))

    def do_POST(self):  # noqa: N802
        if not self.host_is_local():
            self.send_body(421, json.dumps({"error": "local Host header required"}))
            return
        self.send_body(405, json.dumps({"error": "read-only dashboard"}))


def main():
    parser = argparse.ArgumentParser(description="Read-only local ShahTunnel status dashboard")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR,
                        help="ShahTunnel configuration directory (default: /etc/ravanreverse)")
    parser.add_argument("--port", type=int, default=8091, help="local HTTP port (default: 8091)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not args.config_dir.exists():
        print(f"[shah-panel] config directory not found: {args.config_dir}", flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.config_dir = args.config_dir
    server.daemon_threads = True
    print(f"[shah-panel] read-only dashboard: http://127.0.0.1:{args.port}", flush=True)
    print("[shah-panel] loopback-only listener; use SSH port forwarding for remote access", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
