#!/usr/bin/env python3
"""
Simple Minecraft server checker used by scanner.cpp.

Given an IP (and optional port), uses mcstatus to see if the target is a
responding Java Edition server. On success, prints a single-line summary and
exits 0. On failure, prints an error to stderr and exits non-zero.
"""

import argparse
import socket
import sys
import time
from typing import Any

from mcstatus import JavaServer


def _flatten_description(desc: Any) -> str:
    """
    Convert mcstatus description/Chat object into a plain, single-line string.
    """
    try:
        text = desc.to_plain()  # type: ignore[attr-defined]
    except Exception:
        if isinstance(desc, dict):
            if "text" in desc:
                text = str(desc["text"])
            elif "extra" in desc and isinstance(desc["extra"], list):
                text = "".join(str(part.get("text", "")) for part in desc["extra"])
            else:
                text = str(desc)
        else:
            text = str(desc)
    return " ".join(text.split())  # squash whitespace/newlines


def main() -> int:
    parser = argparse.ArgumentParser(description="Check if an endpoint is a live Minecraft server.")
    parser.add_argument("--ip", required=True, help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=25565, help="Target port (default: 25565)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Status timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="Retry count for transient errors")
    parser.add_argument("--retry-delay", type=float, default=0.75, help="Delay between retries (seconds)")
    args = parser.parse_args()

    server = JavaServer.lookup(f"{args.ip}:{args.port}")
    transient_errors = (socket.timeout, TimeoutError, ConnectionResetError, ConnectionRefusedError, OSError)
    last_exc: Exception | None = None

    def log(msg: str) -> None:
        print(f"LOG: {msg}", flush=True)

    for attempt in range(max(1, args.retries)):
        log(f"Attempt {attempt + 1}/{max(1, args.retries)} for {args.ip}:{args.port}")
        try:
            try:
                status = server.status(timeout=args.timeout)
            except TypeError:
                status = server.status()
            log("Status received")
            break
        except transient_errors as exc:
            last_exc = exc
            log(f"Transient failure: {exc}")
            if attempt + 1 < args.retries:
                time.sleep(max(0.0, args.retry_delay))
                continue
            print(f"MC-TIMEOUT: {exc}")
            return 3
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    else:
        print(f"MC-TIMEOUT: {last_exc}")
        return 3

    motd = _flatten_description(status.description)
    latency_ms = getattr(status, "latency", None)
    players_online = getattr(status.players, "online", None)
    players_max = getattr(status.players, "max", None)
    version = getattr(getattr(status, "version", None), "name", None)

    parts = [f"{args.ip}:{args.port}"]
    if players_online is not None and players_max is not None:
        parts.append(f"players {players_online}/{players_max}")
    if latency_ms is not None:
        parts.append(f"latency {latency_ms:.1f} ms")
    if version:
        parts.append(f"version {version}")
    if motd:
        parts.append(f"motd \"{motd}\"")

    print(" | ".join(parts))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - quick failure path
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
