import os
import socket
from urllib.parse import urlparse

from python_signatures.base import SignatureCollector


def _host_from_target(url: str) -> str:
    u = url.strip()
    if u.lower().startswith(("stun:", "stuns:")):
        u = u.split(":", 1)[1]
    else:
        parsed = urlparse(u)
        if parsed.hostname:
            return parsed.hostname
    if "@" in u:
        u = u.split("@", 1)[1]
    if "/" in u:
        u = u.split("/", 1)[0]
    if ":" in u:
        return u.rsplit(":", 1)[0].strip()
    return u.strip()


def docker_chromium_args(url: str) -> list[str]:
    """Pin Chromium to IPv4 used by tcpdump BPF (required in Docker)."""
    host = urlparse(url).hostname or _host_from_target(url)
    if not host:
        return ["--no-sandbox", "--disable-setuid-sandbox"]
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    for info in infos:
        if info[0] == socket.AF_INET:
            ip = str(info[4][0])
            return [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                f"--host-resolver-rules=MAP {host} {ip}",
            ]
    raise RuntimeError(f"No IPv4 for {host}")


def local_ip_for_udp(host: str, port: int) -> str:
    """Local IPv4 used when sending UDP to host:port (for in/out filtering)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        return str(sock.getsockname()[0])
    finally:
        sock.close()


def capture_iface(cfg_iface: str | None, options_iface: str | None) -> str | None:
    if options_iface or cfg_iface:
        return options_iface or cfg_iface
    if os.environ.get("CAPTURE_IN_DOCKER") == "1":
        return "eth0"
    return None
