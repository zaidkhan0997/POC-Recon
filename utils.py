import csv
import json
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse
from models import ReconResult

logger = logging.getLogger("poc_recon")

try:
    import socks  # PySocks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False


def setup_logging(debug: bool = False) -> None:
    """Configures application logger."""
    level = logging.DEBUG if debug else logging.INFO
    format_str = "%(asctime)s [%(levelname)s] %(message)s" if debug else "[%(levelname)s] %(message)s"
    logging.basicConfig(level=level, format=format_str, datefmt="%H:%M:%S")


def create_connection(
    host: str,
    port: int,
    timeout: float = 5.0,
    proxy_url: Optional[str] = None
) -> socket.socket:
    """
    Creates a TCP socket connection to (host, port).
    Supports routing via SOCKS5 proxy if specified (e.g. socks5://127.0.0.1:1080).
    """
    if proxy_url:
        if not SOCKS_AVAILABLE:
            raise RuntimeError(
                "PySocks is required for proxy support. Install it with: pip install PySocks"
            )

        parsed = urlparse(proxy_url)
        proxy_type_str = parsed.scheme.lower()

        if "socks5" in proxy_type_str:
            proxy_type = socks.SOCKS5
        elif "socks4" in proxy_type_str:
            proxy_type = socks.SOCKS4
        elif "http" in proxy_type_str:
            proxy_type = socks.HTTP
        else:
            raise ValueError(f"Unsupported proxy scheme: {proxy_type_str}. Use socks5://")

        proxy_host = parsed.hostname
        proxy_port = parsed.port or 1080
        username = parsed.username
        password = parsed.password

        sock = socks.socksocket()
        sock.set_proxy(
            proxy_type=proxy_type,
            addr=proxy_host,
            port=proxy_port,
            username=username,
            password=password,
            rdns=True
        )
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def export_results_json(result: ReconResult, output_path: str) -> None:
    """Exports ReconResult object to a structured JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)


def export_results_csv(result: ReconResult, output_path: str) -> None:
    """Exports candidate results to a standard CSV file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fieldnames = ["email", "pattern", "status", "smtp_code", "smtp_message", "domain", "primary_mx"]
    primary_mx = result.mx_records[0].host if result.mx_records else "N/A"

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for candidate in result.candidates:
            writer.writerow({
                "email": candidate.email,
                "pattern": candidate.pattern_name,
                "status": str(candidate.status),
                "smtp_code": candidate.smtp_code if candidate.smtp_code is not None else "",
                "smtp_message": candidate.smtp_message or "",
                "domain": result.target_domain,
                "primary_mx": primary_mx,
            })
