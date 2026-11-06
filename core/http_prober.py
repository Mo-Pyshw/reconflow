import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]


def get_tls_expiry_days(hostname: str, port: int = 443, timeout: int = 4) -> Optional[int]:
    """
    Connects to port 443 and returns the number of days until TLS cert expiration.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    return (expiry_date - now).days
    except Exception:
        return None
    return None


def probe_http_host(hostname: str, timeout: int = 6) -> Dict[str, Any]:
    """
    Probes a host across HTTPS (fallback to HTTP) to collect status code,
    page title, server banner, TLS hygiene, and missing security headers.
    """
    probe_result = {
        "url": None,
        "status_code": None,
        "title": "N/A",
        "server": "Hidden / Not Specified",
        "tls_days_left": None,
        "missing_headers": [],
        "reachable": False
    }

    headers = {
        "User-Agent": "ReconFlow-SecurityAudit/1.1"
    }

    for scheme in ("https", "http"):
        target_url = f"{scheme}://{hostname}"
        try:
            resp = requests.get(
                target_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )
            probe_result["reachable"] = True
            probe_result["url"] = resp.url
            probe_result["status_code"] = resp.status_code
            probe_result["server"] = resp.headers.get("Server", "Hidden")

            title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                clean_title = " ".join(title_match.group(1).split())
                probe_result["title"] = clean_title[:65]

            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            missing = []
            for sec_hdr in SECURITY_HEADERS:
                if sec_hdr.lower() not in resp_headers_lower:
                    missing.append(sec_hdr)
            probe_result["missing_headers"] = missing

            if scheme == "https" or resp.url.startswith("https://"):
                probe_result["tls_days_left"] = get_tls_expiry_days(hostname)

            break
        except requests.RequestException:
            continue

    return probe_result
