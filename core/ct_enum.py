import time
import requests
from typing import Set, List


def fetch_subdomains_crtsh(domain: str, timeout: int = 15) -> List[str]:
    """
    Queries crt.sh Certificate Transparency logs for passive subdomain discovery.
    crt.sh occasionally drops connections under heavy load, so we implement
    a polite retry mechanism before failing gracefully.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; ReconFlow-ASM/1.1; +https://github.com)"
    }
    subdomains: Set[str] = set()
    subdomains.add(domain)

    for attempt in range(2):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.splitlines():
                        sub = sub.strip().lower()
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub.endswith(f".{domain}") or sub == domain:
                            if "@" not in sub and " " not in sub:
                                subdomains.add(sub)
                break
            elif response.status_code in (502, 503, 504) and attempt == 0:
                time.sleep(2)
        except (requests.RequestException, ValueError):
            if attempt == 0:
                time.sleep(1.5)
            continue

    return sorted(subdomains)
