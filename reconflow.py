#!/usr/bin/env python3
"""
ReconFlow - Automated Attack Surface & Security Posture Auditor
Author: Mohammed Khudair Abbas
License: MIT
"""

import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.ct_enum import fetch_subdomains_crtsh
from core.dns_analyzer import resolve_host, audit_domain_mail_security
from core.http_prober import probe_http_host
from core.reporter import generate_markdown_report

console = Console()


def analyze_single_subdomain(subdomain: str, timeout: int) -> Dict[str, Any]:
    dns_info = resolve_host(subdomain)
    if dns_info["resolvable"]:
        http_info = probe_http_host(subdomain, timeout=timeout)
    else:
        http_info = {
            "url": None,
            "status_code": None,
            "title": "N/A",
            "server": "-",
            "tls_days_left": None,
            "missing_headers": [],
            "reachable": False
        }
    return {
        "dns": dns_info,
        "http": http_info
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ReconFlow: Passive Subdomain Enumeration & Web Posture Auditor."
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target root domain to audit (e.g., example.com)"
    )
    parser.add_argument(
        "-o", "--output",
        default="report.md",
        help="Output Markdown report path (default: report.md)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Concurrent worker threads for DNS/HTTP checks (default: 10)"
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=50,
        help="Maximum number of discovered subdomains to probe (default: 50)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=6,
        help="HTTP request timeout in seconds (default: 6)"
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you have explicit authorization to audit the target domain"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.authorized:
        console.print(
            Panel(
                "[bold red]Authorization Check Failed[/bold red]\n"
                "You must pass the [bold yellow]--authorized[/bold yellow] flag to confirm "
                "you have permission to assess this target domain.",
                title="ReconFlow Safety Gate",
                border_style="red"
            )
        )
        sys.exit(1)

    target_domain = args.domain.strip().lower()
    console.print(
        Panel.fit(
            f"[bold cyan]ReconFlow v1.1.0[/bold cyan] - Attack Surface & Posture Pipeline\n"
            f"Target: [bold white]{target_domain}[/bold white] | Threads: {args.threads}",
            border_style="cyan"
        )
    )

    console.print("[*] Auditing root domain DNS & email spoofing protections (SPF/DMARC)...")
    dns_mail_audit = audit_domain_mail_security(target_domain)

    console.print(f"[*] Querying Certificate Transparency logs (crt.sh) for [bold]{target_domain}[/bold]...")
    subdomains = fetch_subdomains_crtsh(target_domain)
    total_found = len(subdomains)
    console.print(f"[+] Discovered [bold green]{total_found}[/bold green] unique hostname(s) in CT logs.")

    if total_found > args.max_hosts:
        console.print(
            f"[!] Limiting active DNS/HTTP checks to first {args.max_hosts} hosts "
            f"(override with --max-hosts)."
        )
        subdomains = subdomains[:args.max_hosts]

    results: List[Dict[str, Any]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Probing discovered assets...", total=len(subdomains))
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_map = {
                executor.submit(analyze_single_subdomain, sub, args.timeout): sub
                for sub in subdomains
            }
            for future in as_completed(future_map):
                try:
                    data = future.result()
                    results.append(data)
                except Exception:
                    pass
                progress.advance(task)

    results.sort(key=lambda x: x["dns"]["hostname"])

    table = Table(title=f"Asset Posture Summary ({target_domain})", show_lines=False)
    table.add_column("Subdomain", style="cyan", no_wrap=True)
    table.add_column("IP Address", style="white")
    table.add_column("HTTP", justify="center")
    table.add_column("Server", style="magenta")
    table.add_column("TLS Days", justify="right")
    table.add_column("Missing Sec Headers", justify="center")

    for item in results:
        sub = item["dns"]["hostname"]
        ip_str = item["dns"]["ips"][0] if item["dns"]["ips"] else "[dim]Unresolved[/dim]"
        http = item["http"]

        if http["reachable"]:
            code = http["status_code"]
            if 200 <= code < 300:
                code_str = f"[green]{code}[/green]"
            elif 300 <= code < 400:
                code_str = f"[yellow]{code}[/yellow]"
            else:
                code_str = f"[red]{code}[/red]"

            tls_str = str(http["tls_days_left"]) if http["tls_days_left"] is not None else "-"
            missing_cnt = len(http["missing_headers"])
            hdr_str = f"[red]{missing_cnt} missing[/red]" if missing_cnt > 0 else "[green]0 (Clean)[/green]"
            srv_str = http["server"]
        else:
            code_str = "[dim]-[/dim]"
            tls_str = "[dim]-[/dim]"
            hdr_str = "[dim]-[/dim]"
            srv_str = "[dim]-[/dim]"

        table.add_row(sub, ip_str, code_str, srv_str, tls_str, hdr_str)

    console.print()
    console.print(table)

    report_md = generate_markdown_report(target_domain, dns_mail_audit, results)
    output_path = Path(args.output)
    output_path.write_text(report_md, encoding="utf-8")

    console.print(
        f"\n[bold green][+][/bold green] Full Markdown report saved to: [bold]{output_path.resolve()}[/bold]"
    )


if __name__ == "__main__":
    main()
