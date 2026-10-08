"""
Interactive Command-Line Interface (CLI) for VanguardRecon.

Utilizes Rich formatting for animated progress, styled risk matrices,
and penetration testing audit summaries.
"""

import asyncio
import sys
import argparse
from datetime import datetime
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from vanguard.scope import ScopeManager, ScopeViolationError
from vanguard.config import PORT_PROFILES
from vanguard.core.scanner import AsyncPortScanner
from vanguard.core.fingerprinter import ServiceFingerprinter
from vanguard.core.web_analyzer import WebAnalyzer
from vanguard.core.dns_enumerator import DNSEnumerator
from vanguard.correlation.cve_engine import CVECorrelationEngine, VulnerabilityFinding
from vanguard.reporting.html_reporter import HTMLReporter
from vanguard.reporting.json_reporter import JSONReporter

# Ensure Windows terminal encoding compatibility
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(highlight=False)

BANNER = """[bold cyan]
 __     __                                           _ ____                     
 \\ \\   / /_ _ _ __   __ _ _   _  __ _ _ __ __   ___ | |  _ \\ ___  ___ ___  _ __  
  \\ \\ / / _` | '_ \\ / _` | | | |/ _` | '__/ _` / __| | |_) / _ \\/ __/ _ \\| '_ \\ 
   \\ V / (_| | | | | (_| | |_| | (_| | | | (_| \\__ \\ |  _ <  __/ (_| (_) | | | |
    \\_/ \\__,_|_| |_|\\__, |\\__,_|\\__,_|_|  \\__,_|___/_|_| \\_\\___|\\___\\___/|_| |_|
                    |___/                                                       [/bold cyan]
[dim]Attack Surface Discovery & Automated CVE Intelligence Framework v1.0.0[/dim]
"""


async def run_scan_pipeline(args):
    """Executes the full terminal reconnaissance and vulnerability audit."""
    console.print(BANNER)

    # 1. Scope Validation
    with console.status("[bold cyan]Validating scope and resolving target...", spinner="dots"):
        try:
            target_ip, target_host, is_private = ScopeManager.resolve_target(args.target)
            if is_private and not args.allow_internal:
                console.print(f"[bold red][!] Scope Error:[/bold red] Target {args.target} resolved to private IP {target_ip}. Use --allow-internal to proceed.")
                sys.exit(1)
        except ScopeViolationError as e:
            console.print(f"[bold red][!] Scope Violation:[/bold red] {e}")
            sys.exit(1)

    # Resolve ports
    if args.ports in PORT_PROFILES:
        ports = PORT_PROFILES[args.ports]
    else:
        try:
            ports = ScopeManager.parse_ports(args.ports)
        except ValueError as e:
            console.print(f"[bold red][!] Port Parse Error:[/bold red] {e}")
            sys.exit(1)

    scope_panel = Panel(
        f"[bold]Target:[/bold] {args.target}\n"
        f"[bold]Resolved IP:[/bold] {target_ip} ({'Private / RFC1918' if is_private else 'Public Routable'})\n"
        f"[bold]Ports to Probe:[/bold] {len(ports)} ports\n"
        f"[bold]Concurrency:[/bold] {args.concurrency} workers | [bold]Timeout:[/bold] {args.timeout}s",
        title="[bold green]Scan Parameters[/bold green]",
        border_style="green"
    )
    console.print(scope_panel)

    # 2. Port Scanning
    scanner = AsyncPortScanner(
        target_ip=target_ip,
        ports=ports,
        timeout=args.timeout,
        concurrency=args.concurrency,
        banner_grab=True
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Probing TCP Ports...", total=len(ports))

        def on_probe(port, is_open):
            progress.advance(task)

        open_ports = await scanner.run(progress_callback=on_probe)

    if not open_ports:
        console.print("[yellow][*] No open ports discovered on target within tested range.[/yellow]")
        return

    # Print Open Ports Table
    p_table = Table(title="[bold green]Discovered Open Ports & Banners[/bold green]")
    p_table.add_column("Port", style="cyan", justify="right")
    p_table.add_column("State", style="green")
    p_table.add_column("Service", style="magenta")
    p_table.add_column("Latency (ms)", style="blue")
    p_table.add_column("Banner / Identification", style="white")

    fingerprints = []
    for p in open_ports:
        fp = ServiceFingerprinter.fingerprint(p.service, p.banner)
        fingerprints.append(fp)
        display_banner = p.banner if p.banner else (f"{fp.product} {fp.version}" if fp.product else "-")
        p_table.add_row(
            str(p.port),
            p.state.upper(),
            p.service.upper(),
            f"{p.latency_ms:.1f}",
            display_banner[:60]
        )
    console.print(p_table)

    # 3. CVE & Exploit Intelligence Correlation
    all_findings: list[VulnerabilityFinding] = []
    with console.status("[bold red]Correlating service fingerprints with CVE & KEV databases...", spinner="dots"):
        for p, fp in zip(open_ports, fingerprints):
            vulns = CVECorrelationEngine.correlate(p.port, fp)
            all_findings.extend(vulns)

    risk_posture = CVECorrelationEngine.calculate_risk_posture(all_findings)

    # Print Vulnerability Table
    if all_findings:
        v_table = Table(title="[bold red]Correlated Vulnerabilities & Exploits (CISA KEV / Exploit-DB)[/bold red]")
        v_table.add_column("CVE ID", style="bold red")
        v_table.add_column("Severity", style="bold")
        v_table.add_column("CVSS", justify="center")
        v_table.add_column("Port / Service", style="cyan")
        v_table.add_column("CISA KEV", style="bold red")
        v_table.add_column("Exploit Code", style="bold yellow")
        v_table.add_column("Title / Remediation", style="white")

        for f in all_findings:
            sev_color = "red" if f.severity in ("CRITICAL", "HIGH") else ("yellow" if f.severity == "MEDIUM" else "blue")
            v_table.add_row(
                f.cve_id,
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                str(f.cvss),
                f"{f.port}/{f.service}",
                "[bold red]YES[/bold red]" if f.cisa_kev else "[dim]No[/dim]",
                "[bold yellow]AVAILABLE[/bold yellow]" if f.exploit_available else "[dim]None[/dim]",
                f"[bold]{f.title}[/bold]\n[dim]{f.remediation}[/dim]"
            )
        console.print(v_table)
    else:
        console.print("[green][+] No known critical CVE signatures matched detected service versions.[/green]")

    # 4. Optional Web Security Analysis
    web_res = None
    web_ports = [p.port for p in open_ports if p.port in (80, 443, 8000, 8080, 8443)]
    if args.web and web_ports:
        target_web_port = 443 if 443 in web_ports else web_ports[0]
        with console.status(f"[bold cyan]Auditing HTTP security headers on port {target_web_port}...", spinner="dots"):
            web_res = await WebAnalyzer.analyze(args.target, port=target_web_port)

        w_table = Table(title=f"[bold cyan]Web Security Audit ({web_res.url}) - Score: {web_res.header_score}/100[/bold cyan]")
        w_table.add_column("Header", style="cyan")
        w_table.add_column("Status", justify="center")
        w_table.add_column("Value / Remediation Guidance", style="white")

        for h in web_res.security_headers:
            status_style = "[bold green]PASS[/bold green]" if h.status == "PASS" else "[bold red]FAIL[/bold red]"
            w_table.add_row(
                h.header,
                status_style,
                h.value if h.present else f"[dim]{h.recommendation}[/dim]"
            )
        console.print(w_table)

    # 5. Risk Posture Summary Panel
    risk_color = "red" if risk_posture.severity_label in ("CRITICAL", "HIGH") else ("yellow" if risk_posture.severity_label == "MEDIUM" else "green")
    summary_panel = Panel(
        f"[bold]Overall Host Risk Score:[/bold] [{risk_color}]{risk_posture.overall_score}/100 ({risk_posture.severity_label})[/{risk_color}]\n"
        f"[bold]Critical Findings:[/bold] {risk_posture.critical_count} | [bold]High Findings:[/bold] {risk_posture.high_count} | [bold]Medium:[/bold] {risk_posture.medium_count}\n"
        f"[bold]Active Wild Exploitation (CISA KEV):[/bold] {'[bold red]DETECTED[/bold red]' if risk_posture.cisa_kev_active else '[green]None[/green]'}",
        title="[bold]Executive Risk Assessment[/bold]",
        border_style=risk_color
    )
    console.print(summary_panel)

    # 6. Report Generation
    if args.output or args.html:
        scan_payload = {
            "target": args.target,
            "target_ip": target_ip,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "risk": risk_posture.dict(),
            "open_ports": [p.dict() for p in open_ports],
            "vulns": [f.dict() for f in all_findings],
            "web_audit": web_res.dict() if web_res else None,
            "subdomains": []
        }
        if args.output:
            JSONReporter.generate(scan_payload, args.output)
            console.print(f"[green][+] JSON report saved to: {args.output}[/green]")
        if args.html:
            HTMLReporter.generate(scan_payload, args.html)
            console.print(f"[green][+] Standalone HTML Pentest report saved to: {args.html}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="VanguardRecon - Attack Surface Discovery & Automated CVE Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run attack surface discovery and CVE correlation")
    scan_parser.add_argument("target", help="Target domain name or IP address")
    scan_parser.add_argument("-p", "--ports", default="top20", help="Port profile (top20, top100, web) or custom list (e.g. 80,443,8080)")
    scan_parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Socket timeout in seconds (default: 1.5)")
    scan_parser.add_argument("-c", "--concurrency", type=int, default=50, help="Max concurrent workers (default: 50)")
    scan_parser.add_argument("--web", action="store_true", help="Audit HTTP security headers and tech stack")
    scan_parser.add_argument("--allow-internal", action="store_true", default=True, help="Permit scanning private RFC 1918 / loopback ranges")
    scan_parser.add_argument("-o", "--output", help="Save machine-readable JSON report")
    scan_parser.add_argument("--html", help="Save standalone HTML pentest deliverable")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Launch the interactive Web API & Dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")

    args = parser.parse_args()

    if args.command == "serve":
        console.print(BANNER)
        console.print(f"[bold green][+] Starting VanguardRecon Web Dashboard on http://{args.host}:{args.port}[/bold green]")
        uvicorn.run("vanguard.api.server:app", host=args.host, port=args.port, reload=False)
    elif args.command == "scan":
        asyncio.run(run_scan_pipeline(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
