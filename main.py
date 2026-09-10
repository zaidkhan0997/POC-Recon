#!/usr/bin/env python3
import argparse
import sys
import os
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

from models import ReconResult, VerificationStatus, NameParts
from parser import normalize_domain, parse_person_name, extract_name_from_linkedin_slug
from generator import generate_email_patterns
from verifier import run_verification
from utils import export_results_json, export_results_csv, setup_logging

console = Console()


def display_banner() -> None:
    banner = """[bold cyan]POC-Recon[/bold cyan] [white]| Local-First Business Email Discovery & Verification Engine[/white]
[dim]Privacy-respecting • No web scraping • Direct DNS & SMTP protocol verification[/dim]"""
    console.print(Panel(banner, border_style="cyan", expand=False))


def display_summary_table(
    domain: str,
    person: NameParts,
    company_linkedin: Optional[str],
    person_linkedin: Optional[str],
    result: ReconResult
) -> None:
    table = Table(title="Target Reconnaissance Overview", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="bold white", width=24)
    table.add_column("Value", style="cyan")

    table.add_row("Target Domain", domain)
    table.add_row("Person Name", person.full_name)
    table.add_row("Parsed Components", f"First: {person.first_name} | Middle: {person.middle_name or 'N/A'} | Last: {person.last_name or 'N/A'}")

    if company_linkedin:
        table.add_row("Company LinkedIn", company_linkedin)
    if person_linkedin:
        table.add_row("Person LinkedIn", person_linkedin)

    if result.provider:
        table.add_row("Mail Provider", f"[bold green]{result.provider.name}[/bold green]")
        if result.provider.spf_record:
            table.add_row("SPF Record", f"[dim]{result.provider.spf_record}[/dim]")
        if result.provider.details:
            table.add_row("Provider Notes", f"[dim]{result.provider.details}[/dim]")

    if result.mx_records:
        mx_list = "\n".join([f"{mx.priority}: {mx.host}" for mx in result.mx_records[:3]])
        if len(result.mx_records) > 3:
            mx_list += f"\n... (+{len(result.mx_records) - 3} more)"
        table.add_row("MX Servers", mx_list)
    else:
        table.add_row("MX Servers", "[bold red]None Found[/bold red]")

    # Port 25 Status
    if result.port_25_open:
        table.add_row("Port 25 (SMTP)", "[bold green]✔ Reachable / Open[/bold green]")
    else:
        table.add_row("Port 25 (SMTP)", "[bold red]✖ Blocked by ISP / Firewall[/bold red]")

    # Catch-All Status
    if result.is_catch_all:
        table.add_row("Catch-All Status", "[bold yellow]⚠️ Enabled (Accepts All Recipient Probes)[/bold yellow]")
    else:
        table.add_row("Catch-All Status", "[bold green]✔ Disabled / Strict[/bold green]")

    console.print(table)
    console.print()


def display_results_table(result: ReconResult) -> None:
    table = Table(title="Candidate Email Verification Outcomes", show_header=True, header_style="bold blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Candidate Email", style="bold white")
    table.add_column("Pattern", style="cyan")
    table.add_column("Status", width=26)
    table.add_column("SMTP Code", justify="center", width=10)
    table.add_column("Diagnostics", style="dim")

    for i, c in enumerate(result.candidates, 1):
        status_str = str(c.status)
        if c.status == VerificationStatus.VALID:
            status_render = f"[bold green]{status_str}[/bold green]"
        elif c.status == VerificationStatus.INVALID:
            status_render = f"[red]{status_str}[/red]"
        elif c.status == VerificationStatus.CATCH_ALL_UNVERIFIED:
            status_render = f"[yellow]{status_str}[/yellow]"
        elif c.status == VerificationStatus.UNVERIFIED_PORT_BLOCKED:
            status_render = f"[cyan]{status_str}[/cyan]"
        elif c.status == VerificationStatus.UNVERIFIED_TIMEOUT:
            status_render = f"[magenta]{status_str}[/magenta]"
        else:
            status_render = f"[white]{status_str}[/white]"

        code_str = str(c.smtp_code) if c.smtp_code is not None else "-"
        diag_str = c.smtp_message or ""

        table.add_row(str(i), c.email, c.pattern_name, status_render, code_str, diag_str)

    console.print(table)
    console.print()


def display_port_25_help() -> None:
    help_text = """[bold yellow]Notice: Outbound TCP Port 25 is Blocked on this Network[/bold yellow]
Most consumer ISPs, public Wi-Fi, and default cloud VPS providers block Port 25 to mitigate spam.

[bold white]Bypass Options:[/bold white]
1. [bold cyan]SSH SOCKS5 Tunnel (Free & Instant):[/bold cyan]
   Run this in a separate terminal to tunnel through any remote server with open port 25:
   [bold green]ssh -D 1080 user@your-vps.com[/bold green]
   Then run POC-Recon with:
   [bold green]python main.py --proxy socks5://127.0.0.1:1080 ...[/bold green]

2. [bold cyan]Offline Pattern Generation / Dry-Run Mode:[/bold cyan]
   Generate candidate corporate patterns and DNS intelligence without SMTP verification:
   [bold green]python main.py --no-verify ...[/bold green]"""
    console.print(Panel(help_text, title="Port 25 Troubleshooting", border_style="yellow"))
    console.print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="POC-Recon: Discover and verify corporate business email addresses using pattern generation and DNS/SMTP verification."
    )
    parser.add_argument("--website", "-w", help="Target company website URL or domain (e.g. example.com or https://example.com)")
    parser.add_argument("--name", "-n", help="Target person's full name (e.g. 'Jane Doe' or 'Dr. John C. Smith, PhD')")
    parser.add_argument("--company-linkedin", help="Company LinkedIn URL (reference only)")
    parser.add_argument("--person-linkedin", help="Target person's LinkedIn profile URL (used for slug name fallback)")
    parser.add_argument("--proxy", help="SOCKS5 proxy URL to bypass Port 25 blocks (e.g. socks5://127.0.0.1:1080)")
    parser.add_argument("--dns-timeout", type=float, default=5.0, help="DNS resolution timeout in seconds (default: 5.0)")
    parser.add_argument("--smtp-timeout", type=float, default=8.0, help="SMTP connection timeout in seconds (default: 8.0)")
    parser.add_argument("--delay", type=float, default=0.5, help="Polite delay between SMTP queries in seconds (default: 0.5)")
    parser.add_argument("--no-verify", "--dry-run", action="store_true", help="Generate patterns and DNS intelligence without initiating SMTP connections")
    parser.add_argument("--output", "-o", help="Custom path for result export (e.g. results/output.json or results/output.csv)")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="both", help="Export file format (default: both)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()
    setup_logging(debug=args.debug)
    display_banner()

    # Interactive Prompt Fallbacks
    website = args.website
    if not website:
        website = Prompt.ask("[bold cyan]Enter Company Website URL or Domain[/bold cyan]")

    try:
        domain = normalize_domain(website)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    name_str = args.name
    person_linkedin = args.person_linkedin

    if not name_str and not person_linkedin:
        name_str = Prompt.ask("[bold cyan]Enter Target Person's Full Name[/bold cyan]")

    person: Optional[NameParts] = None

    if name_str:
        try:
            person = parse_person_name(name_str)
        except ValueError as e:
            console.print(f"[yellow]Warning: Could not parse entered name: {e}[/yellow]")

    # Fallback to LinkedIn slug if name was missing or unparseable
    if (not person or not person.first_name) and person_linkedin:
        slug_person = extract_name_from_linkedin_slug(person_linkedin)
        if slug_person:
            person = slug_person
            console.print(f"[dim]Inferred name '{person.full_name}' from LinkedIn profile slug.[/dim]")

    if not person or not person.first_name:
        console.print("[bold red]Error:[/bold red] Valid person name or LinkedIn profile slug is required.")
        sys.exit(1)

    # Candidate Pattern Generation
    console.print(f"[bold green]Generating corporate email patterns for:[/bold green] {person.full_name} @ {domain}")
    candidates = generate_email_patterns(
        first_name=person.first_name,
        middle_name=person.middle_name,
        last_name=person.last_name,
        domain=domain
    )

    if not candidates:
        console.print("[bold red]Error:[/bold red] Failed to generate email patterns.")
        sys.exit(1)

    console.print(f"[dim]Generated {len(candidates)} candidate corporate email patterns.[/dim]\n")

    # Verification Engine Run
    with console.status("[bold cyan]Executing reconnaissance and verification...[/bold cyan]", spinner="dots"):
        result = run_verification(
            domain=domain,
            person=person,
            candidates=candidates,
            dns_timeout=args.dns_timeout,
            smtp_timeout=args.smtp_timeout,
            delay=args.delay,
            proxy_url=args.proxy,
            dry_run=args.no_verify
        )

    # Output Presentation
    display_summary_table(
        domain=domain,
        person=person,
        company_linkedin=args.company_linkedin,
        person_linkedin=person_linkedin,
        result=result
    )

    if not result.port_25_open and not args.no_verify:
        display_port_25_help()

    display_results_table(result)

    # Exporting Results
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    json_path = os.path.join(results_dir, f"{domain}_{person.first_name.lower()}_results.json")
    csv_path = os.path.join(results_dir, f"{domain}_{person.first_name.lower()}_results.csv")

    if args.output:
        if args.output.endswith(".json"):
            json_path = args.output
            args.format = "json"
        elif args.output.endswith(".csv"):
            csv_path = args.output
            args.format = "csv"

    exported_files = []
    if args.format in ("json", "both"):
        export_results_json(result, json_path)
        exported_files.append(json_path)

    if args.format in ("csv", "both"):
        export_results_csv(result, csv_path)
        exported_files.append(csv_path)

    summary_text = f"[bold green]Reconnaissance Complete.[/bold green] Results persisted to:\n"
    for ef in exported_files:
        summary_text += f" • [cyan]{ef}[/cyan]\n"

    console.print(Panel(summary_text.strip(), title="Export Summary", border_style="green"))


if __name__ == "__main__":
    main()
