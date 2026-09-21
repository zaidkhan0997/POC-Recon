#!/usr/bin/env python3
import argparse
import os
import sys
import webbrowser
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
from utils import (
    export_results_json,
    export_results_csv,
    export_results_txt,
    export_results_html,
    setup_logging,
)

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

    # Verification Mode
    if getattr(result, "verification_method", None):
        table.add_row("Verification Mode", f"[bold cyan]{result.verification_method}[/bold cyan]")

    # Catch-All Status
    if result.is_catch_all:
        table.add_row("Catch-All Status", "[bold yellow]⚠️ Enabled (Accepts All Recipient Probes)[/bold yellow]")
    else:
        table.add_row("Catch-All Status", "[bold green]✔ Disabled / Strict[/bold green]")

    console.print(table)
    console.print()


def panel_color(status: VerificationStatus) -> str:
    if status == VerificationStatus.VALID:
        return "green"
    elif status == VerificationStatus.INVALID:
        return "red"
    elif status == VerificationStatus.CATCH_ALL_UNVERIFIED:
        return "yellow"
    elif status == VerificationStatus.UNVERIFIED_PORT_BLOCKED:
        return "cyan"
    return "white"

def display_results_table(result: ReconResult) -> None:
    best = result.get_primary_candidate()
    if best:
        if best.status == VerificationStatus.VALID:
            stat_style = "[bold green]CONFIRMED VALID (100% Deliverable)[/bold green]"
            panel_border = "green"
        else:
            stat_style = f"[{panel_color(best.status)}]{best.status}[/{panel_color(best.status)}]"
            panel_border = "cyan"

        diag = best.smtp_message or "Standard corporate pattern match"
        hero_text = f"""[bold white]Target Person :[/bold white] [bold]{result.person.full_name}[/bold]
[bold white]Working Email :[/bold white] [bold green]{best.email}[/bold green]
[bold white]Pattern Format:[/bold white] [magenta]{best.pattern_name}[/magenta]
[bold white]Status        :[/bold white] {stat_style}
[bold white]Diagnostics   :[/bold white] [dim]{diag}[/dim]"""
        console.print(Panel(hero_text, title="[bold green]🎯 Primary Working Email Found[/bold green]", border_style=panel_border))
        console.print()

    table = Table(title="Candidate Email Verification Outcomes", show_header=True, header_style="bold blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Candidate Email", style="bold white", no_wrap=True)
    table.add_column("Pattern", style="cyan", no_wrap=True)
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


def display_simple_text_summary(
    domain: str,
    person: NameParts,
    result: ReconResult,
    company_linkedin: Optional[str] = None,
    person_linkedin: Optional[str] = None
) -> None:
    """Displays results in a clean, copy-pasteable simple text format directly on screen."""
    primary_mx = result.mx_records[0].host if result.mx_records else "None"
    provider_name = result.provider.name if result.provider else "Unknown"

    text_output = []
    text_output.append("=" * 72)
    text_output.append("          POC-RECON RESULTS: SIMPLE TEXT FORMAT (COPY & PASTE)")
    text_output.append("=" * 72)
    text_output.append(f"Domain    : {domain}")
    text_output.append(f"Target    : {person.full_name}")
    if person_linkedin:
        text_output.append(f"LinkedIn  : {person_linkedin}")
    if company_linkedin:
        text_output.append(f"Company LI: {company_linkedin}")
    text_output.append(f"Provider  : {provider_name} | Primary MX: {primary_mx}")
    text_output.append(f"Port 25   : {'Reachable' if result.port_25_open else 'Blocked by ISP'}")
    text_output.append(f"Catch-All : {'Enabled' if result.is_catch_all else 'Disabled/Strict'}")
    text_output.append("-" * 72)

    best = result.get_primary_candidate()
    if best:
        text_output.append("🎯 PRIMARY WORKING EMAIL:")
        text_output.append(f"Email     : {best.email}")
        text_output.append(f"Pattern   : {best.pattern_name}")
        text_output.append(f"Status    : [{best.status}]")
        text_output.append(f"Notes     : {best.smtp_message or 'Standard provider pattern'}")
        text_output.append("-" * 72)

    text_output.append(f"{'#':<4}{'Candidate Email':<32}{'Status':<16}{'Code / Notes'}")
    text_output.append("-" * 72)

    for i, c in enumerate(result.candidates, 1):
        status_tag = f"[{c.status}]"
        code_str = f"({c.smtp_code}) " if c.smtp_code else ""
        diag = f"{code_str}{c.smtp_message or ''}".strip()
        text_output.append(f"{i:<4}{c.email:<32}{status_tag:<16}{diag}")

    text_output.append("=" * 72)
    text_output.append(f"Summary: {len(result.candidates)} candidates | {len(result.get_valid_emails())} confirmed valid")
    text_output.append("=" * 72)

    simple_text_str = "\n".join(text_output)
    console.print(Panel(simple_text_str, title="[bold green]Simple Text Format[/bold green]", border_style="green", expand=False))
    console.print()


def display_port_25_help(result: Optional[ReconResult] = None) -> None:
    if result and getattr(result, "verification_method", "") == "HTTPS Cloud & Identity Verifier":
        valid_count = len(result.get_valid_emails())
        help_text = f"""[bold green]✔ Automatic HTTPS Cloud Fallback Engaged[/bold green]
Outbound Port 25 (SMTP) is blocked on your local network/ISP.
POC-Recon engaged [bold cyan]HTTPS Cloud & Identity Verifiers[/bold cyan] (Microsoft 365 Cloud Directory, Public OpenPGP Keyrings, and GitHub Commits).

[bold white]Outcome:[/bold white] Successfully analyzed candidates over Port 443 with [bold green]{valid_count} confirmed valid email(s)[/bold green]! Zero external VPS or OCI setup required."""
        console.print(Panel(help_text, title="Cloud Verification Active (Zero Port 25)", border_style="green"))
        console.print()
        return

    help_text = """[bold yellow]Notice: Outbound TCP Port 25 is Blocked on this Network[/bold yellow]
Most consumer ISPs, public Wi-Fi, and default cloud VPS providers block Port 25 to mitigate spam.

[bold white]Bypass Options:[/bold white]
1. [bold cyan]Automatic HTTPS Cloud Fallback (Default):[/bold cyan]
   POC-Recon queries Microsoft 365 Cloud Directory and OpenPGP keyrings over HTTPS (Port 443) without needing Port 25.

2. [bold cyan]SSH SOCKS5 Tunnel (Optional for raw SMTP):[/bold cyan]
   Run in a separate terminal: [bold green]ssh -N -D 1080 user@your-vps.com[/bold green]
   Then run: [bold green]python main.py --proxy socks5://127.0.0.1:1080 ...[/bold green]

3. [bold cyan]Offline Pattern Generation / Dry-Run Mode:[/bold cyan]
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
    parser.add_argument("--no-cloud-fallback", action="store_true", help="Disable automatic HTTPS cloud fallback when Port 25 is blocked")
    parser.add_argument("--output", "-o", help="Custom path for result export (e.g. results/output.json or results/output.csv)")
    parser.add_argument("--format", choices=["json", "csv", "txt", "html", "all", "both"], default="all", help="Export format: all, json, csv, txt, or html (default: all)")
    parser.add_argument("--open", "--open-browser", action="store_true", help="Automatically open the generated HTML website report in your web browser")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args()
    setup_logging(debug=args.debug)
    display_banner()

    is_interactive = not bool(args.website and (args.name or args.person_linkedin))

    # Interactive Prompt Flow
    website = args.website
    if not website:
        website = Prompt.ask("[bold cyan]1. Enter Target Company Website URL or Domain[/bold cyan] [dim](e.g. example.com or https://company.com)[/dim]")

    try:
        domain = normalize_domain(website)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    name_str = args.name
    person_linkedin = args.person_linkedin
    company_linkedin = args.company_linkedin

    if is_interactive:
        if not name_str:
            name_str = Prompt.ask("[bold cyan]2. Enter Target Person's Full Name[/bold cyan] [dim](e.g. 'Jane Doe', or leave blank if using LinkedIn)[/dim]", default="")
            if not name_str.strip():
                name_str = None

        if not person_linkedin:
            person_linkedin = Prompt.ask("[bold cyan]3. Enter Person's LinkedIn Profile URL (Optional)[/bold cyan] [dim](e.g. https://www.linkedin.com/in/jane-doe-12345)[/dim]", default="")
            if not person_linkedin.strip():
                person_linkedin = None

        if not company_linkedin:
            company_linkedin = Prompt.ask("[bold cyan]4. Enter Company LinkedIn URL (Optional)[/bold cyan] [dim](e.g. https://www.linkedin.com/company/example)[/dim]", default="")
            if not company_linkedin.strip():
                company_linkedin = None

        if not args.no_verify:
            run_live = Prompt.ask("[bold cyan]5. Run Live SMTP Verification?[/bold cyan] [dim](y: live DNS & SMTP, n: offline pattern dry-run)[/dim]", choices=["y", "n"], default="y")
            if run_live.lower() == "n":
                args.no_verify = True

    # Parse Person Name
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
        console.print("[bold red]Error:[/bold red] A valid person name or LinkedIn profile URL slug is required.")
        sys.exit(1)

    # Candidate Pattern Generation
    console.print(f"\n[bold green]Generating corporate email patterns for:[/bold green] [bold white]{person.full_name}[/bold white] @ [bold cyan]{domain}[/bold cyan]")
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
    status_msg = "[bold cyan]Generating offline patterns & DNS intelligence...[/bold cyan]" if args.no_verify else "[bold cyan]Executing reconnaissance and live verification...[/bold cyan]"
    with console.status(status_msg, spinner="dots"):
        result = run_verification(
            domain=domain,
            person=person,
            candidates=candidates,
            dns_timeout=args.dns_timeout,
            smtp_timeout=args.smtp_timeout,
            delay=args.delay,
            proxy_url=args.proxy,
            dry_run=args.no_verify,
            cloud_fallback=not args.no_cloud_fallback
        )

    # Screen Display: Summary Table
    display_summary_table(
        domain=domain,
        person=person,
        company_linkedin=company_linkedin,
        person_linkedin=person_linkedin,
        result=result
    )

    if not result.port_25_open and not args.no_verify:
        display_port_25_help(result)

    # Screen Display: Candidate Outcomes Table
    display_results_table(result)

    # Screen Display: Simple Text Format (Clean, Copy-Pasteable)
    display_simple_text_summary(
        domain=domain,
        person=person,
        result=result,
        company_linkedin=company_linkedin,
        person_linkedin=person_linkedin
    )

    # Exporting Results
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    base_name = f"{domain}_{person.first_name.lower()}"
    json_path = os.path.join(results_dir, f"{base_name}_results.json")
    csv_path = os.path.join(results_dir, f"{base_name}_results.csv")
    txt_path = os.path.join(results_dir, f"{base_name}_results.txt")
    html_path = os.path.join(results_dir, f"{base_name}_report.html")

    if args.output:
        if args.output.endswith(".json"):
            json_path = args.output
            args.format = "json"
        elif args.output.endswith(".csv"):
            csv_path = args.output
            args.format = "csv"
        elif args.output.endswith(".txt"):
            txt_path = args.output
            args.format = "txt"
        elif args.output.endswith(".html"):
            html_path = args.output
            args.format = "html"

    exported_files = []
    formats = [args.format] if args.format != "all" and args.format != "both" else ["json", "csv", "txt", "html"]

    if "json" in formats:
        export_results_json(result, json_path)
        exported_files.append(("JSON Data", json_path))

    if "csv" in formats:
        export_results_csv(result, csv_path)
        exported_files.append(("CSV Table", csv_path))

    if "txt" in formats:
        export_results_txt(result, txt_path, company_linkedin=company_linkedin, person_linkedin=person_linkedin)
        exported_files.append(("Simple Text Format", txt_path))

    if "html" in formats:
        export_results_html(result, html_path, company_linkedin=company_linkedin, person_linkedin=person_linkedin)
        exported_files.append(("Interactive Website Report", html_path))

    summary_text = "[bold green]Reconnaissance Complete.[/bold green] Results persisted to:\n"
    for label, ef in exported_files:
        abs_p = os.path.abspath(ef)
        summary_text += f" • [bold white]{label}:[/bold white] [cyan]{ef}[/cyan] [dim](file://{abs_p})[/dim]\n"

    console.print(Panel(summary_text.strip(), title="Export Summary", border_style="green"))

    # Browser Opening Option for HTML Website Report
    if "html" in formats and os.path.exists(html_path):
        open_report = args.open
        if not open_report and is_interactive:
            open_choice = Prompt.ask("\n[bold cyan]Open website report in your web browser now?[/bold cyan]", choices=["y", "n"], default="y")
            open_report = (open_choice.lower() == "y")

        if open_report:
            web_url = f"file://{os.path.abspath(html_path)}"
            console.print(f"[bold green]Opening website in browser:[/bold green] [cyan]{web_url}[/cyan]")
            webbrowser.open(web_url)

    if is_interactive:
        Prompt.ask("\n[dim]Press Enter to exit...[/dim]", default="")


if __name__ == "__main__":
    main()

