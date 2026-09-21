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


def export_results_txt(
    result: ReconResult,
    output_path: str,
    company_linkedin: Optional[str] = None,
    person_linkedin: Optional[str] = None
) -> None:
    """Exports reconnaissance results as a simple, human-readable plain text file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    primary_mx = result.mx_records[0].host if result.mx_records else "None"
    provider_name = result.provider.name if result.provider else "Unknown"
    spf_record = result.provider.spf_record if (result.provider and result.provider.spf_record) else "None"

    ts_str = result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if hasattr(result.timestamp, 'strftime') else str(result.timestamp)
    lines = [
        "=" * 78,
        "POC-RECON: BUSINESS EMAIL DISCOVERY & VERIFICATION REPORT",
        "=" * 78,
        f"Timestamp          : {ts_str}",
        f"Target Domain      : {result.target_domain}",
        f"Person Name        : {result.person.full_name}",
        f"Parsed Components  : First: {result.person.first_name} | Middle: {result.person.middle_name or 'N/A'} | Last: {result.person.last_name or 'N/A'}",
    ]

    if company_linkedin:
        lines.append(f"Company LinkedIn   : {company_linkedin}")
    if person_linkedin:
        lines.append(f"Person LinkedIn    : {person_linkedin}")

    lines.extend([
        "-" * 78,
        "MAIL INFRASTRUCTURE & SECURITY:",
        f"Mail Provider      : {provider_name}",
        f"SPF Record         : {spf_record}",
        f"Primary MX Host    : {primary_mx}",
        f"Port 25 (SMTP)     : {'Open / Reachable' if result.port_25_open else 'Blocked by ISP or Firewall'}",
        f"Catch-All Domain   : {'Yes (Accepts All Probes)' if result.is_catch_all else 'No (Strict Verification)'}",
        "-" * 78,
        "🎯 PRIMARY WORKING EMAIL:",
        f"Working Email      : {result.get_primary_candidate().email if result.get_primary_candidate() else 'None'}",
        f"Confidence Score   : {result.get_primary_candidate().confidence if result.get_primary_candidate() else 0}%",
        f"Pattern Format     : {result.get_primary_candidate().pattern_name if result.get_primary_candidate() else 'N/A'}",
        f"Verification Status: [{result.get_primary_candidate().status if result.get_primary_candidate() else 'N/A'}]",
        f"Diagnostics / Note : {(result.get_primary_candidate().smtp_message if result.get_primary_candidate() else None) or 'Standard provider pattern'}",
        "-" * 78,
        "CANDIDATE EMAIL OUTCOMES:",
        f"{'#':<4}{'Candidate Email':<32}{'Pattern':<14}{'Status':<24}{'Diagnostics'}",
        "-" * 78,
    ])

    for i, c in enumerate(result.candidates, 1):
        status_str = f"[{c.status}]"
        code_str = f"({c.smtp_code}) " if c.smtp_code else ""
        diag_str = f"{code_str}{c.smtp_message or ''}".strip()
        lines.append(f"{i:<4}{c.email:<32}{c.pattern_name:<14}{status_str:<24}{diag_str}")

    lines.extend([
        "=" * 78,
        f"Total Candidates: {len(result.candidates)} | Confirmed Valid: {len(result.get_valid_emails())}",
        "=" * 78,
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def export_results_html(
    result: ReconResult,
    output_path: str,
    company_linkedin: Optional[str] = None,
    person_linkedin: Optional[str] = None
) -> None:
    """Exports reconnaissance results into a standalone, modern interactive HTML website report."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    primary_mx = result.mx_records[0].host if result.mx_records else "None"
    provider_name = result.provider.name if result.provider else "Unknown"
    spf_record = result.provider.spf_record if (result.provider and result.provider.spf_record) else "None"
    provider_details = result.provider.details if (result.provider and result.provider.details) else ""
    timestamp_str = result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if hasattr(result.timestamp, 'strftime') else str(result.timestamp)

    valid_count = sum(1 for c in result.candidates if str(c.status) == "VALID")
    invalid_count = sum(1 for c in result.candidates if str(c.status) == "INVALID")
    other_count = len(result.candidates) - valid_count - invalid_count

    primary_cand = result.get_primary_candidate()
    primary_hero_html = ""
    if primary_cand:
        p_email = primary_cand.email.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        p_diag = (primary_cand.smtp_message or "Provider standard pattern match").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        primary_hero_html = f"""
        <div class="primary-hero-card" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(59, 130, 246, 0.12) 100%); border: 2px solid var(--accent-emerald); border-radius: 12px; padding: 24px; margin-bottom: 28px; box-shadow: 0 10px 25px -5px rgba(16, 185, 129, 0.2);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                <span style="font-weight: 700; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-emerald);">🎯 Primary Working Email Found</span>
                <span class="confidence-badge" style="background: rgba(59, 130, 246, 0.2); border: 1px solid var(--accent-blue); color: var(--accent-blue); font-weight: 700; font-size: 12px; padding: 4px 10px; border-radius: 9999px;">{primary_cand.confidence}% Confidence</span>
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
                <div>
                    <div style="font-size: 24px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em;">{p_email}</div>
                    <div style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">
                        Pattern: <strong style="color: var(--accent-blue);">{primary_cand.pattern_name}</strong> &nbsp;|&nbsp;
                        Status: <span class="badge badge-{str(primary_cand.status).lower()}">[{primary_cand.status}]</span>
                    </div>
                </div>
                <button onclick="copyText('{p_email}', this)" style="background: var(--accent-emerald); color: #000; font-weight: 700; font-size: 13px; border: none; padding: 10px 18px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 6px;">
                    📋 Copy Working Email
                </button>
            </div>
        </div>
        """

    # Build candidate rows
    candidate_rows = []
    for i, c in enumerate(result.candidates, 1):
        st = str(c.status)
        badge_class = "badge-other"
        if st == "VALID":
            badge_class = "badge-valid"
        elif st == "INVALID":
            badge_class = "badge-invalid"
        elif "CATCH-ALL" in st:
            badge_class = "badge-catchall"
        elif "PORT BLOCKED" in st:
            badge_class = "badge-blocked"

        diag = (f"({c.smtp_code}) " if c.smtp_code else "") + (c.smtp_message or "")
        safe_email = c.email.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        safe_diag = diag.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        candidate_rows.append(f"""
        <tr class="candidate-row" data-status="{st}" data-search="{safe_email} {c.pattern_name}">
            <td class="col-num">{i}</td>
            <td class="col-email">
                <span class="email-text">{safe_email}</span>
                <button class="copy-btn" onclick="copyText('{safe_email}', this)" title="Copy to clipboard">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    <span>Copy</span>
                </button>
            </td>
            <td class="col-pattern"><code>{c.pattern_name}</code></td>
            <td class="col-status"><span class="badge {badge_class}">{st}</span></td>
            <td class="col-code">{c.smtp_code if c.smtp_code is not None else "-"}</td>
            <td class="col-diag">{safe_diag}</td>
        </tr>
        """)

    candidate_rows_html = "\n".join(candidate_rows)

    # MX list
    mx_items = "".join([f"<li><span class='prio'>{m.priority}</span> {m.host}</li>" for m in result.mx_records]) if result.mx_records else "<li>No MX records found</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POC-Recon: {result.person.full_name} @ {result.target_domain}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #172033;
            --border: #1f2937;
            --border-highlight: #374151;
            --text: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --valid: #10b981;
            --valid-bg: rgba(16, 185, 129, 0.12);
            --valid-border: rgba(16, 185, 129, 0.3);
            --invalid: #f43f5e;
            --invalid-bg: rgba(244, 63, 94, 0.12);
            --invalid-border: rgba(244, 63, 94, 0.3);
            --catchall: #f59e0b;
            --catchall-bg: rgba(245, 158, 11, 0.12);
            --catchall-border: rgba(245, 158, 11, 0.3);
            --blocked: #06b6d4;
            --blocked-bg: rgba(6, 182, 212, 0.12);
            --blocked-border: rgba(6, 182, 212, 0.3);
            --other: #8b5cf6;
            --other-bg: rgba(139, 92, 246, 0.12);
            --other-border: rgba(139, 92, 246, 0.3);
            --radius: 12px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(180deg, rgba(31, 41, 55, 0.6) 0%, rgba(17, 24, 39, 0.8) 100%);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
        }}
        header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 3px;
            background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .brand-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--accent-glow);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 0.35rem 0.8rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }}
        .timestamp {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        h1 {{
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            margin-bottom: 0.25rem;
        }}
        h1 span.person {{ color: #ffffff; }}
        h1 span.at {{ color: var(--text-muted); font-weight: 400; }}
        h1 span.domain {{ color: var(--accent); }}
        .subtitle {{
            color: var(--text-muted);
            font-size: 0.95rem;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        .stat-title {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 600;
        }}
        .stat-value {{
            font-size: 1.4rem;
            font-weight: 700;
            color: #ffffff;
        }}
        .stat-value.valid {{ color: var(--valid); }}
        .stat-value.blocked {{ color: var(--invalid); }}
        .stat-sub {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }}

        /* Two column layout for details */
        .details-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 768px) {{
            .details-grid {{ grid-template-columns: 1fr; }}
        }}
        .info-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.5rem;
        }}
        .info-card h2 {{
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.75rem;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            font-size: 0.9rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }}
        .info-label {{ color: var(--text-muted); }}
        .info-val {{ color: #ffffff; font-weight: 500; text-align: right; word-break: break-all; }}
        .info-val a {{ color: var(--accent); text-decoration: none; }}
        .info-val a:hover {{ text-decoration: underline; }}
        ul.mx-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        ul.mx-list li {{
            font-size: 0.85rem;
            padding: 0.4rem 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        ul.mx-list span.prio {{
            background: var(--border);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }}

        /* Table Card */
        .table-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.5rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }}
        .table-toolbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .search-box {{
            position: relative;
            min-width: 280px;
        }}
        .search-box input {{
            width: 100%;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.6rem 0.8rem 0.6rem 2.2rem;
            color: var(--text);
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-box input:focus {{ border-color: var(--accent); }}
        .search-box svg {{
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            stroke: var(--text-muted);
        }}
        .filter-group {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover {{
            background: var(--surface-hover);
            color: var(--text);
        }}
        .filter-btn.active {{
            background: var(--accent-glow);
            color: var(--accent);
            border-color: rgba(56, 189, 248, 0.4);
            font-weight: 600;
        }}

        /* Table */
        .table-wrapper {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}
        th {{
            color: var(--text-muted);
            font-weight: 600;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            vertical-align: middle;
        }}
        tr:hover td {{
            background: var(--surface-hover);
        }}
        .col-num {{ width: 40px; color: var(--text-muted); font-size: 0.8rem; }}
        .col-email {{
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .email-text {{ font-family: monospace; font-size: 0.95rem; }}
        .copy-btn {{
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .copy-btn:hover {{
            background: rgba(255, 255, 255, 0.12);
            color: #ffffff;
        }}
        .copy-btn.copied {{
            background: var(--valid-bg);
            color: var(--valid);
            border-color: var(--valid-border);
        }}
        code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--accent);
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.03em;
        }}
        .badge-valid {{ background: var(--valid-bg); color: var(--valid); border: 1px solid var(--valid-border); }}
        .badge-invalid {{ background: var(--invalid-bg); color: var(--invalid); border: 1px solid var(--invalid-border); }}
        .badge-catchall {{ background: var(--catchall-bg); color: var(--catchall); border: 1px solid var(--catchall-border); }}
        .badge-blocked {{ background: var(--blocked-bg); color: var(--blocked); border: 1px solid var(--blocked-border); }}
        .badge-other {{ background: var(--other-bg); color: var(--other); border: 1px solid var(--other-border); }}
        .col-code {{ font-family: monospace; color: var(--text-muted); }}
        .col-diag {{ color: var(--text-muted); font-size: 0.85rem; }}

        footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <span class="brand-badge">POC-Recon Report</span>
                <span class="timestamp">{timestamp_str}</span>
            </div>
            <h1>
                <span class="person">{result.person.full_name}</span>
                <span class="at">@</span>
                <span class="domain">{result.target_domain}</span>
            </h1>
            <p class="subtitle">Local-first corporate email discovery and protocol verification outcome</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-title">Candidates Generated</span>
                <span class="stat-value">{len(result.candidates)}</span>
                <span class="stat-sub">Deterministic corporate patterns</span>
            </div>
            <div class="stat-card">
                <span class="stat-title">Verified Deliverable</span>
                <span class="stat-value valid">{valid_count}</span>
                <span class="stat-sub">Confirmed valid via RCPT TO</span>
            </div>
            <div class="stat-card">
                <span class="stat-title">Mail Provider</span>
                <span class="stat-value" style="font-size: 1.15rem;">{provider_name}</span>
                <span class="stat-sub">{provider_details or 'DNS SPF/MX intelligence'}</span>
            </div>
            <div class="stat-card">
                <span class="stat-title">Port 25 (SMTP)</span>
                <span class="stat-value {'valid' if result.port_25_open else 'blocked'}">{'Open' if result.port_25_open else 'Blocked'}</span>
                <span class="stat-sub">{'Outbound connection successful' if result.port_25_open else 'ISP or firewall filtered'}</span>
            </div>
        </div>

        <div class="details-grid">
            <div class="info-card">
                <h2>Target Information</h2>
                <div class="info-row"><span class="info-label">Domain</span><span class="info-val">{result.target_domain}</span></div>
                <div class="info-row"><span class="info-label">Full Name</span><span class="info-val">{result.person.full_name}</span></div>
                <div class="info-row"><span class="info-label">Parsed First Name</span><span class="info-val">{result.person.first_name}</span></div>
                <div class="info-row"><span class="info-label">Parsed Middle Name</span><span class="info-val">{result.person.middle_name or 'N/A'}</span></div>
                <div class="info-row"><span class="info-label">Parsed Last Name</span><span class="info-val">{result.person.last_name or 'N/A'}</span></div>
                {"<div class='info-row'><span class='info-label'>Person LinkedIn</span><span class='info-val'><a href='" + person_linkedin + "' target='_blank'>" + person_linkedin + "</a></span></div>" if person_linkedin else ""}
                {"<div class='info-row'><span class='info-label'>Company LinkedIn</span><span class='info-val'><a href='" + company_linkedin + "' target='_blank'>" + company_linkedin + "</a></span></div>" if company_linkedin else ""}
            </div>

            <div class="info-card">
                <h2>Infrastructure & DNS</h2>
                <div class="info-row"><span class="info-label">Primary MX</span><span class="info-val">{primary_mx}</span></div>
                <div class="info-row"><span class="info-label">Catch-All Status</span><span class="info-val">{'⚠️ Catch-All Enabled' if result.is_catch_all else '✔ Disabled / Strict'}</span></div>
                <div class="info-row"><span class="info-label">SPF Record</span><span class="info-val" style="font-family: monospace; font-size: 0.8rem;">{spf_record}</span></div>
                <div class="info-row" style="border: none;"><span class="info-label">MX Records:</span></div>
                <ul class="mx-list">{mx_items}</ul>
            </div>
        </div>

        <div class="table-card">
            <div class="table-toolbar">
                <div class="search-box">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                    <input type="text" id="searchInput" placeholder="Search candidate email or pattern..." oninput="filterTable()">
                </div>
                <div class="filter-group">
                    <button class="filter-btn active" onclick="setFilter('ALL', this)">All ({len(result.candidates)})</button>
                    <button class="filter-btn" onclick="setFilter('VALID', this)">Valid ({valid_count})</button>
                    <button class="filter-btn" onclick="setFilter('INVALID', this)">Invalid ({invalid_count})</button>
                    <button class="filter-btn" onclick="setFilter('OTHER', this)">Other ({other_count})</button>
                </div>
            </div>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th class="col-num">#</th>
                            <th>Candidate Email</th>
                            <th>Pattern</th>
                            <th>Status</th>
                            <th>SMTP Code</th>
                            <th>Diagnostics</th>
                        </tr>
                    </thead>
                    <tbody id="candidateBody">
                        {candidate_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            POC-Recon &bull; Protocol-Level Verification (RFC 5321) &bull; Generated locally without scraping or third-party APIs
        </footer>
    </div>

    <script>
        let currentFilter = 'ALL';

        function setFilter(filter, btn) {{
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterTable();
        }}

        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.candidate-row');

            rows.forEach(row => {{
                const status = row.getAttribute('data-status');
                const search = row.getAttribute('data-search').toLowerCase();
                const matchesSearch = search.includes(query);

                let matchesFilter = true;
                if (currentFilter === 'VALID') {{
                    matchesFilter = (status === 'VALID');
                }} else if (currentFilter === 'INVALID') {{
                    matchesFilter = (status === 'INVALID');
                }} else if (currentFilter === 'OTHER') {{
                    matchesFilter = (status !== 'VALID' && status !== 'INVALID');
                }}

                if (matchesSearch && matchesFilter) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function copyText(text, btn) {{
            navigator.clipboard.writeText(text).then(() => {{
                const span = btn.querySelector('span');
                const originalText = span.textContent;
                span.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {{
                    span.textContent = originalText;
                    btn.classList.remove('copied');
                }}, 1800);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

