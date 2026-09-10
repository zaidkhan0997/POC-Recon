# POC-Recon: Local-First POC Business Email Discovery & Verification Tool

A lightweight, privacy-respecting, and modular Python tool designed to discover and verify Point of Contact (POC) business email addresses using corporate pattern generation, DNS MX resolution, and polite SMTP mailbox verification (`RCPT TO`).

---

## 📑 Table of Contents
- [1. Overview & Philosophy](#1-overview--philosophy)
- [2. Architecture & Data Flow](#2-architecture--data-flow)
- [3. Installation & Setup](#3-installation--setup)
- [4. Usage Guide](#4-usage-guide)
  - [Interactive Mode](#interactive-mode)
  - [CLI Mode](#cli-mode)
  - [Offline / Pattern-Only Mode (`--no-verify`)](#offline--pattern-only-mode---no-verify)
- [5. Port 25 ISP Blocking & Solutions](#5-port-25-isp-blocking--solutions)
  - [Why is Port 25 Blocked?](#why-is-port-25-blocked)
  - [Solution 1: SSH SOCKS5 Dynamic Tunnel (Recommended)](#solution-1-ssh-socks5-dynamic-tunnel-recommended)
  - [Solution 2: Pre-Flight Fast-Fail Diagnostic](#solution-2-pre-flight-fast-fail-diagnostic)
  - [Solution 3: DNS Intelligence & Provider Fingerprinting](#solution-3-dns-intelligence--provider-fingerprinting)
- [6. Catch-All Domains & Verification Realities](#6-catch-all-domains--verification-realities)
- [7. CLI Reference](#7-cli-reference)
- [8. Output Formats (JSON & CSV)](#8-output-formats-json--csv)
- [9. Running the Test Suite](#9-running-the-test-suite)
- [10. Ethical & Operational Boundaries](#10-ethical--operational-boundaries)

---

## 1. Overview & Philosophy

Most commercial email finders rely on costly third-party APIs, aggressive web crawlers, or questionable browser-based scraping of LinkedIn. **POC-Recon** takes a strictly local, protocol-level approach:

- **100% Local & Protocol-Driven:** Relies solely on DNS MX/TXT records and direct SMTP handshakes.
- **No LinkedIn Scraping or Headless Browsers:** LinkedIn profile URLs are used strictly for client-side slug extraction (e.g. parsing `jane-doe-12345` into `Jane Doe`) as an offline fallback.
- **RFC 5321 Safe Handshakes:** Connects to port 25, issues polite `EHLO`, `MAIL FROM`, and `RCPT TO` commands, records server diagnostic codes, and terminates with `QUIT`. **Never issues `DATA` or sends email.**
- **Honest Deliverability Classification:** Distinguishes between confirmed addresses (`VALID`), rejected mailboxes (`INVALID`), and ambiguous configurations (`CATCH-ALL / UNVERIFIED`, `PORT BLOCKED`).

---

## 2. Architecture & Data Flow

```text
Target Inputs: Website URL, Person Name, Optional LinkedIn URLs
                            │
                            ▼
     ┌──────────────────────────────────────────────┐
     │           parser.py (Normalization)          │
     │  - Domain syntax validation & extraction     │
     │  - Name parsing (strips honorifics/degrees)  │
     │  - LinkedIn slug fallback name extraction    │
     └──────────────────────┬───────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
┌───────────────────────────┐ ┌──────────────────────────────────────┐
│       generator.py        │ │             verifier.py              │
│ - Standard corporate      │ │ - DNS MX resolution & priority sort  │
│   patterns (first.last,   │ │ - SPF/MX mail provider fingerprint   │
│   flast, first_last, etc.)│ │ - Pre-flight Port 25 connectivity    │
│ - Unicode -> ASCII        │ │ - Catch-all canary probe             │
│ - Deterministic dedup     │ │ - Polite RCPT TO handshake           │
└─────────────┬─────────────┘ └──────────────────┬───────────────────┘
              │                                  │
              └─────────────────┬────────────────┘
                                │
                                ▼
     ┌──────────────────────────────────────────────┐
     │             main.py & utils.py               │
     │  - Rich terminal presentation & tables       │
     │  - Export to results.json and results.csv    │
     └──────────────────────────────────────────────┘
```

---

## 3. Installation & Setup

### Requirements
- Python 3.10+
- Linux, macOS, or Windows WSL

### Step-by-Step Installation

```bash
# Clone or navigate to the repository
cd /path/to/POC-Recon

# 1. Create a Python virtual environment
python3 -m venv .venv

# 2. Activate the virtual environment
# On Linux / macOS:
source .venv/bin/activate
# On Windows (PowerShell):
# .venv\Scripts\Activate.ps1

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Usage Guide

### Interactive Mode
If you run `main.py` without arguments, it launches interactive prompts with rich formatting:

```bash
python main.py
```

### CLI Mode
Provide the target company website and person's name directly via command-line arguments:

```bash
python main.py \
  --website "https://example.com" \
  --name "Jane Doe, MBA" \
  --company-linkedin "https://www.linkedin.com/company/example-corp" \
  --person-linkedin "https://www.linkedin.com/in/jane-doe-12345"
```

### Offline / Pattern-Only Mode (`--no-verify`)
If your current network blocks Port 25 or you only want to generate corporate email combinations and inspect DNS records without initiating SMTP network connections:

```bash
python main.py --website "github.com" --name "Nat Friedman" --no-verify
```

---

## 5. Port 25 ISP Blocking & Solutions

### Why is Port 25 Blocked?
TCP Port 25 is the standard MTA-to-MTA (Mail Transfer Agent) port used by mail servers to deliver messages between each other. 

In the late 1990s and early 2000s, malware and botnets infected residential computers to send millions of spam emails directly via port 25. As a result:
- **Almost all residential ISPs** (Comcast, AT&T, Vodafone, Jio, Airtel, etc.) block outbound TCP port 25 by default.
- **Major cloud hosting providers** (AWS EC2 default, GCP default, DigitalOcean, Azure) also block outbound port 25 on default/new accounts until an unblock request is approved.

When run on a network where port 25 is blocked, direct connections will immediately timeout or be refused.

---

### Solution 1: SSH SOCKS5 Dynamic Tunnel (Recommended)
If you have access to any remote VPS or server where outbound Port 25 is open (e.g., a cheap $3/month VPS on Hetzner, OVH, or Linode), you can route POC-Recon's SMTP verification through an SSH dynamic proxy in **one command**:

#### Step 1: Open the SSH Dynamic SOCKS5 Tunnel
In a separate terminal window, start a dynamic tunnel:

```bash
ssh -N -D 1080 user@your-remote-vps.com
```
*(This sets up a local SOCKS5 proxy listening on `127.0.0.1:1080` that forwards all TCP traffic through your remote server).*

#### Step 2: Run POC-Recon with `--proxy`
In your working terminal, run POC-Recon pointing to your local tunnel:

```bash
python main.py \
  --website "targetcorp.com" \
  --name "John Smith" \
  --proxy socks5://127.0.0.1:1080
```
POC-Recon will route all DNS resolution and SMTP verification handshakes through the SSH tunnel, completely bypassing your local ISP's Port 25 block.

---

### Solution 2: Pre-Flight Fast-Fail Diagnostic
Traditional email scripts attempt to verify each candidate email one-by-one. When port 25 is blocked, each candidate times out for 10 seconds, forcing you to wait 2+ minutes for a failed scan.

POC-Recon features an automated **Pre-Flight Port 25 Check**:
- It tests a single lightweight TCP connection to the primary MX server before touching candidates.
- If blocked, it **immediately stops**, flags candidates as `UNVERIFIED / PORT BLOCKED`, and displays an actionable troubleshooting panel instead of hanging.

---

### Solution 3: DNS Intelligence & Provider Fingerprinting
Even if Port 25 is blocked, POC-Recon queries the target domain's MX and SPF TXT records via standard DNS (UDP/TCP port 53, which is never blocked).

It fingerprints the email infrastructure:
- **Google Workspace (`aspmx.l.google.com`):** Uses strict user validation; returns 550 codes for non-existent users.
- **Microsoft 365 (`mail.protection.outlook.com`):** Edge gateways often accept all recipients and bounce invalid mailboxes internally.
- **Mimecast / Proofpoint:** Enterprise email security gateways that frequently employ greylisting (SMTP 451/421).
- **ProtonMail:** High-security mail provider with strict recipient boundaries.

---

## 6. Catch-All Domains & Verification Realities

### What is a Catch-All Domain?
A Catch-All (or Accept-All) mail server is configured to accept incoming emails sent to **any** address at the domain (e.g., `anything@company.com`), routing them into a central administrator inbox or filtering them later.

### Why SMTP Verification Fails on Catch-All Domains
If a domain has Catch-All enabled, its mail server responds with `250 OK` to **every single recipient**, even completely fictional addresses.

### How POC-Recon Handles It
1. Before testing any real candidate, POC-Recon sends a canary `RCPT TO` for a randomized, non-existent address:
   ```text
   catchall_probe_a1b2c3d4e5f6@company.com
   ```
2. If the server responds with `250 OK`, the domain is classified as **Catch-All Enabled**.
3. POC-Recon will **never** falsely mark candidate emails as `VALID` on a catch-all domain. Instead, candidates are marked:
   ```text
   [CATCH-ALL / UNVERIFIED]
   ```
   This ensures you are never misled by false positives.

---

## 7. CLI Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--website` | `-w` | Prompt | Target company website URL or domain (e.g. `example.com`) |
| `--name` | `-n` | Prompt | Target person's full name (e.g. `Jane Doe, MBA`) |
| `--company-linkedin` | - | None | Company LinkedIn URL (reference only) |
| `--person-linkedin` | - | None | Target person's LinkedIn URL (used for slug name fallback) |
| `--proxy` | - | None | SOCKS5 proxy URL for Port 25 routing (e.g. `socks5://127.0.0.1:1080`) |
| `--no-verify` / `--dry-run` | - | False | Offline mode: generates patterns & DNS data without SMTP checks |
| `--dns-timeout` | - | `5.0` | Timeout in seconds for DNS queries |
| `--smtp-timeout` | - | `8.0` | Timeout in seconds for SMTP connections |
| `--delay` | - | `0.5` | Polite delay between candidate SMTP checks in seconds |
| `--output` | `-o` | `results/` | Path for custom export file |
| `--format` | - | `both` | Export format: `json`, `csv`, or `both` |
| `--debug` | - | False | Enable verbose debugging and network logging |

---

## 8. Output Formats (JSON & CSV)

Results are automatically saved to the `results/` directory.

### Sample JSON (`results/<domain>_<name>_results.json`):
```json
{
  "timestamp": "2026-09-10T10:15:30.123456+00:00",
  "domain": "example.com",
  "person": {
    "first_name": "Jane",
    "middle_name": null,
    "last_name": "Doe",
    "raw_name": "Jane Doe, MBA",
    "full_name": "Jane Doe"
  },
  "provider": {
    "name": "Google Workspace",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "details": "Google Workspace mail servers return strict 550 codes for non-existent users."
  },
  "mx_records": [
    {
      "host": "aspmx.l.google.com",
      "priority": 1
    }
  ],
  "is_catch_all": false,
  "port_25_open": true,
  "candidates": [
    {
      "email": "jane.doe@example.com",
      "pattern": "first.last",
      "status": "VALID",
      "smtp_code": 250,
      "smtp_message": "Mailbox verified deliverable (250 OK)"
    },
    {
      "email": "jane@example.com",
      "pattern": "first",
      "status": "INVALID",
      "smtp_code": 550,
      "smtp_message": "Recipient rejected (550): 5.1.1 User unknown"
    }
  ]
}
```

### Sample CSV (`results/<domain>_<name>_results.csv`):
```csv
email,pattern,status,smtp_code,smtp_message,domain,primary_mx
jane.doe@example.com,first.last,VALID,250,Mailbox verified deliverable (250 OK),example.com,aspmx.l.google.com
jane@example.com,first,INVALID,550,Recipient rejected (550): 5.1.1 User unknown,example.com,aspmx.l.google.com
```

---

## 9. Running the Test Suite

The test suite runs **100% offline** without needing internet access. All DNS queries and SMTP network interactions are mocked:

```bash
# Run all unit tests
.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```

### What is Tested:
- **Parser (`test_parser.py`):** Scheme stripping, www removal, path/query cleanup, RFC domain validation, honorific removal (`Dr.`, `Prof.`), degree/credential stripping (`MBA`, `Ph.D.`, `PMP`), middle initial handling, LinkedIn slug parsing.
- **Generator (`test_generator.py`):** Standard corporate patterns, Unicode accent/diacritic conversion to ASCII (`René Müller` -> `rene.muller`), middle name patterns, deduplication and order preservation.
- **Verifier (`test_verifier.py`):** Mocked DNS MX priority sorting, provider fingerprinting, catch-all detection logic, SMTP 250/550/4xx mapping, and dry-run execution.
- **Utilities (`test_utils.py`):** JSON and CSV file export integrity.

---

## 10. Ethical & Operational Boundaries

1. **Non-Intrusive Handshakes:** POC-Recon connects, probes recipient availability, and immediately closes the session (`QUIT`). It **never** sends spam or message payloads.
2. **Rate-Limiting:** Incorporates a polite delay between candidate inquiries to avoid stressing remote mail servers.
3. **No Scraping:** Adheres strictly to open protocols (DNS and SMTP) and does not violate Terms of Service of social networking sites.
4. **Intended Use:** Designed for legitimate business communications, domain administration, security research, and deliverability verification.
