# POC-Recon: Local-First POC Business Email Discovery & Verification Tool

A lightweight, privacy-respecting, and modular tool designed to discover and verify Point of Contact (POC) business email addresses using corporate pattern intelligence, DNS MX resolution, polite SMTP mailbox verification (`RCPT TO`), and HTTPS Cloud Directory fallback.

> **🎯 Single Working Email Focus:** Unlike tools that dump 10+ confusing permutations, POC-Recon scores candidates with an enterprise intelligence engine to spotlight **the 1 primary working email** (with confidence score) by default. Pass `--all` anytime you wish to inspect all permutations.

---

## 📑 Table of Contents
- [1. Overview & Philosophy](#1-overview--philosophy)
- [2. Architecture & Data Flow](#2-architecture--data-flow)
- [3. Quick Installation (Standalone Executables)](#3-quick-installation-standalone-executables)
  - [🪟 Windows (.exe)](#-windows-exe)
  - [🐧 Linux](#-linux)
  - [🍏 macOS](#-macos)
  - [⚡ Native Go Engine (Optional)](#-native-go-engine-optional)
- [4. Usage Guide](#4-usage-guide)
  - [Interactive Mode](#interactive-mode)
  - [CLI Mode](#cli-mode)
  - [Inspect All Permutations (`--all`)](#inspect-all-permutations---all)
  - [Offline / Pattern-Only Mode (`--no-verify`)](#offline--pattern-only-mode---no-verify)
- [5. Intelligence & Confidence Scoring](#5-intelligence--confidence-scoring)
- [6. Port 25 ISP Blocking & Solutions](#6-port-25-isp-blocking--solutions)
  - [Why is Port 25 Blocked?](#why-is-port-25-blocked)
  - [Solution 1: Automatic HTTPS Cloud Fallback (Zero Port 25)](#solution-1-automatic-https-cloud-fallback-zero-port-25--100-free)
  - [Solution 2: SSH SOCKS5 Dynamic Tunnel (For Remote SMTP)](#solution-2-ssh-socks5-dynamic-tunnel-for-remote-smtp)
  - [Solution 3: Pre-Flight Fast-Fail Diagnostic](#solution-3-pre-flight-fast-fail-diagnostic)
  - [Solution 4: DNS Intelligence & Provider Fingerprinting](#solution-4-dns-intelligence--provider-fingerprinting)
- [7. Catch-All Domains & Verification Realities](#7-catch-all-domains--verification-realities)
- [8. CLI Reference](#8-cli-reference)
- [9. Output Formats (JSON, CSV, Plain Text & Interactive Website)](#9-output-formats-json-csv-plain-text--interactive-website)
- [10. Running the Test Suite](#10-running-the-test-suite)
- [11. Ethical & Operational Boundaries](#11-ethical--operational-boundaries)
- [12. License](#12-license)

---

## 1. Overview & Philosophy

Most commercial email finders rely on costly third-party APIs, aggressive web crawlers, or questionable browser-based scraping of LinkedIn. **POC-Recon** takes a strictly local, protocol-level approach:

- **100% Local & Protocol-Driven:** Relies on DNS MX/SPF records, direct SMTP handshakes, and public cryptographic/cloud directory checks.
- **Single Working Email Spotlight:** Rather than flooding users with 11 guesses, POC-Recon ranks permutations using live validation and enterprise naming statistics to present the single winning email address.
- **No LinkedIn Scraping or Headless Browsers:** LinkedIn profile URLs are used strictly for client-side slug extraction (e.g. parsing `jane-doe-12345` into `Jane Doe`) as an offline fallback.
- **RFC 5321 Safe Handshakes:** Connects to port 25, issues polite `EHLO`, `MAIL FROM`, and `RCPT TO` commands, records server diagnostic codes, and terminates with `QUIT`. **Never issues `DATA` or sends email.**
- **Early-Exit Short-Circuit:** Once an email is 100% verified via SMTP or Cloud Directory, POC-Recon immediately short-circuits to deliver instant results without needless network calls.
- **Honest Deliverability Classification:** Clearly distinguishes between confirmed addresses (`VALID`), rejected mailboxes (`INVALID`), and ambiguous configurations (`CATCH-ALL / UNVERIFIED`, `PORT BLOCKED`).

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
└─────────────┬─────────────┘ │ - HTTPS Cloud Fallback (Port 443)    │
              │               │ - Confidence Scoring & Early Exit    │
              │               └──────────────────┬───────────────────┘
              │                                  │
              └─────────────────┬────────────────┘
                                │
                                ▼
     ┌──────────────────────────────────────────────┐
     │             main.py & utils.py               │
     │  - 🎯 Primary Working Email Spotlight Box    │
     │  - Optional --all permutation view           │
     │  - Rich terminal presentation & summary      │
     │  - Export to JSON, CSV, TXT & HTML Report    │
     └──────────────────────────────────────────────┘
```

---

## 3. Quick Installation (Standalone Executables)

No Python, Git, or virtual environment setup required! POC-Recon is distributed as single-file, zero-dependency standalone executables for all major platforms.

---

### 🪟 Windows (.exe)

#### Method 1: 1-Click PowerShell Installer (Recommended)
Open **PowerShell** and run:
```powershell
irm https://raw.githubusercontent.com/zaidkhan0997/POC-Recon/main/install.ps1 | iex
```
*This automatically installs POC-Recon, adds it to your PATH, and creates a Desktop shortcut!*

#### Method 2: Direct Download
1. Download **[poc-recon-windows-x64.exe](https://github.com/zaidkhan0997/POC-Recon/releases/latest)** from the latest release.
2. Double-click the `.exe` to start the interactive prompt, or run it in Command Prompt / PowerShell:
   ```cmd
   poc-recon-windows-x64.exe --website example.com --name "Jane Doe"
   ```

---

### 🐧 Linux

Install with a single command:
```bash
curl -sSL https://raw.githubusercontent.com/zaidkhan0997/POC-Recon/main/install.sh | bash
```

Or manually download and run:
```bash
# 1. Download the latest Linux binary
curl -L -o poc-recon https://github.com/zaidkhan0997/POC-Recon/releases/latest/download/poc-recon-linux-x64

# 2. Make it executable
chmod +x poc-recon

# 3. Run it
./poc-recon
```

---

### 🍏 macOS (Apple Silicon & Intel)

Install with a single command:
```bash
curl -sSL https://raw.githubusercontent.com/zaidkhan0997/POC-Recon/main/install.sh | bash
```

Or manually download and run:
```bash
# 1. Download the latest macOS binary (arm64 for Apple Silicon, x64 for Intel)
curl -L -o poc-recon https://github.com/zaidkhan0997/POC-Recon/releases/latest/download/poc-recon-macos-arm64

# 2. Make it executable
chmod +x poc-recon

# 3. Run it
./poc-recon
```

---

### ⚡ Native Go Engine (Optional)

For extreme performance and ultra-fast concurrent checks, a native Go engine is available in [`poc-recon-go/`](poc-recon-go):
- **Statically Linked Binary:** ~4 MB single binary, zero dependencies.
- **Instant Cross-Compilation:**
  ```bash
  cd poc-recon-go
  go build -o poc-recon cmd/main.go
  ```

---

## 4. Usage Guide

### Interactive Mode
If you run `poc-recon` without arguments, it launches interactive prompts asking for all target details and verification mode (on Windows, just double-click `poc-recon-windows-x64.exe`!):

```bash
poc-recon
```
**Interactive prompts provided:**
1. **Target Company Website / Domain:** (e.g. `example.com` or `https://example.com`)
2. **Target Person's Full Name:** (e.g. `Jane Doe` or `Dr. John C. Smith, MBA`, or leave blank if using LinkedIn)
3. **Person's LinkedIn Profile URL:** (e.g. `https://www.linkedin.com/in/jane-doe-12345`)
4. **Company LinkedIn URL:** (e.g. `https://www.linkedin.com/company/example-corp`)
5. **Live Verification Mode:** choose `y` for live DNS + SMTP verification, or `n` for offline pattern generation
6. **Open in Browser:** prompt to automatically open the generated interactive website report

---

### CLI Mode
Provide the target company website and person's name directly via command-line arguments:

```bash
poc-recon \
  --website "https://example.com" \
  --name "Jane Doe, MBA" \
  --company-linkedin "https://www.linkedin.com/company/example-corp" \
  --person-linkedin "https://www.linkedin.com/in/jane-doe-12345" \
  --open
```
*(On Windows: replace `poc-recon` with `poc-recon-windows-x64.exe`)*

#### Default Spotlight Output:
```text
╭─────────────────────── 🎯 Primary Working Email Found ───────────────────────╮
│ Target Person : Jane Doe                                                     │
│ Working Email : jane.doe@example.com                                         │
│ Confidence    : 95%                                                          │
│ Pattern Format: first.last                                                   │
│ Status        : HIGH CONFIDENCE (95%) - Standard Provider Pattern            │
│ Diagnostics   : Port 25 blocked by ISP; HTTPS alternative checks             │
│ non-conclusive                                                               │
╰──────────────────────────────────────────────────────────────────────────────╯

💡 1 working email identified out of 11 permutations evaluated. Pass --all to 
inspect all permutations.
```

---

### Inspect All Permutations (`--all`)
If you want to view the full table of all 11 candidate permutations alongside their individual statuses, pass `--all` (or `--show-all`):

```bash
poc-recon --website "example.com" --name "Jane Doe" --all
```

---

### Offline / Pattern-Only Mode (`--no-verify`)
If your current network blocks Port 25 or you only want to generate corporate email combinations and inspect DNS records without initiating SMTP network connections:

```bash
poc-recon --website "github.com" --name "Nat Friedman" --no-verify
```

---

## 5. Intelligence & Confidence Scoring

POC-Recon evaluates each candidate through a multi-tier confidence scoring engine:

| Confidence Score | Rationale & Criteria |
|---|---|
| **100% (Confirmed Valid)** | Mailbox verified deliverable via direct SMTP `250 OK` or confirmed via HTTPS Cloud Directory (Microsoft 365 / Gravatar / OpenPGP / GitHub). |
| **95% (High Confidence)** | Industry-standard enterprise pattern (`first.last`) on major managed providers (Google Workspace / Microsoft 365) when Port 25 is ISP-blocked. |
| **80% (Moderate Confidence)** | Common secondary enterprise pattern (`firstl` or `first`) on verified enterprise infrastructure. |
| **10% – 20% (Low Confidence)** | Uncommon permutations (`f.last`, `first_last`, `lfirst`) on unverified mail servers. |
| **0% (Confirmed Invalid)** | Explicitly rejected mailbox (SMTP `550 User Unknown` or Microsoft 365 `IfExistsResult=1`). |

When a candidate scores **100%**, POC-Recon immediately short-circuits remaining checks, saving time and bandwidth.

---

## 6. Port 25 ISP Blocking & Solutions

### Why is Port 25 Blocked?
TCP Port 25 is the standard MTA-to-MTA port used by mail servers to deliver messages. To prevent spam, almost all residential ISPs (Comcast, AT&T, Vodafone, Jio, Airtel, etc.) and cloud platforms (AWS EC2, GCP, DigitalOcean default) block outbound TCP port 25.

---

### Solution 1: Automatic HTTPS Cloud Fallback (Zero Port 25 / 100% Free)
**No VPS, no SSH tunnels, and no API keys required.**

When POC-Recon detects that Port 25 is blocked by your ISP, it automatically engages its built-in **HTTPS Cloud & Identity Verifier engine** over standard Port 443:
1. **Microsoft 365 Cloud Directory Probe:** For domains using Microsoft 365 / Exchange Online (over 65% of enterprise businesses), queries the real-time directory to verify whether the specific mailbox exists (`IfExistsResult: 0`) or not (`IfExistsResult: 1`).
2. **Gravatar Profile Lookup:** Queries Gravatar over HTTPS to detect whether a candidate has an active avatar identity.
3. **Public OpenPGP Keyring:** Discovers verified cryptographic public key identities published on keyservers (`keyserver.ubuntu.com`).
4. **GitHub Public Commits Engine:** Cross-references open developer and committer metadata for technical staff.

To disable this fallback and enforce SMTP-only probing, pass `--no-cloud-fallback`.

---

### Solution 2: SSH SOCKS5 Dynamic Tunnel (For Remote SMTP)
If you have access to any remote VPS where outbound Port 25 is open (e.g., Hetzner, OVH, Linode):

#### Step 1: Open the SSH Dynamic SOCKS5 Tunnel
```bash
ssh -N -D 1080 user@your-remote-vps.com
```

#### Step 2: Run POC-Recon with `--proxy`
```bash
poc-recon \
  --website "targetcorp.com" \
  --name "John Smith" \
  --proxy socks5://127.0.0.1:1080
```

---

### Solution 3: Pre-Flight Fast-Fail Diagnostic
Traditional scripts attempt to verify each candidate one-by-one, waiting 10 seconds per timeout (wasting 2+ minutes). POC-Recon tests a single lightweight TCP connection to the primary MX server upfront. If blocked, it immediately engages Cloud Fallback or informs you in under 1 second.

---

### Solution 4: DNS Intelligence & Provider Fingerprinting
POC-Recon queries the target domain's MX and SPF TXT records via standard DNS (Port 53), fingerprinting the provider:
- **Google Workspace (`aspmx.l.google.com`):** Uses strict user validation; returns 550 codes for non-existent users.
- **Microsoft 365 (`mail.protection.outlook.com`):** Enterprise gateways often accept all recipients and route internally; verified via Cloud Directory.
- **Mimecast / Proofpoint:** Enterprise email security gateways that frequently employ greylisting.
- **ProtonMail:** High-security mail provider with strict recipient boundaries.

---

## 7. Catch-All Domains & Verification Realities

### What is a Catch-All Domain?
A Catch-All mail server accepts incoming emails sent to **any** address at the domain (responding `250 OK` to even fictional emails).

### How POC-Recon Handles It
1. Before testing candidates, POC-Recon sends a canary `RCPT TO` for a randomized address (`catchall_probe_...`).
2. If the server responds with `250 OK`, the domain is classified as **Catch-All Enabled**.
3. POC-Recon will **never** falsely mark candidate emails as `VALID` on a catch-all domain. Instead, candidates are marked:
   ```text
   [CATCH-ALL / UNVERIFIED]
   ```

---

## 8. CLI Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--website` | `-w` | Prompt | Target company website URL or domain (e.g. `example.com`) |
| `--name` | `-n` | Prompt | Target person's full name (e.g. `Jane Doe, MBA`) |
| `--company-linkedin` | - | Prompt | Company LinkedIn URL (reference only) |
| `--person-linkedin` | - | Prompt | Target person's LinkedIn URL (used for slug name fallback) |
| `--all` / `--show-all` | - | False | Show all 11 permutation candidates instead of only the primary working email |
| `--proxy` | - | None | SOCKS5 proxy URL for Port 25 routing (e.g. `socks5://127.0.0.1:1080`) |
| `--no-cloud-fallback` | - | False | Disable automatic HTTPS cloud verification fallback when Port 25 is blocked |
| `--no-verify` / `--dry-run` | - | False | Offline mode: generates patterns & DNS data without SMTP checks |
| `--dns-timeout` | - | `5.0` | Timeout in seconds for DNS queries |
| `--smtp-timeout` | - | `8.0` | Timeout in seconds for SMTP connections |
| `--delay` | - | `0.5` | Polite delay between candidate SMTP checks in seconds |
| `--output` | `-o` | `results/` | Path for custom export file |
| `--format` | - | `all` | Export format: `all`, `json`, `csv`, `txt`, or `html` |
| `--open` / `--open-browser` | - | False | Automatically open generated interactive HTML website report in browser |
| `--debug` | - | False | Enable verbose debugging and network logging |

---

## 9. Output Formats (JSON, CSV, Plain Text & Interactive Website)

Results are displayed on screen and automatically persisted to the `results/` directory:

- **JSON Data:** `results/<domain>_<name>_results.json`
- **CSV Spreadsheet:** `results/<domain>_<name>_results.csv`
- **Simple Text Summary:** `results/<domain>_<name>_results.txt`
- **Interactive Website Report:** `results/<domain>_<name>_report.html` (responsive dark dashboard with search, copy buttons, and primary email hero card)

### Sample Simple Text Format:
```text
========================================================================
          POC-RECON RESULTS: SIMPLE TEXT FORMAT (COPY & PASTE)
========================================================================
Domain    : example.com
Target    : Jane Doe
Provider  : Google Workspace | Primary MX: aspmx.l.google.com
Port 25   : Reachable
Catch-All : Disabled/Strict
------------------------------------------------------------------------
🎯 PRIMARY WORKING EMAIL:
Email     : jane.doe@example.com
Confidence: 100%
Pattern   : first.last
Status    : [VALID]
Notes     : Mailbox verified deliverable (250 OK)
------------------------------------------------------------------------
Summary: 1 working email identified (11 permutations evaluated).
Note   : Use --all / --show-all to print all candidate permutations.
========================================================================
```

### Sample JSON Output:
```json
{
  "timestamp": "2026-09-21T10:15:30.123456+00:00",
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
  "best_candidate": {
    "email": "jane.doe@example.com",
    "pattern": "first.last",
    "status": "VALID",
    "confidence": 100,
    "smtp_code": 250,
    "smtp_message": "Mailbox verified deliverable (250 OK)"
  },
  "candidates": [
    {
      "email": "jane.doe@example.com",
      "pattern": "first.last",
      "status": "VALID",
      "confidence": 100,
      "smtp_code": 250,
      "smtp_message": "Mailbox verified deliverable (250 OK)"
    }
  ]
}
```

---

## 10. Running the Test Suite

The test suite runs **100% offline** without needing internet access. All DNS queries and SMTP network interactions are mocked:

```bash
# Run tests with pytest
pytest -v

# Or run with Python's built-in unittest
python -m unittest discover -s tests -p "test_*.py" -v
```

### What is Tested:
- **Single Working Email Resolution (`test_single_working_email.py`):** Primary candidate selection, confidence score assignment, early-exit short circuiting, `--all` flag filtering.
- **Cloud Fallback (`test_cloud_fallback.py`):** Microsoft 365, OpenPGP, Gravatar, and GitHub identity checks over Port 443.
- **Parser (`test_parser.py`):** Scheme stripping, honorific removal (`Dr.`, `Prof.`), degree/credential stripping (`MBA`, `Ph.D.`, `PMP`), LinkedIn slug parsing.
- **Generator (`test_generator.py`):** Standard corporate patterns, Unicode accent conversion (`René Müller` -> `rene.muller`), deduplication.
- **Verifier (`test_verifier.py`):** Mocked DNS MX priority sorting, provider fingerprinting, catch-all detection logic, SMTP 250/550/4xx mapping.
- **Utilities (`test_utils.py`):** JSON, CSV, TXT, and HTML report export integrity.

---

## 11. Ethical & Operational Boundaries

1. **Non-Intrusive Handshakes:** POC-Recon connects, probes recipient availability, and immediately closes the session (`QUIT`). It **never** sends spam or message payloads.
2. **Rate-Limiting:** Incorporates a polite delay between candidate inquiries to avoid stressing remote mail servers.
3. **No Scraping:** Adheres strictly to open protocols (DNS and SMTP) and does not violate Terms of Service of social networking sites.
4. **Intended Use:** Designed for legitimate business communications, domain administration, security research, and deliverability verification.

---

## 12. License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for the full text.
