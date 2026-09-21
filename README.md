# POC-Recon: Local-First POC Business Email Discovery & Verification Suite

A lightweight, privacy-respecting, and modular tool designed to discover and verify Point of Contact (POC) business email addresses using corporate pattern intelligence, DNS MX resolution (with DNS-over-HTTPS fallback), polite SMTP mailbox verification (`RCPT TO`), and HTTPS Cloud Directory fallback.

> **🎯 Single Working Email Focus:** Unlike tools that dump 10+ confusing permutations, POC-Recon scores candidates with an enterprise intelligence engine to spotlight **the 1 primary working email** (with confidence score) by default. Pass `--all` anytime you wish to inspect all permutations.

> **🖥️ Now Available as a Native Desktop GUI Application:** Prefer a modern graphical software window instead of the command line? Run POC-Recon as a standalone desktop GUI application for Windows, Linux, and macOS in [poc-recon-desktop/](poc-recon-desktop/).

---

## 📑 Table of Contents
- [1. Overview & Philosophy](#1-overview--philosophy)
- [2. Editions & Architecture](#2-editions--architecture)
  - [🖥️ Native Desktop GUI Software](#-native-desktop-gui-software)
  - [⚡ Native Go CLI Engine](#-native-go-cli-engine)
  - [🐍 Python CLI & Core Engine](#-python-cli--core-engine)
- [3. Quick Installation](#3-quick-installation)
  - [🖥️ Desktop GUI Software (Windows, Linux, macOS)](#️-desktop-gui-software-windows-linux-macos)
  - [🪟 Windows CLI (.exe)](#-windows-cli-exe)
  - [🐧 Linux CLI](#-linux-cli)
  - [🍏 macOS CLI](#-macos-cli)
- [4. Usage Guide](#4-usage-guide)
  - [Desktop GUI Application](#desktop-gui-application)
  - [Interactive CLI Mode](#interactive-cli-mode)
  - [Command-Line Mode](#command-line-mode)
  - [Inspect All Permutations (`--all`)](#inspect-all-permutations---all)
  - [Offline / Pattern-Only Mode (`--no-verify`)](#offline--pattern-only-mode---no-verify)
- [5. Intelligence & Confidence Scoring](#5-intelligence--confidence-scoring)
- [6. Port 25 ISP Blocking & Solutions](#6-port-25-isp-blocking--solutions)
  - [Why is Port 25 Blocked?](#why-is-port-25-blocked)
  - [Solution 1: Automatic HTTPS Cloud Fallback (Zero Port 25 / 100% Free)](#solution-1-automatic-https-cloud-fallback-zero-port-25--100-free)
  - [Solution 2: DNS-over-HTTPS (DoH) MX Fallback](#solution-2-dns-over-https-doh-mx-fallback)
  - [Solution 3: SSH SOCKS5 Dynamic Tunnel (For Remote SMTP)](#solution-3-ssh-socks5-dynamic-tunnel-for-remote-smtp)
  - [Solution 4: Pre-Flight Fast-Fail Diagnostic](#solution-4-pre-flight-fast-fail-diagnostic)
  - [Solution 5: DNS Intelligence & Provider Fingerprinting](#solution-5-dns-intelligence--provider-fingerprinting)
- [7. Catch-All Domains & Verification Realities](#7-catch-all-domains--verification-realities)
- [8. CLI Reference](#8-cli-reference)
- [9. Output Formats (Single Self-Contained HTML Report)](#9-output-formats-single-self-contained-html-report)
- [10. Running the Test Suite](#10-running-the-test-suite)
- [11. Ethical & Operational Boundaries](#11-ethical--operational-boundaries)
- [12. License](#12-license)

---

## 1. Overview & Philosophy

Most commercial email finders rely on costly third-party APIs, aggressive web crawlers, or questionable browser-based scraping of LinkedIn. **POC-Recon** takes a strictly local, protocol-level approach:

- **100% Local & Protocol-Driven:** Relies on DNS MX/SPF records, DNS-over-HTTPS (DoH), direct SMTP handshakes, and public cryptographic/cloud directory checks.
- **Single Working Email Spotlight:** Rather than flooding users with 11 guesses, POC-Recon ranks permutations using live validation and enterprise naming statistics to present the single winning email address.
- **Clean Results Output:** Saves only **1 clean, self-contained interactive HTML report** per search into the `results/` folder by default, avoiding folder clutter.
- **No LinkedIn Scraping or Headless Browsers:** LinkedIn profile URLs are used strictly for client-side slug extraction (e.g. parsing `jane-doe-12345` into `Jane Doe`) as an offline fallback.
- **RFC 5321 Safe Handshakes:** Connects to port 25, issues polite `EHLO`, `MAIL FROM`, and `RCPT TO` commands, records server diagnostic codes, and terminates with `QUIT`. **Never issues `DATA` or sends email.**
- **Early-Exit Short-Circuit:** Once an email is 100% verified via SMTP or Cloud Directory, POC-Recon immediately short-circuits to deliver instant results without needless network calls.
- **Honest Deliverability Classification:** Clearly distinguishes between confirmed addresses (`VALID`), rejected mailboxes (`INVALID`), and ambiguous configurations (`CATCH-ALL / UNVERIFIED`, `PORT BLOCKED`).

---

## 2. Editions & Architecture

POC-Recon is structured into modular editions tailored for both everyday business users and advanced terminal workflows:

### 🖥️ Native Desktop GUI Software
Located in [poc-recon-desktop/](poc-recon-desktop/):
- **Modern Graphical Window:** Zero command-line knowledge required.
- **Real-Time Live Progress:** Visual stage indicators and animated progress bars for DNS, SMTP, and Cloud checks.
- **Primary Working Email Hero Card:** Copy verified emails directly to your clipboard in 1 click.
- **Expandable Candidate Table:** Search, filter, and inspect all evaluated candidate permutations.
- **Direct Report Access:** Integrated **"Open HTML Report"** and **"Open Results Folder"** actions.
- **Cross-Platform:** Native builds for Windows (`.exe`), Linux (`x86_64`), and macOS (`.zip`).

### ⚡ Native Go CLI Engine
Located in [poc-recon-go/](poc-recon-go/):
- **Statically Linked Binary:** Ultra-fast, single ~4 MB binary with zero runtime dependencies.
- **DNS-over-HTTPS (DoH):** Built-in Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) DoH resolvers to bypass local DNS tampering.
- **Cloud Identity Fallbacks:** Real-time Microsoft 365, Gravatar, and OpenPGP keyserver verifiers.
- **High Concurrency:** Built on Go goroutines for blazing-fast verification.

### 🐍 Python CLI & Core Engine
Located in root directory ([main.py](main.py)):
- Complete CLI reference implementation with rich terminal UI, colorized output, interactive prompts, and unit test suites.

---

## 3. Quick Installation

Pre-compiled standalone binaries and desktop software packages are available on the **[GitHub Releases Page](https://github.com/zaidkhan0997/POC-Recon/releases/latest)**.

---

### 🖥️ Desktop GUI Software (Windows, Linux, macOS)

No runtime, Python, or external dependencies required:

| Operating System | Package / Binary | Instructions |
| :--- | :--- | :--- |
| **🪟 Windows** | `poc-recon-desktop-windows-x64.exe` | Download from [Releases](https://github.com/zaidkhan0997/POC-Recon/releases/latest) and double-click to run. |
| **🐧 Linux** | `poc-recon-desktop-linux-x64` | `chmod +x poc-recon-desktop-linux-x64 && ./poc-recon-desktop-linux-x64` |
| **🍏 macOS** | `poc-recon-desktop-macos.zip` | Extract `.zip` and double-click the application. |

---

### 🪟 Windows CLI (.exe)

#### Method 1: 1-Click PowerShell Installer (Recommended)
Open **PowerShell** and run:
```powershell
irm https://raw.githubusercontent.com/zaidkhan0997/POC-Recon/main/install.ps1 | iex
```
*Automatically installs POC-Recon, adds it to your PATH, and creates a Desktop shortcut.*

#### Method 2: Direct Download
1. Download **[poc-recon-windows-x64.exe](https://github.com/zaidkhan0997/POC-Recon/releases/latest)** from the latest release.
2. Run it in Command Prompt / PowerShell:
   ```cmd
   poc-recon-windows-x64.exe --website example.com --name "Jane Doe"
   ```

---

### 🐧 Linux CLI

Install with a single command:
```bash
curl -sSL https://raw.githubusercontent.com/zaidkhan0997/POC-Recon/main/install.sh | bash
```

Or manually download and run:
```bash
# 1. Download the latest Linux CLI binary
curl -L -o poc-recon https://github.com/zaidkhan0997/POC-Recon/releases/latest/download/poc-recon-linux-x64

# 2. Make it executable
chmod +x poc-recon

# 3. Run it
./poc-recon
```

---

### 🍏 macOS CLI

Install with a single command:
```bash
curl -sSL https://raw.githubusercontent.com/zaidkhan0997/POC-Recon/main/install.sh | bash
```

Or manually download and run:
```bash
# 1. Download the latest macOS CLI binary
curl -L -o poc-recon https://github.com/zaidkhan0997/POC-Recon/releases/latest/download/poc-recon-macos-arm64

# 2. Make it executable
chmod +x poc-recon

# 3. Run it
./poc-recon
```

---

## 4. Usage Guide

### Desktop GUI Application
Simply launch the desktop software executable:
1. Enter the target domain (e.g. `example.com`) and person's name (e.g. `Jane Doe`).
2. Enter the person's LinkedIn URL (e.g. `https://www.linkedin.com/in/jane-doe`) and company LinkedIn URL (e.g. `https://www.linkedin.com/company/example`).
3. Click **"Start Reconnaissance"**.
4. Watch real-time stage updates and copy the verified working email from the **Primary Email Hero Card**.
5. Click **"Open Visual Report"** to view the saved interactive HTML dashboard in your browser.

---

### Interactive CLI Mode
If you run `poc-recon` without arguments, it launches interactive prompts asking for all required target details and verification mode:

```bash
poc-recon
```
**Interactive prompts provided:**
1. **Target Company Website / Domain \*:** (e.g. `example.com` or `https://example.com`)
2. **Target Person's Full Name \*:** (e.g. `Jane Doe` or `Dr. John C. Smith, MBA`)
3. **Target Person's LinkedIn Profile URL \*:** (e.g. `https://www.linkedin.com/in/jane-doe-12345`)
4. **Target Company LinkedIn URL \*:** (e.g. `https://www.linkedin.com/company/example-corp`)
5. **Live Verification Mode:** choose `y` for live DNS + SMTP verification, or `n` for offline pattern generation
6. **Open in Browser:** prompt to automatically open the generated interactive website report

---

### Command-Line Mode
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
If you want to view the full table of all candidate permutations alongside their individual statuses, pass `--all` (or `--show-all`):

```bash
poc-recon --website "example.com" --name "Jane Doe" --all
```

---

### Offline / Pattern-Only Mode (`--no-verify`)
If your current network blocks Port 25 or you only want to generate corporate email combinations and inspect DNS records without initiating SMTP network connections:

```bash
poc-recon \
  --website "example.com" \
  --name "Jane Doe" \
  --person-linkedin "https://www.linkedin.com/in/jane-doe" \
  --company-linkedin "https://www.linkedin.com/company/example" \
  --no-verify
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

When a candidate scores **100%**, POC-Recon immediately short-circuits remaining checks, delivering results instantly without unnecessary network traffic.

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

### Solution 2: DNS-over-HTTPS (DoH) MX Fallback
In restricted network environments or networks where standard UDP Port 53 DNS is intercepted or filtered, the native Go engine and desktop application automatically fall back to encrypted **DNS-over-HTTPS (DoH)** queries via **Cloudflare** (`https://cloudflare-dns.com/dns-query`) and **Google Public DNS** (`https://dns.google/resolve`).

---

### Solution 3: SSH SOCKS5 Dynamic Tunnel (For Remote SMTP)
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

### Solution 4: Pre-Flight Fast-Fail Diagnostic
Traditional scripts attempt to verify each candidate one-by-one, waiting 10 seconds per timeout (wasting 2+ minutes). POC-Recon tests a single lightweight TCP connection to the primary MX server upfront. If blocked, it immediately engages Cloud Fallback or informs you in under 1 second.

---

### Solution 5: DNS Intelligence & Provider Fingerprinting
POC-Recon queries the target domain's MX and SPF TXT records via DNS, fingerprinting the provider:
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
| `--website` | `-w` | Prompt | **[REQUIRED]** Target company website URL or domain (e.g. `example.com`) |
| `--name` | `-n` | Prompt | **[REQUIRED]** Target person's full name (e.g. `Jane Doe, MBA`) |
| `--person-linkedin` | - | Prompt | **[REQUIRED]** Target person's LinkedIn profile URL |
| `--company-linkedin` | - | Prompt | **[REQUIRED]** Target company LinkedIn URL |
| `--all` / `--show-all` | - | False | Show all candidate permutations instead of only the primary working email |
| `--proxy` | - | None | SOCKS5 proxy URL for Port 25 routing (e.g. `socks5://127.0.0.1:1080`) |
| `--no-cloud-fallback` | - | False | Disable automatic HTTPS cloud verification fallback when Port 25 is blocked |
| `--no-verify` / `--dry-run` | - | False | Offline mode: generates patterns & DNS data without SMTP checks |
| `--dns-timeout` | - | `5.0` | Timeout in seconds for DNS queries |
| `--smtp-timeout` | - | `8.0` | Timeout in seconds for SMTP connections |
| `--delay` | - | `0.5` | Polite delay between candidate SMTP checks in seconds |
| `--output` | `-o` | `results/` | Path for custom export file |
| `--format` | - | `html` | Export format: `html`, `json`, `csv`, `txt`, or `all` (default: `html`) |
| `--open` / `--open-browser` | - | False | Automatically open generated interactive HTML website report in browser |
| `--debug` | - | False | Enable verbose debugging and network logging |

---

## 9. Output Formats (Single Self-Contained HTML Report)

To keep your workspace and project folders clean, POC-Recon persists **1 single, self-contained interactive HTML report** into the `results/` folder by default:

```text
results/
└── example.com_jane_report.html
```

### Report Features
- **Responsive Dark Theme:** Built for clarity and high-contrast readability.
- **Primary Working Email Hero Card:** Highlights the single confirmed working email with confidence score, pattern details, and 1-click clipboard copying.
- **Full Candidate Permutations Table:** Searchable and filterable table displaying every permutation, status badges, SMTP codes, and detailed diagnostic logs.
- **Provider & DNS Intelligence Badge:** Displays MX priority records, SPF configuration, and mail server provider classification.
- **Zero External Assets:** All styles and scripts are completely inlined—open the file in any browser on any offline computer.

*(If you require machine-readable exports like JSON, CSV, or Plain Text in the CLI, pass `--format all`, `--format json`, `--format csv`, or `--format txt`.)*

---

## 10. Running the Test Suite

The test suite runs **100% offline** without needing internet access. All DNS queries and SMTP network interactions are mocked:

### Python Unit Tests
```bash
# Run with Python's built-in unittest
python -m unittest discover -s tests -p "test_*.py" -v
```

### Go Native Engine Unit Tests
```bash
cd poc-recon-go
go test -v ./...
```

### What is Tested:
- **Single Working Email Resolution:** Primary candidate selection, confidence score assignment, early-exit short circuiting, `--all` flag filtering.
- **Cloud Fallback:** Microsoft 365, OpenPGP, Gravatar, and GitHub identity checks over Port 443.
- **Parser:** Scheme stripping, honorific removal (`Dr.`, `Prof.`), credential stripping (`MBA`, `Ph.D.`, `PMP`), LinkedIn slug parsing.
- **Generator:** Standard corporate patterns, Unicode accent conversion (`René Müller` -> `rene.muller`), deduplication.
- **Verifier:** Mocked DNS MX priority sorting, DoH fallback, provider fingerprinting, catch-all detection logic, SMTP 250/550/4xx mapping.
- **Exporters:** Single HTML report generation, JSON, CSV, and TXT integrity.

---

## 11. Ethical & Operational Boundaries

1. **Non-Intrusive Handshakes:** POC-Recon connects, probes recipient availability, and immediately closes the session (`QUIT`). It **never** sends spam or message payloads.
2. **Rate-Limiting:** Incorporates a polite delay between candidate inquiries to avoid stressing remote mail servers.
3. **No Scraping:** Adheres strictly to open protocols (DNS and SMTP) and does not violate Terms of Service of social networking sites.
4. **Intended Use:** Designed for legitimate business communications, domain administration, security research, and deliverability verification.

---

## 12. License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for the full text.
