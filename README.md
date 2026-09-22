# POC-Recon: Local-First POC Business Email Discovery & Verification Suite

A lightweight, privacy-respecting, and modular tool designed to discover and verify Point of Contact (POC) business email addresses using corporate pattern intelligence, DNS MX resolution (with DNS-over-HTTPS fallback), polite SMTP mailbox verification (`RCPT TO`), and HTTPS Cloud Directory fallback.

> **🎯 Single Working Email Focus:** Unlike tools that dump 10+ confusing permutations, POC-Recon scores candidates with an enterprise intelligence engine to spotlight **the 1 primary working email** (with confidence score) by default. Pass `--all` anytime you wish to inspect all permutations.

> **🖥️ Now Available as a Native Desktop GUI Application:** Prefer a modern graphical software window instead of the command line? Run POC-Recon as a standalone desktop GUI application for Windows, Linux, and macOS in [poc-recon-desktop/](poc-recon-desktop/).

---

## 📑 Table of Contents
- [1. Overview & Philosophy](#1-overview--philosophy)
- [2. Editions & Architecture](#2-editions--architecture)
  - [🖥️ Native Desktop GUI Software](#-native-desktop-gui-software)
  - [⚡ Pure Go Engine & CLI](#-pure-go-engine--cli)
- [3. Quick Installation](#3-quick-installation)
  - [🖥️ Desktop GUI Software (Windows, Linux, macOS)](#️-desktop-gui-software-windows-linux-macos)
  - [🪟 Windows CLI (.exe)](#-windows-cli-exe)
  - [🐧 Linux CLI](#-linux-cli)
  - [🍏 macOS CLI](#-macos-cli)
  - [⚡ Go Install (`go install`)](#-go-install)
  - [🛠️ Building from Source](#️-building-from-source-go-122)
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

### ⚡ Pure Go Engine & CLI
Located in root (`cmd/poc-recon/`, `internal/`, `pkg/`):
- **Statically Linked Binary:** Ultra-fast, single binary (~8 MB) with zero runtime dependencies.
- **DNS-over-HTTPS (DoH):** Built-in Cloudflare (`1.1.1.1`) DoH resolver to ensure reliable MX resolution.
- **Automated OSINT Pattern Detection:** Automatically queries DMARC records and OpenPGP keyservers to deduce company-wide naming conventions (e.g. `first@domain.com` vs `first.last@domain.com`).
- **Cloud Identity Fallbacks:** Real-time Microsoft 365, Gravatar, and OpenPGP keyserver verifiers.
- **High Concurrency:** Goroutine worker pool with context cancellation and instant early exit upon 100% confidence.
- **Terminal UI:** Beautiful modern terminal styling with Lipgloss.

---

## 3. Quick Installation

Pre-compiled standalone binaries and desktop software packages are available on the **[GitHub Releases Page](https://github.com/zaidkhan0997/POC-Recon/releases/latest)**.

---

### 🖥️ Desktop GUI Software (Windows, Linux, macOS)

Zero external dependencies or runtimes required (single self-contained executable):

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

### ⚡ Go Install (`go install`)

If you have Go installed on your machine, you can install POC-Recon directly into your `$GOPATH/bin`:

```bash
go install github.com/zaidkhan0997/POC-Recon/cmd/poc-recon@latest
```

---

### 🛠️ Building from Source (Go 1.22+)

If you have Go installed, you can build the standalone binary directly:

```bash
# Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# Build with Makefile
make build

# The executable will be in bin/poc-recon
./bin/poc-recon --help
```

To cross-compile for all operating systems (Linux, Windows, macOS):
```bash
make cross-compile
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

POC-Recon evaluates each candidate through an OSINT-driven, multi-tier confidence scoring engine with **zero hardcoded pattern bias**:

| Confidence Score | Rationale & Criteria |
|---|---|
| **100% (Confirmed Valid)** | Mailbox verified deliverable via direct RFC 5321 SMTP `250 OK`, Cloud Relay verification, or confirmed exact match discovered in public domain OSINT (DMARC / OpenPGP). |
| **90% – 95% (Active Pattern Match)** | Candidate matches company-wide pattern detected via live domain OSINT (e.g. `first@domain.com` for Stripe/GitHub) or explicit `--pattern` flag, evaluated on enterprise mail infrastructure. |
| **85% (Industry Standard Fallback)** | Common corporate pattern (`first.last`) on enterprise providers (Google Workspace / Microsoft 365) when no specific domain pattern can be inferred from OSINT. |
| **40% – 60% (Secondary Conventions)** | Common alternative corporate permutations (`flast`, `firstlast`, `first_last`) on standard infrastructure. |
| **15% – 35% (Uncommon Permutations)** | Infrequent variations (`f.last`, `last.first`, `lfirst`) on unverified mail servers. |
| **0% (Confirmed Invalid / No MX)** | Explicitly rejected mailbox (SMTP `550 User Unknown`, M365 `IfExistsResult=1`), or domain has no MX records in DNS. |

> **⚡ Early-Exit Short-Circuit:** As soon as any candidate reaches **100% confidence**, the concurrent worker pool immediately cancels remaining in-flight probes, delivering results instantly without unnecessary network traffic or server rate-limits.
>
> **🔎 OSINT Pattern Auto-Detection:** Queries `_dmarc.<domain>` TXT records and OpenPGP keyservers (`keyserver.ubuntu.com`) in real-time. If multiple employees use `first@domain.com`, POC-Recon automatically elevates `first` to 95% confidence instead of forcing `first.last`.

---

## 6. Port 25 ISP Blocking & Solutions

### Why is Port 25 Blocked?
TCP Port 25 is the standard MTA-to-MTA port used by mail servers to deliver messages. To prevent spam, almost all residential ISPs (Comcast, AT&T, Vodafone, Jio, Airtel, etc.) and cloud platforms (AWS EC2, GCP, DigitalOcean default) block outbound TCP port 25.

---

### Solution 1: Free Multi-Signal Cloud Engine (Zero Port 25 / 100% Free / No Accounts)
**No VPS, no SSH tunnels, and zero API keys or user accounts required.**

When POC-Recon detects that Port 25 is blocked by your ISP, it automatically engages its built-in **Multi-Signal Identity & Cloud Verifier engine** over standard Port 443 (HTTP/HTTPS):
1. **Microsoft 365 Cloud Directory Probe:** Probes Microsoft 365 GetCredentialType & Autodiscover endpoints. If the recipient exists in Microsoft 365 / Exchange Online, validates mailbox deliverability without Port 25.
2. **Gravatar Profile Lookup:** Queries Gravatar over HTTPS to detect whether a candidate has an active avatar identity.
3. **Public OpenPGP Keyring:** Discovers verified cryptographic public key identities published on keyservers (`keyserver.ubuntu.com`).
4. **Certificate Transparency OSINT (`crt.sh`):** Harvests historical SSL/TLS certificates to extract real organizational email naming patterns.

### Solution 2: Pure-Go AfterShip SMTP Verifier (Port 25 Direct or Proxy)
When running on networks with open Port 25 (or through SOCKS5 proxy), POC-Recon uses the battle-tested `github.com/AfterShip/email-verifier` RFC 5321 verification engine. It handles MX resolution, SMTP handshake, Catch-All canary probing, and mail server greylisting natively in pure Go.

### Solution 3: Self-Hosted Reacher Container (Optional Docker)
If you prefer running a dedicated email verification daemon in Docker, POC-Recon integrates seamlessly with the open-source **Reacher** (`check-if-email-exists`) engine:
```bash
# Run Reacher backend locally
docker run -p 8080:8080 --rm reacherhq/backend:latest

# Run POC-Recon pointing to your Reacher instance
poc-recon -d acme.com -n "Jane Doe" --reacher-url http://localhost:8080
```
Reacher is also fully accessible in the Desktop GUI app under **Advanced Options > Self-Hosted Reacher URL**.

---

### Solution 4: DNS-over-HTTPS (DoH) MX Fallback
In restricted network environments or networks where standard UDP Port 53 DNS is intercepted or filtered, the native Go engine and desktop application automatically fall back to encrypted **DNS-over-HTTPS (DoH)** queries via **Cloudflare** (`https://cloudflare-dns.com/dns-query`) and **Google Public DNS** (`https://dns.google/resolve`).

---

### Solution 5: SSH SOCKS5 Dynamic Tunnel (For Remote SMTP)
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
| `--website`, `--domain` | `-w`, `-d` | Prompt | Target company website URL or domain (e.g. `stripe.com`) |
| `--name` | `-n` | Prompt | Target person's full name (e.g. `Patrick Collison`) |
| `--person-linkedin`, `--linkedin` | `-l` | None | Target person's LinkedIn profile URL or handle |
| `--company-linkedin` | - | None | Target company LinkedIn URL |
| `--pattern` | `-p` | Auto | Known email pattern override (e.g. `first`, `first.last`, `flast`) |
| `--all` | `-a` | False | Display all evaluated candidate permutations in terminal summary |
| `--concurrency` | `-c` | `4` | Number of concurrent verification workers (1–10) |
| `--proxy` | - | None | SOCKS5 proxy URL for Port 25 routing (e.g. `socks5://127.0.0.1:1080` or env `POC_RECON_PROXY`) |
| `--reacher-url` | - | None | Self-hosted Reacher (check-if-email-exists) HTTP API URL (e.g. `http://localhost:8080` or env `POC_RECON_REACHER_URL`) |
| `--relay-url` | - | None | Cloud relay fallback endpoint URL (or env `POC_RECON_RELAY_URL`) |
| `--relay-token` | - | None | Bearer token for cloud relay (or env `POC_RECON_RELAY_TOKEN`) |
| `--no-cloud-fallback` | - | False | Disable cloud relay and provider-specific checks |
| `--no-verify` | - | False | Offline mode: generates patterns, OSINT & DNS data without SMTP checks |
| `--dns-timeout` | - | `5s` | Timeout in seconds for DNS queries |
| `--smtp-timeout` | - | `10s` | Timeout in seconds for SMTP connections |
| `--delay` | - | `400ms` | Polite delay in milliseconds between SMTP probes |
| `--output` | `-o` | None | Save report to custom file path |
| `--format` | `-f` | Inferred | Export format: `txt`, `html`, `json`, `csv` (inferred from `-o` extension) |
| `--open` | - | False | Automatically open HTML report in browser after generation |

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

### Running Go Unit Tests
```bash
# Run tests across all packages
make test

# Or directly with Go:
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
