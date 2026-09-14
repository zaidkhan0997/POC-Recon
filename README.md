# POC-Recon: Local-First POC Business Email Discovery & Verification Tool

A lightweight, privacy-respecting, and modular Python tool designed to discover and verify Point of Contact (POC) business email addresses using corporate pattern generation, DNS MX resolution, and polite SMTP mailbox verification (`RCPT TO`).

---

## 📑 Table of Contents
- [1. Overview & Philosophy](#1-overview--philosophy)
- [2. Architecture & Data Flow](#2-architecture--data-flow)
- [3. Installation & Setup](#3-installation--setup)
  - [System Requirements](#system-requirements)
  - [🐧 Linux Installation (Per Distro Guide)](#-linux-installation-per-distro-guide)
    - [1. Debian / Ubuntu / Kali Linux / Linux Mint / Pop!_OS](#1-debian--ubuntu--kali-linux--linux-mint--pop_os)
    - [2. Arch Linux / Manjaro / EndeavourOS](#2-arch-linux--manjaro--endeavouros)
    - [3. Fedora / RHEL / CentOS Stream / Rocky Linux / AlmaLinux](#3-fedora--rhel--centos-stream--rocky-linux--almalinux)
    - [4. openSUSE (Tumbleweed / Leap)](#4-opensuse-tumbleweed--leap)
    - [5. Alpine Linux](#5-alpine-linux)
  - [🪟 Windows Installation](#-windows-installation)
    - [Prerequisites & Downloads](#prerequisites--downloads)
    - [Method A: PowerShell (Recommended)](#method-a-using-powershell-recommended)
    - [Method B: Classic Command Prompt (cmd.exe)](#method-b-using-classic-command-prompt-cmdexe)
    - [Method C: Windows Subsystem for Linux (WSL2)](#method-c-using-windows-subsystem-for-linux-wsl2)
  - [🍏 macOS Installation](#-macos-installation)
    - [Prerequisites & Downloads](#prerequisites--downloads-1)
    - [Step-by-Step Setup (Apple Silicon & Intel)](#step-by-step-setup-on-macos-apple-silicon--intel)
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
- [8. Output Formats (JSON, CSV, Plain Text & Interactive Website)](#8-output-formats-json-csv-plain-text--interactive-website)
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

### System Requirements
- **Python:** 3.10 or newer (tested on Python 3.10, 3.11, 3.12, 3.13, and 3.14)
- **Git:** For cloning and updating the repository
- **Supported Platforms:** Linux (all distributions), Windows (10/11 native or WSL2), macOS (Apple Silicon M1/M2/M3/M4 or Intel)

---

### 🐧 Linux Installation (Per Distro Guide)

Most modern Linux distributions implement [PEP 668](https://peps.python.org/pep-0668/) ("externally managed environment"), which requires installing Python packages inside an isolated virtual environment (`.venv`) rather than your root system.

#### 1. Debian / Ubuntu / Kali Linux / Linux Mint / Pop!_OS
- **Package Manager:** `apt`
- **Official Documentation:** [Debian Python Wiki](https://wiki.debian.org/Python) | [Ubuntu Python Package](https://packages.ubuntu.com/search?keywords=python3-venv)

```bash
# 1. Update package lists and install Git, Python 3, pip, and virtual environment support
sudo apt update && sudo apt install -y git python3 python3-pip python3-venv

# 2. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 3. Create the virtual environment
python3 -m venv .venv

# 4. Activate the virtual environment
source .venv/bin/activate

# 5. Upgrade pip and install project requirements
pip install --upgrade pip
pip install -r requirements.txt

# 6. Run POC-Recon
python3 main.py
```

#### 2. Arch Linux / Manjaro / EndeavourOS
- **Package Manager:** `pacman`
- **Official Documentation:** [Arch Linux Python Wiki](https://wiki.archlinux.org/title/Python)

```bash
# 1. Update system databases and install Python, pip, and Git
sudo pacman -Syu git python python-pip

# 2. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 3. Create the virtual environment
python -m venv .venv

# 4. Activate the virtual environment
source .venv/bin/activate

# 5. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Run POC-Recon
python main.py
```

#### 3. Fedora / RHEL / CentOS Stream / Rocky Linux / AlmaLinux
- **Package Manager:** `dnf`
- **Official Documentation:** [Fedora Python Quick Docs](https://docs.fedoraproject.org/en-US/quick-docs/installing-python/)

```bash
# 1. Install Git, Python 3, and pip
sudo dnf install -y git python3 python3-pip

# 2. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 3. Create the virtual environment
python3 -m venv .venv

# 4. Activate the virtual environment
source .venv/bin/activate

# 5. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Run POC-Recon
python3 main.py
```

#### 4. openSUSE (Tumbleweed / Leap)
- **Package Manager:** `zypper`
- **Official Documentation:** [openSUSE Python Portal](https://en.opensuse.org/openSUSE:Packaging_Python)

```bash
# 1. Install Python 3, pip, and Git
sudo zypper install -y git python3 python3-pip

# 2. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 3. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Run POC-Recon
python3 main.py
```

#### 5. Alpine Linux
- **Package Manager:** `apk`
- **Official Documentation:** [Alpine Linux Package Repository](https://pkgs.alpinelinux.org/packages?name=python3)

```bash
# 1. Update repositories and install Python, pip, virtualenv, and Git
sudo apk update && sudo apk add git python3 py3-pip py3-virtualenv

# 2. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 3. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Run POC-Recon
python3 main.py
```

---

### 🪟 Windows Installation

#### Prerequisites & Downloads
1. **Python 3.10+ for Windows:**
   - **Download Link:** [Official Python for Windows (python.org)](https://www.python.org/downloads/windows/)
   - ⚠️ **CRITICAL STEP:** During installation, ensure you check the box: **"Add python.exe to PATH"** before clicking "Install Now".
2. **Git for Windows:**
   - **Download Link:** [Git for Windows Official Installer (git-scm.com)](https://git-scm.com/download/win)
3. *(Alternative 1-Command Installation via Windows Package Manager / Winget)*:
   ```cmd
   winget install Python.Python.3.12 Git.Git
   ```

#### Method A: Using PowerShell (Recommended)
If your PowerShell policy restricts running activation scripts, allow execution for your user:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then clone and set up:
```powershell
# 1. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 2. Create the Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment
.venv\Scripts\Activate.ps1

# 4. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Run POC-Recon
python main.py
```

#### Method B: Using Classic Command Prompt (`cmd.exe`)
```cmd
:: 1. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

:: 2. Create virtual environment
python -m venv .venv

:: 3. Activate virtual environment
.venv\Scripts\activate.bat

:: 4. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

:: 5. Run POC-Recon
python main.py
```

#### Method C: Using Windows Subsystem for Linux (WSL2)
If you prefer running in a full Linux environment inside Windows:
1. Open PowerShell as Administrator and run:
   ```powershell
   wsl --install
   ```
2. Restart your PC, launch **Ubuntu**, and follow the [Debian / Ubuntu Linux instructions](#1-debian--ubuntu--kali-linux--linux-mint--pop_os) above.

---

### 🍏 macOS Installation

#### Prerequisites & Downloads
1. **Homebrew (Recommended Package Manager for macOS):**
   - **Official Site:** [brew.sh](https://brew.sh)
   - Install via Terminal:
     ```bash
     /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
     ```
2. **Apple Command Line Tools:**
   ```bash
   xcode-select --install
   ```
3. *(Alternative Official Installer without Homebrew)*: [Python macOS 64-bit universal installer (python.org)](https://www.python.org/downloads/macos/)

#### Step-by-Step Setup on macOS (Apple Silicon & Intel)
```bash
# 1. Install Python 3 and Git using Homebrew
brew install python git

# 2. Clone the repository
git clone https://github.com/zaidkhan0997/POC-Recon.git
cd POC-Recon

# 3. Create the Python virtual environment
python3 -m venv .venv

# 4. Activate the virtual environment
source .venv/bin/activate

# 5. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Run POC-Recon
python3 main.py
```

---


## 4. Usage Guide

### Interactive Mode
If you run `main.py` without arguments, it launches interactive prompts asking for all target details and verification mode:

```bash
python main.py
```
**Interactive prompts provided:**
1. **Target Company Website / Domain:** (e.g. `example.com` or `https://example.com`)
2. **Target Person's Full Name:** (e.g. `Jane Doe` or `Dr. John C. Smith, MBA`, or leave blank if using LinkedIn)
3. **Person's LinkedIn Profile URL:** (e.g. `https://www.linkedin.com/in/jane-doe-12345`)
4. **Company LinkedIn URL:** (e.g. `https://www.linkedin.com/company/example-corp`)
5. **Live Verification Mode:** choose `y` for live DNS + SMTP verification, or `n` for offline pattern generation
6. **Open in Browser:** prompt to automatically open the generated interactive website report

### CLI Mode
Provide the target company website and person's name directly via command-line arguments:

```bash
python main.py \
  --website "https://example.com" \
  --name "Jane Doe, MBA" \
  --company-linkedin "https://www.linkedin.com/company/example-corp" \
  --person-linkedin "https://www.linkedin.com/in/jane-doe-12345" \
  --open
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

### Solution 1: Automatic HTTPS Cloud Fallback (Zero Port 25 / 100% Free)
**No VPS, no SSH tunnels, and no API keys required.**

When POC-Recon detects that Port 25 is blocked by your ISP, it automatically engages its built-in **HTTPS Cloud & Identity Verifier engine** over standard Port 443:
1. **Microsoft 365 Cloud Directory Probe:** For domains using Microsoft 365 / Exchange Online (over 65% of enterprise businesses), queries the real-time directory to verify whether the specific mailbox exists (`IfExistsResult: 0`) or not (`IfExistsResult: 1`).
2. **Public OpenPGP Keyring:** Discovers verified cryptographic public key identities published on keyservers (`keyserver.ubuntu.com`).
3. **GitHub Public Commits Engine:** Cross-references open developer and committer metadata for technical and open-source company staff.

This runs automatically out-of-the-box. To disable this fallback and strictly enforce SMTP-only probing, pass `--no-cloud-fallback`.

---

### Solution 2: SSH SOCKS5 Dynamic Tunnel (For Remote SMTP)
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

### Solution 3: Pre-Flight Fast-Fail Diagnostic
Traditional email scripts attempt to verify each candidate email one-by-one. When port 25 is blocked, each candidate times out for 10 seconds, forcing you to wait 2+ minutes for a failed scan.

POC-Recon features an automated **Pre-Flight Port 25 Check**:
- It tests a single lightweight TCP connection to the primary MX server before touching candidates.
- If blocked and `--no-cloud-fallback` is set, it **immediately stops**, flags candidates as `UNVERIFIED / PORT BLOCKED`, and displays an actionable troubleshooting panel instead of hanging.

---

### Solution 4: DNS Intelligence & Provider Fingerprinting
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
| `--company-linkedin` | - | Prompt | Company LinkedIn URL (reference only) |
| `--person-linkedin` | - | Prompt | Target person's LinkedIn URL (used for slug name fallback) |
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

## 8. Output Formats (JSON, CSV, Plain Text & Interactive Website)

Results are displayed directly on screen in both a Rich table and a clean **Simple Text Format** (easy to copy & paste), and persisted into the `results/` directory:

- **JSON Data:** `results/<domain>_<name>_results.json`
- **CSV Spreadsheet:** `results/<domain>_<name>_results.csv`
- **Simple Text Summary:** `results/<domain>_<name>_results.txt`
- **Interactive Website Report:** `results/<domain>_<name>_report.html` (responsive dark dashboard with search, filters, and 1-click copy buttons)

### Sample Simple Text Format:
```text
========================================================================
          POC-RECON RESULTS: SIMPLE TEXT FORMAT (COPY & PASTE)
========================================================================
Domain    : example.com
Target    : Jane Doe
LinkedIn  : https://www.linkedin.com/in/jane-doe-12345
Provider  : Google Workspace | Primary MX: aspmx.l.google.com
Port 25   : Reachable
Catch-All : Disabled/Strict
------------------------------------------------------------------------
#   Candidate Email                 Status          Code / Notes
------------------------------------------------------------------------
1   jane.doe@example.com            [VALID]         (250) Mailbox verified deliverable
2   jane@example.com                [INVALID]       (550) Recipient rejected: User unknown
3   jdoe@example.com                [INVALID]       (550) Recipient rejected: User unknown
========================================================================
```

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
