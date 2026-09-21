import json
import logging
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import List, Optional, Tuple

import dns.exception
import dns.resolver

from models import (
    CandidateResult,
    MXRecord,
    NameParts,
    ProviderInfo,
    ReconResult,
    VerificationStatus,
)
from utils import create_connection

logger = logging.getLogger("poc_recon")


class SMTPClient:
    """
    Lightweight, RFC 5321 compliant SMTP client specifically tailored for RCPT TO mailbox verification.
    Supports proxying (SOCKS5/SSH tunnel) and controlled, non-destructive handshakes.
    """

    def __init__(
        self,
        host: str,
        port: int = 25,
        timeout: float = 8.0,
        proxy_url: Optional[str] = None,
        helo_name: str = "mail.verify.local"
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.helo_name = helo_name
        self.sock: Optional[socket.socket] = None

    def connect(self) -> Tuple[int, str]:
        """Establishes TCP connection and reads the SMTP greeting banner."""
        self.sock = create_connection(
            self.host,
            self.port,
            timeout=self.timeout,
            proxy_url=self.proxy_url
        )
        return self._read_response()

    def _send_command(self, cmd: str) -> None:
        if not self.sock:
            raise OSError("Socket not connected.")
        data = (cmd + "\r\n").encode("utf-8")
        self.sock.sendall(data)

    def _read_response(self) -> Tuple[int, str]:
        if not self.sock:
            raise OSError("Socket not connected.")

        lines = []
        code = 0
        buf = ""

        while True:
            chunk = self.sock.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                break
            buf += chunk
            while "\r\n" in buf or "\n" in buf:
                if "\r\n" in buf:
                    line, buf = buf.split("\r\n", 1)
                else:
                    line, buf = buf.split("\n", 1)
                lines.append(line)

                # Check if this line is the terminal line of the SMTP reply
                # Format: "XYZ text" vs "XYZ-text" (multiline)
                if len(line) >= 3 and line[:3].isdigit():
                    code = int(line[:3])
                    if len(line) == 3 or line[3] == " ":
                        return code, "\n".join(lines)

        if lines and len(lines[-1]) >= 3 and lines[-1][:3].isdigit():
            code = int(lines[-1][:3])
        return code, "\n".join(lines)

    def helo(self) -> Tuple[int, str]:
        """Sends EHLO, falling back to HELO if rejected."""
        try:
            self._send_command(f"EHLO {self.helo_name}")
            code, msg = self._read_response()
            if 200 <= code < 300:
                return code, msg
        except Exception:
            pass

        self._send_command(f"HELO {self.helo_name}")
        return self._read_response()

    def mail_from(self, sender: str = "check@verify.local") -> Tuple[int, str]:
        """Issues MAIL FROM:<sender>."""
        self._send_command(f"MAIL FROM:<{sender}>")
        return self._read_response()

    def rcpt_to(self, recipient: str) -> Tuple[int, str]:
        """Issues RCPT TO:<recipient>."""
        self._send_command(f"RCPT TO:<{recipient}>")
        return self._read_response()

    def quit(self) -> None:
        """Sends QUIT and cleanly closes the socket."""
        if self.sock:
            try:
                self._send_command("QUIT")
            except Exception:
                pass
            finally:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None

    def close(self) -> None:
        """Closes the socket without QUIT."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def get_mx_records(domain: str, timeout: float = 5.0) -> List[MXRecord]:
    """
    Queries DNS for MX records of the specified domain.
    Returns list of MXRecord sorted by priority (lowest preference first).
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(domain, "MX")
        records = []
        for rdata in answers:
            host_str = str(rdata.exchange).rstrip(".")
            if not host_str:
                # RFC 7505 Null MX ("0 .") explicitly designates that the domain does not accept email
                continue
            records.append(MXRecord(host=host_str, priority=rdata.preference))
        records.sort(key=lambda x: x.priority)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        logger.warning(f"No MX records found for domain: {domain}")
        return []
    except dns.exception.Timeout:
        logger.warning(f"DNS timeout querying MX records for domain: {domain}")
        return []
    except dns.exception.DNSException as e:
        logger.warning(f"DNS error querying MX records for {domain}: {e}")
        return []


def fingerprint_mail_provider(domain: str, mx_records: List[MXRecord], timeout: float = 5.0) -> ProviderInfo:
    """
    Analyzes MX hostnames and SPF TXT records to detect email infrastructure provider
    (Google Workspace, Microsoft 365, ProtonMail, Proofpoint, Mimecast, etc.).
    """
    mx_hosts = " ".join([mx.host.lower() for mx in mx_records])

    # Query SPF record
    spf_record = None
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt_str = "".join([b.decode("utf-8", errors="replace") for b in rdata.strings])
            if txt_str.startswith("v=spf1"):
                spf_record = txt_str
                break
    except Exception:
        pass

    # Primary check: Inbound MX host (where mail is received)
    # Secondary check: Outbound SPF record (who is authorized to send)
    target_text = (mx_hosts + " " + (spf_record or "")).lower()

    if "outlook.com" in mx_hosts or "mail.protection.outlook.com" in mx_hosts:
        return ProviderInfo(
            name="Microsoft 365 / Exchange Online",
            spf_record=spf_record,
            details="Microsoft 365 gateway. Edge server may accept RCPT TO and bounce internally."
        )
    elif "google.com" in mx_hosts or "aspmx.l.google.com" in mx_hosts or "googlemail.com" in mx_hosts:
        return ProviderInfo(
            name="Google Workspace",
            spf_record=spf_record,
            details="Google Workspace mail servers return strict 550 codes for non-existent users."
        )
    elif "protonmail" in target_text or "proton.me" in target_text:
        return ProviderInfo(
            name="ProtonMail",
            spf_record=spf_record,
            details="End-to-end encrypted email provider; strict recipient validation."
        )
    elif "mimecast" in target_text:
        return ProviderInfo(
            name="Mimecast Secure Gateway",
            spf_record=spf_record,
            details="Enterprise email security gateway with greylisting and rate-limiting."
        )
    elif "pphosted.com" in target_text or "proofpoint" in target_text:
        return ProviderInfo(
            name="Proofpoint",
            spf_record=spf_record,
            details="Enterprise security gateway with dynamic sender reputation."
        )
    elif "zoho" in target_text:
        return ProviderInfo(
            name="Zoho Mail",
            spf_record=spf_record,
            details="Cloud business email suite."
        )
    elif "_spf.google.com" in (spf_record or "").lower():
        return ProviderInfo(
            name="Google Workspace",
            spf_record=spf_record,
            details="Google Workspace mail servers return strict 550 codes for non-existent users."
        )
    elif "spf.protection.outlook.com" in (spf_record or "").lower():
        return ProviderInfo(
            name="Microsoft 365 / Exchange Online",
            spf_record=spf_record,
            details="Microsoft 365 gateway. Edge server may accept RCPT TO and bounce internally."
        )
    else:
        return ProviderInfo(
            name="Custom / Self-Hosted",
            spf_record=spf_record,
            details="Custom mail server infrastructure."
        )


def check_port_25_connectivity(
    mx_host: str,
    timeout: float = 5.0,
    proxy_url: Optional[str] = None
) -> bool:
    """
    Fast pre-flight check to determine if outbound TCP port 25 is reachable.
    Avoids multi-second timeouts on every single candidate if ISP blocks port 25.
    """
    try:
        sock = create_connection(mx_host, 25, timeout=timeout, proxy_url=proxy_url)
        sock.close()
        return True
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Port 25 connectivity check failed against {mx_host}: {e}")
        return False


def check_catch_all(
    mx_host: str,
    domain: str,
    timeout: float = 8.0,
    proxy_url: Optional[str] = None
) -> Tuple[bool, Optional[int], str]:
    """
    Probes a randomized, non-existent address to detect Catch-All / Accept-All configurations.
    Returns: (is_catch_all, smtp_code, smtp_message)
    """
    random_user = f"catchall_probe_{uuid.uuid4().hex[:12]}"
    test_email = f"{random_user}@{domain}"

    client = SMTPClient(mx_host, 25, timeout=timeout, proxy_url=proxy_url)
    try:
        code, msg = client.connect()
        if not (200 <= code < 300):
            return False, code, f"Banner error: {msg}"

        code, msg = client.helo()
        if not (200 <= code < 300):
            return False, code, f"EHLO error: {msg}"

        code, msg = client.mail_from(f"probe@{domain}")
        if not (200 <= code < 300):
            return False, code, f"MAIL FROM error: {msg}"

        code, msg = client.rcpt_to(test_email)
        client.quit()

        # 250 or 251 indicates the server accepted a randomized non-existent address
        if code in (250, 251):
            return True, code, "Domain accepts arbitrary recipients (Catch-All enabled)."
        elif code in (550, 551, 553):
            return False, code, "Domain strictly rejects unknown recipients."
        else:
            return False, code, f"Unexpected response: {code} {msg}"

    except (socket.timeout, TimeoutError):
        return False, None, "SMTP connection timed out during catch-all check."
    except ConnectionRefusedError:
        return False, None, "Connection refused (Port 25 blocked or server down)."
    except OSError as e:
        return False, None, f"Network error during catch-all check: {e}"
    finally:
        client.close()


def verify_single_candidate(
    email: str,
    mx_host: str,
    domain: str,
    timeout: float = 8.0,
    proxy_url: Optional[str] = None
) -> Tuple[VerificationStatus, Optional[int], str]:
    """
    Performs an individual SMTP RCPT TO mailbox check for a candidate address.
    """
    client = SMTPClient(mx_host, 25, timeout=timeout, proxy_url=proxy_url)
    try:
        code, msg = client.connect()
        if not (200 <= code < 300):
            return VerificationStatus.UNVERIFIED_TEMP_ERROR, code, msg

        code, msg = client.helo()
        if not (200 <= code < 300):
            return VerificationStatus.UNVERIFIED_TEMP_ERROR, code, msg

        code, msg = client.mail_from(f"check@{domain}")
        if not (200 <= code < 300):
            return VerificationStatus.UNVERIFIED_TEMP_ERROR, code, msg

        code, msg = client.rcpt_to(email)
        client.quit()

        if code in (250, 251):
            return VerificationStatus.VALID, code, "Mailbox verified deliverable (250 OK)"
        elif code in (550, 551, 552, 553, 554):
            return VerificationStatus.INVALID, code, f"Recipient rejected ({code}): {msg.strip()}"
        elif 400 <= code < 500:
            return VerificationStatus.UNVERIFIED_TEMP_ERROR, code, f"Temporary/Greylisted ({code}): {msg.strip()}"
        else:
            return VerificationStatus.UNVERIFIED_TEMP_ERROR, code, f"SMTP {code}: {msg.strip()}"

    except (socket.timeout, TimeoutError):
        return VerificationStatus.UNVERIFIED_TIMEOUT, None, "SMTP connection timed out"
    except (ConnectionRefusedError, OSError) as e:
        return VerificationStatus.UNVERIFIED_PORT_BLOCKED, None, f"Connection failure / Port 25 blocked: {e}"
    finally:
        client.close()


def verify_m365_cloud(email: str, timeout: float = 5.0) -> Tuple[Optional[VerificationStatus], Optional[int], str]:
    """
    Checks whether an email exists in a Microsoft 365 / Entra ID tenant via public HTTPS endpoint (Port 443).
    Bypasses Port 25 ISP blocks and third-party gateway catch-all filters (Proofpoint, Mimecast).
    Returns (status, code, message).
    """
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    payload = json.dumps({"Username": email}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if_exists = data.get("IfExistsResult")
            throttle = data.get("ThrottleStatus", 0)

            if throttle == 1:
                return VerificationStatus.UNVERIFIED_TEMP_ERROR, 429, "Microsoft 365 request throttled"

            # 0 = Exists in tenant
            if if_exists == 0:
                return VerificationStatus.VALID, 200, "Verified: Mailbox exists in Microsoft 365 Cloud Directory"
            # 1 = Does not exist
            elif if_exists == 1:
                return VerificationStatus.INVALID, 404, "Recipient not found in Microsoft 365 Cloud Directory"
            else:
                return None, None, f"M365 non-definitive response code: {if_exists}"
    except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
        logger.debug(f"M365 lookup timeout or error for {email}: {e}")
        return None, None, f"M365 lookup connection error: {e}"
    except Exception as e:
        logger.debug(f"M365 unexpected error for {email}: {e}")
        return None, None, f"M365 error: {e}"


def verify_pgp_keyring(email: str, timeout: float = 5.0) -> Tuple[Optional[VerificationStatus], Optional[int], str]:
    """
    Queries public OpenPGP keyserver (keyserver.ubuntu.com) over HTTPS (Port 443).
    Returns (status, code, message) if confirmed.
    """
    encoded_email = urllib.parse.quote(email)
    url = f"https://keyserver.ubuntu.com/pks/lookup?search={encoded_email}&op=index&options=mr"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line.startswith("uid:") and email.lower() in line.lower():
                    return VerificationStatus.VALID, 200, "Confirmed via Public OpenPGP Keyring (HTTPS)"
            return None, None, "Email not found in PGP keyring"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None, "Email not found in PGP keyring (404)"
        return None, None, f"PGP keyserver HTTP {e.code}"
    except Exception as e:
        logger.debug(f"PGP lookup error for {email}: {e}")
        return None, None, f"PGP lookup error: {e}"


def verify_github_commits(email: str, timeout: float = 5.0) -> Tuple[Optional[VerificationStatus], Optional[int], str]:
    """
    Queries GitHub public Search API for commit records authored by this email address.
    Returns (status, code, message) if confirmed.
    """
    encoded_email = urllib.parse.quote(email)
    url = f"https://api.github.com/search/commits?q=committer-email:{encoded_email}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.cloak-preview",
            "User-Agent": "POC-Recon-OSINT"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            count = data.get("total_count", 0)
            if count > 0:
                return VerificationStatus.VALID, 200, f"Confirmed via GitHub Commit History ({count} public commits)"
            return None, None, "No GitHub commits found"
    except Exception as e:
        logger.debug(f"GitHub search error for {email}: {e}")
        return None, None, f"GitHub search error: {e}"


def run_alternative_verification(
    candidates: List[Tuple[str, str]],
    domain: str,
    provider: Optional[ProviderInfo],
    timeout: float = 5.0,
    delay: float = 0.3
) -> List[CandidateResult]:
    """
    Executes alternative HTTPS-based verification (M365 Cloud Directory, PGP Keyrings, GitHub Commits).
    Runs completely over Port 443 (HTTPS) without Port 25 or external VPS requirements.
    """
    results: List[CandidateResult] = []
    is_m365 = bool(
        provider and (
            "Microsoft 365" in provider.name or
            "Exchange Online" in provider.name or
            "outlook.com" in provider.details.lower()
        )
    )

    # If provider wasn't explicitly detected as M365 by MX, check if domain is managed by M365:
    if not is_m365 and candidates:
        sample_email = candidates[0][0]
        st, _, _ = verify_m365_cloud(sample_email, timeout=timeout)
        if st in (VerificationStatus.VALID, VerificationStatus.INVALID):
            is_m365 = True

    for i, (email, pattern) in enumerate(candidates):
        if i > 0 and delay > 0:
            time.sleep(delay)

        status: Optional[VerificationStatus] = None
        code: Optional[int] = None
        msg: str = ""

        # Step 1: M365 Directory Check
        if is_m365:
            m_status, m_code, m_msg = verify_m365_cloud(email, timeout=timeout)
            if m_status is not None:
                status = m_status
                code = m_code
                msg = m_msg

        # Step 2: If still not verified, check Public PGP Keyring
        if status != VerificationStatus.VALID:
            p_status, p_code, p_msg = verify_pgp_keyring(email, timeout=timeout)
            if p_status == VerificationStatus.VALID:
                status = p_status
                code = p_code
                msg = p_msg

        # Step 3: If still not verified, check GitHub Commits
        if status != VerificationStatus.VALID:
            g_status, g_code, g_msg = verify_github_commits(email, timeout=timeout)
            if g_status == VerificationStatus.VALID:
                status = g_status
                code = g_code
                msg = g_msg

        # Fallback if no definitive status obtained
        if status is None:
            status = VerificationStatus.UNVERIFIED_PORT_BLOCKED
            code = None
            msg = "Port 25 blocked by ISP; HTTPS alternative checks non-conclusive"

        results.append(
            CandidateResult(
                email=email,
                pattern_name=pattern,
                status=status,
                smtp_code=code,
                smtp_message=msg
            )
        )

    return results


def run_verification(
    domain: str,
    person: NameParts,
    candidates: List[Tuple[str, str]],
    dns_timeout: float = 5.0,
    smtp_timeout: float = 8.0,
    delay: float = 0.5,
    proxy_url: Optional[str] = None,
    dry_run: bool = False,
    cloud_fallback: bool = True,
    early_exit: bool = True
) -> ReconResult:
    """
    Coordinates the end-to-end discovery and verification workflow:
    1. MX record lookup
    2. Provider fingerprinting
    3. Pre-flight Port 25 connectivity check
    4. Catch-All probe
    5. Candidate RCPT TO verification with rate-limiting
    """
    logger.info(f"Resolving MX records for {domain}...")
    mx_records = get_mx_records(domain, timeout=dns_timeout)

    result = ReconResult(
        target_domain=domain,
        person=person,
        mx_records=mx_records
    )

    if not mx_records:
        logger.warning(f"No MX records found for {domain}.")
        for email, pattern in candidates:
            result.candidates.append(
                CandidateResult(
                    email=email,
                    pattern_name=pattern,
                    status=VerificationStatus.NO_MX_RECORD,
                    smtp_message="No mail server found in DNS"
                )
            )
        return result

    # Fingerprint provider
    provider = fingerprint_mail_provider(domain, mx_records, timeout=dns_timeout)
    result.provider = provider

    # Dry-run / pattern-only mode
    if dry_run:
        for email, pattern in candidates:
            result.candidates.append(
                CandidateResult(
                    email=email,
                    pattern_name=pattern,
                    status=VerificationStatus.SKIPPED,
                    smtp_message="Verification skipped in dry-run mode"
                )
            )
        result.best_candidate = result.get_primary_candidate()
        return result

    primary_mx = mx_records[0].host
    logger.info(f"Primary MX server: {primary_mx}")

    # Pre-flight Port 25 check
    logger.info(f"Testing Port 25 connectivity to {primary_mx}...")
    port_25_open = check_port_25_connectivity(primary_mx, timeout=smtp_timeout, proxy_url=proxy_url)
    result.port_25_open = port_25_open

    if not port_25_open:
        if cloud_fallback:
            logger.info("Port 25 blocked by local network. Engaging HTTPS Cloud & Identity Verifiers...")
            result.verification_method = "HTTPS Cloud & Identity Verifier"
            result.candidates = run_alternative_verification(
                candidates=candidates,
                domain=domain,
                provider=provider,
                timeout=smtp_timeout,
                delay=delay
            )
            return result
        else:
            logger.warning("Port 25 is blocked or unreachable on current network.")
            for email, pattern in candidates:
                result.candidates.append(
                    CandidateResult(
                        email=email,
                        pattern_name=pattern,
                        status=VerificationStatus.UNVERIFIED_PORT_BLOCKED,
                        smtp_message="Outbound TCP port 25 blocked by local ISP or cloud firewall"
                    )
                )
            return result

    # Catch-all detection
    logger.info("Checking for Catch-All configuration...")
    is_catch_all, ca_code, ca_msg = check_catch_all(
        primary_mx, domain, timeout=smtp_timeout, proxy_url=proxy_url
    )
    result.is_catch_all = is_catch_all

    if is_catch_all:
        logger.warning("Domain is configured as Catch-All. Mailbox validity cannot be strictly confirmed.")

    # Candidate verification
    for i, (email, pattern) in enumerate(candidates):
        if is_catch_all:
            # Attempt HTTPS cloud resolution for catch-all domains (e.g. Microsoft 365 or PGP)
            resolved = False
            if cloud_fallback:
                is_m365 = bool(
                    provider and (
                        "Microsoft 365" in provider.name or
                        "Exchange Online" in provider.name or
                        "outlook.com" in provider.details.lower()
                    )
                )
                if is_m365:
                    m_st, m_cd, m_m = verify_m365_cloud(email, timeout=smtp_timeout)
                    if m_st == VerificationStatus.VALID:
                        result.candidates.append(
                            CandidateResult(
                                email=email,
                                pattern_name=pattern,
                                status=VerificationStatus.VALID,
                                smtp_code=200,
                                smtp_message="Confirmed: Mailbox exists in Microsoft 365 tenant (resolved catch-all)"
                            )
                        )
                        resolved = True
                    elif m_st == VerificationStatus.INVALID:
                        result.candidates.append(
                            CandidateResult(
                                email=email,
                                pattern_name=pattern,
                                status=VerificationStatus.INVALID,
                                smtp_code=404,
                                smtp_message="Recipient not found in Microsoft 365 tenant (resolved catch-all)"
                            )
                        )
                        resolved = True

                if not resolved:
                    p_st, p_cd, p_m = verify_pgp_keyring(email, timeout=smtp_timeout)
                    if p_st == VerificationStatus.VALID:
                        result.candidates.append(
                            CandidateResult(
                                email=email,
                                pattern_name=pattern,
                                status=VerificationStatus.VALID,
                                smtp_code=200,
                                smtp_message="Confirmed: Email verified via Public PGP Keyring (resolved catch-all)"
                            )
                        )
                        resolved = True

            if resolved:
                continue

            result.candidates.append(
                CandidateResult(
                    email=email,
                    pattern_name=pattern,
                    status=VerificationStatus.CATCH_ALL_UNVERIFIED,
                    smtp_code=ca_code,
                    smtp_message="Server accepts all recipients (Catch-All)"
                )
            )
            continue

        if i > 0 and delay > 0:
            time.sleep(delay)

        status, code, msg = verify_single_candidate(
            email=email,
            mx_host=primary_mx,
            domain=domain,
            timeout=smtp_timeout,
            proxy_url=proxy_url
        )

        result.candidates.append(
            CandidateResult(
                email=email,
                pattern_name=pattern,
                status=status,
                smtp_code=code,
                smtp_message=msg
            )
        )

        # If we successfully found a confirmed VALID email, we log it
        if status == VerificationStatus.VALID:
            logger.info(f"Found VALID email: {email}")
            if early_exit:
                result.best_candidate = result.candidates[-1]
                break

    if not result.best_candidate:
        result.best_candidate = result.get_primary_candidate()

    return result
