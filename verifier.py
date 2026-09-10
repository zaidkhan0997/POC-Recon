import logging
import socket
import time
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


def run_verification(
    domain: str,
    person: NameParts,
    candidates: List[Tuple[str, str]],
    dns_timeout: float = 5.0,
    smtp_timeout: float = 8.0,
    delay: float = 0.5,
    proxy_url: Optional[str] = None,
    dry_run: bool = False
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
        return result

    primary_mx = mx_records[0].host
    logger.info(f"Primary MX server: {primary_mx}")

    # Pre-flight Port 25 check
    logger.info(f"Testing Port 25 connectivity to {primary_mx}...")
    port_25_open = check_port_25_connectivity(primary_mx, timeout=smtp_timeout, proxy_url=proxy_url)
    result.port_25_open = port_25_open

    if not port_25_open:
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

    return result
