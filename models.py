from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


class VerificationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    CATCH_ALL_UNVERIFIED = "CATCH-ALL / UNVERIFIED"
    UNVERIFIED_TIMEOUT = "UNVERIFIED / TIMEOUT"
    UNVERIFIED_PORT_BLOCKED = "UNVERIFIED / PORT BLOCKED"
    UNVERIFIED_TEMP_ERROR = "UNVERIFIED / TEMPORARY ERROR"
    NO_MX_RECORD = "NO MX RECORD"
    SKIPPED = "SKIPPED (DRY-RUN)"

    def __str__(self) -> str:
        return self.value


@dataclass
class NameParts:
    first_name: str
    middle_name: Optional[str] = None
    last_name: str = ""
    raw_name: str = ""

    @property
    def full_name(self) -> str:
        parts = [self.first_name]
        if self.middle_name:
            parts.append(self.middle_name)
        if self.last_name:
            parts.append(self.last_name)
        return " ".join(parts).strip()


@dataclass
class MXRecord:
    host: str
    priority: int


@dataclass
class ProviderInfo:
    name: str
    spf_record: Optional[str] = None
    details: str = ""


@dataclass
class CandidateResult:
    email: str
    pattern_name: str
    status: VerificationStatus
    smtp_code: Optional[int] = None
    smtp_message: Optional[str] = None
    confidence: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "pattern": self.pattern_name,
            "status": str(self.status),
            "smtp_code": self.smtp_code,
            "smtp_message": self.smtp_message,
            "confidence": self.confidence,
        }


@dataclass
class ReconResult:
    target_domain: str
    person: NameParts
    mx_records: List[MXRecord] = field(default_factory=list)
    provider: Optional[ProviderInfo] = None
    is_catch_all: bool = False
    port_25_open: bool = True
    verification_method: str = "SMTP (Port 25)"
    candidates: List[CandidateResult] = field(default_factory=list)
    best_candidate: Optional[CandidateResult] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "domain": self.target_domain,
            "verification_method": self.verification_method,
            "person": {
                "first_name": self.person.first_name,
                "middle_name": self.person.middle_name,
                "last_name": self.person.last_name,
                "raw_name": self.person.raw_name,
                "full_name": self.person.full_name,
            },
            "provider": {
                "name": self.provider.name if self.provider else "Unknown",
                "spf_record": self.provider.spf_record if self.provider else None,
                "details": self.provider.details if self.provider else "",
            } if self.provider else None,
            "mx_records": [{"host": mx.host, "priority": mx.priority} for mx in self.mx_records],
            "is_catch_all": self.is_catch_all,
            "port_25_open": self.port_25_open,
            "best_candidate": self.get_primary_candidate().to_dict() if self.get_primary_candidate() else None,
            "candidates": [c.to_dict() for c in self.candidates],
        }

    def get_valid_emails(self) -> List[str]:
        """Returns list of verified VALID email addresses."""
        return [c.email for c in self.candidates if c.status == VerificationStatus.VALID]

    def get_primary_candidate(self) -> Optional[CandidateResult]:
        """
        Returns the single winning/primary working candidate:
        1. Explicit best_candidate if set
        2. First candidate confirmed VALID (100% deliverable)
        3. Highest ranked candidate / fallback
        """
        if self.best_candidate:
            return self.best_candidate
        valid_candidates = [c for c in self.candidates if c.status == VerificationStatus.VALID]
        if valid_candidates:
            return valid_candidates[0]
        if self.candidates:
            # Sort by confidence descending
            return max(self.candidates, key=lambda c: c.confidence)
        return None

