import re
import unicodedata
from typing import List, Tuple, Optional

# Basic RFC 5322 compliant regex for local-part & domain
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)


def _clean_token(token: str) -> str:
    """
    Normalizes a name token to ASCII, removes diacritics/accents,
    and strips non-alphanumeric characters.
    """
    if not token:
        return ""
    # Normalize unicode to decomposed form and remove non-spacing marks
    nfkd = unicodedata.normalize("NFKD", token)
    ascii_bytes = nfkd.encode("ASCII", "ignore")
    ascii_str = ascii_bytes.decode("utf-8").lower()
    # Strip any punctuation like apostrophes, hyphens, periods
    clean = re.sub(r"[^a-z0-9]", "", ascii_str)
    return clean


def generate_email_patterns(
    first_name: str,
    middle_name: Optional[str],
    last_name: str,
    domain: str
) -> List[Tuple[str, str]]:
    """
    Generates standard corporate email candidates using parsed name components
    and target domain. Returns a deduplicated list of (email_address, pattern_name) tuples,
    maintaining corporate priority order.
    """
    fn = _clean_token(first_name)
    ln = _clean_token(last_name)
    mn = _clean_token(middle_name) if middle_name else ""
    dom = domain.strip().lower()

    if not fn:
        return []

    f_init = fn[0]
    l_init = ln[0] if ln else ""
    m_init = mn[0] if mn else ""

    patterns: List[Tuple[str, str]] = []

    if ln:
        # Standard corporate patterns (with both first and last name)
        patterns.append((f"{fn}.{ln}@{dom}", "first.last"))
        patterns.append((f"{fn}@{dom}", "first"))
        patterns.append((f"{f_init}{ln}@{dom}", "flast"))
        patterns.append((f"{fn}{ln}@{dom}", "firstlast"))
        patterns.append((f"{fn}_{ln}@{dom}", "first_last"))
        patterns.append((f"{ln}.{fn}@{dom}", "last.first"))
        patterns.append((f"{f_init}.{ln}@{dom}", "f.last"))
        patterns.append((f"{ln}@{dom}", "last"))
        patterns.append((f"{l_init}{fn}@{dom}", "lfirst"))
        patterns.append((f"{fn}.{l_init}@{dom}", "first.l"))
        patterns.append((f"{f_init}_{ln}@{dom}", "f_last"))

        # If middle name / initial exists
        if mn:
            patterns.append((f"{fn}.{m_init}.{ln}@{dom}", "first.m.last"))
            patterns.append((f"{fn}{m_init}{ln}@{dom}", "firstmlast"))
            patterns.append((f"{f_init}{m_init}{ln}@{dom}", "fmlast"))
            patterns.append((f"{fn}.{mn}.{ln}@{dom}", "first.middle.last"))
    else:
        # Only single name available
        patterns.append((f"{fn}@{dom}", "first"))
        patterns.append((f"contact@{dom}", "contact"))
        patterns.append((f"info@{dom}", "info"))

    # Deduplicate while preserving order & validate syntax
    seen = set()
    deduped_patterns: List[Tuple[str, str]] = []

    for email, pattern_name in patterns:
        email_clean = email.strip().lower()
        if email_clean not in seen and EMAIL_REGEX.match(email_clean):
            seen.add(email_clean)
            deduped_patterns.append((email_clean, pattern_name))

    return deduped_patterns
