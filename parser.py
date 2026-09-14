import re
from urllib.parse import urlparse
from typing import Optional
from models import NameParts

# Regex for basic domain validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Common honorifics and prefixes to strip (case-insensitive)
HONORIFICS = {
    "mr", "mr.", "mrs", "mrs.", "ms", "ms.", "miss",
    "dr", "dr.", "prof", "prof.", "rev", "rev.", "sir", "dame"
}

# Common credentials and suffixes to strip (case-insensitive)
CREDENTIALS_AND_SUFFIXES = {
    "phd", "ph.d.", "ph.d", "mba", "pmp", "md", "m.d.", "cpa",
    "jd", "j.d.", "esq", "esq.", "jr", "jr.", "sr", "sr.",
    "ii", "iii", "iv", "cissp", "cfa", "pe", "rn", "bsn", "llm"
}


def normalize_domain(url: str) -> str:
    """
    Normalizes a website URL or hostname string into a clean, lowercase domain name.
    Strips protocol, www, paths, queries, fragments, ports, and trailing slashes.
    Validates domain syntax.
    """
    if not url or not url.strip():
        raise ValueError("URL/Domain cannot be empty.")

    clean_url = url.strip()

    # Prepend scheme if missing so urllib.parse can properly extract netloc
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    parsed = urlparse(clean_url)
    domain = parsed.netloc or parsed.path

    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    # Strip www. prefix
    if domain.lower().startswith("www."):
        domain = domain[4:]

    domain = domain.strip("/").strip().lower()

    if not DOMAIN_REGEX.match(domain):
        raise ValueError(f"Invalid domain format: '{domain}'")

    return domain


def parse_person_name(name: str) -> NameParts:
    """
    Parses a person's name into first, optional middle, and last name components.
    Strips common honorifics, titles, credentials, and certifications.
    """
    if not name or not name.strip():
        raise ValueError("Name cannot be empty.")

    raw = name.strip()

    # Replace commas, semicolons, and parentheses used for credentials (e.g. "Jane Doe, MBA")
    normalized = re.sub(r"[,;()]", " ", raw)
    tokens = [t.strip() for t in normalized.split() if t.strip()]

    if not tokens:
        raise ValueError("No valid name characters found.")

    filtered_tokens = []
    for token in tokens:
        clean_token = token.rstrip(".").lower()
        full_token = token.lower()

        # Check if honorific or credential
        if full_token in HONORIFICS or clean_token in HONORIFICS:
            continue
        if full_token in CREDENTIALS_AND_SUFFIXES or clean_token in CREDENTIALS_AND_SUFFIXES:
            continue

        token_stripped = token.strip(".")
        if token_stripped:
            filtered_tokens.append(token_stripped)

    if not filtered_tokens:
        # Fallback if everything was stripped
        filtered_tokens = [t.strip(".") for t in tokens if t.strip(".")]

    # Capitalize cleaned tokens nicely
    cleaned_tokens = [t.capitalize() if t.islower() else t for t in filtered_tokens]

    first_name = cleaned_tokens[0]
    middle_name: Optional[str] = None
    last_name = ""

    if len(cleaned_tokens) == 2:
        last_name = cleaned_tokens[1]
    elif len(cleaned_tokens) == 3:
        middle_name = cleaned_tokens[1]
        last_name = cleaned_tokens[2]
    elif len(cleaned_tokens) > 3:
        middle_name = " ".join(cleaned_tokens[1:-1])
        last_name = cleaned_tokens[-1]

    return NameParts(
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        raw_name=raw
    )


def extract_name_from_linkedin_slug(slug_or_url: str) -> Optional[NameParts]:
    """
    Parses a LinkedIn profile URL or slug and extracts candidate name components.
    Does NOT make any network or scraping requests.

    Example:
      https://www.linkedin.com/in/jane-doe-12345/ -> Jane Doe
      jane-doe -> Jane Doe
    """
    if not slug_or_url or not slug_or_url.strip():
        return None

    clean = slug_or_url.strip()

    # Extract slug from URL if full URL is provided
    if "/in/" in clean:
        match = re.search(r"/in/([^/?#]+)", clean)
        if match:
            clean = match.group(1)
        else:
            return None
    elif "linkedin.com" in clean:
        # User entered something like linkedin.com/jane-doe
        parts = clean.rstrip("/").split("/")
        clean = parts[-1]

    # Remove trailing random hashes/numbers common in LinkedIn slugs (e.g. -12345678, -a1b2c3, or johnsmith18)
    slug = clean.strip()
    slug = re.sub(r"-[0-9a-fA-F]{4,}$", "", slug)
    slug = re.sub(r"-\d+$", "", slug)
    slug = re.sub(r"\d+$", "", slug)

    # Split by hyphen or underscore
    parts = [p.capitalize() for p in re.split(r"[-_.]+", slug) if p and not p.isdigit()]

    if not parts:
        return None

    name_str = " ".join(parts)
    try:
        return parse_person_name(name_str)
    except ValueError:
        return None
