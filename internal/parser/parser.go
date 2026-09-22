package parser

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

var (
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

	prefixes = map[string]bool{
		"dr": true, "dr.": true, "mr": true, "mr.": true, "mrs": true, "mrs.": true,
		"ms": true, "ms.": true, "prof": true, "prof.": true, "sir": true, "rev": true,
		"rev.": true, "hon": true, "hon.": true, "eng": true, "eng.": true, "ceo": true,
		"cto": true, "cfo": true, "cmo": true, "coo": true, "founder": true,
	}

	suffixes = map[string]bool{
		"jr": true, "jr.": true, "sr": true, "sr.": true, "ii": true, "iii": true,
		"iv": true, "phd": true, "ph.d": true, "ph.d.": true, "md": true, "m.d.": true,
		"mba": true, "m.b.a.": true, "esq": true, "esq.": true, "cpa": true, "c.p.a.": true,
		"pe": true, "p.e.": true, "jd": true, "j.d.": true, "bsc": true, "msc": true,
		"eng": true, "ret": true, "ret.": true,
	}
)

func NormalizeDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("target domain cannot be empty")
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil && u.Host != "" {
			raw = u.Host
		}
	}

	// Remove path or query string if present without scheme
	if slashIdx := strings.Index(raw, "/"); slashIdx != -1 {
		raw = raw[:slashIdx]
	}
	if colonIdx := strings.Index(raw, ":"); colonIdx != -1 {
		raw = raw[:colonIdx]
	}

	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "www.")

	if !domainRegex.MatchString(raw) {
		return "", fmt.Errorf("invalid domain format: %q", raw)
	}

	return raw, nil
}

func CleanToken(token string) string {
	token = strings.Trim(token, ",.;:-_\"'()[]{}")
	return token
}

func ParsePersonName(raw string) models.NameParts {
	raw = strings.TrimSpace(raw)
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return models.NameParts{RawName: raw}
	}

	var cleaned []string
	for _, p := range parts {
		token := CleanToken(p)
		lower := strings.ToLower(token)
		if prefixes[lower] || suffixes[lower] {
			continue
		}
		if token != "" {
			cleaned = append(cleaned, token)
		}
	}

	if len(cleaned) == 0 {
		cleaned = parts
	}

	res := models.NameParts{
		RawName: raw,
	}

	switch len(cleaned) {
	case 1:
		res.FirstName = capitalize(cleaned[0])
		res.FullName = res.FirstName
	case 2:
		res.FirstName = capitalize(cleaned[0])
		res.LastName = capitalize(cleaned[1])
		res.FullName = fmt.Sprintf("%s %s", res.FirstName, res.LastName)
	default:
		res.FirstName = capitalize(cleaned[0])
		res.LastName = capitalize(cleaned[len(cleaned)-1])
		res.MiddleName = capitalize(strings.Join(cleaned[1:len(cleaned)-1], " "))
		res.FullName = fmt.Sprintf("%s %s %s", res.FirstName, res.MiddleName, res.LastName)
	}

	return res
}

func ExtractNameFromLinkedInSlug(slugOrURL string) *models.NameParts {
	s := strings.TrimSpace(slugOrURL)
	if strings.Contains(s, "linkedin.com/in/") {
		idx := strings.Index(s, "linkedin.com/in/")
		s = s[idx+len("linkedin.com/in/"):]
	}
	s = strings.Trim(s, "/")
	if qIdx := strings.Index(s, "?"); qIdx != -1 {
		s = s[:qIdx]
	}

	// Remove trailing numeric hash IDs like -12345678 or -a1b2c3d4
	re := regexp.MustCompile(`-[0-9a-f]{5,}$`)
	s = re.ReplaceAllString(s, "")

	tokens := strings.Split(s, "-")
	var valid []string
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if len(t) > 0 && !isNumeric(t) {
			valid = append(valid, capitalize(t))
		}
	}

	if len(valid) == 0 {
		return nil
	}

	res := &models.NameParts{
		RawName: strings.Join(valid, " "),
	}
	if len(valid) == 1 {
		res.FirstName = valid[0]
		res.FullName = valid[0]
	} else if len(valid) == 2 {
		res.FirstName = valid[0]
		res.LastName = valid[1]
		res.FullName = fmt.Sprintf("%s %s", valid[0], valid[1])
	} else {
		res.FirstName = valid[0]
		res.LastName = valid[len(valid)-1]
		res.MiddleName = strings.Join(valid[1:len(valid)-1], " ")
		res.FullName = fmt.Sprintf("%s %s %s", res.FirstName, res.MiddleName, res.LastName)
	}
	return res
}

func ParseName(raw string) models.NameParts {
	return ParsePersonName(raw)
}

func ParseLinkedInSlug(slugOrURL string) *models.NameParts {
	return ExtractNameFromLinkedInSlug(slugOrURL)
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(strings.ToLower(s))
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
