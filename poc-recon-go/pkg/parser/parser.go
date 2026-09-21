package parser

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

var (
	honorifics = map[string]bool{
		"mr": true, "mrs": true, "ms": true, "miss": true, "dr": true,
		"prof": true, "sir": true, "rev": true, "hon": true,
	}
	degrees = map[string]bool{
		"phd": true, "md": true, "jd": true, "mba": true, "bsc": true,
		"msc": true, "ba": true, "ma": true, "esq": true, "cpa": true,
		"jr": true, "sr": true, "ii": true, "iii": true, "iv": true,
	}
)

func NormalizeDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL/domain: %w", err)
	}

	host := parsed.Hostname()
	host = strings.ToLower(strings.Trim(host, "."))

	if strings.HasPrefix(host, "www.") {
		host = host[4:]
	}

	if !strings.Contains(host, ".") {
		return "", fmt.Errorf("domain must contain a TLD (e.g., example.com)")
	}

	return host, nil
}

func ParsePersonName(raw string) models.NameParts {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return models.NameParts{}
	}

	clean := strings.ReplaceAll(raw, ",", " ")
	tokens := strings.Fields(clean)

	var filtered []string
	for _, tok := range tokens {
		lower := strings.ToLower(strings.Trim(tok, "."))
		if honorifics[lower] || degrees[lower] {
			continue
		}
		filtered = append(filtered, tok)
	}

	if len(filtered) == 0 {
		return models.NameParts{
			FullName: raw,
		}
	}

	first := filtered[0]
	middle := ""
	last := ""

	if len(filtered) == 2 {
		last = filtered[1]
	} else if len(filtered) > 2 {
		middle = strings.Join(filtered[1:len(filtered)-1], " ")
		last = filtered[len(filtered)-1]
	}

	return models.NameParts{
		FirstName:  first,
		MiddleName: middle,
		LastName:   last,
		FullName:   strings.Join(filtered, " "),
	}
}

func ExtractNameFromLinkedInSlug(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	re := regexp.MustCompile(`linkedin\.com/in/([^/?#]+)`)
	matches := re.FindStringSubmatch(rawURL)
	if len(matches) < 2 {
		return ""
	}

	slug := matches[1]
	// Remove trailing hashes/IDs like -a1b2c3d4 or -123456
	slug = regexp.MustCompile(`-[0-9a-f]{5,}$`).ReplaceAllString(slug, "")
	slug = regexp.MustCompile(`-[0-9]+$`).ReplaceAllString(slug, "")

	parts := strings.Split(slug, "-")
	var nameParts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			nameParts = append(nameParts, strings.Title(strings.ToLower(p)))
		}
	}

	return strings.Join(nameParts, " ")
}
