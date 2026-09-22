package generator

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$`)

func cleanToken(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	normalized, _, _ := transform.String(t, s)

	var sb strings.Builder
	for _, r := range strings.ToLower(normalized) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

type rawPattern struct {
	PatternName string
	LocalPart   string
}

func GenerateEmailPatterns(domain string, person models.NameParts, preferredPattern string) []models.CandidateResult {
	first := cleanToken(person.FirstName)
	last := cleanToken(person.LastName)
	middle := cleanToken(person.MiddleName)
	dom := strings.ToLower(strings.TrimSpace(domain))

	if first == "" {
		return nil
	}

	var raw []rawPattern

	if last != "" {
		fInit := string(first[0])
		lInit := string(last[0])

		raw = append(raw,
			rawPattern{"first.last", first + "." + last},
			rawPattern{"first", first},
			rawPattern{"flast", fInit + last},
			rawPattern{"firstlast", first + last},
			rawPattern{"first_last", first + "_" + last},
			rawPattern{"first-last", first + "-" + last},
			rawPattern{"last.first", last + "." + first},
			rawPattern{"f.last", fInit + "." + last},
			rawPattern{"last", last},
			rawPattern{"lfirst", lInit + first},
			rawPattern{"first.l", first + "." + lInit},
			rawPattern{"f_last", fInit + "_" + last},
			rawPattern{"lastfirst", last + first},
			rawPattern{"last_first", last + "_" + first},
			rawPattern{"last-first", last + "-" + first},
		)

		if middle != "" {
			mInit := string(middle[0])
			raw = append(raw,
				rawPattern{"first.m.last", first + "." + mInit + "." + last},
				rawPattern{"firstmlast", first + mInit + last},
				rawPattern{"fmlast", fInit + mInit + last},
				rawPattern{"first.middle.last", first + "." + middle + "." + last},
				rawPattern{"first-m-last", first + "-" + mInit + "-" + last},
			)
		}
	} else {
		raw = append(raw,
			rawPattern{"first", first},
			rawPattern{"contact", "contact"},
			rawPattern{"info", "info"},
		)
	}

	seen := make(map[string]bool)
	var candidates []models.CandidateResult

	for _, p := range raw {
		email := p.LocalPart + "@" + dom
		emailLower := strings.ToLower(email)
		if !seen[emailLower] && emailRegex.MatchString(emailLower) {
			seen[emailLower] = true
			candidates = append(candidates, models.CandidateResult{
				Email:       emailLower,
				PatternName: p.PatternName,
				Status:      models.StatusUnverified,
			})
		}
	}

	// Elevate preferred pattern if specified
	if preferredPattern != "" {
		prefClean := strings.ToLower(strings.TrimSpace(preferredPattern))
		var prioritized []models.CandidateResult
		var others []models.CandidateResult

		for _, c := range candidates {
			if strings.EqualFold(c.PatternName, prefClean) {
				prioritized = append(prioritized, c)
			} else {
				others = append(others, c)
			}
		}
		candidates = append(prioritized, others...)
	}

	return candidates
}

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) Generate(person models.NameParts, domain string, preferredPattern string) []models.CandidateResult {
	return GenerateEmailPatterns(domain, person, preferredPattern)
}
