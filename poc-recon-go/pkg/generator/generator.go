package generator

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

func sanitizeASCII(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	res, _, _ := transform.String(t, s)
	res = strings.ToLower(res)
	reg := regexp.MustCompile(`[^a-z0-9]`)
	return reg.ReplaceAllString(res, "")
}

func GenerateEmailPatterns(domain string, person models.NameParts) []models.EmailCandidate {
	first := sanitizeASCII(person.FirstName)
	last := sanitizeASCII(person.LastName)
	middle := sanitizeASCII(person.MiddleName)

	if first == "" && last == "" {
		return nil
	}

	f := ""
	if len(first) > 0 {
		f = string(first[0])
	}

	l := ""
	if len(last) > 0 {
		l = string(last[0])
	}

	m := ""
	if len(middle) > 0 {
		m = string(middle[0])
	}

	type rawPattern struct {
		name  string
		local string
	}

	var raw []rawPattern

	if first != "" && last != "" {
		raw = append(raw,
			rawPattern{"first.last", first + "." + last},
			rawPattern{"first", first},
			rawPattern{"flast", f + last},
			rawPattern{"firstlast", first + last},
			rawPattern{"first_last", first + "_" + last},
			rawPattern{"last.first", last + "." + first},
			rawPattern{"f.last", f + "." + last},
			rawPattern{"last", last},
			rawPattern{"lfirst", l + first},
			rawPattern{"first.l", first + "." + l},
			rawPattern{"f_last", f + "_" + last},
			rawPattern{"firstl", first + l},
			rawPattern{"lastf", last + f},
			rawPattern{"first-last", first + "-" + last},
			rawPattern{"last_first", last + "_" + first},
			rawPattern{"l.first", l + "." + first},
			rawPattern{"last.f", last + "." + f},
		)

		if middle != "" {
			raw = append(raw,
				rawPattern{"first.m.last", first + "." + m + "." + last},
				rawPattern{"fmlast", f + m + last},
				rawPattern{"firstmiddlelast", first + middle + last},
				rawPattern{"first.middle.last", first + "." + middle + "." + last},
			)
		}
	} else if first != "" {
		raw = append(raw, rawPattern{"first", first})
	} else if last != "" {
		raw = append(raw, rawPattern{"last", last})
	}

	seen := make(map[string]bool)
	var candidates []models.EmailCandidate

	for _, p := range raw {
		email := p.local + "@" + domain
		if !seen[email] {
			seen[email] = true
			candidates = append(candidates, models.EmailCandidate{
				Email:       email,
				PatternName: p.name,
				Status:      models.StatusUnverified,
			})
		}
	}

	return candidates
}
