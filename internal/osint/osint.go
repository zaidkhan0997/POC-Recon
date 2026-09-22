package osint

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

var roleAccounts = map[string]bool{
	"info": true, "contact": true, "support": true, "sales": true, "admin": true,
	"administrator": true, "help": true, "billing": true, "office": true, "press": true,
	"media": true, "jobs": true, "careers": true, "hr": true, "legal": true,
	"security": true, "privacy": true, "compliance": true, "abuse": true,
	"postmaster": true, "hostmaster": true, "dmarc": true, "noc": true, "marketing": true,
	"hello": true, "team": true, "inquiries": true, "general": true, "service": true,
	"tech": true, "mail": true, "webmaster": true,
}

func ExtractPatternFromLocalPart(lp string) string {
	lp = strings.ToLower(strings.TrimSpace(lp))
	if roleAccounts[lp] {
		return ""
	}

	if strings.Contains(lp, ".") {
		parts := strings.Split(lp, ".")
		if len(parts) == 2 {
			if len(parts[0]) == 1 && len(parts[1]) > 1 {
				return "f.last"
			} else if len(parts[0]) > 1 && len(parts[1]) == 1 {
				return "first.l"
			} else if len(parts[0]) > 1 && len(parts[1]) > 1 {
				return "first.last"
			}
		} else if len(parts) == 3 {
			return "first.m.last"
		}
	} else if strings.Contains(lp, "_") {
		parts := strings.Split(lp, "_")
		if len(parts) == 2 {
			if len(parts[0]) == 1 && len(parts[1]) > 1 {
				return "f_last"
			} else if len(parts[0]) > 1 && len(parts[1]) > 1 {
				return "first_last"
			}
		}
	} else if strings.Contains(lp, "-") {
		parts := strings.Split(lp, "-")
		if len(parts) == 2 {
			if len(parts[0]) == 1 && len(parts[1]) > 1 {
				return "f-last"
			} else if len(parts[0]) > 1 && len(parts[1]) > 1 {
				return "first-last"
			}
		} else if len(parts) == 3 {
			return "first-m-last"
		}
	} else {
		// Single token: e.g. zaid (first) or zkhan (flast) or compound
		if len(lp) <= 8 && isAlpha(lp) {
			return "first"
		} else if len(lp) > 8 && isAlpha(lp) {
			return "firstlast"
		}
	}

	return ""
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func DetectDomainEmailPattern(
	domain string,
	candidates []models.CandidateResult,
	timeout time.Duration,
) (string, string, []string, *models.CandidateResult) {
	domClean := strings.ToLower(strings.TrimSpace(domain))
	discovered := make(map[string]bool)
	emailRegex := regexp.MustCompile(fmt.Sprintf(`(?i)[a-zA-Z0-9_.+-]+@%s`, regexp.QuoteMeta(domClean)))

	// 1. DNS DMARC TXT record
	txtRecords, err := net.LookupTXT("_dmarc." + domClean)
	if err == nil {
		for _, txt := range txtRecords {
			matches := emailRegex.FindAllString(txt, -1)
			for _, m := range matches {
				discovered[strings.ToLower(m)] = true
			}
		}
	}

	// 2. OpenPGP keyserver lookup for domain
	pgpClient := &http.Client{Timeout: timeout}
	pgpURL := fmt.Sprintf("https://keyserver.ubuntu.com/pks/lookup?search=%s&op=index&options=mr", url.QueryEscape("@"+domClean))
	req, err := http.NewRequest("GET", pgpURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "POC-Recon-Domain-OSINT/1.0")
		resp, err := pgpClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			matches := emailRegex.FindAllString(string(body), -1)
			for _, m := range matches {
				discovered[strings.ToLower(m)] = true
			}
		}
	}

	// 3. Web scraping (Security.txt, contact, about, team, homepage)
	probeURLs := []string{
		fmt.Sprintf("https://%s/.well-known/security.txt", domClean),
		fmt.Sprintf("https://%s/security.txt", domClean),
		fmt.Sprintf("https://%s/contact", domClean),
		fmt.Sprintf("https://%s/contact-us", domClean),
		fmt.Sprintf("https://%s/about", domClean),
		fmt.Sprintf("https://%s/team", domClean),
		fmt.Sprintf("https://%s/people", domClean),
		fmt.Sprintf("https://%s/company", domClean),
		fmt.Sprintf("https://%s/", domClean),
	}

	webClient := &http.Client{Timeout: 2500 * time.Millisecond}
	for _, pURL := range probeURLs {
		if len(discovered) >= 15 {
			break
		}
		wReq, err := http.NewRequest("GET", pURL, nil)
		if err != nil {
			continue
		}
		wReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) POC-Recon/1.0")
		resp, err := webClient.Do(wReq)
		if err == nil {
			lr := io.LimitReader(resp.Body, 262144) // 256KB limit
			body, _ := io.ReadAll(lr)
			resp.Body.Close()
			matches := emailRegex.FindAllString(string(body), -1)
			for _, m := range matches {
				discovered[strings.ToLower(m)] = true
			}
		}
	}

	// 4. Certificate Transparency Log search (crt.sh)
	if len(discovered) < 15 {
		crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domClean))
		crtClient := &http.Client{Timeout: 3 * time.Second}
		cReq, err := http.NewRequest("GET", crtURL, nil)
		if err == nil {
			cReq.Header.Set("User-Agent", "POC-Recon-CT-Log-OSINT/1.0")
			resp, err := crtClient.Do(cReq)
			if err == nil {
				lr := io.LimitReader(resp.Body, 524288) // 512KB limit
				body, _ := io.ReadAll(lr)
				resp.Body.Close()
				matches := emailRegex.FindAllString(string(body), -1)
				for _, m := range matches {
					discovered[strings.ToLower(m)] = true
				}
			}
		}
	}

	var sortedDiscovered []string
	for em := range discovered {
		sortedDiscovered = append(sortedDiscovered, em)
	}
	sort.Strings(sortedDiscovered)

	// Check for direct candidate match
	var directMatch *models.CandidateResult
	candMap := make(map[string]models.CandidateResult)
	for _, c := range candidates {
		candMap[strings.ToLower(c.Email)] = c
	}

	for _, em := range sortedDiscovered {
		if match, ok := candMap[em]; ok {
			directMatch = &match
			directMatch.Status = models.StatusValid
			directMatch.Confidence = 100
			code := 200
			directMatch.SMTPCode = &code
			directMatch.SMTPMessage = "Confirmed: Exact match in public domain OSINT records"
			break
		}
	}

	// Analyze patterns from discovered emails
	patternCounts := make(map[string]int)
	for _, em := range sortedDiscovered {
		lp := strings.Split(em, "@")[0]
		pat := ExtractPatternFromLocalPart(lp)
		if pat != "" {
			patternCounts[pat]++
		}
	}

	detectedPattern := ""
	detectedSource := ""

	if directMatch != nil {
		detectedPattern = directMatch.PatternName
		detectedSource = fmt.Sprintf("Confirmed exact match in public domain OSINT (%s)", directMatch.Email)
	} else if len(patternCounts) > 0 {
		bestPat := ""
		bestCount := -1
		for p, count := range patternCounts {
			if count > bestCount {
				bestCount = count
				bestPat = p
			}
		}
		detectedPattern = bestPat

		var samples []string
		for _, em := range sortedDiscovered {
			if ExtractPatternFromLocalPart(strings.Split(em, "@")[0]) == detectedPattern {
				samples = append(samples, em)
				if len(samples) >= 2 {
					break
				}
			}
		}
		detectedSource = fmt.Sprintf("Inferred from %d matching domain email(s) (e.g. %s)", bestCount, strings.Join(samples, ", "))
	}

	return detectedPattern, detectedSource, sortedDiscovered, directMatch
}

type Engine struct {
	Timeout time.Duration
}

func NewEngine(timeout time.Duration) *Engine {
	return &Engine{Timeout: timeout}
}

func (e *Engine) DetectDomainPattern(domain string, person models.NameParts) (string, string, []string, string) {
	var testCands []models.CandidateResult
	f := strings.ToLower(person.FirstName)
	l := strings.ToLower(person.LastName)
	if f != "" {
		testCands = append(testCands, models.CandidateResult{Email: fmt.Sprintf("%s@%s", f, domain), PatternName: "first"})
		if l != "" {
			fInit := string(f[0])
			testCands = append(testCands,
				models.CandidateResult{Email: fmt.Sprintf("%s.%s@%s", f, l, domain), PatternName: "first.last"},
				models.CandidateResult{Email: fmt.Sprintf("%s%s@%s", fInit, l, domain), PatternName: "flast"},
				models.CandidateResult{Email: fmt.Sprintf("%s%s@%s", f, l, domain), PatternName: "firstlast"},
				models.CandidateResult{Email: fmt.Sprintf("%s_%s@%s", f, l, domain), PatternName: "first_last"},
				models.CandidateResult{Email: fmt.Sprintf("%s.%s@%s", l, f, domain), PatternName: "last.first"},
				models.CandidateResult{Email: fmt.Sprintf("%s@%s", l, domain), PatternName: "last"},
			)
		}
	}

	pat, src, discovered, directMatch := DetectDomainEmailPattern(domain, testCands, e.Timeout)
	directStr := ""
	if directMatch != nil {
		directStr = directMatch.Email
	}
	return pat, src, discovered, directStr
}
