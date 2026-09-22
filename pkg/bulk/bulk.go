package bulk

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zaidkhan0997/POC-Recon/internal/dns"
	"github.com/zaidkhan0997/POC-Recon/internal/generator"
	"github.com/zaidkhan0997/POC-Recon/internal/osint"
	"github.com/zaidkhan0997/POC-Recon/internal/parser"
	"github.com/zaidkhan0997/POC-Recon/internal/scorer"
	"github.com/zaidkhan0997/POC-Recon/internal/smtp"
	"github.com/zaidkhan0997/POC-Recon/pkg/cache"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// LeadTarget represents a single target input for bulk reconnaissance
type LeadTarget struct {
	Domain          string `json:"domain"`
	FullName        string `json:"full_name"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	Pattern         string `json:"pattern,omitempty"`
	PersonLinkedIn  string `json:"person_linkedin,omitempty"`
	CompanyLinkedIn string `json:"company_linkedin,omitempty"`
}

// BatchProgress represents real-time progress updates during batch processing
type BatchProgress struct {
	Index       int                 `json:"index"`
	Total       int                 `json:"total"`
	CurrentLead LeadTarget          `json:"current_lead"`
	Result      *models.ReconResult `json:"result,omitempty"`
	ValidCount  int                 `json:"valid_count"`
	Percentage  int                 `json:"percentage"`
}

// ParseCSV extracts lead targets from any CSV input with intelligent column mapping
func ParseCSV(r io.Reader) ([]LeadTarget, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV must contain at least a header row and 1 data row")
	}

	headers := rows[0]
	colDomain := -1
	colName := -1
	colFirst := -1
	colLast := -1
	colPattern := -1
	colPersonLI := -1
	colCompanyLI := -1

	for i, h := range headers {
		norm := strings.ToLower(strings.TrimSpace(h))
		norm = strings.ReplaceAll(norm, "_", "")
		norm = strings.ReplaceAll(norm, " ", "")

		switch {
		case strings.Contains(norm, "domain") || strings.Contains(norm, "website") || norm == "url" || norm == "companyurl":
			if colDomain == -1 {
				colDomain = i
			}
		case norm == "name" || norm == "fullname" || norm == "contactname" || norm == "leadname" || norm == "person":
			if colName == -1 {
				colName = i
			}
		case norm == "firstname" || norm == "first":
			if colFirst == -1 {
				colFirst = i
			}
		case norm == "lastname" || norm == "last" || norm == "surname":
			if colLast == -1 {
				colLast = i
			}
		case norm == "pattern" || norm == "emailpattern" || norm == "format" || norm == "namingconvention":
			if colPattern == -1 {
				colPattern = i
			}
		case strings.Contains(norm, "personlinkedin") || strings.Contains(norm, "profilelinkedin") || norm == "linkedin" || norm == "linkedinurl":
			if colPersonLI == -1 {
				colPersonLI = i
			}
		case strings.Contains(norm, "companylinkedin") || strings.Contains(norm, "orglinkedin"):
			if colCompanyLI == -1 {
				colCompanyLI = i
			}
		}
	}

	if colDomain == -1 && len(headers) >= 1 {
		colDomain = 0
	}
	if colName == -1 && colFirst == -1 && len(headers) >= 2 {
		colName = 1
	}

	var targets []LeadTarget
	for rowIdx := 1; rowIdx < len(rows); rowIdx++ {
		row := rows[rowIdx]
		if len(row) == 0 {
			continue
		}

		domain := ""
		if colDomain >= 0 && colDomain < len(row) {
			domain = strings.TrimSpace(row[colDomain])
		}

		fullName := ""
		if colName >= 0 && colName < len(row) {
			fullName = strings.TrimSpace(row[colName])
		}

		firstName := ""
		if colFirst >= 0 && colFirst < len(row) {
			firstName = strings.TrimSpace(row[colFirst])
		}

		lastName := ""
		if colLast >= 0 && colLast < len(row) {
			lastName = strings.TrimSpace(row[colLast])
		}

		if fullName == "" && (firstName != "" || lastName != "") {
			fullName = strings.TrimSpace(firstName + " " + lastName)
		}

		pattern := ""
		if colPattern >= 0 && colPattern < len(row) {
			pattern = strings.TrimSpace(row[colPattern])
		}

		personLI := ""
		if colPersonLI >= 0 && colPersonLI < len(row) {
			personLI = strings.TrimSpace(row[colPersonLI])
		}

		companyLI := ""
		if colCompanyLI >= 0 && colCompanyLI < len(row) {
			companyLI = strings.TrimSpace(row[colCompanyLI])
		}

		if domain != "" {
			if normD, err := parser.NormalizeDomain(domain); err == nil {
				domain = normD
			}
		}

		if domain != "" && fullName != "" {
			targets = append(targets, LeadTarget{
				Domain:          domain,
				FullName:        fullName,
				FirstName:       firstName,
				LastName:        lastName,
				Pattern:         pattern,
				PersonLinkedIn:  personLI,
				CompanyLinkedIn: companyLI,
			})
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid lead targets found in CSV (check domain and name columns)")
	}

	return targets, nil
}

// ProcessSingleLead executes the full reconnaissance loop for one lead
func ProcessSingleLead(ctx context.Context, target LeadTarget, proxyURL string, noVerify bool, c *cache.Cache) (*models.ReconResult, error) {
	domain, err := parser.NormalizeDomain(target.Domain)
	if err != nil || domain == "" {
		return nil, fmt.Errorf("invalid domain: %s", target.Domain)
	}

	// 1. Parse Person Name
	nameParts := parser.ParsePersonName(target.FullName)
	if target.PersonLinkedIn != "" {
		slugName := parser.ExtractNameFromLinkedInSlug(target.PersonLinkedIn)
		if slugName.FirstName != "" {
			nameParts.FirstName = slugName.FirstName
			if slugName.LastName != "" {
				nameParts.LastName = slugName.LastName
			}
		}
	}

	if nameParts.FirstName == "" {
		return nil, fmt.Errorf("could not extract first name for: %s", target.FullName)
	}

	// 2. Check User-specified pattern or Local Domain Cache
	activePattern := strings.ToLower(strings.TrimSpace(target.Pattern))
	cachedProviderName := ""
	var cachedProvider *models.ProviderInfo
	if activePattern == "" && c != nil {
		if dInfo, ok := c.GetDomainPattern(domain); ok && dInfo.Pattern != "" {
			activePattern = dInfo.Pattern
			cachedProviderName = dInfo.Provider
			if cachedProviderName != "" {
				cachedProvider = &models.ProviderInfo{
					Name: cachedProviderName,
				}
			}
		}
	}

	// 3. DNS & Mail Server Discovery
	var mxRecords []models.MXRecord
	var provider *models.ProviderInfo
	var port25Open bool
	var isCatchAll bool

	if !noVerify {
		records, err := dns.LookupMX(domain)
		if err == nil && len(records) > 0 {
			mxRecords = records
			provider = dns.FingerprintProvider(domain, records)
			primaryMX := records[0].Host

			verifier := smtp.NewVerifier(proxyURL, 5*time.Second, 150*time.Millisecond)

			// Port 25 Fast-Fail check
			port25Open = verifier.CheckPort25(primaryMX)

			// Catch-All Probe
			if port25Open {
				isCatchAll = verifier.CheckCatchAll(domain, primaryMX)
			}
		}
	}

	if provider == nil && cachedProvider != nil {
		provider = cachedProvider
	}

	// 4. Domain OSINT Check (if pattern not cached)
	directMatch := ""
	if activePattern == "" && !noVerify {
		engine := osint.NewEngine(4 * time.Second)
		detPat, _, _, exact := engine.DetectDomainPattern(domain, nameParts)
		if detPat != "" {
			activePattern = detPat
		}
		if exact != "" {
			directMatch = exact
		}
	}

	// 5. Permutation Generation
	gen := generator.NewGenerator()
	candidates := gen.Generate(nameParts, domain, activePattern)

	// Direct match elevation
	if directMatch != "" {
		for i := range candidates {
			if strings.EqualFold(candidates[i].Email, directMatch) {
				candidates[i].Status = models.StatusValid
				candidates[i].Confidence = 100
				candidates[i].SMTPMessage = "Direct OSINT confirmed match"
				break
			}
		}
	}

	// 6. Verification
	var primaryMX string
	if len(mxRecords) > 0 {
		primaryMX = mxRecords[0].Host
	}

	if port25Open && primaryMX != "" && !isCatchAll && !noVerify {
		verifier := smtp.NewVerifier(proxyURL, 5*time.Second, 150*time.Millisecond)
		for i := range candidates {
			select {
			case <-ctx.Done():
				break
			default:
			}

			if candidates[i].Status == models.StatusValid {
				continue
			}

			status, code, msg := verifier.VerifyEmail(ctx, candidates[i].Email, primaryMX, isCatchAll)
			candidates[i].Status = status
			candidates[i].SMTPCode = code
			candidates[i].SMTPMessage = msg

			if status == models.StatusValid {
				activePattern = candidates[i].PatternName
				break
			}
		}
	}

	// 7. Dynamic Scoring
	scorer.ScoreCandidates(candidates, provider, isCatchAll, port25Open, activePattern, directMatch)

	// 8. Build ReconResult
	result := &models.ReconResult{
		TargetDomain:    domain,
		Person:          nameParts,
		MXRecords:       mxRecords,
		Provider:        provider,
		Port25Open:      port25Open,
		IsCatchAll:      isCatchAll,
		DetectedPattern: activePattern,
		Candidates:      candidates,
	}
	result.BestCandidate = result.GetPrimaryCandidate()

	// 9. Update Cache with confirmed pattern and lead
	if c != nil && result.BestCandidate != nil {
		provStr := "Standard"
		if provider != nil && provider.Name != "" {
			provStr = provider.Name
		}
		if result.BestCandidate.PatternName != "" {
			if result.BestCandidate.Status == models.StatusValid || result.DetectedPattern != "" {
				c.SetDomainPattern(domain, result.BestCandidate.PatternName, provStr, isCatchAll)
			}
		}
		savedLead := cache.ConvertReconResultToSavedLead(result)
		if savedLead != nil {
			c.SaveLead(*savedLead)
		}
	}

	return result, nil
}

// ProcessBatch executes reconnaissance across a list of lead targets with concurrent workers
func ProcessBatch(
	ctx context.Context,
	targets []LeadTarget,
	concurrency int,
	proxyURL string,
	noVerify bool,
	c *cache.Cache,
	onProgress func(BatchProgress),
) ([]*models.ReconResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("target list is empty")
	}

	if concurrency <= 0 {
		concurrency = 5
	}
	if concurrency > 20 {
		concurrency = 20
	}

	total := len(targets)
	results := make([]*models.ReconResult, total)

	type job struct {
		index  int
		target LeadTarget
	}

	jobs := make(chan job, total)
	for i, t := range targets {
		jobs <- job{index: i, target: t}
	}
	close(jobs)

	var wg sync.WaitGroup
	var completedCount int32
	var validCount int32

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				res, err := ProcessSingleLead(ctx, j.target, proxyURL, noVerify, c)
				if err == nil && res != nil {
					results[j.index] = res
					if res.BestCandidate != nil && res.BestCandidate.Status == models.StatusValid {
						atomic.AddInt32(&validCount, 1)
					}
				}

				cur := int(atomic.AddInt32(&completedCount, 1))
				pct := int(float64(cur) / float64(total) * 100)

				if onProgress != nil {
					onProgress(BatchProgress{
						Index:       cur,
						Total:       total,
						CurrentLead: j.target,
						Result:      res,
						ValidCount:  int(atomic.LoadInt32(&validCount)),
						Percentage:  pct,
					})
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}
