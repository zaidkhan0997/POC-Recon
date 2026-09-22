package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zaidkhan0997/POC-Recon/pkg/bulk"
	"github.com/zaidkhan0997/POC-Recon/pkg/cache"
	"github.com/zaidkhan0997/POC-Recon/pkg/export"
	"github.com/zaidkhan0997/POC-Recon/pkg/generator"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
	"github.com/zaidkhan0997/POC-Recon/pkg/parser"
	"github.com/zaidkhan0997/POC-Recon/pkg/verifier"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called at application startup
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// ReconRequest defines the input from the frontend form
type ReconRequest struct {
	Website         string `json:"website"`
	Name            string `json:"name"`
	PersonLinkedIn  string `json:"person_linkedin"`
	CompanyLinkedIn string `json:"company_linkedin"`
	Pattern         string `json:"pattern"`
	ProxyURL        string `json:"proxy_url"`
	NoVerify        bool   `json:"no_verify"`
}

// ProgressUpdate sent over WebSocket/IPC to the UI in real time
type ProgressUpdate struct {
	Step       string `json:"step"`
	Message    string `json:"message"`
	Percentage int    `json:"percentage"`
}

func computeConfidence(status models.VerificationStatus, pattern string, provider *models.ProviderInfo, isCatchAll bool, port25Open bool, preferredPattern string) int {
	if status == models.StatusValid {
		return 100
	}
	if status == models.StatusInvalid || status == models.StatusNoMX {
		return 0
	}
	weights := map[string]int{
		"first.last": 85,
		"first":      60,
		"flast":      50,
		"firstlast":  45,
		"first_last": 40,
		"last.first": 35,
		"f.last":     30,
		"last":       25,
		"lfirst":     20,
		"first.l":    20,
		"f_last":     15,
	}
	score, ok := weights[pattern]
	if !ok {
		score = 15
	}
	if preferredPattern != "" {
		if strings.EqualFold(pattern, preferredPattern) {
			score = 90
		} else if score > 60 {
			score = 60
		}
	}
	if provider != nil {
		targetPat := "first.last"
		if preferredPattern != "" {
			targetPat = preferredPattern
		}
		pLower := strings.ToLower(provider.Name)
		if strings.Contains(pLower, "google") || strings.Contains(pLower, "workspace") || strings.Contains(pLower, "microsoft") {
			if strings.EqualFold(pattern, targetPat) {
				score += 5
			}
		}
		if strings.Contains(provider.SPFRecord, "-all") {
			if strings.EqualFold(pattern, targetPat) || preferredPattern == "" {
				score += 5
			}
		}
	}
	if isCatchAll {
		score = int(float64(score) * 0.75)
	}
	if score > 95 {
		score = 95
	}
	if score < 5 {
		score = 5
	}
	return score
}

// RunRecon executes the email intelligence workflow and streams progress events
func (a *App) RunRecon(req ReconRequest) (*models.ReconResult, error) {
	if strings.TrimSpace(req.Website) == "" || strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.PersonLinkedIn) == "" || strings.TrimSpace(req.CompanyLinkedIn) == "" {
		return nil, fmt.Errorf("website domain, person name, person LinkedIn URL, and company LinkedIn URL are all required")
	}

	a.emitProgress("init", "Normalizing target domain and person name...", 10)

	domain, err := parser.NormalizeDomain(req.Website)
	if err != nil {
		return nil, fmt.Errorf("invalid website domain: %w", err)
	}

	person := parser.ParsePersonName(req.Name)
	candidates := generator.GenerateEmailPatterns(domain, person)
	if req.Pattern != "" {
		var prioritized []models.EmailCandidate
		var others []models.EmailCandidate
		for _, c := range candidates {
			if strings.EqualFold(c.PatternName, req.Pattern) {
				prioritized = append(prioritized, c)
			} else {
				others = append(others, c)
			}
		}
		candidates = append(prioritized, others...)
	}

	a.emitProgress("dns", fmt.Sprintf("Resolving DNS & MX infrastructure for %s (DoH Fallback)...", domain), 25)

	mxList, err := verifier.LookupMXWithDoH(domain, 5*time.Second)
	hasMX := err == nil && len(mxList) > 0

	var provider *models.ProviderInfo
	port25Open := false
	isCatchAll := false

	if hasMX {
		provider = verifier.FingerprintProvider(domain, mxList)
		primaryMX := mxList[0].Host

		if !req.NoVerify {
			a.emitProgress("port25", fmt.Sprintf("Testing SMTP Port 25 connectivity on %s...", primaryMX), 40)
			port25Open = verifier.CheckPort25(primaryMX, 5*time.Second, req.ProxyURL)

			if port25Open {
				a.emitProgress("catchall", "Probing Catch-All configuration...", 50)
				isCatchAll = verifier.CheckCatchAll(context.Background(), primaryMX, domain, 6*time.Second, req.ProxyURL)
			}
		}
	}

	result := &models.ReconResult{
		TargetDomain:       domain,
		Person:             person,
		MXRecords:          mxList,
		Provider:           provider,
		Port25Open:         port25Open,
		IsCatchAll:         isCatchAll,
		VerificationMethod: "Native Go SMTP (RFC 5321)",
		Candidates:         candidates,
		Timestamp:          time.Now(),
	}

	total := len(result.Candidates)

	if !hasMX {
		for i := range result.Candidates {
			result.Candidates[i].Status = models.StatusNoMX
			result.Candidates[i].SMTPMessage = "No MX record in DNS"
			result.Candidates[i].Confidence = 0
		}
	} else if req.NoVerify {
		for i := range result.Candidates {
			result.Candidates[i].Status = models.StatusUnverified
			result.Candidates[i].SMTPMessage = "Verification skipped (Offline Mode)"
			result.Candidates[i].Confidence = computeConfidence(models.StatusUnverified, result.Candidates[i].PatternName, provider, isCatchAll, port25Open, req.Pattern)
		}
	} else if !port25Open {
		a.emitProgress("cloud", "Port 25 blocked by network. Engaging HTTPS Cloud & Identity Verifiers...", 60)
		result.VerificationMethod = "HTTPS Cloud & Identity Verifiers (Port 443)"

		isM365 := false
		if provider != nil && strings.Contains(strings.ToLower(provider.Name), "microsoft") {
			isM365 = true
		}

		for i := range result.Candidates {
			email := result.Candidates[i].Email
			pattern := result.Candidates[i].PatternName
			pct := 60 + int(float64(i+1)/float64(total)*30)
			a.emitProgress("eval", fmt.Sprintf("Checking candidate %d/%d: %s", i+1, total, email), pct)

			resolved := false
			if isM365 {
				st, code, msg := verifier.VerifyM365(email, 5*time.Second)
				if st == models.StatusValid {
					result.Candidates[i].Status = models.StatusValid
					result.Candidates[i].SMTPCode = code
					result.Candidates[i].SMTPMessage = msg
					result.Candidates[i].Confidence = 100
					resolved = true
				} else if st == models.StatusInvalid {
					result.Candidates[i].Status = models.StatusInvalid
					result.Candidates[i].SMTPCode = code
					result.Candidates[i].SMTPMessage = msg
					result.Candidates[i].Confidence = 0
					resolved = true
				}
			}

			if !resolved {
				st, code, msg := verifier.VerifyGravatar(email, 3*time.Second)
				if st == models.StatusValid {
					result.Candidates[i].Status = models.StatusValid
					result.Candidates[i].SMTPCode = code
					result.Candidates[i].SMTPMessage = msg
					result.Candidates[i].Confidence = 100
					resolved = true
				}
			}

			if !resolved {
				st, code, msg := verifier.VerifyPGPKeyring(email, 3*time.Second)
				if st == models.StatusValid {
					result.Candidates[i].Status = models.StatusValid
					result.Candidates[i].SMTPCode = code
					result.Candidates[i].SMTPMessage = msg
					result.Candidates[i].Confidence = 100
					resolved = true
				}
			}

			if !resolved {
				result.Candidates[i].Status = models.StatusPortBlocked
				result.Candidates[i].SMTPMessage = "Port 25 blocked by ISP; HTTPS alternative checks non-conclusive"
				result.Candidates[i].Confidence = computeConfidence(models.StatusPortBlocked, pattern, provider, isCatchAll, false, req.Pattern)
			}

			if result.Candidates[i].Status == models.StatusValid {
				result.BestCandidate = &result.Candidates[i]
				break // Early-exit
			}
		}
	} else if isCatchAll {
		a.emitProgress("cloud", "Catch-All domain. Verifying identities via Cloud APIs...", 60)
		for i := range result.Candidates {
			email := result.Candidates[i].Email
			pattern := result.Candidates[i].PatternName
			pct := 60 + int(float64(i+1)/float64(total)*30)
			a.emitProgress("eval", fmt.Sprintf("Checking candidate %d/%d: %s", i+1, total, email), pct)

			resolved := false
			st, code, msg := verifier.VerifyGravatar(email, 3*time.Second)
			if st == models.StatusValid {
				result.Candidates[i].Status = models.StatusValid
				result.Candidates[i].SMTPCode = code
				result.Candidates[i].SMTPMessage = msg
				result.Candidates[i].Confidence = 100
				resolved = true
			}

			if !resolved {
				st, code, msg := verifier.VerifyPGPKeyring(email, 3*time.Second)
				if st == models.StatusValid {
					result.Candidates[i].Status = models.StatusValid
					result.Candidates[i].SMTPCode = code
					result.Candidates[i].SMTPMessage = msg
					result.Candidates[i].Confidence = 100
					resolved = true
				}
			}

			if !resolved {
				result.Candidates[i].Status = models.StatusCatchAll
				result.Candidates[i].SMTPMessage = "Mail server accepts all probes (Catch-All)"
				result.Candidates[i].Confidence = computeConfidence(models.StatusCatchAll, pattern, provider, isCatchAll, true, req.Pattern)
			}

			if result.Candidates[i].Status == models.StatusValid {
				result.BestCandidate = &result.Candidates[i]
				break
			}
		}
	} else {
		primaryMX := mxList[0].Host
		for i := range result.Candidates {
			pct := 50 + int(float64(i+1)/float64(total)*45)
			a.emitProgress("smtp", fmt.Sprintf("Probing mailbox %d/%d: %s", i+1, total, result.Candidates[i].Email), pct)

			status, code, msg := verifier.VerifyEmail(context.Background(), primaryMX, domain, result.Candidates[i].Email, 8*time.Second, req.ProxyURL)
			result.Candidates[i].Status = status
			result.Candidates[i].SMTPCode = code
			result.Candidates[i].SMTPMessage = msg
			result.Candidates[i].Confidence = computeConfidence(status, result.Candidates[i].PatternName, provider, isCatchAll, port25Open, req.Pattern)

			if status == models.StatusValid {
				result.BestCandidate = &result.Candidates[i]
				break // Early-exit
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	result.BestCandidate = result.GetPrimaryCandidate()

	// Persist to results/ folder automatically (single HTML report)
	a.emitProgress("export", "Exporting visual report to results/...", 95)
	_ = os.MkdirAll("results", 0755)
	base := fmt.Sprintf("results/%s_%s", domain, strings.ToLower(person.FirstName))
	_ = export.ExportHTML(result, base+"_report.html")

	// Save confirmed pattern and lead to local persistent cache
	c := cache.GetDefaultCache()
	provStr := "Standard"
	if provider != nil && provider.Name != "" {
		provStr = provider.Name
	}
	if result.BestCandidate != nil && result.BestCandidate.PatternName != "" {
		c.SetDomainPattern(domain, result.BestCandidate.PatternName, provStr, isCatchAll)
	}
	savedLead := cache.ConvertReconResultToSavedLead(result)
	if savedLead != nil {
		c.SaveLead(*savedLead)
	}

	a.emitProgress("done", "Reconnaissance complete!", 100)
	return result, nil
}

func (a *App) emitProgress(step string, msg string, pct int) {
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "recon-progress", ProgressUpdate{
			Step:       step,
			Message:    msg,
			Percentage: pct,
		})
	}
}

// ParseCSVContent parses raw CSV string into a slice of LeadTarget records
func (a *App) ParseCSVContent(csvContent string) ([]bulk.LeadTarget, error) {
	return bulk.ParseCSV(strings.NewReader(csvContent))
}

// RunBulkRecon processes a slice of LeadTargets in parallel and emits bulk-progress events
func (a *App) RunBulkRecon(targets []bulk.LeadTarget, proxyURL string, noVerify bool) ([]bulk.EnrichedLeadExport, error) {
	c := cache.GetDefaultCache()
	results, err := bulk.ProcessBatch(context.Background(), targets, 6, proxyURL, noVerify, c, func(p bulk.BatchProgress) {
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "bulk-progress", p)
		}
	})
	if err != nil {
		return nil, err
	}

	_ = os.MkdirAll("results", 0755)
	_ = bulk.ExportBatchToCSVFile(results, "results/bulk_verified_leads.csv")

	// Convert to export representation
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	var exports []bulk.EnrichedLeadExport
	for _, res := range results {
		if res == nil {
			continue
		}
		bestEmail := ""
		confidence := 0
		status := "UNVERIFIED"
		pattern := "unknown"
		if res.BestCandidate != nil {
			bestEmail = res.BestCandidate.Email
			confidence = res.BestCandidate.Confidence
			status = string(res.BestCandidate.Status)
			pattern = res.BestCandidate.PatternName
		}
		provider := "Unknown"
		if res.Provider != nil && res.Provider.Name != "" {
			provider = res.Provider.Name
		}
		exports = append(exports, bulk.EnrichedLeadExport{
			FullName:     res.Person.FullName,
			FirstName:    res.Person.FirstName,
			LastName:     res.Person.LastName,
			Domain:       res.TargetDomain,
			Email:        bestEmail,
			Confidence:   confidence,
			Status:       status,
			Pattern:      pattern,
			MailProvider: provider,
			VerifiedAt:   nowStr,
		})
	}
	return exports, nil
}

// GetSavedLeads returns all leads from local cache
func (a *App) GetSavedLeads() []cache.SavedLead {
	return cache.GetDefaultCache().GetLeads()
}

// ClearSavedLeads deletes all saved leads from local cache
func (a *App) ClearSavedLeads() error {
	cache.GetDefaultCache().ClearLeads()
	return nil
}

// ExportSavedLeadsCSV exports all saved leads in cache to results/saved_leads_export.csv
func (a *App) ExportSavedLeadsCSV() (string, error) {
	leads := cache.GetDefaultCache().GetLeads()
	_ = os.MkdirAll("results", 0755)
	filePath := "results/saved_leads_export.csv"
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	_ = writer.Write([]string{
		"Full Name", "First Name", "Last Name", "Domain", "Email", "Confidence", "Status", "Pattern", "Provider", "Date Verified",
	})
	for _, l := range leads {
		_ = writer.Write([]string{
			l.FullName, l.FirstName, l.LastName, l.Domain, l.Email, fmt.Sprintf("%d", l.Confidence), l.Status, l.PatternName, l.Provider, l.VerifiedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return filePath, nil
}

// OpenResultsFolder opens the local results directory in OS file manager
func (a *App) OpenResultsFolder() error {
	_ = os.MkdirAll("results", 0755)
	return export.OpenFolderInFileManager("results")
}

// OpenHTMLReport opens the generated HTML file in default browser
func (a *App) OpenHTMLReport(domain string, firstName string) error {
	path := fmt.Sprintf("results/%s_%s_report.html", domain, strings.ToLower(firstName))
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	case "darwin":
		cmd = exec.Command("open", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}

// OpenURL opens the specified URL in the user's default system browser
func (a *App) OpenURL(url string) error {
	if a.ctx != nil {
		wailsRuntime.BrowserOpenURL(a.ctx, url)
		return nil
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

