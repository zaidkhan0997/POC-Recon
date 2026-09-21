package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/export"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/generator"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/parser"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/verifier"
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
	ProxyURL        string `json:"proxy_url"`
	NoVerify        bool   `json:"no_verify"`
}

// ProgressUpdate sent over WebSocket/IPC to the UI in real time
type ProgressUpdate struct {
	Step       string `json:"step"`
	Message    string `json:"message"`
	Percentage int    `json:"percentage"`
}

func computeConfidence(status models.VerificationStatus, pattern string, provider *models.ProviderInfo, isCatchAll bool, port25Open bool) int {
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
	if provider != nil {
		pLower := strings.ToLower(provider.Name)
		if strings.Contains(pLower, "google") || strings.Contains(pLower, "workspace") || strings.Contains(pLower, "microsoft") {
			if pattern == "first.last" {
				score += 5
			}
		}
		if strings.Contains(provider.SPFRecord, "-all") {
			score += 5
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
	if strings.TrimSpace(req.Website) == "" || strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("website domain and person name are required")
	}

	a.emitProgress("init", "Normalizing target domain and person name...", 10)

	domain, err := parser.NormalizeDomain(req.Website)
	if err != nil {
		return nil, fmt.Errorf("invalid website domain: %w", err)
	}

	person := parser.ParsePersonName(req.Name)
	candidates := generator.GenerateEmailPatterns(domain, person)

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
			result.Candidates[i].Confidence = computeConfidence(models.StatusUnverified, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)
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
				result.Candidates[i].Confidence = computeConfidence(models.StatusPortBlocked, pattern, provider, isCatchAll, false)
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
				result.Candidates[i].Confidence = computeConfidence(models.StatusCatchAll, pattern, provider, isCatchAll, true)
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
			result.Candidates[i].Confidence = computeConfidence(status, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)

			if status == models.StatusValid {
				result.BestCandidate = &result.Candidates[i]
				break // Early-exit
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	result.BestCandidate = result.GetPrimaryCandidate()

	// Persist to results/ folder automatically
	a.emitProgress("export", "Exporting results to results/ folder...", 95)
	_ = os.MkdirAll("results", 0755)
	base := fmt.Sprintf("results/%s_%s", domain, strings.ToLower(person.FirstName))
	_ = export.ExportJSON(result, base+"_results.json")
	_ = export.ExportCSV(result, base+"_results.csv")
	_ = export.ExportTXT(result, base+"_results.txt", true)
	_ = export.ExportHTML(result, base+"_report.html")

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
