package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zaidkhan0997/POC-Recon/internal/cloud"
	"github.com/zaidkhan0997/POC-Recon/internal/config"
	"github.com/zaidkhan0997/POC-Recon/internal/dns"
	"github.com/zaidkhan0997/POC-Recon/internal/generator"
	"github.com/zaidkhan0997/POC-Recon/internal/osint"
	"github.com/zaidkhan0997/POC-Recon/internal/output"
	"github.com/zaidkhan0997/POC-Recon/internal/parser"
	"github.com/zaidkhan0997/POC-Recon/internal/scorer"
	"github.com/zaidkhan0997/POC-Recon/internal/smtp"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func main() {
	cfg, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	output.PrintBanner()

	// 1. Domain & Person Parsing
	domain, err := parser.NormalizeDomain(cfg.Website)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid domain '%s': %v\n", cfg.Website, err)
		os.Exit(1)
	}

	var person models.NameParts
	if cfg.Name != "" {
		person = parser.ParseName(cfg.Name)
	} else if cfg.PersonLinkedIn != "" {
		slugParts := parser.ParseLinkedInSlug(cfg.PersonLinkedIn)
		if slugParts != nil {
			person = *slugParts
		} else {
			person = parser.ParseName(cfg.PersonLinkedIn)
		}
	}

	fmt.Printf("🔍 Target: %s (%s)\n", person.FullName, domain)

	// 2. Concurrently resolve DNS MX records and run OSINT domain pattern detection
	var (
		mxRecords      []models.MXRecord
		provider       *models.ProviderInfo
		detectedPat    string
		detectedSource string
		discoveredList []string
		directMatch    string
		dnsErr         error
	)

	var osintWg sync.WaitGroup
	osintWg.Add(2)

	go func() {
		defer osintWg.Done()
		resolver := dns.NewResolver(cfg.DNSTimeout)
		mxRecords, dnsErr = resolver.LookupMX(domain)
		if dnsErr == nil && len(mxRecords) > 0 {
			provider = resolver.IdentifyProvider(domain, mxRecords)
		}
	}()

	go func() {
		defer osintWg.Done()
		engine := osint.NewEngine(5 * time.Second)
		detectedPat, detectedSource, discoveredList, directMatch = engine.DetectDomainPattern(domain, person)
	}()

	osintWg.Wait()

	if dnsErr != nil || len(mxRecords) == 0 {
		fmt.Printf("⚠️  DNS: No MX records found for domain '%s' (fallback to standard candidates)\n", domain)
	} else {
		primaryMX := mxRecords[0].Host
		pName := "Standard SMTP"
		if provider != nil {
			pName = provider.Name
		}
		fmt.Printf("📡 Mail Infrastructure: %s via MX %s\n", pName, primaryMX)
	}

	// Active pattern selection
	activePattern := ""
	activePatternSource := ""
	if cfg.Pattern != "" {
		activePattern = cfg.Pattern
		activePatternSource = "User flag override"
		fmt.Printf("🎯 Using user-specified pattern override: %s\n", activePattern)
	} else if detectedPat != "" {
		activePattern = detectedPat
		activePatternSource = detectedSource
		fmt.Printf("🔎 OSINT detected active company pattern: %s (Source: %s)\n", activePattern, detectedSource)
	}

	// 3. Candidate Generation
	gen := generator.NewGenerator()
	candidates := gen.Generate(person, domain, activePattern)
	fmt.Printf("⚡ Generated %d corporate email permutations\n", len(candidates))

	// If direct OSINT match found (e.g. DMARC rua/ruf or PGP direct key match), prioritize it!
	if directMatch != "" {
		fmt.Printf("✨ Direct OSINT exact match found: %s\n", directMatch)
		for i := range candidates {
			if candidates[i].Email == directMatch {
				candidates[i].Status = models.StatusValid
				candidates[i].Confidence = 100
				candidates[i].SMTPMessage = fmt.Sprintf("Direct OSINT confirmed match (%s)", detectedSource)
				break
			}
		}
	}

	port25Open := false
	isCatchAll := false
	verificationMethod := "Local Heuristic Evaluation"

	// 4. Verification Engine
	if !cfg.NoVerify && len(mxRecords) > 0 {
		primaryMX := mxRecords[0].Host
		verifier := smtp.NewVerifier(cfg.Proxy, cfg.SMTPTimeout, cfg.Delay)

		fmt.Printf("🔌 Testing Port 25 connectivity to %s...\n", primaryMX)
		port25Open = verifier.CheckPort25(primaryMX)

		if port25Open {
			verificationMethod = "RFC 5321 Direct SMTP Handshake"
			fmt.Println("✅ Port 25 is OPEN. Performing direct mailbox probing...")

			// Catch-all check
			isCatchAll = verifier.CheckCatchAll(domain, primaryMX)
			if isCatchAll {
				fmt.Println("⚠️  Domain has CATCH-ALL enabled. Verifications will be flagged accordingly.")
			}

			// If direct match was already confirmed, we can skip or verify only that one
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Concurrency worker pool
			type task struct {
				index int
				cand  *models.CandidateResult
			}

			taskChan := make(chan task, len(candidates))
			for i := range candidates {
				// If already valid from direct OSINT, don't re-verify
				if candidates[i].Status == models.StatusValid {
					continue
				}
				taskChan <- task{index: i, cand: &candidates[i]}
			}
			close(taskChan)

			var workerWg sync.WaitGroup
			workerCount := cfg.Concurrency
			if workerCount > len(candidates) {
				workerCount = len(candidates)
			}

			var verifiedOnce sync.Once

			for w := 0; w < workerCount; w++ {
				workerWg.Add(1)
				go func() {
					defer workerWg.Done()
					for t := range taskChan {
						select {
						case <-ctx.Done():
							t.cand.Status = models.StatusSkipped
							t.cand.SMTPMessage = "Skipped (Valid email already verified)"
							continue
						default:
						}

						status, code, msg := verifier.VerifyEmail(ctx, t.cand.Email, primaryMX, isCatchAll)
						t.cand.Status = status
						t.cand.SMTPCode = code
						t.cand.SMTPMessage = msg

						if status == models.StatusValid {
							verifiedOnce.Do(func() {
								fmt.Printf("🎯 Validated mailbox: %s (Status: %s)\n", t.cand.Email, status)
								cancel() // Early exit for remaining permutations!
							})
						}
					}
				}()
			}
			workerWg.Wait()

		} else {
			// Port 25 blocked by ISP/Firewall
			fmt.Println("🛡️  Port 25 blocked by local network/ISP.")

			// Check for Cloud Relay or SOCKS5 fallback
			if cfg.RelayURL != "" && !cfg.NoCloudFallback {
				fmt.Println("☁️  Routing through Cloud Relay verification...")
				verificationMethod = "Cloud Relay RFC 5321 Verification"
				relayClient := cloud.NewRelayClient(cfg.RelayURL, cfg.RelayToken, 15*time.Second)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				var relayWg sync.WaitGroup
				for i := range candidates {
					relayWg.Add(1)
					go func(idx int) {
						defer relayWg.Done()
						select {
						case <-ctx.Done():
							return
						default:
						}
						resp, err := relayClient.VerifyCandidate(ctx, candidates[idx].Email, primaryMX)
						if err == nil && resp != nil {
							candidates[idx].Status = resp.Status
							candidates[idx].SMTPCode = resp.SMTPCode
							candidates[idx].SMTPMessage = resp.Message
							if resp.Status == models.StatusValid {
								cancel()
							}
						}
					}(i)
				}
				relayWg.Wait()
			} else {
				fmt.Println("ℹ️  Applying high-fidelity OSINT pattern & heuristic confidence scoring...")
				verificationMethod = "High-Fidelity OSINT Heuristics"
			}
		}
	} else if cfg.NoVerify {
		fmt.Println("⏩ Skipping SMTP verification (--no-verify active).")
		verificationMethod = "Permutation Generation & OSINT Heuristics"
	}

	// 5. Score Candidates
	scorer.ScoreCandidates(candidates, provider, isCatchAll, port25Open, activePattern, directMatch)

	// 6. Build ReconResult
	result := &models.ReconResult{
		TargetDomain:           domain,
		Person:                 person,
		MXRecords:              mxRecords,
		Provider:               provider,
		Port25Open:             port25Open,
		IsCatchAll:             isCatchAll,
		DetectedPattern:        activePattern,
		DetectedPatternSource:  activePatternSource,
		DiscoveredDomainEmails: discoveredList,
		VerificationMethod:     verificationMethod,
		Candidates:             candidates,
		BestCandidate:          nil,
		Timestamp:              time.Now(),
	}
	result.BestCandidate = result.GetPrimaryCandidate()

	// 7. Render Terminal Summary
	output.PrintTerminalSummary(result, cfg.ShowAll)

	// 8. Handle Export & Browser Opening
	exportPath := cfg.OutputFile
	if exportPath == "" && cfg.OpenReport {
		// Generate temporary html in results directory
		resultsDir := "results"
		_ = os.MkdirAll(resultsDir, 0755)
		filename := fmt.Sprintf("poc_recon_%s_%d.html", domain, time.Now().Unix())
		exportPath = filepath.Join(resultsDir, filename)
		cfg.Format = "html"
	}

	if exportPath != "" {
		var exportErr error
		switch cfg.Format {
		case "json":
			exportErr = output.ExportJSON(result, exportPath)
		case "csv":
			exportErr = output.ExportCSV(result, exportPath)
		case "html":
			exportErr = output.ExportHTML(result, exportPath)
		case "txt":
			fallthrough
		default:
			exportErr = output.ExportTXT(result, exportPath, cfg.ShowAll)
		}

		if exportErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to export report to %s: %v\n", exportPath, exportErr)
		} else {
			fmt.Printf("📄 Report saved successfully to %s (%s format)\n", exportPath, strings.ToUpper(cfg.Format))
			if cfg.Format == "html" && cfg.OpenReport {
				output.OpenBrowser(exportPath)
			}
		}
	}
}
