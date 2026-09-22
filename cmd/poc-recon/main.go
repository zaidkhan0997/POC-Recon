package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/bulk"
	"github.com/zaidkhan0997/POC-Recon/pkg/cache"
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

	if cfg.BulkPath != "" {
		runBulkMode(cfg)
		return
	}

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

	// PRE-FLIGHT: Test Port 25 connectivity BEFORE generating candidates
	// This saves time if Port 25 is blocked - we can skip SMTP entirely
	if !cfg.NoVerify && len(mxRecords) > 0 {
		primaryMX := mxRecords[0].Host
		fmt.Printf("🔌 Pre-flight: Testing Port 25 connectivity to %s...\\n", primaryMX)
		testVerifier := smtp.NewVerifier(cfg.Proxy, cfg.SMTPTimeout, cfg.Delay)
		port25Open = testVerifier.CheckPort25(primaryMX)

		if !port25Open {
			fmt.Println("🛡️  Port 25 blocked by local network/ISP — will use cloud-only verification")
		}
	}

	// 4. Verification Engine
	if !cfg.NoVerify && cfg.ReacherURL != "" {
		fmt.Printf("🐳 Engaging self-hosted Reacher verification engine at %s...\n", cfg.ReacherURL)
		verificationMethod = "Self-Hosted Reacher (Docker HTTP)"
		reacherClient := cloud.NewReacherClient(cfg.ReacherURL, cfg.Proxy, cfg.SMTPTimeout)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for i := range candidates {
			select {
			case <-ctx.Done():
				break
			default:
			}
			if candidates[i].Status == models.StatusValid {
				continue
			}
			status, code, msg, err := reacherClient.CheckEmail(ctx, candidates[i].Email)
			if err == nil {
				candidates[i].Status = status
				candidates[i].SMTPCode = code
				candidates[i].SMTPMessage = msg
				if status == models.StatusValid {
					candidates[i].Confidence = 100
					fmt.Printf("🎯 Validated mailbox via Reacher: %s (Status: %s)\n", candidates[i].Email, status)
					cancel() // Short circuit on first valid email!
					break
				}
			}
		}
	} else if !cfg.NoVerify && len(mxRecords) > 0 {
		primaryMX := mxRecords[0].Host

		if port25Open {
			verificationMethod = "AfterShip Pure-Go SMTP (RFC 5321)"
			fmt.Println("✅ Port 25 is OPEN. Performing direct mailbox probing via AfterShip...")

			// Catch-all check
			verifier := smtp.NewVerifier(cfg.Proxy, cfg.SMTPTimeout, cfg.Delay)
			isCatchAll = verifier.CheckCatchAll(domain, primaryMX)
			if isCatchAll {
				fmt.Println("⚠️  Domain has CATCH-ALL enabled. Verifications will be flagged accordingly.")
			}

			afterShipVerifier := smtp.NewAfterShipVerifier(cfg.Proxy, cfg.SMTPTimeout)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// NEW LOGIC: Test ALL candidates first, then evaluate
			validIndices := []int{}

			for i := range candidates {
				select {
				case <-ctx.Done():
					break
				default:
				}
				if candidates[i].Status == models.StatusValid {
					continue
				}

				status, code, msg := afterShipVerifier.VerifyEmail(ctx, candidates[i].Email)
				// Fall back to native verifier if AfterShip was inconclusive
				if status == models.StatusUnverified || status == models.StatusTimeout {
					status, code, msg = verifier.VerifyEmail(ctx, candidates[i].Email, primaryMX, isCatchAll)
				}

				candidates[i].Status = status
				candidates[i].SMTPCode = code
				candidates[i].SMTPMessage = msg

				if status == models.StatusValid {
					validIndices = append(validIndices, i)
				}
			}

			// If catch-all domain, downgrade ALL valid results to StatusCatchAll
			if isCatchAll {
				for _, idx := range validIndices {
					candidates[idx].Status = models.StatusCatchAll
					candidates[idx].Confidence = 0
					candidates[idx].SMTPMessage = "Catch-all domain accepted test address"
				}
				validIndices = nil
			}

			// NOW pick the best candidate from validated ones
			if len(validIndices) > 0 {
				bestIdx := selectBestCandidate(candidates, validIndices, activePattern)
				candidates[bestIdx].Confidence = 100
				fmt.Printf("🎯 Best validated mailbox: %s (Pattern: %s)\\n", candidates[bestIdx].Email, candidates[bestIdx].PatternName)
			}

		} else {
			// Port 25 blocked by ISP/Firewall
			fmt.Println("🛡️  Port 25 blocked by local network/ISP.")

			// Check for Cloud Relay
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
				// Seamless.ai-style Free Multi-Signal Engine (M365 + Google + Gravatar + OpenPGP)
				fmt.Println("⚡ Engaging free Multi-Signal verification (Microsoft 365 + Google Workspace + Gravatar + OpenPGP)...")
				verificationMethod = "Free Multi-Signal Verification (M365 + Google + Gravatar + PGP)"
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// NEW LOGIC: Test ALL candidates first, then evaluate
				validIndices := []int{}

				for i := range candidates {
					select {
					case <-ctx.Done():
						break
					default:
					}
					if candidates[i].Status == models.StatusValid {
						continue
					}

					msRes := cloud.MultiSignalCheck(ctx, candidates[i].Email, 4*time.Second)
					if msRes.Status == models.StatusValid {
						candidates[i].Status = models.StatusValid
						candidates[i].Confidence = msRes.Confidence
						candidates[i].SMTPMessage = msRes.ConfirmedMethod
						code := 200
						candidates[i].SMTPCode = &code
						validIndices = append(validIndices, i)
					} else if msRes.Status == models.StatusInvalid {
						candidates[i].Status = models.StatusInvalid
						candidates[i].Confidence = 0
						code := 404
						candidates[i].SMTPCode = &code
						candidates[i].SMTPMessage = msRes.ConfirmedMethod
					}
				}

				// NOW pick the best candidate from validated ones
				if len(validIndices) > 0 {
					bestIdx := selectBestCandidate(candidates, validIndices, activePattern)
					candidates[bestIdx].Confidence = 100
					fmt.Printf("🎯 Best validated mailbox: %s (Pattern: %s)\\n", candidates[bestIdx].Email, candidates[bestIdx].PatternName)
				}
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

func runBulkMode(cfg *config.Config) {
	fmt.Printf("📂 Loading bulk leads from: %s\n", cfg.BulkPath)
	file, err := os.Open(cfg.BulkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening bulk CSV file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	targets, err := bulk.ParseCSV(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing bulk CSV: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🎯 Successfully loaded %d lead targets.\n", len(targets))
	fmt.Printf("⚡ Starting concurrent batch discovery (%d workers)...\n\n", cfg.Concurrency)

	c := cache.GetDefaultCache()
	ctx := context.Background()

	startTime := time.Now()
	results, err := bulk.ProcessBatch(ctx, targets, cfg.Concurrency, cfg.Proxy, cfg.NoVerify, c, func(p bulk.BatchProgress) {
		leadName := p.CurrentLead.FullName
		if len(leadName) > 20 {
			leadName = leadName[:17] + "..."
		}
		leadDomain := p.CurrentLead.Domain
		if len(leadDomain) > 20 {
			leadDomain = leadDomain[:17] + "..."
		}

		bestEmail := "evaluating..."
		status := "..."
		if p.Result != nil && p.Result.BestCandidate != nil {
			bestEmail = p.Result.BestCandidate.Email
			status = string(p.Result.BestCandidate.Status)
		}

		fmt.Printf("\r\033[K[%3d%%] Target %d/%d: %s (%s) -> %s [%s] (Confirmed Valid: %d)",
			p.Percentage, p.Index, p.Total, leadName, leadDomain, bestEmail, status, p.ValidCount)
	})

	fmt.Println() // Newline after progress
	duration := time.Since(startTime).Round(time.Millisecond)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Batch processing failed: %v\n", err)
		os.Exit(1)
	}

	// Calculate statistics
	validCount := 0
	catchAllCount := 0
	otherCount := 0

	for _, r := range results {
		if r != nil && r.BestCandidate != nil {
			switch r.BestCandidate.Status {
			case models.StatusValid:
				validCount++
			case models.StatusCatchAll:
				catchAllCount++
			default:
				otherCount++
			}
		}
	}

	outPath := cfg.OutputFile
	if outPath == "" {
		outPath = "results/bulk_verified_leads.csv"
	}
	_ = os.MkdirAll(filepath.Dir(outPath), 0755)

	var exportErr error
	if strings.HasSuffix(strings.ToLower(outPath), ".json") {
		exportErr = bulk.ExportBatchToJSONFile(results, outPath)
	} else {
		exportErr = bulk.ExportBatchToCSVFile(results, outPath)
	}

	fmt.Println("\n" + strings.Repeat("=", 64))
	fmt.Println("✨ BATCH RECONNAISSANCE SUMMARY")
	fmt.Println(strings.Repeat("=", 64))
	fmt.Printf("Total Targets Processed: %d\n", len(targets))
	fmt.Printf("🎯 100%% Confirmed Valid: %d (%.1f%%)\n", validCount, float64(validCount)/float64(len(targets))*100)
	fmt.Printf("⚠️  Catch-All / Filtered: %d\n", catchAllCount)
	fmt.Printf("ℹ️  Heuristic Confirmed:  %d\n", otherCount)
	fmt.Printf("⏱️  Execution Time:        %s\n", duration)
	if exportErr != nil {
		fmt.Printf("❌ Failed to save output file: %v\n", exportErr)
	} else {
		fmt.Printf("📄 Enriched CRM Export:   %s\n", outPath)
	}
	fmt.Println(strings.Repeat("=", 64))
}

// selectBestCandidate picks the best candidate from validated indices based on:
// 1. Exact pattern match (activePattern from OSINT)
// 2. Common corporate patterns priority (first.last, first, flast, etc.)
// 3. Order in the original candidate list (OSINT-detected patterns are already prioritized)
func selectBestCandidate(candidates []models.CandidateResult, validIndices []int, activePattern string) int {
	if len(validIndices) == 1 {
		return validIndices[0]
	}

	// Priority order for common corporate email patterns
	patternPriority := map[string]int{
		"first.last":      100,
		"first":           90,
		"flast":           85,
		"firstlast":       80,
		"first_last":      75,
		"first-last":      70,
		"last.first":      65,
		"f.last":          60,
		"last":            55,
		"lfirst":          50,
		"first.l":         45,
		"f_last":          40,
		"lastfirst":       35,
		"last_first":      30,
		"last-first":      25,
		"first.m.last":    20,
		"firstmlast":      15,
		"fmlast":          10,
		"first.middle.last": 5,
		"first-m-last":    3,
	}

	bestIdx := validIndices[0]
	bestScore := -1

	for _, idx := range validIndices {
		c := candidates[idx]
		score := 0

		// Highest priority: exact match with OSINT-detected pattern
		if activePattern != "" && strings.EqualFold(c.PatternName, activePattern) {
			score += 1000
		}

		// Pattern-based priority
		if p, ok := patternPriority[c.PatternName]; ok {
			score += p
		}

		if score > bestScore {
			bestScore = score
			bestIdx = idx
		}
	}

	return bestIdx
}
