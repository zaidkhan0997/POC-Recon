package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/export"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/generator"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/parser"
	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/verifier"
)

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorCyan    = "\033[36m"
)

func printBanner() {
	fmt.Println(colorCyan + colorBold + `
   ___  ____  ______   ___                     
  / _ \/ __ \/ ___/ | / (_)__ _____ ___  ___ _ 
 / ___/ /_/ / /__ | |/ / / -_) __/ _ \/ _ '/ 
/_/   \____/\___/ |___/_/\__/_/  \___/\_, /  
                                     /___/   ` + colorReset)
	fmt.Println(colorDim + " Local-First Business Email Intelligence & Deliverability Suite (Go Engine)" + colorReset)
	fmt.Println("--------------------------------------------------------------------------------")
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, bsd, etc.
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
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

func main() {
	websiteFlag := flag.String("website", "", "Target company website URL or domain (e.g. example.com)")
	flag.StringVar(websiteFlag, "w", "", "Short alias for -website")

	nameFlag := flag.String("name", "", "Target person's full name (e.g. 'Jane Doe')")
	flag.StringVar(nameFlag, "n", "", "Short alias for -name")

	proxyFlag := flag.String("proxy", "", "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)")
	noVerifyFlag := flag.Bool("no-verify", false, "Generate patterns and DNS intel without SMTP probes")
	allFlag := flag.Bool("all", false, "Display all candidate permutations instead of single working email")
	openReportFlag := flag.Bool("open", false, "Automatically open HTML report in web browser")

	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	isInteractive := false

	printBanner()

	rawDomain := *websiteFlag
	rawName := *nameFlag

	if rawDomain == "" || rawName == "" {
		isInteractive = true
		if rawDomain == "" {
			fmt.Printf("%s[?] Enter target company website / domain (e.g. acme.com): %s", colorCyan, colorReset)
			line, _ := reader.ReadString('\n')
			rawDomain = strings.TrimSpace(line)
		}
		if rawName == "" {
			fmt.Printf("%s[?] Enter contact person full name (e.g. Jane Doe): %s", colorCyan, colorReset)
			line, _ := reader.ReadString('\n')
			rawName = strings.TrimSpace(line)
		}
	}

	if rawDomain == "" || rawName == "" {
		fmt.Printf("%s[!] Error: Target domain and contact name are required.%s\n", colorRed, colorReset)
		if isInteractive {
			fmt.Print("\nPress Enter to exit...")
			reader.ReadString('\n')
		}
		os.Exit(1)
	}

	domain, err := parser.NormalizeDomain(rawDomain)
	if err != nil {
		fmt.Printf("%s[!] Invalid website/domain: %v%s\n", colorRed, err, colorReset)
		if isInteractive {
			fmt.Print("\nPress Enter to exit...")
			reader.ReadString('\n')
		}
		os.Exit(1)
	}

	person := parser.ParsePersonName(rawName)
	candidates := generator.GenerateEmailPatterns(domain, person)

	fmt.Printf("\n%s[*] Resolving DNS infrastructure for: %s%s (with DoH Fallback)...%s\n", colorBold, colorCyan, domain, colorReset)
	mxList, err := verifier.LookupMXWithDoH(domain, 5*time.Second)
	hasMX := err == nil && len(mxList) > 0

	var provider *models.ProviderInfo
	port25Open := false
	isCatchAll := false

	if hasMX {
		provider = verifier.FingerprintProvider(domain, mxList)
		primaryMX := mxList[0].Host

		if !*noVerifyFlag {
			fmt.Printf("%s[*] Testing SMTP Port 25 connectivity on %s...%s\n", colorDim, primaryMX, colorReset)
			port25Open = verifier.CheckPort25(primaryMX, 5*time.Second, *proxyFlag)

			if port25Open {
				fmt.Printf("%s[*] Checking Catch-All configuration...%s\n", colorDim, colorReset)
				isCatchAll = verifier.CheckCatchAll(context.Background(), primaryMX, domain, 6*time.Second, *proxyFlag)
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

	if !hasMX {
		for i := range result.Candidates {
			result.Candidates[i].Status = models.StatusNoMX
			result.Candidates[i].SMTPMessage = "No MX record in DNS"
			result.Candidates[i].Confidence = 0
		}
	} else if *noVerifyFlag {
		for i := range result.Candidates {
			result.Candidates[i].Status = models.StatusUnverified
			result.Candidates[i].SMTPMessage = "Verification skipped (--no-verify)"
			result.Candidates[i].Confidence = computeConfidence(models.StatusUnverified, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)
		}
	} else if !port25Open {
		fmt.Printf("%s[!] Port 25 blocked by local network. Engaging HTTPS Cloud & Identity Verifiers...%s\n", colorYellow, colorReset)
		result.VerificationMethod = "HTTPS Cloud & Identity Verifiers (Port 443)"

		isM365 := false
		if provider != nil && strings.Contains(strings.ToLower(provider.Name), "microsoft") {
			isM365 = true
		}

		for i := range result.Candidates {
			email := result.Candidates[i].Email
			pattern := result.Candidates[i].PatternName
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
				st, code, msg := verifier.VerifyGravatar(email, 4*time.Second)
				if st == models.StatusValid {
					result.Candidates[i].Status = models.StatusValid
					result.Candidates[i].SMTPCode = code
					result.Candidates[i].SMTPMessage = msg
					result.Candidates[i].Confidence = 100
					resolved = true
				}
			}

			if !resolved {
				st, code, msg := verifier.VerifyPGPKeyring(email, 4*time.Second)
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
				if !*allFlag {
					break
				}
			}
		}
	} else if isCatchAll {
		fmt.Printf("%s[!] Catch-All active. Engaging HTTPS Cloud & Identity Verifiers...%s\n", colorYellow, colorReset)
		for i := range result.Candidates {
			email := result.Candidates[i].Email
			pattern := result.Candidates[i].PatternName
			resolved := false

			st, code, msg := verifier.VerifyGravatar(email, 4*time.Second)
			if st == models.StatusValid {
				result.Candidates[i].Status = models.StatusValid
				result.Candidates[i].SMTPCode = code
				result.Candidates[i].SMTPMessage = msg
				result.Candidates[i].Confidence = 100
				resolved = true
			}

			if !resolved {
				st, code, msg := verifier.VerifyPGPKeyring(email, 4*time.Second)
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
				if !*allFlag {
					break
				}
			}
		}
	} else {
		primaryMX := mxList[0].Host
		fmt.Printf("\n%s[*] Verifying %d candidate permutations via SMTP...%s\n", colorBold, len(result.Candidates), colorReset)
		for i := range result.Candidates {
			status, code, msg := verifier.VerifyEmail(context.Background(), primaryMX, domain, result.Candidates[i].Email, 8*time.Second, *proxyFlag)
			result.Candidates[i].Status = status
			result.Candidates[i].SMTPCode = code
			result.Candidates[i].SMTPMessage = msg
			result.Candidates[i].Confidence = computeConfidence(status, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)
			if status == models.StatusValid {
				result.BestCandidate = &result.Candidates[i]
				if !*allFlag {
					// Early-exit optimization
					break
				}
			}
			time.Sleep(300 * time.Millisecond) // Polite delay
		}
	}

	result.BestCandidate = result.GetPrimaryCandidate()

	// Print Overview Box
	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Printf(" Target Domain    : %s\n", domain)
	fmt.Printf(" Target Person    : %s\n", person.FullName)
	if provider != nil {
		fmt.Printf(" Mail Provider    : %s\n", provider.Name)
	}
	portStatus := colorRed + "✖ Blocked by ISP or Firewall" + colorReset
	if port25Open {
		portStatus = colorGreen + "✔ Open / Reachable" + colorReset
	}
	fmt.Printf(" Port 25 (SMTP)   : %s\n", portStatus)

	best := result.GetPrimaryCandidate()
	if best != nil {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf(" 🎯 PRIMARY WORKING EMAIL: %s%s%s\n", colorBold+colorGreen, best.Email, colorReset)
		fmt.Printf(" Confidence Score       : %s%d%%%s\n", colorCyan, best.Confidence, colorReset)
		fmt.Printf(" Pattern Format         : %s\n", best.PatternName)
		fmt.Printf(" Verification Status    : %s\n", best.Status)
		if best.SMTPMessage != "" {
			fmt.Printf(" Diagnostics            : %s\n", best.SMTPMessage)
		}
	}

	if *allFlag {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf(" %-4s %-32s %-14s %-6s %-16s %s\n", "#", "Candidate Email", "Pattern", "Conf", "Status", "Code")
		fmt.Println("--------------------------------------------------------------------------------")

		for i, c := range result.Candidates {
			color := colorYellow
			if c.Status == models.StatusValid {
				color = colorGreen
			} else if c.Status == models.StatusInvalid {
				color = colorRed
			}
			codeStr := "-"
			if c.SMTPCode != nil {
				codeStr = fmt.Sprintf("%d", *c.SMTPCode)
			}
			fmt.Printf(" %-4d %-32s %-14s %-6s %s%-16s%s %s\n", i+1, c.Email, c.PatternName, fmt.Sprintf("%d%%", c.Confidence), color, c.Status, colorReset, codeStr)
		}
	} else {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf(" Summary: 1 working email identified (%d permutations evaluated).\n", len(result.Candidates))
		fmt.Printf(" Note   : Pass -all to display all candidate permutations.\n")
	}
	fmt.Println("================================================================================")

	// Export report (single self-contained HTML report)
	_ = os.MkdirAll("results", 0755)
	base := fmt.Sprintf("results/%s_%s", domain, strings.ToLower(person.FirstName))
	htmlPath := base + "_report.html"

	_ = export.ExportHTML(result, htmlPath)

	fmt.Printf("\n%s[✔] Result persisted to HTML report:%s %s\n", colorGreen, colorReset, htmlPath)

	if *openReportFlag || isInteractive {
		if !*openReportFlag {
			fmt.Printf("\n%s[?] Open visual HTML report in your browser now? [Y/n]: %s", colorCyan, colorReset)
			ans, _ := reader.ReadString('\n')
			ans = strings.TrimSpace(strings.ToLower(ans))
			if ans == "" || ans == "y" || ans == "yes" {
				*openReportFlag = true
			}
		}
		if *openReportFlag {
			abs, _ := filepath.Abs(htmlPath)
			openBrowser("file://" + abs)
		}
	}

	if isInteractive {
		fmt.Printf("\n%sPress Enter to exit...%s", colorDim, colorReset)
		reader.ReadString('\n')
	}
}
