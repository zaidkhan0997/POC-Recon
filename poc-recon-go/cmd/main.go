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

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func printBanner() {
	fmt.Printf("%s%sPOC-Recon [Go Native]%s | %sLocal-First Business Email Discovery%s\n",
		colorBold, colorCyan, colorReset, colorDim, colorReset)
	fmt.Printf("%sPrivacy-respecting • Direct DNS & RFC 5321 verification • Zero dependencies%s\n\n",
		colorDim, colorReset)
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
		fmt.Printf("%s[!] Error normalizing domain: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	person := parser.ParsePersonName(rawName)
	candidates := generator.GenerateEmailPatterns(domain, person)

	fmt.Printf("\n%s[*] Resolving DNS infrastructure for: %s%s...%s\n", colorBold, colorCyan, domain, colorReset)
	mxList, err := verifier.LookupMX(domain)
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
		for i := range result.Candidates {
			result.Candidates[i].Status = models.StatusPortBlocked
			result.Candidates[i].SMTPMessage = "Port 25 blocked by ISP or firewall"
			result.Candidates[i].Confidence = computeConfidence(models.StatusPortBlocked, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)
		}
	} else if isCatchAll {
		for i := range result.Candidates {
			result.Candidates[i].Status = models.StatusCatchAll
			result.Candidates[i].SMTPMessage = "Mail server accepts all probes (Catch-All)"
			result.Candidates[i].Confidence = computeConfidence(models.StatusCatchAll, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)
		}
	} else {
		primaryMX := mxList[0].Host
		fmt.Printf("\n%s[*] Verifying %d candidate permutations via SMTP...%s\n", colorBold, len(result.Candidates), colorReset)
		for i := range result.Candidates {
			status, code, msg := verifier.VerifyEmail(context.Background(), primaryMX, domain, result.Candidates[i].Email, 7*time.Second, *proxyFlag)
			result.Candidates[i].Status = status
			result.Candidates[i].SMTPCode = code
			result.Candidates[i].SMTPMessage = msg
			result.Candidates[i].Confidence = computeConfidence(status, result.Candidates[i].PatternName, provider, isCatchAll, port25Open)
			time.Sleep(300 * time.Millisecond) // Polite delay
		}
	}

	// Print Overview Box
	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Printf(" Target Domain    : %s\n", result.TargetDomain)
	fmt.Printf(" Target Person    : %s\n", result.Person.FullName)
	if provider != nil {
		fmt.Printf(" Mail Provider    : %s\n", provider.Name)
	}
	if len(result.MXRecords) > 0 {
		fmt.Printf(" Primary MX Host  : %s\n", result.MXRecords[0].Host)
	}
	portStatus := colorRed + "✖ Blocked / Unreachable" + colorReset
	if port25Open {
		portStatus = colorGreen + "✔ Open / Reachable" + colorReset
	}
	fmt.Printf(" Port 25 (SMTP)   : %s\n", portStatus)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf(" %-4s %-32s %-14s %-16s %s\n", "#", "Candidate Email", "Pattern", "Status", "Code")
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
		fmt.Printf(" %-4d %-32s %-14s %s%-16s%s %s\n", i+1, c.Email, c.PatternName, color, c.Status, colorReset, codeStr)
	}
	fmt.Println("================================================================================")

	// Export reports
	_ = os.MkdirAll("results", 0755)
	base := fmt.Sprintf("results/%s_%s", domain, strings.ToLower(person.FirstName))
	jsonPath := base + "_results.json"
	csvPath := base + "_results.csv"
	htmlPath := base + "_report.html"

	_ = export.ExportJSON(result, jsonPath)
	_ = export.ExportCSV(result, csvPath)
	_ = export.ExportHTML(result, htmlPath)

	fmt.Printf("\n%s[✔] Results persisted to:%s\n", colorGreen, colorReset)
	fmt.Printf("  • JSON: %s\n", jsonPath)
	fmt.Printf("  • CSV : %s\n", csvPath)
	fmt.Printf("  • HTML: %s\n", htmlPath)

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
