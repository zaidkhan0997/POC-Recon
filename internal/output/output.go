package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

var (
	brandStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#38BDF8"))

	subStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9CA3AF"))

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#38BDF8")).
			Padding(1, 2).
			MarginTop(1).
			MarginBottom(1)

	heroCardStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#10B981")).
			Padding(1, 2).
			MarginTop(1).
			MarginBottom(1)

	badgeValid = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("#10B981")).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1)

	badgeInvalid = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("#EF4444")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	badgeWarning = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("#F59E0B")).
			Foreground(lipgloss.Color("#000000")).
			Padding(0, 1)

	badgeDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))
)

// PrintBanner renders the POC-Recon terminal title.
func PrintBanner() {
	banner := `
   ___  ____  ______   ___                     
  / _ \/ __ \/ ___/ | / (_)__ _____ ___  ___ _ 
 / ___/ /_/ / /__ | |/ / / -_) __/ _ \/ _ '/ 
/_/   \____/\___/ |___/_/\__/_/  \___/\_, /  
                                     /___/   `
	fmt.Println(brandStyle.Render(banner))
	fmt.Println(subStyle.Render(" Local-first corporate email discovery and protocol verification outcome"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#9CA3AF")).Render(" Open-source project developed by ") +
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render("zaidkhan0997") +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#9CA3AF")).Render(" (https://zaidkhan0997.pages.dev)"))
	fmt.Println(subStyle.Render("────────────────────────────────────────────────────────────────────────────────"))
}

// PrintTerminalSummary prints the formatted terminal results.
func PrintTerminalSummary(result *models.ReconResult, showAll bool) {
	primaryMX := "None"
	if len(result.MXRecords) > 0 {
		primaryMX = fmt.Sprintf("%s (pri %d)", result.MXRecords[0].Host, result.MXRecords[0].Priority)
	}
	providerName := "Standard SMTP"
	if result.Provider != nil && result.Provider.Name != "" {
		providerName = result.Provider.Name
	}

	port25Str := lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render("Blocked by ISP / Network")
	if result.Port25Open {
		port25Str = lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981")).Render("Open / Reachable")
	}

	catchAllStr := lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981")).Render("No (Strict Mailbox Check)")
	if result.IsCatchAll {
		catchAllStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")).Render("Yes (Accepts All Inboxes)")
	}

	patternInfo := "None detected"
	if result.DetectedPattern != "" {
		patternInfo = fmt.Sprintf("%s (source: %s)", result.DetectedPattern, result.DetectedPatternSource)
	}

	meta := fmt.Sprintf(
		"Target Person  : %s\nTarget Domain  : %s\nMail Provider  : %s\nPrimary MX     : %s\nPort 25 Status : %s\nCatch-All      : %s\nDomain Pattern : %s\nMethod         : %s",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Render(result.Person.FullName),
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render(result.TargetDomain),
		providerName,
		primaryMX,
		port25Str,
		catchAllStr,
		patternInfo,
		result.VerificationMethod,
	)

	fmt.Println(cardStyle.Render(meta))

	// Spotlight Hero Card for Primary Working Email
	best := result.GetPrimaryCandidate()
	if best != nil {
		badge := badgeDim.Render("[" + string(best.Status) + "]")
		switch best.Status {
		case models.StatusValid:
			badge = badgeValid.Render(" VALID ")
		case models.StatusInvalid:
			badge = badgeInvalid.Render(" INVALID ")
		case models.StatusCatchAll, models.StatusPortBlocked, models.StatusTimeout, models.StatusUnverified:
			badge = badgeWarning.Render(" " + string(best.Status) + " ")
		}

		confColor := "#10B981"
		if best.Confidence < 60 {
			confColor = "#F59E0B"
		}
		if best.Confidence < 40 {
			confColor = "#EF4444"
		}
		confStr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(confColor)).Render(fmt.Sprintf("%d%%", best.Confidence))

		diag := best.SMTPMessage
		if diag == "" {
			diag = "Confidence derived from domain pattern & corporate conventions"
		}

		heroContent := fmt.Sprintf(
			"🎯 %s\n\n%s   %s   Conf: %s\n\nPattern Format : %s\nDiagnostics    : %s",
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981")).Render("PRIMARY WORKING EMAIL IDENTIFIED"),
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Render(best.Email),
			badge,
			confStr,
			lipgloss.NewStyle().Foreground(lipgloss.Color("#38BDF8")).Render(best.PatternName),
			diag,
		)
		fmt.Println(heroCardStyle.Render(heroContent))
	}

	if showAll && len(result.Candidates) > 0 {
		fmt.Println(lipgloss.NewStyle().Bold(true).Render("\nALL EVALUATED EMAIL CANDIDATES:"))
		fmt.Println(subStyle.Render("─────────────────────────────────────────────────────────────────────────────────────────────"))
		fmt.Printf("%-3s  %-34s  %-14s  %-6s  %-20s  %s\n", "#", "Candidate Email", "Pattern", "Conf", "Status", "Details")
		fmt.Println(subStyle.Render("─────────────────────────────────────────────────────────────────────────────────────────────"))

		for i, c := range result.Candidates {
			statusStr := string(c.Status)
			switch c.Status {
			case models.StatusValid:
				statusStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981")).Render(statusStr)
			case models.StatusInvalid:
				statusStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Render(statusStr)
			case models.StatusCatchAll, models.StatusPortBlocked:
				statusStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")).Render(statusStr)
			}

			codeInfo := ""
			if c.SMTPCode != nil {
				codeInfo = fmt.Sprintf("[%d] ", *c.SMTPCode)
			}
			diagMsg := codeInfo + c.SMTPMessage
			if len(diagMsg) > 40 {
				diagMsg = diagMsg[:37] + "..."
			}

			fmt.Printf("%-3d  %-34s  %-14s  %3d%%   %-20s  %s\n",
				i+1,
				c.Email,
				c.PatternName,
				c.Confidence,
				statusStr,
				diagMsg,
			)
		}
		fmt.Println(subStyle.Render("─────────────────────────────────────────────────────────────────────────────────────────────"))
		fmt.Printf("Total Permutations: %d | Valid: %d\n", len(result.Candidates), len(result.GetValidEmails()))
	} else {
		fmt.Println(subStyle.Render(fmt.Sprintf("\n💡 1 primary email selected from %d permutations. Pass -all to view all candidate details.", len(result.Candidates))))
	}
}

// OpenBrowser opens the given file or URL in the default web browser.
func OpenBrowser(target string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default: // linux, freebsd, etc.
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}

// OpenFolderInFileManager reveals the given directory in the native OS file manager.
func OpenFolderInFileManager(dirPath string) error {
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		absPath = dirPath
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", filepath.FromSlash(absPath))
	case "darwin":
		cmd = exec.Command("open", absPath)
	default: // linux, bsd
		cmd = exec.Command("xdg-open", absPath)
	}

	return cmd.Start()
}

// ExportJSON saves the recon result as a JSON document.
func ExportJSON(result *models.ReconResult, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ExportCSV exports candidate results to a CSV file.
func ExportCSV(result *models.ReconResult, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"email", "pattern", "confidence", "status", "smtp_code", "smtp_message", "domain", "primary_mx"}
	if err := writer.Write(header); err != nil {
		return err
	}

	primaryMX := "N/A"
	if len(result.MXRecords) > 0 {
		primaryMX = result.MXRecords[0].Host
	}

	for _, c := range result.Candidates {
		smtpCode := ""
		if c.SMTPCode != nil {
			smtpCode = strconv.Itoa(*c.SMTPCode)
		}
		row := []string{
			c.Email,
			c.PatternName,
			fmt.Sprintf("%d%%", c.Confidence),
			string(c.Status),
			smtpCode,
			c.SMTPMessage,
			result.TargetDomain,
			primaryMX,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// ExportTXT exports recon results into a plain text file.
func ExportTXT(result *models.ReconResult, path string, showAll bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	primaryMX := "None"
	if len(result.MXRecords) > 0 {
		primaryMX = result.MXRecords[0].Host
	}
	providerName := "Unknown"
	if result.Provider != nil {
		providerName = result.Provider.Name
	}

	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 78) + "\n")
	sb.WriteString("          POC-RECON: CORPORATE EMAIL DISCOVERY & VERIFICATION\n")
	sb.WriteString(" Local-first corporate email discovery and protocol verification outcome\n")
	sb.WriteString(" Open-source project developed by zaidkhan0997 (https://zaidkhan0997.pages.dev)\n")
	sb.WriteString(strings.Repeat("=", 78) + "\n")
	sb.WriteString(fmt.Sprintf("Target Person      : %s\n", result.Person.FullName))
	sb.WriteString(fmt.Sprintf("Target Domain      : %s\n", result.TargetDomain))
	sb.WriteString(fmt.Sprintf("Mail Provider      : %s\n", providerName))
	sb.WriteString(fmt.Sprintf("Primary MX Host    : %s\n", primaryMX))
	portStr := "Blocked by ISP / Network"
	if result.Port25Open {
		portStr = "Open / Reachable"
	}
	sb.WriteString(fmt.Sprintf("Port 25 (SMTP)     : %s\n", portStr))
	caStr := "No (Strict Mailbox Verification)"
	if result.IsCatchAll {
		caStr = "Yes (Accepts All Inboxes)"
	}
	sb.WriteString(fmt.Sprintf("Catch-All Domain   : %s\n", caStr))
	if result.DetectedPattern != "" {
		sb.WriteString(fmt.Sprintf("Active Pattern     : %s (Source: %s)\n", result.DetectedPattern, result.DetectedPatternSource))
	}
	sb.WriteString(strings.Repeat("-", 78) + "\n")

	best := result.GetPrimaryCandidate()
	if best != nil {
		sb.WriteString("🎯 PRIMARY WORKING EMAIL:\n")
		sb.WriteString(fmt.Sprintf("Working Email      : %s\n", best.Email))
		sb.WriteString(fmt.Sprintf("Confidence Score   : %d%%\n", best.Confidence))
		sb.WriteString(fmt.Sprintf("Pattern Format     : %s\n", best.PatternName))
		sb.WriteString(fmt.Sprintf("Verification Status: [%s]\n", best.Status))
		diag := best.SMTPMessage
		if diag == "" {
			diag = "Confidence derived from corporate pattern & heuristic scoring"
		}
		sb.WriteString(fmt.Sprintf("Diagnostics / Note : %s\n", diag))
		sb.WriteString(strings.Repeat("-", 78) + "\n")
	}

	if showAll && len(result.Candidates) > 0 {
		sb.WriteString("ALL CANDIDATE EMAIL PERMUTATIONS:\n")
		sb.WriteString(strings.Repeat("-", 78) + "\n")
		sb.WriteString(fmt.Sprintf("%-4s %-32s %-14s %-8s %-20s %s\n", "#", "Candidate Email", "Pattern", "Conf", "Status", "Diagnostics"))
		sb.WriteString(strings.Repeat("-", 78) + "\n")
		for i, c := range result.Candidates {
			codeStr := ""
			if c.SMTPCode != nil {
				codeStr = fmt.Sprintf("(%d) ", *c.SMTPCode)
			}
			diag := fmt.Sprintf("%s%s", codeStr, c.SMTPMessage)
			sb.WriteString(fmt.Sprintf("%-4d %-32s %-14s %-8s [%-18s] %s\n", i+1, c.Email, c.PatternName, fmt.Sprintf("%d%%", c.Confidence), c.Status, diag))
		}
		sb.WriteString(strings.Repeat("=", 78) + "\n")
		sb.WriteString(fmt.Sprintf("Total Candidates: %d | Confirmed Valid: %d\n", len(result.Candidates), len(result.GetValidEmails())))
	} else {
		sb.WriteString(fmt.Sprintf("Summary: 1 working email identified (%d permutations evaluated).\n", len(result.Candidates)))
		sb.WriteString("Note   : Run with -all to view all candidate permutations.\n")
	}
	sb.WriteString(strings.Repeat("=", 78) + "\n")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// ExportHTML produces a modern standalone dark-theme HTML report.
func ExportHTML(result *models.ReconResult, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	primaryMX := "None"
	if len(result.MXRecords) > 0 {
		primaryMX = fmt.Sprintf("%s (pri %d)", result.MXRecords[0].Host, result.MXRecords[0].Priority)
	}
	providerName := "Standard SMTP"
	if result.Provider != nil && result.Provider.Name != "" {
		providerName = result.Provider.Name
	}

	best := result.GetPrimaryCandidate()
	bestEmail := "None"
	bestPattern := "N/A"
	bestStatus := "UNKNOWN"
	bestConf := 0
	bestDiag := "Standard corporate pattern match"
	if best != nil {
		bestEmail = best.Email
		bestPattern = best.PatternName
		bestStatus = string(best.Status)
		bestConf = best.Confidence
		if best.SMTPMessage != "" {
			bestDiag = best.SMTPMessage
		}
	}

	var tableRows strings.Builder
	for i, c := range result.Candidates {
		badgeClass := "badge-unverified"
		if c.Status == models.StatusValid {
			badgeClass = "badge-valid"
		} else if c.Status == models.StatusInvalid {
			badgeClass = "badge-invalid"
		}

		codeStr := "-"
		if c.SMTPCode != nil {
			codeStr = strconv.Itoa(*c.SMTPCode)
		}

		tableRows.WriteString(fmt.Sprintf(`
		<tr>
			<td>%d</td>
			<td><strong>%s</strong></td>
			<td><code>%s</code></td>
			<td><span class="conf-pill">%d%%</span></td>
			<td><span class="badge %s">%s</span></td>
			<td>%s</td>
			<td><small>%s</small></td>
		</tr>`, i+1, c.Email, c.PatternName, c.Confidence, badgeClass, c.Status, codeStr, c.SMTPMessage))
	}

	patternDisplay := "None detected"
	if result.DetectedPattern != "" {
		patternDisplay = fmt.Sprintf("%s (%s)", result.DetectedPattern, result.DetectedPatternSource)
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POC-Recon Report | %s</title>
    <style>
        :root {
            --bg: #0b0f19;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #1f2937;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --primary: #38bdf8;
            --valid: #10b981;
            --invalid: #ef4444;
            --unverified: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
        .header h1 { font-size: 1.8rem; color: var(--primary); font-weight: 800; }
        .header p { color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }
        .hero-card { background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%%, rgba(56, 189, 248, 0.1) 100%%); border: 2px solid rgba(16, 185, 129, 0.4); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }
        .hero-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
        .hero-badge { background: #10b981; color: #000; font-weight: 800; font-size: 0.8rem; padding: 4px 10px; border-radius: 6px; text-transform: uppercase; }
        .hero-conf { background: rgba(56, 189, 248, 0.2); color: var(--primary); font-weight: 700; font-size: 0.85rem; padding: 4px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.4); }
        .hero-email { font-size: 1.6rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem; word-break: break-all; }
        .hero-meta { font-size: 0.85rem; color: var(--text-muted); display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
        .hero-diag { font-size: 0.85rem; color: #a7f3d0; background: rgba(16, 185, 129, 0.1); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(16, 185, 129, 0.2); }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
        .card .title { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .card .val { font-size: 1.1rem; font-weight: bold; color: #fff; }
        .copy-btn { background: #38bdf8; color: #0f172a; border: none; padding: 4px 10px; border-radius: 4px; font-weight: 700; cursor: pointer; font-size: 0.8rem; margin-left: 0.5rem; }
        .copy-btn:hover { background: #7dd3fc; }
        table { width: 100%%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); margin-top: 1rem; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        th { background: #1f2937; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
        tr:hover { background: var(--surface-hover); }
        .conf-pill { font-size: 0.8rem; font-weight: 700; color: var(--primary); background: rgba(56, 189, 248, 0.15); padding: 2px 6px; border-radius: 4px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
        .badge-valid { background: rgba(16, 185, 129, 0.2); color: var(--valid); border: 1px solid var(--valid); }
        .badge-invalid { background: rgba(239, 68, 68, 0.2); color: var(--invalid); border: 1px solid var(--invalid); }
        .badge-unverified { background: rgba(245, 158, 11, 0.2); color: var(--unverified); border: 1px solid var(--unverified); }
        code { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; color: #e2e8f0; }
        .footer { margin-top: 2rem; font-size: 0.8rem; color: var(--text-muted); text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>POC-Recon Intelligence Report</h1>
            <p>Target: <strong>%s</strong> &bull; Domain: <strong>%s</strong> &bull; Generated: %s</p>
        </div>

        <div class="hero-card">
            <div class="hero-header">
                <span class="hero-badge">🎯 Primary Working Email</span>
                <span class="hero-conf">Confidence: %d%%</span>
            </div>
            <div class="hero-email">
                %s
                <button class="copy-btn" onclick="navigator.clipboard.writeText('%s'); this.innerText='Copied!'; setTimeout(()=>this.innerText='Copy', 2000)">Copy</button>
            </div>
            <div class="hero-meta">
                <span>Format: <code>%s</code></span>
                <span>Status: <strong>%s</strong></span>
                <span>Verification Method: <strong>%s</strong></span>
            </div>
            <div class="hero-diag">%s</div>
        </div>

        <div class="cards">
            <div class="card">
                <div class="title">Mail Provider</div>
                <div class="val">%s</div>
            </div>
            <div class="card">
                <div class="title">Primary MX Host</div>
                <div class="val" style="font-size: 0.95rem; word-break: break-all;">%s</div>
            </div>
            <div class="card">
                <div class="title">Port 25 (SMTP)</div>
                <div class="val">%t</div>
            </div>
            <div class="card">
                <div class="title">Catch-All Domain</div>
                <div class="val">%t</div>
            </div>
            <div class="card">
                <div class="title">OSINT Detected Pattern</div>
                <div class="val" style="font-size: 0.95rem;">%s</div>
            </div>
        </div>

        <h2 style="font-size: 1.2rem; margin-top: 2rem; margin-bottom: 0.5rem;">All Evaluated Permutations (%d)</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Email Address</th>
                    <th>Pattern</th>
                    <th>Confidence</th>
                    <th>Status</th>
                    <th>SMTP</th>
                    <th>Diagnostics</th>
                </tr>
            </thead>
            <tbody>
                %s
            </tbody>
        </table>

        <div class="footer">
            Local-first corporate email discovery and protocol verification outcome &bull;
            Open-source project developed by <strong>zaidkhan0997</strong> (<a href="https://zaidkhan0997.pages.dev" target="_blank" style="color: #38bdf8; text-decoration: none;">zaidkhan0997.pages.dev</a>)
        </div>
    </div>
</body>
</html>`,
		result.TargetDomain,
		result.Person.FullName,
		result.TargetDomain,
		result.Timestamp.Format("2006-01-02 15:04:05 MST"),
		bestConf,
		bestEmail,
		bestEmail,
		bestPattern,
		bestStatus,
		result.VerificationMethod,
		bestDiag,
		providerName,
		primaryMX,
		result.Port25Open,
		result.IsCatchAll,
		patternDisplay,
		len(result.Candidates),
		tableRows.String(),
	)

	return os.WriteFile(path, []byte(htmlContent), 0644)
}
