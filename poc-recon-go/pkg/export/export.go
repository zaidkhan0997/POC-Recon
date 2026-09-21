package export

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

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

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

// ExportCSV exports candidates to a CSV spreadsheet.
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

// ExportTXT exports results in simple text format with primary email spotlight.
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
	sb.WriteString("          POC-RECON RESULTS: SIMPLE TEXT FORMAT (COPY & PASTE)\n")
	sb.WriteString(strings.Repeat("=", 78) + "\n")
	sb.WriteString(fmt.Sprintf("Target Domain      : %s\n", result.TargetDomain))
	sb.WriteString(fmt.Sprintf("Target Person      : %s\n", result.Person.FullName))
	sb.WriteString(fmt.Sprintf("Mail Provider      : %s\n", providerName))
	sb.WriteString(fmt.Sprintf("Primary MX Host    : %s\n", primaryMX))
	portStr := "Blocked by ISP or Firewall"
	if result.Port25Open {
		portStr = "Open / Reachable"
	}
	sb.WriteString(fmt.Sprintf("Port 25 (SMTP)     : %s\n", portStr))
	caStr := "No (Strict Verification)"
	if result.IsCatchAll {
		caStr = "Yes (Accepts All Probes)"
	}
	sb.WriteString(fmt.Sprintf("Catch-All Domain   : %s\n", caStr))
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
			diag = "Standard corporate pattern match"
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

// ExportHTML generates a self-contained, responsive dark HTML report.
func ExportHTML(result *models.ReconResult, path string) error {
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
        .header h1 { font-size: 1.8rem; color: var(--primary); }
        .hero-card { background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%%, rgba(56, 189, 248, 0.1) 100%%); border: 2px solid rgba(16, 185, 129, 0.4); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }
        .hero-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
        .hero-badge { background: #10b981; color: #000; font-weight: 800; font-size: 0.8rem; padding: 4px 10px; border-radius: 6px; text-transform: uppercase; }
        .hero-conf { background: rgba(56, 189, 248, 0.2); color: var(--primary); font-weight: 700; font-size: 0.85rem; padding: 4px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.4); }
        .hero-email { font-size: 1.6rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem; word-break: break-all; }
        .hero-meta { font-size: 0.85rem; color: var(--text-muted); display: flex; gap: 1.5rem; flex-wrap: wrap; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
        .card .title { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
        .card .val { font-size: 1.2rem; font-weight: bold; }
        table { width: 100%%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        th { background: #1f2937; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }
        .conf-pill { font-size: 0.8rem; font-weight: 700; color: var(--primary); background: rgba(56, 189, 248, 0.15); padding: 2px 6px; border-radius: 4px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
        .badge-valid { background: rgba(16, 185, 129, 0.2); color: var(--valid); border: 1px solid var(--valid); }
        .badge-invalid { background: rgba(239, 68, 68, 0.2); color: var(--invalid); border: 1px solid var(--invalid); }
        .badge-unverified { background: rgba(245, 158, 11, 0.2); color: var(--unverified); border: 1px solid var(--unverified); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>POC-Recon Intelligence Report</h1>
            <p style="color: var(--text-muted);">Target: %s • Contact: %s</p>
        </div>

        <div class="hero-card">
            <div class="hero-header">
                <span class="hero-badge">🎯 Primary Working Email</span>
                <span class="hero-conf">%d%% Confidence</span>
            </div>
            <div class="hero-email">%s</div>
            <div class="hero-meta">
                <span>Pattern: <strong>%s</strong></span>
                <span>Status: <strong>%s</strong></span>
                <span>Diagnostics: %s</span>
            </div>
        </div>

        <div class="cards">
            <div class="card"><div class="title">Mail Provider</div><div class="val">%s</div></div>
            <div class="card"><div class="title">Primary MX</div><div class="val" style="font-size: 0.95rem;">%s</div></div>
            <div class="card"><div class="title">Port 25 Status</div><div class="val" style="color: %s;">%s</div></div>
            <div class="card"><div class="title">Catch-All Domain</div><div class="val">%s</div></div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Candidate Email</th>
                    <th>Pattern</th>
                    <th>Conf</th>
                    <th>Status</th>
                    <th>Code</th>
                    <th>Diagnostics</th>
                </tr>
            </thead>
            <tbody>%s</tbody>
        </table>
    </div>
</body>
</html>`,
		result.TargetDomain,
		result.TargetDomain,
		result.Person.FullName,
		bestConf,
		bestEmail,
		bestPattern,
		bestStatus,
		bestDiag,
		providerName,
		primaryMX,
		map[bool]string{true: "var(--valid)", false: "var(--invalid)"}[result.Port25Open],
		map[bool]string{true: "Open / Reachable", false: "Blocked / Closed"}[result.Port25Open],
		map[bool]string{true: "Enabled (Accepts all)", false: "Disabled (Strict)"}[result.IsCatchAll],
		tableRows.String(),
	)

	return os.WriteFile(path, []byte(htmlContent), 0644)
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
