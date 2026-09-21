package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

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

	header := []string{"email", "pattern", "status", "smtp_code", "smtp_message", "domain", "primary_mx"}
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

func ExportHTML(result *models.ReconResult, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	primaryMX := "N/A"
	if len(result.MXRecords) > 0 {
		primaryMX = result.MXRecords[0].Host
	}
	providerName := "Unknown"
	if result.Provider != nil {
		providerName = result.Provider.Name
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
			<td><span class="badge %s">%s</span></td>
			<td>%s</td>
			<td><small>%s</small></td>
		</tr>`, i+1, c.Email, c.PatternName, badgeClass, c.Status, codeStr, c.SMTPMessage))
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
            --primary: #06b6d4;
            --valid: #10b981;
            --invalid: #ef4444;
            --unverified: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
        .header h1 { font-size: 1.8rem; color: var(--primary); }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
        .card .title { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
        .card .val { font-size: 1.2rem; font-weight: bold; }
        table { width: 100%%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        th { background: #1f2937; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }
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
		providerName,
		primaryMX,
		map[bool]string{true: "var(--valid)", false: "var(--invalid)"}[result.Port25Open],
		map[bool]string{true: "Open / Reachable", false: "Blocked / Closed"}[result.Port25Open],
		map[bool]string{true: "Enabled (Accepts all)", false: "Disabled (Strict)"}[result.IsCatchAll],
		tableRows.String(),
	)

	return os.WriteFile(path, []byte(htmlContent), 0644)
}
