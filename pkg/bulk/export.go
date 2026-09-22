package bulk

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// EnrichedLeadExport represents a flattened, CRM-ready lead record
type EnrichedLeadExport struct {
	FullName          string   `json:"full_name"`
	FirstName         string   `json:"first_name"`
	LastName          string   `json:"last_name"`
	Domain            string   `json:"domain"`
	Email             string   `json:"email"`
	Confidence        int      `json:"confidence"`
	Status            string   `json:"status"`
	Pattern           string   `json:"pattern"`
	MailProvider      string   `json:"mail_provider"`
	VerifiedAt        string   `json:"verified_at"`
	Alternatives      []string `json:"alternatives,omitempty"`
	AlternativeEmails string   `json:"alternative_emails,omitempty"`
}

// ExportBatchToCSV writes verified batch results to any io.Writer in standard CRM CSV format
func ExportBatchToCSV(results []*models.ReconResult, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{
		"Full Name",
		"First Name",
		"Last Name",
		"Company Domain",
		"Verified Email",
		"Confidence Score",
		"Verification Status",
		"Email Pattern",
		"Mail Provider",
		"Alternative Emails",
		"Verified Date",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")

	for _, res := range results {
		if res == nil {
			continue
		}

		bestEmail := ""
		confidence := "0"
		status := "UNVERIFIED"
		pattern := "unknown"

		if res.BestCandidate != nil {
			bestEmail = res.BestCandidate.Email
			confidence = strconv.Itoa(res.BestCandidate.Confidence)
			status = string(res.BestCandidate.Status)
			pattern = res.BestCandidate.PatternName
		}

		provider := "Unknown"
		if res.Provider != nil && res.Provider.Name != "" {
			provider = res.Provider.Name
		}

		var altEmails []string
		for _, c := range res.Candidates {
			if c.Email != "" && !strings.EqualFold(c.Email, bestEmail) {
				altEmails = append(altEmails, c.Email)
			}
		}
		altStr := strings.Join(altEmails, "; ")

		row := []string{
			res.Person.FullName,
			res.Person.FirstName,
			res.Person.LastName,
			res.TargetDomain,
			bestEmail,
			confidence,
			status,
			pattern,
			provider,
			altStr,
			nowStr,
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ExportBatchToCSVFile writes verified batch results to a file path on disk
func ExportBatchToCSVFile(results []*models.ReconResult, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create CSV export file: %w", err)
	}
	defer f.Close()

	return ExportBatchToCSV(results, f)
}

// ExportBatchToJSONFile writes verified batch results to a structured JSON file on disk
func ExportBatchToJSONFile(results []*models.ReconResult, filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create JSON export file: %w", err)
	}
	defer f.Close()

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	var exports []EnrichedLeadExport

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

		var altEmails []string
		for _, c := range res.Candidates {
			if c.Email != "" && !strings.EqualFold(c.Email, bestEmail) {
				altEmails = append(altEmails, c.Email)
			}
		}

		exports = append(exports, EnrichedLeadExport{
			FullName:          res.Person.FullName,
			FirstName:         res.Person.FirstName,
			LastName:          res.Person.LastName,
			Domain:            res.TargetDomain,
			Email:             bestEmail,
			Confidence:        confidence,
			Status:            status,
			Pattern:           pattern,
			MailProvider:      provider,
			VerifiedAt:        nowStr,
			Alternatives:      altEmails,
			AlternativeEmails: strings.Join(altEmails, "; "),
		})
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(exports)
}
