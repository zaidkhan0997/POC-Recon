package dns

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func LookupMX(domain string) ([]models.MXRecord, error) {
	mxList, err := net.LookupMX(domain)
	if err != nil {
		// Attempt DoH fallback
		return LookupMXWithDoH(domain, 4*time.Second)
	}

	var records []models.MXRecord
	for _, mx := range mxList {
		records = append(records, models.MXRecord{
			Host:     strings.TrimSuffix(mx.Host, "."),
			Priority: mx.Pref,
		})
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func LookupMXWithDoH(domain string, timeout time.Duration) ([]models.MXRecord, error) {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=MX", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var doh dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&doh); err != nil {
		return nil, err
	}

	var records []models.MXRecord
	for _, a := range doh.Answer {
		if a.Type == 15 { // MX record
			fields := strings.Fields(a.Data)
			if len(fields) >= 2 {
				var pref uint16
				fmt.Sscanf(fields[0], "%d", &pref)
				host := strings.TrimSuffix(fields[1], ".")
				records = append(records, models.MXRecord{
					Host:     host,
					Priority: pref,
				})
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}

func FingerprintProvider(domain string, mxList []models.MXRecord) *models.ProviderInfo {
	var mxHosts []string
	for _, m := range mxList {
		mxHosts = append(mxHosts, strings.ToLower(m.Host))
	}
	combinedMX := strings.Join(mxHosts, " ")

	txtRecords, _ := net.LookupTXT(domain)
	var spfRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecord = txt
			break
		}
	}

	provider := &models.ProviderInfo{
		Name:      "Standard / On-Premise",
		SPFRecord: spfRecord,
		Details:   "Standard corporate mail infrastructure",
	}

	if strings.Contains(combinedMX, "google.com") || strings.Contains(combinedMX, "googlemail.com") || strings.Contains(combinedMX, "aspmx") {
		provider.Name = "Google Workspace"
		provider.Details = "Strict mailbox validation; accurate signals."
	} else if strings.Contains(combinedMX, "outlook.com") || strings.Contains(combinedMX, "office365") || strings.Contains(combinedMX, "protection.outlook.com") {
		provider.Name = "Microsoft 365 / Exchange Online"
		provider.Details = "Enterprise cloud directory with HTTPS fallback support."
	} else if strings.Contains(combinedMX, "pphosted.com") {
		provider.Name = "Proofpoint Enterprise"
		provider.Details = "Aggressive gateway filtering and greylisting."
	} else if strings.Contains(combinedMX, "mimecast.com") {
		provider.Name = "Mimecast Email Security"
		provider.Details = "Performs greylisting and recipient rate limiting."
	} else if strings.Contains(combinedMX, "zoho.com") {
		provider.Name = "Zoho Mail"
		provider.Details = "Standard RFC recipient rejection codes."
	} else if strings.Contains(combinedMX, "protonmail.ch") || strings.Contains(combinedMX, "proton.me") {
		provider.Name = "Proton Mail"
		provider.Details = "Zero-access encrypted privacy architecture."
	}

	return provider
}

type Resolver struct {
	Timeout time.Duration
}

func NewResolver(timeout time.Duration) *Resolver {
	return &Resolver{Timeout: timeout}
}

func (r *Resolver) LookupMX(domain string) ([]models.MXRecord, error) {
	return LookupMX(domain)
}

func (r *Resolver) IdentifyProvider(domain string, mxList []models.MXRecord) *models.ProviderInfo {
	return FingerprintProvider(domain, mxList)
}
