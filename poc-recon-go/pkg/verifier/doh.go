package verifier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// LookupMXWithDoH queries MX records via standard DNS first, falling back to DNS-over-HTTPS
// (Cloudflare & Google) if local DNS queries fail or are blocked.
func LookupMXWithDoH(domain string, timeout time.Duration) ([]models.MXRecord, error) {
	// 1. Try standard system DNS first
	records, err := LookupMX(domain)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	// 2. Fallback to Cloudflare DoH (Port 443 HTTPS)
	records, err = queryDoH(fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=MX", domain), timeout)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	// 3. Fallback to Google DoH (Port 443 HTTPS)
	records, err = queryDoH(fmt.Sprintf("https://dns.google/resolve?name=%s&type=MX", domain), timeout)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	return nil, fmt.Errorf("all DNS and DoH lookups failed for %s", domain)
}

func queryDoH(apiURL string, timeout time.Duration) ([]models.MXRecord, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; POC-Recon/2.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res dohResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}

	var records []models.MXRecord
	for _, ans := range res.Answer {
		if ans.Type == 15 { // Type 15 is MX
			parts := strings.Fields(ans.Data)
			if len(parts) >= 2 {
				pref, _ := strconv.Atoi(parts[0])
				host := strings.TrimSuffix(parts[1], ".")
				records = append(records, models.MXRecord{
					Host:     host,
					Priority: uint16(pref),
				})
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}
