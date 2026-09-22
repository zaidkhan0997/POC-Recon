package cloud

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// MultiSignalResult aggregates multiple free identity and cloud directory signals
type MultiSignalResult struct {
	Status          models.VerificationStatus
	Confidence      int
	ConfirmedMethod string
	M365Found       bool
	GravatarFound   bool
	PGPFound        bool
	Details         []string
}

// CheckM365Autodiscover probes Microsoft Outlook Autodiscover API for mailbox existence
func CheckM365Autodiscover(ctx context.Context, email string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}
	endpoint := fmt.Sprintf("https://autodiscover-s.outlook.com/autodiscover/autodiscover.json?Email=%s&Protocol=Autodiscoverv1", email)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "POC-Recon/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Only HTTP 200 containing confirmed active Autodiscover endpoint on outlook.office365.com
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if err == nil {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "Autodiscoverv1") && strings.Contains(bodyStr, "outlook.office365.com") {
				return true
			}
		}
	}
	return false
}

// MultiSignalCheck performs multi-source verification without Port 25
func MultiSignalCheck(ctx context.Context, email string, timeout time.Duration) MultiSignalResult {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	result := MultiSignalResult{
		Status:     models.StatusPortBlocked,
		Confidence: 45,
	}

	// 1. Microsoft 365 Cloud Directory probe
	stM365, _, msgM365 := VerifyM365(email, timeout)
	if stM365 == models.StatusValid {
		result.M365Found = true
		result.Details = append(result.Details, "Microsoft 365: Mailbox confirmed in cloud tenant")
	} else if stM365 == models.StatusInvalid {
		// Definitively rejected by tenant
		result.Status = models.StatusInvalid
		result.Confidence = 0
		result.ConfirmedMethod = "Rejected by Microsoft 365 tenant directory"
		return result
	} else {
		// Secondary autodiscover probe
		if CheckM365Autodiscover(ctx, email, timeout) {
			result.M365Found = true
			result.Details = append(result.Details, "Microsoft 365 Autodiscover: Valid mailbox endpoint")
		}
	}

	// 2. Gravatar Identity probe
	stGravatar, _, _ := VerifyGravatar(email, timeout)
	if stGravatar == models.StatusValid {
		result.GravatarFound = true
		result.Details = append(result.Details, "Gravatar: Public identity avatar registered")
	}

	// 3. OpenPGP Keyring probe
	stPGP, _, _ := VerifyPGPKeyring(email, timeout)
	if stPGP == models.StatusValid {
		result.PGPFound = true
		result.Details = append(result.Details, "OpenPGP: Public cryptographic key published")
	}

	// Calculate compound confidence and assign honest status
	signalsCount := 0
	if result.M365Found {
		signalsCount += 2
	}
	if result.GravatarFound {
		signalsCount++
	}
	if result.PGPFound {
		signalsCount++
	}

	if result.M365Found && (result.GravatarFound || result.PGPFound) {
		result.Status = models.StatusValid
		result.Confidence = 95
		result.ConfirmedMethod = fmt.Sprintf("High Confidence (95%%) – Microsoft 365 + %s (No SMTP)", strings.Join(result.Details, ", "))
	} else if result.M365Found {
		result.Status = models.StatusValid
		result.Confidence = 88
		result.ConfirmedMethod = "High Confidence (88%) – Microsoft 365 Cloud Directory (No SMTP)"
	} else if result.GravatarFound && result.PGPFound {
		result.Status = models.StatusValid
		result.Confidence = 82
		result.ConfirmedMethod = "High Confidence (82%) – Gravatar + OpenPGP Verified (No SMTP)"
	} else if result.GravatarFound {
		result.Status = models.StatusValid
		result.Confidence = 75
		result.ConfirmedMethod = "Verified: Gravatar Public Profile Match"
	} else if result.PGPFound {
		result.Status = models.StatusValid
		result.Confidence = 78
		result.ConfirmedMethod = "Verified: OpenPGP Public Keyring Match"
	} else {
		result.Status = models.StatusPortBlocked
		result.Confidence = 48
		result.ConfirmedMethod = "Port 25 filtered; evaluated via heuristic pattern"
		if len(msgM365) > 0 {
			result.Details = append(result.Details, msgM365)
		}
	}

	return result
}
