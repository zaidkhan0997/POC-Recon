package verifier

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

// VerifyM365 queries Microsoft's GetCredentialType endpoint over Port 443 HTTPS.
// IfExistsResult:
//   0 = Mailbox exists in Microsoft 365 / Azure AD tenant (VALID)
//   1 = User / mailbox does not exist (INVALID)
func VerifyM365(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"username":             email,
		"isOtherIdpSupported": true,
		"checkPhones":          false,
		"isRemoteNGCSupported": true,
		"isCookieBannerShown":  false,
		"isFidoSupported":      true,
		"country":              "US",
	})

	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/GetCredentialType", bytes.NewBuffer(reqBody))
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		code := resp.StatusCode
		return models.StatusUnverified, &code, fmt.Sprintf("M365 HTTP status %d", code)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return models.StatusUnverified, nil, err.Error()
	}

	if ifExists, ok := data["IfExistsResult"].(float64); ok {
		code := int(ifExists)
		switch int(ifExists) {
		case 0:
			return models.StatusValid, &code, "Confirmed: Mailbox exists in Microsoft 365 tenant"
		case 1:
			return models.StatusInvalid, &code, "Recipient not found in Microsoft 365 tenant"
		default:
			return models.StatusUnverified, &code, fmt.Sprintf("Ambiguous M365 IfExistsResult code %d", int(ifExists))
		}
	}

	return models.StatusUnverified, nil, "M365 response missing IfExistsResult"
}

// VerifyGravatar queries Gravatar profile avatar over HTTPS.
func VerifyGravatar(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	trimmed := strings.TrimSpace(strings.ToLower(email))
	hash := md5.Sum([]byte(trimmed))
	hashStr := hex.EncodeToString(hash[:])
	avatarURL := fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=404", hashStr)

	req, err := http.NewRequest("HEAD", avatarURL, nil)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; POC-Recon/2.0)")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	if resp.StatusCode == http.StatusOK {
		return models.StatusValid, &code, "Confirmed: Active identity found on Gravatar"
	}

	return models.StatusUnverified, &code, "No Gravatar profile match found"
}

// VerifyPGPKeyring queries public keyservers over HTTPS.
func VerifyPGPKeyring(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	queryURL := fmt.Sprintf("https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=%s", url.QueryEscape(email))

	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; POC-Recon/2.0)")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
			return models.StatusValid, &code, "Confirmed: Email verified via Public PGP Keyring"
		}
	}

	return models.StatusUnverified, &code, "No OpenPGP public key found"
}
