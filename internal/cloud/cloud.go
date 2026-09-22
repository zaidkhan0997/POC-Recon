package cloud

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

type m365Request struct {
	Username string `json:"Username"`
}

type m365Response struct {
	IfExistsResult int `json:"IfExistsResult"`
	ThrottleStatus int `json:"ThrottleStatus"`
}

func VerifyM365(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	payload, _ := json.Marshal(m365Request{Username: email})

	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/GetCredentialType", bytes.NewReader(payload))
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}

	var mResp m365Response
	if err := json.Unmarshal(body, &mResp); err != nil {
		return models.StatusUnverified, nil, "Invalid JSON from M365"
	}

	if mResp.ThrottleStatus == 1 {
		code := 429
		return models.StatusRateLimited, &code, "Microsoft 365 request throttled"
	}

	if mResp.IfExistsResult == 0 {
		code := 200
		return models.StatusValid, &code, "Verified: Mailbox exists in Microsoft 365 Cloud Directory"
	} else if mResp.IfExistsResult == 1 {
		code := 404
		return models.StatusInvalid, &code, "Recipient not found in Microsoft 365 Cloud Directory"
	}

	return models.StatusUnverified, nil, fmt.Sprintf("M365 non-conclusive result code: %d", mResp.IfExistsResult)
}

func VerifyGravatar(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	hasher := md5.New()
	hasher.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	hash := hex.EncodeToString(hasher.Sum(nil))

	reqURL := fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=404", hash)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("User-Agent", "POC-Recon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		code := 200
		return models.StatusValid, &code, "Confirmed: Active identity found on Gravatar/WordPress"
	}

	return models.StatusUnverified, &resp.StatusCode, "No Gravatar identity found"
}

func VerifyPGPKeyring(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	reqURL := fmt.Sprintf("https://keyserver.ubuntu.com/pks/lookup?search=%s&op=index&options=mr", url.QueryEscape(email))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("User-Agent", "POC-Recon/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}

	emailLower := strings.ToLower(email)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "uid:") && strings.Contains(strings.ToLower(line), emailLower) {
			code := 200
			return models.StatusValid, &code, "Confirmed: Email verified via Public OpenPGP Keyring (HTTPS)"
		}
	}

	return models.StatusUnverified, nil, "Email not found in OpenPGP keyring"
}

type ghSearchResponse struct {
	TotalCount int `json:"total_count"`
}

func VerifyGitHubCommits(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	reqURL := fmt.Sprintf("https://api.github.com/search/commits?q=committer-email:%s", url.QueryEscape(email))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("Accept", "application/vnd.github.cloak-preview")
	req.Header.Set("User-Agent", "POC-Recon-OSINT")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var gh ghSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&gh); err == nil && gh.TotalCount > 0 {
			code := 200
			return models.StatusValid, &code, fmt.Sprintf("Confirmed: Found %d public GitHub commits", gh.TotalCount)
		}
	}

	return models.StatusUnverified, &resp.StatusCode, "No GitHub commits found"
}

func VerifyPGP(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return VerifyPGPKeyring(email, timeout)
}

func VerifyGitHub(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return VerifyGitHubCommits(email, timeout)
}

type relayResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func VerifyCloudRelay(email string, relayURL string, token string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	client := &http.Client{Timeout: timeout}
	endpoint := fmt.Sprintf("%s/verify?email=%s", strings.TrimRight(relayURL, "/"), url.QueryEscape(email))
	if token != "" {
		endpoint += fmt.Sprintf("&token=%s", url.QueryEscape(token))
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return models.StatusUnverified, nil, err.Error()
	}
	req.Header.Set("User-Agent", "POC-Recon-Client/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.StatusUnverified, nil, fmt.Sprintf("Relay connection error: %v", err)
	}
	defer resp.Body.Close()

	var rResp relayResponse
	if err := json.NewDecoder(resp.Body).Decode(&rResp); err != nil {
		return models.StatusUnverified, &resp.StatusCode, "Invalid response from relay"
	}

	switch rResp.Status {
	case "VALID":
		return models.StatusValid, &rResp.Code, rResp.Message
	case "INVALID":
		return models.StatusInvalid, &rResp.Code, rResp.Message
	case "CATCH_ALL":
		return models.StatusCatchAll, &rResp.Code, rResp.Message
	default:
		return models.StatusUnverified, &rResp.Code, rResp.Message
	}
}

type RelayVerifyResponse struct {
	Status   models.VerificationStatus
	SMTPCode *int
	Message  string
}

type RelayClient struct {
	URL     string
	Token   string
	Timeout time.Duration
}

func NewRelayClient(url, token string, timeout time.Duration) *RelayClient {
	return &RelayClient{
		URL:     url,
		Token:   token,
		Timeout: timeout,
	}
}

func (r *RelayClient) VerifyCandidate(ctx context.Context, email, mxHost string) (*RelayVerifyResponse, error) {
	status, code, msg := VerifyCloudRelay(email, r.URL, r.Token, r.Timeout)
	return &RelayVerifyResponse{
		Status:   status,
		SMTPCode: code,
		Message:  msg,
	}, nil
}
