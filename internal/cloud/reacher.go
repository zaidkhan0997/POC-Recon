package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// ReacherProxyConfig maps optional proxy parameters to Reacher's API
type ReacherProxyConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// reacherRequest payload for POST /v0/check_email
type reacherRequest struct {
	ToEmail string              `json:"to_email"`
	Proxy   *ReacherProxyConfig `json:"proxy,omitempty"`
}

// reacherResponse describes the output from Reacher (check-if-email-exists)
type reacherResponse struct {
	Input       string `json:"input"`
	IsReachable string `json:"is_reachable"` // "safe" | "invalid" | "risky" | "unknown"
	SMTP        struct {
		CanConnectSMTP bool `json:"can_connect_smtp"`
		HasFullInbox   bool `json:"has_full_inbox"`
		IsCatchAll     bool `json:"is_catch_all"`
		IsDeliverable  bool `json:"is_deliverable"`
		IsDisabled     bool `json:"is_disabled"`
	} `json:"smtp"`
	Syntax struct {
		IsValidSyntax bool `json:"is_valid_syntax"`
	} `json:"syntax"`
}

// ReacherClient communicates with a self-hosted Reacher instance (AGPL-3.0)
type ReacherClient struct {
	BaseURL  string
	ProxyURL string
	Timeout  time.Duration
	client   *http.Client
}

// NewReacherClient creates an initialized ReacherClient
func NewReacherClient(baseURL, proxyURL string, timeout time.Duration) *ReacherClient {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &ReacherClient{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		ProxyURL: proxyURL,
		Timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
	}
}

// parseProxyConfig parses SOCKS5/HTTP proxy string into Reacher's proxy struct
func parseProxyConfig(proxyStr string) *ReacherProxyConfig {
	if proxyStr == "" {
		return nil
	}
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil
	}
	portInt := 1080
	host := u.Hostname()
	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			portInt = p
		}
	}
	cfg := &ReacherProxyConfig{
		Host: host,
		Port: portInt,
	}
	if u.User != nil {
		cfg.Username = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			cfg.Password = pass
		}
	}
	return cfg
}

// CheckEmail sends a candidate email to the Reacher instance and maps the outcome to standard models
func (r *ReacherClient) CheckEmail(ctx context.Context, email string) (models.VerificationStatus, *int, string, error) {
	endpoint := r.BaseURL + "/v0/check_email"

	payloadObj := reacherRequest{
		ToEmail: email,
		Proxy:   parseProxyConfig(r.ProxyURL),
	}

	bodyBytes, err := json.Marshal(payloadObj)
	if err != nil {
		return models.StatusUnverified, nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return models.StatusUnverified, nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "POC-Recon/2.0")

	resp, err := r.client.Do(req)
	if err != nil {
		return models.StatusTimeout, nil, fmt.Sprintf("Reacher connection error: %v", err), err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return models.StatusUnverified, &resp.StatusCode, fmt.Sprintf("Reacher returned HTTP %d: %s", resp.StatusCode, string(respBody)), fmt.Errorf("reacher HTTP error %d", resp.StatusCode)
	}

	var rResp reacherResponse
	if err := json.NewDecoder(resp.Body).Decode(&rResp); err != nil {
		return models.StatusUnverified, nil, "Failed to parse Reacher response JSON", err
	}

	code250 := 250
	code550 := 550

	if rResp.SMTP.IsCatchAll {
		return models.StatusCatchAll, &code250, "Verified via Reacher: Domain is Catch-All", nil
	}

	if rResp.IsReachable == "safe" || rResp.SMTP.IsDeliverable {
		return models.StatusValid, &code250, "Confirmed deliverable via self-hosted Reacher (250 OK)", nil
	}

	if rResp.IsReachable == "invalid" || rResp.SMTP.IsDisabled {
		return models.StatusInvalid, &code550, "Mailbox does not exist (Reacher: invalid)", nil
	}

	if rResp.SMTP.HasFullInbox {
		return models.StatusRateLimited, nil, "Recipient mailbox is full (Reacher)", nil
	}

	return models.StatusUnverified, nil, fmt.Sprintf("Reacher inconclusive result (status: %s)", rResp.IsReachable), nil
}
