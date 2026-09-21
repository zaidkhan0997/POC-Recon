package verifier

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

func LookupMX(domain string) ([]models.MXRecord, error) {
	mxList, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
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
		Details:   "Standard SMTP server",
	}

	if strings.Contains(combinedMX, "google.com") || strings.Contains(combinedMX, "googlemail.com") {
		provider.Name = "Google Workspace"
		provider.Details = "Strict mailbox validation; accurate RCPT TO signals."
	} else if strings.Contains(combinedMX, "outlook.com") || strings.Contains(combinedMX, "office365") {
		provider.Name = "Microsoft 365 / Exchange"
		provider.Details = "May require authentication or tarpit unauthenticated RCPT probes."
	} else if strings.Contains(combinedMX, "pphosted.com") {
		provider.Name = "Proofpoint Enterprise"
		provider.Details = "Aggressive anti-spam filtering and deferred verification."
	} else if strings.Contains(combinedMX, "mimecast.com") {
		provider.Name = "Mimecast Email Security"
		provider.Details = "Performs greylisting and recipient rate limiting."
	} else if strings.Contains(combinedMX, "zoho.com") {
		provider.Name = "Zoho Mail"
		provider.Details = "Standard RFC recipient rejection codes."
	} else if strings.Contains(combinedMX, "protonmail.ch") || strings.Contains(combinedMX, "proton.me") {
		provider.Name = "Proton Mail"
		provider.Details = "Zero-access privacy architecture."
	}

	return provider
}

func dialConnection(host string, port int, timeout time.Duration, proxyURL string) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		var auth *proxy.Auth
		if u.User != nil {
			auth = &proxy.Auth{
				User: u.User.Username(),
			}
			if pass, ok := u.User.Password(); ok {
				auth.Password = pass
			}
		}
		dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		return dialer.Dial("tcp", target)
	}

	return net.DialTimeout("tcp", target, timeout)
}

func CheckPort25(host string, timeout time.Duration, proxyURL string) bool {
	conn, err := dialConnection(host, 25, timeout, proxyURL)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func readResponse(reader *bufio.Reader) (int, string, error) {
	var fullMessage []string
	var finalCode int

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimSpace(line)
		if len(line) < 3 {
			continue
		}

		code, err := strconv.Atoi(line[:3])
		if err != nil {
			continue
		}
		finalCode = code
		msg := ""
		if len(line) > 4 {
			msg = line[4:]
		}
		fullMessage = append(fullMessage, msg)

		// RFC 5321: If 4th char is '-' it's a multiline response, if ' ' or end of line, it's final
		if len(line) == 3 || line[3] == ' ' {
			break
		}
	}

	return finalCode, strings.Join(fullMessage, "; "), nil
}

func sendCommand(writer *bufio.Writer, reader *bufio.Reader, cmd string) (int, string, error) {
	if _, err := writer.WriteString(cmd + "\r\n"); err != nil {
		return 0, "", err
	}
	if err := writer.Flush(); err != nil {
		return 0, "", err
	}
	return readResponse(reader)
}

func VerifyEmail(
	ctx context.Context,
	mxHost string,
	domain string,
	email string,
	timeout time.Duration,
	proxyURL string,
) (models.VerificationStatus, *int, string) {
	conn, err := dialConnection(mxHost, 25, timeout, proxyURL)
	if err != nil {
		return models.StatusPortBlocked, nil, fmt.Sprintf("Connection failed: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read initial 220 banner
	code, banner, err := readResponse(reader)
	if err != nil || code != 220 {
		return models.StatusUnverified, &code, fmt.Sprintf("Invalid banner: %s", banner)
	}

	// EHLO probe
	code, _, err = sendCommand(writer, reader, fmt.Sprintf("EHLO mail.%s", domain))
	if err != nil || (code != 250 && code != 200) {
		// Try HELO fallback
		code, _, err = sendCommand(writer, reader, fmt.Sprintf("HELO mail.%s", domain))
		if err != nil || code != 250 {
			return models.StatusUnverified, &code, "Handshake failed"
		}
	}

	// MAIL FROM
	code, _, err = sendCommand(writer, reader, fmt.Sprintf("MAIL FROM:<recon-probe@%s>", domain))
	if err != nil || code != 250 {
		return models.StatusUnverified, &code, "Sender rejected"
	}

	// RCPT TO
	code, msg, err := sendCommand(writer, reader, fmt.Sprintf("RCPT TO:<%s>", email))
	// Always politely QUIT
	sendCommand(writer, reader, "QUIT")

	if err != nil {
		return models.StatusTimeout, nil, fmt.Sprintf("Timeout or network drop: %v", err)
	}

	if code == 250 || code == 251 {
		return models.StatusValid, &code, msg
	} else if code == 550 || code == 551 || code == 553 || code == 554 {
		return models.StatusInvalid, &code, msg
	} else if code == 421 || code == 450 || code == 451 || code == 452 {
		return models.StatusRateLimited, &code, msg
	}

	return models.StatusUnverified, &code, msg
}

func CheckCatchAll(
	ctx context.Context,
	mxHost string,
	domain string,
	timeout time.Duration,
	proxyURL string,
) bool {
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	canary := fmt.Sprintf("canary-probe-%s@%s", hex.EncodeToString(randomBytes), domain)

	status, code, _ := VerifyEmail(ctx, mxHost, domain, canary, timeout, proxyURL)
	if status == models.StatusValid || (code != nil && (*code == 250 || *code == 251)) {
		return true
	}
	return false
}
