package smtp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func DialConnection(host string, port int, timeout time.Duration, proxyURL string) (net.Conn, error) {
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
	conn, err := DialConnection(host, 25, timeout, proxyURL)
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
	conn, err := DialConnection(mxHost, 25, timeout, proxyURL)
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

	// Check cancellation before sending RCPT TO
	select {
	case <-ctx.Done():
		sendCommand(writer, reader, "QUIT")
		return models.StatusUnverified, nil, "Context cancelled"
	default:
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

type Verifier struct {
	ProxyURL string
	Timeout  time.Duration
	Delay    time.Duration
}

func NewVerifier(proxyURL string, timeout, delay time.Duration) *Verifier {
	return &Verifier{
		ProxyURL: proxyURL,
		Timeout:  timeout,
		Delay:    delay,
	}
}

func (v *Verifier) CheckPort25(host string) bool {
	return CheckPort25(host, v.Timeout, v.ProxyURL)
}

func (v *Verifier) CheckCatchAll(domain, host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), v.Timeout*2)
	defer cancel()
	return CheckCatchAll(ctx, host, domain, v.Timeout, v.ProxyURL)
}

func (v *Verifier) VerifyEmail(ctx context.Context, email, host string, isCatchAll bool) (models.VerificationStatus, *int, string) {
	parts := strings.Split(email, "@")
	dom := ""
	if len(parts) == 2 {
		dom = parts[1]
	}
	if v.Delay > 0 {
		select {
		case <-ctx.Done():
			return models.StatusSkipped, nil, "Context cancelled"
		case <-time.After(v.Delay):
		}
	}
	status, code, msg := VerifyEmail(ctx, host, dom, email, v.Timeout, v.ProxyURL)
	if isCatchAll && status == models.StatusValid {
		status = models.StatusCatchAll
		msg = "Catch-all domain accepted test address"
	}
	return status, code, msg
}
