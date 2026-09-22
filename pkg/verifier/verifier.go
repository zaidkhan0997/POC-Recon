package verifier

import (
	"context"
	"time"

	"github.com/zaidkhan0997/POC-Recon/internal/cloud"
	"github.com/zaidkhan0997/POC-Recon/internal/dns"
	"github.com/zaidkhan0997/POC-Recon/internal/smtp"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func LookupMX(domain string) ([]models.MXRecord, error) {
	return dns.LookupMX(domain)
}

func LookupMXWithDoH(domain string, timeout time.Duration) ([]models.MXRecord, error) {
	return dns.LookupMXWithDoH(domain, timeout)
}

func FingerprintProvider(domain string, mxList []models.MXRecord) *models.ProviderInfo {
	return dns.FingerprintProvider(domain, mxList)
}

func CheckPort25(host string, timeout time.Duration, proxyURL string) bool {
	return smtp.CheckPort25(host, timeout, proxyURL)
}

func CheckCatchAll(ctx context.Context, host string, domain string, timeout time.Duration, proxyURL string) bool {
	return smtp.CheckCatchAll(ctx, host, domain, timeout, proxyURL)
}

func VerifyEmail(ctx context.Context, host string, domain string, email string, timeout time.Duration, proxyURL string) (models.VerificationStatus, *int, string) {
	return smtp.VerifyEmail(ctx, host, domain, email, timeout, proxyURL)
}

func VerifyM365(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyM365(email, timeout)
}

func VerifyGravatar(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyGravatar(email, timeout)
}

func VerifyPGP(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyPGP(email, timeout)
}

func VerifyPGPKeyring(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyPGPKeyring(email, timeout)
}

func VerifyGitHub(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyGitHub(email, timeout)
}

func VerifyGoogleWorkspace(email string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyGoogleWorkspace(email, timeout)
}

func VerifyCloudRelay(email string, relayURL string, token string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	return cloud.VerifyCloudRelay(email, relayURL, token, timeout)
}

// VerifyAfterShip performs pure-Go industrial SMTP verification via AfterShip/email-verifier
func VerifyAfterShip(ctx context.Context, email string, proxyURL string, timeout time.Duration) (models.VerificationStatus, *int, string) {
	v := smtp.NewAfterShipVerifier(proxyURL, timeout)
	return v.VerifyEmail(ctx, email)
}

// VerifyReacher sends verification request to self-hosted Reacher container (Docker HTTP API)
func VerifyReacher(ctx context.Context, email, reacherURL, proxyURL string, timeout time.Duration) (models.VerificationStatus, *int, string, error) {
	client := cloud.NewReacherClient(reacherURL, proxyURL, timeout)
	return client.CheckEmail(ctx, email)
}

// MultiSignalCheck performs multi-signal identity verification (Microsoft 365, Gravatar, OpenPGP) without Port 25
func MultiSignalCheck(ctx context.Context, email string, timeout time.Duration) (models.VerificationStatus, int, string) {
	res := cloud.MultiSignalCheck(ctx, email, timeout)
	return res.Status, res.Confidence, res.ConfirmedMethod
}
