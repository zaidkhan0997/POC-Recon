package smtp

import (
	"context"
	"fmt"
	"time"

	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// AfterShipVerifier wraps AfterShip/email-verifier for pure-Go industrial SMTP checking
type AfterShipVerifier struct {
	verifier *emailverifier.Verifier
	timeout  time.Duration
}

// NewAfterShipVerifier creates an initialized AfterShipVerifier instance
func NewAfterShipVerifier(proxyURL string, timeout time.Duration) *AfterShipVerifier {
	v := emailverifier.NewVerifier().
		EnableSMTPCheck().
		EnableCatchAllCheck().
		ConnectTimeout(timeout).
		OperationTimeout(timeout * 2).
		FromEmail("recon@corporate-audit.internal").
		HelloName("corporate-audit.internal")

	if proxyURL != "" {
		v.Proxy(proxyURL)
	}

	return &AfterShipVerifier{
		verifier: v,
		timeout:  timeout,
	}
}

// VerifyEmail probes an email address using AfterShip's SMTP engine and returns standard status
func (a *AfterShipVerifier) VerifyEmail(ctx context.Context, email string) (models.VerificationStatus, *int, string) {
	select {
	case <-ctx.Done():
		return models.StatusSkipped, nil, "Context cancelled"
	default:
	}

	res, err := a.verifier.Verify(email)
	if err != nil {
		return models.StatusTimeout, nil, fmt.Sprintf("AfterShip SMTP verification probe error: %v", err)
	}

	code250 := 250
	code550 := 550

	if res.SMTP != nil {
		if res.SMTP.CatchAll {
			return models.StatusCatchAll, &code250, "Server in Catch-All mode (accepts all recipients)"
		}
		if res.SMTP.Deliverable {
			return models.StatusValid, &code250, "Mailbox verified deliverable via AfterShip SMTP (250 OK)"
		}
		if res.SMTP.Disabled || (!res.SMTP.Deliverable && res.Reachable == "no") {
			return models.StatusInvalid, &code550, "Mailbox rejected by remote SMTP server (550 User unknown)"
		}
		if res.SMTP.FullInbox {
			return models.StatusRateLimited, nil, "Recipient mailbox is full"
		}
	}

	if res.Reachable == "yes" {
		return models.StatusValid, &code250, "Address verified reachable via AfterShip engine"
	}
	if res.Reachable == "no" {
		return models.StatusInvalid, &code550, "Address rejected via AfterShip engine"
	}

	return models.StatusUnverified, nil, "SMTP response inconclusive / unverified"
}
