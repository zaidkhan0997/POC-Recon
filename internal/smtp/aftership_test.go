package smtp

import (
	"context"
	"testing"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestAfterShipVerifierInvalidSyntax(t *testing.T) {
	v := NewAfterShipVerifier("", 2*time.Second)
	ctx := context.Background()

	// Invalid syntax email
	status, _, reason := v.VerifyEmail(ctx, "invalid-email-no-domain")
	if status == models.StatusValid {
		t.Errorf("expected invalid email to not be StatusValid, got status: %v (%s)", status, reason)
	}
}
