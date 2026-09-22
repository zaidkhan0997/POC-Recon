package cloud

import (
	"context"
	"testing"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestMultiSignalCheckDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// A non-existent email on a dummy domain shouldn't panic and should return honest fallback
	res := MultiSignalCheck(ctx, "fake-user-not-real-xyz123@example.invalid", 1*time.Second)
	if res.Status == models.StatusValid {
		t.Errorf("expected dummy address not to be valid, got StatusValid")
	}
	if res.Confidence > 65 {
		t.Errorf("unverified address should not exceed 65%% confidence, got %d", res.Confidence)
	}
}
