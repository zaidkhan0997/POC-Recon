package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestReacherClientCheckSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/check_email" {
			http.NotFound(w, r)
			return
		}
		var req reacherRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := reacherResponse{
			Input:       req.ToEmail,
			IsReachable: "safe",
		}
		resp.SMTP.CanConnectSMTP = true
		resp.SMTP.IsDeliverable = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewReacherClient(server.URL, "", 2*time.Second)
	status, _, reason, err := client.CheckEmail(context.Background(), "test@company.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != models.StatusValid {
		t.Errorf("expected StatusValid, got %v (%s)", status, reason)
	}
}

func TestReacherClientCheckInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req reacherRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := reacherResponse{
			Input:       req.ToEmail,
			IsReachable: "invalid",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewReacherClient(server.URL, "", 2*time.Second)
	status, _, _, err := client.CheckEmail(context.Background(), "bad@company.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != models.StatusInvalid {
		t.Errorf("expected StatusInvalid, got %v", status)
	}
}

func TestReacherClientCheckCatchAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req reacherRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := reacherResponse{
			Input:       req.ToEmail,
			IsReachable: "unknown",
		}
		resp.SMTP.IsCatchAll = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewReacherClient(server.URL, "", 2*time.Second)
	status, code, _, err := client.CheckEmail(context.Background(), "canary@catchall.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != models.StatusCatchAll {
		t.Errorf("expected StatusCatchAll, got %v", status)
	}
	if code == nil || *code != 250 {
		t.Errorf("expected code 250 for catch-all probe, got %v", code)
	}
}

