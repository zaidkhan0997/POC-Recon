package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestCacheDomainAndLeads(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "test_cache.json")

	c := NewCache(cachePath)

	// Test 1: Domain Pattern caching
	c.SetDomainPattern("example.com", "first.last", "Google Workspace", false)

	info, found := c.GetDomainPattern("EXAMPLE.COM")
	if !found {
		t.Fatalf("expected domain pattern to be found")
	}
	if info.Pattern != "first.last" {
		t.Errorf("expected first.last, got %s", info.Pattern)
	}
	if info.Provider != "Google Workspace" {
		t.Errorf("expected Google Workspace, got %s", info.Provider)
	}

	// Test 2: Save Lead
	lead := SavedLead{
		FullName:    "Jane Doe",
		FirstName:   "Jane",
		LastName:    "Doe",
		Domain:      "example.com",
		Email:       "jane.doe@example.com",
		PatternName: "first.last",
		Confidence:  100,
		Status:      "VALID",
		Provider:    "Google Workspace",
		VerifiedAt:  time.Now(),
	}
	c.SaveLead(lead)

	leads := c.GetLeads()
	if len(leads) != 1 {
		t.Fatalf("expected 1 lead, got %d", len(leads))
	}
	if leads[0].Email != "jane.doe@example.com" {
		t.Errorf("expected email jane.doe@example.com, got %s", leads[0].Email)
	}

	// Test 3: Reload from disk
	c2 := NewCache(cachePath)
	info2, found2 := c2.GetDomainPattern("example.com")
	if !found2 || info2.Pattern != "first.last" {
		t.Errorf("failed to reload domain pattern from disk")
	}
	leads2 := c2.GetLeads()
	if len(leads2) != 1 {
		t.Errorf("failed to reload leads from disk")
	}

	// Test 4: Convert ReconResult to SavedLead
	reconRes := &models.ReconResult{
		TargetDomain: "example.com",
		Person: models.NameParts{
			FullName:  "John Smith",
			FirstName: "John",
			LastName:  "Smith",
		},
		Provider: &models.ProviderInfo{
			Name: "Microsoft 365",
		},
		BestCandidate: &models.CandidateResult{
			Email:       "john.smith@example.com",
			PatternName: "first.last",
			Confidence:  95,
			Status:      models.StatusValid,
		},
	}
	saved := ConvertReconResultToSavedLead(reconRes)
	if saved == nil || saved.Email != "john.smith@example.com" || saved.Provider != "Microsoft 365" {
		t.Errorf("ConvertReconResultToSavedLead returned invalid lead: %+v", saved)
	}

	// Test 5: Clear Leads
	c2.ClearLeads()
	if len(c2.GetLeads()) != 0 {
		t.Errorf("expected 0 leads after ClearLeads")
	}

	_ = os.Remove(cachePath)
}
