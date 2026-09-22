package models

import (
	"testing"
)

func TestGetPrimaryCandidate(t *testing.T) {
	result := ReconResult{
		TargetDomain: "test.com",
		Candidates: []CandidateResult{
			{Email: "zaid.khan@test.com", PatternName: "first.last", Status: StatusUnverified, Confidence: 85},
			{Email: "zaid@test.com", PatternName: "first", Status: StatusUnverified, Confidence: 95},
		},
	}

	best := result.GetPrimaryCandidate()
	if best == nil {
		t.Fatalf("expected primary candidate, got nil")
	}
	if best.Email != "zaid@test.com" {
		t.Errorf("expected zaid@test.com (highest conf 95%%), got %s", best.Email)
	}

	// Now add a valid candidate
	result.Candidates[0].Status = StatusValid
	best = result.GetPrimaryCandidate()
	if best.Email != "zaid.khan@test.com" {
		t.Errorf("expected StatusValid candidate to take priority, got %s", best.Email)
	}
}
