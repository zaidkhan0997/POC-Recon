package models

import (
	"testing"
)

func TestGetPrimaryCandidateValid(t *testing.T) {
	result := ReconResult{
		TargetDomain: "example.com",
		Candidates: []EmailCandidate{
			{
				Email:       "test@example.com",
				PatternName: "first",
				Status:      StatusUnverified,
				Confidence:  60,
			},
			{
				Email:       "valid@example.com",
				PatternName: "first.last",
				Status:      StatusValid,
				Confidence:  100,
			},
		},
	}

	best := result.GetPrimaryCandidate()
	if best == nil {
		t.Fatal("expected primary candidate, got nil")
	}
	if best.Email != "valid@example.com" {
		t.Fatalf("expected valid@example.com, got %s", best.Email)
	}
}

func TestGetPrimaryCandidateHighestConfidence(t *testing.T) {
	result := ReconResult{
		TargetDomain: "example.com",
		Candidates: []EmailCandidate{
			{
				Email:       "low@example.com",
				PatternName: "f_last",
				Status:      StatusUnverified,
				Confidence:  15,
			},
			{
				Email:       "high@example.com",
				PatternName: "first.last",
				Status:      StatusUnverified,
				Confidence:  95,
			},
		},
	}

	best := result.GetPrimaryCandidate()
	if best == nil {
		t.Fatal("expected primary candidate, got nil")
	}
	if best.Email != "high@example.com" {
		t.Fatalf("expected high@example.com, got %s", best.Email)
	}
}
