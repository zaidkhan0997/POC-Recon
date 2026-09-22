package generator

import (
	"testing"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestGenerateEmailPatterns(t *testing.T) {
	person := models.NameParts{
		FirstName: "John",
		LastName:  "Doe",
		FullName:  "John Doe",
	}

	cands := GenerateEmailPatterns("example.com", person, "")
	if len(cands) == 0 {
		t.Fatalf("expected candidates, got 0")
	}

	foundFirst := false
	foundFirstLast := false
	for _, c := range cands {
		if c.Email == "john@example.com" && c.PatternName == "first" {
			foundFirst = true
		}
		if c.Email == "john.doe@example.com" && c.PatternName == "first.last" {
			foundFirstLast = true
		}
	}

	if !foundFirst {
		t.Errorf("expected john@example.com in candidates")
	}
	if !foundFirstLast {
		t.Errorf("expected john.doe@example.com in candidates")
	}
}

func TestPreferredPatternElevation(t *testing.T) {
	person := models.NameParts{
		FirstName: "John",
		LastName:  "Doe",
		FullName:  "John Doe",
	}

	// Elevate "first" pattern
	cands := GenerateEmailPatterns("example.com", person, "first")
	if len(cands) == 0 {
		t.Fatalf("expected candidates")
	}

	if cands[0].PatternName != "first" {
		t.Errorf("expected first candidate to be 'first' pattern, got %s", cands[0].PatternName)
	}
	if cands[0].Email != "john@example.com" {
		t.Errorf("expected first candidate to be john@example.com, got %s", cands[0].Email)
	}
}

func TestNewHyphenAndReversedPatterns(t *testing.T) {
	person := models.NameParts{
		FirstName:  "Alex",
		MiddleName: "James",
		LastName:   "Taylor",
		FullName:   "Alex James Taylor",
	}

	cands := GenerateEmailPatterns("example.com", person, "")
	expectedMap := map[string]string{
		"first-last":   "alex-taylor@example.com",
		"lastfirst":    "tayloralex@example.com",
		"last_first":   "taylor_alex@example.com",
		"last-first":   "taylor-alex@example.com",
		"first-m-last": "alex-j-taylor@example.com",
	}

	foundMap := make(map[string]bool)
	for _, c := range cands {
		if exp, exists := expectedMap[c.PatternName]; exists {
			if c.Email == exp {
				foundMap[c.PatternName] = true
			} else {
				t.Errorf("pattern %s generated %s, expected %s", c.PatternName, c.Email, exp)
			}
		}
	}

	for pat := range expectedMap {
		if !foundMap[pat] {
			t.Errorf("expected pattern %s was not found or incorrect", pat)
		}
	}
}
