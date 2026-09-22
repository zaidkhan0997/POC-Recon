package generator

import (
	"testing"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestGenerateEmailPatterns(t *testing.T) {
	person := models.NameParts{
		FirstName: "Zaid",
		LastName:  "Khan",
		FullName:  "Zaid Khan",
	}

	cands := GenerateEmailPatterns("company.com", person, "")
	if len(cands) == 0 {
		t.Fatalf("expected candidates, got 0")
	}

	foundFirst := false
	foundFirstLast := false
	for _, c := range cands {
		if c.Email == "zaid@company.com" && c.PatternName == "first" {
			foundFirst = true
		}
		if c.Email == "zaid.khan@company.com" && c.PatternName == "first.last" {
			foundFirstLast = true
		}
	}

	if !foundFirst {
		t.Errorf("expected zaid@company.com in candidates")
	}
	if !foundFirstLast {
		t.Errorf("expected zaid.khan@company.com in candidates")
	}
}

func TestPreferredPatternElevation(t *testing.T) {
	person := models.NameParts{
		FirstName: "Zaid",
		LastName:  "Khan",
		FullName:  "Zaid Khan",
	}

	// Elevate "first" pattern
	cands := GenerateEmailPatterns("company.com", person, "first")
	if len(cands) == 0 {
		t.Fatalf("expected candidates")
	}

	if cands[0].PatternName != "first" {
		t.Errorf("expected first candidate to be 'first' pattern, got %s", cands[0].PatternName)
	}
	if cands[0].Email != "zaid@company.com" {
		t.Errorf("expected first candidate to be zaid@company.com, got %s", cands[0].Email)
	}
}

func TestNewHyphenAndReversedPatterns(t *testing.T) {
	person := models.NameParts{
		FirstName:  "Mohd",
		MiddleName: "Zaid",
		LastName:   "Khan",
		FullName:   "Mohd Zaid Khan",
	}

	cands := GenerateEmailPatterns("oneirohire.com", person, "")
	expectedMap := map[string]string{
		"first-last":   "mohd-khan@oneirohire.com",
		"lastfirst":    "khanmohd@oneirohire.com",
		"last_first":   "khan_mohd@oneirohire.com",
		"last-first":   "khan-mohd@oneirohire.com",
		"first-m-last": "mohd-z-khan@oneirohire.com",
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
