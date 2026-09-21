package generator

import (
	"testing"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

func TestGenerateEmailPatterns(t *testing.T) {
	person := models.NameParts{
		FirstName: "Jane",
		LastName:  "Doe",
		FullName:  "Jane Doe",
	}

	candidates := GenerateEmailPatterns("example.com", person)
	if len(candidates) == 0 {
		t.Fatal("expected candidate permutations, got 0")
	}

	foundFirstDotLast := false
	for _, c := range candidates {
		if c.Email == "jane.doe@example.com" && c.PatternName == "first.last" {
			foundFirstDotLast = true
			break
		}
	}

	if !foundFirstDotLast {
		t.Fatal("expected to find jane.doe@example.com in generated candidates")
	}
}
