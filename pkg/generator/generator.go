package generator

import (
	"github.com/zaidkhan0997/POC-Recon/internal/generator"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func GenerateEmailPatterns(domain string, person models.NameParts) []models.CandidateResult {
	return generator.GenerateEmailPatterns(domain, person, "")
}

func GenerateEmailPatternsWithPreferred(domain string, person models.NameParts, preferredPattern string) []models.CandidateResult {
	return generator.GenerateEmailPatterns(domain, person, preferredPattern)
}
