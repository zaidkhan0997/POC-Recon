package osint

import (
	"time"

	"github.com/zaidkhan0997/POC-Recon/internal/osint"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// DetectDomainEmailPattern inspects domain DMARC, PGP keyservers, and security records
func DetectDomainEmailPattern(domain string, candidates []models.CandidateResult, timeout time.Duration) (string, string, []string, *models.CandidateResult) {
	return osint.DetectDomainEmailPattern(domain, candidates, timeout)
}

// DetectDomainPattern uses the internal OSINT engine to infer active naming patterns and direct matches
func DetectDomainPattern(domain string, person models.NameParts, timeout time.Duration) (string, string, []string, string) {
	engine := osint.NewEngine(timeout)
	return engine.DetectDomainPattern(domain, person)
}
