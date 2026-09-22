package scorer

import (
	"github.com/zaidkhan0997/POC-Recon/internal/scorer"
	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

// ComputeConfidence calculates an honest confidence score based on verification status, naming pattern, provider, and network reachability
func ComputeConfidence(
	status models.VerificationStatus,
	pattern string,
	provider *models.ProviderInfo,
	isCatchAll bool,
	port25Open bool,
	preferredPattern string,
	detectedPattern string,
) int {
	return scorer.ComputeConfidence(status, pattern, provider, isCatchAll, port25Open, preferredPattern, detectedPattern)
}

// ScoreCandidates calculates and assigns confidence scores across a slice of email candidates
func ScoreCandidates(
	candidates []models.CandidateResult,
	provider *models.ProviderInfo,
	isCatchAll bool,
	port25Open bool,
	activePattern string,
	directMatch string,
) {
	scorer.ScoreCandidates(candidates, provider, isCatchAll, port25Open, activePattern, directMatch)
}
