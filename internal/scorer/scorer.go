package scorer

import (
	"strings"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

var defaultWeights = map[string]int{
	"first.last":        85,
	"first":             60,
	"flast":             50,
	"firstlast":         45,
	"first_last":        40,
	"last.first":        35,
	"f.last":            30,
	"last":              25,
	"lfirst":            20,
	"first.l":           20,
	"f_last":            15,
	"first.m.last":      25,
	"firstmlast":        20,
	"fmlast":            20,
	"first.middle.last": 15,
}

func ComputeConfidence(
	status models.VerificationStatus,
	pattern string,
	provider *models.ProviderInfo,
	isCatchAll bool,
	port25Open bool,
	preferredPattern string,
	detectedPattern string,
) int {
	if status == models.StatusValid {
		return 100
	}
	if status == models.StatusInvalid || status == models.StatusNoMX {
		return 0
	}

	activePattern := strings.ToLower(strings.TrimSpace(preferredPattern))
	if activePattern == "" {
		activePattern = strings.ToLower(strings.TrimSpace(detectedPattern))
	}

	patLower := strings.ToLower(strings.TrimSpace(pattern))
	baseWeight, ok := defaultWeights[patLower]
	if !ok {
		baseWeight = 15
	}

	score := baseWeight
	if activePattern != "" {
		if patLower == activePattern {
			score = 90
		} else {
			if score > 60 {
				score = 60
			}
		}
	}

	// Provider heuristics
	if provider != nil {
		targetPat := activePattern
		if targetPat == "" {
			targetPat = "first.last"
		}

		pName := strings.ToLower(provider.Name)
		if strings.Contains(pName, "google") || strings.Contains(pName, "workspace") || strings.Contains(pName, "microsoft") || strings.Contains(pName, "exchange") || strings.Contains(pName, "office") {
			if patLower == targetPat {
				score += 5
			}
		}
		if strings.Contains(provider.SPFRecord, "-all") {
			if patLower == targetPat || activePattern == "" {
				score += 5
			}
		}
	}

	if isCatchAll {
		score = int(float64(score) * 0.75)
	}

	if score > 95 {
		score = 95
	}
	if score < 5 {
		score = 5
	}
	return score
}

func ScoreCandidates(
	candidates []models.CandidateResult,
	provider *models.ProviderInfo,
	isCatchAll bool,
	port25Open bool,
	activePattern string,
	directMatch string,
) {
	for i := range candidates {
		if directMatch != "" && strings.EqualFold(candidates[i].Email, directMatch) {
			candidates[i].Status = models.StatusValid
			candidates[i].Confidence = 100
			continue
		}
		candidates[i].Confidence = ComputeConfidence(
			candidates[i].Status,
			candidates[i].PatternName,
			provider,
			isCatchAll,
			port25Open,
			activePattern,
			"",
		)
	}
}
