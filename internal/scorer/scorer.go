package scorer

import (
	"strings"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

var defaultWeights = map[string]int{
	"first.last":        70,
	"flast":             68,
	"first":             65,
	"firstlast":         60,
	"f.last":            58,
	"first_last":        55,
	"first-last":        55,
	"last.first":        50,
	"last":              40,
	"lfirst":            35,
	"first.l":           35,
	"f_last":            30,
	"lastfirst":         30,
	"last_first":        28,
	"last-first":        28,
	"first.m.last":      25,
	"firstmlast":        20,
	"fmlast":            20,
	"first.middle.last": 15,
	"first-m-last":      15,
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

	prefPat := strings.ToLower(strings.TrimSpace(preferredPattern))
	detPat := strings.ToLower(strings.TrimSpace(detectedPattern))
	activePattern := prefPat
	if activePattern == "" {
		activePattern = detPat
	}

	patLower := strings.ToLower(strings.TrimSpace(pattern))

	// For unverified or port-blocked candidates: honest realistic ratings
	if status != models.StatusValid {
		score := 30
		if activePattern != "" {
			if patLower == activePattern {
				if detPat != "" {
					score = 70 // OSINT evidence confirms corporate convention
				} else {
					score = 65 // User-specified pattern preference
				}
			} else {
				score = 40
			}
		} else {
			// No pattern confirmed: balanced heuristic range (28% - 50%)
			unverifiedWeights := map[string]int{
				"first.last":        50,
				"flast":             48,
				"first":             48,
				"firstlast":         45,
				"f.last":            44,
				"first_last":        42,
				"first-last":        42,
				"last":              40,
				"last.first":        38,
				"first.l":           35,
				"lfirst":            34,
				"f_last":            32,
				"lastfirst":         30,
				"last_first":        28,
				"last-first":        28,
				"first.m.last":      25,
				"first-m-last":      20,
			}
			if w, ok := unverifiedWeights[patLower]; ok {
				score = w
			}
		}

		if isCatchAll {
			score = int(float64(score) * 0.75)
		}
		if score > 70 {
			score = 70
		}
		if score < 5 {
			score = 5
		}
		return score
	}

	// For verified candidates (StatusValid)
	return 100
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
