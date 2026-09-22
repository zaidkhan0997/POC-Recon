package scorer

import (
	"testing"

	"github.com/zaidkhan0997/POC-Recon/pkg/models"
)

func TestScorerValidStatus(t *testing.T) {
	conf := ComputeConfidence(models.StatusValid, "first", nil, false, true, "", "")
	if conf != 100 {
		t.Errorf("expected StatusValid to be 100%%, got %d", conf)
	}
}

func TestScorerDetectedPatternElevation(t *testing.T) {
	// When "first" is the detected pattern, "first" should score higher than default "first.last"
	firstConf := ComputeConfidence(models.StatusUnverified, "first", nil, false, false, "first", "")
	firstLastConf := ComputeConfidence(models.StatusUnverified, "first.last", nil, false, false, "first", "")

	if firstConf <= firstLastConf {
		t.Errorf("expected 'first' conf (%d) > 'first.last' conf (%d) when 'first' is active pattern", firstConf, firstLastConf)
	}
	if firstConf < 60 || firstConf > 75 {
		t.Errorf("expected 'first' conf to be in honest 60-75%% range when active pattern unverified, got %d", firstConf)
	}
}

func TestScorerCatchAllDiscount(t *testing.T) {
	standardConf := ComputeConfidence(models.StatusUnverified, "first.last", nil, false, false, "", "")
	catchAllConf := ComputeConfidence(models.StatusUnverified, "first.last", nil, true, false, "", "")

	if catchAllConf >= standardConf {
		t.Errorf("expected catchAllConf (%d) < standardConf (%d)", catchAllConf, standardConf)
	}
}
