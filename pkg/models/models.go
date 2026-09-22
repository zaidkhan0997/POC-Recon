package models

import (
	"encoding/json"
	"time"
)

type VerificationStatus string

const (
	StatusValid             VerificationStatus = "VALID"
	StatusInvalid           VerificationStatus = "INVALID"
	StatusCatchAll          VerificationStatus = "CATCH_ALL_UNVERIFIED"
	StatusPortBlocked       VerificationStatus = "UNVERIFIED_PORT_BLOCKED"
	StatusTimeout           VerificationStatus = "UNVERIFIED_TIMEOUT"
	StatusSkipped           VerificationStatus = "SKIPPED"
	StatusNoMX              VerificationStatus = "NO_MX_RECORD"
	StatusRateLimited       VerificationStatus = "RATE_LIMITED"
	StatusUnverified        VerificationStatus = "UNVERIFIED"
)

type NameParts struct {
	FirstName  string `json:"first_name"`
	MiddleName string `json:"middle_name,omitempty"`
	LastName   string `json:"last_name,omitempty"`
	RawName    string `json:"raw_name"`
	FullName   string `json:"full_name"`
}

type CandidateResult struct {
	Email       string             `json:"email"`
	PatternName string             `json:"pattern_name"`
	Status      VerificationStatus `json:"status"`
	Confidence  int                `json:"confidence"`
	SMTPCode    *int               `json:"smtp_code,omitempty"`
	SMTPMessage string             `json:"smtp_message,omitempty"`
}

type EmailCandidate = CandidateResult

type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

type ProviderInfo struct {
	Name      string `json:"name"`
	SPFRecord string `json:"spf_record,omitempty"`
	Details   string `json:"details,omitempty"`
}

type ReconResult struct {
	TargetDomain           string            `json:"target_domain"`
	Person                 NameParts         `json:"person"`
	MXRecords              []MXRecord        `json:"mx_records"`
	Provider               *ProviderInfo     `json:"provider,omitempty"`
	Port25Open             bool              `json:"port_25_open"`
	IsCatchAll             bool              `json:"is_catch_all"`
	DetectedPattern        string            `json:"detected_pattern,omitempty"`
	DetectedPatternSource  string            `json:"detected_pattern_source,omitempty"`
	DiscoveredDomainEmails []string          `json:"discovered_domain_emails,omitempty"`
	VerificationMethod     string            `json:"verification_method"`
	Candidates             []CandidateResult `json:"candidates"`
	BestCandidate          *CandidateResult  `json:"best_candidate,omitempty"`
	Timestamp              time.Time         `json:"timestamp"`
}

func (r *ReconResult) GetValidEmails() []string {
	var valid []string
	for _, c := range r.Candidates {
		if c.Status == StatusValid {
			valid = append(valid, c.Email)
		}
	}
	return valid
}

func (r *ReconResult) GetPrimaryCandidate() *CandidateResult {
	if r.BestCandidate != nil {
		return r.BestCandidate
	}
	// 1. Return first candidate confirmed VALID (100%)
	for i := range r.Candidates {
		if r.Candidates[i].Status == StatusValid {
			return &r.Candidates[i]
		}
	}
	// 2. Return candidate matching detected/preferred pattern if present
	if r.DetectedPattern != "" {
		for i := range r.Candidates {
			if r.Candidates[i].PatternName == r.DetectedPattern && r.Candidates[i].Confidence > 0 {
				return &r.Candidates[i]
			}
		}
	}
	// 3. Fallback to highest confidence candidate
	if len(r.Candidates) > 0 {
		best := &r.Candidates[0]
		for i := range r.Candidates {
			if r.Candidates[i].Confidence > best.Confidence {
				best = &r.Candidates[i]
			}
		}
		return best
	}
	return nil
}

func (r *ReconResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
