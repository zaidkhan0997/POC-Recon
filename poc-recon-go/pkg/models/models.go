package models

import "time"

type VerificationStatus string

const (
	StatusValid        VerificationStatus = "VALID"
	StatusInvalid      VerificationStatus = "INVALID"
	StatusCatchAll     VerificationStatus = "CATCH-ALL / UNVERIFIED"
	StatusNoMX         VerificationStatus = "NO MX RECORD"
	StatusPortBlocked  VerificationStatus = "PORT BLOCKED"
	StatusTimeout      VerificationStatus = "TIMEOUT"
	StatusRateLimited  VerificationStatus = "RATE LIMITED"
	StatusUnverified   VerificationStatus = "UNVERIFIED"
)

type NameParts struct {
	FirstName  string `json:"first_name"`
	MiddleName string `json:"middle_name,omitempty"`
	LastName   string `json:"last_name,omitempty"`
	FullName   string `json:"full_name"`
}

type EmailCandidate struct {
	Email       string             `json:"email"`
	PatternName string             `json:"pattern_name"`
	Status      VerificationStatus `json:"status"`
	SMTPCode    *int               `json:"smtp_code,omitempty"`
	SMTPMessage string             `json:"smtp_message,omitempty"`
}

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
	TargetDomain       string           `json:"target_domain"`
	Person             NameParts        `json:"person"`
	MXRecords          []MXRecord       `json:"mx_records"`
	Provider           *ProviderInfo    `json:"provider,omitempty"`
	Port25Open         bool             `json:"port_25_open"`
	IsCatchAll         bool             `json:"is_catch_all"`
	VerificationMethod string           `json:"verification_method"`
	Candidates         []EmailCandidate `json:"candidates"`
	Timestamp          time.Time        `json:"timestamp"`
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
