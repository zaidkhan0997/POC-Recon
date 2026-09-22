package parser

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasErr   bool
	}{
		{"https://stripe.com/", "stripe.com", false},
		{"http://www.google.com/search?q=test", "google.com", false},
		{"sub.domain.co.uk", "sub.domain.co.uk", false},
		{"", "", true},
		{"   ", "", true},
		{"not-a-domain", "", true},
	}

	for _, tc := range tests {
		got, err := NormalizeDomain(tc.input)
		if (err != nil) != tc.hasErr {
			t.Errorf("NormalizeDomain(%q) unexpected err: %v", tc.input, err)
		}
		if got != tc.expected {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestParsePersonName(t *testing.T) {
	tests := []struct {
		input     string
		first     string
		last      string
		rawTokens string
	}{
		{"Alex Morgan", "Alex", "Morgan", "Alex Morgan"},
		{"Dr. Jane M. Doe PhD", "Jane", "Doe", "Dr. Jane M. Doe PhD"},
		{"Satya Nadella", "Satya", "Nadella", "Satya Nadella"},
		{"Alice", "Alice", "", "Alice"},
		{"John Paul Jones", "John", "Jones", "John Paul Jones"},
	}

	for _, tc := range tests {
		got := ParsePersonName(tc.input)
		if got.FirstName != tc.first {
			t.Errorf("ParsePersonName(%q).FirstName = %q, want %q", tc.input, got.FirstName, tc.first)
		}
		if got.LastName != tc.last {
			t.Errorf("ParsePersonName(%q).LastName = %q, want %q", tc.input, got.LastName, tc.last)
		}
	}
}

func TestExtractNameFromLinkedInSlug(t *testing.T) {
	tests := []struct {
		input string
		first string
		last  string
	}{
		{"https://www.linkedin.com/in/alex-morgan-123456", "Alex", "Morgan"},
		{"jane-doe", "Jane", "Doe"},
		{"https://linkedin.com/in/satyanadella", "Satyanadella", ""},
	}

	for _, tc := range tests {
		got := ExtractNameFromLinkedInSlug(tc.input)
		if got == nil {
			t.Fatalf("ExtractNameFromLinkedInSlug(%q) returned nil", tc.input)
		}
		if got.FirstName != tc.first {
			t.Errorf("ExtractNameFromLinkedInSlug(%q).FirstName = %q, want %q", tc.input, got.FirstName, tc.first)
		}
		if got.LastName != tc.last {
			t.Errorf("ExtractNameFromLinkedInSlug(%q).LastName = %q, want %q", tc.input, got.LastName, tc.last)
		}
	}
}
