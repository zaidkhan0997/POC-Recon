package parser

import "testing"

func TestNormalizeDomainValid(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://www.example.com/", "example.com"},
		{"http://example.com/about?ref=test", "example.com"},
		{"www.example.com#section", "example.com"},
		{"example.com/", "example.com"},
		{"sub.domain.corp.co.uk", "sub.domain.corp.co.uk"},
		{"https://EXAMPLE.COM/path", "example.com"},
		{"example.com:8080/test", "example.com"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got, err := NormalizeDomain(c.input)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", c.input, err)
			}
			if got != c.expected {
				t.Fatalf("NormalizeDomain(%q) = %q, want %q", c.input, got, c.expected)
			}
		})
	}
}

func TestNormalizeDomainInvalid(t *testing.T) {
	invalid := []string{"", "   ", "http://", "not_a_valid_domain", "example..com"}

	for _, bad := range invalid {
		t.Run(bad, func(t *testing.T) {
			if _, err := NormalizeDomain(bad); err == nil {
				t.Fatalf("NormalizeDomain(%q) expected an error, got nil", bad)
			}
		})
	}
}

func TestParsePersonNameSimple(t *testing.T) {
	parts := ParsePersonName("Jane Doe")
	if parts.FirstName != "Jane" {
		t.Errorf("FirstName = %q, want %q", parts.FirstName, "Jane")
	}
	if parts.MiddleName != "" {
		t.Errorf("MiddleName = %q, want empty", parts.MiddleName)
	}
	if parts.LastName != "Doe" {
		t.Errorf("LastName = %q, want %q", parts.LastName, "Doe")
	}
}

func TestParsePersonNameWithMiddle(t *testing.T) {
	parts := ParsePersonName("John C. Smith")
	if parts.FirstName != "John" {
		t.Errorf("FirstName = %q, want %q", parts.FirstName, "John")
	}
	if parts.MiddleName != "C" {
		t.Errorf("MiddleName = %q, want %q", parts.MiddleName, "C")
	}
	if parts.LastName != "Smith" {
		t.Errorf("LastName = %q, want %q", parts.LastName, "Smith")
	}
}

func TestParsePersonNameWithHonorifics(t *testing.T) {
	parts := ParsePersonName("Dr. Jane Doe")
	if parts.FirstName != "Jane" || parts.LastName != "Doe" {
		t.Errorf("got first=%q last=%q, want first=Jane last=Doe", parts.FirstName, parts.LastName)
	}

	parts2 := ParsePersonName("Prof. John Smith")
	if parts2.FirstName != "John" || parts2.LastName != "Smith" {
		t.Errorf("got first=%q last=%q, want first=John last=Smith", parts2.FirstName, parts2.LastName)
	}
}

func TestParsePersonNameWithCredentials(t *testing.T) {
	parts := ParsePersonName("Jane Doe, MBA")
	if parts.FirstName != "Jane" || parts.LastName != "Doe" {
		t.Errorf("got first=%q last=%q, want first=Jane last=Doe", parts.FirstName, parts.LastName)
	}
}

func TestParsePersonNameSingle(t *testing.T) {
	parts := ParsePersonName("Cher")
	if parts.FirstName != "Cher" {
		t.Errorf("FirstName = %q, want %q", parts.FirstName, "Cher")
	}
	if parts.LastName != "" {
		t.Errorf("LastName = %q, want empty", parts.LastName)
	}
}

func TestParsePersonNameEmpty(t *testing.T) {
	parts := ParsePersonName("")
	if parts.FirstName != "" || parts.LastName != "" || parts.FullName != "" {
		t.Errorf("expected zero-value NameParts for empty input, got %+v", parts)
	}
}

func TestExtractNameFromLinkedInSlug(t *testing.T) {
	name := ExtractNameFromLinkedInSlug("https://www.linkedin.com/in/jane-doe-12345678/")
	if name != "Jane Doe" {
		t.Errorf("got %q, want %q", name, "Jane Doe")
	}
}

func TestExtractNameFromLinkedInSlugWithMiddleName(t *testing.T) {
	name := ExtractNameFromLinkedInSlug("john-c-smith-987654")
	if name != "John C Smith" {
		t.Errorf("got %q, want %q", name, "John C Smith")
	}
}

func TestExtractNameFromLinkedInSlugEmpty(t *testing.T) {
	if name := ExtractNameFromLinkedInSlug(""); name != "" {
		t.Errorf("expected empty result for empty input, got %q", name)
	}
}
