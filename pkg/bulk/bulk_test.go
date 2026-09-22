package bulk

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/zaidkhan0997/POC-Recon/pkg/cache"
)

func TestParseCSVVariedHeaders(t *testing.T) {
	csvData := `Full Name,Company Domain,Person LinkedIn,Company LinkedIn
Jane Doe,example.com,https://linkedin.com/in/jane-doe,https://linkedin.com/company/example
John Smith,acme.org,,
`
	targets, err := ParseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if targets[0].FullName != "Jane Doe" || targets[0].Domain != "example.com" {
		t.Errorf("target 0 mismatch: %+v", targets[0])
	}
	if targets[1].FullName != "John Smith" || targets[1].Domain != "acme.org" {
		t.Errorf("target 1 mismatch: %+v", targets[1])
	}
}

func TestParseCSVFirstLastColumns(t *testing.T) {
	csvData := `first_name,last_name,website
Alice,Wonderland,https://wonder.io/team
Bob,Builder,builder.co
`
	targets, err := ParseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if targets[0].FullName != "Alice Wonderland" || targets[0].Domain != "wonder.io" {
		t.Errorf("target 0 mismatch: %+v", targets[0])
	}
	if targets[1].FullName != "Bob Builder" || targets[1].Domain != "builder.co" {
		t.Errorf("target 1 mismatch: %+v", targets[1])
	}
}

func TestParseCSVWithPattern(t *testing.T) {
	csvData := `First Name,Last Name,Company Domain,Pattern
Mohd,Zaid,oneirohire.com,first
Satya,Nadella,microsoft.com,first.last
`
	targets, err := ParseCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if targets[0].Pattern != "first" || targets[0].Domain != "oneirohire.com" {
		t.Errorf("expected target 0 pattern 'first', got: %+v", targets[0])
	}
	if targets[1].Pattern != "first.last" {
		t.Errorf("expected target 1 pattern 'first.last', got: %+v", targets[1])
	}
}

func TestProcessBatchOffline(t *testing.T) {
	targets := []LeadTarget{
		{FullName: "Jane Doe", Domain: "example.com"},
		{FullName: "John Smith", Domain: "example.com"},
	}

	c := cache.NewCache(t.TempDir() + "/test_cache.json")
	c.SetDomainPattern("example.com", "first.last", "Google Workspace", false)

	progressCount := 0
	results, err := ProcessBatch(context.Background(), targets, 2, "", true, c, func(p BatchProgress) {
		progressCount++
	})

	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if progressCount < 2 {
		t.Errorf("expected at least 2 progress callbacks, got %d", progressCount)
	}

	for _, r := range results {
		if r == nil || r.BestCandidate == nil {
			t.Fatalf("expected valid result and best candidate")
		}
		if !strings.Contains(r.BestCandidate.Email, "@example.com") {
			t.Errorf("unexpected candidate email: %s", r.BestCandidate.Email)
		}
	}

	var buf bytes.Buffer
	err = ExportBatchToCSV(results, &buf)
	if err != nil {
		t.Fatalf("ExportBatchToCSV failed: %v", err)
	}

	csvStr := buf.String()
	if !strings.Contains(csvStr, "Full Name,First Name,Last Name") {
		t.Errorf("expected CSV header in output: %s", csvStr)
	}
	if !strings.Contains(csvStr, "jane.doe@example.com") {
		t.Errorf("expected jane.doe@example.com in CSV output: %s", csvStr)
	}
}
