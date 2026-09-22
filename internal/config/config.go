package config

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Website         string
	Name            string
	PersonLinkedIn  string
	CompanyLinkedIn string
	Pattern         string
	Proxy           string
	RelayURL        string
	RelayToken      string
	DNSTimeout      time.Duration
	SMTPTimeout     time.Duration
	Delay           time.Duration
	NoVerify        bool
	NoCloudFallback bool
	ShowAll         bool
	OutputFile      string
	Format          string
	OpenReport      bool
	Concurrency     int
}

func ParseFlags() (*Config, error) {
	cfg := &Config{}

	var (
		website         string
		domain          string
		name            string
		personLinkedIn  string
		companyLinkedIn string
		pattern         string
		proxy           string
		relayURL        string
		relayToken      string
		dnsTimeoutSec   int
		smtpTimeoutSec  int
		delayMs         int
		noVerify        bool
		noCloudFallback bool
		showAll         bool
		outputFile      string
		format          string
		openReport      bool
		concurrency     int
	)

	flag.StringVar(&website, "w", "", "Target company website/domain (e.g. acme.com)")
	flag.StringVar(&website, "website", "", "Target company website/domain")
	flag.StringVar(&domain, "d", "", "Target domain (alias for -w)")
	flag.StringVar(&domain, "domain", "", "Target domain (alias for -website)")

	flag.StringVar(&name, "n", "", "Target person full name (e.g. 'Jane Doe')")
	flag.StringVar(&name, "name", "", "Target person full name")

	flag.StringVar(&personLinkedIn, "l", "", "Person LinkedIn profile URL or handle")
	flag.StringVar(&personLinkedIn, "linkedin", "", "Person LinkedIn profile URL or handle")
	flag.StringVar(&personLinkedIn, "person-linkedin", "", "Person LinkedIn profile URL")

	flag.StringVar(&companyLinkedIn, "company-linkedin", "", "Company LinkedIn URL")

	flag.StringVar(&pattern, "p", "", "Known email pattern override (e.g. 'first.last', 'first', 'firstl')")
	flag.StringVar(&pattern, "pattern", "", "Known email pattern override")

	flag.StringVar(&proxy, "proxy", "", "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)")
	flag.StringVar(&relayURL, "relay-url", "", "Cloud relay fallback endpoint URL")
	flag.StringVar(&relayToken, "relay-token", "", "Bearer token for cloud relay")

	flag.IntVar(&dnsTimeoutSec, "dns-timeout", 5, "DNS resolution timeout in seconds")
	flag.IntVar(&smtpTimeoutSec, "smtp-timeout", 10, "SMTP connection timeout in seconds")
	flag.IntVar(&delayMs, "delay", 400, "Delay in milliseconds between SMTP probes")

	flag.BoolVar(&noVerify, "no-verify", false, "Generate candidates without RFC 5321 SMTP verification")
	flag.BoolVar(&noCloudFallback, "no-cloud-fallback", false, "Disable cloud relay and provider-specific checks")

	flag.BoolVar(&showAll, "a", false, "Display all permutations in terminal summary")
	flag.BoolVar(&showAll, "all", false, "Display all permutations in terminal summary")

	flag.StringVar(&outputFile, "o", "", "Save report to output file (path)")
	flag.StringVar(&outputFile, "output", "", "Save report to output file")

	flag.StringVar(&format, "f", "", "Report format (txt, json, csv, html). Inferred from output file if omitted.")
	flag.StringVar(&format, "format", "", "Report format")

	flag.BoolVar(&openReport, "open", false, "Automatically open HTML report in browser after generation")
	flag.IntVar(&concurrency, "c", 4, "Number of concurrent verification workers")
	flag.IntVar(&concurrency, "concurrency", 4, "Number of concurrent verification workers")

	flag.Parse()

	// Environment variable overrides
	if proxy == "" {
		proxy = os.Getenv("POC_RECON_PROXY")
	}
	if relayURL == "" {
		relayURL = os.Getenv("POC_RECON_RELAY_URL")
	}
	if relayToken == "" {
		relayToken = os.Getenv("POC_RECON_RELAY_TOKEN")
	}

	if website == "" && domain != "" {
		website = domain
	}

	cfg.Website = strings.TrimSpace(website)
	cfg.Name = strings.TrimSpace(name)
	cfg.PersonLinkedIn = strings.TrimSpace(personLinkedIn)
	cfg.CompanyLinkedIn = strings.TrimSpace(companyLinkedIn)
	cfg.Pattern = strings.TrimSpace(pattern)
	cfg.Proxy = strings.TrimSpace(proxy)
	cfg.RelayURL = strings.TrimSpace(relayURL)
	cfg.RelayToken = strings.TrimSpace(relayToken)
	cfg.DNSTimeout = time.Duration(dnsTimeoutSec) * time.Second
	cfg.SMTPTimeout = time.Duration(smtpTimeoutSec) * time.Second
	cfg.Delay = time.Duration(delayMs) * time.Millisecond
	cfg.NoVerify = noVerify
	cfg.NoCloudFallback = noCloudFallback
	cfg.ShowAll = showAll
	cfg.OutputFile = strings.TrimSpace(outputFile)
	cfg.OpenReport = openReport
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 10 {
		concurrency = 10
	}
	cfg.Concurrency = concurrency

	// Infer or validate format
	cfg.Format = strings.ToLower(strings.TrimSpace(format))
	if cfg.Format == "" && cfg.OutputFile != "" {
		ext := strings.ToLower(filepath.Ext(cfg.OutputFile))
		switch ext {
		case ".json":
			cfg.Format = "json"
		case ".csv":
			cfg.Format = "csv"
		case ".html", ".htm":
			cfg.Format = "html"
		default:
			cfg.Format = "txt"
		}
	} else if cfg.Format == "" {
		cfg.Format = "txt"
	}

	// Interactive prompt if required arguments are missing
	if cfg.Website == "" || (cfg.Name == "" && cfg.PersonLinkedIn == "") {
		reader := bufio.NewReader(os.Stdin)

		if cfg.Website == "" {
			fmt.Print("Enter target company website / domain (e.g. stripe.com): ")
			input, _ := reader.ReadString('\n')
			cfg.Website = strings.TrimSpace(input)
		}

		if cfg.Name == "" && cfg.PersonLinkedIn == "" {
			fmt.Print("Enter target person full name (or LinkedIn URL): ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if strings.Contains(input, "linkedin.com") {
				cfg.PersonLinkedIn = input
			} else {
				cfg.Name = input
			}
		}
	}

	if cfg.Website == "" {
		return nil, fmt.Errorf("target website/domain is required")
	}
	if cfg.Name == "" && cfg.PersonLinkedIn == "" {
		return nil, fmt.Errorf("target person name or LinkedIn profile is required")
	}

	return cfg, nil
}
