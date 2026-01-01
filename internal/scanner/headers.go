package scanner

import (
	"net/http"
	"strings"

	"github.com/ismailtsdln/HeaderSentinel/internal/rules"
)

// Finding represents a single security finding.
type Finding struct {
	Header         string
	Status         string // present / missing / misconfigured
	Risk           rules.RiskLevel
	Description    string
	Recommendation string
	Exploit        string
}

// HeaderScanner analyzes response headers.
type HeaderScanner struct {
	Rules []rules.SecurityRule
}

// NewHeaderScanner creates a new header scanner.
func NewHeaderScanner() *HeaderScanner {
	return &HeaderScanner{
		Rules: rules.SecurityHeaders,
	}
}

// Scan analyzes the headers of an HTTP response.
func (s *HeaderScanner) Scan(resp *http.Response) []Finding {
	findings := []Finding{}

	for _, rule := range s.Rules {
		value := resp.Header.Get(rule.Header)
		finding := Finding{
			Header:         rule.Header,
			Description:    rule.Description,
			Recommendation: rule.Recommendation,
			Exploit:        rule.Exploit,
		}

		if value == "" {
			// If header is missing, it's only a risk for required security headers
			if rule.Header != "Server" && rule.Header != "X-Powered-By" {
				finding.Status = "missing"
				finding.Risk = rule.Risk
				findings = append(findings, finding)
			}
			continue
		}

		// Basic misconfiguration checks
		switch rule.Header {
		case "Strict-Transport-Security":
			if !strings.Contains(value, "max-age") {
				finding.Status = "misconfigured"
				finding.Risk = rules.RiskMedium
				findings = append(findings, finding)
			}
		case "X-Frame-Options":
			v := strings.ToUpper(value)
			if v != "DENY" && v != "SAMEORIGIN" {
				finding.Status = "misconfigured"
				finding.Risk = rules.RiskMedium
				findings = append(findings, finding)
			}
		case "X-Content-Type-Options":
			if strings.ToLower(value) != "nosniff" {
				finding.Status = "misconfigured"
				finding.Risk = rules.RiskLow
				findings = append(findings, finding)
			}
		case "Server", "X-Powered-By":
			finding.Status = "present"
			finding.Risk = rules.RiskLow // Presence of these headers is a low risk information disclosure
			findings = append(findings, finding)
		}
	}

	return findings
}
