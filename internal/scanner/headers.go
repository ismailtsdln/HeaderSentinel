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
		headerName := rule.Header
		values := resp.Header.Values(headerName)

		if len(values) == 0 {
			// If header is missing, it's only a risk for required security headers
			if headerName != "Server" && headerName != "X-Powered-By" && headerName != "Set-Cookie" {
				finding := s.createFinding(rule, "missing", rule.Risk)
				findings = append(findings, finding)
			}
			continue
		}

		for _, value := range values {
			finding := s.createFinding(rule, "present", rules.RiskInfo)

			// Special handling for Set-Cookie
			if headerName == "Set-Cookie" {
				s.analyzeCookie(value, rule, &findings)
				continue
			}

			// Basic misconfiguration checks
			switch headerName {
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
			case "Content-Security-Policy":
				if strings.Contains(value, "unsafe-inline") || strings.Contains(value, "unsafe-eval") {
					finding.Status = "misconfigured"
					finding.Risk = rules.RiskMedium
					finding.Description += " (Unsafe directives detected)"
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

func (s *HeaderScanner) createFinding(rule rules.SecurityRule, status string, risk rules.RiskLevel) Finding {
	return Finding{
		Header:         rule.Header,
		Status:         status,
		Risk:           risk,
		Description:    rule.Description,
		Recommendation: rule.Recommendation,
		Exploit:        rule.Exploit,
	}
}

func (s *HeaderScanner) analyzeCookie(value string, rule rules.SecurityRule, findings *[]Finding) {
	lowerValue := strings.ToLower(value)

	switch rule.CheckName {
	case "Insecure Cookie (Missing HttpOnly)":
		if !strings.Contains(lowerValue, "httponly") {
			finding := s.createFinding(rule, "misconfigured", rules.RiskMedium)
			*findings = append(*findings, finding)
		}
	case "Insecure Cookie (Missing Secure)":
		if !strings.Contains(lowerValue, "secure") {
			finding := s.createFinding(rule, "misconfigured", rules.RiskMedium)
			*findings = append(*findings, finding)
		}
	case "Insecure Cookie (Missing SameSite)":
		if !strings.Contains(lowerValue, "samesite") {
			finding := s.createFinding(rule, "misconfigured", rules.RiskLow)
			*findings = append(*findings, finding)
		}
	}
}
