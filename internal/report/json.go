package report

import (
	"encoding/json"

	"github.com/ismailtsdln/HeaderSentinel/internal/scanner"
	"github.com/ismailtsdln/HeaderSentinel/internal/scoring"
)

// ScanReport represents the full scan result for a URL.
type ScanReport struct {
	URL           string                 `json:"url"`
	Status        scanner.StatusResult   `json:"status"`
	Redirects     scanner.RedirectResult `json:"redirects"`
	SecurityScore scoring.ScoreResult    `json:"security_score"`
}

// JSONFormatter formats the report as JSON.
func JSONFormatter(data any) (string, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
