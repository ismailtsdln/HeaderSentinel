package scoring

import (
	"github.com/ismailtsdln/HeaderSentinel/internal/rules"
	"github.com/ismailtsdln/HeaderSentinel/internal/scanner"
)

// ScoreResult holds the final security score and findings.
type ScoreResult struct {
	Score     int
	Findings  []scanner.Finding
	RiskLevel string
}

// CalculateScore calculates a security score based on findings.
func CalculateScore(findings []scanner.Finding) ScoreResult {
	score := 100

	for _, f := range findings {
		switch f.Risk {
		case rules.RiskCritical:
			score -= 40
		case rules.RiskHigh:
			score -= 20
		case rules.RiskMedium:
			score -= 10
		case rules.RiskLow:
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}

	risk := "Excellent"
	switch {
	case score < 30:
		risk = "Critical"
	case score < 50:
		risk = "High"
	case score < 70:
		risk = "Medium"
	case score < 90:
		risk = "Low"
	}

	return ScoreResult{
		Score:     score,
		Findings:  findings,
		RiskLevel: risk,
	}
}
