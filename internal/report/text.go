package report

import (
	"fmt"
	"os"
	"text/tabwriter"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
)

// PrintTable prints the scan result in a nice CLI table.
func PrintTable(report ScanReport, showFix bool) {
	scoreColor := colorGreen
	if report.SecurityScore.Score < 50 {
		scoreColor = colorRed
	} else if report.SecurityScore.Score < 80 {
		scoreColor = colorYellow
	}

	fmt.Printf("\nTarget: %s%s%s\n", colorCyan, report.URL, colorReset)
	fmt.Printf("Security Score: %s%d/100 (%s)%s\n", scoreColor, report.SecurityScore.Score, report.SecurityScore.RiskLevel, colorReset)
	fmt.Printf("Status: %d %s\n", report.Status.StatusCode, report.Status.Message)

	if len(report.Redirects.Chain) > 1 {
		fmt.Println("Redirect Chain:")
		for _, hop := range report.Redirects.Chain {
			fmt.Printf("  -> [%d] %s\n", hop.StatusCode, hop.URL)
		}
		if report.Redirects.InsecureDowngrade {
			fmt.Printf("  %s[!] WARNING: Insecure downgrade detected in redirect chain!%s\n", colorRed, colorReset)
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n%sHEADER\tSTATUS\tRISK\tRECOMMENDATION%s\n", colorCyan, colorReset)
	fmt.Fprintln(w, "------\t------\t----\t--------------")

	for _, f := range report.SecurityScore.Findings {
		riskColor := colorReset
		switch f.Risk {
		case "CRITICAL", "HIGH":
			riskColor = colorRed
		case "MEDIUM":
			riskColor = colorYellow
		case "LOW":
			riskColor = colorBlue
		}

		fmt.Fprintf(w, "%s\t%s\t%s%s%s\t%s\n", f.Header, f.Status, riskColor, f.Risk, colorReset, f.Recommendation)

		if showFix && (f.NginxConfig != "" || f.ApacheConfig != "") {
			w.Flush() // Flush to ensure previous line is printed
			if f.NginxConfig != "" {
				fmt.Printf("  %s[Nginx]%s %s\n", colorBlue, colorReset, f.NginxConfig)
			}
			if f.ApacheConfig != "" {
				fmt.Printf("  %s[Apache]%s %s\n", colorBlue, colorReset, f.ApacheConfig)
			}
		}
	}
	w.Flush()
	fmt.Println()
}
