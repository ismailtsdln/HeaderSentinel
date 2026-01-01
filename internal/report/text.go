package report

import (
	"fmt"
	"os"
	"text/tabwriter"
)

// PrintTable prints the scan result in a nice CLI table.
func PrintTable(report ScanReport) {
	fmt.Printf("\nTarget: %s\n", report.URL)
	fmt.Printf("Security Score: %d/100 (%s)\n", report.SecurityScore.Score, report.SecurityScore.RiskLevel)
	fmt.Printf("Status: %d %s\n", report.Status.StatusCode, report.Status.Message)

	if len(report.Redirects.Chain) > 1 {
		fmt.Println("Redirect Chain:")
		for _, hop := range report.Redirects.Chain {
			fmt.Printf("  -> [%d] %s\n", hop.StatusCode, hop.URL)
		}
		if report.Redirects.InsecureDowngrade {
			fmt.Println("  [!] WARNING: Insecure downgrade detected in redirect chain!")
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nHEADER\tSTATUS\tRISK\tRECOMMENDATION")
	fmt.Fprintln(w, "------\t------\t----\t--------------")

	for _, f := range report.SecurityScore.Findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Header, f.Status, f.Risk, f.Recommendation)
	}
	w.Flush()
	fmt.Println()
}
