package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ismailtsdln/HeaderSentinel/internal/report"
	"github.com/ismailtsdln/HeaderSentinel/internal/scanner"
	"github.com/ismailtsdln/HeaderSentinel/internal/scoring"
	"github.com/ismailtsdln/HeaderSentinel/internal/utils"
)

var (
	urlFlag            string
	inputFileFlag      string
	timeoutFlag        int
	followRedirectFlag bool
	jsonOutputFlag     string
	sarifOutputFlag    string
	concurrencyFlag    int
	failThresholdFlag  int
)

func init() {
	flag.StringVar(&urlFlag, "u", "", "Single URL to scan")
	flag.StringVar(&inputFileFlag, "i", "", "Path to bulk input file")
	flag.IntVar(&timeoutFlag, "t", 10, "Timeout in seconds")
	flag.BoolVar(&followRedirectFlag, "follow", true, "Follow redirects")
	flag.StringVar(&jsonOutputFlag, "json", "", "Output report in JSON format to file")
	flag.StringVar(&sarifOutputFlag, "sarif", "", "Output report in SARIF format to file")
	flag.IntVar(&concurrencyFlag, "c", 10, "Concurrency level for bulk scanning")
	flag.IntVar(&failThresholdFlag, "fail-threshold", 0, "Exit with non-zero code if security score is below this threshold")
}

func main() {
	flag.Parse()

	if urlFlag == "" && inputFileFlag == "" {
		fmt.Println("Usage of HeaderSentinel:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	targets := []string{}
	if urlFlag != "" {
		targets = append(targets, urlFlag)
	}
	if inputFileFlag != "" {
		file, err := os.Open(inputFileFlag)
		if err != nil {
			fmt.Printf("Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			target := strings.TrimSpace(scanner.Text())
			if target != "" {
				targets = append(targets, target)
			}
		}
	}

	httpClient := utils.NewHTTPClient(time.Duration(timeoutFlag)*time.Second, followRedirectFlag)
	headerScanner := scanner.NewHeaderScanner()

	reports := []report.ScanReport{}
	reportChan := make(chan report.ScanReport, len(targets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrencyFlag)

	for _, target := range targets {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}

			rep := scanURL(httpClient.Client, headerScanner, url)
			reportChan <- rep
		}(target)
	}

	go func() {
		wg.Wait()
		close(reportChan)
	}()

	for rep := range reportChan {
		reports = append(reports, rep)
		if jsonOutputFlag == "" && sarifOutputFlag == "" {
			report.PrintTable(rep)
		}
	}

	if jsonOutputFlag != "" {
		var content string
		var err error
		if len(reports) == 1 {
			content, err = report.JSONFormatter(reports[0])
		} else {
			// For bulk, wrap in a list
			importB, _ := report.JSONFormatter(reports)
			content = importB
		}

		if err == nil {
			err = os.WriteFile(jsonOutputFlag, []byte(content), 0644)
		}
		if err != nil {
			fmt.Printf("Error writing JSON output: %v\n", err)
		} else {
			fmt.Printf("JSON report saved to %s\n", jsonOutputFlag)
		}
	}

	if sarifOutputFlag != "" {
		content, err := report.SARIFFormatter(reports)
		if err == nil {
			err = os.WriteFile(sarifOutputFlag, []byte(content), 0644)
		}
		if err != nil {
			fmt.Printf("Error writing SARIF output: %v\n", err)
		} else {
			fmt.Printf("SARIF report saved to %s\n", sarifOutputFlag)
		}
	}

	// CI/CD failure threshold check
	if failThresholdFlag > 0 {
		lowestScore := 100
		for _, rep := range reports {
			if rep.SecurityScore.Score < lowestScore {
				lowestScore = rep.SecurityScore.Score
			}
		}
		if lowestScore < failThresholdFlag {
			fmt.Printf("\n[!] CI/CD Failure: Lowest security score (%d) is below threshold (%d)\n", lowestScore, failThresholdFlag)
			os.Exit(1)
		}
	}
}

func scanURL(client *http.Client, headerScanner *scanner.HeaderScanner, url string) report.ScanReport {
	rep := report.ScanReport{URL: url}

	// Analyze redirects
	redirectResult, err := scanner.AnalyzeRedirects(client, url)
	if err == nil {
		rep.Redirects = redirectResult
	}

	// perform final request
	resp, err := client.Get(url)
	if err != nil {
		rep.Status = scanner.StatusResult{Message: fmt.Sprintf("Error: %v", err)}
		return rep
	}
	defer resp.Body.Close()

	rep.Status = scanner.AnalyzeStatus(resp)
	findings := headerScanner.Scan(resp)
	rep.SecurityScore = scoring.CalculateScore(findings)

	return rep
}
