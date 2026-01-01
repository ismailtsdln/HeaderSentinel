package report

import (
	"encoding/json"
	"fmt"
)

// SARIFReport represents a basic SARIF structure.
type SARIFReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Version        string `json:"version"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	Address Address `json:"address"`
}

type Address struct {
	BaseAddress string `json:"baseAddress"`
}

// SARIFFormatter formats the report as SARIF.
func SARIFFormatter(reports []ScanReport) (string, error) {
	sarif := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "HeaderSentinel",
						InformationURI: "https://github.com/ismailtsdln/HeaderSentinel",
						Version:        "1.0.0",
					},
				},
				Results: []Result{},
			},
		},
	}

	for _, rep := range reports {
		for _, f := range rep.SecurityScore.Findings {
			if f.Status == "present" && f.Risk == "INFO" {
				continue
			}

			level := "warning"
			if f.Risk == "CRITICAL" || f.Risk == "HIGH" {
				level = "error"
			} else if f.Risk == "LOW" || f.Risk == "INFO" {
				level = "note"
			}

			res := Result{
				RuleID: f.Header,
				Level:  level,
				Message: Message{
					Text: fmt.Sprintf("%s: %s. Recommendation: %s", f.Header, f.Description, f.Recommendation),
				},
				Locations: []Location{
					{
						PhysicalLocation: PhysicalLocation{
							Address: Address{
								BaseAddress: rep.URL,
							},
						},
					},
				},
			}
			sarif.Runs[0].Results = append(sarif.Runs[0].Results, res)
		}
	}

	b, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
