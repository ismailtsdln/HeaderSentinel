package scanner

import (
	"net/http"
)

// StatusResult represents the analysis of an HTTP status code.
type StatusResult struct {
	StatusCode int
	Message    string
	Risk       string // None, Low, Medium, High
}

// AnalyzeStatus analyzes the HTTP status code of a response.
func AnalyzeStatus(resp *http.Response) StatusResult {
	code := resp.StatusCode
	result := StatusResult{
		StatusCode: code,
		Risk:       "None",
	}

	switch {
	case code >= 200 && code < 300:
		result.Message = "Success"
	case code >= 300 && code < 400:
		result.Message = "Redirection"
	case code == 401 || code == 403:
		result.Message = "Access Denied"
		result.Risk = "Low"
	case code >= 400 && code < 500:
		result.Message = "Client Error"
	case code >= 500:
		result.Message = "Server Error"
		result.Risk = "Low"
	}

	return result
}
