package scanner

import (
	"net/http"
	"strings"
)

// RedirectChain represents a hop in a redirect chain.
type RedirectHop struct {
	URL        string
	StatusCode int
}

// RedirectResult represents the analysis of a redirect chain.
type RedirectResult struct {
	Chain             []RedirectHop
	InsecureDowngrade bool
}

// AnalyzeRedirects trace the redirect chain for a given URL using a custom client.
func AnalyzeRedirects(client *http.Client, startURL string) (RedirectResult, error) {
	result := RedirectResult{
		Chain: []RedirectHop{},
	}

	currentURL := startURL
	for i := 0; i < 10; i++ { // Limit to 10 redirects
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return result, err
		}

		// Use a local transport to avoid following redirects automatically in this loop
		transport := &http.Transport{}
		tempClient := &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := tempClient.Do(req)
		if err != nil {
			return result, err
		}
		defer resp.Body.Close()

		hop := RedirectHop{
			URL:        currentURL,
			StatusCode: resp.StatusCode,
		}
		result.Chain = append(result.Chain, hop)

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			nextURL := resp.Header.Get("Location")
			if nextURL == "" {
				break
			}

			// Detect insecure downgrade
			if strings.HasPrefix(currentURL, "https://") && strings.HasPrefix(nextURL, "http://") {
				result.InsecureDowngrade = true
			}

			currentURL = nextURL
		} else {
			break
		}
	}

	return result, nil
}
